#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <argon2.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>

// Configuration structure
typedef struct {
    char pin_dir[1024];
    int min_length;
    int max_length;
    int require_digits_only;
    int max_attempts;
    int lockout_window;
    int rate_limit_window;
    int enable_lockout;
    int lockout_duration;
    int log_attempts;
    int log_success;
    int log_failures;
    int debug;
    int allow_user_config;
    int lockout_fails_auth;
} pinlock_config_t;

// Rate limiting structure
typedef struct {
    time_t first_attempt;
    int attempt_count;
    time_t lockout_until;
    int lockout_count;
} rate_limit_t;

// Secure memory wipe
static void memwipe(void *v, size_t n) {
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2,25)
    explicit_bzero(v,n);
    return;
#endif
#endif
    volatile unsigned char *p=(volatile unsigned char*)v; 
    while(n--) *p++=0;
}

// Read first line from file
static int read_first_line(const char *path, char **out) {
    *out = NULL;
#ifdef O_NOFOLLOW
    int fd = open(path, O_RDONLY|O_NOFOLLOW);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) return -1;
    FILE *f = fdopen(fd,"r");
    if(!f) { close(fd); return -1; }
    size_t cap=0; ssize_t n=getline(out,&cap,f); fclose(f);
    if(n<=0) { free(*out); *out=NULL; return -1; }
    while(n>0 && ((*out)[n-1]=='\n'||(*out)[n-1]=='\r')) (*out)[--n]=0;
    return 0;
}

static int file_exists(const char *path) { 
    struct stat st; 
    return stat(path,&st)==0 && S_ISREG(st.st_mode); 
}

// Prompt user for PIN
static int prompt_pin(pam_handle_t *pamh, const char *prompt, char **out_pin) {
    *out_pin=NULL;
    const char *display_prompt = prompt ? prompt : "PIN: ";
    size_t display_len = strlen(display_prompt);

    if (display_len > 0 && (display_prompt[0] == '"' || display_prompt[0] == '\'')) {
        char quote = display_prompt[0];
        display_prompt++;
        display_len--;
        if (display_len > 0 && display_prompt[display_len - 1] == quote) display_len--;
    }
    if (display_len > INT_MAX) display_len = INT_MAX;

    int r=pam_prompt(pamh,PAM_PROMPT_ECHO_OFF,out_pin,"%.*s",(int)display_len,display_prompt);
    return (r==PAM_SUCCESS && *out_pin)?PAM_SUCCESS:PAM_AUTH_ERR;
}

// Load default config
static void load_default_config(pinlock_config_t *config) {
    config->pin_dir[0] = '\0';
    config->min_length = 6;
    config->max_length = 32;
    config->require_digits_only = 1;
    config->max_attempts = 5;
    config->lockout_window = 300;
    config->rate_limit_window = 60;
    config->enable_lockout = 0;
    config->lockout_duration = 900;
    config->log_attempts = 1;
    config->log_success = 1;
    config->log_failures = 1;
    config->debug = 0;
    config->allow_user_config = 0;
    config->lockout_fails_auth = 0;
}

static int parse_bool(const char *value) {
    if (!value) return 0;
    return (strcasecmp(value, "yes") == 0 || 
            strcasecmp(value, "true") == 0 || 
            strcasecmp(value, "1") == 0);
}

static int parse_int_range(const char *value, int min, int max, int *out) {
    if (!value || !*value) return 0;

    errno = 0;
    char *end = NULL;
    long n = strtol(value, &end, 10);
    while (end && isspace((unsigned char)*end)) end++;
    if (errno || !end || *end || n < min || n > max) return 0;

    *out = (int)n;
    return 1;
}

static void strip_inline_comment(char *value) {
    char *hash = strchr(value, '#');
    if (hash) *hash = '\0';
}

static void trim_right(char *value) {
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) *--end = '\0';
}

static void validate_config(pinlock_config_t *config) {
    if (config->min_length < 1) config->min_length = 1;
    if (config->max_length < config->min_length) config->max_length = config->min_length;
    if (config->max_length > 128) config->max_length = 128;
    if (config->max_attempts < 1) config->max_attempts = 1;
    if (config->rate_limit_window < 1) config->rate_limit_window = 1;
    if (config->lockout_window < 0) config->lockout_window = 0;
    if (config->lockout_duration < 1) config->lockout_duration = 1;
}

// Load config from file
static void load_config_file(const char *path, pinlock_config_t *config) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        
        char *eq = strchr(p, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        trim_right(key);
        while (isspace((unsigned char)*value)) value++;
        strip_inline_comment(value);
        trim_right(value);

        int parsed = 0;
        if (strcmp(key, "pin_dir") == 0) {
            if (!*value || *value == '/') snprintf(config->pin_dir, sizeof(config->pin_dir), "%s", value);
        }
        else if (strcmp(key, "min_length") == 0 && parse_int_range(value, 1, 128, &parsed)) config->min_length = parsed;
        else if (strcmp(key, "max_length") == 0 && parse_int_range(value, 1, 128, &parsed)) config->max_length = parsed;
        else if (strcmp(key, "require_digits_only") == 0) config->require_digits_only = parse_bool(value);
        else if (strcmp(key, "max_attempts") == 0 && parse_int_range(value, 1, 50, &parsed)) config->max_attempts = parsed;
        else if (strcmp(key, "lockout_window") == 0 && parse_int_range(value, 0, 86400, &parsed)) config->lockout_window = parsed;
        else if (strcmp(key, "rate_limit_window") == 0 && parse_int_range(value, 1, 86400, &parsed)) config->rate_limit_window = parsed;
        else if (strcmp(key, "enable_lockout") == 0) config->enable_lockout = parse_bool(value);
        else if (strcmp(key, "lockout_duration") == 0 && parse_int_range(value, 1, 604800, &parsed)) config->lockout_duration = parsed;
        else if (strcmp(key, "max_lockout_attempts") == 0) continue;
        else if (strcmp(key, "log_attempts") == 0) config->log_attempts = parse_bool(value);
        else if (strcmp(key, "log_success") == 0) config->log_success = parse_bool(value);
        else if (strcmp(key, "log_failures") == 0) config->log_failures = parse_bool(value);
        else if (strcmp(key, "debug") == 0) config->debug = parse_bool(value);
        else if (strcmp(key, "allow_user_config") == 0) config->allow_user_config = parse_bool(value);
        else if (strcmp(key, "lockout_fails_auth") == 0) config->lockout_fails_auth = parse_bool(value);
    }
    
    fclose(f);
}

// Load config for user
static void load_config(const char *user, pinlock_config_t *config) {
    load_default_config(config);
    load_config_file("/etc/pinlock.conf", config);

    if (!config->allow_user_config) {
        validate_config(config);
        return;
    }

    struct passwd *pw = getpwnam(user);
    if (pw) {
        char user_config[1024];
        int n = snprintf(user_config, sizeof(user_config), "%s/.pinlock/pinlock.conf", pw->pw_dir);
        if (n >= 0 && n < (int)sizeof(user_config)) load_config_file(user_config, config);
    }

    validate_config(config);
}

// Parse module args
static void parse_args(int argc, const char **argv, const char **prompt, int *retries, pinlock_config_t *config) {
    *prompt = NULL;
    *retries = 1;
    for(int i=0;i<argc;i++) {
        if(strncmp(argv[i],"prompt=",7)==0) *prompt=argv[i]+7;
        else if(strncmp(argv[i],"pin_dir=",8)==0) {
            const char *dir = argv[i]+8;
            if (!*dir || *dir == '/') snprintf(config->pin_dir, sizeof(config->pin_dir), "%s", dir);
        }
        else if(strncmp(argv[i],"retries=",8)==0) {
            int parsed = 0;
            if (parse_int_range(argv[i]+8, 1, 50, &parsed)) *retries = parsed;
        }
        else if(strcmp(argv[i],"debug")==0) config->debug=1;
    }
}

// Get configured PIN directory, defaulting to user .pinlock dir
static const char* get_pinlock_dir(const char* user, const pinlock_config_t *config) {
    static char dir[1024];

    if(config->pin_dir[0]) {
        int n = snprintf(dir,sizeof(dir),"%s",config->pin_dir);
        if(n < 0 || n >= (int)sizeof(dir)) return NULL;
        return dir;
    }

    struct passwd* pw=getpwnam(user);
    if(!pw) return NULL;
    int n = snprintf(dir,sizeof(dir),"%s/.pinlock",pw->pw_dir);
    if(n < 0 || n >= (int)sizeof(dir)) return NULL;
    return dir;
}

static int system_pin_dir_enabled(const pinlock_config_t *config) {
    return config->pin_dir[0] != '\0';
}

static int lockout_result(const pinlock_config_t *config) {
    return config->lockout_fails_auth ? PAM_AUTH_ERR : PAM_IGNORE;
}

static int check_pin_dir(pam_handle_t *pamh, const char *dir, const struct passwd *pw, const pinlock_config_t *config) {
    struct stat st;
    if (lstat(dir, &st) != 0) {
        int saved_errno = errno;
        if (saved_errno == ENOENT) return PAM_IGNORE;
        if (config->debug) pam_syslog(pamh, LOG_WARNING, "pinlock: cannot stat PIN directory %s: %s", dir, strerror(saved_errno));
        return PAM_AUTH_ERR;
    }

    if (!S_ISDIR(st.st_mode)) {
        pam_syslog(pamh, LOG_WARNING, "pinlock: PIN path %s is not a directory", dir);
        return PAM_AUTH_ERR;
    }

    if (system_pin_dir_enabled(config)) {
        if (st.st_uid != 0) {
            pam_syslog(pamh, LOG_WARNING, "pinlock: system PIN directory %s is not root-owned", dir);
            return PAM_AUTH_ERR;
        }
    } else if (st.st_uid != 0 && (!pw || st.st_uid != pw->pw_uid)) {
        pam_syslog(pamh, LOG_WARNING, "pinlock: user PIN directory %s has unsafe owner", dir);
        return PAM_AUTH_ERR;
    }

    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        pam_syslog(pamh, LOG_WARNING, "pinlock: PIN directory %s must not be group/world accessible", dir);
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

static int check_pin_file(pam_handle_t *pamh, const char *path, const struct passwd *pw, const pinlock_config_t *config) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        int saved_errno = errno;
        if (saved_errno == ENOENT) return PAM_IGNORE;
        if (config->debug) pam_syslog(pamh, LOG_WARNING, "pinlock: cannot stat PIN file %s: %s", path, strerror(saved_errno));
        return PAM_AUTH_ERR;
    }

    if (!S_ISREG(st.st_mode)) {
        pam_syslog(pamh, LOG_WARNING, "pinlock: PIN file %s is not a regular file", path);
        return PAM_AUTH_ERR;
    }

    if (system_pin_dir_enabled(config)) {
        if (st.st_uid != 0) {
            pam_syslog(pamh, LOG_WARNING, "pinlock: system PIN file %s is not root-owned", path);
            return PAM_AUTH_ERR;
        }
    } else if (st.st_uid != 0 && (!pw || st.st_uid != pw->pw_uid)) {
        pam_syslog(pamh, LOG_WARNING, "pinlock: user PIN file %s has unsafe owner", path);
        return PAM_AUTH_ERR;
    }

    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        pam_syslog(pamh, LOG_WARNING, "pinlock: PIN file %s must not be group/world accessible", path);
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

// Rate-limit file helpers
static int load_rate_limit(const char *path, rate_limit_t *rl) {
    FILE *f = fopen(path, "r");
    if (!f) { memset(rl,0,sizeof(*rl)); return 0; }
    int ret = fscanf(f, "%ld %d %ld %d", &rl->first_attempt, &rl->attempt_count, &rl->lockout_until, &rl->lockout_count);
    fclose(f);
    if (ret != 4) { memset(rl,0,sizeof(*rl)); return 0; }
    return 1;
}

static int save_rate_limit(const char *path, const rate_limit_t *rl) {
#ifdef O_NOFOLLOW
    int fd = open(path,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);
#else
    int fd = open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);
#endif
    if(fd<0) return -1;
    char buf[256];
    int n = snprintf(buf,sizeof(buf),"%ld %d %ld %d\n", rl->first_attempt, rl->attempt_count, rl->lockout_until, rl->lockout_count);
    if(n < 0 || n >= (int)sizeof(buf)) { close(fd); return -1; }
    ssize_t written = write(fd,buf,n);
    close(fd);
    return (written==n)?0:-1;
}

// Rate limit / lockout checks
static int check_rate_limit(pam_handle_t *pamh, const char *user, const char *dir, const pinlock_config_t *config, int success) {
    char rl_path[1024];
    int n = snprintf(rl_path,sizeof(rl_path),"%s/%s.ratelimit",dir,user);
    if(n<0||n>=(int)sizeof(rl_path)) return PAM_AUTH_ERR;
    
    rate_limit_t rl;
    load_rate_limit(rl_path,&rl);
    time_t now=time(NULL);
    
    if(rl.lockout_until > now) {
        if(config->log_failures)
            pam_syslog(pamh,LOG_WARNING,"pinlock: user %s PIN unavailable until %ld",user,rl.lockout_until);
        return lockout_result(config);
    }
    
    if(now - rl.first_attempt > config->rate_limit_window) {
        rl.first_attempt = now;
        rl.attempt_count = 0;
    }
    
    if(success) { memset(&rl,0,sizeof(rl)); save_rate_limit(rl_path,&rl); return PAM_SUCCESS; }
    
    if(rl.attempt_count==0) rl.first_attempt=now;
    rl.attempt_count++;
    
    if(config->log_attempts)
        pam_syslog(pamh,LOG_INFO,"pinlock: failed attempt %d/%d for user %s", rl.attempt_count, config->max_attempts, user);
    
    if(rl.attempt_count >= config->max_attempts) {
        if(config->enable_lockout) {
            rl.lockout_count++;
            rl.lockout_until = now + config->lockout_duration;
            rl.attempt_count = 0;
            if(config->log_failures)
                pam_syslog(pamh,LOG_WARNING,"pinlock: user %s locked out for %d seconds (lockout #%d)", user, config->lockout_duration, rl.lockout_count);
        } else if(config->log_failures)
            pam_syslog(pamh,LOG_WARNING,"pinlock: rate limit exceeded for user %s, try again later", user);
        if(!config->enable_lockout) {
            rl.lockout_until = now + config->lockout_window;
            rl.attempt_count = 0;
        }
        save_rate_limit(rl_path,&rl);
        return lockout_result(config);
    }
    
    save_rate_limit(rl_path,&rl);
    return PAM_SUCCESS;
}

// Validate PIN
static int validate_pin(const char *pin, const pinlock_config_t *config) {
    if(!pin) return 0;
    size_t len = strlen(pin);
    if(len < (size_t)config->min_length || len > (size_t)config->max_length) return 0;
    if(config->require_digits_only) {
        for(size_t i=0;i<len;i++) if(!isdigit((unsigned char)pin[i])) return 0;
    }
    return 1;
}

// Authentication
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags;

    const char *user = NULL;
    struct passwd *pw = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user) {
        pw = getpwuid(getuid());
        if (!pw) return PAM_IGNORE;
        user = pw->pw_name;
    }
    if (!pw) pw = getpwnam(user);

    pinlock_config_t config;
    load_config(user, &config);

    const char *prompt = NULL;
    int retries = 1;
    parse_args(argc, argv, &prompt, &retries, &config);
    if (!prompt) prompt = "PIN: ";

    const char *dir = get_pinlock_dir(user, &config);
    if (!dir) return PAM_AUTH_ERR;

    int dir_status = check_pin_dir(pamh, dir, pw, &config);
    if (dir_status != PAM_SUCCESS) return dir_status;

    char pin_path[1024], rl_path[1024];
    int n = snprintf(pin_path, sizeof(pin_path), "%s/%s.pin", dir, user);
    if(n<0||n>=(int)sizeof(pin_path)) return PAM_IGNORE;
    n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if(n<0||n>=(int)sizeof(rl_path)) return PAM_IGNORE;

    if (config.debug)
        pam_syslog(pamh, LOG_INFO, "pinlock: authenticating user '%s' with PIN file '%s'", user, pin_path);

    int file_status = check_pin_file(pamh, pin_path, pw, &config);
    if (file_status == PAM_AUTH_ERR) return PAM_AUTH_ERR;
    if (file_status == PAM_IGNORE || !file_exists(pin_path)) {
        if (config.debug)
            pam_syslog(pamh, LOG_INFO, "pinlock: no PIN file for %s at %s, skipping", user, pin_path);
        return PAM_IGNORE;
    }

    int attempt;
    for (attempt = 0; attempt < retries; ++attempt) {
        rate_limit_t rl;
        load_rate_limit(rl_path, &rl);
        time_t now = time(NULL);

        if (rl.lockout_until > now) {
            if (config.log_failures)
                pam_syslog(pamh, LOG_WARNING,
                           "pinlock: PIN unavailable for user %s until %ld",
                           user, rl.lockout_until);
            return lockout_result(&config);
        }

        if (rl.attempt_count >= config.max_attempts &&
            now - rl.first_attempt <= config.rate_limit_window) {
            if (config.log_failures)
                pam_syslog(pamh, LOG_WARNING,
                           "pinlock: max PIN attempts reached for user %s",
                           user);
            return lockout_result(&config);
        }

        char *pin = NULL;
        if (prompt_pin(pamh, prompt, &pin) != PAM_SUCCESS)
            return PAM_AUTH_ERR;

        if (!validate_pin(pin, &config)) {
            memwipe(pin, strlen(pin));
            free(pin);
            continue; // re-prompt
        }

        char *encoded = NULL;
        if (read_first_line(pin_path, &encoded) != 0 || !encoded) {
            memwipe(pin, strlen(pin));
            free(pin);
            return PAM_IGNORE;
        }

        int v = argon2id_verify(encoded, pin, strlen(pin));
        memwipe(pin, strlen(pin)); free(pin); free(encoded);

        if (v == ARGON2_OK) {
            check_rate_limit(pamh, user, dir, &config, 1);
            if (config.log_success)
                pam_syslog(pamh, LOG_INFO,
                           "pinlock: successful authentication for user %s", user);
            return PAM_SUCCESS;
        }

        check_rate_limit(pamh, user, dir, &config, 0);
        if (config.log_failures)
            pam_syslog(pamh, LOG_WARNING,
                       "pinlock: PIN incorrect for user %s, local attempt %d/%d",
                       user, attempt + 1, retries);
    }

    // By default, PIN exhaustion falls back to the next PAM method.
    return lockout_result(&config);
}


// Set credentials
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,const char **argv){
    (void)pamh;(void)flags;(void)argc;(void)argv;
    return PAM_IGNORE;
}
