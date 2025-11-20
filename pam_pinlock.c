#include <security/_pam_types.h>
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
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

// Configuration structure
typedef struct {
    int min_length;
    int max_length;
    int require_digits_only;
    int max_attempts;
    int lockout_window;
    int rate_limit_window;
    int enable_lockout;
    int lockout_duration;
    int max_lockout_attempts;
    int log_attempts;
    int log_success;
    int log_failures;
    int debug;
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
    FILE *f = fopen(path,"re"); if(!f) return -1;
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
    int r=pam_prompt(pamh,PAM_PROMPT_ECHO_OFF,out_pin,"%s",prompt?prompt:"PIN: ");
    return (r==PAM_SUCCESS && *out_pin)?PAM_SUCCESS:PAM_AUTH_ERR;
}

// Load default config
static void load_default_config(pinlock_config_t *config) {
    config->min_length = 6;
    config->max_length = 32;
    config->require_digits_only = 1;
    config->max_attempts = 5;
    config->lockout_window = 300;
    config->rate_limit_window = 60;
    config->enable_lockout = 0;
    config->lockout_duration = 900;
    config->max_lockout_attempts = 3;
    config->log_attempts = 1;
    config->log_success = 1;
    config->log_failures = 1;
    config->debug = 0;
}

static int parse_bool(const char *value) {
    if (!value) return 0;
    return (strcasecmp(value, "yes") == 0 || 
            strcasecmp(value, "true") == 0 || 
            strcasecmp(value, "1") == 0);
}

// Load config from file
static void load_config_file(const char *path, pinlock_config_t *config) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (isspace(*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        
        char *eq = strchr(p, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        char *end = key + strlen(key) - 1;
        while (end > key && isspace(*end)) *end-- = '\0';
        while (isspace(*value)) value++;
        end = value + strlen(value) - 1;
        while (end > value && isspace(*end)) *end-- = '\0';
        
        if (strcmp(key, "min_length") == 0) config->min_length = atoi(value);
        else if (strcmp(key, "max_length") == 0) config->max_length = atoi(value);
        else if (strcmp(key, "require_digits_only") == 0) config->require_digits_only = parse_bool(value);
        else if (strcmp(key, "max_attempts") == 0) config->max_attempts = atoi(value);
        else if (strcmp(key, "lockout_window") == 0) config->lockout_window = atoi(value);
        else if (strcmp(key, "rate_limit_window") == 0) config->rate_limit_window = atoi(value);
        else if (strcmp(key, "enable_lockout") == 0) config->enable_lockout = parse_bool(value);
        else if (strcmp(key, "lockout_duration") == 0) config->lockout_duration = atoi(value);
        else if (strcmp(key, "max_lockout_attempts") == 0) config->max_lockout_attempts = atoi(value);
        else if (strcmp(key, "log_attempts") == 0) config->log_attempts = parse_bool(value);
        else if (strcmp(key, "log_success") == 0) config->log_success = parse_bool(value);
        else if (strcmp(key, "log_failures") == 0) config->log_failures = parse_bool(value);
        else if (strcmp(key, "debug") == 0) config->debug = parse_bool(value);
    }
    
    fclose(f);
}

// Load config for user
static void load_config(const char *user, pinlock_config_t *config) {
    load_default_config(config);
    load_config_file("/etc/pinlock.conf", config);
    
    struct passwd *pw = getpwnam(user);
    if (pw) {
        char user_config[1024];
        int n = snprintf(user_config, sizeof(user_config), "%s/.pinlock/pinlock.conf", pw->pw_dir);
        if (n < 0 || n >= (int)sizeof(user_config)) return;
        load_config_file(user_config, config);
    }
}

// Parse module args
static void parse_args(int argc, const char **argv, const char **prompt, pinlock_config_t *config) {
    *prompt = NULL;
    for(int i=0;i<argc;i++) {
        if(strncmp(argv[i],"prompt=",7)==0) *prompt=argv[i]+7;
        else if(strcmp(argv[i],"debug")==0) config->debug=1;
    }
}

// Get user .pinlock dir
static const char* get_pinlock_dir(const char* user) {
    struct passwd* pw=getpwnam(user);
    if(!pw) return NULL;
    static char dir[1024];
    int n = snprintf(dir,sizeof(dir),"%s/.pinlock",pw->pw_dir);
    if(n < 0 || n >= (int)sizeof(dir)) return NULL;
    return dir;
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
    int fd = open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);
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
    
    if(config->enable_lockout && rl.lockout_until > now) {
        if(config->log_failures)
            pam_syslog(pamh,LOG_WARNING,"pinlock: user %s locked out until %ld",user,rl.lockout_until);
        return PAM_IGNORE;
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
        save_rate_limit(rl_path,&rl);
        return PAM_IGNORE;
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
        for(size_t i=0;i<len;i++) if(!isdigit(pin[i])) return 0;
    }
    return 1;
}

// Authentication
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags;

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user) {
        struct passwd *pw = getpwuid(getuid());
        if (!pw) return PAM_IGNORE;
        user = pw->pw_name;
    }

    pinlock_config_t config;
    load_config(user, &config);

    const char *prompt = NULL;
    parse_args(argc, argv, &prompt, &config);
    if (!prompt) prompt = "PIN: ";

    const char *dir = get_pinlock_dir(user);
    if (!dir) return PAM_AUTH_ERR;

    char pin_path[1024], rl_path[1024];
    int n = snprintf(pin_path, sizeof(pin_path), "%s/%s.pin", dir, user);
    if(n<0||n>=(int)sizeof(pin_path)) return PAM_IGNORE;
    n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if(n<0||n>=(int)sizeof(rl_path)) return PAM_IGNORE;

    if (!file_exists(pin_path)) {
        if (config.debug)
            pam_syslog(pamh, LOG_INFO, "pinlock: no PIN file for %s, skipping", user);
        return PAM_IGNORE;
    }

    int attempt;
    for (attempt = 0; attempt < config.max_attempts; ++attempt) {
        rate_limit_t rl;
        load_rate_limit(rl_path, &rl);
        time_t now = time(NULL);

        if (rl.attempt_count >= config.max_attempts &&
            now - rl.first_attempt <= config.rate_limit_window) {
            if (config.log_failures)
                pam_syslog(pamh, LOG_WARNING,
                           "pinlock: max PIN attempts reached for user %s, falling back to pam_unix",
                           user);
            return PAM_IGNORE;
        }

        char *pin = NULL;
        if (prompt_pin(pamh, prompt, &pin) != PAM_SUCCESS)
            return PAM_AUTH_ERR;

        if (!validate_pin(pin, &config)) {
            memwipe(pin, strlen(pin));
            free(pin);
            check_rate_limit(pamh, user, dir, &config, 0);
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
                       "pinlock: PIN incorrect for user %s, attempt %d/%d",
                       user, attempt + 1, config.max_attempts);
    }

    // If we reach max attempts, fall back to pam_unix
    return PAM_IGNORE;
}


// Set credentials
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,const char **argv){
    (void)pamh;(void)flags;(void)argc;(void)argv;
    return PAM_IGNORE;
}
