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
    int local_retries;  // NEW: number of retries within this PAM call
} pinlock_config_t;

// Rate limiting structure
typedef struct {
    time_t first_attempt;
    int attempt_count;
    time_t lockout_until;
    int lockout_count;
} rate_limit_t;

static void memwipe(void *v, size_t n) {
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2,25)
    explicit_bzero(v,n);
    return;
#endif
#endif
    volatile unsigned char *p=(volatile unsigned char*)v; while(n--) *p++=0;
}

static int read_first_line(const char *path, char **out) {
    *out=NULL;
    FILE *f=fopen(path,"re"); if(!f) return -1;
    size_t cap=0; ssize_t n=getline(out,&cap,f); fclose(f);
    if(n<=0) { free(*out); *out=NULL; return -1; }
    while(n>0 && ((*out)[n-1]=='\n'||(*out)[n-1]=='\r')) (*out)[--n]=0;
    return 0;
}

static int file_exists(const char *path) { 
    struct stat st; 
    return stat(path,&st)==0 && S_ISREG(st.st_mode); 
}

static int prompt_pin(pam_handle_t *pamh, const char *prompt, char **out_pin) {
    *out_pin=NULL;
    int r=pam_prompt(pamh,PAM_PROMPT_ECHO_OFF,out_pin,"%s",prompt?prompt:"PIN: ");
    return (r==PAM_SUCCESS && *out_pin)?PAM_SUCCESS:PAM_AUTH_ERR;
}

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
    config->local_retries = 3;  // NEW: default to 3 attempts
}

static int parse_bool(const char *value) {
    if (!value) return 0;
    return (strcasecmp(value, "yes") == 0 || 
            strcasecmp(value, "true") == 0 || 
            strcasecmp(value, "1") == 0);
}

static void load_config_file(const char *path, pinlock_config_t *config) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        char *p = line;
        while (isspace(*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        
        // Find the = sign
        char *eq = strchr(p, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        // Trim whitespace
        char *end = key + strlen(key) - 1;
        while (end > key && isspace(*end)) *end-- = '\0';
        while (isspace(*value)) value++;
        end = value + strlen(value) - 1;
        while (end > value && isspace(*end)) *end-- = '\0';
        
        // Parse configuration values
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
        else if (strcmp(key, "local_retries") == 0) config->local_retries = atoi(value);  // NEW
    }
    
    fclose(f);
}

static void load_config(const char *user, pinlock_config_t *config) {
    load_default_config(config);
    
    // Try system config first
    load_config_file("/etc/pinlock.conf", config);
    
    // Try user config
    struct passwd *pw = getpwnam(user);
    if (pw) {
        char user_config[1024];
        snprintf(user_config, sizeof(user_config), "%s/.pinlock/pinlock.conf", pw->pw_dir);
        load_config_file(user_config, config);
    }
}

static void parse_args(int argc, const char **argv, const char **prompt, pinlock_config_t *config) {
    *prompt = NULL;
    for(int i=0;i<argc;i++) {
        if(strncmp(argv[i],"prompt=",7)==0) *prompt=argv[i]+7;
        else if(strcmp(argv[i],"debug")==0) config->debug=1;
        else if(strncmp(argv[i],"retries=",8)==0) config->local_retries=atoi(argv[i]+8);  // NEW
    }
}

static const char* get_pinlock_dir(const char* user) {
    struct passwd* pw=getpwnam(user);
    if(!pw) return NULL;
    static char dir[1024];
    int n = snprintf(dir,sizeof(dir),"%s/.pinlock",pw->pw_dir);
    if(n < 0 || n >= (int)sizeof(dir)) return NULL;
    return dir;
}

static int load_rate_limit(const char *path, rate_limit_t *rl) {
    FILE *f = fopen(path, "r");
    if (!f) {
        memset(rl, 0, sizeof(*rl));
        return 0;
    }
    
    int ret = fscanf(f, "%ld %d %ld %d", &rl->first_attempt, &rl->attempt_count, 
                     &rl->lockout_until, &rl->lockout_count);
    fclose(f);
    
    if (ret != 4) {
        memset(rl, 0, sizeof(*rl));
        return 0;
    }
    return 1;
}

static int save_rate_limit(const char *path, const rate_limit_t *rl) {
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return -1;
    
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "%ld %d %ld %d\n", 
                     rl->first_attempt, rl->attempt_count, 
                     rl->lockout_until, rl->lockout_count);
    
    ssize_t written = write(fd, buf, n);
    close(fd);
    
    return (written == n) ? 0 : -1;
}

static int check_rate_limit(pam_handle_t *pamh, const char *user, const char *dir, 
                           const pinlock_config_t *config, int success) {
    char rl_path[1024];
    snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    
    rate_limit_t rl;
    load_rate_limit(rl_path, &rl);
    
    time_t now = time(NULL);
    
    // Check if locked out
    if (config->enable_lockout && rl.lockout_until > now) {
        if (config->log_failures) {
            pam_syslog(pamh, LOG_WARNING, "pinlock: user %s locked out until %ld", 
                      user, rl.lockout_until);
        }
        return PAM_AUTH_ERR;
    }
    
    // Reset rate limit window if expired
    if (now - rl.first_attempt > config->rate_limit_window) {
        rl.first_attempt = now;
        rl.attempt_count = 0;
    }
    
    if (success) {
        // Reset on successful auth
        memset(&rl, 0, sizeof(rl));
        save_rate_limit(rl_path, &rl);
        return PAM_SUCCESS;
    }
    
    // Failed attempt
    if (rl.attempt_count == 0) {
        rl.first_attempt = now;
    }
    rl.attempt_count++;
    
    if (config->log_attempts) {
        pam_syslog(pamh, LOG_INFO, "pinlock: failed attempt %d/%d for user %s", 
                  rl.attempt_count, config->max_attempts, user);
    }
    
    // Check if we've exceeded rate limit
    if (rl.attempt_count >= config->max_attempts) {
        if (config->enable_lockout) {
            rl.lockout_count++;
            rl.lockout_until = now + config->lockout_duration;
            rl.attempt_count = 0; // Reset attempts after lockout
            
            if (config->log_failures) {
                pam_syslog(pamh, LOG_WARNING, 
                          "pinlock: user %s locked out for %d seconds (lockout #%d)", 
                          user, config->lockout_duration, rl.lockout_count);
            }
        } else {
            // Just delay without permanent lockout
            if (config->log_failures) {
                pam_syslog(pamh, LOG_WARNING, 
                          "pinlock: rate limit exceeded for user %s, try again later", user);
            }
        }
        
        save_rate_limit(rl_path, &rl);
        return PAM_AUTH_ERR;
    }
    
    save_rate_limit(rl_path, &rl);
    return PAM_SUCCESS; // Allow this attempt
}

static int validate_pin(const char *pin, const pinlock_config_t *config) {
    if (!pin) return 0;
    
    size_t len = strlen(pin);
    if (len < (size_t)config->min_length || len > (size_t)config->max_length) {
        return 0;
    }
    
    if (config->require_digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit(pin[i])) return 0;
        }
    }
    
    return 1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags;
    
    const char *user=NULL;
    int pret=pam_get_user(pamh,&user,NULL);
    if(pret!=PAM_SUCCESS || !user || !*user) {
        uid_t uid=getuid();
        struct passwd *pw=getpwuid(uid);
        if(!pw) { 
            pam_syslog(pamh,LOG_ERR,"pinlock: cannot resolve user"); 
            return PAM_AUTH_ERR; 
        }
        user=pw->pw_name;
    }
    
    // Load configuration
    pinlock_config_t config;
    load_config(user, &config);
    
    const char *prompt;
    parse_args(argc, argv, &prompt, &config);
    
    if(config.debug) {
        pam_syslog(pamh,LOG_DEBUG,"pinlock: authenticating user '%s'",user);
    }

    // Build default prompt with username if not specified via args
    static char default_prompt[256];
    if(!prompt) {
        int n = snprintf(default_prompt, sizeof(default_prompt), "PIN (%s): ", user);
        if(n < 0 || n >= (int)sizeof(default_prompt)) {
            prompt = "PIN: ";
        } else {
            prompt = default_prompt;
        }
    }
    
    const char* dir=get_pinlock_dir(user);
    if(!dir) { 
        pam_syslog(pamh,LOG_ERR,"pinlock: cannot resolve home directory for user %s", user); 
        return PAM_AUTH_ERR; 
    }
    
    char path[1024];
    int n = snprintf(path,sizeof(path),"%s/%s.pin",dir,user);
    if(n < 0 || n >= (int)sizeof(path)) {
        pam_syslog(pamh,LOG_ERR,"pinlock: path too long for user %s",user);
        return PAM_AUTH_ERR;
    }
    
    if(!file_exists(path)) {
        if(config.debug) {
            pam_syslog(pamh,LOG_DEBUG,"pinlock: no PIN file for %s -> IGNORE",user);
        }
        return PAM_IGNORE;
    }
    
    // Check rate limiting before prompting
    int rate_check = check_rate_limit(pamh, user, dir, &config, 0);
    if (rate_check != PAM_SUCCESS) {
        return rate_check;
    }
    
    char *encoded=NULL;
    if(read_first_line(path,&encoded)!=0 || !encoded || !*encoded) { 
        pam_syslog(pamh,LOG_ERR,"pinlock: failed to read PIN file for user %s",user);
        free(encoded); 
        return PAM_AUTH_ERR; 
    }
    
    // NEW: Retry loop - prompt multiple times before failing
    int attempts = 0;
    int max_local_attempts = config.local_retries > 0 ? config.local_retries : 1;
    
    for (attempts = 0; attempts < max_local_attempts; attempts++) {
        char *pin=NULL;
        
        // Show attempt number if more than 1 attempt allowed
        char retry_prompt[256];
        if (max_local_attempts > 1) {
            snprintf(retry_prompt, sizeof(retry_prompt), "%s (attempt %d/%d): ", 
                    prompt, attempts + 1, max_local_attempts);
        } else {
            snprintf(retry_prompt, sizeof(retry_prompt), "%s", prompt);
        }
        
        int pr=prompt_pin(pamh, retry_prompt, &pin);
        if(pr!=PAM_SUCCESS) { 
            pam_syslog(pamh,LOG_ERR,"pinlock: failed to prompt for PIN for user %s",user);
            free(encoded); 
            return PAM_AUTH_ERR; 
        }
        
        // Validate PIN format
        if (!validate_pin(pin, &config)) {
            if (config.log_failures) {
                pam_syslog(pamh,LOG_WARNING,"pinlock: invalid PIN format for user %s (attempt %d/%d)",
                          user, attempts + 1, max_local_attempts);
            }
            memwipe(pin,strlen(pin));
            free(pin);
            
            // Check if this was the last attempt
            if (attempts + 1 >= max_local_attempts) {
                check_rate_limit(pamh, user, dir, &config, 0); // Record failed attempt
                free(encoded);
                return PAM_AUTH_ERR;
            }
            
            // Show error message and continue to next attempt
            pam_info(pamh, "Invalid PIN format. Please try again.");
            continue;
        }
        
        // Verify PIN
        int v=argon2id_verify(encoded,pin,strlen(pin));
        memwipe(pin,strlen(pin));
        free(pin);
        
        if(v==ARGON2_OK) { 
            // Success - reset rate limiting
            check_rate_limit(pamh, user, dir, &config, 1);
            
            if(config.log_success) {
                pam_syslog(pamh,LOG_INFO,"pinlock: successful authentication for user %s",user);
            }
            free(encoded);
            return PAM_SUCCESS; 
        }
        
        // Failed verification
        if(config.log_failures) {
            pam_syslog(pamh,LOG_WARNING,"pinlock: authentication failed for user %s (attempt %d/%d, argon2 error %d)",
                      user, attempts + 1, max_local_attempts, v);
        }
        
        // Check if this was the last attempt
        if (attempts + 1 >= max_local_attempts) {
            check_rate_limit(pamh, user, dir, &config, 0); // Record failed attempt
            free(encoded);
            return PAM_AUTH_ERR;
        }
        
        // Show error message and continue to next attempt
        pam_info(pamh, "Incorrect PIN. Please try again.");
    }
    
    // Should not reach here, but just in case
    free(encoded);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,const char **argv) {
    (void)pamh;(void)flags;(void)argc;(void)argv;
    return PAM_IGNORE;
}
