#define _GNU_SOURCE
#include <argon2.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>

// Configuration structure (same as PAM module)
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

static void die(const char *msg) { perror(msg); exit(1); }

static void usage(const char *prog) {
    printf("Usage: %s <command> [username]\n", prog);
    printf("Commands:\n");
    printf("  enroll, set    Set a new PIN for the user\n");
    printf("  remove         Remove the PIN for the user\n");
    printf("  status         Show whether a PIN is set\n");
    printf("  unlock         Clear rate limiting/lockout for user\n");
    printf("  check          Check PIN storage configuration and permissions\n");
    printf("  config         Show current configuration\n");
    printf("  help           Show this help message\n");
    exit(0);
}

static char *get_username(int argc, char **argv) {
    if (argc >= 3 && argv[2] && *argv[2]) return strdup(argv[2]);

    char buf[128];
    fprintf(stderr, "Enter username: ");
    fflush(stderr);
    if (!fgets(buf, sizeof(buf), stdin)) return NULL;
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1]=='\n' || buf[len-1]=='\r')) buf[--len]=0;
    if (len==0) return NULL;
    return strdup(buf);
}

static char *get_pinlock_dir(const char *user, const pinlock_config_t *config) {
    static char dir[1024];

    if (config->pin_dir[0]) {
        int n = snprintf(dir, sizeof(dir), "%s", config->pin_dir);
        if (n < 0 || n >= (int)sizeof(dir)) return NULL;
        return dir;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) return NULL;
    int n = snprintf(dir, sizeof(dir), "%s/.pinlock", pw->pw_dir);
    if (n < 0 || n >= (int)sizeof(dir)) return NULL;
    return dir;
}

static int system_pin_dir_enabled(const pinlock_config_t *config) {
    return config->pin_dir[0] != '\0';
}

static int ensure_dir(const char *dir, const struct passwd *pw, int system_dir) {
    struct stat st;
    if (lstat(dir, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    if (errno == ENOENT) {
        if (mkdir(dir, 0700) != 0) return -1;
        if (!system_dir && pw && geteuid() == 0 && chown(dir, pw->pw_uid, pw->pw_gid) != 0) return -1;
        return 0;
    }
    return -1;
}

static int write_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n <= 0) return -1;
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_file_restrict(const char *dir, const char *path, const char *data, const struct passwd *pw, int system_dir) {
    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || n >= (int)sizeof(tmp)) return -1;

#ifdef O_NOFOLLOW
    int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600);
#else
    int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL, 0600);
#endif
    if (fd < 0) return -1;

    if (!system_dir && pw && geteuid() == 0 && fchown(fd, pw->pw_uid, pw->pw_gid) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }

    if (write_all(fd, data, strlen(data)) != 0 || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }

#ifdef O_DIRECTORY
    int dirfd = open(dir, O_RDONLY|O_DIRECTORY);
    if (dirfd >= 0) {
        fsync(dirfd);
        close(dirfd);
    }
#endif

    return 0;
}

static void noecho(int off) {
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &t) == 0) {
        if (off) t.c_lflag &= ~ECHO;
        else t.c_lflag |= ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    }
}

static char *prompt_hidden(const char *label) {
    fprintf(stderr, "%s", label); fflush(stderr);
    noecho(1);
    char *line = NULL; size_t cap=0;
    ssize_t n = getline(&line, &cap, stdin);
    noecho(0); fprintf(stderr, "\n");
    if (n <=0) { free(line); return NULL; }
    while(n>0 && (line[n-1]=='\n'||line[n-1]=='\r')) line[--n]=0;
    return line;
}

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

static void load_config_file(const char *path, pinlock_config_t *config) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        
        // Find the = sign
        char *eq = strchr(p, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        
        // Trim whitespace
        trim_right(key);
        while (isspace((unsigned char)*value)) value++;
        strip_inline_comment(value);
        trim_right(value);
        
        // Parse configuration values
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

static void load_config(const char *user, pinlock_config_t *config) {
    load_default_config(config);
    
    // Try system config first
    load_config_file("/etc/pinlock.conf", config);

    if (!config->allow_user_config) {
        validate_config(config);
        return;
    }

    // Try user config
    struct passwd *pw = getpwnam(user);
    if (pw) {
        char user_config[1024];
        int n = snprintf(user_config, sizeof(user_config), "%s/.pinlock/pinlock.conf", pw->pw_dir);
        if (n >= 0 && n < (int)sizeof(user_config)) load_config_file(user_config, config);
    }

    validate_config(config);
}

static int validate_pin(const char *pin, const pinlock_config_t *config) {
    if (!pin) return 0;
    
    size_t len = strlen(pin);
    if (len < (size_t)config->min_length || len > (size_t)config->max_length) {
        return 0;
    }
    
    if (config->require_digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)pin[i])) return 0;
        }
    }
    
    return 1;
}

static int check_pin_dir_security(const char *dir, const struct passwd *pw, const pinlock_config_t *config, int verbose) {
    struct stat st;
    if (lstat(dir, &st) != 0) {
        if (verbose) printf("PIN directory: missing (%s)\n", dir);
        return -1;
    }

    int issues = 0;
    if (!S_ISDIR(st.st_mode)) {
        if (verbose) printf("PIN directory: not a directory (%s)\n", dir);
        return 1;
    }

    if (system_pin_dir_enabled(config)) {
        if (st.st_uid != 0) {
            if (verbose) printf("PIN directory: unsafe owner uid %ld, expected root\n", (long)st.st_uid);
            issues = 1;
        }
    } else if (st.st_uid != 0 && (!pw || st.st_uid != pw->pw_uid)) {
        if (verbose) printf("PIN directory: unsafe owner uid %ld\n", (long)st.st_uid);
        issues = 1;
    }

    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        if (verbose) printf("PIN directory: unsafe mode %04o, expected no group/world permissions\n", st.st_mode & 07777);
        issues = 1;
    }

    if (verbose && !issues) printf("PIN directory: ok (%s, mode %04o)\n", dir, st.st_mode & 07777);
    return issues;
}

static int check_pin_file_security(const char *path, const struct passwd *pw, const pinlock_config_t *config, int verbose) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (verbose) printf("PIN file: missing (%s)\n", path);
        return -1;
    }

    int issues = 0;
    if (!S_ISREG(st.st_mode)) {
        if (verbose) printf("PIN file: not a regular file (%s)\n", path);
        return 1;
    }

    if (system_pin_dir_enabled(config)) {
        if (st.st_uid != 0) {
            if (verbose) printf("PIN file: unsafe owner uid %ld, expected root\n", (long)st.st_uid);
            issues = 1;
        }
    } else if (st.st_uid != 0 && (!pw || st.st_uid != pw->pw_uid)) {
        if (verbose) printf("PIN file: unsafe owner uid %ld\n", (long)st.st_uid);
        issues = 1;
    }

    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        if (verbose) printf("PIN file: unsafe mode %04o, expected no group/world permissions\n", st.st_mode & 07777);
        issues = 1;
    }

    if (verbose && !issues) printf("PIN file: ok (%s, mode %04o)\n", path, st.st_mode & 07777);
    return issues;
}

static int show_storage_check(const char *user, const char *dir, const char *path, const struct passwd *pw, const pinlock_config_t *config) {
    printf("Storage check for user '%s':\n", user);
    printf("  Mode: %s\n", system_pin_dir_enabled(config) ? "system" : "per-user");
    printf("  Directory: %s\n", dir);
    printf("  PIN file: %s\n", path);

    int dir_status = check_pin_dir_security(dir, pw, config, 1);
    int file_status = check_pin_file_security(path, pw, config, 1);

    char rl_path[1024];
    int n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if (n >= 0 && n < (int)sizeof(rl_path)) {
        printf("Rate limit file: %s\n", access(rl_path, F_OK) == 0 ? rl_path : "not present");
    }

    return dir_status == 1 || file_status == 1;
}

static void show_config(const char *user) {
    pinlock_config_t config;
    load_config(user, &config);
    
    printf("Configuration for user '%s':\n", user);
    printf("  PIN Storage:\n");
    printf("    Directory: %s\n", config.pin_dir[0] ? config.pin_dir : "~/.pinlock");

    printf("  PIN Requirements:\n");
    printf("    Minimum length: %d\n", config.min_length);
    printf("    Maximum length: %d\n", config.max_length);
    printf("    Digits only: %s\n", config.require_digits_only ? "yes" : "no");
    
    printf("  Rate Limiting:\n");
    printf("    Max attempts: %d\n", config.max_attempts);
    printf("    Rate limit window: %d seconds\n", config.rate_limit_window);
    printf("    Cooldown after rate limit: %d seconds\n", config.lockout_window);
    
    printf("  PIN Lockout:\n");
    printf("    Enabled: %s\n", config.enable_lockout ? "yes" : "no");
    printf("    Lockout duration: %d seconds\n", config.lockout_duration);
    
    printf("  Logging:\n");
    printf("    Log attempts: %s\n", config.log_attempts ? "yes" : "no");
    printf("    Log success: %s\n", config.log_success ? "yes" : "no");
    printf("    Log failures: %s\n", config.log_failures ? "yes" : "no");
    printf("    Debug: %s\n", config.debug ? "yes" : "no");
    printf("  Policy:\n");
    printf("    User config overrides: %s\n", config.allow_user_config ? "yes" : "no");
    printf("    PIN lockout fails auth: %s\n", config.lockout_fails_auth ? "yes" : "no");
}

static void unlock_user(const char *user, const char *dir) {
    char rl_path[1024];
    int n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
    if (n >= (int)sizeof(rl_path)) {
        printf("Error: path too long for user '%s'\n", user);
        return;
    }
    
    if (unlink(rl_path) == 0) {
        printf("Rate limiting/lockout cleared for user '%s'\n", user);
    } else {
        printf("No rate limiting data found for user '%s'\n", user);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) usage(argv[0]);

    const char *cmd = argv[1];
    if (strcmp(cmd, "help") == 0) usage(argv[0]);

    char *user = get_username(argc, argv);
    if (!user) die("No username provided");

    pinlock_config_t config;
    load_config(user, &config);

    if (!strcmp(cmd, "config")) {
        show_config(user);
        free(user);
        return 0;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) die("Cannot resolve user");

    char *dir = get_pinlock_dir(user, &config);
    if (!dir) die("Cannot resolve PIN directory");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s.pin", dir, user);
    if (n < 0 || n >= (int)sizeof(path)) die("Path too long");

    if (!strcmp(cmd, "check")) {
        int issues = show_storage_check(user, dir, path, pw, &config);
        free(user);
        return issues ? 1 : 0;
    }

    if (!strcmp(cmd, "status")) {
        printf("PIN directory: %s\n", dir);
        int file_status = check_pin_file_security(path, pw, &config, 0);
        if (file_status == 0 && access(path, R_OK)==0) {
            printf("PIN enrolled for %s\n", user);
            
            // Check if user is currently locked out
            char rl_path[1024];
            int rl_n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
            if (rl_n < (int)sizeof(rl_path) && access(rl_path, R_OK) == 0) {
                printf("Rate limiting data exists (check logs for lockout status)\n");
            }
        } else if (file_status == 1) {
            printf("PIN storage for %s has unsafe permissions or ownership\n", user);
        } else {
            printf("No PIN set for %s\n", user);
        }
        free(user); 
        return 0;
    }

    if (!strcmp(cmd, "unlock")) {
        unlock_user(user, dir);
        free(user);
        return 0;
    }

    if (!strcmp(cmd, "remove")) {
        unlink(path);  // ignore error
        
        // Also remove rate limiting data
        char rl_path[1024];
        int rl_n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
        if (rl_n < (int)sizeof(rl_path)) {
            unlink(rl_path);  // ignore error
        }
        
        printf("PIN and rate limiting data removed for user '%s'\n", user);
        free(user); 
        return 0;
    }

    if (!strcmp(cmd, "enroll") || !strcmp(cmd, "set")) {
        if (ensure_dir(dir, pw, system_pin_dir_enabled(&config)) != 0) die("Cannot create PIN directory");
        if (check_pin_dir_security(dir, pw, &config, 0) != 0) die("Unsafe PIN directory");

        char *p1 = prompt_hidden("Enter new PIN: ");
        if (!p1 || !*p1) { 
            fprintf(stderr, "No PIN entered.\n");
            free(p1); free(user); return 1; 
        }

        // Validate PIN according to configuration
        if (!validate_pin(p1, &config)) {
            fprintf(stderr, "PIN does not meet requirements:\n");
            fprintf(stderr, "  - Length: %d-%d characters\n", config.min_length, config.max_length);
            if (config.require_digits_only) {
                fprintf(stderr, "  - Must contain only digits (0-9)\n");
            }
            memset(p1, 0, strlen(p1));
            free(p1); free(user);
            return 1;
        }

        char *p2 = prompt_hidden("Confirm PIN: ");
        if (!p2 || strcmp(p1,p2)!=0) { 
            fprintf(stderr, "PINs do not match.\n");
            memset(p1, 0, strlen(p1));
            if (p2) memset(p2, 0, strlen(p2));
            free(p1); free(p2); free(user); return 1; 
        }

        unsigned char salt[16];
        int rnd = open("/dev/urandom", O_RDONLY);
        if (rnd<0 || read(rnd, salt, sizeof(salt))!=(ssize_t)sizeof(salt)) die("urandom");
        close(rnd);

        unsigned long t_cost=3, m_cost=1u<<16, parallel=1;
        size_t enc_len = argon2_encodedlen(t_cost, m_cost, parallel, sizeof(salt), 32, Argon2_id);
        char *encoded = malloc(enc_len);
        if (!encoded) die("malloc");

        int rc = argon2id_hash_encoded((uint32_t)t_cost,(uint32_t)m_cost,(uint32_t)parallel,
                                       p1, strlen(p1), salt, sizeof(salt), 32, encoded, enc_len);
        if (rc!=ARGON2_OK) { 
            fprintf(stderr, "Failed to hash PIN (argon2 error %d)\n", rc);
            memset(p1, 0, strlen(p1)); memset(p2, 0, strlen(p2));
            free(encoded); free(p1); free(p2); free(user); return 1; 
        }

        if (write_file_restrict(dir, path, encoded, pw, system_pin_dir_enabled(&config))!=0) die("write pin file");

        // Clear any existing rate limiting data on successful PIN change
        char rl_path[1024];
        int rl_n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
        if (rl_n < (int)sizeof(rl_path)) {
            unlink(rl_path);  // ignore error
        }

        printf("PIN successfully set for user '%s'\n", user);
        printf("Configuration applied:\n");
        printf("  - Length requirement: %d-%d characters\n", config.min_length, config.max_length);
        printf("  - Digits only: %s\n", config.require_digits_only ? "yes" : "no");
        printf("  - Rate limiting: %d attempts per %d seconds\n", config.max_attempts, config.rate_limit_window);
        printf("  - PIN lockout: %s\n", config.enable_lockout ? "enabled" : "disabled");

        memset(p1,0,strlen(p1)); memset(p2,0,strlen(p2));
        free(p1); free(p2); free(encoded); free(user);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    free(user);
    usage(argv[0]);
    return 2;
}
