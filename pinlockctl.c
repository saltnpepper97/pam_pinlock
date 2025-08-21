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

static void die(const char *msg) { perror(msg); exit(1); }

static void usage(const char *prog) {
    printf("Usage: %s <command> [username]\n", prog);
    printf("Commands:\n");
    printf("  enroll, set    Set a new PIN for the user\n");
    printf("  remove         Remove the PIN for the user\n");
    printf("  status         Show whether a PIN is set\n");
    printf("  unlock         Clear rate limiting/lockout for user\n");
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

static char *get_pinlock_dir(const char *user) {
    struct passwd *pw = getpwnam(user);
    if (!pw) return NULL;
    static char dir[1024];
    int n = snprintf(dir, sizeof(dir), "%s/.pinlock", pw->pw_dir);
    if (n < 0 || n >= (int)sizeof(dir)) return NULL;
    return dir;
}

static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) return 0;
    if (errno == ENOENT) return mkdir(dir, 0700);
    return -1;
}

static int write_file_restrict(const char *path, const char *data) {
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    if (n < 0 || (size_t)n != strlen(data)) { close(fd); return -1; }
    close(fd);
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

static void show_config(const char *user) {
    pinlock_config_t config;
    load_config(user, &config);
    
    printf("Configuration for user '%s':\n", user);
    printf("  PIN Requirements:\n");
    printf("    Minimum length: %d\n", config.min_length);
    printf("    Maximum length: %d\n", config.max_length);
    printf("    Digits only: %s\n", config.require_digits_only ? "yes" : "no");
    
    printf("  Rate Limiting:\n");
    printf("    Max attempts: %d\n", config.max_attempts);
    printf("    Rate limit window: %d seconds\n", config.rate_limit_window);
    
    printf("  Account Lockout:\n");
    printf("    Enabled: %s\n", config.enable_lockout ? "yes" : "no");
    printf("    Lockout duration: %d seconds\n", config.lockout_duration);
    printf("    Max lockout attempts: %d\n", config.max_lockout_attempts);
    
    printf("  Logging:\n");
    printf("    Log attempts: %s\n", config.log_attempts ? "yes" : "no");
    printf("    Log success: %s\n", config.log_success ? "yes" : "no");
    printf("    Log failures: %s\n", config.log_failures ? "yes" : "no");
    printf("    Debug: %s\n", config.debug ? "yes" : "no");
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

    if (!strcmp(cmd, "config")) {
        show_config(user);
        free(user);
        return 0;
    }

    char *dir = get_pinlock_dir(user);
    if (!dir) die("Cannot resolve home directory");

    if (ensure_dir(dir) != 0) die("Cannot create ~/.pinlock");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s.pin", dir, user);
    if (n < 0 || n >= (int)sizeof(path)) die("Path too long");

    if (!strcmp(cmd, "status")) {
        if (access(path, R_OK)==0) {
            printf("PIN enrolled for %s\n", user);
            
            // Check if user is currently locked out
            char rl_path[1024];
            int rl_n = snprintf(rl_path, sizeof(rl_path), "%s/%s.ratelimit", dir, user);
            if (rl_n < (int)sizeof(rl_path) && access(rl_path, R_OK) == 0) {
                printf("Rate limiting data exists (check logs for lockout status)\n");
            }
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
        // Load config to check PIN requirements
        pinlock_config_t config;
        load_config(user, &config);
        
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
            free(p1); free(user);
            return 1;
        }

        char *p2 = prompt_hidden("Confirm PIN: ");
        if (!p2 || strcmp(p1,p2)!=0) { 
            fprintf(stderr, "PINs do not match.\n");
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
            free(encoded); free(p1); free(p2); free(user); return 1; 
        }

        if (write_file_restrict(path, encoded)!=0) die("write pin file");

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
        printf("  - Account lockout: %s\n", config.enable_lockout ? "enabled" : "disabled");

        memset(p1,0,strlen(p1)); memset(p2,0,strlen(p2));
        free(p1); free(p2); free(encoded); free(user);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    free(user);
    usage(argv[0]);
    return 2;
}

