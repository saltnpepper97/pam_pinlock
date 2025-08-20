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

static void die(const char *msg) { perror(msg); exit(1); }

static void usage(const char *prog) {
    printf("Usage: %s <command> [username]\n", prog);
    printf("Commands:\n");
    printf("  enroll, set    Set a new PIN for the user\n");
    printf("  remove         Remove the PIN for the user\n");
    printf("  status         Show whether a PIN is set\n");
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

int main(int argc, char **argv) {
    if (argc < 2) usage(argv[0]);

    const char *cmd = argv[1];
    if (strcmp(cmd, "help") == 0) usage(argv[0]);

    char *user = get_username(argc, argv);
    if (!user) die("No username provided");

    char *dir = get_pinlock_dir(user);
    if (!dir) die("Cannot resolve home directory");

    if (ensure_dir(dir) != 0) die("Cannot create ~/.pinlock");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s.pin", dir, user);
    if (n < 0 || n >= (int)sizeof(path)) die("Path too long");

    if (!strcmp(cmd, "status")) {
        if (access(path, R_OK)==0) printf("PIN enrolled for %s\n", user);
        else printf("No PIN set for %s\n", user);
        free(user); return 0;
    }

    if (!strcmp(cmd, "remove")) {
        unlink(path);  // ignore error
        free(user); return 0;
    }

    if (!strcmp(cmd, "enroll") || !strcmp(cmd, "set")) {
        char *p1 = prompt_hidden("Enter new PIN: ");
        if (!p1 || !*p1) { free(p1); free(user); return 1; }
        char *p2 = prompt_hidden("Confirm PIN: ");
        if (!p2 || strcmp(p1,p2)!=0) { free(p1); free(p2); free(user); return 1; }

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
        if (rc!=ARGON2_OK) { free(encoded); free(p1); free(p2); free(user); return 1; }

        if (write_file_restrict(path, encoded)!=0) die("write pin file");

        memset(p1,0,strlen(p1)); memset(p2,0,strlen(p2));
        free(p1); free(p2); free(encoded); free(user);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage(argv[0]);
    return 2;
}
