#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <argon2.h>
#include <syslog.h>
#include <pwd.h>

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

static int file_exists(const char *path) { struct stat st; return stat(path,&st)==0 && S_ISREG(st.st_mode); }

static int prompt_pin(pam_handle_t *pamh, const char *prompt, char **out_pin) {
    *out_pin=NULL;
    int r=pam_prompt(pamh,PAM_PROMPT_ECHO_OFF,out_pin,"%s",prompt?prompt:"PIN: ");
    return (r==PAM_SUCCESS && *out_pin)?PAM_SUCCESS:PAM_AUTH_ERR;
}

static void parse_args(int argc, const char **argv, const char **prompt, int *debug) {
    *prompt="PIN (this machine): ";
    *debug=0;
    for(int i=0;i<argc;i++) {
        if(strncmp(argv[i],"prompt=",7)==0) *prompt=argv[i]+7;
        else if(strcmp(argv[i],"debug")==0) *debug=1;
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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags;
    const char *prompt; int debug;
    parse_args(argc, argv, &prompt, &debug);

    const char *user=NULL;
    int pret=pam_get_user(pamh,&user,NULL);

    if(pret!=PAM_SUCCESS || !user || !*user) {
        uid_t uid=getuid();
        struct passwd *pw=getpwuid(uid);
        if(!pw) { pam_syslog(pamh,LOG_ERR,"pinlock: cannot resolve user"); return PAM_AUTH_ERR; }
        user=pw->pw_name;
        if(debug) pam_syslog(pamh,LOG_DEBUG,"pinlock: fallback user '%s'",user);
    }

    const char* dir=get_pinlock_dir(user);
    if(!dir) { pam_syslog(pamh,LOG_ERR,"pinlock: cannot resolve home"); return PAM_AUTH_ERR; }

    char path[1024];
    int n = snprintf(path,sizeof(path),"%s/%s.pin",dir,user);
    if(n < 0 || n >= (int)sizeof(path)) {
        pam_syslog(pamh,LOG_ERR,"pinlock: path too long for user %s",user);
        return PAM_AUTH_ERR;
    }

    if(!file_exists(path)) {
        if(debug) pam_syslog(pamh,LOG_DEBUG,"pinlock: no PIN for %s -> IGNORE",user);
        return PAM_IGNORE;
    }

    char *encoded=NULL;
    if(read_first_line(path,&encoded)!=0 || !encoded || !*encoded) { free(encoded); return PAM_AUTH_ERR; }

    char *pin=NULL;
    int pr=prompt_pin(pamh,prompt,&pin);
    if(pr!=PAM_SUCCESS) { free(encoded); return PAM_AUTH_ERR; }

    int v=argon2id_verify(encoded,pin,strlen(pin));
    memwipe(pin,strlen(pin));
    free(pin); free(encoded);

    if(v==ARGON2_OK) { if(debug) pam_syslog(pamh,LOG_DEBUG,"pinlock: OK for %s",user); return PAM_SUCCESS; }
    if(debug) pam_syslog(pamh,LOG_DEBUG,"pinlock: verify failed (%d) for %s",v,user);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,const char **argv) {
    (void)pamh;(void)flags;(void)argc;(void)argv;
    return PAM_IGNORE;
}
