/* EnvScope's root timezone worker. Fixed system commands, no user code or RPC.
 * Compile-time fixture paths are available only in a separate acceptance build.
 */
#define _DARWIN_C_SOURCE
#include <CoreFoundation/CoreFoundation.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#ifndef ENVSCOPE_TZ_ROOT
#define ENVSCOPE_TZ_ROOT "/Library/PrivilegedHelperTools/io.qudadd.envscope.timezone"
#define ENVSCOPE_TZ_LOCALTIME "/etc/localtime"
#define ENVSCOPE_TZ_ZONES "/var/db/timezone/zoneinfo"
#define ENVSCOPE_TZ_SETTER "/usr/sbin/systemsetup"
#define ENVSCOPE_TZ_FIXTURE 0
#endif
#ifndef ENVSCOPE_RELEASE
#define ENVSCOPE_RELEASE "development"
#endif

static volatile sig_atomic_t stopped = 0;
static int initial_mode = 0;
static void stop_now(int signal_number) { (void)signal_number; stopped = 1; }

static int legacy_clear(int root) {
#if ENVSCOPE_TZ_FIXTURE
    struct stat item; return fstatat(root,"legacy-conflict",&item,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;
#else
    (void)root;struct stat item;
    if(lstat("/Library/LaunchDaemons/local.tz-watchdog.plist",&item)==0||errno!=ENOENT)return 0;
    int fds[2];if(pipe(fds))return 0;pid_t child=fork();
    if(child<0){close(fds[0]);close(fds[1]);return 0;}
    if(!child){close(fds[0]);dup2(fds[1],1);dup2(fds[1],2);close(fds[1]);
        char *const args[]={"/bin/launchctl","print","system/local.tz-watchdog",NULL};
        char *const env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};execve(args[0],args,env);_exit(127);}
    close(fds[1]);int flags=fcntl(fds[0],F_GETFL);int error=flags<0||fcntl(fds[0],F_SETFL,flags|O_NONBLOCK)<0;
    char buffer[8193];size_t used=0;int code=0,finished=0;
    for(int i=0;i<250&&!error;i++){
        ssize_t got;
        while(used<sizeof(buffer)-1&&(got=read(fds[0],buffer+used,sizeof(buffer)-1-used))>0)used+=(size_t)got;
        if(used==sizeof(buffer)-1){error=1;break;}
        pid_t result=waitpid(child,&code,WNOHANG);
        if(result==child){finished=1;while(used<sizeof(buffer)-1&&(got=read(fds[0],buffer+used,sizeof(buffer)-1-used))>0)used+=(size_t)got;break;}
        if(result<0&&errno!=EINTR){finished=1;error=1;break;}usleep(20000);
    }
    close(fds[0]);buffer[used]=0;
    if(!finished){kill(child,SIGKILL);while(waitpid(child,&code,0)<0&&errno==EINTR){}}
    return finished&&!error&&used<sizeof(buffer)-1&&WIFEXITED(code)&&WEXITSTATUS(code)!=0&&strcasestr(buffer,"could not find service")!=NULL;
#endif
}

static int protected_stat(int fd, int directory) {
    struct stat st;
    return fstat(fd, &st) == 0 && st.st_uid == 0 && !(st.st_mode & 0022)
        && (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode) && st.st_nlink == 1);
}

static CFMutableDictionaryRef read_plist(int root, const char *name, int optional) {
    int fd = openat(root, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return optional && errno == ENOENT ? CFDictionaryCreateMutable(NULL,0,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks) : NULL;
    struct stat st;
    if (!protected_stat(fd,0) || fstat(fd,&st) || st.st_size < 1 || st.st_size > 65536) { close(fd); return NULL; }
    UInt8 *bytes = malloc((size_t)st.st_size);
    if (!bytes) { close(fd); return NULL; }
    size_t used = 0;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, bytes+used, (size_t)st.st_size-used);
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    CFDataRef data = CFDataCreate(NULL,bytes,(CFIndex)used); free(bytes);
    CFPropertyListRef value = used == (size_t)st.st_size ? CFPropertyListCreateWithData(NULL,data,
        kCFPropertyListMutableContainersAndLeaves,NULL,NULL) : NULL;
    CFRelease(data);
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) { if(value)CFRelease(value); return NULL; }
    return (CFMutableDictionaryRef)value;
}

static int write_all(int fd, const void *bytes, size_t size) {
    const char *p = bytes;
    while (size) {
        ssize_t n = write(fd,p,size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        p += n; size -= (size_t)n;
    }
    return 1;
}

static int save_plist(int root, const char *name, CFDictionaryRef value, mode_t mode) {
    CFDataRef data = CFPropertyListCreateData(NULL,value,kCFPropertyListXMLFormat_v1_0,0,NULL);
    if (!data) return 0;
    char stage[100]; snprintf(stage,sizeof(stage),".%s.%d.%u",name,getpid(),arc4random());
    int fd = openat(root,stage,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode);
    int ok = fd >= 0 && protected_stat(fd,0) && fchmod(fd,mode) == 0
        && write_all(fd,CFDataGetBytePtr(data),(size_t)CFDataGetLength(data)) && fsync(fd) == 0;
    if (fd >= 0) close(fd);
    if (ok) ok = renameat(root,stage,root,name) == 0 && fsync(root) == 0;
    if (!ok) unlinkat(root,stage,0);
    CFRelease(data); return ok;
}

static void put_text(CFMutableDictionaryRef d, CFStringRef key, const char *text) {
    CFStringRef s = CFStringCreateWithCString(NULL,text,kCFStringEncodingUTF8);
    CFDictionarySetValue(d,key,s); CFRelease(s);
}
static void put_number(CFMutableDictionaryRef d, CFStringRef key, long long n) {
    CFNumberRef v = CFNumberCreate(NULL,kCFNumberLongLongType,&n);
    CFDictionarySetValue(d,key,v); CFRelease(v);
}
static int number(CFDictionaryRef d, CFStringRef key, long long *out) {
    CFTypeRef v = CFDictionaryGetValue(d,key);
    return v && CFGetTypeID(v) == CFNumberGetTypeID() && !CFNumberIsFloatType(v)
        && CFNumberGetValue(v,kCFNumberLongLongType,out);
}
static int text(CFDictionaryRef d, CFStringRef key, char *out, size_t size) {
    CFTypeRef v = CFDictionaryGetValue(d,key);
    return v && CFGetTypeID(v) == CFStringGetTypeID() && CFStringGetCString(v,out,(CFIndex)size,kCFStringEncodingUTF8);
}

static int valid_zone(const char *zone) {
    size_t n = strlen(zone);
    if (!n || n > 100 || zone[0] == '/' || strstr(zone,"..")) return 0;
    for (size_t i=0;i<n;i++) {
        unsigned char c=(unsigned char)zone[i];
        if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='/'||c=='_'||c=='+'||c=='-')) return 0;
    }
    return 1;
}

static int canonical_zone(const char *zone, char result[4096]) {
    char input[4096];
    if (!valid_zone(zone) || snprintf(input,sizeof(input),"%s/%s",ENVSCOPE_TZ_ZONES,zone) >= (int)sizeof(input)) return 0;
    return realpath(input,result) != NULL;
}

static int current_zone(char result[110]) {
    char path[4096], base[4096];
    if (!realpath(ENVSCOPE_TZ_LOCALTIME,path) || !realpath(ENVSCOPE_TZ_ZONES,base)) return 0;
    size_t n=strlen(base);
    if (strncmp(path,base,n) || path[n]!='/' || !valid_zone(path+n+1)) return 0;
    snprintf(result,110,"%s",path+n+1); return 1;
}

static int equal_zone(const char *a, const char *b) {
    char x[4096], y[4096];
    return canonical_zone(a,x) && canonical_zone(b,y) && !strcmp(x,y);
}

static int event(int root, const char *phase, const char *before, const char *target, long long now) {
    time_t stamp=(time_t)now;struct tm utc;gmtime_r(&stamp,&utc);
    char date[32],name[90],line[1024];strftime(date,sizeof(date),"%Y-%m-%d",&utc);
    snprintf(name,sizeof(name),"events-%s.private.jsonl",date);
    int fd=openat(root,name,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0)return 0;
    int n=snprintf(line,sizeof(line),"{\"at_epoch\":%lld,\"kind\":\"timezone_guard\",\"phase\":\"%s\",\"before\":\"%s\",\"target\":\"%s\",\"fixture\":%s}\n",
        now,phase,before,target,ENVSCOPE_TZ_FIXTURE?"true":"false");
    int ok=protected_stat(fd,0)&&fchmod(fd,0644)==0&&n>0&&n<(int)sizeof(line)&&write_all(fd,line,(size_t)n)&&fsync(fd)==0;
    close(fd);return ok;
}

static int set_zone(const char *target) {
    pid_t child=fork();
    if(child<0)return 0;
    if(child==0) {
        // systemsetup creates public system timezone links. Do not propagate
        // the installer's private-file umask into that OS command.
        umask(0022);
        int null=open("/dev/null",O_RDWR);
        if(null>=0){dup2(null,0);dup2(null,1);dup2(null,2);if(null>2)close(null);}
        char *const args[]={(char*)ENVSCOPE_TZ_SETTER,"-settimezone",(char*)target,NULL};
        char *const env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};
        execve(ENVSCOPE_TZ_SETTER,args,env);_exit(127);
    }
    struct timespec start,current;clock_gettime(CLOCK_MONOTONIC,&start);
    int status=0;
    for(;;) {
        pid_t done=waitpid(child,&status,WNOHANG);
        if(done==child)return WIFEXITED(status)&&WEXITSTATUS(status)==0;
        if(done<0&&errno!=EINTR)return 0;
        clock_gettime(CLOCK_MONOTONIC,&current);
        if(stopped||current.tv_sec-start.tv_sec>=20)break;
        usleep(100000);
    }
    // Until waitpid reaps this child its PID cannot be reused for another task.
    kill(child,SIGTERM);usleep(100000);
    if(waitpid(child,&status,WNOHANG)==0){kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}}
    return 0;
}

static int publish_status(int root, CFMutableDictionaryRef state, const char *phase,
                          const char *observed, const char *target, long long now, int count) {
    if(!save_plist(root,"state.plist",state,0600))return 0;
    CFMutableDictionaryRef status=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    put_number(status,CFSTR("format"),1);put_number(status,CFSTR("guard_policy"),2);put_number(status,CFSTR("at_epoch"),now);put_number(status,CFSTR("attempt_count"),count);
    put_text(status,CFSTR("state"),phase);put_text(status,CFSTR("observed"),observed);put_text(status,CFSTR("target"),target);
    put_text(status,CFSTR("release"),ENVSCOPE_RELEASE);
    CFDictionarySetValue(status,CFSTR("fixture"),ENVSCOPE_TZ_FIXTURE?kCFBooleanTrue:kCFBooleanFalse);
    CFDictionarySetValue(status,CFSTR("initial"),initial_mode?kCFBooleanTrue:kCFBooleanFalse);
    int ok=save_plist(root,"status.plist",status,0644);CFRelease(status);return ok;
}

int main(int argc, char **argv) {
    if(argc==2&&!strcmp(argv[1],"--version")) {
        printf("{\"format\":1,\"release\":\"%s\",\"fixture\":%s}\n",ENVSCOPE_RELEASE,ENVSCOPE_TZ_FIXTURE?"true":"false");return 0;
    }
    if(getuid()!=0||geteuid()!=0)return 77;
    if(argc==3&&(!strcmp(argv[1],"--check-zone")||!strcmp(argv[1],"--restore-zone"))) {
        char observed[110],canonical[4096];
        if(!canonical_zone(argv[2],canonical)||!current_zone(observed))return 78;
        if(!strcmp(argv[1],"--check-zone"))return equal_zone(observed,argv[2])?0:79;
        if(!equal_zone(observed,argv[2])&&!set_zone(argv[2]))return 74;
        return current_zone(observed)&&equal_zone(observed,argv[2])?0:74;
    }
    int probe=argc==2&&!strcmp(argv[1],"--probe");
    int initial=argc==2&&!strcmp(argv[1],"--initial-apply");
    int lifecycle=argc==2&&!strcmp(argv[1],"--lifecycle");
    initial_mode=initial;
    if(argc!=2||(!probe&&!initial&&!lifecycle&&strcmp(argv[1],"--once")))return 77;
    int root=open(ENVSCOPE_TZ_ROOT,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0||!protected_stat(root,1))return 78;
    if(lifecycle) {
        // Root-only installer utility. The application has already obtained
        // administrator authorization for the concrete stdin script. Keep the
        // OS lock across exec, including interrupted installer recovery.
        int lease=openat(root,".lifecycle.lock",O_RDWR|O_CREAT|O_NOFOLLOW,0600);
        if(lease<0||!protected_stat(lease,0)||flock(lease,LOCK_EX|LOCK_NB))return 75;
        char *const args[]={"/bin/sh","-s",NULL};
        char *const env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C","HOME=/var/root",NULL};
        execve("/bin/sh",args,env);return 127;
    }
    struct stat transaction;
    if(!probe&&!initial&&fstatat(root,"pending",&transaction,AT_SYMLINK_NOFOLLOW)==0)return 75;
    int lock=openat(root,".worker.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lock<0||!protected_stat(lock,0)||flock(lock,LOCK_EX|LOCK_NB))return 75;
    CFMutableDictionaryRef config=read_plist(root,"baseline.plist",0);
    long long format=0,owner=-1;char target[110],original[110],observed[110],canonical[4096];
    if(!config||!number(config,CFSTR("format"),&format)||format!=1||!number(config,CFSTR("owner_uid"),&owner)||owner<0
        ||!text(config,CFSTR("target"),target,sizeof(target))||!text(config,CFSTR("original"),original,sizeof(original))
        ||!canonical_zone(target,canonical)||!valid_zone(original)||!current_zone(observed))return 78;
    CFRelease(config);
    if(probe){printf("{\"target\":\"%s\",\"observed\":\"%s\",\"fixture\":%s}\n",target,observed,ENVSCOPE_TZ_FIXTURE?"true":"false");return 0;}
    struct sigaction action;memset(&action,0,sizeof(action));action.sa_handler=stop_now;sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);
    CFMutableDictionaryRef state=read_plist(root,"state.plist",1);
    if(!state)return 78;
    CFTypeRef raw=CFDictionaryGetValue(state,CFSTR("attempts"));
    if(raw&&CFGetTypeID(raw)!=CFArrayGetTypeID())return 78;
    CFArrayRef attempts=raw;long long now=(long long)time(NULL),recent[3],last=0;int count=0;
    if(attempts) {
        if(CFArrayGetCount(attempts)>3)return 78;
        for(CFIndex i=0;i<CFArrayGetCount(attempts);i++) {
            CFTypeRef v=CFArrayGetValueAtIndex(attempts,i);long long stamp=0;
            if(CFGetTypeID(v)!=CFNumberGetTypeID()||CFNumberIsFloatType(v)||!CFNumberGetValue(v,kCFNumberLongLongType,&stamp)||stamp<0||stamp>now) {
                publish_status(root,state,"clock_attention",observed,target,now,0);return 0;
            }
            if(now-stamp<86400){recent[count++]=stamp;if(stamp>last)last=stamp;}
        }
    }
    CFTypeRef pending=CFDictionaryGetValue(state,CFSTR("pending"));
    if(pending&&CFGetTypeID(pending)!=CFBooleanGetTypeID())return 78;
    const char *phase=!legacy_clear(root)?"legacy_conflict":pending==kCFBooleanTrue?"interrupted":equal_zone(observed,target)?"healthy":count>=3?"paused":last&&now-last<300?"cooldown":NULL;
    if(phase&&!strcmp(phase,"legacy_conflict")){
        CFMutableDictionaryRef previous=read_plist(root,"status.plist",1);char old[60]="";
        if(!previous)return 78;int same=text(previous,CFSTR("state"),old,sizeof(old))&&!strcmp(old,phase);CFRelease(previous);
        if(!same&&!event(root,phase,observed,target,now))return 74;
    }
    if(phase){int ok=publish_status(root,state,phase,observed,target,now,count);CFRelease(state);close(lock);close(root);return ok?0:74;}
    if(!event(root,"drift",observed,target,now))return 74;
    CFMutableArrayRef next=CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);
    for(int i=0;i<count;i++){CFNumberRef n=CFNumberCreate(NULL,kCFNumberLongLongType,&recent[i]);CFArrayAppendValue(next,n);CFRelease(n);}
    CFNumberRef n=CFNumberCreate(NULL,kCFNumberLongLongType,&now);CFArrayAppendValue(next,n);CFRelease(n);
    CFDictionarySetValue(state,CFSTR("attempts"),next);CFRelease(next);
    CFDictionarySetValue(state,CFSTR("pending"),kCFBooleanTrue);
    if(!publish_status(root,state,"repairing",observed,target,now,count+1))return 74;
    int written=set_zone(target);char after[110];
    int readable=current_zone(after);
    if(!readable)strcpy(after,"unknown");
    phase=stopped?"interrupted":written&&readable&&equal_zone(after,target)?"restored":"repair_failed";
    if(!event(root,phase,after,target,now))return 74;
    CFDictionarySetValue(state,CFSTR("pending"),stopped?kCFBooleanTrue:kCFBooleanFalse);
    int ok=publish_status(root,state,phase,after,target,(long long)time(NULL),count+1);
    CFRelease(state);close(lock);close(root);return ok?0:74;
}
