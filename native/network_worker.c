/* One-shot network transactions. No daemon, network listener or user code.
 * A separately compiled fixture backend never changes SystemConfiguration.
 */
#define _DARWIN_C_SOURCE
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
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

#ifndef ENVSCOPE_NET_ROOT
#define ENVSCOPE_NET_ROOT "/Library/PrivilegedHelperTools/io.qudadd.envscope.network"
#define ENVSCOPE_NET_FIXTURE 0
#endif
#ifndef ENVSCOPE_RELEASE
#define ENVSCOPE_RELEASE "development"
#endif
#define LIMIT (2*1024*1024)
static volatile sig_atomic_t stopped=0;
static void stop_now(int sig){(void)sig;stopped=1;}
static CFMutableDictionaryRef dict(void){return CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);}
static int protected_fd(int fd,int directory){struct stat s;return !fstat(fd,&s)&&s.st_uid==0&&!(s.st_mode&0022)&&
    (directory?S_ISDIR(s.st_mode):S_ISREG(s.st_mode)&&s.st_nlink==1);}
static void text(CFMutableDictionaryRef d,CFStringRef k,const char *v){CFStringRef s=CFStringCreateWithCString(NULL,v,kCFStringEncodingUTF8);CFDictionarySetValue(d,k,s);CFRelease(s);}
static void number(CFMutableDictionaryRef d,CFStringRef k,long long n){CFNumberRef v=CFNumberCreate(NULL,kCFNumberLongLongType,&n);CFDictionarySetValue(d,k,v);CFRelease(v);}
static int get_number(CFDictionaryRef d,CFStringRef k,long long *n){CFTypeRef v=CFDictionaryGetValue(d,k);return v&&CFGetTypeID(v)==CFNumberGetTypeID()&&!CFNumberIsFloatType(v)&&CFNumberGetValue(v,kCFNumberLongLongType,n);}
static int get_text(CFDictionaryRef d,CFStringRef k,char *v,size_t size){CFTypeRef s=CFDictionaryGetValue(d,k);return s&&CFGetTypeID(s)==CFStringGetTypeID()&&CFStringGetCString(s,v,(CFIndex)size,kCFStringEncodingUTF8);}
static int is_dict(CFTypeRef v){return v&&CFGetTypeID(v)==CFDictionaryGetTypeID();}
static int is_array(CFTypeRef v){return v&&CFGetTypeID(v)==CFArrayGetTypeID();}
static int is_bool(CFTypeRef v){return v&&CFGetTypeID(v)==CFBooleanGetTypeID();}
static int write_all(int fd,const void *bytes,size_t size){const char *p=bytes;while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return 0;p+=n;size-=(size_t)n;}return 1;}
static CFMutableDictionaryRef read_plist_fd(int fd){
    UInt8 *bytes=malloc(LIMIT+1);if(!bytes)return NULL;size_t n=0;
    while(n<LIMIT+1){ssize_t got=read(fd,bytes+n,LIMIT+1-n);if(got<0&&errno==EINTR)continue;if(got<=0)break;n+=(size_t)got;}
    CFDataRef data=CFDataCreate(NULL,bytes,(CFIndex)n);free(bytes);
    CFPropertyListRef v=n&&n<=LIMIT?CFPropertyListCreateWithData(NULL,data,kCFPropertyListMutableContainersAndLeaves,NULL,NULL):NULL;
    CFRelease(data);if(!is_dict(v)){if(v)CFRelease(v);return NULL;}return (CFMutableDictionaryRef)v;
}
static CFMutableDictionaryRef read_plist(int root,const char *name,int optional){
    int fd=openat(root,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return optional&&errno==ENOENT?dict():NULL;
    CFMutableDictionaryRef v=protected_fd(fd,0)?read_plist_fd(fd):NULL;close(fd);return v;
}
static int save(int root,const char *name,CFDictionaryRef value,mode_t mode){
    CFDataRef data=CFPropertyListCreateData(NULL,value,kCFPropertyListXMLFormat_v1_0,0,NULL);if(!data)return 0;
    char stage[120];snprintf(stage,sizeof(stage),".%s.%d.%u",name,getpid(),arc4random());
    int fd=openat(root,stage,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode);
    int ok=fd>=0&&protected_fd(fd,0)&&!fchmod(fd,mode)&&write_all(fd,CFDataGetBytePtr(data),(size_t)CFDataGetLength(data))&&!fsync(fd);
    if(fd>=0)close(fd);if(ok)ok=!renameat(root,stage,root,name)&&!fsync(root);if(!ok)unlinkat(root,stage,0);CFRelease(data);return ok;
}
static int emit(CFDictionaryRef value){CFDataRef d=CFPropertyListCreateData(NULL,value,kCFPropertyListXMLFormat_v1_0,0,NULL);if(!d)return 0;
    int ok=write_all(STDOUT_FILENO,CFDataGetBytePtr(d),(size_t)CFDataGetLength(d));CFRelease(d);return ok;}
static int valid_id(const char *s,int uuid){size_t n=strlen(s);if(n!=(uuid?36:32))return 0;
    for(size_t i=0;i<n;i++){if(uuid&&(i==8||i==13||i==18||i==23)){if(s[i]!='-')return 0;}
        else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')||(s[i]>='A'&&s[i]<='F')))return 0;}return 1;}
#if !ENVSCOPE_NET_FIXTURE
static CFMutableArrayRef array(void){return CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);}
static CFMutableDictionaryRef normal_config(CFDictionaryRef config){CFMutableDictionaryRef d=config?CFDictionaryCreateMutableCopy(NULL,0,config):dict();
    CFDictionaryRemoveValue(d,CFSTR("__INACTIVE__"));return d;}
#endif
static int valid_rows(CFArrayRef rows){
    if(!is_array(rows)||CFArrayGetCount(rows)>256)return 0;
    for(CFIndex i=0;i<CFArrayGetCount(rows);i++){
        CFDictionaryRef r=CFArrayGetValueAtIndex(rows,i);char id[40];
        if(!is_dict(r)||!get_text(r,CFSTR("id"),id,sizeof(id))||!valid_id(id,1)||
           !is_bool(CFDictionaryGetValue(r,CFSTR("ipv6_enabled")))||!is_dict(CFDictionaryGetValue(r,CFSTR("config"))))return 0;
        for(CFIndex j=0;j<i;j++)if(CFEqual(CFDictionaryGetValue(r,CFSTR("id")),CFDictionaryGetValue(CFArrayGetValueAtIndex(rows,j),CFSTR("id"))))return 0;
    }return 1;
}
static CFDictionaryRef find_row(CFArrayRef rows,CFStringRef id){for(CFIndex i=0;i<CFArrayGetCount(rows);i++){
    CFDictionaryRef r=CFArrayGetValueAtIndex(rows,i);if(CFEqual(CFDictionaryGetValue(r,CFSTR("id")),id))return r;}return NULL;}

#if ENVSCOPE_NET_FIXTURE
typedef struct{int root;int opened;CFMutableDictionaryRef data;} Backend;
static int backend_open(Backend *b,int write){(void)write;b->root=open(ENVSCOPE_NET_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(b->root<0)return 0;b->opened=1;b->data=read_plist(b->root,"fixture.plist",0);return b->data&&valid_rows(CFDictionaryGetValue(b->data,CFSTR("adapters")));}
static CFArrayRef backend_rows(Backend *b){return CFArrayCreateCopy(NULL,CFDictionaryGetValue(b->data,CFSTR("adapters")));}
static int backend_set(Backend *b,CFStringRef id,Boolean enabled){CFMutableDictionaryRef r=(CFMutableDictionaryRef)find_row(CFDictionaryGetValue(b->data,CFSTR("adapters")),id);
    if(!r||faccessat(b->root,"fail-set",F_OK,AT_SYMLINK_NOFOLLOW)==0)return 0;CFDictionarySetValue(r,CFSTR("ipv6_enabled"),enabled?kCFBooleanTrue:kCFBooleanFalse);return 1;}
static int backend_commit(Backend *b){
    int ok=faccessat(b->root,"fail-commit",F_OK,AT_SYMLINK_NOFOLLOW)!=0&&save(b->root,"fixture.plist",b->data,0644);
    if(ok&&faccessat(b->root,"interrupt-after-commit",F_OK,AT_SYMLINK_NOFOLLOW)==0)_exit(137);
    return ok;
}
static void backend_close(Backend *b){if(b->data){CFRelease(b->data);b->data=NULL;}if(b->opened){close(b->root);b->opened=0;}}
static int flush_dns(void){int root=open(ENVSCOPE_NET_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(root<0)return 0;
    int ok=faccessat(root,"fail-dns",F_OK,AT_SYMLINK_NOFOLLOW)!=0;
    if(ok){CFMutableDictionaryRef d=dict();text(d,CFSTR("state"),"flushed");ok=save(root,"fixture-dns.plist",d,0644);CFRelease(d);}close(root);return ok;}
#else
typedef struct{SCPreferencesRef prefs;int locked;} Backend;
static int backend_open(Backend *b,int write){b->prefs=SCPreferencesCreate(NULL,CFSTR("EnvScope.Network"),NULL);b->locked=0;
    if(!b->prefs)return 0;if(write){if(!SCPreferencesLock(b->prefs,FALSE))return 0;b->locked=1;}return 1;}
static CFArrayRef backend_rows(Backend *b){
    CFArrayRef services=SCNetworkServiceCopyAll(b->prefs);if(!services)return NULL;CFMutableArrayRef rows=array();
    SCDynamicStoreRef store=SCDynamicStoreCreate(NULL,CFSTR("EnvScope.Network.Read"),NULL,NULL);
    for(CFIndex i=0;i<CFArrayGetCount(services);i++){
        SCNetworkServiceRef service=(SCNetworkServiceRef)CFArrayGetValueAtIndex(services,i);
        SCNetworkProtocolRef p=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeIPv6);if(!p)continue;
        CFStringRef id=SCNetworkServiceGetServiceID(service),name=SCNetworkServiceGetName(service);
        CFMutableDictionaryRef row=dict(),config=normal_config(SCNetworkProtocolGetConfiguration(p));
        CFDictionarySetValue(row,CFSTR("id"),id);CFDictionarySetValue(row,CFSTR("name"),name?name:CFSTR("Network service"));
        CFDictionarySetValue(row,CFSTR("config"),config);CFRelease(config);
        CFDictionarySetValue(row,CFSTR("ipv6_enabled"),SCNetworkProtocolGetEnabled(p)?kCFBooleanTrue:kCFBooleanFalse);
        int active=0;
        for(int family=4;store&&family<=6;family+=2){CFStringRef key=CFStringCreateWithFormat(NULL,NULL,CFSTR("State:/Network/Service/%@/IPv%d"),id,family);
            CFPropertyListRef state=SCDynamicStoreCopyValue(store,key);CFRelease(key);if(is_dict(state)&&CFDictionaryGetCount(state))active=1;if(state)CFRelease(state);}
        CFDictionarySetValue(row,CFSTR("active"),active&&SCNetworkServiceGetEnabled(service)?kCFBooleanTrue:kCFBooleanFalse);
        CFArrayAppendValue(rows,row);CFRelease(row);CFRelease(p);
    }
    if(store)CFRelease(store);CFRelease(services);return rows;
}
static int backend_set(Backend *b,CFStringRef id,Boolean enabled){SCNetworkServiceRef s=SCNetworkServiceCopy(b->prefs,id);if(!s)return 0;
    SCNetworkProtocolRef p=SCNetworkServiceCopyProtocol(s,kSCNetworkProtocolTypeIPv6);int ok=p&&SCNetworkProtocolSetEnabled(p,enabled);
    if(p)CFRelease(p);CFRelease(s);return ok;}
static int backend_commit(Backend *b){return SCPreferencesCommitChanges(b->prefs)&&SCPreferencesApplyChanges(b->prefs);}
static void backend_close(Backend *b){if(b->prefs){if(b->locked)SCPreferencesUnlock(b->prefs);CFRelease(b->prefs);}}
static int command(const char *path,char *const args[]){
    pid_t child=fork();if(child<0)return 0;if(!child){umask(0022);int n=open("/dev/null",O_RDWR);if(n>=0){dup2(n,0);dup2(n,1);dup2(n,2);if(n>2)close(n);}
        char *const env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};execve(path,args,env);_exit(127);}
    struct timespec start,now;clock_gettime(CLOCK_MONOTONIC,&start);int status=0;
    for(;;){pid_t done=waitpid(child,&status,WNOHANG);if(done==child)return WIFEXITED(status)&&!WEXITSTATUS(status);if(done<0&&errno!=EINTR)return 0;
        clock_gettime(CLOCK_MONOTONIC,&now);if(stopped||now.tv_sec-start.tv_sec>=20)break;usleep(100000);}
    kill(child,SIGTERM);usleep(100000);if(!waitpid(child,&status,WNOHANG)){kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}}return 0;
}
static int flush_dns(void){char *const a[]={"/usr/bin/dscacheutil","-flushcache",NULL},*const b[]={"/usr/bin/killall","-HUP","mDNSResponder",NULL};
    return command(a[0],a)&&command(b[0],b);}
#endif

static int selected_match(CFArrayRef current,CFArrayRef expected,int desired){
    if(!valid_rows(current)||!valid_rows(expected))return 0;
    for(CFIndex i=0;i<CFArrayGetCount(expected);i++){
        CFDictionaryRef before=CFArrayGetValueAtIndex(expected,i),now=find_row(current,CFDictionaryGetValue(before,CFSTR("id")));
        if(!now||!CFEqual(CFDictionaryGetValue(now,CFSTR("config")),CFDictionaryGetValue(before,CFSTR("config"))))return 0;
        CFTypeRef target=desired?kCFBooleanFalse:CFDictionaryGetValue(before,CFSTR("ipv6_enabled"));
        if(!CFEqual(CFDictionaryGetValue(now,CFSTR("ipv6_enabled")),target))return 0;
    }return 1;
}
static int event(int root,const char *phase,const char *id){
    char name[90],date[30],line[256];time_t stamp=time(NULL);struct tm utc;gmtime_r(&stamp,&utc);strftime(date,sizeof(date),"%Y-%m-%d",&utc);
    snprintf(name,sizeof(name),"events-%s.private.jsonl",date);int fd=openat(root,name,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0)return 0;int n=snprintf(line,sizeof(line),"{\"at_epoch\":%lld,\"phase\":\"%s\",\"transaction\":\"%s\",\"fixture\":%s}\n",(long long)stamp,phase,id,ENVSCOPE_NET_FIXTURE?"true":"false");
    int ok=protected_fd(fd,0)&&!fchmod(fd,0644)&&n>0&&n<(int)sizeof(line)&&write_all(fd,line,(size_t)n)&&!fsync(fd);close(fd);return ok;
}
static int publish(int root,CFMutableDictionaryRef record,const char *state){
    char id[40];if(!get_text(record,CFSTR("id"),id,sizeof(id))||!valid_id(id,0))return 0;
    text(record,CFSTR("state"),state);number(record,CFSTR("at_epoch"),(long long)time(NULL));
    char backup[90];snprintf(backup,sizeof(backup),"record-%s.private.plist",id);
    return save(root,backup,record,0600)&&save(root,"latest.plist",record,0644)&&event(root,state,id);
}
static int restore_config(Backend *b,CFArrayRef before){
    CFArrayRef rows=backend_rows(b);int ok=valid_rows(rows),changed=0;
    for(CFIndex i=0;ok&&i<CFArrayGetCount(before);i++){
        CFDictionaryRef r=CFArrayGetValueAtIndex(before,i),live=find_row(rows,CFDictionaryGetValue(r,CFSTR("id")));
        if(!live||!CFEqual(CFDictionaryGetValue(live,CFSTR("config")),CFDictionaryGetValue(r,CFSTR("config"))))ok=0;
    }
    if(!ok){if(rows)CFRelease(rows);return 0;}
    for(CFIndex i=0;i<CFArrayGetCount(before);i++){
        CFDictionaryRef r=CFArrayGetValueAtIndex(before,i);
        CFDictionaryRef live=find_row(rows,CFDictionaryGetValue(r,CFSTR("id")));
        if(CFEqual(CFDictionaryGetValue(live,CFSTR("ipv6_enabled")),CFDictionaryGetValue(r,CFSTR("ipv6_enabled"))))continue;
        changed=1;
        if(!backend_set(b,CFDictionaryGetValue(r,CFSTR("id")),CFDictionaryGetValue(r,CFSTR("ipv6_enabled"))==kCFBooleanTrue)){CFRelease(rows);return 0;}
    }CFRelease(rows);return !changed||backend_commit(b);
}
static int readback(CFArrayRef before,int desired){Backend b={0};if(!backend_open(&b,0)){backend_close(&b);return 0;}
    CFArrayRef rows=backend_rows(&b);int ok=rows&&selected_match(rows,before,desired);if(rows)CFRelease(rows);backend_close(&b);return ok;}
static int transaction(int root,CFMutableDictionaryRef plan,int restoring){
    long long format,owner;if(!get_number(plan,CFSTR("format"),&format)||format!=1||!get_number(plan,CFSTR("owner"),&owner)||owner<0)return 65;
    CFMutableDictionaryRef last=read_plist(root,"latest.plist",1),record=NULL;
    if(!last)return 78;char previous[40]="",nonce[40],state[40]="";
    if(CFDictionaryGetCount(last)){
        long long v;
        if(!get_text(last,CFSTR("id"),previous,sizeof(previous))||!valid_id(previous,0)||!get_text(last,CFSTR("state"),state,sizeof(state))||
           !get_number(last,CFSTR("format"),&v)||v!=1||CFDictionaryGetValue(last,CFSTR("fixture"))!=(ENVSCOPE_NET_FIXTURE?kCFBooleanTrue:kCFBooleanFalse)||
           !valid_rows(CFDictionaryGetValue(last,CFSTR("adapters")))||
           (strcmp(state,"prepared")&&strcmp(state,"partial")&&strcmp(state,"committed")&&strcmp(state,"rolled_back")&&strcmp(state,"restored"))){CFRelease(last);return 78;}
    }
    if(restoring){
        long long old_owner;char wanted[40];
        if(!get_text(plan,CFSTR("record_id"),wanted,sizeof(wanted))||strcmp(wanted,previous)||
           !get_number(last,CFSTR("owner"),&old_owner)||old_owner!=owner||!valid_rows(CFDictionaryGetValue(last,CFSTR("adapters")))){CFRelease(last);return 79;}
        char backup[90];snprintf(backup,sizeof(backup),"record-%s.private.plist",previous);
        CFMutableDictionaryRef original=read_plist(root,backup,0);long long original_owner;
        if(!original||!get_number(original,CFSTR("owner"),&original_owner)||original_owner!=owner||
           !valid_rows(CFDictionaryGetValue(original,CFSTR("adapters")))||
           !CFEqual(CFDictionaryGetValue(original,CFSTR("adapters")),CFDictionaryGetValue(last,CFSTR("adapters")))){
            if(original)CFRelease(original);CFRelease(last);return 78;}
        CFRelease(original);record=last; /* Ownership transfers to this restoration operation. */
    }else{
        char expected[40];CFArrayRef before=CFDictionaryGetValue(plan,CFSTR("adapters"));CFTypeRef dns=CFDictionaryGetValue(plan,CFSTR("flush_dns"));
        if(!get_text(plan,CFSTR("nonce"),nonce,sizeof(nonce))||!valid_id(nonce,0)||
           !get_text(plan,CFSTR("expected_record"),expected,sizeof(expected))||strcmp(expected,previous)||
           !valid_rows(before)||!is_bool(dns)||(!CFArrayGetCount(before)&&dns!=kCFBooleanTrue)||
           !strcmp(state,"prepared")||!strcmp(state,"partial")){CFRelease(last);return 79;}
        char backup[90];struct stat exists;snprintf(backup,sizeof(backup),"record-%s.private.plist",nonce);
        if(!fstatat(root,backup,&exists,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT){CFRelease(last);return 79;}
        record=dict();number(record,CFSTR("format"),1);number(record,CFSTR("owner"),owner);text(record,CFSTR("id"),nonce);
        text(record,CFSTR("release"),ENVSCOPE_RELEASE);CFDictionarySetValue(record,CFSTR("fixture"),ENVSCOPE_NET_FIXTURE?kCFBooleanTrue:kCFBooleanFalse);
        CFDictionarySetValue(record,CFSTR("adapters"),before);CFDictionarySetValue(record,CFSTR("flush_dns_requested"),dns);
        text(record,CFSTR("dns_flush"),dns==kCFBooleanTrue?"pending":"not_requested");CFRelease(last);
    }
    CFArrayRef before=CFDictionaryGetValue(record,CFSTR("adapters"));Backend b={0};
    if(!backend_open(&b,1)){backend_close(&b);CFRelease(record);return 75;}
    CFArrayRef observed=backend_rows(&b);int ok=observed&&valid_rows(observed);
    if(!restoring&&ok)ok=selected_match(observed,before,0);
    if(observed)CFRelease(observed);
    int result=79;
    if(!ok)goto done;
    if(restoring){
        if(!restore_config(&b,before))goto partial;
        backend_close(&b);memset(&b,0,sizeof(b));
        if(!readback(before,0))goto partial;
        result=publish(root,record,"restored")?0:74;goto done;
    }
    if(!publish(root,record,"prepared")){result=74;goto done;}
    for(CFIndex i=0;i<CFArrayGetCount(before);i++){
        if(stopped||!backend_set(&b,CFDictionaryGetValue(CFArrayGetValueAtIndex(before,i),CFSTR("id")),FALSE))goto rollback;
    }
    if(CFArrayGetCount(before)&&!backend_commit(&b))goto rollback;
    backend_close(&b);memset(&b,0,sizeof(b));
    if(!readback(before,1))goto rollback;
    if(CFDictionaryGetValue(record,CFSTR("flush_dns_requested"))==kCFBooleanTrue){
        int flushed=!stopped&&flush_dns();text(record,CFSTR("dns_flush"),flushed?"completed":"unverified");if(!flushed)goto partial;
    }
    result=publish(root,record,"committed")?0:74;goto done;
rollback:
    backend_close(&b);memset(&b,0,sizeof(b));
    if(backend_open(&b,1)&&restore_config(&b,before)){
        backend_close(&b);memset(&b,0,sizeof(b));
        if(readback(before,0)){publish(root,record,"rolled_back");result=74;goto done;}
    }
partial:publish(root,record,"partial");result=74;
done:backend_close(&b);CFRelease(record);return result;
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--version")){printf("{\"format\":1,\"release\":\"%s\",\"fixture\":%s}\n",ENVSCOPE_RELEASE,ENVSCOPE_NET_FIXTURE?"true":"false");return 0;}
    if(argc==2&&!strcmp(argv[1],"--snapshot")){
        Backend b={0};if(!backend_open(&b,0)){backend_close(&b);return 74;}CFArrayRef rows=backend_rows(&b);CFMutableDictionaryRef d=dict();
        if(!rows||!valid_rows(rows)){if(rows)CFRelease(rows);CFRelease(d);backend_close(&b);return 74;}
        number(d,CFSTR("format"),1);number(d,CFSTR("owner"),(long long)getuid());CFDictionarySetValue(d,CFSTR("adapters"),rows);
        CFDictionarySetValue(d,CFSTR("fixture"),ENVSCOPE_NET_FIXTURE?kCFBooleanTrue:kCFBooleanFalse);text(d,CFSTR("release"),ENVSCOPE_RELEASE);
        int ok=emit(d);CFRelease(rows);CFRelease(d);backend_close(&b);return ok?0:74;
    }
    if(getuid()!=0||geteuid()!=0)return 77;
    int root=open(ENVSCOPE_NET_ROOT,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0||!protected_fd(root,1))return 78;
    int lifecycle=argc==2&&!strcmp(argv[1],"--lifecycle");
    int lease=openat(root,lifecycle?".lifecycle.lock":".transaction.lock",O_RDWR|O_CREAT|O_NOFOLLOW,0600);
    if(lease<0||!protected_fd(lease,0)||fchmod(lease,0600)||flock(lease,LOCK_EX|LOCK_NB))return 75;
    if(lifecycle){char *const args[]={"/bin/sh","-s",NULL};char *const env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C","HOME=/var/root",NULL};execve(args[0],args,env);return 74;}
    if(argc!=2||(strcmp(argv[1],"--apply")&&strcmp(argv[1],"--restore")))return 64;
    signal(SIGTERM,stop_now);signal(SIGINT,stop_now);signal(SIGHUP,stop_now);
    CFMutableDictionaryRef plan=read_plist_fd(STDIN_FILENO);if(!plan)return 65;
    int result=transaction(root,plan,!strcmp(argv[1],"--restore"));CFRelease(plan);close(lease);close(root);return result;
}
