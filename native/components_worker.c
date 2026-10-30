/* Fixed legacy component retirement/recovery. No network or timezone writes.
 * Launchd registration is compared with the approved definition before removal.
 * User-agent file writes drop privileges; account and script files are read-only.
 */
#define _DARWIN_C_SOURCE
#include <CoreFoundation/CoreFoundation.h>
#include <ServiceManagement/ServiceManagement.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/acl.h>
#include <membership.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef ENVSCOPE_COMPONENT_ROOT
#define ENVSCOPE_COMPONENT_ROOT "/Library/PrivilegedHelperTools/io.qudadd.envscope.components"
#define ENVSCOPE_COMPONENT_SOURCE "/Library/Application Support/claude-switcher"
#define ENVSCOPE_COMPONENT_DAEMONS "/Library/LaunchDaemons"
#define ENVSCOPE_COMPONENT_HOME ""
#define ENVSCOPE_COMPONENT_LABEL_GUARD "local.claude-bodyguard"
#define ENVSCOPE_COMPONENT_LABEL_TIMEZONE "local.tz-watchdog"
#define ENVSCOPE_COMPONENT_LABEL_UPDATE "local.claude-update"
#define ENVSCOPE_COMPONENT_LABEL_USER "local.claude-update"
#define ENVSCOPE_COMPONENT_FIXTURE 0
#endif
#ifndef ENVSCOPE_RELEASE
#define ENVSCOPE_RELEASE "development"
#endif
#define LIMIT (2*1024*1024)
typedef struct {const char *id,*label,*file;int user;} Role;
static const Role roles[]={
 {"guard",ENVSCOPE_COMPONENT_LABEL_GUARD,"claude-bodyguard.sh",0},
 {"timezone",ENVSCOPE_COMPONENT_LABEL_TIMEZONE,"tz-watchdog.sh",0},
 {"update.system",ENVSCOPE_COMPONENT_LABEL_UPDATE,"claude-switch.sh",0},
 {"update.user",ENVSCOPE_COMPONENT_LABEL_USER,"claude-switch.sh",1}};
static char self_path[4096],home[4096];
static uid_t actor;
static CFMutableDictionaryRef dict(void){return CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);}
static CFMutableArrayRef array(void){return CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);}
static int is_dict(CFTypeRef v){return v&&CFGetTypeID(v)==CFDictionaryGetTypeID();}
static int is_array(CFTypeRef v){return v&&CFGetTypeID(v)==CFArrayGetTypeID();}
static void text(CFMutableDictionaryRef d,CFStringRef k,const char *v){CFStringRef s=CFStringCreateWithCString(NULL,v,kCFStringEncodingUTF8);CFDictionarySetValue(d,k,s);CFRelease(s);}
static void boolean(CFMutableDictionaryRef d,CFStringRef k,int b){CFDictionarySetValue(d,k,b?kCFBooleanTrue:kCFBooleanFalse);}
static int get_text(CFDictionaryRef d,CFStringRef k,char *v,size_t n){CFTypeRef s=CFDictionaryGetValue(d,k);return s&&CFGetTypeID(s)==CFStringGetTypeID()&&CFStringGetCString(s,v,(CFIndex)n,kCFStringEncodingUTF8);}
static int true_at(CFDictionaryRef d,CFStringRef k){return CFDictionaryGetValue(d,k)==kCFBooleanTrue;}
static void number_at(CFMutableDictionaryRef d,CFStringRef k,long long n){CFNumberRef v=CFNumberCreate(NULL,kCFNumberLongLongType,&n);CFDictionarySetValue(d,k,v);CFRelease(v);}
static int integer_at(CFDictionaryRef d,CFStringRef k,long long *n){CFTypeRef v=CFDictionaryGetValue(d,k);return v&&CFGetTypeID(v)==CFNumberGetTypeID()&&!CFNumberIsFloatType(v)&&CFNumberGetValue(v,kCFNumberLongLongType,n);}
static int eq(CFDictionaryRef a,CFDictionaryRef b,CFStringRef k){CFTypeRef x=CFDictionaryGetValue(a,k),y=CFDictionaryGetValue(b,k);return x&&y&&CFEqual(x,y);}
static int hex(const char *s,int n){if((int)strlen(s)!=n)return 0;for(int i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1;}
static CFStringRef string(const char *s){return CFStringCreateWithCString(NULL,s,kCFStringEncodingUTF8);}
static int write_all(int fd,const void *p,size_t n){const char *s=p;while(n){ssize_t v=write(fd,s,n);if(v<0&&errno==EINTR)continue;if(v<=0)return 0;s+=v;n-=(size_t)v;}return 1;}
static int safe_acl(int fd,uid_t owner){
 acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);if(!acl)return errno==ENOENT;
 uuid_t uuid;if(mbr_uid_to_uuid(owner,uuid)){acl_free(acl);return 0;}acl_entry_t entry;int which=ACL_FIRST_ENTRY,ok=1;
 while(acl_get_entry(acl,which,&entry)==0){which=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t perms;
  if(acl_get_tag_type(entry,&tag)||acl_get_permset(entry,&perms)){ok=0;break;}if(tag!=ACL_EXTENDED_ALLOW)continue;
  const acl_perm_t writes[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};int writable=0;
  for(int i=0;i<8;i++){int p=acl_get_perm_np(perms,writes[i]);if(p<0){ok=0;break;}if(p)writable=1;}
  if(!ok)break;if(writable){void *who=acl_get_qualifier(entry);if(!who||memcmp(who,uuid,sizeof(uuid)))ok=0;if(who)acl_free(who);if(!ok)break;}
 }acl_free(acl);return ok;
}
static int safe_fd(int fd,uid_t owner,int directory){struct stat s;return !fstat(fd,&s)&&s.st_uid==owner&&!(s.st_mode&0022)&&(directory?S_ISDIR(s.st_mode):S_ISREG(s.st_mode)&&s.st_nlink==1)&&safe_acl(fd,owner);}
static int directory(const char *path,int user){
 if(path[0]!='/')return -1;char buf[4096];if(strlen(path)>=sizeof(buf))return -1;strcpy(buf,path);
 int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);char *state=NULL,*part=strtok_r(buf,"/",&state);
 while(fd>=0&&part){if(!strcmp(part,".")||!strcmp(part,"..")){close(fd);return -1;}
  int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;
  struct stat s;if(fd>=0&&(fstat(fd,&s)||!S_ISDIR(s.st_mode)||(s.st_mode&0022)||(s.st_uid!=0&&(!user||s.st_uid!=actor))||!safe_acl(fd,s.st_uid))){close(fd);return -1;}
  part=strtok_r(NULL,"/",&state);
 }return fd;
}
static CFDataRef read_fd(int fd,uid_t owner){
 if(!safe_fd(fd,owner,0))return NULL;struct stat a,b;if(fstat(fd,&a)||a.st_size<0||a.st_size>LIMIT)return NULL;
 UInt8 *data=malloc(LIMIT+1);if(!data)return NULL;size_t n=0;
 while(n<LIMIT+1){ssize_t got=read(fd,data+n,LIMIT+1-n);if(got<0&&errno==EINTR)continue;if(got<0){free(data);return NULL;}if(!got)break;n+=(size_t)got;}
 int ok=n<=LIMIT&&!fstat(fd,&b)&&a.st_ino==b.st_ino&&a.st_dev==b.st_dev&&a.st_size==b.st_size&&a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec;
 CFDataRef value=ok?CFDataCreate(NULL,data,(CFIndex)n):NULL;free(data);return value;
}
static CFDataRef read_at(int dir,const char *name,uid_t owner,int *absent){
 *absent=0;int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0){*absent=errno==ENOENT;return NULL;}CFDataRef d=read_fd(fd,owner);close(fd);return d;
}
static CFMutableDictionaryRef parse(CFDataRef data){
 CFPropertyListRef v=data?CFPropertyListCreateWithData(NULL,data,kCFPropertyListMutableContainersAndLeaves,NULL,NULL):NULL;
 if(!is_dict(v)){if(v)CFRelease(v);return NULL;}return (CFMutableDictionaryRef)v;
}
static void hash(CFDataRef d,char out[65]){unsigned char bytes[CC_SHA256_DIGEST_LENGTH];CC_SHA256(CFDataGetBytePtr(d),(CC_LONG)CFDataGetLength(d),bytes);for(int i=0;i<CC_SHA256_DIGEST_LENGTH;i++)snprintf(out+i*2,3,"%02x",bytes[i]);}
static int emit(CFDictionaryRef v){CFDataRef d=CFPropertyListCreateData(NULL,v,kCFPropertyListXMLFormat_v1_0,0,NULL);if(!d)return 0;int ok=write_all(1,CFDataGetBytePtr(d),(size_t)CFDataGetLength(d));CFRelease(d);return ok;}
static CFStringRef encode(CFDataRef data){
 static const char chars[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";size_t n=(size_t)CFDataGetLength(data);const UInt8 *p=CFDataGetBytePtr(data);
 char *out=malloc(4*((n+2)/3)+1);if(!out)return NULL;size_t j=0;
 for(size_t i=0;i<n;i+=3){unsigned v=(unsigned)p[i]<<16;if(i+1<n)v|=(unsigned)p[i+1]<<8;if(i+2<n)v|=p[i+2];out[j++]=chars[(v>>18)&63];out[j++]=chars[(v>>12)&63];out[j++]=i+1<n?chars[(v>>6)&63]:'=';out[j++]=i+2<n?chars[v&63]:'=';}
 out[j]=0;CFStringRef value=string(out);free(out);return value;
}
static CFDataRef decode(CFStringRef s){
 if(!s||CFGetTypeID(s)!=CFStringGetTypeID())return NULL;CFIndex max=CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),kCFStringEncodingUTF8)+1;
 if(max<1||max>LIMIT)return NULL;char *raw=malloc((size_t)max);if(!raw)return NULL;
 if(!CFStringGetCString(s,raw,max,kCFStringEncodingUTF8)){free(raw);return NULL;}size_t n=strlen(raw);if(n%4){free(raw);return NULL;}
 UInt8 *out=malloc(n+1);if(!out){free(raw);return NULL;}size_t count=0;unsigned v=0;int bits=0,pad=0;
 for(size_t i=0;i<n;i++){int c=(unsigned char)raw[i],x=c>='A'&&c<='Z'?c-'A':c>='a'&&c<='z'?c-'a'+26:c>='0'&&c<='9'?c-'0'+52:c=='+'?62:c=='/'?63:-1;
  if(c=='='){pad++;if(i<n-2||pad>2)goto bad;continue;}if(x<0||pad)goto bad;v=(v<<6)|(unsigned)x;bits+=6;if(bits>=8){bits-=8;out[count++]=(UInt8)(v>>bits);}}
 {CFDataRef d=CFDataCreate(NULL,out,(CFIndex)count);free(out);free(raw);return d;}
bad:free(out);free(raw);return NULL;
}
static int set_actor(const char *value){char *end=NULL;unsigned long v=strtoul(value,&end,10);if(!value[0]||!end||*end||!v||v>2147483647)return 0;
 actor=(uid_t)v;struct passwd *pw=getpwuid(actor);if(!pw)return 0;
 const char *p=ENVSCOPE_COMPONENT_HOME[0]?ENVSCOPE_COMPONENT_HOME:pw->pw_dir;return realpath(p,home)!=NULL;
}
static int drop_actor(void){struct passwd *pw=getpwuid(actor);return pw&&(!initgroups(pw->pw_name,pw->pw_gid))&&!setgid(pw->pw_gid)&&!setuid(actor)&&getuid()==actor&&geteuid()==actor;}
static int paths(int i,char defdir[4096],char name[160],char scriptdir[4096]){
 if(roles[i].user){if(snprintf(defdir,4096,"%s/Library/LaunchAgents",home)>=4096||snprintf(scriptdir,4096,"%s/.local/bin",home)>=4096)return 0;}
 else{snprintf(defdir,4096,"%s",ENVSCOPE_COMPONENT_DAEMONS);snprintf(scriptdir,4096,"%s",ENVSCOPE_COMPONENT_SOURCE);}
 return snprintf(name,160,"%s.plist",roles[i].label)<160;
}
static CFMutableDictionaryRef job(int i){
 CFStringRef label=string(roles[i].label);if(!label)return NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 CFDictionaryRef raw=SMJobCopyDictionary(roles[i].user?kSMDomainUserLaunchd:kSMDomainSystemLaunchd,label);
#pragma clang diagnostic pop
 CFRelease(label);CFMutableDictionaryRef value=raw?CFDictionaryCreateMutableCopy(NULL,0,raw):dict();if(raw)CFRelease(raw);return value;
}
static int command(char *const argv[]){pid_t pid=fork();if(pid<0)return -1;if(!pid){int fd=open("/dev/null",O_RDWR);if(fd>=0){dup2(fd,1);dup2(fd,2);close(fd);}execv(argv[0],argv);_exit(127);}int code;while(waitpid(pid,&code,0)<0){if(errno!=EINTR)return -1;}return WIFEXITED(code)?WEXITSTATUS(code):-1;}
static int presence(const char *target){
 int p[2];if(pipe(p))return -1;pid_t pid=fork();if(pid<0){close(p[0]);close(p[1]);return -1;}
 if(!pid){close(p[0]);dup2(p[1],1);dup2(p[1],2);close(p[1]);execl("/bin/launchctl","launchctl","print",target,(char*)NULL);_exit(127);}
 close(p[1]);char buf[LIMIT+1];size_t n=0;while(n<LIMIT){ssize_t got=read(p[0],buf+n,LIMIT-n);if(got<0&&errno==EINTR)continue;if(got<=0)break;n+=(size_t)got;}close(p[0]);buf[n]=0;int code;while(waitpid(pid,&code,0)<0)if(errno!=EINTR)return -1;
 if(n==LIMIT||!WIFEXITED(code))return -1;if(!WEXITSTATUS(code))return 1;
 return strcasestr(buf,"could not find service")?0:-1;
}
static CFMutableDictionaryRef user_job(void){
 int pipes[2];if(pipe(pipes))return NULL;char uid[32];snprintf(uid,sizeof(uid),"%u",actor);pid_t p=fork();
 if(p<0){close(pipes[0]);close(pipes[1]);return NULL;}
 if(!p){close(pipes[0]);dup2(pipes[1],1);close(pipes[1]);execl("/bin/launchctl","launchctl","asuser",uid,self_path,"--user-job",uid,(char*)NULL);_exit(127);}
 close(pipes[1]);UInt8 *bytes=malloc(LIMIT+1);if(!bytes){close(pipes[0]);return NULL;}size_t n=0;
 while(n<LIMIT+1){ssize_t got=read(pipes[0],bytes+n,LIMIT+1-n);if(got<0&&errno==EINTR)continue;if(got<=0)break;n+=(size_t)got;}close(pipes[0]);int code;while(waitpid(p,&code,0)<0)if(errno!=EINTR){free(bytes);return NULL;}
 CFDataRef d=n<=LIMIT&&WIFEXITED(code)&&!WEXITSTATUS(code)?CFDataCreate(NULL,bytes,(CFIndex)n):NULL;free(bytes);CFMutableDictionaryRef v=parse(d);if(d)CFRelease(d);return v;
}
static int args_match(CFDictionaryRef d,int i){
 char dir[4096],name[160],src[4096],full[4300];if(!paths(i,dir,name,src))return 0;snprintf(full,sizeof(full),"%s/%s",src,roles[i].file);
 CFTypeRef raw=CFDictionaryGetValue(d,CFSTR("ProgramArguments"));if(!is_array(raw)||CFArrayGetCount(raw)!=(i>=2?4:2))return 0;
 const char *want[]={"/bin/bash",full,"update","--auto"};for(CFIndex j=0;j<CFArrayGetCount(raw);j++){CFStringRef v=string(want[j]);int ok=CFEqual(CFArrayGetValueAtIndex(raw,j),v);CFRelease(v);if(!ok)return 0;}
 CFStringRef l=string(roles[i].label);int ok=CFEqual(CFDictionaryGetValue(d,CFSTR("Label"))?:CFSTR(""),l);CFRelease(l);return ok;
}
static int definition_match(CFDictionaryRef d,int i){
 if(!is_dict(d)||!args_match(d,i))return 0;
 const CFStringRef allowed[]={CFSTR("Label"),CFSTR("Program"),CFSTR("ProgramArguments"),CFSTR("RunAtLoad"),CFSTR("StartInterval"),CFSTR("Disabled"),CFSTR("StandardOutPath"),CFSTR("StandardErrorPath"),CFSTR("ProcessType"),CFSTR("Nice"),CFSTR("LowPriorityIO"),CFSTR("ThrottleInterval"),CFSTR("ExitTimeOut"),CFSTR("UserName")};
 CFIndex n=CFDictionaryGetCount(d);if(n<0||n>14)return 0;const void *keys[14];CFDictionaryGetKeysAndValues(d,keys,NULL);
 for(CFIndex j=0;j<n;j++){int found=0;for(int k=0;k<14;k++)if(CFEqual(keys[j],allowed[k]))found=1;if(!found)return 0;}
 CFTypeRef p=CFDictionaryGetValue(d,CFSTR("Program")),u=CFDictionaryGetValue(d,CFSTR("UserName"));
 if((p&&!CFEqual(p,CFSTR("/bin/bash")))||(u&&(roles[i].user||!CFEqual(u,CFSTR("root")))))return 0;
 long long interval=0;if(!integer_at(d,CFSTR("StartInterval"),&interval)||interval<=0)return 0;
 const CFStringRef bools[]={CFSTR("RunAtLoad"),CFSTR("Disabled")};for(int k=0;k<2;k++){CFTypeRef v=CFDictionaryGetValue(d,bools[k]);if(v&&v!=kCFBooleanTrue&&v!=kCFBooleanFalse)return 0;}
 return 1;
}
static CFMutableDictionaryRef snapshot_row(int i){
 char dir[4096],name[160],src[4096],target[300],sha[65];if(!paths(i,dir,name,src))return NULL;
 CFMutableDictionaryRef row=dict();text(row,CFSTR("id"),roles[i].id);
 int fd=directory(dir,roles[i].user),absent=0;CFDataRef body=fd>=0?read_at(fd,name,roles[i].user?actor:0,&absent):NULL;if(fd>=0)close(fd);
 if(fd<0){struct stat st;if(lstat(dir,&st)&&errno==ENOENT)absent=1;else goto bad;}
 if(!body&&!absent)goto bad;boolean(row,CFSTR("present"),!absent);
 if(body){struct stat info;int df=directory(dir,roles[i].user);if(df<0||fstatat(df,name,&info,AT_SYMLINK_NOFOLLOW)){if(df>=0)close(df);goto bad;}
  int entry=openat(df,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(df);if(entry<0)goto bad;
   acl_t acl=acl_get_fd_np(entry,ACL_TYPE_EXTENDED);int acl_error=errno;close(entry);if(!acl&&acl_error==ENOENT)acl=acl_init(0);if(!acl)goto bad;ssize_t size=acl_size(acl);void *bytes=size>0&&size<LIMIT?malloc((size_t)size):NULL;
  ssize_t copied=bytes?acl_copy_ext(bytes,acl,size):-1;if(copied<=0||copied>size){if(bytes)free(bytes);acl_free(acl);goto bad;}
  CFDataRef raw_acl=CFDataCreate(NULL,bytes,(CFIndex)copied);free(bytes);acl_free(acl);CFStringRef encoded_acl=encode(raw_acl);CFRelease(raw_acl);if(!encoded_acl)goto bad;CFDictionarySetValue(row,CFSTR("acl"),encoded_acl);CFRelease(encoded_acl);
  number_at(row,CFSTR("mode"),info.st_mode&0777);number_at(row,CFSTR("group"),info.st_gid);}
 CFMutableDictionaryRef live=roles[i].user?user_job():job(i);if(!live)goto bad;
 if(roles[i].user)snprintf(target,sizeof(target),"gui/%u/%s",actor,roles[i].label);else snprintf(target,sizeof(target),"system/%s",roles[i].label);
 int listed=presence(target),found=CFDictionaryContainsKey(live,CFSTR("Label"));
 if(listed<0||listed!=found||(found&&!args_match(live,i))){CFRelease(live);goto bad;}
 boolean(row,CFSTR("registered"),found);CFTypeRef pid=CFDictionaryGetValue(live,CFSTR("PID"));long long number=0;
 boolean(row,CFSTR("running"),pid&&CFGetTypeID(pid)==CFNumberGetTypeID()&&CFNumberGetValue(pid,kCFNumberLongLongType,&number)&&number>0);CFRelease(live);
  if(body){CFMutableDictionaryRef value=parse(body);if(!value||!definition_match(value,i)){if(value)CFRelease(value);goto bad;}
  hash(body,sha);text(row,CFSTR("definition_sha"),sha);CFStringRef b64=encode(body);if(!b64){CFRelease(value);goto bad;}CFDictionarySetValue(row,CFSTR("definition"),b64);CFRelease(b64);
  boolean(row,CFSTR("enabled"),!true_at(value,CFSTR("Disabled")));CFRelease(value);
 }else if(found)goto bad;
 {int sf=directory(src,roles[i].user),missing=0;CFDataRef script=sf>=0?read_at(sf,roles[i].file,roles[i].user?actor:0,&missing):NULL;if(sf>=0)close(sf);
  if(script){hash(script,sha);CFRelease(script);text(row,CFSTR("script_sha"),sha);}else if(body)goto bad;}
 if(body)CFRelease(body);return row;
bad:if(body)CFRelease(body);CFRelease(row);return NULL;
}
static int same(CFDictionaryRef now,CFDictionaryRef before){
 const CFStringRef keys[]={CFSTR("present"),CFSTR("registered"),CFSTR("definition_sha"),CFSTR("script_sha"),CFSTR("enabled"),CFSTR("mode"),CFSTR("group")};
 for(int k=0;k<7;k++){if(k>=2&&!true_at(before,CFSTR("present")))continue;if(!eq(now,before,keys[k]))return 0;}return 1;
}
static int save(int root,const char *name,CFDictionaryRef v,mode_t mode){
 CFDataRef d=CFPropertyListCreateData(NULL,v,kCFPropertyListXMLFormat_v1_0,0,NULL);if(!d)return 0;char tmp[160];snprintf(tmp,sizeof(tmp),".next-%d-%u",getpid(),arc4random());
 int fd=openat(root,tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode),ok=fd>=0&&safe_fd(fd,0,0)&&!fchmod(fd,mode)&&write_all(fd,CFDataGetBytePtr(d),(size_t)CFDataGetLength(d))&&!fsync(fd);if(fd>=0)close(fd);CFRelease(d);
 if(ok)ok=!renameat(root,tmp,root,name)&&!fsync(root);if(!ok)unlinkat(root,tmp,0);return ok;
}
static CFMutableDictionaryRef read_record(int root,const char *name,int optional){int missing=0;CFDataRef raw=read_at(root,name,0,&missing);CFMutableDictionaryRef v=raw?parse(raw):optional&&missing?dict():NULL;if(raw)CFRelease(raw);return v;}
static int publish(int root,CFMutableDictionaryRef record,const char *phase){
 text(record,CFSTR("state"),phase);char id[40],name[90];if(!get_text(record,CFSTR("id"),id,sizeof(id))||!hex(id,32))return 0;
 snprintf(name,sizeof(name),"record-%s.private.plist",id);if(!save(root,name,record,0600))return 0;
 CFMutableDictionaryRef summary=dict();const CFStringRef keep[]={CFSTR("format"),CFSTR("fixture"),CFSTR("actor"),CFSTR("id"),CFSTR("state"),CFSTR("roles"),CFSTR("release")};
 for(int i=0;i<7;i++){CFTypeRef v=CFDictionaryGetValue(record,keep[i]);if(!v){CFRelease(summary);return 0;}CFDictionarySetValue(summary,keep[i],v);}
 CFArrayRef rows=CFDictionaryGetValue(record,CFSTR("before"));CFMutableArrayRef originals=array();
 for(CFIndex i=0;i<CFArrayGetCount(rows);i++){CFMutableDictionaryRef row=CFDictionaryCreateMutableCopy(NULL,0,CFArrayGetValueAtIndex(rows,i));CFDictionaryRemoveValue(row,CFSTR("definition"));CFDictionaryRemoveValue(row,CFSTR("acl"));CFArrayAppendValue(originals,row);CFRelease(row);}
 CFDictionarySetValue(summary,CFSTR("original"),originals);CFRelease(originals);int ok=save(root,"latest.plist",summary,0644);CFRelease(summary);
 int fd=openat(root,"events.private.jsonl",O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);char line[300];int n=snprintf(line,sizeof(line),"{\"at_epoch\":%lld,\"transaction\":\"%s\",\"phase\":\"%s\"}\n",(long long)time(NULL),id,phase);
 if(fd<0)return 0;ok=ok&&safe_fd(fd,0,0)&&write_all(fd,line,(size_t)n)&&!fsync(fd);close(fd);return ok;
}
static int file_change(int i,CFDictionaryRef before,int restore){
 char dir[4096],name[160],src[4096];if(!paths(i,dir,name,src))return 0;int parent=directory(dir,roles[i].user);if(parent<0)return 0;
 CFDataRef data=restore?decode(CFDictionaryGetValue(before,CFSTR("definition"))):NULL;long long mode=0644,group=0;
 if(restore){char got[65],wanted[65];if(!data||!get_text(before,CFSTR("definition_sha"),wanted,sizeof(wanted))||!integer_at(before,CFSTR("mode"),&mode)||mode<0||mode>0777||(mode&0022)||!integer_at(before,CFSTR("group"),&group)||group<0||group>2147483647){if(data)CFRelease(data);close(parent);return 0;}hash(data,got);if(strcmp(wanted,got)){CFRelease(data);close(parent);return 0;}}
  if(restore){CFMutableDictionaryRef definition=parse(data);int ok=definition&&definition_match(definition,i);if(definition)CFRelease(definition);if(!ok){CFRelease(data);close(parent);return 0;}}
 struct stat parent_info;if(roles[i].user&&(fstat(parent,&parent_info)||parent_info.st_uid!=actor)){if(data)CFRelease(data);close(parent);return 0;}
 char stage[90]="";int output=-1;
 if(restore){snprintf(stage,sizeof(stage),".envscope-%d-%u.plist",getpid(),arc4random());output=openat(parent,stage,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  CFDataRef raw_acl=decode(CFDictionaryGetValue(before,CFSTR("acl")));acl_t acl=raw_acl?acl_copy_int(CFDataGetBytePtr(raw_acl)):NULL;
  int ok=output>=0&&acl&&!fchown(output,roles[i].user?actor:0,(gid_t)group)&&!fchmod(output,(mode_t)mode)&&!acl_set_fd_np(output,acl,ACL_TYPE_EXTENDED);
  if(acl)acl_free(acl);if(raw_acl)CFRelease(raw_acl);
  if(!ok){if(output>=0)close(output);unlinkat(parent,stage,0);CFRelease(data);close(parent);return 0;}}
 pid_t pid=fork();if(pid<0){if(data)CFRelease(data);close(parent);return 0;}
 if(!pid){if(roles[i].user&&!drop_actor())_exit(77);int ok=0;
  if(restore){
   ok=output>=0&&write_all(output,CFDataGetBytePtr(data),(size_t)CFDataGetLength(data))&&!fsync(output);if(output>=0)close(output);
   if(ok)ok=!linkat(parent,stage,parent,name,0);unlinkat(parent,stage,0);
  }else ok=!unlinkat(parent,name,0);
  if(ok)ok=!fsync(parent);_exit(ok?0:74);
 }
 if(output>=0)close(output);if(data)CFRelease(data);int code;while(waitpid(pid,&code,0)<0)if(errno!=EINTR){close(parent);return 0;}if(stage[0])unlinkat(parent,stage,0);close(parent);return WIFEXITED(code)&&!WEXITSTATUS(code);
}
static int job_change(int i,int restore){
 char target[300],dir[4096],name[160],src[4096],file[4300];paths(i,dir,name,src);snprintf(file,sizeof(file),"%s/%s",dir,name);
  if(roles[i].user){if(restore)snprintf(target,sizeof(target),"gui/%u",actor);else snprintf(target,sizeof(target),"gui/%u/%s",actor,roles[i].label);}
  else{if(restore)snprintf(target,sizeof(target),"system");else snprintf(target,sizeof(target),"system/%s",roles[i].label);}
 char *args[]={"/bin/launchctl",restore?"bootstrap":"bootout",target,restore?file:NULL,NULL};return command(args)==0;
}
static int restore_rows(CFArrayRef rows){
 for(CFIndex j=0;j<CFArrayGetCount(rows);j++){CFDictionaryRef before=CFArrayGetValueAtIndex(rows,j);char id[40];if(!is_dict(before)||!get_text(before,CFSTR("id"),id,sizeof(id)))return 0;int i;for(i=0;i<4;i++)if(!strcmp(id,roles[i].id))break;if(i==4)return 0;
  CFMutableDictionaryRef now=snapshot_row(i);if(!now)return 0;
  if(!eq(now,before,CFSTR("script_sha"))){CFRelease(now);return 0;}
  if(true_at(now,CFSTR("present"))){CFMutableDictionaryRef expected=CFDictionaryCreateMutableCopy(NULL,0,before);CFDictionarySetValue(expected,CFSTR("registered"),CFDictionaryGetValue(now,CFSTR("registered")));int ok=same(now,expected)&&(!true_at(now,CFSTR("registered"))||true_at(before,CFSTR("registered")));CFRelease(expected);if(!ok){CFRelease(now);return 0;}}
  else if(!file_change(i,before,1)){CFRelease(now);return 0;}
  int registered=true_at(now,CFSTR("registered"));CFRelease(now);
  if(true_at(before,CFSTR("registered"))&&!registered&&!job_change(i,1))return 0;
  now=snapshot_row(i);int ok=now&&same(now,before);if(now)CFRelease(now);if(!ok)return 0;
 }return 1;
}
static int execute(int root,CFDictionaryRef plan,int restoring){
 char id[40],owner[32],expected[40];CFArrayRef requested=CFDictionaryGetValue(plan,CFSTR("roles")),before=CFDictionaryGetValue(plan,CFSTR("before"));
 if(!get_text(plan,CFSTR("id"),id,sizeof(id))||!hex(id,32)||!get_text(plan,CFSTR("actor"),owner,sizeof(owner))||!set_actor(owner)||!get_text(plan,CFSTR("expected_record"),expected,sizeof(expected))||!is_array(requested)||CFArrayGetCount(requested)<1||CFArrayGetCount(requested)>4)return 65;
  CFMutableDictionaryRef last=read_record(root,"latest.plist",1);if(!last)return 78;char lastid[40]="",phase[40]="";get_text(last,CFSTR("id"),lastid,sizeof(lastid));get_text(last,CFSTR("state"),phase,sizeof(phase));if(strcmp(expected,lastid)){CFRelease(last);return 79;}
  if(CFDictionaryGetCount(last)){long long format=0;if(!integer_at(last,CFSTR("format"),&format)||format!=1||!hex(lastid,32)||true_at(last,CFSTR("fixture"))!=ENVSCOPE_COMPONENT_FIXTURE||!eq(last,plan,CFSTR("actor"))){CFRelease(last);return 79;}}
 CFMutableDictionaryRef record=NULL;
 if(restoring){char saved[90],saved_owner[32];if(!hex(lastid,32)||(strcmp(phase,"prepared")&&strcmp(phase,"partial")&&strcmp(phase,"committed"))){CFRelease(last);return 79;}
  snprintf(saved,sizeof(saved),"record-%s.private.plist",lastid);record=read_record(root,saved,0);
   long long format=0;char saved_id[40];
   if(!record||!integer_at(record,CFSTR("format"),&format)||format!=1||true_at(record,CFSTR("fixture"))!=ENVSCOPE_COMPONENT_FIXTURE||!get_text(record,CFSTR("id"),saved_id,sizeof(saved_id))||strcmp(saved_id,lastid)||!eq(record,last,CFSTR("roles"))||!eq(record,plan,CFSTR("roles"))||!get_text(record,CFSTR("actor"),saved_owner,sizeof(saved_owner))||strcmp(saved_owner,owner)){if(record)CFRelease(record);CFRelease(last);return 79;}
   CFRelease(last);before=CFDictionaryGetValue(record,CFSTR("before"));if(!is_array(before)||!publish(root,record,"prepared")||!restore_rows(before)){publish(root,record,"partial");CFRelease(record);return 74;}
  int ok=publish(root,record,"restored");CFRelease(record);return ok?0:74;
 }
 if(!strcmp(phase,"prepared")||!strcmp(phase,"partial")||!is_array(before)){CFRelease(last);return 79;}CFRelease(last);
 CFMutableArrayRef actual=array();
 for(CFIndex j=0;j<CFArrayGetCount(requested);j++){CFStringRef wanted=CFArrayGetValueAtIndex(requested,j);int i;for(i=0;i<4;i++){CFStringRef s=string(roles[i].id);int yes=CFEqual(wanted,s);CFRelease(s);if(yes)break;}if(i==4)goto invalid;
  for(CFIndex k=0;k<j;k++)if(CFEqual(wanted,CFArrayGetValueAtIndex(requested,k)))goto invalid;
  CFDictionaryRef original=NULL;for(CFIndex k=0;k<CFArrayGetCount(before);k++){CFDictionaryRef row=CFArrayGetValueAtIndex(before,k);if(is_dict(row)&&CFEqual(wanted,CFDictionaryGetValue(row,CFSTR("id"))?:CFSTR("")))original=row;}
  CFMutableDictionaryRef now=snapshot_row(i);if(!original||!now||!true_at(now,CFSTR("present"))||!same(now,original)||!eq(now,original,CFSTR("running"))){if(now)CFRelease(now);goto invalid;}
  CFArrayAppendValue(actual,now);CFRelease(now);
 }
 {char filename[90];snprintf(filename,sizeof(filename),"record-%s.private.plist",id);struct stat s;if(!fstatat(root,filename,&s,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto invalid;}
 record=dict();CFNumberRef format=CFNumberCreate(NULL,kCFNumberIntType,&(int){1});CFDictionarySetValue(record,CFSTR("format"),format);CFRelease(format);
 text(record,CFSTR("actor"),owner);text(record,CFSTR("id"),id);text(record,CFSTR("release"),ENVSCOPE_RELEASE);boolean(record,CFSTR("fixture"),ENVSCOPE_COMPONENT_FIXTURE);CFDictionarySetValue(record,CFSTR("roles"),requested);CFDictionarySetValue(record,CFSTR("before"),actual);
 if(!publish(root,record,"prepared")){CFRelease(actual);CFRelease(record);return 74;}
 for(CFIndex j=0;j<CFArrayGetCount(actual);j++){CFDictionaryRef row=CFArrayGetValueAtIndex(actual,j);char role[40];get_text(row,CFSTR("id"),role,sizeof(role));int i;for(i=0;i<4;i++)if(!strcmp(role,roles[i].id))break;
  if(true_at(row,CFSTR("registered"))&&!job_change(i,0))goto rollback;
  CFMutableDictionaryRef now=snapshot_row(i);if(!now||true_at(now,CFSTR("registered"))||!eq(now,row,CFSTR("definition_sha"))||!eq(now,row,CFSTR("script_sha"))){if(now)CFRelease(now);goto rollback;}CFRelease(now);
  if(!file_change(i,row,0))goto rollback;
  now=snapshot_row(i);int ok=now&&!true_at(now,CFSTR("present"))&&!true_at(now,CFSTR("registered"));if(now)CFRelease(now);if(!ok)goto rollback;
 }
 {int ok=publish(root,record,"committed");CFRelease(actual);CFRelease(record);return ok?0:74;}
rollback:{int ok=restore_rows(actual);publish(root,record,ok?"rolled_back":"partial");CFRelease(actual);CFRelease(record);return 74;}
invalid:CFRelease(actual);return 79;
}
#include "components_software.h"
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--version")){printf("{\"format\":1,\"release\":\"%s\",\"fixture\":%s}\n",ENVSCOPE_RELEASE,ENVSCOPE_COMPONENT_FIXTURE?"true":"false");return 0;}
 if(!realpath(argv[0],self_path))return 65;
 if(argc==3&&!strcmp(argv[1],"--user-job")){if(geteuid()!=0||!set_actor(argv[2])||!drop_actor())return 77;CFMutableDictionaryRef v=job(3);if(!v)return 74;int ok=emit(v);CFRelease(v);return ok?0:74;}
 int software=argc>1&&(!strcmp(argv[1],"--retire-files")||!strcmp(argv[1],"--restore-files"));
 if(argc!=5||(!software&&strcmp(argv[1],"--retire")&&strcmp(argv[1],"--restore"))||geteuid()!=0||!hex(argv[3],64))return 65;
 actor=0;int root=directory(ENVSCOPE_COMPONENT_ROOT,0);if(root<0||!safe_fd(root,0,1))return 77;
 int lock=openat(root,".transaction.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);if(lock<0||!safe_fd(lock,0,0)||flock(lock,LOCK_EX|LOCK_NB)){if(lock>=0)close(lock);close(root);return 75;}
 int input=open(argv[2],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat info;if(input<0||fstat(input,&info)||!S_ISREG(info.st_mode)||info.st_nlink!=1||info.st_size>LIMIT){if(input>=0)close(input);close(lock);close(root);return 65;}
 UInt8 *bytes=malloc(LIMIT+1);if(!bytes)return 74;size_t n=0;while(n<LIMIT+1){ssize_t got=read(input,bytes+n,LIMIT+1-n);if(got<0&&errno==EINTR)continue;if(got<=0)break;n+=(size_t)got;}close(input);
 CFDataRef raw=n<=LIMIT?CFDataCreate(NULL,bytes,(CFIndex)n):NULL;free(bytes);if(!raw)return 65;char sha[65];hash(raw,sha);if(strcmp(sha,argv[3])){CFRelease(raw);return 79;}
 CFMutableDictionaryRef plan=parse(raw);CFRelease(raw);if(!plan)return 65;
 /* argv[4] binds the reviewed ordinary user's identity, independently of data. */
 char owner[32];if(!get_text(plan,CFSTR("actor"),owner,sizeof(owner))||strcmp(owner,argv[4])){CFRelease(plan);return 79;}
 int result=software?software_execute(root,plan,!strcmp(argv[1],"--restore-files")):execute(root,plan,!strcmp(argv[1],"--restore"));CFRelease(plan);close(lock);close(root);return result;
}
