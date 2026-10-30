/* Restricted Windows timezone worker. No shell, user scripts or network. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>
#include <string.h>

#ifndef ENVSCOPE_RELEASE
#define ENVSCOPE_RELEASE "development"
#endif
#ifndef ENVSCOPE_FIXTURE
#define ENVSCOPE_FIXTURE 0
#endif
static wchar_t root[MAX_PATH], target[128], observed[128];
static int fixture = ENVSCOPE_FIXTURE;
#if ENVSCOPE_FIXTURE
static int live_clock=0;
#endif
static long long epoch;

static int system_identity(void) {
    HANDLE token=NULL;BYTE user[1024],sid[SECURITY_MAX_SID_SIZE];DWORD used=0,size=sizeof(sid);int ok=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 0;
    if(GetTokenInformation(token,TokenUser,user,sizeof(user),&used)&&CreateWellKnownSid(WinLocalSystemSid,NULL,sid,&size))ok=EqualSid(((TOKEN_USER*)user)->User.Sid,sid);
    CloseHandle(token);return ok;
}
static int drop_privileges(void) {
    HANDLE token=NULL;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&token))return 0;
    int ok=AdjustTokenPrivileges(token,TRUE,NULL,0,NULL,NULL);CloseHandle(token);return ok;
}

static int path_for(wchar_t *out, const wchar_t *name) {
    return swprintf(out, MAX_PATH, L"%ls\\%ls", root, name) > 0 && wcslen(out) < MAX_PATH-1;
}
static int safe_file(const wchar_t *path, int optional) {
    DWORD attributes=GetFileAttributesW(path);
    if(attributes==INVALID_FILE_ATTRIBUTES)return optional && GetLastError()==ERROR_FILE_NOT_FOUND;
    if(attributes & FILE_ATTRIBUTE_REPARSE_POINT)return 0;
    if(fixture)return 1;
    PSID owner=NULL; PACL acl=NULL; PSECURITY_DESCRIPTOR sd=NULL;
    BYTE system[SECURITY_MAX_SID_SIZE], admins[SECURITY_MAX_SID_SIZE];
    DWORD a=sizeof(system), b=sizeof(admins); int ok=1;
    if(!CreateWellKnownSid(WinLocalSystemSid,NULL,system,&a) || !CreateWellKnownSid(WinBuiltinAdministratorsSid,NULL,admins,&b))return 0;
    if(GetNamedSecurityInfoW((LPWSTR)path,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,NULL,&acl,NULL,&sd)!=ERROR_SUCCESS)return 0;
    if(!owner || !acl || (!EqualSid(owner,system) && !EqualSid(owner,admins)))ok=0;
    for(DWORD i=0;ok && i<acl->AceCount;i++) {
        void *raw=NULL; if(!GetAce(acl,i,&raw)){ok=0;break;}
        ACE_HEADER *header=(ACE_HEADER*)raw;
        if(header->AceFlags & INHERIT_ONLY_ACE)continue;
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE && header->AceType!=ACCESS_DENIED_ACE_TYPE){ok=0;break;}
        if(header->AceType==ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *ace=(ACCESS_ALLOWED_ACE*)raw; PSID sid=(PSID)&ace->SidStart;
            DWORD writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
            if((ace->Mask&writes) && !EqualSid(sid,system) && !EqualSid(sid,admins))ok=0;
        }
    }
    LocalFree(sd);return ok;
}
static int read_value(const wchar_t *file,const wchar_t *key,wchar_t *value,DWORD size) {
    wchar_t path[MAX_PATH];if(!path_for(path,file)||!safe_file(path,0))return 0;
    DWORD n=GetPrivateProfileStringW(L"guard",key,L"",value,size,path);
    return n>0 && n<size-1;
}
static int text_safe(const wchar_t *v) {
    size_t n=wcslen(v);if(!n||n>100)return 0;
    for(size_t i=0;i<n;i++)if(!((v[i]>=L'A'&&v[i]<=L'Z')||(v[i]>=L'a'&&v[i]<=L'z')||(v[i]>=L'0'&&v[i]<=L'9')||wcschr(L" _+-",v[i])))return 0;
    return 1;
}
static int replace_text(const wchar_t *name,const char *data) {
    wchar_t path[MAX_PATH], temp[MAX_PATH];if(!path_for(path,name)||!path_for(temp,L"write.tmp")||!safe_file(path,1)||!safe_file(temp,1))return 0;
    HANDLE h=CreateFileW(temp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(h==INVALID_HANDLE_VALUE)return 0;
    DWORD written=0, size=(DWORD)strlen(data);int ok=WriteFile(h,data,size,&written,NULL)&&written==size&&FlushFileBuffers(h);
    CloseHandle(h);return ok && MoveFileExW(temp,path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
}
static int ascii(const wchar_t *in,char *out,int size) {
    return WideCharToMultiByte(CP_UTF8,0,in,-1,out,size,NULL,NULL)>0;
}
static int own_hash(wchar_t out[65]) {
    wchar_t file[MAX_PATH];BYTE digest[32], buffer[16384];BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;
    if(!GetModuleFileNameW(NULL,file,MAX_PATH)||!safe_file(file,0))return 0;
    HANDLE h=CreateFileW(file,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(h==INVALID_HANDLE_VALUE)return 0;
    int ok=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)==0 && BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0)==0;
    DWORD count;while(ok){if(!ReadFile(h,buffer,sizeof(buffer),&count,NULL)){ok=0;break;}if(!count)break;ok=BCryptHashData(hash,buffer,count,0)==0;}
    if(ok)ok=BCryptFinishHash(hash,digest,sizeof(digest),0)==0;
    if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);CloseHandle(h);
    if(ok){for(int i=0;i<32;i++)swprintf(out+i*2,3,L"%02x",digest[i]);out[64]=0;}return ok;
}
static int read_zone(void) {
#if ENVSCOPE_FIXTURE
    return read_value(L"clock.ini",L"timezone",observed,128)&&text_safe(observed);
#else
    DYNAMIC_TIME_ZONE_INFORMATION value;
    if(GetDynamicTimeZoneInformation(&value)==TIME_ZONE_ID_INVALID)return 0;
    wcscpy_s(observed,128,value.TimeZoneKeyName);return text_safe(observed);
#endif
}
static int write_zone(void) {
#if ENVSCOPE_FIXTURE
    char zone[256], data[512];if(!ascii(target,zone,sizeof(zone)))return 0;
    if(live_clock)snprintf(data,sizeof(data),"[guard]\ntimezone=%s\nat_epoch=live\n",zone);
    else snprintf(data,sizeof(data),"[guard]\ntimezone=%s\nat_epoch=%lld\n",zone,epoch);
    return replace_text(L"clock.ini",data);
#else
    DYNAMIC_TIME_ZONE_INFORMATION zone;int found=0;
    for(DWORD i=0;EnumDynamicTimeZoneInformation(i,&zone)==ERROR_SUCCESS;i++)if(wcscmp(zone.TimeZoneKeyName,target)==0){found=1;break;}
    if(!found)return 0;
    HANDLE token=NULL;TOKEN_PRIVILEGES privileges,previous;DWORD size=sizeof(previous);
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token))return 0;
    privileges.PrivilegeCount=1;privileges.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    int ok=LookupPrivilegeValueW(NULL,SE_TIME_ZONE_NAME,&privileges.Privileges[0].Luid);
    if(ok){SetLastError(ERROR_SUCCESS);ok=AdjustTokenPrivileges(token,FALSE,&privileges,sizeof(previous),&previous,&size)&&GetLastError()==ERROR_SUCCESS;}
    if(ok){zone.DynamicDaylightTimeDisabled=FALSE;ok=SetDynamicTimeZoneInformation(&zone);AdjustTokenPrivileges(token,FALSE,&previous,0,NULL,NULL);}
    CloseHandle(token);return ok;
#endif
}
static int status(const char *state,const wchar_t *attempts,int pending) {
    char t[256],o[256],tries[512],data[2048];if(!ascii(target,t,sizeof(t))||!ascii(observed,o,sizeof(o))||!ascii(attempts,tries,sizeof(tries)))return 0;
    snprintf(data,sizeof(data),"[guard]\nformat=1\nguard_policy=2\nrelease=%s\nfixture=%d\ninitial=%d\nat_epoch=%lld\nstate=%s\ntarget=%s\nobserved=%s\n",ENVSCOPE_RELEASE,fixture,!system_identity(),epoch,state,t,o);
    if(!replace_text(L"status.ini",data))return 0;
    wchar_t prior[64]=L"";read_value(L"state.ini",L"state",prior,64);
    char before[128];ascii(prior,before,sizeof(before));
    if(strcmp(before,state)!=0 || !strcmp(state,"repairing")) {
        SYSTEMTIME now;GetSystemTime(&now);wchar_t name[64],path[MAX_PATH];
        swprintf(name,64,L"events-%04d-%02d-%02d.jsonl",now.wYear,now.wMonth,now.wDay);
        if(!path_for(path,name)||!safe_file(path,1))return 0;
        HANDLE h=CreateFileW(path,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        if(h==INVALID_HANDLE_VALUE)return 0;
        snprintf(data,sizeof(data),"{\"at_epoch\":%lld,\"state\":\"%s\",\"target\":\"%s\",\"observed\":\"%s\",\"fixture\":%s}\n",epoch,state,t,o,fixture?"true":"false");
        DWORD size=(DWORD)strlen(data),written=0;int ok=WriteFile(h,data,size,&written,NULL)&&written==size&&FlushFileBuffers(h);CloseHandle(h);if(!ok)return 0;
    }
    snprintf(data,sizeof(data),"[guard]\nstate=%s\nattempts=%s\npending=%d\n",state,tries,pending);return replace_text(L"state.ini",data);
}
static int once(void) {
    wchar_t file[MAX_PATH],value[512],hash[65];
    if(!safe_file(root,0)||!path_for(file,L"baseline.ini")||!safe_file(file,0))return 72;
    if(!read_value(L"baseline.ini",L"worker_sha256",value,512)||!own_hash(hash)||wcscmp(hash,value))return 73;
    if(!read_value(L"baseline.ini",L"target",target,128)||!text_safe(target)||!read_zone())return 74;
    if(!path_for(file,L"run.lock")||!safe_file(file,1))return 72;
    HANDLE lock=CreateFileW(file,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(lock==INVALID_HANDLE_VALUE)return 75;
    int ok=0;wchar_t attempts[512]=L"", pending[8]=L"", state_path[MAX_PATH];
    path_for(state_path,L"state.ini");
    if(GetFileAttributesW(state_path)!=INVALID_FILE_ATTRIBUTES && (!read_value(L"state.ini",L"pending",pending,8)||!safe_file(state_path,0)||(wcscmp(pending,L"0")&&wcscmp(pending,L"1"))))goto done;
    read_value(L"state.ini",L"attempts",attempts,512);
    if(!wcscmp(pending,L"1")){ok=status("attention",attempts,1);goto done;}
    if(!wcscmp(observed,target)){ok=status("healthy",attempts,0);goto done;}
    long long last=0, values[3];int count=0;wchar_t *cursor=attempts;
    while(*cursor){wchar_t *end;long long stamp=wcstoll(cursor,&end,10);if(end==cursor||(*end&&*end!=L',')){ok=status("attention",attempts,1);goto done;}
        if(stamp>epoch){ok=status("clock_changed",attempts,0);goto done;}
        if(epoch-stamp<86400){if(count==3){ok=status("paused",attempts,0);goto done;}values[count++]=stamp;last=stamp;}cursor=*end?end+1:end;}
    if(count>=3){ok=status("paused",attempts,0);goto done;}
    if(last&&epoch-last<300){ok=status("cooldown",attempts,0);goto done;}
    values[count++]=epoch;attempts[0]=0;
    for(int i=0;i<count;i++){wchar_t entry[64];swprintf(entry,64,L"%ls%lld",i?L",":L"",values[i]);wcscat_s(attempts,512,entry);}
    if(!status("repairing",attempts,1))goto done;
    if(!write_zone()||!read_zone()||wcscmp(observed,target)){ok=status("write_failed",attempts,0);goto done;}
    ok=status("restored",attempts,0);
done:CloseHandle(lock);return ok?0:76;
}
int wmain(int argc,wchar_t **argv) {
    if(argc==2&&!wcscmp(argv[1],L"--version")){printf("{\"format\":1,\"release\":\"%s\",\"fixture\":%s}\n",ENVSCOPE_RELEASE,fixture?"true":"false");return 0;}
    if(argc!=(fixture?3:2)||wcscmp(argv[1],L"--once"))return 64;
    epoch=(long long)time(NULL);
#if ENVSCOPE_FIXTURE
    if(!GetFullPathNameW(argv[2],MAX_PATH,root,NULL))return 64;
    wchar_t stamp[64];if(read_value(L"clock.ini",L"at_epoch",stamp,64)){live_clock=!wcscmp(stamp,L"live");if(!live_clock)epoch=wcstoll(stamp,NULL,10);}
#else
    if(SHGetFolderPathW(NULL,CSIDL_COMMON_APPDATA,NULL,SHGFP_TYPE_CURRENT,root)!=S_OK)return 72;
    wchar_t drive[4]={root[0],L':',L'\\',0};if(root[1]!=L':'||GetDriveTypeW(drive)!=DRIVE_FIXED)return 72;
    wcscat_s(root,MAX_PATH,L"\\EnvScope");if(!safe_file(root,0))return 72;
    wcscat_s(root,MAX_PATH,L"\\TimezoneGuard");
#endif
    if(!drop_privileges())return 77;
    return once();
}
