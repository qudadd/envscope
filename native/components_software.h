/* Fixed system program quarantine. Included by components_worker.c so it uses
 * the same root staging, identity binding, no-link traversal and transaction
 * lock. No installed script is executed by these entry points. */
static const char *software_ids[]={"guard","timezone","core"};
static const char *software_files[]={"claude-bodyguard.sh","tz-watchdog.sh","claude-switch.sh"};
static int software_index(CFDictionaryRef row){
 char id[40];if(!is_dict(row)||!get_text(row,CFSTR("id"),id,sizeof(id)))return -1;
 for(int i=0;i<3;i++)if(!strcmp(id,software_ids[i]))return i;return -1;
}
static CFMutableDictionaryRef software_row(int parent,int i){
 int absent=0;CFDataRef raw=read_at(parent,software_files[i],0,&absent);if(!raw&&!absent)return NULL;
 CFMutableDictionaryRef row=dict();text(row,CFSTR("id"),software_ids[i]);boolean(row,CFSTR("present"),!absent);
 if(raw){
  const char *first[]={"Claude","tz-watchdog.log","claude-switch"};
  const char *second[]={"claude-bodyguard.log","settimezone","checkdetail"};
  size_t n=(size_t)CFDataGetLength(raw);char *body=malloc(n+1);
  if(!body){CFRelease(raw);CFRelease(row);return NULL;}memcpy(body,CFDataGetBytePtr(raw),n);body[n]=0;
  int recognized=!memchr(body,0,n)&&strstr(body,first[i])&&strstr(body,second[i]);free(body);
  struct stat s;char sha[65];hash(raw,sha);CFRelease(raw);
  if(!recognized||fstatat(parent,software_files[i],&s,AT_SYMLINK_NOFOLLOW)){CFRelease(row);return NULL;}
  text(row,CFSTR("sha256"),sha);number_at(row,CFSTR("mode"),s.st_mode&0777);number_at(row,CFSTR("group"),s.st_gid);
 }return row;
}
static int software_equal(CFDictionaryRef actual,CFDictionaryRef approved){
 if(!actual||!is_dict(approved)||!eq(actual,approved,CFSTR("present")))return 0;
 if(!true_at(actual,CFSTR("present")))return 1;
 return eq(actual,approved,CFSTR("sha256"))&&eq(actual,approved,CFSTR("mode"))&&eq(actual,approved,CFSTR("group"));
}
static int software_jobs_absent(void){
 for(int i=0;i<4;i++){CFMutableDictionaryRef row=snapshot_row(i);int ok=row&&!true_at(row,CFSTR("present"))&&!true_at(row,CFSTR("registered"));if(row)CFRelease(row);if(!ok)return 0;}return 1;
}
static int software_publish(int root,CFMutableDictionaryRef record,const char *phase){
 char id[40],name[100];if(!get_text(record,CFSTR("id"),id,sizeof(id))||!hex(id,32))return 0;
 text(record,CFSTR("state"),phase);snprintf(name,sizeof(name),"software-record-%s.private.plist",id);
 if(!save(root,name,record,0600)||!save(root,"software-latest.plist",record,0644))return 0;
 int fd=openat(root,"software-events.private.jsonl",O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);
 char line[240];int n=snprintf(line,sizeof(line),"{\"at_epoch\":%lld,\"transaction\":\"%s\",\"phase\":\"%s\"}\n",(long long)time(NULL),id,phase);
 int ok=fd>=0&&safe_fd(fd,0,0)&&write_all(fd,line,(size_t)n)&&!fsync(fd);if(fd>=0)close(fd);return ok;
}
static int software_execute(int root,CFDictionaryRef plan,int restoring){
 const char *step="validate-input";
 char id[40],owner[32],expected[40],lastid[40]="",phase[40]="";long long format=0;
 CFArrayRef selected=CFDictionaryGetValue(plan,CFSTR("roles")),before=CFDictionaryGetValue(plan,CFSTR("before"));
 if(!integer_at(plan,CFSTR("format"),&format)||format!=1||!get_text(plan,CFSTR("id"),id,sizeof(id))||!hex(id,32)
    ||!get_text(plan,CFSTR("actor"),owner,sizeof(owner))||!set_actor(owner)
    ||!get_text(plan,CFSTR("expected_record"),expected,sizeof(expected))||!is_array(selected)||CFArrayGetCount(selected)<1||CFArrayGetCount(selected)>3)return 65;
 CFMutableDictionaryRef last=read_record(root,"software-latest.plist",1),record=NULL;
 if(!last)return 78;get_text(last,CFSTR("id"),lastid,sizeof(lastid));get_text(last,CFSTR("state"),phase,sizeof(phase));
 if(strcmp(lastid,expected)){CFRelease(last);return 79;}
 if(CFDictionaryGetCount(last)&&(!integer_at(last,CFSTR("format"),&format)||format!=1||!hex(lastid,32)
    ||true_at(last,CFSTR("fixture"))!=ENVSCOPE_COMPONENT_FIXTURE||!eq(last,plan,CFSTR("actor")))){CFRelease(last);return 79;}
 if(restoring){
  char filename[100];if(strcmp(lastid,id)||(strcmp(phase,"prepared")&&strcmp(phase,"moving")&&strcmp(phase,"partial")&&strcmp(phase,"committed")&&strcmp(phase,"restoring"))){CFRelease(last);return 79;}
  snprintf(filename,sizeof(filename),"software-record-%s.private.plist",id);record=read_record(root,filename,0);
  if(!record||!eq(record,last,CFSTR("id"))||!eq(record,plan,CFSTR("actor"))||!eq(record,plan,CFSTR("roles"))
      ||!eq(record,last,CFSTR("before"))||true_at(record,CFSTR("fixture"))!=ENVSCOPE_COMPONENT_FIXTURE){if(record)CFRelease(record);CFRelease(last);return 79;}
  before=CFDictionaryGetValue(record,CFSTR("before"));
 }else{
  if(CFDictionaryGetCount(last)&&strcmp(phase,"restored")){CFRelease(last);return 79;}
 }
 CFRelease(last);
 if(!is_array(before)||!software_jobs_absent()){fprintf(stderr,"legacy-programs: old-jobs-or-plan-unverified\n");if(record)CFRelease(record);return 79;}
 int source=directory(ENVSCOPE_COMPONENT_SOURCE,0);if(source<0){if(record)CFRelease(record);return 77;}
 CFMutableArrayRef originals=array();
 step="compare-programs";
 for(CFIndex j=0;j<CFArrayGetCount(selected);j++){
  CFStringRef wanted=CFArrayGetValueAtIndex(selected,j);int i;
  for(i=0;i<3;i++){CFStringRef s=string(software_ids[i]);int found=CFEqual(wanted,s);CFRelease(s);if(found)break;}
  if(i==3)goto invalid_software;
  for(CFIndex k=0;k<j;k++)if(CFEqual(wanted,CFArrayGetValueAtIndex(selected,k)))goto invalid_software;
  CFDictionaryRef approved=NULL;for(CFIndex k=0;k<CFArrayGetCount(before);k++){CFDictionaryRef candidate=CFArrayGetValueAtIndex(before,k);if(software_index(candidate)==i){if(approved)goto invalid_software;approved=candidate;}}
  if(!approved||!true_at(approved,CFSTR("present")))goto invalid_software;
  if(!restoring){CFMutableDictionaryRef now=software_row(source,i);int ok=software_equal(now,approved);if(now)CFRelease(now);if(!ok)goto invalid_software;}
  CFArrayAppendValue(originals,approved);
 }
 if(!record){
  char filename[100];struct stat info;snprintf(filename,sizeof(filename),"software-record-%s.private.plist",id);
  if(!fstatat(root,filename,&info,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto invalid_software;
  record=dict();number_at(record,CFSTR("format"),1);text(record,CFSTR("id"),id);text(record,CFSTR("actor"),owner);
  text(record,CFSTR("release"),ENVSCOPE_RELEASE);boolean(record,CFSTR("fixture"),ENVSCOPE_COMPONENT_FIXTURE);
  CFDictionarySetValue(record,CFSTR("roles"),selected);CFDictionarySetValue(record,CFSTR("before"),originals);
 }
 step="save-originals";if(!software_publish(root,record,restoring?"restoring":"prepared"))goto failed_software;
 char vault_name[90];snprintf(vault_name,sizeof(vault_name),".envscope-legacy-%s",id);
 step="create-vault";int created=!restoring&&!mkdirat(source,vault_name,0700);
 if(!restoring&&!created&&errno!=EEXIST)goto failed_software;
 int vault=openat(source,vault_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(vault>=0&&created){acl_t empty=acl_init(0);int ok=empty&&!fchmod(vault,0700)&&!acl_set_fd_np(vault,empty,ACL_TYPE_EXTENDED);if(empty)acl_free(empty);if(!ok){close(vault);goto failed_software;}}
 struct stat vault_info;acl_t vault_acl=vault>=0?acl_get_fd_np(vault,ACL_TYPE_EXTENDED):NULL;acl_entry_t entry;
 int private_acl=vault_acl&&acl_get_entry(vault_acl,ACL_FIRST_ENTRY,&entry)!=0;if(vault_acl)acl_free(vault_acl);
 if(vault<0||!safe_fd(vault,0,1)||fstat(vault,&vault_info)||(vault_info.st_mode&0077)||!private_acl){if(vault>=0)close(vault);goto failed_software;}
 if(!software_publish(root,record,restoring?"restoring":"moving")){close(vault);goto failed_software;}
 step="move-and-readback";
 for(CFIndex j=0;j<CFArrayGetCount(originals);j++){
  CFDictionaryRef approved=CFArrayGetValueAtIndex(originals,j);int i=software_index(approved);
  CFMutableDictionaryRef original=software_row(source,i),backup=software_row(vault,i);
  int original_present=original&&true_at(original,CFSTR("present")),backup_present=backup&&true_at(backup,CFSTR("present"));
  int ok=original&&backup&&software_jobs_absent();
  if(restoring&&original_present&&!backup_present&&software_equal(original,approved)){
   CFRelease(original);CFRelease(backup);continue;
  }
  ok=ok&&(restoring?(!original_present&&backup_present&&software_equal(backup,approved)):(original_present&&!backup_present&&software_equal(original,approved)));
  if(original)CFRelease(original);if(backup)CFRelease(backup);
  if(!ok||renameatx_np(restoring?vault:source,software_files[i],restoring?source:vault,software_files[i],RENAME_EXCL)||fsync(source)||fsync(vault)){close(vault);goto failed_software;}
  original=software_row(source,i);backup=software_row(vault,i);
  ok=original&&backup&&(restoring?(software_equal(original,approved)&&!true_at(backup,CFSTR("present"))):(!true_at(original,CFSTR("present"))&&software_equal(backup,approved)));
  if(original)CFRelease(original);if(backup)CFRelease(backup);if(!ok){close(vault);goto failed_software;}
 }
 close(vault);close(source);CFRelease(originals);
 {int ok=software_publish(root,record,restoring?"restored":"committed");CFRelease(record);return ok?0:74;}
failed_software:fprintf(stderr,"legacy-programs: %s incomplete (errno=%d)\n",step,errno);software_publish(root,record,"partial");CFRelease(record);CFRelease(originals);close(source);return 74;
invalid_software:fprintf(stderr,"legacy-programs: %s changed-or-unverified\n",step);if(record)CFRelease(record);CFRelease(originals);close(source);return 79;
}
