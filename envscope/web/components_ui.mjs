const $=id=>document.getElementById(id);
const el=(tag,text)=>{const node=document.createElement(tag);node.textContent=text;return node;};
let last={},locked=false,loaded=false;
const selected=new Set();
const eligible=row=>row.owned===true&&row.present===true&&!row.error&&typeof row.registered==='boolean'&&typeof row.enabled==='boolean';
const pending=value=>['prepared','partial'].includes(value.state);

export function renderComponents(value=last,busy=false){
  if(!$('components-panel'))return;
  last=value;locked=busy;
  const names={not_checked:'尚未读取',unavailable:'需要手动核对',not_configured:'尚未迁移',prepared:'上次操作未完成',partial:'需要恢复或手动核对',committed:'旧任务已移除，恢复副本保留',restored:'已恢复原任务',rolled_back:'上次操作已回滚'};
  $('components-state').textContent=names[value.state]||'状态待核实';
  $('components-status').textContent=[value.reason,value.cached?'上次读取距今 '+value.cache_age_seconds+' 秒；执行前会重新核对。':''].filter(Boolean).join(' ');
  $('components-status').classList.toggle('manual-guidance',pending(value)||value.state==='unavailable');
  const old=[...selected],rows=value.rows||[];
  for(const id of old)if(!rows.some(r=>r.id===id&&eligible(r)))selected.delete(id);
  const nodes=rows.map(row=>{
    const box=el('div',''),label=el('label',''),input=document.createElement('input');
    input.type='checkbox';input.dataset.role=row.id;input.checked=selected.has(row.id);input.disabled=busy||!eligible(row)||pending(value)||value.state==='committed';
    const state=row.error||row.present===null||row.registered===null?'未核实':row.present===false&&row.registered===false?'未安装':row.enabled===false?'已暂停':row.running===true?'正在运行':row.registered===true?'已登记，当前未运行':'文件保留，尚未登记';
    label.className='checkbox';label.append(input,document.createTextNode(row.title+' · '+state));box.append(label);
    const note=el('p',row.reason||row.label+(row.path?' · '+row.path:''));note.className='note';box.append(note);
    if(row.error||!row.owned){
      note.classList.add('manual-guidance');note.append(document.createTextNode(' 请由原用户或管理员核对任务的程序路径与账户。Windows：任务计划程序 → 任务计划程序库 → 对应名称 → 属性。macOS：核对所列 launchd 定义与系统权限。先保存原定义，不删除账号目录；未核实的任务不自动停用。'));
    }
    input.addEventListener('change',()=>{input.checked?selected.add(row.id):selected.delete(row.id);$('components-plan').replaceChildren();renderComponents();});
    return box;
  });
  $('components-rows').replaceChildren(...nodes);
  const choices=rows.filter(eligible),count=choices.filter(r=>selected.has(r.id)).length;
  $('components-all').checked=choices.length>0&&count===choices.length;$('components-all').indeterminate=count>0&&count<choices.length;
  $('components-all').disabled=busy||!choices.length||pending(value)||value.state==='committed';
  $('components-read').disabled=busy;$('components-prepare').disabled=busy||!count||pending(value)||value.state==='committed';
  $('components-restore').disabled=busy||!value.can_restore;
}

export function initComponents({action,retest}){
  const clear=()=>$('components-plan').replaceChildren();
  async function read(){
    clear();const value=await action('components-status',{},'components-output');
    if(!value)return;
    if(!loaded)for(const row of value.rows||[])if(eligible(row))selected.add(row.id);
    loaded=true;renderComponents(value);
  }
  $('components-read').addEventListener('click',read);
  document.querySelector('[data-page="upkeep"]').addEventListener('click',()=>{if(!loaded)void read();});
  $('components-all').addEventListener('change',()=>{
    const checked=$('components-all').checked;selected.clear();if(checked)for(const row of last.rows||[])if(eligible(row))selected.add(row.id);
    clear();renderComponents();
  });
  for(const event of ['envscope-audit-start','envscope-target-editing'])document.addEventListener(event,clear);
  async function plan(restore=false){
    clear();const value=await action('components-plan',restore?{restore:true}:{roles:[...selected]},'components-output');
    $('components-output').classList.toggle('manual-guidance',!!value&&value.state!=='planned');
    if(value?.state!=='planned')return;
    const choice=[...selected].sort().join('|'),list=el('ul','');for(const text of value.effects||[])list.append(el('li',text));
    const button=el('button',restore?'确认恢复原任务并复检':'确认停用所选旧任务并复检');
    button.addEventListener('click',async()=>{
      if(!restore&&choice!==[...selected].sort().join('|')){clear();return;}
      button.disabled=true;
      const result=await action('components-apply',{plan_id:value.plan_id},'components-output',true);
      clear();$('components-output').classList.toggle('manual-guidance',!!result&&!['completed','restored'].includes(result.state));
      if(result?.needs_retest&&retest)await retest();
    });
    $('components-plan').append(el('h3',restore?'恢复整笔原任务事务':'停用所选旧后台任务'),list,button);
  }
  $('components-prepare').addEventListener('click',()=>plan());
  $('components-restore').addEventListener('click',()=>plan(true));
}

let softwareLast={},softwareLoaded=false;
const softwareSelected=new Set();
export function renderSoftware(value=softwareLast,busy=false){
  if(!$('software-panel'))return;
  softwareLast=value;
  const states={not_checked:'尚未读取',not_configured:'尚未清理',prepared:'上次操作未完成',retiring_jobs:'正在停用旧任务',moving:'程序移动待核对',restoring:'程序恢复待核对',partial:'需要恢复或手动核对',committed:'所选程序已清理，存档保留',restored:'旧程序已恢复',invalid:'恢复记录无法核实'};
  const rows=value.rows||[],choices=rows.filter(r=>r.eligible===true&&r.present===true);
  const blocked=!!value.can_restore;
  for(const id of [...softwareSelected])if(!choices.some(r=>r.id===id))softwareSelected.delete(id);
  $('software-state').textContent=states[value.state]||'状态待核对';
  const attention=rows.filter(r=>r.present!==false&&r.eligible!==true).length;
  $('software-status').textContent=[value.reason,attention?attention+' 项需手动核对，请展开下方程序清单。':'',choices.length?'发现 '+choices.length+' 项可清理程序。':''].filter(Boolean).join(' ');
  $('software-status').classList.toggle('manual-guidance',attention>0||value.needs_recovery||value.state==='invalid');
  $('software-rows').replaceChildren(...rows.map(row=>{
    const box=el('div',''),label=el('label',''),input=document.createElement('input');input.type='checkbox';input.dataset.software=row.id;
    input.checked=softwareSelected.has(row.id);input.disabled=busy||blocked||row.eligible!==true||row.present!==true;
    const state=row.present===false?'未安装':row.eligible===true?'可清理':'需手动核对';
    const titles={core:'核心脚本',ui:'旧版界面',guard:'进程守护脚本',timezone:'时区守护脚本',shortcut:'桌面快捷方式',app:'桌面应用',stun:'UDP 探测脚本','core.backup':'核心脚本旧副本','guard.backup':'进程守护旧副本','timezone.backup':'时区守护旧副本','template.guard':'进程守护安装模板','template.timezone':'时区守护安装模板','template.update':'更新任务安装模板','system.guard':'系统进程守护脚本','system.timezone':'系统时区守护脚本','system.core':'系统核心旧脚本'};
    label.className='checkbox';label.append(input,document.createTextNode((titles[row.id]||row.id)+' · '+state));
    const note=el('p',row.path+(row.reason?' · '+row.reason:''));note.className='note';
    if(row.present!==false&&row.eligible!==true){note.classList.add('manual-guidance');note.append(document.createTextNode(' 先退出旧界面与脚本，由原用户或管理员核对所列路径；保存副本后只移走程序文件，保留 .claude-switcher 内的 accounts、current、keepdata 和凭据。'));
    }
    input.addEventListener('change',()=>{input.checked?softwareSelected.add(row.id):softwareSelected.delete(row.id);$('software-plan').replaceChildren();renderSoftware();});
    box.append(label,note);return box;
  }));
  const count=choices.filter(r=>softwareSelected.has(r.id)).length;
  $('software-all').checked=count>0&&count===choices.length;$('software-all').indeterminate=count>0&&count<choices.length;
  $('software-all').disabled=busy||blocked||!choices.length;$('software-read').disabled=busy;
  $('software-prepare').disabled=busy||blocked||!count;$('software-restore').disabled=busy||!value.can_restore;
}

export function initSoftware({action,retest}){
  const clear=()=>$('software-plan').replaceChildren();
  async function read(){
    clear();const value=await action('software-status',{},'legacy-software-output');if(!value)return;
    if(!softwareLoaded)for(const row of value.rows||[])if(row.eligible===true&&row.present===true)softwareSelected.add(row.id);
    softwareLoaded=true;renderSoftware(value);
  }
  $('software-read').addEventListener('click',read);
  document.querySelector('[data-page="upkeep"]').addEventListener('click',()=>{
    if(softwareLoaded)return;
    // The task inventory starts first on this page. Queue this read so the
    // shared operation lock does not silently discard the second inventory.
    void(async()=>{
      for(let i=0;i<2400;i++){
        if(softwareLoaded||$('page-upkeep').hidden)return;
        if(document.documentElement.dataset.operationBusy!=='true'&&!$('start').disabled){await read();return;}
        await new Promise(resolve=>setTimeout(resolve,100));
      }
    })();
  });
  $('software-all').addEventListener('change',()=>{
    const checked=$('software-all').checked;softwareSelected.clear();
    if(checked)for(const row of softwareLast.rows||[])if(row.eligible===true&&row.present===true)softwareSelected.add(row.id);
    clear();renderSoftware();
  });
  for(const event of ['envscope-audit-start','envscope-target-editing'])document.addEventListener(event,clear);
  async function plan(restore=false){
    clear();const value=await action('software-plan',restore?{restore:true}:{roles:[...softwareSelected]},'legacy-software-output');
    $('legacy-software-output').classList.toggle('manual-guidance',!!value&&value.state!=='planned');if(value?.state!=='planned')return;
    const list=el('ul','');for(const effect of value.effects||[])list.append(el('li',effect));
    const choice=[...softwareSelected].sort().join('|');
    const button=el('button',restore?'确认恢复旧程序并复检':'确认清理所选旧软件并复检');
    button.addEventListener('click',async()=>{
      if(!restore&&choice!==[...softwareSelected].sort().join('|')){clear();return;}button.disabled=true;
      const result=await action('software-apply',{plan_id:value.plan_id},'legacy-software-output',true);clear();
      $('legacy-software-output').classList.toggle('manual-guidance',!!result&&!['completed','restored'].includes(result.state));
      if(result?.needs_retest&&retest)await retest();
    });
    $('software-plan').append(el('h3',restore?'恢复旧程序，后台任务保持停用':'清理所选旧软件，保留账号'),list,button);
  }
  $('software-prepare').addEventListener('click',()=>plan());$('software-restore').addEventListener('click',()=>plan(true));
}
