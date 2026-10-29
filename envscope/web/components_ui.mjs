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
