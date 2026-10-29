// A visible inventory, including unmeasured rows; no missing result becomes PASS.
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const states={not_run:'尚未检测',pass:'所列范围通过',warn:'需要复核',fail:'需要处理',unknown:'尚未核实',skipped:'本次未测量',not_configured:'未设比较目标',info:'资料项'};
const explained={passed:'通过',review:'需要复核',problem:'发现问题',permission:'需要读取权限',probe_incomplete:'探测未完成',unavailable:'未取得结果',unsupported:'本版未支持',not_applicable:'不适用',informational:'参考资料'};

export function initInspection({run,operate,isBusy,retest}){
  let catalog=[],report=null,phase='not_run',selection=new Set(),visible=[],groups=[],source='current',initialized=false,defaultsKey=null;
  const selected=()=>[...selection];
  const output=$('checks-output');
  const button=(text,fn)=>{const b=el('button',text,'link');b.type='button';b.addEventListener('click',fn);return b;};
  const operateHere=fn=>operate(fn,output);
  function invalidate(){$('checks-plan').replaceChildren();$('checks-selected-count').textContent=`已勾选 ${selection.size} 项。所需依赖自动包含；未选项目不算通过。`;$('checks-run').disabled=!selection.size||phase==='running';$('checks-repair').disabled=!selection.size||phase==='running'||!report||source!=='current';}
  async function check(ids=selected()){
    if(isBusy()||phase==='running')return;
    if(!ids.length){output.textContent='请先勾选要检查的项目。';return;}
    await retest(ids);
  }
  function manualItems(items){
    for(const item of items||[]){const row=el('div',undefined,'manual-guidance');row.append(el('strong','需手动处理 · '+item.title));const list=el('ol');for(const step of item.steps||[])list.append(el('li',step));row.append(list);$('checks-plan').append(row);}
  }
  async function prepare(ids=selected()){
    if(!report||source!=='current'){output.textContent='先检测所选项目，再生成当前方案。';return;}
    const value=await run('inspection-plan',{report_id:report.report_id,check_ids:ids,group:$('checks-node-group').value,node:$('checks-node').value});
    $('checks-plan').replaceChildren();output.textContent=value.reason||'';manualItems(value.manual_items);
    if(value.state==='planned'){
      const effects=el('ul');for(const effect of value.effects)effects.append(el('li',effect));
      const apply=button('确认并一键修改',()=>operateHere(async()=>{
        $('checks-plan').replaceChildren();output.textContent='正在按方案处理，请完成系统授权提示…';
        const result=await run('inspection-apply',{plan_id:value.plan_id},true);
        output.textContent=result.reason||'操作已返回，请核对复检结果。';
        output.classList.toggle('inspection-error',['failed','partial','blocked'].includes(result.state));
        for(const r of result.results||[result])for(const step of r.steps||[])if(step.state==='manual')manualItems([{title:step.item,steps:[step.reason]}]);
        for(const b of result.backups||[])$('checks-plan').append(button('撤销 '+b.label,()=>operateHere(async()=>{const undone=await run('solution-undo',{backup_id:b.id},true);output.textContent=undone.reason;await retest(ids);})));
        if(result.needs_retest){await retest(ids);if(result.next_review)await prepare(ids);}
        if(result.state==='waiting_install')$('checks-plan').append(button('安装完成，复检所选',()=>void check(ids)));
        await refreshRecovery();
      }));apply.id='checks-apply';$('checks-plan').prepend(el('h2','本次将修改'),effects,apply);
    }
    if(value.state==='retest_required')$('checks-plan').append(button('检测所选',()=>void check(ids)));
  }
  function renderNodes(){
    const row=groups.find(g=>g.name===$('checks-node-group').value);
    $('checks-node').replaceChildren(new Option('保持不变',''),...(row?.nodes||[]).map(n=>new Option(n+(n===row.now?'（当前）':''),n)));
    invalidate();
  }
  async function loadNodes(){
    const value=await run('region-options');groups=value.groups||[];
    $('checks-node-group').replaceChildren(new Option('选择代理组',''),...groups.map(g=>new Option(g.name,g.name)));
    if(groups.length===1)$('checks-node-group').value=groups[0].name;
    $('checks-node-note').textContent=value.node_reason;renderNodes();
  }
  async function refreshRecovery(){
    // The catalog's record is private local state, displayed only in this session.
    const value=await run('region-recovery');showRecovery(value.recovery);
  }
  function showRecovery(record){
    $('checks-region-undo').hidden=!record;$('checks-region-recovery').replaceChildren();
    if(record){for(const [key,value] of Object.entries(record.changes||{}))$('checks-region-recovery').append(el('p',`${key}：原值 ${record.before?.[key]||'未记录'} → 计划值 ${value}`,'note'));}
  }
  $('checks-run').addEventListener('click',()=>void check());
  $('checks-repair').addEventListener('click',()=>operateHere(()=>prepare()));
  $('checks-select-visible').addEventListener('click',()=>{visible.forEach(id=>selection.add(id));render();});
  $('checks-select-all').addEventListener('click',()=>{selection=new Set(catalog.map(c=>c.id));render();});
  $('checks-select-problems').addEventListener('click',()=>{selection=new Set(Object.entries(report?.repair_options||{}).filter(([,v])=>v.needs_attention).map(([k])=>k));render();});
  $('checks-clear').addEventListener('click',()=>{selection.clear();render();});
  $('checks-load-nodes').addEventListener('click',()=>operateHere(loadNodes));
  $('checks-node-group').addEventListener('change',renderNodes);$('checks-node').addEventListener('change',invalidate);
  $('checks-region-undo').addEventListener('click',()=>{
    $('checks-plan').replaceChildren(el('p','将恢复上方记录的时区、地区格式及节点原值。检测目标保留；后续已经手动改变的值会拒绝覆盖。'),button('确认恢复原值',()=>operateHere(async()=>{const value=await run('region-undo',{},true);output.textContent=value.reason;if(value.needs_retest)await retest(selected());await refreshRecovery();})));
  });
  document.addEventListener('envscope-region-configure',()=>{selection=new Set(['baseline.timezone','baseline.locale','baseline.country']);navigate();$('checks-region-options').open=true;render();void operateHere(loadNodes);});
  const navigate=()=>document.querySelector('.tab[data-page="checks"]')?.click();
  $('show-all-checks').addEventListener('click',navigate);
  $('checks-return').addEventListener('click',()=>document.querySelector('.tab[data-page="audit"]')?.click());
  for(const id of ['check-search','check-group','check-status'])$(id).addEventListener(id==='check-search'?'input':'change',render);
  function render(){
    const found=new Map((report?.findings||[]).map(f=>[f.id,f]));
    const known=new Set(catalog.map(c=>c.id));
    const items=[...catalog,...(report?.findings||[]).filter(f=>!known.has(f.id)).map(f=>({id:f.id,title:f.title,label:f.title,group:f.id.startsWith('target.')?'target':'measurement',why:f.id.startsWith('target.')?'按已确认的用途和连接方式，核对本次证据是否达到目标。':'独立记录测量来源和范围；检测目录与补充测量分别列出。'}))];
    const annotations=new Map((report?.assessment?.items||[]).map(i=>[i.id,i]));
    const rows=items.map(c=>({...c,annotation:annotations.get(c.id)||(report&&c.group==='target'&&!found.has(c.id)?{state:'not_applicable',reason:'所选用途或连接方式不需要此项。',required:false}:null),remedy:report?.repair_options?.[c.id],finding:found.get(c.id),status:report?(found.get(c.id)?.status||'skipped'):phase==='not_run'?'not_run':'unknown'}));
    rows.sort((a,b)=>Number(!!b.annotation?.required)-Number(!!a.annotation?.required)||Number(b.group==='target')-Number(a.group==='target'));
    const query=$('check-search').value.trim().toLowerCase(),group=$('check-group').value,state=$('check-status').value;
    const selected=rows.filter(c=>(group==='all'||group===c.group)&&(!query||[c.label,c.title,c.id,c.why,c.finding?.summary].join(' ').toLowerCase().includes(query))&&(state==='all'||state==='required'&&c.annotation?.required||state==='attention'&&(c.annotation?['problem','review'].includes(c.annotation.state):['warn','fail'].includes(c.status))||state==='unknown'&&(c.annotation?['permission','probe_incomplete','unavailable'].includes(c.annotation.state):['unknown','skipped','not_configured'].includes(c.status))||state==='excluded'&&['unsupported','not_applicable','informational'].includes(c.annotation?.state)||state==='pass'&&(c.annotation?c.annotation.state==='passed':c.status==='pass')||state==='not_run'&&c.status==='not_run'));
    const basics=rows.filter(r=>r.group==='baseline').length,extras=rows.filter(r=>r.group==='extra').length;
    visible=selected.map(c=>c.id);invalidate();
    $('check-count').textContent=`显示 ${selected.length} / ${rows.length} 项。基础 ${basics} 项，扩展 ${extras} 项，其余为目标验收及补充测量。`;
    const nodes=selected.map(c=>{
      const row=el('details',undefined,'inspection-row');row.dataset.inspection=c.id;
      row.dataset.manual=String(!!c.remedy?.manual);
      const summary=el('summary'),name=el('span',undefined,'inspection-name'),state=el('span',undefined,'inspection-state'),disclosure=el('small','查看说明');
      const label=el('label',undefined,'inspection-select'),checkbox=el('input');checkbox.type='checkbox';checkbox.checked=selection.has(c.id);checkbox.setAttribute('aria-label','选择 '+c.label);checkbox.disabled=phase==='running';
      label.append(checkbox);label.addEventListener('click',event=>event.stopPropagation());checkbox.addEventListener('change',()=>{if(checkbox.checked)selection.add(c.id);else selection.delete(c.id);invalidate();});summary.append(label);
      const statusText=c.finding?.scope==='not-selected'?'未勾选 · 未检测':c.remedy?.manual?(c.annotation?.state==='permission'?'需要读取权限 · 需手动处理':'需手动处理'):explained[c.annotation?.state]||states[c.status]||'未取得结果';
      name.append(el('strong',c.label),el('small',c.title+' · '+({baseline:'基础',extra:'扩展',measurement:'补充测量',target:'目标验收'})[c.group]+(c.annotation?.required?' · 本次必需':'')+(report?.selection?.dependencies?.includes(c.id)?' · 依赖测量':'')));state.append(el('span',statusText),disclosure);summary.append(name,state);row.append(summary);
      row.addEventListener('toggle',()=>{disclosure.textContent=row.open?'收起说明':'查看说明';});
      row.append(el('h3','查什么'),el('p',c.why),el('h3','当前结果'),el('p',c.finding?.summary||(phase==='running'?'正在检测，等待本轮证据。':phase==='failed'?'本轮没有完成，请重新检测；未沿用上轮结论。':report?'这份报告未包含该项目。':'尚未测量。点击首页的一键检测后，这里会逐项显示结果。')));
      if(c.annotation)row.append(el('p',c.annotation.reason));
      row.append(el('h3','下一步'),el('p',c.annotation?.next_step||c.finding?.suggestion||c.next_step||'根据实际测量结果处理；无需仅为获得通过而修改环境。'));
      if(c.annotation?.action==='permission-help'){const b=el('button','处理读取权限','link'),out=el('p','');b.type='button';b.addEventListener('click',()=>document.dispatchEvent(new CustomEvent('envscope-permission',{detail:{id:c.id,output:out,button:b}})));row.append(b,out);}
      const actions=el('div',undefined,'actions');actions.append(button('检测本项',()=>void check([c.id])));
      if(c.remedy?.action==='region'||c.remedy?.action==='solution')actions.append(button('预览本项修改',()=>operateHere(()=>prepare([c.id]))));
      if(['baseline.timezone','baseline.locale'].includes(c.id))actions.append(button('打开对应系统设置',()=>operateHere(async()=>{const value=await run('region-settings',{item:c.id.split('.')[1]});output.textContent=value.reason;})));
      const problem=(report?.diagnosis?.problems||[]).find(p=>c.remedy?.problem_ids?.includes(p.id)&&['config-cli','config-desktop','clock-settings','storage-settings','proxy-settings','hosts-file'].includes(p.action));
      if(problem)actions.append(button(problem.action.startsWith('config-')?'备份并打开配置文件':'打开处理位置',()=>operateHere(async()=>{const value=await run('solution-open',{problem_id:problem.id,report_id:report.report_id},problem.action.startsWith('config-'));output.textContent=value.reason;})));
      if(c.remedy?.manual){const manual=el('div',undefined,'manual-guidance');manual.append(el('strong','无法直接自动修复，请按以下步骤处理'));const list=el('ol');for(const step of c.remedy.steps||[])list.append(el('li',step));manual.append(list);row.append(manual);}
      row.append(actions);
      if(c.upkeep)row.append(el('h3','怎样保持'),el('p',c.upkeep));
      if(c.finding){const technical=el('details');technical.append(el('summary','测量范围与原始证据'),el('p',c.finding.scope,'note'),el('p',(c.finding.limitations||[]).join(' '),'note'),el('pre',JSON.stringify(c.finding.evidence||[],null,2)));row.append(technical);}
      return row;
    });
    $('all-checks-list').replaceChildren(...(nodes.length?nodes:[el('p',catalog.length?'没有符合条件的项目，试试清除搜索或切换筛选。':'检查目录尚未取得，请检查本地服务连接。','note')]));
  }
  const applyDefaults=config=>{
    if(!config)return false;
    const key=JSON.stringify(config.default_checks);
    if(defaultsKey!==key){defaultsKey=key;selection=new Set(config.default_checks||catalog.map(c=>c.id));initialized=true;return true;}
    return false;
  };
  document.addEventListener('envscope-check-preferences-changed',event=>{applyDefaults(event.detail);render();});
  document.addEventListener('envscope-catalog',event=>{const next=event.detail.checks||catalog;let changed=false;if(JSON.stringify(next)!==JSON.stringify(catalog)){catalog=next;if(!initialized){selection=new Set(catalog.map(c=>c.id));initialized=true;}changed=true;}if(applyDefaults(event.detail.check_config)||changed)render();showRecovery(event.detail.region_recovery);});
  document.addEventListener('envscope-report',event=>{
    report=event.detail.report;phase='complete';source=event.detail.source||'current';
    $('all-checks-context').textContent=({history:'历史报告',maintenance:'后台巡检',current:'本次检测'})[source]+' · '+new Date(report.created_at).toLocaleString()+(report.selection?.mode==='selected'?' · 部分检查':' · 全部检查')+'。未知与未检测不算通过；历史结果不代表当前状态。';render();
  });
  document.addEventListener('envscope-audit-start',()=>{report=null;phase='running';$('all-checks-context').textContent='本轮正在检测，已清除上轮状态；结果返回后逐项更新。';render();});
  document.addEventListener('envscope-target-changed',()=>{report=null;phase='not_run';render();});
  document.addEventListener('envscope-audit-end',event=>{if(!event.detail.has_report){report=null;phase='failed';$('all-checks-context').textContent='本轮检测没有完成，请重新检测；下方保留检查目录。';render();}});
}
