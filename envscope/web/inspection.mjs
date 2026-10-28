// A visible inventory, including unmeasured rows; no missing result becomes PASS.
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const states={not_run:'尚未检测',pass:'所列范围通过',warn:'需要复核',fail:'需要处理',unknown:'尚未核实',skipped:'本次未测量',not_configured:'未设比较目标',info:'资料项'};
const explained={passed:'通过',review:'需要复核',problem:'发现问题',permission:'需要读取权限',probe_incomplete:'探测未完成',unavailable:'未取得结果',unsupported:'本版未支持',not_applicable:'不适用',informational:'参考资料'};

export function initInspection(){
  let catalog=[],report=null,phase='not_run';
  const navigate=()=>document.querySelector('.tab[data-page="checks"]')?.click();
  $('show-all-checks').addEventListener('click',navigate);
  $('checks-return').addEventListener('click',()=>document.querySelector('.tab[data-page="audit"]')?.click());
  for(const id of ['check-search','check-group','check-status'])$(id).addEventListener(id==='check-search'?'input':'change',render);
  function render(){
    const found=new Map((report?.findings||[]).map(f=>[f.id,f]));
    const known=new Set(catalog.map(c=>c.id));
    const items=[...catalog,...(report?.findings||[]).filter(f=>!known.has(f.id)).map(f=>({id:f.id,title:f.title,label:f.title,group:f.id.startsWith('target.')?'target':'measurement',why:f.id.startsWith('target.')?'按已确认的用途和连接方式，核对本次证据是否达到目标。':'独立记录测量来源和范围；检测目录与补充测量分别列出。'}))];
    const annotations=new Map((report?.assessment?.items||[]).map(i=>[i.id,i]));
    const rows=items.map(c=>({...c,annotation:annotations.get(c.id),finding:found.get(c.id),status:report?(found.get(c.id)?.status||'skipped'):phase==='not_run'?'not_run':'unknown'}));
    rows.sort((a,b)=>Number(!!b.annotation?.required)-Number(!!a.annotation?.required)||Number(b.group==='target')-Number(a.group==='target'));
    const query=$('check-search').value.trim().toLowerCase(),group=$('check-group').value,state=$('check-status').value;
    const selected=rows.filter(c=>(group==='all'||group===c.group)&&(!query||[c.label,c.title,c.id,c.why,c.finding?.summary].join(' ').toLowerCase().includes(query))&&(state==='all'||state==='required'&&c.annotation?.required||state==='attention'&&(c.annotation?['problem','review'].includes(c.annotation.state):['warn','fail'].includes(c.status))||state==='unknown'&&(c.annotation?['permission','probe_incomplete','unavailable'].includes(c.annotation.state):['unknown','skipped','not_configured'].includes(c.status))||state==='excluded'&&['unsupported','not_applicable','informational'].includes(c.annotation?.state)||state==='pass'&&(c.annotation?c.annotation.state==='passed':c.status==='pass')||state==='not_run'&&c.status==='not_run'));
    const basics=rows.filter(r=>r.group==='baseline').length,extras=rows.filter(r=>r.group==='extra').length;
    $('check-count').textContent=`显示 ${selected.length} / ${rows.length} 项。基础 ${basics} 项，扩展 ${extras} 项${rows.length>basics+extras?`，补充测量 ${rows.length-basics-extras} 项`:''}。`;
    const nodes=selected.map(c=>{
      const row=el('details',undefined,'inspection-row');row.dataset.inspection=c.id;
      const summary=el('summary'),name=el('span'),state=el('span',undefined,'inspection-state'),disclosure=el('small','查看说明');
      name.append(el('strong',c.label),el('small',c.title+' · '+({baseline:'基础',extra:'扩展',measurement:'补充测量',target:'目标验收'})[c.group]+(c.annotation?.required?' · 本次必需':'')));state.append(el('span',explained[c.annotation?.state]||states[c.status]||'未取得结果'),disclosure);summary.append(name,state);row.append(summary);
      row.addEventListener('toggle',()=>{disclosure.textContent=row.open?'收起说明':'查看说明';});
      row.append(el('h3','查什么'),el('p',c.why),el('h3','当前结果'),el('p',c.finding?.summary||(phase==='running'?'正在检测，等待本轮证据。':phase==='failed'?'本轮没有完成，请重新检测；未沿用上轮结论。':report?'这份报告未包含该项目。':'尚未测量。点击首页的一键检测后，这里会逐项显示结果。')));
      if(c.annotation)row.append(el('p',c.annotation.reason));
      row.append(el('h3','下一步'),el('p',c.annotation?.next_step||c.finding?.suggestion||c.next_step||'根据实际测量结果处理；无需仅为获得通过而修改环境。'));
      if(c.annotation?.action==='permission-help'){const b=el('button','处理读取权限','link'),out=el('p','');b.type='button';b.addEventListener('click',()=>document.dispatchEvent(new CustomEvent('envscope-permission',{detail:{id:c.id,output:out,button:b}})));row.append(b,out);}
      if(c.upkeep)row.append(el('h3','怎样保持'),el('p',c.upkeep));
      if(c.finding){const technical=el('details');technical.append(el('summary','测量范围与原始证据'),el('p',c.finding.scope,'note'),el('p',(c.finding.limitations||[]).join(' '),'note'),el('pre',JSON.stringify(c.finding.evidence||[],null,2)));row.append(technical);}
      return row;
    });
    $('all-checks-list').replaceChildren(...(nodes.length?nodes:[el('p',catalog.length?'没有符合条件的项目，试试清除搜索或切换筛选。':'检查目录尚未取得，请检查本地服务连接。','note')]));
  }
  document.addEventListener('envscope-catalog',event=>{const next=event.detail.checks||catalog;if(JSON.stringify(next)!==JSON.stringify(catalog)){catalog=next;render();}});
  document.addEventListener('envscope-report',event=>{
    report=event.detail.report;phase='complete';
    $('all-checks-context').textContent=({history:'历史报告',maintenance:'后台巡检',current:'本次检测'})[event.detail.source||'current']+' · '+new Date(report.created_at).toLocaleString()+'。未知与未检测不算通过；历史结果不代表当前状态。';render();
  });
  document.addEventListener('envscope-audit-start',()=>{report=null;phase='running';$('all-checks-context').textContent='本轮正在检测，已清除上轮状态；结果返回后逐项更新。';render();});
  document.addEventListener('envscope-audit-end',event=>{if(!event.detail.has_report){report=null;phase='failed';$('all-checks-context').textContent='本轮检测没有完成，请重新检测；下方保留检查目录。';render();}});
}
