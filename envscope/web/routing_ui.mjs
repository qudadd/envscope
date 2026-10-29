const $=id=>document.getElementById(id);
const el=(tag,text)=>{const node=document.createElement(tag);node.textContent=text;return node;};
export function renderRouting(value={}) {
  if(!$('routing-state'))return;
  const labels={not_configured:'尚未配置',committed:'上次加载已验证',rolled_back:'已恢复原配置',writing:'写入尚未完成',loaded:'等待核对加载结果',rolling_back:'恢复尚未完成',partial:'需要继续恢复',invalid:'恢复记录需手动核对'};
  $('routing-state').textContent=labels[value.state]||'状态待核实';
  $('routing-status').textContent=value.reason||'';
  $('routing-status').classList.toggle('manual-guidance',['writing','loaded','rolling_back','partial','invalid'].includes(value.state));
  $('routing-backup').textContent=value.backup_path?'私有备份：'+value.backup_path:'';
  $('routing-restore').disabled=!value.can_undo;
  $('routing-prepare').disabled=['writing','loaded','rolling_back','partial','invalid'].includes(value.state);
}
export function initRouting({action,reportId,retest}) {
  const clear=()=>$('routing-plan').replaceChildren();
  $('routing-group').addEventListener('change',clear);
  document.addEventListener('envscope-audit-start',clear);
  async function plan(restore=false){
    clear();const group=$('routing-group').value;
    const result=await action(restore?'routing-undo-plan':'routing-plan',restore?{}:{report_id:reportId(),group},'routing-output');
    if(result?.state!=='planned')return;
    const list=el('ul','');for(const effect of result.effects||[])list.append(el('li',effect));
    const apply=el('button',restore?'确认恢复原路由配置':'确认配置并验证路由');
    apply.addEventListener('click',async()=>{
      if(!restore&&group!==$('routing-group').value){clear();return;}
      apply.disabled=true;
      const value=await action(restore?'routing-undo':'routing-apply',{plan_id:result.plan_id},'routing-output',true);
      clear();
      if(value?.needs_retest&&retest)await retest();
    });
    $('routing-plan').append(el('h3',restore?'恢复范围':'将执行这些修改'),list);
    if(result.rules?.length){const details=el('details','');details.append(el('summary','查看 16 条目标规则'),el('pre',result.rules.join('\n')));$('routing-plan').append(details);}
    $('routing-plan').append(apply);
  }
  $('routing-load').addEventListener('click',async()=>{
    clear();const value=await action('routing-options',{},'routing-output');if(!value)return;
    const previous=$('routing-group').value,rows=[el('option','按已确认目标 / 唯一可用组')];rows[0].value='';
    for(const name of value.groups||[]){const option=el('option',name);option.value=name;rows.push(option);}
    $('routing-group').replaceChildren(...rows);
    if(rows.some(row=>row.value===previous))$('routing-group').value=previous;
    $('routing-output').classList.toggle('manual-guidance',value.state==='guided');
  });
  $('routing-prepare').addEventListener('click',()=>plan());
  $('routing-restore').addEventListener('click',()=>plan(true));
}
