const $=id=>document.getElementById(id);
const el=(tag,text)=>{const node=document.createElement(tag);node.textContent=text;return node;};
export function renderTimezoneService(value={},busy=false){
  const panel=$('timezone-service-panel');if(!panel)return;
  panel.hidden=!value.supported;if(panel.hidden)return;
  const labels={not_installed:'尚未授权',active:'系统时区守护正常',waiting:'等待新心跳',attention:'需要处理',unregistered:'注册状态需恢复',recovery_required:'上次操作需恢复',conflict:'另一用户正在管理'};
  $('timezone-service-state').textContent=labels[value.state]||'状态待核实';
  $('timezone-service-status').textContent=[value.reason,value.target?'批准时区：'+value.target:'',value.heartbeat_at?'最近心跳：'+new Date(value.heartbeat_at*1000).toLocaleString():'',value.needs_update?'辅助程序有新版本，请预览更新。':''].filter(Boolean).join(' ');
  $('timezone-service-status').classList.toggle('manual-guidance',['attention','unregistered','recovery_required','conflict'].includes(value.state));
  $('timezone-service-prepare').disabled=busy||!!value.pending||value.state==='conflict';
  $('timezone-service-stop').disabled=busy||!value.installed||!!value.pending||value.state==='conflict'&&!value.owner;
  $('timezone-service-recover').hidden=!value.pending;
  $('timezone-service-recover').disabled=busy;
  $('timezone-service-undo').hidden=!value.can_undo;
  $('timezone-service-undo').disabled=busy;
  $('timezone-service-refresh').disabled=busy;
  $('timezone-service-restore').disabled=busy||!!value.pending;
  $('timezone-service-journal').textContent=value.journal_path?'系统日志与保留备份：'+value.journal_path:'';
}
export function initTimezoneService({action,reportId,retest}){
  const clear=()=>$('timezone-service-plan').replaceChildren();
  $('timezone-service-restore').addEventListener('change',clear);
  document.addEventListener('envscope-audit-start',clear);
  async function plan(mode){
    clear();const restore=$('timezone-service-restore').checked;
    const special={recover:'timezone-service-recovery-plan',undo:'timezone-service-undo-plan'};
    const value=await action(special[mode]||'timezone-service-plan',special[mode]?{}:{report_id:reportId(),remove:mode==='remove',restore},'timezone-service-output');
    $('timezone-service-output').classList.toggle('manual-guidance',!!value&&['blocked','guided','retest_required','recovery_required','partial'].includes(value.state));
    if(value?.state!=='planned')return;
    const list=el('ul','');for(const effect of value.effects||[])list.append(el('li',effect));
    const button=el('button',mode==='recover'?'确认恢复时区服务':mode==='undo'?'确认撤销上次时区操作':mode==='remove'?'确认移除时区守护':'确认配置并申请系统授权');
    button.addEventListener('click',async()=>{
      if(mode==='remove'&&restore!==$('timezone-service-restore').checked){clear();return;}
      button.disabled=true;
      const result=await action(mode==='recover'?'timezone-service-recover':mode==='undo'?'timezone-service-undo':'timezone-service-apply',{plan_id:value.plan_id},'timezone-service-output',true);
      clear();$('timezone-service-output').classList.toggle('manual-guidance',result?.state==='partial');
      if(result?.needs_retest&&retest)await retest();
    });
    $('timezone-service-plan').append(el('h3','将执行这些操作'),list,button);
  }
  $('timezone-service-prepare').addEventListener('click',()=>plan('install'));
  $('timezone-service-stop').addEventListener('click',()=>plan('remove'));
  $('timezone-service-recover').addEventListener('click',()=>plan('recover'));
  $('timezone-service-undo').addEventListener('click',()=>plan('undo'));
  $('timezone-service-refresh').addEventListener('click',async()=>{
    const value=await action('timezone-service-status',{},'timezone-service-output');if(value)renderTimezoneService(value);
  });
}
