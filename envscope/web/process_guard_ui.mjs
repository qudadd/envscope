const $=id=>document.getElementById(id);
const el=(tag,text)=>{const node=document.createElement(tag);node.textContent=text;return node;};
export function renderProcessGuard(value={},settings={}){
  if(!$('process-guard-state'))return;
  const states={disabled:'未启用',waiting:'等待首次心跳',armed:'正在守护',blocked:'连接异常，已确认桌面未运行',attention:'需要手动处理',paused:'目标改变，已暂停',stale:'守护心跳失效',outdated:'需要更新守护任务',schedule_unverified:'系统任务待核实',invalid:'守护记录无法读取'};
  $('process-guard-state').textContent=states[value.state]||'状态待核实';
  $('process-guard-status').textContent=[value.reason,value.heartbeat?'最近心跳：'+new Date(value.heartbeat).toLocaleString():''].filter(Boolean).join(' ');
  $('process-guard-status').classList.toggle('manual-guidance',['blocked','attention','paused','stale','outdated','invalid','schedule_unverified'].includes(value.state));
  $('process-guard-stop').disabled=!value.enabled&&!value.scheduler?.present;
  $('process-guard-interface-row').hidden=settings.connection_mode!=='tun';
  $('process-guard-interface').disabled=settings.connection_mode!=='tun';
  $('process-guard-route').textContent=settings.client==='wireguard'?'WireGuard：核对具体隧道服务、程序路径与摘要，再监测对应网卡。程序更新后需重新审核。':settings.connection_mode==='http_proxy'?'监测当前目标的本机代理端口：'+(settings.target_proxy||'尚未填写；请在检测目标中填写确切地址'):'按当前目标选择实际使用的隧道网卡；自动识别模式只监测所选网卡。';
  $('process-guard-journal').textContent=value.journal_path||'';
  const rows=(value.events||[]).slice().reverse().map(event=>el('p',new Date(event.at).toLocaleString()+' · '+event.text));
  $('process-guard-events').replaceChildren(...(rows.length?rows:[el('p','尚无进程守护事件。')]));
}
export function initProcessGuard({action,reportId}){
  const clear=()=>$('process-guard-plan').replaceChildren();
  $('process-guard-interface').addEventListener('change',clear);
  document.addEventListener('envscope-audit-start',clear);
  $('process-guard-load').addEventListener('click',async()=>{
    clear();const value=await action('guard-options',{},'process-guard-output');if(!value)return;
    const before=$('process-guard-interface').value;
    const rows=[el('option','选择隧道网卡')];rows[0].value='';
    for(const name of value.interfaces||[]){const node=el('option',name);node.value=name;rows.push(node);}
    $('process-guard-interface').replaceChildren(...rows);
    if(rows.some(r=>r.value===before))$('process-guard-interface').value=before;
    if((value.interfaces||[]).length===1&&!$('process-guard-interface').value)$('process-guard-interface').value=value.interfaces[0];
    $('process-guard-output').textContent=value.reason||'未读取到可选网卡，请检查读取权限。';
  });
  $('process-guard-prepare').addEventListener('click',async()=>{
    clear();const interfaceName=$('process-guard-interface').disabled?'':$('process-guard-interface').value;
    const value=await action('guard-plan',{report_id:reportId(),interface:interfaceName},'process-guard-output');
    if(value?.state!=='planned')return;
    const list=document.createElement('ul');for(const effect of value.effects||[])list.append(el('li',effect));
    const apply=el('button','确认启用自动停止保护');
    apply.addEventListener('click',async()=>{
      if(interfaceName!==($('process-guard-interface').disabled?'':$('process-guard-interface').value)){clear();return;}
      apply.disabled=true;await action('guard-enable',{plan_id:value.plan_id},'process-guard-output',true);clear();
    });
    $('process-guard-plan').append(el('h3','请确认自动停止的范围'),list,apply);
  });
  $('process-guard-stop').addEventListener('click',async()=>{await action('guard-disable',{},'process-guard-output',true);clear();});
  $('process-guard-refresh').addEventListener('click',()=>action('guard-status',{},'process-guard-output'));
  $('process-guard-logs').addEventListener('click',()=>action('guard-logs',{},'process-guard-output'));
}
