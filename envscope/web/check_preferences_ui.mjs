// Saved defaults are shared by one-click and background checks. Raw failures stay visible.
const $=id=>document.getElementById(id);

export function initCheckPreferences({action,retest}){
  let dirty=false,last=null,confirmedTarget=false;
  const form=$('check-preferences-form');
  form.addEventListener('change',()=>{dirty=true;});
  function render(config,diagnostics){
    if(!config)return;
    if(!dirty||!last){
      for(const input of form.querySelectorAll('[name="optional"]'))input.checked=!(config.disabled||[]).includes(input.value);
      $('optional-failures').checked=config.allow_optional_failures===true;
      $('diagnostic-logging').checked=config.logging===true;
    }
    for(const group of config.groups||[]){
      const node=$('optional-required-'+group.id);
      if(node)node.textContent=group.required?.length?'所选目标需要的检查会保留。':'';
    }
    $('diagnostic-log-state').textContent=diagnostics?.state==='unavailable'?'命令日志未能读取，检测和修复结果单独保留。':
      config.logging?`仅记录命令、时间、耗时与状态；当前 ${diagnostics?.entries??0} 条。每份最多 512 KiB，保留两份。`:
      '命令日志已关闭；不新增记录，导出也不包含旧命令日志。修复备份与守护留痕仍保留。';
    last=config;
  }
  document.addEventListener('envscope-catalog',event=>{confirmedTarget=event.detail.settings?.environment_confirmed===true;render(event.detail.check_config,event.detail.diagnostics);});
  form.addEventListener('submit',async event=>{
    event.preventDefault();
    const disabled=[...form.querySelectorAll('[name="optional"]')].filter(n=>!n.checked).map(n=>n.value);
    const changed=JSON.stringify([...disabled].sort())!==JSON.stringify(last?.disabled||[])||$('optional-failures').checked!==last?.allow_optional_failures;
    const result=await action('check-config-save',{disabled,allow_optional_failures:$('optional-failures').checked,
      logging:$('diagnostic-logging').checked},'check-preferences-output');
    if(result?.state==='completed'){
      dirty=false;render(result.check_config);
      if(changed)document.dispatchEvent(new CustomEvent('envscope-target-changed'));
      document.dispatchEvent(new CustomEvent('envscope-check-preferences-changed',{detail:result.check_config}));
      if(changed&&confirmedTarget)await retest();
    }
  });
  $('diagnostics-export').addEventListener('click',()=>action('diagnostics-export',{},'diagnostics-output',true));
  $('diagnostics-clear').addEventListener('click',()=>action('diagnostics-clear',{},'diagnostics-output',
    '将清除两份命令诊断日志；检测历史、修复备份和守护留痕保留。'));
  $('checks-preferences').addEventListener('click',()=>{
    document.querySelector('.tab[data-page="settings"]')?.click();form.scrollIntoView({block:'start'});
    form.querySelector('input')?.focus({preventScroll:true});
  });
}
