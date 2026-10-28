const $=id=>document.getElementById(id);

export function initTargetEnvironment({sessionPromise,run,retest,isBusy}){
  let settings=null,loading=false,saving=false,pendingUsage=null,profiles=[];
  const form=$('target-form');
  const field=name=>form.elements.namedItem(name);
  function visibility(){
    const code=['cli','both'].includes(field('usage').value);
    $('target-code-fields').hidden=!code;
    $('target-proxy-field').hidden=field('connection_mode').value!=='http_proxy';
    $('target-language-field').hidden=!['desktop','both'].includes(field('usage').value);
    if($('target-language-field').hidden)field('language').value='';
    if(!code){field('provider').value='anthropic';field('auth_mode').value='existing';}
  }
  function populate(value){
    for(const node of form.elements){if(!node.name||!(node.name in value))continue;node.value=Array.isArray(value[node.name])?value[node.name].join('\n'):value[node.name]??'';}
    if(!field('usage').value)field('usage').value='desktop';
    if(!field('connection_mode').value)field('connection_mode').value='direct';
    visibility();
  }
  function sync(value){
    settings=value;
    $('target-summary').textContent=value?.environment_confirmed?
      `${({desktop:'桌面版',cli:'Code',both:'桌面版与 Code',web:'网页版'})[value.usage]} · ${({direct:'直连',http_proxy:'HTTP / 系统代理',tun:'TUN / VPN'})[value.connection_mode]} · 实际地区 ${value.usage_country||'待确认'} · ${value.timezone||'不比较时区'}`:
      '尚未确认目标。先确认用途与连接方式，再进行有针对性的检查。';
    $('target-edit').textContent=value?.environment_confirmed?'调整目标':'设置目标';
    if(value?.environment_confirmed){
      $('usage').value=value.usage;
      $('enhance-cli').checked=['cli','both'].includes(value.usage);
      $('workflow-proxy').value=value.target_proxy?'manual':'auto';$('workflow-proxy-url').value=value.target_proxy||'';
      $('connection-options').hidden=true;
    }else $('connection-options').hidden=true;
  }
  async function open(){
    if(loading||saving||isBusy())return;
    if(!await sessionPromise)return;
    form.hidden=false;populate(settings||{});$('target-output').textContent='';
    document.dispatchEvent(new CustomEvent('envscope-target-editing'));
    $('target-cancel').hidden=!settings?.environment_confirmed;
    loading=true;$('target-confirm').disabled=true;
    $('target-observed').textContent='正在读取当前系统、时区及连接配置；不会修改它们。';
    try{
      const value=await run('environment-suggest');
      profiles=value.profiles||[];
      $('target-region-profile').replaceChildren(new Option('自定义 / 仅观察',''),...profiles.map(p=>new Option(p.label,p.id)));
      populate(value.proposed||{});
      if(['cli','desktop','both','web'].includes(pendingUsage)){field('usage').value=pendingUsage;pendingUsage=null;visibility();}
      const o=value.observed||{};
      $('target-observed').textContent=`当前电脑：${o.system||'未读取'} ${o.version||''}；时区 ${o.timezone||'未读取'}；地区格式 ${o.locale||'未读取'}。下方是待确认的目标。`;
    }catch(error){$('target-observed').textContent='当前设置未能完整读取，可手动填写目标。'+error.message;}
    finally{loading=false;$('target-confirm').disabled=false;}
    if(!form.hidden&&!$('audit-content').hidden){form.scrollIntoView({block:'nearest'});field('usage').focus();}
  }
  field('usage').addEventListener('change',visibility);field('connection_mode').addEventListener('change',visibility);
  field('region_profile').addEventListener('change',()=>{
    const selected=profiles.find(p=>p.id===field('region_profile').value);
    if(selected)for(const k of ['country','timezone','locale'])field(k).value=selected[k];
    $('target-output').textContent=selected?'已填入 '+selected.label+' 的目标值。确认后先检测，修改系统需再审核方案。':'自定义目标；留空的项目只记录。';
  });
  for(const k of ['country','timezone','locale'])field(k).addEventListener('input',()=>{field('region_profile').value='';});
  $('target-configure').addEventListener('click',()=>{
    if(!settings?.environment_confirmed||!form.hidden){void open();$('target-output').textContent='先选择期望地区与城市，确认目标并检测。';return;}
    document.dispatchEvent(new CustomEvent('envscope-region-configure'));
  });
  $('target-edit').addEventListener('click',()=>void open());
  $('target-cancel').addEventListener('click',()=>{if(!saving&&!loading){form.hidden=true;$('target-edit').focus();}});
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(loading||saving||isBusy())return;
    saving=true;$('target-confirm').disabled=true;
    let completed=false;
    try{
      const params=Object.fromEntries(new FormData(form));
      params.allowed_ipv6=params.allowed_ipv6.split(/[\s,]+/).filter(Boolean);
      if(params.connection_mode!=='http_proxy')params.target_proxy='';
      const value=await run('environment-confirm',params);
      sync(value.settings);form.hidden=true;completed=true;
      document.dispatchEvent(new CustomEvent('envscope-target-changed',{detail:{settings:value.settings}}));
    }catch(error){$('target-output').textContent='目标未保存：'+error.message;}
    finally{saving=false;$('target-confirm').disabled=false;}
    if(completed)await retest();
  });
  document.addEventListener('envscope-catalog',event=>{sync(event.detail.settings);if((!settings?.environment_confirmed||!settings?.usage_country)&&form.hidden)void open();});
  document.addEventListener('envscope-target-review',event=>{pendingUsage=['cli','desktop','both','web'].includes(event.detail?.usage)?event.detail.usage:null;if(!loading&&pendingUsage&&!form.hidden){field('usage').value=pendingUsage;visibility();pendingUsage=null;}else if(form.hidden)void open();});
  document.addEventListener('envscope-audit-start',()=>{$('target-edit').disabled=true;});
  document.addEventListener('envscope-audit-end',()=>{$('target-edit').disabled=false;});
  return {async ensure(){
    if(!await sessionPromise)return true;
    if(loading||saving)return false;
    if(settings?.environment_confirmed&&form.hidden)return true;
    if(form.hidden)await open();else{form.scrollIntoView({block:'nearest'});field('usage').focus();}
    return false;
  }};
}
