import {countryCode,cityChoices,suggestedCity} from './region_choices.mjs';
const $=id=>document.getElementById(id);

export function initTargetEnvironment({sessionPromise,run,retest,isBusy}){
  let settings=null,loading=false,saving=false,pendingUsage=null,profiles=[];
  let lookupBusy=false,lookupTimer=null,lookupRevision=0,editRevision=0;
  const form=$('target-form');
  const field=name=>form.elements.namedItem(name);
  function fillCity(selected){
    if(!selected)return;
    field('region_profile').value=selected.id;
    for(const k of ['country','timezone','locale'])field(k).value=selected[k];
    field('language').value=['desktop','both'].includes(field('usage').value)?selected.language:'';
  }
  function filterCities(country,{clear=false}={}){
    const previous=field('region_profile').value,choices=cityChoices(profiles,country);
    field('region_profile').replaceChildren(new Option(choices.length?'选择城市 / 自定义':'此地区暂无预设，可自定义',''),...choices.map(p=>new Option(p.label,p.id)));
    const preserved=choices.find(p=>p.id===previous);
    if(preserved&&!clear)field('region_profile').value=previous;
    else if(previous||clear)for(const k of ['timezone','locale','language'])field(k).value='';
    return choices;
  }
  function controls(){
    $('target-confirm').disabled=loading||saving||lookupBusy||!!lookupTimer;
    $('target-read-ip').disabled=loading||saving||lookupBusy||!countryCode(field('usage_country').value);
  }
  function queueLookup(delay=300){
    clearTimeout(lookupTimer);lookupTimer=null;lookupRevision++;
    if(form.hidden||!countryCode(field('usage_country').value)){controls();return;}
    if(lookupBusy){controls();return;}
    lookupTimer=setTimeout(()=>{lookupTimer=null;void locate();},delay);controls();
  }
  async function locate(){
    if(form.hidden||loading||saving||isBusy()||!countryCode(field('usage_country').value)){controls();return;}
    const revision=lookupRevision,edited=editRevision;
    const params={connection_mode:field('connection_mode').value,target_proxy:field('connection_mode').value==='http_proxy'?field('target_proxy').value.trim():''};
    lookupBusy=true;controls();$('target-ip-status').textContent='正在按所选连接读取出口 IP…';
    try{
      const value=await run('environment-location',params);
      if(revision!==lookupRevision||form.hidden)return;
      if(edited!==editRevision){$('target-ip-status').textContent='读取期间你修改了目标，已保留手动选择。需要时可重新读取 IP。';return;}
      const country=countryCode(value.country),actual=countryCode(field('usage_country').value);
      if(country){
        const changed=field('country').value!==country;
        field('country').value=country;const choices=filterCities(country,{clear:changed});
        const recommended=suggestedCity(profiles,value);
        if(!field('region_profile').value&&recommended)fillCity(recommended);
        const mismatch=actual!==country?' 与填写的实际地区不同，请核对；实际地区未被更改。':'';
        $('target-ip-status').textContent=`出口 IP：${value.ip||'多个地址'} · ${country}。${value.reason||''} `+(choices.length?`仅显示 ${country} 的 ${choices.length} 个城市。`:'此国家暂无城市预设，请自定义目标。')+(recommended?` 时区对应建议：${recommended.label}。`:' 请选择城市后匹配时区与语言。')+mismatch;
      }else{
        const fallback=countryCode(field('country').value)||actual;
        filterCities(fallback);
        $('target-ip-status').textContent=(value.reason||'IP 未能读取。')+` 当前按手动目标或实际地区 ${fallback} 筛选，尚未根据 IP 匹配；可在“其他目标”修改出口国家。`;
      }
    }catch(error){
      if(revision===lookupRevision&&!form.hidden)$('target-ip-status').textContent='IP 读取未完成：'+error.message+'。可手动选择城市，或重新读取。';
    }finally{
      lookupBusy=false;controls();if(revision!==lookupRevision&&!form.hidden)queueLookup(0);
    }
  }
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
      filterCities(countryCode(field('country').value)||countryCode(field('usage_country').value));
      if(['cli','desktop','both','web'].includes(pendingUsage)){field('usage').value=pendingUsage;pendingUsage=null;visibility();}
      const o=value.observed||{};
      $('target-observed').textContent=`当前电脑：${o.system||'未读取'} ${o.version||''}；时区 ${o.timezone||'未读取'}；地区格式 ${o.locale||'未读取'}。下方是待确认的目标。`;
    }catch(error){$('target-observed').textContent='当前设置未能完整读取，可手动填写目标。'+error.message;}
    finally{loading=false;controls();}
    if(countryCode(field('usage_country').value))queueLookup(0);
    if(!form.hidden&&!$('audit-content').hidden){form.scrollIntoView({block:'nearest'});field('usage').focus();}
  }
  field('usage').addEventListener('change',()=>{visibility();const p=profiles.find(p=>p.id===field('region_profile').value);if(p)fillCity(p);editRevision++;});
  field('connection_mode').addEventListener('change',()=>{visibility();queueLookup();});
  field('usage_country').addEventListener('input',()=>{
    if(!lookupBusy)filterCities(countryCode(field('country').value)||countryCode(field('usage_country').value));
    queueLookup();
  });
  field('target_proxy').addEventListener('input',()=>queueLookup(500));
  $('target-read-ip').addEventListener('click',()=>queueLookup(0));
  field('region_profile').addEventListener('change',()=>{
    const selected=profiles.find(p=>p.id===field('region_profile').value);
    editRevision++;fillCity(selected);
    $('target-output').textContent=selected?'已填入 '+selected.label+' 的目标值。确认后先检测，修改系统需再审核方案。':'自定义目标；留空的项目只记录。';
  });
  for(const k of ['timezone','locale','language'])field(k).addEventListener('input',()=>{editRevision++;if(k!=='language')field('region_profile').value='';});
  field('country').addEventListener('input',()=>{editRevision++;filterCities(field('country').value,{clear:true});$('target-ip-status').textContent='正在使用手动出口国家；选择城市后匹配时区和语言。';});
  $('target-configure').addEventListener('click',()=>{
    if(!settings?.environment_confirmed||!form.hidden){void open();$('target-output').textContent='先选择期望地区与城市，确认目标并检测。';return;}
    document.dispatchEvent(new CustomEvent('envscope-region-configure'));
  });
  $('target-edit').addEventListener('click',()=>void open());
  $('target-cancel').addEventListener('click',()=>{if(!saving&&!loading){form.hidden=true;lookupRevision++;clearTimeout(lookupTimer);lookupTimer=null;controls();$('target-edit').focus();}});
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(loading||saving||lookupBusy||lookupTimer||isBusy())return;
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
    if(loading||saving||lookupBusy||lookupTimer)return false;
    if(settings?.environment_confirmed&&form.hidden)return true;
    if(form.hidden)await open();else{form.scrollIntoView({block:'nearest'});field('usage').focus();}
    return false;
  }};
}
