import {countryCode,cityChoices,suggestedCity} from './region_choices.mjs';
const $=id=>document.getElementById(id);

export function initTargetEnvironment({sessionPromise,run,retest,isBusy}){
  let settings=null,loading=false,saving=false,pendingUsage=null,profiles=[];
  let lookupBusy=false,lookupTimer=null,lookupRevision=0,editRevision=0,manualTarget=false;
  const form=$('target-form');
  const field=name=>form.elements.namedItem(name);
  function describeTarget(){
    $('target-matched').textContent=field('locale').value?`地区格式 ${field('locale').value}${field('language').value?'，应用语言目标 '+field('language').value:''}。可在下方展开调整。`:'选择城市后自动匹配时区与地区格式。';
    $('target-connection-label').textContent=`${field('usage').selectedOptions[0]?.textContent||'使用方式'}，${field('connection_mode').selectedOptions[0]?.textContent||'连接方式'} · 调整连接选项`;
    const unsupported=['CN','RU','HK','MO'].includes(countryCode(field('usage_country').value));
    $('target-country-policy').textContent=unsupported?'实际地区未列入 Claude 官方支持名单；改变节点或时区不能使地区条件通过。':'实际使用地区填写所在地，节点地区按出口 IP 建议，可手动调整。';
    $('target-country-policy').classList.toggle('inspection-error',unsupported);
  }
  function countryOptions(countries){
    if(!countries?.length)return;
    const before=field('country').value;
    field('country').replaceChildren(new Option('选择节点 / 期望配置地区',''),...countries.map(c=>new Option(c.label+' ('+c.code+')',c.code)));
    if(before&&!countries.some(c=>c.code===before))field('country').add(new Option(before,before));
    field('country').value=before;
    $('region-codes').replaceChildren(...countries.map(c=>{const option=new Option(c.code,c.code);option.label=c.label;return option;}));
  }
  function showWireguard(value={},saved=field('wireguard_service').value){
    const select=field('wireguard_service');
    const rows=Array.isArray(value.services)?value.services:[];
    const options=rows.filter(r=>typeof r.service==='string').map(r=>new Option(`${r.tunnel||r.service} · ${r.error==='permission_denied'?'读取权限被拒绝':r.error?'身份未核实':r.verified===true?'服务运行，身份已核对':r.state==='stopped'?'未激活':r.state==='paused'?'已暂停':'状态待确认'}`,r.service));
    select.replaceChildren(new Option('仅有一个隧道时自动识别',''),...options);
    if(saved&&!options.some(o=>o.value===saved))select.add(new Option(saved+' · 已保存，尚未读取',saved));
    select.value=saved;
    $('target-wireguard-note').textContent=value.platform&&value.platform!=='Windows'?'此专项检查适用于 Windows 官方 WireGuard；macOS 请使用其他 VPN 模式。':value.error==='permission_denied'?'系统拒绝读取服务列表。请核对 Windows 服务读取权限后重试；未核实的服务不会通过。':value.complete===true?`已读取 ${rows.length} 个隧道。${rows.length>1?'请选择本次使用的一个隧道。':'激活后会继续检查对应网卡与目标选路。'}不读取 VPN 配置与私钥。`:'服务读取尚未完成。可以保留目标，检查时会明确显示缺失证据；不读取 VPN 配置与私钥。';
  }
  async function readWireguard(){
    if(loading||saving||isBusy())return;
    loading=true;controls();$('target-wireguard-note').textContent='正在只读核对 Windows 隧道服务…';
    try{showWireguard(await run('wireguard-options'));}
    catch(error){$('target-wireguard-note').textContent='未能读取隧道：'+error.message;}
    finally{loading=false;controls();}
  }
  function fillCity(selected){
    if(!selected)return;
    field('region_profile').value=selected.id;
    for(const k of ['country','timezone','locale'])field(k).value=selected[k];
    field('language').value=['desktop','both'].includes(field('usage').value)?selected.language:'';
    describeTarget();
  }
  function filterCities(country,{clear=false}={}){
    const previous=field('region_profile').value,choices=cityChoices(profiles,country);
    field('region_profile').replaceChildren(new Option(choices.length?'选择城市 / 自定义':'此地区暂无预设，可自定义',''),...choices.map(p=>new Option(p.label,p.id)));
    const preserved=choices.find(p=>p.id===previous);
    if(preserved&&!clear)field('region_profile').value=previous;
    else if(previous||clear)for(const k of ['timezone','locale','language'])field(k).value='';
    describeTarget();return choices;
  }
  function controls(){
    $('target-confirm').disabled=loading||saving||lookupBusy||!!lookupTimer;
    $('target-read-ip').disabled=loading||saving||lookupBusy||!countryCode(field('usage_country').value);
    $('target-wireguard-read').disabled=loading||saving;
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
      if(edited!==editRevision||manualTarget){$('target-ip-status').textContent=`${value.country?'本次出口 '+value.country+'。':''}已保留手动选择或已保存目标。点“重新读取 IP”可重新匹配。`;return;}
      const country=countryCode(value.country),actual=countryCode(field('usage_country').value);
      if(country){
        if(![...field('country').options].some(o=>o.value===country))field('country').add(new Option(country,country));
        const changed=field('country').value!==country;
        field('country').value=country;const choices=filterCities(country,{clear:changed});
        const recommended=suggestedCity(profiles,value);
        if(!field('region_profile').value&&recommended)fillCity(recommended);
        const mismatch=actual!==country?' 与填写的实际地区不同，请核对；实际地区未被更改。':'';
        $('target-ip-status').textContent=`出口 IP：${value.ip||'多个地址'} · ${country}。`+(choices.length?`仅显示 ${country} 的 ${choices.length} 个城市 / 时区。`:'此地区暂无映射，可手动填写时区与地区格式。')+(recommended?` 建议：${recommended.label}。`:value.reason||'请选择城市后匹配时区与语言。')+mismatch;
      }else{
        const fallback=countryCode(field('country').value)||actual;
        filterCities(fallback);
        $('target-ip-status').textContent=(value.reason||'IP 未能读取。')+` 当前按 ${fallback} 筛选，尚未根据 IP 匹配；可直接选择节点地区。`;
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
    describeTarget();
    if($('target-language-field').hidden)field('language').value='';
    if(!code){field('provider').value='anthropic';field('auth_mode').value='existing';}
    $('target-wireguard').hidden=field('client').value!=='wireguard';
  }
  function populate(value){
    if(value.country&&![...field('country').options].some(o=>o.value===value.country))field('country').add(new Option(value.country,value.country));
    for(const node of form.elements){if(!node.name||!(node.name in value))continue;node.value=Array.isArray(value[node.name])?value[node.name].join('\n'):value[node.name]??'';}
    if(!field('usage').value)field('usage').value='desktop';
    if(!field('connection_mode').value)field('connection_mode').value='direct';
    visibility();
  }
  function sync(value){
    settings=value;
    $('target-summary').textContent=value?.environment_confirmed?
      `${({desktop:'桌面版',cli:'Code',both:'桌面版与 Code',web:'网页版'})[value.usage]} · ${({direct:'直连',http_proxy:'HTTP / 系统代理',tun:'TUN / VPN'})[value.connection_mode]} · 实际地区 ${value.usage_country||'待确认'} · 节点目标 ${value.country||'仅观察'} · ${value.timezone||'不比较时区'}`:
      '尚未确认目标。先确认用途与连接方式，再进行有针对性的检查。';
    $('target-edit').textContent=value?.environment_confirmed?'调整地区与时区':'设置地区与时区';
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
    form.hidden=false;manualTarget=!!settings?.environment_confirmed;populate(settings||{});$('target-output').textContent='';
    $('start').hidden=true;$('audit-results').hidden=true;
    document.dispatchEvent(new CustomEvent('envscope-target-editing'));
    $('target-cancel').hidden=!settings?.environment_confirmed;
    loading=true;$('target-confirm').disabled=true;
    $('target-observed').textContent='正在读取当前系统、时区及连接配置；不会修改它们。';
    try{
      const value=await run('environment-suggest');
      profiles=value.profiles||[];
      countryOptions(value.countries);
      $('target-region-profile').replaceChildren(new Option('自定义 / 仅观察',''),...profiles.map(p=>new Option(p.label,p.id)));
      populate(value.proposed||{});
      showWireguard(value.wireguard||{},value.proposed?.wireguard_service||'');
      filterCities(countryCode(field('country').value)||countryCode(field('usage_country').value));
      if(['cli','desktop','both','web'].includes(pendingUsage)){field('usage').value=pendingUsage;pendingUsage=null;visibility();}
      const o=value.observed||{};
      $('target-observed').textContent=`当前电脑：${o.system||'未读取'} ${o.version||''}；时区 ${o.timezone||'未读取'}；地区格式 ${o.locale||'未读取'}。下方是待确认的目标。`;
    }catch(error){$('target-observed').textContent='当前设置未能完整读取，可手动填写目标。'+error.message;}
    finally{loading=false;controls();}
    if(countryCode(field('usage_country').value))queueLookup(0);
    if(!form.hidden&&!$('audit-content').hidden){form.scrollIntoView({block:'nearest'});field('usage_country').focus();}
  }
  field('usage').addEventListener('change',()=>{visibility();const p=profiles.find(p=>p.id===field('region_profile').value);if(p)fillCity(p);editRevision++;});
  field('connection_mode').addEventListener('change',()=>{manualTarget=false;visibility();queueLookup();});
  field('client').addEventListener('change',()=>{
    if(field('client').value==='wireguard')field('connection_mode').value='tun';
    else field('wireguard_service').value='';
    visibility();editRevision++;
  });
  $('target-wireguard-read').addEventListener('click',()=>void readWireguard());
  field('usage_country').addEventListener('input',()=>{
    manualTarget=false;
    describeTarget();
    if(!lookupBusy)filterCities(countryCode(field('country').value)||countryCode(field('usage_country').value));
    queueLookup();
  });
  field('target_proxy').addEventListener('input',()=>queueLookup(500));
  $('target-read-ip').addEventListener('click',()=>{manualTarget=false;queueLookup(0);});
  field('region_profile').addEventListener('change',()=>{
    const selected=profiles.find(p=>p.id===field('region_profile').value);
    editRevision++;manualTarget=true;fillCity(selected);
    $('target-output').textContent=selected?'已填入 '+selected.label+' 的目标值。确认后先检测，修改系统需再审核方案。':'自定义目标；留空的项目只记录。';
  });
  for(const k of ['timezone','locale','language'])field(k).addEventListener('input',()=>{editRevision++;manualTarget=true;if(k!=='language')field('region_profile').value='';describeTarget();});
  field('country').addEventListener('change',()=>{editRevision++;manualTarget=true;const choices=filterCities(field('country').value,{clear:true});if(choices.length===1)fillCity(choices[0]);$('target-ip-status').textContent='正在使用手动节点地区；选择城市后匹配时区和语言。';});
  $('target-configure').addEventListener('click',()=>{
    if(!settings?.environment_confirmed||!form.hidden){void open();$('target-output').textContent='先选择期望地区与城市，确认目标并检测。';return;}
    document.dispatchEvent(new CustomEvent('envscope-region-configure'));
  });
  $('target-edit').addEventListener('click',()=>void open());
  $('target-cancel').addEventListener('click',()=>{if(!saving&&!loading){form.hidden=true;$('start').hidden=false;$('audit-results').hidden=$('workspace').dataset.state!=='complete';lookupRevision++;clearTimeout(lookupTimer);lookupTimer=null;controls();$('target-edit').focus();}});
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(loading||saving||lookupBusy||lookupTimer||isBusy())return;
    saving=true;$('target-confirm').disabled=true;$('start').disabled=true;
    document.dispatchEvent(new CustomEvent('envscope-operation-state',{detail:{busy:true}}));
    let completed=false;
    try{
      const params=Object.fromEntries(new FormData(form));
      params.allowed_ipv6=params.allowed_ipv6.split(/[\s,]+/).filter(Boolean);
      if(params.connection_mode!=='http_proxy')params.target_proxy='';
      if(params.client!=='wireguard')params.wireguard_service='';
      const value=await run('environment-confirm',params);
      sync(value.settings);form.hidden=true;$('start').hidden=false;completed=true;
      document.dispatchEvent(new CustomEvent('envscope-target-changed',{detail:{settings:value.settings}}));
    }catch(error){$('target-output').textContent='目标未保存：'+error.message;}
    finally{saving=false;$('target-confirm').disabled=false;if(!completed)$('start').disabled=false;document.dispatchEvent(new CustomEvent('envscope-operation-state',{detail:{busy:false}}));}
    if(completed){try{await retest();}finally{$('start').disabled=isBusy();}}
  });
  document.addEventListener('envscope-catalog',event=>{sync(event.detail.settings);if((!settings?.environment_confirmed||!settings?.usage_country)&&form.hidden)void open();});
  document.addEventListener('envscope-target-review',event=>{pendingUsage=['cli','desktop','both','web'].includes(event.detail?.usage)?event.detail.usage:null;if(!loading&&pendingUsage&&!form.hidden){field('usage').value=pendingUsage;visibility();pendingUsage=null;}else if(form.hidden)void open();});
  document.addEventListener('envscope-audit-start',()=>{$('target-edit').disabled=true;});
  document.addEventListener('envscope-audit-end',()=>{$('target-edit').disabled=false;});
  return {async ensure(){
    if(!await sessionPromise)return true;
    if(loading||saving||lookupBusy||lookupTimer)return false;
    if(settings?.environment_confirmed&&form.hidden)return true;
    if(form.hidden)await open();else{form.scrollIntoView({block:'nearest'});field('usage_country').focus();}
    return false;
  }};
}
