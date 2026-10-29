const $=id=>document.getElementById(id);
const el=(tag,text)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;return node;};
const pending=new Set(['prepared','stopping','writing','starting','rolling_back','partial']);
let apps=[],loaded=false,auditing=false,last={},settings={},busy=false,externalBusy=false;
let language={},languageSettings={},languageBusy=false;

export function renderClient(value=last,preferences=settings,locked=false){
  if(!$('client-panel'))return;
  last=value;settings=preferences;busy=locked;
  const states={not_configured:'尚无操作记录',committed:'上次操作已读回',rolled_back:'已恢复原偏好与启动状态',not_applied:'上次未修改代理',partial:'需要恢复或手动核对',invalid:'恢复记录无法读取'};
  $('client-state').textContent=states[value.state]||(pending.has(value.state)?'上次操作未完成':'尚未读取');
  $('client-status').textContent=value.reason||'先读取已安装客户端。程序启动、TUN 配置和连接分别核对。';
  $('client-status').classList.toggle('manual-guidance',pending.has(value.state)||value.state==='invalid');
  const selected=apps.find(app=>app.id===$('client-app').value);
  const tun=settings.connection_mode==='tun'&&selected?.tun_supported===true;
  const blocked=busy||externalBusy||auditing||pending.has(value.state)||value.state==='invalid';
  $('client-app').disabled=blocked||!loaded;
  $('client-load').disabled=busy||externalBusy||auditing;
  $('client-tun').disabled=blocked||!tun;
  if(!tun)$('client-tun').checked=false;
  $('client-restart').disabled=blocked||!selected||$('client-tun').checked;
  $('client-force').disabled=busy||externalBusy||auditing;
  $('client-prepare').disabled=blocked||!loaded||!selected;
  $('client-restore').disabled=busy||externalBusy||auditing||!value.can_restore;
  $('client-policy').textContent=tun?'当前目标使用 TUN，可备份并修复 Clash Verge 的 TUN 偏好；随后核对内核和目标选路。':
    selected?'本入口可启动或重开所选客户端。TUN 开关请在原客户端中处理；选择 TUN 目标及 Clash Verge 后可预览持久化修复。':'没有可选程序时，先安装或打开自己使用的代理客户端，再重新读取。sing-box 按已有服务方式启动。';
}

export function initClient({action,reportId,retest}){
  const clear=()=>$('client-plan').replaceChildren();
  const key=()=>JSON.stringify([$('client-app').value,$('client-tun').checked,$('client-restart').checked,$('client-force').checked]);
  for(const id of ['client-app','client-tun','client-restart','client-force'])$(id).addEventListener('change',()=>{clear();renderClient(last,settings,busy);});
  for(const event of ['envscope-target-changed','envscope-target-editing'])document.addEventListener(event,clear);
  document.addEventListener('envscope-audit-start',()=>{clear();auditing=true;renderClient(last,settings,busy);});
  document.addEventListener('envscope-audit-end',()=>{auditing=false;renderClient(last,settings,busy);});
  document.addEventListener('envscope-operation-state',event=>{externalBusy=event.detail.busy;renderClient(last,settings,busy);renderLanguage(language,languageSettings,languageBusy);});
  $('client-load').addEventListener('click',async()=>{
    clear();const value=await action('client-options',{},'client-output');if(!value)return;
    loaded=value.state==='completed';apps=value.apps||[];
    const previous=$('client-app').value;
    const rows=[el('option','选择实际使用的客户端')];rows[0].value='';
    for(const app of apps){const row=el('option',app.label+' · '+app.path);row.value=app.id;rows.push(row);}
    $('client-app').replaceChildren(...rows);
    const matching=apps.filter(app=>settings.client==='auto'||settings.client===app.mode);
    $('client-app').value=apps.some(app=>app.id===previous)?previous:matching.length===1?matching[0].id:'';
    $('client-tun').checked=settings.connection_mode==='tun'&&apps.find(app=>app.id===$('client-app').value)?.tun_supported===true;
    $('client-output').textContent=[apps.length?'读取完成，选择操作后预览具体影响。':'未找到已识别的图形客户端。',value.note].filter(Boolean).join('\n');
    $('client-output').classList.toggle('manual-guidance',!apps.length);
    renderClient(value.recovery||last,settings,busy);
  });
  async function plan(restore=false){
    clear();const selected=key();
    const params=restore?{allow_force:$('client-force').checked}:{report_id:reportId(),app_id:$('client-app').value,
      tun:$('client-tun').checked,restart:$('client-restart').checked,allow_force:$('client-force').checked};
    const value=await action(restore?'client-restore-plan':'client-plan',params,'client-output');
    $('client-output').classList.toggle('manual-guidance',!!value&&value.state!=='planned');
    if(value?.state!=='planned'){
      if(value)$('client-output').textContent=[value.reason,...value.manual||[]].filter(Boolean).join('\n');
      return;
    }
    const list=el('ul');for(const effect of value.effects||[])list.append(el('li',effect));
    const button=el('button',restore?'确认恢复并复检':'确认操作并复检');
    button.addEventListener('click',async()=>{
      if(selected!==key()){clear();return;}
      button.disabled=true;
      const result=await action(restore?'client-restore':'client-apply',{plan_id:value.plan_id},'client-output',true);
      clear();$('client-force').checked=false;
      $('client-output').classList.toggle('manual-guidance',!!result&&result.state!=='completed');
      if(result?.needs_retest&&retest)await retest();
    });
    $('client-plan').append(el('h3',restore?'将恢复这些设置':'将执行这些操作'),list,button);
  }
  $('client-prepare').addEventListener('click',()=>plan());
  $('client-restore').addEventListener('click',()=>plan(true));
}

export function renderLanguage(value={},preferences={},locked=false){
  if(!$('language-panel'))return;
  language=value;languageSettings=preferences;languageBusy=locked;
  const states={not_configured:'尚无应用语言修改',committed:'上次应用偏好已读回',rolled_back:'原应用语言键已恢复',not_applied:'上次未改写语言',invalid:'恢复记录无法读取'};
  $('language-state').textContent=states[value.state]||(pending.has(value.state)?'上次操作未完成':'尚未读取');
  $('language-status').textContent=value.reason||'根据已确认的应用语言目标处理。';
  $('language-status').classList.toggle('manual-guidance',pending.has(value.state)||value.state==='invalid');
  $('language-target').textContent='当前目标：'+(preferences.language||'尚未填写应用语言')+'。'+(value.supported===false?
    '此平台请在 Claude 实际支持的设置中确认语言。':'macOS 仅写入 Claude 专用偏好；实际界面是否支持此语言需在应用中确认。');
  const blocked=locked||externalBusy||auditing;
  $('language-prepare').disabled=blocked||!value.supported||!preferences.language||pending.has(value.state)||value.state==='invalid';
  $('language-restore').disabled=blocked||!value.can_restore;
}

export function initLanguage({action,reportId,retest}){
  const clear=()=>$('language-plan').replaceChildren();
  for(const event of ['envscope-audit-start','envscope-target-changed','envscope-target-editing'])document.addEventListener(event,()=>{clear();renderLanguage(language,languageSettings,languageBusy);});
  document.addEventListener('envscope-audit-end',()=>renderLanguage(language,languageSettings,languageBusy));
  async function plan(restore=false){
    clear();const value=await action(restore?'language-restore-plan':'language-plan',restore?{}:{report_id:reportId()},'language-output');
    $('language-output').classList.toggle('manual-guidance',!!value&&value.state!=='planned');
    if(value?.state!=='planned'){
      if(value)$('language-output').textContent=[value.reason,...value.manual||[]].filter(Boolean).join('\n');
      return;
    }
    const list=el('ul');for(const effect of value.effects||[])list.append(el('li',effect));
    const button=el('button',restore?'确认恢复应用语言':'确认设置语言并复检');
    button.addEventListener('click',async()=>{
      button.disabled=true;
      const result=await action(restore?'language-restore':'language-apply',{plan_id:value.plan_id},'language-output',true);
      clear();$('language-output').classList.toggle('manual-guidance',!!result&&result.state!=='completed');
      if(result?.needs_retest&&retest)await retest();
    });
    $('language-plan').append(el('h3',restore?'将恢复应用专用语言键':'将设置应用专用语言'),list,button);
  }
  $('language-prepare').addEventListener('click',()=>plan());
  $('language-restore').addEventListener('click',()=>plan(true));
}
