// Fixed desktop actions. No user input becomes an executable or shell command.
import {initCheckPreferences} from './check_preferences_ui.mjs';
import {describeProxy} from './diagnosis.mjs';
import {DISCONNECTED, disconnected} from './connection.mjs';
import {initProcessGuard,renderProcessGuard} from './process_guard_ui.mjs';
import {initComponents,renderComponents} from './components_ui.mjs';
import {initAccountRecovery,renderAccountRecovery} from './account_recovery_ui.mjs';
import {initRouting,renderRouting} from './routing_ui.mjs';
import {initTimezoneService,renderTimezoneService} from './timezone_ui.mjs';
import {initNetwork,renderNetwork} from './network_ui.mjs';
import {initClient,renderClient,initLanguage,renderLanguage} from './client_ui.mjs';
const $=id=>document.getElementById(id);
const LABELS={install:"安装维护核心与后台保护",uninstall:"卸载原版维护组件",status:"读取原版账号状态",check:"原版概要检测",checkdetail:"原版完整检测",fix:"修复环境", "update-check":"检查维护核心更新","update-apply":"更新维护核心","set-region":"按出口重设系统地区","set-client":"更换原版代理客户端",fingerprint:"设备信息","cli-info":"CLI 安装信息","open-safe":"打开临时浏览器","snapshot-export":"导出加密 DMG","snapshot-import":"导入加密 DMG","diagnose-proxy":"原版代理诊断"};
import {watchdogSelection} from './watchdog_ui.mjs';
const VERDICTS={blocked:"发现策略违反",incomplete:"检测尚不完整",review:"需要复核",clear_in_scope:"配置范围内通过"};
const STATES={completed:"操作完成",started:"已提交启动请求，请查看外部窗口",failed:"操作未完成",blocked:"操作已阻止",confirmation_required:"需要确认",unsupported:"当前系统不支持",unavailable:"维护核心尚未就绪",rejected:"输入未通过验证"};
Object.assign(LABELS,{'legacy-cli-info':'原版 CLI 详细检查（macOS）','legacy-fingerprint':'原版设备详细检查（macOS）'});
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const cell=(row,text)=>{const n=el("td",text);row.append(n);return n;};
const table=headers=>{const t=el("table"),head=el("thead"),r=el("tr");for(const h of headers)r.append(el("th",h));head.append(r);const body=el("tbody");t.append(head,body);return [t,body];};
const button=(text,fn)=>{const b=el("button",text,"link");b.type="button";b.addEventListener("click",fn);return b;};

export async function initDesktopControls({sessionPromise,onReport,download,retest}) {
  const session=await sessionPromise;if(!session)return;
  $("desktop-nav").hidden=false;
  let catalog=null,busy=false,lastReportId=null,statusRevision=0,statusPending=false;
  document.addEventListener('envscope-audit-start',()=>{statusRevision++;});
  document.addEventListener('envscope-operation-state',event=>{if(event.detail.busy)statusRevision++;});
  function page(name){
    for(const n of document.querySelectorAll(".page"))n.hidden=n.id!=="page-"+name;
    for(const n of document.querySelectorAll(".tab")){if(n.dataset.page===name)n.setAttribute("aria-current","page");else n.removeAttribute("aria-current");}
    window.scrollTo(0,0);
  }
  for(const n of document.querySelectorAll(".tab"))n.addEventListener("click",()=>page(n.dataset.page));
  async function refresh(){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
    try{
    const response=await fetch("/api/catalog",{signal:controller.signal,headers:{"X-EnvScope-Token":session.token},cache:"no-store"});
    if(!response.ok)throw new Error("无法读取本机功能列表，请刷新状态或重新打开程序。");
    catalog=await response.json();renderAccounts();renderHistory();renderSettings();renderMaintenance();renderUpkeep(catalog.maintenance);renderProcessGuard(catalog.process_guard,catalog.settings);renderRouting(catalog.routing);renderTimezoneService(catalog.timezone_service,busy);renderNetwork(catalog.system_network,catalog.settings,busy);renderClient(catalog.client_repair,catalog.settings,busy);renderLanguage(catalog.client_language,catalog.settings,busy);renderComponents(catalog.legacy_components,busy);renderBackups();$('catalog-error').hidden=true;
    document.dispatchEvent(new CustomEvent('envscope-catalog',{detail:{desktop:catalog.desktop,learning:catalog.learning,settings:catalog.settings,maintenance:catalog.maintenance,proxies:catalog.proxies,checks:catalog.checks,features:catalog.features,check_config:catalog.check_config,diagnostics:catalog.diagnostics,region_recovery:catalog.region_recovery}}));
    const options=[el("option","手动填写")];options[0].value="";
    for(const proxy of catalog.proxies||[]){const option=el("option",proxy.url+" · "+proxy.sources.join(" / "));option.value=proxy.url;options.push(option);}
    $("proxy-found").replaceChildren(...options);
    if(!$("proxy-url").value&&catalog.proxies?.length===1)$("proxy-url").value=catalog.proxies[0].url;
    if(options.some(o=>o.value===$("proxy-url").value))$("proxy-found").value=$("proxy-url").value;
    }catch(error){$('catalog-error').hidden=false;throw error;}finally{clearTimeout(timer);}
  }
  $('catalog-retry').addEventListener('click',async()=>{if(busy||$('start').disabled)return;try{await refresh();}catch{$('catalog-error').hidden=false;}});
  function information(value){
    const out=$('environment-output');out.replaceChildren(el('h3',value.title||'环境信息'));
    if(value.state==='partial')out.append(el('p','已显示可读取的资料，部分信息尚未取得。','note'));
    const list=el('dl');for(const row of value.rows||[]){const item=el('div');item.append(el('dt',row.label),el('dd',String(row.value??'尚未取得')));list.append(item);}out.append(list);
    if(value.note)out.append(el('p',value.note,'note'));out.focus({preventScroll:true});out.scrollIntoView({block:'nearest'});
  }
  async function action(id,params={},output="tool-output",confirmation=null){
    if(document.documentElement.dataset.serviceConnected==='false'){$(output).textContent=DISCONNECTED;disconnected();return null;}
    if(document.documentElement.dataset.operationBusy==='true'||$('start').disabled){$(output).textContent="正在检测或处理，请等待本次完成。";return null;}
    if(busy){$(output).textContent="已有操作进行中，请稍候。";return null;}
    const descriptor=catalog?.legacy?.actions?.find(a=>a.id===id);
    const needsConfirmation=confirmation!==null||descriptor?.requires_confirmation===true;
    const effects=confirmation||descriptor?.effects?.join("\n")||"此操作会修改本机资料。";
    if(needsConfirmation&&confirmation!==true&&!window.confirm(effects+"\n\n继续执行？"))return null;
    const disabledBefore=[...document.querySelectorAll('#page-accounts button, #page-accounts input, #page-accounts select, #param-snapshot input, #param-snapshot select, #environment-tools button, #proxy-test, #maintenance-run, #browser-cleanup, #history-compare, #settings-form button, #process-guard-panel button, #routing-panel button, #timezone-service-panel button, #timezone-service-panel input, #network-panel button, #network-panel input, #client-panel button, #client-panel input, #client-panel select, #language-panel button, #components-panel button, #components-panel input, #check-preferences-panel button, #check-preferences-panel input')].map(node=>[node,node.disabled]);
    disabledBefore.push(...['browser-folder','browser-logs','browser-open','safe-url'].map(id=>[$(id),$(id).disabled]));
    for(const [node] of disabledBefore)node.disabled=true;
    busy=true;statusRevision++;document.documentElement.dataset.operationBusy='true';$('start').disabled=true;$(output).textContent=["account-switch","app-launch","open-safe"].includes(id)?"正在重新检测启动条件，请稍候…":"正在执行，请稍候…";
    $(output).scrollIntoView({block:'nearest'});
    if(id.startsWith('browser-')||id==='open-safe')$(output).classList.remove('manual-guidance');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),/^(archive|snapshot)-/.test(id)?1200000:240000);
    try {
      const response=await fetch("/api/action",{method:"POST",signal:controller.signal,headers:{"Content-Type":"application/json","X-EnvScope-Token":session.token},
        body:JSON.stringify({action:id,params,confirmed:needsConfirmation})});
      const result=await response.json();
      if(!response.ok)throw new Error(({invalid_session:'本地会话已失效，请重新打开 EnvScope。',audit_running:'正在进行其他检测或操作，请等待完成。',operation_unavailable_or_deadline:'本次读取未能完成，请稍后重试；不影响其他功能。'})[result.error]||result.error||"操作无法完成");
      if(result.latest_report)onReport(result.latest_report);
      if(id==='archive-choose-file'){if(result.file)$('encrypted-path').value=result.file;$(output).textContent=result.reason||(result.file?'文件位置已选择。':'已取消选择。');}
      else if(['archive-export','archive-import','archive-cleanup','snapshot-export','snapshot-import','browser-cleanup','browser-folder','browser-logs','open-safe'].includes(id)){
        $(output).textContent=[result.reason,result.boundary].filter(Boolean).join('\n');
        if(id==='browser-cleanup')$(output).classList.toggle('manual-guidance',!!(result.retained||result.unverified||result.overflow));
      }
      else if(['cli-info','fingerprint'].includes(id)&&result.rows)information(result);
      else if(id.startsWith('maintenance-')||id.startsWith('guard-')||id.startsWith('routing-')||id.startsWith('timezone-service-')||id.startsWith('system-network-')||id.startsWith('client-')||id.startsWith('language-')||id.startsWith('components-'))$(output).textContent=result.reason||({planned:'方案已生成，请核对下方影响。',enabled:'持续维护已启用。',disabled:'持续维护已停用。',completed:'已刷新维护结果。',confirmation_required:'请先审核方案并确认。'})[result.state]||'本次操作尚未确认完成。';
      else if(result.state==="completed"&&["settings-save","settings-restore"].includes(id))$(output).textContent=id==="settings-save"?"已保存，后续检测使用新偏好。":"已恢复上次偏好。";
      else if(result.state==="completed"&&id==="account-label")$(output).textContent="账号名称已保存。";
      else if(id.startsWith('account-recovery-'))$(output).textContent=[result.reason,result.manual].filter(Boolean).join('\n');
      else if(result.state==="completed"&&id==="account-switch")$(output).textContent="已准备槽位 "+result.result.slot+(result.result.launched?"，已提交应用启动请求。":"，应用未启动，请查看安装状态。")+(result.result.warnings?.length?"\n"+result.result.warnings.join("\n"):"");
      else if(id==='app-launch')$(output).textContent=[result.reason,...result.reasons||[]].filter(Boolean).join('\n');
      else if(id.startsWith('diagnostics-')||id==='check-config-save')$(output).textContent=result.reason||'操作未完成。';
      else if(result.state==="completed"&&id==="support-bundle")$(output).textContent="诊断包已导出，分享前请复核。"+(!result.bundle?.checks?.length?' 本轮尚无检测报告，包内仅含偏好与能力摘要。':'');
      else if(result.state==="completed"&&id==="history-report")$(output).textContent="已读取历史结果。";
      else if(result.state==="completed"&&id==="proxy-diagnose")$(output).textContent=result.evidence.map(describeProxy).join("\n\n")+"\n\n"+(result.boundary||"");
      else if(result.stdout!==undefined)$(output).textContent=(STATES[result.state]||result.state)+"\n原版输出（未独立验证）\n"+result.stdout+"\n"+(result.stderr||result.reason||"");
      else if(result.state==="blocked")$(output).textContent="操作已阻止。\n"+(result.reason||"")+"\n"+(result.reasons||[]).join("\n");
      else {const display={...result};delete display.latest_report;$(output).textContent=(STATES[result.state]||result.state||"")+"\n"+JSON.stringify(display,null,2);}
      if(result.bundle)download(result.bundle,"support");
      if(result.archive)download(result.archive,"diagnostics");
      // Information reads do not mutate the catalog; don't turn a successful
      // display into an error just because an unrelated catalog refresh fails.
      if(!['cli-info','fingerprint','support-bundle','proxy-diagnose'].includes(id)){
        try{await refresh();}catch{$(output).append(el('p','操作已返回，但功能列表刷新失败。请重新打开程序核对状态。','note'));}
      }return result;
    }catch(error){if(error instanceof TypeError){disconnected();$(output).textContent=DISCONNECTED;}else $(output).textContent=error.name==="AbortError"?"等待已超时。操作可能仍在后台执行；请查看实际状态，避免重复执行。":String(error.message);if(/^(archive|snapshot)-/.test(id)){ $(output).classList.add('manual-guidance'); try{await refresh();}catch{} }return null;}
    finally{clearTimeout(timer);busy=false;document.documentElement.dataset.operationBusy='false';$('start').disabled=false;for(const [node,disabled] of disabledBefore)if(node.isConnected)node.disabled=disabled;if(catalog){renderAccounts();setParameters();renderProcessGuard(catalog.process_guard,catalog.settings);renderRouting(catalog.routing);renderTimezoneService(catalog.timezone_service);renderNetwork(catalog.system_network,catalog.settings);renderClient(catalog.client_repair,catalog.settings);renderLanguage(catalog.client_language,catalog.settings);renderComponents(catalog.legacy_components);}}
  }
  function renderBrowserSessions(sessions={}){
    const attention=sessions.state==='unreadable'||sessions.unverified||sessions.pending||sessions.legacy||sessions.overflow||(sessions.sessions&&['unverified','stale'].includes(sessions.worker));
    $('browser-session-status').classList.toggle('manual-guidance',!!attention);
    const worker=({running:'进程身份与心跳已核对',not_running:'未运行或已结束',stale:'心跳已过期',unverified:'状态无法核实'})[sessions.worker]||'尚无记录';
    $('browser-session-status').textContent=sessions.state==='unreadable'?'会话记录无法读取，未自动清理。请打开临时资料目录核实。':`临时会话记录 ${sessions.sessions||0} 个，待重试 ${sessions.pending||0} 个，旧版资料 ${sessions.legacy||0} 个，无法核实 ${sessions.unverified||0} 个。使用中或无法核实的资料保留。${sessions.sessions?'后台清理：'+worker+'。':''}${sessions.overflow?'资料超过单轮检查上限，请先手动核实目录。':''}`;
  }
  function renderAccounts(){
    renderBrowserSessions(catalog.isolated_browser?.sessions);
    const value=catalog.accounts;
    const dmg=catalog.dmg_archives||{};
    $('encrypted-format').querySelector('[value="dmg"]').disabled=!dmg.available;
    if(!dmg.available&&$('encrypted-format').value==='dmg')$('encrypted-format').value='envsnap';
    $('encrypted-recovery').hidden=!dmg.pending?.length;
    $('encrypted-recovery-note').textContent=dmg.reason||'';
    $('encrypted-cleanup').disabled=busy||!dmg.available;
    renderAccountRecovery(value,busy);
    const locked=!!value.pending?.length||!!value.error;
    $('account-note').classList.toggle('manual-guidance',locked);
    for(const id of ['account-add','account-export','account-import','encrypted-export','encrypted-import'])$(id).disabled=busy||locked;
    $("account-note").textContent=value.error|| (value.pending?.length?"发现未完成的事务，已保留所有副本并阻止切换。请检查："+value.pending.join("、"):
      value.current?"当前资料："+value.current+"。当前只代表已载入该资料，登录是否有效请在 Claude 中确认。":"尚未归档当前资料。首次使用会先将现有桌面资料保留为 A；不会自动注册账号。");
    const [t,body]=table(["槽位","名称","状态","存档大小",""]);
    for(const a of value.accounts){const r=el("tr");r.dataset.account=a.slot;cell(r,a.slot);cell(r,a.label||"未命名");cell(r,({active:"当前资料",archived:"已有存档",empty:"空资料",recovery_required:"需恢复"})[a.state]||a.state);
      cell(r,a.bytes===null?"—":(a.bytes/1048576).toFixed(1)+" MB");const c=cell(r,"");
      const first=!value.current&&a.slot==='A';
      const b=button(a.is_current?'打开当前账号':first?'保存当前资料到 A':a.has_snapshot?'切换并打开':'首次登录',async()=>{
        const force=!a.is_current&&$('account-force-close').checked;
        const result=await action(a.is_current?'app-launch':'account-switch',a.is_current?{}:{slot:a.slot,allow_force:force},'account-output',
          a.is_current?'将重新检测并打开当前 Claude 桌面资料；登录有效性仍需在 Claude 中确认。':`请先保存 Claude 中的工作。将重新检测、退出桌面应用，再${first?'把现有资料归为 A':`保留当前资料并载入 ${a.label||a.slot}` }。${!value.current&&!first?'现有资料先保留在 A。':''}${!a.has_snapshot&&!first?'目标为空资料，需要在 Claude 中手动登录自己的另一个账号。':''}${force?'\n已选择：正常退出失败时强制退出已识别的 Claude 桌面进程，未保存内容可能丢失。':''}`);
        if(result?.state==='completed')$('account-force-close').checked=false;
      });
      b.disabled=busy||locked;const rename=button("命名",()=>{const label=window.prompt("显示名称（仅作本机备注，不是登录邮箱）",a.label||"");if(label!==null)void action("account-label",{slot:a.slot,label},"account-output");});rename.disabled=busy||locked;c.append(b,rename);body.append(r);
    }$("account-list").replaceChildren(t);
  }
  function renderHistory(){
    const history=catalog.history||[],[t,body]=table(["检测时间","结果",""]);
    for(const h of [...history].reverse()){const r=el("tr");cell(r,new Date(h.created_at).toLocaleString());cell(r,VERDICTS[h.verdict]||h.verdict);
      cell(r,"").append(button("查看",async()=>{const result=await action("history-report",{id:h.id},"history-output");if(result?.report){onReport(result.report,'history');page("audit");$("session-state").textContent="正在查看历史结果，启动时仍会重新检测";}}));body.append(r);}
    $("history-list").replaceChildren(history.length?t:el("p","尚无检测记录。","note"));
    for(const name of ["before","after"]){const select=$("history-"+name);select.replaceChildren(...history.map(h=>{const o=el("option",new Date(h.created_at).toLocaleString());o.value=h.id;return o;}));}
    if(history.length){$("history-after").value=history.at(-1).id;$("history-before").value=history.at(-2)?.id||history.at(-1).id;}
    $("history-compare").disabled=history.length<2;
  }
  initAccountRecovery(action);
  function renderSettings(){
    const form=$("settings-form");for(const [key,value] of Object.entries(catalog.settings)){const field=form.elements.namedItem(key);if(!field)continue;
      if(field.type==="checkbox")field.checked=value;else field.value=Array.isArray(value)?value.join("\n"):value;}
    $("usage").value=catalog.settings.usage||"auto";
  }
  function renderMaintenance(){
    const l=catalog.legacy,select=$("maintenance-action"),previous=select.value;
    select.replaceChildren(...l.actions.filter(a=>LABELS[a.id]&&!["cli-info","fingerprint","diagnose-proxy"].includes(a.id)).map(a=>{
      const o=el("option",LABELS[a.id]+(!a.supported?" · 此系统不支持":!a.available?" · 需安装":""));o.value=a.id;return o;
    }));
    if([...select.options].some(o=>o.value===previous))select.value=previous;
    $("backend-note").textContent=(l.backend.installed?"已发现已安装的原版维护核心。":"尚未安装维护核心，可从下方安装。")+" 随附源码校验："+(l.vendor.verified?"通过":"未通过，安装已禁用")+"。";
    setParameters();
  }
  function setParameters(){
    if(!catalog){$('maintenance-availability').textContent='功能列表尚未取得，请重新连接本地服务。';$('maintenance-run').disabled=true;return;}
    const id=$("maintenance-action").value,a=catalog.legacy.actions.find(a=>a.id===id);
    $("maintenance-effects").replaceChildren(...(a?.effects||[]).map(text=>el("p",text)));
    $("maintenance-run").disabled=busy||!a?.available;
    $("maintenance-availability").textContent=id==='open-safe'?catalog.isolated_browser?.reason||'':!a?.supported?"此平台的原版未提供此功能":!a.available?"需要先安装支持该操作的维护核心":"";
    $("param-client").hidden=id!=="set-client";
    $("param-policy").hidden=id!=="fix"||catalog.legacy.platform!=="Darwin";
    $("param-snapshot").hidden=!["snapshot-export","snapshot-import"].includes(id);
  }
  function renderUpkeep(value){
    if(!value)return;
    const states={disabled:'尚未启用持续维护',active:'最近一轮巡检已完成',attention:'巡检已完成，配置保持需要处理',waiting:'已注册，等待首次巡检',stale:'巡检已超期',failed:'最近一轮没有完成',schedule_unverified:'系统任务状态未确认',invalid:'维护记录无法核实'};
    $('upkeep-state').textContent=states[value.state]||'维护状态待核实';
    $('upkeep-status').textContent=[value.completed_at?'最近完成：'+new Date(value.completed_at).toLocaleString():'还没有完成记录。',value.enabled?`每 ${value.interval} 分钟复检。`:'',value.has_report?`${value.problem_count} 个待处理问题。`:'',value.auto_restore?(value.restore_note||'Code 配置保持已选择，等待首次执行。'):'Code 配置保持未开启。',value.reason].filter(Boolean).join(' ');
    const e=value.egress_48h||{},samples=Number.isInteger(e.observations)&&e.observations>0;
    $('upkeep-egress').textContent=samples?`最近 48 小时有效观测 ${e.observations} 次，不同出口集合 ${Number.isInteger(e.unique_sets)?e.unique_sets:'待统计'} 种，集合变化 ${e.changes||0} 次。仅统计已保存的最近 600 次观测；变化本身不判定为账号风险。`:'尚无有效出口观测，无法统计出口集合与变化；不会据此判定环境合格。';
    $('upkeep-watchdog-state').textContent=value.watchdog_enabled?Object.entries(value.watchdog||{}).map(([k,v])=>`${({timezone:'时区',locale:'地区格式',proxy:'代理'})[k]||k}：${v.note||'等待首次巡检'}`).join('；')||'守护已批准，等待首次巡检。':'系统与代理守护尚未开启。';
    $('upkeep-watchdog-state').classList.toggle('manual-guidance',Object.values(value.watchdog||{}).some(v=>['attention','paused'].includes(v.state)));
    $('upkeep-journal').textContent=value.journal_path?'完整事件日志（按日追加，停用后保留）：'+value.journal_path:'';
    $('upkeep-run').disabled=!value.enabled;$('upkeep-stop').disabled=!value.enabled&&!value.scheduler?.present;$('upkeep-report').disabled=!value.has_report;
    $('quit').textContent=catalog.desktop?.mode==='native'?(value.enabled?'退出软件，定时维护继续':'退出 EnvScope'):(value.enabled?'结束界面，维护继续':'结束本地服务');
    const [t,body]=table(['时间','发生了什么','操作']);
    for(const event of [...value.events||[]].reverse()){
      const row=el('tr');cell(row,new Date(event.at).toLocaleString());cell(row,event.text);const controls=cell(row,'');
      if(event.before!==undefined){const detail=el('details');detail.append(el('summary','查看变更'),el('p','原值：'+String(event.before)),el('p','批准目标：'+String(event.target)));controls.append(detail);}
      for(const backup of event.backups||[]){const undo=button((backup.availability==='undone'?'已撤销 ':backup.availability==='changed'?'文件已变化，保留备份 ':'停用并撤销 ')+backup.label,async()=>{
        const result=await action('maintenance-undo',{backup_id:backup.id},'upkeep-output',true);
        if(result?.state==='completed')$('upkeep-output').textContent=result.reason;
      });undo.disabled=backup.availability!=='available';controls.append(undo);}body.append(row);
    }
    $('upkeep-events').replaceChildren(value.events?.length?t:el('p','尚无维护事件。','note'));
  }
  function renderBackups(){
    const records=catalog.config_backups||[],[t,body]=table(['备份时间','配置','恢复状态']);
    for(const record of records){
      const row=el('tr');cell(row,new Date(record.created_at).toLocaleString());cell(row,record.label);const control=cell(row,'');
      if(record.availability==='available')control.append(button('停用维护并撤销',async()=>{
        const result=await action('maintenance-undo',{backup_id:record.id},'tool-output',true);
        if(result?.state==='completed'){page('audit');if(retest)await retest();}
      }));
      else control.textContent=({undone:'已撤销',changed:'文件有后续修改，需手动合并',unavailable:'恢复证据不足，保留备份'})[record.availability]||'待核实';
      body.append(row);
    }
    $('config-backups').replaceChildren(records.length?t:el('p','尚无配置恢复记录。','note'));
  }
  initProcessGuard({action,reportId:()=>lastReportId});
  initRouting({action,reportId:()=>lastReportId,retest});
  initTimezoneService({action,reportId:()=>lastReportId,retest});
  initNetwork({action,reportId:()=>lastReportId,retest});
  initCheckPreferences({action,retest});
  initClient({action,reportId:()=>lastReportId,retest});
  initLanguage({action,reportId:()=>lastReportId,retest});
  initComponents({action,retest});
  $('upkeep-prepare').addEventListener('click',async()=>{
    $('upkeep-plan').replaceChildren();
    const value=await action('maintenance-plan',{report_id:lastReportId,interval:Number($('upkeep-interval').value),auto_restore:$('upkeep-restore').checked,watchdog:watchdogSelection('upkeep')},'upkeep-output');
    if(value?.state!=='planned')return;
    const list=el('ul');for(const effect of value.effects)list.append(el('li',effect));
    const apply=button('确认启用持续维护',async()=>{
      apply.disabled=true;const result=await action('maintenance-enable',{plan_id:value.plan_id},'upkeep-output',true);
      $('upkeep-plan').replaceChildren();if(result?.state==='enabled')$('upkeep-output').textContent=result.reason;
    });
    $('upkeep-plan').append(el('h3','本次维护方案'),list,apply);
  });
  $('upkeep-run').addEventListener('click',async()=>{await action('maintenance-run',{},'upkeep-output');});
  $('upkeep-refresh').addEventListener('click',async()=>{await action('maintenance-status',{},'upkeep-output');});
  $('upkeep-open-logs').addEventListener('click',()=>action('maintenance-logs',{},'upkeep-output'));
  $('upkeep-stop').addEventListener('click',async()=>{await action('maintenance-disable',{},'upkeep-output',true);$('upkeep-plan').replaceChildren();});
  $('upkeep-report').addEventListener('click',async()=>{
    const value=await action('maintenance-report',{},'upkeep-output');
    if(value?.report){onReport(value.report,'maintenance');page('audit');$('session-state').textContent='正在查看后台原生巡检；浏览器与登录未测，处理前请重新检测。';}
  });
  $("account-add").addEventListener("click",async()=>{
    const slot=$('new-slot').value.trim(),label=$('new-label').value.trim()||slot;
    if(!/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/.test(slot)||/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i.test(slot)){$('account-output').textContent='请填写 1–32 个英文字母、数字、下划线或短横线，以字母或数字开头，避开 CON、NUL 等系统保留名称；显示名称可以使用中文。';$('new-slot').focus();return;}
    const value=await action('account-label',{slot,label},'account-output');if(value?.state==='completed'){$('new-slot').value='';$('new-label').value='';}
  });
  $('account-check').addEventListener('click',async()=>{
    if(busy||$('start').disabled)return;
    $('account-output').textContent='';
    page('audit');$('learning-panel').hidden=true;$('audit-content').hidden=false;
    if(retest)await retest();page('accounts');$('account-readiness').scrollIntoView({block:'nearest'});
  });
  $('account-view-checks').addEventListener('click',()=>{
    page('audit');$('learning-panel').hidden=true;$('audit-content').hidden=false;
    if(!$('desktop-handoff').hidden){$('desktop-conditions').open=true;$('desktop-conditions').scrollIntoView({block:'center'});}else $('start').focus();
  });
  document.addEventListener('envscope-report',event=>{
    const {report,source}=event.detail;
    $('account-readiness').textContent=(source==='history'?'这是历史报告，切换前仍需新检测。 ':'')+(report.launch?.ready?'本轮启动条件已核实，切换时还会复检。':(report.launch?.reasons?.slice(0,3).join('；')||'启动条件尚未完整确认，请先检测。'));
  });
  document.addEventListener('envscope-audit-start',()=>{$('account-readiness').textContent='正在检测启动条件，等待本轮结果。';});
  document.addEventListener('envscope-audit-end',event=>{if(!event.detail.has_report)$('account-readiness').textContent='本轮检测未完成，请重新检测；未沿用旧结论。';});
  for(const id of ["account-export","account-import"])$(id).addEventListener("click",()=>action(id,{slot:$("archive-slot").value.trim(),file:$("archive-path").value.trim()},"account-output",
    id==="account-export"?"将创建未加密的账号目录备份。文件含登录资料，请保存在受保护的本机目录。":"将读取指定目录并导入空的非活动槽位。不会覆盖现有槽位。"));
  $('encrypted-format').addEventListener('change',()=>{
    const format=$('encrypted-format').value,dmg=format==='dmg',csnap=format==='csnap';
    $('encrypted-format-note').textContent=csnap?'兼容原版 Windows .csnap，可在 Windows / macOS 导入、导出；仅支持 A–D，导入必须选择存档原槽位。新密码至少 8 字符，旧备份使用原密码。先验签再解密，导出后回读比对全部文件。':dmg?'兼容原版 macOS DMG，仅支持 A–D；导入必须选择存档原槽位。新密码至少 12 字符，旧备份使用原密码。DMG 校验和与 .envsnap 认证加密的验证范围不同。':'.envsnap 使用认证加密，可导入任意空槽位。';
    $('encrypted-password').placeholder=csnap?'导出至少 8 字符；导入用原密码':dmg?'导出至少 12 字符；导入用原密码':'至少 12 个字符';
    $('encrypted-password').minLength=csnap||dmg?1:12;
    $('encrypted-path').value='';$('encrypted-password').value='';
    $('encrypted-path').placeholder=`选择或填写 .${format} 文件的绝对路径`;
  });
  $('encrypted-cleanup').addEventListener('click',()=>action('archive-cleanup',{},'account-output','将核实并卸载 EnvScope 的临时 DMG，随后清理暂存副本。账号槽位、原备份和已导出文件保留。'));
  for(const mode of ['export','import']){
    $('encrypted-choose-'+mode).addEventListener('click',()=>action('archive-choose-file',{mode,format:$('encrypted-format').value},'account-output'));
    $('encrypted-'+mode).addEventListener('click',async()=>{
      const input=$('encrypted-password'),format=$('encrypted-format').value,min=format!=='envsnap'&&mode==='import'?1:format==='csnap'?8:12;
      if(input.value.length<min){$('account-output').textContent=`请填写${min===1?'原存档':`至少 ${min} 个字符的存档`}密码。`;input.focus();return;}
      if(format!=='envsnap'&&!/^[A-D]$/i.test($('encrypted-slot').value.trim())){$('account-output').textContent=`.${format} 仅支持 A–D 槽位；导入请选择存档原来的槽位。`;$('encrypted-slot').focus();return;}
      $('account-output').classList.remove('manual-guidance');
      const password=input.value;input.value='';
      await action('archive-'+mode,{slot:$('encrypted-slot').value.trim(),file:$('encrypted-path').value.trim(),password,format},'account-output',mode==='export'?'将复制非活动槽位，在受限临时目录中打包，使用密码加密并回读校验后导出。密码不会保存；临时明文随后清理。':`将用密码打开存档，校验格式与复制结果，再导入空槽位。${format==='dmg'?'DMG 只读挂载且槽位须与原存档一致。':format==='csnap'?'.csnap 先验签再解密，槽位须与原存档一致。':''}不覆盖现有资料，不启动 Claude。`);
    });
  }
  $('browser-cleanup').addEventListener('click',()=>action('browser-cleanup',{},'tool-output','将清理 EnvScope 中已关闭的临时浏览器资料，包括旧版遗留的临时登录资料。使用中或无法确认退出的资料保留，日常浏览器不受影响。'));
  $('browser-open').addEventListener('click',()=>action('open-safe',{url:$('safe-url').value.trim()},'tool-output','将重新检测后打开独立临时浏览器，不带入日常浏览器资料。关闭全部临时窗口后清理；应用退出后独立清理进程继续检查。'));
  for(const id of ['browser-folder','browser-logs'])$(id).addEventListener('click',()=>action(id,{},'tool-output'));
  $("proxy-found").addEventListener("change",()=>{$("proxy-url").value=$("proxy-found").value;});
  $("proxy-test").addEventListener("click",()=>action("proxy-diagnose",{proxy:$("proxy-url").value.trim()}));
  $("cli-info").addEventListener("click",()=>action("cli-info",{},'environment-output'));$("device-info").addEventListener("click",()=>action("fingerprint",{},'environment-output'));
  $("support-bundle").addEventListener("click",()=>action("support-bundle",{},'environment-output'));
  $("browser-info").addEventListener("click",async()=>{
    const result={language:navigator.languages,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,screen:{width:screen.width,height:screen.height,colorDepth:screen.colorDepth},hardwareThreads:navigator.hardwareConcurrency||null};
    try{const canvas=document.createElement("canvas");canvas.width=220;canvas.height=40;const c=canvas.getContext("2d");c.font="16px sans-serif";c.fillText("EnvScope 0123456789",3,24);
      const bytes=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canvas.toDataURL()));result.canvas_sha256=[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
    }catch{result.canvas_sha256="unavailable";}
    try{const gl=document.createElement("canvas").getContext("webgl");const ext=gl?.getExtension("WEBGL_debug_renderer_info");result.webgl=ext?{vendor:gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),renderer:gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)}:"unavailable_or_limited";gl?.getExtension("WEBGL_lose_context")?.loseContext();}
    catch{result.webgl="unavailable";}
    information({title:'浏览器信息',rows:[{label:'语言',value:result.language.join('、')},{label:'时区',value:result.timezone},{label:'屏幕',value:`${result.screen.width} × ${result.screen.height}`},{label:'逻辑线程数',value:result.hardwareThreads},{label:'图形渲染器',value:typeof result.webgl==='object'?result.webgl.renderer:'浏览器未提供或限制访问'},{label:'画布摘要',value:result.canvas_sha256}],note:'仅在本页展示，未上传；缺少图形或画布信息不代表故障，也不构成账号风险结论。'});
  });
  $("maintenance-action").addEventListener("change",setParameters);
  $("maintenance-run").addEventListener("click",async()=>{
    const id=$("maintenance-action").value,params={};
    if(id==="set-client")params.client=$("legacy-client").value;
    if(id==="fix"&&catalog.legacy.platform==="Darwin")params.webrtc_policy=$("legacy-policy").value;
    if(id==="open-safe")params.url=$("safe-url").value;
    if(["snapshot-export","snapshot-import"].includes(id))Object.assign(params,{account:$("snapshot-account").value,file:$("snapshot-file").value,password:$("snapshot-password").value});
    try{await action(id,params);}finally{$("snapshot-password").value="";}
  });
  $("history-compare").addEventListener("click",async()=>{
    const result=await action("history-compare",{before:$("history-before").value,after:$("history-after").value},"history-output");
    if(result)$("history-output").textContent=(result.observed_address_set_changed===null?"出口证据不足，无法比较":result.observed_address_set_changed?"两次观测的出口集合不同":"两次观测的出口集合相同")+"\n"+(result.changes.length?JSON.stringify(result.changes,null,2):"各检查项状态未变。")+"\n"+result.note;
  });
  $("settings-form").addEventListener("submit",event=>{
    event.preventDefault();const params={},form=event.currentTarget;
    for(const field of form.elements){if(!field.name)continue;params[field.name]=field.type==="checkbox"?field.checked:field.name.startsWith("allowed_")?field.value.split(/[\s,;]+/).filter(Boolean):field.value.trim();}
    void action("settings-save",params,"settings-output");
  });
  $("settings-restore").addEventListener("click",()=>action("settings-restore",{},"settings-output"));
  document.addEventListener("envscope-audit-complete",event=>{lastReportId=event.detail?.report_id||null;void refresh().catch(()=>{});});
  document.addEventListener('envscope-maintenance-change',()=>{void refresh().catch(()=>{});});
  setInterval(async()=>{
    if(statusPending||document.hidden||($('page-tools').hidden&&$('page-upkeep').hidden&&($('page-audit').hidden||!catalog?.maintenance?.enabled))||busy||$('start').disabled||document.documentElement.dataset.operationBusy==='true')return;
    const revision=statusRevision,controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);statusPending=true;
    try{
      const response=await fetch('/api/status',{signal:controller.signal,headers:{'X-EnvScope-Token':session.token},cache:'no-store'});
      if(!response.ok)return;
      const value=await response.json();
      // A read begun before an action/audit must not paint its older state over
      // the new result. Read-only polling never acquires the mutation lock.
      if(revision!==statusRevision||busy||$('start').disabled||document.documentElement.dataset.operationBusy==='true')return;
      if(value.browser_sessions)renderBrowserSessions(value.browser_sessions);
      renderUpkeep(value.maintenance);document.dispatchEvent(new CustomEvent('envscope-maintenance-status',{detail:value.maintenance}));
      if(!$('page-upkeep').hidden){
        renderProcessGuard(value.process_guard,value.settings);renderTimezoneService(value.timezone_service);
        renderNetwork(value.system_network,value.settings);renderClient(value.client_repair,value.settings);renderLanguage(value.client_language,value.settings);renderComponents(value.legacy_components);
      }
    }catch{/* Keep the explicit last completion time; never fabricate a new heartbeat. */}
    finally{clearTimeout(timer);statusPending=false;}
  },15000);
  try{await refresh();}catch(error){$("backend-note").textContent=error.message;document.dispatchEvent(new CustomEvent('envscope-catalog-error'));}
}
