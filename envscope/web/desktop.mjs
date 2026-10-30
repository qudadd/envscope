// Native lifecycle and software updates are separate from environment repairs.
const $=id=>document.getElementById(id);
const el=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
export function initDesktopApp({run,operate}){
  let desktop=null,report=null;
  const output=$('software-output');
  const updateLabels={not_checked:'尚未检查更新',available:'发现可用新版',up_to_date:'当前通道没有更新的完整软件包',unavailable:'暂时无法核验更新',ready:'新版已核验，重启后使用'};
  function render(value){
    desktop=value;const native=value?.mode==='native';$('native-preferences').hidden=!native;
    $('desktop-mode').textContent=native?(value.tray?'独立软件正在运行。可从系统托盘或 macOS 菜单栏重新打开。':'独立窗口正在运行。托盘未就绪时，关闭窗口将退出软件。'):'当前为浏览器兼容模式。后台驻留和软件更新请使用 EnvScope 独立桌面包。';
    if(!native)return;
    for(const [id,key] of [['desktop-keep','keep_running'],['desktop-update-check','check_updates'],['desktop-preview','preview_updates']])$(id).checked=!!value.preferences?.[key];
    const u=value.updates||{};
    $('app-update-state').textContent=`${u.current||''}。${updateLabels[u.state]||'等待结果'}${u.version?'：'+u.version:''}。`;
    $('app-update-details').replaceChildren();
    if(u.reason)$('app-update-details').append(el('p',u.reason));
    if(u.notes){const details=el('details','');details.append(el('summary','查看本次更新说明'),el('pre',u.notes));$('app-update-details').append(details);}
    $('app-update-install').hidden=u.state!=='available'||!value.can_install;
    $('app-update-restart').hidden=u.state!=='ready'||!value.can_install;
    $('app-update-rollback').hidden=!value.can_rollback;
    $('upstream-update').textContent=u.upstream?(u.upstream.changed?'参考项目存在新提交。':'')+u.upstream.note:'参考项目的新提交会经过兼容性测试，再随 EnvScope 发布。';
  }
  async function action(name,params={}){
    await operate(async()=>{
      output.textContent=name==='app-update-install'?'正在下载、校验和安装，完成前请保持应用运行…':'正在处理…';
      let value=await run(name,params);
      if(value.state==='confirmation_required'){
        if(!window.confirm(value.reason)){output.textContent='已取消。';return;}
        value=await run(name,params,true);
      }
      output.textContent=value.reason||'已完成。';
      if(value.state!=='restarting'){
        const status=await run('desktop-status');if(status.desktop)render(status.desktop);
      }
    },output);
  }
  $('desktop-save').addEventListener('click',()=>action('desktop-save',{keep_running:$('desktop-keep').checked,check_updates:$('desktop-update-check').checked,preview_updates:$('desktop-preview').checked}));
  $('desktop-hide').addEventListener('click',()=>action('desktop-hide'));
  $('app-update-check').addEventListener('click',()=>action('app-update-check'));
  $('app-update-install').addEventListener('click',()=>action('app-update-install',{version:desktop?.updates?.version}));
  $('app-update-restart').addEventListener('click',()=>action('app-update-restart'));
  $('app-update-rollback').addEventListener('click',()=>action('app-update-rollback'));
  document.querySelector('[data-page="settings"]').addEventListener('click',()=>{
    if(desktop?.mode==='native')void operate(async()=>{
      const value=await run('desktop-status');if(value.desktop)render(value.desktop);
    },output);
  });
  document.addEventListener('envscope-catalog',e=>render(e.detail.desktop));
  document.addEventListener('envscope-report',e=>{
    report=e.detail.report;const a=report.assessment;$('qualification').hidden=!a;if(!a)return;
    $('verdict').textContent=a.headline;$('verdict-note').textContent=a.summary;
    const c=a.counts;$('qualification-counts').textContent=`需要读取权限 ${c.permission} 项，探测未完成 ${c.probe_incomplete+c.unavailable} 项，不适用 ${c.not_applicable} 项，本版未支持 ${c.unsupported} 项。`;
    $('qualification-boundary').textContent=a.boundary;
    const pending=a.items.filter(i=>i.required&&!['passed','not_applicable','informational'].includes(i.state));
    $('qualification-pending').replaceChildren(...(pending.length?pending.map(i=>{const p=el('p',''),f=report.findings.find(f=>f.id===i.id);p.append(el('strong',(f?.title||i.id)+'：'),document.createTextNode(i.reason+' '+i.next_step));return p;}):[el('p','本次列出的关键使用条件已完成核对。')]));
  });
  document.addEventListener('envscope-audit-start',()=>{report=null;$('qualification').hidden=true;});
}
