// Visible pages keep their loopback server alive. Reopened stale pages explain recovery.
const $=id=>document.getElementById(id);
export const DISCONNECTED='本地服务已断开。请重新双击 EnvScope 启动器，使用新打开的页面；旧地址可能已失效。';
export function disconnected(){
  document.documentElement.dataset.serviceConnected='false';
  $('connection-banner').hidden=false;$('connection-title').textContent='本地服务已断开';$('connection-message').textContent=DISCONNECTED;
  $('connection-status').textContent='未连接本地服务';
}
export function initConnection(sessionPromise){
  let active=false,checking=false,closed=false;
  async function check(){
    if(checking||closed||document.hidden)return;
    checking=true;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);
    try{
      const session=await sessionPromise;
      const response=await fetch('/api/session',{signal:controller.signal,cache:'no-store',credentials:'omit'});
      if(!response.ok)throw new Error('offline');
      const current=await response.json();
      if(current.mode!=='desktop'||typeof current.token!=='string')throw new Error('offline');
      if(!session||current.token!==session.token){location.reload();return;}
      document.documentElement.dataset.serviceConnected='true';$('connection-banner').hidden=true;
      $('connection-status').textContent='本地服务已连接'+(current.version?' · '+current.version:'')+(current.shell==='native'?' · 独立软件':' · 页面打开时保持连接');
    }catch{disconnected();}finally{checking=false;clearTimeout(timer);}
  }
  void sessionPromise.then(session=>{active=!!session||location.hostname==='127.0.0.1';if(active)void check();else $('connection-status').textContent='浏览器独立模式';});
  $('connection-retry').addEventListener('click',()=>{closed=false;void check();});
  document.addEventListener('visibilitychange',()=>{if(active&&!document.hidden)void check();});
  window.addEventListener('focus',()=>{if(active)void check();});
  document.addEventListener('envscope-service-closed',()=>{closed=true;disconnected();$('connection-title').textContent='本地服务已结束';});
  // Event delegation also catches buttons created after catalog refresh.
  document.addEventListener('click',event=>{
    const button=event.target.closest('button');
    if(!button||document.documentElement.dataset.serviceConnected!=='false'||button.classList.contains('tab')||button.id==='connection-retry'||['show-all-checks','checks-return','browser-info','account-view-checks'].includes(button.id))return;
    event.preventDefault();event.stopImmediatePropagation();disconnected();$('connection-banner').scrollIntoView({block:'start'});
  },true);
  setInterval(()=>{if(active)void check();},30000);
}
