// Teaching and user-reported trial results never change a diagnostic verdict.
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const button=(text,fn,cls='')=>{const n=el('button',text,cls);n.type='button';n.addEventListener('click',fn);return n;};
const link=(text,url)=>{const n=el('a',text,'link');n.href=url;n.target='_blank';n.rel='noopener noreferrer';return n;};
const docs='https://code.claude.com/docs/en/';

export const SYMPTOMS={
  connect:{title:'先确定连接停在哪一步',steps:['先看本次检测最上方的问题，优先处理端口没有回应、解析失败或证书错误。','打开平时使用的连接工具，再测试已发现的代理；失败时不会偷偷改为直连。','连接有回应后，在实际客户端重试一次。网页校验或账号登录仍需要你自己完成。'],sources:[['官方网络配置',docs+'network-config']]},
  login:{title:'连接能通，也需要单独确认登录',steps:['确认系统时间正确，先查看官方服务是否异常。','在你平时使用的官方 Claude 客户端完成登录；本工具不读取密码、验证码或登录令牌。','Code 用户在会话中用 /status 查看认证方式；按官方登录排障核对组织、订阅和提供方。不要直接清空账号资料。'],sources:[['官方安装与登录排障',docs+'troubleshoot-install'],['Claude 服务状态','https://status.claude.com/']]},
  interrupt:{title:'把“什么时候中断”留下记录',steps:['先重新检测，再到历史中比较正常与异常时的连接结果。','连接恢复后，按需要启用定时复检；已经验证的 Code 配置可单独选择保持。','更换代理或更新客户端后重新检测；需要进程保护时预览 claude-switcher 的安装影响。进程保护可能中断工作，不能替代防火墙。'],sources:[['claude-switcher 开源项目','https://github.com/YOURSJEYO/claude-switcher'],['官方稳定性排障',docs+'troubleshooting']]},
  certificate:{title:'恢复可信连接，再重试',steps:['先核对电脑的日期和时间，启用系统自动校时后复检。','组织网络可能需要管理员提供的 CA 证书；Code 可以通过 NODE_EXTRA_CA_CERTS 指定可信证书文件。','不要关闭证书验证来获得“通过”。本工具能预览恢复 Code 证书验证的改动，缺失的组织证书仍需你取得。'],sources:[['官方证书与代理配置',docs+'network-config']]},
  code:{title:'在你平时使用的终端里确认',steps:['如果刚安装过 Claude Code，完全关闭终端再打开。检测只检查已知入口，不执行陌生程序。','能打开 Claude Code 时运行 /doctor；打不开时，在终端运行 claude doctor。该命令可能提出修复，请在 Claude 自己的提示中审核。','Code 的 HTTP / HTTPS 代理可单独配置；SOCKS 不能直接作为 Code 的代理。修改后重开会话，再检测。'],sources:[['官方安装与登录排障',docs+'troubleshoot-install'],['官方 /doctor 说明',docs+'troubleshooting']],commands:['/doctor','claude doctor']},
  mcp:{title:'把 Claude 连接和具体工具分开排查',steps:['先确认 Claude 本身能收到回复。只有某个工具失败时，不要直接重装网络环境。','在 Claude Code 运行 /mcp 查看具体服务器的状态、认证和错误；桌面版在自己的 MCP 配置与日志中核对。','配置格式有效只代表文件能读，不代表 MCP 服务正在运行。保留现有设置和密钥，再按该开源 MCP 的说明排查。'],sources:[['官方 MCP 排障',docs+'mcp']],commands:['/mcp']},
};

function command(text){
  const row=el('div',undefined,'command-row'),code=el('code',text),status=el('span','','note');
  const copy=button('复制',async()=>{try{await navigator.clipboard.writeText(text);status.textContent='已复制，请在自己的终端或 Claude 会话中运行。';}catch{status.textContent='无法访问剪贴板，可选中左侧命令复制。';}},'link');
  row.append(code,copy,status);return row;
}

export function initGuide({sessionPromise,run,retest,isBusy,operate,onReport}){
  let step=0,usage='auto',initialized=false,saving=false,previousFocus=null;
  function close(){
    $('learning-panel').hidden=true;$('audit-content').hidden=false;
    if(previousFocus?.isConnected)previousFocus.focus();else $('start').focus();
  }
  function renderLesson(){
    $('learning-panel').hidden=false;$('audit-content').hidden=true;$('welcome-loading').hidden=true;
    $('learning-progress').textContent=`使用教学 · ${step+1} / 3`;$('learning-back').hidden=step===0;
    $('learning-next').textContent=step===2?'开始第一次检测':'继续';$('learning-output').textContent='';
    const body=$('learning-body');body.replaceChildren();
    if(step===0){
      $('learning-title').textContent='你准备怎样使用 Claude？';body.append(el('p','选你平时使用的方式，检测和处理建议会跟着调整。不了解这些区别，可以选自动识别。','subtle'));
      const group=el('fieldset');group.append(el('legend','选择使用方式','sr-only'));
      for(const [value,title,description] of [['desktop','Claude 桌面版','从桌面图标打开，有聊天窗口。'],['cli','Claude Code','在终端或编辑器里写代码、运行任务。'],['both','两种都用','同时检查桌面版和 Code 的相关设置。'],['auto','帮我自动识别','不确定时，先根据本机的软件和配置判断。']]){
        const label=el('label',undefined,'usage-choice'),radio=el('input');radio.type='radio';radio.name='lesson-usage';radio.value=value;radio.checked=value===usage;radio.addEventListener('change',()=>{usage=value;});
        const text=el('span');text.append(el('strong',title),el('span',description,'note'));label.append(radio,text);group.append(label);
      }body.append(group);
    }else if(step===1){
      $('learning-title').textContent='检测后，只用先看下一步';body.append(el('p','不用先弄懂 DNS、TUN 或每个技术名词。先跟着结果处理真正影响使用的事情。','subtle'));
      const rows=el('ol',undefined,'lesson-steps');
      for(const [title,text] of [['看原因','首页先说明哪里影响使用。左侧“全部检查”可查看 32 项用途和结果。没有测到的内容会写“还不能确认”，不会算成电脑故障。'],['看改动，再修复','先预览要修改的内容；你确认后才执行。修改配置先备份，完成后自动复检，可在工具页撤销。'],['回到 Claude 试用','本工具测试网络，不验证账号权限。最后需要在自己的 Claude 登录，并收到一条实际回复。只有管理多个桌面账号时，才需要在账号页保存资料。']]){const li=el('li');li.append(el('h2',title),el('p',text));rows.append(li);}body.append(rows);
    }else{
      $('learning-title').textContent='能正常使用后，再选择怎样保持';body.append(el('p','第一次检测只读，不会安装后台任务。下面两项都需要后续单独确认。','subtle'));
      const rows=el('dl',undefined,'lesson-options');for(const [title,text] of [['定时复检','按 5 / 15 / 60 分钟记录连接和配置变化，关闭界面后也可运行。'],['配置保持','可选恢复已经验证的 Code 代理与证书校验设置；每次先备份，保留其他配置。'],['开源进程保护','沿用 claude-switcher 的独立维护入口；可能停止客户端，安装前列出影响。']]){const row=el('div');row.append(el('dt',title),el('dd',text));rows.append(row);}body.append(rows,el('p','开始前，打开你平时使用的连接工具。检测会联系 Claude、网络出口和实时连接探测服务；仅在本机保留脱敏记录。','note'));
    }
    $('learning-title').focus();
  }
  function open(){
    if(isBusy()||$('start').disabled)return;
    previousFocus=document.activeElement;document.querySelector('.tab[data-page="audit"]')?.click();step=0;usage=$('usage').value;renderLesson();window.scrollTo(0,0);
  }
  async function finish(start){
    if(saving)return;saving=true;$('learning-next').disabled=true;$('learning-skip').disabled=true;$('learning-back').disabled=true;
    try{
      if(await sessionPromise){
        if(start)document.dispatchEvent(new CustomEvent('envscope-target-review',{detail:{usage}}));
        await run('learning-complete',{version:1});
      }
      if(start)$('usage').value=usage;
      close();if(start)await retest();
    }catch(error){$('learning-output').textContent='教学进度未保存：'+error.message+'。请重试；尚未开始检测。';}
    finally{saving=false;$('learning-next').disabled=false;$('learning-skip').disabled=false;$('learning-back').disabled=false;}
  }
  $('learning-next').addEventListener('click',()=>{if(step<2){step++;renderLesson();}else void finish(true);});
  $('learning-back').addEventListener('click',()=>{step=Math.max(0,step-1);renderLesson();});
  $('learning-skip').addEventListener('click',()=>finish(false));$('learning-replay').addEventListener('click',open);
  document.addEventListener('envscope-catalog',event=>{
    if(initialized)return;initialized=true;usage=event.detail.settings?.usage||'auto';$('welcome-loading').hidden=true;
    if(event.detail.learning?.completed){$('audit-content').hidden=false;}
    else renderLesson();
  });
  void sessionPromise.then(value=>{if(!value){initialized=true;$('welcome-loading').hidden=true;$('audit-content').hidden=false;}});
  document.addEventListener('envscope-catalog-error',()=>{if(!initialized){initialized=true;$('welcome-loading').hidden=true;renderLesson();}});
  function advice(){
    const value=SYMPTOMS[$('symptom').value]||SYMPTOMS.connect,area=$('symptom-advice');area.replaceChildren(el('h3',value.title));
    const list=el('ol');for(const text of value.steps)list.append(el('li',text));area.append(list);
    for(const text of value.commands||[])area.append(command(text));
    const refs=el('div',undefined,'reference-links');for(const item of value.sources)refs.append(link(...item));area.append(refs);
  }
  $('symptom').addEventListener('change',advice);advice();
  $('try-success').addEventListener('click',()=>{
    $('try-feedback').textContent='你已确认本次在 Claude 收到回复。连接变化、重开客户端或更新后建议复检；这条手动确认不会改变技术检测结论。';
    $('try-success').textContent='本次试用已由你确认';$('try-success').disabled=true;
  });
  $('try-help').addEventListener('click',()=>{$('symptom-help').open=true;$('symptom').focus();$('symptom-help').scrollIntoView({block:'start'});});
  $('try-upkeep').addEventListener('click',()=>document.querySelector('.tab[data-page="upkeep"]')?.click());
  async function desktopAction(restart){
    if(isBusy()||$('start').disabled)return;
    const effects=restart?'请先保存 Claude 中的工作。将先重新检测启动条件，通过后请求 Claude 正常退出，再次复检并重开；未确认退出时不会强制终止。':'将重新检测本机启动条件，通过后提交 Claude 桌面打开请求。';
    if(!window.confirm(effects+'\n账号资料不会交换，登录与实际回复仍需你在 Claude 中确认。\n\n继续执行？'))return;
    await operate(async()=>{
      $('desktop-launch').disabled=true;$('desktop-restart').disabled=true;
      $('desktop-output').textContent='正在重新检测启动条件，请稍候。';
      try{
        const value=await run(restart?'app-restart':'app-launch',{},true);
        if(value.latest_report)onReport(value.latest_report);
        $('desktop-output').textContent=[value.reason,...(value.reasons||[])].filter(Boolean).join(' ');
      }finally{$('desktop-launch').disabled=false;$('desktop-restart').disabled=false;}
    },$('desktop-output'));
  }
  $('desktop-launch').addEventListener('click',()=>desktopAction(false));
  $('desktop-restart').addEventListener('click',()=>desktopAction(true));
  function render(value){
    const guide=value.guide;$('try-claude').hidden=!guide;
    if(!guide){const row=el('li');row.append(el('span','—','task-number'),el('p','这份旧报告没有使用步骤，请重新检测。'));$('usage-tasks').replaceChildren(row);return;}
    const tasks=$('usage-tasks');tasks.replaceChildren();
    const states={attention:'需要处理',checked:'所列范围已核实',responding:'已收到回应',unverified:'还不能确认',optional:'按需要启用'};
    guide.tasks.forEach((task,i)=>{const row=el('li');row.dataset.task=task.id;const text=el('div');text.append(el('h3',task.title),el('p',task.text));row.append(el('span',String(i+1),'task-number'),text,el('span',states[task.state]||'还不能确认','task-state'));tasks.append(row);});
    const area=$('try-instructions');area.replaceChildren();
    if(guide.manual_confirmation?.state==='blocked'){
      $('try-claude').hidden=true;$('desktop-handoff').hidden=true;$('try-success').disabled=true;
      $('try-feedback').textContent=guide.manual_confirmation.text;return;
    }
    const usage=value.usage;
    $('desktop-handoff').hidden=['cli','web'].includes(usage);
    const readiness=value.launch;
    $('desktop-readiness').textContent=readiness?.ready?'本轮所列启动条件已核实。打开前仍会复检，账号登录和实际回复需要你确认。':'下方列出的启动条件还需处理或确认。操作前会复检；未通过时保留资料并列出原因。';
    $('desktop-condition-list').replaceChildren(...(readiness?.checks||[]).map(item=>el('li',item.title+'：'+item.reason)));
    if(usage!=='cli')area.append(link('在浏览器打开 Claude','https://claude.ai/'));
    if(['auto','cli','both'].includes(usage)){area.append(el('p','Code 用户：打开平时使用的终端，进入自己的项目，再启动 Claude Code。需要检查实际会话时可运行：','note'),command('/doctor'));}
    $('try-feedback').textContent='尚未由你确认实际回复。';$('try-success').textContent='我已收到 Claude 的回复';$('try-success').disabled=false;
  }
  document.addEventListener('envscope-audit-start',()=>{
    $('try-claude').hidden=true;$('try-feedback').textContent='';$('desktop-output').textContent='';$('beginner-checks').hidden=true;
    const row=el('li'),text=el('div');text.append(el('h3','正在检查连接和设置'),el('p','等待本轮结果。上一次检测的状态不会当作本次证据。'));row.append(el('span','…','task-number'),text);$('usage-tasks').replaceChildren(row);
  });
  document.addEventListener('envscope-audit-end',event=>{
    if(event.detail?.has_report)return;
    const row=el('li'),text=el('div');text.append(el('h3','尚无本轮系统结论'),el('p','重新检测后再处理。上次的状态和手动试用确认均不作为本次证据。'));row.append(el('span','—','task-number'),text);$('usage-tasks').replaceChildren(row);
  });
  // These are separate external projects. Only documented interfaces are used.
  const options=$('opensource-options');
  for(const [name,status,text,url] of [
    ['claude-switcher','已随附固定版本','负责原版环境修复、账号相关维护和进程保护。EnvScope 提供预览入口，执行后仍独立复检。','https://github.com/YOURSJEYO/claude-switcher'],
    ['Mihomo','已接入只读兼容接口','读取本机正在生效的路由规则、选定代理组和 TUN 配置。控制接口不可读时保留未核实，不根据文件猜测生效。','https://github.com/MetaCubeX/mihomo'],
    ['Clash Verge Rev','可选外部客户端','Windows / macOS 上管理已有连接，提供系统代理和 TUN。可与 EnvScope 的代理发现、端口测试和 Mihomo 规则核对配合；不内置节点或代替服务。','https://github.com/clash-verge-rev/clash-verge-rev'],
  ]){const row=el('section',undefined,'opensource-option');row.append(el('h3',name),el('span',status,'note'),el('p',text),link('项目与安装说明',url));options.append(row);}
  return {render};
}
