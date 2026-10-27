// Human-facing diagnosis and a reviewed plan -> execute -> recheck workflow.
// Only fixed API actions and server-issued plan/backup IDs reach the backend.
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const labels={"config-desktop":"备份并打开桌面配置","config-cli":"备份并打开 Code 配置","clock-settings":"打开日期与时间设置","storage-settings":"打开存储设置","proxy-settings":"打开系统代理设置","hosts-file":"打开 hosts 文件"};
const links={"claude-web":["在浏览器打开 Claude","https://claude.ai/"],"service-status":["查看官方服务状态","https://status.claude.com/"],"cli-install":["打开官方安装说明","https://code.claude.com/docs/en/troubleshoot-install"],"desktop-install":["打开官方下载入口","https://claude.ai/download"]};
const errorText={audit_running:"已有检测或操作正在进行，请等待完成。",invalid_session:"本地服务会话已失效，请重新打开桌面程序。",operation_unavailable_or_deadline:"操作没有在期限内返回。先检查实际状态，再复检，避免重复执行。"};

export function describeProxy(item){
  const name=item.endpoint?.includes('api.anthropic.com')?'Claude API':'Claude 网页',code=item.http_status;
  const errors={'curl_exit_5':'代理名称解析失败','curl_exit_6':'目标域名解析失败','curl_exit_7':'TCP 连接未建立','curl_exit_28':'请求超时','deadline_exceeded':'请求超时','curl_exit_35':'TLS 握手失败','curl_exit_60':'证书校验失败','curl_exit_77':'CA 文件无法读取'};
  const message=code===407?'代理要求认证，请在代理客户端或组织指定位置完成认证':item.error?(errors[item.error]||'连接没有完成'):
    code===401?(item.endpoint?.includes('api.anthropic.com')?'API 已响应；本工具未发送密钥，此 401 无需修复，登录需在客户端确认':'网页要求认证，请在常用浏览器中确认登录'):code===403?'自动探测被拒绝，请在常用浏览器确认访问校验':code===429?'服务限流，请停止连续重试':code>=500?'服务返回错误，先查看官方服务状态':code>=200&&code<400?'已收到响应；尚未验证账号登录':'收到响应，但未确认服务可用';
  const time=Number.isFinite(item.elapsed_ms)?`，耗时 ${item.elapsed_ms} ms`:'';
  return `${name}：${message}（HTTP ${code||'无响应'}${time}）。`;
}

export function initDiagnosis({sessionPromise,retest}) {
  let report=null,busy=false,proxies=[],executionFailed=false;
  const output=$('solution-output');
  function button(text,fn){const b=el('button',text);b.type='button';b.addEventListener('click',fn);return b;}
  function link(text,url){const a=el('a',text,'link');a.href=url;a.target='_blank';a.rel='noopener noreferrer';return a;}
  function setBusy(value){busy=value;$('start').disabled=value;$('prepare-solution').disabled=value;$('quick-proxy').disabled=value;document.documentElement.dataset.operationBusy=value?'true':'false';}
  async function run(action,params={},confirmed=false){
    const session=await sessionPromise;if(!session)throw new Error('请打开本地桌面程序，再使用处理功能。');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),240000);
    try{
      const response=await fetch('/api/action',{method:'POST',signal:controller.signal,headers:{'Content-Type':'application/json','X-EnvScope-Token':session.token},body:JSON.stringify({action,params,confirmed})});
      const value=await response.json();if(!response.ok)throw new Error(errorText[value.error]||value.error||'本次操作没有完成。');return value;
    }finally{clearTimeout(timer);}
  }
  async function action(fn){
    if(busy||$('start').disabled)return;
    setBusy(true);
    try{await fn();}catch(error){output.textContent=error.name==='AbortError'?'等待超时。操作可能仍在进行；查看实际状态后再复检。':error.message;}
    finally{setBusy(false);}
  }
  async function refreshProxies(){
    const session=await sessionPromise;if(!session)return;
    const response=await fetch('/api/catalog',{headers:{'X-EnvScope-Token':session.token},cache:'no-store'});
    if(!response.ok)return;
    const catalog=await response.json();proxies=catalog.proxies||[];
    $('quick-proxy-select').replaceChildren(...proxies.map(p=>{const o=el('option',p.url);o.value=p.url;return o;}));
    $('quick-proxy-select').hidden=proxies.length<2;
    $('quick-proxy').textContent=proxies.length?'测试已发现代理':'打开代理设置';
  }
  function showProxyResult(value){
    output.replaceChildren();
    for(const item of value.evidence||[]){
      output.append(el('p',describeProxy(item)));
    }
  }
  async function proxyTest(){
    await refreshProxies();
    if(!proxies.length){
      const problem=report?.diagnosis?.problems.find(p=>['proxy-settings','proxy-test'].includes(p.action));
      if(problem?.action==='proxy-settings'){const value=await run('solution-open',{problem_id:problem.id,report_id:report.report_id});output.textContent=value.reason;}
      else output.textContent='没有发现已配置的本机代理。请在代理客户端开启 HTTP / mixed 端口，或在工具页填写确切地址后测试；不会扫描端口。';
      return;
    }
    output.textContent='正在经选定代理分别测试网页与 API，不回退直连…';
    const proxy=$('quick-proxy-select').value||proxies[0].url;
    showProxyResult(await run('proxy-diagnose',{proxy}));
  }
  function backups(items){
    for(const record of items||[]){
      const b=button('撤销 '+record.label,()=>action(async()=>{
        output.textContent='正在校验备份和当前文件…';
        const value=await run('solution-undo',{backup_id:record.id},true);output.textContent=value.reason||'撤销尚未完成。';
        if(value.state==='completed'){b.disabled=true;await retest();}
      }));
      $('solution-backups').append(b);
    }
  }
  async function applyPlan(value){
    $('solution-plan').replaceChildren();output.textContent='正在执行已确认的方案。配置写入完成后还需复检。';
    const result=await run('solution-apply',{plan_id:value.plan_id},true);
    executionFailed=['partial','failed'].includes(result.state);
    backups(result.backups);output.textContent=result.reason||'操作已返回，正在检查实际结果。';
    if(result.state==='waiting_install'){
      $('solution-plan').append(button('安装完成，继续复检',()=>action(async()=>{await retest();})));
    }else if(result.needs_retest){await retest();}
  }
  async function prepare(){
    output.textContent='正在核对可自动处理的配置和代理，生成具体方案…';
    const value=await run('solution-plan',{report_id:report?.report_id});$('solution-plan').replaceChildren();
    output.textContent=[value.reason,...value.manual||[]].filter(Boolean).join('\n');
    if(value.state==='planned'){
      const h=el('h3','本次处理方案'),list=el('ul');for(const effect of value.effects)list.append(el('li',effect));
      $('solution-plan').append(h,list,el('p','确认后才写入配置或调用维护核心。不会删除账号资料；备份仅保存在本机。','note'),button('确认执行此方案',()=>action(()=>applyPlan(value))));
      $('solution-plan').scrollIntoView({block:'center',behavior:'auto'});
    }
  }
  function renderProblem(problem){
    const row=el('section',undefined,'problem');row.dataset.problem=problem.id;
    row.append(el('h3',problem.title),el('p',problem.observed,'observed'),el('p',problem.cause,'cause'));
    const steps=el('ol');for(const step of problem.steps)steps.append(el('li',step));row.append(steps);
    const controls=el('div',undefined,'problem-actions');
    if(labels[problem.action]){
      if(problem.action.startsWith('config-'))row.append(el('p','此入口先创建含原配置的私有备份，再用系统编辑器打开文件。','note'));
      controls.append(button(labels[problem.action],()=>action(async()=>{
        const value=await run('solution-open',{problem_id:problem.id,report_id:report.report_id},problem.action.startsWith('config-'));output.textContent=value.reason;
      })));
    }else if(problem.action==='proxy-test')controls.append(button('测试已发现代理',()=>action(proxyTest)));
    else if(problem.action==='maintenance')controls.append(button('生成修复方案',()=>action(prepare)));
    else if(['settings','accounts'].includes(problem.action))controls.append(button(problem.action==='settings'?'调整比较或启动设置':'打开账号管理',()=>document.querySelector(`.tab[data-page="${problem.action}"]`)?.click()));
    else if(links[problem.action])controls.append(link(...links[problem.action]));
    controls.append(button('重新检测',()=>{if(!busy)void retest();}));row.append(controls);return row;
  }
  function render(reportValue){
    report=reportValue;const diagnosis=report.diagnosis;
    if(!diagnosis){$('verdict').textContent='历史结果需要重新分析';$('verdict-note').textContent='这份旧报告没有问题归因，请重新检测以生成处理方案。';return;}
    $('workspace').dataset.state='complete';$('verdict').textContent=diagnosis.headline;$('verdict-note').textContent=diagnosis.summary;
    $('coverage-count').textContent=diagnosis.problems.length?`${diagnosis.problems.length} 个问题`:'本次诊断';
    $('problems').replaceChildren(...diagnosis.problems.map(renderProblem));
    $('normal-observations').replaceChildren(...diagnosis.normal.map(text=>el('p',text)));
    if(diagnosis.state==='responding')$('normal-observations').append(link('打开 Claude 网页','https://claude.ai/'));
    $('coverage-note').textContent=diagnosis.coverage;
    $('solution-plan').replaceChildren();$('prepare-solution').hidden=!diagnosis.repairable_count;
    $('quick-proxy').hidden=diagnosis.state==='responding'&&!diagnosis.problems.some(p=>p.action==='proxy-test');
    $('solution-tools').hidden=diagnosis.state==='responding'&&!diagnosis.problems.length&&!$('solution-backups').children.length&&!executionFailed;
    const table=el('table'),head=el('thead'),hr=el('tr'),body=el('tbody');hr.append(el('th','检查项目'),el('th','本次说明'));head.append(hr);table.append(head,body);
    for(const check of diagnosis.checks){const tr=el('tr');tr.dataset.check=check.id;tr.append(el('td',check.title),el('td',check.text));body.append(tr);}
    $('checks').replaceChildren(table);
    if(report.resolution){
      const value=report.resolution;
      $('resolution').textContent=`复检：${value.resolved.length} 项已确认消除，${value.remaining.length} 项仍存在，${value.unverified.length} 项本次无法核实，${value.new.length} 项新问题。`;
      $('resolution').hidden=false;
      $('resolution').scrollIntoView({block:'center',behavior:'auto'});
      if(!executionFailed&&value.resolved.length&& !value.remaining.length && !value.unverified.length && !value.new.length)$('solution-output').textContent='本次处理涉及的问题已在所列项目的复检中确认消除。'+($('solution-backups').children.length?'配置变更仍需重开受影响的 Claude 客户端后生效。':'');
    }else $('resolution').hidden=true;
    void refreshProxies().catch(()=>{});
  }
  $('prepare-solution').addEventListener('click',()=>action(prepare));
  $('quick-proxy').addEventListener('click',()=>action(proxyTest));
  return {render,run,isBusy:()=>busy};
}
