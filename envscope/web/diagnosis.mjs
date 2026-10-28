// Human-facing diagnosis and a reviewed plan -> execute -> recheck workflow.
// Only fixed API actions and server-issued plan/backup IDs reach the backend.
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const labels={"config-desktop":"备份并打开桌面配置","config-cli":"备份并打开 Code 配置","clock-settings":"打开日期与时间设置","storage-settings":"打开存储设置","proxy-settings":"打开系统代理设置","hosts-file":"打开 hosts 文件"};
const links={"claude-web":["在浏览器打开 Claude","https://claude.ai/"],"service-status":["查看官方服务状态","https://status.claude.com/"],"cli-install":["打开官方安装说明","https://code.claude.com/docs/en/troubleshoot-install"],"desktop-install":["打开官方下载入口","https://claude.ai/download"]};
const errorText={audit_running:"已有检测或操作正在进行，请等待完成。",invalid_session:"本地服务会话已失效，请重新打开桌面程序。",operation_unavailable_or_deadline:"操作没有在期限内返回。先检查实际状态，再复检，避免重复执行。"};

export function setFlowStage(stage,text){
  for(const row of document.querySelectorAll('[data-flow-step]'))row.dataset.active=String(row.dataset.flowStep===stage);
  $('flow-state').textContent=text;
}

export function describeProxy(item){
  const name=item.endpoint?.includes('api.anthropic.com')?'Claude API':'Claude 网页',code=item.http_status;
  const errors={'curl_exit_5':'代理名称解析失败','curl_exit_6':'目标域名解析失败','curl_exit_7':'TCP 连接未建立','curl_exit_28':'请求超时','deadline_exceeded':'请求超时','curl_exit_35':'TLS 握手失败','curl_exit_60':'证书校验失败','curl_exit_77':'CA 文件无法读取'};
  const message=code===407?'代理要求认证，请在代理客户端或组织指定位置完成认证':item.error?(errors[item.error]||'连接没有完成'):
    code===401?(item.endpoint?.includes('api.anthropic.com')?'API 已响应；本工具未发送密钥，此 401 无需修复，登录需在客户端确认':'网页要求认证，请在常用浏览器中确认登录'):code===403?'自动探测被拒绝，请在常用浏览器确认访问校验':code===429?'服务限流，请停止连续重试':code>=500?'服务返回错误，先查看官方服务状态':code>=200&&code<400?'已收到响应；尚未验证账号登录':'收到响应，但未确认服务可用';
  const time=Number.isFinite(item.elapsed_ms)?`，耗时 ${item.elapsed_ms} ms`:'';
  return `${name}：${message}（HTTP ${code||'无响应'}${time}）。`;
}

export function initDiagnosis({sessionPromise,retest}) {
  let report=null,busy=false,proxies=[],executionFailed=false,activeCheck=null;
  const output=$('solution-output');
  function button(text,fn){const b=el('button',text);b.type='button';b.addEventListener('click',fn);return b;}
  function link(text,url){const a=el('a',text,'link');a.href=url;a.target='_blank';a.rel='noopener noreferrer';return a;}
  function setBusy(value){busy=value;for(const id of ['start','prepare-solution','quick-proxy','flow-upkeep-prepare','flow-upkeep-stop','flow-upkeep-interval','flow-upkeep-restore','enhance-cli','workflow-proxy','workflow-proxy-url','usage'])$(id).disabled=value;document.documentElement.dataset.operationBusy=value?'true':'false';}
  async function run(action,params={},confirmed=false){
    const session=await sessionPromise;if(!session)throw new Error('请打开本地桌面程序，再使用处理功能。');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),240000);
    try{
      const response=await fetch('/api/action',{method:'POST',signal:controller.signal,headers:{'Content-Type':'application/json','X-EnvScope-Token':session.token},body:JSON.stringify({action,params,confirmed})});
      const value=await response.json();if(!response.ok)throw new Error(errorText[value.error]||value.error||'本次操作没有完成。');return value;
    }finally{clearTimeout(timer);}
  }
  async function action(fn,errorOutput=output){
    if(busy||$('start').disabled)return;
    setBusy(true);
    try{await fn();}catch(error){errorOutput.textContent=error.name==='AbortError'?'等待超时。操作可能仍在进行；查看实际状态后再复检。':error.message;}
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
    renderProxyOptions(proxies);
  }
  function renderProxyOptions(items){
    const select=$('workflow-proxy'),previous=select.value;
    const automatic=el('option','自动核对现有连接');automatic.value='auto';
    const manual=el('option','手动填写本机 HTTP 地址');manual.value='manual';
    const options=(items||[]).filter(p=>p.url?.startsWith('http://')||p.url?.startsWith('https://')).map(p=>{const n=el('option',p.url);n.value=p.url;return n;});
    select.replaceChildren(automatic,...options,manual);
    select.value=[...select.options].some(n=>n.value===previous)?previous:'auto';
    $('workflow-proxy-manual').hidden=select.value!=='manual';
    updateOptionsLabel();
  }
  function updateOptionsLabel(){$('connection-options').querySelector('summary').textContent='环境设置：'+($('usage').selectedOptions[0]?.textContent||'自动识别')+($('enhance-cli').checked?'，按需完善 Code 连接':'，仅修复已定位问题');}
  function optionsKey(){return JSON.stringify([$('usage').value,$('enhance-cli').checked,$('workflow-proxy').value,$('workflow-proxy-url').value.trim()]);}
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
  async function applyPlan(value,options=null){
    if(options!==null&&options!==optionsKey()){output.textContent='环境选项已经变化，请重新检测并审核新的方案。';$('solution-plan').replaceChildren();return;}
    setFlowStage('repair','正在执行已确认的改动；先备份配置，完成后自动复检。');
    $('solution-plan').replaceChildren();output.textContent='正在执行已确认的方案。配置写入完成后还需复检。';
    const result=await run('solution-apply',{plan_id:value.plan_id},true);
    executionFailed=['partial','failed','blocked'].includes(result.state);
    backups(result.backups);output.textContent=result.reason||'操作已返回，正在检查实际结果。';
    if(result.state==='waiting_install'){
      $('solution-plan').append(button('安装完成，继续复检',()=>action(async()=>{await retest();})));
    }else if(result.needs_retest){await retest();}
  }
  async function prepare(checkId=null,workflow=false){
    activeCheck=checkId;$('solution-tools').hidden=false;
    $('solution-tools').dataset.workflow=String(workflow);
    if(workflow){$('prepare-solution').hidden=true;$('quick-proxy').hidden=true;$('quick-proxy-select').hidden=true;}
    if(workflow)$('session-state').textContent='正在验证连接与生成方案';
    setFlowStage('review','正在合并配置与修复方案，测试候选连接；尚未写入。');
    output.textContent='正在核对可自动处理的配置和代理，生成具体方案…';
    const params={report_id:report?.report_id};if(checkId)params.check_id=checkId;
    if(workflow){params.enhance_cli=$('enhance-cli').checked;const selected=$('workflow-proxy').value;if(params.enhance_cli&&selected!=='auto')params.proxy=selected==='manual'?$('workflow-proxy-url').value.trim():selected;}
    let value;
    try{value=await run('solution-plan',params);}catch(error){if(workflow)$('session-state').textContent='方案未完成，请重新检测';setFlowStage('review','方案未完成，尚未写入配置。请重试或按具体问题处理。');throw error;}
    $('solution-plan').replaceChildren();
    if(workflow)$('session-state').textContent=value.state==='planned'?'方案已就绪，等待你确认':'本轮方案核对已结束';
    output.textContent=[value.reason,...value.manual||[]].filter(Boolean).join('\n');
    for(const item of value.connections||[]){const detail=el('details',undefined,'connection-evidence');detail.append(el('summary',item.proxy+'：'+(item.verified?'API 连接已验证，未认证账号':'本次未验证可用')));for(const response of item.evidence||[])detail.append(el('p',describeProxy(response)));$('solution-plan').append(detail);}
    if(value.manual_items?.length){const manual=el('details',undefined,'manual-items');manual.append(el('summary',`${value.manual_items.length} 项需要你配合处理`));for(const item of value.manual_items)manual.append(button(item.title,()=>{const row=[...document.querySelectorAll('[data-problem]')].find(n=>n.dataset.problem===item.id);if(row){const parent=row.closest('details');if(parent)parent.open=true;row.scrollIntoView({block:'start'});}}));$('solution-plan').append(manual);}
    if(value.state==='planned'){
      const h=el('h3',workflow?'确认后完成这些设置和修复':'本次处理方案'),list=el('ul');for(const effect of value.effects)list.append(el('li',effect));
      const key=workflow?optionsKey():null;
      const apply=button(workflow?'确认配置并修复':'确认执行此方案',()=>action(()=>applyPlan(value,key)));apply.id='apply-solution';
      $('solution-plan').append(h,list,el('p','确认后才写入配置或调用维护核心，完成后自动复检。用户配置可被项目或组织设置覆盖，实际会话仍需重开并确认。','note'),apply);
      setFlowStage('review','方案已生成。核对下面的具体改动，确认一次后执行并复检。');
      if(workflow){$('verdict').textContent='检测完成，请核对处理方案';$('verdict-note').textContent=`本次有 ${report.diagnosis.problems.length} 项需要处理或核对的问题，方案包含 ${value.steps.length} 个执行步骤。确认后处理，完成后重新检查。`;}
      if(!workflow)$('solution-plan').scrollIntoView({block:'center',behavior:'auto'});
    }else{
      setFlowStage('review',value.state==='retest_required'?'检测已过期，请重新一键检测。':'检测和方案核对已完成；本次没有执行配置写入。');
    }
  }
  function renderInlineUpkeep(value){
    if(!value)return;
    const states={disabled:'尚未启用',waiting:'已启用，等待首次巡检',active:'最近一轮已完成',attention:'巡检完成，配置保持需核对',stale:'巡检已超期',failed:'最近一轮未完成',schedule_unverified:'系统任务状态未确认',invalid:'维护记录无法核实'};
    $('flow-upkeep-status').textContent=[states[value.state]||'状态待核实',value.completed_at?'完成于 '+new Date(value.completed_at).toLocaleString():'',value.enabled?`每 ${value.interval} 分钟复检`:'',value.reason].filter(Boolean).join('。');
    $('flow-upkeep-stop').hidden=!value.enabled&&!value.scheduler?.present;
  }
  $('flow-upkeep-prepare').addEventListener('click',()=>action(async()=>{
    const value=await run('maintenance-plan',{report_id:report?.report_id,interval:Number($('flow-upkeep-interval').value),auto_restore:$('flow-upkeep-restore').checked});
    $('flow-upkeep-plan').replaceChildren();$('flow-upkeep-output').textContent=value.reason||'';
    if(value.state!=='planned')return;
    const list=el('ul');for(const effect of value.effects)list.append(el('li',effect));
    const settings=JSON.stringify([$('flow-upkeep-interval').value,$('flow-upkeep-restore').checked]);
    $('flow-upkeep-plan').append(el('h3','长期保持方案'),list,button('确认启用长期保持',()=>action(async()=>{
      if(settings!==JSON.stringify([$('flow-upkeep-interval').value,$('flow-upkeep-restore').checked])){$('flow-upkeep-output').textContent='保持选项已变化，请重新预览方案。';$('flow-upkeep-plan').replaceChildren();return;}
      const result=await run('maintenance-enable',{plan_id:value.plan_id},true);$('flow-upkeep-output').textContent=result.reason||'请核对维护状态。';$('flow-upkeep-plan').replaceChildren();
      if(result.state==='enabled')setFlowStage('keep','长期保持已启用，实际执行时间和状态见下方。');
      document.dispatchEvent(new CustomEvent('envscope-maintenance-change'));
    })));
  }));
  $('flow-upkeep-stop').addEventListener('click',()=>action(async()=>{
    const value=await run('maintenance-disable',{},true);$('flow-upkeep-output').textContent=value.reason||'已提交停用请求，请核对任务状态。';$('flow-upkeep-plan').replaceChildren();document.dispatchEvent(new CustomEvent('envscope-maintenance-change'));
  }));
  document.addEventListener('envscope-catalog',event=>{renderInlineUpkeep(event.detail.maintenance);renderProxyOptions(event.detail.proxies);});
  document.addEventListener('envscope-maintenance-status',event=>renderInlineUpkeep(event.detail));
  document.addEventListener('envscope-audit-start',()=>{report=null;$('flow-upkeep').hidden=true;$('flow-upkeep-plan').replaceChildren();$('solution-plan').replaceChildren();});
  for(const id of ['usage','enhance-cli','workflow-proxy','workflow-proxy-url'])$(id).addEventListener('change',()=>{
    updateOptionsLabel();
    $('workflow-proxy-manual').hidden=$('workflow-proxy').value!=='manual';
    if($('solution-plan').children.length){$('solution-plan').replaceChildren();output.textContent='环境选项已变化，请重新检测并生成方案。';}
  });
  function renderProblem(problem){
    const row=el('section',undefined,'problem');row.dataset.problem=problem.id;
    row.append(el('h3',problem.title),el('p','发生了什么','explain-label'),el('p',problem.observed,'observed'),el('p','为什么需要处理','explain-label'),el('p',problem.cause,'cause'),el('p','接下来这样做','explain-label'));
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
  function renderChecklist(value){
    const items=value.claude_checks?.items||[];
    $('claude-checklist').hidden=!items.length;
    $('beginner-checks').hidden=!items.length;
    const list=el('div',undefined,'plain-checks');
    for(const item of items){
      const row=el('details');row.dataset.claudeCheck=item.id;const summary=el('summary'),explanation=item.explanation||{};
      summary.append(el('span',`${item.number}. ${explanation.label||item.title}`),el('span',explanation.result||'还不能确认','check-state'));row.append(summary);
      const observation=el('div',undefined,'check-explanation'),remedy=el('div'),upkeep=el('div');
      observation.append(el('h3','这是查什么'),el('p',explanation.why||item.measurement),el('h3','当前证据'),el('p',item.summary),el('p',`技术名称：${explanation.term||item.title}。${item.measurement}`,'note'));
      for(const part of (item.observations||[]).filter(p=>p.id!==`baseline.${item.id}`).slice(0,2))observation.append(el('p',part.title+'：'+part.summary,'note'));
      remedy.append(el('h3','现在需要做什么'),el('p',explanation.next_step||item.remedy));
      const advanced=el('details'),advancedTitle=el('summary','具体处理方法');advanced.append(advancedTitle,el('p',item.remedy));remedy.append(advanced);
      upkeep.append(el('h3','怎样长期保持'),el('p',item.upkeep));
      if(item.action==='solution'&&['warn','fail','unknown'].includes(item.status))remedy.append(button('审核本项处理方案',()=>action(()=>prepare(item.id))));
      else if(item.action==='proxy-test')remedy.append(button('测试已发现代理',()=>action(proxyTest)));
      else if(item.action==='settings')remedy.append(button('核对比较与启动设置',()=>document.querySelector('.tab[data-page="settings"]')?.click()));
      row.append(observation,remedy,upkeep);list.append(row);
    }
    $('claude-check-rows').replaceChildren(list,link('核对 claude-switcher 的固定版本源码',items[0]?.source||'https://github.com/YOURSJEYO/claude-switcher'));
  }
  function render(reportValue){
    report=reportValue;const diagnosis=report.diagnosis;
    if(!diagnosis){$('verdict').textContent='历史结果需要重新分析';$('verdict-note').textContent='这份旧报告没有问题归因，请重新检测以生成处理方案。';return;}
    $('workspace').dataset.state='complete';$('verdict').textContent=report.guide?.headline||diagnosis.headline;$('verdict-note').textContent=report.guide?.summary||diagnosis.summary;
    $('coverage-count').textContent=diagnosis.problems.length?`${diagnosis.problems.length} 个问题`:'本次诊断';
    const problemNodes=diagnosis.problems.slice(0,1).map(renderProblem);
    if(diagnosis.problems.length>1){const rest=el('details',undefined,'other-problems');rest.append(el('summary',`其他 ${diagnosis.problems.length-1} 项需要处理的问题`),...diagnosis.problems.slice(1).map(renderProblem));problemNodes.push(rest);}
    $('problems').replaceChildren(...problemNodes);
    const normal=el('details');normal.append(el('summary','已取得的连接回应'),...diagnosis.normal.map(text=>el('p',text)));
    $('normal-observations').replaceChildren(...(diagnosis.normal.length?[normal]:[]));
    $('coverage-note').textContent=diagnosis.coverage;
    renderChecklist(report);
    $('flow-upkeep').hidden=false;
    $('solution-plan').replaceChildren();$('prepare-solution').hidden=!diagnosis.repairable_count;
    $('quick-proxy').hidden=diagnosis.state==='responding'&&!diagnosis.problems.some(p=>p.action==='proxy-test');
    $('solution-tools').hidden=diagnosis.state==='responding'&&!diagnosis.problems.length&&!$('solution-backups').children.length&&!executionFailed&&!activeCheck;
    const table=el('table'),head=el('thead'),hr=el('tr'),body=el('tbody');hr.append(el('th','检查项目'),el('th','本次说明'));head.append(hr);table.append(head,body);
    for(const check of diagnosis.checks){const tr=el('tr');tr.dataset.check=check.id;tr.append(el('td',check.title),el('td',check.text));body.append(tr);}
    $('checks').replaceChildren(table);
    if(report.resolution){
      const value=report.resolution;
      const selected=value.item?`${value.item.title}：${({verified:'所列测量范围已核实',unverified:'本次仍未核实',review:'仍需核对'})[value.item.state]}。`:'';
      $('resolution').textContent=selected+`复检：${value.resolved.length} 项已确认消除，${value.remaining.length} 项仍存在，${value.unverified.length} 项本次无法核实，${value.new.length} 项新问题。`;
      const configured=value.configuration||[];
      if(configured.length){const verified=configured.filter(c=>c.state==='verified').length;$('resolution').textContent+=` 配置文件核对：${verified} / ${configured.length} 份符合本次方案；这不代替实际会话验证。`;}
      if(value.configuration_pending?.length)$('resolution').textContent+=' 未自动处理：'+value.configuration_pending.join(' ');
      $('resolution').hidden=false;
      $('resolution').scrollIntoView({block:'center',behavior:'auto'});
      setFlowStage('repair','本次复检已完成。按下方实际证据核对，再到自己的 Claude 试用。');
      if(!executionFailed&&value.resolved.length&& !value.remaining.length && !value.unverified.length && !value.new.length)$('solution-output').textContent='本次处理涉及的问题已在所列项目的复检中确认消除。'+($('solution-backups').children.length?'配置变更仍需重开受影响的 Claude 客户端后生效。':'');
    }else $('resolution').hidden=true;
    void refreshProxies().catch(()=>{});
  }
  $('prepare-solution').addEventListener('click',()=>action(()=>prepare(null,true)));
  $('quick-proxy').addEventListener('click',()=>action(proxyTest));
  return {render,run,prepareWorkflow:()=>action(()=>prepare(null,true)),operate:(fn,target)=>action(fn,target),isBusy:()=>busy||document.documentElement.dataset.operationBusy==='true'};
}
