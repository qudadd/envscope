// Summarize actual failures and missing required evidence without treating either as a pass.
export function workflowIssues(report){
  const findings=new Map((report.findings||[]).map(f=>[f.id,f]));
  const annotations=new Map((report.assessment?.items||[]).map(i=>[i.id,i]));
  const options=report.repair_options||{};
  const problems=(report.diagnosis?.problems||[]).map(p=>{
    const checks=Object.entries(options).filter(([,v])=>v.problem_ids?.includes(p.id)).map(([id])=>id);
    const check=checks.find(id=>annotations.get(id)?.required)||checks[0]||p.id;
    const annotation=annotations.get(check),automatic=!!p.repair||checks.some(id=>id!=='baseline.country'&&['region','solution'].includes(options[id]?.action));
    return {...p,check,automatic,required:!!annotation?.required,state:annotation?.state||(p.certainty==='confirmed'?'problem':'review')};
  });
  const known=new Set(problems.map(p=>p.id));
  for(const item of report.assessment?.items||[]){
    if(!item.required||['passed','not_applicable','informational'].includes(item.state)||known.has(item.id))continue;
    const mapped=options[item.id]?.problem_ids||[];
    if(mapped.some(id=>known.has(id)))continue;
    const finding=findings.get(item.id),remedy=options[item.id]||{};
    problems.push({id:item.id,check:item.id,title:finding?.title||item.title||item.id,
      observed:finding?.summary||item.reason||'本轮未取得必需证据',cause:item.reason,
      steps:remedy.steps||[item.next_step||'补全本项证据后重新检测。'],
      action:item.action==='permission-help'?'permission-help':'retest',
      automatic:item.id!=='baseline.country'&&['region','solution'].includes(remedy.action),required:true,state:item.state});
    known.add(item.id);
  }
  return problems.sort((a,b)=>Number(b.required)-Number(a.required)||(a.priority??2)-(b.priority??2));
}

export function workflowChecks(report,enhanceCli=false){
  const findings=new Map((report.findings||[]).map(f=>[f.id,f]));
  const annotations=new Map((report.assessment?.items||[]).map(i=>[i.id,i]));
  const problems=new Set((report.diagnosis?.problems||[]).map(p=>p.id));
  // The report carries the server-validated selection; never infer permission from UI labels.
  return (report.selection?.selected||[]).filter(id=>{
    const finding=findings.get(id),annotation=annotations.get(id),remedy=report.repair_options?.[id];
    if(enhanceCli&&id==='extra.cli_env'&&finding&&finding.scope!=='not-selected'&&
      !['not_applicable','unsupported'].includes(annotation?.state)&&
      (['cli','both'].includes(report.usage)||report.usage==='auto'&&finding.evidence?.some(e=>e.installation_count||e.config?.exists)))return true;
    return finding&&finding.scope!=='not-selected'&&remedy?.needs_attention&&
      !['not_applicable','informational','unsupported'].includes(annotation?.state)&&
      (annotation?.required||finding.status==='fail'||remedy.problem_ids?.some(p=>problems.has(p)));
  });
}
