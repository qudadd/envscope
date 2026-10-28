const $=id=>document.getElementById(id);
const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
const statuses={pass:'所列范围已测',warn:'需要复核',fail:'发现问题',unknown:'证据不足',skipped:'未测量',not_measured:'未测量',not_applicable:'本次不适用'};
export function browserEnvironment(){
  const result={timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'unknown',languages:[...navigator.languages],
    platform:navigator.userAgentData?.platform||navigator.platform||'unknown',automated:navigator.webdriver===true,
    hardware_threads:navigator.hardwareConcurrency||null,screen_width:screen.width,screen_height:screen.height,color_depth:screen.colorDepth};
  try{result.canvas_available=!!document.createElement('canvas').getContext('2d');}catch{result.canvas_available=false;}
  try{const gl=document.createElement('canvas').getContext('webgl');const extension=gl?.getExtension('WEBGL_debug_renderer_info');
    if(extension){result.vendor=String(gl.getParameter(extension.UNMASKED_VENDOR_WEBGL));result.renderer=String(gl.getParameter(extension.UNMASKED_RENDERER_WEBGL));}
    gl?.getExtension('WEBGL_lose_context')?.loseContext();
  }catch{/* Missing fields remain missing, never a privacy pass. */}
  return result;
}
export function initCoverage(){
  function navigate(page){document.querySelector(`.tab[data-page="${page}"]`)?.click();}
  document.addEventListener('envscope-catalog',e=>{
    const catalog=e.detail.features;if(!catalog)return;
    $('feature-boundary').textContent=catalog.boundary;
    $('feature-catalog').replaceChildren(...catalog.rows.map(row=>{
      const item=el('details');item.className='coverage-feature';item.dataset.feature=row.id;
      const summary=el('summary');summary.append(el('strong',row.title),el('span',({native:'原生实现',legacy:'通过原版核心',needs_core:'需要安装维护核心',needs_browser:'需要兼容浏览器',not_upstream:'原版未提供此平台功能'})[row.state]));
      const button=el('button','前往相关功能');button.className='link';button.onclick=()=>navigate(row.page);
      item.append(summary,el('p',row.note),button);return item;
    }));
  });
  document.addEventListener('envscope-report',e=>{
    const portrait=e.detail.report?.portrait;if(!portrait)return;
    $('coverage-context').textContent=({history:'历史报告',maintenance:'后台巡检',current:'本次检测'})[e.detail.source||'current']+' · '+new Date(portrait.created_at).toLocaleString()+'。'+portrait.scope;
    $('coverage-dimensions').replaceChildren(...portrait.dimensions.map(d=>{
      const item=el('details');item.className='coverage-dimension';item.dataset.dimension=d.id;
      const summary=el('summary');const counts=[`已测 ${d.measured}`,d.problems?`问题 ${d.problems}`:'',d.review?`复核 ${d.review}`:'',d.pending?`待补证据 ${d.pending}`:'',d.not_applicable?`不适用 ${d.not_applicable}`:''].filter(Boolean).join(' · ');summary.append(el('strong',d.title),el('span',counts));item.append(summary,el('p',d.note));
      for(const r of d.rows){const row=el('div');row.className='coverage-evidence';row.append(el('strong',r.title+' · '+statuses[r.status]+(r.required?' · 本次必需':'')),el('p',r.summary));
        if(r.next_step)row.append(el('p',r.next_step));const button=el('button','查看详细证据');button.className='link';button.onclick=()=>{navigate('checks');$('check-search').value=r.id;$('check-group').value='all';$('check-status').value='all';$('check-search').dispatchEvent(new Event('input'));const detail=document.querySelector(`[data-inspection="${r.id}"]`);if(detail)detail.open=true;};row.append(button);item.append(row);}
      return item;
    }));
  });
  document.addEventListener('envscope-audit-start',()=>{$('coverage-dimensions').replaceChildren();$('coverage-context').textContent='本轮正在检测，等待新证据；不沿用上轮结论。';});
  document.addEventListener('envscope-audit-end',e=>{if(!e.detail.has_report)$('coverage-context').textContent='本轮未完成，重新检测后查看证据。';});
}
