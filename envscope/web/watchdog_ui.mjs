const $=id=>document.getElementById(id);
export function watchdogSelection(prefix){
  const value=Object.fromEntries(['timezone','locale','proxy'].map(k=>[k,$(prefix+'-guard-'+k).checked]));
  return Object.values(value).some(Boolean)?{...value,client:$(prefix+'-guard-client').value}:null;
}
export function initWatchdogForms(run){
  for(const prefix of ['upkeep','flow-upkeep']){
    for(const k of ['timezone','locale','proxy','client'])$(prefix+'-guard-'+k).addEventListener('change',()=>$(prefix+'-plan').replaceChildren());
    $(prefix+'-guard-load').addEventListener('click',async()=>{
      const button=$(prefix+'-guard-load');button.disabled=true;
      try{
        const value=await run('watchdog-options');
        for(const p of ['upkeep','flow-upkeep']){
          const select=$(p+'-guard-client'),previous=select.value;
          select.replaceChildren(new Option('不重开客户端，仅恢复可读取节点',''),...(value.clients||[]).map(c=>new Option(c.label+' · '+c.path,c.id)));
          if([...select.options].some(o=>o.value===previous))select.value=previous;
          const capabilityNote=Object.values(value.capabilities||{}).map(c=>c.reason).filter(Boolean).join(' ');
          $(p+'-guard-note').textContent=[capabilityNote,value.note,!(value.clients||[]).length?'未找到支持的已安装客户端；代理离线需手动处理。':''].filter(Boolean).join(' ');
          $(p+'-plan').replaceChildren();
        }
      }catch(e){$(prefix+'-guard-note').textContent='未读取客户端：'+e.message;}finally{button.disabled=false;}
    });
  }
}
