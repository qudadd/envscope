const $=id=>document.getElementById(id);
const el=(tag,text)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;return node;};
const pending=new Set(['prepared','applying','partial']);
let allowed=false,locked=false,loaded=false;

export function renderNetwork(value={},settings={},busy=false){
  const panel=$('network-panel');if(!panel)return;
  panel.hidden=value.supported===false;
  allowed=settings.ipv6_mode==='disabled';locked=busy||pending.has(value.state);
  const names={not_configured:'尚无修改记录',committed:'上次设置已读回',restored:'已恢复原设置',rolled_back:'失败后已恢复原设置',prepared:'上次操作未完成',partial:'需要恢复或手动核对',unavailable:'网络资料未能读取'};
  $('network-state').textContent=names[value.state]||'尚未读取';
  $('network-status').textContent=value.reason||(pending.has(value.state)?'原备份已保留。先预览恢复，避免覆盖未完成的修改。':'配置读回只证明所列设置；解析、连接和出口需要重新检测。');
  $('network-status').classList.toggle('manual-guidance',pending.has(value.state)||value.state==='unavailable');
  $('network-policy').textContent=allowed?'当前目标：关闭 IPv6。可选择具体接口，默认仅勾选正在使用且已启用 IPv6 的接口。':'当前目标保留 IPv6；本页不会关闭它。需要关闭时，先在检测目标中明确选择并重新检测。';
  $('network-prepare').disabled=locked||!loaded||value.state==='unavailable';
  $('network-restore').disabled=busy||!value.can_restore;
  $('network-load').disabled=busy;
  $('network-all').disabled=locked||!loaded||!allowed;
  $('network-none').disabled=locked||!loaded;
  $('network-dns').disabled=locked;
  for(const box of panel.querySelectorAll('.network-adapter')){
    box.disabled=locked||!allowed||box.dataset.enabled!=='true';
    if(!allowed)box.checked=false;
  }
}

export function initNetwork({action,reportId,retest}){
  const clear=()=>$('network-plan').replaceChildren();
  for(const event of ['envscope-audit-start','envscope-target-changed','envscope-target-editing'])document.addEventListener(event,clear);
  $('network-dns').addEventListener('change',clear);
  function choose(all){clear();for(const box of $('network-adapters').querySelectorAll('input'))if(!box.disabled)box.checked=all;}
  $('network-all').addEventListener('click',()=>choose(true));
  $('network-none').addEventListener('click',()=>choose(false));
  async function load(message=null,attention=false){
    clear();const value=await action('system-network-options',{},'network-output');if(!value)return;
    loaded=value.state==='completed';$('network-adapters').replaceChildren();
    if(loaded){
      for(const row of value.adapters||[]){
        const label=el('label'),box=el('input');label.className='checkbox';box.type='checkbox';box.className='network-adapter';
        box.value=row.id;box.dataset.enabled=String(row.ipv6_enabled);box.checked=allowed&&row.active&&row.ipv6_enabled;
        box.disabled=locked||!allowed||!row.ipv6_enabled;box.addEventListener('change',clear);
        label.append(box,document.createTextNode(row.name+' · '+(row.active?'正在使用':'未连接')+' · IPv6 '+(row.ipv6_enabled?'已启用':'已关闭')));
        $('network-adapters').append(label);
      }
      if(!value.adapters?.length)$('network-adapters').append(el('p','没有读取到可处理的网络接口，可单独选择刷新 DNS 缓存。'));
      $('network-output').textContent=message||'接口读取完成；请勾选要修改的接口，再预览具体影响。';
    }else{
      $('network-output').textContent=[value.reason,...value.manual||[]].filter(Boolean).join('\n');
    }
    $('network-output').classList.toggle('manual-guidance',attention||!loaded);
    $('network-prepare').disabled=locked||!loaded;
    $('network-all').disabled=locked||!loaded||!allowed;$('network-none').disabled=locked||!loaded;
  }
  $('network-load').addEventListener('click',()=>load());
  const selected=()=>[...$('network-adapters').querySelectorAll('input:checked')].map(box=>box.value);
  async function plan(restore=false){
    clear();const ids=selected(),dns=$('network-dns').checked;
    const value=await action(restore?'system-network-restore-plan':'system-network-plan',restore?{}:{report_id:reportId(),adapter_ids:ids,flush_dns:dns},'network-output');
    $('network-output').classList.toggle('manual-guidance',!!value&&value.state!=='planned');
    if(value?.state!=='planned')return;
    const list=el('ul');for(const effect of value.effects||[])list.append(el('li',effect));
    const button=el('button',restore?'确认恢复原网络设置':'确认修改并复检');
    button.addEventListener('click',async()=>{
      if(!restore&&(JSON.stringify(ids)!==JSON.stringify(selected())||dns!==$('network-dns').checked)){clear();return;}
      button.disabled=true;
      const result=await action(restore?'system-network-restore':'system-network-apply',{plan_id:value.plan_id},'network-output',true);
      clear();$('network-output').classList.toggle('manual-guidance',!!result&&result.state!=='completed');
      if(result?.needs_retest&&retest)await retest();
      if(result?.needs_retest)await load(result.reason,result.state!=='completed');
    });
    $('network-plan').append(el('h3',restore?'将恢复这些设置':'将执行这些修改'),list,button);
  }
  $('network-prepare').addEventListener('click',()=>plan());
  $('network-restore').addEventListener('click',()=>plan(true));
}
