const $=id=>document.getElementById(id);
let preview=null,transaction=null;

export function renderAccountRecovery(accounts,busy=false){
  const recovery=accounts?.recovery;
  const visible=!!accounts?.pending?.length||!!accounts?.error||recovery?.available;
  $('account-recovery').hidden=!visible;
  if(!visible||transaction!==recovery?.transaction){
    preview=null;
    $('account-recovery-plan').hidden=true;
    $('account-recovery-effects').replaceChildren();
  }
  transaction=recovery?.transaction;
  $('account-recovery-status').textContent=recovery?.reason||'请先保留现有副本，再检查可恢复方案。';
  $('account-recovery-check').disabled=busy||!recovery?.available;
  $('account-recovery-confirm').disabled=busy||!preview;
}

export function initAccountRecovery(action){
  $('account-recovery-check').addEventListener('click',async()=>{
    preview=null;
    $('account-recovery-plan').hidden=true;
    const result=await action('account-recovery-plan',{},'account-output');
    if(result?.state!=='planned'){
      if(result)$('account-output').textContent=[result.reason,result.manual].filter(Boolean).join('\n');
      return;
    }
    preview=result;
    const nodes=result.effects.map(text=>{const node=document.createElement('li');node.textContent=text;return node;});
    $('account-recovery-effects').replaceChildren(...nodes);
    $('account-recovery-plan').hidden=false;
    $('account-recovery-confirm').disabled=false;
  });
  $('account-recovery-confirm').addEventListener('click',async()=>{
    if(!preview)return;
    const plan=preview;preview=null;
    const result=await action('account-recovery-apply',{plan_id:plan.plan_id},'account-output',true);
    if(result?.state==='completed')$('account-recovery-plan').hidden=true;
  });
}
