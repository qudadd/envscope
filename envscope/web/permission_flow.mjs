// Opening an OS pane is never evidence that permission was granted.
const key=context=>JSON.stringify([context?.report?.report_id,context?.report?.environment?.fingerprint,
  context?.report?.selection?.selected,context?.revision]);
export function permissionContinuation({getContext,recheck,notify,isBusy=()=>false}){
  let pending=null,running=false;
  return {
    arm(id,context,left=false){pending={id,key:key(context),checks:context.report.selection?.selected?.slice()||null,left};notify('waiting');},
    leave(){if(pending)pending.left=true;},
    cancel(){pending=null;notify('cancelled');},
    invalidate(){if(pending){pending=null;notify('stale');}},
    async resume(manual=false){
      if(!pending||running||isBusy()||(!manual&&!pending.left))return false;
      const step=pending;pending=null;
      if(step.key!==key(getContext())){notify('stale');return false;}
      running=true;notify('checking');
      try{
        const report=await recheck(step.checks);
        const item=report?.assessment?.items?.find(row=>row.id===step.id);
        if(!report||!item)notify('incomplete');
        else if(item.state==='permission')notify('denied');
        else if(item.state==='passed')notify('verified');
        else notify('review');
      }catch{notify('incomplete');}
      finally{running=false;}
      return true;
    }
  };
}

export function initPermissionFlow({run,operate,recheck,getContext,isBusy}){
  const panel=document.getElementById('permission-status'),text=document.getElementById('permission-message');
  const resume=document.getElementById('permission-resume'),cancel=document.getElementById('permission-cancel');
  const messages={waiting:'已打开系统入口。处理后返回本窗口，将按原勾选范围自动复检一次。',checking:'正在重新读取权限和检测结果…',
    cancelled:'已停止自动复检。系统中已做的操作不会被撤销。',stale:'检测目标、范围或报告已改变，请按当前目标重新检测。',
    denied:'复检仍被系统拒绝。请按该项说明处理；不会重复弹出授权窗口。',verified:'本项已重新读取并通过检测，修复方案已更新。',
    review:'复检已完成，请查看新的检测结果和处理方案。',incomplete:'复检未取得本项的完整结果，请重新检测。'};
  function notify(state){panel.hidden=false;panel.dataset.state=state;text.textContent=messages[state];resume.hidden=cancel.hidden=state!=='waiting';}
  const flow=permissionContinuation({getContext,recheck,isBusy,notify});
  let opening=false,leftDuringOpen=false;
  const leave=()=>{if(opening)leftDuringOpen=true;flow.leave();};
  window.addEventListener('blur',leave);
  window.addEventListener('focus',()=>{void flow.resume();});
  document.addEventListener('visibilitychange',()=>{if(document.hidden)leave();else void flow.resume();});
  resume.addEventListener('click',()=>void flow.resume(true));
  cancel.addEventListener('click',()=>flow.cancel());
  for(const name of ['envscope-target-changed','envscope-selection-changed','envscope-check-preferences-changed'])document.addEventListener(name,()=>flow.invalidate());
  document.addEventListener('envscope-permission',event=>{
    const context=getContext();if(!context?.report){notify('stale');return;}
    void operate(async()=>{
      const {id,button,output}=event.detail;button.disabled=true;
      try{
        const params={report_id:context.report.report_id,finding_id:id};
        let value=await run('permission-help',params);
        if(value.state==='confirmation_required'){
          if(!window.confirm(value.reason)){output.textContent='已取消，未打开权限入口。';return;}
          opening=true;leftDuringOpen=false;
          value=await run('permission-help',params,true);
        }
        output.textContent=value.reason||'请根据本项说明处理后复检。';
        if(value.state==='opened'&&value.recheck_on_return===true){
          flow.arm(id,context,leftDuringOpen);
        }
      }finally{opening=false;button.disabled=false;}
    },event.detail.output);
  });
  return flow;
}
