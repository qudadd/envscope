import test from 'node:test';
import assert from 'node:assert/strict';
import {permissionContinuation} from '../envscope/web/permission_flow.mjs';

function fixture(){
  let context={report:{report_id:'r1',selection:{selected:['target.config']},environment:{fingerprint:'target1'}},revision:0};
  const calls=[],messages=[];
  const flow=permissionContinuation({getContext:()=>context,isBusy:()=>false,
    recheck:async checks=>{calls.push(checks);return {report_id:'r2',assessment:{items:[{id:'target.config',state:'permission'}]}};},
    notify:(...args)=>messages.push(args)});
  return {flow,calls,messages,setContext:value=>{context=value;},context};
}
test('return from OS settings rechecks original selection once, never grants from focus',async()=>{
  const f=fixture();f.flow.arm('target.config',f.context);
  assert.equal(await f.flow.resume(),false);
  f.flow.leave();await Promise.all([f.flow.resume(),f.flow.resume()]);
  assert.deepEqual(f.calls,[['target.config']]);
  assert.equal(f.messages.at(-1)[0],'denied');
  await f.flow.resume();assert.equal(f.calls.length,1);
});
test('changed target, report or selection invalidates pending continuation',async()=>{
  for(const change of [{revision:1},{report:{report_id:'new'}},{report:{...fixture().context.report,environment:{fingerprint:'new'}}}]){
    const f=fixture();f.flow.arm('target.config',f.context);f.flow.leave();
    f.setContext({...f.context,...change});await f.flow.resume();assert.equal(f.calls.length,0);
    assert.equal(f.messages.at(-1)[0],'stale');
  }
});
test('cancel is final and manual continue can recheck without a focus transition',async()=>{
  const f=fixture();f.flow.arm('target.config',f.context);f.flow.cancel();f.flow.leave();
  await f.flow.resume(true);assert.equal(f.calls.length,0);
  f.flow.arm('target.config',f.context);await f.flow.resume(true);assert.equal(f.calls.length,1);
});
