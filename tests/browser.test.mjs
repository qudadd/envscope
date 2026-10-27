import test from "node:test";
import {describeProxy} from "../envscope/web/diagnosis.mjs";
import assert from "node:assert/strict";
import {normalizeIP,isPublicIP,parseCandidate,assessHTTP,assessICE,sharingSnapshot} from "../envscope/web/logic.mjs";

test("IPv6 equivalent spellings and mapped IPv4 canonicalize",()=>{
  assert.equal(normalizeIP("2001:4860::1"),normalizeIP("2001:4860:0:0:0:0:0:1"));
  assert.equal(normalizeIP("::ffff:8.8.8.8"),"8.8.8.8");
  for(const value of ["999.2.3.4","1::2::3","a:b:c","01.2.3.4","fe80::1%eth0"])assert.equal(normalizeIP(value),null);
});
test("special and local ranges are not public candidates",()=>{
  for(const value of ["198.18.0.1","198.19.1.2","100.64.1.2","192.168.1.1","fd00::1","fe80::1","2001:db8::1","224.0.0.1","::1"])assert.equal(isPublicIP(value),false,value);
  assert.equal(isPublicIP("8.8.8.8"),true);assert.equal(isPublicIP("2001:4860::1"),true);
});
test("candidate parser preserves type instead of treating relay as client IP",()=>{
  assert.equal(parseCandidate("candidate:1 1 udp 1 8.8.8.8 1000 typ relay").type,"relay");
  assert.equal(parseCandidate("candidate:bad"),null);
});
test("no candidates, mDNS and relay-only are unknown",()=>{
  for(const candidates of [[],[{address:"host.local",type:"host"}],[{address:"8.8.8.8",type:"relay"}]])assert.equal(assessICE(candidates,[],true).status,"unknown");
});
test("timeouts and one provider cannot pass an HTTP crosscheck",()=>{
  assert.equal(assessHTTP([],4).status,"unknown");
  assert.equal(assessHTTP([{ip:"8.8.8.8",source:"a"}],4).status,"warn");
  assert.equal(assessHTTP([{ip:"8.8.8.8",source:"a"},{ip:"1.1.1.1",source:"b"}],4).status,"warn");
});
test("WebRTC compares within this browser and requires completed gathering",()=>{
  const http=[{ip:"8.8.8.8",source:"a"},{ip:"8.8.8.8",source:"b"}];
  const ice=[{address:"8.8.8.8",type:"srflx"}];
  assert.equal(assessICE(ice,http,true).status,"pass");
  assert.equal(assessICE(ice,http,false).status,"unknown");
  assert.equal(assessICE([{address:"1.1.1.1",type:"srflx"}],http,true).status,"warn");
  assert.equal(assessICE(ice,http.slice(0,1),true).status,"warn");
});
test("IPv6 availability needs an explicit allowed range, absence is unknown",()=>{
  assert.equal(assessHTTP([],6).status,"unknown");
  assert.equal(assessHTTP([{ip:"2001:4860::1",source:"a"}],6).status,"warn");
});
test("sharing snapshots remove all candidate addresses while preserving equality",()=>{
  const safe=sharingSnapshot({http:[{ip:"8.8.8.8"}],ice:[{address:"8.8.8.8",type:"srflx"},{address:"host.local",type:"host"}],contains_sensitive:true});
  assert.equal(safe.http[0].ip,safe.ice[0].address);assert.equal(safe.contains_sensitive,false);
  assert.ok(!JSON.stringify(safe).includes("8.8.8.8"));assert.ok(!JSON.stringify(safe).includes("host.local"));
});

test("proxy explanation recognizes anonymous API 401 without claiming a bad key",()=>{
  const text=describeProxy({endpoint:'https://api.anthropic.com/v1/models',http_status:401});
  assert.ok(text.includes('此 401 无需修复'));
  assert.ok(!text.includes('密钥失效'));
});

test("CONNECT 407 takes precedence over its curl receive error",()=>{
  const text=describeProxy({http_status:407,error:'curl_exit_56'});
  assert.ok(text.includes('代理要求认证'));
  assert.ok(!text.includes('连接没有完成'));
});

test("proxy explanations separate DNS, TLS and rate limits without dumping raw errors",()=>{
  assert.ok(describeProxy({error:'curl_exit_6'}).includes('目标域名解析失败'));
  assert.ok(describeProxy({error:'curl_exit_60'}).includes('证书校验失败'));
  assert.ok(describeProxy({http_status:429}).includes('停止连续重试'));
});
