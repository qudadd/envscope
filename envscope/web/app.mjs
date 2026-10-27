import {STATUS_TEXT, normalizeIP, isPublicIP, parseCandidate, assessHTTP, assessICE, sharingSnapshot} from "./logic.mjs";
import {initDesktopControls} from "./controls.mjs";
import {initDiagnosis} from "./diagnosis.mjs";

const byId=id=>document.getElementById(id);
const nodes={start:byId("start"),share:byId("share"),checks:byId("checks"),quit:byId("quit")};
let lastSnapshot=null,lastReport=null;
const sessionPromise=(async()=>{
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),1500);
  try {
    const response=await fetch("/api/session",{signal:controller.signal,credentials:"omit",cache:"no-store"});
    if(!response.ok)return null;
    const value=await response.json();
    if(value.mode!=="desktop"||typeof value.token!=="string")return null;
    byId("mode-note").textContent="汇总 32 项检查，直接给出问题、处理方案与复检结果。";
    nodes.quit.hidden=false;
    return value;
  } catch {return null;} finally {clearTimeout(timer);}
})();
const environment={timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||"unknown",languages:[...navigator.languages],
  platform:navigator.userAgentData?.platform||navigator.platform||"unknown",automated:navigator.webdriver===true};
const envRows=[["时区",environment.timezone],["语言",environment.languages.join(" · ")],["运行环境",environment.platform+(environment.automated?" / 自动化会话":"")]];
byId("environment").replaceChildren(...envRows.map(([label,value])=>{const row=document.createElement("div");const dt=document.createElement("dt");const dd=document.createElement("dd");dt.textContent=label;dd.textContent=value;row.append(dt,dd);return row;}));

async function request(url,parser,source,family) {
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),4000);
  try {
    const response=await fetch(url,{signal:controller.signal,credentials:"omit",cache:"no-store",redirect:"error",referrerPolicy:"no-referrer"});
    if(response.status!==200) return {source,family,error:`http_${response.status}`};
    const text=await response.text();
    if(text.length>65536) return {source,family,error:"oversized_response"};
    let ip;
    if(parser==="json") {const value=JSON.parse(text);ip=value?.ip;}
    else {const line=text.split("\n").find(x=>x.startsWith("ip="));ip=line?.slice(3).trim();}
    const normalized=normalizeIP(ip);
    if(!normalized || !isPublicIP(ip) || (normalized.includes(":")?6:4)!==family) return {source,family,error:"invalid_ip_payload"};
    return {source,family,ip:normalized};
  } catch {return {source,family,error:"unavailable_or_blocked"};}
  finally {clearTimeout(timer);}
}

async function gatherICE() {
  if(!window.RTCPeerConnection) return {candidates:[],complete:false,error:"unsupported"};
  let pc;
  try {pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.cloudflare.com:3478"},{urls:"stun:stun.l.google.com:19302"}]});}
  catch {return {candidates:[],complete:false,error:"unavailable"};}
  const candidates=[];const seen=new Set();let settle;let finished=false;
  const completed=new Promise(resolve=>{settle=resolve;});
  const finish=complete=>{if(!finished){finished=true;settle({candidates,complete});}};
  const timer=setTimeout(()=>finish(false),5500);
  pc.onicecandidate=event=>{
    if(!event.candidate){finish(true);return;}
    const candidate=parseCandidate(event.candidate.candidate);
    if(candidate && candidates.length<128) {const key=JSON.stringify(candidate);if(!seen.has(key)){candidates.push(candidate);seen.add(key);}}
  };
  pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==="complete")finish(true);};
  try {
    pc.createDataChannel("envscope");
    // Race the whole gathering setup as well as the candidate wait.
    void (async()=>{try{await pc.setLocalDescription(await pc.createOffer());}catch{finish(false);}})();
    return await completed;
  } finally {clearTimeout(timer);pc.onicecandidate=null;pc.onicegatheringstatechange=null;pc.close();}
}

function render(snapshot) {
  byId("workspace").dataset.state="complete";
  const results=[assessHTTP(snapshot.http.filter(o=>o.family===4),4),assessHTTP(snapshot.http.filter(o=>o.family===6),6),assessICE(snapshot.ice,snapshot.http,snapshot.ice_complete)];
  nodes.checks.replaceChildren(...results.map((r,i)=>{const p=document.createElement("p");p.textContent=["浏览器 IPv4","浏览器 IPv6","浏览器 WebRTC"][i]+"："+r.summary;return p;}));
  byId("verdict").textContent="浏览器探测已完成";
  byId("verdict-note").textContent="正在等待系统结果。仅凭浏览器探测不能定位全部本机问题。";
  byId("coverage-count").textContent="浏览器阶段";
  byId("session-state").textContent="正在合并系统检查";
}

function renderDesktop(report) {
  byId("checks-title").hidden=false;
  diagnosisUI.render(report);
  byId("session-state").textContent="完成于 "+new Date(report.created_at).toLocaleTimeString();
}
const diagnosisUI=initDiagnosis({sessionPromise,retest:()=>runAudit()});

async function nativeAudit(session,snapshot) {
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),90000);
  try {
    const response=await fetch("/api/audit",{method:"POST",signal:controller.signal,credentials:"omit",
      headers:{"Content-Type":"application/json","X-EnvScope-Token":session.token},body:JSON.stringify({snapshot})});
    if(!response.ok)throw new Error("native_unavailable");
    const report=await response.json();
    if(report.tool!=="envscope"||report.contains_sensitive!==false||!Array.isArray(report.findings))throw new Error("invalid_report");
    return report;
  } finally {clearTimeout(timer);}
}

async function runAudit(){
  nodes.start.disabled=true;nodes.share.disabled=true;lastSnapshot=null;lastReport=null;
  nodes.start.textContent="检测中…";byId("audit-results").setAttribute("aria-busy","true");
  byId("workspace").dataset.state="running";
  nodes.checks.replaceChildren();byId("problems").replaceChildren();byId("normal-observations").replaceChildren();
  byId("checks-title").hidden=true;byId("solution-tools").hidden=true;byId("resolution").hidden=true;
  byId("coverage-count").textContent="正在检测";byId("verdict-note").textContent="正在采集本次观测并分析问题。请保持本地页面打开。";
  byId("session-state").textContent="正在收集证据";byId("verdict").textContent="观测中…";
  try {
    if(await sessionPromise)await diagnosisUI.run("settings-save",{usage:byId("usage").value});
    const [http,ice]=await Promise.all([
      Promise.all([request("https://api4.ipify.org?format=json","json","ipify-v4",4),request("https://www.cloudflare.com/cdn-cgi/trace","trace","cloudflare-v4",4),request("https://api6.ipify.org?format=json","json","ipify-v6",6)]),
      gatherICE()
    ]);
    // Browser fetch cannot force an address family on a dual-stack endpoint;
    // the IPv6-specific service supplies an observation, never a negative proof.
    lastSnapshot={schema_version:1,kind:"envscope-browser-observations",created_at:new Date().toISOString(),
      contains_sensitive:true,http,ice:ice.candidates,ice_complete:ice.complete,environment};
    render(lastSnapshot);
    const session=await sessionPromise;
    if(session){
      byId("session-state").textContent="正在检测系统网络";
      byId("verdict-note").textContent="浏览器观测已完成，正在合并系统检查。";
      try {lastReport=await nativeAudit(session,lastSnapshot);renderDesktop(lastReport);document.dispatchEvent(new Event("envscope-audit-complete"));}
      catch {byId("verdict-note").textContent="系统检测未完成，已保留浏览器观测；可重新检测。";byId("session-state").textContent="系统检测未完成";}
    }else{byId("verdict-note").textContent="当前仅检测浏览器；Windows / macOS 请使用本地启动程序完成系统检测。";}
    nodes.share.disabled=false;
  } catch {byId("verdict").textContent="观测未完成";byId("verdict-note").textContent="浏览器功能不可用或采集发生错误，不能判定通过。";byId("session-state").textContent="需要重新检测";}
  finally {nodes.start.disabled=false;nodes.start.textContent="重新检测";byId("audit-results").setAttribute("aria-busy","false");}
}
nodes.start.addEventListener("click",()=>{if(!diagnosisUI.isBusy())void runAudit();});

function download(value,suffix) {
  const blob=new Blob([JSON.stringify(value,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);
  const link=document.createElement("a");link.href=url;link.download=`envscope-${suffix}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
void initDesktopControls({sessionPromise,download,onReport:report=>{lastReport=report;renderDesktop(report);nodes.share.disabled=false;}});
nodes.share.addEventListener("click",()=>{if(lastReport)download(lastReport,"report");else if(lastSnapshot)download(sharingSnapshot(lastSnapshot),"share");});
nodes.quit.addEventListener("click",async()=>{
  const session=await sessionPromise;if(!session)return;
  try{const response=await fetch("/api/quit",{method:"POST",headers:{"X-EnvScope-Token":session.token}});
    if(response.ok){nodes.start.disabled=true;nodes.quit.hidden=true;byId("session-state").textContent="本地检测已结束";}}
  catch{byId("session-state").textContent="本地进程已停止";}
});
