// Independent implementation of standard WebRTC/HTTP observations; see notices.
export const STATUS_TEXT = {pass:"范围内通过",warn:"需要复核",fail:"策略违反",unknown:"未知",skipped:"未检测"};

export function normalizeIP(input) {
  if (typeof input !== "string" || input.includes("%")) return null;
  let value = input.trim().toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    const bytes = value.split(".");
    if (bytes.some(b => Number(b)>255 || (b.length>1 && b[0]==="0"))) return null;
    return bytes.map(Number).join(".");
  }
  if (value.includes(".")) {
    const last = value.lastIndexOf(":");
    if (last<0) return null;
    const v4 = normalizeIP(value.slice(last+1));
    if (!v4 || v4.includes(":")) return null;
    const bytes = v4.split(".").map(Number);
    value = value.slice(0,last+1) + ((bytes[0]<<8)|bytes[1]).toString(16) + ":" + ((bytes[2]<<8)|bytes[3]).toString(16);
  }
  if (!/^[a-f0-9:]+$/.test(value) || value.split("::").length>2) return null;
  const halves = value.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length===2 && halves[1] ? halves[1].split(":") : [];
  if ([...left,...right].some(x => !/^[a-f0-9]{1,4}$/.test(x))) return null;
  const missing = 8-left.length-right.length;
  if ((halves.length===1 && left.length!==8) || (halves.length===2 && missing<1)) return null;
  const groups = halves.length===2 ? [...left,...Array(missing).fill("0"),...right] : left;
  const nums = groups.map(x=>parseInt(x,16));
  if (nums.slice(0,5).every(x=>x===0) && nums[5]===0xffff) return [nums[6]>>8,nums[6]&255,nums[7]>>8,nums[7]&255].join(".");
  return nums.map(x=>x.toString(16).padStart(4,"0")).join(":");
}

export function isPublicIP(value) {
  const normalized=normalizeIP(value);
  if (!normalized) return false;
  if (!normalized.includes(":")) {
    const [a,b,c]=normalized.split(".").map(Number);
    return !(a===0 || a===10 || a===127 || a>=224 || (a===100 && b>=64 && b<=127) ||
      (a===169&&b===254) || (a===172&&b>=16&&b<=31) || (a===192&&b===168) ||
      (a===192&&b===0&&c===0) || (a===192&&b===0&&c===2) || (a===192&&b===88&&c===99) ||
      (a===198&&(b===18||b===19)) || (a===198&&b===51&&c===100) || (a===203&&b===0&&c===113));
  }
  // Conservative global-unicast allow space; special ranges remain unverified.
  const groups=normalized.split(":").map(x=>parseInt(x,16));
  return groups[0]>=0x2000 && groups[0]<=0x3fff && !(groups[0]===0x2001 &&
    (groups[1]===0x0db8 || groups[1]<0x0200)) && !(groups[0]===0x2002) &&
    !(groups[0]===0x3fff && groups[1]<=0x0fff);
}

export function parseCandidate(candidate) {
  if (typeof candidate!=="string" || candidate.length>2048) return null;
  const tokens=candidate.trim().replace(/^a=/,"").split(/\s+/);
  if (!tokens[0]?.startsWith("candidate:") || tokens.length<8 || tokens[6]!=="typ" ||
      !["host","srflx","prflx","relay"].includes(tokens[7])) return null;
  return {address:tokens[4],type:tokens[7],protocol:tokens[2].toLowerCase()};
}

export function assessHTTP(observations, family=4) {
  const valid=observations.filter(o=>isPublicIP(o.ip) && (normalizeIP(o.ip).includes(":")?6:4)===family);
  if (!valid.length) return {status:"unknown",summary:"未取得有效地址；不能由超时推断安全。",evidence:observations};
  if (family===6) return {status:"warn",summary:"已观测 IPv6 出口；需在 CLI 配置 IPv6 允许范围后复核。",evidence:observations};
  if (new Set(valid.map(o=>o.source)).size<2) return {status:"warn",summary:"只有一个独立服务返回有效地址，证据不足。",evidence:observations};
  if (new Set(valid.map(o=>normalizeIP(o.ip))).size>1) return {status:"warn",summary:"独立服务返回不同出口，可能存在多出口或分流。",evidence:observations};
  return {status:"pass",summary:"两个独立服务观测到相同 IPv4；仅证明本次 HTTP 出口一致。",evidence:observations};
}

export function assessICE(candidates, http, complete) {
  const comparable=candidates.filter(c=>["host","srflx","prflx"].includes(c.type)&&isPublicIP(c.address));
  if (!complete) return {status:"unknown",summary:"ICE 收集未完成，不能判定通过。",evidence:candidates};
  if (!comparable.length) return {status:"unknown",summary:"没有可比较的公网候选；mDNS、relay 或无响应均不是零暴露证明。",evidence:candidates};
  const observed=new Set(http.filter(o=>isPublicIP(o.ip)).map(o=>normalizeIP(o.ip)));
  if (comparable.some(c=>!observed.has(normalizeIP(c.address)))) return {status:"warn",summary:"出现不同于浏览器 HTTP 的公网候选；需结合允许地址和网络路径复核。",evidence:candidates};
  const families=new Set(comparable.map(c=>normalizeIP(c.address).includes(":")?6:4));
  if ([...families].some(f=>new Set(http.filter(o=>isPublicIP(o.ip)&&(normalizeIP(o.ip).includes(":")?6:4)===f).map(o=>o.source)).size<2))
    return {status:"warn",summary:"候选与已观测地址相符，但同地址族的 HTTP 对照不足。",evidence:candidates};
  return {status:"pass",summary:"本次收集的公网候选与同一浏览器 HTTP 观测相符。",evidence:candidates};
}

export function sharingSnapshot(snapshot) {
  const result=structuredClone(snapshot);
  const aliases=new Map();
  const alias=value=>{const key=normalizeIP(value)||value;if(!aliases.has(key)) aliases.set(key,`[address-${aliases.size+1}]`);return aliases.get(key);};
  result.http=result.http.map(o=>o.ip?{...o,ip:alias(o.ip)}:o);
  result.ice=result.ice.map(o=>({...o,address:alias(o.address)}));
  result.contains_sensitive=false;
  return result;
}
