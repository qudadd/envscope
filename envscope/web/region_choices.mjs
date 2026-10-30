// Suggestions are form values, never evidence of the user's physical location.
export const countryCode=value=>/^[A-Za-z]{2}$/.test(String(value||'').trim())?String(value).trim().toUpperCase():'';
export function cityChoices(profiles,country){return profiles.filter(p=>p.country===countryCode(country));}
export function suggestedCity(profiles,observation){
  if(observation?.state!=='observed'||!observation.timezone)return null;
  const matches=cityChoices(profiles,observation.country).filter(p=>p.iana===observation.timezone||p.aliases?.includes(observation.timezone));
  return matches.length===1?matches[0]:null;
}
