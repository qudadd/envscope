// Reorder existing controls without duplicating their state or action handlers.
export function initWorkspace(){
  const setup=document.getElementById('upkeep-prepare')?.closest('section');
  const status=document.querySelector('#page-upkeep>.upkeep-state');
  if(setup&&status){setup.id='upkeep-setup';status.after(setup);}
  const advanced=document.createElement('details');advanced.id='advanced-maintenance';
  const title=document.createElement('summary');title.textContent='系统守护与高级修复';advanced.append(title);
  for(const id of ['timezone-service-panel','process-guard-panel','client-panel','language-panel','network-panel','routing-panel','components-panel','software-panel']){
    const section=document.getElementById(id);if(section)advanced.append(section);
  }
  setup?.after(advanced);
  const tools=document.getElementById('environment-tools'),heading=document.querySelector('#page-tools>h1');
  if(tools&&heading)heading.after(tools);
  const sources=document.getElementById('opensource-tools');
  if(sources){
    const disclosure=document.createElement('details'),summary=document.createElement('summary');
    disclosure.id=sources.id;disclosure.className=sources.className;summary.textContent='开源方案使用说明';
    sources.querySelector('h2')?.remove();disclosure.append(summary,...sources.childNodes);sources.replaceWith(disclosure);
    document.getElementById('tool-output')?.before(disclosure);
  }
}
