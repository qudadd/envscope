// Original MIT-licensed EnvScope line icons. All symbols retain visible labels.
const paths={
  scan:'M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M8 12h8M12 8v8',
  guard:'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Zm-4 9 3 3 5-6',
  accounts:'M8 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-6 9v-2a6 6 0 0 1 12 0v2m3-15a4 4 0 0 1 0 8m1 3a5 5 0 0 1 4 4',
  checks:'m3 6 1 1 2-3m-3 9 1 1 2-3m-3 9 1 1 2-3M10 6h11M10 13h11M10 20h11',
  tools:'M14 6a5 5 0 0 0-6 6L3 17a2.8 2.8 0 0 0 4 4l5-5a5 5 0 0 0 6-6l-3 3-4-4 3-3Z',
  history:'M3 11a9 9 0 1 1 2 7M3 4v7h7m2-5v6l4 3',
  settings:'M4 6h16M4 12h16M4 18h16M8 3v6m8 0v6m-8 0v6',
  coverage:'M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z',
  more:'M4 6h16M4 12h16M4 18h16',
  help:'M9 8a3 3 0 1 1 5 2c-2 1-2 2-2 3m0 4h.01M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20',
  power:'M12 2v10M6 5a9 9 0 1 0 12 0'
};
export function icon(name){
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('class','ui-icon');svg.setAttribute('aria-hidden','true');svg.setAttribute('focusable','false');
  const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',paths[name]||paths.scan);svg.append(path);return svg;
}
export function mountIcons(){
  const names={audit:'scan',upkeep:'guard',accounts:'accounts',checks:'checks',tools:'tools',history:'history',settings:'settings',coverage:'coverage'};
  for(const button of document.querySelectorAll('.tab[data-page]'))button.prepend(icon(names[button.dataset.page]));
  for(const [id,name] of [['learning-replay','help'],['quit','power']])document.getElementById(id)?.prepend(icon(name));
  document.querySelector('#more-menu>summary')?.prepend(icon('more'));
}
