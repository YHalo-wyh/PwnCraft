/** PwnCraft non-AI parallel file analysis renderer. */
(() => {
  'use strict';
  const runs=new Map();
  const esc=v=>String(v??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const icon=n=>window.lucideIcon?window.lucideIcon(n):'';
  const basename=p=>String(p||'').split(/[\\/]/).pop()||p;

  function ensurePage(){
    let page=document.getElementById('page-parallel');
    if(!page){page=document.createElement('section');page.id='page-parallel';page.className='page';page.hidden=true;document.getElementById('pages').appendChild(page);}
    return page;
  }
  function ensureActivity(){
    const bar=document.getElementById('activitybar');if(!bar||bar.querySelector('[data-key="parallel"]'))return;
    const button=document.createElement('button');button.className='activity-item';button.dataset.key='parallel';button.title='并行文件分析 · Vehicle / UAV / Web3 / Forensics';button.setAttribute('aria-label',button.title);button.innerHTML=icon('layers-3');
    const after=bar.querySelector('[data-key="analysis"]');if(after?.nextSibling)bar.insertBefore(button,after.nextSibling);else bar.appendChild(button);
    button.addEventListener('click',()=>{render();window.PwnApp.switchPage('parallel');});
  }
  function renderTrack(track){
    const title={vehicle:'车联网',uav:'低空 / UAV',web3:'Web3',forensics:'通用取证'}[track.track]||track.track;
    const status=track.status==='matched'?`${track.findings.length} 条`:(track.status==='error'?'错误':'未命中');
    const findings=(track.findings||[]).slice(0,80).map(f=>`<div class="pfa-finding sev-${esc(f.severity)}"><span>${esc(f.severity)}</span><b>${esc(f.title)}</b><p>${esc(f.detail||f.message||'')}</p></div>`).join('');
    return `<section class="pfa-track ${track.status}"><header><b>${esc(title)}</b><span>${esc(status)} · ${esc(track.durationMs??0)} ms</span></header>${findings||'<div class="pfa-empty">没有足够证据，未强行解释。</div>'}</section>`;
  }
  function render(){
    const page=ensurePage();const values=[...runs.values()];
    page.innerHTML=`<div class="pfa-shell">
      <div class="pfa-toolbar"><div><h2>Parallel Analysis</h2><p>一个文件同时送入 Pwn（仅 ELF）和非 AI 分析器。各链互不阻塞，不执行输入文件。</p></div><span class="flex-spacer"></span><button class="btn" id="pfa-clear">清空</button><button class="btn primary" id="pfa-pick">选择文件</button></div>
      <div class="pfa-lanes"><span>Pwn / ELF</span><span>Vehicle</span><span>UAV</span><span>Web3</span><span>Forensics</span></div>
      <div id="pfa-runs">${values.length?values.map(item=>{
        if(item.state==='running')return `<article class="pfa-run"><header><b>${esc(basename(item.path))}</b><span>并行解析中…</span></header><div class="pfa-progress"></div></article>`;
        if(item.state==='error')return `<article class="pfa-run"><header><b>${esc(basename(item.path))}</b><span class="bad">失败</span></header><pre>${esc(item.error)}</pre></article>`;
        const r=item.result;return `<article class="pfa-run"><header><div><b>${esc(r.file.name)}</b><small>${esc(r.file.path)} · ${r.file.size} bytes${r.file.truncated?' · bounded read':''}</small></div><span>${r.file.isElf?'Pwn + ':''}${r.matchedTracks.length?r.matchedTracks.join(' / '):'无非 AI 命中'} · ${r.durationMs} ms</span></header><div class="pfa-track-list">${r.results.map(renderTrack).join('')}</div></article>`;
      }).join(''):'<div class="pfa-drop-empty">拖入任意赛题文件，或点右上角“选择文件”。ELF 会继续走 PwnCraft 原始 Pwn 工作区，其余方向并行只读分析。</div>'}</div>
    </div>`;
    page.querySelector('#pfa-pick')?.addEventListener('click',pick);
    page.querySelector('#pfa-clear')?.addEventListener('click',()=>{runs.clear();render();});
  }

  async function ingest(path,{show=true}={}){
    if(!path)return;const old=runs.get(path);if(old?.state==='running')return;
    runs.set(path,{path,state:'running'});render();if(show)window.PwnApp.switchPage('parallel');
    const sidecar=window.pwncraft.parallelAnalyze(path);
    let probe=null;
    try{probe=await window.pwncraft.probeFile(path);}catch(error){runs.set(path,{path,state:'error',error:error.message});render();return;}
    if(probe.isElf&&window.__pwncraftDebug?.importElf){window.__pwncraftDebug.importElf(path);}
    try{const result=await sidecar;runs.set(path,{path,state:'done',result});render();if(!probe.isElf&&show)window.PwnApp.switchPage('parallel');}
    catch(error){runs.set(path,{path,state:'error',error:error.message});render();if(!probe.isElf&&show)window.PwnApp.switchPage('parallel');}
  }
  async function pick(){const path=await window.pwncraft.pickOpenPath('analysis');if(path)ingest(path,{show:true});}

  function relabelWelcome(){
    const drop=document.getElementById('drop-square');if(!drop)return;
    const main=drop.querySelector('.drop-main'),sub=drop.querySelector('.drop-sub');
    if(main)main.textContent='拖入赛题文件 · 自动并行分析';
    if(sub)sub.textContent='ELF 保留原 Pwn 解析 · 同时尝试 Vehicle / UAV / Web3 / 通用取证 · 或点击选择';
  }
  function overlay(){let o=document.getElementById('parallel-drop-overlay');if(o)return o;o=document.createElement('div');o.id='parallel-drop-overlay';o.hidden=true;o.innerHTML=`<div class="pfa-overlay-box">${icon('layers-3')}<b>松开开始并行分析</b><span>ELF → Pwn 原链 + Vehicle / UAV / Web3 / Forensics</span></div>`;document.body.appendChild(o);return o;}
  function bindUnifiedInput(){
    let depth=0;const codeDrag=()=>window.__pwncraftCodeDrag===true;
    document.addEventListener('dragenter',e=>{if(codeDrag())return;e.preventDefault();e.stopImmediatePropagation();depth++;overlay().hidden=false;},true);
    document.addEventListener('dragover',e=>{if(codeDrag())return;e.preventDefault();e.stopImmediatePropagation();},true);
    document.addEventListener('dragleave',e=>{if(codeDrag())return;e.preventDefault();e.stopImmediatePropagation();depth=Math.max(0,depth-1);if(!depth)overlay().hidden=true;},true);
    document.addEventListener('drop',e=>{if(codeDrag())return;e.preventDefault();e.stopImmediatePropagation();depth=0;overlay().hidden=true;const file=e.dataTransfer?.files?.[0];if(!file)return;const path=window.pwncraft.filePathFor?window.pwncraft.filePathFor(file):(file.path||'');if(path)ingest(path,{show:true});},true);
    document.addEventListener('click',e=>{if(!e.target.closest?.('#drop-square'))return;e.preventDefault();e.stopImmediatePropagation();pick();},true);
    document.addEventListener('keydown',e=>{
      if(e.target.closest?.('#drop-square')&&(e.key==='Enter'||e.key===' ')){e.preventDefault();e.stopImmediatePropagation();pick();return;}
      if(e.ctrlKey&&!e.altKey&&!e.metaKey&&!e.shiftKey&&e.key.toLowerCase()==='o'){e.preventDefault();e.stopImmediatePropagation();pick();}
    },true);
  }
  document.addEventListener('DOMContentLoaded',()=>{ensurePage();ensureActivity();render();relabelWelcome();bindUnifiedInput();});
  window.PwnParallelAnalysis={ingest,pick,render,runs};
})();
