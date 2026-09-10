'use strict';

const {performance}=require('perf_hooks');
const {readFileBounded,isElfBuffer,DEFAULT_MAX_BYTES}=require('./common');
const {analyzeVehicle}=require('./vehicle');
const {analyzeUav}=require('./uav');
const {analyzeWeb3}=require('./web3');
const {analyzeForensics}=require('./forensics');

const ANALYZERS=[
  {track:'vehicle',run:analyzeVehicle},
  {track:'uav',run:analyzeUav},
  {track:'web3',run:analyzeWeb3},
  {track:'forensics',run:analyzeForensics}
];

function sanitizeError(error){return String(error?.message||error||'unknown error').slice(0,500);}
async function analyzeFileParallel(filePath,options={}){
  const started=performance.now();
  const file=readFileBounded(filePath,options.maxBytes||DEFAULT_MAX_BYTES);
  const jobs=ANALYZERS.map(async analyzer=>{
    const t=performance.now();
    try{
      const value=await Promise.resolve().then(()=>analyzer.run(file));
      return {...value,track:analyzer.track,durationMs:Number((performance.now()-t).toFixed(2))};
    }catch(error){return {track:analyzer.track,status:'error',matched:false,findings:[],error:sanitizeError(error),durationMs:Number((performance.now()-t).toFixed(2))};}
  });
  const results=await Promise.all(jobs);
  const matched=results.filter(x=>x.status==='matched');
  return {
    schema:'pwncraft.parallel-file-analysis.v1',
    file:{path:file.path,name:file.name,ext:file.ext,size:file.size,readBytes:file.readBytes,truncated:file.truncated,sha256:file.sha256,isElf:isElfBuffer(file.buffer)},
    status:matched.length?'matched':'no-match',matchedTracks:matched.map(x=>x.track),
    results,
    errors:results.filter(x=>x.status==='error').map(x=>({track:x.track,error:x.error})),
    durationMs:Number((performance.now()-started).toFixed(2)),
    safety:{readOnly:true,executedInput:false,maxBytes:options.maxBytes||DEFAULT_MAX_BYTES,aiAnalyzers:false}
  };
}
function probeFile(filePath){
  const file=readFileBounded(filePath,4096);
  return {path:file.path,name:file.name,size:file.size,isElf:isElfBuffer(file.buffer)};
}

module.exports={ANALYZERS,analyzeFileParallel,probeFile};
