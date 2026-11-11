'use strict';
const {parentPort,workerData}=require('worker_threads');
const {analyzeFileParallel}=require('./parallel_file_analysis');
(async()=>{
  try{parentPort.postMessage({ok:true,result:await analyzeFileParallel(workerData.filePath,workerData.options||{})});}
  catch(error){parentPort.postMessage({ok:false,error:String(error?.message||error).slice(0,1000)});}
})();
