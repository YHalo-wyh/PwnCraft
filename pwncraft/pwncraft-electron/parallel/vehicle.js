'use strict';

const {result,textView,likelyText}=require('./common');

const UDS_SERVICES={0x10:'DiagnosticSessionControl',0x11:'ECUReset',0x14:'ClearDiagnosticInformation',0x19:'ReadDTCInformation',0x22:'ReadDataByIdentifier',0x23:'ReadMemoryByAddress',0x27:'SecurityAccess',0x28:'CommunicationControl',0x2e:'WriteDataByIdentifier',0x31:'RoutineControl',0x34:'RequestDownload',0x35:'RequestUpload',0x36:'TransferData',0x37:'RequestTransferExit',0x3e:'TesterPresent',0x85:'ControlDTCSetting'};
const UDS_NRC={0x10:'generalReject',0x11:'serviceNotSupported',0x12:'subFunctionNotSupported',0x13:'incorrectMessageLengthOrInvalidFormat',0x21:'busyRepeatRequest',0x22:'conditionsNotCorrect',0x24:'requestSequenceError',0x31:'requestOutOfRange',0x33:'securityAccessDenied',0x35:'invalidKey',0x36:'exceedNumberOfAttempts',0x37:'requiredTimeDelayNotExpired',0x70:'uploadDownloadNotAccepted',0x71:'transferDataSuspended',0x72:'generalProgrammingFailure',0x73:'wrongBlockSequenceCounter',0x78:'responsePending'};

function parseCanLine(line){
  const raw=String(line||'').trim();if(!raw||raw.startsWith('#'))return null;
  let timestamp=null,id=null,payload=null,m;
  m=raw.match(/^\(([-\d.]+)\)\s+\S+\s+([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]*)/);
  if(m){timestamp=Number(m[1]);id=m[2];payload=m[3];}
  else if((m=raw.match(/^(?:\S+\s+)?([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]*)/))){id=m[1];payload=m[2];}
  else if((m=raw.match(/^(?:\(([-\d.]+)\)\s+)?\S*\s*([0-9A-Fa-f]{3,8})\s+\[(\d+)\]\s+(.+)$/))){timestamp=m[1]?Number(m[1]):null;id=m[2];payload=m[4].replace(/[^0-9A-Fa-f]/g,'');}
  if(!id||payload==null||payload.length%2)return null;
  return {timestamp:Number.isFinite(timestamp)?timestamp:null,id:id.toUpperCase(),bytes:[...Buffer.from(payload,'hex')],raw};
}

function decodeUdsBytes(bytes){
  if(!bytes||!bytes.length)return null;
  const sid=bytes[0];
  if(sid===0x7f&&bytes.length>=3)return {negative:true,requestSid:`0x${bytes[1].toString(16)}`,service:UDS_SERVICES[bytes[1]]||'unknown',nrc:`0x${bytes[2].toString(16)}`,nrcName:UDS_NRC[bytes[2]]||'unknown'};
  const positive=sid>=0x40&&UDS_SERVICES[sid-0x40];
  const requestSid=positive?sid-0x40:sid;
  const out={sid:`0x${sid.toString(16)}`,positive:Boolean(positive),service:UDS_SERVICES[requestSid]||'unknown'};
  if(requestSid===0x27&&bytes.length>=2)out.securityAccess={subFunction:bytes[1],level:Math.ceil(bytes[1]/2),meaning:bytes[1]%2?'requestSeed':'sendKey',seedOrKey:bytes.length>2?Buffer.from(bytes.slice(2)).toString('hex'):''};
  if(requestSid===0x10&&bytes.length>=2)out.session={subFunction:bytes[1],name:({1:'defaultSession',2:'programmingSession',3:'extendedDiagnosticSession'})[bytes[1]]||'vendorSpecific'};
  if(requestSid===0x22&&bytes.length>=3)out.did=`0x${Buffer.from(bytes.slice(1,3)).toString('hex')}`;
  if(requestSid===0x36&&bytes.length>=2)out.transferData={blockSequenceCounter:bytes[1],dataLength:Math.max(0,bytes.length-2)};
  if(requestSid===0x23&&bytes.length>=2){
    const alfid=bytes[1],addressLength=alfid&0xf,sizeLength=alfid>>4,need=2+addressLength+sizeLength;
    if(addressLength&&sizeLength&&bytes.length>=need){
      const toBig=a=>a.reduce((v,b)=>(v<<8n)|BigInt(b),0n);
      out.readMemory={address:`0x${toBig(bytes.slice(2,2+addressLength)).toString(16)}`,size:toBig(bytes.slice(2+addressLength,need)).toString()};
    }
  }
  return out;
}

function reassembleIsoTpFrames(frames){
  const active=new Map(),sessions=[];
  const finish=(s,complete,error=null)=>{const payload=s.data.slice(0,s.totalLength);sessions.push({canId:`0x${s.id}`,complete,error,totalLength:s.totalLength,collectedLength:s.data.length,frameCount:s.frameCount,payload:Buffer.from(payload).toString('hex'),uds:complete?decodeUdsBytes(payload):null});};
  frames.forEach((frame,index)=>{
    const b=frame.bytes||[],id=String(frame.id||'').toUpperCase();if(!id||!b.length)return;
    const type=b[0]>>4;
    if(type===0){const len=b[0]&0xf;if(!len||len>b.length-1)return;const p=b.slice(1,1+len);sessions.push({canId:`0x${id}`,complete:true,totalLength:len,collectedLength:len,frameCount:1,payload:Buffer.from(p).toString('hex'),uds:decodeUdsBytes(p)});return;}
    if(type===1&&b.length>=3){const total=((b[0]&0xf)<<8)|b[1];if(total<=b.length-2)return;const prev=active.get(id);if(prev)finish(prev,false,'new-first-frame-before-completion');active.set(id,{id,totalLength:total,data:b.slice(2),expected:1,frameCount:1,start:index+1});return;}
    if(type===2){const s=active.get(id);if(!s)return;const seq=b[0]&0xf;if(seq!==s.expected){finish(s,false,`sequence-mismatch expected=${s.expected} actual=${seq}`);active.delete(id);return;}s.data.push(...b.slice(1));s.frameCount++;s.expected=(s.expected+1)&0xf;if(s.data.length>=s.totalLength){finish(s,true);active.delete(id);}}
  });
  for(const s of active.values())finish(s,false,'capture-ended-before-completion');
  return sessions;
}

function analyzeCanopen(frames){
  const events=[];
  for(let i=0;i<frames.length;i++){
    const f=frames[i],id=parseInt(f.id,16),b=f.bytes||[];if(b.length<4)continue;
    let direction=null,nodeId=null;
    if(id>=0x600&&id<=0x67f){direction='client-to-server';nodeId=id-0x600;}
    else if(id>=0x580&&id<=0x5ff){direction='server-to-client';nodeId=id-0x580;}
    else continue;
    const cs=b[0],index=b[1]|(b[2]<<8),subIndex=b[3];
    const known=({0x1000:'Device Type',0x1008:'Manufacturer Device Name',0x1009:'Manufacturer Hardware Version',0x100a:'Manufacturer Software Version',0x1018:'Identity Object'})[index]||null;
    let transfer='sdo';
    if((cs&0xe0)===0x40)transfer='upload-initiate';
    else if((cs&0xe0)===0x20)transfer='download-initiate';
    else if((cs&0xe0)===0x00)transfer='download-segment';
    else if((cs&0xe0)===0x60)transfer='upload-segment';
    else if(cs===0x80)transfer='abort';
    const expedited=Boolean(cs&0x02),sizeIndicated=Boolean(cs&0x01);
    let dataHex='',ascii='';
    if(expedited&&b.length>=8){const unused=(cs>>2)&3;const len=sizeIndicated?Math.max(0,4-unused):4;const d=Buffer.from(b.slice(4,4+len));dataHex=d.toString('hex');ascii=d.toString('utf8').replace(/[^\x20-\x7e]/g,'.');}
    events.push({frameIndex:i+1,cobId:`0x${id.toString(16)}`,nodeId,direction,transfer,index:`0x${index.toString(16).padStart(4,'0')}`,subIndex,knownObject:known,expedited,dataHex,ascii});
  }
  return events;
}

function analyzeVehicle(file){
  const text=textView(file.buffer);
  const lines=text.split(/\r?\n/);
  const frames=likelyText(file.buffer)?lines.map(parseCanLine).filter(Boolean):[];
  if(!frames.length)return result('vehicle',false,[],{evidence:{parsedFrames:0}});
  const findings=[];
  const groups=new Map();frames.forEach(f=>{if(!groups.has(f.id))groups.set(f.id,[]);groups.get(f.id).push(f);});
  const ids=[...groups.entries()].map(([id,list])=>({id:`0x${id}`,count:list.length,dlc:[...new Set(list.map(f=>f.bytes.length))]})).sort((a,b)=>b.count-a.count);
  const isoTp=reassembleIsoTpFrames(frames);
  const uds=isoTp.filter(s=>s.complete&&s.uds&&s.uds.service!=='unknown');
  const canopen=analyzeCanopen(frames);
  if(frames.length)findings.push({severity:'info',title:`识别 CAN/CAN-FD 文本帧 ${frames.length} 条`,detail:`${ids.length} 个 CAN ID`});
  for(const s of uds.slice(0,30)){
    const u=s.uds;let severity='info';
    if(u.service==='SecurityAccess'||u.service==='RequestDownload'||u.service==='RequestUpload'||u.service==='TransferData'||u.service==='ReadMemoryByAddress')severity='high';
    findings.push({severity,title:`UDS ${u.service}`,detail:`${s.canId} ${s.payload}${u.nrcName?` · NRC ${u.nrcName}`:''}`,evidence:s});
  }
  const knownCanopen=canopen.filter(e=>e.knownObject);
  for(const e of knownCanopen.slice(0,20))findings.push({severity:'medium',title:`CANopen ${e.knownObject}`,detail:`${e.cobId} ${e.index}:${e.subIndex}${e.ascii?` · ${e.ascii}`:''}`,evidence:e});
  return result('vehicle',true,findings,{evidence:{parsedFrames:frames.length,uniqueIds:ids.length,ids:ids.slice(0,80),isoTpSessions:isoTp.slice(0,100),canopen:canopen.slice(0,120)}});
}

module.exports={parseCanLine,decodeUdsBytes,reassembleIsoTpFrames,analyzeCanopen,analyzeVehicle};
