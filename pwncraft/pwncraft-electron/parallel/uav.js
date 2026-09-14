'use strict';

const {result,textView,likelyText,walkPcap}=require('./common');

const MAV_NAMES={0:'HEARTBEAT',1:'SYS_STATUS',24:'GPS_RAW_INT',30:'ATTITUDE',33:'GLOBAL_POSITION_INT',39:'MISSION_ITEM',44:'MISSION_COUNT',47:'MISSION_ACK',73:'MISSION_ITEM_INT',76:'COMMAND_LONG',77:'COMMAND_ACK',110:'FILE_TRANSFER_PROTOCOL',126:'SERIAL_CONTROL',253:'STATUSTEXT'};
const MAV_CMD={22:'NAV_TAKEOFF',176:'DO_SET_MODE',178:'DO_CHANGE_SPEED',300:'MISSION_START',400:'COMPONENT_ARM_DISARM',185:'DO_FLIGHTTERMINATION'};

function readU48LE(b,o){let v=0n;for(let i=5;i>=0;i--)v=(v<<8n)|BigInt(b[o+i]);return v;}
function parseMavlinkFrames(buffer,limit=6000){
  const frames=[];let o=0;
  while(o<buffer.length&&frames.length<limit){
    const magic=buffer[o];if(magic!==0xfe&&magic!==0xfd){o++;continue;}
    if(magic===0xfe){
      if(o+8>buffer.length)break;const len=buffer[o+1],size=6+len+2;if(o+size>buffer.length){o++;continue;}
      frames.push({version:1,offset:o,frameLength:size,payloadLength:len,seq:buffer[o+2],sysid:buffer[o+3],compid:buffer[o+4],msgid:buffer[o+5],signed:false,payload:buffer.subarray(o+6,o+6+len)});o+=size;continue;
    }
    if(o+12>buffer.length)break;const len=buffer[o+1],flags=buffer[o+2],signed=Boolean(flags&1),unsignedSize=10+len+2,size=unsignedSize+(signed?13:0);
    if(o+size>buffer.length){o++;continue;}
    let signature=null;if(signed){const t=buffer.subarray(o+unsignedSize,o+size);signature={linkId:t[0],timestamp:readU48LE(t,1).toString(),signatureHex:t.subarray(7,13).toString('hex')};}
    frames.push({version:2,offset:o,frameLength:size,payloadLength:len,seq:buffer[o+4],sysid:buffer[o+5],compid:buffer[o+6],msgid:buffer[o+7]|(buffer[o+8]<<8)|(buffer[o+9]<<16),signed,signature,payload:buffer.subarray(o+10,o+10+len)});o+=size;
  }
  return frames;
}
function decodeCommandLong(p){if(p.length<33)return null;return {params:Array.from({length:7},(_,i)=>p.readFloatLE(i*4)),command:p.readUInt16LE(28),targetSystem:p[30],targetComponent:p[31],confirmation:p[32]};}
function decodeHeartbeat(p){if(p.length<9)return null;return {customMode:p.readUInt32LE(0),type:p[4],autopilot:p[5],baseMode:p[6],systemStatus:p[7],mavlinkVersion:p[8],armed:Boolean(p[6]&0x80)};}
function decodeStatusText(p){if(p.length<2)return null;const x=p.subarray(1,Math.min(p.length,51)),z=x.indexOf(0);return {severity:p[0],text:x.subarray(0,z>=0?z:x.length).toString('utf8')};}
function decodeFtp(p){
  if(p.length<15)return null;const ftp=p.subarray(3),size=ftp[4],data=ftp.subarray(12,12+Math.min(size,Math.max(0,ftp.length-12))),opcode=ftp[3],reqOpcode=ftp[5];
  const out={targetSystem:p[1],targetComponent:p[2],sequence:ftp.readUInt16LE(0),session:ftp[2],opcode,reqOpcode,offset:ftp.readUInt32LE(8),dataLength:data.length};
  if([3,4,6,8,9,10,11,13,14,16].includes(opcode)){const z=data.indexOf(0);out.path=data.subarray(0,z>=0?z:data.length).toString('utf8').replace(/[^\x20-\x7e]/g,'.');}
  if((opcode===128&&[5,15].includes(reqOpcode))||opcode===15)out.chunkHex=data.toString('hex');
  return out;
}
function inspectMavlink(buffer){
  const frames=parseMavlinkFrames(buffer);const findings=[],counts={},commands=[],ftp=[],status=[];let signed=0,unsignedV2=0;
  frames.forEach((f,i)=>{
    const name=MAV_NAMES[f.msgid]||`MSG_${f.msgid}`;counts[name]=(counts[name]||0)+1;if(f.version===2){if(f.signed)signed++;else unsignedV2++;}
    if(f.msgid===0){const h=decodeHeartbeat(f.payload);if(h?.armed)findings.push({severity:'medium',title:'MAVLink HEARTBEAT 显示 armed',detail:`frame ${i+1} · sys=${f.sysid} comp=${f.compid}`,evidence:h});}
    if(f.msgid===76){const c=decodeCommandLong(f.payload);if(c){commands.push({...c,frameIndex:i+1});const n=MAV_CMD[c.command]||`CMD_${c.command}`;const sev=[400,185,22,300].includes(c.command)?'high':'medium';findings.push({severity:sev,title:`MAVLink COMMAND_LONG ${n}`,detail:`frame ${i+1} → ${c.targetSystem}:${c.targetComponent}`,evidence:c});}}
    if(f.msgid===110){const x=decodeFtp(f.payload);if(x){ftp.push({...x,frameIndex:i+1});if(x.path)findings.push({severity:'medium',title:'MAVLink FTP 文件访问',detail:`${x.path} · opcode=${x.opcode}`,evidence:x});}}
    if(f.msgid===253){const x=decodeStatusText(f.payload);if(x?.text)status.push({...x,frameIndex:i+1});}
  });
  if(frames.length)findings.unshift({severity:'info',title:`识别 MAVLink ${frames.length} 帧`,detail:`${Object.entries(counts).slice(0,8).map(([k,v])=>`${k}:${v}`).join(' · ')}`});
  if(unsignedV2&&signed)findings.push({severity:'medium',title:'MAVLink2 同时出现 signed / unsigned 流量',detail:`signed=${signed}, unsigned=${unsignedV2}`});
  return {matched:frames.length>0,findings,evidence:{frameCount:frames.length,messageCounts:counts,signedV2:signed,unsignedV2,commands:commands.slice(0,120),ftp:ftp.slice(0,120),statusText:status.slice(0,120)}};
}

function nmeaCoord(raw,hemi){if(!raw)return null;const v=Number(raw);if(!Number.isFinite(v))return null;const deg=Math.floor(v/100),min=v-deg*100;let out=deg+min/60;if(hemi==='S'||hemi==='W')out=-out;return Number(out.toFixed(7));}
function inspectNmea(text){
  const rows=[];for(const line of String(text||'').split(/\r?\n/)){
    const m=line.match(/^\$(?:GP|GN|GL|GA)(RMC|GGA),([^*\r\n]*)/);if(!m)continue;const fields=m[2].split(',');
    if(m[1]==='RMC')rows.push({type:'RMC',time:fields[0],valid:fields[1]==='A',lat:nmeaCoord(fields[2],fields[3]),lon:nmeaCoord(fields[4],fields[5]),speedKnots:Number(fields[6])||0,date:fields[8]});
    else rows.push({type:'GGA',time:fields[0],lat:nmeaCoord(fields[1],fields[2]),lon:nmeaCoord(fields[3],fields[4]),fix:Number(fields[5])||0,satellites:Number(fields[6])||0,altitude:Number(fields[8])});
  }
  const findings=[];if(rows.length)findings.push({severity:'info',title:`识别 NMEA GNSS ${rows.length} 条`,detail:'RMC/GGA 坐标与定位状态已解析'});
  for(let i=1;i<rows.length;i++){const a=rows[i-1],b=rows[i];if(a.lat==null||b.lat==null)continue;const d=Math.hypot((b.lat-a.lat)*111000,(b.lon-a.lon)*111000*Math.cos((a.lat||0)*Math.PI/180));if(d>50000)findings.push({severity:'high',title:'GNSS 位置出现超大跳变',detail:`相邻记录约 ${Math.round(d/1000)} km`,evidence:{from:a,to:b}});}
  return {matched:rows.length>0,findings,evidence:{rows:rows.slice(0,300)}};
}

function inspectFlightLogs(file,text){
  const findings=[],evidence={};let matched=false;
  if(file.buffer.length>=7&&file.buffer.subarray(0,7).equals(Buffer.from([0x55,0x4c,0x6f,0x67,0x01,0x12,0x35]))){matched=true;evidence.ulog={magic:'ULog 0x011235',size:file.size};findings.push({severity:'info',title:'识别 PX4 ULog',detail:`${file.size} bytes`});}
  const dataflashLines=String(text||'').split(/\r?\n/).filter(l=>/^(?:FMT|GPS|GPS2|PARM|MODE|EV|MSG),/.test(l));
  if(dataflashLines.length){matched=true;const kinds={};for(const l of dataflashLines)kinds[l.split(',')[0]]=(kinds[l.split(',')[0]]||0)+1;evidence.dataflash={records:dataflashLines.length,kinds,sample:dataflashLines.slice(0,80)};findings.push({severity:'info',title:`识别 ArduPilot DataFlash 文本日志 ${dataflashLines.length} 条`,detail:Object.entries(kinds).map(([k,v])=>`${k}:${v}`).join(' · ')});}
  return {matched,findings,evidence};
}

function inspectMediaFirmware(file){
  const b=file.buffer,findings=[],evidence={signatures:[]};let matched=false;
  const sigs=[
    {name:'SquashFS',needle:Buffer.from('hsqs'),severity:'medium'},
    {name:'GZIP',needle:Buffer.from([0x1f,0x8b,0x08]),severity:'info'},
    {name:'UBI',needle:Buffer.from('UBI#'),severity:'medium'},
    {name:'uImage',needle:Buffer.from([0x27,0x05,0x19,0x56]),severity:'medium'},
    {name:'H264 Annex-B',needle:Buffer.from([0,0,0,1,0x67]),severity:'info'},
    {name:'H265 Annex-B',needle:Buffer.from([0,0,0,1,0x40]),severity:'info'}
  ];
  for(const s of sigs){const o=b.indexOf(s.needle);if(o>=0){matched=true;evidence.signatures.push({name:s.name,offset:o,offsetHex:`0x${o.toString(16)}`});findings.push({severity:s.severity,title:`发现 ${s.name} 签名`,detail:`offset=0x${o.toString(16)}`});}}
  if(b.length>=2&&b.subarray(0,2).toString('latin1')==='PA'){
    matched=true;findings.push({severity:'info',title:'识别 ArduPilot AP_Param EEPROM',detail:`${b.length} bytes`});
    const magic=Buffer.from([0xd1,0xfc,0x52,0x38]),o=b.indexOf(magic);if(o>=0&&o+48<=b.length){const key=b.subarray(o+16,o+48);findings.push({severity:'high',title:'发现 MAVLink2 signing-key 结构',detail:`offset=0x${o.toString(16)} · 32-byte key`,evidence:{offset:o,keyHex:key.toString('hex')}});}
  }
  return {matched,findings,evidence};
}

function inspectWifiPcap(buffer){
  const walked=walkPcap(buffer,6000);if(!walked.header||![105,127].includes(walked.header.linkType))return {matched:false,findings:[],evidence:{}};
  let management=0,data=0,deauth=0,eapolHint=0;
  for(const p of walked.packets){let d=p.data;if(walked.header.linkType===127){if(d.length<4)continue;const rtLen=d.readUInt16LE(2);if(rtLen<4||rtLen>d.length)continue;d=d.subarray(rtLen);}if(d.length<2)continue;const fc=d.readUInt16LE(0),type=(fc>>2)&3,sub=(fc>>4)&15;if(type===0){management++;if(sub===12)deauth++;}else if(type===2)data++;if(p.data.includes(Buffer.from([0x88,0x8e])))eapolHint++;}
  const findings=[{severity:'info',title:'识别 802.11 PCAP',detail:`linktype=${walked.header.linkType} · packets=${walked.packets.length}`}];
  if(deauth)findings.push({severity:'medium',title:'发现 802.11 Deauthentication 帧',detail:`count=${deauth}`});
  if(eapolHint)findings.push({severity:'medium',title:'发现可能的 EAPOL/WPA 握手流量',detail:`packets≈${eapolHint}`});
  return {matched:true,findings,evidence:{linkType:walked.header.linkType,packets:walked.packets.length,management,data,deauth,eapolHint}};
}

function analyzeUav(file){
  const text=likelyText(file.buffer)?textView(file.buffer):'';
  const parts=[inspectMavlink(file.buffer),inspectNmea(text),inspectFlightLogs(file,text),inspectMediaFirmware(file),inspectWifiPcap(file.buffer)];
  const matched=parts.some(p=>p.matched);const findings=parts.flatMap(p=>p.findings||[]);const evidence={};
  Object.assign(evidence,{mavlink:parts[0].evidence,nmea:parts[1].evidence,flightLog:parts[2].evidence,mediaFirmware:parts[3].evidence,wifi:parts[4].evidence});
  return result('uav',matched,findings,{evidence});
}

module.exports={parseMavlinkFrames,inspectMavlink,inspectNmea,inspectFlightLogs,inspectMediaFirmware,inspectWifiPcap,analyzeUav};
