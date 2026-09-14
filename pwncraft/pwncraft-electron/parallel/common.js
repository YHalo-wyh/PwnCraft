'use strict';

const fs=require('fs');
const path=require('path');
const crypto=require('crypto');

const DEFAULT_MAX_BYTES=64*1024*1024;

function readFileBounded(filePath,maxBytes=DEFAULT_MAX_BYTES){
  const resolved=path.resolve(String(filePath||''));
  const st=fs.statSync(resolved);
  if(!st.isFile()) throw new Error('仅支持普通文件');
  const limit=Math.max(4096,Number(maxBytes)||DEFAULT_MAX_BYTES);
  const take=Math.min(st.size,limit);
  const fd=fs.openSync(resolved,'r');
  try{
    const buffer=Buffer.allocUnsafe(take);
    let read=0;
    while(read<take){
      const n=fs.readSync(fd,buffer,read,take-read,read);
      if(!n)break;
      read+=n;
    }
    const data=read===take?buffer:buffer.subarray(0,read);
    return {
      path:resolved,name:path.basename(resolved),ext:path.extname(resolved).toLowerCase(),
      size:st.size,readBytes:data.length,truncated:st.size>data.length,
      sha256:crypto.createHash('sha256').update(data).digest('hex'),buffer:data
    };
  } finally { fs.closeSync(fd); }
}

function isElfBuffer(buffer){return Buffer.isBuffer(buffer)&&buffer.length>=4&&buffer[0]===0x7f&&buffer[1]===0x45&&buffer[2]===0x4c&&buffer[3]===0x46;}
function isElfPath(filePath){
  const fd=fs.openSync(path.resolve(String(filePath||'')),'r');
  try{const b=Buffer.alloc(4);return fs.readSync(fd,b,0,4,0)===4&&isElfBuffer(b);}finally{fs.closeSync(fd);}
}

function likelyText(buffer){
  if(!buffer||!buffer.length)return false;
  const sample=buffer.subarray(0,Math.min(buffer.length,65536));
  let printable=0,zero=0;
  for(const b of sample){if(b===0)zero++;if(b===9||b===10||b===13||(b>=0x20&&b<0x7f)||b>=0xc2)printable++;}
  return zero===0&&printable/sample.length>=0.82;
}
function textView(buffer,max=4*1024*1024){
  if(!buffer)return '';
  return buffer.subarray(0,Math.min(buffer.length,max)).toString('utf8');
}
function cleanHex(input){
  const value=String(input||'').replace(/^0x/i,'').replace(/[^0-9a-f]/gi,'');
  if(!value||value.length%2)return '';
  return value.toLowerCase();
}
function severityRank(v){return ({critical:0,high:1,medium:2,low:3,info:4})[v]??9;}
function normalizeFinding(item,track){
  return {track,severity:item.severity||'info',title:String(item.title||item.id||'发现'),detail:String(item.detail||item.message||item.evidence||''),...item};
}
function summarizeFindings(findings){
  const counts={critical:0,high:0,medium:0,low:0,info:0};
  for(const f of findings||[])counts[f.severity]=(counts[f.severity]||0)+1;
  return counts;
}
function result(track,matched,findings=[],extra={}){
  const normalized=(findings||[]).map(x=>normalizeFinding(x,track)).sort((a,b)=>severityRank(a.severity)-severityRank(b.severity));
  return {track,status:matched?'matched':'no-match',matched:Boolean(matched),findings:normalized,summary:summarizeFindings(normalized),...extra};
}

function parsePcapHeader(buffer){
  if(!buffer||buffer.length<24)return null;
  const magic=buffer.readUInt32LE(0);
  let le=true,nano=false;
  if(magic===0xa1b2c3d4){le=true;}
  else if(magic===0xd4c3b2a1){le=false;}
  else if(magic===0xa1b23c4d){le=true;nano=true;}
  else if(magic===0x4d3cb2a1){le=false;nano=true;}
  else return null;
  const read32=(o)=>le?buffer.readUInt32LE(o):buffer.readUInt32BE(o);
  return {format:'pcap',littleEndian:le,nanosecond:nano,linkType:read32(20),snaplen:read32(16)};
}
function walkPcap(buffer,limit=12000){
  const header=parsePcapHeader(buffer);if(!header)return {header:null,packets:[]};
  const packets=[];let off=24;
  const read32=(o)=>header.littleEndian?buffer.readUInt32LE(o):buffer.readUInt32BE(o);
  while(off+16<=buffer.length&&packets.length<limit){
    const tsSec=read32(off),tsFrac=read32(off+4),incl=read32(off+8),orig=read32(off+12);
    if(incl>16*1024*1024||off+16+incl>buffer.length)break;
    packets.push({index:packets.length+1,tsSec,tsFrac,includedLength:incl,originalLength:orig,data:buffer.subarray(off+16,off+16+incl)});
    off+=16+incl;
  }
  return {header,packets};
}
function isPcapng(buffer){return !!(buffer&&buffer.length>=12&&buffer.readUInt32LE(0)===0x0a0d0d0a);}

module.exports={DEFAULT_MAX_BYTES,readFileBounded,isElfBuffer,isElfPath,likelyText,textView,cleanHex,result,summarizeFindings,parsePcapHeader,walkPcap,isPcapng};
