'use strict';

const zlib=require('zlib');
const {result,textView,likelyText,parsePcapHeader,isPcapng}=require('./common');

const MAGIC=[
  {name:'ELF',bytes:Buffer.from([0x7f,0x45,0x4c,0x46]),kind:'binary'},
  {name:'PE',bytes:Buffer.from('MZ'),kind:'binary'},
  {name:'PNG',bytes:Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]),kind:'image'},
  {name:'JPEG',bytes:Buffer.from([0xff,0xd8,0xff]),kind:'image'},
  {name:'ZIP',bytes:Buffer.from([0x50,0x4b,0x03,0x04]),kind:'archive'},
  {name:'GZIP',bytes:Buffer.from([0x1f,0x8b,0x08]),kind:'archive'},
  {name:'7z',bytes:Buffer.from([0x37,0x7a,0xbc,0xaf,0x27,0x1c]),kind:'archive'},
  {name:'RAR',bytes:Buffer.from([0x52,0x61,0x72,0x21,0x1a,0x07]),kind:'archive'},
  {name:'SQLite',bytes:Buffer.from('SQLite format 3\x00','binary'),kind:'database'},
  {name:'SquashFS',bytes:Buffer.from('hsqs'),kind:'firmware'},
  {name:'UBI',bytes:Buffer.from('UBI#'),kind:'firmware'},
  {name:'uImage',bytes:Buffer.from([0x27,0x05,0x19,0x56]),kind:'firmware'},
  {name:'PDF',bytes:Buffer.from('%PDF-'),kind:'document'}
];
function magicHits(buffer){
  const out=[];for(const m of MAGIC){let from=0,count=0;while(from<buffer.length&&count<12){const o=buffer.indexOf(m.bytes,from);if(o<0)break;out.push({name:m.name,kind:m.kind,offset:o,offsetHex:`0x${o.toString(16)}`});from=o+1;count++;}}return out.sort((a,b)=>a.offset-b.offset);
}
function printableStrings(buffer,min=6,limit=800){
  const out=[];let start=-1;for(let i=0;i<=buffer.length;i++){const b=i<buffer.length?buffer[i]:0;const ok=b>=0x20&&b<=0x7e;if(ok&&start<0)start=i;if(!ok&&start>=0){if(i-start>=min){out.push({offset:start,text:buffer.subarray(start,i).toString('ascii')});if(out.length>=limit)break;}start=-1;}}return out;
}
function findInterestingStrings(strings){
  const rules=[
    {id:'flag-shape',re:/\b(?:flag|ctf|iscc|ciscn|actf|ynuctf|palu)\{[^}\r\n]{1,160}\}/i,severity:'high',title:'发现 flag-shaped 字符串'},
    {id:'url',re:/https?:\/\/[^\s"'<>]{5,180}/i,severity:'info',title:'发现 URL'},
    {id:'credential',re:/(?:password|passwd|token|secret|api[_-]?key|username)\s*[:=]\s*[^\s,;]{3,100}/i,severity:'medium',title:'发现凭据/secret 线索'},
    {id:'ftp',re:/\b(?:USER|PASS)\s+[^\r\n]{1,80}/i,severity:'medium',title:'发现 FTP 明文认证线索'},
    {id:'rtsp',re:/rtsp:\/\/[^\s"'<>]{5,180}/i,severity:'medium',title:'发现 RTSP 地址'}
  ];
  const findings=[];for(const s of strings){for(const r of rules){const m=s.text.match(r.re);if(m)findings.push({severity:r.severity,title:r.title,detail:m[0].slice(0,220),evidence:{offset:s.offset,text:s.text.slice(0,260)},id:r.id});if(findings.length>=120)return findings;}}
  return findings;
}
function recursiveDecodeText(text){
  const findings=[],seen=new Set();let frontier=[{label:'raw',text:String(text||'').trim(),depth:0}];
  for(let round=0;round<3&&frontier.length;round++){
    const next=[];for(const item of frontier){const key=item.text.slice(0,4096);if(seen.has(key))continue;seen.add(key);const candidates=[];
      if(/^[A-Za-z0-9+/=\r\n]{16,}$/.test(item.text)&&item.text.replace(/\s/g,'').length%4===0){try{const b=Buffer.from(item.text.replace(/\s/g,''),'base64');if(b.length)candidates.push({kind:'base64',buffer:b});}catch{}}
      const hex=item.text.replace(/\s+/g,'');if(/^(?:0x)?[0-9a-fA-F]{16,}$/.test(hex)){const h=hex.replace(/^0x/,'');if(h.length%2===0)candidates.push({kind:'hex',buffer:Buffer.from(h,'hex')});}
      for(const c of candidates){let b=c.buffer,kind=c.kind;if(b.length>=3&&b[0]===0x1f&&b[1]===0x8b&&b[2]===0x08){try{b=zlib.gunzipSync(b,{maxOutputLength:8*1024*1024});kind+='→gzip';}catch{}}
        const decoded=b.toString('utf8');if(/[\x20-\x7e\u4e00-\u9fff]/.test(decoded)){findings.push({severity:'info',title:`递归解码 ${kind}`,detail:decoded.slice(0,240),evidence:{depth:item.depth+1,bytes:b.length}});if(item.depth<2)next.push({label:kind,text:decoded.trim(),depth:item.depth+1});}}
    }frontier=next;
  }
  return findings.slice(0,50);
}
function inspectZipNames(buffer){
  const names=[];let o=0;while(o+30<=buffer.length&&names.length<300){const sig=buffer.readUInt32LE(o);if(sig!==0x04034b50){o++;continue;}const method=buffer.readUInt16LE(o+8),csize=buffer.readUInt32LE(o+18),usize=buffer.readUInt32LE(o+22),nlen=buffer.readUInt16LE(o+26),xlen=buffer.readUInt16LE(o+28);if(o+30+nlen+xlen>buffer.length){o++;continue;}const name=buffer.subarray(o+30,o+30+nlen).toString('utf8');names.push({name,method,compressedSize:csize,uncompressedSize:usize,pathTraversal:/(^|[\\/])\.\.([\\/]|$)/.test(name)||/^[A-Za-z]:/.test(name)||name.startsWith('/')});const next=o+30+nlen+xlen+csize;if(next<=o||next>buffer.length)break;o=next;}return names;
}
function analyzeForensics(file){
  const b=file.buffer,hits=magicHits(b),strings=printableStrings(b),findings=findInterestingStrings(strings),evidence={magic:hits.slice(0,100),stringsScanned:strings.length};let matched=false;
  const head=hits.filter(h=>h.offset===0);if(head.length){matched=true;findings.unshift({severity:'info',title:`文件格式：${head.map(x=>x.name).join('/')}`,detail:'magic @ 0x0'});}
  const embedded=hits.filter(h=>h.offset>0&&['archive','firmware','image'].includes(h.kind));if(embedded.length){matched=true;for(const h of embedded.slice(0,30))findings.push({severity:h.kind==='firmware'?'medium':'info',title:`嵌入 ${h.name}`,detail:`offset=${h.offsetHex}`});}
  if(findings.length)matched=true;
  const pcap=parsePcapHeader(b);if(pcap){matched=true;evidence.capture=pcap;findings.push({severity:'info',title:'识别 PCAP',detail:`linkType=${pcap.linkType} · snaplen=${pcap.snaplen}`});}
  else if(isPcapng(b)){matched=true;evidence.capture={format:'pcapng'};findings.push({severity:'info',title:'识别 PCAPNG',detail:'Section Header Block magic 命中'});}
  if(b.length>=4&&b.readUInt32LE(0)===0x04034b50){const entries=inspectZipNames(b);evidence.zipEntries=entries;const traversal=entries.filter(x=>x.pathTraversal);if(entries.length){matched=true;findings.push({severity:'info',title:`ZIP 本地文件头 ${entries.length} 项`,detail:entries.slice(0,8).map(x=>x.name).join(' · ')});}if(traversal.length)findings.push({severity:'high',title:'ZIP 路径穿越条目',detail:traversal.slice(0,10).map(x=>x.name).join(' · ')});}
  if(likelyText(b)){const text=textView(b,2*1024*1024),decoded=recursiveDecodeText(text);if(decoded.length){matched=true;findings.push(...decoded);evidence.recursiveDecode=decoded.length;}}
  return result('forensics',matched,findings,{evidence});
}

module.exports={magicHits,printableStrings,findInterestingStrings,recursiveDecodeText,inspectZipNames,analyzeForensics};
