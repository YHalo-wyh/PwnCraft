'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');
const {analyzeVehicle}=require('../parallel/vehicle');
const {analyzeUav}=require('../parallel/uav');
const {analyzeWeb3,extractSelectors,disasmEvm}=require('../parallel/web3');
const {analyzeForensics}=require('../parallel/forensics');
const {analyzeFileParallel,probeFile,ANALYZERS}=require('../parallel/parallel_file_analysis');

const mk=(name,buffer)=>({name,ext:path.extname(name).toLowerCase(),size:buffer.length,buffer});

test('vehicle migration parses CAN, UDS and CANopen in one pass',()=>{
  const text=[
    '(1.0) can0 7DF#032701AA',
    '(1.1) can0 7E8#036701BB',
    '(1.2) can0 580#4300100001000000',
    '(1.3) can0 123#01020304'
  ].join('\n');
  const r=analyzeVehicle(mk('capture.log',Buffer.from(text)));
  assert.equal(r.status,'matched');
  assert.ok(r.evidence.isoTpSessions.some(x=>x.uds?.service==='SecurityAccess'));
  assert.ok(r.evidence.canopen.some(x=>x.knownObject==='Device Type'));
});

test('uav migration recognizes MAVLink command and NMEA',()=>{
  const payload=Buffer.alloc(33);payload.writeUInt16LE(400,28);payload[30]=1;payload[31]=1;
  const mav=Buffer.concat([Buffer.from([0xfe,33,1,255,190,76]),payload,Buffer.from([0,0])]);
  const r=analyzeUav(mk('telemetry.bin',mav));
  assert.equal(r.status,'matched');
  assert.ok(r.findings.some(x=>/ARM_DISARM/.test(x.title)));
  const n=analyzeUav(mk('gps.nmea',Buffer.from('$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A\n')));
  assert.equal(n.status,'matched');
  assert.ok(n.findings.some(x=>/NMEA/.test(x.title)));
});

test('web3 migration audits Solidity and extracts EVM dispatcher selector',()=>{
  const sol='pragma solidity ^0.8.20; contract X { function x(address a, bytes calldata d) external { a.delegatecall(d); } }';
  const r=analyzeWeb3(mk('X.sol',Buffer.from(sol)));
  assert.equal(r.status,'matched');
  assert.ok(r.findings.some(x=>x.id==='delegatecall'));
  const bytecode=Buffer.from('63a9059cbb14600a5700','hex');
  const selectors=extractSelectors(disasmEvm(bytecode));
  assert.equal(selectors[0].selector,'0xa9059cbb');
  assert.equal(selectors[0].looksLikeDispatcher,true);
});

test('forensics migration detects embedded firmware/archive and suspicious strings',()=>{
  const b=Buffer.concat([Buffer.from('header secret=abc123 FLAG{demo}\x00'),Buffer.from('hsqs'),Buffer.from([0x1f,0x8b,0x08])]);
  const r=analyzeForensics(mk('dump.bin',b));
  assert.equal(r.status,'matched');
  assert.ok(r.findings.some(x=>/flag-shaped/.test(x.title)));
  assert.ok(r.evidence.magic.some(x=>x.name==='SquashFS'));
});

test('parallel dispatcher fans out only non-AI tracks',async()=>{
  assert.deepEqual(ANALYZERS.map(x=>x.track),['vehicle','uav','web3','forensics']);
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pwncraft-parallel-'));
  const p=path.join(dir,'mixed.txt');
  fs.writeFileSync(p,'pragma solidity ^0.8.20; contract X { function x() external { selfdestruct(payable(msg.sender)); } }\n(1.0) can0 7DF#032701AA\n');
  const r=await analyzeFileParallel(p);
  assert.equal(r.schema,'pwncraft.parallel-file-analysis.v1');
  assert.ok(r.matchedTracks.includes('vehicle'));
  assert.ok(r.matchedTracks.includes('web3'));
  assert.equal(r.results.some(x=>x.track==='ai'),false);
  assert.equal(r.safety.aiAnalyzers,false);
  assert.equal(r.safety.executedInput,false);
});

test('ELF probe is magic-based and sidecar does not replace Pwn truth',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pwncraft-parallel-'));
  const elf=path.join(dir,'pwn');fs.writeFileSync(elf,Buffer.from([0x7f,0x45,0x4c,0x46,2,1,1,0]));
  const fake=path.join(dir,'not-elf.elf');fs.writeFileSync(fake,'plain text');
  assert.equal(probeFile(elf).isElf,true);
  assert.equal(probeFile(fake).isElf,false);
  const r=await analyzeFileParallel(elf);
  assert.equal(r.file.isElf,true);
  assert.equal(r.safety.readOnly,true);
});

test('parallel dispatcher leaves random binary no-match without throwing',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pwncraft-parallel-'));
  const p=path.join(dir,'random.bin');fs.writeFileSync(p,Buffer.from([1,2,3,4,5,6,7,8,9]));
  const r=await analyzeFileParallel(p);
  assert.ok(['matched','no-match'].includes(r.status));
  assert.equal(r.errors.length,0);
});

test('renderer owns generic drag/drop but delegates real ELF to untouched importElf hook',()=>{
  const renderer=fs.readFileSync(path.join(__dirname,'..','renderer','parallel_analysis.js'),'utf8');
  const app=fs.readFileSync(path.join(__dirname,'..','renderer','app.js'),'utf8');
  assert.match(renderer,/parallelAnalyze\(path\)/);
  assert.match(renderer,/probe\.isElf.*__pwncraftDebug\?\.importElf/);
  assert.match(app,/async function importElf\(path\)/);
  assert.match(app,/request\('import_target'/);
});
