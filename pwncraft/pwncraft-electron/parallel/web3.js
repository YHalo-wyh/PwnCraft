'use strict';

const {result,textView,likelyText,cleanHex}=require('./common');

const KNOWN_SELECTORS=new Map([
  ['0xa9059cbb','transfer(address,uint256)'],['0x23b872dd','transferFrom(address,address,uint256)'],['0x095ea7b3','approve(address,uint256)'],['0x70a08231','balanceOf(address)'],['0xdd62ed3e','allowance(address,address)'],['0x18160ddd','totalSupply()'],['0x06fdde03','name()'],['0x95d89b41','symbol()'],['0x313ce567','decimals()'],['0x8da5cb5b','owner()']
]);
const OPCODES={0x00:'STOP',0x01:'ADD',0x02:'MUL',0x03:'SUB',0x04:'DIV',0x10:'LT',0x11:'GT',0x14:'EQ',0x15:'ISZERO',0x16:'AND',0x17:'OR',0x18:'XOR',0x19:'NOT',0x20:'SHA3',0x30:'ADDRESS',0x31:'BALANCE',0x32:'ORIGIN',0x33:'CALLER',0x34:'CALLVALUE',0x35:'CALLDATALOAD',0x36:'CALLDATASIZE',0x37:'CALLDATACOPY',0x3b:'EXTCODESIZE',0x3d:'RETURNDATASIZE',0x3e:'RETURNDATACOPY',0x50:'POP',0x51:'MLOAD',0x52:'MSTORE',0x53:'MSTORE8',0x54:'SLOAD',0x55:'SSTORE',0x56:'JUMP',0x57:'JUMPI',0x5b:'JUMPDEST',0x5f:'PUSH0',0xf0:'CREATE',0xf1:'CALL',0xf2:'CALLCODE',0xf3:'RETURN',0xf4:'DELEGATECALL',0xf5:'CREATE2',0xfa:'STATICCALL',0xfd:'REVERT',0xfe:'INVALID',0xff:'SELFDESTRUCT'};
for(let i=1;i<=32;i++)OPCODES[0x5f+i]=`PUSH${i}`;for(let i=1;i<=16;i++){OPCODES[0x7f+i]=`DUP${i}`;OPCODES[0x8f+i]=`SWAP${i}`;}

function maskNonCode(source){
  const c=[...String(source||'')];let state='code',quote=null;const blank=i=>{if(c[i]!=='\n'&&c[i]!=='\r')c[i]=' ';};
  for(let i=0;i<c.length;i++){
    const a=c[i],b=c[i+1];
    if(state==='line'){if(a==='\n'||a==='\r')state='code';else blank(i);continue;}
    if(state==='block'){if(a==='*'&&b==='/'){blank(i);blank(i+1);i++;state='code';}else blank(i);continue;}
    if(state==='string'){if(a==='\\'){blank(i);if(i+1<c.length){blank(i+1);i++;}}else if(a===quote){blank(i);state='code';quote=null;}else blank(i);continue;}
    if(a==='/'&&b==='/'){blank(i);blank(i+1);i++;state='line';continue;}if(a==='/'&&b==='*'){blank(i);blank(i+1);i++;state='block';continue;}if(a==='"'||a==="'"){quote=a;blank(i);state='string';}
  }
  return c.join('');
}
function lineAt(s,i){return s.slice(0,i).split(/\r?\n/).length;}
function snippet(s,i){return s.slice(Math.max(0,i-60),Math.min(s.length,i+180)).trim();}
function auditSolidity(source){
  source=String(source||'');const code=maskNonCode(source),findings=[];
  const push=(id,severity,title,index,detail)=>findings.push({id,severity,title,line:lineAt(source,index),detail,evidence:snippet(source,index)});
  const rules=[
    [/\btx\.origin\b/g,'tx-origin','high','使用 tx.origin','授权链可能被中间合约影响'],
    [/\.delegatecall\s*\(/g,'delegatecall','high','发现 DELEGATECALL','检查 target 可控性、升级权限与 storage layout'],
    [/\bselfdestruct\s*\(/g,'selfdestruct','medium','发现 SELFDESTRUCT','检查调用权限与生命周期语义'],
    [/\.call\s*(?:\{|\()/g,'low-level-call','medium','发现低级 CALL','检查 target/value/data 可控性、返回值与重入'],
    [/\bunchecked\s*\{/g,'unchecked','low','存在 unchecked 算术块','核对计数与边界逻辑'],
    [/\bassembly\s*\{/g,'assembly','medium','存在内联 assembly','关注 calldata/storage/memory 手工偏移'],
    [/\becrecover\s*\(/g,'ecdsa-recover','medium','发现 ecrecover','核对 domain separation、nonce/replay 与 low-s'],
    [/abi\.encodePacked\s*\([^)]*(?:string|bytes)/g,'encode-packed-dynamic','medium','动态类型参与 abi.encodePacked','多个动态字段可能产生拼接歧义']
  ];
  for(const [re,id,sev,title,detail] of rules){let m;while((m=re.exec(code)))push(id,sev,title,m.index,detail);}
  const loads=[...code.matchAll(/calldataload\s*\(\s*([A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+)\s*\)/g)];const dynamic=/function\s+\w+\s*\([^)]*\bbytes\s+calldata\s+\w+/g.test(code);const offsets=new Set([...code.matchAll(/(?:uint\d*\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:\d+\s*\+\s*)?\d+\s*\*\s*\d+\s*;/g)].map(x=>x[1]));
  if(dynamic)for(const x of loads)if(offsets.has(x[1]))push('abi-smuggling-offset','high','动态 bytes 使用硬编码 calldata 偏移',x.index,'可能出现授权 selector 与实际 actionData selector 不一致');
  let m;const init=/function\s+(?:initialize|init|setPermissions)\s*\([^)]*\)\s+(?:external|public)\b/g;while((m=init.exec(code))){const nearby=code.slice(m.index,m.index+900);if(/\binitialized\b/.test(nearby)&&!/(onlyOwner|initializer|onlyRole|auth|requiresAuth)/.test(m[0]))push('first-caller-init','medium','公开一次性初始化入口',m.index,'确认部署时是否原子初始化，防止 first-caller 抢占');}
  return findings;
}

function disasmEvm(buffer,limit=16000){
  const out=[];for(let pc=0;pc<buffer.length&&out.length<limit;){const op=buffer[pc],name=OPCODES[op]||`OP_${op.toString(16).padStart(2,'0')}`;const item={pc,opcode:`0x${op.toString(16).padStart(2,'0')}`,name};pc++;if(op>=0x60&&op<=0x7f){const n=op-0x5f,itemBytes=buffer.subarray(pc,Math.min(buffer.length,pc+n));item.immediate='0x'+itemBytes.toString('hex');pc+=n;}out.push(item);}return out;
}
function extractSelectors(ins){
  const seen=new Set(),out=[];for(let i=0;i<ins.length;i++){const x=ins[i];if(x.name!=='PUSH4'||!x.immediate||seen.has(x.immediate))continue;const w=ins.slice(i+1,i+7),eq=w.findIndex(y=>y.name==='EQ'),ji=w.findIndex(y=>y.name==='JUMPI'),dispatch=eq>=0&&ji>eq;let destination=null;if(dispatch){const p=w.slice(eq+1,ji).find(y=>/^PUSH[1-4]$/.test(y.name)&&y.immediate);destination=p?.immediate||null;}seen.add(x.immediate);out.push({pc:x.pc,selector:x.immediate.toLowerCase(),knownSignature:KNOWN_SELECTORS.get(x.immediate.toLowerCase())||null,looksLikeDispatcher:dispatch,destination});}return out.sort((a,b)=>Number(b.looksLikeDispatcher)-Number(a.looksLikeDispatcher));
}
function runtimeBufferFromFile(file,text){
  const ext=file.ext;if(['.evm','.bytecode','.hex','.bin'].includes(ext)&&likelyText(file.buffer)){const h=cleanHex(text);if(h&&h.length>=20)return Buffer.from(h,'hex');}
  const m=String(text||'').match(/(?:bytecode|deployedBytecode|runtimeBytecode)["'\s:=]+(?:0x)?([0-9a-fA-F]{20,})/);if(m&&m[1].length%2===0)return Buffer.from(m[1],'hex');
  return null;
}
function inspectEvm(file,text){
  const b=runtimeBufferFromFile(file,text);if(!b||b.length<8)return {matched:false,findings:[],evidence:{}};const ins=disasmEvm(b),selectors=extractSelectors(ins),findings=[{severity:'info',title:`识别 EVM runtime ${b.length} bytes`,detail:`${ins.length} instructions · ${selectors.filter(x=>x.looksLikeDispatcher).length} dispatcher selectors`}];
  const counts={};for(const x of ins)counts[x.name]=(counts[x.name]||0)+1;
  if(counts.DELEGATECALL)findings.push({severity:'high',title:'EVM runtime 含 DELEGATECALL',detail:`count=${counts.DELEGATECALL}`});
  if(counts.SELFDESTRUCT)findings.push({severity:'medium',title:'EVM runtime 含 SELFDESTRUCT',detail:`count=${counts.SELFDESTRUCT}`});
  if(counts.CALL)findings.push({severity:'medium',title:'EVM runtime 含外部 CALL',detail:`count=${counts.CALL}`});
  for(const s of selectors.filter(x=>x.looksLikeDispatcher&&x.knownSignature).slice(0,20))findings.push({severity:'info',title:`Selector ${s.selector}`,detail:s.knownSignature,evidence:s});
  return {matched:true,findings,evidence:{byteLength:b.length,selectors:selectors.slice(0,100),opcodeCounts:counts,instructions:ins.slice(0,400)}};
}
function inspectSolana(text){
  const s=String(text||'');const rust=/\b(?:solana_program|anchor_lang|Program<'info|AccountInfo<'|declare_id!)\b/.test(s);const js=/\b(?:@solana\/web3\.js|PublicKey|TransactionInstruction|SystemProgram)\b/.test(s);if(!rust&&!js)return {matched:false,findings:[],evidence:{}};
  const findings=[{severity:'info',title:'识别 Solana / Anchor 源码',detail:rust?'Rust/Anchor':'JavaScript/TypeScript'}];
  if(/AccountInfo<'[^>]*>/.test(s)&&!/(Signer<'|has_one\s*=|constraint\s*=|owner\s*=)/.test(s))findings.push({severity:'medium',title:'AccountInfo 权限约束需复核',detail:'存在裸 AccountInfo，未在同一源码中观察到明显 signer/owner/constraint 约束'});
  if(/invoke_signed\s*\(/.test(s))findings.push({severity:'medium',title:'发现 invoke_signed CPI',detail:'核对 PDA seeds/bump 与被调用 program/account 绑定'});
  if(/UncheckedAccount/.test(s))findings.push({severity:'medium',title:'发现 UncheckedAccount',detail:'Anchor 不自动验证该账户，需要人工核对约束'});
  return {matched:true,findings,evidence:{anchor:rust,web3js:js}};
}

function analyzeWeb3(file){
  const text=likelyText(file.buffer)?textView(file.buffer):'';const solidity=/\bpragma\s+solidity\b|\bcontract\s+[A-Za-z_$]|\binterface\s+[A-Za-z_$]/.test(text)||file.ext==='.sol';
  const findings=[],evidence={};let matched=false;
  if(solidity){matched=true;const f=auditSolidity(text);findings.push({severity:'info',title:'识别 Solidity 源码',detail:`静态审计命中 ${f.length} 条规则`},...f);evidence.solidity={findingCount:f.length};}
  const evm=inspectEvm(file,text);if(evm.matched){matched=true;findings.push(...evm.findings);evidence.evm=evm.evidence;}
  const solana=inspectSolana(text);if(solana.matched){matched=true;findings.push(...solana.findings);evidence.solana=solana.evidence;}
  return result('web3',matched,findings,{evidence});
}

module.exports={maskNonCode,auditSolidity,disasmEvm,extractSelectors,inspectEvm,inspectSolana,analyzeWeb3};
