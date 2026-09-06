from __future__ import annotations
import json,sys
from dataclasses import asdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from pwncraft.features.heapviz import AllocatorConfig,GlibcHeapEngine,analyze_heap_source
base=Path(__file__).resolve().parent
profile=json.loads((base/'traditional.pwncraft-helper.json').read_text('utf8'))
source=Path(r'C:\Users\WYH\Desktop\软安决赛\traditional\exp.py').read_text('utf8',errors='replace')
analysis=analyze_heap_source(source,learned_rules=profile['rules'])
engine=GlibcHeapEngine(AllocatorConfig(version=(2,35),arch='amd64',bits=64,safe_linking=True,simulation_mode='strict'))
snaps=engine.replay(analysis.operations)
out={
 'source':r'C:\Users\WYH\Desktop\软安决赛\traditional\exp.py',
 'operations':[{'line':b.line,'source':b.source_text,'operation':o.to_dict()} for o,b in zip(analysis.operations,analysis.bindings)],
 'diagnostics':[asdict(x) for x in analysis.diagnostics],
 'snapshot_count':len(snaps),
 'snapshots':[{
   'step':s.step,'operation_id':s.operation_id,'event_title':s.event_title,'aborted':s.aborted,
   'chunk_count':len(s.chunks),
   'chunks':{k:{'address':v.address,'user_address':v.user_address,'request_size':v.request_size,'chunk_size':v.chunk_size,'lifecycle':v.lifecycle,'bin':v.bin_location,'fd':v.fd,'bk':v.bk,'data':v.data,'indexes':list(v.menu_indexes)} for k,v in s.chunks.items()},
   'bins':asdict(s.bins),'warnings':[asdict(w) for w in s.warnings],
   'observations':[asdict(v) for v in s.observations],
 } for s in snaps],
}
(base/'traditional_corrected_replay.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'operations':len(analysis.operations),'snapshots':len(snaps),'final_chunks':len(snaps[-1].chunks),'final_aborted':snaps[-1].aborted,'diagnostics':[x.code for x in analysis.diagnostics],'final_warnings':[x.code for x in snaps[-1].warnings]},ensure_ascii=False))
