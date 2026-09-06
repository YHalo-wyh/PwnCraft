from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from pwnbao.features.ai import AIKnowledgeStore, AIProposal, FeedbackRecord, LearnedRule

MODEL='qwen3-coder-30b-a3b-instruct'
BASE=Path(__file__).resolve().parent
store=AIKnowledgeStore()

# Remove global rules that were attributed to the previously selected dense model.
for old in ('rule_a82c425bd8b5d802cbee75a7','rule_6eedec0711d4a720e7377d2a'):
    store.delete_rule(old)

records=[]
def add_feedback(proposal_dict, decision, source_hash, source_fragment, final=None):
    proposal=AIProposal.from_dict(proposal_dict)
    final_value=dict(final or proposal.to_dict())
    saved=store.add_feedback(FeedbackRecord('',source_hash,source_fragment,decision,proposal.to_dict(),final_value,MODEL),proposal.signature())
    records.append({'feedback_id':saved.feedback_id,'decision':decision,'proposal_id':proposal.proposal_id})
    return proposal

def load_result(rel):
    return json.loads((BASE/rel).read_text('utf8'))['result']

# Model-returned dispatcher rules: keep them as reviewed examples and a per-challenge
# helper profile. They are deliberately not global because cmd(1,...) is challenge-specific.
dispatch=[]
for rel in ('targeted/cmd_alloc_free.json','targeted/cmd_edit_show.json','targeted/cmd_copy.json'):
    result=load_result(rel)
    for raw in result.get('proposals',[]):
        final=json.loads(json.dumps(raw))
        rule=final['rule']; matcher=rule['matcher']; output=rule['output']
        output['arg_offset']=1
        semantic=rule['semantic']; choice=str(matcher['argument_equals']['0'])
        rule['rule_id']=f'traditional_cmd_{choice}_{semantic}'
        rule['source']='qwen-coder-reviewed-scenario'
        final['rule']=rule
        decision='accepted' if raw['rule'].get('output',{}).get('arg_offset')==1 and raw['rule'].get('rule_id')==rule['rule_id'] else 'modified'
        add_feedback(raw,decision,result['source_hash'],f"cmd choice={choice} -> {semantic}",final)
        dispatch.append(rule)

# Positive distinctive helper proposals from the full-EXP reviews.
positive_specs=[
 ('results/03_traditional_solve_alt.json','copy_chunk',['src','dst','length'],['src','dst','length'],'copy'),
 ('results/05_题目附件_solve_local.json','edit_bio',['size','data'],['size','data'],'edit'),
 ('targeted/student_review.json','reg',['Id','name','passwd'],['index','data'],'alloc'),
]
learned=[]
for rel,function,params,roles,semantic in positive_specs:
    result=load_result(rel)
    candidate=next((p for p in result.get('proposals',[]) if p.get('helper_mapping',{}).get('function')==function),None)
    if not candidate:
        continue
    final=json.loads(json.dumps(candidate))
    final['helper_mapping'].update({'semantic':semantic,'function':function,'roles':roles,'arity':len(params),'keywords':[],'parameter_names':params})
    decision='accepted' if final==candidate else 'modified'
    add_feedback(candidate,decision,result['source_hash'],candidate.get('source_text') or function,final)
    identity={'semantic':semantic,'matcher':{'function':function,'arity':len(params),'parameter_names':params},'output':{'roles':roles}}
    raw=json.dumps(identity,ensure_ascii=False,sort_keys=True,separators=(',',':'))
    rule=LearnedRule(
        'rule_'+hashlib.sha256(raw.encode()).hexdigest()[:24], semantic,
        {'function':function,'arity':len(params),'keywords':[],'parameter_names':params},
        {'roles':roles}, source='qwen-coder-reviewed',
    )
    learned.append(store.save_rule(rule).to_dict())

# Studentmanagement's stateful edit(size,payload) variant is source-proven and is
# stored as an exact signature rule. It complements the accepted reg feedback.
identity={'semantic':'edit','matcher':{'function':'edit','arity':2,'parameter_names':['size','payload']},'output':{'roles':['size','data']}}
raw=json.dumps(identity,ensure_ascii=False,sort_keys=True,separators=(',',':'))
learned.append(store.save_rule(LearnedRule(
    'rule_'+hashlib.sha256(raw.encode()).hexdigest()[:24], 'edit',
    {'function':'edit','arity':2,'keywords':[],'parameter_names':['size','payload']},
    {'roles':['size','data']}, source='qwen-coder-reviewed-static-feedback',
)).to_dict())

# Wrong/speculative suggestions become negative examples: debug guards do not prove
# true, and size/payload must never be rewritten as index/data.
for rel in ('results/01_traditional_exp.json','results/03_traditional_solve_alt.json','results/05_题目附件_solve_local.json'):
    result=load_result(rel)
    for raw in result.get('proposals',[]):
        if raw.get('action')=='branch_choice':
            add_feedback(raw,'rejected',result['source_hash'],raw.get('source_text') or 'args.GDB',{})
result=load_result('results/04_题目附件_exp.json')
for raw in result.get('proposals',[]):
    if raw.get('helper_mapping',{}).get('function')=='edit':
        add_feedback(raw,'rejected',result['source_hash'],raw.get('source_text') or 'edit(size,payload)',{})

profile={'schema_version':1,'scope':'scenario','source':'Qwen3-Coder reviewed traditional/exp.py','rules':dispatch}
(BASE/'traditional.pwnbao-helper.json').write_text(json.dumps(profile,ensure_ascii=False,indent=2),encoding='utf8')
export_count=store.export_jsonl(BASE/'reviewed_feedback.jsonl')
summary={'knowledge_path':str(store.path),'feedback_added':records,'global_rules':learned,'scenario_rules':dispatch,'exported_feedback_count':export_count}
(BASE/'learning_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(summary,ensure_ascii=False,indent=2))
