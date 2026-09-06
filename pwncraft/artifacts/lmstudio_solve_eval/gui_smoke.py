from __future__ import annotations
import json, os, sys
from pathlib import Path
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from PyQt5.QtWidgets import QApplication
from pwncraft.gui.panels.heap_panel import HeapPanel

source=Path(r'C:/Users/WYH/Desktop/软安决赛/traditional/solve.py').read_text(encoding='utf8')
app=QApplication.instance() or QApplication([])
panel=HeapPanel(
 profile_provider=lambda:{'arch':'amd64','bits':64,'libc_version':'glibc 2.35'},
 insert_callback=lambda _text:None,
 log_callback=lambda _text:None,
)
panel.exp_view.setPlainText(source)
parsed=panel._parse_exp_calls_with_spans(source)
panel.operations=[op for op,_start,_end in parsed]
request=panel._build_ai_request(1)
budget=panel._request_prompt_budget(request)
rules=panel._active_learned_rules()
result={
 'model':panel._ai_config.model,
 'enabled':panel._ai_enabled,
 'analysis_mode':panel._ai_config.analysis_mode,
 'context_budget_tokens':panel._ai_config.context_budget_tokens,
 'max_input_tokens':panel._ai_config.max_input_tokens,
 'max_tokens':panel._ai_config.max_tokens,
 'json_prefill':panel._ai_config.json_prefill,
 'static_operations':len(panel._analysis_result.operations),
 'learned_rule_ids':[str(rule.get('rule_id') or '') for rule in rules],
 'prompt_budget':budget.__dict__,
}
Path('artifacts/lmstudio_solve_eval/gui_smoke.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(result,ensure_ascii=False,indent=2))
panel.close(); app.processEvents()
