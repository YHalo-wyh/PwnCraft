# Sunshine EXP AST / HeapViz 批量回放报告

- corpus: `C:\Users\WYH\Desktop\sunshine 附件`
- EXP candidates: **52**
- syntax valid: **52/52**
- PARSE_ONLY: **9**
- MODEL_READY: **2**
- PARTIAL_REPLAY: **18**
- FULL_REPLAY: **23**
- SEMANTIC_VERIFIED: **0**
- STATIC_ELIGIBLE: **26**
- STATIC_PARTIAL: **17**
- RUNTIME_REQUIRED: **9**
- Raw Corpus Coverage: **43/52 = 82.69%**
- Static-Scope Coverage: **43/43 = 100.00%**

> `MODEL_READY` 表示 AST 已产生 allocator IR；`FULL_REPLAY` 仍不等于外部真值校准。
> 自定义 allocator、服务端隐式 malloc、竞态和动态分支必须配 behavior profile / pwndbg checkpoint，禁止猜测。

| status | eligibility | ops | chunks | aborted | reason | EXP | artifact |
|---|---|---:|---:|:---:|---|---|---|
| FULL_REPLAY | STATIC_ELIGIBLE | 12 | 4 | no | external semantic truth oracle not provided | `99PWN/08_堆利用/pwn_160/exp.py` | `cases/c47c79bfab9a4ba5.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 27 | 11 | no | external semantic truth oracle not provided | `比赛/0xfunCTF2026/67(堆)/six-seven-lmao/exploit.py` | `cases/70dc3372047e9271.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 36 | 16 | no | external semantic truth oracle not provided | `比赛/0xfunCTF2026/67(堆)/six-seven-lmao/solve.py` | `cases/776706a633f69161.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 44 | 20 | no | external semantic truth oracle not provided | `比赛/0xfunCTF2026/67-revenge(堆)/six-seven-revenge/exploit_dev.py` | `cases/b6c2cdc0bdefd9bf.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 42 | 35 | no | external semantic truth oracle not provided | `比赛/0xfunCTF2026/67-revenge(堆)/six-seven-revenge/exploit_final.py` | `cases/ec63e4a114bd64f7.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 20 | 4 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/exploit_jqnote.py` | `cases/bc9b85ca832e0b9a.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 18 | 7 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve.py` | `cases/348b2e64d1eb7105.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 19 | 7 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve_jqnote.py` | `cases/b59aa34bd78b01c4.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 19 | 9 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve_jqnote_full.py` | `cases/93ab7f38aede8c91.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 21 | 6 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve_jqnote_pow.py` | `cases/0ea5a85365269e70.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 23 | 7 | no | unknown allocation size | `比赛/jqctf2026/easynote(堆)/solve_jqnote_v2.py` | `cases/82848f0656125bba.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 23 | 7 | no | unknown allocation size | `比赛/jqctf2026/easynote(堆)/solve_jqnote_v3.py` | `cases/1fb7fc83e5d0bb71.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 19 | 9 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve_pwntools.py` | `cases/cc5f7b33b1c907dc.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 19 | 9 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve_pwntools_pow.py` | `cases/9973183b7617c336.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 19 | 9 | no | external semantic truth oracle not provided | `比赛/jqctf2026/easynote(堆)/solve_pwntools_v2.py` | `cases/415a42220fa54a99.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 10 | 5 | no | external semantic truth oracle not provided | `比赛/polarisctf招新赛/ezheap(堆)/solve.py` | `cases/6396df3b389b2bfa.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 18 | 8 | no | unknown allocation size | `比赛/polarisctf招新赛/pwn-music-box(堆)/exp.py` | `cases/22794d4e154b4b26.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 21 | 8 | no | unknown allocation size; unresolved branch candidate: args.REMOTE=true; runtime selection unresolved | `比赛/polarisctf招新赛/pwn-music-box(堆)/exp_stop.py` | `cases/7cba9626b9a95433.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 1 | 0 | no | external runtime dependency | `比赛/polarisctf招新赛/pwn-throne-hazard(堆)/attachments/solve.py` | `cases/9f964c2906612ec3.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 1 | 0 | no | external runtime dependency | `比赛/polarisctf招新赛/pwn-throne-hazard(堆)/solve.py` | `cases/24c4b5eca5ef0f8b.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 10 | 4 | no | external semantic truth oracle not provided | `比赛/polar春季挑战赛2026/2free(堆)/exp.py` | `cases/c278fa300d533a11.json` |
| MODEL_READY | STATIC_ELIGIBLE | 30 | 0 | no | external semantic truth oracle not provided | `比赛/R3CTF2026/polys(堆)/solve.py` | `cases/2b771167abbbc0dd.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 2 | 0 | no | external semantic truth oracle not provided | `比赛/R3CTF2026/polys(堆)/solve_final_bruteforce.py` | `cases/bb0aea7063c52cb5.json` |
| MODEL_READY | STATIC_ELIGIBLE | 4 | 0 | no | external semantic truth oracle not provided | `比赛/R3CTF2026/polys(堆)/solve_polys_final_cmdraw.py` | `cases/097ff2fb9c31df6e.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 6 | 4 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/exp.py` | `cases/96024bb087c12c32.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 6 | 4 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/exp2.py` | `cases/dbf823db1a81bf7e.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 7 | 5 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/exp3.py` | `cases/290d1b9229cfb7b0.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 25 | 16 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/exp_v2.py` | `cases/56020fe94ccee1e0.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 8 | 6 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/exploit.py` | `cases/dfb98e4845b29293.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 11 | 5 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/exploit_local.py` | `cases/b382cab429d847be.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 17 | 6 | no | unknown allocation size | `比赛/SCTF2026/heapmage(堆)/solve.py` | `cases/31ee1a2ae9103677.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 26 | 16 | no | unknown allocation size; unresolved branch candidate: args.HEAP=true; runtime selection unresolved | `比赛/SCTF2026/solve_heapmage_ssl.py` | `cases/53b9a5fd48311b17.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 5 | 3 | no | zero-argument entrypoint candidate: case_dup_realloc(); runtime selection unresolved | `比赛/SCTF2026/UBW(堆)/attchment/exp_try.py` | `cases/9ab48c7f1a758a8c.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 48 | 13 | no | external semantic truth oracle not provided | `比赛/SCTF2026/UBW(堆)/attchment/exploit_accumulation.py` | `cases/f3f78497a695e304.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 1 | 0 | no | external semantic truth oracle not provided | `比赛/SCTF2026/UBW(堆)/solve_music_secret.py` | `cases/5ccb912f03460204.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 1 | 0 | no | external runtime dependency | `比赛/SekaiCTF2026/pwn_ppp(堆)/exp_ppp_remote_fixed.py` | `cases/be20d96c0f1b34c3.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 1 | 0 | no | external runtime dependency | `比赛/SekaiCTF2026/pwn_ppp(堆)/exp_ppp_remote_v2.py` | `cases/c49ab818cef1fb4b.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 1 | 0 | no | external runtime dependency | `比赛/SekaiCTF2026/pwn_ppp(堆)/exp_ppp_remote_v3.py` | `cases/fd9dad18b62fe895.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 6 | 4 | no | unknown allocation size | `比赛/UMDC/bookmaker(堆)/exp.py` | `cases/1a12f6f7b9db07b7.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 0 | 0 | no | external runtime dependency | `比赛/UMDC/bookmaker(堆)/solve.py` | `cases/c924e32de0d7fd71.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 22 | 6 | no | external semantic truth oracle not provided | `比赛/UMDC/velvet-table(堆)/exp.py` | `cases/35855a555b99ac16.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 21 | 6 | no | external semantic truth oracle not provided | `比赛/UMDC/velvet-table(堆)/solve.py` | `cases/32d2cb70bb0d4182.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 19 | 5 | no | external semantic truth oracle not provided | `比赛/ycb2024/hard+sandbox(堆)/exp.py` | `cases/02c6b4f9dda873e4.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 26 | 16 | no | external semantic truth oracle not provided | `比赛/ycb2024/TravelGraph(堆)/exp.py` | `cases/ae7f34302a2e5000.json` |
| PARTIAL_REPLAY | STATIC_ELIGIBLE | 58 | 15 | yes | unsupported allocator transition: tcache_double_free_abort | `比赛/ycb2025/malloc(堆)/exploit.py` | `cases/f4bdf0c3e2438b80.json` |
| PARSE_ONLY | RUNTIME_REQUIRED | 0 | 0 | no | external semantic truth oracle not provided | `比赛/帕鲁杯/newheap(堆)/task.py/solve_flag.py` | `cases/b2d91de8bde11727.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 78 | 40 | no | unknown allocation size | `比赛/软安决赛/Studentmanagement-题目附件(堆)/exp.py` | `cases/ee6db083c42fb582.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 85 | 40 | no | unknown allocation size | `比赛/软安决赛/Studentmanagement-题目附件(堆)/pwn_student_fsop_refactor.py` | `cases/8406c9a6cc852d7c.json` |
| PARTIAL_REPLAY | STATIC_PARTIAL | 84 | 40 | no | unknown allocation size | `比赛/软安决赛/Studentmanagement-题目附件(堆)/solve_local.py` | `cases/77deda74f68d62ec.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 44 | 20 | no | external semantic truth oracle not provided | `比赛/软安决赛/traditional(堆)/exp.py` | `cases/b3583b20cecc9ca9.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 57 | 27 | no | external semantic truth oracle not provided | `比赛/软安决赛/traditional(堆)/solve.py` | `cases/fda16261d1a12d58.json` |
| FULL_REPLAY | STATIC_ELIGIBLE | 58 | 27 | no | external semantic truth oracle not provided | `比赛/软安决赛/traditional(堆)/solve_alt.py` | `cases/a981ba78dd389b26.json` |
