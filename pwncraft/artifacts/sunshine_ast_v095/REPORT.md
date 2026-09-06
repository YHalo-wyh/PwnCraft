# Sunshine EXP AST / HeapViz 批量回放报告

- corpus: `/mnt/c/Users/WYH/Desktop/sunshine 附件`
- EXP candidates: **52**
- syntax valid: **52/52**
- heap model ready: **39**
- partial / needs profile: **10**
- excluded non-heap: **3**

> `heap_model_ready` 表示 AST 已产生可重放 allocator IR，不等于已用 pwndbg 真值证明每个地址。
> 自定义 allocator、服务端隐式 malloc、竞态和动态分支必须配 behavior profile / pwndbg checkpoint，禁止猜测。

| status | ops | chunks | aborted | EXP | artifact |
|---|---:|---:|:---:|---|---|
| heap_model_ready | 12 | 4 | no | `99PWN/08_堆利用/pwn_160/exp.py` | `cases/c47c79bfab9a4ba5.json` |
| heap_model_ready | 27 | 11 | no | `比赛/0xfunCTF2026/67(堆)/six-seven-lmao/exploit.py` | `cases/70dc3372047e9271.json` |
| heap_model_ready | 36 | 13 | yes | `比赛/0xfunCTF2026/67(堆)/six-seven-lmao/solve.py` | `cases/776706a633f69161.json` |
| heap_model_ready | 44 | 20 | no | `比赛/0xfunCTF2026/67-revenge(堆)/six-seven-revenge/exploit_dev.py` | `cases/b6c2cdc0bdefd9bf.json` |
| heap_model_ready | 42 | 35 | no | `比赛/0xfunCTF2026/67-revenge(堆)/six-seven-revenge/exploit_final.py` | `cases/ec63e4a114bd64f7.json` |
| partial_needs_allocation_profile | 30 | 0 | no | `比赛/R3CTF2026/polys(堆)/solve.py` | `cases/2b771167abbbc0dd.json` |
| excluded_non_heap | 2 | 0 | no | `比赛/R3CTF2026/polys(堆)/solve_final_bruteforce.py` | `cases/bb0aea7063c52cb5.json` |
| partial_needs_allocation_profile | 4 | 0 | no | `比赛/R3CTF2026/polys(堆)/solve_polys_final_cmdraw.py` | `cases/097ff2fb9c31df6e.json` |
| needs_challenge_behavior_profile | 0 | 0 | no | `比赛/SCTF2026/UBW(堆)/attchment/exp_try.py` | `cases/9ab48c7f1a758a8c.json` |
| heap_model_ready | 48 | 13 | no | `比赛/SCTF2026/UBW(堆)/attchment/exploit_accumulation.py` | `cases/f3f78497a695e304.json` |
| excluded_non_heap | 1 | 0 | no | `比赛/SCTF2026/UBW(堆)/solve_music_secret.py` | `cases/5ccb912f03460204.json` |
| heap_model_ready | 6 | 4 | no | `比赛/SCTF2026/heapmage(堆)/exp.py` | `cases/96024bb087c12c32.json` |
| heap_model_ready | 6 | 4 | no | `比赛/SCTF2026/heapmage(堆)/exp2.py` | `cases/dbf823db1a81bf7e.json` |
| heap_model_ready | 7 | 5 | no | `比赛/SCTF2026/heapmage(堆)/exp3.py` | `cases/290d1b9229cfb7b0.json` |
| heap_model_ready | 25 | 16 | no | `比赛/SCTF2026/heapmage(堆)/exp_v2.py` | `cases/56020fe94ccee1e0.json` |
| heap_model_ready | 8 | 6 | no | `比赛/SCTF2026/heapmage(堆)/exploit.py` | `cases/dfb98e4845b29293.json` |
| heap_model_ready | 11 | 5 | no | `比赛/SCTF2026/heapmage(堆)/exploit_local.py` | `cases/b382cab429d847be.json` |
| heap_model_ready | 18 | 7 | no | `比赛/SCTF2026/heapmage(堆)/solve.py` | `cases/31ee1a2ae9103677.json` |
| needs_challenge_behavior_profile | 1 | 0 | no | `比赛/SCTF2026/solve_heapmage_ssl.py` | `cases/53b9a5fd48311b17.json` |
| needs_challenge_behavior_profile | 1 | 0 | no | `比赛/SekaiCTF2026/pwn_ppp(堆)/exp_ppp_remote_fixed.py` | `cases/be20d96c0f1b34c3.json` |
| needs_challenge_behavior_profile | 1 | 0 | no | `比赛/SekaiCTF2026/pwn_ppp(堆)/exp_ppp_remote_v2.py` | `cases/c49ab818cef1fb4b.json` |
| needs_challenge_behavior_profile | 1 | 0 | no | `比赛/SekaiCTF2026/pwn_ppp(堆)/exp_ppp_remote_v3.py` | `cases/fd9dad18b62fe895.json` |
| heap_model_ready | 6 | 4 | no | `比赛/UMDC/bookmaker(堆)/exp.py` | `cases/1a12f6f7b9db07b7.json` |
| needs_challenge_behavior_profile | 0 | 0 | no | `比赛/UMDC/bookmaker(堆)/solve.py` | `cases/c924e32de0d7fd71.json` |
| heap_model_ready | 22 | 6 | no | `比赛/UMDC/velvet-table(堆)/exp.py` | `cases/35855a555b99ac16.json` |
| heap_model_ready | 21 | 6 | no | `比赛/UMDC/velvet-table(堆)/solve.py` | `cases/32d2cb70bb0d4182.json` |
| heap_model_ready | 20 | 4 | no | `比赛/jqctf2026/easynote(堆)/exploit_jqnote.py` | `cases/bc9b85ca832e0b9a.json` |
| heap_model_ready | 18 | 7 | no | `比赛/jqctf2026/easynote(堆)/solve.py` | `cases/348b2e64d1eb7105.json` |
| heap_model_ready | 19 | 7 | no | `比赛/jqctf2026/easynote(堆)/solve_jqnote.py` | `cases/b59aa34bd78b01c4.json` |
| heap_model_ready | 19 | 9 | no | `比赛/jqctf2026/easynote(堆)/solve_jqnote_full.py` | `cases/93ab7f38aede8c91.json` |
| heap_model_ready | 21 | 6 | no | `比赛/jqctf2026/easynote(堆)/solve_jqnote_pow.py` | `cases/0ea5a85365269e70.json` |
| heap_model_ready | 23 | 7 | no | `比赛/jqctf2026/easynote(堆)/solve_jqnote_v2.py` | `cases/82848f0656125bba.json` |
| heap_model_ready | 23 | 7 | no | `比赛/jqctf2026/easynote(堆)/solve_jqnote_v3.py` | `cases/1fb7fc83e5d0bb71.json` |
| heap_model_ready | 19 | 9 | no | `比赛/jqctf2026/easynote(堆)/solve_pwntools.py` | `cases/cc5f7b33b1c907dc.json` |
| heap_model_ready | 19 | 9 | no | `比赛/jqctf2026/easynote(堆)/solve_pwntools_pow.py` | `cases/9973183b7617c336.json` |
| heap_model_ready | 19 | 9 | no | `比赛/jqctf2026/easynote(堆)/solve_pwntools_v2.py` | `cases/415a42220fa54a99.json` |
| heap_model_ready | 10 | 5 | no | `比赛/polarisctf招新赛/ezheap(堆)/solve.py` | `cases/6396df3b389b2bfa.json` |
| heap_model_ready | 18 | 8 | no | `比赛/polarisctf招新赛/pwn-music-box(堆)/exp.py` | `cases/22794d4e154b4b26.json` |
| heap_model_ready | 18 | 8 | no | `比赛/polarisctf招新赛/pwn-music-box(堆)/exp_stop.py` | `cases/7cba9626b9a95433.json` |
| needs_challenge_behavior_profile | 1 | 0 | no | `比赛/polarisctf招新赛/pwn-throne-hazard(堆)/attachments/solve.py` | `cases/9f964c2906612ec3.json` |
| needs_challenge_behavior_profile | 1 | 0 | no | `比赛/polarisctf招新赛/pwn-throne-hazard(堆)/solve.py` | `cases/24c4b5eca5ef0f8b.json` |
| heap_model_ready | 10 | 4 | no | `比赛/polar春季挑战赛2026/2free(堆)/exp.py` | `cases/c278fa300d533a11.json` |
| heap_model_ready | 26 | 16 | no | `比赛/ycb2024/TravelGraph(堆)/exp.py` | `cases/ae7f34302a2e5000.json` |
| heap_model_ready | 19 | 5 | no | `比赛/ycb2024/hard+sandbox(堆)/exp.py` | `cases/02c6b4f9dda873e4.json` |
| heap_model_ready | 58 | 15 | yes | `比赛/ycb2025/malloc(堆)/exploit.py` | `cases/f4bdf0c3e2438b80.json` |
| excluded_non_heap | 0 | 0 | no | `比赛/帕鲁杯/newheap(堆)/task.py/solve_flag.py` | `cases/b2d91de8bde11727.json` |
| heap_model_ready | 78 | 40 | no | `比赛/软安决赛/Studentmanagement-题目附件(堆)/exp.py` | `cases/ee6db083c42fb582.json` |
| heap_model_ready | 85 | 40 | no | `比赛/软安决赛/Studentmanagement-题目附件(堆)/pwn_student_fsop_refactor.py` | `cases/8406c9a6cc852d7c.json` |
| heap_model_ready | 84 | 40 | no | `比赛/软安决赛/Studentmanagement-题目附件(堆)/solve_local.py` | `cases/77deda74f68d62ec.json` |
| heap_model_ready | 44 | 20 | no | `比赛/软安决赛/traditional(堆)/exp.py` | `cases/b3583b20cecc9ca9.json` |
| heap_model_ready | 57 | 27 | no | `比赛/软安决赛/traditional(堆)/solve.py` | `cases/fda16261d1a12d58.json` |
| heap_model_ready | 58 | 27 | no | `比赛/软安决赛/traditional(堆)/solve_alt.py` | `cases/a981ba78dd389b26.json` |
