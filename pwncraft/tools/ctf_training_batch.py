"""CTF-Archives 批量训练：拉题 → 检测 → EXP → 真跑验证 → 打通即删。

断点续跑：progress 记录在 ctf_training/state.json；已 VERIFIED 的题删除
工作目录（解决一个题删一个题）；失败/未打通的保留在 pending 供复查。
"""
import json
import re
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, r"F:\pwn宝\pwncraft")

ROOT = Path(r"F:\pwn宝\pwncraft\artifacts\ctf_training")
STATE = ROOT / "state.json"
LOG = ROOT / "training.jsonl"
ZIP_DIR = ROOT / "zips"
WORK = ROOT / "work"
API = "https://api.github.com"


def http_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "pwncraft-training"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def download(url: str, dest: Path) -> bool:
    req = urllib.request.Request(url, headers={"User-Agent": "pwncraft-training"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as out:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                out.write(chunk)
        return True
    except Exception as error:
        print(f"  download fail: {str(error)[:60]}")
        return False


def find_elms(directory: Path) -> list[Path]:
    """解包目录里的主程序 ELF（排除 libc/ld/so 与非 ELF）。"""
    out = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.read_bytes()[:4] != b"\x7fELF":
                continue
        except OSError:
            continue
        name = path.name.lower()
        if (".so" in name or name.startswith(("libc", "ld-", "ld64"))
                or path.suffix in (".o", ".c", ".py", ".txt", ".md", ".id0",
                                   ".id1", ".id2", ".nam", ".til", ".i64")):
            continue
        # 排除脚本容器
        try:
            head = path.read_bytes()[:64]
        except OSError:
            continue
        if b"ELF" not in head[:20]:
            continue
        out.append(path)
    return out


def state_load() -> dict:
    if STATE.is_file():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {"repos_done": [], "assets_done": [], "verified": [], "attempted": []}


def state_save(state: dict):
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def log_line(record: dict):
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps(record, ensure_ascii=False)[:200])


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    ZIP_DIR.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    state = state_load()

    from pwncraft.electron_bridge import ElectronBridge
    bridge = ElectronBridge()

    # ---- 1) 枚举 pwn 仓库（3 页） ----
    repos = []
    for page in (1, 2, 3):
        try:
            repos += http_json(f"{API}/orgs/CTF-Archives/repos?per_page=100&page={page}")
        except Exception as error:
            print(f"repo list page {page} fail: {error}")
    pwn_repos = sorted({r["name"] for r in repos
                        if "pwn" in r["name"].lower() or "wdb" in r["name"].lower()})
    print(f"pwn repos: {len(pwn_repos)}")

    # ---- 2) 逐仓库拉附件 → 解包 → 逐 ELF 闭环 ----
    attempted = len(state["attempted"])
    for repo in pwn_repos:
        if repo in state["repos_done"]:
            continue
        if attempted >= 140:
            print("reach 140 attempted cap")
            break
        try:
            releases = http_json(f"{API}/repos/CTF-Archives/{repo}/releases?per_page=5")
        except Exception as error:
            print(f"{repo}: releases fail {str(error)[:50]}")
            state["repos_done"].append(repo)
            state_save(state)
            continue
        assets = [a for rel in releases for a in (rel.get("assets") or [])
                  if a["name"].lower().endswith(".zip") and a["size"] <= 8 << 20]
        if not assets:
            state["repos_done"].append(repo)
            state_save(state)
            print(f"{repo}: no zip assets")
            continue
        for asset in assets:
            key = f"{repo}/{asset['name']}"
            if key in state["assets_done"] or attempted >= 140:
                continue
            zip_path = ZIP_DIR / f"{repo}__{asset['name']}"
            if not zip_path.is_file() and not download(asset["browser_download_url"], zip_path):
                state["assets_done"].append(key)
                state_save(state)
                continue
            work_dir = WORK / f"{repo}__{asset['name'][:24]}"
            if not work_dir.exists():
                work_dir.mkdir(parents=True)
                try:
                    with zipfile.ZipFile(zip_path) as z:
                        for member in z.namelist():
                            if ".." in member:
                                continue
                            try:
                                z.extract(member, work_dir)
                            except Exception:
                                pass
                except Exception as error:
                    print(f"  extract fail {key}: {str(error)[:40]}")
                    state["assets_done"].append(key)
                    state_save(state)
                    continue
            elms = find_elms(work_dir)
            print(f"== {key}: {len(elms)} ELF")
            for elf in find_elms(work_dir):
                attempted += 1
                state["attempted"].append(str(elf))
                rec = {"repo": repo, "asset": asset["name"],
                       "binary": str(elf), "name": elf.name}
                try:
                    t0 = time.time()
                    result = bridge.rpc_synth_verify(
                        {"path": str(elf), "apply": False, "timeout": 20})
                    runtime = result.get("runtime") or {}
                    best = result.get("best") or {}
                    verdict = ((result.get("verification") or {}).get("status")
                               or (result.get("verdict") or {}).get("verdict") or "?")
                    rec.update({
                        "offset": runtime.get("offset"),
                        "offset_confidence": runtime.get("confidence"),
                        "strategy": f"{best.get('id')}={best.get('status')}",
                        "unresolved": len(result.get("unresolved") or []),
                        "exec": ((result.get("execution") or {}).get("status") or "NOT_RUN"),
                        "verdict": verdict,
                        "seconds": round(time.time() - t0, 1),
                    })
                    if verdict == "VERIFIED_SHELL":
                        state["verified"].append(str(elf))
                        shutil.rmtree(work_dir, ignore_errors=True)
                        rec["deleted"] = True
                        print(f"  ✓✓ VERIFIED offset={rec['offset']} {rec['strategy']} — 已删题")
                    else:
                        print(f"  · {rec['strategy']} exec={rec['exec']} offset={rec['offset']}")
                except Exception as error:
                    rec["error"] = str(error)[:100]
                    print(f"  ERR {rec['error']}")
                log_line(rec)
                state["assets_done"].append(key)
                state_save(state)
        state["repos_done"].append(repo)
        state_save(state)
        print(f"-- repo done: {repo} | attempted={attempted} "
              f"verified={len(state['verified'])}")
    print(f"TRAINING DONE attempted={attempted} verified={len(state['verified'])}")


import shutil  # noqa: E402

if __name__ == "__main__":
    main()
