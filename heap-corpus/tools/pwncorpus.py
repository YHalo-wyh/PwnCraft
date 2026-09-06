#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PwnCraft Heap Corpus Collector - batch pipeline (static analysis only).

Never executes challenge binaries. Evidence-preserving: anything not provable
is emitted as UNKNOWN / null / LOW confidence.

Subcommands:
  discover : walk a staged repo checkout, cluster files into challenge units,
             assess heap evidence / glibc provenance / techniques / EXP helpers.
             Writes candidates JSONL. No files are copied or modified.
  select   : apply scope + tier rules to candidates; emit assemble config.
  assemble : copy canonical cases into corpus bundles + manifests,
             non-canonical duplicates recorded only; build review_queue /
             bronze index / duplicate registry / batch summary.
  report   : aggregate collection_report.json
"""
import ast
import hashlib
import json
import os
import re
import shutil
import struct
import sys
from pathlib import Path

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------- fs helpers

def lp(p) -> str:
    p = os.path.abspath(str(p))
    if os.name == "nt" and not p.startswith("\\\\?\\"):
        return "\\\\?\\" + p
    return p

def read_bytes(path):
    with open(lp(path), "rb") as f:
        return f.read()

def peek(path, n=4):
    with open(lp(path), "rb") as f:
        return f.read(n)

def sha256_file(path):
    h = hashlib.sha256()
    with open(lp(path), "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------------- ELF parsing

EM_ARCH = {
    0x03: "x86", 0x08: "mips", 0x28: "arm", 0x3E: "amd64",
    0xB7: "aarch64", 0xF3: "riscv", 0x14: "ppc", 0x15: "ppc64",
}

def parse_elf_head(path):
    try:
        head = peek(path, 20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    ei_class, ei_data = head[4], head[5]
    e_type = int.from_bytes(head[16:18], "little")
    e_machine = int.from_bytes(head[18:20], "little")
    return {
        "bits": 64 if ei_class == 2 else (32 if ei_class == 1 else None),
        "endian": "little" if ei_data == 1 else "big",
        "e_type": e_type,  # 2=EXEC, 3=DYN (PIE / shared object)
        "arch": EM_ARCH.get(e_machine, f"em_{e_machine}"),
    }

SHT_DYNSYM = 11

def elf_dynsym_names(data: bytes):
    """Parse .dynsym symbol names from an ELF image (static parse).
    Returns a set of symbol-name strings, or None if not parseable."""
    try:
        if data[:4] != b"\x7fELF":
            return None
        end = "<" if data[5] == 1 else ">"
        bits = 64 if data[4] == 2 else 32
        if bits == 64:
            e_shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
        else:
            e_shoff = struct.unpack_from(end + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x2E)
        if not e_shoff or not e_shnum or e_shentsize < 40:
            return None
        secs = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if bits == 64:
                fields = struct.unpack_from(end + "IIQQQQIIQQ", data, off)
            else:
                fields = struct.unpack_from(end + "IIIIIIIIII", data, off)
            sh_type, sh_off, sh_size, sh_link = fields[1], fields[4], fields[5], fields[6]
            secs.append((sh_type, sh_off, sh_size, sh_link))
        names = set()
        for sh_type, sh_off, sh_size, sh_link in secs:
            if sh_type != SHT_DYNSYM or sh_link >= len(secs):
                continue
            _, str_off, str_size, _ = secs[sh_link]
            strtab = data[str_off:str_off + str_size]
            entsize = 24 if bits == 64 else 16
            for so in range(sh_off, sh_off + sh_size - entsize + 1, entsize):
                st_name = struct.unpack_from(end + "I", data, so)[0]
                if 0 < st_name < len(strtab):
                    e = strtab.find(b"\x00", st_name)
                    if e > st_name:
                        names.add(strtab[st_name:e].decode("ascii", "replace"))
        return names
    except Exception:
        return None

ALLOC_SYMBOLS = {"malloc", "calloc", "realloc", "free", "reallocarray",
                 "posix_memalign", "memalign"}

# ---------------------------------------------------------------- file roles

RE_LIBC = re.compile(r"(^|[/\\])(libc[.\-]?so(\.\d+)*|libc-?[\d.]+\.so)$", re.I)
RE_LD = re.compile(r"(^|[/\\])(ld(-linux[a-z0-9-]*)?[-_]?so(\.\d+)*|ld-[\d.]+\.so|ld\.so(\.\d+)*)$", re.I)
RE_SRC = re.compile(r"\.(c|cc|cpp|cxx|h|hpp|s|rs)$", re.I)
RE_PY = re.compile(r"\.py$", re.I)
RE_DOC = re.compile(r"\.(md|markdown|txt|rst|pdf|doc|docx|tgz|zip|tar|gz)$", re.I)
RE_DOCKER = re.compile(r"(^|[/\\])(Dockerfile.*|docker-compose.*\.ya?ml)$", re.I)
RE_MAKE = re.compile(r"(^|[/\\])((gnu)?makefile.*|.*\.mk)$", re.I)

RE_EXP_NAME = re.compile(r"(exp|exploit|solve|payload|pwn)", re.I)

UNIT_FORMING_EXT_SRC = RE_SRC

def is_unit_forming(p: Path, head: bytes) -> bool:
    """A file that marks its directory as belonging to a challenge unit."""
    name = p.name
    rel = str(p).replace("\\", "/")
    if RE_LIBC.search(rel) or RE_LD.search(rel):
        return True
    if head[:4] == b"\x7fELF":
        return True
    if head[:2] == b"MZ":
        return True
    if RE_PY.search(name):
        return True
    if RE_SRC.search(name):
        return True
    if RE_DOCKER.search(rel) or RE_MAKE.search(rel):
        return True
    return False

def file_role(p: Path, head: bytes):
    rel = str(p).replace("\\", "/")
    name = p.name
    if RE_LIBC.search(rel):
        return "libc"
    if RE_LD.search(rel):
        return "ld"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if RE_PY.search(name):
        return "python"
    if RE_SRC.search(name):
        return "source"
    if RE_DOCKER.search(rel):
        return "docker"
    if RE_MAKE.search(rel):
        return "makefile"
    if RE_DOC.search(name):
        return "doc"
    return "other"

# ---------------------------------------------------------------- glibc banner

GLIBC_BANNER = re.compile(
    rb"GNU C Library \(([^)\r\n]*)\)[^\r\n]{0,200}?[Rr]elease version ([0-9]+\.[0-9]+)"
)

def glibc_version_from_banner(data: bytes):
    m = GLIBC_BANNER.search(data)
    if m:
        return m.group(2).decode("ascii", "replace"), m.group(1).decode("ascii", "replace")
    return None, None

# ---------------------------------------------------------------- evidence

HEAP_API = re.compile(r"\b(malloc|calloc|realloc|free|reallocarray|memalign|posix_memalign)\b")

HEAP_KEYWORD = re.compile(
    r"(tcache|fastbin|unsorted[ _-]?bin|smallbin|small[ _-]?bin|largebin|large[ _-]?bin|"
    r"main_arena|top[ _-]?chunk|\bchunks?\b|"
    r"heap[ _-]?(overflow|layout|exploit|grooming|feng|note|chunk|pointer|segment|base|addr|shrink|extend|bin)"
    r"|use[ -]?after[ -]?free|\buaf\b|double[ _-]?free|poison|safe[ _-]?linking|unlink|overlap"
    r"|house[ _-]?of[ _-][a-z]+"
    r"|堆(溢出|利用|块|题|布局|管理))",
    re.I,
)

# Heap-specific strings a glibc binary may embed. Note: mere GLIBC symbol
# versioning (GLIBC_2.x / "libc.so.6") is NOT heap evidence and must not be
# listed here -- every dynamically linked ELF contains those.
GENERIC_BIN_EVIDENCE = [
    ("tcache_struct", rb"tcache"),
    ("fastbin", rb"fastbin"),
    ("unsorted_bin", rb"unsorted[ _-]?bin"),
    ("smallbin", rb"smallbin"),
    ("largebin", rb"largebin"),
    ("main_arena", rb"main_arena"),
    ("safe_linking", rb"safe[ _-]?linking"),
    ("protected_ptr", rb"protected?_ptr"),
]

TECHNIQUE_PATTERNS = [
    ("heap_overflow", r"heap[ _-]?(buffer[ _-])?overflow|堆溢出"),
    ("uaf", r"\buaf\b|use[ -]?after[ -]?free|释放后利用"),
    ("double_free", r"double[ _-]?free|双重释放"),
    ("tcache_poisoning", r"tcache[ _-]?poison"),
    ("tcache_dup", r"tcache[ _-]?dup"),
    ("fastbin_dup", r"fastbin[ _-]?dup|fastbin[ _-]?double"),
    ("unsafe_unlink", r"unsafe[ _-]?unlink"),
    ("unsorted_bin_attack", r"unsorted[ _-]?bin[ _-]?attack"),
    ("unsorted_bin_leak", r"unsorted[ _-]?bin[^\n]{0,40}leak|leak[^\n]{0,40}(main_arena|unsorted)"),
    ("largebin_attack", r"largebin[ _-]?attack"),
    ("chunk_overlap", r"(chunk|heap)[ _-]?overlap|overlap(ing)?[ _-]?(chunk|heap)|堆块重叠"),
    ("off_by_one", r"off[ _-]?by[ _-]?one"),
    ("off_by_null", r"off[ _-]?by[ _-]?null|null[ _-]?byte[ _-]?overflow|off[ _-]?by[ _-]?one[ _-]?byte"),
    ("safe_linking", r"safe[ _-]?linking"),
    ("house_of_force", r"house[ _-]?of[ _-]?force"),
    ("house_of_spirit", r"house[ _-]?of[ _-]?spirit"),
    ("house_of_botcake", r"house[ _-]?of[ _-]?botcake"),
    ("house_of_einherjar", r"house[ _-]?of[ _-]?einherjar"),
    ("house_of_orange", r"house[ _-]?of[ _-]?orange"),
    ("house_of_lore", r"house[ _-]?of[ _-]?lore"),
    ("house_of_apple", r"house[ _-]?of[ _-]?apple"),
    ("house_of_emma", r"house[ _-]?of[ _-]?emma"),
    ("house_of_cat", r"house[ _-]?of[ _-]?cat"),
    ("fsop", r"\bfsop\b|_IO_(2)?file_(jumps|struct)|_IO_list_all|_IO_FILE"),
    ("stdout_leak", r"_IO_2_1_stdout|stdout[ _-]?(leak|struct|file)"),
]

def grep_lines(text, rx, max_hits=3):
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if rx.search(line):
            hits.append((i, line.strip()[:200]))
            if len(hits) >= max_hits:
                break
    return hits

# ---------------------------------------------------------------- EXP analysis

OP_PATTERNS = [
    (re.compile(r"^(add|create|alloc|new|malloc|ins|insert|push)\w*", re.I), "alloc"),
    (re.compile(r"(del|free|rm|remove|delete)", re.I), "free"),
    (re.compile(r"(edit|change|update|modif|fill|set_?content)", re.I), "edit"),
    (re.compile(r"(show|view|print|leak|dump|disp)", re.I), "show"),
    (re.compile(r"(copy|move|dup(?!e))", re.I), "copy"),
]

IO_FUNCS = re.compile(
    r"(sendlineafter|sendafter|sendline|send|recvuntil|recvline|recv|interactive|"
    r"remote|process|gdb\.attach|sl|sa|sd|ru|rv|ia)", re.X)

def _call_name(node):
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None

def analyze_exp(path: Path):
    """AST static extraction of menu-style heap helpers. Confidence reflects
    how strongly the code itself supports the classification."""
    try:
        src = read_bytes(path).decode("utf-8", "replace")
        tree = ast.parse(src)
    except SyntaxError as e:
        return {"parse_ok": False, "error": f"SyntaxError: {e.msg} line {e.lineno}",
                "imports_pwntools": None, "helpers": [], "candidate_operations": [],
                "aliases": [], "wrappers": [], "call_examples": [], "loops": []}
    except Exception as e:
        return {"parse_ok": False, "error": repr(e), "imports_pwntools": None,
                "helpers": [], "candidate_operations": [], "aliases": [],
                "wrappers": [], "call_examples": [], "loops": []}

    imports_pwntools = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports_pwntools |= any(a.name.split(".")[0] in ("pwn", "pwnlib") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports_pwntools |= (node.module or "").split(".")[0] in ("pwn", "pwnlib")

    helpers, name_to_op = [], {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        calls, io_calls, strs = set(), [], []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                n = _call_name(sub)
                if n:
                    calls.add(n)
                    if IO_FUNCS.search(n):
                        io_calls.append((ast.get_source_segment(src, sub) or n)[:200])
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) and len(sub.value) <= 120:
                strs.append(sub.value)
        op, conf = "unknown", "LOW"
        for rx, o in OP_PATTERNS:
            if rx.search(node.name):
                op, conf = o, "MEDIUM"
                break
        if op != "unknown" and io_calls:
            conf = "HIGH"
        helpers.append({
            "function": node.name, "source_line": node.lineno, "end_line": node.end_lineno,
            "parameter_names": [a.arg for a in node.args.args],
            "calls": sorted(calls)[:25], "io_call_examples": io_calls[:6],
            "menu_strings": strs[:8], "operation": op, "confidence": conf,
        })
        if op != "unknown":
            name_to_op[node.name] = (op, conf)

    aliases = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = node.value
            if isinstance(v, ast.Name) and v.id in name_to_op:
                op, conf = name_to_op[v.id]
                aliases.append({"alias": node.targets[0].id, "of": v.id,
                                "source_line": node.lineno, "operation": op, "confidence": conf})
            elif isinstance(v, ast.Lambda):
                refs = [n.id for n in ast.walk(v) if isinstance(n, ast.Name) and n.id in name_to_op]
                if refs:
                    aliases.append({"alias": node.targets[0].id, "of_lambda": refs,
                                    "source_line": node.lineno,
                                    "operation": name_to_op[refs[0]][0], "confidence": "LOW"})

    wrappers = []
    for h in helpers:
        inner = [c for c in h["calls"] if c in name_to_op and c != h["function"]]
        if inner:
            wrappers.append({"function": h["function"], "wraps": inner, "source_line": h["source_line"]})

    examples = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            n = _call_name(node)
            if n in name_to_op:
                seg = (ast.get_source_segment(src, node) or n)[:200]
                examples.append({"helper": n, "source_line": node.lineno, "call": seg})
    examples = examples[:40]

    loops = []
    for node in tree.body:
        if isinstance(node, (ast.For, ast.While)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    n = _call_name(sub)
                    if n in name_to_op:
                        loops.append({"loop_line": node.lineno, "helper": n, "operation": name_to_op[n][0]})
                        break

    candidate_operations = [
        {"operation": h["operation"], "helper": h["function"], "confidence": h["confidence"],
         "evidence": [f"{Path(path).name}:{h['source_line']} def {h['function']}({', '.join(h['parameter_names'])})"]
                     + [f"io: {c}" for c in h["io_call_examples"][:2]]}
        for h in helpers if h["operation"] != "unknown"
    ] + [
        {"operation": a["operation"], "helper": a["alias"], "confidence": a["confidence"],
         "evidence": [f"alias of {a.get('of') or a.get('of_lambda')} at line {a['source_line']}"]}
        for a in aliases
    ]

    return {"parse_ok": True, "imports_pwntools": imports_pwntools, "helpers": helpers,
            "candidate_operations": candidate_operations, "aliases": aliases,
            "wrappers": wrappers, "call_examples": examples, "loops": loops}

# ---------------------------------------------------------------- unit clustering

def cluster_units(files):
    """files: list of (Path, size). Returns list of unit dir strings.
    Anchors = dirs directly containing unit-forming files. An anchor climbs to
    its highest ancestor that is a 'container' (holds no unit-forming files of
    its own) AND whose anchor set is entirely within this anchor's subtree."""
    unit_forming = []
    for p, sz in files:
        try:
            head = peek(p, 8)
        except OSError:
            continue
        extless = not p.suffix
        if is_unit_forming(p, head) or (extless and head[:4] == b"\x7fELF"):
            unit_forming.append(p)
    anchors = {str(p.parent) for p in unit_forming}
    if not anchors:
        return []

    by_dir = {}
    for p in unit_forming:
        by_dir.setdefault(str(p.parent), []).append(p)

    def children_dirs(d):
        try:
            return [x for x in os.listdir(lp(d)) if os.path.isdir(lp(os.path.join(d, x)))]
        except OSError:
            return []

    def dir_direct_unit_forming(d):
        return d in by_dir

    units = set()
    for a in sorted(anchors):
        cur = a
        while True:
            parent = os.path.dirname(cur)
            if not parent or parent == cur or len(parent) < len(str(Path(files[0][0]).anchor if files else "")):
                break
            if dir_direct_unit_forming(parent):
                break  # parent itself anchors another/own unit; stop
            # parent is a container; does it host sibling anchor subtrees?
            siblings = False
            try:
                for entry in os.listdir(lp(parent)):
                    full = os.path.join(parent, entry)
                    if os.path.isdir(lp(full)) and os.path.abspath(full) != os.path.abspath(cur):
                        # any anchor under this sibling subtree?
                        for anc in anchors:
                            if (anc + os.sep).startswith(os.path.abspath(full) + os.sep) or anc == str(full):
                                siblings = True
                                break
                    if siblings:
                        break
            except OSError:
                break
            if siblings:
                break
            cur = parent
        units.add(cur)
    # drop units that are ancestors of other units (keep most specific when both present)
    final = []
    for u in units:
        if not any(v != u and (u + os.sep) in (v + os.sep) for v in units):
            final.append(u)
    return sorted(final)

# ---------------------------------------------------------------- discover

def discover_repo(repo_root: Path, repo_meta: dict, out_path: Path):
    root = Path(repo_root)
    excludes = set(repo_meta.get("exclude_dirs", []))
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".github", "__pycache__") and d not in excludes]
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            files.append((p, sz))
    files.sort(key=lambda x: str(x[0]).lower())

    units = cluster_units(files)
    print(f"[discover] {root.name}: {len(files)} files -> {len(units)} units")

    results = []
    for u in units:
        unit_rel = str(Path(u).relative_to(root))
        rec = assess_unit(root, unit_rel, repo_meta)
        if rec:
            results.append(rec)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lp(out_path), "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    print("[discover] outcomes:", Counter([(x["heap"]["confidence"], x["reject"]) for x in results]).most_common())
    return results

def assess_unit(root: Path, unit: str, repo_meta: dict):
    unit_path = root / unit
    entries = []  # (rel, abs, role, size, head)
    for p in sorted(unit_path.rglob("*")):
        if not p.is_file() or ".git" in p.parts:
            continue
        try:
            sz = p.stat().st_size
            head = peek(p, 8)
        except OSError:
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        entries.append({"rel": rel, "abs": str(p), "role": file_role(p, head), "size": sz})

    files = {"binaries": [], "libc": [], "ld": [], "source": [], "python": [],
             "docs": [], "docker": [], "makefile": [], "others": []}
    for e in entries:
        r = e["role"]
        if r == "elf":
            e["elf"] = parse_elf_head(e["abs"])
            files["binaries"].append(e)
        elif r == "pe":
            e["elf"] = None
            e["is_pe"] = True
            files["binaries"].append(e)
        elif r in ("libc", "ld", "source", "python", "docker", "makefile"):
            files[r].append(e)
        elif r == "doc":
            files["docs"].append(e)
        else:
            files["others"].append(e)

    primary = None
    for b in files["binaries"]:
        base = Path(b["rel"]).name.lower()
        if "libc" in base or base.startswith("ld-") or base.startswith("ld."):
            continue
        primary = b
        break
    if primary is None:
        for b in files["binaries"]:
            base = Path(b["rel"]).name.lower()
            if not (base.startswith("libc") or base.startswith("ld")):
                primary = b
                break

    # ---------------- heap evidence
    evidence = []

    src_ev = []
    for s in files["source"][:8]:
        try:
            if s["size"] > 4 * 1024 * 1024:
                continue
            text = read_bytes(s["abs"]).decode("utf-8", "replace")
        except OSError:
            continue
        n = len(HEAP_API.findall(text))
        if n:
            src_ev.append({"file": s["rel"], "allocator_api_calls": n})
    if src_ev:
        evidence.append({"class": "source_binary", "kind": "allocator_api_in_source", "detail": src_ev})

    if primary:
        try:
            data = read_bytes(primary["abs"]) if primary["size"] < 64 * 1024 * 1024 else b""
        except OSError:
            data = b""
        str_hits = [k for k, rx in GENERIC_BIN_EVIDENCE if re.search(rx, data)]
        syms = elf_dynsym_names(data) or set()
        alloc_imports = sorted(syms & ALLOC_SYMBOLS)
        dynamic_glibc = b"libc.so.6" in data or b"GLIBC_2." in data
        if alloc_imports or str_hits:
            evidence.append({"class": "source_binary", "kind": "binary_heap_semantics",
                             "detail": {"binary": primary["rel"],
                                        "allocator_dynsym_imports": alloc_imports,
                                        "heap_string_hits": str_hits,
                                        "dynamic_glibc_ref": dynamic_glibc}})

    exp_entry, exp_analysis, exp_files = None, None, []
    for py in files["python"]:
        try:
            if py["size"] > 2 * 1024 * 1024:
                continue
            data = read_bytes(py["abs"])
            text = data.decode("utf-8", "replace")
        except OSError:
            continue
        is_expish = bool(RE_EXP_NAME.search(Path(py["rel"]).name)) or "pwn" in text[:4096]
        if not is_expish:
            continue
        kw = grep_lines(text, HEAP_KEYWORD)
        has_io = bool(re.search(r"\b(remote|process|sendline|recvuntil|ssh)\b", text))
        heap_relevant, reason = False, None
        if kw:
            heap_relevant = True
            reason = "heap_keywords"
        else:
            # menu-structure heuristic: >=3 distinct alloc/free/edit/show ops
            # implemented as named helpers (spec: add/delete/edit/show helpers)
            an = analyze_exp(Path(py["abs"]))
            ops = {c["operation"] for c in an.get("candidate_operations", [])
                   if c.get("confidence") in ("MEDIUM", "HIGH")
                   and c["operation"] in ("alloc", "free", "edit", "show")}
            if len(ops) >= 3:
                heap_relevant = True
                reason = f"menu_helpers:{sorted(ops)}"
            if exp_entry is None:
                exp_entry, exp_analysis = py["rel"], an
        exp_files.append({"file": py["rel"], "heap_relevant": heap_relevant,
                          "reason": reason,
                          "heap_kw_hits": [h[1] for h in kw[:2]], "io_calls": has_io})
        if heap_relevant and exp_entry is None:
            exp_entry = py["rel"]
            exp_analysis = analyze_exp(Path(py["abs"]))
    if any(f["heap_relevant"] for f in exp_files):
        evidence.append({"class": "exp", "kind": "exp_script_heap_semantics",
                         "detail": exp_files[:6]})

    doc_ev = []
    for dc in files["docs"][:8]:
        if dc["size"] > 4 * 1024 * 1024 or not dc["rel"].lower().endswith((".md", ".txt", ".rst")):
            continue
        try:
            text = read_bytes(dc["abs"]).decode("utf-8", "replace")
        except OSError:
            continue
        hits = grep_lines(text, HEAP_KEYWORD, max_hits=2)
        if hits:
            doc_ev.append({"file": dc["rel"], "samples": [h[1] for h in hits]})
    if doc_ev:
        evidence.append({"class": "docs", "kind": "writeup_heap_keywords", "detail": doc_ev})

    classes = {e["class"] for e in evidence}
    if len(classes) >= 2:
        heap_conf = "HIGH"
    elif classes == {"exp"} or classes == {"docs"}:
        heap_conf = "MEDIUM"
    elif classes == {"source_binary"}:
        heap_conf = "MEDIUM"
    else:
        heap_conf = "LOW"

    # ---------------- techniques
    corpus_texts = []
    for group in ("python", "docs", "source"):
        for e in files[group][:10]:
            if e["size"] > 4 * 1024 * 1024:
                continue
            if e["role"] == "doc" and not e["rel"].lower().endswith((".md", ".txt", ".rst")):
                continue
            try:
                corpus_texts.append((e["rel"], read_bytes(e["abs"]).decode("utf-8", "replace")))
            except OSError:
                pass
    techniques, tprov = [], {}
    for tag, pat in TECHNIQUE_PATTERNS:
        rx = re.compile(pat, re.I)
        for fpath, text in corpus_texts:
            hits = grep_lines(text, rx, max_hits=1)
            if hits:
                techniques.append(tag)
                tprov[tag] = {"file": fpath, "line": hits[0][0], "sample": hits[0][1]}
                break
    techniques = sorted(set(techniques))

    # ---------------- glibc provenance
    glibc = {"version": None, "confidence": "LOW", "evidence": []}
    if files["libc"]:
        l0 = files["libc"][0]
        try:
            data = read_bytes(l0["abs"])
        except OSError:
            data = b""
        ver, distro = glibc_version_from_banner(data)
        if ver:
            glibc = {"version": ver, "confidence": "HIGH",
                     "evidence": [f"banner string parsed from shipped {l0['rel']} "
                                  f"(GNU C Library, {distro or 'distro string not matched'})"]}
        else:
            glibc["evidence"].append(f"libc present ({l0['rel']}) but no version banner found")
    if files["ld"] and glibc["version"] is None:
        l0 = files["ld"][0]
        try:
            ver, _ = glibc_version_from_banner(read_bytes(l0["abs"]))
        except OSError:
            ver = None
        if ver:
            glibc = {"version": ver, "confidence": "MEDIUM",
                     "evidence": [f"banner string parsed from shipped loader {l0['rel']}"]}
    if files["docker"]:
        try:
            dtext = read_bytes(files["docker"][0]["abs"]).decode("utf-8", "replace")
        except OSError:
            dtext = ""
        m = re.search(r"^FROM\s+(\S+)", dtext, re.M)
        if m:
            glibc["evidence"].append(f"docker FROM {m.group(1)} (distro-level hint only, NOT a version claim)")

    # ---------------- scope / rejection pre-assessment
    reject = None
    arch = ((primary or {}).get("elf") or {}).get("arch") if primary else None
    if primary is None:
        reject = "NO_BINARY"
    elif primary.get("is_pe"):
        reject = "WINDOWS_HEAP"
    elif arch != "amd64":
        reject = "UNSUPPORTED_ARCH"
    unit_lower = unit.lower()
    if "kernel" in unit_lower or any(e["rel"].lower().endswith(".ko") for e in entries):
        reject = "KERNEL"
    for e in entries:
        nm = Path(e["rel"]).name.lower()
        if e["role"] == "elf" and ("vmlinux" in nm or "bzimage" in nm or nm == "image"):
            reject = "KERNEL"
    for l in files["libc"]:
        try:
            if b"musl" in read_bytes(l["abs"])[:65536]:
                reject = "MUSL"
        except OSError:
            pass
    if not files["python"]:
        reject = reject or "NO_EXP"
    if heap_conf == "LOW":
        reject = reject or "INSUFFICIENT_EVIDENCE"

    return {
        "repo": repo_meta,
        "unit": unit.replace("\\", "/"),
        "challenge_name": Path(unit).name or repo_meta.get("repository") or "unknown",
        "files": {k: [{kk: vv for kk, vv in e.items() if kk != "abs"} for e in v]
                  for k, v in files.items()},
        "primary_binary": ({k: v for k, v in primary.items() if k != "abs"} if primary else None),
        "heap": {"confidence": heap_conf, "evidence": evidence, "techniques": techniques,
                 "technique_provenance": tprov},
        "glibc": glibc,
        "exp_entry": exp_entry,
        "exp_analysis": exp_analysis,
        "reject": reject,
    }

# ---------------------------------------------------------------- select

SOURCE_CLASS_PRIORITY = {"author_repo": 0, "official_archive": 1, "curator_archive": 2,
                         "team_writeup": 3, "fork": 4}

def cmd_select(args):
    base = Path(args.base)
    metas = json.loads(read_bytes(base / "repos_meta.json").decode("utf-8"))
    selected, rejected = [], []
    for cand_file in metas["candidates_files"]:
        for line in read_bytes(base / cand_file).decode("utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            heap = rec["heap"]
            tier, issues = None, []
            reject = rec["reject"]
            has_bin = bool(rec["primary_binary"])
            has_exp = rec["exp_entry"] is not None
            env = bool(rec["files"]["libc"] or rec["files"]["ld"] or rec["files"]["docker"])

            if reject is None:
                if heap["confidence"] == "HIGH" and has_bin and has_exp and env:
                    tier = "GOLD"
                elif heap["confidence"] == "HIGH" and has_bin and has_exp:
                    tier = "SILVER"
                    issues.append("environment incomplete (no shipped libc/ld/docker)")
                elif heap["confidence"] == "MEDIUM":
                    tier = "REVIEW"
                    issues.append("heap evidence MEDIUM: awaiting second review")
                elif has_bin and heap["confidence"] == "HIGH":
                    tier = "BRONZE"
                    issues.append("no pwntools-style EXP script")
                else:
                    tier = "BRONZE"
                    issues.append("incomplete attachments for supervision")
            else:
                # out-of-scope targets stay rejected regardless of evidence
                scope_rejects = {"KERNEL", "UNSUPPORTED_ARCH", "WINDOWS_HEAP", "MUSL"}
                if reject in scope_rejects:
                    tier = "REJECT"
                elif heap["confidence"] in ("HIGH", "MEDIUM") and (
                        has_bin or has_exp or rec["files"]["source"] or rec["files"]["docs"]):
                    tier = "BRONZE"
                    issues.append(f"attachments/writeup only (pre-reject={reject})")
                else:
                    tier = "REJECT"

            entry = {"tier": tier, "issues": issues, "record": rec}
            if tier == "REJECT":
                rejected.append({"repo_url": rec["repo"]["url"], "unit": rec["unit"],
                                 "challenge_name": rec["challenge_name"],
                                 "reason": reject, "heap_confidence": heap["confidence"]})
                continue
            if tier in ("GOLD", "SILVER", "REVIEW"):
                stage = Path(rec["repo"]["staging_path"])
                entry["binary_sha256"] = sha256_file(stage / rec["primary_binary"]["rel"]) if has_bin else None
                entry["libc_sha256"] = sha256_file(stage / rec["files"]["libc"][0]["rel"]) if rec["files"]["libc"] else None
                entry["ld_sha256"] = sha256_file(stage / rec["files"]["ld"][0]["rel"]) if rec["files"]["ld"] else None
            selected.append(entry)

    with open(lp(base / "assemble_config.json"), "w", encoding="utf-8") as f:
        json.dump({"base_dir": str(base.resolve()), "cases": selected}, f, ensure_ascii=False)
    with open(lp(base / "pre_rejects.json"), "w", encoding="utf-8") as f:
        json.dump(rejected, f, ensure_ascii=False, indent=2)
    from collections import Counter
    print("[select]", Counter(e["tier"] for e in selected).most_common(), "pre-rejected:", len(rejected))

# ---------------------------------------------------------------- assemble

def cmd_assemble(args):
    cfg = json.loads(read_bytes(args.config).decode("utf-8"))
    base = Path(cfg["base_dir"])
    corpus_dir, review_dir, index_dir = base / "corpus", base / "review_queue", base / "index"
    for d in (corpus_dir, review_dir, index_dir):
        d.mkdir(parents=True, exist_ok=True)

    selected = [c for c in cfg["cases"] if c["tier"] in ("GOLD", "SILVER", "REVIEW")]
    gold_silver = [c for c in selected if c["tier"] in ("GOLD", "SILVER")]

    # ---- pass 1: duplicate registry over GOLD/SILVER by binary sha
    dup_registry = {}
    for c in gold_silver:
        sha = c.get("binary_sha256")
        if sha:
            dup_registry.setdefault(sha, []).append(c)
    canonical = {}
    for sha, members in dup_registry.items():
        best = min(members, key=lambda c: (SOURCE_CLASS_PRIORITY.get(c["record"]["repo"].get("source_class"), 9),
                                           c["record"]["repo"]["url"], c["record"]["unit"]))
        canonical[sha] = best["record"]["unit"]

    summary = {"gold": [], "silver": [], "review": [], "bronze": [], "rejected": []}
    with open(lp(base / "pre_rejects.json"), encoding="utf-8") as f:
        summary["rejected"] = json.loads(f.read() or "[]")

    dup_out = []

    for c in cfg["cases"]:
        tier = c["tier"]
        rec = c["record"]
        repo = rec["repo"]
        entry = {"repo_url": repo["url"], "unit": rec["unit"],
                 "challenge_name": rec["challenge_name"], "ctf": repo.get("ctf"),
                 "year": repo.get("year"), "heap_confidence": rec["heap"]["confidence"],
                 "tier": tier}

        if tier == "BRONZE":
            summary["bronze"].append({**entry, "issues": c["issues"]})
            continue
        if tier == "REJECT":
            continue

        binsha = c.get("binary_sha256")
        dup_group = None
        is_canon = True
        if binsha and binsha in dup_registry and len(dup_registry[binsha]) > 1:
            dup_group = "dupg-" + binsha[:16]
            is_canon = canonical[binsha] == rec["unit"]
            entry.update({"duplicate_group_id": dup_group, "canonical": is_canon})
            if not is_canon:
                entry["reason"] = "DUPLICATE"
                summary["rejected"].append(entry)
                continue

        if tier == "REVIEW":
            entry["reason"] = None

        # ---- copy bundle
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", rec["challenge_name"]).strip("-").lower()[:40] or "unknown"
        ctfslug = re.sub(r"[^a-zA-Z0-9]+", "-", (repo.get("ctf") or repo.get("owner") or "repo")).strip("-").lower()[:24]
        case_id = f"heap-{ctfslug}-{slug}-{(binsha or 'nobin')[:8]}"
        # phase-1 rule: only GOLD lands in corpus/; SILVER/REVIEW go to review_queue
        bundle = (corpus_dir if tier == "GOLD" else review_dir) / case_id
        if bundle.exists():
            n = 2
            while (bundle.parent / f"{case_id}-{n}").exists():
                n += 1
            case_id = f"{case_id}-{n}"
            bundle = bundle.parent / case_id

        unit_src = Path(repo["staging_path"]) / rec["unit"]

        def to_unit_rel(repo_rel):
            try:
                return Path(repo_rel).relative_to(rec["unit"]).as_posix()
            except ValueError:
                return Path(repo_rel).as_posix()

        exp_rel = to_unit_rel(rec.get("exp_entry") or "") if rec.get("exp_entry") else None
        doc_rels = {to_unit_rel(d["rel"]) for d in rec["files"]["docs"]}
        for sub in ("original/challenge", "original/solution", "original/docs"):
            (bundle / sub).mkdir(parents=True, exist_ok=True)
        for p in sorted(unit_src.rglob("*")):
            if not p.is_file() or ".git" in p.parts:
                continue
            rel = p.relative_to(unit_src).as_posix()
            if exp_rel and rel == exp_rel:
                role = "solution"
            elif rel in doc_rels:
                role = "docs"
            else:
                role = "challenge"
            dst = bundle / "original" / role / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(lp(str(p)), lp(str(dst)))
            if sha256_file(dst) != sha256_file(str(p)):
                raise SystemExit(f"[!!] copy integrity failure: {p}")

        # ---- manifest
        commit = repo.get("commit_sha")
        repo_url = repo["url"].removesuffix(".git")
        files_manifest = []
        for p in sorted((bundle / "original").rglob("*")):
            if not p.is_file():
                continue
            rel_bundle = p.relative_to(bundle).as_posix()
            role = p.relative_to(bundle / "original").parts[0]
            rest = p.relative_to(bundle / "original").parts[1:]
            rel_repo = "/".join([rec["unit"].strip("/")] + list(rest))
            files_manifest.append({
                "path": rel_bundle, "role": role, "repo_relative_path": rel_repo,
                "source_url": f"{repo_url}/blob/{commit}/{rel_repo}" if commit else None,
                "sha256": sha256_file(str(p)), "size": p.stat().st_size,
            })

        arch = ((rec.get("primary_binary") or {}).get("elf") or {}).get("arch")
        year = repo.get("year")
        year_provenance = None
        m = re.match(r"^(19|20)\d{2}[_-]", rec["challenge_name"])
        if m:
            year, year_provenance = int(rec["challenge_name"][:4]), "parsed_from_challenge_dirname_prefix"
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "source": {
                "repository_url": repo["url"], "commit_sha": commit,
                "challenge_path": rec["unit"], "ctf": repo.get("ctf"),
                "year": year, "year_provenance": year_provenance,
                "challenge_name": rec["challenge_name"],
                "license": repo.get("license"), "source_class": repo.get("source_class"),
            },
            "target": {"arch": arch, "os": "linux", "binary_sha256": binsha,
                       "libc_sha256": c.get("libc_sha256"), "ld_sha256": c.get("ld_sha256")},
            "glibc": rec["glibc"],
            "heap": {"confidence": rec["heap"]["confidence"], "evidence": rec["heap"]["evidence"],
                     "techniques": rec["heap"]["techniques"],
                     "technique_provenance": rec["heap"]["technique_provenance"]},
            "files": files_manifest,
            "exp_analysis": {
                "entry_file": rec.get("exp_entry"),
                "parse_ok": (rec.get("exp_analysis") or {}).get("parse_ok"),
                "imports_pwntools": (rec.get("exp_analysis") or {}).get("imports_pwntools"),
                "helpers": (rec.get("exp_analysis") or {}).get("helpers", []),
                "candidate_operations": (rec.get("exp_analysis") or {}).get("candidate_operations", []),
                "aliases": (rec.get("exp_analysis") or {}).get("aliases", []),
                "wrappers": (rec.get("exp_analysis") or {}).get("wrappers", []),
                "call_examples": (rec.get("exp_analysis") or {}).get("call_examples", []),
                "loops": (rec.get("exp_analysis") or {}).get("loops", []),
                "correctness": "UNVERIFIED",
            },
            "quality": {"tier": tier, "issues": c.get("issues", []) + ["exp_correctness_unverified"]},
        }
        if dup_group:
            manifest["dedup"] = {"duplicate_group_id": dup_group, "canonical": is_canon,
                                 "group_binary_sha256": binsha}
        with open(lp(str(bundle / "manifest.json")), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)

        entry.update({"case_id": case_id, "manifest": str(bundle / "manifest.json"),
                      "issues": c.get("issues", [])})
        summary[tier.lower()].append(entry)

    # ---- duplicate registry file
    for sha, members in dup_registry.items():
        if len(members) > 1:
            dup_out.append({"duplicate_group_id": "dupg-" + sha[:16], "binary_sha256": sha,
                            "canonical_case_unit": canonical[sha],
                            "members": [{"repo_url": m["record"]["repo"]["url"],
                                         "unit": m["record"]["unit"],
                                         "priority": SOURCE_CLASS_PRIORITY.get(m["record"]["repo"].get("source_class"), 9)}
                                        for m in members]})
    with open(lp(index_dir / "duplicates.json"), "w", encoding="utf-8") as f:
        json.dump(dup_out, f, ensure_ascii=False, indent=2)
    with open(lp(base / "batch_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[assemble] gold={len(summary['gold'])} silver={len(summary['silver'])} "
          f"review={len(summary['review'])} bronze={len(summary['bronze'])} "
          f"rejected={len(summary['rejected'])} dup_groups={len(dup_out)}")

# ---------------------------------------------------------------- report

def cmd_report(args):
    base = Path(args.base)
    bs = json.loads(read_bytes(base / "batch_summary.json").decode("utf-8"))
    metas = json.loads(read_bytes(base / "repos_meta.json").decode("utf-8"))
    dup = json.loads(read_bytes(base / "index" / "duplicates.json").decode("utf-8"))
    rej_reasons = {}
    for e in bs["rejected"]:
        r = e.get("reason") or "UNSPECIFIED"
        rej_reasons[r] = rej_reasons.get(r, 0) + 1
    report = {
        "schema_version": SCHEMA_VERSION,
        "batch": args.batch,
        "generated_at": args.now,
        "repositories_scanned": metas["repos_scanned"],
        "scan_scope": metas.get("scan_scope", []),
        "challenges_found": len(bs["gold"]) + len(bs["silver"]) + len(bs["review"]) + len(bs["bronze"]) + len(bs["rejected"]),
        "heap_candidates": len(bs["gold"]) + len(bs["silver"]) + len(bs["review"]) + len(bs["bronze"]),
        "gold_cases": len(bs["gold"]),
        "silver_cases": len(bs["silver"]),
        "review_queue": len(bs["review"]),
        "bronze_indexed": len(bs["bronze"]),
        "rejected_cases": len(bs["rejected"]),
        "rejection_reasons": rej_reasons,
        "duplicates": {"groups": len(dup), "detail": dup},
        "method_notes": [
            "Static analysis only; no challenge binary was executed.",
            "Candidate universe per repo = challenge units clustered from staged (sparse) checkouts curated by the collector.",
            "heap_confidence HIGH requires >=2 independent evidence classes (source/binary, exp, docs).",
            "glibc version only claimed from shipped libc/ld banner strings; Dockerfile FROM recorded as hint only.",
            "EXP correctness NOT verified (collector role, not solver); recorded as exp_correctness_unverified.",
            "Original files copied verbatim; SHA256 verified after copy; staging repos are pristine clones.",
            "Duplicate grouping by binary SHA256; non-canonical duplicates excluded from corpus, provenance kept.",
        ],
        "cases": bs,
    }
    with open(lp(str(base / "collection_report.json")), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[report] gold={report['gold_cases']} silver={report['silver_cases']} "
          f"review={report['review_queue']} bronze={report['bronze_indexed']} "
          f"rejected={report['rejected_cases']} dups={report['duplicates']['groups']}")

# ---------------------------------------------------------------- cli

def main():
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover")
    d.add_argument("--root", required=True)
    d.add_argument("--meta", required=True)
    d.add_argument("--base", required=True)
    d.add_argument("--out", required=True)
    a = sub.add_parser("select")
    a.add_argument("--base", required=True)
    s = sub.add_parser("assemble")
    s.add_argument("--config", required=True)
    r = sub.add_parser("report")
    r.add_argument("--base", required=True)
    r.add_argument("--batch", default="batch-1")
    r.add_argument("--now", default="")
    args = ap.parse_args()
    if args.cmd == "discover":
        meta = json.loads(read_bytes(args.meta).decode("utf-8"))
        discover_repo(Path(args.root), meta, Path(args.out))
    elif args.cmd == "select":
        cmd_select(args)
    elif args.cmd == "assemble":
        cmd_assemble(args)
    elif args.cmd == "report":
        cmd_report(args)

if __name__ == "__main__":
    main()
