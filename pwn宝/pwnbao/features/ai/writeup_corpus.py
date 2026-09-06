from __future__ import annotations

import ast
from collections import Counter
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_HEADING_RE = re.compile(r"(?i)\bpwn\s*(\d{3})\b")
_PYTHON_START_RE = re.compile(r"^\s*(?:from\s+pwn\s+import\b|import\s+pwn\b)")
_ALLOC_RE = re.compile(r"(?i)\b(?:add|alloc|allocate|malloc|new|create|insert|buy)[A-Za-z0-9_]*\s*\(")
_FREE_RE = re.compile(r"(?i)\b(?:delete|free|remove|drop|destroy|release|erase)[A-Za-z0-9_]*\s*\(")
_CODE_FENCE_RE = re.compile(r"```(?P<lang>[^\n`]*)\n(?P<body>.*?)```", re.DOTALL)
_SOURCE_EXTENSIONS = {".py", ".md", ".txt"}
_SKIP_DIR_NAMES = {
    ".git", ".idea", ".vscode", "__pycache__", ".pytest_cache", ".ruff_cache",
    "node_modules", "venv", ".venv", "build", "dist",
}
_HEAP_KEYWORDS = (
    "heap", "堆", "chunk", "tcache", "fastbin", "unsorted", "smallbin", "largebin",
    "off_by_null", "off-by-null", "overlap", "unlink", "malloc_hook", "free_hook",
)


@dataclass(frozen=True)
class WriteupCase:
    challenge_id: str
    pdf_name: str
    page_start: int
    page_end: int
    text: str


@dataclass(frozen=True)
class LocalSourceSnippet:
    source_path: Path
    snippet_index: int
    text: str
    extraction: str


class LocalSourceCorpusScanner:
    """Build a hash-locked local Heap AI corpus from user-provided source trees."""

    schema_version = 1
    max_file_bytes = 2 * 1024 * 1024

    def scan(self, root: str | Path, output_dir: str | Path) -> dict[str, object]:
        source_root = Path(root).resolve()
        output_root = Path(output_dir).resolve()
        if not source_root.is_dir():
            raise FileNotFoundError(f"local corpus root does not exist: {source_root}")

        output_root.mkdir(parents=True, exist_ok=True)
        derived_root = output_root / "sources"
        derived_root.mkdir(parents=True, exist_ok=True)

        files = [path for path in sorted(source_root.rglob("*")) if self._should_scan_file(path)]
        if not files:
            raise FileNotFoundError(f"local corpus root contains no .py/.md/.txt files: {source_root}")

        file_index: list[dict[str, object]] = []
        case_index: list[dict[str, object]] = []
        manifest_cases: list[dict[str, object]] = []
        helper_candidates: list[dict[str, object]] = []
        seen_case_ids: set[str] = set()

        for path in files:
            relative = path.relative_to(source_root).as_posix()
            file_record: dict[str, object] = {
                "path": str(path),
                "relative_path": relative,
                "bytes": path.stat().st_size,
                "sha256": self._sha256_file(path),
                "scanned": False,
            }
            if path.stat().st_size > self.max_file_bytes:
                file_record["skip_reason"] = "text file exceeds 2 MiB"
                file_index.append(file_record)
                continue
            text = self._read_text(path)
            snippets = self.extract_sources(path, text)
            file_record["scanned"] = True
            file_record["snippets"] = len(snippets)
            file_index.append(file_record)

            for snippet in snippets:
                source = snippet.text.strip() + "\n"
                source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
                context = f"{relative}\n{text}"
                heap_candidate = self.is_heap_source(source, context)
                record: dict[str, object] = {
                    "relative_path": relative,
                    "snippet_index": snippet.snippet_index,
                    "extraction": snippet.extraction,
                    "source_sha256": source_hash,
                    "source_lines": len(source.splitlines()),
                    "heap_candidate": heap_candidate,
                }
                if not heap_candidate:
                    record["skip_reason"] = "not enough heap/pwn helper evidence"
                    case_index.append(record)
                    continue

                derived_path = derived_root / f"ruanan-{source_hash[:16]}.py"
                if not derived_path.exists():
                    derived_path.write_text(source, encoding="utf-8", newline="\n")
                technique = PdfWriteupCorpusScanner.infer_technique(context + "\n" + source)
                version, version_evidence = PdfWriteupCorpusScanner.infer_glibc(context + "\n" + source)
                arch = PdfWriteupCorpusScanner.infer_arch(source, context)
                case_id = self._unique_case_id(relative, source_hash, seen_case_ids)
                split = PdfWriteupCorpusScanner.split_for_technique(technique)
                record.update({
                    "case_id": case_id,
                    "split": split,
                    "technique": technique,
                    "glibc": version,
                    "glibc_evidence": version_evidence,
                    "arch": arch,
                    "derived_source": str(derived_path),
                })
                case_index.append(record)
                manifest_cases.append({
                    "case_id": case_id,
                    "split": split,
                    "technique": technique,
                    "source_uri": str(derived_path),
                    "source_hash": source_hash,
                    "source_language": "python",
                    "purpose": "semantic",
                    "license": "local-user-provided",
                    "allocator": {
                        "family": "glibc",
                        "version": version,
                        "version_evidence": version_evidence,
                        "arch": arch,
                    },
                    "expected_ir": [],
                    "operations": [],
                    "assertions": [],
                    "note": (
                        f"Derived locally from {relative} snippet {snippet.snippet_index}; "
                        f"file SHA256 {file_record['sha256']}."
                    ),
                })
                helper_candidates.extend(
                    self.extract_helper_candidates(source, case_id=case_id, source_path=relative)
                )

        manifest = {"schema_version": 1, "cases": manifest_cases}
        manifest_path = output_root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        prompt_guidance = self.build_prompt_guidance(helper_candidates)
        prompt_guidance_path = output_root / "prompt_guidance.json"
        prompt_guidance_path.write_text(
            json.dumps(prompt_guidance, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        index = {
            "schema_version": self.schema_version,
            "source_root": str(source_root),
            "files": file_index,
            "cases": case_index,
            "summary": {
                "file_count": len(file_index),
                "snippet_count": len(case_index),
                "heap_cases": len(manifest_cases),
                "helper_candidates": len(helper_candidates),
                "techniques": dict(Counter(str(item["technique"]) for item in manifest_cases)),
            },
            "manifest": str(manifest_path),
            "prompt_guidance": str(prompt_guidance_path),
        }
        (output_root / "source_index.json").write_text(
            json.dumps(index, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return index

    @classmethod
    def extract_sources(cls, path: str | Path, text: str) -> tuple[LocalSourceSnippet, ...]:
        source_path = Path(path)
        suffix = source_path.suffix.lower()
        normalized = PdfWriteupCorpusScanner._normalize_text(text)
        snippets: list[LocalSourceSnippet] = []

        if suffix == ".py":
            return (LocalSourceSnippet(source_path, 1, normalized, "python-file"),)

        for match in _CODE_FENCE_RE.finditer(normalized):
            lang = match.group("lang").strip().lower()
            body = PdfWriteupCorpusScanner._normalize_text(match.group("body"))
            if lang and lang not in {"py", "python", "python3"}:
                continue
            if not cls._looks_like_python(body):
                continue
            snippets.append(LocalSourceSnippet(source_path, len(snippets) + 1, body, "markdown-fence"))

        recovered = PdfWriteupCorpusScanner.extract_python(normalized)
        if recovered and cls._looks_like_python(recovered):
            snippets.append(LocalSourceSnippet(source_path, len(snippets) + 1, recovered, "pwn-import-block"))
        elif suffix == ".txt" and cls._looks_like_python(normalized):
            snippets.append(LocalSourceSnippet(source_path, len(snippets) + 1, normalized, "text-python"))

        unique: list[LocalSourceSnippet] = []
        seen_hashes: set[str] = set()
        for snippet in snippets:
            digest = hashlib.sha256(snippet.text.strip().encode("utf-8")).hexdigest()
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            unique.append(snippet)
        return tuple(unique)

    @staticmethod
    def is_heap_source(source: str, context: str = "") -> bool:
        if PdfWriteupCorpusScanner.is_heap_source(source, context):
            return True
        combined = (source + "\n" + context).lower()
        has_pwn_runtime = "from pwn import" in combined or "import pwn" in combined or "p64(" in source or "u64(" in source
        has_menu_heap = bool(_ALLOC_RE.search(source)) and bool(_FREE_RE.search(source))
        heapish_context = any(keyword.lower() in combined for keyword in _HEAP_KEYWORDS)
        exploit_context = any(token in combined for token in ("libc", "heap", "chunk", "tcache", "unsorted", "__free_hook"))
        return has_menu_heap and has_pwn_runtime and (heapish_context or exploit_context)

    @staticmethod
    def extract_helper_candidates(source: str, *, case_id: str, source_path: str) -> list[dict[str, object]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        candidates: list[dict[str, object]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            semantic = LocalSourceCorpusScanner._semantic_hint(node.name)
            if not semantic:
                continue
            raw_parameters = [arg.arg for arg in node.args.args]
            receiver = raw_parameters[0] if raw_parameters and raw_parameters[0] in {"self", "cls"} else ""
            parameters = raw_parameters[1:] if receiver else raw_parameters
            roles = [LocalSourceCorpusScanner._role_hint(parameter) for parameter in parameters]
            candidates.append({
                "case_id": case_id,
                "source_path": source_path,
                "function": node.name,
                "semantic": semantic,
                "arity": len(parameters),
                "parameters": parameters,
                "roles": roles,
                "receiver": receiver,
                "line": int(getattr(node, "lineno", 0) or 0),
            })
        return candidates

    @staticmethod
    def build_prompt_guidance(helper_candidates: list[dict[str, object]]) -> dict[str, object]:
        semantic_counts = Counter(str(item.get("semantic") or "") for item in helper_candidates)
        function_counts = Counter(str(item.get("function") or "") for item in helper_candidates)
        return {
            "schema_version": 1,
            "model": "qwen3-coder-30b-a3b-instruct",
            "purpose": "local prompt/rule guidance; not model-weight training",
            "prompt_reminders": [
                "EXP 是源码事实；不要执行 EXP，也不要把注释/利用意图提升为 allocator 事实。",
                "只输出 JSON；最多给一个最高价值 proposal；没有把握时 proposals 为空。",
                "source_start/source_end 必须是 exp_source 的字节偏移，source_text 必须等于 exp_source[start:end]。",
                "helper_mapping 只描述 helper 的语义、函数名、参数 roles；menu choice 常量不能当成 chunk index。",
                "copy/move/memcpy 统一用 semantic=copy，roles 使用 src/dst/length；方向不确定时不要提交。",
                "login/select/use 之后的 edit_bio(size,payload) 这类对象字段写入使用 active index；size 不是 index。",
                "fd/bk、consolidate、safe-linking 等只能通过 heap_rule_call 或可重放 operation 表达，不能直接改图。",
                "Pwndbg 粘贴才是 observed；静态源码和 AI 推断只能标 inferred/assumed。",
            ],
            "structured_output_contract": {
                "root_keys": ["source_hash", "proposals", "diagnostics"],
                "proposal_keys": [
                    "proposal_id", "action", "source_start", "source_end",
                    "source_text", "confidence", "rationale", "payload_json",
                ],
                "preferred_actions": [
                    "helper_mapping", "heap_rule_call", "replace_operation",
                    "insert_after", "branch_choice", "memory_annotation",
                ],
            },
            "rule_output_examples": [
                {
                    "name": "custom delete/free helper",
                    "proposal": {
                        "action": "helper_mapping",
                        "payload_json": json.dumps({
                            "semantic": "free",
                            "function": "destroy",
                            "roles": ["index"],
                            "arity": 1,
                            "parameter_names": ["idx"],
                        }, ensure_ascii=False, separators=(",", ":")),
                    },
                },
                {
                    "name": "copy helper",
                    "proposal": {
                        "action": "helper_mapping",
                        "payload_json": json.dumps({
                            "semantic": "copy",
                            "function": "copy_chunk",
                            "roles": ["src", "dst", "length"],
                            "arity": 3,
                            "parameter_names": ["src", "dst", "length"],
                        }, ensure_ascii=False, separators=(",", ":")),
                    },
                },
                {
                    "name": "selected object field edit",
                    "proposal": {
                        "action": "helper_mapping",
                        "payload_json": json.dumps({
                            "semantic": "edit",
                            "function": "edit_bio",
                            "roles": ["size", "data"],
                            "arity": 2,
                            "parameter_names": ["size", "payload"],
                        }, ensure_ascii=False, separators=(",", ":")),
                    },
                },
                {
                    "name": "catalog rule call",
                    "proposal": {
                        "action": "heap_rule_call",
                        "payload_json": json.dumps({
                            "rule_id": "allocator.consolidate",
                            "arguments": {"trigger": "large_malloc"},
                            "placement": "insert_after",
                        }, ensure_ascii=False, separators=(",", ":")),
                    },
                },
            ],
            "discovered_helper_summary": {
                "by_semantic": dict(sorted(semantic_counts.items())),
                "top_functions": dict(function_counts.most_common(16)),
            },
            "review_candidates": helper_candidates[:64],
            "negative_examples": [
                "sendlineafter(b'choice:', enc(1)) 只是 helper 内菜单选择，不是 free/show 操作本身。",
                "sendMessage(payload) / io.send(payload) 只有 payload 发送语义，不能单独映射成 heap free。",
                "注释里的 Layout/House 名称只能作为 intent，不能直接产生 chunk/bin 事实。",
            ],
        }

    @staticmethod
    def _should_scan_file(path: Path) -> bool:
        if not path.is_file() or path.suffix.lower() not in _SOURCE_EXTENSIONS:
            return False
        lowered_parts = {part.lower() for part in path.parts}
        return not bool(lowered_parts & _SKIP_DIR_NAMES)

    @staticmethod
    def _read_text(path: Path) -> str:
        data = path.read_bytes()
        for encoding in ("utf-8-sig", "utf-8", "gb18030"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _looks_like_python(text: str) -> bool:
        sample = text.strip()
        if not sample:
            return False
        if _PYTHON_START_RE.search(sample) or re.search(r"^\s*def\s+\w+\s*\(", sample, re.MULTILINE):
            return True
        return any(token in sample for token in ("p64(", "u64(", "sendlineafter", "recvuntil"))

    @staticmethod
    def _unique_case_id(relative_path: str, source_hash: str, seen: set[str]) -> str:
        stem = re.sub(r"[^A-Za-z0-9_.:-]+", "-", Path(relative_path).with_suffix("").as_posix())
        stem = stem.strip("-._:") or "case"
        case_id = f"local.ruanan.{stem}"
        if len(case_id) > 112:
            case_id = case_id[:112].rstrip("-._:")
        case_id = f"{case_id}.{source_hash[:8]}"
        original = case_id
        suffix = 2
        while case_id in seen:
            case_id = f"{original}.{suffix}"
            suffix += 1
        seen.add(case_id)
        return case_id

    @staticmethod
    def _semantic_hint(function_name: str) -> str:
        lowered = function_name.lower()
        if re.search(r"(copy|clone|duplicate|memcpy|memmove|move)", lowered):
            return "copy"
        if _ALLOC_RE.search(function_name + "("):
            return "alloc"
        if _FREE_RE.search(function_name + "("):
            return "free"
        if re.search(r"(edit|update|write|change|modify|fill|rename|set)", lowered):
            return "edit"
        if re.search(r"(show|view|display|leak|dump|read|puts|see)", lowered):
            return "show"
        return ""

    @staticmethod
    def _role_hint(parameter: str) -> str:
        lowered = parameter.lower()
        if lowered in {"src", "source", "from_idx", "from_index"}:
            return "src"
        if lowered in {"dst", "dest", "destination", "to_idx", "to_index"}:
            return "dst"
        if lowered in {"length", "len", "n", "count"}:
            return "length"
        if "size" in lowered:
            return "size"
        if lowered in {"idx", "index", "slot", "id", "pos", "note_idx"} or lowered.endswith("_idx"):
            return "index"
        if lowered in {"content", "data", "payload", "buf", "value"}:
            return "data"
        return parameter

    @staticmethod
    def _sha256_file(path: Path) -> str:
        return PdfWriteupCorpusScanner._sha256_file(path)


class PdfWriteupCorpusScanner:
    """Build a hash-locked local Heap AI corpus from user-owned PDFs."""

    schema_version = 1

    def scan(self, root: str | Path, output_dir: str | Path) -> dict[str, object]:
        source_root = Path(root).resolve()
        output_root = Path(output_dir).resolve()
        if not source_root.is_dir():
            raise FileNotFoundError(f"writeup root does not exist: {source_root}")
        pdfs = sorted(source_root.glob("*.pdf"))
        if not pdfs:
            raise FileNotFoundError(f"writeup root contains no PDF: {source_root}")
        try:
            from pypdf import PdfReader
        except ImportError as error:
            raise RuntimeError("PDF corpus scan requires pypdf>=6.0") from error

        output_root.mkdir(parents=True, exist_ok=True)
        derived_root = output_root / "sources"
        derived_root.mkdir(parents=True, exist_ok=True)
        pdf_index: list[dict[str, object]] = []
        case_index: list[dict[str, object]] = []
        manifest_cases: list[dict[str, object]] = []
        seen_case_ids: set[str] = set()
        for pdf_path in pdfs:
            pdf_hash = self._sha256_file(pdf_path)
            reader = PdfReader(str(pdf_path))
            pages = [self._normalize_text(page.extract_text() or "") for page in reader.pages]
            writeups = self.extract_cases(pdf_path.name, pages)
            pdf_index.append({
                "path": str(pdf_path),
                "sha256": pdf_hash,
                "bytes": pdf_path.stat().st_size,
                "pages": len(pages),
                "detected_cases": len(writeups),
            })
            for writeup in writeups:
                source = self.extract_python(writeup.text)
                heap_candidate = bool(source and self.is_heap_source(source, writeup.text, writeup.challenge_id))
                record: dict[str, object] = {
                    "challenge_id": writeup.challenge_id,
                    "pdf": writeup.pdf_name,
                    "pdf_sha256": pdf_hash,
                    "page_start": writeup.page_start,
                    "page_end": writeup.page_end,
                    "python_extracted": bool(source),
                    "heap_candidate": heap_candidate,
                }
                if source:
                    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
                    source_path = derived_root / f"ctfshow-pwn-{writeup.challenge_id}-{source_hash[:12]}.py"
                    source_path.write_text(source, encoding="utf-8", newline="\n")
                    record["source_sha256"] = source_hash
                    record["source_lines"] = len(source.splitlines())
                    record["derived_source"] = str(source_path)
                if not heap_candidate:
                    case_index.append(record)
                    continue
                technique = self.infer_technique(writeup.text + "\n" + source)
                version, version_evidence = self.infer_glibc(writeup.text)
                arch = self.infer_arch(source, writeup.text)
                case_id = f"local.ctfshow.pwn{writeup.challenge_id}"
                if case_id in seen_case_ids:
                    case_id += "." + source_hash[:8]
                seen_case_ids.add(case_id)
                split = self.split_for_technique(technique)
                record.update({
                    "case_id": case_id,
                    "technique": technique,
                    "split": split,
                    "glibc": version,
                    "glibc_evidence": version_evidence,
                    "arch": arch,
                })
                case_index.append(record)
                manifest_cases.append({
                    "case_id": case_id,
                    "split": split,
                    "technique": technique,
                    "source_uri": str(source_path),
                    "source_hash": source_hash,
                    "source_language": "python",
                    "purpose": "semantic",
                    "license": "local-user-provided",
                    "allocator": {
                        "family": "glibc",
                        "version": version,
                        "version_evidence": version_evidence,
                        "arch": arch,
                    },
                    "expected_ir": [],
                    "operations": [],
                    "assertions": [],
                    "note": (
                        f"Derived locally from {pdf_path.name} pages "
                        f"{writeup.page_start}-{writeup.page_end}; PDF SHA256 {pdf_hash}."
                    ),
                })

        manifest = {"schema_version": 1, "cases": manifest_cases}
        manifest_path = output_root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        index = {
            "schema_version": self.schema_version,
            "source_root": str(source_root),
            "pdfs": pdf_index,
            "cases": case_index,
            "summary": {
                "pdf_count": len(pdf_index),
                "page_count": sum(int(item["pages"]) for item in pdf_index),
                "detected_cases": len(case_index),
                "python_cases": sum(bool(item["python_extracted"]) for item in case_index),
                "heap_cases": len(manifest_cases),
            },
            "manifest": str(manifest_path),
        }
        (output_root / "writeup_index.json").write_text(
            json.dumps(index, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return index

    @classmethod
    def extract_cases(cls, pdf_name: str, pages: Iterable[str]) -> tuple[WriteupCase, ...]:
        cases: list[WriteupCase] = []
        current_id = ""
        current_start = 0
        current_lines: list[str] = []

        def finish(page_end: int) -> None:
            if current_id and current_lines:
                cases.append(WriteupCase(current_id, pdf_name, current_start, page_end, "\n".join(current_lines)))

        page_number = 0
        for page_number, page_text in enumerate(pages, 1):
            for line in page_text.splitlines():
                matches = _HEADING_RE.findall(line)
                is_range = len(matches) > 1 and bool(re.search(r"[-~]\s*pwn", line, re.IGNORECASE))
                if matches and not is_range:
                    finish(page_number)
                    current_id = matches[0]
                    current_start = page_number
                    current_lines = [line]
                elif current_id:
                    current_lines.append(line)
        finish(page_number)
        return tuple(cases)

    @classmethod
    def extract_python(cls, text: str) -> str:
        lines = cls._normalize_text(text).splitlines()
        cleaned = [line for line in lines if not re.fullmatch(r"\s*\d+\s*", line)]
        starts = [index for index, line in enumerate(cleaned) if _PYTHON_START_RE.search(line)]
        candidates: list[str] = []
        for position, start in enumerate(starts):
            stop = starts[position + 1] if position + 1 < len(starts) else len(cleaned)
            block = cleaned[start:stop][:3000]
            variants = (block, cls._normalize_python_indentation(block))
            for variant in variants:
                for end in range(len(variant), 3, -1):
                    candidate = "\n".join(variant[:end]).strip() + "\n"
                    try:
                        ast.parse(candidate)
                    except (SyntaxError, ValueError, TypeError):
                        continue
                    candidates.append(candidate)
                    break
        if not candidates:
            return ""
        return max(candidates, key=lambda value: (len(value.splitlines()), len(value)))

    @staticmethod
    def is_heap_source(source: str, context: str = "", challenge_id: str = "") -> bool:
        combined = (source + "\n" + context).lower()
        keyword_score = sum(keyword.lower() in combined for keyword in _HEAP_KEYWORDS)
        has_alloc = bool(_ALLOC_RE.search(source))
        has_free = bool(_FREE_RE.search(source))
        hook_signal = any(name in source for name in ("__malloc_hook", "__free_hook", "_IO_list_all"))
        in_heap_course = challenge_id.isdigit() and int(challenge_id) >= 159
        if in_heap_course:
            return keyword_score >= 1 and (has_alloc or has_free or hook_signal)
        return has_alloc and has_free and keyword_score >= 2

    @staticmethod
    def infer_technique(text: str) -> str:
        lower = text.lower().replace(" ", "")
        rules = (
            ("safe-link-double-protect", ("doubleprotect", "safe-linking")),
            ("tcache-stashing-unlink", ("stashing", "tcache_stashing")),
            ("large-bin", ("largebin", "large-bin")),
            ("small-bin", ("smallbin", "small-bin")),
            ("unsorted-bin", ("unsortedbin", "unsorted-bin")),
            ("fastbin", ("fastbin",)),
            ("overlap", ("overlap", "off_by_null", "off-by-null")),
            ("unlink", ("unlink",)),
            ("tcache", ("tcache",)),
        )
        for technique, keywords in rules:
            if any(keyword in lower for keyword in keywords):
                return technique
        return "heap-general"

    @staticmethod
    def infer_glibc(text: str) -> tuple[str, str]:
        normalized = text.replace(" ", "")
        explicit = re.search(r"(?:glibc|libc)[-_]?(2\.\d{2})", normalized, re.IGNORECASE)
        if explicit:
            return explicit.group(1), explicit.group(0)
        ubuntu = re.search(r"Ubuntu(16\.04|18\.04|20\.04|22\.04|24\.04)", normalized, re.IGNORECASE)
        mapping = {"16.04": "2.23", "18.04": "2.27", "20.04": "2.31", "22.04": "2.35", "24.04": "2.39"}
        if ubuntu:
            release = ubuntu.group(1)
            return mapping[release], f"Ubuntu {release}"
        return "2.35", "unspecified; review required"

    @staticmethod
    def infer_arch(source: str, text: str) -> str:
        combined = source + "\n" + text
        if re.search(r"context\s*\([^\n]*arch\s*=\s*['\"]i386", combined) or "p32(" in source:
            return "i386"
        return "amd64"

    @staticmethod
    def split_for_technique(technique: str) -> str:
        bucket = hashlib.sha256(technique.encode("utf-8")).digest()[0]
        if bucket < 180:
            return "train"
        if bucket < 224:
            return "dev"
        return "holdout"

    @staticmethod
    def _normalize_text(text: str) -> str:
        value = str(text or "").replace("\u00a0", " ").replace("\ufeff", "")
        value = "".join(" " if ord(char) < 32 and char not in "\n\t" else char for char in value)
        return value.replace("\r\n", "\n").replace("\r", "\n")

    @staticmethod
    def _normalize_python_indentation(lines: list[str]) -> list[str]:
        normalized: list[str] = []
        for line in lines:
            expanded = line.expandtabs(4)
            stripped = expanded.lstrip(" ")
            width = len(expanded) - len(stripped)
            if width:
                width = max(4, int((width + 2) // 4) * 4)
            normalized.append(" " * width + stripped)
        return normalized

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
