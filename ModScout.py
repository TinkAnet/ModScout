#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import datetime
import importlib
import inspect
import json
import os
import re
import sys
import sysconfig
from typing import Any, Dict, List, Optional

SYSTEM_MODULES = {
    "os", "sys", "subprocess", "ctypes", "multiprocessing", "pathlib", "socket",
    "ssl", "http", "ftplib", "telnetlib", "select", "selectors", "shutil",
    "signal", "resource", "fcntl", "pty", "platform", "shlex", "winreg", "uuid",
    "tempfile", "atexit", "importlib",
}

SYSTEM_CALLABLES = {
    "system", "popen", "Popen", "run", "call", "check_call", "check_output",
    "spawn", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "execv", "execve", "execl", "execlp", "execlpe", "execvp", "execvpe",
    "fork", "forkpty",
    "open", "unlink", "remove", "rmdir", "rmtree", "mkfifo", "mknod",
    "chmod", "chown",
}

DEFAULT_CONFIG = {
    "roots": ["random"],
    "rules": [
        {"type": "category", "category": "system"},
        {"type": "category", "category": "builtin"}
    ],
    "scan": {
        "max_depth": 4,
        "max_objects": 60000,
        "prune_dunders": True,
        "risk_getattr": False,
        "follow_classes": True,
        "follow_instances": False,
        "exclude_module_prefixes": ["numpy", "pandas", "torch", "tensorflow"]
    },
    "output": {
        "json_path": "modscan_report.json",
        "limit": 2000
    }
}

def is_builtin_module(mod: Any) -> bool:
    try:
        name = mod.__name__
    except Exception:
        return False
    if name in sys.builtin_module_names:
        return True
    spec = getattr(mod, "__spec__", None)
    return bool(spec and getattr(spec, "origin", None) == "built-in")


def is_stdlib_module(mod: Any) -> bool:
    spec = getattr(mod, "__spec__", None)
    if not spec:
        return False
    origin = getattr(spec, "origin", None)
    if origin == "built-in":
        return True
    if not isinstance(origin, str):
        return False
    try:
        stdlib = sysconfig.get_paths()["stdlib"]
    except Exception:
        return False
    try:
        return os.path.abspath(origin).startswith(os.path.abspath(stdlib))
    except Exception:
        return False


def iter_attr_names(obj: Any, use_dir: bool = True) -> List[str]:
    names = set()
    d = getattr(obj, "__dict__", None)
    if isinstance(d, dict):
        names.update(d.keys())
    elif d is not None:
        try:
            names.update(d.keys())
        except Exception:
            pass
    if use_dir:
        try:
            for n in dir(obj):
                names.add(n)
        except Exception:
            pass
    return list(names)


_MISSING = object()


class SafeGetAttr:
    def __init__(self, risk: bool = False) -> None:
        self.risk = risk

    def get(self, obj: Any, name: str) -> Any:
        d = getattr(obj, "__dict__", None)
        if isinstance(d, dict) and name in d:
            return d[name]
        if d is not None:
            try:
                if name in d.keys():
                    return d[name]
            except Exception:
                pass
        if not self.risk:
            return _MISSING
        try:
            return getattr(obj, name)
        except Exception:
            return _MISSING


def is_traversable(child: Any,
                   follow_classes: bool = True,
                   follow_instances: bool = False) -> bool:
    if inspect.ismodule(child):
        return True
    if follow_classes and inspect.isclass(child):
        return True
    if follow_instances:
        if isinstance(child, (str, bytes, bytearray, memoryview, int, float, complex, bool)):
            return False
        return hasattr(child, "__dict__")
    return False


def qual_from_path(path: List[str]) -> str:
    return ".".join(path)


def describe_object(obj: Any) -> Dict[str, Any]:
    try:
        mod = getattr(obj, "__module__", None)
    except Exception:
        mod = None
    try:
        qn = getattr(obj, "__qualname__", None)
    except Exception:
        qn = None
    try:
        name = getattr(obj, "__name__", None)
    except Exception:
        name = None
    spec = getattr(obj, "__spec__", None) if inspect.ismodule(obj) else None
    origin = getattr(spec, "origin", None) if spec else None
    file = getattr(obj, "__file__", None) if inspect.ismodule(obj) else None
    return {
        "type": "module" if inspect.ismodule(obj) else type(obj).__name__,
        "module": mod,
        "qualname": qn,
        "name": name,
        "module_file": file,
        "spec_origin": origin,
    }


def match_rules(child: Any,
                name: str,
                path: List[str],
                rules: List[Dict[str, Any]],
                categories: Optional[Dict[str, Dict[str, List[str]]]] = None) -> List[Dict[str, Any]]:
    categories = categories or {}
    qpath = qual_from_path(path)
    hits: List[Dict[str, Any]] = []

    for rule in rules:
        kind = rule.get("type") or rule.get("kind")
        pat = rule.get("pattern") or rule.get("value")
        cat = rule.get("category")
        reason = None

        if kind == "module_name":
            if inspect.ismodule(child) and getattr(child, "__name__", None) == pat:
                reason = f"module_name == {pat}"

        elif kind == "module_startswith":
            if inspect.ismodule(child):
                n = getattr(child, "__name__", None)
                if isinstance(n, str) and n.startswith(pat):
                    reason = f"module startswith {pat}"

        elif kind == "qualname":
            if qpath == pat:
                reason = f"path == {pat}"

        elif kind == "qualname_regex":
            try:
                if re.search(pat, qpath):
                    reason = f"path matches /{pat}/"
            except re.error:
                pass

        elif kind == "callable_name":
            if callable(child) and name == pat:
                reason = f"callable name == {pat}"

        elif kind == "attr_name":
            if name == pat:
                reason = f"attr name == {pat}"

        elif kind == "builtin_module":
            if inspect.ismodule(child) and is_builtin_module(child):
                reason = "builtin module"

        elif kind == "stdlib_module":
            if inspect.ismodule(child) and is_stdlib_module(child):
                reason = "stdlib module"

        elif kind == "category":
            modules = set(categories.get(cat, {}).get("modules", []))
            callables = set(categories.get(cat, {}).get("callables", []))
            if not modules and not callables:
                if cat == "system":
                    modules, callables = SYSTEM_MODULES, SYSTEM_CALLABLES
                elif cat == "builtin":
                    modules, callables = set(), set()

            if cat == "system":
                if (inspect.ismodule(child) and getattr(child, "__name__", None) in modules) or \
                   (callable(child) and name in callables):
                    reason = f"category:{cat}"
            elif cat == "builtin":
                if inspect.ismodule(child) and is_builtin_module(child):
                    reason = f"category:{cat}"

        if reason:
            hits.append({"kind": kind, "reason": reason, "rule": rule})

    return hits


def scan_roots(roots: List[str],
               rules: List[Dict[str, Any]],
               *,
               max_depth: int = 5,
               max_objects: int = 50000,
               prune_dunders: bool = True,
               risk_getattr: bool = False,
               follow_classes: bool = True,
               follow_instances: bool = False,
               exclude_module_prefixes: Optional[List[str]] = None,
               categories: Optional[Dict[str, Dict[str, List[str]]]] = None) -> List[Dict[str, Any]]:
    exclude_module_prefixes = exclude_module_prefixes or []
    sg = SafeGetAttr(risk=risk_getattr)
    visited: set[int] = set()
    queue = collections.deque()

    findings: List[Dict[str, Any]] = []
    count = 0

    for root in roots:
        try:
            mod = importlib.import_module(root)
            queue.append((mod, root, [root], 0))
        except Exception as e:
            print(f"[WARN] Failed to import root {root}: {e}", file=sys.stderr)

    while queue and count < max_objects:
        obj, name, path, depth = queue.popleft()
        oid = id(obj)
        if oid in visited:
            continue
        visited.add(oid)
        count += 1

        if inspect.ismodule(obj):
            modname = getattr(obj, "__name__", None)
            if modname and any(modname.startswith(pfx) for pfx in exclude_module_prefixes):
                continue

        for hit in match_rules(obj, path[-1], path, rules, categories=categories):
            findings.append({
                "path": qual_from_path(path),
                "name": path[-1],
                "depth": depth,
                "match": hit,
                "object": describe_object(obj),
            })

        if depth >= max_depth:
            continue

        names = iter_attr_names(obj, use_dir=True)
        if prune_dunders:
            names = [n for n in names if not (n.startswith("__") and n.endswith("__"))]

        for n in names:
            child = sg.get(obj, n)
            if child is _MISSING:
                continue
            child_path = path + [n]

            for hit in match_rules(child, n, child_path, rules, categories=categories):
                findings.append({
                    "path": qual_from_path(child_path),
                    "name": n,
                    "depth": depth + 1,
                    "match": hit,
                    "object": describe_object(child),
                })

            if is_traversable(child, follow_classes=follow_classes, follow_instances=follow_instances):
                queue.append((child, n, child_path, depth + 1))

    return findings


def run_with_config(cfg: Dict[str, Any]):
    roots = cfg.get("roots", [])
    rules = cfg.get("rules", [])
    scan = cfg.get("scan", {})
    out = cfg.get("output", {})
    categories = cfg.get("categories", {})

    findings = scan_roots(
        roots=roots,
        rules=rules,
        max_depth=scan.get("max_depth", 5),
        max_objects=scan.get("max_objects", 50000),
        prune_dunders=scan.get("prune_dunders", True),
        risk_getattr=scan.get("risk_getattr", False),
        follow_classes=scan.get("follow_classes", True),
        follow_instances=scan.get("follow_instances", False),
        exclude_module_prefixes=scan.get("exclude_module_prefixes", []),
        categories=categories,
    )

    summary = collections.defaultdict(int)
    for f in findings:
        summary[f["match"]["reason"]] += 1
    return findings, summary


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Analyze Python module chains using dir() recursively and flag target modules/objects."
    )
    p.add_argument("-c", "--config", help="Path to JSON config. See --write-example to generate one.")
    p.add_argument("--roots", help="Comma-separated roots to scan (overrides config).")
    p.add_argument("--targets", help="Comma-separated shorthand categories, e.g. 'system,builtin' (adds to rules).")
    p.add_argument("--max-depth", type=int, help="Override scan.max_depth.")
    p.add_argument("--risk-getattr", action="store_true",
                   help="Also use getattr() when __dict__ lacks an attribute (WARNING: may import or trigger descriptors).")
    p.add_argument("--write-example", action="store_true", help="Write modscan.example.json and exit.")
    p.add_argument("--json-out", help="Where to write JSON report (overrides config.output.json_path).")
    p.add_argument("--limit", type=int, default=5000, help="Limit findings in JSON (0 = no limit).")
    args = p.parse_args(argv)

    if args.write_example:
        example = {
            "roots": ["random"],
            "rules": [
                {"type": "category", "category": "system"},
                {"type": "category", "category": "builtin"},
                {"type": "qualname_regex", "pattern": r"random\._os\.(system|popen|Popen|fork)"},
            ],
            "categories": {
                "system": {
                    "modules": sorted(list(SYSTEM_MODULES)),
                    "callables": sorted(list(SYSTEM_CALLABLES)),
                }
            },
            "scan": {
                "max_depth": 4,
                "max_objects": 60000,
                "prune_dunders": True,
                "risk_getattr": False,
                "follow_classes": True,
                "follow_instances": False,
                "exclude_module_prefixes": ["numpy", "pandas", "torch", "tensorflow"],
            },
            "output": {
                "json_path": "modscan_report.json",
                "limit": 2000
            }
        }
        with open("modscan.example.json", "w", encoding="utf-8") as f:
            json.dump(example, f, indent=2, ensure_ascii=False)
        print("Wrote modscan.example.json")
        return 0

    cfg = DEFAULT_CONFIG.copy()
    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    if args.roots:
        cfg["roots"] = [r.strip() for r in args.roots.split(",") if r.strip()]
    if args.targets:
        targs = [t.strip() for t in args.targets.split(",") if t.strip()]
        cfg.setdefault("rules", [])
        for t in targs:
            cfg["rules"].append({"type": "category", "category": t})
    if args.max_depth is not None:
        cfg.setdefault("scan", {})["max_depth"] = args.max_depth
    if args.risk_getattr:
        cfg.setdefault("scan", {})["risk_getattr"] = True
    if args.json_out:
        cfg.setdefault("output", {})["json_path"] = args.json_out
    if args.limit is not None:
        cfg.setdefault("output", {})["limit"] = args.limit

    findings, summary = run_with_config(cfg)

    print("=== Summary ===")
    print("Roots:", ", ".join(cfg.get("roots", [])))
    for k, v in sorted(summary.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"{v:5d}  {k}")

    show_n = min(30, len(findings))
    print(f"\n=== First {show_n} findings ===")
    for f in findings[:show_n]:
        obj = f["object"]
        obj_loc = f"{obj['module']}.{obj['qualname'] or obj['name']}" if obj['module'] else (obj['qualname'] or obj['name'])
        print(f"[d={f['depth']}] {f['path']} :: {obj['type']} ({obj_loc})  -- {f['match']['reason']}")

    out_path = cfg.get("output", {}).get("json_path")
    if out_path:
        limit = cfg.get("output", {}).get("limit", 0) or None
        to_write = findings if limit is None else findings[:limit]
        payload = {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "roots": cfg.get("roots", []),
            "rules": cfg.get("rules", []),
            "scan": cfg.get("scan", {}),
            "summary": dict(summary),
            "total_matches": len(findings),
            "findings": to_write,
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"\nSaved JSON report to {out_path}  (items written: {len(to_write)}/{len(findings)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
