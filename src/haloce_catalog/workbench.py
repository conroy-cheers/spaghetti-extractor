from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path
from typing import Any

from .util import sha256_file, write_json


def ensure_reimplementation_workbench(corpus_dir: Path, *, html_dir: Path | None = None) -> dict[str, Any]:
    corpus_dir = corpus_dir.resolve()
    plan = write_reimplementation_plan(corpus_dir)
    cli_index = write_cli_index(corpus_dir, plan=plan)
    rendered = render_dirty_corpus(corpus_dir, html_dir or (corpus_dir / "review-html"), plan=plan, cli_index=cli_index)
    return {"plan": plan, "cli_index": cli_index, "html": rendered}


def write_reimplementation_plan(corpus_dir: Path) -> dict[str, Any]:
    index = _collect_corpus_index(corpus_dir)
    tasks: list[dict[str, Any]] = []
    for routine in index["routines"]:
        label = routine["label"]
        routine_dir = routine["dir"]
        blocks = [block for block in index["blocks"] if block.get("function_label") == label]
        covered_tests = sorted(
            {
                str(test)
                for block in blocks
                for test in ((block.get("coverage_summary") or {}).get("covered_by_tests") or [])
            }
        )
        contracts = routine.get("contracts") if isinstance(routine.get("contracts"), list) else []
        tasks.append(
            {
                "task_id": f"routine-{label}",
                "task_kind": "routine_cluster",
                "title": f"Rewrite routine {label}",
                "labels": [label] + [block["label"] for block in blocks],
                "known_facts": [
                    f"static_name={routine.get('name', 'unknown')}",
                    f"subsystem={routine.get('subsystem', 'unknown')}",
                    f"purity={routine.get('purity', 'unknown')}",
                    f"side_effects={routine.get('side_effects', 'unknown')}",
                    f"blocks={len(blocks)}",
                    f"contracts={len(contracts)}",
                ],
                "observed_examples": covered_tests,
                "private_evidence_links": _existing_links(
                    corpus_dir,
                    routine_dir,
                    [
                        "manifest.json",
                        "index.md",
                        "static/cfg.json",
                        "static/semantics.json",
                        "static/decompiler-status.json",
                        "static/disassembly.asm",
                        "dynamic/coverage.json",
                        "draft/dirty-contract.md",
                    ],
                )
                + [
                    block["rel_manifest"]
                    for block in blocks[:50]
                ],
                "clean_rewrite_target": _first_existing_link(corpus_dir, routine_dir, ["draft/dirty-contract.md"]),
                "acceptance_tests": covered_tests,
                "open_questions": [
                    "What public behavior can be stated without preserving original expression?",
                    "Which black-box or internal harness tests prove this rewrite?",
                ],
                "review_status": "todo",
            }
        )

    review_by_category: dict[str, list[dict[str, Any]]] = {}
    for packet in index["review_packets"]:
        review_by_category.setdefault(str(packet.get("category") or "review"), []).append(packet)
    for category, packets in sorted(review_by_category.items()):
        tasks.append(
            {
                "task_id": f"evidence-{category}",
                "task_kind": "behavior_surface",
                "title": f"Review {category.replace('-', ' ')} evidence",
                "labels": [str(packet.get("label")) for packet in packets if packet.get("label")],
                "known_facts": [f"review_packets={len(packets)}"],
                "observed_examples": [str(packet.get("title") or packet.get("label")) for packet in packets[:25]],
                "private_evidence_links": [str(packet.get("rel_dirty")) for packet in packets if packet.get("rel_dirty")],
                "clean_rewrite_target": "review/",
                "acceptance_tests": [str(packet.get("test_surface") or packet.get("label")) for packet in packets[:25]],
                "open_questions": ["Which clean facts and fixtures should be promoted from this private packet group?"],
                "review_status": "todo",
            }
        )

    plan = {
        "format": "wincr-reimplementation-plan-v1",
        "artifact_role": "private_reimplementation_workbench_plan",
        "corpus_dir": str(corpus_dir),
        "summary": {
            "modules": len(index["modules"]),
            "routines": len(index["routines"]),
            "blocks": len(index["blocks"]),
            "review_packets": len(index["review_packets"]),
            "tasks": len(tasks),
        },
        "tasks": tasks,
    }
    write_json(corpus_dir / "reimplementation-plan.json", plan)
    (corpus_dir / "reimplementation-plan.md").write_text(_plan_markdown(plan), encoding="utf-8")
    return plan


def write_cli_index(corpus_dir: Path, *, plan: dict[str, Any] | None = None) -> dict[str, Any]:
    corpus_dir = corpus_dir.resolve()
    plan = plan or _load_json(corpus_dir / "reimplementation-plan.json", {})
    index = _collect_corpus_index(corpus_dir)
    labels: dict[str, dict[str, Any]] = {}
    for kind in ("modules", "routines", "blocks"):
        for item in index[kind]:
            label = str(item.get("label") or "")
            if not label:
                continue
            labels[label] = {
                "kind": kind[:-1] if kind.endswith("s") else kind,
                "title": str(item.get("name") or item.get("filename") or label),
                "path": str(item.get("rel_manifest") or item.get("rel_index") or ""),
                "summary": _search_text(item)[:1000],
            }
    for packet in index["review_packets"]:
        label = str(packet.get("label") or "")
        if label:
            labels[label] = {
                "kind": "review_packet",
                "title": str(packet.get("title") or label),
                "path": str(packet.get("rel_dirty") or ""),
                "summary": _search_text(packet)[:1000],
            }
    for task in plan.get("tasks", []):
        label = str(task.get("task_id") or "")
        if label:
            labels[label] = {
                "kind": "reimplementation_task",
                "title": str(task.get("title") or label),
                "path": "reimplementation-plan.json",
                "summary": _search_text(task)[:1000],
            }
    cli_index = {
        "format": "wincr-dirty-corpus-cli-index-v1",
        "corpus_dir": str(corpus_dir),
        "summary": {
            "labels": len(labels),
            "modules": len(index["modules"]),
            "routines": len(index["routines"]),
            "blocks": len(index["blocks"]),
            "review_packets": len(index["review_packets"]),
            "tasks": len(plan.get("tasks", [])),
        },
        "labels": dict(sorted(labels.items())),
        "todos": [
            {
                "task_id": task.get("task_id"),
                "title": task.get("title"),
                "task_kind": task.get("task_kind"),
                "review_status": task.get("review_status"),
            }
            for task in plan.get("tasks", [])
            if task.get("review_status") != "done"
        ],
    }
    write_json(corpus_dir / "cli-index.json", cli_index)
    return cli_index


def render_dirty_corpus(
    corpus_dir: Path,
    out_dir: Path,
    *,
    plan: dict[str, Any] | None = None,
    cli_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    corpus_dir = corpus_dir.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    plan = plan or _load_json(corpus_dir / "reimplementation-plan.json", {})
    cli_index = cli_index or _load_json(corpus_dir / "cli-index.json", {})
    if not plan:
        plan = write_reimplementation_plan(corpus_dir)
    if not cli_index:
        cli_index = write_cli_index(corpus_dir, plan=plan)
    index = _collect_corpus_index(corpus_dir)
    files: list[Path] = []

    assets_css = out_dir / "style.css"
    assets_css.write_text(_css(), encoding="utf-8")
    files.append(assets_css)
    search_json = out_dir / "search-index.json"
    write_json(search_json, cli_index)
    files.append(search_json)

    routines_dir = out_dir / "routines"
    blocks_dir = out_dir / "blocks"
    routines_dir.mkdir(exist_ok=True)
    blocks_dir.mkdir(exist_ok=True)
    for routine in index["routines"]:
        page = routines_dir / f"{routine['label']}.html"
        page.write_text(_routine_html(corpus_dir, out_dir, page, routine, index), encoding="utf-8")
        files.append(page)
    for block in index["blocks"]:
        page = blocks_dir / f"{block['label']}.html"
        page.write_text(_block_html(corpus_dir, out_dir, page, block), encoding="utf-8")
        files.append(page)

    index_html = out_dir / "index.html"
    index_html.write_text(_index_html(corpus_dir, out_dir, index, plan, cli_index), encoding="utf-8")
    files.append(index_html)
    return {
        "format": "wincr-dirty-corpus-html-v1",
        "out_dir": str(out_dir),
        "index_html": str(index_html),
        "files": [str(path) for path in files],
        "summary": {
            "routines": len(index["routines"]),
            "blocks": len(index["blocks"]),
            "review_packets": len(index["review_packets"]),
            "tasks": len(plan.get("tasks", [])),
        },
    }


def refresh_content_manifest(corpus_dir: Path) -> dict[str, Any] | None:
    corpus_dir = corpus_dir.resolve()
    manifest_path = corpus_dir / "content-manifest.json"
    if not manifest_path.exists():
        return None
    manifest = _load_json(manifest_path, {})
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    refreshed = 0
    missing = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        rel_path = str(artifact.get("path") or "")
        if not rel_path:
            continue
        path = corpus_dir / rel_path
        if not path.exists() or not path.is_file():
            missing += 1
            continue
        artifact["size"] = path.stat().st_size
        artifact["sha256"] = sha256_file(path)
        refreshed += 1
    manifest["artifact_count"] = len(artifacts)
    write_json(manifest_path, manifest)
    return {
        "content_manifest": str(manifest_path),
        "artifacts": len(artifacts),
        "refreshed": refreshed,
        "missing": missing,
    }


def review_dirty_corpus(
    corpus_dir: Path,
    *,
    search: str | None = None,
    label: str | None = None,
    todos: bool = False,
    summary: bool = False,
    interactive: bool = False,
) -> dict[str, Any]:
    corpus_dir = corpus_dir.resolve()
    cli_index = _load_json(corpus_dir / "cli-index.json", {})
    if not cli_index:
        plan = write_reimplementation_plan(corpus_dir)
        cli_index = write_cli_index(corpus_dir, plan=plan)
    result: dict[str, Any] = {
        "format": "wincr-dirty-corpus-review-v1",
        "corpus_dir": str(corpus_dir),
        "summary": cli_index.get("summary", {}),
    }
    labels = cli_index.get("labels", {}) if isinstance(cli_index.get("labels"), dict) else {}
    if label:
        result["label"] = labels.get(label)
    if search:
        needle = search.casefold()
        matches = []
        for item_label, item in labels.items():
            haystack = f"{item_label} {item.get('title', '')} {item.get('summary', '')}".casefold()
            if needle in haystack:
                matches.append({"label": item_label, **item})
        result["search"] = {"query": search, "matches": matches[:100], "total": len(matches)}
    if todos:
        result["todos"] = cli_index.get("todos", [])
    if summary:
        result["summary_only"] = True
    if interactive:
        result["interactive"] = _interactive_review(labels, cli_index)
    return result


def _collect_corpus_index(corpus_dir: Path) -> dict[str, Any]:
    modules: list[dict[str, Any]] = []
    routines: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    review_packets: list[dict[str, Any]] = []
    modules_dir = corpus_dir / "modules"
    for manifest_path in sorted(modules_dir.glob("*/manifest.json")) if modules_dir.exists() else []:
        module = _load_json(manifest_path, {})
        if not isinstance(module, dict):
            continue
        module["dir"] = manifest_path.parent
        module["rel_manifest"] = manifest_path.relative_to(corpus_dir).as_posix()
        module["rel_index"] = (manifest_path.parent / "index.md").relative_to(corpus_dir).as_posix()
        modules.append(module)
        for routine_path in sorted((manifest_path.parent / "routines").glob("*/manifest.json")):
            routine = _load_json(routine_path, {})
            if not isinstance(routine, dict):
                continue
            routine["dir"] = routine_path.parent
            routine["rel_manifest"] = routine_path.relative_to(corpus_dir).as_posix()
            routine["rel_index"] = (routine_path.parent / "index.md").relative_to(corpus_dir).as_posix()
            routines.append(routine)
        for block_path in sorted((manifest_path.parent / "blocks").glob("*/manifest.json")):
            block = _load_json(block_path, {})
            if not isinstance(block, dict):
                continue
            block["dir"] = block_path.parent
            block["rel_manifest"] = block_path.relative_to(corpus_dir).as_posix()
            block["rel_index"] = (block_path.parent / "index.md").relative_to(corpus_dir).as_posix()
            blocks.append(block)
    review_dir = corpus_dir / "review"
    for dirty_path in sorted(review_dir.glob("*/*/dirty.json")) if review_dir.exists() else []:
        packet = _load_json(dirty_path, {})
        if not isinstance(packet, dict):
            continue
        packet["dir"] = dirty_path.parent
        packet["rel_dirty"] = dirty_path.relative_to(corpus_dir).as_posix()
        packet["rel_index"] = (dirty_path.parent / "index.md").relative_to(corpus_dir).as_posix()
        review_packets.append(packet)
    return {"modules": modules, "routines": routines, "blocks": blocks, "review_packets": review_packets}


def _plan_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Reimplementation Plan",
        "",
        "Private task index for rewriting clean behavior from the dirty corpus.",
        "",
        f"- Tasks: {len(plan.get('tasks', []))}",
        f"- Routines: {plan.get('summary', {}).get('routines', 0)}",
        f"- Blocks: {plan.get('summary', {}).get('blocks', 0)}",
        "",
    ]
    for task in plan.get("tasks", []):
        lines.extend(
            [
                f"## {task.get('title', task.get('task_id'))}",
                "",
                f"- Task id: `{task.get('task_id')}`",
                f"- Kind: `{task.get('task_kind')}`",
                f"- Status: `{task.get('review_status')}`",
                f"- Acceptance tests: {len(task.get('acceptance_tests') or [])}",
                "",
            ]
        )
    return "\n".join(lines)


def _index_html(
    corpus_dir: Path,
    out_dir: Path,
    index: dict[str, Any],
    plan: dict[str, Any],
    cli_index: dict[str, Any],
) -> str:
    routines = index["routines"]
    blocks = index["blocks"]
    tasks = plan.get("tasks", [])
    labels_json = json.dumps(cli_index.get("labels", {}), sort_keys=True)
    routine_rows = "\n".join(
        f"<tr><td><a href='routines/{_h(r['label'])}.html'>{_h(r['label'])}</a></td>"
        f"<td>{_h(r.get('name'))}</td><td>{_h(r.get('subsystem'))}</td>"
        f"<td>{len([b for b in blocks if b.get('function_label') == r.get('label')])}</td></tr>"
        for r in routines
    )
    block_rows = "\n".join(
        f"<tr><td><a href='blocks/{_h(b['label'])}.html'>{_h(b['label'])}</a></td>"
        f"<td>{_h(b.get('function_label'))}</td><td>{_h((b.get('coverage_summary') or {}).get('covered'))}</td>"
        f"<td>{_h((b.get('decompiler') or {}).get('status'))}</td></tr>"
        for b in blocks[:500]
    )
    task_rows = "\n".join(
        f"<li><strong>{_h(task.get('title'))}</strong> <code>{_h(task.get('task_id'))}</code> "
        f"{_h(task.get('task_kind'))}</li>"
        for task in tasks[:200]
    )
    return _html_page(
        "Dirty Corpus Workbench",
        f"""
        <section class="hero">
          <h1>Dirty Corpus Workbench</h1>
          <p>{_h(str(corpus_dir))}</p>
          <div class="stats">
            <span>Routines <strong>{len(routines)}</strong></span>
            <span>Blocks <strong>{len(blocks)}</strong></span>
            <span>Tasks <strong>{len(tasks)}</strong></span>
            <span>Review packets <strong>{len(index['review_packets'])}</strong></span>
          </div>
        </section>
        <section>
          <h2>Search</h2>
          <input id="search" type="search" placeholder="label, routine, block, task">
          <div id="results"></div>
        </section>
        <section>
          <h2>Reimplementation Tasks</h2>
          <ul>{task_rows}</ul>
          <p><a href="{_rel(out_dir / 'index.html', corpus_dir / 'reimplementation-plan.json')}">reimplementation-plan.json</a></p>
        </section>
        <section>
          <h2>Routines</h2>
          <table><thead><tr><th>Label</th><th>Name</th><th>Subsystem</th><th>Blocks</th></tr></thead><tbody>{routine_rows}</tbody></table>
        </section>
        <section>
          <h2>Block Coverage</h2>
          <table><thead><tr><th>Label</th><th>Routine</th><th>Covered</th><th>Decompiler</th></tr></thead><tbody>{block_rows}</tbody></table>
        </section>
        <script>
        const labels = {labels_json};
        const input = document.getElementById('search');
        const results = document.getElementById('results');
        input.addEventListener('input', () => {{
          const q = input.value.toLowerCase();
          results.innerHTML = '';
          if (!q) return;
          Object.entries(labels).filter(([label, item]) =>
            (label + ' ' + item.title + ' ' + item.summary).toLowerCase().includes(q)
          ).slice(0, 50).forEach(([label, item]) => {{
            const div = document.createElement('div');
            div.className = 'result';
            div.innerHTML = `<strong>${{label}}</strong> <span>${{item.kind}}</span><p>${{item.title}}</p>`;
            results.appendChild(div);
          }});
        }});
        </script>
        """,
    )


def _routine_html(corpus_dir: Path, out_dir: Path, page: Path, routine: dict[str, Any], index: dict[str, Any]) -> str:
    blocks = [block for block in index["blocks"] if block.get("function_label") == routine.get("label")]
    links = _artifact_links(page, corpus_dir, routine["dir"], ["manifest.json", "static/cfg.json", "static/semantics.json", "static/decompiler-status.json", "static/decompiled.c", "dynamic/coverage.json", "draft/dirty-contract.md"])
    block_links = "\n".join(
        f"<li><a href='../blocks/{_h(block['label'])}.html'>{_h(block['label'])}</a> covered={_h((block.get('coverage_summary') or {}).get('covered'))}</li>"
        for block in blocks
    )
    return _html_page_with_css(
        f"Routine {routine.get('label')}",
        f"""
        <p><a href="../index.html">Workbench</a></p>
        <h1>Routine {_h(routine.get('label'))}</h1>
        <dl>
          <dt>Name</dt><dd>{_h(routine.get('name'))}</dd>
          <dt>Module</dt><dd>{_h(routine.get('module_label'))}</dd>
          <dt>Subsystem</dt><dd>{_h(routine.get('subsystem'))}</dd>
          <dt>Signature</dt><dd>{_h(routine.get('signature'))}</dd>
        </dl>
        <h2>Evidence</h2>
        <ul>{links}</ul>
        <h2>Blocks</h2>
        <ul>{block_links}</ul>
        """,
        "../style.css",
    )


def _block_html(corpus_dir: Path, out_dir: Path, page: Path, block: dict[str, Any]) -> str:
    links = _artifact_links(page, corpus_dir, block["dir"], ["manifest.json", "static/context.json", "static/instructions.json", "static/pcode.json", "static/data-flow.json", "static/xrefs.json", "static/decompiler-status.json", "semantic-summary.md", "draft/clean-template.json"])
    return _html_page_with_css(
        f"Block {block.get('label')}",
        f"""
        <p><a href="../index.html">Workbench</a></p>
        <h1>Block {_h(block.get('label'))}</h1>
        <dl>
          <dt>Routine</dt><dd>{_h(block.get('function_label'))}</dd>
          <dt>Module</dt><dd>{_h(block.get('module_label'))}</dd>
          <dt>Covered</dt><dd>{_h((block.get('coverage_summary') or {}).get('covered'))}</dd>
          <dt>Decompiler</dt><dd>{_h((block.get('decompiler') or {}).get('status'))}</dd>
        </dl>
        <h2>Evidence</h2>
        <ul>{links}</ul>
        """,
        "../style.css",
    )


def _html_page(title: str, body: str) -> str:
    return _html_page_with_css(title, body, "style.css")


def _html_page_with_css(title: str, body: str, css_href: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_h(title)}</title>
  <link rel="stylesheet" href="{_h(css_href)}">
</head>
<body>{body}</body>
</html>
"""


def _css() -> str:
    return """
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f7f7f4;color:#20221f}
body{line-height:1.45} section,.hero,body>h1,body>p,body>dl,body>ul{max-width:1160px;margin:0 auto;padding:20px}
.hero{background:#24332f;color:#fff;max-width:none}.hero p{padding:0;margin:6px 0 0;color:#dce7e1}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px}.stats span{background:#fff1;padding:10px 12px;border:1px solid #fff3}
h1,h2{letter-spacing:0} table{width:100%;border-collapse:collapse;background:#fff}td,th{padding:8px 10px;border-bottom:1px solid #ddd;text-align:left}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #999;background:#fff;font:inherit}
.result{padding:10px;border-bottom:1px solid #ddd;background:#fff}.result span{color:#60716a;margin-left:8px}
code{background:#e8ece8;padding:1px 4px} a{color:#135f4c}
dl{display:grid;grid-template-columns:minmax(120px,220px) 1fr;gap:8px 14px}dt{font-weight:700}
"""


def _artifact_links(page: Path, corpus_dir: Path, packet_dir: Path, rels: list[str]) -> str:
    return "\n".join(
        f"<li><a href='{_h(_rel(page, packet_dir / rel))}'>{_h(rel)}</a></li>"
        for rel in rels
        if (packet_dir / rel).exists()
    )


def _existing_links(corpus_dir: Path, packet_dir: Path, rels: list[str]) -> list[str]:
    return [(packet_dir / rel).relative_to(corpus_dir).as_posix() for rel in rels if (packet_dir / rel).exists()]


def _first_existing_link(corpus_dir: Path, packet_dir: Path, rels: list[str]) -> str | None:
    links = _existing_links(corpus_dir, packet_dir, rels)
    return links[0] if links else None


def _rel(from_page: Path, target: Path) -> str:
    return os.path.relpath(target, start=from_page.parent)


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _search_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _h(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _interactive_review(labels: dict[str, Any], cli_index: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    print("wincr dirty corpus review. Commands: search <text>, label <label>, todos, quit", file=sys.stderr)
    while True:
        try:
            line = input("wincr-review> ").strip()
        except EOFError:
            break
        if line in {"quit", "exit"}:
            break
        if line == "todos":
            item = {"todos": cli_index.get("todos", [])}
            print(json.dumps(item, indent=2, sort_keys=True))
            events.append(item)
            continue
        if line.startswith("label "):
            key = line.split(" ", 1)[1]
            item = {"label": key, "item": labels.get(key)}
            print(json.dumps(item, indent=2, sort_keys=True))
            events.append(item)
            continue
        if line.startswith("search "):
            query = line.split(" ", 1)[1].casefold()
            matches = [
                {"label": label, **item}
                for label, item in labels.items()
                if query in f"{label} {item.get('title', '')} {item.get('summary', '')}".casefold()
            ][:25]
            item = {"query": query, "matches": matches}
            print(json.dumps(item, indent=2, sort_keys=True))
            events.append(item)
            continue
        print("unknown command", file=sys.stderr)
    return events
