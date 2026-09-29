"""Exercise public CLI on prepared packages. Run inside ONE headless Wayland.

Usage: PYTHONPATH=src python .../walkthrough.py PACKAGES NEW_OUTPUT
The child CLI inherits current source/dependencies; all commands are retained.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("packages", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    packages = a.packages.resolve()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    if not os.environ.get("WAYLAND_DISPLAY"):
        raise RuntimeError("run inside spaghetti-headless-wayland")
    commands = []
    results = {}
    cli = [sys.executable, "-m", "spaghetti_extractor"]
    identities = {
        "value-get": "value-get",
        "value-set": "value-set",
        "path-get": "path-get",
        "path-set": "path-set",
        "path-get-network": "path-get",
        "path-set-network": "path-set",
    }

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def command(name, args, expected=0):
        argv = cli + list(map(str, args))
        start = time.monotonic()
        with (
            (out / (name + ".stdout")).open("w") as stdout,
            (out / (name + ".stderr")).open("w") as stderr,
        ):
            r = subprocess.run(argv, stdout=stdout, stderr=stderr)
        commands.append(
            dict(
                name=name,
                argv=argv,
                returncode=r.returncode,
                seconds=time.monotonic() - start,
            )
        )
        save("commands.json", commands)
        print(name, r.returncode, round(commands[-1]["seconds"], 3), flush=True)
        if expected is not None:
            assert r.returncode == expected, (
                name,
                (out / (name + ".stdout")).read_text(),
                (out / (name + ".stderr")).read_text(),
            )
        return r.returncode

    def check(
        kind, name, reuse=None, package=None, case=None, expected=0, formal=False,
        comparison_status=None
    ):
        args = [
            "component",
            "check",
            "jq",
            identities[kind],
            "--comparison-package",
            package or out / (kind + "-draft"),
            "--output",
            out / name,
        ]
        if package is None and kind.endswith("network"):
            selected = (
                ["value-get"]
                if kind == "path-get-network"
                else ["value-get", "value-set"]
            )
            for dep in selected:
                args += [
                    "--dependency-package",
                    dep + "=" + str(out / (dep + "-draft")),
                ]
        if reuse:
            args += ["--reuse-comparison", out / reuse]
        if case:
            args += ["--case", case]
        if formal:
            args += ["--local-contracts"]
        command(name, args, expected)
        r = json.loads((out / name / "comparison-result.json").read_text())
        results[name] = r
        assert r["authorizing"] is False and r["status"] == (comparison_status or (
            "match" if expected == 0 else "mismatch"
        )), (name, r["status"])
        return r

    for kind, unit in identities.items():
        command(
            "start-" + kind,
            [
                "component",
                "start",
                "jq",
                unit,
                "--comparison-package",
                packages / kind,
                "--output",
                out / (kind + "-draft"),
            ],
        )
        check(kind, kind + "-baseline", formal=kind == "path-set-network")
    # This header is inside the declared include tree but is not read by any TU.
    unread=out/'value-get-draft/headers/unread-workflow.h'
    unread.write_text('/* unread edit must not trigger compiler or execution */\n')
    unchanged=check('value-get','unread-header',reuse='value-get-baseline')
    assert unchanged['reuse']['ignored_unread_headers']==['headers/unread-workflow.h']
    assert not any(unchanged['work_counts'].values())
    unread.unlink()
    source = out / "value-get-draft/source/get.c"
    good = source.read_text()
    edited = good.replace("if (index < 0)", "if (index <= -1)")
    assert edited != good
    source.write_text(edited)
    for kind in identities:
        r = check(kind, kind + "-edited", reuse=kind + "-baseline")
        if kind in ["value-set", "path-get", "path-set"]:
            assert r["reuse"]["status"] == "reused" and not any(
                r["work_counts"].values()
            )
        else:
            assert (
                r["reuse"]["status"] == "invalidated"
                and r["work_counts"]["execution"] > 0
            )
            assert r['work_counts']['compiler']==1,r['work_counts']
    bad = edited.replace(
        "index += (int32_t)s->length(e, s->copy(e, value));",
        "index += (int32_t)s->length(e, s->copy(e, value)) - 1;",
    )
    assert bad != edited
    source.write_text(bad)
    check("value-get", "value-get-wrong", reuse="value-get-edited", expected=2)
    wrong = check(
        "path-set-network", "network-wrong", reuse="path-set-network-edited", expected=2
    )
    first = next(c["id"] for c in wrong["cases"] if c["status"] == "mismatch")
    source.write_text(edited)
    check(
        "path-set-network",
        "retained-replay",
        package=out / "network-wrong/inputs",
        case=first,
        expected=2,
    )
    for kind in ["value-get", "path-set-network"]:
        r = check(kind, kind + "-repaired", reuse=kind + "-edited")
        assert r["reuse"]["status"] == "reused" and not any(r["work_counts"].values())
    # Resource diagnostics remain separate from matching sampled JSON/aliases.
    path_source = out / "path-get-draft/source/getpath.c"
    path_good = path_source.read_text()
    path_source.write_text(
        path_good.replace(
            "  void *e = s->context;",
            "  void *e = s->context;\n  s->copy(e, root); /* negative control: leaked reference */",
        )
    )
    instrumented=bool(json.loads((out/'path-get-draft/comparison-plan.json').read_text()).get('resource_checks'))
    leak=check("path-get", "reference-leak", reuse="path-get-edited",
        expected=2 if instrumented else 0,comparison_status='match')
    if instrumented:
        from spaghetti_extractor.components.comparison_resources import resource_applicability
        assert resource_applicability(leak)!='satisfied'
        check('path-get','reference-leak-replay',package=out/'reference-leak/inputs',
            case=leak['cases'][0]['id'],expected=2,comparison_status='match')
    path_source.write_text(path_good)
    r = check("path-get", "path-get-repaired", reuse="path-get-edited")
    assert r["reuse"]["status"] == "reused" and not any(r["work_counts"].values())
    # Same C signature, changed declared semantic assumptions: must be rejected.
    plan = out / "value-get-draft/comparison-plan.json"
    old = plan.read_text()
    changed = json.loads(old)
    changed["assumptions"].append("changed contract for assessment negative control")
    if 'composition' in changed:
        from spaghetti_extractor.components.comparison_composition import composition_graph
        changed['composition']=composition_graph(plan.parent,changed)
    plan.write_text(json.dumps(changed))
    code = command(
        "changed-contract",
        [
            "component",
            "check",
            "jq",
            "path-set",
            "--comparison-package",
            out / "path-set-network-draft",
            "--dependency-package",
            "value-get=" + str(out / "value-get-draft"),
            "--output",
            out / "changed-contract",
        ],
        expected=None,
    )
    assert code != 0
    assert (
        "dependency contract changed"
        in (out / "changed-contract.stderr").read_text()
        + (out / "changed-contract.stdout").read_text()
    )
    plan.write_text(old)
    command(
        "experimental-build",
        [
            "candidate",
            "build",
            "jq",
            "--experimental-comparison",
            out / "path-set-network-repaired",
            "--component-comparison",
            "value-get=" + str(out / "value-get-repaired"),
            "--component-comparison",
            "value-set=" + str(out / "value-set-edited"),
            "--component-comparison",
            "path-get=" + str(out / "path-get-network-edited"),
            "--experimental-policy",
            packages / "experimental-policy.json",
            "--output",
            out / "experimental",
        ],
    )
    command(
        "experimental-run",
        [
            "candidate",
            "test",
            "jq",
            "--experimental-package",
            out / "experimental",
            "--output",
            out / "experimental-run",
        ],
    )
    save(
        "audit.json",
        {
            "scope": "four jq operations, public current-source CLI, practical comparisons only",
            "commands": commands,
            "comparisons": {
                n: {
                    k: r[k]
                    for k in [
                        "status",
                        "receipt_sha256",
                        "work_counts",
                        "timings",
                        "reuse",
                        "formal_check",
                    ]
                }
                for n, r in results.items()
            },
            "negative_replay_case": first,
            "resource_instrumentation": instrumented,
            "wayland_display": os.environ["WAYLAND_DISPLAY"],
        },
    )
    print("Audit:", out / "audit.json", flush=True)


if __name__ == "__main__":
    main()
