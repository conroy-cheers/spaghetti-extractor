"""Check unread-header reuse and retain the uninstrumented ownership control.

Run inside spaghetti-headless-wayland with PACKAGES and a new OUTPUT directory.
The deliberately broken source is repaired before successful completion.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if json.loads((args.packages/'path-get/comparison-plan.json').read_text()).get('resource_checks'):
        raise ValueError('this raw negative control requires packages prepared without --resource-checks; the standard walkthrough checks the instrumented leak')
    assert os.environ.get("WAYLAND_DISPLAY"), "use spaghetti-headless-wayland"
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    draft = root / "draft"
    commands, results = [], {}

    def command(name, argv, expected):
        argv = [sys.executable, "-m", "spaghetti_extractor", *map(str, argv)]
        start = time.monotonic()
        with (root / (name + ".stdout")).open("w") as stdout:
            with (root / (name + ".stderr")).open("w") as stderr:
                result = subprocess.run(argv, stdout=stdout, stderr=stderr)
        commands.append(
            dict(
                name=name,
                argv=argv,
                returncode=result.returncode,
                seconds=time.monotonic() - start,
            )
        )
        (root / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        assert result.returncode == expected, (name, result.returncode)

    def check(name, reuse=None, expected=0):
        argv = [
            "component",
            "check",
            "jq",
            "path-get",
            "--comparison-package",
            draft,
            "--case",
            "nested",
            "--output",
            root / name,
        ]
        if reuse:
            argv += ["--reuse-comparison", root / reuse]
        command(name, argv, expected)
        value = json.loads((root / name / "comparison-result.json").read_text())
        results[name] = value
        assert value["status"] == ("match" if expected == 0 else "mismatch")
        return value

    command(
        "start",
        [
            "component",
            "start",
            "jq",
            "path-get",
            "--comparison-package",
            args.packages.resolve() / "path-get",
            "--output",
            draft,
        ],
        0,
    )
    baseline = check("baseline")
    unused = draft / "headers/interpreter.h"
    old_header = unused.read_text()
    assert not any(
        name.endswith("/interpreter.h") for name in baseline["compiler_dependencies"]
    )
    unused.write_text(old_header + "\n/* unrelated, unread header edit */\n")
    changed = check("unread-header-edit", reuse="baseline")
    assert changed["reuse"]["status"] == "reused"
    assert not any(changed["work_counts"].values())
    unused.write_text(old_header)
    source = draft / "source/getpath.c"
    good = source.read_text()
    source.write_text(
        good.replace(
            "  void *e = s->context;", "  void *e = s->context;\n  s->copy(e, root);"
        )
    )
    check("leak-missed", reuse="baseline")
    # Add a lifetime-related observation without changing either algorithm.
    driver = draft / "adapters/driver.c"
    body = driver.read_text()
    before = (
        '  printf("{\\"outcome\\":\\"%s\\",",jv_is_valid(result)?"value":"invalid");'
    )
    after = '  printf("{\\"root_refcount\\":%d,\\"outcome\\":\\"%s\\",",jv_get_refcnt(kept_root),jv_is_valid(result)?"value":"invalid");'
    assert before in body
    driver.write_text(body.replace(before, after))
    plan = draft / "comparison-plan.json"
    payload = json.loads(plan.read_text())
    payload["observation_fields"].append("root_refcount")
    plan.write_text(json.dumps(payload))
    caught = check("leak-detected", reuse="leak-missed", expected=2)
    assert caught["cases"][0]["status"] == "mismatch"
    source.write_text(good)
    check("repaired-with-refcount")
    (root / "audit.json").write_text(
        json.dumps(
            {
                "commands": commands,
                "comparisons": {
                    name: {
                        key: value[key]
                        for key in [
                            "status",
                            "work_counts",
                            "reuse",
                            "timings",
                            "cases",
                            "receipt_sha256",
                        ]
                    }
                    for name, value in results.items()
                },
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
