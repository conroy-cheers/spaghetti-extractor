"""Veto-only performance checks for canonical linking and optional precision."""

from __future__ import annotations

import argparse
import filecmp
import json
import multiprocessing
from multiprocessing.connection import Connection
import resource
import tempfile
import time
from pathlib import Path

from ..util import write_json
from .formats import SEMANTIC_LINK_PERFORMANCE_FORMAT
from .module_v2 import write_linked_semantic_module_from_inputs_v2
from .worklist import compile_semantic_link_worklist_facts


def _semantic_link_sample(arguments: argparse.Namespace) -> dict[str, int]:
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary)
        link_cpu_before = time.process_time_ns()
        link_wall_before = time.perf_counter_ns()
        write_linked_semantic_module_from_inputs_v2(
            semantic_object=arguments.semantic_object,
            out=output,
        )
        link_cpu_milliseconds = (
            time.process_time_ns() - link_cpu_before
        ) // 1_000_000
        link_wall_milliseconds = (
            time.perf_counter_ns() - link_wall_before
        ) // 1_000_000
        if not filecmp.cmp(
            output / "linked-semantic-module.json",
            arguments.canonical,
            shallow=False,
        ):
            raise RuntimeError(
                "performance run contradicted the canonical semantic module"
            )

        precision_cpu_before = time.process_time_ns()
        precision_wall_before = time.perf_counter_ns()
        precision_output = output / "optional-precision"
        compile_semantic_link_worklist_facts(
            semantic_object=arguments.semantic_object,
            behavioral_roots=arguments.behavioral_roots,
            original_pe=arguments.original,
            out=precision_output,
            maximum_worklist_steps=arguments.maximum_worklist_steps,
            retain_transfer_plan=False,
        )
        precision_cpu_milliseconds = (
            time.process_time_ns() - precision_cpu_before
        ) // 1_000_000
        precision_wall_milliseconds = (
            time.perf_counter_ns() - precision_wall_before
        ) // 1_000_000
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "link_cpu_milliseconds": link_cpu_milliseconds,
        "link_wall_milliseconds": link_wall_milliseconds,
        "optional_precision_cpu_milliseconds": precision_cpu_milliseconds,
        "optional_precision_wall_milliseconds": precision_wall_milliseconds,
        "peak_rss_kib": int(usage.ru_maxrss),
    }


def _sample_worker(
    arguments: argparse.Namespace,
    sender: Connection,
) -> None:
    try:
        sender.send(("ok", _semantic_link_sample(arguments)))
    except BaseException as exc:
        sender.send(("error", f"{type(exc).__name__}: {exc}"))
        raise
    finally:
        sender.close()


def _isolated_semantic_link_samples(
    arguments: argparse.Namespace, *, count: int,
) -> list[dict[str, int]]:
    # A semantic link is a one-shot pure Nix phase.  Isolate samples so this
    # veto measures the maximum per-phase resident set, not allocator pages
    # retained by an artificial in-process repetition that production forbids.
    # Samples have no dependency on one another, so run them concurrently:
    # the speed-first policy deliberately trades a larger transient resident
    # set for the wall time of one sample instead of three.
    context = multiprocessing.get_context("fork")
    workers: list[tuple[Connection, multiprocessing.Process]] = []
    for _sample in range(count):
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_sample_worker, args=(arguments, sender)
        )
        process.start()
        sender.close()
        workers.append((receiver, process))

    results: list[dict[str, int]] = []
    failures: list[str] = []
    for receiver, process in workers:
        try:
            status, payload = receiver.recv()
        except EOFError:
            status, payload = (
                "error", f"worker exited {process.exitcode} without a result"
            )
        finally:
            receiver.close()
        process.join()
        if (
            status != "ok"
            or process.exitcode != 0
            or not isinstance(payload, dict)
        ):
            failures.append(str(payload))
        else:
            results.append(payload)
    if failures:
        raise RuntimeError(
            "semantic-link performance workers failed: " + "; ".join(failures)
        )
    return results


def check_semantic_link_performance(arguments: argparse.Namespace) -> None:
    samples = _isolated_semantic_link_samples(arguments, count=3)

    worst_cpu = max(
        row["optional_precision_cpu_milliseconds"] for row in samples
    )
    worst_wall = max(
        row["optional_precision_wall_milliseconds"] for row in samples
    )
    worst_link_cpu = max(
        row["link_cpu_milliseconds"] for row in samples
    )
    worst_link_wall = max(
        row["link_wall_milliseconds"] for row in samples
    )
    peak_rss = max(row["peak_rss_kib"] for row in samples)
    observations = {
        "format": SEMANTIC_LINK_PERFORMANCE_FORMAT,
        "samples": samples,
        "worst_optional_precision_cpu_milliseconds": worst_cpu,
        "worst_optional_precision_wall_milliseconds": worst_wall,
        "worst_link_cpu_milliseconds": worst_link_cpu,
        "worst_link_wall_milliseconds": worst_link_wall,
        "peak_rss_kib": peak_rss,
        "budgets": {
            "maximum_cpu_milliseconds": arguments.maximum_cpu_milliseconds,
            "maximum_prepared_link_milliseconds": (
                arguments.maximum_prepared_link_milliseconds
            ),
        },
    }
    if arguments.observations is not None:
        write_json(arguments.observations, observations)
    print(json.dumps(observations, sort_keys=True, separators=(",", ":")))
    if worst_cpu >= arguments.maximum_cpu_milliseconds:
        raise SystemExit(
            "semantic-link CPU budget exceeded: "
            f"worst of three samples was {worst_cpu} ms >= "
            f"{arguments.maximum_cpu_milliseconds} ms; "
            f"worst wall={worst_wall} ms"
        )
    if max(worst_link_cpu, worst_link_wall) >= (
        arguments.maximum_prepared_link_milliseconds
    ):
        raise SystemExit(
            "canonical semantic-link budget exceeded: "
            f"worst CPU={worst_link_cpu} ms, "
            f"worst wall={worst_link_wall} ms >= "
            f"{arguments.maximum_prepared_link_milliseconds} ms"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--semantic-object", type=Path, required=True)
    parser.add_argument("--behavioral-roots", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--canonical", type=Path, required=True)
    parser.add_argument("--maximum-worklist-steps", type=int, required=True)
    parser.add_argument("--maximum-cpu-milliseconds", type=int, required=True)
    parser.add_argument(
        "--maximum-prepared-link-milliseconds", type=int, required=True
    )
    parser.add_argument("--observations", type=Path)
    check_semantic_link_performance(parser.parse_args())


if __name__ == "__main__":
    main()
