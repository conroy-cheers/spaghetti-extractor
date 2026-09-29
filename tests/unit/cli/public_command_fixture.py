from __future__ import annotations
import argparse


def _operator_status(
    subject: str,
    *,
    state: str = "complete",
    authority: str = "not-applicable",
    blockers: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    groups = [] if blockers is None else blockers
    count = sum(int(row["count"]) for row in groups)
    return {
        "format": "spaghetti-extractor-operator-work-status-v2",
        "target_id": "gnu-hello",
        "scope": "test",
        "status": state,
        "counts": {
            "subjects": 1,
            "complete": int(state == "complete"),
            "incomplete": int(state == "incomplete"),
            "violated": int(state == "violated"),
            "authority_held": int(authority == "held"),
            "blockers": count,
        },
        "subjects": [{
            "subject": subject,
            "kind": subject.split(":", 1)[0],
            "state": state,
            "authority": authority,
            "stage": None,
            "sources": [],
            "blockers": {"count": count, "groups": groups},
            "next_action": None,
        }],
    }


def _subcommands(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    return next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )


def _command_parser(
    parser: argparse.ArgumentParser, command: str
) -> argparse.ArgumentParser:
    namespace, name = command.split(" ", 1)
    return _subcommands(_subcommands(parser).choices[namespace]).choices[name]
