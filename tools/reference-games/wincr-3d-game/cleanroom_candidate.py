#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


GAME_VERSION = 1
MAX_FRAMES = 7200
SCENARIO_LIMIT = 31
USAGE = (
    "usage: wincr-3d-game.exe --json [--scenario idle|orbit|collect|dive|burnout|aim_miss] [--frames N] [--seed N]\n"
    "       wincr-3d-game-window.exe --window-smoke [--scenario idle|orbit|collect|dive|burnout|aim_miss] [--frames N] [--seed N]\n"
)
_INTEGER_PREFIX = re.compile(r"^[+-]?[0-9]+")


def main() -> int:
    args = parse_command_line(sys.argv[1:])
    if args["help"]:
        sys.stdout.write(USAGE)
        return 0

    contract = json.loads(Path(args["contract"]).read_text(encoding="utf-8"))
    if not args["json"]:
        sys.stderr.write("pass --json for deterministic transcript output\n")
        return 4

    game = ContractGame(contract, mutant=args["mutant"])
    frames = clamp(int(args["frames"]), 1, int(contract["constants"]["max_frames"]))
    transcript = game.transcript(str(args["scenario"]), int(args["seed"]) & 0xFFFFFFFF, frames)
    print(json.dumps(transcript, separators=(",", ":")))
    return 0


def parse_command_line(argv: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "contract": Path(__file__).with_name("behavior-contract.json"),
        "json": False,
        "help": False,
        "scenario": "orbit",
        "frames": 180,
        "seed": 7,
        "mutant": None,
    }
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--help":
            result["help"] = True
            index += 1
        elif arg == "--contract":
            value, index = next_option_value(argv, index)
            if value is not None:
                result["contract"] = Path(value)
        elif arg == "--mutant":
            value, index = next_option_value(argv, index)
            if value is not None:
                result["mutant"] = value
        elif arg == "--json":
            result["json"] = True
            index += 1
        elif arg == "--scenario":
            value, index = next_option_value(argv, index)
            if value is not None:
                result["scenario"] = value[:SCENARIO_LIMIT]
        elif arg == "--frames":
            value, index = next_option_value(argv, index)
            if value is not None:
                result["frames"] = parse_int_prefix(value, int(result["frames"]))
        elif arg == "--seed":
            value, index = next_option_value(argv, index)
            if value is not None:
                result["seed"] = parse_int_prefix(value, int(result["seed"])) & 0xFFFFFFFF
        else:
            index += 1
    return result


def next_option_value(argv: list[str], index: int) -> tuple[str | None, int]:
    if index + 1 >= len(argv):
        return None, index + 1
    return argv[index + 1], index + 2


def parse_int_prefix(value: str, default: int) -> int:
    match = _INTEGER_PREFIX.match(value)
    if match is None:
        return default
    return int(match.group(0), 10)


class ContractGame:
    def __init__(self, contract: dict[str, Any], *, mutant: str | None = None) -> None:
        constants = contract["constants"]
        masks = constants["input_masks"]
        self.screen_w = int(constants["screen_w"])
        self.screen_h = int(constants["screen_h"])
        self.target_count = int(constants["target_count"])
        self.sin_table = [int(item) for item in constants["sin_table"]]
        self.cube_vertices = [[int(value) for value in item] for item in constants["cube_vertices"]]
        self.input_left = int(masks["left"])
        self.input_right = int(masks["right"])
        self.input_up = int(masks["up"])
        self.input_down = int(masks["down"])
        self.input_thrust = int(masks["thrust"])
        self.input_fire = int(masks["fire"])
        self.mutant = mutant

    def transcript(self, scenario: str, seed: int, frames: int) -> dict[str, Any]:
        state = self.initial_state(seed)
        targets = self.init_targets(seed)
        aggregate = 2166136261
        samples: list[dict[str, int]] = []

        for frame in range(frames):
            input_mask = self.scenario_input(scenario, frame)
            hash_before = self.frame_hash(state, targets, input_mask)
            if frame < 16 or frame == frames - 1 or frame % 30 == 0:
                samples.append(self.sample(state, input_mask, hash_before))
            aggregate = mix_u32(aggregate, hash_before)
            self.step(state, targets, input_mask)

        aggregate = mix_u32(aggregate, self.frame_hash(state, targets, 0))
        return {
            "format": "wincr-3d-game-transcript-v1",
            "game": "wincr-3d-reference-game",
            "version": GAME_VERSION,
            "scenario": scenario,
            "seed": seed,
            "frames": frames,
            "constants": {
                "fixed_scale": 1024,
                "screen_w": self.screen_w,
                "screen_h": self.screen_h,
                "target_count": self.target_count,
            },
            "targets": [dict(target) for target in targets],
            "samples": samples,
            "final": {
                "frame": state["frame"],
                "x": state["x"],
                "y": state["y"],
                "z": state["z"],
                "vx": state["vx"],
                "vy": state["vy"],
                "vz": state["vz"],
                "yaw": state["yaw"],
                "pitch": state["pitch"],
                "energy": state["energy"],
                "health": state["health"],
                "score": state["score"],
                "cooldown": state["cooldown"],
                "collected_mask": state["collected_mask"],
            },
            "aggregate_hash": aggregate,
        }

    def initial_state(self, seed: int) -> dict[str, int]:
        return {
            "frame": 0,
            "x": 0,
            "y": 0,
            "z": 768,
            "vx": 0,
            "vy": 0,
            "vz": 0,
            "yaw": 0,
            "pitch": 0,
            "energy": 1000,
            "health": 1000,
            "score": 0,
            "cooldown": 0,
            "collected_mask": 0,
            "rng": seed,
        }

    def init_targets(self, seed: int) -> list[dict[str, int]]:
        rng = (seed ^ 0xA51C3D2F) & 0xFFFFFFFF
        targets: list[dict[str, int]] = []
        for index in range(self.target_count):
            x, rng = self.rng_range(rng, -1400, 2801)
            y, rng = self.rng_range(rng, -700, 1401)
            z, rng = self.rng_range(rng, 2600, 3601)
            targets.append(
                {
                    "x": x,
                    "y": y,
                    "z": z + index * 280,
                    "radius": 260 + index * 30,
                    "value": 100 + index * 75,
                }
            )
        return targets

    def rng_range(self, rng: int, min_value: int, span: int) -> tuple[int, int]:
        increment = 1013904223
        if self.mutant == "bad_target_generation":
            increment = 1013904224
        rng = ((rng * 1664525) + increment) & 0xFFFFFFFF
        return min_value + ((rng >> 8) % span), rng

    def scenario_input(self, scenario: str, frame: int) -> int:
        input_mask = 0
        if scenario == "idle":
            return 0
        if scenario == "collect":
            if frame < (88 if self.mutant == "bad_input_schedule" else 96):
                input_mask |= self.input_thrust
            if (frame // 24) % 2 == 0:
                input_mask |= self.input_right
            else:
                input_mask |= self.input_left
            if 20 <= frame < 70:
                input_mask |= self.input_up
            if frame in {34, 78, 118}:
                input_mask |= self.input_fire
            return input_mask
        if scenario == "dive":
            if frame < 8:
                input_mask |= self.input_left
            if 8 <= frame < 120:
                input_mask |= self.input_thrust
            return input_mask
        if scenario == "burnout":
            input_mask |= self.input_thrust
            return input_mask
        if scenario == "aim_miss":
            if frame == 0:
                input_mask |= self.input_fire
            return input_mask

        if frame < 48:
            input_mask |= self.input_left
        if 48 <= frame < 112:
            input_mask |= self.input_right
        if 12 <= frame < 120:
            input_mask |= self.input_thrust
        if frame % 40 == 16:
            input_mask |= self.input_fire
        if 70 <= frame < 118:
            input_mask |= self.input_down
        if self.mutant == "bad_input_schedule" and frame == 12:
            input_mask &= ~self.input_thrust
        return input_mask

    def project_point(self, state: dict[str, int], world_x: int, world_y: int, world_z: int) -> dict[str, int]:
        rx = world_x - state["x"]
        ry = world_y - state["y"]
        rz = world_z - state["z"] + 2048
        denom = rz
        if self.mutant != "bad_projection":
            denom = 96 if rz <= 96 else rz
        elif denom == 0:
            denom = 1
        x = self.screen_w // 2 + trunc_div(rx * 180, denom)
        y = self.screen_h // 2 - trunc_div(ry * 180, denom)
        visible = int(rz > 96 and -64 < x < self.screen_w + 64 and -64 < y < self.screen_h + 64)
        return {"x": x, "y": y, "visible": visible}

    def frame_hash(self, state: dict[str, int], targets: list[dict[str, int]], input_mask: int) -> int:
        hash_value = 2166136261
        for value in [
            state["frame"],
            input_mask,
            state["x"],
            state["y"],
            state["z"],
            state["vx"],
            state["vy"],
            state["vz"],
            state["yaw"],
            state["pitch"],
            state["energy"],
            state["health"],
            state["score"],
            state["collected_mask"],
        ]:
            hash_value = mix_u32(hash_value, value)
        for target in targets:
            point = self.project_point(state, target["x"], target["y"], target["z"])
            hash_value = mix_u32(hash_value, point["x"])
            hash_value = mix_u32(hash_value, point["y"])
            hash_value = mix_u32(hash_value, point["visible"])
        if self.mutant == "bad_frame_hash":
            return hash_value
        for vertex in self.cube_vertices:
            point = self.project_point(
                state,
                state["x"] + vertex[0],
                state["y"] + vertex[1],
                state["z"] + 1400 + vertex[2],
            )
            hash_value = mix_u32(hash_value, point["x"])
            hash_value = mix_u32(hash_value, point["y"])
            hash_value = mix_u32(hash_value, point["visible"])
        return hash_value

    def step(self, state: dict[str, int], targets: list[dict[str, int]], input_mask: int) -> None:
        if input_mask & self.input_left:
            state["yaw"] = (state["yaw"] + 31) & 31
        if input_mask & self.input_right:
            state["yaw"] = (state["yaw"] + 1) & 31
        if input_mask & self.input_up:
            state["pitch"] = clamp(state["pitch"] + 16, -384, 384)
        if input_mask & self.input_down:
            state["pitch"] = clamp(state["pitch"] - 16, -384, 384)
        if not (input_mask & (self.input_up | self.input_down)):
            state["pitch"] = trunc_div(state["pitch"] * 7, 8)

        if (input_mask & self.input_thrust) and state["energy"] > 0:
            state["vx"] += trunc_div(self.cos_yaw(state["yaw"]), 24)
            state["vz"] += trunc_div(self.sin_yaw(state["yaw"]), 24) + 18
            state["vy"] += trunc_div(state["pitch"], 96)
            state["energy"] = clamp(state["energy"] - 3, 0, 1000)
        else:
            state["energy"] = clamp(state["energy"] + 2, 0, 1000)

        state["x"] += state["vx"]
        state["y"] += state["vy"]
        state["z"] += state["vz"]
        damping = 30 if self.mutant == "wrong_state_transition" else 31
        state["vx"] = trunc_div(state["vx"] * damping, 32)
        state["vy"] = trunc_div(state["vy"] * damping, 32)
        state["vz"] = trunc_div(state["vz"] * damping, 32)

        if state["cooldown"] > 0:
            state["cooldown"] -= 1

        for index, target in enumerate(targets):
            bit = 1 << index
            if state["collected_mask"] & bit:
                continue
            dx = target["x"] - state["x"]
            dy = target["y"] - state["y"]
            dz = target["z"] - state["z"]
            if abs(dx) < target["radius"] and abs(dy) < target["radius"] and abs(dz) < target["radius"]:
                state["collected_mask"] |= bit
                state["score"] += target["value"]
                state["energy"] = clamp(state["energy"] + 80, 0, 1000)
            elif (input_mask & self.input_fire) and state["cooldown"] == 0:
                point = self.project_point(state, target["x"], target["y"], target["z"])
                if point["visible"] and abs(point["x"] - self.screen_w // 2) <= 18 and abs(point["y"] - self.screen_h // 2) <= 18:
                    state["score"] += 25
                    state["cooldown"] = 12

        if state["z"] < 0:
            state["z"] = 0
            state["vz"] = 0
            state["health"] = clamp(state["health"] - 5, 0, 1000)
        state["frame"] += 1

    def sample(self, state: dict[str, int], input_mask: int, hash_value: int) -> dict[str, int]:
        return {
            "frame": state["frame"],
            "input": input_mask,
            "x": state["x"],
            "y": state["y"],
            "z": state["z"],
            "vx": state["vx"],
            "vy": state["vy"],
            "vz": state["vz"],
            "yaw": state["yaw"],
            "pitch": state["pitch"],
            "energy": state["energy"],
            "health": state["health"],
            "score": state["score"],
            "collected_mask": state["collected_mask"],
            "hash": hash_value,
        }

    def sin_yaw(self, yaw: int) -> int:
        return self.sin_table[yaw & 31]

    def cos_yaw(self, yaw: int) -> int:
        return self.sin_table[(yaw + 8) & 31]


def mix_u32(hash_value: int, value: int) -> int:
    value &= 0xFFFFFFFF
    for shift in range(0, 32, 8):
        hash_value ^= (value >> shift) & 0xFF
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    return hash_value


def clamp(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(max_value, value))


def trunc_div(numerator: int, denominator: int) -> int:
    sign = -1 if (numerator < 0) ^ (denominator < 0) else 1
    return sign * (abs(numerator) // abs(denominator))


if __name__ == "__main__":
    raise SystemExit(main())
