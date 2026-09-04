#!/usr/bin/python3

import hashlib
import pathlib
import re
import subprocess
import sys


CANONICAL_COMMIT = "eaebfe5048757c3daa2e257e9a74175ca3fe1d4c"
SHARED_FUNCTIONS = {
    "crates/ed301-eddsa/src/edwards.rs": (
        "add",
        "add_affine",
        "double",
    ),
    "crates/ed301-eddsa/src/field_5x64.rs": (
        "multiply_wide",
        "multiply_five_by_u32",
        "square_wide",
        "reduce_wide",
        "reduce_wide_unreduced",
        "accumulate_fold",
    ),
}


def function_block(source: str, name: str) -> str:
    pattern = re.compile(rf"(?m)^\s*(?:pub\(crate\)\s+)?(?:const\s+)?fn\s+{name}\b")
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise ValueError(f"expected one function {name}, found {len(matches)}")
    start = matches[0].start()
    line_start = source.rfind("\n", 0, start) + 1
    previous_end = line_start - 1
    while previous_end > 0:
        previous_start = source.rfind("\n", 0, previous_end) + 1
        if not source[previous_start:previous_end].lstrip().startswith("#["):
            break
        line_start = previous_start
        previous_end = previous_start - 1
    brace = source.find("{", matches[0].end())
    if brace < 0:
        raise ValueError(f"function {name} has no body")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[line_start : index + 1]
    raise ValueError(f"function {name} has an unterminated body")


def git_head(root: pathlib.Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ED301_ROOT X301_ROOT")
    ed301 = pathlib.Path(sys.argv[1]).resolve(strict=True)
    x301 = pathlib.Path(sys.argv[2]).resolve(strict=True)
    if git_head(ed301) != CANONICAL_COMMIT:
        raise SystemExit("canonical Ed301 checkout is at the wrong commit")

    for relative, functions in SHARED_FUNCTIONS.items():
        ed_source = (ed301 / relative).read_text(encoding="utf-8")
        x_source = (x301 / relative).read_text(encoding="utf-8")
        for function in functions:
            expected = function_block(ed_source, function)
            actual = function_block(x_source, function)
            if actual != expected:
                raise SystemExit(f"shared arithmetic differs: {relative}:{function}")
            digest = hashlib.sha256(expected.encode()).hexdigest()
            print(f"shared_arithmetic={relative}:{function} sha256={digest}")
    print(f"ed301_arithmetic_provenance=PASS commit={CANONICAL_COMMIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
