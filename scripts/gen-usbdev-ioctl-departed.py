#!/usr/bin/env python3
"""Generate build/usbdev-ioctl-departed-vectors.h from the recorded table.

The gate the header exists for: the usbdevfs ioctl surface is read out of
src/syscall/usbdev.c's dispatch rather than listed by hand, and every request
it dispatches must have a row in tests/usbdev-ioctl-departed.tbl saying what
Linux answers for it on a departed device. An ioctl added to the layer with no
row fails here, so no prose has to carry the enumeration.

The arm that catches everything the dispatch does not is part of the surface
and was not part of the join, which is how a comment claiming the table said
what every arm answers stayed true of every arm but that one. A row may
therefore name a USBDEVFS_ request src/syscall/usbdev.c defines and dispatches
nowhere; it drives the default arm. While usbdev_ioctl has a default arm, at
least one such row must exist, and a row naming a request the file does not
define at all still fails here.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = ROOT / "src" / "syscall" / "usbdev.c"
DEFAULT_TABLE = ROOT / "tests" / "usbdev-ioctl-departed.tbl"
DEFAULT_OUTPUT = ROOT / "build" / "usbdev-ioctl-departed-vectors.h"

DEFINE_RE = re.compile(r"^#define\s+USBDEVFS_([A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)u\s*$")
CASE_RE = re.compile(r"^\s*case USBDEVFS_([A-Z0-9_]+):")
EARLY_RE = re.compile(r"request == USBDEVFS_([A-Z0-9_]+)")
DEFAULT_RE = re.compile(r"^\s{4}default:\s*$")

PHASES = {"fresh": "USBDEV_DEPARTED_FRESH",
          "held-claim": "USBDEV_DEPARTED_HELD_CLAIM",
          "held-release": "USBDEV_DEPARTED_HELD_RELEASE"}
REVENTS = {"ERRHUP": "(POLLERR | POLLHUP)", "NONE": "0"}


def dispatched(path: pathlib.Path) -> tuple[dict[str, str], list[str], bool]:
    """The request codes the layer defines, the ones usbdev_ioctl reaches by a
    case label of its own, and whether it has a default arm to catch the rest.
    """
    text = path.read_text(encoding="utf-8")
    codes = {m.group(1): m.group(2)
             for m in (DEFINE_RE.match(line) for line in text.splitlines()) if m}
    start = text.find("\nint64_t usbdev_ioctl(")
    if start < 0:
        raise ValueError(f"{path}: no usbdev_ioctl definition")
    body = text[start:]
    end = body.find("\n}\n")
    if end < 0:
        raise ValueError(f"{path}: usbdev_ioctl has no closing brace")
    body = body[:end]

    names: list[str] = []
    for name in EARLY_RE.findall(body) + [
            m.group(1) for m in (CASE_RE.match(l) for l in body.splitlines()) if m]:
        if name in ("IOCTL_DISCONNECT", "IOCTL_CONNECT"):
            continue  # sub-codes of USBDEVFS_IOCTL, not requests of their own
        if name not in codes:
            raise ValueError(f"{path}: usbdev_ioctl dispatches USBDEVFS_{name} "
                             "with no request code defined for it")
        if name not in names:
            names.append(name)
    if not names:
        raise ValueError(f"{path}: usbdev_ioctl dispatches nothing")
    has_default = any(DEFAULT_RE.match(line) for line in body.splitlines())
    return codes, names, has_default


def tuple_fields(spec: str, where: str) -> tuple[str, str, str, str]:
    parts = spec.split("/")
    if len(parts) != 4:
        raise ValueError(f"{where}: '{spec}' is not rc/errno/stamp/peer")
    rc, err, stamp, peer = parts
    try:
        int(rc, 0)
    except ValueError:
        raise ValueError(f"{where}: rc '{rc}' is not a number") from None
    if err != "NONE" and not re.fullmatch(r"E[A-Z0-9]+", err):
        raise ValueError(f"{where}: errno '{err}' is neither NONE nor an E name")
    for name in (stamp, peer):
        if name not in REVENTS:
            raise ValueError(f"{where}: revents '{name}' is not one of "
                             + ", ".join(sorted(REVENTS)))
    return rc, "0" if err == "NONE" else err, REVENTS[stamp], REVENTS[peer]


def parse_table(path: pathlib.Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        where = f"{path}:{lineno}"
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0].isspace():
            if not rows:
                raise ValueError(f"{where}: note with no row above it")
            note = rows[-1]["note"]
            rows[-1]["note"] = (note + " " + raw.strip()) if note else raw.strip()
            continue
        fields = raw.split()
        if len(fields) != 6:
            raise ValueError(f"{where}: expected 6 columns, got {len(fields)}")
        rid, req, phase, lin, here, cite = fields
        if phase not in PHASES:
            raise ValueError(f"{where}: phase '{phase}' is not one of "
                             + ", ".join(sorted(PHASES)))
        if any(r["id"] == rid for r in rows):
            raise ValueError(f"{where}: duplicate row id '{rid}'")
        rows.append({
            "id": rid, "req": req, "phase": phase,
            "kernel": tuple_fields(lin, where),
            "here": None if here == "-" else tuple_fields(here, where),
            "cite": int(cite), "note": "",
        })
    for row in rows:
        if not row["note"]:
            raise ValueError(f"{path}: row '{row['id']}' has no note")
    return rows


def cross_check(rows: list[dict[str, object]], codes: dict[str, str],
                names: list[str], has_default: bool,
                table: pathlib.Path, source: pathlib.Path) -> None:
    covered = {row["req"] for row in rows}
    missing = [n for n in names if n not in covered]
    if missing:
        raise ValueError(
            f"{table}: no recorded Linux answer for USBDEVFS_"
            + ", USBDEVFS_".join(missing)
            + f" (dispatched by {source}). Add a row saying what Linux answers "
              "for it on a departed device.")
    unknown = sorted(covered - set(codes))
    if unknown:
        raise ValueError(
            f"{table}: rows name USBDEVFS_" + ", USBDEVFS_".join(unknown)
            + f", which {source} defines no request code for.")
    fallthrough = sorted(covered - set(names))
    if fallthrough and not has_default:
        raise ValueError(
            f"{table}: rows name USBDEVFS_" + ", USBDEVFS_".join(fallthrough)
            + f", which {source} neither dispatches nor catches: usbdev_ioctl "
              "has no default arm for them to reach.")
    if has_default and not fallthrough:
        raise ValueError(
            f"{table}: usbdev_ioctl has a default arm and no row drives it. "
            "Add a row naming a USBDEVFS_ request the layer defines and does "
            "not dispatch, so what that arm answers on a departed device is "
            "measured rather than assumed.")


def c_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(rows: list[dict[str, object]], codes: dict[str, str]) -> str:
    out = [
        "/*",
        " * What the usbdevfs ioctls this layer names answer on a departed device",
        " *",
        " * Copyright 2026 elfuse contributors",
        " * SPDX-License-Identifier: Apache-2.0",
        " *",
        " * GENERATED by scripts/gen-usbdev-ioctl-departed.py from",
        " * tests/usbdev-ioctl-departed.tbl; do not edit. The table records what",
        " * Linux answers and why, the generator checks it against the dispatch in",
        " * src/syscall/usbdev.c, and tests/test-usbdev-ioctl-departed.c drives it.",
        " *",
        " * Include <errno.h>, <poll.h> and <stdbool.h> before this header.",
        " */",
        "",
        "#pragma once",
        "",
        "enum {",
        "    USBDEV_DEPARTED_FRESH,",
        "    USBDEV_DEPARTED_HELD_CLAIM,",
        "    USBDEV_DEPARTED_HELD_RELEASE,",
        "};",
        "",
        "/* One observation of a departed-device ioctl. rc is the ioctl(2) return,",
        " * err the errno behind an rc of -1, stamp the poll revents left on the fd",
        " * that asked, and peer the revents on another fd open on the same node.",
        " */",
        "typedef struct {",
        "    long rc;",
        "    int err;",
        "    short stamp;",
        "    short peer;",
        "} usbdev_departed_tuple_t;",
        "",
        "typedef struct {",
        "    const char *id;",
        "    const char *req_name;",
        "    unsigned long request;",
        "    int phase;",
        "    usbdev_departed_tuple_t kernel;",
        "    bool diverges;",
        "    usbdev_departed_tuple_t here;",
        "    int devio_line;",
        "    const char *note;",
        "} usbdev_departed_row_t;",
        "",
        "/* One driver per row, declared here and defined by the lane, so a row",
        " * with no driver behind it fails to compile rather than going undriven.",
        " */",
        "typedef long usbdev_departed_fn(int fd, unsigned long request);",
        "",
    ]
    out += [f"static usbdev_departed_fn departed_drive_{row['id']};"
            for row in rows]
    out.append("")
    out.append("static usbdev_departed_fn *const usbdev_departed_drivers[] = {")
    out += [f"    departed_drive_{row['id']}," for row in rows]
    out.append("};")
    out.append("")
    out.append(f"#define USBDEV_DEPARTED_NROWS {len(rows)}")
    out.append("")
    out.append("static const usbdev_departed_row_t usbdev_departed_rows[] = {")
    for row in rows:
        lin = row["kernel"]
        here = row["here"] or ("0", "0", "0", "0")
        out += [
            "    {",
            f"        .id = {c_string(str(row['id']))},",
            f"        .req_name = {c_string('USBDEVFS_' + str(row['req']))},",
            f"        .request = {codes[str(row['req'])]}ul,",
            f"        .phase = {PHASES[str(row['phase'])]},",
            f"        .kernel = {{{lin[0]}, {lin[1]}, {lin[2]}, {lin[3]}}},",
            f"        .diverges = {'true' if row['here'] else 'false'},",
            f"        .here = {{{here[0]}, {here[1]}, {here[2]}, {here[3]}}},",
            f"        .devio_line = {row['cite']},",
            f"        .note = {c_string(str(row['note']))},",
            "    },",
        ]
    out.append("};")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, default=DEFAULT_SOURCE)
    parser.add_argument("--table", type=pathlib.Path, default=DEFAULT_TABLE)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    codes, names, has_default = dispatched(args.source)
    rows = parse_table(args.table)
    cross_check(rows, codes, names, has_default, args.table, args.source)
    output = render(rows, codes)

    if args.check:
        if not args.output.exists():
            print(f"{args.output}: missing; run "
                  "'python3 scripts/gen-usbdev-ioctl-departed.py'", file=sys.stderr)
            return 1
        if args.output.read_text(encoding="utf-8") != output:
            print(f"{args.output}: stale; run "
                  "'python3 scripts/gen-usbdev-ioctl-departed.py'", file=sys.stderr)
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
