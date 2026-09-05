#!/usr/bin/env python3
"""Fail when a function carrying an ACSL contract is missing from the proof set.

Frama-C ASSUMES the contract of any function it is not asked to prove. A
contracted helper left out of -wp-fct therefore becomes an unchecked axiom that
every goal above it rests on, and the gate still reports success. That is not
hypothetical: hex_nibble sat outside the RSP proof set, and replacing its body
with "return 15;" -- which contradicts its own ensures -- still produced
"PROVED 74 of 74", because gdb_parse_hex's termination and gdb_hex_decode's
stop-at-NUL both follow from that contract and from nothing else.

Usage:
    check-acsl-coverage.py --fcts "a b c" FILE [FILE ...]

Exits non-zero, naming the offenders, when a scanned file carries an ACSL
contract that is not in the proof set -- or one this script cannot attribute to
a function at all, since a contract it cannot read is one it cannot confirm.
"""

import argparse
import re
import sys

# ACSL annotations. Both forms count: Frama-C assumes a contract written with
# one-line //@ exactly as readily as a /*@ ... */ block, so scanning only the
# block form would let two characters re-open the very hole this script exists
# to close.
ACSL_BLOCK = re.compile(
    r"/\*@.*?\*/"  # /*@ ... */
    r"|^[ \t]*//@[^\n]*(?:\n[ \t]*//[^\n]*)*",  # //@ ..., plus its continuations
    re.DOTALL | re.MULTILINE,
)

# Annotations that are not function contracts, so have no function to attribute
# to: logic declarations (no C definition at all) and statement annotations
# (attached to a loop or a statement inside a body already covered by its own
# function's contract).
NOT_A_CONTRACT = re.compile(
    r"^\s*(predicate|logic|axiomatic|lemma|type|ghost"
    r"|loop|assert|check|admit|assume|breaks|continues|returns)\b"
)

# A C function definition header, up to the opening brace. Deliberately loose:
# the codebase writes one parameter per line, so match across newlines and take
# the identifier that precedes the parameter list.
DEFINITION = re.compile(
    r"""^[ \t]*                       # start of a line
        (?:static\s+|inline\s+)*      # storage/inline qualifiers
        [A-Za-z_][A-Za-z_0-9\s*]*?    # return type, possibly with pointers
        \b(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*   # the function name
        \([^;{]*?\)\s*                # parameter list
        \{                            # a body, not a declaration
    """,
    re.VERBOSE | re.DOTALL,
)


def contracted_definitions(text):
    """Contracted function names in @text, plus contracts not attributable to one.

    Returns (names, unattributed). Anything this cannot identify goes into
    `unattributed` and fails the run rather than being skipped: silently
    ignoring a contract is precisely the failure this script exists to prevent,
    so an unrecognized construct must be loud, not absent. A preprocessor
    directive or an ordinary comment between the annotation and the function is
    enough to defeat a regex, so those are stepped over explicitly.
    """
    names, unattributed = [], []
    for block in ACSL_BLOCK.finditer(text):
        raw = block.group(0)
        if raw.startswith("/*"):
            body = raw[3:-2]
        else:
            # //@ form: drop the marker from the first line and the leading //
            # from any continuation lines.
            body = "\n".join(
                re.sub(r"^[ \t]*//@?", "", line) for line in raw.splitlines()
            )
        if NOT_A_CONTRACT.match(body.lstrip("\n")):
            continue

        # Step over what can legitimately sit between an annotation and the
        # function it applies to: further annotation blocks (a predicate
        # declared just above its user), ordinary comments, and preprocessor
        # directives.
        rest = text[block.end() :]
        while True:
            stripped = rest.lstrip()
            if stripped.startswith("/*"):
                rest = stripped[stripped.index("*/") + 2 :]
            elif stripped.startswith("//") or stripped.startswith("#"):
                newline = stripped.find("\n")
                if newline < 0:
                    rest = ""
                    break
                rest = stripped[newline + 1 :]
            else:
                rest = stripped
                break

        match = DEFINITION.match(rest)
        if match:
            names.append(match.group("name"))
        else:
            unattributed.append(first_line(rest))
    return names, unattributed


# The gcc_x86_64 data model is a sound stand-in for arm64 macOS on every
# property these proofs use EXCEPT plain-char signedness (see the table in
# mk/verify.mk). What keeps the results signedness-independent is that no
# proved function reads a plain char without an explicit (unsigned char) or
# (uint8_t) cast first.
#
# This regex is the cheap half and it names the offending function, which is
# what makes a failure actionable. It cannot see a char reached through a
# typedef or a macro; check-char-signedness.py settles that half with the
# compiler, which resolves both, and "make verify" runs it. The five below
# satisfy the invariant and are listed and hand-audited rather than rewritten.
#
# The four RSP ones predate the invariant and cast at every read.
# nl_parse_link_filter is a different shape: its char * is an output buffer it
# only ever writes, and the byte it writes comes from a uint8_t source through
# an explicit (char) cast. It reads no plain char at all, so there is nothing
# for the signedness to change.
CHAR_PARAM_ALLOWLIST = {
    "gdb_hex_pair",
    "gdb_hex_decode",
    "gdb_parse_hex",
    "rsp_checksum",
    "nl_parse_link_filter",
    # The three elf.c entries take a const char *display_path they only ever
    # hand to log_error as %s. None dereferences it, so like
    # nl_parse_link_filter there is no plain char read for the signedness to
    # change.
    "elf_place_segment",
    "elf_check_placement",
    "elf_record_load",
    # elf_read_interp takes display_path on the same terms, and additionally
    # reads the interpreter name it just filled. Those two reads go through an
    # explicit (unsigned char), which is the invariant the rest of this list
    # satisfies by never reading a plain char at all.
    "elf_read_interp",
}

# A char parameter, with its signedness qualifier if it has one. Matching the
# qualifier as part of the pattern rather than as a lookbehind is what makes
# this tolerant of "unsigned  char" and of a qualifier split across lines; a
# fixed-width lookbehind cannot express either.
CHAR_PARAM = re.compile(r"\b(?:(signed|unsigned)\s+)?char\b")

# DEFINITION anchors ^ at position 0 because its caller matches it against a
# slice starting at the function. Searching a whole file needs the same pattern
# with MULTILINE so ^ means start-of-line.
DEFINITION_ANYWHERE = re.compile(DEFINITION.pattern, DEFINITION.flags | re.MULTILINE)


def blank_comments_and_literals(text):
    """Replace comments and string/char literals with spaces, same length.

    A char scan over raw source trips on the word "char" in prose and on a
    literal like \'c\'. Blanking them keeps every offset intact so the
    definition regex still matches at the same places.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        two = text[i : i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
        elif two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
        elif text[i] in "\"'":
            quote, j = text[i], i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
        else:
            out.append(text[i])
            i += 1
            continue
        out.append(" " * (j - i))
        i = j
    return "".join(out)


def plain_char_params(text, proved):
    """Proved functions in @text that name a plain char.

    Scans the whole definition, parameters and body, not just the parameter
    list: a plain char local or return type is exactly as signedness-dependent
    as a parameter, and scanning only the signature would let one through.

    Names the offending function, which is what makes a failure actionable, and
    misses a char behind a typedef or a macro. check-char-signedness.py covers
    that blind spot with the compiler; the two run together under "make verify"
    and neither replaces the other.
    """
    clean = blank_comments_and_literals(text)
    offenders = []
    for match in DEFINITION_ANYWHERE.finditer(clean):
        name = match.group("name")
        if name not in proved or name in CHAR_PARAM_ALLOWLIST:
            continue
        # Brace-match from the opening brace to get the whole definition.
        depth, j, end = 0, match.end() - 1, -1
        while j < len(clean):
            if clean[j] == "{":
                depth += 1
            elif clean[j] == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        if end < 0:
            # Brace matching runs on unpreprocessed source, so a definition
            # whose #if branches open braces unevenly never balances. Scanning
            # to end of file would blame this function for every char after it,
            # and failing the build would reject perfectly good code, so narrow
            # to the signature and let check-char-signedness.py cover the body:
            # it compiles the real thing and misses none of this.
            end = match.end() - 1
        if any(
            m.group(1) is None
            for m in CHAR_PARAM.finditer(clean[match.start() : end + 1])
        ):
            offenders.append(name)
    return offenders


def first_line(text):
    """First non-empty line of @text, for an error message."""
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:72]
    return "<end of file>"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fcts", required=True, help="space-separated names passed to -wp-fct"
    )
    parser.add_argument(
        "--target", default="the proof", help="proof name, for the error message"
    )
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()

    proved = set(args.fcts.split())
    missing, unattributed, char_params = [], [], []
    for path in args.files:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        names, strays = contracted_definitions(text)
        missing += [(path, n) for n in names if n not in proved]
        unattributed += [(path, s) for s in strays]
        char_params += [(path, n) for n in plain_char_params(text, proved)]

    if char_params:
        sys.stderr.write(
            "  plain char: %d proved function(s) take a plain char\n" % len(char_params)
        )
        for path, name in char_params:
            sys.stderr.write("    %s: %s\n" % (path, name))
        sys.stderr.write(
            "  The data model gcc_x86_64 makes plain char SIGNED; arm64 macOS\n"
            "  makes it unsigned. Read the char through an explicit\n"
            "  (unsigned char) or (uint8_t) cast, or add the function to\n"
            "  CHAR_PARAM_ALLOWLIST once you have checked every use casts.\n"
        )
        return 1

    if unattributed:
        sys.stderr.write(
            "  ACSL coverage: %d contract(s) not attributable to a function\n"
            % len(unattributed)
        )
        for path, excerpt in unattributed:
            sys.stderr.write("           %s: before %r\n" % (path, excerpt))
        sys.stderr.write(
            "           Refusing to guess: a contract this script cannot read\n"
            "           is one it cannot confirm is proved, which is the blind\n"
            "           spot it exists to close.\n"
        )
        return 1

    if missing:
        sys.stderr.write(
            "  ACSL coverage: %d contracted function(s) are assumed, not proved\n"
            % len(missing)
        )
        for path, name in missing:
            sys.stderr.write("           %s: %s\n" % (path, name))
        sys.stderr.write(
            "           Frama-C assumes the contract of any function outside\n"
            "           -wp-fct, so each of these is an unchecked axiom the\n"
            "           rest of %s rests on. Add them to the proof set, or\n"
            "           drop their contracts if they are not load-bearing.\n"
            % args.target
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
