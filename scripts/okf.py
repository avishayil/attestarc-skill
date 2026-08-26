#!/usr/bin/env python3
"""Deterministic reader/writer for the OKF concept subset AttestArc ships.

AttestArc's verified-knowledge plane is an Open Knowledge Format (OKF) bundle: a
directory tree of UTF-8 markdown concept files, each a YAML frontmatter block
(delimited by ``---``) followed by a markdown body. The shipped skill is
**stdlib-only** (SPECIFICATION.md §12; CLAUDE.md), so this module is a small,
hand-written parser/emitter for exactly the frontmatter *subset* we produce —
the second such deliberately-scoped reader alongside
``knowledge_compile.load_registry`` (which reads ``sources.yaml``). It is NOT a
general YAML implementation.

Design rules (mirror the rest of the knowledge helpers):

* **Facts, not verdicts.** This module (de)serializes; it makes no trust
  decision. OKF's advisory ``status``/``generated``/``verified``/``stale_after``
  are just data here — the cryptographic gate lives elsewhere.
* **Never crashes the host.** ``parse_frontmatter``/``read_concept`` never raise:
  any grammar violation degrades to ``{"_parse_partial": True, "_raw": <capped>}``
  so a malformed concept fails closed (skipped by the read path), never reasoned
  over line-by-line.
* **One normal form.** The writer sorts keys, indents by two spaces, always
  double-quotes strings, and emits block sequences as a bare ``-`` followed by
  the item block. This yields a single canonical serialization such that
  ``render(parse(render(x))) == render(x)`` and, for a file we generated,
  ``render(read(bytes)) == bytes``. The release pipeline asserts that fixpoint
  over every shipped concept, closing the parser-differential hole (a shipped
  file has exactly one reading).

The subset:

* Frontmatter is a top-level mapping. Keys match ``[A-Za-z0-9_.-]+``.
* Values are inline scalars, nested block mappings (2-space indent), or block
  sequences. Prose (the ``claim``) lives in the markdown **body**, so frontmatter
  carries **no multi-line scalars** — the single biggest YAML footgun is absent.
* Scalars: double-quoted strings (with ``\\`` ``\"`` ``\\n`` ``\\t`` escapes),
  integers, ``true``/``false``, ``null``/empty, and the empty-container literals
  ``{}`` / ``[]``. No flow collections, anchors, tags, or multi-line scalars.
* A sequence item is either ``- <scalar>`` or a bare ``-`` whose block (a mapping
  or nested sequence) begins two columns deeper.
"""

from __future__ import annotations

import re

_RAW_CAP = 2000               # cap on the excerpt kept for a partial parse
_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+")
_INT_RE = re.compile(r"-?[0-9]+")

# OKF reserved bundle files: shipped and byte-pinned, but NOT concepts (they carry
# no ``attestarc`` namespace). ``index.md`` is the bundle/organizational index and
# ``log.md`` the chronological history; the concept read path skips both.
_OKF_RESERVED = ("index.md", "log.md")


class OKFError(Exception):
    """Raised only by the WRITER on an unserializable value (a programming error
    surfaced in tests/compile). The reader never raises — it degrades."""


class _ParseError(Exception):
    """Internal: a frontmatter grammar violation. Caught and turned into a
    ``parse_partial`` result; never escapes this module."""


# --------------------------------------------------------------------------- #
# Scalars
# --------------------------------------------------------------------------- #
def _quote(s: str) -> str:
    return '"' + (s.replace("\\", "\\\\").replace('"', '\\"')
                  .replace("\n", "\\n").replace("\t", "\\t")) + '"'


def _unquote(tok: str) -> str:
    if len(tok) < 2 or not tok.startswith('"') or not tok.endswith('"'):
        raise _ParseError(f"malformed quoted string: {tok!r}")
    body = tok[1:-1]
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            if i + 1 >= len(body):
                raise _ParseError("dangling escape in string")
            nxt = body[i + 1]
            out.append({"\\": "\\", '"': '"', "n": "\n", "t": "\t"}.get(nxt))
            if out[-1] is None:
                raise _ParseError(f"unknown escape \\{nxt}")
            i += 2
        elif ch == '"':
            raise _ParseError("unescaped quote in string")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _parse_scalar(tok: str):
    if tok == "" or tok == "null":
        return None
    if tok == "true":
        return True
    if tok == "false":
        return False
    if tok == "{}":
        return {}
    if tok == "[]":
        return []
    if tok.startswith('"'):
        return _unquote(tok)
    if _INT_RE.fullmatch(tok):
        return int(tok)
    # Tolerant: a bare token our writer would have quoted. Accept it as a string
    # so a hand-authored file still reads, but the canonical writer will quote it.
    return tok


def _dump_scalar(val) -> str:
    if val is None:
        return "null"
    if val is True:
        return "true"
    if val is False:
        return "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        return _quote(val)
    raise OKFError(f"unserializable scalar of type {type(val).__name__}: {val!r}")


# --------------------------------------------------------------------------- #
# Reader
# --------------------------------------------------------------------------- #
def _items(fm_text: str) -> list:
    """Filtered ``(indent, content)`` pairs for the non-blank frontmatter lines.

    Rejects tab-indentation and odd indentation outright (``_ParseError``) — the
    canonical writer never produces them, so their presence means the file is
    outside our subset and must fail closed rather than be misread."""
    items = []
    for raw in fm_text.split("\n"):
        if "\t" in raw:
            raise _ParseError("tab character in frontmatter")
        stripped = raw.strip()
        if not stripped:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2 != 0:
            raise _ParseError(f"odd indentation ({indent})")
        items.append((indent, stripped))
    return items


def _valid_key(key: str) -> bool:
    return bool(_KEY_RE.fullmatch(key))


def _parse_block(items: list, i: int, indent: int):
    """Parse the block at column ``indent`` starting at ``items[i]``; return
    ``(value, next_index)``. A leading ``-`` makes it a sequence, else a mapping."""
    if i >= len(items):
        raise _ParseError("expected a block, found end of input")
    _, content = items[i]
    if content == "-" or content.startswith("- "):
        return _parse_seq(items, i, indent)
    return _parse_map(items, i, indent)


def _parse_map(items: list, i: int, indent: int):
    result: dict = {}
    while i < len(items):
        ind, content = items[i]
        if ind < indent:
            break
        if ind > indent:
            raise _ParseError(f"unexpected indent {ind} (want {indent})")
        if content == "-" or content.startswith("- "):
            raise _ParseError("sequence item where a mapping key was expected")
        if ":" not in content:
            raise _ParseError(f"expected 'key:' , got {content!r}")
        key, _, val = content.partition(":")
        key = key.strip()
        val = val.strip()
        if not _valid_key(key):
            raise _ParseError(f"invalid key {key!r}")
        if key in result:
            raise _ParseError(f"duplicate key {key!r}")
        if val == "":
            # Opens a nested block two columns deeper (or an empty value).
            if i + 1 < len(items) and items[i + 1][0] == indent + 2:
                sub, i = _parse_block(items, i + 1, indent + 2)
                result[key] = sub
            elif i + 1 < len(items) and items[i + 1][0] > indent:
                raise _ParseError("misindented nested block")
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _parse_scalar(val)
            i += 1
    return result, i


def _parse_seq(items: list, i: int, indent: int):
    result: list = []
    while i < len(items):
        ind, content = items[i]
        if ind < indent:
            break
        if ind > indent:
            raise _ParseError(f"unexpected indent {ind} in sequence (want {indent})")
        if content == "-":
            # Bare dash: the item is the block beginning two columns deeper.
            if i + 1 < len(items) and items[i + 1][0] == indent + 2:
                sub, i = _parse_block(items, i + 1, indent + 2)
                result.append(sub)
            else:
                raise _ParseError("bare '-' without an item block")
        elif content.startswith("- "):
            result.append(_parse_scalar(content[2:].strip()))
            i += 1
        else:
            break
    return result, i


def parse_frontmatter(fm_text: str) -> dict:
    """Parse the frontmatter text (between the ``---`` fences) to a dict.

    Never raises: on any violation of the subset returns
    ``{"_parse_partial": True, "_raw": <capped excerpt>}`` so the caller fails
    closed. An empty block parses to ``{}``."""
    try:
        items = _items(fm_text)
        if not items:
            return {}
        value, consumed = _parse_block(items, 0, 0)
        if consumed != len(items):
            raise _ParseError("trailing content after top-level block")
        if not isinstance(value, dict):
            raise _ParseError("frontmatter top level must be a mapping")
        return value
    except _ParseError:
        return {"_parse_partial": True, "_raw": fm_text[:_RAW_CAP]}


# --------------------------------------------------------------------------- #
# Writer
# --------------------------------------------------------------------------- #
def _dump_map(obj: dict, indent: int) -> list:
    lines = []
    pad = " " * indent
    for key in sorted(obj):
        if not _valid_key(key):
            raise OKFError(f"invalid frontmatter key {key!r}")
        val = obj[key]
        if isinstance(val, dict) and val:
            lines.append(f"{pad}{key}:")
            lines.extend(_dump_map(val, indent + 2))
        elif isinstance(val, list) and val:
            lines.append(f"{pad}{key}:")
            lines.extend(_dump_seq(val, indent + 2))
        elif isinstance(val, dict):
            lines.append(f"{pad}{key}: {{}}")
        elif isinstance(val, list):
            lines.append(f"{pad}{key}: []")
        else:
            lines.append(f"{pad}{key}: {_dump_scalar(val)}")
    return lines


def _dump_seq(seq: list, indent: int) -> list:
    lines = []
    pad = " " * indent
    for item in seq:
        if isinstance(item, dict) and item:
            lines.append(f"{pad}-")
            lines.extend(_dump_map(item, indent + 2))
        elif isinstance(item, list) and item:
            lines.append(f"{pad}-")
            lines.extend(_dump_seq(item, indent + 2))
        elif isinstance(item, dict):
            lines.append(f"{pad}- {{}}")
        elif isinstance(item, list):
            lines.append(f"{pad}- []")
        else:
            lines.append(f"{pad}- {_dump_scalar(item)}")
    return lines


def dump_frontmatter(obj: dict) -> str:
    """Serialize a mapping to canonical frontmatter text (no trailing newline).

    Keys sorted, 2-space indent, strings always double-quoted, sequences as bare
    ``-`` + block. Raises ``OKFError`` on an unserializable value (writer-side
    programming error)."""
    if not isinstance(obj, dict):
        raise OKFError("frontmatter must be a mapping")
    return "\n".join(_dump_map(obj, 0))


# --------------------------------------------------------------------------- #
# Concept files (frontmatter + body)
# --------------------------------------------------------------------------- #
def split_frontmatter(text: str):
    """Split a concept file into ``(frontmatter_text, body)``, preserving the body
    bytes exactly. Returns ``(None, text)`` when there is no ``---`` block."""
    if not text.startswith("---\n"):
        return None, text
    rest = text[4:]
    end = rest.find("\n---\n")
    if end != -1:
        return rest[:end], rest[end + 5:]
    if rest.endswith("\n---"):        # closing fence with no trailing newline
        return rest[:-4], ""
    return None, text                 # unterminated frontmatter


def render_concept(frontmatter: dict, body: str) -> str:
    """Assemble the canonical concept-file text. The single source of truth for
    both ``write_concept`` and the release round-trip self-check."""
    return "---\n" + dump_frontmatter(frontmatter) + "\n---\n" + body


def canonical_frontmatter(frontmatter: dict) -> dict:
    """The normal-form frontmatter dict (``parse(dump(fm))``) — the projection a
    content digest should be taken over, independent of key order/whitespace."""
    return parse_frontmatter(dump_frontmatter(frontmatter))


def read_concept(text_or_path: str, *, is_path: bool = True) -> dict:
    """Read a concept. With ``is_path`` (default) ``text_or_path`` is a file path;
    otherwise it is the raw text. Returns
    ``{"frontmatter", "body", "_parse_partial"}`` and never raises — an
    unreadable/malformed file degrades to ``_parse_partial`` with an empty
    frontmatter so the read path fails closed."""
    if is_path:
        try:
            with open(text_or_path, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            return {"frontmatter": {}, "body": "", "_parse_partial": True,
                    "_raw": ""}
    else:
        raw = text_or_path
    fm_text, body = split_frontmatter(raw)
    if fm_text is None:
        return {"frontmatter": {}, "body": raw, "_parse_partial": True,
                "_raw": raw[:_RAW_CAP]}
    fm = parse_frontmatter(fm_text)
    if isinstance(fm, dict) and fm.get("_parse_partial") is True:
        return {"frontmatter": {}, "body": body, "_parse_partial": True,
                "_raw": fm.get("_raw", "")}
    return {"frontmatter": fm, "body": body, "_parse_partial": False}


def write_concept(path: str, frontmatter: dict, body: str) -> None:
    """Write a concept file in canonical form (LF newlines, UTF-8)."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_concept(frontmatter, body))


def roundtrip_ok(raw: str) -> bool:
    """True iff ``raw`` is already in canonical form: it parses cleanly and
    re-rendering the parsed (frontmatter, body) reproduces the exact bytes. The
    release pipeline asserts this over every shipped concept."""
    got = read_concept(raw, is_path=False)
    if got["_parse_partial"]:
        return False
    try:
        return render_concept(got["frontmatter"], got["body"]) == raw
    except OKFError:
        return False


# --------------------------------------------------------------------------- #
# AttestArc entry <-> OKF concept mapping
# --------------------------------------------------------------------------- #
# The knowledge helpers work on an internal *entry dict* (schemas/knowledge.schema.json).
# A concept file carries the SAME information as an OKF document:
#
#   * ``kind``   -> OKF-native ``type`` (the concept type; also drives routing)
#   * ``claim``  -> the markdown BODY (prose leaves the frontmatter)
#   * everything the security code reads -> under one ``attestarc:`` mapping
#     (authoritative), so a trust decision never rests on an OKF-native field
#   * OKF-native ``title``/``tags``/``sources``/``status``/``stale_after`` -> a
#     DERIVED, ADVISORY projection for OKF consumers. Code never reads it, and it
#     is excluded from the content digest, so it can be regenerated freely.
#
# ``entry_from_concept`` and ``concept_from_entry`` are exact inverses over the
# authoritative content, so ``load_packs`` reconstructs byte-identical entry
# dicts (hence identical content hashes) from the markdown bundle.

# Authoritative entry fields carried under the ``attestarc`` namespace. ``kind``
# and ``claim`` are intentionally absent (they map to ``type`` and the body).
_NAMESPACE_FIELDS = (
    "id", "platform", "subject", "claim_key", "applies_to", "valid_from",
    "expires", "status", "confidence", "effect", "sources", "supersedes",
    "last_verified", "compiler", "extensions")

# Advisory OKF lifecycle projection (lossy: the 5 AttestArc statuses collapse to
# OKF's 3). Read by nothing — the authoritative status lives in ``attestarc``.
_OKF_STATUS = {"active": "stable", "draft": "draft", "superseded": "deprecated",
               "retired": "deprecated", "disputed": "deprecated"}


def _strip_runtime(entry: dict) -> dict:
    return {k: v for k, v in (entry or {}).items() if not k.startswith("_")}


def concept_from_entry(entry: dict):
    """Map an internal entry dict to an OKF concept ``(frontmatter, body)``.

    The frontmatter carries the authoritative ``attestarc`` namespace plus a
    derived advisory OKF projection; the body is the claim prose."""
    clean = _strip_runtime(entry)
    attestarc = {k: clean[k] for k in _NAMESPACE_FIELDS if k in clean}

    frontmatter = {"type": clean.get("kind"), "attestarc": attestarc}

    # Advisory OKF-native projection (never read back; excluded from the digest).
    subject = clean.get("subject")
    platform = clean.get("platform")
    if subject:
        frontmatter["title"] = subject
    tags = [t for t in (platform, subject) if t]
    if tags:
        frontmatter["tags"] = tags
    sources = clean.get("sources")
    if isinstance(sources, list) and sources:
        native = []
        for src in sources:
            if not isinstance(src, dict):
                continue
            proj = {}
            if src.get("url"):
                proj["resource"] = src["url"]
            if src.get("publisher"):
                proj["author"] = src["publisher"]
            if proj:
                native.append(proj)
        if native:
            frontmatter["sources"] = native
    status = clean.get("status")
    if status in _OKF_STATUS:
        frontmatter["status"] = _OKF_STATUS[status]
    expires = clean.get("expires")
    if isinstance(expires, str) and expires:
        frontmatter["stale_after"] = f"{expires[:10]}T00:00:00Z"

    body = (clean.get("claim") or "") + "\n"
    return frontmatter, body


def entry_from_concept(frontmatter: dict, body: str) -> dict:
    """Reconstruct the internal entry dict from an OKF concept. The exact inverse
    of ``concept_from_entry`` over the authoritative content: reads only ``type``,
    the body, and the ``attestarc`` namespace — never an advisory OKF field."""
    attestarc = frontmatter.get("attestarc")
    attestarc = attestarc if isinstance(attestarc, dict) else {}
    entry = {k: attestarc[k] for k in _NAMESPACE_FIELDS if k in attestarc}
    if "type" in frontmatter:
        entry["kind"] = frontmatter["type"]
    entry["claim"] = body[:-1] if body.endswith("\n") else body
    return entry


def concept_slug(entry: dict) -> str:
    """Deterministic concept filename for an entry: the id minus the ``KE-``
    prefix, plus ``.md``. Ids are unique, so slugs are unique within a bundle."""
    eid = entry.get("id") or "entry"
    stem = eid[3:] if eid.startswith("KE-") else eid
    return f"{stem}.md"
