"""RTF (Rich Text Format) embedded-object parsing — bounded, stdlib only.

RTF is still a live delivery vector. The format carries an embedded object in
a ``{\\*\\objdata ...}`` destination as a hex run (occasionally a ``\\binN``
raw run), usually named by a sibling ``{\\*\\objclass Package}``. For a
``Package`` object the decoded bytes are an OLE/CFB compound file, so the
parser in ``engine/intake/ole.py`` finishes the job: decompress the VBA
project (MS-OVBA) and carve the ``\\x01Ole10Native`` payload. This is the same
two-stage pattern used for an Office document delivered as an OLE file.

This module is the *parser* half. ``engine/intake/delivery.py::_extract_rtf``
owns the shared depth/child/size bounds and writes the children. Nothing here
executes anything, and every loop is bounded: the group scanner skips ``\\bin``
raw regions so binary payloads cannot confuse group tracking, embedded objects
are counted and size-capped, and a malformed document raises ``RtfError``
rather than returning silently empty.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass, field
from typing import Optional

# Destinations whose group content this parser cares about.
_DESTINATIONS = {b"objdata", b"objclass", b"objname"}


class RtfError(ValueError):
    """Raised when an RTF document cannot be parsed within the bounds."""


@dataclass
class RtfObject:
    """One object carved out of an ``\\objdata`` destination."""

    data: bytes = b""
    objclass: str = ""
    objname: str = ""
    used_bin: bool = False
    odd_nibble: bool = False


@dataclass
class RtfDocument:
    """The embedded objects (and a few structural flags) of one RTF file."""

    objects: list[RtfObject] = field(default_factory=list)
    has_objemb: bool = False
    has_objlink: bool = False
    has_objupdate: bool = False
    unterminated: bool = False


@dataclass
class _Group:
    """A group's destination name and where its content begins."""

    name: bytes = b""
    content_start: int = 0


def _is_alpha(byte: int) -> bool:
    return 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def _is_digit(byte: int) -> bool:
    return 0x30 <= byte <= 0x39


def _is_hex(byte: int) -> bool:
    return _is_digit(byte) or 0x41 <= byte <= 0x46 or 0x61 <= byte <= 0x66


def _read_control(data: bytes, pos: int) -> tuple[bytes, Optional[int], int]:
    """Read a control word at ``pos`` (a backslash).

    Returns ``(word, number, next_pos)``. ``word`` is empty for a control
    symbol; ``number`` is the optional signed parameter. ``next_pos`` is after
    the word, its parameter and one optional delimiter space.
    """
    length = len(data)
    j = pos + 1
    if j >= length or not _is_alpha(data[j]):
        return b"", None, min(length, pos + 2)
    k = j
    while k < length and _is_alpha(data[k]):
        k += 1
    word = data[j:k]
    sign = 1
    if k < length and data[k] in (0x2D, 0x2B):  # '-' or '+'
        if data[k] == 0x2D:
            sign = -1
        k += 1
    number_start = k
    while k < length and _is_digit(data[k]):
        k += 1
    number = sign * int(data[number_start:k]) if k > number_start else None
    if k < length and data[k] == 0x20:
        k += 1
    return word, number, k


def _decode_text(payload: bytes) -> str:
    """Reduce an ``\\objclass``/``\\objname`` payload to printable text."""

    text = payload.decode("latin-1", "replace")
    out: list[str] = []
    pos = 0
    length = len(text)
    while pos < length:
        char = text[pos]
        if char == "\\":
            if pos + 1 < length and (text[pos + 1].isalpha()):
                pos += 1
                while pos < length and text[pos].isalpha():
                    pos += 1
                if pos < length and text[pos] in "+-":
                    pos += 1
                while pos < length and text[pos].isdigit():
                    pos += 1
                out.append(" ")
                continue
            pos += 2
            continue
        if char not in "{}":
            out.append(char)
        pos += 1
    return " ".join("".join(out).split())


def _decode_objdata(payload: bytes, *, max_bytes: int) -> tuple[bytes, bool, bool]:
    """Decode an ``\\objdata`` destination into the embedded object bytes.

    The data is normally a hex run (whitespace allowed); some writers embed it
    as raw bytes with ``\\binN``. Returns ``(data, used_bin, odd_nibble)``.
    """
    out = bytearray()
    hex_digits = bytearray()
    used_bin = False
    odd_nibble = False

    def flush() -> None:
        nonlocal odd_nibble
        if len(hex_digits) % 2:
            odd_nibble = True
            del hex_digits[-1]
        out.extend(binascii.unhexlify(bytes(hex_digits)))
        hex_digits.clear()

    pos = 0
    length = len(payload)
    while pos < length:
        byte = payload[pos]
        if byte == 0x5C:
            word, number, next_pos = _read_control(payload, pos)
            if word == b"bin" and number is not None:
                flush()
                if number < 0:
                    raise RtfError("\\bin has a negative length")
                if next_pos + number > length:
                    raise RtfError("\\bin region extends past the end of the document")
                if len(out) + number > max_bytes:
                    raise RtfError("embedded object exceeds the configured cap")
                out.extend(payload[next_pos:next_pos + number])
                used_bin = True
                pos = next_pos + number
                continue
            pos = next_pos
            continue
        if _is_hex(byte):
            hex_digits.append(byte)
            if len(hex_digits) > max_bytes * 2 + 2:
                raise RtfError("embedded object exceeds the configured cap")
            pos += 1
            continue
        pos += 1
    flush()
    if len(out) > max_bytes:
        raise RtfError("embedded object exceeds the configured cap")
    return bytes(out), used_bin, odd_nibble


def parse_rtf(
    data: bytes,
    *,
    max_objects: int = 64,
    max_object_bytes: int = 64 * 1024 * 1024,
) -> RtfDocument:
    """Extract every embedded object from an RTF document.

    Raises ``RtfError`` only when the bytes are not an RTF document or an
    embedded object violates a bound; a well-formed RTF with no embedded
    object returns an empty ``objects`` list (which the caller reports, not
    hides).
    """
    if not data.startswith(b"{\\rtf"):
        raise RtfError("not an RTF document")

    document = RtfDocument(
        has_objemb=b"\\objemb" in data,
        has_objlink=b"\\objlink" in data,
        has_objupdate=b"\\objupdate" in data,
    )
    stack: list[_Group] = []
    pending_class = ""
    pending_name = ""
    length = len(data)
    pos = 0
    while pos < length:
        byte = data[pos]
        if byte == 0x7B:  # '{'
            stack.append(_Group(content_start=pos + 1))
            pos += 1
            continue
        if byte == 0x7D:  # '}'
            if stack:
                group = stack.pop()
                payload = data[group.content_start:pos]
                if group.name == b"objdata":
                    if len(document.objects) < max_objects:
                        decoded, used_bin, odd = _decode_objdata(
                            payload, max_bytes=max_object_bytes
                        )
                        document.objects.append(
                            RtfObject(
                                data=decoded,
                                objclass=pending_class,
                                objname=pending_name,
                                used_bin=used_bin,
                                odd_nibble=odd,
                            )
                        )
                    pending_class = ""
                    pending_name = ""
                elif group.name == b"objclass":
                    pending_class = _decode_text(payload)
                elif group.name == b"objname":
                    pending_name = _decode_text(payload)
            pos += 1
            continue
        if byte == 0x5C:  # '\\'
            word, number, next_pos = _read_control(data, pos)
            if word == b"bin" and number is not None:
                # Skip the raw region: it must not be scanned as RTF, or a
                # stray brace in binary data would corrupt group tracking.
                if number < 0:
                    raise RtfError("\\bin has a negative length")
                if next_pos + number > length:
                    raise RtfError("\\bin region extends past the end of the document")
                pos = next_pos + number
                continue
            if word in _DESTINATIONS and stack:
                stack[-1].name = word
                stack[-1].content_start = pos + 1 + len(word)
            pos = next_pos
            continue
        pos += 1
    document.unterminated = bool(stack)
    return document
