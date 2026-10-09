"""Test-only builder for RTF fixtures with an embedded object.

The runtime parses RTF with the standard library (``engine/intake/rtf.py``);
tests need to *produce* an RTF wrapper around an OLE/CFB object, so this writes
one from the documented ``\\object``/``\\objdata`` shape and the suite
cross-validates the result against ``oletools.rtfobj`` — an independent RTF
OLE-object extractor — so a bug in HATCHERY's decoder cannot be mirrored by
its own fixture builder.

Nothing in this module ships; it is not collected by pytest (leading ``_``).
"""

from __future__ import annotations

import binascii


def _object_group(
    payload: bytes,
    *,
    objclass: str = "Package",
    objname: str = "invoice.doc",
    use_bin: bool = False,
    wrap: int = 128,
) -> bytes:
    if use_bin:
        body = b"\\bin" + str(len(payload)).encode("ascii") + b" " + payload
    else:
        hexdata = binascii.hexlify(payload)
        body = b"\n".join(hexdata[i:i + wrap] for i in range(0, len(hexdata), wrap))

    parts = [b"{\\object\\objemb\n"]
    if objclass:
        parts.append(b"{\\*\\objclass " + objclass.encode("ascii") + b"}\n")
    if objname:
        parts.append(b"{\\*\\objname " + objname.encode("ascii") + b"}\n")
    parts.append(b"{\\*\\objdata " + body + b"}\n")
    parts.append(b"}\n")
    return b"".join(parts)


def build_rtf_embedded(
    payload: bytes,
    *,
    objclass: str = "Package",
    objname: str = "invoice.doc",
    use_bin: bool = False,
    wrap: int = 128,
) -> bytes:
    """Wrap ``payload`` in the RTF embedded-object shape.

    With ``use_bin`` the object is written as a ``\\binN`` raw region instead of
    the usual hex run, which exercises the parser's binary-region handling.
    """

    group = _object_group(
        payload, objclass=objclass, objname=objname, use_bin=use_bin, wrap=wrap
    )
    return b"{\\rtf1\\ansi\\deff0\n" + group + b"}\n"


def build_rtf_objects(objects: list[dict]) -> bytes:
    """Wrap several objects in one RTF document (each a dict of group kwargs)."""

    body = b"".join(_object_group(**obj) for obj in objects)
    return b"{\\rtf1\\ansi\\deff0\n" + body + b"}\n"
