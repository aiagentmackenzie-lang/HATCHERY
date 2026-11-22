"""ELF analysis on both pyelftools header representations (D36).

pyelftools 0.33 returns enum *names* from the ELF header (``"EM_X86_64"``,
``"ET_EXEC"``); earlier versions return integers. D28-era code formatted the
value with ``:x``, which raised ``Unknown format code 'x' for object of type
'str'`` before any metadata was reported. These tests pin the normalisation:
the fixture parses with real metadata, both representations agree, and PIE is
decided from the number rather than from a string comparison.
"""

from __future__ import annotations

from pathlib import Path

from elftools.elf.elffile import ELFFile

from engine.intake.elf_analyzer import (
    ELF_MACHINES,
    ELF_TYPES,
    ELFAnalyzer,
    _ELF_MACHINE_NAMES,
    _ELF_TYPE_NAMES,
    _enum_label,
    _enum_number,
)

FIXTURE = Path(__file__).parent / "fixtures" / "acceptance" / "benign" / "hello.elf"


def test_header_enums_are_normalised_from_both_representations() -> None:
    for value in (62, "EM_X86_64"):
        assert _enum_number(value, _ELF_MACHINE_NAMES) == 62
        assert _enum_label(value, _ELF_MACHINE_NAMES, ELF_MACHINES, 4) == "x86-64"
    for value in (2, "ET_EXEC"):
        assert _enum_number(value, _ELF_TYPE_NAMES) == 2
        assert _enum_label(value, _ELF_TYPE_NAMES, ELF_TYPES, 4) == "EXEC (executable)"


def test_an_unknown_enum_is_reported_not_formatted_to_death() -> None:
    assert _enum_number(0x1234, _ELF_MACHINE_NAMES) == 0x1234
    assert _enum_label(0x1234, _ELF_MACHINE_NAMES, ELF_MACHINES, 4) == "0x1234"
    assert _enum_number("EM_MADE_UP", _ELF_MACHINE_NAMES) is None
    assert _enum_label("EM_MADE_UP", _ELF_MACHINE_NAMES, ELF_MACHINES, 4) == "EM_MADE_UP"


def test_the_fixture_parses_with_real_metadata() -> None:
    result = ELFAnalyzer().analyze(FIXTURE)

    assert result.error is None
    assert result.is_valid_elf is True
    assert (result.arch, result.bits, result.elf_type) == ("x86-64", 64, "EXEC (executable)")
    assert result.entry_point == 0x401000
    assert [section.name for section in result.sections] == ["", ".text", ".shstrtab"]
    assert result.security.is_pie is False
    assert result.security.is_stripped is True


def test_pie_is_decided_from_the_normalised_type() -> None:
    analyzer = ELFAnalyzer()
    with FIXTURE.open("rb") as handle:
        elf = ELFFile(handle)
        dynamic = analyzer._analyze_security(elf, [], 3)
        executable = analyzer._analyze_security(elf, [], 2)

    assert dynamic.is_pie is True
    assert executable.is_pie is False


def test_a_non_elf_is_a_named_error_not_a_traceback(tmp_path: Path) -> None:
    not_an_elf = tmp_path / "not-an-elf.bin"
    not_an_elf.write_bytes(b"%PDF-1.7\nnot an ELF at all\n")

    result = ELFAnalyzer().analyze(not_an_elf)

    assert result.is_valid_elf is False
    assert result.error and result.error.startswith("ELF parsing error:")
    assert "Traceback" not in result.error
