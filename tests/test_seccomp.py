"""Tests for the sandbox seccomp profile.

The profile previously denied `ptrace` while the entrypoint ran the sample
*under strace*. That combination means the isolation profile silently disables
the monitoring the whole product depends on. These tests pin the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

SECCOMP_PATH = (
    Path(__file__).resolve().parents[1] / "engine" / "sandbox" / "seccomp.json"
)

# The sample and the tracers need these. Denying any of them breaks the product.
REQUIRED_ALLOWED = (
    "ptrace",       # strace attaches with this
    "socket",       # tcpdump opens a raw socket
    "execve",       # the sample has to run
    "clone",        # threads and forks
    "connect",      # observed network behavior
    "openat",       # observed filesystem behavior
    "write",        # observed output
    "setuid",       # entrypoint drops privileges via setpriv
    "setgid",
)


@pytest.fixture(scope="module")
def profile() -> dict:
    return json.loads(SECCOMP_PATH.read_text())


def _denied_syscalls(profile: dict) -> set[str]:
    denied: set[str] = set()
    for rule in profile.get("syscalls", []):
        if rule.get("action") in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS"):
            denied.update(rule.get("names", []))
    return denied


def test_profile_is_valid_json(profile: dict):
    assert isinstance(profile, dict)
    assert "syscalls" in profile


def test_default_action_is_allow_and_that_is_documented(profile: dict):
    """This is a deny-list, so it is hardening rather than a boundary. The file
    must say so, because a deny-list sold as isolation is a lie."""
    assert profile["defaultAction"] == "SCMP_ACT_ALLOW"
    comment = " ".join(profile.get("_comment", []))
    assert "NOT the sample/host boundary" in comment


@pytest.mark.parametrize("syscall", REQUIRED_ALLOWED)
def test_required_syscalls_are_not_denied(profile: dict, syscall: str):
    assert syscall not in _denied_syscalls(profile), (
        f"{syscall} must not be denied: the sandbox cannot work without it"
    )


def test_ptrace_remains_allowed_for_the_tracer(profile: dict):
    text = SECCOMP_PATH.read_text()
    assert "ptrace MUST stay allowed" in text
    assert "ptrace" not in _denied_syscalls(profile)


def test_dangerous_syscalls_are_denied(profile: dict):
    denied = _denied_syscalls(profile)
    for syscall in ("mount", "unshare", "setns", "init_module", "bpf", "kexec_load"):
        assert syscall in denied, f"{syscall} should be denied"


def test_architectures_are_restricted(profile: dict):
    archs = profile.get("architectures") or []
    assert "SCMP_ARCH_X86_64" in archs
    assert "SCMP_ARCH_AARCH64" in archs


def test_every_rule_has_a_comment_and_names(profile: dict):
    for rule in profile["syscalls"]:
        assert rule.get("names"), f"rule without names: {rule}"
        assert rule.get("comment"), f"rule without a comment: {rule}"
        assert rule.get("action")


def test_no_misspelled_errno_keys(profile: dict):
    """A previous revision shipped `erronoRet` on one rule, which meant that
    rule silently kept the default errno. Catch typos structurally."""
    allowed_keys = {"names", "action", "errnoRet", "comment"}
    for rule in profile["syscalls"]:
        extra = set(rule) - allowed_keys
        assert not extra, f"unexpected key(s) {extra} in rule {rule.get('names')}"


def test_errno_rules_declare_an_errno(profile: dict):
    for rule in profile["syscalls"]:
        if rule["action"] == "SCMP_ACT_ERRNO":
            assert rule.get("errnoRet") == 1, rule
