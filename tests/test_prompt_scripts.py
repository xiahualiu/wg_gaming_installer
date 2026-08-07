"""Tests for wg_gaming_installer.prompt_scripts."""

import pytest

import wg_gaming_installer.prompt_scripts as prompt_scripts
from wg_gaming_installer.prompt_scripts import reconfigure_wg_prompt, validate_name


def test_validate_name_valid() -> None:
    assert validate_name("peer1")
    assert validate_name("my_peer")
    assert validate_name("a-b.c")
    assert validate_name("A")


def test_validate_name_empty() -> None:
    assert not validate_name("")


def test_validate_name_too_long() -> None:
    assert not validate_name("a" * 17)


def test_validate_name_invalid_chars() -> None:
    assert not validate_name("peer name")
    assert not validate_name("peer@1")
    assert not validate_name("peer/1")


@pytest.mark.parametrize(
    "answer,expected",
    [
        ("yes", True),
        ("y", True),
        ("no", False),
        ("n", False),
    ],
)
def test_reconfigure_wg_prompt(monkeypatch, answer: str, expected: bool) -> None:
    monkeypatch.setattr(prompt_scripts, "prompt", lambda *a, **k: answer)
    assert reconfigure_wg_prompt() is expected


def test_reconfigure_wg_prompt_invalid_then_valid(monkeypatch) -> None:
    answers = iter(["maybe", "yes"])
    monkeypatch.setattr(prompt_scripts, "prompt", lambda *a, **k: next(answers))
    assert reconfigure_wg_prompt() is True
