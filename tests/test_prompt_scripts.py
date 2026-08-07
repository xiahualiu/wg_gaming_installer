"""Tests for wg_gaming_installer.prompt_scripts."""

from wg_gaming_installer.prompt_scripts import validate_name


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
