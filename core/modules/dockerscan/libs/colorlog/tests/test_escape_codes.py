"""Test the colorlog.escape_codes module."""

from colorlog.escape_codes import escape_codes, esc, parse_colors

import pytest


def test_esc():
    assert esc('1', '2', '3') == '\033[1;2;3m'


def test_reset():
    assert escape_codes['reset'] == '\033[0m'


def test_bold_color():
    assert escape_codes['bold_red'] == '\033[01;31m'


def test_fg_color():
    assert escape_codes['fg_bold_yellow'] == '\033[01;33m'


def test_bg_color():
    assert escape_codes['bg_bold_blue'] == '\033[104m'


def test_rainbow(create_and_test_logger):
    """Test *all* escape codes, useful to ensure backwards compatibility."""
    create_and_test_logger(
        "%(log_color)s%(levelname)s%(reset)s:%(bold_black)s%(name)s:"
        "%(message)s%(reset)s:"

        "%(bold_red)sr%(red)sa%(yellow)si%(green)sn%(bold_blue)sb"
        "%(blue)so%(purple)sw%(reset)s "

        "%(fg_bold_red)sr%(fg_red)sa%(fg_yellow)si%(fg_green)sn"
        "%(fg_bold_blue)sb%(fg_blue)so%(fg_purple)sw%(reset)s "

        "%(bg_red)sr%(bg_bold_red)sa%(bg_yellow)si%(bg_green)sn"
        "%(bg_bold_blue)sb%(bg_blue)so%(bg_purple)sw%(reset)s "
    )


def test_parse_colors():
    assert parse_colors('reset') == '\033[0m'


def test_parse_multiple_colors():
    assert parse_colors('bold_red,bg_bold_blue') == '\033[01;31m\033[104m'


def test_parse_invalid_colors():
    with pytest.raises(KeyError):
        parse_colors('false')
