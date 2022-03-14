"""Test that `from colorlog import *` works correctly."""

from colorlog import *  # noqa


def test_exports():
    assert set((
        'ColoredFormatter', 'default_log_colors', 'escape_codes',
        'basicConfig', 'root', 'getLogger', 'debug', 'info', 'warning',
        'error', 'exception', 'critical', 'log', 'exception'
    )) < set(globals())
