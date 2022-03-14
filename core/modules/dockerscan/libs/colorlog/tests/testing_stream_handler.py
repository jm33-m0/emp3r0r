import logging
import sys
import traceback


class TestingStreamHandler(logging.StreamHandler):
    """Raise errors to be caught by py.test instead of printing to stdout."""

    def handleError(self, record):
        _type, value, _traceback = sys.exc_info()
        raise value
