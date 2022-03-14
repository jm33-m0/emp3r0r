"""Fixtures that can be used in other tests."""

from __future__ import print_function

import inspect
import logging
import sys

import colorlog

import pytest
import testing_stream_handler


def assert_log_message(log_function, message, capsys):
    """Call a log function and check the message has been output."""
    log_function(message)
    out, err = capsys.readouterr()
    # Print the output so that py.test shows it when a test fails
    print(err, end='', file=sys.stderr)
    # Assert the message send to the logger was output
    assert message in err, 'Log message not output to STDERR'
    return err


@pytest.fixture()
def reset_loggers():
    logging.root.handlers = list()
    logging.root.setLevel(logging.DEBUG)


@pytest.fixture()
def test_logger(reset_loggers, capsys):
    def function(logger, validator=None):
        lines = [
            assert_log_message(logger.debug, 'a debug message', capsys),
            assert_log_message(logger.info, 'an info message', capsys),
            assert_log_message(logger.warning, 'a warning message', capsys),
            assert_log_message(logger.error, 'an error message', capsys),
            assert_log_message(logger.critical, 'a critical message', capsys)
        ]

        if validator is not None:
            for line in lines:
                valid = validator(line.strip())
                assert valid, "{!r} did not validate".format(line.strip())

        return lines
    return function


@pytest.fixture()
def create_and_test_logger(test_logger):
    def function(*args, **kwargs):
        validator = kwargs.pop('validator', None)
        formatter_cls = kwargs.pop('formatter_class', colorlog.ColoredFormatter)

        formatter = formatter_cls(*args, **kwargs)

        stream = testing_stream_handler.TestingStreamHandler()
        stream.setLevel(logging.DEBUG)
        stream.setFormatter(formatter)

        logger = logging.getLogger(inspect.stack()[1][3])
        logger.setLevel(logging.DEBUG)
        logger.addHandler(stream)

        return test_logger(logger, validator)
    return function
