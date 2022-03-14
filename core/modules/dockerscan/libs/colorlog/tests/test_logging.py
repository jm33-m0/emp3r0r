"""Test the colorlog.logging module."""

import logging

import colorlog


def test_logging_module(test_logger):
    test_logger(logging)


def test_colorlog_module(test_logger):
    test_logger(colorlog)


def test_colorlog_basicConfig(test_logger):
    colorlog.basicConfig()
    test_logger(colorlog.getLogger())
