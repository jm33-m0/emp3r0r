import logging

from dockerscan import get_log_level, DockerscanTimeoutError, run_in_console, \
    DockerscanError

from .api import *
from .model import *
from ..helpers import sanitize_url, display_results_console

log = logging.getLogger('dockerscan')


def launch_dockerscan_analyze_info_in_console(config: DockerAnalyzeInfoModel):

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        try:
            log.console("Starting analyzing docker Registry...")
            log.console("Selected registry: '{}'".format(
                sanitize_url(config.registry)))

            results = run_analyze_info_dockerscan(config)

            # Show results
            log.console("Analysis finished. Results:")
            display_results_console(results, log)
        except DockerscanTimeoutError as e:
            log.console(e)


def launch_dockerscan_analyze_push_in_console(config: DockerAnalyzePushModel):

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        try:
            log.console("Starting pushing process to Registry...")
            log.console("Selected registry: '{}'".format(
                sanitize_url(config.registry)))

            link = run_analyze_push_dockerscan(config)

            # Show results
            log.console("Image uploaded")
            log.console("  > {}".format(link))

        except DockerscanTimeoutError as e:
            log.console(e)


def launch_dockerscan_analyze_upload_in_console(config: DockerAnalyzeUploadModel):

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        try:
            log.console("Uploading file to Registry...")
            log.console("Selected registry: '{}'".format(
                sanitize_url(config.registry)))

            link = run_analyze_upload_dockerscan(config)

            # Show results
            log.console("File location:")
            log.console("  > {}".format(link))

        except DockerscanTimeoutError as e:
            log.console(e)


def launch_dockerscan_analyze_delete_in_console(config: DockerAnalyzePushModel):

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        try:
            log.console("Starting delete process to Registry...")
            log.console("Selected registry: '{}'".format(
                sanitize_url(config.registry)))

            run_analyze_delete_dockerscan(config)

            log.console("Deleted images")

            # Show results
            log.console("Image uploaded")
        except DockerscanError as e:
            log.console(e)
        except DockerscanTimeoutError as e:
            log.console(e)


__all__ = ("launch_dockerscan_analyze_info_in_console",
           "launch_dockerscan_analyze_push_in_console",
           "launch_dockerscan_analyze_delete_in_console",
           "launch_dockerscan_analyze_upload_in_console")
