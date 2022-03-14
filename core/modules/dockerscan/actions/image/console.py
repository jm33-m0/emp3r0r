import os
import logging

from dockerscan import get_log_level, run_in_console

from .api import *
from .model import *
from ..helpers import display_results_console

log = logging.getLogger('dockerscan')


def launch_dockerscan_image_info_in_console(config: DockerImageInfoModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting analyzing docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))

        results = run_image_info_dockerscan(config)

        # Display image summary
        log.console("Analysis finished. Results:")
        display_results_console(results, log)


def launch_dockerscan_image_extract_in_console(config: DockerImageInfoModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting the extraction of docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))

        run_image_extract_dockerscan(config)

        # Display image summary
        log.console("Image content extracted")


def launch_dockerscan_image_analyze_in_console(config: DockerImageAnalyzeModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting the analysis of docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))

        results = run_image_analyze_dockerscan(config)

        # Display image summary
        log.console("Analysis finished. Results:")
        display_results_console(results, log)


__all__ = ("launch_dockerscan_image_info_in_console",
           "launch_dockerscan_image_extract_in_console",
           "launch_dockerscan_image_analyze_in_console")
