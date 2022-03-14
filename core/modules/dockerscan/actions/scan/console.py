import logging

from dockerscan import get_log_level, run_in_console

from .api import *
from .model import *

log = logging.getLogger('dockerscan')


def launch_dockerscan_scan_in_console(config: DockerScanModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting the scanning")

        results = run_scan_dockerscan(config)

        log.console("Scanning results:")
        if results:
            for result in results:
                for host, open_ports in result.items():
                    log.console(" > Registry: {}".format(host))

                    for port, status, is_ssl in open_ports:
                        log.console("   - {}/TCP - [SSL: {}] - [{}]".format(
                            port,
                            "Enabled" if is_ssl else "Disabled",
                            status.upper()))

        else:
            log.console("No registries found")


__all__ = ("launch_dockerscan_scan_in_console",)
