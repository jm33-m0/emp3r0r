import click

from .model import *
from .console import *
from ..helpers import check_console_input_config


@click.command(help="Search for Open Docker Registries")
@click.pass_context
@click.argument("target")
@click.option("--timeout", "-t", "timeout", help="timeout for each port-check")
@click.option("--ports", "-p", "ports",
              help="ports to test. i.e: 80,443,8000-8080")
@click.option("-c", "concurrency", help="Maximum concurrency scans")
def scan(ctx, **kwargs):
    config = DockerScanModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_scan_in_console(config)
