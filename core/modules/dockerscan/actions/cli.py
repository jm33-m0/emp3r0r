import click
import logging

from dockerscan import global_options

from .scan.cli import scan
from .image.cli import image
from .registry.cli import registry

log = logging.getLogger('dockerscan')


@global_options()
@click.pass_context
def cli(ctx, **kwargs):
    ctx.obj = kwargs

cli.add_command(scan)
cli.add_command(image)
cli.add_command(registry)


if __name__ == "__main__" and __package__ is None:  # pragma no cover
    cli()
