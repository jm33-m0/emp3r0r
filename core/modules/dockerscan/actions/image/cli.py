import click


from .model import *
from .console import *
from .modifiers.cli import *
from ..helpers import check_console_input_config


@click.group(help="Docker images commands")
@click.pass_context
def image(ctx, **kwargs):
    pass


@image.command(help="get docker image information")
@click.pass_context
@click.argument("image_path")
def info(ctx, **kwargs):
    config = DockerImageInfoModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_info_in_console(config)


@image.command(help="extract docker image content")
@click.pass_context
@click.argument("image_path")
@click.argument("extract_path")
def extract(ctx, **kwargs):
    config = DockerImageExtractModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_extract_in_console(config)


@image.command(help="looking for sensitive data from docker image")
@click.pass_context
@click.argument("image_path")
def analyze(ctx, **kwargs):
    config = DockerImageAnalyzeModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_analyze_in_console(config)

image.add_command(modify)
