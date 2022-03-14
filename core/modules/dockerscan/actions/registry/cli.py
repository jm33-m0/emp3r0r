import click


from .model import *
from .console import *
from ..helpers import check_console_input_config


@click.group("registry", help="Docker registry actions")
@click.pass_context
def registry(ctx, **kwargs):
    pass


@registry.command(help="get a summary from remote registry")
@click.pass_context
@click.argument("registry")
def info(ctx, **kwargs):
    config = DockerAnalyzeInfoModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_analyze_info_in_console(config)


@registry.command(help="Push a docker image to remote registry")
@click.pass_context
@click.argument("registry")
@click.argument("local_image")
@click.argument("image_name")
@click.option("--tag", "-t", default="latest")
def push(ctx, **kwargs):
    config = DockerAnalyzePushModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_analyze_push_in_console(config)


@registry.command(help="upload a file to remote registry")
@click.pass_context
@click.argument("registry")
@click.argument("local_file")
@click.option("--remote-filename", "-r", "remote_filename")
def upload(ctx, **kwargs):
    config = DockerAnalyzeUploadModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_analyze_upload_in_console(config)


@registry.command(help="delete a image form remote registry")
@click.pass_context
@click.argument("registry")
@click.argument("image_name")
@click.option("--tag", "-t", default="latest")
def delete(ctx, **kwargs):
    config = DockerAnalyzePushModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_analyze_delete_in_console(config)
