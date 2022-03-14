import tempfile

from ...core import DockerscanError

from .model import *
from .docker_api import *
from .image_analyzer import *


def run_image_info_dockerscan(config: DockerImageInfoModel) -> DockerImageInfo:
    assert isinstance(config, DockerImageInfoModel)

    # Get docker info
    docker_info = DockerImageInfo()
    for layer in get_docker_image_layers(config.image_path):
        docker_info.add_layer_info(layer)

    return docker_info


def run_image_extract_dockerscan(config: DockerImageExtractModel):
    assert isinstance(config, DockerImageExtractModel)

    extract_docker_image(config.image_path,
                         config.extract_path)


def run_image_analyze_dockerscan(config: DockerImageAnalyzeModel):
    assert isinstance(config, DockerImageAnalyzeModel)

    with tempfile.TemporaryDirectory() as tmp_dir:

        # Get docker info
        docker_info = DockerImageInfo()

        try:
            for layer in get_docker_image_layers(config.image_path):
                docker_info.add_layer_info(layer)
        except KeyError as e:
            raise DockerscanError(e)

        # Extract docker data
        extract_docker_image(config.image_path,
                             tmp_dir)

        # Run the analysis
        analysis_results = analyze_docker_image(tmp_dir, docker_info)

    return analysis_results


__all__ = ("run_image_info_dockerscan",
           "run_image_extract_dockerscan",
           "run_image_analyze_dockerscan",)
