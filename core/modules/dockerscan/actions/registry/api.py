import random
import string

from typing import Union

from .model import *
from ...core.exceptions import DockerscanTimeoutError
from ..helpers import get_remote_registry_info, sanitize_url, \
    get_ssl_common_names

from .libs import *


def run_analyze_info_dockerscan(config: DockerAnalyzeInfoModel) -> \
        Union[DockerscanTimeoutError,
              RemoteRegistryDetails]:

    assert isinstance(config, DockerAnalyzeInfoModel)

    # Sanitize the URL
    target = sanitize_url(config.registry)

    # Detect remote version and if is authenticated
    version, is_auth = get_remote_registry_info(target)

    ssl_domains = get_ssl_common_names(target)

    # Build the results
    result = RemoteRegistryDetails(target,
                                   version,
                                   ssl_domains,
                                   is_auth)

    if result.version == 2:
        result.add_respositories(list_repositories_v2(target))

    return result


def run_analyze_push_dockerscan(config: DockerAnalyzePushModel):

    assert isinstance(config, DockerAnalyzePushModel)

    # Sanitize the URL
    target = sanitize_url(config.registry)

    link = push_image_v2(target,
                         config.image_name,
                         config.local_image,
                         config.tag)

    return link


def run_analyze_upload_dockerscan(config: DockerAnalyzeUploadModel):

    assert isinstance(config, DockerAnalyzeUploadModel)

    # Sanitize the URL
    target = sanitize_url(config.registry)

    # Build remote file name
    remote_filename = config.remote_filename
    if not remote_filename:
        characters = string.ascii_lowercase + string.digits

        remote_filename = "".join(random.choice(characters)
                                  for x in range(random.randint(5, 20)))

    link, _ = upload_content_v2(target,
                                remote_filename,
                                config.local_file)

    return link


def run_analyze_delete_dockerscan(config: DockerAnalyzePushModel):

    assert isinstance(config, DockerAnalyzePushModel)

    # Sanitize the URL
    target = sanitize_url(config.registry)

    delete_image_v2(target, config.image_name, config.tag)


__all__ = ("run_analyze_info_dockerscan", "run_analyze_push_dockerscan",
           "run_analyze_delete_dockerscan", "run_analyze_upload_dockerscan")
