"""
This file is was taken idea from 'undocker' project. Thank for your work and
for shared the code. It was very useful to write this lib.

Undocker project:

https://github.com/larsks/undocker
"""

import os
import io
import re
import errno
import shutil
import os.path
import tarfile
import logging
import hashlib
import tempfile

try:
    import ujson as json
except ImportError:
    import json

from typing import Dict, Tuple, List, Union
from contextlib import closing, contextmanager
from dockerscan import DockerscanNotExitsError, DockerscanError

log = logging.getLogger("dockerscan")


# --------------------------------------------------------------------------
# Aux functions
# --------------------------------------------------------------------------
def _find_metadata_in_layers(img, id) -> dict:
    with closing(img.extractfile('%s/json' % id)) as fd:
        f_content = fd.read()
        if hasattr(f_content, "decode"):
            f_content = f_content.decode()
        yield json.loads(f_content)


def _find_layers(img, id):
    with closing(img.extractfile('%s/json' % id)) as fd:
        f_content = fd.read()
        if hasattr(f_content, "decode"):
            f_content = f_content.decode()
        info = json.loads(f_content)

    log.debug('layer = %s', id)
    for k in ['os', 'architecture', 'author', 'created']:
        if k in info:
            log.debug('%s = %s', k, info[k])

    yield id

    if 'parent' in info:
        pid = info['parent']
        for layer in _find_layers(img, pid):
            yield layer


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
@contextmanager
def open_docker_image(image_path: str):
    """
    This function is a context manager that allow to open a docker image and
    return their layers and the layers metadata.

    yields img:TarFile, first_layer, image_and_tag, manifest

    >>> with open_docker_image("~/images/nginx:latest") as (img, first_layer, image_and_tag, manifest):
            print(img)
            print(first_layer)
            print(image_and_tag)
            print(manifest)
    <tarfile.TarFile object at 0x10464be48>
    '2dc9f5ef4d45394b3bfedbe23950de81cabd941519f59e163d243a7d4f859622'
    {'nginx': 'latest'}
    [{'Layers': ['8327c7df0d8cfe8652fc4be305e15e516b1b5bb48e13bb39780a87a58316c522/layer.tar', '076538d7e850181c3cccbdbce3a0811698efad376e2c99a72a203493739c2bf2/layer.tar', '2dc9f5ef4d45394b3bfedbe23950de81cabd941519f59e163d243a7d4f859622/layer.tar'], 'RepoTags': ['nginx:latest'], 'Config': 'db079554b4d2f7c65c4df3adae88cb72d051c8c3b8613eb44e86f60c945b1ca7.json'}]

    """
    tmp_image = os.path.basename(image_path)

    if ":" in tmp_image:
        image, tag, *_ = tmp_image.split(":", maxsplit=1)
    else:
        image, tag = tmp_image, "latest"

    #: Docker image layers and tags
    image_layers_tags = {}

    with tarfile.open(image_path, "r") as img:

        # read the manifest
        manifest_content = read_file_from_image(img, "manifest.json")
        if hasattr(manifest_content, "decode"):
            manifest_content = manifest_content.decode()
        manifest_content = json.loads(manifest_content)

        # Read the repo info
        repo_content = read_file_from_image(img, "repositories")
        if hasattr(repo_content, "decode"):
            repo_content = repo_content.decode()

        repos_info = json.loads(repo_content)

        for name, tags in repos_info.items():
            image_layers_tags[name] = " ".join(tags)

        try:
            top_layers = repos_info[image][tag]
        except KeyError:
            image = list(image_layers_tags.keys())[0]
            tag = list(repos_info[image].keys())[0]

            top_layers = repos_info[image][tag]

        yield img, top_layers, image_layers_tags, manifest_content


@contextmanager
def extract_layer_in_tmp_dir(img: tarfile.TarFile,
                             layer_digest: str) -> str:
    """
    This context manager allow to extract a selected layer into a temporal
    directory and yield the directory path

    >>> with open_docker_image(image_path) as (img,
                                               top_layer,
                                               _,
                                               manifest):
            last_layer_digest = get_last_image_layer(manifest)
            with extract_layer_in_tmp_dir(img, last_layer_digest) as d:
                print(d)
    """
    with tempfile.TemporaryDirectory() as d:
        log.debug(" > Extracting layer content in temporal "
                  "dir: {}".format(d))

        extract_docker_layer(img, layer_digest, d)

        yield d


def get_last_image_layer(manifest: Dict) -> str:
    log.debug(" > Getting de last layer in the docker image")

    # Layers are ordered in inverse order
    return get_layers_ids_from_manifest(manifest)[-1]


@contextmanager
def modify_docker_image_metadata(image_path: str,
                                 output_docker_image: str):
    """
    This context manager allow to modify the image metadata

    This context manager expect a DockerscanReturnContextManager() exception to
     get the wanted information from context excution.

    This exception raise must have 2 parameters:
    - Last layer JSON metadata content
    - roote layer JSON metadata content

    >>> with modify_docker_image_metadata(image_path,
                                          output_docker_image) as (last_layer_json,
                                                                   root_layer_json):

            new_json_data_last_layer = update_layer_user(last_layer_json,
                                                         config.new_user)
            new_json_info_root_layer = update_layer_user(root_layer_json,
                                                         config.new_user)

            raise DockerscanReturnContextManager(new_json_data_last_layer,
                                                 new_json_info_root_layer)
    """

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

            _, json_info_root_layer = get_root_json_from_image(img)

            new_json_data_last_layer, new_json_info_root_layer = None, None

            try:
                yield json_info_last_layer, json_info_root_layer
            except Exception as e:
                if e.__class__.__name__ == "DockerscanReturnContextManager":
                    new_json_data_last_layer, new_json_info_root_layer = e.args

            if new_json_data_last_layer is None:
                return

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


def build_image_layer_from_dir(layer_name: str,
                               source_dir: str) -> Tuple[str, str]:
    """
    Create a new .tar docker layer from a directory content and return
    the new layer location and their digest

    >>> build_image_layer_from_dir("new_layer", "/tmp/new_layer/")
    "/tmp/new_layer/new_layer.tar", "076538d7e850181c3cccbdbce3a0811698efad376e2c99a72a203493739c2bf2"
    """
    if "tar" not in layer_name:
        layer_name = "{}.tar".format(layer_name)

    # Build new layer
    log.info(" > Building new {} layer image".format(layer_name))

    new_layer_path = os.path.join(source_dir, layer_name)
    with tarfile.open(new_layer_path, "w") as nl:
        nl.add(source_dir, arcname="/")

    # Calculating the digest
    log.info(" > Calculating new SHA256 hash for the new layer")

    with open(new_layer_path, "rb") as f:
        m = hashlib.sha256()
        m.update(f.read())
        new_layer_sha256 = m.hexdigest()

    return new_layer_path, new_layer_sha256


def build_manifest_with_new_layer(old_manifest: dict,
                                  old_layer_digest: str,
                                  new_layer_digest: str) -> dict:
    """
    Build a new manifest with the information of new layer and return the new
    manifest object

    :return: JSON with the new manifest
    """
    log.info(" > Updating the manifest")

    new_manifest = old_manifest.copy()

    for i, layer_id in enumerate(old_manifest[0]["Layers"]):
        if old_layer_digest in layer_id:
            new_manifest[0]["Layers"][i] = "{}/layer.tar" \
                                           "".format(new_layer_digest)
            break

    return new_manifest


def read_file_from_image(img: tarfile.TarFile,
                         file_path: str,
                         autoclose=False) -> bytes:
    if autoclose:
        with closing(img.extractfile(file_path)) as fd:
            return fd.read()
    else:
        return img.extractfile(file_path).read()


def replace_or_append_file_to_layer(file_to_replace: str,
                                    content_or_path: bytes,
                                    img: tarfile.TarFile):
    # Is content or path?
    if not os.path.exists(content_or_path):

        # Is a content
        t = tarfile.TarInfo(file_to_replace)
        t.size = len(content_or_path)
        img.addfile(t, io.BytesIO(content_or_path))

    else:
        # Is a path
        img.add(content_or_path, file_to_replace)


def add_new_file_to_image(file_to_append: str,
                          path_in_image: str,
                          image_path: str):
    file_to_append = os.path.abspath(file_to_append)

    with tempfile.NamedTemporaryFile() as tmp_out_image:

        with open_docker_image(image_path) as (
                img, top_layer, _, manifest):

            # 1 - Get the last layer in manifest
            old_layer_digest = get_last_image_layer(manifest)

            with extract_layer_in_tmp_dir(img, old_layer_digest) as d:

                # 2 - Copying new info
                copy_file_to_image_folder(d,
                                          file_to_append,
                                          path_in_image)

                new_layer_path, new_layer_digest = \
                    build_image_layer_from_dir("new_layer.tar", d)

                # 3 - Updating the manifest
                new_manifest = build_manifest_with_new_layer(manifest,
                                                             old_layer_digest,
                                                             new_layer_digest)

                # 4 - Create new docker image
                create_new_docker_image(new_manifest,
                                        tmp_out_image.name,
                                        img,
                                        old_layer_digest,
                                        new_layer_path,
                                        new_layer_digest)

        # Replace old image with the new
        shutil.copy(tmp_out_image.name,
                    image_path)


def _update_json_values(update_points: list,
                        values: Union[dict, str]):

    for point in update_points:
        if isinstance(values, dict):
            for var_name, var_value in values.items():
                point.append("{}={}".format(
                    var_name,
                    var_value
                ))
        elif isinstance(values, (str, bytes)):
            if hasattr(values, "decode"):
                values = values.decode()
            setattr(point, values)


def update_layer_environment_vars(json_info: dict,
                                  new_environment_vars: dict) -> dict:

    new_json_info = json_info.copy()

    update_points = [
        new_json_info["config"]["Env"],
        new_json_info["container_config"]["Env"]
    ]

    for point in update_points:
        for var_name, var_value in new_environment_vars.items():
            point.append("{}={}".format(
                var_name,
                var_value
            ))

    return new_json_info


def update_layer_user(json_info: dict,
                      new_user: str) -> dict:

    new_json_info = json_info.copy()

    update_points = [
        new_json_info["config"],
        new_json_info["container_config"]
    ]

    for point in update_points:
        point["User"] = new_user

    return new_json_info


def update_layer_entry_point(json_info: dict,
                             new_cmd: str) -> dict:

    new_json_info = json_info.copy()

    update_points = [
        new_json_info["config"],
        new_json_info["container_config"]
    ]

    for point in update_points:
        point["Entrypoint"] = new_cmd

    return new_json_info


def create_new_docker_image(manifest: dict,
                            image_output_path: str,
                            img: tarfile.TarFile,
                            old_layer_digest: str,
                            new_layer_path: str,
                            new_layer_digest: str,
                            json_metadata_last_layer: dict = None,
                            json_metadata_root: dict = None):
    with tarfile.open(image_output_path, "w") as s:

        for f in img.getmembers():
            log.debug("    _> Processing file: {}".format(f.name))

            # Add new manifest
            if f.name == "manifest.json":
                # Dump Manifest to JSON
                new_manifest_json = json.dumps(manifest).encode()
                replace_or_append_file_to_layer("manifest.json",
                                                new_manifest_json,
                                                s)

            #
            # NEW LAYER INFO
            #
            elif old_layer_digest in f.name:
                # Skip for old layer.tar file
                if f.name == "{}/layer.tar".format(old_layer_digest) or \
                        "/" not in f.name:

                    log.debug(
                        "    _> Replacing layer {} by {}".format(
                            f.name,
                            new_layer_digest
                        ))

                    replace_or_append_file_to_layer("{}/layer.tar".format(
                        new_layer_digest),
                        new_layer_path,
                        s)
                else:
                    #
                    # Extra files: "json" and "VERSION"
                    #
                    c = read_file_from_image(img, f.name)

                    if "json" in f.name:
                        # Modify the JSON content to add the new
                        # hash
                        if json_metadata_last_layer:
                            c = json.dumps(json_metadata_last_layer).encode()
                        else:
                            c = c.decode().replace(old_layer_digest,
                                                   new_layer_digest).encode()

                    replace_or_append_file_to_layer("{}/{}".format(
                        new_layer_digest,
                        os.path.basename(f.name)), c, s)

            #
            # Root .json file with the global info
            #
            elif "repositories" in f.name:
                c = read_file_from_image(img, f, autoclose=False)
                j = json.loads(c.decode())

                image = list(j.keys())[0]
                tag = list(j[image].keys())[0]

                # Update the latest layer
                j[image][tag] = new_layer_digest

                new_c = json.dumps(j).encode()

                replace_or_append_file_to_layer(f.name, new_c, s)

            elif ".json" in f.name and "/" not in f.name:
                c = read_file_from_image(img, f, autoclose=False)

                # Modify the JSON content to add the new
                # hash
                if json_metadata_root:
                    j = json_metadata_root
                else:
                    j = json.loads(c.decode())

                j["rootfs"]["diff_ids"][-1] = \
                    "sha256:{}".format(new_layer_digest)

                new_c = json.dumps(j).encode()

                replace_or_append_file_to_layer(f.name, new_c, s)

            # Add the rest of files / dirs
            else:
                s.addfile(f, img.extractfile(f))


def get_root_json_from_image(img: tarfile.TarFile) -> Tuple[str, dict]:
    """
    Every docker image has a root .json file with the metadata information.
    this function locate this file, load it and return the value of it and
    their name

    >>> get_docker_image_layers(img)
    ('db079554b4d2f7c65c4df3adae88cb72d051c8c3b8613eb44e86f60c945b1ca7', dict(...))
    """
    for f in img.getmembers():
        if f.name.endswith("json") and "/" not in f.name:
            c = img.extractfile(f.name).read()
            if hasattr(c, "decode"):
                c = c.decode()

            return f.name.split(".")[0], json.loads(c)

    return None, None


def get_file_path_from_img(image_content_dir: str,
                           image_file_path: str) -> str:

    if image_file_path.startswith("/"):
        image_file_path = image_file_path[1:]

    return os.path.join(image_content_dir, image_file_path)


def copy_file_to_image_folder(image_content_dir: str,
                              src_file: str,
                              dst_file: str) -> str:

    if dst_file.startswith("/"):
        dst_file = dst_file[1:]

    remote_path = os.path.join(image_content_dir, dst_file)
    remote_dir = os.path.dirname(remote_path)

    if not os.path.exists(remote_dir):
        os.makedirs(remote_dir)

    shutil.copy(src_file,
                remote_path)


def get_layers_ids_from_manifest(manifest: dict) -> List[str]:
    try:
        return [x.split("/")[0] for x in manifest[0]["Layers"]]

    except (IndexError, KeyError):
        raise DockerscanError("Invalid manifest")


def extract_docker_layer(img: tarfile.TarFile,
                         layer_id: str,
                         extract_path: str):
    with tarfile.open(fileobj=img.extractfile('%s/layer.tar' % layer_id),
                      errorlevel=0,
                      dereference=True) as layer:

        layer.extractall(path=extract_path)

        log.debug('processing whiteouts')
        for member in layer.getmembers():
            path = member.path
            if path.startswith('.wh.') or '/.wh.' in path:
                if path.startswith('.wh.'):
                    newpath = path[4:]
                else:
                    newpath = path.replace('/.wh.', '/')

                try:
                    log.debug('removing path %s', newpath)
                    os.unlink(path)
                    os.unlink(newpath)
                except OSError as err:
                    if err.errno != errno.ENOENT:
                        raise


def extract_docker_image(image_path: str,
                         extract_path: str):
    """Extract a docker image content to a path location"""
    if not os.path.exists(image_path):
        raise DockerscanNotExitsError("Docker image not exits at path: {}". \
                                      format(image_path))

    with open_docker_image(image_path) as (img, first_layer, _, _):
        layers = list(_find_layers(img, first_layer))

        if not os.path.isdir(extract_path):
            os.makedirs(extract_path)

        for layer_id in reversed(layers):
            log.debug('extracting layer %s', layer_id)

            extract_docker_layer(img, layer_id, extract_path)


def resolve_text_var_from_metadata_vars(text: str,
                                        image_metadata: dict) -> str:
    if "$" not in text:
        return text

    # Extract var name
    REGEX_EXTRACT_ENV_VAR = re.compile(r'''(\$[{]*[\w]+[}]*)''')
    REGEX_EXTRACT_ENV_VAR_NAME = re.compile(r'''(\$[{]*)([\w]+)([}]*)''')

    var_name_mark = REGEX_EXTRACT_ENV_VAR.search(text).group(1)
    var_name = REGEX_EXTRACT_ENV_VAR_NAME.search(var_name_mark).group(2)

    # Get image metadata vars
    image_metadata_environ = set()
    image_metadata_environ.update(image_metadata["config"]["Env"])
    image_metadata_environ.update(image_metadata["container_config"]["Env"])

    # Search in environment vars
    for env in image_metadata_environ:
        env_name, env_value = env.split("=", maxsplit=1)

        if var_name in env_name:
            text = text.replace(var_name_mark,
                                env_value)
            break

    return text


def get_entry_point_from_image_metadata(image_metadata: dict) -> str:
    # Build the launching command
    entrypoint = image_metadata["config"]["Entrypoint"]

    if type(entrypoint) is list:
        entrypoint = " ".join(entrypoint)

    # Locate the entry-point
    cmd = image_metadata["config"]["Cmd"]
    if type(cmd) is list:
        cmd = " ".join(cmd)

    if entrypoint and cmd:
        start_point = "{} {}".format(entrypoint, cmd)
    elif entrypoint and not cmd:
        start_point = entrypoint
    elif not entrypoint and cmd:
        start_point = cmd
    else:
        start_point = ""

    raw_start_point = start_point.strip()

    # replace environment vars, like ${HOME} in entry point
    return resolve_text_var_from_metadata_vars(raw_start_point,
                                               image_metadata)


def get_docker_image_layers(image_path: str) -> dict:
    """
    This function get a docker image layers and yield them

    >>> for x in get_docker_image_layers("/path/image.tar"):
            print(x)
    """
    with open_docker_image(image_path) as (img, top_layers, _, _):
        layers_meta = _find_metadata_in_layers(img, top_layers)

        for layer in layers_meta:
            yield layer


__all__ = ("open_docker_image", "extract_layer_in_tmp_dir",
           "get_last_image_layer", "get_docker_image_layers",
           "build_image_layer_from_dir", "build_manifest_with_new_layer",
           "get_file_path_from_img", "copy_file_to_image_folder",
           "extract_docker_image", "extract_docker_layer",
           "create_new_docker_image",
           "extract_docker_layer", "get_layers_ids_from_manifest",
           "update_layer_environment_vars", "get_root_json_from_image",
           "read_file_from_image", "update_layer_user",
           "modify_docker_image_metadata",
           "get_entry_point_from_image_metadata",
           "resolve_text_var_from_metadata_vars",
           "replace_or_append_file_to_layer",
           "update_layer_entry_point",
           "add_new_file_to_image")