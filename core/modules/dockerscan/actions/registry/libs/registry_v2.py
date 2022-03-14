import os
from typing import Set, Tuple, Union

import requests

from dxf import DXF
from dockerscan import DockerscanNotExitsError, DockerscanError


def _get_digest_by_tag(registry: str,
                       remote_image_name: str,
                       tag: str) -> str:
    insecure, registry_without_schema = _get_schema_and_security(registry)

    d = DXF(registry_without_schema,
            remote_image_name,
            insecure=insecure)

    try:
        return d.get_alias(alias=tag)[0]
    except (IndexError, requests.exceptions.HTTPError):
        return ""


def _get_schema_and_security(registry:str) -> tuple:
    insecure = True
    if registry.startswith("https://"):
        insecure = False

    if registry.startswith("http"):
        k = "://"
        registry_without_schema = registry[registry.find(k) + len(k):]
    else:
        registry_without_schema = registry

    return insecure, registry_without_schema


def list_repositories_v2(registry: str):

    # List repositories
    r = requests.get("{}/v2/_catalog".format(registry),
                     timeout=2,
                     allow_redirects=False,
                     verify=False)
    return r.json().get("repositories", [])


def upload_content_v2(registry: str,
                      remote_image_name: str,
                      local_image: str) -> Tuple[str, str]:
    """
    Push a content to Docker Registry and return the URL to access

    :return: a tuple (image_link: str, image_digest: str)
    """

    # Replace \\ -> none --> because in command line we can't write
    # "nginx:latest" without the \\ ---> "nginx\:latest"
    _image = os.path.abspath(local_image.replace("\\", ""))

    if not os.path.exists(_image):
        raise DockerscanNotExitsError("Local image selected do not exits")

    insecure, registry_without_schema = _get_schema_and_security(registry)

    d = DXF(registry_without_schema,
            remote_image_name,
            insecure=insecure)
    image_digest = d.push_blob(_image)

    # Image link
    img_link = "{schema}://{host}/v2/{repo}/blobs/sha256:{digest}".format(
        schema="http" if insecure else "https",
        host=registry_without_schema,
        repo=remote_image_name,
        digest=image_digest
    )

    return img_link, image_digest


def push_image_v2(registry: str,
                  remote_image_name: str,
                  local_image: str,
                  tag: str) -> str:
    """Push a content to Docker Registry and return the URL to access"""

    insecure, registry_without_schema = _get_schema_and_security(registry)

    download_link, digest = upload_content_v2(registry, remote_image_name, local_image)

    d = DXF(registry_without_schema,
            remote_image_name,
            insecure=insecure)
    d.set_alias(tag, digest)

    return download_link


def delete_image_v2(registry: str,
                    remote_image_name: str,
                    tag: str = "latest") -> Union[Set[str],
                                                  DockerscanError]:
    """
    delete selected images from remote repo.

        remote_image_name can contain regex expressions.

    :return: return a set() with the images deleted
    """
    insecure, registry_without_schema = _get_schema_and_security(registry)

    d = DXF(registry_without_schema,
            remote_image_name,
            insecure=insecure)

    removed = set()

    # Getting remote digest for the tag
    digest = _get_digest_by_tag(registry, remote_image_name, tag)

    if not digest:
        raise DockerscanError("> Can't obtain digest reference for selected "
                              "image / tag")

    try:
        if digest:
            # If digest found -> remote image is not a regex. Then remove it

            d.del_alias(digest)

            removed.add(remote_image_name)

        return removed

    except requests.exceptions.HTTPError:
        raise DockerscanError("> Registry does not support delete "
                              "operations. Default Docker Registry does not "
                              "support deletion. For more information see: "
                              "https://docs.docker.com/registry/"
                              "configuration/")

__all__ = ("list_repositories_v2", "upload_content_v2", "push_image_v2",
           "delete_image_v2")
