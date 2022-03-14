from dockerscan import SharedConfig, String


class DockerImageInfoModifyTrojanizeModel(SharedConfig):
    image_path = String()
    remote_addr = String()
    remote_port = String(default="2222")
    output_image = String(default="")
    custom_shell = String(default="")


class DockerImageInfoModifyUserModel(SharedConfig):
    image_path = String()
    output_image = String(default="")
    new_user = String(default="")


class DockerImageInfoModifyEntryPointModel(SharedConfig):
    image_path = String()
    new_entry_point = String()
    output_image = String(default="")
    binary_path = String(default="")


__all__ = ("DockerImageInfoModifyTrojanizeModel",
           "DockerImageInfoModifyUserModel",
           "DockerImageInfoModifyEntryPointModel")
