from dockerscan import SharedConfig, String


class DockerAnalyzeInfoModel(SharedConfig):
    registry = String()


class DockerAnalyzeUploadModel(SharedConfig):
    registry = String()
    local_file = String()
    remote_filename = String(default="")


class DockerAnalyzePushModel(SharedConfig):
    registry = String()
    local_image = String()
    image_name = String()
    tag = String(default="latest")


class DockerAnalyzeDeleteModel(SharedConfig):
    registry = String()
    image = String()


class RemoteRegistryDetails:

    def __init__(self,
                 address: str,
                 version: int,
                 domains: set,
                 has_authentication: bool):
        self.address = address
        self.version = version
        self.domains = domains
        self.has_authentication = has_authentication or False
        self.repositories = set()

    def add_respositories(self, repos: list):
        self.repositories.update(repos)

    def __repr__(self):
        return "<Registry:'{}' version={} / auth={}>".format(
            self.address,
            self.version,
            "Open" if not self.has_authentication else "Enabled"
        )

__all__ = ("DockerAnalyzeInfoModel", "RemoteRegistryDetails",
           "DockerAnalyzeUploadModel", "DockerAnalyzeDeleteModel",
           "DockerAnalyzePushModel")
