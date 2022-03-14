
from dockerscan import SharedConfig, String, Integer


class DockerScanModel(SharedConfig):
    ports = String(default="443,80,8080,8000,5000")
    target = String()
    concurrency = String(default="4")
    timeout = String(default="2")

__all__ = ("DockerScanModel",)
