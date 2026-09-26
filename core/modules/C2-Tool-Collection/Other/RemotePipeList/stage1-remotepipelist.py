from typing import List
from pathlib import Path

from outflank_stage1.implant import ImplantArch
from outflank_stage1.task import BaseTask


class RemotePipeListTask(BaseTask):
    BINARY_NAME = "RemotePipeList.exe"

    def __init__(self):
        super().__init__("remotepipelist", supported_architectures=[ImplantArch.INTEL_X64])

        self.parser.add_argument("target_ip")
        self.parser.add_argument("username")
        self.parser.add_argument("password")

        self.parser.description = "List the named pipes on a remote system"
        self.parser.epilog = "Examples:\n" "- remotepipelist 127.0.0.1 DOMAIN\\domainuser Password123"

    def run(self, arguments: List[str]):
        p = Path(__file__).with_name(self.BINARY_NAME)
        with p.open("rb") as f:
            self.set_binary_content(f.read())
            self.set_binary_content_name(self.BINARY_NAME)

        self.set_out_name("exec_dotnet")
        self.append_response(f'[*] Running .NET binary with name "{self.get_binary_content_name()}"\n\n')

        super().run(arguments)
