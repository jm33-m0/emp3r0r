from typing import List, Tuple

from outflank_stage1.implant import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class WdToggleBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("WdToggle", supported_architectures=[ImplantArch.INTEL_X64])
        self.parser.description = "Patch lsass to enable WDigest credential caching and to circumvent Credential Guard (if enabled)."
