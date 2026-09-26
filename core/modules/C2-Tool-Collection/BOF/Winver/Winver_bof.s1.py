from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class WinverBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("Winver")
        self.parser.description = "Display the version of Windows that is running, the build number and patch release (Update Build Revision)."
