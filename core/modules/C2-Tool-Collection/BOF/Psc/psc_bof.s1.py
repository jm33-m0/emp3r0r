from outflank_stage1.task.base_bof_task import BaseBOFTask


class PscBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("psc", base_binary_name="Psc")

        self.parser.description = "Show detailed information from processes with established TCP and RDP connections."
