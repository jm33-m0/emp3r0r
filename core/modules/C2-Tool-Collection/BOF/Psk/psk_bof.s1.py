from outflank_stage1.task.base_bof_task import BaseBOFTask


class PskBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("psk", base_binary_name="Psk")

        self.parser.description = "Show detailed information from the windows kernel and loaded driver modules."
