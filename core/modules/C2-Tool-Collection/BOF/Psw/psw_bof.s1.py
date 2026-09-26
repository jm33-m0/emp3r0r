from outflank_stage1.task.base_bof_task import BaseBOFTask


class PswBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("psw", base_binary_name="Psw")
        self.parser.description = (
            "Show Window titles from processes with active Windows."
        )
