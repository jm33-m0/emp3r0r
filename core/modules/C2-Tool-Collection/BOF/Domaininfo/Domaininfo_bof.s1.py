from outflank_stage1.task.base_bof_task import BaseBOFTask


class DomainInfoBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("Domaininfo")
        self.parser.description = (
            "Using Active Directory Domain Services to enumerate domain information."
        )
