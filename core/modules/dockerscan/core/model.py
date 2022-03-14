# -*- coding: utf-8 -*-

from booby import *


class SharedConfig(Model):
    verbosity = Integer(default=0)
    debug = Boolean(default=False)
    timeout = Integer(default=10)
