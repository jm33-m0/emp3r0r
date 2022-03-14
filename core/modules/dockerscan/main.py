#!/usr/bin/env python

import os
import sys

if len(sys.argv) == 1:
    args = os.environ["ARGS"]
    cmd = f"{sys.argv[0]} {args}"
    os.system(cmd)
    sys.exit(0)

libs = f"{os.getcwd()}/libs"

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, parent_dir)
sys.path.insert(1, libs)

import dockerscan

# Run the cmd
from dockerscan.actions.cli import cli

cli()
