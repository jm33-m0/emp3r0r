#!/usr/bin/env python

import sys
import os

print("\n\nLet's check some basic info")
os.system("python -m pip list")
print(f"sys.path = {sys.path}")
print(f"sys.argv = {sys.argv}")
print(f"sys.api_version = {sys.api_version}")
print(f"sys.platform= {sys.platform}")
print(f"ENV = {os.environ}")
print("Hello, if you see this line, emp3r0r's python is working")
