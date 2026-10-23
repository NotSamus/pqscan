#!/usr/local/bin/python3
"""Fixed compiler wrapper used only by the isolated build recipe."""
import json
import os
from pathlib import Path
import sys
import uuid

args = sys.argv[1:]
if '-c' in args:
    (Path('/work/commands') / (uuid.uuid4().hex + '.json')).write_text(
        json.dumps({'directory': os.getcwd(), 'arguments': args}))
os.execv('/usr/bin/clang-14', ['/usr/bin/clang-14'] + args)
