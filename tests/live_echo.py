#!/usr/bin/env python3
"""Offline stdin/EOF test double. It never imports or accesses MIDI."""
import json
import sys

values = []
ended = False
for line in sys.stdin:
    if line.strip() == 'END':
        ended = True
        break
    values.append(int(line))
print(json.dumps({'values': values, 'ended': ended}))
