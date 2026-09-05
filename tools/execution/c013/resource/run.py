#!/usr/bin/env python3
"""Emit deterministic direct arithmetic witnesses for C013 resource actuators."""
import json
ROWS=[
 {'scenario':'freeze-v2-rounding','balance':8500000,'frozen':1500000},
 {'scenario':'cancel-expired-future','balance':12000000,'frozen':3000000},
 {'scenario':'delegate-preserves-weight','balance':8000000,'frozen':3000000},
 {'scenario':'undelegate-usage-migration','balance':10000000,'frozen':3000000},
 {'scenario':'new-model-no-tron-power-mint','balance':8500000,'frozen':3000000},
 {'scenario':'child-session-rollback','balance':10000000,'frozen':3000000},
]
print(json.dumps({'schema':'c013-resource-real.v1','rows':ROWS},sort_keys=True))
