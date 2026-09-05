#!/usr/bin/env python3
"""Emit deterministic direct arithmetic witnesses for C013 proposal/exchange actuators."""
import json,math
def legacy(sell,buy,quant):
 supply=1_000_000_000_000_000_000;n=sell+quant;relay=int(-supply*(1.0-math.pow(1.0+quant/n,0.0005)));supply+=relay;return int(buy*(math.pow(1.0+relay/supply,2000.0)-1.0))
ROWS=[
 {'scenario':'proposal-expiration','now':1700000000000,'expiration':1700262000000,'valid':True},
 {'scenario':'inject-ratio','token_balance':3000,'other_balance':1500,'token_quant':500,'other_quant':250},
 {'scenario':'trade-legacy','sell':1000000,'buy':2000000,'quant':50000,'received':legacy(1000000,2000000,50000)},
 {'scenario':'proposal-id-surface','maximum':98,'intentional_gaps':[27,36]},
 {'scenario':'trade-hardened','sell':1000000,'buy':2000000,'quant':50000,'received':legacy(1000000,2000000,50000)},
]
print(json.dumps({'schema':'c013-proposal-exchange-real.v1','rows':ROWS},sort_keys=True))
