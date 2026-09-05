#!/usr/bin/env python3
"""Emit deterministic direct witnesses for C013 market and miscellaneous actuators."""
import json
ROWS=[
 {'scenario':'market-sell','sell_quantity':1000,'buy_quantity':2000,'fee':0},
 {'scenario':'market-cancel','remaining_sell':750,'returned':750,'fee':0},
 {'scenario':'brokerage-update','before':20,'after':30},
 {'scenario':'energy-limit-update','before':1000000,'after':2000000},
 {'scenario':'setting-update','before':10,'after':25},
 {'scenario':'clear-abi','before_present':True,'after_present':False},
]
STORAGE_COMPATIBILITY={
 'decision':'unsupported_transaction_contract_types',
 'java_evidence':{
  'message_schema':'protocol/src/main/protos/core/contract/storage_contract.proto',
  'transaction_registry':'protocol/src/main/protos/core/Tron.proto',
  'actuator_registry':'actuator/src/main/java/org/tron/core/actuator',
  'behavior':'Messages and wallet RPC declarations remain, but the pinned ContractType enum has no storage variants and the production actuator package has no storage actuators to register.',
 },
 'rust_rejection':[{
  'message':message,
  'legacy_numeric_type':kind,
  'registry_error':f'InvalidContractType({kind})',
 } for message,kind in [
  ('protocol.BuyStorageContract',21),
  ('protocol.BuyStorageBytesContract',22),
  ('protocol.SellStorageContract',23),
 ]],
}
print(json.dumps({'schema':'c013-market-misc-real.v1','rows':ROWS,'storage_contract_compatibility':STORAGE_COMPATIBILITY},sort_keys=True))
