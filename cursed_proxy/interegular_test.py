from cursed_proxy.proxy import CursedProxy

keys, values = CursedProxy.compile_regex(".*david.*")

print(f"Total Transitions (eBPF map keys): {len(keys)}")
print(f"Sample key: {keys[0] if keys else None}")
