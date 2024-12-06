```
11e36558: Remove isAtLeastR (Patrick Rohr <prohr@google.com>)
63dac211: Remove isAtLeastR() check (Patrick Rohr <prohr@google.com>)
d929a0f0: Use LazyLock rather than lazy_static. (Andrew Walbran <qwandor@google.com>)
9991b91a: Include DoH config as well as DoT config in dumpys. (Lorenzo Colitti <lorenzo@google.com>)
d68d651d: Don't call initDohLocked if there are no DoH servers. (Lorenzo Colitti <lorenzo@google.com>)
47f97f7c: Check that DoH provider list is not used if DDR is enabled, (Lorenzo Colitti <lorenzo@google.com>)
60bb7102: Disable DoT->DoH upgrade when DDR is enabled (Remi NGUYEN VAN <reminv@google.com>)
e26e4022: Do not check whether DoT server list is empty in setDoh (Mike Yu <yumike@google.com>)
96138070: Read DohParamsParcel and set to DoH engine (Mike Yu <yumike@google.com>)
d1c18200: Suppress some dead code warnings for DnsResolver (Stephen Hines <srhines@google.com>)
3f370bd8: Add force-no-test-error option to resolv_gold_test. (Jahin Imtiaz <jahinimtiaz@google.com>)
64391381: Fix stack corruption in _find_src_addr (Andrei Makeev <amaksoft@meta.com>)
f508d1f6: libc++fs is part of libc++ now. (Elliott Hughes <enh@google.com>)
```

