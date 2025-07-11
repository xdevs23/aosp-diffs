```
28d0d72: Move AuthMgr AIDL rust build rule (Gil Cukierman <cukie@google.com>)
95273a9: make/library.mk: Trigger copying the headers on configheader changes (Bartłomiej Grzesik <bgrzesik@google.com>)
2744a75: lib/syscall-stubs: Trigger regeneration on configheader changes (Bartłomiej Grzesik <bgrzesik@google.com>)
4bfb6fa: service_manager: workaround known long names (Gil Cukierman <cukie@google.com>)
83b87d7: pvmdice: Add sign_data (Gil Cukierman <cukie@google.com>)
a086d34: pvmdice: Initial pvmdice implementation (Gil Cukierman <cukie@google.com>)
d9874e9: unittest-rust: Support `E: !Display` in `assert_ok` (Weston Carvalho <westoncarvalho@google.com>)
326c863: interface: arm_ffa: Add FFA_PARTITION_INFO_GET (Ayrton Munoz <ayrton@google.com>)
a26f872: Remove incorrect dependencies (Hasini Gunasinghe <hasinitg@google.com>)
a2b8504: unittest-rust: Reorganize items used in macros (Weston Carvalho <westoncarvalho@google.com>)
f0dc862: unittest-rust: Clean up `asserts` functions (Weston Carvalho <westoncarvalho@google.com>)
43351d7: unittest-rust: Manually format code inside macros (Weston Carvalho <westoncarvalho@google.com>)
a5971c2: make: Add MODULE_BINDGEN_BLOCK_TYPES to saved variables (Per Larsen <perlarsen@google.com>)
9e0db19: vmm_obj: Add rust bindings. (Brian Granaghan <granaghan@google.com>)
668f556: rust: trusty-log: Use OnceLock instead of static mut (Weston Carvalho <westoncarvalho@google.com>)
48eed09: Add rules.mk file for authmgr-be-impl crate (Hasini Gunasinghe <hasinitg@google.com>)
229b188: Add tests for the tipc raw lib (Dmitriy Filchenko <dmitriyf@google.com>)
aa6191f: Add a workaround for the issue in binder RPC session setup (Hasini Gunasinghe <hasinitg@google.com>)
3155343: Add a module with thread-safety and a flexible tipc user space API (Hasini Gunasinghe <hasinitg@google.com>)
e7026a7: rust: trusty-log: Silence new Rust 1.83 lint (Per Larsen <perlarsen@google.com>)
537dbe0: rust: libhashbrown: Enable raw-entry feature (Per Larsen <perlarsen@google.com>)
e8ca750: Add the ITrustedServicesHandover AIDL API (Hasini Gunasinghe <hasinitg@google.com>)
f90ebc6: Add rules.mk for authmgr-be crate (Hasini Gunasinghe <hasinitg@google.com>)
a3646fc: Add rules.mk files for the authmgr-common crates (Hasini Gunasinghe <hasinitg@google.com>)
6665d09: Add rules.mk file for dice-policy-builder (Hasini Gunasinghe <hasinitg@google.com>)
415e859: Add rules.mk file for authgraph_core_test (Hasini Gunasinghe <hasinitg@google.com>)
7baa447: service_manager: Add trusty service manager (Gil Cukierman <cukie@google.com>)
70d0ca3: include/user: Add `HSET_DEL_GET_COOKIE` (Dmitriy Filchenko <dmitriyf@google.com>)
510a16f: hwbcc: srv: introduce HwBccOps (Gil Cukierman <cukie@google.com>)
92dc0f1: interface: arm_ffa: Add VM availability messages (Andrei Homescu <ahomescu@google.com>)
1ac371e: make: bindgen: Add support for --blocklist-types (Ayrton Munoz <ayrton@google.com>)
9b30203: storage: Add Android module for interface (Weston Carvalho <westoncarvalho@google.com>)
526de74: storage: Run clang-format (Weston Carvalho <westoncarvalho@google.com>)
a289d8f: Add Widevine VM UUID to allowlist (Matt Feddersen <mattfedd@google.com>)
2c75327: Allow converting `trusty_sys::uuid` into `Uuid` (Dmitriy Filchenko <dmitriyf@google.com>)
28c5c1e: Add getters for `PortCfg` (Dmitriy Filchenko <dmitriyf@google.com>)
bab99ee: interface: arm_ffa: Add FFA_YIELD SMC opcode (Ayrton Munoz <ayrton@google.com>)
34e15d8: interface: arm_ffa: Bump FFA version to 1.2 (Ayrton Munoz <ayrton@google.com>)
156f9c5: interface: arm_ffa: Add FFA_MSG_SEND_DIRECT_REQ2/RESP2 (Ayrton Munoz <ayrton@google.com>)
338a3fd: swbcc: fix memory leakage in swbcc_init (Dan Fess <dfess@google.com>)
1292f93: rust: Fixup rust directiories to use direct link, not symlink (Donnie Pollitz <donpollitz@google.com>)
6480252: hwbcc: srv: initial rust server scaffolding (Gil Cukierman <cukie@google.com>)
dabd279: interface: arm_ffa: Update to version 1.1 (Andrei Homescu <ahomescu@google.com>)
c61406e: tipc: Update to zerocopy 0.8 (Alyssa Haroldsen <kupiakos@google.com>)
0fb8d97: hwbcc: Add unified request struct (Gil Cukierman <cukie@google.com>)
a34f150: make: Don't rustdoc libraries from Rust's stdlib (Per Larsen <perlarsen@google.com>)
dbe1bdd: make: aidl: Disable all lints for auto-generated Rust code (Andrei Homescu <ahomescu@google.com>)
39756c7: make: aidl: Add explicit dependency on the aidl binary (Andrei Homescu <ahomescu@google.com>)
8fe0536: dice: add diced_open_dice tests (Gil Cukierman <cukie@google.com>)
8a04bef: lib: compiler_builtins-rust: Update for Rust 1.82 support (Per Larsen <perlarsen@google.com>)
b7c0c79: lib: trusty-std: Adjustments for Rust 1.82 (Per Larsen <perlarsen@google.com>)
32c0b35: make: remove trailing slashes in trusty-std/rules.mk (Per Larsen <perlarsen@google.com>)
```

