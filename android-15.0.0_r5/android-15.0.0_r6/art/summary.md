```
8a5a51addd: Remove the shared dex data handling from oat_writer. (Martin Stjernholm <mast@google.com>)
6caf34aff9: Fix record trace entry points to correctly update entries (Mythri Alle <mythria@google.com>)
91f44f6bfe: Update volatile variables to C++20 (Santiago Aboy Solanes <solanes@google.com>)
56d62450fc: Store reference to the target class in MH object. (Almaz Mingaleev <mingaleev@google.com>)
e5d19588b1: Try to fix 2276-const-method-type-gc-cleanup. (Almaz Mingaleev <mingaleev@google.com>)
e23d7335d3: More suspend timeout improvements (Hans Boehm <hboehm@google.com>)
ed67125787: Revert "Do not unmap twice a mapping." (Greg Kaiser <gkaiser@google.com>)
4320035f70: LUCI: Revert 'Checkout full android tree for qemu-armv8' (David Srbecky <dsrbecky@google.com>)
6b7fc69a6a: Check receiver for null in invokeExact intrinsic. (Almaz Mingaleev <mingaleev@google.com>)
68742f619e: Fix incorrect assertion checking default values of system properties (Kunal Sareen <kunal.sareen@anu.edu.au>)
888d691d61: Offload `PreRebootDexoptJob.onUpdateReady` to a separate thread. (Jiakai Zhang <jiakaiz@google.com>)
8a5ecf2f67: Report dex2oat metrics to StatsD when dexopting (Stefano Cianciulli <scianciulli@google.com>)
a303efff17: Do not unmap twice a mapping. (Nicolas Geoffray <ngeoffray@google.com>)
3d68eb62b6: Add missing new line before dumping image spaces. (Nicolas Geoffray <ngeoffray@google.com>)
23387b1324: madvise moving space after uffd registration (Lokesh Gidra <lokeshgidra@google.com>)
c29ac896a1: Lower annotation log to WARNING (Santiago Aboy Solanes <solanes@google.com>)
cee56bcb90: Add missing return statement in UnstartedClassGetEnclosingClass (Santiago Aboy Solanes <solanes@google.com>)
44e2172427: Print the full relative address in Arm64 (Santiago Aboy Solanes <solanes@google.com>)
526a334716: Improve the GC strategy for the gtest of the class verification fuzzer's... (Ioana-Teodora Isar <ioanaisar@google.com>)
c326e0e9e3: Check that method is defined in the class in... (Almaz Mingaleev <mingaleev@google.com>)
e463f5d235: Fix standalone-apex-files. (Jiakai Zhang <jiakaiz@google.com>)
ff71a99515: Return early if trace is being stopped concurrently on another thread (Mythri Alle <mythria@google.com>)
31a3ffa963: Remove unused constants kProfileForground, kProfileBackground. (Richard Uhler <ruhler@google.com>)
df862a93fe: Consider MethodType/Handle annotations in VisitClassAnnotations (Santiago Aboy Solanes <solanes@google.com>)
d094263fe5: buildbot-vm.sh: use QEMU bundled with cuttlefish for arm64 as well. (Ulya Trofimovich <skvadrik@google.com>)
2f3ae8fa8d: riscv64 autovectorization needs a little more space. (Elliott Hughes <enh@google.com>)
3424f3e76b: Improve the GC strategy for the class verification fuzzer (Ioana-Teodora Isar <ioanaisar@google.com>)
4dad0f3614: Fix the offset discrepancy for --dump-method-and-offset-as-json. (Jiakai Zhang <jiakaiz@google.com>)
3df5451580: Fix discrepancy between oatdump offsets and ELF offsets. (Jiakai Zhang <jiakaiz@google.com>)
b1aeb15401: Disable usage of MADV_FREE for the heap. (Nicolas Geoffray <ngeoffray@google.com>)
3a15fe2475: Don't special case 0 for annotation set item (Santiago Aboy Solanes <solanes@google.com>)
d0bc68e1f4: riscv64: Add node Rol, fix InstructionBuilder (Anton Romanov <anton.romanov@syntacore.com>)
d0929a5662: RunCheckpoint cleanup (Hans Boehm <hboehm@google.com>)
956fbc47a6: Change arguments order in VarHandles::VarHandleInvokeAccessor. (Almaz Mingaleev <mingaleev@google.com>)
7c6f2ee63a: riscv64 testing: fix incremental `repo sync` (Ulya Trofimovich <skvadrik@google.com>)
506527aec2: riscv64 testing: use QEMU path from the cuttlefish repo. (Ulya Trofimovich <skvadrik@google.com>)
38e82add2a: Use MAP_FIXED_NOREPLACE on host (David Srbecky <dsrbecky@google.com>)
c24482f7d3: Change to a single StackHandleScope. (Christopher Ferris <cferris@google.com>)
da53336c50: Remove remnants of init_anonymous_namespace in libnativebridge and in te... (Martin Stjernholm <mast@google.com>)
25d8fb090c: Remove prebuilt_visibility from art module sdk and exports (Spandan Das <spandandas@google.com>)
744830cb24: Revert "riscv64: Add node Rol, fix InstructionBuilder" (Nicolas Geoffray <ngeoffray@google.com>)
88c7e963f7: Adds an interface to collect on demand art traces (Mythri Alle <mythria@google.com>)
b602b6e057: Fix leak introduced by aosp/3111768 (Hans Boehm <hboehm@google.com>)
b166ff7065: Revert "Introduce black-dense region in moving space" (Lokesh Gidra <lokeshgidra@google.com>)
22f222c91b: LUCI: Create couple (hidden) experimental builders. (David Srbecky <dsrbecky@google.com>)
e83264aa1e: Restrict exported symbols from libnative{loader,bridge} lazy libs. (Martin Stjernholm <mast@google.com>)
39927bc359: riscv64: Add node Rol, fix InstructionBuilder (Anton Romanov <anton.romanov@syntacore.com>)
e36cb730c4: Clean up UnflaggedApi. (Jiakai Zhang <jiakaiz@google.com>)
e736081033: Improve Unsafe.get* code generation on arm64. (Nicolas Geoffray <ngeoffray@google.com>)
c9e493db2a: Allow RunCheckpoint to lock mutator repeatedly (Hans Boehm <hboehm@google.com>)
6f2055f376: Remove unused variables. (Christopher Ferris <cferris@google.com>)
2c6ab1619b: Make dex2oats visible to //tools/vendor/google_prebuilts/arc. (Wei Li <weiwli@google.com>)
07749518c5: Introduce black-dense region in moving space (Lokesh Gidra <lokeshgidra@google.com>)
2c814207a1: Remove duplicate CPU options when launching QEMU/riscv64 VM. (Ulya Trofimovich <skvadrik@google.com>)
30289fde22: Revert "Log huge allocations and explicit concurrent GCs" (Hans Boehm <hboehm@google.com>)
e99f7ed19e: Intrinsify Unsafe/JdkUnsafe.arrayBaseOffset. (Nicolas Geoffray <ngeoffray@google.com>)
3fe46365ce: Don't filter default package list for first boot dexopt (Rashid Zaman <rashidz@meta.com>)
114656eb2f: Set context before bind-mount (Jooyung Han <jooyung@google.com>)
3b3257604f: LUCI: Checkout full android tree for qemu-armv8 (David Srbecky <dsrbecky@google.com>)
6123b270e6: LUCI: Remove riscv build-only builder (David Srbecky <dsrbecky@google.com>)
27f602cba6: Do not create MethodType objects in compiled code... (Almaz Mingaleev <mingaleev@google.com>)
f423eb1692: Remove unused dependencies. (Jiakai Zhang <jiakaiz@google.com>)
4e81c9ff0c: Remove libunwindstack from public.libraries.buildbot.txt. (Jiakai Zhang <jiakaiz@google.com>)
733e2ccf80: Revert^3 "Object.clone() allocates more movable objects" (Pechetty Sravani (xWF) <pechetty@google.com>)
17c82897fe: LUCI: Create shadow bucket to enable LED builds. (David Srbecky <dsrbecky@google.com>)
fc0ed57a5f: Revert^3 "Object.clone() allocates more movable objects" (Pechetty Sravani (xWF) <pechetty@google.com>)
d3472f2a4c: cleanup: change Set/GetIntrinsic in ArtMethod to use Intrinsics (Santiago Aboy Solanes <solanes@google.com>)
01d865abe8: Typo fix: instrinsic -> intrinsic (Santiago Aboy Solanes <solanes@google.com>)
8ff3ec2695: Don't devirtualize to an intrinsic invalid after the builder phase (Santiago Aboy Solanes <solanes@google.com>)
1647f4c5ed: Fix the watchdog test that may kill dex2oat with SIGABRT. (Martin Stjernholm <mast@google.com>)
f2c43572c8: Address follow-up comments from aosp/2721077. (Almaz Mingaleev <mingaleev@google.com>)
ab13b431d4: Delete monthly ramp flags. (Martin Stjernholm <mast@google.com>)
6adca9709d: Optimizations on arm64 for Unsafe.put* (Nicolas Geoffray <ngeoffray@google.com>)
ab8c7ae89b: Package ART gtest `art_standalone_dex2oat_cts_tests` in ART MTS. (Roland Levillain <rpl@google.com>)
8d62fc97fd: Refactor SweepArray into GarbageCollector for reuse (Lokesh Gidra <lokeshgidra@google.com>)
1956542906: Revert^2 "Object.clone() allocates more movable objects" (Hans Boehm <hboehm@google.com>)
7959b0a464: Check if the art_fake directory exists before copying fake libs. (Martin Stjernholm <mast@google.com>)
13ffd71e4a: LUCI: Explicitly use Ubuntu-20 for host builders. (David Srbecky <dsrbecky@google.com>)
54136ac527: Reland "Check alloc-stack in CMC IsMarked for black allocations" (Lokesh Gidra <lokeshgidra@google.com>)
24bbb4db97: Add ART JVM TI CTS tests to the ART MTS definition. (Roland Levillain <rpl@google.com>)
69b95f708d: Log huge allocations and explicit concurrent GCs (Hans Boehm <hboehm@google.com>)
d00577e3b5: Add REQUIRES(g_{dex,jit}_debug_lock) in debugger_interface.cc (David Srbecky <dsrbecky@google.com>)
4809d2fcee: Fix error propagation from dex2oat command execution in tests. (Martin Stjernholm <mast@google.com>)
e40d236781: Disable metrics reporting to StatsD in chroot tests (Stefano Cianciulli <scianciulli@google.com>)
fe6fbae51d: Add a fake heapprofd_client_api for chroot testing. (Jiakai Zhang <jiakaiz@google.com>)
4fad1f2882: Use a fake libartpalette in chroot tests and disable libartpalette_test. (Jiakai Zhang <jiakaiz@google.com>)
dd06f773e8: Support configuring additional partitions for Pre-reboot Dexopt. (Jiakai Zhang <jiakaiz@google.com>)
3394ab00a0: Add some debugging code for b/361916648. (Nicolas Geoffray <ngeoffray@google.com>)
d888982146: tests: avoid vector<const T> (Ryan Prichard <rprichard@google.com>)
c4287192e1: LUCI: Specify Android version to use. (David Srbecky <dsrbecky@google.com>)
b943ce4866: Replace statsd apex with a fake one for chroot testing. (Jiakai Zhang <jiakaiz@google.com>)
ddbcd4956b: Initialize metrics only for Zygote process or when forced via CLI arg (Stefano Cianciulli <scianciulli@google.com>)
c005493d56: cleanup: Use AddRegisterTemps where appropriate (Santiago Aboy Solanes <solanes@google.com>)
93163edd92: x86_64: Add instrinsic for  MethodHandle::invokeExact... (Almaz Mingaleev <mingaleev@google.com>)
46a77ad7d2: Fix dex2oat CTS test to work in 64-bit only builds. (Martin Stjernholm <mast@google.com>)
c9ea8725f4: Add LSE gtests for inserting type conversions. (Vladimir Marko <vmarko@google.com>)
074876edf2: Remove remnants of Partial LSE. (Vladimir Marko <vmarko@google.com>)
484e4f228d: Fix ahat accounting for cleaned native registrations (Jared Duke <jdduke@google.com>)
aface21c61: Use the appropriate enum constant in the fatal exit from the watchdog. (Martin Stjernholm <mast@google.com>)
aa5a5d1aaf: Improve handling of errors between fork and exec. (Martin Stjernholm <mast@google.com>)
7de4c946b2: Delete dead test class. (Martin Stjernholm <mast@google.com>)
94dab79b1c: ART: Clean up environment construction in gtests. (Vladimir Marko <vmarko@google.com>)
68fc9f4f23: Add `CtsJvmtiRunTest988HostTestCases` to the ART MTS definition. (Roland Levillain <rpl@google.com>)
581f40f661: Fix selinux failure in art_standalone_dex2oat_cts_tests on S. (Martin Stjernholm <mast@google.com>)
951a3d9208: Add `CtsJvmtiRunTest988HostTestCases` to the ART MTS definition. (Roland Levillain <rpl@google.com>)
f289a23eec: Reintroduce the TODO to enable art-aconfig-flags-lib for all targets. (Martin Stjernholm <mast@google.com>)
8cebfd7298: Add a fallback to bind-mount external libs elsewhere during Pre-reboot. (Jiakai Zhang <jiakaiz@google.com>)
e68e2282df: riscv64: Support Zbs ISA extension in ART disassembler (s.kozub <s.kozub@syntacore.com>)
f797b3fabb: Get Multidex checksums without opening dex files. (Jiakai Zhang <jiakaiz@google.com>)
b17478f8e8: riscv64: Support Zbs ISA extension in ART assembler (s.kozub <s.kozub@syntacore.com>)
389112846c: Optimize DexUseManagerLocal.findOwningPackage - Step 2. (Jiakai Zhang <jiakaiz@google.com>)
d3e41fd633: Regenerate ART test files (2024-08-21). (Roland Levillain <rpl@google.com>)
2b0a73bc7d: Remove the dependency on libselinux from odrefresh_test. (Jiakai Zhang <jiakaiz@google.com>)
01e082af26: Add conscrypt for the class verification fuzzer (Ioana-Teodora Isar <ioanaisar@google.com>)
3416a05cda: Clean up unused gtest jars from art_standalone_dex2oat_cts_tests. (Martin Stjernholm <mast@google.com>)
434a327234: Revert "Calculate the number of out vregs." (Vladimír Marko <vmarko@google.com>)
fe33c18114: Clean up dead code in artd_test. (Jiakai Zhang <jiakaiz@google.com>)
77c14d181d: Clean up instruction_set's switch cases regarding isas (Santiago Aboy Solanes <solanes@google.com>)
7effb7fac7: Print the intrinsic for all invokes when dumping the cfg (Santiago Aboy Solanes <solanes@google.com>)
c08fb725b5: Change `MakeCondition()` to take `IfCondition`... (Vladimir Marko <vmarko@google.com>)
1ea8807afe: Stop iterating VerifyNewArray when a hard failure appears (Santiago Aboy Solanes <solanes@google.com>)
1bf57ac401: Revert^2 "Remove ART Service tests from chroot tests." (Jiakai Zhang <jiakaiz@google.com>)
6767780c02: Add core-icu4j for Runtime (Ioana-Teodora Isar <ioanaisar@google.com>)
cc49e6ffd8: hiddenapi: Accept Unsupported/Sdk conflict (Atneya Nair <atneya@google.com>)
27eb1043f3: Revert "Check alloc-stack in CMC IsMarked for black allocations" (Lokesh Gidra <lokeshgidra@google.com>)
b73d535382: Revert "Object.clone() allocates more movable objects" (Hans Boehm <hboehm@google.com>)
7c89f49c2c: Revert "Object.clone() allocates more movable objects" (Hans Boehm <hboehm@google.com>)
2823b10ddd: Revert "Object.clone() allocates more movable objects" (Hans Boehm <hboehm@google.com>)
3f6e2fdf5d: Revert "Object.clone() allocates more movable objects" (Hans Boehm <hboehm@google.com>)
806ace6dfa: Bump app profile uncompressed size limit to 15MB. (Jiakai Zhang <jiakaiz@google.com>)
542a1c8e78: Use ScopedThreadSuspension to release mutator_lock_ (dimitry <dimitry@google.com>)
21afda7e64: Check alloc-stack in CMC IsMarked for black allocations (Lokesh Gidra <lokeshgidra@google.com>)
2e593076d3: ART: Clean up loop construction in gtests. (Vladimir Marko <vmarko@google.com>)
30970448e6: Separate the varhandle-perf tests (Santiago Aboy Solanes <solanes@google.com>)
73a49cd990: Revert "Remove ART Service tests from chroot tests." (Priyanka Advani (xWF) <padvani@google.com>)
389340dc00: Update buildbot-vm.sh to launch the right QEMU with correct CPU options. (Ulya Trofimovich <skvadrik@google.com>)
a18a521d86: Remove ART Service tests from chroot tests. (Jiakai Zhang <jiakaiz@google.com>)
323f0e045e: Reland "Fix 32-bit tests for `arm_v7_v8`." (Vladimír Marko <vmarko@google.com>)
a5001fed23: Object.clone() allocates more movable objects (Hans Boehm <hboehm@google.com>)
3b6024d5db: Clean up condition simplification. (Vladimir Marko <vmarko@google.com>)
4910586af2: Revert^2 "Implement transform from signed to unsigned compare" (Roman Artemev <roman.artemev@syntacore.com>)
b9075fca15: Add a gtest to automatically test the class verification fuzzer's corpus... (Ioana-Teodora Isar <ioanaisar@google.com>)
ef7d905b28: Revert^2 "Move always_enable_profile_code flag to art_performance" (Martin Stjernholm <mast@google.com>)
c698d34998: Make art-aconfig-flags visible to frameworks/base (Victor Chang <vichang@google.com>)
649a2e6c17: Simplify test configs by disabling append-bitness and pushing the whole ... (Martin Stjernholm <mast@google.com>)
275cf7423e: Revert "Implement transform from signed to unsigned compare" (Vladimír Marko <vmarko@google.com>)
7496a81f42: Implement transform from signed to unsigned compare (Roman Artemev <roman.artemev@syntacore.com>)
3e75615ad2: Calculate the number of out vregs. (Vladimir Marko <vmarko@google.com>)
ccbbe37bb1: Add reference to image version location (Roman Artemev <roman.artemev@syntacore.com>)
75e123b285: Fix IsPerformingCompaction check in VerifyOverflowReferenceBitmap() (Lokesh Gidra <lokeshgidra@google.com>)
3ad282d75d: Link libraries with unstable ABIs statically into libnativebridge-tests. (Martin Stjernholm <mast@google.com>)
606f8a4172: Allow .so files in the same directory as the test binary. (Martin Stjernholm <mast@google.com>)
bda2905666: riscv64: implement signum{float|double} and copySign{float|double} intri... (Olga Mikhaltsova <olga.mikhaltsova@syntacore.com...)
3244be57e9: Revert "Move always_enable_profile_code flag to art_performance" (Pechetty Sravani (xWF) <pechetty@google.com>)
033e808454: Add ishcheikin to the ART OWNERS (Santiago Aboy Solanes <solanes@google.com>)
936ada167f: riscv64: Fix Shl+Add simplification. (Vladimir Marko <vmarko@google.com>)
4018a7d772: ART: Clean up HIR construction in gtests. (Vladimir Marko <vmarko@google.com>)
bed0b477e8: Remove unnecessary Handle<> (dimitry <dimitry@google.com>)
f9af3fa4d5: Fix big negative dex2oatWallTimeMillis. (Jiakai Zhang <jiakaiz@google.com>)
8bf0b0a013: Promote two ART run-tests to presubmits (2024-08-09). (Roland Levillain <rpl@google.com>)
6d384196ae: Add `art_standalone_dex2oat_cts_tests` to ART Test Mapping and ART MTS. (Roland Levillain <rpl@google.com>)
fd20e55b80: Remove unnecessary std::move (Yi Kong <yikong@google.com>)
ca8a9fd091: Move always_enable_profile_code flag to art_performance (Mythri Alle <mythria@google.com>)
2e2c1ac96d: Support inline cache for boot image profile HRF in Profman. (Islam Elbanna <islamelbanna@google.com>)
a77898cedd: Revert "Add dirty-image-objects for ART module" (Priyanka Advani (xWF) <padvani@google.com>)
080239fc2f: Bind-mount /system{,_ext}/lib{,64} during Pre-reboot Dexopt. (Jiakai Zhang <jiakaiz@google.com>)
c6c500a217: Add dirty-image-objects for ART module (Dmitrii Ishcheikin <ishcheikin@google.com>)
948f4b70e6: Revert "Fix 32-bit tests for `arm_v7_v8`." (Vladimír Marko <vmarko@google.com>)
969335dd8d: testrunner: Fix test name parsing (Richard Neill <richard.neill@arm.com>)
52343d76d4: Fix 32-bit tests for `arm_v7_v8`. (Vladimir Marko <vmarko@google.com>)
bf1e9ceb79: Add native JNI call VMRuntime.getFullGcCount() (Eric Miao <ericymiao@google.com>)
398266ba87: Fix run-jdwp-tests.sh to use set_lunch_paths instead of setpaths. (Sorin Basca <sorinbasca@google.com>)
6f40f38674: Use variable sized ref-offset bitmap for fast VisitReferences() (Lokesh Gidra <lokeshgidra@google.com>)
f067186db7: Update x86-64 stack layout comment. (Almaz Mingaleev <mingaleev@google.com>)
4106d8ef0a: Replace soong config module types with selects (Cole Faust <colefaust@google.com>)
6d0c6524ab: Remove unused variables. (Christopher Ferris <cferris@google.com>)
430d5fb274: Use a aconfig flag to enable on demand tracing (Mythri Alle <mythria@google.com>)
dde4fc2372: buildbot-build.sh: add "libapexsupport" to riscv64 dependencies. (Ulya Trofimovich <skvadrik@google.com>)
e90e6f26ed: Clean up after exception delivery rewrite. (Vladimir Marko <vmarko@google.com>)
010414cb2b: Revert "Use JDK 17 to build RI hprof test dump" (Sorin Basca <sorinbasca@google.com>)
83fda9b80f: Also bypass loading libwalkstack.so for b/349878424. (Jiakai Zhang <jiakaiz@google.com>)
04bba053ca: Update test expectations due to renaming methods/fields in String (Victor Chang <vichang@google.com>)
8023683179: ART: Avoid deprecated implicit capture of `this`. (Vladimir Marko <vmarko@google.com>)
f3b8986d23: ART: Suppress -Wdeprecated-declarations for vixl includes. (Vladimir Marko <vmarko@google.com>)
66bbaa0243: Convert `art-libartd-libopenjdkd-host-dependency` to Android.bp (Nelson Li <nelsonli@google.com>)
3ea38e1d3e: Rework exception delivery and deoptimization (Chris Jones <christopher.jones@arm.com>)
0a8d0cd9a4: Class verification fuzzer: remove logging (Ioana-Teodora Isar <ioanaisar@google.com>)
1793c0985d: Add support for the experimental on-demand tracing (Mythri Alle <mythria@google.com>)
2339531e3a: Class verification fuzzer: fix Boot classpath error and add logging (Ioana-Teodora Isar <ioanaisar@google.com>)
c2152ff2d3: Promote one more ART run-test to presubmits (2024-07-27). (Roland Levillain <rpl@google.com>)
9c8893ef0c: Tag more ART run-tests as slow tests. (Roland Levillain <rpl@google.com>)
12dbf524a2: Regenerate ART test files (2024-07-29). (Roland Levillain <rpl@google.com>)
b012172c9c: Remove unused host snapshot (Kiyoung Kim <kiyoungkim@google.com>)
28a8166319: Use the guaranteed to work page size function. (Christopher Ferris <cferris@google.com>)
6979528e6e: Clean up the mounts for Pre-reboot Dexopt on system_server restart. (Jiakai Zhang <jiakaiz@google.com>)
8fd86be0bd: Startup methods should be compiled for non-low RAM devices (zhaoxuyang.6 <zhaoxuyang.6@bytedance.com>)
0684cb1369: Move a check out of thread destructor (Mythri Alle <mythria@google.com>)
f9c33ca817: Improve and cleanup post-compaction synchronization with mutators (Lokesh Gidra <lokeshgidra@google.com>)
19a4c4853e: Ignore import statements when parsing build.prop. (Jiakai Zhang <jiakaiz@google.com>)
e9ad234237: Add a class verification fuzzer (Ioana-Teodora Isar <ioanaisar@google.com>)
7640dd1396: Fix for b/349878424 (Nicolas Geoffray <ngeoffray@google.com>)
c7031c2acf: Convert `art-tools` to Android.bp (Nelson Li <nelsonli@google.com>)
e1dcb8a8e0: Revert "Only depend on aconfig for android and linux host builds." (Ivan Lozano <ivanlozano@google.com>)
0bc028f1e2: Don't abort on hard verifier error in odrefresh. (Jiakai Zhang <jiakaiz@google.com>)
a59ac6ddb5: Trim duplicate function symbols. (Christopher Ferris <cferris@google.com>)
ec92fc1c09: Initialize uffd-features without asserting SIGBUS (Lokesh Gidra <lokeshgidra@google.com>)
c4391b9b54: Avoid redundant GCs and waits when near OOM (Hans Boehm <hboehm@google.com>)
c2ed77e953: Update ahat version number to 1.7.3 (Eric Miao <ericymiao@google.com>)
20cb02cf71: Fix size of elements in resolvedMethodsArray and resolvedFieldsArray (zhaoxuyang.6 <zhaoxuyang.6@bytedance.com>)
70f6132cf7: Remove threaded-mode related code from CMC GC (Lokesh Gidra <lokeshgidra@google.com>)
623a4456a0: Mark methods that failed compilation as kAccCompileDontBother (Mythri Alle <mythria@google.com>)
bdb056806d: Move FuzzerCorpusTest from art/libdexfile/dex to art/runtime (Ioana-Teodora Isar <ioanaisar@google.com>)
a8ac825ec7: Make Dexdump::AccessFor an enum class (Ioana-Teodora Isar <ioanaisar@google.com>)
05d977cfcf: Optimize DexUseManagerLocal.findOwningPackage - Step 1. (Jiakai Zhang <jiakaiz@google.com>)
42096ba228: Skip non-existing second arch tests. (Jiakai Zhang <jiakaiz@google.com>)
cb97ccd23e: Add libdebugstore_cxx as an implementation lib dependency. (Jiakai Zhang <jiakaiz@google.com>)
20f6c15aed: Remove minor-fault related code from CMC GC (Lokesh Gidra <lokeshgidra@google.com>)
b2f1766aeb: Embed component-size shift in class-flags (Lokesh Gidra <lokeshgidra@google.com>)
841e48f39d: Stop the metrics thread in teardown in MetricsReporterTest (Stefano Cianciulli <scianciulli@google.com>)
65727194ab: Make ART debug APEX visible to aosp_mainline_modules (Kiyoung Kim <kiyoungkim@google.com>)
ffe52b0806: Allow madvise(MADV_HUGEPAGE) on moving space (Lokesh Gidra <lokeshgidra@google.com>)
399d238b18: Remove the second arch "libarttools" and "libartservice". (Jiakai Zhang <jiakaiz@google.com>)
c295d71a56: hprof: output header size of arrays (Mark Hansen <markhansen@google.com>)
59501af329: Use JDK21 for ART tests (Sorin Basca <sorinbasca@google.com>)
53ceab0bff: Revert^2 "Add support for multiple dirty-image-objects files" (Dmitrii Ishcheikin <ishcheikin@google.com>)
1fe9dc85a7: Add stubs to libdexfiled, to make the build system add it to provideNati... (Martin Stjernholm <mast@google.com>)
57fe2140f6: riscv64: Extend Shl+Add optimization for many Adds (Anton Romanov <anton.romanov@syntacore.com>)
91c9502fdf: Update InductionVarRange::Replace to match more cases (Santiago Aboy Solanes <solanes@google.com>)
5514bcedf5: Revert^2 "Use a current entry pointer instead of index for the method tr... (Mythri Alle <mythria@google.com>)
ff18b2cbfb: Promote more ART run-tests to presubmits (2024-07-12). (Roland Levillain <rpl@google.com>)
e7d0188efe: Regenerate ART test files (2024-07-12). (Roland Levillain <rpl@google.com>)
5091b5042c: Add 2279-aconfig-flags test (Victor Chang <vichang@google.com>)
a9f4aa93eb: Add an aconfig flag to use for testing. (Martin Stjernholm <mast@google.com>)
2f78b627a5: Offload `onStartJob` and `onStopJob` calls from the main thread. (Jiakai Zhang <jiakaiz@google.com>)
44b5204a81: Revert "Use a current entry pointer instead of index for the method trac... (Nicolas Geoffray <ngeoffray@google.com>)
beb0105d80: Also bind-mount "/system" when setting up chroot. (Jiakai Zhang <jiakaiz@google.com>)
e1f58a747f: Make art/build/flags visible to all subpackages of libcore/ (Victor Chang <vichang@google.com>)
b67495b6aa: Use a current entry pointer instead of index for the method trace buffer (Mythri Alle <mythria@google.com>)
3b92bd7e57: Move art-aconfig-flags-java-lib to core-libart in the bootclasspath (Victor Chang <vichang@google.com>)
f4c3b0f938: Update GC triggering documentation (Hans Boehm <hboehm@google.com>)
ebd162f44e: Add oryon to the supported cpu variant list (Roopesh Nataraja <quic_roopeshr@quicinc.com>)
e311c2d90f: Skip fixed rate tasks test on host (Sorin Basca <sorinbasca@google.com>)
98e1a5f6ea: Add link to flag docs and approximate ramp dates as comments. (Martin Stjernholm <mast@google.com>)
23d41e80e7: Don't override is_min in the UseFullTripCount case (Santiago Aboy Solanes <solanes@google.com>)
894751180d: Use atomics for find_array_class_cache_ (Mythri Alle <mythria@google.com>)
d668220ac5: Keep lists of ART run-tests ordered numerically in `regen-test-files`. (Roland Levillain <rpl@google.com>)
93b4b72316: Regenerate ART test files (2024-07-09). (Roland Levillain <rpl@google.com>)
09bd487c39: Refactor MTS test list file generation a bit in `regen-test-files`. (Roland Levillain <rpl@google.com>)
f617c4bafe: Add two more tests to the ART MTS test list file of "eng-only" tests. (Roland Levillain <rpl@google.com>)
8fb2a7f95f: Generate the ART MTS test list file of "eng-only" tests. (Roland Levillain <rpl@google.com>)
0c16114bac: Increase dex2oat timeout for VM tests. (Ulya Trofimovich <skvadrik@google.com>)
270cdb2bef: Style changes in `libnativebridge-tests`. (Roland Levillain <rpl@google.com>)
a8e94b7dda: Revert "Add support for multiple dirty-image-objects files" (Dmitrii Ishcheikin <ishcheikin@google.com>)
801c4c9d8c: Ensure x86 uses a byte register. (Nicolas Geoffray <ngeoffray@google.com>)
342fef7476: Fix code generation of Unsafe.putByte in x86 and x64. (Nicolas Geoffray <ngeoffray@google.com>)
d685b0e5d8: Redirect dex2oat logs to stderr for VM tests. (Ulya Trafimovich <skvadrik@google.com>)
b0b9465f5e: Skip Secondary dexopt for PrivacySandbox SDKs. (Anton Kulakov <akulakov@google.com>)
ca92bc74a3: Fix lock ordering problem in FindNativeLoaderNamespaceByClassLoader (dimitry <dimitry@google.com>)
ba209d65dd: Introduce a new lock for JIT data structures accessed by mutators. (Nicolas Geoffray <ngeoffray@google.com>)
db75f5b0c7: Forbid calling init repeatedly. (Jiakai Zhang <jiakaiz@google.com>)
dbd0d11683: Skip tests for embedded profile on user builds. (Jiakai Zhang <jiakaiz@google.com>)
d9c3f810c1: Limit the embedded profile feature to V+. (Jiakai Zhang <jiakaiz@google.com>)
67eb034e31: Only depend on aconfig for android and linux host builds. (Martin Stjernholm <mast@google.com>)
bfb7f772d1: Add support for multiple dirty-image-objects files (Dmitrii Ishcheikin <ishcheikin@google.com>)
c1d49fdab3: Allow com.android.libcore package for aconfig flags lib (Victor Chang <vichang@google.com>)
97948af7d0: Use TreeMultimap to identify duplicate bitmaps (Eric Miao <ericymiao@google.com>)
d26aa738de: Disable 2265-const-method-type-gc-cleanup in trace variant. (Almaz Mingaleev <mingaleev@google.com>)
55f1fed0c4: Revert^4 "x86_64: Add JIT support for LoadMethodType." (Almaz Mingaleev <mingaleev@google.com>)
6a44606e6b: Don't add compile task  if we already have optimized code (Mythri Alle <mythria@google.com>)
0933278fc4: Use art-aconfig-flags in service-art (Victor Chang <vichang@google.com>)
f513aece93: Accept immediate comments in x86(_64) assembly (Chris Jones <christopher.jones@arm.com>)
ebaa564631: [RESTRICT AUTOMERGE] Add mcts tags (Tongbo Liu <liutongbo@google.com>)
36a6e82709: Set default concurrency for post-boot reasons to 1. (Jiakai Zhang <jiakaiz@google.com>)
1d9301bc2e: Remove missing nocache output of art gtests (Spandan Das <spandandas@google.com>)
e2e951533d: Promote more ART run-tests to presubmits (2024-06-24). (Roland Levillain <rpl@google.com>)
663a706fef: Add a warning when generating an app image without a profile (Santiago Aboy Solanes <solanes@google.com>)
fc747e6c30: Revert "Use ALLOW_MISSING_DEPENDENCIES=true for host tools" (Tomasz Wasilczyk <twasilczyk@google.com>)
77eb738bb5: Regenerate ART test files (2024-06-24). (Roland Levillain <rpl@google.com>)
98325ca7c1: Fix 2275-pthread-name race (Hans Boehm <hboehm@google.com>)
8efa0b1129: Remove compact dex support from nterp. (Vladimir Marko <vmarko@google.com>)
729a39b6e1: Remove 202-thread-oome from known failures. (Pirama Arumuga Nainar <pirama@google.com>)
5d1c1fc4a9: [DO NOT MERGE] Add mcts tags (Tongbo Liu <liutongbo@google.com>)
330fb44dd9: Add 2275-pthread-name test for Thread.setName (Hans Boehm <hboehm@google.com>)
83cc7f2316: Add ART release APEX with imgdiag (Dmitrii Ishcheikin <ishcheikin@google.com>)
22a9432fde: Better document GcRoot (Hans Boehm <hboehm@google.com>)
ef83ca8a6c: Update tracing format V2 for non-streaming case (Mythri Alle <mythria@google.com>)
1eee0eca06: Hide most symbols in `ClassLinker`. (Vladimir Marko <vmarko@google.com>)
9344e7267e: Reduce 2029-contended-monitors iteration count (Hans Boehm <hboehm@google.com>)
9958427fa1: Fix typo in OatFileAssistant::OatFileStatusToString (Santiago Aboy Solanes <solanes@google.com>)
c749428752: Update VM test instructions: replace setup-ssh step with install-keys. (Ulya Trafimovich <skvadrik@google.com>)
ffac61a0a6: Fix typo in test expectation file. (Nicolas Geoffray <ngeoffray@google.com>)
9f75ef5c82: Use ALLOW_MISSING_DEPENDENCIES=true for host tools (Prashant Dubey <prashantdubey@google.com>)
974251aa41: Remove a failing DCHECK for IAE in an edge case. (Vladimir Marko <vmarko@google.com>)
65b4d39a8a: Update trace entry header format to not include initial values (Mythri Alle <mythria@google.com>)
c282701a62: Add aconfig flags for ART. (Martin Stjernholm <mast@google.com>)
b63adc919b: Revert^3 "x86_64: Add JIT support for LoadMethodType." (Santiago Aboy Solanes <solanes@google.com>)
6a4404c710: Revert "Make MethodType's DCHECK in JitCodeCache more accurate." (Almaz Mingaleev <mingaleev@google.com>)
54f5c27b02: Make MethodType's DCHECK in JitCodeCache more accurate. (Almaz Mingaleev <mingaleev@google.com>)
e459d9f34c: Ensure ART gtests are both or neither in CTS and MCTS. (Roland Levillain <rpl@google.com>)
d6c0adcd67: Ensure tests are both or neither in CTS and MCTS in `regen-test-files`. (Roland Levillain <rpl@google.com>)
c4eeff3335: Regenerate ART test files (2024-06-20). (Roland Levillain <rpl@google.com>)
0b9aeb87e6: Honor the Lint baseline file in `regen-test-files`, if present. (Roland Levillain <rpl@google.com>)
3aa213f18b: Update test 663- after D8 branch optimization fix (Santiago Aboy Solanes <solanes@google.com>)
08b60ea296: Eliminate never taken loops (Santiago Aboy Solanes <solanes@google.com>)
50a7c38d0e: Only increase the hotness for UI thread after startup. (Nicolas Geoffray <ngeoffray@google.com>)
d92a43f431: Revert^2 "x86_64: Add JIT support for LoadMethodType." (Almaz Mingaleev <mingaleev@google.com>)
fc87179fb4: Handle null source file when providing method information (Mythri Alle <mythria@google.com>)
818c357ec4: Make SetEntryPointFromQuickCompileCode just update the field. (Nicolas Geoffray <ngeoffray@google.com>)
c0e77cbf0b: Specify instruction format in `HInstructionBuilder`. (Vladimir Marko <vmarko@google.com>)
90b7adbd41: Don't invoke SetEntryPointFromQuickCompiledCode when relocating image. (Nicolas Geoffray <ngeoffray@google.com>)
8ac93e5c7f: Condition the use of parallel image loading. (Nicolas Geoffray <ngeoffray@google.com>)
65535f73cd: Make sure to mark classes/methods as startup. (islamelbanna <islamelbanna@google.com>)
05a5ff2a41: Move some classes from `runtime/` to `dex2oat/`. (Vladimir Marko <vmarko@google.com>)
9e9f99747a: Drop native static libs from the SDK. (Martin Stjernholm <mast@google.com>)
cad2e60903: riscv64: SystemArrayCopyChar/Int/Byte intrinsic (Aleksandr Soldatov <aleksandr.soldatov@syntacore...)
dccbcc35b3: Revert "Add debugging code for a potential leftover bug." (Nicolas Geoffray <ngeoffray@google.com>)
7b23aad719: Replace `ScopedAssertNoNewTransactionRecords`... (Vladimir Marko <vmarko@google.com>)
daf65911a4: Change CreateInternalStackTrace to return a mirror::Object. (Nicolas Geoffray <ngeoffray@google.com>)
7d4ebce2d8: Recognise system/system_ext as a system image partition path. (Martin Stjernholm <mast@google.com>)
b8d63dfa69: Link libnativeloader statically into its unit tests. (Martin Stjernholm <mast@google.com>)
9a3665096c: Revert "Add proposed trendy teams for CTS modules to be added in platinu... (Roland Levillain <rpl@google.com>)
386b1261d3: libc++fs: missed one last comment somehow... (Elliott Hughes <enh@google.com>)
fc26196d86: Add dobrota@, islamelbanna@, and prashantdubey@ to the ART OWNERS (Vali Dobrota <dobrota@google.com>)
afd86f9c87: Add debugging code for a potential leftover bug. (Nicolas Geoffray <ngeoffray@google.com>)
e00748b45a: riscv64: Implement `LongCondCBranch`. (Vladimir Marko <vmarko@google.com>)
4e8443e276: riscv64: Enable two assembler tests after clang update. (Vladimir Marko <vmarko@google.com>)
00e6586769: Add ART MTS eng-only tests to the test plan of ART MTS shard 03. (Roland Levillain <rpl@google.com>)
a087b9d4c7: Promote more ART run-tests to presubmits (2024-06-07). (Roland Levillain <rpl@google.com>)
d03f8fa229: Regenerate ART test files (2024-06-07). (Roland Levillain <rpl@google.com>)
f46e7c5272: Reset trace buffer and add few logs (Mythri Alle <mythria@google.com>)
342533ff99: Add java.math.BigInteger.BigIntegerTest#testConstructor to failed tests. (Nicolas Geoffray <ngeoffray@google.com>)
b9485ace61: Move `jni_stub_hash_map_test.cc` to `compiler/`. (Vladimir Marko <vmarko@google.com>)
3004a295d4: Revert^2 "Update test status after D8 fix" (Ian Zerny <zerny@google.com>)
c105cd8f7b: riscv64: Clean up after compressed branch fixup. (Vladimir Marko <vmarko@google.com>)
ed8e44a176: Fix static linking of libcrypto_for_art. (Martin Stjernholm <mast@google.com>)
b3a90a5bab: Move definitions into the binaries for things that the tests get via lib... (Martin Stjernholm <mast@google.com>)
dad7f49b84: Always set page agnostic flag. (Steven Moreland <smoreland@google.com>)
c07cf28705: arm/arm64: Relax register allocation for Baker RB. (Vladimir Marko <vmarko@google.com>)
cb64c645f0: Simplify LSE after Partial LSE removal. (Vladimir Marko <vmarko@google.com>)
```
