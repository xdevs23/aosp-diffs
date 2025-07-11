```
0436293045: Don't mount vendor-specific files. (Jiakai Zhang <jiakaiz@google.com>)
f675a98ccb: Fix `art` script for Golem. (Jiakai Zhang <jiakaiz@google.com>)
abf032d28d: Fix two issues in fast baseline compiler. (Nicolas Geoffray <ngeoffray@google.com>)
efe4925792: Run-test: Add 'ArtTest' atest target (David Srbecky <dsrbecky@google.com>)
b7dc01d1e4: Address review comments from aosp/2671457. (Nicolas Geoffray <ngeoffray@google.com>)
9c2a0a8bfc: arm64: fix reference unpoisoning in invokeExact intrinsic. (Almaz Mingaleev <mingaleev@google.com>)
2371fcce4b: Run-test: Remove sanitize_dex2oat_cmdline (David Srbecky <dsrbecky@google.com>)
3e4b2425a3: Fix libartpalette MCTS tests to not link the runtime statically. (Martin Stjernholm <mast@google.com>)
7ff689c7a1: Update LUCI config (David Srbecky <dsrbecky@google.com>)
89a9e799a8: Add more failing tests for host / gcstress / debug. (Nicolas Geoffray <ngeoffray@google.com>)
d6e56a41da: Delete SDM files on "pm delete-dexopt" and "pm compile --reset". (Jiakai Zhang <jiakaiz@google.com>)
9126e6fb21: Delete SDM and SDC files on a successful dexopt. (Jiakai Zhang <jiakaiz@google.com>)
f1cf622ecc: Support loading SDM files at runtime. (Jiakai Zhang <jiakaiz@google.com>)
751ffe4a74: Update the file GC to clean up SDM files. (Jiakai Zhang <jiakaiz@google.com>)
0f7d94bd99: Count SDM files into TYPE_DEXOPT_ARTIFACT in ART-managed file stats. (Jiakai Zhang <jiakaiz@google.com>)
0e235bd9b7: Add documentation about persistent states of the <SDM, SDC> file pair. (Jiakai Zhang <jiakaiz@google.com>)
d62d66437f: Omit file existence check on notifyDexContainersLoaded. (Jiakai Zhang <jiakaiz@google.com>)
4f163f8c78: Pass filename by reference. (Jiakai Zhang <jiakaiz@google.com>)
dcc5709295: Update input vdex selection logic for SDM. (Jiakai Zhang <jiakaiz@google.com>)
4383f83896: Create SDC files on dexopt. (Jiakai Zhang <jiakaiz@google.com>)
aa405ccd29: Add an artd method to create an SDC file. (Jiakai Zhang <jiakaiz@google.com>)
5045a8060a: Allow APEX versions in the OAT header to be overriden. (Jiakai Zhang <jiakaiz@google.com>)
b2d23dd55d: Add helper classes for reading and writing SDC files. (Jiakai Zhang <jiakaiz@google.com>)
6f3beba5e0: Move more path logic for tests to testing.cc, so it can be used without ... (Martin Stjernholm <mast@google.com>)
8badd48197: Run-test: Remove intermediate files from the build output. (David Srbecky <dsrbecky@google.com>)
aa42bf962c: Optimizing: Avoid unnecessary work in `LinearScan()`. (Vladimir Marko <vmarko@google.com>)
b67aed38aa: riscv64: Support RISC-V in JitLogger (Roman Artemev <roman.artemev@syntacore.com>)
e966e271e8: Use a raw string in `run_test_build.py`. (Vladimir Marko <vmarko@google.com>)
2fda8f36c8: Fix LSE to track type conversions correctly. (Vladimir Marko <vmarko@google.com>)
59aaec4d51: Revert^2 "Call target method in accessor MHs when it is set." (Almaz Mingaleev <mingaleev@google.com>)
a23f363908: Disable 055-enum-performance on tradefed (Mythri Alle <mythria@google.com>)
5ce388aa50: Do not override register storing MethodType in invokeExact. (Almaz Mingaleev <mingaleev@google.com>)
3d94fe6d11: Introduce abstract instruction `HFieldAccess`. (Vladimir Marko <vmarko@google.com>)
8a23cf5602: Don't redefine MREMAP_DONTUNMAP. (Elliott Hughes <enh@google.com>)
72810fa753: Dump references when found invalid without type-of (Lokesh Gidra <lokeshgidra@google.com>)
75cfb5844d: Fix iterating over long running method buffers when flushing (Mythri Alle <mythria@google.com>)
14c9edceee: Fix typo (Hans Boehm <hboehm@google.com>)
3210dddfbf: Increase the threshold for long running methods (Mythri Alle <mythria@google.com>)
6cc70a4e83: Revert^4 "Use nanoseconds for v2 method tracing" (Mythri Alle <mythria@google.com>)
c181671659: Fix StackWalker implementation with Proxy methods (Victor Chang <vichang@google.com>)
1abd2dcf05: Remove workaround for arm32 Linux 3.4 kernels. (Elliott Hughes <enh@google.com>)
0d81e9de89: libartbase (utils.cc): remove unused includes. (Elliott Hughes <enh@google.com>)
5b8e94a000: Update VIXL simulator features (Chris Jones <christopher.jones@arm.com>)
894b32807a: Re-enable warnings for VIXL (Chris Jones <christopher.jones@arm.com>)
f6359f8f6a: Clear thread-local interpreter cache, instead of sweeping it (Lokesh Gidra <lokeshgidra@google.com>)
76d4111105: Clarify native memory computation (Hans Boehm <hboehm@google.com>)
ce4b13518c: Remove min_sdk_verison property (Gurpreet Singh <gurpreetgs@google.com>)
49189d0836: Reland "Implement if instructions in fast baseline compiler." (Nicolas Geoffray <ngeoffray@google.com>)
38a1949da3: IsSealFutureWriteSupported isn't bionic-specific. (Elliott Hughes <enh@google.com>)
e5d43edd02: membarrier.cc: fix sense of kernel version test. (Elliott Hughes <enh@google.com>)
5a4fec7e90: Don't manually define syscall numbers. (Elliott Hughes <enh@google.com>)
ad0c8326a7: All the constants are now available on glibc too. (Elliott Hughes <enh@google.com>)
2c0dfe5c2e: membarrier.cc: reuse IsKernelVersionAtLeast(). (Elliott Hughes <enh@google.com>)
f1c6babf21: Change allocations from strings to object arrays in HeapTest#GCMetrics (Stefano Cianciulli <scianciulli@google.com>)
f3f82a4466: Call ProcessMarkStack() after each category of GC-root is visited (Lokesh Gidra <lokeshgidra@google.com>)
fc2f6b36c4: Revert "Enforce core platform hiddenapi checks for Baklava (reland)." (Martin Stjernholm <mast@google.com>)
0f6a15bb17: Clean up code that invalidated vdex files containing cdex. (Martin Stjernholm <mast@google.com>)
6654a2743f: 1963-add-to-dex-classloader-in-memory: remove workaround. (Elliott Hughes <enh@google.com>)
559dc08683: Fix string truncation for oat key value store. (Jiakai Zhang <jiakaiz@google.com>)
148a9d7dd6: Disable post-GC verifications for non-debug builds (Lokesh Gidra <lokeshgidra@google.com>)
11a5d95861: Fix --oat-location for mainline boot image extension. (Jiakai Zhang <jiakaiz@google.com>)
ca2362c05e: Remove memfd_create_compat(). (Elliott Hughes <enh@google.com>)
4370b86853: Ensure oat checksum determinism across hosts and devices. (Jiakai Zhang <jiakaiz@google.com>)
a6a75dba00: Remove SDM status from dump. (Jiakai Zhang <jiakaiz@google.com>)
4b88637ae7: Add a parser for processing long running method traces (Mythri Alle <mythria@google.com>)
abeeacd902: Fix SELinux denial on GMS Core's symlinks to secondary dex files. (Jiakai Zhang <jiakaiz@google.com>)
9f360eb65f: cpplint: disable new categories for upgrade preparation (Mike Frysinger <vapier@google.com>)
45ef50aad2: cpplint: disable new categories for upgrade preparation (Mike Frysinger <vapier@google.com>)
7e0bfd62fa: Revert "Pass the dex register array to NterpGetInstanceField." (Nicolas Geoffray <ngeoffray@google.com>)
71fcdfac2f: Test1963: remove unnecessary JNI. (Elliott Hughes <enh@google.com>)
1cdb151ce1: Ensure for any object in old-gen its class is also in there (Lokesh Gidra <lokeshgidra@google.com>)
0237ac8218: Pass the dex register array to NterpGetInstanceField. (Nicolas Geoffray <ngeoffray@google.com>)
2a5d4b397a: Os.memfd_create() now works on the host too. (Elliott Hughes <enh@google.com>)
336a1845af: Revert "Call target method in accessor MHs when it is set." (Almaz Mingaleev <mingaleev@google.com>)
ee8ab31257: Revert "Implement if instructions in fast baseline compiler." (Nicolas Geoffray <ngeoffray@google.com>)
1e7f64367f: Add find_unshared_pages tool (Dmitrii Ishcheikin <ishcheikin@google.com>)
629bb664e4: Improve log message when invalid reference is found post GC (Lokesh Gidra <lokeshgidra@google.com>)
3e768b62a0: Remove fugu workarounds from run-libcore-tests.py. (Elliott Hughes <enh@google.com>)
2505d2028a: Initialize callback for pulled atoms after boot is complete (Stefano Cianciulli <scianciulli@google.com>)
02a80d00ff: Revert^3 "Use nanoseconds for v2 method tracing" (Mythri Alle <mythria@google.com>)
b8764bb1b9: Revert "Convert cpplint-art-all to Android.bp" (Mike Frysinger <vapier@google.com>)
d952b6bb20: Call target method in accessor MHs when it is set. (Almaz Mingaleev <mingaleev@google.com>)
6ffde7f20f: Fix C++23 build. (Elliott Hughes <enh@google.com>)
568ccec2e7: Dump the event time in nanoseconds instead of timestamps (Mythri Alle <mythria@google.com>)
a7f2b44e84: Add a new API getExecutableMethodFileOffsets (Yu-Ting Tseng <yutingtseng@google.com>)
0c209c5244: Fix the logic of adjusting class-after-obj map in FinishPhase() (Lokesh Gidra <lokeshgidra@google.com>)
05396abbca: Enforce core platform hiddenapi checks for Baklava (reland). (Martin Stjernholm <mast@google.com>)
be727cf341: Remove `HInstruction::IsFieldAccess()`. (Vladimir Marko <vmarko@google.com>)
074c9a399c: Revert "Avoid computing post-compact address when not performing compact... (Lokesh Gidra <lokeshgidra@google.com>)
f667233594: Improve reference verification at end of GC cycle (Lokesh Gidra <lokeshgidra@google.com>)
0f1215ff58: Revert "Partially mitigate Clang compile hang" (David Srbecky <dsrbecky@google.com>)
5d16fdff4f: riscv64: handle invoke-virtual and invoke-direct in invokeExact (Anton Romanov <anton.romanov@syntacore.com>)
2e0be6e9f3: Add app/GC interference metrics in ART (Stefano Cianciulli <scianciulli@google.com>)
01003fe4b2: Use right type when using unique_ptr for array (Mythri Alle <mythria@google.com>)
aeafd882b9: Partially mitigate Clang compile hang (Yi Kong <yikong@google.com>)
2a720301c1: Avoid computing post-compact address when not performing compaction (Lokesh Gidra <lokeshgidra@google.com>)
8e3b7d7dbd: Compute references for unreachable instances too. (Richard Uhler <ruhler@google.com>)
05343671f7: Fix a memory leak in dum_trace used in 2246-trace-v2 (Mythri Alle <mythria@google.com>)
dedff45b6a: Add HeapTargetUtilization documentation (Hans Boehm <hboehm@google.com>)
de2b4b7e19: Don't include thread information in long running method traces (Mythri Alle <mythria@google.com>)
729bf33173: cpplint: disable new categories for upgrade preparation (Mike Frysinger <vapier@google.com>)
e29eb53ebf: Ensure the dex use database cannot grow unboundedly. (Jiakai Zhang <jiakaiz@google.com>)
b1bd98df0d: Turn string raw in testrunner.py (Santiago Aboy Solanes <solanes@google.com>)
88310308d9: Age dirty cards in MarkingPause for full GCs as well (Lokesh Gidra <lokeshgidra@google.com>)
2a482e0c8b: Revert "Enforce core platform hiddenapi checks for Baklava." (Jiakai Zhang <jiakaiz@google.com>)
992be819d0: Cleanup python version properties (Cole Faust <colefaust@google.com>)
31308e27c4: Implement if instructions in fast baseline compiler. (Nicolas Geoffray <ngeoffray@google.com>)
e280e935f1: Flag classes that have unresolved type checks. (Nicolas Geoffray <ngeoffray@google.com>)
3477cfd772: Re-order two lines for performance. (Nicolas Geoffray <ngeoffray@google.com>)
e36b5d67dc: Address follow-up comments from aosp/3409718. (Almaz Mingaleev <mingaleev@google.com>)
bcec5e63f3: Verify surviving objects post-GC (Lokesh Gidra <lokeshgidra@google.com>)
0ed0b7d7b2: Reject compact dex files on load. (Martin Stjernholm <mast@google.com>)
44656e8fc0: Enforce core platform hiddenapi checks for Baklava. (Martin Stjernholm <mast@google.com>)
94f4f3c764: Optimizing: Reduce size of `LocationSummary`. (Vladimir Marko <vmarko@google.com>)
225ed9282e: Remove `HInstruction::GetAllocator()`. (Vladimir Marko <vmarko@google.com>)
a04fda337f: Speed up `SsaRedundantPhiElimination`. (Vladimir Marko <vmarko@google.com>)
22cfc7f2de: Speed up DCE, CFRE and `ReplaceUsesDominatedBy()`... (Vladimir Marko <vmarko@google.com>)
12f7d1eb0f: Fast field lookup in nterp. (Nicolas Geoffray <ngeoffray@google.com>)
6d9c6c00c7: Change the thread / method info format for low overhead traces (Mythri Alle <mythria@google.com>)
75d941cef2: Add card-table verification at the end of GC for generational CMC (Lokesh Gidra <lokeshgidra@google.com>)
faa89ac4b6: Fix mid-gen-end alignment when deciding to skip compaction (Lokesh Gidra <lokeshgidra@google.com>)
710c7ae536: A few fixes when dumping long running traces (Mythri Alle <mythria@google.com>)
c9fd9b7cd6: [Sim] Support Simulator in the build system. (Chris Jones <christopher.jones@arm.com>)
e31ace2919: Revert^2 "Minimal hiddenapibypass breakage demo." (Almaz Mingaleev <mingaleev@google.com>)
17b204c244: Update boot image and system server profiles [M46C37P58S0PP] (art-benchmark-service <art-benchmark-service-bot...)
9aad1508e7: Disable -Wcast-function-type-mismatch (Aditya Kumar <appujee@google.com>)
c15df4f176: Allow accesses to unsupported APIs from platform to core platform. (Martin Stjernholm <mast@google.com>)
4fddbcf3da: I18n isn't updatable, so don't treat it as a core platform component. (Martin Stjernholm <mast@google.com>)
8b75fafb81: Convert cpplint-art-all to Android.bp (Nelson Li <nelsonli@google.com>)
4421e7c33e: Optimize field lookup. (Nicolas Geoffray <ngeoffray@google.com>)
4ea9dbdd63: Work-around for deapexer crash due to locale settings (David Srbecky <dsrbecky@google.com>)
5fea485598: Optimizing: Speed up SSA Liveness Analysis. (Vladimir Marko <vmarko@google.com>)
6da94fc231: Optimizing: Speed up GVN by using `BitVectorView<>`. (Vladimir Marko <vmarko@google.com>)
a0dedaaddd: Add logs after every GC to debug issues with generational CMC (Lokesh Gidra <lokeshgidra@google.com>)
3174b53128: Refactor OatFileAssistant - Step 1. (Jiakai Zhang <jiakaiz@google.com>)
a7d85a831f: Support loading an ART file from a zip file. (Jiakai Zhang <jiakaiz@google.com>)
191dd49487: Speed up `HGraph::BuildDominatorTree()`. (Vladimir Marko <vmarko@google.com>)
0ecda2b3ac: Fix post-compact object address comparison in FinishPhase() (Lokesh Gidra <lokeshgidra@google.com>)
4e244861ab: Check native-roots (to young-gen) of all objects during marking (Lokesh Gidra <lokeshgidra@google.com>)
69f0fd807b: Remove extraneous apex_available from art tests (Colin Cross <ccross@android.com>)
52ea66f5bd: Report atoms to StatsD also when DexOpt is skipped (Stefano Cianciulli <scianciulli@google.com>)
16a42183af: Introduce `BitVectorView<>`. (Vladimir Marko <vmarko@google.com>)
c6aa6f7f1c: Use a more concise binary format when dumping long running methods (Mythri Alle <mythria@google.com>)
b10a134d63: Revert "Temporarily enable post-gc heap verification" (Pechetty Sravani (xWF) <pechetty@google.com>)
ee712c170c: Temporarily enable post-gc heap verification (Lokesh Gidra <lokeshgidra@google.com>)
50f41ab016: [Sim] Build target boot image for simulator (Chris Jones <christopher.jones@arm.com>)
11bd0da6cf: Readability fixes and some API cleanup in art::hiddenapi::ApiList. (Martin Stjernholm <mast@google.com>)
c154e7f571: Use host_linux instead of linux_glibc to support musl as well (Aditya Kumar <appujee@google.com>)
4b40bb5932: Revert "art: Refactor buildbot-build.sh to run test targets directly" (David Srbecky <dsrbecky@google.com>)
efd0dec24f: Avoid mocking the Process class in DexUseManagerTest. (Jiakai Zhang <jiakaiz@google.com>)
0e80913124: [Sim] Add a restricted mode setup (Chris Jones <christopher.jones@arm.com>)
0c35b6b7b0: dex2oat: Faster .bss and *.rel.ro data collection. (Vladimir Marko <vmarko@google.com>)
0921300b49: Move some utils from `compiler/` to `dex2oat/`. (Vladimir Marko <vmarko@google.com>)
ea5184ac8e: dex2oat: Change reported data for `--dump-timings`. (Vladimir Marko <vmarko@google.com>)
b47314beb4: art: Refactor buildbot-build.sh to run test targets directly (Nelson Li <nelsonli@google.com>)
2f42cd2d9a: Add logging information when memory corruption takes place (Lokesh Gidra <lokeshgidra@google.com>)
1955b77efa: Implement Async Pre-reboot Dexopt using update_engine API. (Jiakai Zhang <jiakaiz@google.com>)
9b365d3fe7: Support SDM files for multiple ISAs. (Jiakai Zhang <jiakaiz@google.com>)
ff7c1a9d5b: Fix lock level violations when dumping low overhead traces (Mythri Alle <mythria@google.com>)
73067c5af4: Update test expectation. (Nicolas Geoffray <ngeoffray@google.com>)
21cd7790cb: Optimizing: Remove dead Partial LSE test helpers. (Vladimir Marko <vmarko@google.com>)
9a4f8f8fe5: `AllocArt{Field,Method}Array()` requires mutator lock. (Vladimir Marko <vmarko@google.com>)
17c7ed2de7: Refactor `Instrumentation` out of `Runtime`. (Vladimir Marko <vmarko@google.com>)
cb3c3b2819: Do not inline a method that was marked as un-compilable. (Nicolas Geoffray <ngeoffray@google.com>)
b4d4a7c4c3: Don't use suspend all scope when dumping low overhead traces (Mythri Alle <mythria@google.com>)
39b153dff3: Support loading a VDEX file from a zip file at an address. (Jiakai Zhang <jiakaiz@google.com>)
5bcb526ba5: Support loading an ELF file from a zip file. (Jiakai Zhang <jiakaiz@google.com>)
70c0403aff: Optimizing: Add comments to `HInstruction::Add{,Env}UseAt()`. (Vladimir Marko <vmarko@google.com>)
3dde8e37a4: Update the implementation of lowoverhead tracing start (Mythri Alle <mythria@google.com>)
b03ab575b9: Only locking error and runtime throws should retrigger verification. (Nicolas Geoffray <ngeoffray@google.com>)
143d99f3ef: Optimizing: Rename `GetNextInstructionId()`. (Vladimir Marko <vmarko@google.com>)
e82d04b374: Optimizing: Speed up `HInstruction::Add{,Env}UseAt()`. (Vladimir Marko <vmarko@google.com>)
474e99956e: Refactor `ArtMethod` entrypoint initialization. (Vladimir Marko <vmarko@google.com>)
e7776615ea: Optimizing: Do not crash on bad `filled-new-array` opcode. (Vladimir Marko <vmarko@google.com>)
3075cc5e59: Pass the instance type in the AbstractMethodError message. (Nicolas Geoffray <ngeoffray@google.com>)
34c2dc9824: Do most of `ClassLinker::LoadClass()` in native state. (Vladimir Marko <vmarko@google.com>)
fef892b06f: Clarify the exact behavior of "pm compile --reset". (Jiakai Zhang <jiakaiz@google.com>)
560dd5f2bd: Fix OatFileAssistant non-determinism in choosing best oat files. (Jiakai Zhang <jiakaiz@google.com>)
ac3a3207c6: Avoids copy using float registers on aarch64 for faster memcpy (Victor Chang <vichang@google.com>)
8c80783c05: verifier: Reject `filled-new-array/-range` with `[J`/`[D`. (Vladimir Marko <vmarko@google.com>)
ce10dc6fbd: cpplint: disable new categories for upgrade preparation (Mike Frysinger <vapier@google.com>)
48bdb4ec03: Initialize the buffer for longrunning method traces (Mythri Alle <mythria@google.com>)
1151690044: Optimize HConstantFoldingVisitor::PropagateValue (Santiago Aboy Solanes <solanes@google.com>)
1a3ce3502d: Refactor ElfFile. (Jiakai Zhang <jiakaiz@google.com>)
1802832343: Refactor OatFileAssistant - Step 3. (Jiakai Zhang <jiakaiz@google.com>)
bde490d3c2: Refactor OatFileAssistant - Step 2. (Jiakai Zhang <jiakaiz@google.com>)
153ccc814f: Revert^2 "Remove old and duplicated logic in picking up the best artifac... (Jiakai Zhang <jiakaiz@google.com>)
4ef61af6f7: Update dirty-image-objects generation how-to (Dmitrii Ishcheikin <ishcheikin@google.com>)
99f6baed65: Fix deallocation of OatHeader. (Nicolas Geoffray <ngeoffray@google.com>)
0b5b2f22f2: Double suspend timeouts for user builds (Hans Boehm <hboehm@google.com>)
506532f701: Account for the new debug store footer in libartpalette tests (Mohamad Mahmoud <mohamadmahmoud@google.com>)
4bcbbe50ab: Extend suspend timeout for debug activities (Hans Boehm <hboehm@google.com>)
f937d3d230: s/oat_location/oat_filename/ when opening an oat file (Yu-Ting Tseng <yutingtseng@google.com>)
a334d1c710: verifier: Clean up `return*` instruction verification. (Vladimir Marko <vmarko@google.com>)
d7a557c867: Add a flag for virtual thread (Victor Chang <vichang@google.com>)
e6e5f771a6: Use HInstructionIteratorHandleChanges again in RTP (Santiago Aboy Solanes <solanes@google.com>)
9a36de5022: Fix unnecessary warnings on embedded profile not found. (Jiakai Zhang <jiakaiz@google.com>)
8ad405adff: Reland "Avoid moving old-gen object to young-gen in generational CMC" (Lokesh Gidra <lokeshgidra@google.com>)
9c9ef3f501: Improve cleanup robustness after adb push failures. (Martin Stjernholm <mast@google.com>)
8b9c4525fc: Add implemention of j.i.m.Unsafe::allocateInstance. (Almaz Mingaleev <mingaleev@google.com>)
632aaa397e: Potential buffer overflow in environment local storage (shivam tiwari <shivam.tiwari00021@gmail.com>)
b53c968c4b: Revert "Avoid moving old-gen object to young-gen in generational CMC" (Lokesh Gidra <lokeshgidra@google.com>)
6990f50c75: FindProtoId: avoid UB on empty signature_type_idxs (Ryan Prichard <rprichard@google.com>)
9dd0dc2b89: Remove more dead code for ELF file. (Jiakai Zhang <jiakaiz@google.com>)
ac94fdd1de: Remove dead code for ELF file. (Jiakai Zhang <jiakaiz@google.com>)
5b9aac8979: Remove required on i18n apex (Colin Cross <ccross@android.com>)
dd33afc86b: Avoid moving old-gen object to young-gen in generational CMC (Lokesh Gidra <lokeshgidra@google.com>)
01a7d31673: verifier: Keep locking info for no-op move-object. (Vladimir Marko <vmarko@google.com>)
74072380fe: Fix memory leak when deallocating OatWriter. (Nicolas Geoffray <ngeoffray@google.com>)
321bf229a5: Optimize FindVisitedBlockWithRecyclableSet (Santiago Aboy Solanes <solanes@google.com>)
7c2bfb75a8: Bump size of debug store dump from 1k -> 4k. (Ben Miles <benmiles@google.com>)
84c6090500: Revert^2 "Use nanoseconds for v2 method tracing" (Mythri Alle <mythria@google.com>)
6d198c0cc7: Handle overflow when writing events to the file in V2 trace format (Mythri Alle <mythria@google.com>)
2687609506: DexMetadataHelper: Fix logging for missing config.pb file (Stefano Cianciulli <scianciulli@google.com>)
57d3e443e6: Add //apex_available:platform to art tests (Colin Cross <ccross@android.com>)
58626c558d: Add details to "Unsupported class loader" warning (Tomasz Wasilczyk <twasilczyk@google.com>)
78dbd5c6ee: SafeMul: avoid UB on signed overflow (Ryan Prichard <rprichard@google.com>)
d6d5643407: Delete DexFile.getDexFileStatus. (Jiakai Zhang <jiakaiz@google.com>)
7dc95b4990: Add a native method to fetch SDKExtension S-level in ART (Mohannad Farrag <aymanm@google.com>)
6c2ef6e2a6: cleanup: Remove never executed break (Santiago Aboy Solanes <solanes@google.com>)
1c2039372b: Optimize RemoveInstruction (Santiago Aboy Solanes <solanes@google.com>)
6ebd0862f7: Use `std::string_view` for `DescriptorToDot()`, ... (Vladimir Marko <vmarko@google.com>)
6fbb37a751: Better linking of native bridged methods (dimitry <dimitry@google.com>)
764be11a8f: ThreadList::Dump() fix (Hans Boehm <hboehm@google.com>)
f850690a90: Use `ClassAccessor::GetViewDescriptor()` more. (Vladimir Marko <vmarko@google.com>)
08f1b58976: Remove cdex support from `ArtMethod`... (Vladimir Marko <vmarko@google.com>)
95cebecfa3: Delete obsolete --compact-dex-level flag. (Martin Stjernholm <mast@google.com>)
fe15882217: Fix the divide-by-zero in odrefresh. (Jiakai Zhang <jiakaiz@google.com>)
b6714bc183: Reduce HashSet's kMinBuckets to 10 (Santiago Aboy Solanes <solanes@google.com>)
3428f9be71: nativebridge: Add isNativeBridgeFunctionPointer method (dimitry <dimitry@google.com>)
65914c03ce: Check if InsnsSizeInCodeUnits is 0 a bit before (Santiago Aboy Solanes <solanes@google.com>)
45f0aefb36: Keep the symbols for host to symbolize crash stack traces (Santiago Aboy Solanes <solanes@google.com>)
ef5054636c: Refactor `ImTable::GetImtIndex()`. (Vladimir Marko <vmarko@google.com>)
a7045d8fd8: `ImTable::GetImtIndex()` is not used for proxy methods. (Vladimir Marko <vmarko@google.com>)
eb6797da31: Increment odex version to skip 257. (Martin Stjernholm <mast@google.com>)
3e33f0dcc9: Optimize FindReferenceInfoOf (Santiago Aboy Solanes <solanes@google.com>)
59b8c0c148: Update boot image and system server profiles [M44C35P56S0PP] (art-benchmark-service <art-benchmark-service-bot...)
0f64014c85: Update some identifiers since the hiddenapi access messages are no longe... (Martin Stjernholm <mast@google.com>)
31c61c922f: Convert art/tools/ahat/Android.mk to Android.bp (Wei Li <weiwli@google.com>)
0076c0512f: Optimizing: Remove `kNotCompiledLargeMethodNoBranches`. (Vladimir Marko <vmarko@google.com>)
cfb4bdbe11: Optimizing: New statistic for diamond removal. (Vladimir Marko <vmarko@google.com>)
c8e37ce90d: Optimizing: Remove Partial LSE statistics. (Vladimir Marko <vmarko@google.com>)
d3580df91b: verifier: Clean up unary/binary ops verification. (Vladimir Marko <vmarko@google.com>)
7a0ce584df: Add option to write zeros instead of sparse. (David Srbecky <dsrbecky@google.com>)
d8261f0d75: Revert "Force 4K ELF alignment on art/odex files." (Steven Moreland <smoreland@google.com>)
15faea56c8: Luci: Add gcstress-cmc and allow running on Android B (David Srbecky <dsrbecky@google.com>)
7e3cf2bac4: Move dynamic sections to start of OAT file. (Konstantin Baladurin <konstantin.baladurin@arm.c...)
55cb961ae8: Reduce alignment for .rodata section in OAT files (Richard Neill <richard.neill@arm.com>)
f10036f351: Avoid implicit conversion to bool in SideEffect's methods (Santiago Aboy Solanes <solanes@google.com>)
fc034369e3: Add ArtShellCommandTest and cover pre-reboot dexopt commands. (Jiakai Zhang <jiakaiz@google.com>)
2a5c50ab33: WrapGetSystemProperties code replace unsafe strcpy() with memcpy() (shivam tiwari <shivam.tiwari00021@gmail.com>)
63cde04711: Optimize ValueSet::Kill (Santiago Aboy Solanes <solanes@google.com>)
6b39013f18: Process mark-stack more frequently to avoid expanding it (Lokesh Gidra <lokeshgidra@google.com>)
22a222b0ed: Add ConditionVariable debugging checks (Hans Boehm <hboehm@google.com>)
0f800d14c6: Remove old workaround in RecordPcInfo (Santiago Aboy Solanes <solanes@google.com>)
ce21c4bbe5: Move stats reporting from PreRebootDriver to PreRebootDexoptJob. (Jiakai Zhang <jiakaiz@google.com>)
e792071058: Remove unused dex_pc from GenerateUnresolvedFieldAccess (Santiago Aboy Solanes <solanes@google.com>)
465a50fce2: Optimizing: Fix `SimplifyIfs()` for FP bias mismatch. (Vladimir Marko <vmarko@google.com>)
72345a79d5: Ignore hiddenapi denial errors on qemu as well. (Martin Stjernholm <mast@google.com>)
60f65abcd7: Use log level INFO for hiddenapi messages if access is allowed. (Martin Stjernholm <mast@google.com>)
258822ee77: Use a more accurate name for the hiddenapi domain comparison function. (Martin Stjernholm <mast@google.com>)
64031cfed5: Fix missing logging of core platform API violations in just-warn mode. (Martin Stjernholm <mast@google.com>)
701bd96db0: Do not always set ART_TEST_CHROOT in testrunner.py. (Martin Stjernholm <mast@google.com>)
6ddb3569b3: Avoid deflating monitors in the zygote space. (Richard Uhler <ruhler@google.com>)
a4bb8c9182: Remove unused dex_pc from InvokeRuntime (Santiago Aboy Solanes <solanes@google.com>)
128e41a29a: Don't iterate past the item in CheckCallSite (Santiago Aboy Solanes <solanes@google.com>)
a590d5a18e: Add alignment check for DEX's map data items (Santiago Aboy Solanes <solanes@google.com>)
babd720769: Remove explicit dex_pc from RecordPcInfo (Santiago Aboy Solanes <solanes@google.com>)
b3ca9f3c87: Log info about the caller and callee in hiddenapi denial messages. (Martin Stjernholm <mast@google.com>)
162e2634ca: Allow ART internal libs to load libs in NATIVELOADER_DEFAULT_NAMESPACE_L... (Martin Stjernholm <mast@google.com>)
daacc31423: Use libarttest(d)_external to fix 656-annotation-lookup-generic-jni, and... (Martin Stjernholm <mast@google.com>)
920c10a2a8: Fix the loading of libarttest(d).so in 150-loadlibrary and enable it aga... (Martin Stjernholm <mast@google.com>)
1107d58d6f: Use libarttest(d)_external to fix 674-hiddenapi, and enable it on target... (Martin Stjernholm <mast@google.com>)
30dfb7e6ef: "Macroise" symbol accesses from Arm64 entrypoints (Chris Jones <christopher.jones@arm.com>)
4349121766: Limit 1336-short-finalizer-timeout with emulation (Hans Boehm <hboehm@google.com>)
feae68a363: Use runtime_native_boot P/H flag for generational GC (Lokesh Gidra <lokeshgidra@google.com>)
e6fd904071: Update a method's name so it's more clear (Mythri Alle <mythria@google.com>)
705809a601: Add a one-pass baseline compiler for arm64. (Nicolas Geoffray <ngeoffray@google.com>)
00c7f9fbce: Simplify PrimitiveArray<T>::Memcpy (Victor Chang <vichang@google.com>)
e8ea3a17d6: Revert "Use nanoseconds for v2 method tracing" (Mythri Alle <mythria@google.com>)
d465db82d1: Revert "Manually initialize WellKnownClasses required by tests." (Nicolas Geoffray <ngeoffray@google.com>)
39d441a04d: Simplify Buffer Handling in Non-Linux Platforms (shivam tiwari <shivam.tiwari00021@gmail.com>)
ff0184c6af: Don't use WellKnownClasses in ReferenceProcessor's GetSlowPathFlagOffset... (Nicolas Geoffray <ngeoffray@google.com>)
f79077ad9e: Optimizing: Rename `HCodeFlowSimplifier`... (Vladimir Marko <vmarko@google.com>)
1d173559d4: Initialize the lowoverhead trace entry points to nop entry points (Mythri Alle <mythria@google.com>)
9f681acb57: riscv64: handle invoke-static in invokeExact intrinsic. (Anton Romanov <anton.romanov@syntacore.com>)
1a9a8abf19: Use nanoseconds for v2 method tracing (Mythri Alle <mythria@google.com>)
2576b59a2d: Enable pre-GC heap-verification for debug builds (Lokesh Gidra <lokeshgidra@google.com>)
b979fd508c: Fix memory-leak in mid_to_old_promo_bit_vec_ (Lokesh Gidra <lokeshgidra@google.com>)
7ed44baf0f: Stop using MAP_32BIT for mapping in <4GB on x86_64 (Lokesh Gidra <lokeshgidra@google.com>)
85b7a098e7: Continue GC when reloading class from obj during marking works (Lokesh Gidra <lokeshgidra@google.com>)
ea1443585c: Support generating split dirty-image-objects profile (Dmitrii Ishcheikin <ishcheikin@google.com>)
70292c9cea: Manually initialize WellKnownClasses required by tests. (Nicolas Geoffray <ngeoffray@google.com>)
4a1b177c77: Address comments from aosp/3457760. (Nicolas Geoffray <ngeoffray@google.com>)
d334567391: Skip MapAnonymousFailNullError on host (Richard Neill <richard.neill@arm.com>)
7345dfdec5: Skip tests for sparse file handling on host (Richard Neill <richard.neill@arm.com>)
cf6e01f7b2: Avoid using trace_data_lock_ in TraceStartCheckpoint (Mythri Alle <mythria@google.com>)
f562686141: Don't use SuspendAllScope for starting and dumping low overhead trace (Mythri Alle <mythria@google.com>)
1bf1220ef5: Optimizing: Generate `HSelect` if there are more phis... (Vladimir Marko <vmarko@google.com>)
d661c115a5: Optimizing: Remove `CreateDoWhileLoop()`. (Vladimir Marko <vmarko@google.com>)
74d140050d: Avoid setting live-bit for nullptr in large-object space with CMC (Lokesh Gidra <lokeshgidra@google.com>)
b0af4d2bc4: Disable GCMetric.GCDuration and GCDurationDelta gtests (Lokesh Gidra <lokeshgidra@google.com>)
401c400b4c: Remove generation of ahat test dumps from ahat/Android.mk (Richard Uhler <ruhler@google.com>)
2892bd9731: Optimizing: Test for `HSelect` in irreducible loop. (Vladimir Marko <vmarko@google.com>)
6d6d26f1fe: Optimizing: Allow moving `HCondition` to use site. (Vladimir Marko <vmarko@google.com>)
8d38ee1b7a: Enable Generational CMC (Lokesh Gidra <lokeshgidra@google.com>)
c682b8b029: Make CMC GC generational (Lokesh Gidra <lokeshgidra@google.com>)
a874b96ed1: Restore a line that was accidentally dropped in aosp/3434019 (Mythri Alle <mythria@google.com>)
38f9f08494: AtomicPair needs to occasionally sleep (Hans Boehm <hboehm@google.com>)
b30c5a0d84: Add new WellKnownClasses fields to avoid harcoded constants. (Nicolas Geoffray <ngeoffray@google.com>)
761ea222e3: Add support for collecting long running methods (Mythri Alle <mythria@google.com>)
612ee65f6a: Introduce an "external" variant of libarttest(d).so and use it to fix an... (Martin Stjernholm <mast@google.com>)
bd36a3bcd6: Set no write barrier for primitive types. (Nicolas Geoffray <ngeoffray@google.com>)
38f8f04fdc: Revert "Minimal hiddenapibypass breakage demo." (Daniel Chapin <chapin@google.com>)
ebf48c0bad: Revert "Minimal hiddenapibypass breakage demo." (Daniel Chapin <chapin@google.com>)
e7d9821a5c: Improve class fuzzer initialization (Santiago Aboy Solanes <solanes@google.com>)
da4ef06a30: Use Java 17 `toList` method. (Jiakai Zhang <jiakaiz@google.com>)
e2ec442bdf: Flush profiles upon `pm dump-profiles`. (Jiakai Zhang <jiakaiz@google.com>)
564ffff5b4: Optimizing: Fix `InsertInputAt()`. (Vladimir Marko <vmarko@google.com>)
f5cca5b059: Optimizing: Rename `HSelectGenerator`... (Vladimir Marko <vmarko@google.com>)
b3e84e14c6: Remove unused fields in shadow frames (Victor Chang <vichang@google.com>)
984487963e: Fix crash when calling a public Object method with invokesuper. (Nicolas Geoffray <ngeoffray@google.com>)
861374be54: Fix PaletteDebugStoreGetString fake (Hans Boehm <hboehm@google.com>)
f19b2056ed: Update test. (Nicolas Geoffray <ngeoffray@google.com>)
ecdd2c1a79: Add //cts/libcore/vmdebug to visibility of ART aconfig flags (Mythri Alle <mythria@google.com>)
990cf07523: Merge sFields and iFields. (Nicolas Geoffray <ngeoffray@google.com>)
ae13bd8a14: Make it an error to call an Object method with super in an interface. (Nicolas Geoffray <ngeoffray@google.com>)
5108b62231: Make ResolveField respect the is_static parameter. (Santiago Aboy Solanes <solanes@google.com>)
7655e9ab53: Pass new device version values to derive_classpath. (Jiakai Zhang <jiakaiz@google.com>)
b5419617cf: verifier: Clean up `HandleMoveException`. (Vladimir Marko <vmarko@google.com>)
55bed4cd5c: Minimal hiddenapibypass breakage demo. (Almaz Mingaleev <mingaleev@google.com>)
27123e7573: Add an explicit destructor for DisassemblerArm. (Elliott Hughes <enh@google.com>)
93a24263dd: Enable lazy release on CC for some targets. (Nicolas Geoffray <ngeoffray@google.com>)
98430ec86f: Disable test on RI. (Nicolas Geoffray <ngeoffray@google.com>)
3ed5749285: verifier: Minor clean up of hard error reporting. (Vladimir Marko <vmarko@google.com>)
456ffe56e2: Fail dex verification for duplicate static/instance fields. (Nicolas Geoffray <ngeoffray@google.com>)
56fa678dd0: verifier: Do not mark registers as conflict for return. (Vladimir Marko <vmarko@google.com>)
df60e1f0f1: verifier: Use `RegTypeCache::kUndefinedCacheId` more. (Vladimir Marko <vmarko@google.com>)
502bbbac8b: Clean up `Instruction::CanFlowThrough()`. (Vladimir Marko <vmarko@google.com>)
790a81400b: verifier: Reduce duplication for `kVerifierDebug`. (Vladimir Marko <vmarko@google.com>)
252c90b89e: Add java library for core icu4j for the fuzzer (Santiago Aboy Solanes <solanes@google.com>)
8698830510: Pass the correct class loader in the class verifier fuzzer (Santiago Aboy Solanes <solanes@google.com>)
e37d995993: Add a debug version of the class verifier fuzzer (Santiago Aboy Solanes <solanes@google.com>)
de151a9527: Bind-mount the old etc dirs in Pre-reboot Dexopt. (Jiakai Zhang <jiakaiz@google.com>)
e7f8149401: Optimizing: Unary and binary operations are movable. (Vladimir Marko <vmarko@google.com>)
b594ff6de0: Fix DCHECK in RegType::IsObjectArrayTypes (Santiago Aboy Solanes <solanes@google.com>)
64a21fa4dc: verifier: Remove `FailOrAbort()`. (Vladimir Marko <vmarko@google.com>)
7e2ae92b43: verifier: Speed up failure recording. (Vladimir Marko <vmarko@google.com>)
d70f568664: Skip 2286-method-trace-aot-code on RI (Mythri Alle <mythria@google.com>)
c418e6f89e: Add tests with a permanently enabled flag in art-flags.aconfig. (Martin Stjernholm <mast@google.com>)
699a36d4c6: Fix linkerconfig generation in an AOSP tree that has built a system imag... (Martin Stjernholm <mast@google.com>)
fe90069d7f: Clean up `Instruction::SizeInCodeUnitsComplexOpcode()`. (Vladimir Marko <vmarko@google.com>)
364066f0a0: verifier: Mark `GetFieldIdxOfFieldAccess()` ALWAYS_INLINE. (Vladimir Marko <vmarko@google.com>)
ba8f35fc60: verifier: Speed up `ComputeWidthsAndCountOps()`. (Vladimir Marko <vmarko@google.com>)
7d01971161: verifier: Rewrite branch target verification. (Vladimir Marko <vmarko@google.com>)
5135b91da8: asm_defines.s: suppress error about unused -c argument (Ryan Prichard <rprichard@google.com>)
bdf31e2ff9: Handle invoke-virtual targeting invokeExact gracefully. (Almaz Mingaleev <mingaleev@google.com>)
26040bb028: Add a test to check AOT code is used when method tracing is stopped (Mythri Alle <mythria@google.com>)
8842f9debe: Remove superblock cloner's DoVersioning (Santiago Aboy Solanes <solanes@google.com>)
970075bedb: x86_64: Refactor assembler code for arithmetic ops. (Vladimir Marko <vmarko@google.com>)
82efdc3c6b: Rename `GetBootImageVarHandleField()`, drop "Boot". (Vladimir Marko <vmarko@google.com>)
44022f13f1: Remove ahat's dependency on guava. (Richard Uhler <ruhler@google.com>)
3f87b5be94: AHAT 1.8 release (Shai Barack <shayba@google.com>)
b1b951474f: Show retained size in the heap dump size table. (Shai Barack <shayba@google.com>)
b9ebeba09b: AHAT: allow downloading byte[] contents as file (Shai Barack <shayba@google.com>)
bfe5bd118f: Convert hprofdump.py to py3 (Shai Barack <shayba@google.com>)
bd66b99b81: Update Ahat OWNERS to use ahat's bug component (Shai Barack <shayba@google.com>)
72d95ccd2c: Rename Unsafe.putOrdered* intrinsic identifiers. (Vladimir Marko <vmarko@google.com>)
0994519289: x86_64: Clean up VEX prefix generation for load/store. (Vladimir Marko <vmarko@google.com>)
4be0254a65: arm64: add invoke-interface support in invokeExact. (Almaz Mingaleev <mingaleev@google.com>)
6cf6c027e7: Rename `AsAddOrSub()` - add suffix `OrNull`. (Vladimir Marko <vmarko@google.com>)
ffa1f7611b: Verifier: Clean up `GetFieldIdxOfFieldAccess()`. (Vladimir Marko <vmarko@google.com>)
30b5cd0e6e: x86/x86-64: Clean up `p{sll,srl,sra}` tests. (Vladimir Marko <vmarko@google.com>)
2ed671e29d: x86_64: Clean up `movd()`, `movq()`. (Vladimir Marko <vmarko@google.com>)
1f6c5e7eb7: verifier: Inline `Check.*Op*()`. (Vladimir Marko <vmarko@google.com>)
3b5c3b2609: Add some folks to the tools/ahat/OWNERS file. (Shai Barack <shayba@google.com>)
fb6116af25: qemu: Update to Ubuntu 24.04 LTS (Noble Numbat) (David Srbecky <dsrbecky@google.com>)
48056fc027: Include useful context in the zip error messages, like the file or zip e... (Martin Stjernholm <mast@google.com>)
920b937cd8: Fix MapAnonymousFailNullError for MAP_FIXED_NOREPLACE (David Srbecky <dsrbecky@google.com>)
f9a04e35ce: Also use two-step mmap allocation on target if 'addr' hint is provided. (David Srbecky <dsrbecky@google.com>)
3df940f58e: run-test: Rename eng-prod archive file (David Srbecky <dsrbecky@google.com>)
fe38f9fdb7: Add back a test that was missed from a previous CL. (Nicolas Geoffray <ngeoffray@google.com>)
184ee711b8: qemu: Use 'ar' instead of '7z' (David Srbecky <dsrbecky@google.com>)
8b522a00ee: qemu: Create boot output file first to avoid race (David Srbecky <dsrbecky@google.com>)
f8a57338dc: Use jit_mutator_lock in JitCodeCache::VisitRootTables. (Nicolas Geoffray <ngeoffray@google.com>)
37ec22b569: Document and fix thread flags memory ordering (Hans Boehm <hboehm@google.com>)
81101f0095: Add test.java.lang.runtime.SwitchBootstrapsTest to run-libcore-tests (Sorin Basca <sorinbasca@google.com>)
9c13a3bcd9: Revert^2 "Reduce hotness on interpreter lookups." (Nicolas Geoffray <ngeoffray@google.com>)
22b0de6055: Revert "Reduce hotness on interpreter lookups." (Liana Kazanova <lkazanova@google.com>)
44436be34f: arm64: handle invoke-virtual and invoke-direct in invokeExact (Almaz Mingaleev <mingaleev@google.com>)
7e780be335: Add more WellKnownClasses fields for boxing/unboxing. (Nicolas Geoffray <ngeoffray@google.com>)
5c6e77ec99: Replace the limited libcrypto_for_art with libcrypto_static. (Martin Stjernholm <mast@google.com>)
648bfc7971: run-test: Fix dump cfg on target (Roman Artemev <roman.artemev@syntacore.com>)
a603e11f8d: Limit boot-image-profile-generate.sh to generate framework boot image pr... (Islam Elbanna <islamelbanna@google.com>)
2b82752ce8: qemu: Reduce work for 153-reference-stress (David Srbecky <dsrbecky@google.com>)
14acc4c7ba: qemu: Increase timeout for 2040-huge-native-alloc (David Srbecky <dsrbecky@google.com>)
```

