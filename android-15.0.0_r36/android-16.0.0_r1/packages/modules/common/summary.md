```
8ec2a07: Add import sys (Cole Faust <colefaust@google.com>)
283f117: Allow dependencies on com.android.nfc.module.flags-aconfig-cpp (James Willcox <jwillcox@google.com>)
9b6850e: Add libenv_filter Rust crate to allowed_deps.txt (Marcin Radomski <dextero@google.com>)
9bbc433: Update uprobestats allowed_deps (Matt Gilbride <mattgilbride@google.com>)
e6ac9ba: Add allowed dependency for grpc-java libraries (Ling-Yu Lee <lingyulee@google.com>)
04a1f35: Add v17 of the netd AIDL interfaces to allowed_deps. (Lorenzo Colitti <lorenzo@google.com>)
be628c9: Add libstatspull_headers to allowed_deps (Yu-Ting Tseng <yutingtseng@google.com>)
f769fe9: Update allowed_deps for AudioVolumgeGroupCallback refactor (François Gaffie <francois.gaffie@renault.com>)
794dbdf: Revert "swcodec module uses a trimmed libcodec2_aidl library" (Ray Essick <essick@google.com>)
a67afa9: Don't set soong_env to empty dict for VIC (Manish Singh <psych@google.com>)
25d3c89: Enable use of liblc3 on platform (Antoine SOULIER <asoulier@google.com>)
fb08133: Revert "Don't set soong_env to empty dict for VIC and Baklava" (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
d928e81: Added ExtServices aconfig flags lib (Kiran Ramachandra <kiranmr@google.com>)
79bdb70: Don't set soong_env to empty dict for VIC and Baklava (Manish Singh <psych@google.com>)
6aa7c58: Add basic proguard config for module framework targets (Jared Duke <jdduke@google.com>)
4456010: Add networkstack-aidl-interfaces-V23-java to allowed_deps. (Lorenzo Colitti <lorenzo@google.com>)
40c0fa1: swcodec module uses a trimmed libcodec2_aidl library (Ray Essick <essick@google.com>)
3a3388e: Cleanup python version properties (Cole Faust <colefaust@google.com>)
3463a63: Allowlist aconfig dependencies (Manish Singh <psych@google.com>)
e9e74dc: Add libbpf and dependencies to allow_deps (Motomu Utsumi <motomuman@google.com>)
f145e08: [owners] Remove satayev@google.com from javatests/com/android/modules/ap... (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
64bb19a: [owners] Remove andreionea@google.com from javatests/com/android/modules... (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
ce5dbc9: [owners] Remove andreionea@google.com from javatests/com/android/modules... (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
ab3dcb2: Change min SDK of b-launched-apex-module defaults to 36 (Pedro Loureiro <pedroql@google.com>)
d5d78f5: Revert^2 "Add SDK extension host exports to module SDKs." (Jiakai Zhang <jiakaiz@google.com>)
0976156: Revert "Add SDK extension host exports to module SDKs." (Chaitanya Cheemala (xWF) <ccheemala@google.com>)
9ab096d: Add SDK extension host exports to module SDKs. (Jiakai Zhang <jiakaiz@google.com>)
bad54c6: Make libclasspaths_proto support host. (Jiakai Zhang <jiakaiz@google.com>)
d299f41: Exporting build flags to permissions module (Jared Finder <jfinder@google.com>)
6037176: Provide min sdk version as ApiLevel instead of string. (Yu Liu <yudiliu@google.com>)
cb6110b: Add SDK team as prebuilt_module_owners (Linus Tufvesson <lus@google.com>)
03df303: Prepare for some changes in aosp where some string representations of mi... (Yu Liu <yudiliu@google.com>)
79b18dc: Update healthfitness apex dependencies for expressive theming. Previous-... (Teo Georgescu <teog@google.com>)
70f0a37: apex(dependencies): Bump min sdk to 36 (Roshan Pius <rpius@google.com>)
d6f7a71: Add dry_run mode for finalize_sdk.py (Linus Tufvesson <lus@google.com>)
6242ddc: Sorted the arguments for better readability. (Linus Tufvesson <lus@google.com>)
1a67c19: Update allowed_deps.txt for libstatslog_rust_header (Shintaro Kawamura <kawasin@google.com>)
f76f4a9: build/allowed_deps.txt: add libz(minSdkVersion:apex_inherit) (Lingyun Zhao <lingyunzhao@google.com>)
1717a3c: Add NfcNciApexGoogle to allowed_deps.txt (Colin Cross <ccross@android.com>)
67bfe93: Add wear permission components in allowed dependencies. (vignesh ramanathan <vigneshrsastra@google.com>)
b8aa88a: build/allowed_deps.txt: add libaom{sse4_[12],avx,avx2} (James Zern <jzern@google.com>)
b0c676f: Allow new repackaged module in ConfigInfra (Ted Bauer <tedbauer@google.com>)
892bec6: build/allowed_deps.txt: add libvpx{sse4,avx,avx2,avx512} (James Zern <jzern@google.com>)
f3f8b8e: Reduce minSdkVersion for zerocopy. (Andrew Walbran <qwandor@google.com>)
adeaf7b: Adding net_aidl_interface v16 to allowed_deps.txt (Melisa CZ <melisacz@google.com>)
68a22f6: Allow proto lib in ConfigInfra (Ted Bauer <tedbauer@google.com>)
c1e9c00: Allow new name for bssl inline header wrappers (Matthew Maurer <mmaurer@google.com>)
47c3285: Add NFC service to apex_available (Brad Lassey <lassey@google.com>)
2a4ea7a: Add libhashbrown-0.12.3 to allowed deps. (James Farrell <jamesfarrell@google.com>)
7d177cc: Add New SDK Extension B (nanaasiedu <nanaasiedu@google.com>)
cf6541b: Add psych to OWNERS list (Manish Singh <psych@google.com>)
47bbcc1: Rename libnet_utils_device_common_timerfdjni to libconnectivityutilsjni (Patrick Rohr <prohr@google.com>)
aad563a: Add com.android.permission.flags-aconfig-java-export to framework (James Willcox <jwillcox@google.com>)
54fec96: Remove one more wrongly added build target (Chan Wang <chanwang@google.com>)
5a8047b: Remove wrongly added SDV build targets (Chan Wang <chanwang@google.com>)
1e127d5: Allow SettingsTheme aconfig flags (Edgar Wang <edgarwang@google.com>)
d60a8d7: Revert^2 "Update NFC modules dependencies" (Roshan Pius <rpius@google.com>)
6078869: Add Rust aconfig library to allowed deps in ConfigInfra (Ted Bauer <tedbauer@google.com>)
86c940d: Update healthfitness apex dependencies for expressive theming. Previous-... (Teo Georgescu <teog@google.com>)
bc0fea5: Revert "Update NFC modules dependencies" (ELIYAZ MOMIN <mohammedeliyaz@google.com>)
4f98d0f: Add check_derive_classpath tool (Mårten Kongstad <amhk@google.com>)
c6289ca: Remove wrongly added build targets (Chan Wang <chanwang@google.com>)
eac2e89: Remove ancr from owners (Alexei Nicoara <ancr@google.com>)
466bb3b: Update NFC modules dependencies (Justin Chung <justinkchung@google.com>)
54a9177: Update healthfitness apex dependency for SettingsLibIntroPreference (csitari <csitari@google.com>)
d475057: Fix allowed_deps.txt to list files in alphabetical order (Chan Wang <chanwang@google.com>)
47256c9: Expose jakarta.inject to apex (Dave Mankoff <mankoff@google.com>)
691da09: Add profiling module to mainline modules sdk (Yisroel Forta <yforta@google.com>)
e9da591: Update base_system.mk change (Justin Yun <justinyun@google.com>)
74589e6: Revert^4 "[crashrecovery] Add module to mainline_modules_sdks.py." (Harshit Mahajan <harshitmahajan@google.com>)
3b31a6a: Revert^3 "[crashrecovery] Add module to mainline_modules_sdks.py." (Priyanka Advani (xWF) <padvani@google.com>)
40fc795: Revert^2 "[crashrecovery] Add module to mainline_modules_sdks.py." (Harshit Mahajan <harshitmahajan@google.com>)
6036d8f: Update healthfitness apex dependencies for expressive theming. Previous-... (Teo Georgescu <teog@google.com>)
368de55: Add Rust aconfig library to allowed deps in ConfigInfra (Ted Bauer <tedbauer@google.com>)
dd45634: Update healthfitness apex dependency for SettingsLibButtonPreference (csitari <csitari@google.com>)
697b92a: Allow regex rust lib use in ConfigInfra (Ted Bauer <tedbauer@google.com>)
3b52d0e: Revert "[crashrecovery] Add module to mainline_modules_sdks.py." (Liana Kazanova (xWF) <lkazanova@google.com>)
817ab6b: [crashrecovery] Add module to mainline_modules_sdks.py. (Harshit Mahajan <harshitmahajan@google.com>)
e989527: Update base_system.mk change (Justin Yun <justinyun@google.com>)
dd8ebe8: Revert^2 "[bt] Add module to mainline_modules_sdks.py." (William Escande <wescande@google.com>)
366968e: Revert "[bt] Add module to mainline_modules_sdks.py." (Priyanka Advani (xWF) <padvani@google.com>)
1a75fb4: [bt] Add module to mainline_modules_sdks.py. (William Escande <wescande@google.com>)
07bab64: Allow SettingsLib aconfig flags (Chris Antol <cantol@google.com>)
13fdfcb: libc++fs is an empty library. (Elliott Hughes <enh@google.com>)
2e44df3: Update nfc apex dependencies (Roshan Pius <rpius@google.com>)
7c1000b: Update nfc apex dependencies (Roshan Pius <rpius@google.com>)
5aac6e9: Attempt to fix merge problems with min_sdk_version and 3p Rust crates. (James Farrell <jamesfarrell@google.com>)
016d200: Attempt to fix merge problems with min_sdk_version and 3p Rust crates. (James Farrell <jamesfarrell@google.com>)
7aaf7cf: Add libhashbrown-0.12.3 to allowed deps. (James Farrell <jamesfarrell@google.com>)
5e66ed7: Add libhashbrown-0.12.3 to allowed deps. (James Farrell <jamesfarrell@google.com>)
cb9b9cc: Add allowed dependencies for VCN modularization (Yan Yan <evitayan@google.com>)
70eb221: build/allowed_deps.txt: add libvpx_sve2 (James Zern <jzern@google.com>)
```

