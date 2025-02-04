```
692b2169: Use std::sync::OnceLock rather than once_cell. (Andrew Walbran <qwandor@google.com>)
38b72d20: simpleperf: inject: Change comments for bolt output (Yabin Cui <yabinc@google.com>)
86478d87: Made minor refactoring and lint improvements. (Esteban Barrero-Hernandez <estebanbarrero@google...)
f89907db: Created README file for torq. (Esteban Barrero-Hernandez <estebanbarrero@google...)
813aae2d: Implemented tracing of the app-startup event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
d344a99b: simpleperf: dump: Add --dump-feature (Yabin Cui <yabinc@google.com>)
47eb5f73: simpleperf: Update doc for bolt (Yabin Cui <yabinc@google.com>)
c1555528: simpleperf: inject: Fix address conversion for bolt output (Yabin Cui <yabinc@google.com>)
97bcb317: check_elf_alignment.sh: Escape star chars (Shoham Peller <shohamp@gmail.com>)
264da89c: Implemented argument validation for app-startup and multiple runs. (Esteban Barrero-Hernandez <estebanbarrero@google...)
d3928f91: simpleperf: inject: Add output format for bolt (Yabin Cui <yabinc@google.com>)
81a75e72: Added AdbDevice APIs needed to execute the app-startup event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
c6f624d8: simpleperf: Fix dumping build ids when recording ETM data (Yabin Cui <yabinc@google.com>)
ab9cb23d: simpleperf: Update calculating file_offset for AutoFDO output (Yabin Cui <yabinc@google.com>)
80749a27: Add ethanalee@ to Torq OWNERS file (Ethan Lee <ethanalee@google.com>)
65c7ee3f: Implemented tracing of the boot event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
f9ddfb18: Added AdbDevice APIs needed to execute the boot event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
52978c3c: Made refactoring changes to long string constants in test/config_builder... (Esteban Barrero-Hernandez <estebanbarrero@google...)
c0324cc5: Implemented the handling of custom perfetto configs. (Esteban Barrero-Hernandez <estebanbarrero@google...)
d21aef14: Remove NDK exports (Steven Moreland <smoreland@google.com>)
93b7d7dc: profcollect: Rename usage_setting to usage_setting.txt (Yi Kong <yikong@google.com>)
a45adef1: Made style and refactoring changes to command.py and command_executor_un... (Esteban Barrero-Hernandez <estebanbarrero@google...)
7f367659: Implemented tracing of the user-switch event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
e3fc4471: simpleperf: Avoid allocating high order pages for ETM recording (Yabin Cui <yabinc@google.com>)
e7e52387: profcollect: Remove reconfig command from the help message (Yi Kong <yikong@google.com>)
26a65d8b: simpleperf: Fix script tests. (Yabin Cui <yabinc@google.com>)
7a3de473: simpleperf: update simpleperf prebuilts to build 12284122. (Yabin Cui <yabinc@google.com>)
8ad70641: profcollectd: Use --no-dump-build-id for system wide ETM recording (Yabin Cui <yabinc@google.com>)
7d2336d0: simpleperf: record: Add --no-dump-build-id (Yabin Cui <yabinc@google.com>)
43568883: Added more argument validation for the user-switch event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
2875cea5: Disable simpleperf_writer_fuzzer for AFL framework (Onkar Shinde <onkar.shinde@ittiam.com>)
b006fb7b: Added AdbDevice APIs needed to execute the user-switch event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
bb8cb501: Fix up color generation in gecko_profile_generation (Mark Hansen <markhansen@google.com>)
8b973e91: Update test goldens for gecko_profile_generator (Mark Hansen <markhansen@google.com>)
5f616496: simpleperf: Fix dumping build id for system wide etm recording (Yabin Cui <yabinc@google.com>)
f161f10e: simpleperf: use libc++_static for darwin host build (Yabin Cui <yabinc@google.com>)
c6a7fdeb: Refactored device.py and tests/device_unit_test.py. (Esteban Barrero-Hernandez <estebanbarrero@google...)
79f8dd05: Disable libsimpleperf_report_fuzzer for AFL framework (Onkar Shinde <onkar.shinde@ittiam.com>)
0bf695bc: simpleperf: inject: Add option to search binaries with filename (Yabin Cui <yabinc@google.com>)
7e420744: Implemented uploading prefetto trace output to perfetto web UI. (Esteban Barrero-Hernandez <estebanbarrero@google...)
7f865008: Changed mocking approach to tests/command_executor_unit_test.py. (Esteban Barrero-Hernandez <estebanbarrero@google...)
72301852: simpleperf: update simpleperf prebuilts to build 12252562. (Yabin Cui <yabinc@google.com>)
fc11e25f: Implemented perfetto profiling of custom event. (Esteban Barrero-Hernandez <estebanbarrero@google...)
acb75460: lpdump: don't dump snapshot info when running with --json (Sandeep Dhavale <dhavale@google.com>)
85d8f60b: check_elf_alignment.sh: fail on deapexer (Steven Moreland <smoreland@google.com>)
1e6d59d8: Lint changes in torq.py, tests/torq_unit_test.py, and command_executor.p... (Esteban Barrero-Hernandez <estebanbarrero@google...)
e7b8b42c: Fix build issue for targets depending on libverity_tree (Kelvin Zhang <zhangkelvin@google.com>)
560f7879: Implemented creating the default perfetto config and its unit tests. (Esteban Barrero-Hernandez <estebanbarrero@google...)
c8d52c1e: Implemented testing connection to device and its unit tests. (Esteban Barrero-Hernandez <estebanbarrero@google...)
e3594c2f: profile-extras: remove unused #includes. (Elliott Hughes <enh@google.com>)
66b33e7c: simpleperf: handle events collected by --add-counter in pprof profile (Howie Peng <howiepeng@google.com>)
b1d73e26: Implemented the framework for executing commads. (Esteban Barrero-Hernandez <estebanbarrero@google...)
ef6b3ca2: simpleperf: pprof_proto_generator.py: Add --tagroot (Yabin Cui <yabinc@google.com>)
3d1d8606: simpleperf: update simpleperf prebuilts to build 12154051. (Yabin Cui <yabinc@google.com>)
edee5fc0: Implemented unit tests for argument parsing and command creation in torq... (Esteban Barrero-Hernandez <estebanbarrero@google...)
2168cd9f: boottime_tools: Add Android.bp for bootanalyze (Yanye Li <yanyeli@google.com>)
4c923fb8: simpleperf: report_lib: Add function to get process name (Yabin Cui <yabinc@google.com>)
f4519f38: Remove nputikhin@google.com from libatrace_rust/OWNERS (Owner Cleanup Bot <swarming-tasks@owners-cleanup...)
90fc4c95: profcollect: Allow specifying custom trace_process duration (Yi Kong <yikong@google.com>)
c33e032e: profcollectd: compress ETM data instead of decoding it when recording (Yabin Cui <yabinc@google.com>)
fff50a27: Implemented handling of argument file and directory paths in torq.py. (Esteban Barrero-Hernandez <estebanbarrero@google...)
79346c9b: simpleperf: Support compressing init_map feature section (Yabin Cui <yabinc@google.com>)
99f599ae: simpleperf: Support compressing ETM data (Yabin Cui <yabinc@google.com>)
0913622c: simpleperf: Add -z in the record cmd (Yabin Cui <yabinc@google.com>)
86e7a161: simpleperf: Fix OPT_STRING_AFTER_EQUAL parsing at the end of args (Yabin Cui <yabinc@google.com>)
9c51e107: Implemented argument parsing and command creation in torq.py. (Esteban Barrero-Hernandez <estebanbarrero@google...)
2777042c: simpleperf: init OptionValue properly (Yabin Cui <yabinc@google.com>)
f8c8bcb6: simpleperf: Fix handling of BPF symbols (Tomislav Novak <tnovak@meta.com>)
e4df6a27: check_elf_alignment: print name of APK analyzed (Steven Moreland <smoreland@google.com>)
f5d7a3b2: simpleperf: Support option value after '=' (Yabin Cui <yabinc@google.com>)
ce2385db: simpleperf: Add wrapper for zstd compression/decompression (Yabin Cui <yabinc@google.com>)
f8e5f609: Remove __libcpp_verbose_abort() workaround. (Elliott Hughes <enh@google.com>)
f9321b98: Update URL for PProf UI (Yabin Cui <yabinc@google.com>)
bae27488: profcollect: Add support for tracing processes (Yi Kong <yikong@google.com>)
d5f247be: simpleperf: Switch GetMemorySize to use sysinfo syscall (Yi Kong <yikong@google.com>)
acc42576: Remove unused system/extras/Android.mk (kellyhung <kellyhung@google.com>)
c26c15b5: profcollect: Rename trace_once to trace_system (Yi Kong <yikong@google.com>)
a0e438f9: simpleperf: Store init map records in a feature section (Yabin Cui <yabinc@google.com>)
6d58fa1f: check_elf_alignment.sh: check all files, warn some (Steven Moreland <smoreland@google.com>)
41bc1687: Remove unused system/extras/tests/Android.mk (kellyhung <kellyhung@google.com>)
189eae28: simpleperf: Detect test environment before running tests (Yabin Cui <yabinc@google.com>)
87d71560: Convert Android.mk under system/extras/tests to Android.bp (kellyhung <kellyhung@google.com>)
7a01345d: simpleperf: Detect test environment before running tests (Yabin Cui <yabinc@google.com>)
c440d1f9: simpleperf: Fix flaky tests when running in emulator (Yabin Cui <yabinc@google.com>)
fc2a380e: Convert Android.mk under system/extras/tests to Android.bp (kellyhung <kellyhung@google.com>)
d4ed9b87: simpleperf: Handle unused space in sample record (Yabin Cui <yabinc@google.com>)
6b218798: Remove unused system/extras/tests/bootloader/Android.mk (kellyhung <kellyhung@google.com>)
4cba1f72: Convert Android.mk under system/extras/simpleperf to Android.bp (kellyhung <kellyhung@google.com>)
63da2206: simpleperf_writer_fuzzer: Bug Fix (Onkar Shinde <onkar.shinde@ittiam.com>)
```

