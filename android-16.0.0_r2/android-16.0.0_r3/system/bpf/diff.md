```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 6a65edc..b2c5185 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "libbpf_load_test"
-    }
-  ],
-  "hwasan-postsubmit": [
-    {
-      "name": "libbpf_load_test"
+      "name": "bpfloader_tests"
     }
   ],
   "imports": [
diff --git a/include/defs/android_bpf_defs.h b/include/defs/android_bpf_defs.h
index 35cf057..3f3f158 100644
--- a/include/defs/android_bpf_defs.h
+++ b/include/defs/android_bpf_defs.h
@@ -7,10 +7,19 @@
 // When using vmlinux.h, you can't use any system level headers.
 #include <vmlinux.h>
 #else
+#include <linux/bpf.h>
 #include <linux/types.h>
 #endif  // USE_VMLINUX
 #include <bpf/bpf_helpers.h>
 
+// bpf_helpers.h defines __always_inline using "inline __attribute__((always_inline))".
+// To prevent potential "duplicate 'inline' declaration" issues depending on the include order,
+// redefine using the cdefs.h definition of __always_inline.
+#undef __always_inline
+#define __always_inline __attribute__((__always_inline__))
+
+#include <sys/cdefs.h>
+
 #define DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)               \
     struct {                                                                                   \
         __uint(type, BPF_MAP_TYPE_##TYPE);                                                     \
@@ -40,11 +49,38 @@
 #define DEFINE_BPF_MAP_GRO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
     DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)
 
+#define DEFINE_BPF_RINGBUF(the_map, ValueType, num_entries, usr, grp, md)              \
+    struct {                                                                           \
+        __uint(type, BPF_MAP_TYPE_RINGBUF);                                            \
+        __uint(max_entries, num_entries);                                              \
+    } the_map SEC(".maps");                                                            \
+                                                                                       \
+    static inline __always_inline __unused int bpf_##the_map##_output(ValueType* v) {  \
+        return bpf_ringbuf_output(&the_map, v, sizeof(*v), 0);                         \
+    };                                                                                 \
+                                                                                       \
+    static inline __always_inline __unused ValueType* bpf_##the_map##_reserve() {      \
+        return bpf_ringbuf_reserve(&the_map, sizeof(ValueType), 0);                    \
+    }                                                                                  \
+                                                                                       \
+    static inline __always_inline __unused void bpf_##the_map##_submit(ValueType* v) { \
+        bpf_ringbuf_submit(v, 0);                                                      \
+    }
+
 #define DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog) \
     SEC(SECTION_NAME)                                               \
     int the_prog
 
+#define DEFINE_BPF_PROG_KVER(SECTION_NAME, prog_uid, prog_gid, the_prog, kver) \
+    DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog)
+
 #define LICENSE(NAME) char _license[] SEC("license") = (NAME)
+#define CRITICAL(NAME)
+
+// LLVM eBPF builtins: they directly generate BPF_LD_ABS/BPF_LD_IND (skb may be ignored?)
+unsigned long long load_byte(void* skb, unsigned long long off) asm("llvm.bpf.load.byte");
+unsigned long long load_half(void* skb, unsigned long long off) asm("llvm.bpf.load.half");
+unsigned long long load_word(void* skb, unsigned long long off) asm("llvm.bpf.load.word");
 
 #else  // LIBBPF DISABLED
 
diff --git a/loader/Android.bp b/loader/Android.bp
index c4a42cb..ab8ed49 100644
--- a/loader/Android.bp
+++ b/loader/Android.bp
@@ -74,40 +74,8 @@ rust_bindgen {
     ],
 }
 
-cc_test {
-    name: "libbpf_load_test",
-    test_suites: ["general-tests"],
-    header_libs: ["bpf_headers"],
-    srcs: [
-        "BpfLoadTest.cpp",
-    ],
-    defaults: ["bpf_cc_defaults"],
-    cflags: [
-        "-Wno-error=unused-variable",
-    ],
-    static_libs: [
-        "libbpf_android",
-        "libgmock",
-    ],
-    shared_libs: [
-        "libbpf_bcc",
-        "libbase",
-        "liblog",
-        "libutils",
-    ],
-
-    data: [
-        ":bpfLoadTpProg.o",
-    ],
-    require_root: true,
-}
-
-rust_binary {
-    name: "bpfloader",
-    cfgs: select(release_flag("RELEASE_BPF_ENABLE_LIBBPF"), {
-        true: ["enable_libbpf"],
-        default: [],
-    }),
+rust_defaults {
+    name: "bpfloader_defaults",
     srcs: [
         "bpfloader.rs",
     ],
@@ -118,20 +86,28 @@ rust_binary {
         "libanyhow",
         "liblog_rust",
         "liblibbpf_rs",
+        "liblibbpf_sys",
         "liblibc",
+        "librustutils",
+    ],
+}
+
+rust_test {
+    name: "bpfloader_tests",
+    defaults: ["bpfloader_defaults"],
+    test_suites: ["general-tests"],
+}
+
+rust_binary {
+    name: "bpfloader",
+    defaults: ["bpfloader_defaults"],
+    required: [
+        "timeInState.bpf",
     ],
-    required: [] + select(release_flag("RELEASE_BPF_ENABLE_LIBBPF"), {
-        true: [
-            "timeInState.bpf",
-        ],
-        default: [
-            "timeInState.o",
-        ],
-    }),
     product_variables: {
         debuggable: {
             required: [
-                "bpfRingbufProg.o",
+                "bpfRingbufProg.bpf",
             ],
         },
     },
diff --git a/loader/BpfLoadTest.cpp b/loader/BpfLoadTest.cpp
deleted file mode 100644
index 4ec89be..0000000
--- a/loader/BpfLoadTest.cpp
+++ /dev/null
@@ -1,131 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#include <android-base/file.h>
-#include <android-base/macros.h>
-#include <gtest/gtest.h>
-#include <libbpf.h>
-#include <stdlib.h>
-#include <unistd.h>
-#include <iostream>
-#include "bpf/BpfMap.h"
-#include "bpf/BpfUtils.h"
-#include "include/libbpf_android.h"
-
-namespace android {
-namespace bpf {
-
-class BpfLoadTest : public ::testing::Test {
-  protected:
-    BpfLoadTest() {}
-    int mProgFd;
-    std::string mTpProgPath;
-    std::string mTpNeverLoadProgPath;
-    std::string mTpMapPath;
-
-    void SetUp() {
-        /*
-         * b/326156952
-         *
-         * Kernels prior to 5.11 used rlimit memlock accounting for bpf memory
-         * allocations, and therefore require increasing the rlimit of this
-         * process for the maps to be created successfully.
-         *
-         * 5.11 introduces cgroup-based accounting as discussed here:
-         * https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com/
-         */
-        if (!isAtLeastKernelVersion(5, 11, 0)) EXPECT_EQ(setrlimitForTest(), 0);
-
-        mTpProgPath = "/sys/fs/bpf/prog_bpfLoadTpProg_tracepoint_sched_sched_switch";
-        unlink(mTpProgPath.c_str());
-
-        mTpNeverLoadProgPath = "/sys/fs/bpf/prog_bpfLoadTpProg_tracepoint_sched_sched_wakeup";
-        unlink(mTpNeverLoadProgPath.c_str());
-
-        mTpMapPath = "/sys/fs/bpf/map_bpfLoadTpProg_cpu_pid_map";
-        unlink(mTpMapPath.c_str());
-
-        auto progPath = android::base::GetExecutableDirectory() + "/bpfLoadTpProg.o";
-        bool critical = true;
-
-        bpf_prog_type kAllowed[] = {
-                BPF_PROG_TYPE_UNSPEC,
-        };
-
-        Location loc = {
-            .dir = "",
-            .prefix = "",
-            .allowedProgTypes = kAllowed,
-            .allowedProgTypesLength = arraysize(kAllowed),
-        };
-        EXPECT_EQ(android::bpf::loadProg(progPath.c_str(), &critical, loc), -1);
-
-        ASSERT_EQ(android::bpf::loadProg(progPath.c_str(), &critical), 0);
-        EXPECT_EQ(false, critical);
-
-        mProgFd = retrieveProgram(mTpProgPath.c_str());
-        ASSERT_GT(mProgFd, 0);
-
-        int ret = bpf_attach_tracepoint(mProgFd, "sched", "sched_switch");
-        EXPECT_NE(ret, 0);
-    }
-
-    void TearDown() {
-        close(mProgFd);
-        unlink(mTpProgPath.c_str());
-        unlink(mTpMapPath.c_str());
-    }
-
-    void checkMapNonZero() {
-        // The test program installs a tracepoint on sched:sched_switch
-        // and expects the kernel to populate a PID corresponding to CPU
-        android::bpf::BpfMap<uint32_t, uint32_t> m(mTpMapPath.c_str());
-
-        // Wait for program to run a little
-        sleep(1);
-
-        int non_zero = 0;
-        const auto iterFunc = [&non_zero](const uint32_t& key, const uint32_t& val,
-                                          BpfMap<uint32_t, uint32_t>& map) {
-            if (val && !non_zero) {
-                non_zero = 1;
-            }
-
-            UNUSED(key);
-            UNUSED(map);
-            return base::Result<void>();
-        };
-
-        EXPECT_RESULT_OK(m.iterateWithValue(iterFunc));
-        EXPECT_EQ(non_zero, 1);
-    }
-
-    void checkKernelVersionEnforced() {
-        ASSERT_EQ(retrieveProgram(mTpNeverLoadProgPath.c_str()), -1);
-        ASSERT_EQ(errno, ENOENT);
-    }
-};
-
-TEST_F(BpfLoadTest, bpfCheckMap) {
-    checkMapNonZero();
-}
-
-TEST_F(BpfLoadTest, bpfCheckMinKernelVersionEnforced) {
-    checkKernelVersionEnforced();
-}
-
-}  // namespace bpf
-}  // namespace android
diff --git a/loader/Loader.cpp b/loader/Loader.cpp
index 940ce19..9fbea05 100644
--- a/loader/Loader.cpp
+++ b/loader/Loader.cpp
@@ -36,6 +36,7 @@
 #include "bpf_map_def.h"
 #include "include/libbpf_android.h"
 
+#include <algorithm>
 #include <cstdlib>
 #include <fstream>
 #include <iostream>
diff --git a/loader/bpfloader.rs b/loader/bpfloader.rs
index 48f7319..b3af300 100644
--- a/loader/bpfloader.rs
+++ b/loader/bpfloader.rs
@@ -16,15 +16,21 @@
 
 //! BPF loader for system and vendor applications
 
-// Enable dead_code until feature flag is removed.
-#![cfg_attr(not(enable_libbpf), allow(dead_code))]
-
-use android_ids::{AID_ROOT, AID_SYSTEM};
+use android_ids::{AID_GRAPHICS, AID_MEDIA_RW, AID_ROOT, AID_SYSTEM};
 use android_logger::AndroidLogger;
 use anyhow::{anyhow, ensure};
-use libbpf_rs::{MapCore, ObjectBuilder};
-use libc::{mode_t, S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR};
-use log::{debug, error, info, Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
+use libbpf_rs::{
+    set_print, AsRawLibbpf, MapCore, ObjectBuilder, OpenObject, OpenProgramMut, PrintLevel,
+    ProgramType,
+};
+use libbpf_sys::{bpf_map__autocreate, bpf_program__set_type};
+use libc::{
+    mode_t, uname, utsname, S_IRGRP, S_IRUSR, S_IRWXG, S_IRWXO, S_IRWXU, S_ISVTX, S_IWGRP, S_IWUSR,
+};
+use log::{debug, error, info, warn, Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
+use rustutils::system_properties;
+use std::ffi::CStr;
+use std::mem::MaybeUninit;
 use std::{
     cmp::max,
     env, fs,
@@ -37,6 +43,15 @@ use std::{
     sync::{Arc, Mutex},
 };
 
+const fn kver(a: u32, b: u32, c: u32) -> u32 {
+    (a << 24) + (b << 16) + c
+}
+
+const KVER_NONE: u32 = kver(0, 0, 0);
+const KVER_INF: u32 = 0xFFFFFFFF;
+const KVER_5_10: u32 = kver(5, 10, 0);
+const KVER_6_1: u32 = kver(6, 1, 0);
+
 enum KernelLevel {
     // Commented out unused due to rust complaining...
     // EMERG = 0,
@@ -122,22 +137,67 @@ impl BpfKmsgLogger {
     }
 }
 
+fn libbpf_print(level: PrintLevel, mut msg: String) {
+    if msg.ends_with('\n') {
+        msg.pop();
+    }
+    match level {
+        PrintLevel::Debug => debug!("{}", msg),
+        PrintLevel::Info => info!("{}", msg),
+        PrintLevel::Warn => warn!("{}", msg),
+    }
+}
+
 struct MapDesc {
     name: &'static str,
     perms: mode_t,
+    owner: u32,
+    group: u32,
+    // Map is loaded if kernel_version() is >= min_kver and < max_kver
+    min_kver: u32,
+    max_kver: u32,
+}
+
+impl MapDesc {
+    pub const fn new(group: u32, perms: mode_t, name: &'static str) -> Self {
+        MapDesc { name, perms, owner: AID_ROOT, group, min_kver: KVER_NONE, max_kver: KVER_INF }
+    }
+
+    pub const fn new_kver(group: u32, perms: mode_t, min_kver: u32, name: &'static str) -> Self {
+        MapDesc { name, perms, owner: AID_ROOT, group, min_kver, max_kver: KVER_INF }
+    }
 }
 
 struct ProgDesc {
     name: &'static str,
+    owner: u32,
+    group: u32,
+    // Prog is loaded if kernel_version() is >= min_kver and < max_kver
+    min_kver: u32,
+    max_kver: u32,
+}
+
+impl ProgDesc {
+    pub const fn new(group: u32, name: &'static str) -> Self {
+        ProgDesc { name, owner: AID_ROOT, group, min_kver: KVER_NONE, max_kver: KVER_INF }
+    }
+
+    pub const fn new_kver(group: u32, min_kver: u32, name: &'static str) -> Self {
+        ProgDesc { name, owner: AID_ROOT, group, min_kver, max_kver: KVER_INF }
+    }
 }
 
 struct BpfFileDesc {
     filename: &'static str,
+    // The directory where the BPF file is located.
+    dir: &'static str,
+    // Maps and Progs are pinned under /sys/fs/bpf/<prefix>.
+    prefix: &'static str,
     // Warning: setting this to 'true' will cause the system to boot loop if there are any issues
     // loading the bpf program.
     critical: bool,
-    owner: u32,
-    group: u32,
+    // If this is true, maps and programs in the bpf object file are not loaded.
+    skip_on_user: bool,
     maps: &'static [MapDesc],
     progs: &'static [ProgDesc],
 }
@@ -147,57 +207,339 @@ const PERM_GRO: mode_t = S_IRUSR | S_IWUSR | S_IRGRP;
 const PERM_GWO: mode_t = S_IRUSR | S_IWUSR | S_IWGRP;
 const PERM_UGR: mode_t = S_IRUSR | S_IRGRP;
 
-const FILE_ARR: &[BpfFileDesc] = &[BpfFileDesc {
-    filename: "timeInState.bpf",
-    critical: false,
-    owner: AID_ROOT,
-    group: AID_SYSTEM,
-    maps: &[
-        MapDesc { name: "cpu_last_pid_map", perms: PERM_GWO },
-        MapDesc { name: "cpu_last_update_map", perms: PERM_GWO },
-        MapDesc { name: "cpu_policy_map", perms: PERM_GWO },
-        MapDesc { name: "freq_to_idx_map", perms: PERM_GWO },
-        MapDesc { name: "nr_active_map", perms: PERM_GWO },
-        MapDesc { name: "pid_task_aggregation_map", perms: PERM_GWO },
-        MapDesc { name: "pid_time_in_state_map", perms: PERM_GRO },
-        MapDesc { name: "pid_tracked_hash_map", perms: PERM_GWO },
-        MapDesc { name: "pid_tracked_map", perms: PERM_GWO },
-        MapDesc { name: "policy_freq_idx_map", perms: PERM_GWO },
-        MapDesc { name: "policy_nr_active_map", perms: PERM_GWO },
-        MapDesc { name: "total_time_in_state_map", perms: PERM_GRW },
-        MapDesc { name: "uid_concurrent_times_map", perms: PERM_GRW },
-        MapDesc { name: "uid_last_update_map", perms: PERM_GRW },
-        MapDesc { name: "uid_time_in_state_map", perms: PERM_GRW },
-    ],
-    progs: &[
-        ProgDesc { name: "tracepoint_power_cpu_frequency" },
-        ProgDesc { name: "tracepoint_sched_sched_process_free" },
-        ProgDesc { name: "tracepoint_sched_sched_switch" },
-    ],
-}];
+const GID_ROOT: u32 = AID_ROOT;
+const GID_SYSTEM: u32 = AID_SYSTEM;
+const GID_GRAPHICS: u32 = AID_GRAPHICS;
+const GID_MEDIA_RW: u32 = AID_MEDIA_RW;
+
+const FILE_ARR: &[BpfFileDesc] = &[
+    BpfFileDesc {
+        filename: "timeInState.bpf",
+        dir: "/etc/bpf/",
+        prefix: "",
+        critical: false,
+        skip_on_user: false,
+        maps: &[
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "cpu_last_pid_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "cpu_last_update_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "cpu_policy_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "freq_to_idx_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "nr_active_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "pid_task_aggregation_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GRO, "pid_time_in_state_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "pid_tracked_hash_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "pid_tracked_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "policy_freq_idx_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GWO, "policy_nr_active_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GRW, "total_time_in_state_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GRW, "uid_concurrent_times_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GRW, "uid_last_update_map"),
+            MapDesc::new(GID_SYSTEM, PERM_GRW, "uid_time_in_state_map"),
+        ],
+        progs: &[
+            ProgDesc::new(GID_SYSTEM, "tracepoint_power_cpu_frequency"),
+            ProgDesc::new(GID_SYSTEM, "tracepoint_sched_sched_process_free"),
+            ProgDesc::new(GID_SYSTEM, "tracepoint_sched_sched_switch"),
+        ],
+    },
+    BpfFileDesc {
+        filename: "fuseMedia.bpf",
+        dir: "/etc/bpf/",
+        prefix: "",
+        critical: false,
+        skip_on_user: false,
+        maps: &[],
+        progs: &[ProgDesc::new(GID_MEDIA_RW, "fuse_media")],
+    },
+    BpfFileDesc {
+        filename: "gpuMem.bpf",
+        dir: "/etc/bpf/",
+        prefix: "",
+        critical: false,
+        skip_on_user: false,
+        maps: &[MapDesc::new(GID_GRAPHICS, PERM_GRO, "gpu_mem_total_map")],
+        progs: &[ProgDesc::new(GID_GRAPHICS, "tracepoint_gpu_mem_gpu_mem_total")],
+    },
+    BpfFileDesc {
+        filename: "gpuWork.bpf",
+        dir: "/etc/bpf/",
+        prefix: "",
+        critical: false,
+        skip_on_user: false,
+        maps: &[
+            MapDesc::new(GID_GRAPHICS, PERM_GRW, "gpu_work_map"),
+            MapDesc::new(GID_GRAPHICS, PERM_GRW, "gpu_work_global_data"),
+        ],
+        progs: &[ProgDesc::new(GID_GRAPHICS, "tracepoint_power_gpu_work_period")],
+    },
+    BpfFileDesc {
+        filename: "bpfMemEvents.bpf",
+        dir: "/etc/bpf/memevents/",
+        prefix: "memevents/",
+        critical: false,
+        skip_on_user: false,
+        maps: &[
+            MapDesc::new_kver(GID_SYSTEM, PERM_GRW, KVER_5_10, "ams_rb"),
+            MapDesc::new_kver(GID_SYSTEM, PERM_GRW, KVER_5_10, "lmkd_rb"),
+        ],
+        progs: &[
+            ProgDesc::new_kver(GID_SYSTEM, KVER_5_10, "tracepoint_oom_mark_victim_ams"),
+            ProgDesc::new_kver(
+                GID_SYSTEM,
+                KVER_5_10,
+                "tracepoint_vmscan_mm_vmscan_direct_reclaim_begin_lmkd",
+            ),
+            ProgDesc::new_kver(
+                GID_SYSTEM,
+                KVER_5_10,
+                "tracepoint_vmscan_mm_vmscan_direct_reclaim_end_lmkd",
+            ),
+            ProgDesc::new_kver(
+                GID_SYSTEM,
+                KVER_5_10,
+                "tracepoint_vmscan_mm_vmscan_kswapd_wake_lmkd",
+            ),
+            ProgDesc::new_kver(
+                GID_SYSTEM,
+                KVER_5_10,
+                "tracepoint_vmscan_mm_vmscan_kswapd_sleep_lmkd",
+            ),
+            ProgDesc::new_kver(
+                GID_SYSTEM,
+                KVER_6_1,
+                "tracepoint_android_vendor_lmk_android_trigger_vendor_lmk_kill_lmkd",
+            ),
+            ProgDesc::new_kver(
+                GID_SYSTEM,
+                KVER_6_1,
+                "tracepoint_kmem_mm_calculate_totalreserve_pages_lmkd",
+            ),
+        ],
+    },
+    BpfFileDesc {
+        filename: "bpfMemEventsTest.bpf",
+        dir: "/etc/bpf/memevents/",
+        prefix: "memevents/",
+        critical: false,
+        skip_on_user: true,
+        maps: &[MapDesc::new_kver(GID_SYSTEM, PERM_GRW, KVER_5_10, "rb")],
+        progs: &[
+            ProgDesc::new_kver(GID_SYSTEM, KVER_5_10, "tracepoint_oom_mark_victim"),
+            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_oom_kill"),
+            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_direct_reclaim_begin"),
+            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_direct_reclaim_end"),
+            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_kswapd_wake"),
+            ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_kswapd_sleep"),
+            ProgDesc::new_kver(GID_SYSTEM, KVER_6_1, "skfilter_android_trigger_vendor_lmk_kill"),
+            ProgDesc::new_kver(GID_ROOT, KVER_6_1, "skfilter_calculate_totalreserve_pages"),
+        ],
+    },
+    BpfFileDesc {
+        filename: "bpfRingbufProg.bpf",
+        dir: "/etc/bpf/",
+        prefix: "",
+        critical: true,
+        skip_on_user: true,
+        maps: &[MapDesc::new_kver(GID_ROOT, PERM_GRW, KVER_5_10, "test_ringbuf")],
+        progs: &[ProgDesc::new_kver(GID_ROOT, KVER_5_10, "skfilter_ringbuf_test")],
+    },
+    BpfFileDesc {
+        filename: "filterPowerSupplyEvents.bpf",
+        dir: "vendor/etc/bpf/",
+        prefix: "vendor/",
+        critical: true,
+        skip_on_user: false,
+        maps: &[],
+        progs: &[ProgDesc::new_kver(GID_SYSTEM, KVER_5_10, "skfilter_power_supply")],
+    },
+];
+
+// TODO: Remove this code when fuse-bpf is upstreamed
+fn set_fuse_prog_type(prog: OpenProgramMut) -> Result<(), anyhow::Error> {
+    let path = Path::new("/sys/fs/fuse/bpf_prog_type_fuse");
+    let prog_type_str =
+        fs::read_to_string(path).map_err(|e| anyhow!("Failed to read fuse prog type: {e}"))?;
+    let prog_type = prog_type_str
+        .trim()
+        .parse::<u32>()
+        .map_err(|e| anyhow!("Failed to parse fuse prog type {prog_type_str}: {e}"))?;
+    // SAFETY: If the return value is 0, program type should be updated correctly.
+    // prog.set_prog_type can not be used because ProgramType does not contain BPF_PROG_TYPE_FUSE
+    if unsafe { bpf_program__set_type(prog.as_libbpf_object().as_ptr(), prog_type) } != 0 {
+        return Err(anyhow!("Failed to set fuse prog type {prog_type}"));
+    }
+    Ok(())
+}
+
+fn set_prog_types(open_file: &mut OpenObject) -> Result<(), anyhow::Error> {
+    for mut prog in open_file.progs_mut() {
+        let section_name =
+            prog.section().to_str().ok_or_else(|| anyhow!("Failed to parse prog section name"))?;
+        if section_name.starts_with("skfilter/") {
+            prog.set_prog_type(ProgramType::SocketFilter);
+        } else if section_name.starts_with("fuse/") {
+            set_fuse_prog_type(prog)?;
+        }
+    }
+    Ok(())
+}
+
+fn create_dir(dir_path: &Path) -> Result<(), anyhow::Error> {
+    if dir_path.exists() {
+        return Ok(());
+    }
+    fs::create_dir(dir_path)
+        .map_err(|e| anyhow!("Failed to create {}: {e}", dir_path.display()))?;
+    // The cast is not unnecessary on all platforms.
+    #[allow(clippy::unnecessary_cast)]
+    fs::set_permissions(
+        dir_path,
+        Permissions::from_mode((S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO) as u32),
+    )
+    .map_err(|e| anyhow!("Failed to set permissions for {}: {e}", dir_path.display()))?;
+    Ok(())
+}
+
+fn leading_number(str: &str) -> u32 {
+    let mut num_str = String::new();
+    for c in str.chars() {
+        if c.is_ascii_digit() {
+            num_str.push(c);
+        } else {
+            break;
+        }
+    }
+    num_str.parse().unwrap_or(0)
+}
+
+// Parses a kernel release string into a tuple of (major, minor, sub) version numbers.
+// Examples:
+// - "6.1.128-android14" returns (6, 1, 128)
+// - "6.1.128android14" returns (6, 1, 128)
+// - "6.1" returns (6, 1, 0)
+fn parse_release(release: &str) -> (u32, u32, u32) {
+    let mut iter = release.splitn(3, '.');
+    let major = leading_number(iter.next().unwrap_or(""));
+    let minor = leading_number(iter.next().unwrap_or(""));
+    let sub = leading_number(iter.next().unwrap_or(""));
+    (major, minor, sub)
+}
+
+fn kernel_version() -> Result<u32, anyhow::Error> {
+    let mut buf: MaybeUninit<utsname> = MaybeUninit::zeroed();
+    // SAFETY: If uname returns 0, the buf should be properly initialized.
+    if unsafe { uname(buf.as_mut_ptr()) } != 0 {
+        return Err(anyhow!("Failed to call uname system call."));
+    }
+    // SAFETY: `uname` returned 0, so the buf should be properly initialized.
+    let buf = unsafe { buf.assume_init() };
+    // SAFETY: buf.release is part of the utsname struct populated by uname.
+    let release_cstr = unsafe { CStr::from_ptr(buf.release.as_ptr()) };
+    let release = release_cstr
+        .to_str()
+        .map_err(|e| anyhow!("utsname release string is not valid UTF-8: {}", e))?;
+
+    let (major, minor, sub) = parse_release(release);
+    Ok(kver(major, minor, sub))
+}
+
+fn set_skip_loading(
+    open_file: &mut OpenObject,
+    file_desc: &BpfFileDesc,
+) -> Result<(), anyhow::Error> {
+    let kvers = kernel_version()?;
+
+    for mut map in open_file.maps_mut() {
+        let name =
+            map.name().to_str().ok_or_else(|| anyhow!("Failed to parse map name into UTF-8"))?;
+        for map_desc in file_desc.maps {
+            if map_desc.name == name {
+                if kvers < map_desc.min_kver || kvers >= map_desc.max_kver {
+                    info!(
+                        "skipping map {} min_kver:{:x} max_kver:{:x} kvers:{:x}",
+                        name, map_desc.min_kver, map_desc.max_kver, kvers
+                    );
+                    map.set_autocreate(false)?;
+                }
+                break;
+            }
+        }
+    }
+
+    for mut prog in open_file.progs_mut() {
+        let name =
+            prog.name().to_str().ok_or_else(|| anyhow!("Failed to parse prog name into UTF-8"))?;
+        for prog_desc in file_desc.progs {
+            if prog_desc.name == name {
+                if kvers < prog_desc.min_kver || kvers >= prog_desc.max_kver {
+                    info!(
+                        "skipping program {} min_kver:{:x} max_kver:{:x} kvers:{:x}",
+                        name, prog_desc.min_kver, prog_desc.max_kver, kvers
+                    );
+                    prog.set_autoload(false);
+                }
+                break;
+            }
+        }
+    }
+
+    Ok(())
+}
+
+fn is_user_build() -> Result<bool, anyhow::Error> {
+    if let Some(build_string) = system_properties::read("ro.build.type")? {
+        Ok(build_string == "user")
+    } else {
+        Ok(false)
+    }
+}
 
 fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
     info!("Loading {}", file_desc.filename);
-    let filepath = Path::new("/etc/bpf/").join(file_desc.filename);
-    ensure!(filepath.exists(), "File not found {}", filepath.display());
+    if file_desc.skip_on_user && is_user_build()? {
+        info!("Skip loading {} on user build", file_desc.filename);
+        return Ok(());
+    }
+    let filepath = Path::new(file_desc.dir).join(file_desc.filename);
+    // TODO: Make this error once the BPF loader migration completes.
+    if !filepath.exists() {
+        info!("Skipping load of {} as it does not exist", filepath.display());
+        return Ok(());
+    }
     let filename =
         filepath.file_stem().ok_or_else(|| anyhow!("Failed to parse stem from filename"))?;
     let filename = filename.to_str().ok_or_else(|| anyhow!("Failed to parse filename"))?;
 
     let mut ob = ObjectBuilder::default();
-    let open_file = ob.open_file(&filepath)?;
+    let mut open_file = ob.open_file(&filepath)?;
+    // libbpf's open_file attempts to infer the prog type based on the section name. But, some
+    // section names are not recognized, so the program type must be set explicitly for them.
+    set_prog_types(&mut open_file)?;
+    set_skip_loading(&mut open_file, file_desc)?;
     let mut loaded_file = open_file.load()?;
 
-    let bpffs_path = "/sys/fs/bpf/".to_owned();
+    let bpffs_path = "/sys/fs/bpf/".to_owned() + file_desc.prefix;
+    create_dir(Path::new(&bpffs_path))?;
 
     for mut map in loaded_file.maps_mut() {
         let mut desc_found = false;
         let name =
             map.name().to_str().ok_or_else(|| anyhow!("Failed to parse map name into UTF-8"))?;
         let name = String::from(name);
+        if name.ends_with(".rodata") {
+            // Skip pinning map for .rodata section.
+            continue;
+        }
         for map_desc in file_desc.maps {
             if map_desc.name == name {
                 desc_found = true;
+                // SAFETY: bpf_map__autocreate just returns the field value of libbpf struct
+                let autocreate = unsafe { bpf_map__autocreate(map.as_libbpf_object().as_ptr()) };
+                if !autocreate {
+                    // This map is not loaded
+                    continue;
+                }
+
                 let pinpath_str = bpffs_path.clone() + "map_" + filename + "_" + &name;
                 let pinpath = Path::new(&pinpath_str);
                 debug!("Pinning: {}", pinpath.display());
@@ -211,12 +553,12 @@ fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
                         )
                     },
                 )?;
-                chown(pinpath, Some(file_desc.owner), Some(file_desc.group)).map_err(|e| {
+                chown(pinpath, Some(map_desc.owner), Some(map_desc.group)).map_err(|e| {
                     anyhow!(
                         "Failed to chown {} with owner: {} group: {} err: {e}",
                         pinpath.display(),
-                        file_desc.owner,
-                        file_desc.group
+                        map_desc.owner,
+                        map_desc.group
                     )
                 })?;
                 break;
@@ -233,6 +575,10 @@ fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
         for prog_desc in file_desc.progs {
             if prog_desc.name == name {
                 desc_found = true;
+                if !prog.autoload() {
+                    // This program is not loaded
+                    continue;
+                }
                 let pinpath_str = bpffs_path.clone() + "prog_" + filename + "_" + &name;
                 let pinpath = Path::new(&pinpath_str);
                 debug!("Pinning: {}", pinpath.display());
@@ -245,12 +591,12 @@ fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
                         )
                     },
                 )?;
-                chown(pinpath, Some(file_desc.owner), Some(file_desc.group)).map_err(|e| {
+                chown(pinpath, Some(prog_desc.owner), Some(prog_desc.group)).map_err(|e| {
                     anyhow!(
                         "Failed to chown {} with owner: {} group: {} err: {e}",
                         pinpath.display(),
-                        file_desc.owner,
-                        file_desc.group
+                        prog_desc.owner,
+                        prog_desc.group
                     )
                 })?;
                 break;
@@ -261,7 +607,6 @@ fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
     Ok(())
 }
 
-#[cfg(enable_libbpf)]
 fn load_libbpf_progs() {
     info!("Loading libbpf programs");
     for file_desc in FILE_ARR {
@@ -275,12 +620,6 @@ fn load_libbpf_progs() {
     }
 }
 
-#[cfg(not(enable_libbpf))]
-fn load_libbpf_progs() {
-    // Empty stub for feature flag disabled case
-    info!("Loading libbpf programs DISABLED");
-}
-
 fn main() {
     let kmsg_fd = env::var("ANDROID_FILE__dev_kmsg").unwrap().parse::<i32>().unwrap();
     // SAFETY: The init script opens this file for us
@@ -295,6 +634,9 @@ fn main() {
         error!("{}", panic_info);
     }));
 
+    // Enable logging from libbpf
+    set_print(Some((PrintLevel::Debug, libbpf_print)));
+
     load_libbpf_progs();
     info!("Loading legacy BPF progs");
 
@@ -308,3 +650,20 @@ fn main() {
         bpf_android_bindgen::execNetBpfLoadDone();
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn verify_parse_release() {
+        assert_eq!(parse_release("6.1.128-android14-11-g213d628eb429-ab13297919"), (6, 1, 128));
+        assert_eq!(parse_release("6.1.128_android14"), (6, 1, 128));
+        assert_eq!(parse_release("6.1.128.4"), (6, 1, 128));
+        assert_eq!(parse_release("6.1.android14"), (6, 1, 0));
+        assert_eq!(parse_release("6.1-android14"), (6, 1, 0));
+        assert_eq!(parse_release("6.1"), (6, 1, 0));
+        assert_eq!(parse_release("6"), (6, 0, 0));
+        assert_eq!(parse_release("android14"), (0, 0, 0));
+    }
+}
diff --git a/progs/Android.bp b/progs/Android.bp
index 3d9c5a6..9401df5 100644
--- a/progs/Android.bp
+++ b/progs/Android.bp
@@ -31,3 +31,11 @@ bpf {
     name: "bpfRingbufProg.o",
     srcs: ["bpfRingbufProg.c"],
 }
+
+libbpf_prog {
+    name: "bpfRingbufProg.bpf",
+    srcs: ["bpfRingbufProg.c"],
+    header_libs: [
+        "android_bpf_defs",
+    ],
+}
diff --git a/progs/bpfRingbufProg.c b/progs/bpfRingbufProg.c
index 4f268bf..459705e 100644
--- a/progs/bpfRingbufProg.c
+++ b/progs/bpfRingbufProg.c
@@ -14,7 +14,13 @@
  * limitations under the License.
  */
 
+// Because include_dirs is not allowed under system/bpf, include
+// <android_bpf_defs.h> only if the code is built for libbpf_prog target.
+#ifdef ENABLE_LIBBPF
+#include <android_bpf_defs.h>
+#else
 #include "bpf_helpers.h"
+#endif
 
 // This can't be easily changed since the program is loaded on boot and may be
 // run against tests at a slightly different version.
@@ -25,7 +31,8 @@ DEFINE_BPF_RINGBUF(test_ringbuf, __u64, 4096, AID_ROOT, AID_ROOT, 0660);
 
 // This program is for test purposes only - it should never be attached to a
 // socket, only executed manually with BPF_PROG_RUN.
-DEFINE_BPF_PROG_KVER("skfilter/ringbuf_test", AID_ROOT, AID_ROOT, test_ringbuf_prog, KVER(5, 8, 0))
+DEFINE_BPF_PROG_KVER("skfilter/ringbuf_test", AID_ROOT, AID_ROOT, skfilter_ringbuf_test,
+                     KVER(5, 10, 0))
 (void* __unused ctx) {
     __u64* output = bpf_test_ringbuf_reserve();
     if (output == NULL) return 1;
```

