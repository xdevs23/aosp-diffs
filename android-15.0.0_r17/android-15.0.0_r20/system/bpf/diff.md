```diff
diff --git a/Android.bp b/Android.bp
index dca9aba..14a195b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -33,6 +33,11 @@ cc_library_headers {
     },
 }
 
+cc_library_headers {
+    name: "android_bpf_defs",
+    export_include_dirs: ["include/defs"],
+}
+
 cc_defaults {
     name: "bpf_cc_defaults",
     cflags: [
diff --git a/include/defs/android_bpf_defs.h b/include/defs/android_bpf_defs.h
new file mode 100644
index 0000000..35cf057
--- /dev/null
+++ b/include/defs/android_bpf_defs.h
@@ -0,0 +1,59 @@
+#pragma once
+
+#ifdef ENABLE_LIBBPF
+
+// Either vmlinux.h or linux/types.h must be included before bpf/bpf_helpers.h
+#ifdef USE_VMLINUX
+// When using vmlinux.h, you can't use any system level headers.
+#include <vmlinux.h>
+#else
+#include <linux/types.h>
+#endif  // USE_VMLINUX
+#include <bpf/bpf_helpers.h>
+
+#define DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)               \
+    struct {                                                                                   \
+        __uint(type, BPF_MAP_TYPE_##TYPE);                                                     \
+        __type(key, KeyType);                                                                  \
+        __type(value, ValueType);                                                              \
+        __uint(max_entries, num_entries);                                                      \
+    } the_map SEC(".maps");                                                                    \
+                                                                                               \
+    static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(             \
+            const KeyType* k) {                                                                \
+        return bpf_map_lookup_elem(&the_map, k);                                               \
+    };                                                                                         \
+                                                                                               \
+    static inline __always_inline __unused int bpf_##the_map##_update_elem(                    \
+            const KeyType* k, const ValueType* v, unsigned long long flags) {                  \
+        return bpf_map_update_elem(&the_map, k, v, flags);                                     \
+    };                                                                                         \
+                                                                                               \
+    static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) { \
+        return bpf_map_delete_elem(&the_map, k);                                               \
+    };
+
+#define DEFINE_BPF_MAP_GRW(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)
+#define DEFINE_BPF_MAP_GWO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)
+#define DEFINE_BPF_MAP_GRO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_BASE(the_map, TYPE, KeyType, ValueType, num_entries, gid)
+
+#define DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog) \
+    SEC(SECTION_NAME)                                               \
+    int the_prog
+
+#define LICENSE(NAME) char _license[] SEC("license") = (NAME)
+
+#else  // LIBBPF DISABLED
+
+#include <bpf_helpers.h>
+
+#define bpf_printk(fmt, ...)                                       \
+    ({                                                             \
+        char ____fmt[] = fmt;                                      \
+        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
+    })
+
+#endif  // ENABLE_LIBBPF
diff --git a/loader/Android.bp b/loader/Android.bp
index 1e68f92..c4a42cb 100644
--- a/loader/Android.bp
+++ b/loader/Android.bp
@@ -113,11 +113,21 @@ rust_binary {
     ],
     rustlibs: [
         "libbpf_android_bindgen",
+        "libandroid_ids",
+        "libandroid_logger",
+        "libanyhow",
+        "liblog_rust",
+        "liblibbpf_rs",
+        "liblibc",
     ],
-    required: [
-        "timeInState.o",
-    ],
-
+    required: [] + select(release_flag("RELEASE_BPF_ENABLE_LIBBPF"), {
+        true: [
+            "timeInState.bpf",
+        ],
+        default: [
+            "timeInState.o",
+        ],
+    }),
     product_variables: {
         debuggable: {
             required: [
diff --git a/loader/Loader.cpp b/loader/Loader.cpp
index cf6bf36..09e2e17 100644
--- a/loader/Loader.cpp
+++ b/loader/Loader.cpp
@@ -1014,23 +1014,3 @@ void execNetBpfLoadDone() {
     ALOGE("FATAL: execve(): %d[%s]", errno, strerror(errno));
     exit(122);
 }
-
-void logVerbose(const char* msg) {
-    ALOGV("%s", msg);
-}
-
-void logDebug(const char* msg) {
-    ALOGD("%s", msg);
-}
-
-void logInfo(const char* msg) {
-    ALOGI("%s", msg);
-}
-
-void logWarn(const char* msg) {
-    ALOGW("%s", msg);
-}
-
-void logError(const char* msg) {
-    ALOGE("%s", msg);
-}
diff --git a/loader/bpfloader.rs b/loader/bpfloader.rs
index ede1a29..48f7319 100644
--- a/loader/bpfloader.rs
+++ b/loader/bpfloader.rs
@@ -16,18 +16,287 @@
 
 //! BPF loader for system and vendor applications
 
+// Enable dead_code until feature flag is removed.
+#![cfg_attr(not(enable_libbpf), allow(dead_code))]
+
+use android_ids::{AID_ROOT, AID_SYSTEM};
+use android_logger::AndroidLogger;
+use anyhow::{anyhow, ensure};
+use libbpf_rs::{MapCore, ObjectBuilder};
+use libc::{mode_t, S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR};
+use log::{debug, error, info, Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
+use std::{
+    cmp::max,
+    env, fs,
+    fs::{File, Permissions},
+    io::{LineWriter, Write},
+    os::fd::FromRawFd,
+    os::unix::fs::{chown, PermissionsExt},
+    panic,
+    path::Path,
+    sync::{Arc, Mutex},
+};
+
+enum KernelLevel {
+    // Commented out unused due to rust complaining...
+    // EMERG = 0,
+    // ALERT = 1,
+    // CRIT = 2,
+    ERR = 3,
+    WARNING = 4,
+    // NOTICE = 5,
+    INFO = 6,
+    DEBUG = 7,
+}
+
+fn level_to_kern_level(level: &Level) -> u8 {
+    let result = match level {
+        Level::Error => KernelLevel::ERR,
+        Level::Warn => KernelLevel::WARNING,
+        Level::Info => KernelLevel::INFO,
+        Level::Debug => KernelLevel::DEBUG,
+        Level::Trace => KernelLevel::DEBUG,
+    };
+    result as u8
+}
+
+/// A logger implementation to enable bpfloader to write to kmsg on error as
+/// bpfloader runs at early init prior to the availability of standard Android
+/// logging. If a crash were to occur, we can disrupt boot, and therefore we
+/// need the ability to access the logs on the serial port.
+pub struct BpfKmsgLogger {
+    log_level: LevelFilter,
+    tag: String,
+    kmsg_writer: Arc<Mutex<Box<dyn Write + Send>>>,
+    a_logger: AndroidLogger,
+}
+
+impl Log for BpfKmsgLogger {
+    fn enabled(&self, metadata: &Metadata) -> bool {
+        metadata.level() <= self.log_level || self.a_logger.enabled(metadata)
+    }
+
+    fn log(&self, record: &Record) {
+        if !self.enabled(record.metadata()) {
+            return;
+        }
+
+        if record.metadata().level() <= self.log_level {
+            let mut writer = self.kmsg_writer.lock().unwrap();
+            write!(
+                writer,
+                "<{}>{}: {}",
+                level_to_kern_level(&record.level()),
+                self.tag,
+                record.args()
+            )
+            .unwrap();
+            let _ = writer.flush();
+        }
+        self.a_logger.log(record);
+    }
+
+    fn flush(&self) {}
+}
+
+impl BpfKmsgLogger {
+    /// Initialize the logger
+    pub fn init(kmsg_file: File) -> Result<(), SetLoggerError> {
+        let alog_level = LevelFilter::Info;
+        let kmsg_level = LevelFilter::Error;
+
+        let log_config = android_logger::Config::default()
+            .with_tag("BpfLoader-rs")
+            .with_max_level(alog_level)
+            .with_log_buffer(android_logger::LogId::Main)
+            .format(|buf, record| writeln!(buf, "{}", record.args()));
+
+        let writer = Box::new(LineWriter::new(kmsg_file)) as Box<dyn Write + Send>;
+        log::set_max_level(max(alog_level, kmsg_level));
+        log::set_boxed_logger(Box::new(BpfKmsgLogger {
+            log_level: kmsg_level,
+            tag: "BpfLoader-rs".to_string(),
+            kmsg_writer: Arc::new(Mutex::new(writer)),
+            a_logger: AndroidLogger::new(log_config),
+        }))
+    }
+}
+
+struct MapDesc {
+    name: &'static str,
+    perms: mode_t,
+}
+
+struct ProgDesc {
+    name: &'static str,
+}
+
+struct BpfFileDesc {
+    filename: &'static str,
+    // Warning: setting this to 'true' will cause the system to boot loop if there are any issues
+    // loading the bpf program.
+    critical: bool,
+    owner: u32,
+    group: u32,
+    maps: &'static [MapDesc],
+    progs: &'static [ProgDesc],
+}
+
+const PERM_GRW: mode_t = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
+const PERM_GRO: mode_t = S_IRUSR | S_IWUSR | S_IRGRP;
+const PERM_GWO: mode_t = S_IRUSR | S_IWUSR | S_IWGRP;
+const PERM_UGR: mode_t = S_IRUSR | S_IRGRP;
+
+const FILE_ARR: &[BpfFileDesc] = &[BpfFileDesc {
+    filename: "timeInState.bpf",
+    critical: false,
+    owner: AID_ROOT,
+    group: AID_SYSTEM,
+    maps: &[
+        MapDesc { name: "cpu_last_pid_map", perms: PERM_GWO },
+        MapDesc { name: "cpu_last_update_map", perms: PERM_GWO },
+        MapDesc { name: "cpu_policy_map", perms: PERM_GWO },
+        MapDesc { name: "freq_to_idx_map", perms: PERM_GWO },
+        MapDesc { name: "nr_active_map", perms: PERM_GWO },
+        MapDesc { name: "pid_task_aggregation_map", perms: PERM_GWO },
+        MapDesc { name: "pid_time_in_state_map", perms: PERM_GRO },
+        MapDesc { name: "pid_tracked_hash_map", perms: PERM_GWO },
+        MapDesc { name: "pid_tracked_map", perms: PERM_GWO },
+        MapDesc { name: "policy_freq_idx_map", perms: PERM_GWO },
+        MapDesc { name: "policy_nr_active_map", perms: PERM_GWO },
+        MapDesc { name: "total_time_in_state_map", perms: PERM_GRW },
+        MapDesc { name: "uid_concurrent_times_map", perms: PERM_GRW },
+        MapDesc { name: "uid_last_update_map", perms: PERM_GRW },
+        MapDesc { name: "uid_time_in_state_map", perms: PERM_GRW },
+    ],
+    progs: &[
+        ProgDesc { name: "tracepoint_power_cpu_frequency" },
+        ProgDesc { name: "tracepoint_sched_sched_process_free" },
+        ProgDesc { name: "tracepoint_sched_sched_switch" },
+    ],
+}];
+
+fn libbpf_worker(file_desc: &BpfFileDesc) -> Result<(), anyhow::Error> {
+    info!("Loading {}", file_desc.filename);
+    let filepath = Path::new("/etc/bpf/").join(file_desc.filename);
+    ensure!(filepath.exists(), "File not found {}", filepath.display());
+    let filename =
+        filepath.file_stem().ok_or_else(|| anyhow!("Failed to parse stem from filename"))?;
+    let filename = filename.to_str().ok_or_else(|| anyhow!("Failed to parse filename"))?;
+
+    let mut ob = ObjectBuilder::default();
+    let open_file = ob.open_file(&filepath)?;
+    let mut loaded_file = open_file.load()?;
+
+    let bpffs_path = "/sys/fs/bpf/".to_owned();
+
+    for mut map in loaded_file.maps_mut() {
+        let mut desc_found = false;
+        let name =
+            map.name().to_str().ok_or_else(|| anyhow!("Failed to parse map name into UTF-8"))?;
+        let name = String::from(name);
+        for map_desc in file_desc.maps {
+            if map_desc.name == name {
+                desc_found = true;
+                let pinpath_str = bpffs_path.clone() + "map_" + filename + "_" + &name;
+                let pinpath = Path::new(&pinpath_str);
+                debug!("Pinning: {}", pinpath.display());
+                map.pin(pinpath).map_err(|e| anyhow!("Failed to pin map {name}: {e}"))?;
+                fs::set_permissions(pinpath, Permissions::from_mode(map_desc.perms as _)).map_err(
+                    |e| {
+                        anyhow!(
+                            "Failed to set permissions: {} on pinned map {}: {e}",
+                            map_desc.perms,
+                            pinpath.display()
+                        )
+                    },
+                )?;
+                chown(pinpath, Some(file_desc.owner), Some(file_desc.group)).map_err(|e| {
+                    anyhow!(
+                        "Failed to chown {} with owner: {} group: {} err: {e}",
+                        pinpath.display(),
+                        file_desc.owner,
+                        file_desc.group
+                    )
+                })?;
+                break;
+            }
+        }
+        ensure!(desc_found, "Descriptor for {name} not found!");
+    }
+
+    for mut prog in loaded_file.progs_mut() {
+        let mut desc_found = false;
+        let name =
+            prog.name().to_str().ok_or_else(|| anyhow!("Failed to parse prog name into UTF-8"))?;
+        let name = String::from(name);
+        for prog_desc in file_desc.progs {
+            if prog_desc.name == name {
+                desc_found = true;
+                let pinpath_str = bpffs_path.clone() + "prog_" + filename + "_" + &name;
+                let pinpath = Path::new(&pinpath_str);
+                debug!("Pinning: {}", pinpath.display());
+                prog.pin(pinpath).map_err(|e| anyhow!("Failed to pin prog {name}: {e}"))?;
+                fs::set_permissions(pinpath, Permissions::from_mode(PERM_UGR as _)).map_err(
+                    |e| {
+                        anyhow!(
+                            "Failed to set permissions on pinned prog {}: {e}",
+                            pinpath.display()
+                        )
+                    },
+                )?;
+                chown(pinpath, Some(file_desc.owner), Some(file_desc.group)).map_err(|e| {
+                    anyhow!(
+                        "Failed to chown {} with owner: {} group: {} err: {e}",
+                        pinpath.display(),
+                        file_desc.owner,
+                        file_desc.group
+                    )
+                })?;
+                break;
+            }
+        }
+        ensure!(desc_found, "Descriptor for {name} not found!");
+    }
+    Ok(())
+}
+
 #[cfg(enable_libbpf)]
 fn load_libbpf_progs() {
-    // Libbpf loader functionality here.
+    info!("Loading libbpf programs");
+    for file_desc in FILE_ARR {
+        if let Err(e) = libbpf_worker(file_desc) {
+            if file_desc.critical {
+                panic!("Error when loading {0}: {e}", file_desc.filename);
+            } else {
+                error!("Error when loading {0}: {e}", file_desc.filename);
+            }
+        };
+    }
 }
 
 #[cfg(not(enable_libbpf))]
 fn load_libbpf_progs() {
     // Empty stub for feature flag disabled case
+    info!("Loading libbpf programs DISABLED");
 }
 
 fn main() {
+    let kmsg_fd = env::var("ANDROID_FILE__dev_kmsg").unwrap().parse::<i32>().unwrap();
+    // SAFETY: The init script opens this file for us
+    let kmsg_file = unsafe { File::from_raw_fd(kmsg_fd) };
+
+    if let Err(logger) = BpfKmsgLogger::init(kmsg_file) {
+        error!("BpfLoader-rs: log::setlogger failed: {}", logger);
+    }
+
+    // Redirect panic messages to both logcat and serial port
+    panic::set_hook(Box::new(|panic_info| {
+        error!("{}", panic_info);
+    }));
+
     load_libbpf_progs();
+    info!("Loading legacy BPF progs");
 
     // SAFETY: Linking in the existing legacy bpfloader functionality.
     // Any of the four following bindgen functions can abort() or exit()
diff --git a/loader/include/libbpf_android.h b/loader/include/libbpf_android.h
index 8e5a887..ae4a36d 100644
--- a/loader/include/libbpf_android.h
+++ b/loader/include/libbpf_android.h
@@ -53,13 +53,6 @@ void createBpfFsSubDirectories();
 void legacyBpfLoader();
 __noreturn void execNetBpfLoadDone();
 
-// For logging from rust
-void logVerbose(const char* msg);
-void logDebug(const char* msg);
-void logInfo(const char* msg);
-void logWarn(const char* msg);
-void logError(const char* msg);
-
 #ifdef __cplusplus
 }  // extern C
 #endif
diff --git a/progs/include/test/mock_bpf_helpers.h b/progs/include/test/mock_bpf_helpers.h
deleted file mode 100644
index 141ee4f..0000000
--- a/progs/include/test/mock_bpf_helpers.h
+++ /dev/null
@@ -1,94 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#pragma once
-
-/* Mock BPF helpers to be used for testing of BPF programs loaded by Android */
-
-#include <linux/bpf.h>
-#include <stdbool.h>
-#include <stdint.h>
-
-#include <cutils/android_filesystem_config.h>
-
-typedef void* mock_bpf_map_t;
-
-/* type safe macro to declare a map and related accessor functions */
-#define DEFINE_BPF_MAP_UGM(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, usr, grp, md)     \
-    mock_bpf_map_t mock_bpf_map_##the_map;                                                       \
-                                                                                                 \
-    mock_bpf_map_t get_mock_bpf_map_##the_map() {                                                \
-        if (mock_bpf_map_##the_map == 0) {                                                       \
-            mock_bpf_map_##the_map = mock_bpf_map_create(sizeof(TypeOfKey), sizeof(TypeOfValue), \
-                                                         BPF_MAP_TYPE_##TYPE);                   \
-        }                                                                                        \
-        return mock_bpf_map_##the_map;                                                           \
-    }                                                                                            \
-    __unused TypeOfValue* bpf_##the_map##_lookup_elem(const TypeOfKey* k) {                      \
-        return (TypeOfValue*)mock_bpf_lookup_elem(get_mock_bpf_map_##the_map(), (void*)k);       \
-    };                                                                                           \
-                                                                                                 \
-    __unused int bpf_##the_map##_update_elem(const TypeOfKey* k, const TypeOfValue* v,           \
-                                             uint64_t flags) {                                   \
-        return mock_bpf_update_elem(get_mock_bpf_map_##the_map(), (void*)k, (void*)v, flags);    \
-    };                                                                                           \
-                                                                                                 \
-    __unused int bpf_##the_map##_delete_elem(const TypeOfKey* k) {                               \
-        return mock_bpf_delete_elem(get_mock_bpf_map_##the_map(), (void*)k);                     \
-    };
-
-#define DEFINE_BPF_MAP(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries) \
-    DEFINE_BPF_MAP_UGM(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, AID_ROOT, AID_ROOT, 0600)
-
-#define DEFINE_BPF_MAP_GWO(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, gid) \
-    DEFINE_BPF_MAP_UGM(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, AID_ROOT, gid, 0620)
-
-#define DEFINE_BPF_MAP_GRO(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, gid) \
-    DEFINE_BPF_MAP_UGM(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, AID_ROOT, gid, 0640)
-
-#define DEFINE_BPF_MAP_GRW(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, gid) \
-    DEFINE_BPF_MAP_UGM(the_map, TYPE, TypeOfKey, TypeOfValue, num_entries, AID_ROOT, gid, 0660)
-
-#define DEFINE_BPF_PROG(section, owner, group, name) int name
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-mock_bpf_map_t mock_bpf_map_create(uint32_t key_size, uint32_t value_size, uint32_t type);
-void* mock_bpf_lookup_elem(mock_bpf_map_t map, void* key);
-int mock_bpf_update_elem(mock_bpf_map_t map, void* key, void* value, uint64_t flags);
-int mock_bpf_delete_elem(mock_bpf_map_t map, void* key);
-
-uint64_t bpf_ktime_get_ns();
-uint64_t bpf_get_smp_processor_id();
-uint64_t bpf_get_current_uid_gid();
-uint64_t bpf_get_current_pid_tgid();
-
-void mock_bpf_set_ktime_ns(uint64_t time_ns);
-void mock_bpf_set_smp_processor_id(uint32_t cpu);
-void mock_bpf_set_current_uid_gid(uint32_t uid);
-void mock_bpf_set_current_pid_tgid(uint64_t pid_tgid);
-
-#ifdef __cplusplus
-}  // extern "C"
-#endif
-
-/* place things in different elf sections */
-#define SECTION(NAME) __attribute__((section(NAME), used))
-
-/* Example use: LICENSE("GPL"); or LICENSE("Apache 2.0"); */
-#define LICENSE(NAME) char _license[] SECTION("license") = (NAME)
diff --git a/rustfmt.toml b/rustfmt.toml
new file mode 120000
index 0000000..ee92d9e
--- /dev/null
+++ b/rustfmt.toml
@@ -0,0 +1 @@
+../../build/soong/scripts/rustfmt.toml
\ No newline at end of file
```

