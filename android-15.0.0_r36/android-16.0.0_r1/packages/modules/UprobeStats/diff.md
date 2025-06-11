```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index b37c0e0..8c62122 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -2,6 +2,8 @@
 clang_format = true
 google_java_format = true
 bpfmt = true
+rustfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=${REPO_ROOT}/build/soong/scripts/rustfmt.toml
diff --git a/apex/Android.bp b/apex/Android.bp
index 4d14fb4..ad25e2b 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -55,6 +55,7 @@ apex {
         "BitmapAllocation.o",
         "GenericInstrumentation.o",
         "ProcessManagement.o",
+        "MalwareSignal.o",
     ],
 
     native_shared_libs: [
@@ -65,7 +66,4 @@ apex {
     key: "com.android.uprobestats.key",
     certificate: ":com.android.uprobestats.certificate",
     defaults: ["b-launched-apex-module"],
-    // temporarily override the value from the V defaults so that
-    // the build still works on `next` for now.
-    min_sdk_version: "35",
 }
diff --git a/rust/Android.bp b/rust/Android.bp
new file mode 100644
index 0000000..3e15942
--- /dev/null
+++ b/rust/Android.bp
@@ -0,0 +1,14 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_performance",
+}
+
+rust_defaults {
+    name: "uprobestats_rust_defaults",
+    rustlibs: ["libanyhow"],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+    min_sdk_version: "36",
+}
diff --git a/rust/ffi/Android.bp b/rust/ffi/Android.bp
new file mode 100644
index 0000000..d3a6ab1
--- /dev/null
+++ b/rust/ffi/Android.bp
@@ -0,0 +1,97 @@
+rust_library {
+    name: "libuprobestats_bpf",
+    crate_name: "uprobestats_bpf",
+    defaults: ["uprobestats_rust_defaults"],
+    srcs: ["bpf.rs"],
+    rustlibs: [
+        "liblog_rust",
+        "libuprobestats_bpf_bindgen",
+    ],
+}
+
+rust_bindgen {
+    name: "libuprobestats_bpf_bindgen",
+    crate_name: "uprobestats_bpf_bindgen",
+    defaults: ["uprobestats_rust_defaults"],
+    wrapper_src: "bpf_wrapper.h",
+    source_stem: "bindings",
+    shared_libs: ["libuprobestats_bpf_cc"],
+    visibility: ["//packages/modules/UprobeStats:__subpackages__"],
+}
+
+cc_library_shared {
+    name: "libuprobestats_bpf_cc",
+    srcs: ["bpf.cpp"],
+    header_libs: [
+        "uprobestats_bpf_headers",
+    ],
+    shared_libs: [
+        "libandroid",
+        "libbase",
+        "liblog",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+    min_sdk_version: "36",
+}
+
+rust_library {
+    name: "libdynamic_instrumentation_manager",
+    defaults: ["uprobestats_rust_defaults"],
+    crate_name: "dynamic_instrumentation_manager",
+    srcs: ["dynamic_instrumentation_manager.rs"],
+    rustlibs: [
+        "libdynamic_instrumentation_manager_bindgen",
+    ],
+}
+
+rust_bindgen {
+    name: "libdynamic_instrumentation_manager_bindgen",
+    crate_name: "dynamic_instrumentation_manager_bindgen",
+    defaults: ["uprobestats_rust_defaults"],
+    wrapper_src: "dynamic_instrumentation_manager_wrapper.h",
+    source_stem: "bindings",
+    shared_libs: ["libandroid"],
+}
+
+rust_library {
+    name: "libstatssocket_rs",
+    defaults: ["uprobestats_rust_defaults"],
+    crate_name: "statssocket",
+    srcs: ["statssocket.rs"],
+    rustlibs: [
+        "libstatssocket_bindgen",
+    ],
+}
+
+rust_bindgen {
+    name: "libstatssocket_bindgen",
+    defaults: ["uprobestats_rust_defaults"],
+    wrapper_src: "statssocket_wrapper.h",
+    crate_name: "statssocket_bindgen",
+    source_stem: "bindings",
+    shared_libs: ["libstatssocket"],
+}
+
+rust_library {
+    name: "libstatslog_uprobestats_rs",
+    defaults: ["uprobestats_rust_defaults"],
+    crate_name: "statslog_uprobestats",
+    srcs: [
+        "statslog_wrapper.rs",
+        ":statslog_uprobestats.rs",
+    ],
+    rustlibs: [
+        "libstatslog_rust_header",
+        "libstatspull_bindgen",
+    ],
+}
+
+genrule {
+    name: "statslog_uprobestats.rs",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --module uprobestats --rustHeaderCrate statslog_rust_header --rust $(genDir)/statslog_uprobestats.rs",
+    out: ["statslog_uprobestats.rs"],
+}
diff --git a/rust/ffi/bpf.cpp b/rust/ffi/bpf.cpp
new file mode 100644
index 0000000..fe7dfba
--- /dev/null
+++ b/rust/ffi/bpf.cpp
@@ -0,0 +1,90 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#define LOG_TAG "uprobestats"
+
+#include "bpf.h"
+
+#include <BpfSyscallWrappers.h>
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <linux/perf_event.h>
+
+#include <string>
+
+#include "bpf/BpfRingbuf.h"
+
+int pollRingBuf(const char *mapPath, int timeoutMs, size_t valueSize,
+                void (*callback)(const void *, void *), void *cookie) {
+  auto result = android::bpf::BpfRingbufSized::Create(mapPath, valueSize);
+  if (!result.ok()) {
+    return -1;
+  }
+  if (!result.value()->wait(timeoutMs)) {
+    return 0;
+  }
+  auto count = result.value()->ConsumeAll(
+      [&](const void *value) { callback(value, cookie); });
+  if (!count.ok()) {
+    LOG(ERROR) << "Failed to consume events from ring buffer. Error: "
+               << count.error().message();
+    return -2;
+  }
+  return count.value();
+}
+
+const char *PMU_TYPE_FILE = "/sys/bus/event_source/devices/uprobe/type";
+
+int bpfPerfEventOpen(const char *filename, int offset, int pid,
+                     const char *bpfProgramPath) {
+  android::base::unique_fd bpfProgramFd(
+      android::bpf::retrieveProgram(bpfProgramPath));
+  if (bpfProgramFd < 0) {
+    LOG(ERROR) << "retrieveProgram failed";
+    return -1;
+  }
+  std::string typeStr;
+  if (!android::base::ReadFileToString(PMU_TYPE_FILE, &typeStr)) {
+    LOG(ERROR) << "Failed to open pmu type file";
+    return -1;
+  }
+  int pmu_type = (int)strtol(typeStr.c_str(), NULL, 10);
+  struct perf_event_attr attr = {};
+  attr.sample_period = 1;
+  attr.wakeup_events = 1;
+  attr.config2 = offset;
+  attr.size = sizeof(attr);
+  attr.type = pmu_type;
+  attr.config1 = android::bpf::ptr_to_u64((void *)filename);
+  attr.exclude_kernel = true;
+  int perfEventFd = syscall(__NR_perf_event_open, &attr, pid, /*cpu=*/-1,
+                            /* group_fd=*/-1, PERF_FLAG_FD_CLOEXEC);
+  if (perfEventFd < 0) {
+    LOG(ERROR) << "syscall(__NR_perf_event_open) failed. "
+               << "perfEventFd: " << perfEventFd << " "
+               << "error: " << strerror(errno);
+    return -1;
+  }
+  if (ioctl(perfEventFd, PERF_EVENT_IOC_SET_BPF, int(bpfProgramFd)) < 0) {
+    LOG(ERROR) << "PERF_EVENT_IOC_SET_BPF failed. " << strerror(errno);
+    return -1;
+  }
+  if (ioctl(perfEventFd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
+    LOG(ERROR) << "PERF_EVENT_IOC_ENABLE failed. " << strerror(errno);
+    return -1;
+  }
+  return 0;
+}
diff --git a/rust/ffi/bpf.h b/rust/ffi/bpf.h
new file mode 100644
index 0000000..ab9407c
--- /dev/null
+++ b/rust/ffi/bpf.h
@@ -0,0 +1,78 @@
+
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef __UPROBESTATSBPF_H__
+#define __UPROBESTATSBPF_H__
+
+#include <sys/types.h>
+
+__BEGIN_DECLS
+
+struct CallTimestamp {
+  unsigned int event;
+  unsigned long timestampNs;
+};
+
+struct CallResult {
+  unsigned long pc;
+  unsigned long regs[10];
+};
+
+struct SetUidTempAllowlistStateRecord {
+  __u64 uid;
+  bool onAllowlist;
+};
+
+struct UpdateDeviceIdleTempAllowlistRecord {
+  int changing_uid;
+  bool adding;
+  long duration_ms;
+  int type;
+  int reason_code;
+  char reason[256];
+  int calling_uid;
+};
+
+#pragma pack(push, 1) // Pack structs with 1-byte boundary
+struct WmBoundUid {
+  __u64 client_uid;
+  char client_package_name[64];
+  unsigned long bind_flags;
+  bool initialized;
+};
+
+struct ComponentEnabledSetting {
+  char package_name[64];
+  char class_name[64];
+  int new_state;
+  char calling_package_name[64];
+  bool initialized;
+};
+
+struct MalwareSignal {
+  struct WmBoundUid wm_bound_uid;
+  struct ComponentEnabledSetting component_enabled_setting;
+};
+#pragma pack(pop)
+
+int pollRingBuf(const char *mapPath, int timeoutMs, size_t valueSize,
+                void (*callback)(const void *, void *), void *cookie);
+int bpfPerfEventOpen(const char *filename, int offset, int pid,
+                     const char *bpfProgramPath);
+
+__END_DECLS
+
+#endif  // __UPROBESTATSBPF_H__
diff --git a/rust/ffi/bpf.rs b/rust/ffi/bpf.rs
new file mode 100644
index 0000000..dfbbdb2
--- /dev/null
+++ b/rust/ffi/bpf.rs
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+//! Functions to interact with BPF through C FFI.
+
+use anyhow::{ensure, Result};
+use uprobestats_bpf_bindgen::{bpfPerfEventOpen, pollRingBuf};
+
+use std::{ffi::c_void, fmt::Debug, mem::size_of};
+
+mod c_string;
+use c_string::c_string;
+
+/// Polls the BPF ring buffer at the passed `map_path`, collecting any values
+/// emitted within `timeout_ms` into a `Vec<T>`, where `T` is expected to be
+/// the type written to the ring buffer by a corresponding eBPF program.
+///
+/// # Safety
+///   - `T` matches the type that is written to the BPF ring buffer at `map_path`.
+pub unsafe fn poll_ring_buf<T: Copy + Debug>(map_path: &str, timeout_ms: i32) -> Result<Vec<T>> {
+    let map_path = c_string(map_path)?;
+    let mut data: Vec<T> = Vec::new();
+    let data_ptr = &mut data as *mut _ as *mut c_void;
+    // SAFETY:
+    // - `map_path` is a valid pointer by virtue of coming from a `CString`.
+    // - caller has guaranteed that `T` is the right type, which we use to derive its size.
+    // - `callback` is a valid function pointer defined below.
+    // - `data_ptr` is a valid pointer from the `Vec::new` construction above.
+    // - due to all of the above, `callback` will be called with a valid pointer to a `T` and a
+    //   valid pointer to a `Vec<T>`, which is safe to mutate because we have an exclusive
+    //   reference to the `Vec`.
+    let result = unsafe {
+        pollRingBuf(map_path.as_ptr(), timeout_ms, size_of::<T>(), Some(callback::<T>), data_ptr)
+    };
+    ensure!(result >= 0, "Failed to poll ring buffer. Error code: {}", result);
+    Ok(data)
+}
+
+/// Callback function for `pollRingBuf`.
+///
+/// # Safety
+///   - `value` must be a valid, non-null pointer to a value of type `T` written to the BPF ring buffer.
+///   - `cookie` must be a valid, non-null pointer to a `Vec<T>`.
+unsafe extern "C" fn callback<T: Copy + Debug>(value: *const c_void, cookie: *mut c_void) {
+    let value = value as *const T;
+    // SAFETY: the caller has guaranteed a valid pointer to a `T`, which is `Copy`, so we can get an owned value.
+    let value = unsafe { *value };
+    // SAFETY: the caller has guaranteed a is a valid pointer to a `Vec<T>`.
+    let cookie: &mut Vec<T> = unsafe { &mut *(cookie as *mut Vec<T>) };
+    cookie.push(value);
+}
+
+/// Attaches the eBPF program specified at `bpf_program_path`
+/// to the user space program for process `pid`, located by `filename` and `offset`.
+pub fn bpf_perf_event_open(
+    filename: String,
+    offset: i32,
+    pid: i32,
+    bpf_program_path: String,
+) -> Result<()> {
+    let filename = c_string(&filename)?;
+    let bpf_program_path = c_string(&bpf_program_path)?;
+    let res =
+        // SAFETY: `filename` and `bpf_program_path` are valid by virtue of being derived from a `CString`.
+        unsafe { bpfPerfEventOpen(filename.as_ptr(), offset, pid, bpf_program_path.as_ptr()) };
+    ensure!(res == 0, "Failed to attach BPF. Error code: {}", res);
+    Ok(())
+}
diff --git a/rust/ffi/bpf_wrapper.h b/rust/ffi/bpf_wrapper.h
new file mode 100644
index 0000000..dffde9f
--- /dev/null
+++ b/rust/ffi/bpf_wrapper.h
@@ -0,0 +1 @@
+#include "bpf.h"
diff --git a/rust/ffi/c_string.rs b/rust/ffi/c_string.rs
new file mode 100644
index 0000000..8341ffa
--- /dev/null
+++ b/rust/ffi/c_string.rs
@@ -0,0 +1,9 @@
+//! Utils for working with C strings, returning `anyhow::Result` on failure.
+
+use anyhow::{Context, Result};
+use std::ffi::CString;
+
+/// Create a `CString` from a `&str`, returning an `anyhow::Result` on failure.
+pub fn c_string(string: &str) -> Result<CString> {
+    CString::new(string.as_bytes()).context("Failed to create CString")
+}
diff --git a/rust/ffi/dynamic_instrumentation_manager.rs b/rust/ffi/dynamic_instrumentation_manager.rs
new file mode 100644
index 0000000..bbdbbbb
--- /dev/null
+++ b/rust/ffi/dynamic_instrumentation_manager.rs
@@ -0,0 +1,185 @@
+//! Safe wrapper around the platform dynamic_instrumentation_manager API
+use anyhow::{ensure, Result};
+use dynamic_instrumentation_manager_bindgen::{
+    ADynamicInstrumentationManager_ExecutableMethodFileOffsets,
+    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy,
+    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset,
+    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath,
+    ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset,
+    ADynamicInstrumentationManager_MethodDescriptor,
+    ADynamicInstrumentationManager_MethodDescriptor_create,
+    ADynamicInstrumentationManager_MethodDescriptor_destroy,
+    ADynamicInstrumentationManager_TargetProcess,
+    ADynamicInstrumentationManager_TargetProcess_create,
+    ADynamicInstrumentationManager_TargetProcess_destroy,
+    ADynamicInstrumentationManager_getExecutableMethodFileOffsets,
+};
+use std::ffi::{CStr, CString};
+use std::os::raw::c_char;
+use std::ptr::NonNull;
+
+mod c_string;
+use c_string::c_string;
+
+/// Describes the code offsets for a given method.
+pub struct ExecutableMethodFileOffsets {
+    instance: NonNull<ADynamicInstrumentationManager_ExecutableMethodFileOffsets>,
+}
+
+impl ExecutableMethodFileOffsets {
+    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_create` in `dynamic_instrumentation_manager.h`
+    pub fn get(
+        target_process: &TargetProcess,
+        method_descriptor: &MethodDescriptor,
+    ) -> Result<Option<Self>> {
+        let mut instance: *const ADynamicInstrumentationManager_ExecutableMethodFileOffsets =
+            std::ptr::null_mut();
+        // SAFETY:
+        // - `TargetProcess` and `MethodDescriptor` types wrap valid pointers to the underlying C structs.
+        // - We hold an exclusive mutable reference to the `instance` out parameter.
+        let status = unsafe {
+            ADynamicInstrumentationManager_getExecutableMethodFileOffsets(
+                target_process.as_ptr(),
+                method_descriptor.as_ptr(),
+                &mut instance
+                    as *mut *const ADynamicInstrumentationManager_ExecutableMethodFileOffsets,
+            )
+        };
+
+        ensure!(status == 0, "Failed to get executable method file offsets: {}", status);
+
+        Ok(NonNull::new(
+            instance as *mut ADynamicInstrumentationManager_ExecutableMethodFileOffsets,
+        )
+        .map(|instance| Self { instance }))
+    }
+
+    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath` in `dynamic_instrumentation_manager.h`
+    pub fn get_container_path(&self) -> String {
+        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
+        let container_path = unsafe {
+            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath(
+                self.instance.as_ptr(),
+            )
+        };
+        // SAFETY: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath` returns a valid pointer to a null-terminated C string.
+        let cstr = unsafe { CStr::from_ptr(container_path) };
+        String::from_utf8_lossy(cstr.to_bytes()).to_string()
+    }
+
+    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset` in `dynamic_instrumentation_manager.h`
+    pub fn get_container_offset(&self) -> u64 {
+        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
+        unsafe {
+            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset(
+                self.instance.as_ptr(),
+            )
+        }
+    }
+
+    /// See: `ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset` in `dynamic_instrumentation_manager.h`
+    pub fn get_method_offset(&self) -> u64 {
+        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
+        unsafe {
+            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset(
+                self.instance.as_ptr(),
+            )
+        }
+    }
+}
+
+impl Drop for ExecutableMethodFileOffsets {
+    fn drop(&mut self) {
+        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
+        unsafe {
+            ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy(
+                self.instance.as_ptr(),
+            );
+        }
+    }
+}
+
+/// Describes a method for which we can fetch code offsets.
+pub struct MethodDescriptor {
+    instance: *const ADynamicInstrumentationManager_MethodDescriptor,
+}
+
+impl MethodDescriptor {
+    /// See: `ADynamicInstrumentationManager_MethodDescriptor_create` in `dynamic_instrumentation_manager.h`
+    pub fn new(
+        fully_qualified_class_name: &str,
+        method_name: &str,
+        fully_qualified_parameters: impl IntoIterator<Item = String>,
+    ) -> Result<Self> {
+        let fully_qualified_class_name = c_string(fully_qualified_class_name)?;
+        let method_name = c_string(method_name)?;
+
+        let fully_qualified_parameters: Result<Vec<CString>> =
+            fully_qualified_parameters.into_iter().map(|s| c_string(&s)).collect();
+        let fully_qualified_parameters = fully_qualified_parameters?;
+        let mut fully_qualified_parameters: Vec<*const c_char> =
+            fully_qualified_parameters.iter().map(|c| c.as_ptr()).collect();
+        // SAFETY:
+        // - all pointers are valid by virtue of being derived from owned `CString`s.
+        // - `ADynamicInstrumentationManager_MethodDescriptor_create` makes copies of the data pointed to by its arguments.
+        let instance = unsafe {
+            ADynamicInstrumentationManager_MethodDescriptor_create(
+                fully_qualified_class_name.as_ptr(),
+                method_name.as_ptr(),
+                fully_qualified_parameters.as_mut_ptr(),
+                fully_qualified_parameters.len(),
+            )
+        };
+        Ok(Self { instance })
+    }
+
+    fn as_ptr(&self) -> *const ADynamicInstrumentationManager_MethodDescriptor {
+        self.instance
+    }
+}
+
+impl Drop for MethodDescriptor {
+    fn drop(&mut self) {
+        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
+        unsafe {
+            ADynamicInstrumentationManager_MethodDescriptor_destroy(self.instance);
+        }
+    }
+}
+
+/// Identifies a single process on device.
+pub struct TargetProcess {
+    instance: *const ADynamicInstrumentationManager_TargetProcess,
+}
+
+impl TargetProcess {
+    /// See: `ADynamicInstrumentationManager_TargetProcess_create` in `dynamic_instrumentation_manager.h`
+    pub fn new(uid: u32, pid: i32, process_name: &str) -> Result<Self> {
+        let process_name = c_string(process_name)?;
+        // SAFETY:
+        // - `process_name` is valid by virtue of being derived from an owned `CString`.
+        // - `ADynamicInstrumentationManager_TargetProcess_create` makes a copy of `process_name` pointer.
+        let instance = unsafe {
+            ADynamicInstrumentationManager_TargetProcess_create(uid, pid, process_name.as_ptr())
+        };
+        Ok(Self { instance })
+    }
+
+    /// Returns a `TargetProcess` for system server.
+    pub fn system_server() -> Result<Self> {
+        Self::new(0, 0, "system_server")
+    }
+
+    fn as_ptr(&self) -> *const ADynamicInstrumentationManager_TargetProcess {
+        self.instance
+    }
+}
+
+impl Drop for TargetProcess {
+    fn drop(&mut self) {
+        // SAFETY: `instance` is a pointer to the valid C struct that is owned by `self`.
+        unsafe {
+            ADynamicInstrumentationManager_TargetProcess_destroy(self.instance);
+        }
+    }
+}
diff --git a/rust/ffi/dynamic_instrumentation_manager_wrapper.h b/rust/ffi/dynamic_instrumentation_manager_wrapper.h
new file mode 100644
index 0000000..61fc5dc
--- /dev/null
+++ b/rust/ffi/dynamic_instrumentation_manager_wrapper.h
@@ -0,0 +1 @@
+#include <android/dynamic_instrumentation_manager.h>
diff --git a/rust/ffi/statslog_wrapper.rs b/rust/ffi/statslog_wrapper.rs
new file mode 100644
index 0000000..4c484b1
--- /dev/null
+++ b/rust/ffi/statslog_wrapper.rs
@@ -0,0 +1,21 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#![allow(clippy::needless_lifetimes)]
+#![allow(clippy::too_many_arguments)]
+#![allow(clippy::undocumented_unsafe_blocks)]
+#![allow(missing_docs)]
+#![allow(unused)]
+
+include!(concat!(env!("OUT_DIR"), "/statslog_uprobestats.rs"));
diff --git a/rust/ffi/statssocket.rs b/rust/ffi/statssocket.rs
new file mode 100644
index 0000000..ed09a23
--- /dev/null
+++ b/rust/ffi/statssocket.rs
@@ -0,0 +1,74 @@
+//! Bindings for AStatsEvent NDK API.
+use anyhow::Result;
+use statssocket_bindgen::{
+    AStatsEvent as AStatsEvent_raw, AStatsEvent_obtain, AStatsEvent_release, AStatsEvent_setAtomId,
+    AStatsEvent_write, AStatsEvent_writeBool, AStatsEvent_writeInt32, AStatsEvent_writeInt64,
+    AStatsEvent_writeString,
+};
+use std::ptr::NonNull;
+
+mod c_string;
+use c_string::c_string;
+
+/// Safe wrapper around raw `AStatsEvent`.
+pub struct AStatsEvent {
+    event_raw: NonNull<AStatsEvent_raw>,
+}
+
+impl AStatsEvent {
+    /// Constructor for an `AStatsEvent` with the given `atom_id`.
+    pub fn new(atom_id: u32) -> Self {
+        // SAFETY: trivially safe
+        let event_raw = unsafe {
+            let event = AStatsEvent_obtain();
+            AStatsEvent_setAtomId(event, atom_id);
+            event
+        };
+        Self { event_raw: NonNull::new(event_raw).unwrap() }
+    }
+
+    /// Writes a `bool` value to the `AStatsEvent`.
+    pub fn write_bool(&mut self, value: bool) {
+        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
+        unsafe { AStatsEvent_writeBool(self.as_ptr(), value) };
+    }
+
+    /// Writes an `i32` value to the `AStatsEvent`.
+    pub fn write_int32(&mut self, value: i32) {
+        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
+        unsafe { AStatsEvent_writeInt32(self.as_ptr(), value) };
+    }
+
+    /// Writes an `i64` value to the `AStatsEvent`.
+    pub fn write_int64(&mut self, value: i64) {
+        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
+        unsafe { AStatsEvent_writeInt64(self.as_ptr(), value) };
+    }
+
+    /// Writes a `str` value to the `AStatsEvent`.
+    pub fn write_string(&mut self, value: &str) -> Result<()> {
+        let value = c_string(value)?;
+        // SAFETY:
+        // - `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
+        // - we've just created a valid &CStr from `value`.
+        unsafe { AStatsEvent_writeString(self.as_ptr(), value.as_ptr()) };
+        Ok(())
+    }
+
+    /// Write the event to statsd.
+    pub fn write(mut self) {
+        // SAFETY: `self` is an owned reference to a non-null `AStatsEvent_raw`.
+        unsafe { AStatsEvent_write(self.as_ptr()) };
+    }
+
+    fn as_ptr(&mut self) -> *mut AStatsEvent_raw {
+        self.event_raw.as_ptr()
+    }
+}
+
+impl Drop for AStatsEvent {
+    fn drop(&mut self) {
+        // SAFETY: `&mut self` is an exclusive reference to a non-null `AStatsEvent_raw`.
+        unsafe { AStatsEvent_release(self.as_ptr()) };
+    }
+}
diff --git a/rust/ffi/statssocket_wrapper.h b/rust/ffi/statssocket_wrapper.h
new file mode 100644
index 0000000..9c0a034
--- /dev/null
+++ b/rust/ffi/statssocket_wrapper.h
@@ -0,0 +1 @@
+#include "stats_event.h"
diff --git a/rust/src/Android.bp b/rust/src/Android.bp
new file mode 100644
index 0000000..cf64814
--- /dev/null
+++ b/rust/src/Android.bp
@@ -0,0 +1,57 @@
+rust_library {
+    name: "libuprobestats_rs",
+    crate_name: "uprobestats_rs",
+    defaults: ["uprobestats_rust_defaults"],
+    srcs: ["lib.rs"],
+    rustlibs: [
+        "libdynamic_instrumentation_manager",
+        "liblog_rust",
+        "liblogger",
+        "libprotobuf",
+        "libuprobestats_bpf",
+        "libuprobestats_proto",
+        "librustutils",
+        "libserde_json",
+    ],
+    shared_libs: ["libuprobestats_bpf_cc"],
+}
+
+rust_binary {
+    name: "uprobestats_rs",
+    stem: "uprobestats",
+    enabled: false,
+    srcs: ["main.rs"],
+    defaults: ["uprobestats_rust_defaults"],
+    rustlibs: [
+        "libzerocopy",
+        "libstatslog_uprobestats_rs",
+        "libstatssocket_rs",
+        "libuprobestats_rs",
+        "libuprobestats_proto",
+        "libprotobuf",
+        "libbinder_rs",
+        "liblog_rust",
+        "liblogger",
+        "libuprobestats_bpf",
+        "libuprobestats_bpf_bindgen",
+        "librustutils",
+        "libuprobestats_mainline_flags_rust",
+    ],
+}
+
+rust_test {
+    name: "uprobestats_rs_test",
+    srcs: ["lib.rs"],
+    defaults: ["uprobestats_rust_defaults"],
+    rustlibs: [
+        "libuprobestats_rs",
+        "libdynamic_instrumentation_manager",
+        "liblog_rust",
+        "liblogger",
+        "libprotobuf",
+        "libuprobestats_bpf",
+        "libuprobestats_proto",
+        "librustutils",
+        "libserde_json",
+    ],
+}
diff --git a/rust/src/art.rs b/rust/src/art.rs
new file mode 100644
index 0000000..9e3bbb0
--- /dev/null
+++ b/rust/src/art.rs
@@ -0,0 +1,43 @@
+//! Android Runtime (ART) integration
+use anyhow::{anyhow, Result};
+use serde_json::Value;
+use std::process::{Command, Stdio};
+
+/// Gets the precompiled offset of the given method (which should be present in the given file on device)
+pub(crate) fn get_method_offset_from_oatdump(
+    oat_file: &str,
+    method_signature: &str,
+) -> Result<Option<i32>> {
+    let output = Command::new("oatdump")
+        .arg(format!("--oat-file={}", oat_file))
+        .arg("--dump-method-and-offset-as-json")
+        .stdout(Stdio::piped())
+        .spawn()
+        .map_err(|e| anyhow!("could not execute oatdump: {e}"))?;
+    let output =
+        output.wait_with_output().map_err(|e| anyhow!("could not get output from oatdump: {e}"))?;
+    if !output.status.success() {
+        let stderr = String::from_utf8(output.stderr)
+            .map_err(|e| anyhow!("oatdump failed, error parsing stderr: {e}"))?;
+        return Err(anyhow!("error from oatdump: {}", stderr));
+    }
+
+    let lines = String::from_utf8(output.stdout)
+        .map_err(|e| anyhow!("could not read oatdump stdout: {e}"))?;
+    let lines = lines.lines();
+    for line in lines {
+        let json: Value =
+            serde_json::from_str(line).map_err(|e| anyhow!("error parsing oatdump json: {}", e))?;
+        let method =
+            json["method"].as_str().map(|s| s.to_string()).ok_or(anyhow!("bad json method"))?;
+        if method == method_signature {
+            let offset =
+                json["offset"].as_str().map(|s| s.to_string()).ok_or(anyhow!("bad json offset"))?;
+            let offset = i32::from_str_radix(offset.trim_start_matches("0x"), 16)
+                .map_err(|e| anyhow!("could not parse offset {}: {}", offset, e))?;
+            return Ok(Some(offset));
+        }
+    }
+
+    Ok(None)
+}
diff --git a/rust/src/bpf_map/generic_instrumentation.rs b/rust/src/bpf_map/generic_instrumentation.rs
new file mode 100644
index 0000000..e36458c
--- /dev/null
+++ b/rust/src/bpf_map/generic_instrumentation.rs
@@ -0,0 +1,75 @@
+use super::{OnItem, JAVA_ARGUMENT_REGISTER_OFFSET};
+use anyhow::{anyhow, Result};
+use log::debug;
+use protobuf::MessageField;
+use statssocket::AStatsEvent;
+use uprobestats_bpf_bindgen::{CallResult, CallTimestamp};
+use uprobestats_proto::config::uprobestats_config::Task;
+
+// SAFETY: `CallTimestamp` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for CallTimestamp {
+    const MAP_PATH: &'static str =
+        "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_timestamp_buf";
+    fn on_item(&self, task: &Task) -> Result<()> {
+        debug!("CallTimestamp - event: {}, timestamp_ns: {}", self.event, self.timestampNs,);
+
+        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+            return Ok(());
+        };
+
+        debug!("has logging config");
+        let atom_id = statsd_logging_config
+            .atom_id
+            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;
+
+        debug!("attempting to write atom id: {}", atom_id);
+        let mut event = AStatsEvent::new(atom_id.try_into()?);
+        event.write_int32(self.event.try_into()?);
+        event.write_int64(self.timestampNs.try_into()?);
+        event.write();
+        debug!("successfully wrote atom id: {}", atom_id);
+        Ok(())
+    }
+}
+
+// SAFETY: `CallResult` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for CallResult {
+    const MAP_PATH: &'static str =
+        "/sys/fs/bpf/uprobestats/map_GenericInstrumentation_call_detail_buf";
+    fn on_item(&self, task: &Task) -> Result<()> {
+        debug!("CallResult - register: pc = {}", self.pc,);
+        for i in 0..10 {
+            debug!("CallResult - register: {} = {}", i, self.regs[i],);
+        }
+
+        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+            return Ok(());
+        };
+
+        debug!("has logging config");
+        let atom_id = statsd_logging_config
+            .atom_id
+            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;
+
+        debug!("attempting to write atom id: {}", atom_id);
+        let mut event = AStatsEvent::new(atom_id.try_into()?);
+
+        for primitive_argument_position in &statsd_logging_config.primitive_argument_positions {
+            let register_index: usize =
+                (JAVA_ARGUMENT_REGISTER_OFFSET + primitive_argument_position).try_into()?;
+            let primitive_argument: i32 = self.regs[register_index].try_into()?;
+            debug!(
+                "writing primitive_argument: {} from position: {}",
+                primitive_argument, primitive_argument_position
+            );
+            event.write_int32(primitive_argument);
+        }
+
+        event.write();
+        debug!("successfully wrote atom id: {}", atom_id);
+
+        Ok(())
+    }
+}
diff --git a/rust/src/bpf_map/malware_signal.rs b/rust/src/bpf_map/malware_signal.rs
new file mode 100644
index 0000000..8c02088
--- /dev/null
+++ b/rust/src/bpf_map/malware_signal.rs
@@ -0,0 +1,20 @@
+use super::OnItem;
+use anyhow::Result;
+use log::debug;
+use uprobestats_bpf_bindgen::MalwareSignal;
+use uprobestats_proto::config::uprobestats_config::Task;
+
+// SAFETY: `MalwareSignal` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for MalwareSignal {
+    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_MalwareSignal_output_buf";
+    fn on_item(&self, _task: &Task) -> Result<()> {
+        if self.wm_bound_uid.initialized {
+            debug!("wm_bound_uid: {:?}", self.wm_bound_uid);
+        }
+        if self.component_enabled_setting.initialized {
+            debug!("component_enabled_setting: {:?}", self.component_enabled_setting);
+        }
+        Ok(())
+    }
+}
diff --git a/rust/src/bpf_map/mod.rs b/rust/src/bpf_map/mod.rs
new file mode 100644
index 0000000..904c7de
--- /dev/null
+++ b/rust/src/bpf_map/mod.rs
@@ -0,0 +1,82 @@
+use anyhow::{bail, Result};
+use log::debug;
+use std::{
+    collections::HashMap,
+    fmt::Debug,
+    sync::LazyLock,
+    time::{Duration, Instant},
+};
+use uprobestats_bpf::poll_ring_buf;
+use uprobestats_bpf_bindgen::{
+    CallResult, CallTimestamp, MalwareSignal, SetUidTempAllowlistStateRecord,
+    UpdateDeviceIdleTempAllowlistRecord,
+};
+use uprobestats_proto::config::uprobestats_config::Task;
+
+mod generic_instrumentation;
+mod malware_signal;
+mod process_management;
+
+pub(crate) fn poll_and_loop(
+    map_path: &str,
+    now: Instant,
+    duration: Duration,
+    task: Task,
+) -> Result<()> {
+    let duration_millis = duration.as_millis();
+    let mut elapsed_millis = now.elapsed().as_millis();
+    while elapsed_millis <= duration_millis {
+        let timeout_millis = duration_millis - elapsed_millis;
+        let timeout_millis: i32 = timeout_millis.try_into()?;
+        debug!("polling {} for {} seconds", map_path, timeout_millis / 1000);
+        let Some(do_poll) = REGISTRY.get(map_path) else {
+            bail!("unsupported map_path: {}", map_path);
+        };
+        do_poll(map_path, timeout_millis, &task)?;
+        elapsed_millis = now.elapsed().as_millis();
+    }
+    Ok(())
+}
+
+fn poll<T: OnItem + Debug + Copy>(map_path: &str, timeout_millis: i32, task: &Task) -> Result<()> {
+    if map_path != T::MAP_PATH {
+        bail!("map_path mismatch: {} != {}", map_path, T::MAP_PATH)
+    }
+    // SAFETY: we've just checked that the passed `map_path` is the same as the one
+    // expected by the `OnItem` implementation, which encodes how the expected type is mapped to the
+    // ring buffer's path.
+    let result: Result<Vec<T>> = unsafe { poll_ring_buf(map_path, timeout_millis) };
+    let result = result?;
+    debug!("Done polling {}, event count: {}", map_path, result.len());
+    for i in &result {
+        i.on_item(task)?;
+    }
+    Ok(())
+}
+
+const JAVA_ARGUMENT_REGISTER_OFFSET: i32 = 2;
+
+/// Interface for reading items out of a BPF ring buffer.
+/// # Safety
+/// There *must* exist a BPF ring buffer at the path represented by `MAP_PATH`
+/// which holds items of type `T` implementing this trait.
+unsafe trait OnItem {
+    const MAP_PATH: &'static str;
+    fn on_item(&self, task: &Task) -> Result<()>;
+}
+
+type Registry = HashMap<&'static str, fn(&str, i32, &Task) -> Result<()>>;
+
+fn register<T: OnItem + Debug + Copy>(registry: &mut Registry) {
+    registry.insert(T::MAP_PATH, poll::<T> as _);
+}
+
+static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
+    let mut map = HashMap::new();
+    register::<CallTimestamp>(&mut map);
+    register::<CallResult>(&mut map);
+    register::<MalwareSignal>(&mut map);
+    register::<SetUidTempAllowlistStateRecord>(&mut map);
+    register::<UpdateDeviceIdleTempAllowlistRecord>(&mut map);
+    map
+});
diff --git a/rust/src/bpf_map/process_management.rs b/rust/src/bpf_map/process_management.rs
new file mode 100644
index 0000000..0203f7d
--- /dev/null
+++ b/rust/src/bpf_map/process_management.rs
@@ -0,0 +1,79 @@
+use super::OnItem;
+use anyhow::{anyhow, Result};
+use log::debug;
+use protobuf::MessageField;
+use statssocket::AStatsEvent;
+use std::ffi::CStr;
+use zerocopy::IntoBytes;
+use uprobestats_bpf_bindgen::{
+    SetUidTempAllowlistStateRecord, UpdateDeviceIdleTempAllowlistRecord,
+};
+use uprobestats_proto::config::uprobestats_config::Task;
+
+// SAFETY: `SetUidTempAllowlistStateRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for SetUidTempAllowlistStateRecord {
+    const MAP_PATH: &'static str =
+        "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
+    fn on_item(&self, task: &Task) -> Result<()> {
+        debug!("SetUidTempAllowlistStateRecord: {:?}", self);
+
+        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+            return Ok(());
+        };
+
+        debug!("has logging config");
+        let atom_id = statsd_logging_config
+            .atom_id
+            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;
+
+        debug!("attempting to write atom id: {}", atom_id);
+        let mut event = AStatsEvent::new(atom_id.try_into()?);
+
+        event.write_int32(self.uid.try_into()?);
+        event.write_bool(self.onAllowlist);
+
+        event.write();
+        debug!("successfully wrote atom id: {}", atom_id);
+
+        Ok(())
+    }
+}
+
+// SAFETY: `UpdateDeviceIdleTempAllowlistRecord` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
+// layout of the corresponding C struct.
+unsafe impl OnItem for UpdateDeviceIdleTempAllowlistRecord {
+    const MAP_PATH: &'static str =
+        "/sys/fs/bpf/uprobestats/map_ProcessManagement_update_device_idle_temp_allowlist_records";
+    fn on_item(&self, task: &Task) -> Result<()> {
+        debug!("UpdateDeviceIdleTempAllowlistRecord: {:?}", self);
+
+        let MessageField(Some(ref statsd_logging_config)) = task.statsd_logging_config else {
+            return Ok(());
+        };
+
+        debug!("has logging config");
+        let atom_id = statsd_logging_config
+            .atom_id
+            .ok_or(anyhow!("atom_id required if statsd_logging_config provided"))?;
+
+        debug!("attempting to write atom id: {}", atom_id);
+        let mut event = AStatsEvent::new(atom_id.try_into()?);
+
+        event.write_int32(self.changing_uid);
+        event.write_bool(self.adding);
+        event.write_int64(self.duration_ms);
+        event.write_int32(self.type_);
+        event.write_int32(self.reason_code);
+
+        let reason = CStr::from_bytes_until_nul(self.reason.as_bytes())?;
+        event.write_string(reason.to_str()?)?;
+
+        event.write_int32(self.calling_uid);
+
+        event.write();
+        debug!("successfully wrote atom id: {}", atom_id);
+
+        Ok(())
+    }
+}
diff --git a/rust/src/config_resolver.rs b/rust/src/config_resolver.rs
new file mode 100644
index 0000000..c291094
--- /dev/null
+++ b/rust/src/config_resolver.rs
@@ -0,0 +1,144 @@
+//! Validates uprobestats config protos and adds additional info.
+use anyhow::{anyhow, Result};
+use dynamic_instrumentation_manager::{
+    ExecutableMethodFileOffsets, MethodDescriptor, TargetProcess,
+};
+use log::debug;
+use protobuf::Message;
+use std::collections::HashSet;
+use std::fs::File;
+use std::io::Read;
+use uprobestats_proto::config::{
+    uprobestats_config::task::ProbeConfig, uprobestats_config::Task, UprobestatsConfig,
+};
+
+use crate::{art::get_method_offset_from_oatdump, process::get_pid};
+
+/// Validated probe proto + probe target's code filename and offset.
+pub struct ResolvedProbe {
+    _probe: ProbeConfig,
+    /// The filename of the code that contains the probe's method.
+    pub filename: String,
+    /// The offset of the probe's method in the code file.
+    pub offset: i32,
+    /// Absolute path to the bpf program.
+    pub bpf_program_path: String,
+}
+
+/// Validated task proto + probe target's pid.
+pub struct ResolvedTask {
+    /// The task proto.
+    pub task: Task,
+    /// The duration of the task in seconds.
+    pub duration_seconds: i32,
+    /// The pid of the task's target process.
+    pub pid: i32,
+    /// The set of absolute bpf map paths used by the task.
+    pub bpf_map_paths: HashSet<String>,
+}
+
+/// Validates a single task proto and adds additional info.
+pub fn resolve_single_task(config: UprobestatsConfig) -> Result<ResolvedTask> {
+    let mut tasks = config.tasks.into_iter();
+    let task = tasks.next().ok_or_else(|| anyhow!("No tasks found in config"))?;
+
+    let duration_seconds =
+        task.duration_seconds.ok_or_else(|| anyhow!("Task duration is required"))?;
+    if duration_seconds <= 0 {
+        return Err(anyhow!("Task duration must be greater than 0"));
+    }
+
+    let target_process_name = task
+        .target_process_name
+        .clone()
+        .ok_or_else(|| anyhow!("Target process name is required"))?;
+    if target_process_name != "system_server" {
+        return Err(anyhow!("system_server is the only target process currently supported"));
+    }
+
+    let pid = get_pid(&target_process_name)
+        .ok_or_else(|| anyhow!("Failed to get pid for process: {target_process_name}"))?;
+
+    let bpf_map_paths = task.bpf_maps.iter().map(|bpf_map| prefix_bpf(bpf_map)).collect();
+
+    Ok(ResolvedTask { duration_seconds, task, pid, bpf_map_paths })
+}
+
+/// Validates a single probe proto and adds additional info.
+pub fn resolve_probes(task: &Task) -> Result<Vec<ResolvedProbe>> {
+    let resolved_probes = task.probe_configs.clone().into_iter().map(|probe| {
+        let bpf_name = probe.bpf_name.as_ref().ok_or_else(|| anyhow!("bpf_name is required"))?;
+        let bpf_program_path = prefix_bpf(bpf_name);
+        if let Some(ref fully_qualified_class_name) = probe.fully_qualified_class_name {
+            debug!("using getExecutableMethodFileOffsets to retrieve offsets");
+            let method_name =
+                probe.method_name.clone().ok_or_else(|| anyhow!("method_name is required"))?;
+            let fully_qualified_parameters = probe.fully_qualified_parameters.clone();
+            let offsets = ExecutableMethodFileOffsets::get(
+                &TargetProcess::system_server()?,
+                &MethodDescriptor::new(
+                    &fully_qualified_class_name.clone(),
+                    &method_name,
+                    fully_qualified_parameters,
+                )?,
+            )?;
+            let offsets = offsets.ok_or_else(|| {
+                anyhow!("Failed to get offsets for class: {fully_qualified_class_name}")
+            })?;
+            let offset: i32 = offsets
+                .get_method_offset()
+                .try_into()
+                .map_err(|e| anyhow!("Failed to convert method offset to i32: {e}"))?;
+            Ok(ResolvedProbe {
+                _probe: probe,
+                bpf_program_path,
+                offset,
+                filename: offsets.get_container_path(),
+            })
+        } else {
+            debug!("using oatdump to retrieve offsets");
+            let method_signature =
+                probe.method_signature.clone().ok_or(anyhow!("method_signature is required"))?;
+            let mut offset: i32 = 0;
+            let mut found_file_path: String = "".to_string();
+            for file_path in &probe.file_paths {
+                let found_offset = get_method_offset_from_oatdump(file_path, &method_signature)?;
+                let Some(found_offset) = found_offset else {
+                    continue;
+                };
+                if found_offset > 0 {
+                    found_file_path = file_path.to_string();
+                    offset = found_offset;
+                    break;
+                }
+            }
+            if offset > 0 {
+                Ok(ResolvedProbe {
+                    _probe: probe,
+                    bpf_program_path,
+                    filename: found_file_path,
+                    offset,
+                })
+            } else {
+                Err(anyhow!("Failed to get offset for method: {method_signature}"))
+            }
+        }
+    });
+
+    resolved_probes.collect()
+}
+
+/// Reads a config file and parses it into a UprobestatsConfig proto.
+pub fn read_config(config_path: &str) -> Result<UprobestatsConfig> {
+    let mut file =
+        File::open(config_path).map_err(|e| anyhow!("Failed to open config file: {e}"))?;
+    let mut buffer = Vec::new();
+    file.read_to_end(&mut buffer).map_err(|e| anyhow!("Failed to read config file: {e}"))?;
+    UprobestatsConfig::parse_from_bytes(&buffer)
+        .map_err(|e| anyhow!("Failed to parse config file: {e}"))
+}
+
+const BPF_DIR: &str = "/sys/fs/bpf/uprobestats/";
+fn prefix_bpf(path: &str) -> String {
+    BPF_DIR.to_string() + path
+}
diff --git a/rust/src/guardrail.rs b/rust/src/guardrail.rs
new file mode 100644
index 0000000..e401d89
--- /dev/null
+++ b/rust/src/guardrail.rs
@@ -0,0 +1,169 @@
+//! Handles allow list of code that can be instrumented on user devices.
+use anyhow::{anyhow, bail, Result};
+use uprobestats_proto::config::{uprobestats_config::task::ProbeConfig, UprobestatsConfig};
+
+const ALLOWED_METHOD_PREFIXES: [&str; 4] = [
+    "com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist",
+    "com.android.server.am.CachedAppOptimizer",
+    "com.android.server.am.OomAdjuster",
+    "com.android.server.am.OomAdjusterModernImpl",
+];
+
+/// Checks if the given config is allowed to be instrumented on user devices.
+///
+/// If the device is a user build, all configs are allowed. Otherwise, only configs that are
+/// explicitly allowed are allowed.
+pub fn is_allowed(
+    config: &UprobestatsConfig,
+    is_user_build: bool,
+    offsets_api_enabled: bool,
+) -> Result<bool> {
+    if !is_user_build {
+        return Ok(true);
+    }
+    for task in &config.tasks {
+        for probe in &task.probe_configs {
+            let full_method_name = get_full_method_name(probe, offsets_api_enabled)?;
+            let mut allowed = false;
+            for prefix in ALLOWED_METHOD_PREFIXES {
+                if full_method_name == prefix
+                    || full_method_name.starts_with(&(prefix.to_string() + "("))
+                    || full_method_name.starts_with(&(prefix.to_string() + "."))
+                    || full_method_name.starts_with(&(prefix.to_string() + "$"))
+                {
+                    allowed = true;
+                    break;
+                }
+            }
+            if !allowed {
+                return Ok(false);
+            }
+        }
+    }
+    Ok(true)
+}
+
+fn get_full_method_name(probe_config: &ProbeConfig, offsets_api_enabled: bool) -> Result<String> {
+    if offsets_api_enabled {
+        let Some(ref fqcn) = probe_config.fully_qualified_class_name else {
+            bail!("Fully qualified class name is empty")
+        };
+        let Some(ref method_name) = probe_config.method_name else { bail!("Method name is empty") };
+        Ok(format!("{}.{}", fqcn, method_name))
+    } else {
+        let Some(ref method_signature) = probe_config.method_signature else {
+            bail!("Method signature is empty")
+        };
+        let mut parts = method_signature.split(" ");
+        parts.nth(1).map(String::from).ok_or(anyhow!("Method signature is invalid"))
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::clone::Clone;
+    use uprobestats_proto::config::uprobestats_config::Task;
+
+    #[test]
+    fn everything_allowed_on_userdebug() {
+        let config = setup_config(vec![setup_probe_config(
+            "com.android.server.am.SomeClass",
+            "doWork",
+            vec![],
+        )]);
+
+        assert!(is_allowed(&config, false, true).unwrap());
+        assert!(is_allowed(&config, false, false).unwrap());
+    }
+
+    #[test]
+    fn oom_adjuster_allowed() {
+        let config = setup_config(vec![
+            setup_probe_config(
+                "com.android.server.am.OomAdjuster",
+                "setUidTempAllowlistStateLSP",
+                vec!["int".to_string(), "boolean".to_string()],
+            ),
+            setup_probe_config(
+                "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0",
+                "accept",
+                vec!["java.lang.String".to_string()],
+            ),
+        ]);
+
+        assert!(is_allowed(&config, false, false).unwrap());
+        assert!(is_allowed(&config, true, false).unwrap());
+        assert!(is_allowed(&config, false, true).unwrap());
+        assert!(is_allowed(&config, true, true).unwrap());
+    }
+
+    #[test]
+    fn update_device_idle_temp_allowlist_allowed() {
+        let config = setup_config(vec![setup_probe_config(
+            "com.android.server.am.ActivityManagerService$LocalService",
+            "updateDeviceIdleTempAllowlist",
+            vec![],
+        )]);
+
+        assert_eq!(
+            "com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist()",
+            &get_full_method_name(&config.tasks[0].probe_configs[0], false).unwrap()
+        );
+
+        assert!(is_allowed(&config, false, false).unwrap());
+        // TODO: does this actually work in the c++ impl? @mattgilbride ask @yutingtseng
+        // assert!(is_allowed(&config, true, false).unwrap());
+        assert!(is_allowed(&config, false, true).unwrap());
+        assert!(is_allowed(&config, true, true).unwrap());
+    }
+
+    #[test]
+    fn oom_adjuster_with_suffix_disallowed() {
+        let config = setup_config(vec![setup_probe_config(
+            "com.android.server.am.OomAdjusterWithSomeSuffix",
+            "doWork",
+            vec![],
+        )]);
+
+        assert!(!is_allowed(&config, true, false).unwrap());
+        assert!(!is_allowed(&config, true, true).unwrap());
+    }
+
+    #[test]
+    fn disallowed_method_in_second_task_disallowed() {
+        let config = setup_config(vec![
+            setup_probe_config("com.android.server.am.OomAdjusterWithSomeSuffix", "doWork", vec![]),
+            setup_probe_config("com.android.server.am.DisallowedClass", "doWork", vec![]),
+        ]);
+
+        assert!(!is_allowed(&config, true, false).unwrap());
+        assert!(!is_allowed(&config, true, true).unwrap());
+    }
+
+    fn setup_config(probe_configs: Vec<ProbeConfig>) -> UprobestatsConfig {
+        UprobestatsConfig {
+            tasks: vec![Task { probe_configs, ..Task::default() }],
+            ..UprobestatsConfig::default()
+        }
+    }
+
+    fn setup_probe_config(
+        class_name: &str,
+        method_name: &str,
+        fully_qualified_parameters: impl IntoIterator<Item = String> + Clone,
+    ) -> ProbeConfig {
+        ProbeConfig {
+            fully_qualified_class_name: Some(class_name.to_string()),
+            method_name: Some(method_name.to_string()),
+            fully_qualified_parameters: fully_qualified_parameters.clone().into_iter().collect(),
+            method_signature: Some(format!(
+                "void {}.{}({})",
+                class_name,
+                method_name,
+                fully_qualified_parameters.into_iter().collect::<Vec<String>>().join(", ")
+            )),
+            ..ProbeConfig::default()
+        }
+    }
+}
diff --git a/rust/src/lib.rs b/rust/src/lib.rs
new file mode 100644
index 0000000..21d8b08
--- /dev/null
+++ b/rust/src/lib.rs
@@ -0,0 +1,5 @@
+//! UprobeStats library
+mod art;
+pub mod config_resolver;
+pub mod guardrail;
+mod process;
diff --git a/rust/src/main.rs b/rust/src/main.rs
new file mode 100644
index 0000000..6f46ce9
--- /dev/null
+++ b/rust/src/main.rs
@@ -0,0 +1,101 @@
+//! UProbestats executable.
+use anyhow::{anyhow, bail, ensure, Result};
+use binder::ProcessState;
+use log::{debug, error, LevelFilter};
+use rustutils::system_properties;
+use std::process::exit;
+use std::{
+    thread,
+    time::{Duration, Instant},
+};
+use uprobestats_bpf::bpf_perf_event_open;
+use uprobestats_rs::{config_resolver, guardrail};
+
+mod bpf_map;
+
+fn main() {
+    logger::init(
+        logger::Config::default()
+            .with_tag_on_device("uprobestats")
+            .with_max_level(if is_user_build() { LevelFilter::Info } else { LevelFilter::Trace }),
+    );
+
+    if let Err(e) = main_impl() {
+        error!("{}", e);
+        exit(1);
+    };
+}
+
+fn main_impl() -> Result<()> {
+    debug!("started");
+
+    ensure!(is_uprobestats_enabled(), "Uprobestats disabled by flag");
+
+    let config = config_resolver::read_config("/data/misc/uprobestats-configs/config")?;
+    ensure!(
+        guardrail::is_allowed(&config, is_user_build(), true)?,
+        "uprobestats probing config disallowed on this device"
+    );
+    let task = config_resolver::resolve_single_task(config)?;
+
+    ProcessState::start_thread_pool();
+
+    let probes = config_resolver::resolve_probes(&task.task)?;
+    for probe in probes {
+        bpf_perf_event_open(
+            probe.filename.clone(),
+            probe.offset,
+            task.pid,
+            probe.bpf_program_path.clone(),
+        )?;
+        debug!(
+            "attached bpf {} to {} at {}",
+            probe.bpf_program_path, &probe.filename, &probe.offset
+        );
+    }
+
+    let duration_seconds: u64 = task.duration_seconds.try_into()?;
+    let now = Instant::now();
+    let duration = Duration::from_secs(duration_seconds);
+
+    let results = task.bpf_map_paths.into_iter().map(|map_path| {
+        debug!("Spawning thread for map_path: {}", map_path);
+        match thread::spawn({
+            let task_proto = task.task.clone();
+            move || bpf_map::poll_and_loop(&map_path, now, duration, task_proto)
+        })
+        .join()
+        {
+            Ok(result) => result.map_err(|e| anyhow!("Thread error: {}", e)),
+            Err(panic) => bail!("Thread panic: {:?}", panic),
+        }
+    });
+
+    let errors: Vec<_> = results
+        .filter_map(|r| match r {
+            Ok(()) => None,
+            Err(e) => Some(e),
+        })
+        .collect();
+
+    if !errors.is_empty() {
+        let msg = errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>().join(",");
+        let msg = format!("At least one thread returned error: {}", msg);
+        bail!("{}", msg);
+    }
+
+    debug!("done");
+
+    Ok(())
+}
+
+fn is_user_build() -> bool {
+    if let Ok(Some(val)) = system_properties::read("ro.build.type") {
+        return val == "user";
+    }
+    true
+}
+
+fn is_uprobestats_enabled() -> bool {
+    uprobestats_mainline_flags_rust::enable_uprobestats()
+}
diff --git a/rust/src/process.rs b/rust/src/process.rs
new file mode 100644
index 0000000..9999155
--- /dev/null
+++ b/rust/src/process.rs
@@ -0,0 +1,27 @@
+//! Utils for dealing with processes
+
+use std::fs::{read, read_dir};
+
+/// return PID given name
+pub(crate) fn get_pid(process_name: &str) -> Option<i32> {
+    for entry in read_dir("/proc").ok()? {
+        let entry = entry.ok()?;
+        let path = entry.path();
+
+        if path.is_dir() {
+            let cmdline_path = path.join("cmdline");
+            if let Ok(cmdline_bytes) = read(cmdline_path) {
+                let cmdline = String::from_utf8_lossy(&cmdline_bytes);
+                if cmdline == process_name || cmdline.starts_with(process_name) {
+                    if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
+                        if let Ok(pid) = pid_str.parse::<i32>() {
+                            return Some(pid);
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    None
+}
diff --git a/src/Android.bp b/src/Android.bp
index 8873d00..fe4d24a 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -24,7 +24,7 @@ cc_aconfig_library {
         "//apex_available:platform",
         "com.android.uprobestats",
     ],
-    min_sdk_version: "35",
+    min_sdk_version: "36",
 }
 
 cc_aconfig_library {
@@ -34,7 +34,7 @@ cc_aconfig_library {
         "//apex_available:platform",
         "com.android.uprobestats",
     ],
-    min_sdk_version: "35",
+    min_sdk_version: "36",
 }
 
 java_aconfig_library {
@@ -58,6 +58,13 @@ java_aconfig_library {
     ],
 }
 
+rust_aconfig_library {
+    name: "libuprobestats_mainline_flags_rust",
+    crate_name: "uprobestats_mainline_flags_rust",
+    defaults: ["uprobestats_rust_defaults"],
+    aconfig_declarations: "uprobestats_mainline_flags",
+}
+
 soong_config_module_type {
     name: "uprobestats_cc_library",
     module_type: "cc_library",
@@ -120,6 +127,7 @@ uprobestats_cc_library {
 
 cc_binary {
     name: "uprobestats",
+    enabled: true,
     srcs: [
         "UprobeStats.cpp",
         "config.proto",
@@ -147,6 +155,7 @@ cc_binary {
             "BitmapAllocation.o",
             "GenericInstrumentation.o",
             "ProcessManagement.o",
+            "MalwareSignal.o",
         ],
     }),
 
@@ -162,6 +171,11 @@ cc_binary {
     min_sdk_version: "35",
 }
 
+filegroup {
+    name: "uprobestats-proto-files",
+    srcs: ["config.proto"],
+}
+
 java_library_host {
     name: "uprobestats-protos",
     srcs: [
@@ -175,53 +189,6 @@ java_library_host {
     },
 }
 
-java_test_host {
-    name: "uprobestats-test",
-    srcs: [
-        "test/*.java",
-        "config.proto",
-    ],
-    java_resources: ["test/*.textproto"],
-    libs: [
-        "compatibility-host-util",
-        "core_cts_test_resources",
-        "cts-tradefed",
-        "host-libprotobuf-java-full",
-        "tradefed",
-        "truth",
-    ],
-    static_libs: [
-        "android.hardware.usb.flags-aconfig-java-host",
-        "android.os.flags-aconfig-java-host",
-        "cts-statsd-atom-host-test-utils",
-        "flag-junit-host",
-        "perfetto_config-full",
-        "art_flags_uprobestats_java_lib",
-        "uprobestats_flags_java_lib",
-    ],
-    proto: {
-        type: "full",
-    },
-    test_suites: [
-        "general-tests",
-        "mts-uprobestats",
-    ],
-}
-
-python_binary_host {
-    name: "hello_uprobestats",
-    main: "test/hello_uprobestats.py",
-    srcs: [
-        "test/hello_uprobestats.py",
-        "config.proto",
-    ],
-    data: ["test/*.textproto"],
-    libs: ["libprotobuf-python"],
-    proto: {
-        canonical_path_from_root: false,
-    },
-}
-
 cc_test {
     name: "libuprobestats_test",
     srcs: [
@@ -242,4 +209,16 @@ cc_test {
         type: "lite",
         static: true,
     },
+    test_suites: [
+        "general-tests",
+        "mts-uprobestats",
+    ],
+}
+
+rust_protobuf {
+    name: "libuprobestats_proto",
+    crate_name: "uprobestats_proto",
+    defaults: ["uprobestats_rust_defaults"],
+    protos: ["config.proto"],
+    source_stem: "libuprobestats_proto",
 }
diff --git a/src/Bpf.cpp b/src/Bpf.cpp
index 1d87d34..d024683 100644
--- a/src/Bpf.cpp
+++ b/src/Bpf.cpp
@@ -101,6 +101,9 @@ pollRingBuf(const char *mapPath, int timeoutMs);
 template std::vector<UpdateDeviceIdleTempAllowlistRecord>
 pollRingBuf(const char *mapPath, int timeoutMs);
 
+template std::vector<MalwareSignal> pollRingBuf(const char *mapPath,
+                                                int timeoutMs);
+
 std::vector<int32_t> consumeRingBuf(const char *mapPath) {
   auto result = android::bpf::BpfRingbuf<uint64_t>::Create(mapPath);
   std::vector<int32_t> vec;
diff --git a/src/Bpf.h b/src/Bpf.h
index 8464803..9d957f6 100644
--- a/src/Bpf.h
+++ b/src/Bpf.h
@@ -51,6 +51,28 @@ struct UpdateDeviceIdleTempAllowlistRecord {
   int calling_uid;
 };
 
+#pragma pack(push, 1) // Pack structs with 1-byte boundary
+struct WmBoundUid {
+  __u64 client_uid;
+  char client_package_name[64];
+  unsigned long bind_flags;
+  bool initialized;
+};
+
+struct ComponentEnabledSetting {
+  char package_name[64];
+  char class_name[64];
+  int new_state;
+  char calling_package_name[64];
+  bool initialized;
+};
+
+struct MalwareSignal {
+  struct WmBoundUid wm_bound_uid;
+  struct ComponentEnabledSetting component_enabled_setting;
+};
+#pragma pack(pop)
+
 template <typename T>
 std::vector<T> pollRingBuf(const char *mapPath, int timeoutMs);
 
diff --git a/src/ConfigResolver.cpp b/src/ConfigResolver.cpp
index da78f6c..831729f 100644
--- a/src/ConfigResolver.cpp
+++ b/src/ConfigResolver.cpp
@@ -95,6 +95,11 @@ resolveSingleTask(::uprobestats::protos::UprobestatsConfig config) {
     LOG(ERROR) << "task.target_process_name is required.";
     return {};
   }
+  if (taskConfig.target_process_name() != "system_server") {
+    LOG(ERROR)
+        << "system_server is the only target process currently supported";
+    return {};
+  }
   auto process_name = taskConfig.target_process_name();
   int pid = process::getPid(process_name);
   if (pid < 0) {
diff --git a/src/Guardrail-test.cpp b/src/Guardrail-test.cpp
index 6c70df9..89890ec 100644
--- a/src/Guardrail-test.cpp
+++ b/src/Guardrail-test.cpp
@@ -68,6 +68,26 @@ TEST_F(GuardrailTest, OomAdjusterAllowed) {
   EXPECT_TRUE(guardrail::isAllowed(newConfig, "eng", true));
 }
 
+TEST_F(GuardrailTest, UpdateDeviceIdleTempAllowlistAllowed) {
+  ::uprobestats::protos::UprobestatsConfig config;
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig *probeConfig =
+      config.add_tasks()->add_probe_configs();
+  probeConfig->set_fully_qualified_class_name(
+      "com.android.server.am.ActivityManagerService$LocalService");
+  probeConfig->set_method_name("updateDeviceIdleTempAllowlist");
+  EXPECT_TRUE(guardrail::isAllowed(config, "user", true));
+  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug", true));
+  EXPECT_TRUE(guardrail::isAllowed(config, "eng", true));
+
+  ::uprobestats::protos::UprobestatsConfig oldConfig;
+  oldConfig.add_tasks()->add_probe_configs()->set_method_signature(
+      "void com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist()");
+
+  EXPECT_TRUE(guardrail::isAllowed(oldConfig, "user", false));
+  EXPECT_TRUE(guardrail::isAllowed(oldConfig, "userdebug", false));
+  EXPECT_TRUE(guardrail::isAllowed(oldConfig, "eng", false));
+}
+
 TEST_F(GuardrailTest, DisallowOomAdjusterWithSuffix) {
   ::uprobestats::protos::UprobestatsConfig config;
   config.add_tasks()->add_probe_configs()->set_method_signature(
diff --git a/src/Guardrail.cpp b/src/Guardrail.cpp
index e19222e..5bc0a11 100644
--- a/src/Guardrail.cpp
+++ b/src/Guardrail.cpp
@@ -27,6 +27,8 @@ using std::string;
 namespace {
 
 constexpr std::array kAllowedMethodPrefixes = {
+    "com.android.server.am.ActivityManagerService$LocalService."
+    "updateDeviceIdleTempAllowlist",
     "com.android.server.am.CachedAppOptimizer",
     "com.android.server.am.OomAdjuster",
     "com.android.server.am.OomAdjusterModernImpl",
@@ -64,7 +66,9 @@ bool isAllowed(const ::uprobestats::protos::UprobestatsConfig &config,
       bool allowed = false;
       for (const std::string allowedPrefix : kAllowedMethodPrefixes) {
         if (android::base::StartsWith(fullMethodName, allowedPrefix + ".") ||
-            android::base::StartsWith(fullMethodName, allowedPrefix + "$")) {
+            android::base::StartsWith(fullMethodName, allowedPrefix + "$") ||
+            android::base::StartsWith(fullMethodName, allowedPrefix + "(") ||
+            fullMethodName == allowedPrefix) {
           allowed = true;
           break;
         }
diff --git a/src/UprobeStats.cpp b/src/UprobeStats.cpp
index fa88823..cff83e8 100644
--- a/src/UprobeStats.cpp
+++ b/src/UprobeStats.cpp
@@ -23,6 +23,7 @@
 #include <android-base/scopeguard.h>
 #include <android-base/strings.h>
 #include <android/binder_process.h>
+#include <android_uprobestats_mainline_flags.h>
 #include <config.pb.h>
 #include <iostream>
 #include <stdio.h>
@@ -46,6 +47,7 @@ const std::string kUpdateDeviceIdleTempAllowlistMap =
     std::string("ProcessManagement_update_device_idle_temp_allowlist_records");
 const std::string kProcessManagementMap =
     std::string("ProcessManagement_output_buf");
+const std::string kMalwareSignalMap = std::string("MalwareSignal_output_buf");
 const int kJavaArgumentRegisterOffset = 2;
 
 bool isUprobestatsEnabled() {
@@ -60,6 +62,11 @@ struct PollArgs {
   ::uprobestats::protos::UprobestatsConfig::Task taskConfig;
 };
 
+bool startsWith(const std::string &str, const std::string &prefix) {
+  return str.length() >= prefix.length() &&
+         std::equal(prefix.begin(), prefix.end(), str.begin());
+}
+
 void doPoll(PollArgs args) {
   auto mapPath = args.mapPath;
   auto durationSeconds = args.taskConfig.duration_seconds();
@@ -181,6 +188,27 @@ void doPoll(PollArgs args) {
         AStatsEvent_write(event);
         AStatsEvent_release(event);
       }
+    } else if (mapPath.find(kMalwareSignalMap) != std::string::npos) {
+      auto result =
+          bpf::pollRingBuf<bpf::MalwareSignal>(mapPath.c_str(), timeoutMs);
+      for (auto value : result) {
+        if (value.component_enabled_setting.initialized == true) {
+          LOG_IF_DEBUG(
+              "ComponentEnabledSetting: package_name="
+              << value.component_enabled_setting.package_name
+              << " class_name=" << value.component_enabled_setting.class_name
+              << " new_state=" << value.component_enabled_setting.new_state
+              << " calling_package_name="
+              << value.component_enabled_setting.calling_package_name);
+        }
+        if (value.wm_bound_uid.initialized == true) {
+          LOG_IF_DEBUG(
+              "WmBoundUid: clientUid:" << value.wm_bound_uid.client_uid);
+          LOG_IF_DEBUG(
+              "clientPackageName:" << value.wm_bound_uid.client_package_name);
+          LOG_IF_DEBUG("bindFlags:" << value.wm_bound_uid.bind_flags);
+        }
+      }
     } else {
       LOG_IF_DEBUG("Polling for i64 result");
       auto result = bpf::pollRingBuf<uint64_t>(mapPath.c_str(), timeoutMs);
@@ -198,11 +226,6 @@ int main() {
   if (android::uprobestats::flag_selector::executable_method_file_offsets()) {
     ABinderProcess_startThreadPool();
   }
-  const auto guard = ::android::base::make_scope_guard([] {
-    if (android::uprobestats::flag_selector::executable_method_file_offsets()) {
-      ABinderProcess_joinThreadPool();
-    }
-  });
   if (!isUprobestatsEnabled()) {
     LOG(ERROR) << "uprobestats disabled by flag. Exiting.";
     return 1;
@@ -242,6 +265,22 @@ int main() {
             uprobestats_support_update_device_idle_temp_allowlist()) {
       LOG(ERROR) << "update_device_idle_temp_allowlist disabled by flag";
     }
+    if (resolvedProbe.filename ==
+            "prog_MalwareSignal_uprobe_add_bound_client_uid" &&
+        !android::uprobestats::mainline::flags::
+            uprobestats_monitor_disruptive_app_activities()) {
+      LOG(ERROR)
+          << "uprobestats_monitor_disruptive_app_activities disabled by flag";
+      continue;
+    }
+    if (resolvedProbe.filename ==
+            "prog_MalwareSignal_uprobe_set_component_enabled_setting" &&
+        !android::uprobestats::mainline::flags::
+            uprobestats_monitor_disruptive_app_activities()) {
+      LOG(ERROR)
+          << "uprobestats_monitor_disruptive_app_activities disabled by flag";
+      continue;
+    }
     auto openResult = bpf::bpfPerfEventOpen(
         resolvedProbe.filename.c_str(), resolvedProbe.offset,
         resolvedTask.value().pid,
@@ -261,6 +300,13 @@ int main() {
             uprobestats_support_update_device_idle_temp_allowlist()) {
       LOG(ERROR) << "update_device_idle_temp_allowlist disabled by flag";
     }
+    if (mapPath == "map_MalwareSignal_output_buf" &&
+        !android::uprobestats::mainline::flags::
+            uprobestats_monitor_disruptive_app_activities()) {
+      LOG(ERROR)
+          << "uprobestats_monitor_disruptive_app_activities disabled by flag";
+      continue;
+    }
     auto pollArgs =
         PollArgs{prefixBpf(mapPath), resolvedTask.value().taskConfig};
     LOG_IF_DEBUG(
diff --git a/src/bpf/headers/Android.bp b/src/bpf/headers/Android.bp
index e25dfe3..97704fb 100644
--- a/src/bpf/headers/Android.bp
+++ b/src/bpf/headers/Android.bp
@@ -57,5 +57,8 @@ cc_test {
         "libutils",
     ],
     require_root: true,
-    test_suites: ["general-tests"],
+    test_suites: [
+        "general-tests",
+        "mts-uprobestats",
+    ],
 }
diff --git a/src/bpf/headers/include/bpf/BpfRingbuf.h b/src/bpf/headers/include/bpf/BpfRingbuf.h
index 4bcd259..923de77 100644
--- a/src/bpf/headers/include/bpf/BpfRingbuf.h
+++ b/src/bpf/headers/include/bpf/BpfRingbuf.h
@@ -288,5 +288,44 @@ inline base::Result<int> BpfRingbuf<Value>::ConsumeAll(
   });
 }
 
+class BpfRingbufSized : public BpfRingbufBase {
+ public:
+  using MessageCallback = std::function<void(const void*)>;
+
+  // Creates a ringbuffer wrapper from a pinned path. This initialization will
+  // abort on error. To handle errors, initialize with Create instead.
+  BpfRingbufSized(const char* path, size_t value_size)
+      : BpfRingbufBase(path, value_size) {}
+
+  // Creates a ringbuffer wrapper from a pinned path. There are no guarantees
+  // that the ringbuf outputs messaged of type `Value`, only that they are the
+  // same size. Size is only checked in ConsumeAll.
+  static base::Result<std::unique_ptr<BpfRingbufSized>> Create(
+      const char* path, size_t value_size);
+
+  // Consumes all messages from the ring buffer, passing them to the callback.
+  // Returns the number of messages consumed or a non-ok result on error. If the
+  // ring buffer has no pending messages an OK result with count 0 is returned.
+  base::Result<int> ConsumeAll(const MessageCallback& callback);
+
+ protected:
+  // Empty ctor for use by Create.
+  BpfRingbufSized(size_t value_size) : BpfRingbufBase(value_size) {}
+};
+
+inline base::Result<std::unique_ptr<BpfRingbufSized>>
+BpfRingbufSized::Create(const char* path, size_t value_size) {
+  auto rb = std::unique_ptr<BpfRingbufSized>(new BpfRingbufSized(value_size));
+  if (auto status = rb->Init(path); !status.ok()) return status.error();
+  return rb;
+}
+
+inline base::Result<int> BpfRingbufSized::ConsumeAll(
+    const MessageCallback& callback) {
+  return BpfRingbufBase::ConsumeAll([&](const void* value) {
+    callback(value);
+  });
+}
+
 }  // namespace bpf
 }  // namespace android
diff --git a/src/bpf_progs/Android.bp b/src/bpf_progs/Android.bp
index 1b7bf63..4d9a0af 100644
--- a/src/bpf_progs/Android.bp
+++ b/src/bpf_progs/Android.bp
@@ -24,3 +24,9 @@ bpf {
     ],
     sub_dir: "uprobestats",
 }
+
+bpf {
+    name: "MalwareSignal.o",
+    srcs: ["MalwareSignal.c"],
+    sub_dir: "uprobestats",
+}
diff --git a/src/bpf_progs/MalwareSignal.c b/src/bpf_progs/MalwareSignal.c
new file mode 100644
index 0000000..c6f69c5
--- /dev/null
+++ b/src/bpf_progs/MalwareSignal.c
@@ -0,0 +1,123 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <bpf_helpers.h>
+#include <linux/bpf.h>
+#include <stdbool.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <string.h>
+
+struct pt_regs {
+  unsigned long regs[16];
+  unsigned long pc;
+  unsigned long pr;
+  unsigned long sr;
+  unsigned long gbr;
+  unsigned long mach;
+  unsigned long macl;
+  long tra;
+};
+
+#pragma pack(push, 1) // Pack structs with 1-byte boundary
+struct WmBoundUid {
+  __u64 client_uid;
+  char client_package_name[64];
+  unsigned long bind_flags;
+  bool initialized;
+};
+
+struct ComponentEnabledSetting {
+  char package_name[64];
+  char class_name[64];
+  int new_state;
+  char calling_package_name[64];
+  bool initialized;
+};
+
+struct MalwareSignal {
+  struct WmBoundUid wm_bound_uid;
+  struct ComponentEnabledSetting component_enabled_setting;
+};
+#pragma pack(pop)
+
+void recordString(void *jstring, unsigned int max_length, char *dest) {
+  // Assumes the following memory layout of a Java String object:
+  // byte offset 8-11: count (this is the length of the string * 2)
+  // byte offset 12-15: hash_code
+  // byte offset 16 and beyond: string content
+  __u32 count;
+  bpf_probe_read_user(&count, sizeof(count), jstring + 8);
+  count /= 2;
+  bpf_probe_read_user_str(dest, max_length < count + 1 ? max_length : count + 1,
+                          jstring + 16);
+}
+
+DEFINE_BPF_RINGBUF_EXT(output_buf, struct MalwareSignal, 4096, AID_UPROBESTATS,
+                       AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+DEFINE_BPF_PROG("uprobe/add_bound_client_uid", AID_UPROBESTATS, AID_UPROBESTATS,
+                BPF_KPROBE2)
+(struct pt_regs *ctx) {
+  struct MalwareSignal *output = bpf_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  struct WmBoundUid output_1 = {};
+  output_1.client_uid = ctx->regs[2];
+  output_1.bind_flags = ctx->regs[4];
+  void *j_clientPackageName = (void *)ctx->regs[3];
+  recordString(j_clientPackageName, 64, output_1.client_package_name);
+  output_1.initialized = true;
+  output->wm_bound_uid = output_1;
+  output->component_enabled_setting.initialized = false;
+  bpf_output_buf_submit(output);
+  return 0;
+}
+
+DEFINE_BPF_PROG("uprobe/set_component_enabled_setting", AID_UPROBESTATS,
+                AID_UPROBESTATS, BPF_KPROBE3)
+(struct pt_regs *ctx) {
+  struct MalwareSignal *output = bpf_output_buf_reserve();
+  if (output == NULL)
+    return 1;
+
+  struct ComponentEnabledSetting output_1 = {};
+  void *component_name_ptr = (void *)ctx->regs[2];
+  void *class_name = NULL;
+  void *package_name = NULL;
+
+  bpf_probe_read_user(&class_name, 4, component_name_ptr + 8);
+  recordString(class_name, 64, output_1.class_name);
+
+  bpf_probe_read_user(&package_name, 4, component_name_ptr + 12);
+  recordString(package_name, 64, output_1.package_name);
+
+  void *calling_package_name = (void *)ctx->regs[6];
+  recordString(calling_package_name, 64, output_1.calling_package_name);
+
+  output_1.new_state = ctx->regs[3];
+  output_1.initialized = true;
+  output->component_enabled_setting = output_1;
+  output->wm_bound_uid.initialized = false;
+
+  bpf_output_buf_submit(output);
+  return 0;
+}
+
+LICENSE("GPL");
diff --git a/src/bpfloader/UprobeStatsBpfLoad.cpp b/src/bpfloader/UprobeStatsBpfLoad.cpp
index f38e868..ce9121a 100644
--- a/src/bpfloader/UprobeStatsBpfLoad.cpp
+++ b/src/bpfloader/UprobeStatsBpfLoad.cpp
@@ -483,9 +483,9 @@ static int readCodeSections(ifstream &elfFile, vector<codeSection> &cs,
     ret = getSectionSymNames(elfFile, oldName, csSymNames, STT_FUNC);
     if (ret || !csSymNames.size())
       return ret;
-    for (size_t i = 0; i < progDefNames.size(); ++i) {
-      if (!progDefNames[i].compare(csSymNames[0] + "_def")) {
-        cs_temp.prog_def = pd[i];
+    for (size_t j = 0; j < progDefNames.size(); ++j) {
+      if (!progDefNames[j].compare(csSymNames[0] + "_def")) {
+        cs_temp.prog_def = pd[j];
         break;
       }
     }
diff --git a/src/mainline-flag.aconfig b/src/mainline-flag.aconfig
index 2b334d8..a227cc6 100644
--- a/src/mainline-flag.aconfig
+++ b/src/mainline-flag.aconfig
@@ -17,6 +17,14 @@ flag {
     is_fixed_read_only: true
 }
 
+flag {
+    name: "uprobestats_monitor_disruptive_app_activities"
+    namespace: "responsible_apis"
+    description: "Whether to enable uprobestats support of monitoring disruptive app activities"
+    bug: "395129335"
+    is_fixed_read_only: true
+}
+
 flag {
     name: "executable_method_file_offsets"
     namespace: "system_performance"
diff --git a/src/test/Android.bp b/src/test/Android.bp
new file mode 100644
index 0000000..5a792c1
--- /dev/null
+++ b/src/test/Android.bp
@@ -0,0 +1,51 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_performance",
+}
+
+java_test_host {
+    name: "uprobestats-test",
+    srcs: [
+        "*.java",
+    ],
+    java_resources: ["test/*.textproto"],
+    libs: [
+        "compatibility-host-util",
+        "core_cts_test_resources",
+        "cts-tradefed",
+        "host-libprotobuf-java-full",
+        "tradefed",
+        "truth",
+    ],
+    static_libs: [
+        "android.hardware.usb.flags-aconfig-java-host",
+        "android.os.flags-aconfig-java-host",
+        "cts-statsd-atom-host-test-utils",
+        "flag-junit-host",
+        "perfetto_config-full",
+        "art_flags_uprobestats_java_lib",
+        "uprobestats_flags_java_lib",
+        "uprobestats-protos",
+    ],
+    proto: {
+        type: "full",
+    },
+    test_suites: [
+        "general-tests",
+        "mts-uprobestats",
+    ],
+}
+
+python_binary_host {
+    name: "hello_uprobestats",
+    main: "hello_uprobestats.py",
+    srcs: [
+        "hello_uprobestats.py",
+        ":uprobestats-proto-files",
+    ],
+    data: ["test/*.textproto"],
+    libs: ["libprotobuf-python"],
+    proto: {
+        canonical_path_from_root: false,
+    },
+}
diff --git a/src/test/AndroidTest.xml b/src/test/AndroidTest.xml
new file mode 100644
index 0000000..d438ed3
--- /dev/null
+++ b/src/test/AndroidTest.xml
@@ -0,0 +1,12 @@
+<?xml version="1.0" encoding="utf-8"?>
+<configuration description="Config for UprobeStats tests">
+
+    <test class="com.android.compatibility.common.tradefed.testtype.JarHostTest" >
+        <option name="jar" value="uprobestats-test.jar" />
+    </test>
+
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
+        <option name="mainline-module-package-name" value="com.google.android.uprobestats" />
+    </object>
+
+</configuration>
diff --git a/src/test/SmokeTest.java b/src/test/SmokeTest.java
index e26d166..7f79496 100644
--- a/src/test/SmokeTest.java
+++ b/src/test/SmokeTest.java
@@ -36,7 +36,6 @@ import com.android.compatibility.common.util.CpuFeatures;
 import com.android.internal.os.StatsdConfigProto;
 import com.android.os.StatsLog;
 import com.android.os.framework.FrameworkExtensionAtoms;
-import com.android.os.framework.FrameworkExtensionAtoms.DeviceIdleTempAllowlistUpdated;
 import com.android.os.uprobestats.TestUprobeStatsAtomReported;
 import com.android.os.uprobestats.UprobestatsExtensionAtoms;
 import com.android.tradefed.device.ITestDevice;
@@ -128,13 +127,21 @@ public class SmokeTest extends BaseHostJUnit4Test {
     }
 
     @Test
-    @RequiresFlagsEnabled({FLAG_ENABLE_UPROBESTATS, FLAG_EXECUTABLE_METHOD_FILE_OFFSETS})
+    @RequiresFlagsEnabled({
+        FLAG_ENABLE_UPROBESTATS,
+        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
+        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS
+    })
     public void batteryStats_artApi() throws Exception {
         batteryStats(BATTERY_STATS_CONFIG_ART);
     }
 
     @Test
-    @RequiresFlagsEnabled({FLAG_ENABLE_UPROBESTATS, FLAG_EXECUTABLE_METHOD_FILE_OFFSETS})
+    @RequiresFlagsEnabled({
+        FLAG_ENABLE_UPROBESTATS,
+        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
+        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS
+    })
     public void batteryStats_oatdump_fallback() throws Exception {
         batteryStats(BATTERY_STATS_CONFIG_OATDUMP);
     }
@@ -182,11 +189,21 @@ public class SmokeTest extends BaseHostJUnit4Test {
         // See if the atom made it
         List<StatsLog.EventMetricData> data =
                 ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
-        assertThat(data.size()).isEqualTo(1);
-        DeviceIdleTempAllowlistUpdated reported =
-                data.get(0)
-                        .getAtom()
-                        .getExtension(FrameworkExtensionAtoms.deviceIdleTempAllowlistUpdated);
-        assertThat(reported.getReason()).isEqualTo("shell");
+        assertThat(data.size()).isGreaterThan(0);
+        boolean anyMatch =
+                data.stream()
+                        .map(StatsLog.EventMetricData::getAtom)
+                        .filter(
+                                atom ->
+                                        atom.hasExtension(
+                                                FrameworkExtensionAtoms
+                                                        .deviceIdleTempAllowlistUpdated))
+                        .map(
+                                atom ->
+                                        atom.getExtension(
+                                                FrameworkExtensionAtoms
+                                                        .deviceIdleTempAllowlistUpdated))
+                        .anyMatch(reported -> reported.getReason().equals("shell"));
+        assertThat(anyMatch).isTrue();
     }
 }
diff --git a/src/test/hello_uprobestats.py b/src/test/hello_uprobestats.py
index d540139..dd9c1f7 100644
--- a/src/test/hello_uprobestats.py
+++ b/src/test/hello_uprobestats.py
@@ -32,7 +32,7 @@ def create_and_push_config_proto(name="test_slog"):
       temp.flush()
       print(f"creating {name}")
       config_cmd = (
-          f"adb push {temp.name} /data/misc/uprobestats-configs/{name}.proto"
+          f"adb push {temp.name} /data/misc/uprobestats-configs/config"
       )
       subprocess.run(config_cmd, **kwargs)
 
@@ -42,12 +42,15 @@ def clear_logcat():
   subprocess.run("adb logcat -c", **kwargs)
 
 
-def start_uprobestats(name="test_slog"):
-  print("starting uprobestats")
-  subprocess.run(
-      f"adb shell setprop uprobestats.start_with_config {name}.proto", **kwargs
-  )
-
+def start_uprobestats(run_as_shell=False):
+  if (run_as_shell):
+    print("starting uprobestats as Shell")
+    subprocess.run(
+      f"adb shell /apex/com.android.uprobestats/bin/uprobestats", **kwargs)
+  else:
+    print("starting uprobestats")
+    subprocess.run(
+        f"adb shell setprop ctl.start uprobestats", **kwargs)
 
 def get_ring_buffer_values():
   time.sleep(10)
@@ -103,17 +106,22 @@ if __name__ == "__main__":
           " logcat output to exit successfully"
       ),
   )
+  parser.add_argument(
+    "-s",
+    action="store_true",  # Store True if the flag is present
+    help="Run uprobestats as Shell",
+)
   args = parser.parse_args()
 
   adb_root()
   create_and_push_config_proto(args.name)
 
   if not args.test:
-    start_uprobestats(args.name)
+    start_uprobestats(args.s)
     sys.exit(0)
 
   clear_logcat()
-  start_uprobestats(args.name)
+  start_uprobestats(args.s)
   time.sleep(60)
   ring_buf = get_ring_buffer_size()
   get_ring_buffer_values()
diff --git a/src/test/malware_signal.textproto b/src/test/malware_signal.textproto
new file mode 100644
index 0000000..3e5983f
--- /dev/null
+++ b/src/test/malware_signal.textproto
@@ -0,0 +1,20 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs {
+        bpf_name: "prog_MalwareSignal_uprobe_set_component_enabled_setting"
+        fully_qualified_class_name: "com.android.server.pm.PackageManagerService$IPackageManagerImpl"
+        method_name: "setComponentEnabledSetting"
+        fully_qualified_parameters: ["android.content.ComponentName", "int", "int", "int", "java.lang.String"]
+    }
+    probe_configs {
+        bpf_name: "prog_MalwareSignal_uprobe_add_bound_client_uid"
+        fully_qualified_class_name: "com.android.server.wm.BackgroundLaunchProcessController"
+        method_name: "addBoundClientUid"
+        fully_qualified_parameters: ["int", "java.lang.String", "long"]
+    }
+    bpf_maps: "map_MalwareSignal_output_buf"
+    target_process_name: "system_server"
+    duration_seconds: 300
+}
diff --git a/src/test/test_ams_onServiceInfoChangedLocked.textproto b/src/test/test/test_ams_onServiceInfoChangedLocked.textproto
similarity index 100%
rename from src/test/test_ams_onServiceInfoChangedLocked.textproto
rename to src/test/test/test_ams_onServiceInfoChangedLocked.textproto
diff --git a/src/test/test_bss_noteEvent.textproto b/src/test/test/test_bss_noteEvent.textproto
similarity index 100%
rename from src/test/test_bss_noteEvent.textproto
rename to src/test/test/test_bss_noteEvent.textproto
diff --git a/src/test/test_bss_noteScreenState.textproto b/src/test/test/test_bss_noteScreenState.textproto
similarity index 100%
rename from src/test/test_bss_noteScreenState.textproto
rename to src/test/test/test_bss_noteScreenState.textproto
diff --git a/src/test/test_bss_setBatteryState_artApi.textproto b/src/test/test/test_bss_setBatteryState_artApi.textproto
similarity index 100%
rename from src/test/test_bss_setBatteryState_artApi.textproto
rename to src/test/test/test_bss_setBatteryState_artApi.textproto
diff --git a/src/test/test_bss_setBatteryState_oatdump.textproto b/src/test/test/test_bss_setBatteryState_oatdump.textproto
similarity index 100%
rename from src/test/test_bss_setBatteryState_oatdump.textproto
rename to src/test/test/test_bss_setBatteryState_oatdump.textproto
diff --git a/src/test/test_cm_addCall.textproto b/src/test/test/test_cm_addCall.textproto
similarity index 100%
rename from src/test/test_cm_addCall.textproto
rename to src/test/test/test_cm_addCall.textproto
diff --git a/src/test/test_cm_markCallAsActive.textproto b/src/test/test/test_cm_markCallAsActive.textproto
similarity index 100%
rename from src/test/test_cm_markCallAsActive.textproto
rename to src/test/test/test_cm_markCallAsActive.textproto
diff --git a/src/test/test_csw_setActive.textproto b/src/test/test/test_csw_setActive.textproto
similarity index 100%
rename from src/test/test_csw_setActive.textproto
rename to src/test/test/test_csw_setActive.textproto
diff --git a/src/test/test_mp_start.textproto b/src/test/test/test_mp_start.textproto
similarity index 100%
rename from src/test/test_mp_start.textproto
rename to src/test/test/test_mp_start.textproto
diff --git a/src/test/test_pis_validateApkInstallLocked.textproto b/src/test/test/test_pis_validateApkInstallLocked.textproto
similarity index 100%
rename from src/test/test_pis_validateApkInstallLocked.textproto
rename to src/test/test/test_pis_validateApkInstallLocked.textproto
diff --git a/src/test/test_setUidTempAllowlistStateLSP.textproto b/src/test/test/test_setUidTempAllowlistStateLSP.textproto
similarity index 100%
rename from src/test/test_setUidTempAllowlistStateLSP.textproto
rename to src/test/test/test_setUidTempAllowlistStateLSP.textproto
diff --git a/src/test/test_slog.textproto b/src/test/test/test_slog.textproto
similarity index 100%
rename from src/test/test_slog.textproto
rename to src/test/test/test_slog.textproto
diff --git a/src/test/test_tsi_placeCall.textproto b/src/test/test/test_tsi_placeCall.textproto
similarity index 100%
rename from src/test/test_tsi_placeCall.textproto
rename to src/test/test/test_tsi_placeCall.textproto
diff --git a/src/test/test_updateDeviceIdleTempAllowlist.textproto b/src/test/test/test_updateDeviceIdleTempAllowlist.textproto
similarity index 70%
rename from src/test/test_updateDeviceIdleTempAllowlist.textproto
rename to src/test/test/test_updateDeviceIdleTempAllowlist.textproto
index dc4a9f1..9379587 100644
--- a/src/test/test_updateDeviceIdleTempAllowlist.textproto
+++ b/src/test/test/test_updateDeviceIdleTempAllowlist.textproto
@@ -6,6 +6,9 @@ tasks {
         bpf_name: "prog_ProcessManagement_uprobe_update_device_idle_temp_allowlist"
         file_paths: "/system/framework/oat/arm64/services.odex"
         method_signature: "void com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist(int[], int, boolean, long, int, int, java.lang.String, int)"
+        fully_qualified_class_name: "com.android.server.am.ActivityManagerService$LocalService"
+        method_name: "updateDeviceIdleTempAllowlist"
+        fully_qualified_parameters: ["int[]", "int", "boolean", "long", "int", "int", "java.lang.String", "int"]
     }
     bpf_maps: "map_ProcessManagement_update_device_idle_temp_allowlist_records"
     target_process_name: "system_server"
```

