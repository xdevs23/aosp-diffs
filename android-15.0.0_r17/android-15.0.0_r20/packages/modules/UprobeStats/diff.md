```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index 5aa6f81..4d14fb4 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -27,6 +27,13 @@ android_app_certificate {
     certificate: "com.android.uprobestats",
 }
 
+prebuilt_etc {
+    name: "com.android.uprobestats.init.rc",
+    src: "UprobeStats-mainline.rc",
+    filename: "init.rc",
+    installable: false,
+}
+
 apex {
     // This apex will be enabled using release_uprobestats_module flag
     enabled: select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
@@ -35,6 +42,24 @@ apex {
     }),
 
     name: "com.android.uprobestats",
+    binaries: [
+        "uprobestats",
+        "uprobestatsbpfload",
+    ],
+
+    prebuilts: [
+        "com.android.uprobestats.init.rc",
+    ],
+
+    bpfs: [
+        "BitmapAllocation.o",
+        "GenericInstrumentation.o",
+        "ProcessManagement.o",
+    ],
+
+    native_shared_libs: [
+        "libuprobestats_client",
+    ],
     manifest: "manifest.json",
     file_contexts: ":com.android.uprobestats-file_contexts",
     key: "com.android.uprobestats.key",
diff --git a/apex/UprobeStats-mainline.rc b/apex/UprobeStats-mainline.rc
new file mode 100644
index 0000000..9ee98ef
--- /dev/null
+++ b/apex/UprobeStats-mainline.rc
@@ -0,0 +1,6 @@
+service uprobestats /apex/com.android.uprobestats/bin/uprobestats
+    disabled
+    user uprobestats
+    group uprobestats readproc
+    oneshot
+    capabilities PERFMON
diff --git a/src/Android.bp b/src/Android.bp
index 69ae4ec..8873d00 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -10,37 +10,112 @@ aconfig_declarations {
     srcs: ["flag.aconfig"],
 }
 
+aconfig_declarations {
+    name: "uprobestats_mainline_flags",
+    package: "android.uprobestats.mainline.flags",
+    container: "com.android.uprobestats",
+    srcs: ["mainline-flag.aconfig"],
+}
+
 cc_aconfig_library {
     name: "uprobestats_flags_c_lib",
     aconfig_declarations: "uprobestats_flags",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+    min_sdk_version: "35",
+}
+
+cc_aconfig_library {
+    name: "uprobestats_mainline_flags_c_lib",
+    aconfig_declarations: "uprobestats_mainline_flags",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+    min_sdk_version: "35",
+}
+
+java_aconfig_library {
+    name: "uprobestats_flags_java_lib",
+    aconfig_declarations: "uprobestats_flags",
+    host_supported: true,
+}
+
+java_aconfig_library {
+    name: "art_flags_uprobestats_java_lib",
+    aconfig_declarations: "art-aconfig-flags",
+    host_supported: true,
+}
+
+java_aconfig_library {
+    name: "uprobestats_mainline_flags_java_lib",
+    aconfig_declarations: "uprobestats_mainline_flags",
+    host_supported: true,
+    visibility: [
+        "//cts/hostsidetests/statsdatom:__subpackages__",
+    ],
+}
+
+soong_config_module_type {
+    name: "uprobestats_cc_library",
+    module_type: "cc_library",
+    config_namespace: "ANDROID",
+    bool_variables: [
+        "release_uprobestats_module",
+    ],
+    properties: [
+        "cflags",
+    ],
+}
+
+soong_config_bool_variable {
+    name: "release_uprobestats_module",
 }
 
-cc_library {
+uprobestats_cc_library {
     name: "libuprobestats",
+    soong_config_variables: {
+        release_uprobestats_module: {
+            cflags: [
+                "-DUPROBESTATS_IN_MAINLINE=1",
+            ],
+        },
+    },
     srcs: [
         "Art.cpp",
         "Bpf.cpp",
         "ConfigResolver.cpp",
+        "DynamicInstrumentationManager.cpp",
+        "FlagSelector.cpp",
         "Process.cpp",
         "Guardrail.cpp",
         "config.proto",
     ],
     header_libs: [
-        "bpf_headers",
+        "uprobestats_bpf_headers",
     ],
     shared_libs: [
+        "libandroid",
+        "libbinder_ndk",
         "libbase",
         "liblog",
     ],
     static_libs: [
-        "libc++fs",
         "libjsoncpp",
         "uprobestats_flags_c_lib",
+        "uprobestats_mainline_flags_c_lib",
     ],
     proto: {
         export_proto_headers: true,
         type: "lite",
     },
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+    min_sdk_version: "35",
 }
 
 cc_binary {
@@ -50,29 +125,54 @@ cc_binary {
         "config.proto",
     ],
     static_libs: [
-        "libc++fs",
         "libjsoncpp",
         "libprotoutil",
         "libuprobestats",
         "uprobestats_flags_c_lib",
+        "uprobestats_mainline_flags_c_lib",
     ],
     shared_libs: [
+        "libandroid",
         "libbase",
+        "libbinder_ndk",
         "liblog",
         "libstatssocket",
     ],
     init_rc: [
-        "UprobeStats.rc",
-    ],
-    required: [
-        "BitmapAllocation.o",
-        "GenericInstrumentation.o",
-        "ProcessManagement.o",
-    ],
+        "UprobeStats-platform.rc",
+    ],
+    required: select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
+        true: [],
+        false: [
+            "BitmapAllocation.o",
+            "GenericInstrumentation.o",
+            "ProcessManagement.o",
+        ],
+    }),
+
     proto: {
         type: "lite",
         static: true,
     },
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+
+    min_sdk_version: "35",
+}
+
+java_library_host {
+    name: "uprobestats-protos",
+    srcs: [
+        "config.proto",
+    ],
+    proto: {
+        include_dirs: [
+            "external/protobuf/src",
+        ],
+        type: "full",
+    },
 }
 
 java_test_host {
@@ -96,11 +196,16 @@ java_test_host {
         "cts-statsd-atom-host-test-utils",
         "flag-junit-host",
         "perfetto_config-full",
+        "art_flags_uprobestats_java_lib",
+        "uprobestats_flags_java_lib",
     ],
     proto: {
         type: "full",
     },
-    test_suites: ["general-tests"],
+    test_suites: [
+        "general-tests",
+        "mts-uprobestats",
+    ],
 }
 
 python_binary_host {
diff --git a/src/Bpf.cpp b/src/Bpf.cpp
index 9ff8920..1d87d34 100644
--- a/src/Bpf.cpp
+++ b/src/Bpf.cpp
@@ -98,6 +98,9 @@ template std::vector<CallTimestamp> pollRingBuf(const char *mapPath,
 template std::vector<SetUidTempAllowlistStateRecord>
 pollRingBuf(const char *mapPath, int timeoutMs);
 
+template std::vector<UpdateDeviceIdleTempAllowlistRecord>
+pollRingBuf(const char *mapPath, int timeoutMs);
+
 std::vector<int32_t> consumeRingBuf(const char *mapPath) {
   auto result = android::bpf::BpfRingbuf<uint64_t>::Create(mapPath);
   std::vector<int32_t> vec;
diff --git a/src/Bpf.h b/src/Bpf.h
index 16a64d9..8464803 100644
--- a/src/Bpf.h
+++ b/src/Bpf.h
@@ -41,6 +41,16 @@ struct SetUidTempAllowlistStateRecord {
   bool onAllowlist;
 };
 
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
 template <typename T>
 std::vector<T> pollRingBuf(const char *mapPath, int timeoutMs);
 
diff --git a/src/ConfigResolver.cpp b/src/ConfigResolver.cpp
index 68dcd1f..da78f6c 100644
--- a/src/ConfigResolver.cpp
+++ b/src/ConfigResolver.cpp
@@ -30,6 +30,9 @@
 
 #include "Art.h"
 #include "ConfigResolver.h"
+#include "DebugLog.h"
+#include "DynamicInstrumentationManager.h"
+#include "FlagSelector.h"
 #include "Process.h"
 
 namespace android {
@@ -105,13 +108,43 @@ resolveSingleTask(::uprobestats::protos::UprobestatsConfig config) {
 }
 
 std::optional<std::vector<ResolvedProbe>>
-resolveProbes(::uprobestats::protos::UprobestatsConfig::Task taskConfig) {
+resolveProbes(::uprobestats::protos::UprobestatsConfig::Task &taskConfig) {
   if (taskConfig.probe_configs().size() == 0) {
     LOG(ERROR) << "task has no probe configs";
     return {};
   }
   std::vector<ResolvedProbe> result;
   for (auto &probeConfig : taskConfig.probe_configs()) {
+    if (android::uprobestats::flag_selector::executable_method_file_offsets() &&
+        probeConfig.has_fully_qualified_class_name()) {
+      LOG_IF_DEBUG("using getExecutableMethodFileOffsets to retrieve offsets");
+      std::vector<std::string> fqParameters(
+          probeConfig.fully_qualified_parameters().begin(),
+          probeConfig.fully_qualified_parameters().end());
+      std::string processName(taskConfig.target_process_name());
+      std::string fqcn(probeConfig.fully_qualified_class_name());
+      std::string methodName(probeConfig.method_name());
+      std::optional<
+          dynamic_instrumentation_manager::ExecutableMethodFileOffsets>
+          offsets =
+              dynamic_instrumentation_manager::getExecutableMethodFileOffsets(
+                  processName, fqcn, methodName, fqParameters);
+      if (!offsets.has_value()) {
+        LOG(ERROR) << "Unable to find method offset for "
+                   << probeConfig.fully_qualified_class_name() << "#"
+                   << probeConfig.method_name();
+        return {};
+      }
+
+      ResolvedProbe probe;
+      probe.filename = offsets->containerPath;
+      probe.offset = offsets->methodOffset;
+      probe.probeConfig = probeConfig;
+      result.push_back(probe);
+      continue;
+    }
+
+    LOG_IF_DEBUG("using oatdump to retrieve offsets");
     int offset = 0;
     std::string matched_file_path;
     for (auto &file_path : probeConfig.file_paths()) {
diff --git a/src/ConfigResolver.h b/src/ConfigResolver.h
index 8793c2d..b6294f9 100644
--- a/src/ConfigResolver.h
+++ b/src/ConfigResolver.h
@@ -42,7 +42,7 @@ std::optional<ResolvedTask>
 resolveSingleTask(::uprobestats::protos::UprobestatsConfig config);
 
 std::optional<std::vector<ResolvedProbe>>
-resolveProbes(::uprobestats::protos::UprobestatsConfig::Task taskConfig);
+resolveProbes(::uprobestats::protos::UprobestatsConfig::Task &taskConfig);
 
 } // namespace config_resolver
 } // namespace uprobestats
diff --git a/src/DebugLog.h b/src/DebugLog.h
new file mode 100644
index 0000000..d254a92
--- /dev/null
+++ b/src/DebugLog.h
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+const bool kDebug = false;
+
+#define LOG_IF_DEBUG(msg)                                                      \
+  do {                                                                         \
+    if (kDebug) {                                                              \
+      LOG(INFO) << msg;                                                        \
+    }                                                                          \
+  } while (0)
diff --git a/src/DynamicInstrumentationManager.cpp b/src/DynamicInstrumentationManager.cpp
new file mode 100644
index 0000000..5699c96
--- /dev/null
+++ b/src/DynamicInstrumentationManager.cpp
@@ -0,0 +1,184 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include "DynamicInstrumentationManager.h"
+#include "DebugLog.h"
+#include <android-base/logging.h>
+#include <android-base/scopeguard.h>
+#include <assert.h>
+#include <dlfcn.h>
+#include <log/log.h>
+#include <optional>
+#include <string>
+#include <vector>
+
+namespace android::uprobestats::dynamic_instrumentation_manager {
+
+struct ADynamicInstrumentationManager_MethodDescriptor;
+typedef struct ADynamicInstrumentationManager_MethodDescriptor
+    ADynamicInstrumentationManager_MethodDescriptor;
+
+struct ADynamicInstrumentationManager_TargetProcess;
+typedef struct ADynamicInstrumentationManager_TargetProcess
+    ADynamicInstrumentationManager_TargetProcess;
+
+struct ADynamicInstrumentationManager_ExecutableMethodFileOffsets;
+typedef struct ADynamicInstrumentationManager_ExecutableMethodFileOffsets
+    ADynamicInstrumentationManager_ExecutableMethodFileOffsets;
+
+typedef ADynamicInstrumentationManager_TargetProcess *(
+    *ADynamicInstrumentationManager_TargetProcess_create)(
+    uid_t uid, pid_t pid, const char *processName);
+typedef void (*ADynamicInstrumentationManager_TargetProcess_destroy)(
+    const ADynamicInstrumentationManager_TargetProcess *instance);
+
+typedef ADynamicInstrumentationManager_MethodDescriptor *(
+    *ADynamicInstrumentationManager_MethodDescriptor_create)(
+    const char *fullyQualifiedClassName, const char *methodName,
+    const char *fullyQualifiedParameters[], unsigned int numParameters);
+typedef void (*ADynamicInstrumentationManager_MethodDescriptor_destroy)(
+    const ADynamicInstrumentationManager_MethodDescriptor *instance);
+
+typedef const char *(
+    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath)(
+    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
+typedef unsigned long (
+    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset)(
+    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
+typedef unsigned long (
+    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset)(
+    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
+typedef void (
+    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy)(
+    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
+
+typedef int32_t (
+    *ADynamicInstrumentationManager_getExecutableMethodFileOffsets)(
+    const ADynamicInstrumentationManager_TargetProcess &targetProcess,
+    const ADynamicInstrumentationManager_MethodDescriptor &methodDescriptor,
+    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets **out);
+
+const char kLibandroidPath[] = "libandroid.so";
+
+template <typename T>
+void getLibFunction(void *handle, const char *identifier, T *out) {
+  auto result = reinterpret_cast<T>(dlsym(handle, identifier));
+  if (!result) {
+    ALOGE("dlsym error: %s %s %s", __func__, dlerror(), identifier);
+    assert(result);
+  }
+  *out = result;
+}
+
+std::optional<ExecutableMethodFileOffsets>
+getExecutableMethodFileOffsets(std::string &processName, std::string &fqcn,
+                               std::string &methodName,
+                               std::vector<std::string> &fqParameters) {
+  void *handle = dlopen(kLibandroidPath, RTLD_NOW | RTLD_LOCAL);
+  if (!handle) {
+    ALOGE("dlopen error: %s %s", __func__, dlerror());
+    return {};
+  }
+
+  ADynamicInstrumentationManager_TargetProcess_create targetProcess_create;
+  getLibFunction(handle, "ADynamicInstrumentationManager_TargetProcess_create",
+                 &targetProcess_create);
+  ADynamicInstrumentationManager_TargetProcess_destroy targetProcess_destroy;
+  getLibFunction(handle, "ADynamicInstrumentationManager_TargetProcess_destroy",
+                 &targetProcess_destroy);
+  ADynamicInstrumentationManager_MethodDescriptor_create
+      methodDescriptor_create;
+  getLibFunction(handle,
+                 "ADynamicInstrumentationManager_MethodDescriptor_create",
+                 &methodDescriptor_create);
+  ADynamicInstrumentationManager_MethodDescriptor_destroy
+      methodDescriptor_destroy;
+  getLibFunction(handle,
+                 "ADynamicInstrumentationManager_MethodDescriptor_destroy",
+                 &methodDescriptor_destroy);
+  ADynamicInstrumentationManager_getExecutableMethodFileOffsets
+      getExecutableMethodFileOffsets;
+  getLibFunction(
+      handle, "ADynamicInstrumentationManager_getExecutableMethodFileOffsets",
+      &getExecutableMethodFileOffsets);
+  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy
+      executableMethodFileOffsets_destroy;
+  getLibFunction(
+      handle,
+      "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy",
+      &executableMethodFileOffsets_destroy);
+  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath
+      getContainerPath;
+  getLibFunction(handle,
+                 "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_"
+                 "getContainerPath",
+                 &getContainerPath);
+  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset
+      getContainerOffset;
+  getLibFunction(handle,
+                 "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_"
+                 "getContainerOffset",
+                 &getContainerOffset);
+  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset
+      getMethodOffset;
+  getLibFunction(handle,
+                 "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_"
+                 "getMethodOffset",
+                 &getMethodOffset);
+
+  const ADynamicInstrumentationManager_TargetProcess *targetProcess =
+      targetProcess_create(0, 0, processName.c_str());
+
+  std::vector<const char *> fqpVec;
+  for (size_t i = 0; i < fqParameters.size(); ++i) {
+    fqpVec.push_back(fqParameters[i].c_str());
+  }
+  const ADynamicInstrumentationManager_MethodDescriptor *methodDescriptor =
+      methodDescriptor_create(fqcn.c_str(), methodName.c_str(), fqpVec.data(),
+                              fqParameters.size());
+
+  const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *offsets =
+      nullptr;
+  int32_t result = getExecutableMethodFileOffsets(*targetProcess,
+                                                  *methodDescriptor, &offsets);
+
+  targetProcess_destroy(targetProcess);
+  methodDescriptor_destroy(methodDescriptor);
+
+  if (result != 0) {
+    LOG(ERROR) << "error calling getExecutableMethodFileOffsets. result: "
+               << result;
+  }
+
+  if (offsets == nullptr) {
+    LOG(ERROR) << "could not find offset for " << methodName;
+    return {};
+  }
+
+  const char *cp = getContainerPath(offsets);
+  std::string containerPath(cp);
+  uint64_t containerOffset = getContainerOffset(offsets);
+  uint64_t methodOffset = getMethodOffset(offsets);
+
+  executableMethodFileOffsets_destroy(offsets);
+
+  ExecutableMethodFileOffsets executableMethodFileOffsets;
+  executableMethodFileOffsets.containerPath = containerPath;
+  executableMethodFileOffsets.containerOffset = containerOffset;
+  executableMethodFileOffsets.methodOffset = methodOffset;
+  return executableMethodFileOffsets;
+}
+} // namespace android::uprobestats::dynamic_instrumentation_manager
diff --git a/src/DynamicInstrumentationManager.h b/src/DynamicInstrumentationManager.h
new file mode 100644
index 0000000..a01e9b7
--- /dev/null
+++ b/src/DynamicInstrumentationManager.h
@@ -0,0 +1,36 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#pragma once
+
+#import <optional>
+#import <string>
+#import <vector>
+
+namespace android::uprobestats::dynamic_instrumentation_manager {
+
+struct ExecutableMethodFileOffsets {
+  std::string containerPath;
+  uint64_t containerOffset;
+  uint64_t methodOffset;
+};
+
+std::optional<ExecutableMethodFileOffsets>
+getExecutableMethodFileOffsets(std::string &processName, std::string &fqcn,
+                               std::string &methodName,
+                               std::vector<std::string> &fqParameters);
+
+} // namespace android::uprobestats::dynamic_instrumentation_manager
diff --git a/src/FlagSelector.cpp b/src/FlagSelector.cpp
new file mode 100644
index 0000000..d845104
--- /dev/null
+++ b/src/FlagSelector.cpp
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <android_uprobestats_flags.h>
+#include <android_uprobestats_mainline_flags.h>
+
+#include "FlagSelector.h"
+
+namespace android {
+namespace uprobestats {
+namespace flag_selector {
+
+bool enable_uprobestats() {
+#ifdef UPROBESTATS_IN_MAINLINE
+  return android::uprobestats::mainline::flags::enable_uprobestats();
+#else
+  return android::uprobestats::flags::enable_uprobestats();
+#endif
+}
+
+bool uprobestats_support_update_device_idle_temp_allowlist() {
+#ifdef UPROBESTATS_IN_MAINLINE
+  return android::uprobestats::mainline::flags::
+      uprobestats_support_update_device_idle_temp_allowlist();
+#else
+  return android::uprobestats::flags::
+      uprobestats_support_update_device_idle_temp_allowlist();
+#endif
+}
+
+bool executable_method_file_offsets() {
+#ifdef UPROBESTATS_IN_MAINLINE
+  return android::uprobestats::mainline::flags::
+      executable_method_file_offsets();
+#else
+  return android::uprobestats::flags::executable_method_file_offsets();
+#endif
+}
+
+} // namespace flag_selector
+} // namespace uprobestats
+} // namespace android
diff --git a/src/FlagSelector.h b/src/FlagSelector.h
new file mode 100644
index 0000000..57825c6
--- /dev/null
+++ b/src/FlagSelector.h
@@ -0,0 +1,29 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#pragma once
+
+namespace android {
+namespace uprobestats {
+namespace flag_selector {
+
+bool enable_uprobestats();
+bool uprobestats_support_update_device_idle_temp_allowlist();
+bool executable_method_file_offsets();
+
+} // namespace flag_selector
+} // namespace uprobestats
+} // namespace android
diff --git a/src/Guardrail-test.cpp b/src/Guardrail-test.cpp
index 968c534..6c70df9 100644
--- a/src/Guardrail-test.cpp
+++ b/src/Guardrail-test.cpp
@@ -27,8 +27,16 @@ TEST_F(GuardrailTest, EverythingAllowedOnUserDebugAndEng) {
   ::uprobestats::protos::UprobestatsConfig config;
   config.add_tasks()->add_probe_configs()->set_method_signature(
       "void com.android.server.am.SomeClass.doWork()");
-  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug"));
-  EXPECT_TRUE(guardrail::isAllowed(config, "eng"));
+  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug", false));
+  EXPECT_TRUE(guardrail::isAllowed(config, "eng", false));
+
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
+  probeConfig.set_fully_qualified_class_name("com.android.server.am.SomeClass");
+  probeConfig.set_method_name("doWork");
+  ::uprobestats::protos::UprobestatsConfig newConfig;
+  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
+  EXPECT_TRUE(guardrail::isAllowed(newConfig, "userdebug", true));
+  EXPECT_TRUE(guardrail::isAllowed(newConfig, "eng", true));
 }
 
 TEST_F(GuardrailTest, OomAdjusterAllowed) {
@@ -40,16 +48,39 @@ TEST_F(GuardrailTest, OomAdjusterAllowed) {
       "void "
       "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0.accept(java."
       "lang.Object)");
-  EXPECT_TRUE(guardrail::isAllowed(config, "user"));
-  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug"));
-  EXPECT_TRUE(guardrail::isAllowed(config, "eng"));
+  EXPECT_TRUE(guardrail::isAllowed(config, "user", false));
+  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug", false));
+  EXPECT_TRUE(guardrail::isAllowed(config, "eng", false));
+
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
+  probeConfig.set_fully_qualified_class_name(
+      "com.android.server.am.OomAdjuster");
+  probeConfig.set_method_name("setUidTempAllowlistStateLSP");
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfigTwo;
+  probeConfigTwo.set_fully_qualified_class_name(
+      "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0");
+  probeConfigTwo.set_method_name("accept");
+  ::uprobestats::protos::UprobestatsConfig newConfig;
+  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
+  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfigTwo);
+  EXPECT_TRUE(guardrail::isAllowed(newConfig, "user", true));
+  EXPECT_TRUE(guardrail::isAllowed(newConfig, "userdebug", true));
+  EXPECT_TRUE(guardrail::isAllowed(newConfig, "eng", true));
 }
 
 TEST_F(GuardrailTest, DisallowOomAdjusterWithSuffix) {
   ::uprobestats::protos::UprobestatsConfig config;
   config.add_tasks()->add_probe_configs()->set_method_signature(
       "void com.android.server.am.OomAdjusterWithSomeSuffix.doWork()");
-  EXPECT_FALSE(guardrail::isAllowed(config, "user"));
+  EXPECT_FALSE(guardrail::isAllowed(config, "user", false));
+
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
+  probeConfig.set_fully_qualified_class_name(
+      "com.android.server.am.OomAdjusterWithSomeSuffix");
+  probeConfig.set_method_name("doWork");
+  ::uprobestats::protos::UprobestatsConfig newConfig;
+  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
+  EXPECT_FALSE(guardrail::isAllowed(newConfig, "user", true));
 }
 
 TEST_F(GuardrailTest, DisallowedMethodInSecondTask) {
@@ -59,7 +90,20 @@ TEST_F(GuardrailTest, DisallowedMethodInSecondTask) {
       "boolean)");
   config.add_tasks()->add_probe_configs()->set_method_signature(
       "void com.android.server.am.disallowedClass.doWork()");
-  EXPECT_FALSE(guardrail::isAllowed(config, "user"));
+  EXPECT_FALSE(guardrail::isAllowed(config, "user", false));
+
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
+  probeConfig.set_fully_qualified_class_name(
+      "com.android.server.am.OomAdjuster");
+  probeConfig.set_method_name("setUidTempAllowlistStateLSP");
+  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfigTwo;
+  probeConfigTwo.set_fully_qualified_class_name(
+      "com.android.server.am.disallowedClass");
+  probeConfigTwo.set_method_name("doWork");
+  ::uprobestats::protos::UprobestatsConfig newConfig;
+  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
+  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfigTwo);
+  EXPECT_FALSE(guardrail::isAllowed(newConfig, "user", true));
 }
 
 } // namespace uprobestats
diff --git a/src/Guardrail.cpp b/src/Guardrail.cpp
index a55411e..e19222e 100644
--- a/src/Guardrail.cpp
+++ b/src/Guardrail.cpp
@@ -34,20 +34,33 @@ constexpr std::array kAllowedMethodPrefixes = {
 
 } // namespace
 
+std::string getFullMethodName(
+    const ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig
+        &probeConfig,
+    bool executabeMethodFileOffsetsApiEnabled) {
+  if (executabeMethodFileOffsetsApiEnabled &&
+      probeConfig.has_fully_qualified_class_name()) {
+    return probeConfig.fully_qualified_class_name() + "." +
+           probeConfig.method_name();
+  }
+  const string &methodSignature = probeConfig.method_signature();
+  std::vector<string> components = android::base::Split(methodSignature, " ");
+  if (components.size() < 2) {
+    return "";
+  }
+  return components[1];
+}
+
 bool isAllowed(const ::uprobestats::protos::UprobestatsConfig &config,
-               const string &buildType) {
+               const string &buildType,
+               bool executabeMethodFileOffsetsApiEnabled) {
   if (buildType != "user") {
     return true;
   }
   for (const auto &task : config.tasks()) {
     for (const auto &probeConfig : task.probe_configs()) {
-      const string &methodSignature = probeConfig.method_signature();
-      std::vector<string> components =
-          android::base::Split(methodSignature, " ");
-      if (components.size() < 2) {
-        return false;
-      }
-      const string &fullMethodName = components[1];
+      const string &fullMethodName =
+          getFullMethodName(probeConfig, executabeMethodFileOffsetsApiEnabled);
       bool allowed = false;
       for (const std::string allowedPrefix : kAllowedMethodPrefixes) {
         if (android::base::StartsWith(fullMethodName, allowedPrefix + ".") ||
diff --git a/src/Guardrail.h b/src/Guardrail.h
index 30c5591..9bc054f 100644
--- a/src/Guardrail.h
+++ b/src/Guardrail.h
@@ -24,7 +24,8 @@ namespace uprobestats {
 namespace guardrail {
 
 bool isAllowed(const ::uprobestats::protos::UprobestatsConfig &config,
-               const std::string &buildType);
+               const std::string &buildType,
+               bool executableMethodFileOffsetsApiEnabled);
 
 } // namespace guardrail
 } // namespace uprobestats
diff --git a/src/TEST_MAPPING b/src/TEST_MAPPING
index b7f5416..6e33618 100644
--- a/src/TEST_MAPPING
+++ b/src/TEST_MAPPING
@@ -3,5 +3,13 @@
         {
             "name": "uprobestats-test"
         }
+    ],
+    "uprobestats-mainline-presubmit": [
+        {
+            "name": "uprobestats-test"
+        },
+        {
+            "name": "CtsStatsdAtomHostTestCases"
+        }
     ]
 }
diff --git a/src/UprobeStats-platform.rc b/src/UprobeStats-platform.rc
new file mode 100644
index 0000000..c5395c5
--- /dev/null
+++ b/src/UprobeStats-platform.rc
@@ -0,0 +1,6 @@
+service uprobestats /system/bin/uprobestats
+    disabled
+    user uprobestats
+    group uprobestats readproc
+    oneshot
+    capabilities PERFMON
diff --git a/src/UprobeStats.cpp b/src/UprobeStats.cpp
index ad660cc..fa88823 100644
--- a/src/UprobeStats.cpp
+++ b/src/UprobeStats.cpp
@@ -20,8 +20,9 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/properties.h>
+#include <android-base/scopeguard.h>
 #include <android-base/strings.h>
-#include <android_uprobestats_flags.h>
+#include <android/binder_process.h>
 #include <config.pb.h>
 #include <iostream>
 #include <stdio.h>
@@ -30,6 +31,8 @@
 
 #include "Bpf.h"
 #include "ConfigResolver.h"
+#include "DebugLog.h"
+#include "FlagSelector.h"
 #include "Guardrail.h"
 #include <stats_event.h>
 
@@ -39,20 +42,14 @@ const std::string kGenericBpfMapDetail =
     std::string("GenericInstrumentation_call_detail");
 const std::string kGenericBpfMapTimestamp =
     std::string("GenericInstrumentation_call_timestamp");
+const std::string kUpdateDeviceIdleTempAllowlistMap =
+    std::string("ProcessManagement_update_device_idle_temp_allowlist_records");
 const std::string kProcessManagementMap =
     std::string("ProcessManagement_output_buf");
 const int kJavaArgumentRegisterOffset = 2;
-const bool kDebug = true;
-
-#define LOG_IF_DEBUG(msg)                                                      \
-  do {                                                                         \
-    if (kDebug) {                                                              \
-      LOG(INFO) << msg;                                                        \
-    }                                                                          \
-  } while (0)
 
 bool isUprobestatsEnabled() {
-  return android::uprobestats::flags::enable_uprobestats();
+  return android::uprobestats::flag_selector::enable_uprobestats();
 }
 
 const std::string kBpfPath = std::string("/sys/fs/bpf/uprobestats/");
@@ -134,6 +131,35 @@ void doPoll(PollArgs args) {
         AStatsEvent_release(event);
         LOG_IF_DEBUG("successfully wrote atom id: " << atom_id);
       }
+    } else if (mapPath.find(kUpdateDeviceIdleTempAllowlistMap) !=
+               std::string::npos) {
+      LOG_IF_DEBUG("Polling for UpdateDeviceIdleTempAllowlistRecord result");
+      auto result = bpf::pollRingBuf<bpf::UpdateDeviceIdleTempAllowlistRecord>(
+          mapPath.c_str(), timeoutMs);
+      for (auto value : result) {
+        LOG_IF_DEBUG("UpdateDeviceIdleTempAllowlistRecord result... "
+                     << " changing_uid: " << value.changing_uid
+                     << " reason_code: " << value.reason_code << " reason: "
+                     << value.reason << " calling_uid: " << value.calling_uid
+                     << " mapPath: " << mapPath);
+        if (!args.taskConfig.has_statsd_logging_config()) {
+          LOG_IF_DEBUG("no statsd logging config");
+          continue;
+        }
+        auto statsd_logging_config = args.taskConfig.statsd_logging_config();
+        int atom_id = statsd_logging_config.atom_id();
+        AStatsEvent *event = AStatsEvent_obtain();
+        AStatsEvent_setAtomId(event, atom_id);
+        AStatsEvent_writeInt32(event, value.changing_uid);
+        AStatsEvent_writeBool(event, value.adding);
+        AStatsEvent_writeInt64(event, value.duration_ms);
+        AStatsEvent_writeInt32(event, value.type);
+        AStatsEvent_writeInt32(event, value.reason_code);
+        AStatsEvent_writeString(event, value.reason);
+        AStatsEvent_writeInt32(event, value.calling_uid);
+        AStatsEvent_write(event);
+        AStatsEvent_release(event);
+      }
     } else if (mapPath.find(kProcessManagementMap) != std::string::npos) {
       LOG_IF_DEBUG("Polling for SetUidTempAllowlistStateRecord result");
       auto result = bpf::pollRingBuf<bpf::SetUidTempAllowlistStateRecord>(
@@ -168,24 +194,30 @@ void doPoll(PollArgs args) {
   LOG_IF_DEBUG("finished polling for mapPath: " << mapPath);
 }
 
-int main(int argc, char **argv) {
+int main() {
+  if (android::uprobestats::flag_selector::executable_method_file_offsets()) {
+    ABinderProcess_startThreadPool();
+  }
+  const auto guard = ::android::base::make_scope_guard([] {
+    if (android::uprobestats::flag_selector::executable_method_file_offsets()) {
+      ABinderProcess_joinThreadPool();
+    }
+  });
   if (!isUprobestatsEnabled()) {
     LOG(ERROR) << "uprobestats disabled by flag. Exiting.";
     return 1;
   }
-  if (argc < 2) {
-    LOG(ERROR) << "Not enough command line arguments. Exiting.";
-    return 1;
-  }
-
-  auto config = config_resolver::readConfig(
-      std::string("/data/misc/uprobestats-configs/") + argv[1]);
+  auto config =
+      config_resolver::readConfig("/data/misc/uprobestats-configs/config");
   if (!config.has_value()) {
-    LOG(ERROR) << "Failed to parse uprobestats config: " << argv[1];
+    LOG(ERROR) << "Failed to parse uprobestats config.";
     return 1;
   }
-  if (!guardrail::isAllowed(config.value(), android::base::GetProperty(
-                                                "ro.build.type", "unknown"))) {
+  if (!guardrail::isAllowed(
+          config.value(),
+          android::base::GetProperty("ro.build.type", "unknown"),
+          android::uprobestats::flag_selector::
+              executable_method_file_offsets())) {
     LOG(ERROR) << "uprobestats probing config disallowed on this device.";
     return 1;
   }
@@ -204,6 +236,12 @@ int main(int argc, char **argv) {
   }
   for (auto &resolvedProbe : resolvedProbeConfigs.value()) {
     LOG_IF_DEBUG("Opening bpf perf event from probe: " << resolvedProbe);
+    if (resolvedProbe.filename ==
+            "prog_ProcessManagement_uprobe_update_device_idle_temp_allowlist" &&
+        !android::uprobestats::flag_selector::
+            uprobestats_support_update_device_idle_temp_allowlist()) {
+      LOG(ERROR) << "update_device_idle_temp_allowlist disabled by flag";
+    }
     auto openResult = bpf::bpfPerfEventOpen(
         resolvedProbe.filename.c_str(), resolvedProbe.offset,
         resolvedTask.value().pid,
@@ -217,6 +255,12 @@ int main(int argc, char **argv) {
 
   std::vector<std::thread> threads;
   for (auto mapPath : resolvedTask.value().taskConfig.bpf_maps()) {
+    if (mapPath ==
+            "map_ProcessManagement_update_device_idle_temp_allowlist_record" &&
+        !android::uprobestats::flag_selector::
+            uprobestats_support_update_device_idle_temp_allowlist()) {
+      LOG(ERROR) << "update_device_idle_temp_allowlist disabled by flag";
+    }
     auto pollArgs =
         PollArgs{prefixBpf(mapPath), resolvedTask.value().taskConfig};
     LOG_IF_DEBUG(
diff --git a/src/UprobeStats.rc b/src/UprobeStats.rc
deleted file mode 100644
index e44392d..0000000
--- a/src/UprobeStats.rc
+++ /dev/null
@@ -1,9 +0,0 @@
-service uprobestats /system/bin/uprobestats ${uprobestats.start_with_config}
-    disabled
-    user uprobestats
-    group uprobestats readproc
-    oneshot
-    capabilities PERFMON
-
-on property:uprobestats.start_with_config=*
-    start uprobestats
diff --git a/src/bpf/headers/Android.bp b/src/bpf/headers/Android.bp
new file mode 100644
index 0000000..e25dfe3
--- /dev/null
+++ b/src/bpf/headers/Android.bp
@@ -0,0 +1,61 @@
+// Copyright (C) 2021 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_performance",
+}
+
+cc_library_headers {
+    name: "uprobestats_bpf_headers",
+    vendor_available: true,
+    recovery_available: true,
+    host_supported: true,
+    native_bridge_supported: true,
+    header_libs: ["uprobestats_bpf_syscall_wrappers"],
+    export_header_lib_headers: ["uprobestats_bpf_syscall_wrappers"],
+    export_include_dirs: ["include"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    sdk_version: "35",
+    min_sdk_version: "35",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+}
+
+cc_test {
+    name: "uprobestats_libbpf_android_test",
+    srcs: [
+        "BpfMapTest.cpp",
+        "BpfRingbufTest.cpp",
+    ],
+    defaults: ["bpf_cc_defaults"],
+    cflags: [
+        "-Wno-unused-variable",
+        "-Wno-sign-compare",
+    ],
+    header_libs: ["uprobestats_bpf_headers"],
+    static_libs: ["libgmock"],
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libutils",
+    ],
+    require_root: true,
+    test_suites: ["general-tests"],
+}
diff --git a/src/bpf/headers/BpfMapTest.cpp b/src/bpf/headers/BpfMapTest.cpp
new file mode 100644
index 0000000..862114d
--- /dev/null
+++ b/src/bpf/headers/BpfMapTest.cpp
@@ -0,0 +1,254 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+#include <fstream>
+#include <iostream>
+#include <string>
+#include <vector>
+
+#include <fcntl.h>
+#include <inttypes.h>
+#include <linux/inet_diag.h>
+#include <linux/sock_diag.h>
+#include <net/if.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <unistd.h>
+
+#include <gtest/gtest.h>
+
+#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+
+#define BPF_MAP_MAKE_VISIBLE_FOR_TESTING
+#include "bpf/BpfMap.h"
+#include "bpf/BpfUtils.h"
+
+using ::testing::Test;
+
+namespace android {
+namespace bpf {
+
+using base::Result;
+using base::unique_fd;
+
+constexpr uint32_t TEST_MAP_SIZE = 10;
+constexpr uint32_t TEST_KEY1 = 1;
+constexpr uint32_t TEST_VALUE1 = 10;
+constexpr const char PINNED_MAP_PATH[] = "/sys/fs/bpf/testMap";
+
+class BpfMapTest : public testing::Test {
+  protected:
+    BpfMapTest() {}
+
+    void SetUp() {
+        EXPECT_EQ(0, setrlimitForTest());
+        if (!access(PINNED_MAP_PATH, R_OK)) {
+            EXPECT_EQ(0, remove(PINNED_MAP_PATH));
+        }
+    }
+
+    void TearDown() {
+        if (!access(PINNED_MAP_PATH, R_OK)) {
+            EXPECT_EQ(0, remove(PINNED_MAP_PATH));
+        }
+    }
+
+    void checkMapInvalid(BpfMap<uint32_t, uint32_t>& map) {
+        EXPECT_FALSE(map.isValid());
+        EXPECT_EQ(-1, map.getMap().get());
+    }
+
+    void checkMapValid(BpfMap<uint32_t, uint32_t>& map) {
+        EXPECT_LE(0, map.getMap().get());
+        EXPECT_TRUE(map.isValid());
+    }
+
+    void writeToMapAndCheck(BpfMap<uint32_t, uint32_t>& map, uint32_t key, uint32_t value) {
+        ASSERT_RESULT_OK(map.writeValue(key, value, BPF_ANY));
+        uint32_t value_read;
+        ASSERT_EQ(0, findMapEntry(map.getMap(), &key, &value_read));
+        checkValueAndStatus(value, value_read);
+    }
+
+    void checkValueAndStatus(uint32_t refValue, Result<uint32_t> value) {
+        ASSERT_RESULT_OK(value);
+        ASSERT_EQ(refValue, value.value());
+    }
+
+    void populateMap(uint32_t total, BpfMap<uint32_t, uint32_t>& map) {
+        for (uint32_t key = 0; key < total; key++) {
+            uint32_t value = key * 10;
+            EXPECT_RESULT_OK(map.writeValue(key, value, BPF_ANY));
+        }
+    }
+
+    void expectMapEmpty(BpfMap<uint32_t, uint32_t>& map) {
+        Result<bool> isEmpty = map.isEmpty();
+        ASSERT_RESULT_OK(isEmpty);
+        ASSERT_TRUE(isEmpty.value());
+    }
+};
+
+TEST_F(BpfMapTest, constructor) {
+    BpfMap<uint32_t, uint32_t> testMap1;
+    checkMapInvalid(testMap1);
+
+    BpfMap<uint32_t, uint32_t> testMap2;
+    ASSERT_RESULT_OK(testMap2.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    checkMapValid(testMap2);
+}
+
+TEST_F(BpfMapTest, basicHelpers) {
+    BpfMap<uint32_t, uint32_t> testMap;
+    ASSERT_RESULT_OK(testMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    uint32_t key = TEST_KEY1;
+    uint32_t value_write = TEST_VALUE1;
+    writeToMapAndCheck(testMap, key, value_write);
+    Result<uint32_t> value_read = testMap.readValue(key);
+    checkValueAndStatus(value_write, value_read);
+    Result<uint32_t> key_read = testMap.getFirstKey();
+    checkValueAndStatus(key, key_read);
+    ASSERT_RESULT_OK(testMap.deleteValue(key));
+    ASSERT_GT(0, findMapEntry(testMap.getMap(), &key, &value_read));
+    ASSERT_EQ(ENOENT, errno);
+}
+
+TEST_F(BpfMapTest, reset) {
+    BpfMap<uint32_t, uint32_t> testMap;
+    ASSERT_RESULT_OK(testMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    uint32_t key = TEST_KEY1;
+    uint32_t value_write = TEST_VALUE1;
+    writeToMapAndCheck(testMap, key, value_write);
+
+    testMap.reset(-1);
+    checkMapInvalid(testMap);
+    ASSERT_GT(0, findMapEntry(testMap.getMap(), &key, &value_write));
+    ASSERT_EQ(EBADF, errno);
+}
+
+TEST_F(BpfMapTest, moveConstructor) {
+    BpfMap<uint32_t, uint32_t> testMap1;
+    ASSERT_RESULT_OK(testMap1.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    BpfMap<uint32_t, uint32_t> testMap2;
+    testMap2 = std::move(testMap1);
+    uint32_t key = TEST_KEY1;
+    checkMapInvalid(testMap1);
+    uint32_t value = TEST_VALUE1;
+    writeToMapAndCheck(testMap2, key, value);
+}
+
+TEST_F(BpfMapTest, SetUpMap) {
+    EXPECT_NE(0, access(PINNED_MAP_PATH, R_OK));
+    BpfMap<uint32_t, uint32_t> testMap1;
+    ASSERT_RESULT_OK(testMap1.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    ASSERT_EQ(0, bpfFdPin(testMap1.getMap(), PINNED_MAP_PATH));
+    EXPECT_EQ(0, access(PINNED_MAP_PATH, R_OK));
+    checkMapValid(testMap1);
+    BpfMap<uint32_t, uint32_t> testMap2;
+    EXPECT_RESULT_OK(testMap2.init(PINNED_MAP_PATH));
+    checkMapValid(testMap2);
+    uint32_t key = TEST_KEY1;
+    uint32_t value = TEST_VALUE1;
+    writeToMapAndCheck(testMap1, key, value);
+    Result<uint32_t> value_read = testMap2.readValue(key);
+    checkValueAndStatus(value, value_read);
+}
+
+TEST_F(BpfMapTest, iterate) {
+    BpfMap<uint32_t, uint32_t> testMap;
+    ASSERT_RESULT_OK(testMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    populateMap(TEST_MAP_SIZE, testMap);
+    int totalCount = 0;
+    int totalSum = 0;
+    const auto iterateWithDeletion = [&totalCount, &totalSum](const uint32_t& key,
+                                                              BpfMap<uint32_t, uint32_t>& map) {
+        EXPECT_GE((uint32_t)TEST_MAP_SIZE, key);
+        totalCount++;
+        totalSum += key;
+        return map.deleteValue(key);
+    };
+    EXPECT_RESULT_OK(testMap.iterate(iterateWithDeletion));
+    EXPECT_EQ((int)TEST_MAP_SIZE, totalCount);
+    EXPECT_EQ(((1 + TEST_MAP_SIZE - 1) * (TEST_MAP_SIZE - 1)) / 2, (uint32_t)totalSum);
+    expectMapEmpty(testMap);
+}
+
+TEST_F(BpfMapTest, iterateWithValue) {
+    BpfMap<uint32_t, uint32_t> testMap;
+    ASSERT_RESULT_OK(testMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    populateMap(TEST_MAP_SIZE, testMap);
+    int totalCount = 0;
+    int totalSum = 0;
+    const auto iterateWithDeletion = [&totalCount, &totalSum](const uint32_t& key,
+                                                              const uint32_t& value,
+                                                              BpfMap<uint32_t, uint32_t>& map) {
+        EXPECT_GE((uint32_t)TEST_MAP_SIZE, key);
+        EXPECT_EQ(value, key * 10);
+        totalCount++;
+        totalSum += value;
+        return map.deleteValue(key);
+    };
+    EXPECT_RESULT_OK(testMap.iterateWithValue(iterateWithDeletion));
+    EXPECT_EQ((int)TEST_MAP_SIZE, totalCount);
+    EXPECT_EQ(((1 + TEST_MAP_SIZE - 1) * (TEST_MAP_SIZE - 1)) * 5, (uint32_t)totalSum);
+    expectMapEmpty(testMap);
+}
+
+TEST_F(BpfMapTest, mapIsEmpty) {
+    BpfMap<uint32_t, uint32_t> testMap;
+    ASSERT_RESULT_OK(testMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE, BPF_F_NO_PREALLOC));
+    expectMapEmpty(testMap);
+    uint32_t key = TEST_KEY1;
+    uint32_t value_write = TEST_VALUE1;
+    writeToMapAndCheck(testMap, key, value_write);
+    Result<bool> isEmpty = testMap.isEmpty();
+    ASSERT_RESULT_OK(isEmpty);
+    ASSERT_FALSE(isEmpty.value());
+    ASSERT_RESULT_OK(testMap.deleteValue(key));
+    ASSERT_GT(0, findMapEntry(testMap.getMap(), &key, &value_write));
+    ASSERT_EQ(ENOENT, errno);
+    expectMapEmpty(testMap);
+    int entriesSeen = 0;
+    EXPECT_RESULT_OK(testMap.iterate(
+            [&entriesSeen](const unsigned int&,
+                           const BpfMap<unsigned int, unsigned int>&) -> Result<void> {
+                entriesSeen++;
+                return {};
+            }));
+    EXPECT_EQ(0, entriesSeen);
+    EXPECT_RESULT_OK(testMap.iterateWithValue(
+            [&entriesSeen](const unsigned int&, const unsigned int&,
+                           const BpfMap<unsigned int, unsigned int>&) -> Result<void> {
+                entriesSeen++;
+                return {};
+            }));
+    EXPECT_EQ(0, entriesSeen);
+}
+
+TEST_F(BpfMapTest, mapClear) {
+    BpfMap<uint32_t, uint32_t> testMap;
+    ASSERT_RESULT_OK(testMap.resetMap(BPF_MAP_TYPE_HASH, TEST_MAP_SIZE));
+    populateMap(TEST_MAP_SIZE, testMap);
+    Result<bool> isEmpty = testMap.isEmpty();
+    ASSERT_RESULT_OK(isEmpty);
+    ASSERT_FALSE(*isEmpty);
+    ASSERT_RESULT_OK(testMap.clear());
+    expectMapEmpty(testMap);
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/BpfRingbufTest.cpp b/src/bpf/headers/BpfRingbufTest.cpp
new file mode 100644
index 0000000..e81fb92
--- /dev/null
+++ b/src/bpf/headers/BpfRingbufTest.cpp
@@ -0,0 +1,157 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+#include <android-base/file.h>
+#include <android-base/macros.h>
+#include <android-base/result-gmock.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+#include <stdlib.h>
+#include <unistd.h>
+
+#include "BpfSyscallWrappers.h"
+#include "bpf/BpfRingbuf.h"
+#include "bpf/BpfUtils.h"
+#include "bpf/KernelUtils.h"
+
+#define TEST_RINGBUF_MAGIC_NUM 12345
+
+namespace android {
+namespace bpf {
+using ::android::base::testing::HasError;
+using ::android::base::testing::HasValue;
+using ::android::base::testing::WithCode;
+using ::testing::AllOf;
+using ::testing::Gt;
+using ::testing::HasSubstr;
+using ::testing::Lt;
+
+class BpfRingbufTest : public ::testing::Test {
+ protected:
+  BpfRingbufTest()
+      : mProgPath("/sys/fs/bpf/prog_bpfRingbufProg_skfilter_ringbuf_test"),
+        mRingbufPath("/sys/fs/bpf/map_bpfRingbufProg_test_ringbuf") {}
+
+  void SetUp() {
+    if (!android::bpf::isAtLeastKernelVersion(5, 8, 0)) {
+      GTEST_SKIP() << "BPF ring buffers not supported below 5.8";
+    }
+
+    errno = 0;
+    mProgram.reset(retrieveProgram(mProgPath.c_str()));
+    EXPECT_EQ(errno, 0);
+    ASSERT_GE(mProgram.get(), 0)
+        << mProgPath << " was either not found or inaccessible.";
+  }
+
+  void RunProgram() {
+    char fake_skb[128] = {};
+    EXPECT_EQ(runProgram(mProgram, fake_skb, sizeof(fake_skb)), 0);
+  }
+
+  void RunTestN(int n) {
+    int run_count = 0;
+    uint64_t output = 0;
+    auto callback = [&](const uint64_t& value) {
+      output = value;
+      run_count++;
+    };
+
+    auto result = BpfRingbuf<uint64_t>::Create(mRingbufPath.c_str());
+    ASSERT_RESULT_OK(result);
+    EXPECT_TRUE(result.value()->isEmpty());
+
+    struct timespec t1, t2;
+    EXPECT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t1));
+    EXPECT_FALSE(result.value()->wait(1000 /*ms*/));  // false because wait should timeout
+    EXPECT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t2));
+    long long time1 = t1.tv_sec * 1000000000LL + t1.tv_nsec;
+    long long time2 = t2.tv_sec * 1000000000LL + t2.tv_nsec;
+    EXPECT_GE(time2 - time1, 1000000000 /*ns*/);  // 1000 ms as ns
+
+    for (int i = 0; i < n; i++) {
+      RunProgram();
+    }
+
+    EXPECT_FALSE(result.value()->isEmpty());
+
+    EXPECT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t1));
+    EXPECT_TRUE(result.value()->wait());
+    EXPECT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t2));
+    time1 = t1.tv_sec * 1000000000LL + t1.tv_nsec;
+    time2 = t2.tv_sec * 1000000000LL + t2.tv_nsec;
+    EXPECT_LE(time2 - time1, 1000000 /*ns*/);  // in x86 CF testing < 5000 ns
+
+    EXPECT_THAT(result.value()->ConsumeAll(callback), HasValue(n));
+    EXPECT_TRUE(result.value()->isEmpty());
+    EXPECT_EQ(output, TEST_RINGBUF_MAGIC_NUM);
+    EXPECT_EQ(run_count, n);
+  }
+
+  std::string mProgPath;
+  std::string mRingbufPath;
+  android::base::unique_fd mProgram;
+};
+
+TEST_F(BpfRingbufTest, ConsumeSingle) { RunTestN(1); }
+TEST_F(BpfRingbufTest, ConsumeMultiple) { RunTestN(3); }
+
+TEST_F(BpfRingbufTest, FillAndWrap) {
+  int run_count = 0;
+  auto callback = [&](const uint64_t&) { run_count++; };
+
+  auto result = BpfRingbuf<uint64_t>::Create(mRingbufPath.c_str());
+  ASSERT_RESULT_OK(result);
+
+  // 4kb buffer with 16 byte payloads (8 byte data, 8 byte header) should fill
+  // after 255 iterations. Exceed that so that some events are dropped.
+  constexpr int iterations = 300;
+  for (int i = 0; i < iterations; i++) {
+    RunProgram();
+  }
+
+  // Some events were dropped, but consume all that succeeded.
+  EXPECT_THAT(result.value()->ConsumeAll(callback),
+              HasValue(AllOf(Gt(250), Lt(260))));
+  EXPECT_THAT(run_count, AllOf(Gt(250), Lt(260)));
+
+  // After consuming everything, we should be able to use the ring buffer again.
+  run_count = 0;
+  RunProgram();
+  EXPECT_THAT(result.value()->ConsumeAll(callback), HasValue(1));
+  EXPECT_EQ(run_count, 1);
+}
+
+TEST_F(BpfRingbufTest, WrongTypeSize) {
+  // The program under test writes 8-byte uint64_t values so a ringbuffer for
+  // 1-byte uint8_t values will fail to read from it. Note that the map_def does
+  // not specify the value size, so we fail on read, not creation.
+  auto result = BpfRingbuf<uint8_t>::Create(mRingbufPath.c_str());
+  ASSERT_RESULT_OK(result);
+
+  RunProgram();
+
+  EXPECT_THAT(result.value()->ConsumeAll([](const uint8_t&) {}),
+              HasError(WithCode(EMSGSIZE)));
+}
+
+TEST_F(BpfRingbufTest, InvalidPath) {
+  EXPECT_THAT(BpfRingbuf<int>::Create("/sys/fs/bpf/bad_path"),
+              HasError(WithCode(ENOENT)));
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/include/bpf/BpfClassic.h b/src/bpf/headers/include/bpf/BpfClassic.h
new file mode 100644
index 0000000..81be37d
--- /dev/null
+++ b/src/bpf/headers/include/bpf/BpfClassic.h
@@ -0,0 +1,184 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#pragma once
+
+// Accept the full packet
+#define BPF_ACCEPT BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF)
+
+// Reject the packet
+#define BPF_REJECT BPF_STMT(BPF_RET | BPF_K, 0)
+
+// Note arguments to BPF_JUMP(opcode, operand, true_offset, false_offset)
+
+// If not equal, jump over count instructions
+#define BPF_JUMP_IF_NOT_EQUAL(v, count) \
+	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (v), 0, (count))
+
+// *TWO* instructions: compare and if not equal jump over the accept statement
+#define BPF2_ACCEPT_IF_EQUAL(v) \
+	BPF_JUMP_IF_NOT_EQUAL((v), 1), \
+	BPF_ACCEPT
+
+// *TWO* instructions: compare and if equal jump over the reject statement
+#define BPF2_REJECT_IF_NOT_EQUAL(v) \
+	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (v), 1, 0), \
+	BPF_REJECT
+
+// *TWO* instructions: compare and if greater or equal jump over the reject statement
+#define BPF2_REJECT_IF_LESS_THAN(v) \
+	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (v), 1, 0), \
+	BPF_REJECT
+
+// *TWO* instructions: compare and if *NOT* greater jump over the reject statement
+#define BPF2_REJECT_IF_GREATER_THAN(v) \
+	BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (v), 0, 1), \
+	BPF_REJECT
+
+// *THREE* instructions: compare and if *NOT* in range [lo, hi], jump over the reject statement
+#define BPF3_REJECT_IF_NOT_IN_RANGE(lo, hi) \
+	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (lo), 0, 1), \
+	BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (hi), 0, 1), \
+	BPF_REJECT
+
+// *TWO* instructions: compare and if none of the bits are set jump over the reject statement
+#define BPF2_REJECT_IF_ANY_MASKED_BITS_SET(v) \
+	BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, (v), 0, 1), \
+	BPF_REJECT
+
+// loads skb->protocol
+#define BPF_LOAD_SKB_PROTOCOL \
+	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, (__u32)SKF_AD_OFF + SKF_AD_PROTOCOL)
+
+// 8-bit load relative to start of link layer (mac/ethernet) header.
+#define BPF_LOAD_MAC_RELATIVE_U8(ofs) \
+	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, (__u32)SKF_LL_OFF + (ofs))
+
+// Big/Network Endian 16-bit load relative to start of link layer (mac/ethernet) header.
+#define BPF_LOAD_MAC_RELATIVE_BE16(ofs) \
+	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, (__u32)SKF_LL_OFF + (ofs))
+
+// Big/Network Endian 32-bit load relative to start of link layer (mac/ethernet) header.
+#define BPF_LOAD_MAC_RELATIVE_BE32(ofs) \
+	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (__u32)SKF_LL_OFF + (ofs))
+
+// 8-bit load relative to start of network (IPv4/IPv6) header.
+#define BPF_LOAD_NET_RELATIVE_U8(ofs) \
+	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, (__u32)SKF_NET_OFF + (ofs))
+
+// Big/Network Endian 16-bit load relative to start of network (IPv4/IPv6) header.
+#define BPF_LOAD_NET_RELATIVE_BE16(ofs) \
+	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, (__u32)SKF_NET_OFF + (ofs))
+
+// Big/Network Endian 32-bit load relative to start of network (IPv4/IPv6) header.
+#define BPF_LOAD_NET_RELATIVE_BE32(ofs) \
+	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (__u32)SKF_NET_OFF + (ofs))
+
+#define field_sizeof(struct_type,field) sizeof(((struct_type *)0)->field)
+
+// 8-bit load from IPv4 header field.
+#define BPF_LOAD_IPV4_U8(field) \
+	BPF_LOAD_NET_RELATIVE_U8(({ \
+	  _Static_assert(field_sizeof(struct iphdr, field) == 1, "field of wrong size"); \
+	  offsetof(iphdr, field); \
+	}))
+
+// Big/Network Endian 16-bit load from IPv4 header field.
+#define BPF_LOAD_IPV4_BE16(field) \
+	BPF_LOAD_NET_RELATIVE_BE16(({ \
+	  _Static_assert(field_sizeof(struct iphdr, field) == 2, "field of wrong size"); \
+	  offsetof(iphdr, field); \
+	}))
+
+// Big/Network Endian 32-bit load from IPv4 header field.
+#define BPF_LOAD_IPV4_BE32(field) \
+	BPF_LOAD_NET_RELATIVE_BE32(({ \
+	  _Static_assert(field_sizeof(struct iphdr, field) == 4, "field of wrong size"); \
+	  offsetof(iphdr, field); \
+	}))
+
+// 8-bit load from IPv6 header field.
+#define BPF_LOAD_IPV6_U8(field) \
+	BPF_LOAD_NET_RELATIVE_U8(({ \
+	  _Static_assert(field_sizeof(struct ipv6hdr, field) == 1, "field of wrong size"); \
+	  offsetof(ipv6hdr, field); \
+	}))
+
+// Big/Network Endian 16-bit load from IPv6 header field.
+#define BPF_LOAD_IPV6_BE16(field) \
+	BPF_LOAD_NET_RELATIVE_BE16(({ \
+	  _Static_assert(field_sizeof(struct ipv6hdr, field) == 2, "field of wrong size"); \
+	  offsetof(ipv6hdr, field); \
+	}))
+
+// Big/Network Endian 32-bit load from IPv6 header field.
+#define BPF_LOAD_IPV6_BE32(field) \
+	BPF_LOAD_NET_RELATIVE_BE32(({ \
+	  _Static_assert(field_sizeof(struct ipv6hdr, field) == 4, "field of wrong size"); \
+	  offsetof(ipv6hdr, field); \
+	}))
+
+// Load the length of the IPv4 header into X index register.
+// ie. X := 4 * IPv4.IHL, where IPv4.IHL is the bottom nibble
+// of the first byte of the IPv4 (aka network layer) header.
+#define BPF_LOADX_NET_RELATIVE_IPV4_HLEN \
+    BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, (__u32)SKF_NET_OFF)
+
+// Blindly assumes no IPv6 extension headers, just does X := 40
+// You may later adjust this as you parse through IPv6 ext hdrs.
+#define BPF_LOADX_CONSTANT_IPV6_HLEN \
+    BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, sizeof(struct ipv6hdr))
+
+// NOTE: all the following require X to be setup correctly (v4: 20+, v6: 40+)
+
+// 8-bit load from L4 (TCP/UDP/...) header
+#define BPF_LOAD_NETX_RELATIVE_L4_U8(ofs) \
+    BPF_STMT(BPF_LD | BPF_B | BPF_IND, (__u32)SKF_NET_OFF + (ofs))
+
+// Big/Network Endian 16-bit load from L4 (TCP/UDP/...) header
+#define BPF_LOAD_NETX_RELATIVE_L4_BE16(ofs) \
+    BPF_STMT(BPF_LD | BPF_H | BPF_IND, (__u32)SKF_NET_OFF + (ofs))
+
+// Big/Network Endian 32-bit load from L4 (TCP/UDP/...) header
+#define BPF_LOAD_NETX_RELATIVE_L4_BE32(ofs) \
+    BPF_STMT(BPF_LD | BPF_W | BPF_IND, (__u32)SKF_NET_OFF + (ofs))
+
+// Both ICMPv4 and ICMPv6 start with u8 type, u8 code
+#define BPF_LOAD_NETX_RELATIVE_ICMP_TYPE BPF_LOAD_NETX_RELATIVE_L4_U8(0)
+#define BPF_LOAD_NETX_RELATIVE_ICMP_CODE BPF_LOAD_NETX_RELATIVE_L4_U8(1)
+
+// IPv6 extension headers (HOPOPTS, DSTOPS, FRAG) begin with a u8 nexthdr
+#define BPF_LOAD_NETX_RELATIVE_V6EXTHDR_NEXTHDR BPF_LOAD_NETX_RELATIVE_L4_U8(0)
+
+// IPv6 fragment header is always exactly 8 bytes long
+#define BPF_LOAD_CONSTANT_V6FRAGHDR_LEN \
+    BPF_STMT(BPF_LD | BPF_IMM, 8)
+
+// HOPOPTS/DSTOPS follow up with 'u8 len', counting 8 byte units, (0->8, 1->16)
+// *THREE* instructions
+#define BPF3_LOAD_NETX_RELATIVE_V6EXTHDR_LEN \
+    BPF_LOAD_NETX_RELATIVE_L4_U8(1), \
+    BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 1), \
+    BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 3)
+
+// *TWO* instructions: A += X; X := A
+#define BPF2_ADD_A_TO_X \
+    BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0), \
+    BPF_STMT(BPF_MISC | BPF_TAX, 0)
+
+// UDP/UDPLITE/TCP/SCTP/DCCP all start with be16 srcport, dstport
+#define BPF_LOAD_NETX_RELATIVE_SRC_PORT BPF_LOAD_NETX_RELATIVE_L4_BE16(0)
+#define BPF_LOAD_NETX_RELATIVE_DST_PORT BPF_LOAD_NETX_RELATIVE_L4_BE16(2)
diff --git a/src/bpf/headers/include/bpf/BpfMap.h b/src/bpf/headers/include/bpf/BpfMap.h
new file mode 100644
index 0000000..1037beb
--- /dev/null
+++ b/src/bpf/headers/include/bpf/BpfMap.h
@@ -0,0 +1,381 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+#pragma once
+
+#include <linux/bpf.h>
+
+#include <android/log.h>
+#include <android-base/result.h>
+#include <android-base/stringprintf.h>
+#include <android-base/unique_fd.h>
+
+#include "BpfSyscallWrappers.h"
+#include "bpf/BpfUtils.h"
+
+#include <functional>
+
+namespace android {
+namespace bpf {
+
+using base::Result;
+using base::unique_fd;
+using std::function;
+
+// This is a class wrapper for eBPF maps. The eBPF map is a special in-kernel
+// data structure that stores data in <Key, Value> pairs. It can be read/write
+// from userspace by passing syscalls with the map file descriptor. This class
+// is used to generalize the procedure of interacting with eBPF maps and hide
+// the implementation detail from other process. Besides the basic syscalls
+// wrapper, it also provides some useful helper functions as well as an iterator
+// nested class to iterate the map more easily.
+//
+// NOTE: A kernel eBPF map may be accessed by both kernel and userspace
+// processes at the same time. Or if the map is pinned as a virtual file, it can
+// be obtained by multiple eBPF map class object and accessed concurrently.
+// Though the map class object and the underlying kernel map are thread safe, it
+// is not safe to iterate over a map while another thread or process is deleting
+// from it. In this case the iteration can return duplicate entries.
+template <class Key, class Value>
+class BpfMapRO {
+  public:
+    BpfMapRO<Key, Value>() {};
+
+    // explicitly force no copy constructor, since it would need to dup the fd
+    // (later on, for testing, we still make available a copy assignment operator)
+    BpfMapRO<Key, Value>(const BpfMapRO<Key, Value>&) = delete;
+
+  protected:
+    void abortOnMismatch(bool writable) const {
+        if (!mMapFd.ok()) abort();
+        if (isAtLeastKernelVersion(4, 14, 0)) {
+            int flags = bpfGetFdMapFlags(mMapFd);
+            if (flags < 0) abort();
+            if (flags & BPF_F_WRONLY) abort();
+            if (writable && (flags & BPF_F_RDONLY)) abort();
+            if (bpfGetFdKeySize(mMapFd) != sizeof(Key)) abort();
+            if (bpfGetFdValueSize(mMapFd) != sizeof(Value)) abort();
+        }
+    }
+
+  public:
+    explicit BpfMapRO<Key, Value>(const char* pathname) {
+        mMapFd.reset(mapRetrieveRO(pathname));
+        abortOnMismatch(/* writable */ false);
+    }
+
+    Result<Key> getFirstKey() const {
+        Key firstKey;
+        if (getFirstMapKey(mMapFd, &firstKey)) {
+            return ErrnoErrorf("BpfMap::getFirstKey() failed");
+        }
+        return firstKey;
+    }
+
+    Result<Key> getNextKey(const Key& key) const {
+        Key nextKey;
+        if (getNextMapKey(mMapFd, &key, &nextKey)) {
+            return ErrnoErrorf("BpfMap::getNextKey() failed");
+        }
+        return nextKey;
+    }
+
+    Result<Value> readValue(const Key key) const {
+        Value value;
+        if (findMapEntry(mMapFd, &key, &value)) {
+            return ErrnoErrorf("BpfMap::readValue() failed");
+        }
+        return value;
+    }
+
+  protected:
+    [[clang::reinitializes]] Result<void> init(const char* path, int fd, bool writable) {
+        mMapFd.reset(fd);
+        if (!mMapFd.ok()) {
+            return ErrnoErrorf("Pinned map not accessible or does not exist: ({})", path);
+        }
+        // Normally we should return an error here instead of calling abort,
+        // but this cannot happen at runtime without a massive code bug (K/V type mismatch)
+        // and as such it's better to just blow the system up and let the developer fix it.
+        // Crashes are much more likely to be noticed than logs and missing functionality.
+        abortOnMismatch(writable);
+        return {};
+    }
+
+  public:
+    // Function that tries to get map from a pinned path.
+    [[clang::reinitializes]] Result<void> init(const char* path) {
+        return init(path, mapRetrieveRO(path), /* writable */ false);
+    }
+
+    // Iterate through the map and handle each key retrieved based on the filter
+    // without modification of map content.
+    Result<void> iterate(
+            const function<Result<void>(const Key& key,
+                                        const BpfMapRO<Key, Value>& map)>& filter) const;
+
+    // Iterate through the map and get each <key, value> pair, handle each <key,
+    // value> pair based on the filter without modification of map content.
+    Result<void> iterateWithValue(
+            const function<Result<void>(const Key& key, const Value& value,
+                                        const BpfMapRO<Key, Value>& map)>& filter) const;
+
+#ifdef BPF_MAP_MAKE_VISIBLE_FOR_TESTING
+    const unique_fd& getMap() const { return mMapFd; };
+
+    // Copy assignment operator - due to need for fd duping, should not be used in non-test code.
+    BpfMapRO<Key, Value>& operator=(const BpfMapRO<Key, Value>& other) {
+        if (this != &other) mMapFd.reset(fcntl(other.mMapFd.get(), F_DUPFD_CLOEXEC, 0));
+        return *this;
+    }
+#else
+    BpfMapRO<Key, Value>& operator=(const BpfMapRO<Key, Value>&) = delete;
+#endif
+
+    // Move assignment operator
+    BpfMapRO<Key, Value>& operator=(BpfMapRO<Key, Value>&& other) noexcept {
+        if (this != &other) {
+            mMapFd = std::move(other.mMapFd);
+            other.reset();
+        }
+        return *this;
+    }
+
+#ifdef BPF_MAP_MAKE_VISIBLE_FOR_TESTING
+    // Note that unique_fd.reset() carefully saves and restores the errno,
+    // and BpfMap.reset() won't touch the errno if passed in fd is negative either,
+    // hence you can do something like BpfMap.reset(systemcall()) and then
+    // check BpfMap.isValid() and look at errno and see why systemcall() failed.
+    [[clang::reinitializes]] void reset(int fd) {
+        mMapFd.reset(fd);
+        if (mMapFd.ok()) abortOnMismatch(/* writable */ false);  // false isn't ideal
+    }
+
+    // unique_fd has an implicit int conversion defined, which combined with the above
+    // reset(int) would result in double ownership of the fd, hence we either need a custom
+    // implementation of reset(unique_fd), or to delete it and thus cause compile failures
+    // to catch this and prevent it.
+    void reset(unique_fd fd) = delete;
+#endif
+
+    [[clang::reinitializes]] void reset() {
+        mMapFd.reset();
+    }
+
+    bool isValid() const { return mMapFd.ok(); }
+
+    Result<bool> isEmpty() const {
+        auto key = getFirstKey();
+        if (key.ok()) return false;
+        if (key.error().code() == ENOENT) return true;
+        return key.error();
+    }
+
+  protected:
+    unique_fd mMapFd;
+};
+
+template <class Key, class Value>
+Result<void> BpfMapRO<Key, Value>::iterate(
+        const function<Result<void>(const Key& key,
+                                    const BpfMapRO<Key, Value>& map)>& filter) const {
+    Result<Key> curKey = getFirstKey();
+    while (curKey.ok()) {
+        const Result<Key>& nextKey = getNextKey(curKey.value());
+        Result<void> status = filter(curKey.value(), *this);
+        if (!status.ok()) return status;
+        curKey = nextKey;
+    }
+    if (curKey.error().code() == ENOENT) return {};
+    return curKey.error();
+}
+
+template <class Key, class Value>
+Result<void> BpfMapRO<Key, Value>::iterateWithValue(
+        const function<Result<void>(const Key& key, const Value& value,
+                                    const BpfMapRO<Key, Value>& map)>& filter) const {
+    Result<Key> curKey = getFirstKey();
+    while (curKey.ok()) {
+        const Result<Key>& nextKey = getNextKey(curKey.value());
+        Result<Value> curValue = readValue(curKey.value());
+        if (!curValue.ok()) return curValue.error();
+        Result<void> status = filter(curKey.value(), curValue.value(), *this);
+        if (!status.ok()) return status;
+        curKey = nextKey;
+    }
+    if (curKey.error().code() == ENOENT) return {};
+    return curKey.error();
+}
+
+template <class Key, class Value>
+class BpfMap : public BpfMapRO<Key, Value> {
+  protected:
+    using BpfMapRO<Key, Value>::mMapFd;
+    using BpfMapRO<Key, Value>::abortOnMismatch;
+
+  public:
+    using BpfMapRO<Key, Value>::getFirstKey;
+    using BpfMapRO<Key, Value>::getNextKey;
+    using BpfMapRO<Key, Value>::readValue;
+
+    BpfMap<Key, Value>() {};
+
+    explicit BpfMap<Key, Value>(const char* pathname) {
+        mMapFd.reset(mapRetrieveRW(pathname));
+        abortOnMismatch(/* writable */ true);
+    }
+
+    // Function that tries to get map from a pinned path.
+    [[clang::reinitializes]] Result<void> init(const char* path) {
+        return BpfMapRO<Key,Value>::init(path, mapRetrieveRW(path), /* writable */ true);
+    }
+
+    Result<void> writeValue(const Key& key, const Value& value, uint64_t flags) {
+        if (writeToMapEntry(mMapFd, &key, &value, flags)) {
+            return ErrnoErrorf("BpfMap::writeValue() failed");
+        }
+        return {};
+    }
+
+    Result<void> deleteValue(const Key& key) {
+        if (deleteMapEntry(mMapFd, &key)) {
+            return ErrnoErrorf("BpfMap::deleteValue() failed");
+        }
+        return {};
+    }
+
+    Result<void> clear() {
+        while (true) {
+            auto key = getFirstKey();
+            if (!key.ok()) {
+                if (key.error().code() == ENOENT) return {};  // empty: success
+                return key.error();                           // Anything else is an error
+            }
+            auto res = deleteValue(key.value());
+            if (!res.ok()) {
+                // Someone else could have deleted the key, so ignore ENOENT
+                if (res.error().code() == ENOENT) continue;
+                ALOGE("Failed to delete data %s", strerror(res.error().code()));
+                return res.error();
+            }
+        }
+    }
+
+#ifdef BPF_MAP_MAKE_VISIBLE_FOR_TESTING
+    [[clang::reinitializes]] Result<void> resetMap(bpf_map_type map_type,
+                                                   uint32_t max_entries,
+                                                   uint32_t map_flags = 0) {
+        if (map_flags & BPF_F_WRONLY) abort();
+        if (map_flags & BPF_F_RDONLY) abort();
+        mMapFd.reset(createMap(map_type, sizeof(Key), sizeof(Value), max_entries,
+                               map_flags));
+        if (!mMapFd.ok()) return ErrnoErrorf("BpfMap::resetMap() failed");
+        abortOnMismatch(/* writable */ true);
+        return {};
+    }
+#endif
+
+    // Iterate through the map and handle each key retrieved based on the filter
+    // without modification of map content.
+    Result<void> iterate(
+            const function<Result<void>(const Key& key,
+                                        const BpfMap<Key, Value>& map)>& filter) const;
+
+    // Iterate through the map and get each <key, value> pair, handle each <key,
+    // value> pair based on the filter without modification of map content.
+    Result<void> iterateWithValue(
+            const function<Result<void>(const Key& key, const Value& value,
+                                        const BpfMap<Key, Value>& map)>& filter) const;
+
+    // Iterate through the map and handle each key retrieved based on the filter
+    Result<void> iterate(
+            const function<Result<void>(const Key& key,
+                                        BpfMap<Key, Value>& map)>& filter);
+
+    // Iterate through the map and get each <key, value> pair, handle each <key,
+    // value> pair based on the filter.
+    Result<void> iterateWithValue(
+            const function<Result<void>(const Key& key, const Value& value,
+                                        BpfMap<Key, Value>& map)>& filter);
+
+};
+
+template <class Key, class Value>
+Result<void> BpfMap<Key, Value>::iterate(
+        const function<Result<void>(const Key& key,
+                                    const BpfMap<Key, Value>& map)>& filter) const {
+    Result<Key> curKey = getFirstKey();
+    while (curKey.ok()) {
+        const Result<Key>& nextKey = getNextKey(curKey.value());
+        Result<void> status = filter(curKey.value(), *this);
+        if (!status.ok()) return status;
+        curKey = nextKey;
+    }
+    if (curKey.error().code() == ENOENT) return {};
+    return curKey.error();
+}
+
+template <class Key, class Value>
+Result<void> BpfMap<Key, Value>::iterateWithValue(
+        const function<Result<void>(const Key& key, const Value& value,
+                                    const BpfMap<Key, Value>& map)>& filter) const {
+    Result<Key> curKey = getFirstKey();
+    while (curKey.ok()) {
+        const Result<Key>& nextKey = getNextKey(curKey.value());
+        Result<Value> curValue = readValue(curKey.value());
+        if (!curValue.ok()) return curValue.error();
+        Result<void> status = filter(curKey.value(), curValue.value(), *this);
+        if (!status.ok()) return status;
+        curKey = nextKey;
+    }
+    if (curKey.error().code() == ENOENT) return {};
+    return curKey.error();
+}
+
+template <class Key, class Value>
+Result<void> BpfMap<Key, Value>::iterate(
+        const function<Result<void>(const Key& key,
+                                    BpfMap<Key, Value>& map)>& filter) {
+    Result<Key> curKey = getFirstKey();
+    while (curKey.ok()) {
+        const Result<Key>& nextKey = getNextKey(curKey.value());
+        Result<void> status = filter(curKey.value(), *this);
+        if (!status.ok()) return status;
+        curKey = nextKey;
+    }
+    if (curKey.error().code() == ENOENT) return {};
+    return curKey.error();
+}
+
+template <class Key, class Value>
+Result<void> BpfMap<Key, Value>::iterateWithValue(
+        const function<Result<void>(const Key& key, const Value& value,
+                                    BpfMap<Key, Value>& map)>& filter) {
+    Result<Key> curKey = getFirstKey();
+    while (curKey.ok()) {
+        const Result<Key>& nextKey = getNextKey(curKey.value());
+        Result<Value> curValue = readValue(curKey.value());
+        if (!curValue.ok()) return curValue.error();
+        Result<void> status = filter(curKey.value(), curValue.value(), *this);
+        if (!status.ok()) return status;
+        curKey = nextKey;
+    }
+    if (curKey.error().code() == ENOENT) return {};
+    return curKey.error();
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/include/bpf/BpfRingbuf.h b/src/bpf/headers/include/bpf/BpfRingbuf.h
new file mode 100644
index 0000000..4bcd259
--- /dev/null
+++ b/src/bpf/headers/include/bpf/BpfRingbuf.h
@@ -0,0 +1,292 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/result.h>
+#include <android-base/unique_fd.h>
+#include <linux/bpf.h>
+#include <poll.h>
+#include <sys/epoll.h>
+#include <sys/mman.h>
+#include <utils/Log.h>
+
+#include "bpf/BpfUtils.h"
+
+#include <atomic>
+
+namespace android {
+namespace bpf {
+
+// BpfRingbufBase contains the non-templated functionality of BPF ring buffers.
+class BpfRingbufBase {
+ public:
+  virtual ~BpfRingbufBase() {
+    if (mConsumerPos) munmap(mConsumerPos, mConsumerSize);
+    if (mProducerPos) munmap(mProducerPos, mProducerSize);
+    mConsumerPos = nullptr;
+    mProducerPos = nullptr;
+  }
+
+  bool isEmpty(void);
+
+  // returns !isEmpty() for convenience
+  bool wait(int timeout_ms = -1);
+
+ protected:
+  // Non-initializing constructor, used by Create.
+  BpfRingbufBase(size_t value_size) : mValueSize(value_size) {}
+
+  // Full construction that aborts on error (use Create/Init to handle errors).
+  BpfRingbufBase(const char* path, size_t value_size) : mValueSize(value_size) {
+    if (auto status = Init(path); !status.ok()) {
+      ALOGE("BpfRingbuf init failed: %s", status.error().message().c_str());
+      abort();
+    }
+  }
+
+  // Delete copy constructor (class owns raw pointers).
+  BpfRingbufBase(const BpfRingbufBase&) = delete;
+
+  // Initialize the base ringbuffer components. Must be called exactly once.
+  base::Result<void> Init(const char* path);
+
+  // Consumes all messages from the ring buffer, passing them to the callback.
+  base::Result<int> ConsumeAll(
+      const std::function<void(const void*)>& callback);
+
+  // Replicates c-style void* "byte-wise" pointer addition.
+  template <typename Ptr>
+  static Ptr pointerAddBytes(void* base, ssize_t offset_bytes) {
+    return reinterpret_cast<Ptr>(reinterpret_cast<char*>(base) + offset_bytes);
+  }
+
+  // Rounds len by clearing bitmask, adding header, and aligning to 8 bytes.
+  static uint32_t roundLength(uint32_t len) {
+    len &= ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);
+    len += BPF_RINGBUF_HDR_SZ;
+    return (len + 7) & ~7;
+  }
+
+  const size_t mValueSize;
+
+  size_t mConsumerSize;
+  size_t mProducerSize;
+  unsigned long mPosMask;
+  android::base::unique_fd mRingFd;
+
+  void* mDataPos = nullptr;
+  // The kernel uses an "unsigned long" type for both consumer and producer position.
+  // Unsigned long is a 4 byte value on a 32-bit kernel, and an 8 byte value on a 64-bit kernel.
+  // To support 32-bit kernels, producer pos is capped at 4 bytes (despite it being 8 bytes on
+  // 64-bit kernels) and all comparisons of consumer and producer pos only compare the low-order 4
+  // bytes (an inequality comparison is performed to support overflow).
+  // This solution is bitness agnostic. The consumer only increments the 8 byte consumer pos, which,
+  // in a little-endian architecture, is safe since the entire page is mapped into memory and a
+  // 32-bit kernel will just ignore the high-order bits.
+  std::atomic_uint64_t* mConsumerPos = nullptr;
+  std::atomic_uint32_t* mProducerPos = nullptr;
+
+  // In order to guarantee atomic access in a 32 bit userspace environment, atomic_uint64_t is used
+  // in addition to std::atomic<T>::is_always_lock_free that guarantees that read / write operations
+  // are indeed atomic.
+  // Since std::atomic does not support wrapping preallocated memory, an additional static assert on
+  // the size of the atomic and the underlying type is added to ensure a reinterpret_cast from type
+  // to its atomic version is safe (is_always_lock_free being true should provide additional
+  // confidence).
+  static_assert(std::atomic_uint64_t::is_always_lock_free);
+  static_assert(std::atomic_uint32_t::is_always_lock_free);
+  static_assert(sizeof(std::atomic_uint64_t) == sizeof(uint64_t));
+  static_assert(sizeof(std::atomic_uint32_t) == sizeof(uint32_t));
+};
+
+// This is a class wrapper for eBPF ring buffers. An eBPF ring buffer is a
+// special type of eBPF map used for sending messages from eBPF to userspace.
+// The implementation relies on fast shared memory and atomics for the producer
+// and consumer management. Ring buffers are a faster alternative to eBPF perf
+// buffers.
+//
+// This class is thread compatible, but not thread safe.
+//
+// Note: A kernel eBPF ring buffer may be accessed by both kernel and userspace
+// processes at the same time. However, the userspace consumers of a given ring
+// buffer all share a single read pointer. There is no guarantee which readers
+// will read which messages.
+template <typename Value>
+class BpfRingbuf : public BpfRingbufBase {
+ public:
+  using MessageCallback = std::function<void(const Value&)>;
+
+  // Creates a ringbuffer wrapper from a pinned path. This initialization will
+  // abort on error. To handle errors, initialize with Create instead.
+  BpfRingbuf(const char* path) : BpfRingbufBase(path, sizeof(Value)) {}
+
+  // Creates a ringbuffer wrapper from a pinned path. There are no guarantees
+  // that the ringbuf outputs messaged of type `Value`, only that they are the
+  // same size. Size is only checked in ConsumeAll.
+  static base::Result<std::unique_ptr<BpfRingbuf<Value>>> Create(
+      const char* path);
+
+  int epoll_ctl_add(int epfd, struct epoll_event *event) {
+    return epoll_ctl(epfd, EPOLL_CTL_ADD, mRingFd.get(), event);
+  }
+
+  int epoll_ctl_mod(int epfd, struct epoll_event *event) {
+    return epoll_ctl(epfd, EPOLL_CTL_MOD, mRingFd.get(), event);
+  }
+
+  int epoll_ctl_del(int epfd) {
+    return epoll_ctl(epfd, EPOLL_CTL_DEL, mRingFd.get(), NULL);
+  }
+
+  // Consumes all messages from the ring buffer, passing them to the callback.
+  // Returns the number of messages consumed or a non-ok result on error. If the
+  // ring buffer has no pending messages an OK result with count 0 is returned.
+  base::Result<int> ConsumeAll(const MessageCallback& callback);
+
+ protected:
+  // Empty ctor for use by Create.
+  BpfRingbuf() : BpfRingbufBase(sizeof(Value)) {}
+};
+
+
+inline base::Result<void> BpfRingbufBase::Init(const char* path) {
+  mRingFd.reset(mapRetrieveExclusiveRW(path));
+  if (!mRingFd.ok()) {
+    return android::base::ErrnoError()
+           << "failed to retrieve ringbuffer at " << path;
+  }
+
+  int map_type = android::bpf::bpfGetFdMapType(mRingFd);
+  if (map_type != BPF_MAP_TYPE_RINGBUF) {
+    errno = EINVAL;
+    return android::base::ErrnoError()
+           << "bpf map has wrong type: want BPF_MAP_TYPE_RINGBUF ("
+           << BPF_MAP_TYPE_RINGBUF << ") got " << map_type;
+  }
+
+  int max_entries = android::bpf::bpfGetFdMaxEntries(mRingFd);
+  if (max_entries < 0) {
+    return android::base::ErrnoError()
+           << "failed to read max_entries from ringbuf";
+  }
+  if (max_entries == 0) {
+    errno = EINVAL;
+    return android::base::ErrnoError() << "max_entries must be non-zero";
+  }
+
+  mPosMask = max_entries - 1;
+  mConsumerSize = getpagesize();
+  mProducerSize = getpagesize() + 2 * max_entries;
+
+  {
+    void* ptr = mmap(NULL, mConsumerSize, PROT_READ | PROT_WRITE, MAP_SHARED,
+                     mRingFd, 0);
+    if (ptr == MAP_FAILED) {
+      return android::base::ErrnoError()
+             << "failed to mmap ringbuf consumer pages";
+    }
+    mConsumerPos = reinterpret_cast<decltype(mConsumerPos)>(ptr);
+  }
+
+  {
+    void* ptr = mmap(NULL, mProducerSize, PROT_READ, MAP_SHARED, mRingFd,
+                     mConsumerSize);
+    if (ptr == MAP_FAILED) {
+      return android::base::ErrnoError()
+             << "failed to mmap ringbuf producer page";
+    }
+    mProducerPos = reinterpret_cast<decltype(mProducerPos)>(ptr);
+  }
+
+  mDataPos = pointerAddBytes<void*>(mProducerPos, getpagesize());
+  return {};
+}
+
+inline bool BpfRingbufBase::isEmpty(void) {
+  uint32_t prod_pos = mProducerPos->load(std::memory_order_relaxed);
+  uint64_t cons_pos = mConsumerPos->load(std::memory_order_relaxed);
+  return (cons_pos & 0xFFFFFFFF) == prod_pos;
+}
+
+inline bool BpfRingbufBase::wait(int timeout_ms) {
+  // possible optimization: if (!isEmpty()) return true;
+  struct pollfd pfd = {  // 1-element array
+    .fd = mRingFd.get(),
+    .events = POLLIN,
+  };
+  (void)poll(&pfd, 1, timeout_ms);  // 'best effort' poll
+  return !isEmpty();
+}
+
+inline base::Result<int> BpfRingbufBase::ConsumeAll(
+    const std::function<void(const void*)>& callback) {
+  int64_t count = 0;
+  uint32_t prod_pos = mProducerPos->load(std::memory_order_acquire);
+  // Only userspace writes to mConsumerPos, so no need to use std::memory_order_acquire
+  uint64_t cons_pos = mConsumerPos->load(std::memory_order_relaxed);
+  while ((cons_pos & 0xFFFFFFFF) != prod_pos) {
+    // Find the start of the entry for this read (wrapping is done here).
+    void* start_ptr = pointerAddBytes<void*>(mDataPos, cons_pos & mPosMask);
+
+    // The entry has an 8 byte header containing the sample length.
+    // struct bpf_ringbuf_hdr {
+    //   u32 len;
+    //   u32 pg_off;
+    // };
+    uint32_t length = *reinterpret_cast<volatile uint32_t*>(start_ptr);
+
+    // If the sample isn't committed, we're caught up with the producer.
+    if (length & BPF_RINGBUF_BUSY_BIT) return count;
+
+    cons_pos += roundLength(length);
+
+    if ((length & BPF_RINGBUF_DISCARD_BIT) == 0) {
+      if (length != mValueSize) {
+        mConsumerPos->store(cons_pos, std::memory_order_release);
+        errno = EMSGSIZE;
+        return android::base::ErrnoError()
+               << "BPF ring buffer message has unexpected size (want "
+               << mValueSize << " bytes, got " << length << " bytes)";
+      }
+      callback(pointerAddBytes<const void*>(start_ptr, BPF_RINGBUF_HDR_SZ));
+      count++;
+    }
+
+    mConsumerPos->store(cons_pos, std::memory_order_release);
+  }
+
+  return count;
+}
+
+template <typename Value>
+inline base::Result<std::unique_ptr<BpfRingbuf<Value>>>
+BpfRingbuf<Value>::Create(const char* path) {
+  auto rb = std::unique_ptr<BpfRingbuf>(new BpfRingbuf);
+  if (auto status = rb->Init(path); !status.ok()) return status.error();
+  return rb;
+}
+
+template <typename Value>
+inline base::Result<int> BpfRingbuf<Value>::ConsumeAll(
+    const MessageCallback& callback) {
+  return BpfRingbufBase::ConsumeAll([&](const void* value) {
+    callback(*reinterpret_cast<const Value*>(value));
+  });
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/include/bpf/BpfUtils.h b/src/bpf/headers/include/bpf/BpfUtils.h
new file mode 100644
index 0000000..9dd5822
--- /dev/null
+++ b/src/bpf/headers/include/bpf/BpfUtils.h
@@ -0,0 +1,98 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+#pragma once
+
+#include <errno.h>
+#include <linux/if_ether.h>
+#include <linux/pfkeyv2.h>
+#include <net/if.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/resource.h>
+#include <sys/socket.h>
+#include <sys/utsname.h>
+
+#include <log/log.h>
+
+#include "KernelUtils.h"
+
+namespace android {
+namespace bpf {
+
+// See kernel's net/core/sock_diag.c __sock_gen_cookie()
+// the implementation of which guarantees 0 will never be returned,
+// primarily because 0 is used to mean not yet initialized,
+// and socket cookies are only assigned on first fetch.
+constexpr const uint64_t NONEXISTENT_COOKIE = 0;
+
+static inline uint64_t getSocketCookie(int sockFd) {
+    uint64_t sock_cookie;
+    socklen_t cookie_len = sizeof(sock_cookie);
+    if (getsockopt(sockFd, SOL_SOCKET, SO_COOKIE, &sock_cookie, &cookie_len)) {
+        // Failure is almost certainly either EBADF or ENOTSOCK
+        const int err = errno;
+        ALOGE("Failed to get socket cookie: %s\n", strerror(err));
+        errno = err;
+        return NONEXISTENT_COOKIE;
+    }
+    if (cookie_len != sizeof(sock_cookie)) {
+        // This probably cannot actually happen, but...
+        ALOGE("Failed to get socket cookie: len %d != 8\n", cookie_len);
+        errno = 523; // EBADCOOKIE: kernel internal, seems reasonable enough...
+        return NONEXISTENT_COOKIE;
+    }
+    return sock_cookie;
+}
+
+static inline int synchronizeKernelRCU() {
+    // This is a temporary hack for network stats map swap on devices running
+    // 4.9 kernels. The kernel code of socket release on pf_key socket will
+    // explicitly call synchronize_rcu() which is exactly what we need.
+    //
+    // Linux 4.14/4.19/5.4/5.10/5.15/6.1 (and 6.3-rc5) still have this same behaviour.
+    // see net/key/af_key.c: pfkey_release() -> synchronize_rcu()
+    // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/key/af_key.c?h=v6.3-rc5#n185
+    const int pfSocket = socket(AF_KEY, SOCK_RAW | SOCK_CLOEXEC, PF_KEY_V2);
+
+    if (pfSocket < 0) {
+        const int err = errno;
+        ALOGE("create PF_KEY socket failed: %s", strerror(err));
+        return -err;
+    }
+
+    // When closing socket, synchronize_rcu() gets called in sock_release().
+    if (close(pfSocket)) {
+        const int err = errno;
+        ALOGE("failed to close the PF_KEY socket: %s", strerror(err));
+        return -err;
+    }
+    return 0;
+}
+
+static inline int setrlimitForTest() {
+    // Set the memory rlimit for the test process if the default MEMLOCK rlimit is not enough.
+    struct rlimit limit = {
+            .rlim_cur = 1073741824,  // 1 GiB
+            .rlim_max = 1073741824,  // 1 GiB
+    };
+    const int res = setrlimit(RLIMIT_MEMLOCK, &limit);
+    if (res) ALOGE("Failed to set the default MEMLOCK rlimit: %s", strerror(errno));
+    return res;
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/include/bpf/KernelUtils.h b/src/bpf/headers/include/bpf/KernelUtils.h
new file mode 100644
index 0000000..68bc607
--- /dev/null
+++ b/src/bpf/headers/include/bpf/KernelUtils.h
@@ -0,0 +1,190 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+#pragma once
+
+#include <stdio.h>
+#include <string.h>
+#include <sys/personality.h>
+#include <sys/utsname.h>
+
+namespace android {
+namespace bpf {
+
+#define KVER(a, b, c) (((a) << 24) + ((b) << 16) + (c))
+
+static inline unsigned uncachedKernelVersion() {
+    struct utsname buf;
+    if (uname(&buf)) return 0;
+
+    unsigned kver_major = 0;
+    unsigned kver_minor = 0;
+    unsigned kver_sub = 0;
+    (void)sscanf(buf.release, "%u.%u.%u", &kver_major, &kver_minor, &kver_sub);
+    return KVER(kver_major, kver_minor, kver_sub);
+}
+
+static inline unsigned kernelVersion() {
+    static unsigned kver = uncachedKernelVersion();
+    return kver;
+}
+
+static inline bool isAtLeastKernelVersion(unsigned major, unsigned minor, unsigned sub) {
+    return kernelVersion() >= KVER(major, minor, sub);
+}
+
+static inline bool isKernelVersion(unsigned major, unsigned minor) {
+    return isAtLeastKernelVersion(major, minor, 0) && !isAtLeastKernelVersion(major, minor + 1, 0);
+}
+
+static inline bool __unused isLtsKernel() {
+    return isKernelVersion(4,  4) ||  // minimum for Android R
+           isKernelVersion(4,  9) ||  // minimum for Android S & T
+           isKernelVersion(4, 14) ||  // minimum for Android U
+           isKernelVersion(4, 19) ||  // minimum for Android V
+           isKernelVersion(5,  4) ||  // first supported in Android R, min for W
+           isKernelVersion(5, 10) ||  // first supported in Android S
+           isKernelVersion(5, 15) ||  // first supported in Android T
+           isKernelVersion(6,  1) ||  // first supported in Android U
+           isKernelVersion(6,  6) ||  // first supported in Android V
+           isKernelVersion(6, 12);    // first supported in Android W
+}
+
+// Figure out the bitness of userspace.
+// Trivial and known at compile time.
+static constexpr bool isUserspace32bit() {
+    return sizeof(void*) == 4;
+}
+
+static constexpr bool isUserspace64bit() {
+    return sizeof(void*) == 8;
+}
+
+#if defined(__LP64__)
+static_assert(isUserspace64bit(), "huh? LP64 must have 64-bit userspace");
+#elif defined(__ILP32__)
+static_assert(isUserspace32bit(), "huh? ILP32 must have 32-bit userspace");
+#else
+#error "huh? must be either LP64 (64-bit userspace) or ILP32 (32-bit userspace)"
+#endif
+
+static_assert(isUserspace32bit() || isUserspace64bit(), "must be either 32 or 64 bit");
+
+// Figure out the bitness of the kernel.
+static inline bool isKernel64Bit() {
+    // a 64-bit userspace requires a 64-bit kernel
+    if (isUserspace64bit()) return true;
+
+    static bool init = false;
+    static bool cache = false;
+    if (init) return cache;
+
+    // Retrieve current personality - on Linux this system call *cannot* fail.
+    int p = personality(0xffffffff);
+    // But if it does just assume kernel and userspace (which is 32-bit) match...
+    if (p == -1) return false;
+
+    // This will effectively mask out the bottom 8 bits, and switch to 'native'
+    // personality, and then return the previous personality of this thread
+    // (likely PER_LINUX or PER_LINUX32) with any extra options unmodified.
+    int q = personality((p & ~PER_MASK) | PER_LINUX);
+    // Per man page this theoretically could error out with EINVAL,
+    // but kernel code analysis suggests setting PER_LINUX cannot fail.
+    // Either way, assume kernel and userspace (which is 32-bit) match...
+    if (q != p) return false;
+
+    struct utsname u;
+    (void)uname(&u);  // only possible failure is EFAULT, but u is on stack.
+
+    // Switch back to previous personality.
+    // Theoretically could fail with EINVAL on arm64 with no 32-bit support,
+    // but then we wouldn't have fetched 'p' from the kernel in the first place.
+    // Either way there's nothing meaningful we can do in case of error.
+    // Since PER_LINUX32 vs PER_LINUX only affects uname.machine it doesn't
+    // really hurt us either.  We're really just switching back to be 'clean'.
+    (void)personality(p);
+
+    // Possible values of utsname.machine observed on x86_64 desktop (arm via qemu):
+    //   x86_64 i686 aarch64 armv7l
+    // additionally observed on arm device:
+    //   armv8l
+    // presumably also might just be possible:
+    //   i386 i486 i586
+    // and there might be other weird arm32 cases.
+    // We note that the 64 is present in both 64-bit archs,
+    // and in general is likely to be present in only 64-bit archs.
+    cache = !!strstr(u.machine, "64");
+    init = true;
+    return cache;
+}
+
+static inline __unused bool isKernel32Bit() {
+    return !isKernel64Bit();
+}
+
+static constexpr bool isArm() {
+#if defined(__arm__)
+    static_assert(isUserspace32bit(), "huh? arm must be 32 bit");
+    return true;
+#elif defined(__aarch64__)
+    static_assert(isUserspace64bit(), "aarch64 must be LP64 - no support for ILP32");
+    return true;
+#else
+    return false;
+#endif
+}
+
+static constexpr bool isX86() {
+#if defined(__i386__)
+    static_assert(isUserspace32bit(), "huh? i386 must be 32 bit");
+    return true;
+#elif defined(__x86_64__)
+    static_assert(isUserspace64bit(), "x86_64 must be LP64 - no support for ILP32 (x32)");
+    return true;
+#else
+    return false;
+#endif
+}
+
+static constexpr bool isRiscV() {
+#if defined(__riscv)
+    static_assert(isUserspace64bit(), "riscv must be 64 bit");
+    return true;
+#else
+    return false;
+#endif
+}
+
+static_assert(isArm() || isX86() || isRiscV(), "Unknown architecture");
+
+static __unused const char * describeArch() {
+    // ordered so as to make it easier to compile time optimize,
+    // only thing not known at compile time is isKernel64Bit()
+    if (isUserspace64bit()) {
+        if (isArm()) return "64-on-aarch64";
+        if (isX86()) return "64-on-x86-64";
+        if (isRiscV()) return "64-on-riscv64";
+    } else if (isKernel64Bit()) {
+        if (isArm()) return "32-on-aarch64";
+        if (isX86()) return "32-on-x86-64";
+    } else {
+        if (isArm()) return "32-on-arm32";
+        if (isX86()) return "32-on-x86-32";
+    }
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/include/bpf/WaitForProgsLoaded.h b/src/bpf/headers/include/bpf/WaitForProgsLoaded.h
new file mode 100644
index 0000000..bc4168e
--- /dev/null
+++ b/src/bpf/headers/include/bpf/WaitForProgsLoaded.h
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ * Android BPF library - public API
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
+#pragma once
+
+#include <log/log.h>
+
+#include <android-base/properties.h>
+
+namespace android {
+namespace bpf {
+
+// Wait for bpfloader to load BPF programs.
+static inline void waitForProgsLoaded() {
+    // infinite loop until success with 5/10/20/40/60/60/60... delay
+    for (int delay = 5;; delay *= 2) {
+        if (delay > 60) delay = 60;
+        if (android::base::WaitForProperty("bpf.progs_loaded", "1", std::chrono::seconds(delay)))
+            return;
+        ALOGW("Waited %ds for bpf.progs_loaded, still waiting...", delay);
+    }
+}
+
+}  // namespace bpf
+}  // namespace android
diff --git a/src/bpf/headers/include/bpf_helpers.h b/src/bpf/headers/include/bpf_helpers.h
new file mode 100644
index 0000000..ac5ffda
--- /dev/null
+++ b/src/bpf/headers/include/bpf_helpers.h
@@ -0,0 +1,473 @@
+/* Common BPF helpers to be used by all BPF programs loaded by Android */
+
+#include <linux/bpf.h>
+#include <stdbool.h>
+#include <stdint.h>
+
+#include "bpf_map_def.h"
+
+/******************************************************************************
+ * WARNING: CHANGES TO THIS FILE OUTSIDE OF AOSP/MAIN ARE LIKELY TO BREAK     *
+ * DEVICE COMPATIBILITY WITH MAINLINE MODULES SHIPPING EBPF CODE.             *
+ *                                                                            *
+ * THIS WILL LIKELY RESULT IN BRICKED DEVICES AT SOME ARBITRARY FUTURE TIME   *
+ *                                                                            *
+ * THAT GOES ESPECIALLY FOR THE 'SECTION' 'LICENSE' AND 'CRITICAL' MACROS     *
+ *                                                                            *
+ * We strongly suggest that if you need changes to bpfloader functionality    *
+ * you get your changes reviewed and accepted into aosp/master.               *
+ *                                                                            *
+ ******************************************************************************/
+
+// The actual versions of the bpfloader that shipped in various Android releases
+
+// Android P/Q/R: BpfLoader was initially part of netd,
+// this was later split out into a standalone binary, but was unversioned.
+
+// Android S / 12 (api level 31) - added 'tethering' mainline eBPF support
+#define BPFLOADER_S_VERSION 2u
+
+// Android T / 13 (api level 33) - support for shared/selinux_context/pindir
+#define BPFLOADER_T_VERSION 19u
+
+// BpfLoader v0.25+ support obj@ver.o files
+#define BPFLOADER_OBJ_AT_VER_VERSION 25u
+
+// Bpfloader v0.33+ supports {map,prog}.ignore_on_{eng,user,userdebug}
+#define BPFLOADER_IGNORED_ON_VERSION 33u
+
+// Android U / 14 (api level 34) - various new program types added
+#define BPFLOADER_U_VERSION 38u
+
+// Android U QPR2 / 14 (api level 34) - platform only
+// (note: the platform bpfloader in V isn't really versioned at all,
+//  as there is no need as it can only load objects compiled at the
+//  same time as itself and the rest of the platform)
+#define BPFLOADER_U_QPR2_VERSION 41u
+#define BPFLOADER_PLATFORM_VERSION BPFLOADER_U_QPR2_VERSION
+
+// Android Mainline - this bpfloader should eventually go back to T (or even S)
+// Note: this value (and the following +1u's) are hardcoded in NetBpfLoad.cpp
+#define BPFLOADER_MAINLINE_VERSION 42u
+
+// Android Mainline BpfLoader when running on Android T (sdk=33)
+#define BPFLOADER_MAINLINE_T_VERSION (BPFLOADER_MAINLINE_VERSION + 1u)
+
+// Android Mainline BpfLoader when running on Android U (sdk=34)
+#define BPFLOADER_MAINLINE_U_VERSION (BPFLOADER_MAINLINE_T_VERSION + 1u)
+
+// Android Mainline BpfLoader when running on Android U QPR3
+#define BPFLOADER_MAINLINE_U_QPR3_VERSION (BPFLOADER_MAINLINE_U_VERSION + 1u)
+
+// Android Mainline BpfLoader when running on Android V (sdk=35)
+#define BPFLOADER_MAINLINE_V_VERSION (BPFLOADER_MAINLINE_U_QPR3_VERSION + 1u)
+
+// Android Mainline BpfLoader when running on Android W (sdk=36)
+#define BPFLOADER_MAINLINE_W_VERSION (BPFLOADER_MAINLINE_V_VERSION + 1u)
+
+/* For mainline module use, you can #define BPFLOADER_{MIN/MAX}_VER
+ * before #include "bpf_helpers.h" to change which bpfloaders will
+ * process the resulting .o file.
+ *
+ * While this will work outside of mainline too, there just is no point to
+ * using it when the .o and the bpfloader ship in sync with each other.
+ * In which case it's just best to use the default.
+ */
+#ifndef BPFLOADER_MIN_VER
+#define BPFLOADER_MIN_VER BPFLOADER_PLATFORM_VERSION  // inclusive, ie. >=
+#endif
+
+#ifndef BPFLOADER_MAX_VER
+#define BPFLOADER_MAX_VER 0x10000u  // exclusive, ie. < v1.0
+#endif
+
+/* place things in different elf sections */
+#define SECTION(NAME) __attribute__((section(NAME), used))
+
+/* Must be present in every program, example usage:
+ *   LICENSE("GPL"); or LICENSE("Apache 2.0");
+ *
+ * We also take this opportunity to embed a bunch of other useful values in
+ * the resulting .o (This is to enable some limited forward compatibility
+ * with mainline module shipped ebpf programs)
+ *
+ * The bpfloader_{min/max}_ver defines the [min, max) range of bpfloader
+ * versions that should load this .o file (bpfloaders outside of this range
+ * will simply ignore/skip this *entire* .o)
+ * The [inclusive,exclusive) matches what we do for kernel ver dependencies.
+ *
+ * The size_of_bpf_{map,prog}_def allow the bpfloader to load programs where
+ * these structures have been extended with additional fields (they will of
+ * course simply be ignored then).
+ *
+ * If missing, bpfloader_{min/max}_ver default to 0/0x10000 ie. [v0.0, v1.0),
+ * while size_of_bpf_{map/prog}_def default to 32/20 which are the v0.0 sizes.
+ *
+ * This macro also disables loading BTF map debug information, as versions
+ * of the platform bpfloader that support BTF require fork-exec of btfloader
+ * which causes a regression in boot time.
+ */
+#define LICENSE(NAME)                                                                              \
+    unsigned int _bpfloader_min_ver SECTION("bpfloader_min_ver") = BPFLOADER_MIN_VER;              \
+    unsigned int _bpfloader_max_ver SECTION("bpfloader_max_ver") = BPFLOADER_MAX_VER;              \
+    size_t _size_of_bpf_map_def SECTION("size_of_bpf_map_def") = sizeof(struct bpf_map_def);       \
+    size_t _size_of_bpf_prog_def SECTION("size_of_bpf_prog_def") = sizeof(struct bpf_prog_def);    \
+    unsigned _btf_min_bpfloader_ver SECTION("btf_min_bpfloader_ver") = BPFLOADER_MAINLINE_VERSION; \
+    unsigned _btf_user_min_bpfloader_ver SECTION("btf_user_min_bpfloader_ver") = 0xFFFFFFFFu;      \
+    char _license[] SECTION("license") = (NAME)
+
+/* flag the resulting bpf .o file as critical to system functionality,
+ * loading all kernel version appropriate programs in it must succeed
+ * for bpfloader success
+ */
+#define CRITICAL(REASON) char _critical[] SECTION("critical") = (REASON)
+
+/*
+ * Helper functions called from eBPF programs written in C. These are
+ * implemented in the kernel sources.
+ */
+
+struct kver_uint { unsigned int kver; };
+#define KVER_(v) ((struct kver_uint){ .kver = (v) })
+#define KVER(a, b, c) KVER_(((a) << 24) + ((b) << 16) + (c))
+#define KVER_NONE KVER_(0)
+#define KVER_4_14 KVER(4, 14, 0)
+#define KVER_4_19 KVER(4, 19, 0)
+#define KVER_5_4  KVER(5, 4, 0)
+#define KVER_5_8  KVER(5, 8, 0)
+#define KVER_5_9  KVER(5, 9, 0)
+#define KVER_5_10 KVER(5, 10, 0)
+#define KVER_5_15 KVER(5, 15, 0)
+#define KVER_6_1  KVER(6, 1, 0)
+#define KVER_6_6  KVER(6, 6, 0)
+#define KVER_INF KVER_(0xFFFFFFFFu)
+
+#define KVER_IS_AT_LEAST(kver, a, b, c) ((kver).kver >= KVER(a, b, c).kver)
+
+/*
+ * BPFFS (ie. /sys/fs/bpf) labelling is as follows:
+ *   subdirectory   selinux context      mainline  usecase / usable by
+ *   /              fs_bpf               no [*]    core operating system (ie. platform)
+ *   /loader        fs_bpf_loader        no, U+    (as yet unused)
+ *   /net_private   fs_bpf_net_private   yes, T+   network_stack
+ *   /net_shared    fs_bpf_net_shared    yes, T+   network_stack & system_server
+ *   /netd_readonly fs_bpf_netd_readonly yes, T+   network_stack & system_server & r/o to netd
+ *   /netd_shared   fs_bpf_netd_shared   yes, T+   network_stack & system_server & netd [**]
+ *   /tethering     fs_bpf_tethering     yes, S+   network_stack
+ *   /vendor        fs_bpf_vendor        no, T+    vendor
+ *
+ * [*] initial support for bpf was added back in P,
+ *     but things worked differently back then with no bpfloader,
+ *     and instead netd doing stuff by hand,
+ *     bpfloader with pinning into /sys/fs/bpf was (I believe) added in Q
+ *     (and was definitely there in R).
+ *
+ * [**] additionally bpf programs are accessible to netutils_wrapper
+ *      for use by iptables xt_bpf extensions.
+ *
+ * See cs/p:aosp-master%20-file:prebuilts/%20file:genfs_contexts%20"genfscon%20bpf"
+ */
+
+/* generic functions */
+
+/*
+ * Type-unsafe bpf map functions - avoid if possible.
+ *
+ * Using these it is possible to pass in keys/values of the wrong type/size,
+ * or, for 'bpf_map_lookup_elem_unsafe' receive into a pointer to the wrong type.
+ * You will not get a compile time failure, and for certain types of errors you
+ * might not even get a failure from the kernel's ebpf verifier during program load,
+ * instead stuff might just not work right at runtime.
+ *
+ * Instead please use:
+ *   DEFINE_BPF_MAP(foo_map, TYPE, KeyType, ValueType, num_entries)
+ * where TYPE can be something like HASH or ARRAY, and num_entries is an integer.
+ *
+ * This defines the map (hence this should not be used in a header file included
+ * from multiple locations) and provides type safe accessors:
+ *   ValueType * bpf_foo_map_lookup_elem(const KeyType *)
+ *   int bpf_foo_map_update_elem(const KeyType *, const ValueType *, flags)
+ *   int bpf_foo_map_delete_elem(const KeyType *)
+ *
+ * This will make sure that if you change the type of a map you'll get compile
+ * errors at any spots you forget to update with the new type.
+ *
+ * Note: these all take pointers to const map because from the C/eBPF point of view
+ * the map struct is really just a readonly map definition of the in kernel object.
+ * Runtime modification of the map defining struct is meaningless, since
+ * the contents is only ever used during bpf program loading & map creation
+ * by the bpf loader, and not by the eBPF program itself.
+ */
+static void* (*bpf_map_lookup_elem_unsafe)(const struct bpf_map_def* map,
+                                           const void* key) = (void*)BPF_FUNC_map_lookup_elem;
+static int (*bpf_map_update_elem_unsafe)(const struct bpf_map_def* map, const void* key,
+                                         const void* value, unsigned long long flags) = (void*)
+        BPF_FUNC_map_update_elem;
+static int (*bpf_map_delete_elem_unsafe)(const struct bpf_map_def* map,
+                                         const void* key) = (void*)BPF_FUNC_map_delete_elem;
+static int (*bpf_ringbuf_output_unsafe)(const struct bpf_map_def* ringbuf,
+                                        const void* data, __u64 size, __u64 flags) = (void*)
+        BPF_FUNC_ringbuf_output;
+static void* (*bpf_ringbuf_reserve_unsafe)(const struct bpf_map_def* ringbuf,
+                                           __u64 size, __u64 flags) = (void*)
+        BPF_FUNC_ringbuf_reserve;
+static void (*bpf_ringbuf_submit_unsafe)(const void* data, __u64 flags) = (void*)
+        BPF_FUNC_ringbuf_submit;
+
+#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)  \
+        struct ____btf_map_##name {                     \
+                type_key key;                           \
+                type_val value;                         \
+        };                                              \
+        struct ____btf_map_##name                       \
+        __attribute__ ((section(".maps." #name), used)) \
+                ____btf_map_##name = { }
+
+#define BPF_ASSERT_LOADER_VERSION(min_loader, ignore_eng, ignore_user, ignore_userdebug) \
+    _Static_assert(                                                                      \
+        (min_loader) >= BPFLOADER_IGNORED_ON_VERSION ||                                  \
+            !((ignore_eng).ignore_on_eng ||                                              \
+              (ignore_user).ignore_on_user ||                                            \
+              (ignore_userdebug).ignore_on_userdebug),                                   \
+        "bpfloader min version must be >= 0.33 in order to use ignored_on");
+
+#define DEFINE_BPF_MAP_BASE(the_map, TYPE, keysize, valuesize, num_entries, \
+                            usr, grp, md, selinux, pindir, share, minkver,  \
+                            maxkver, minloader, maxloader, ignore_eng,      \
+                            ignore_user, ignore_userdebug)                  \
+    const struct bpf_map_def SECTION("maps") the_map = {                    \
+        .type = BPF_MAP_TYPE_##TYPE,                                        \
+        .key_size = (keysize),                                              \
+        .value_size = (valuesize),                                          \
+        .max_entries = (num_entries),                                       \
+        .map_flags = 0,                                                     \
+        .uid = (usr),                                                       \
+        .gid = (grp),                                                       \
+        .mode = (md),                                                       \
+        .bpfloader_min_ver = (minloader),                                   \
+        .bpfloader_max_ver = (maxloader),                                   \
+        .min_kver = (minkver).kver,                                         \
+        .max_kver = (maxkver).kver,                                         \
+        .selinux_context = (selinux),                                       \
+        .pin_subdir = (pindir),                                             \
+        .shared = (share).shared,                                           \
+        .ignore_on_eng = (ignore_eng).ignore_on_eng,                        \
+        .ignore_on_user = (ignore_user).ignore_on_user,                     \
+        .ignore_on_userdebug = (ignore_userdebug).ignore_on_userdebug,      \
+    };                                                                      \
+    BPF_ASSERT_LOADER_VERSION(minloader, ignore_eng, ignore_user, ignore_userdebug);
+
+// Type safe macro to declare a ring buffer and related output functions.
+// Compatibility:
+// * BPF ring buffers are only available kernels 5.8 and above. Any program
+//   accessing the ring buffer should set a program level min_kver >= 5.8.
+// * The definition below sets a map min_kver of 5.8 which requires targeting
+//   a BPFLOADER_MIN_VER >= BPFLOADER_S_VERSION.
+#define DEFINE_BPF_RINGBUF_EXT(the_map, ValueType, size_bytes, usr, grp, md,   \
+                               selinux, pindir, share, min_loader, max_loader, \
+                               ignore_eng, ignore_user, ignore_userdebug)      \
+    DEFINE_BPF_MAP_BASE(the_map, RINGBUF, 0, 0, size_bytes, usr, grp, md,      \
+                        selinux, pindir, share, KVER_5_8, KVER_INF,            \
+                        min_loader, max_loader, ignore_eng, ignore_user,       \
+                        ignore_userdebug);                                     \
+                                                                               \
+    _Static_assert((size_bytes) >= 4096, "min 4 kiB ringbuffer size");         \
+    _Static_assert((size_bytes) <= 0x10000000, "max 256 MiB ringbuffer size"); \
+    _Static_assert(((size_bytes) & ((size_bytes) - 1)) == 0,                   \
+                   "ring buffer size must be a power of two");                 \
+                                                                               \
+    static inline __always_inline __unused int bpf_##the_map##_output(         \
+            const ValueType* v) {                                              \
+        return bpf_ringbuf_output_unsafe(&the_map, v, sizeof(*v), 0);          \
+    }                                                                          \
+                                                                               \
+    static inline __always_inline __unused                                     \
+            ValueType* bpf_##the_map##_reserve() {                             \
+        return bpf_ringbuf_reserve_unsafe(&the_map, sizeof(ValueType), 0);     \
+    }                                                                          \
+                                                                               \
+    static inline __always_inline __unused void bpf_##the_map##_submit(        \
+            const ValueType* v) {                                              \
+        bpf_ringbuf_submit_unsafe(v, 0);                                       \
+    }
+
+#define DEFINE_BPF_RINGBUF(the_map, ValueType, size_bytes, usr, grp, md)                \
+    DEFINE_BPF_RINGBUF_EXT(the_map, ValueType, size_bytes, usr, grp, md,                \
+                           DEFAULT_BPF_MAP_SELINUX_CONTEXT, DEFAULT_BPF_MAP_PIN_SUBDIR, \
+                           PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,               \
+                           LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+
+/* There exist buggy kernels with pre-T OS, that due to
+ * kernel patch "[ALPS05162612] bpf: fix ubsan error"
+ * do not support userspace writes into non-zero index of bpf map arrays.
+ *
+ * We use this assert to prevent us from being able to define such a map.
+ */
+
+#ifdef THIS_BPF_PROGRAM_IS_FOR_TEST_PURPOSES_ONLY
+#define BPF_MAP_ASSERT_OK(type, entries, mode)
+#elif BPFLOADER_MIN_VER >= BPFLOADER_T_VERSION
+#define BPF_MAP_ASSERT_OK(type, entries, mode)
+#else
+#define BPF_MAP_ASSERT_OK(type, entries, mode) \
+  _Static_assert(((type) != BPF_MAP_TYPE_ARRAY) || ((entries) <= 1) || !((mode) & 0222), \
+  "Writable arrays with more than 1 element not supported on pre-T devices.")
+#endif
+
+/* type safe macro to declare a map and related accessor functions */
+#define DEFINE_BPF_MAP_EXT(the_map, TYPE, KeyType, ValueType, num_entries, usr, grp, md,         \
+                           selinux, pindir, share, min_loader, max_loader, ignore_eng,           \
+                           ignore_user, ignore_userdebug)                                        \
+  DEFINE_BPF_MAP_BASE(the_map, TYPE, sizeof(KeyType), sizeof(ValueType),                         \
+                      num_entries, usr, grp, md, selinux, pindir, share,                         \
+                      KVER_NONE, KVER_INF, min_loader, max_loader,                               \
+                      ignore_eng, ignore_user, ignore_userdebug);                                \
+    BPF_MAP_ASSERT_OK(BPF_MAP_TYPE_##TYPE, (num_entries), (md));                                 \
+    _Static_assert(sizeof(KeyType) < 1024, "aosp/2370288 requires < 1024 byte keys");            \
+    _Static_assert(sizeof(ValueType) < 65536, "aosp/2370288 requires < 65536 byte values");      \
+    BPF_ANNOTATE_KV_PAIR(the_map, KeyType, ValueType);                                           \
+                                                                                                 \
+    static inline __always_inline __unused ValueType* bpf_##the_map##_lookup_elem(               \
+            const KeyType* k) {                                                                  \
+        return bpf_map_lookup_elem_unsafe(&the_map, k);                                          \
+    };                                                                                           \
+                                                                                                 \
+    static inline __always_inline __unused int bpf_##the_map##_update_elem(                      \
+            const KeyType* k, const ValueType* v, unsigned long long flags) {                    \
+        return bpf_map_update_elem_unsafe(&the_map, k, v, flags);                                \
+    };                                                                                           \
+                                                                                                 \
+    static inline __always_inline __unused int bpf_##the_map##_delete_elem(const KeyType* k) {   \
+        return bpf_map_delete_elem_unsafe(&the_map, k);                                          \
+    };
+
+#ifndef DEFAULT_BPF_MAP_SELINUX_CONTEXT
+#define DEFAULT_BPF_MAP_SELINUX_CONTEXT ""
+#endif
+
+#ifndef DEFAULT_BPF_MAP_PIN_SUBDIR
+#define DEFAULT_BPF_MAP_PIN_SUBDIR ""
+#endif
+
+#ifndef DEFAULT_BPF_MAP_UID
+#define DEFAULT_BPF_MAP_UID AID_ROOT
+#elif BPFLOADER_MIN_VER < 28u
+#error "Bpf Map UID must be left at default of AID_ROOT for BpfLoader prior to v0.28"
+#endif
+
+// for maps not meant to be accessed from userspace
+#define DEFINE_BPF_MAP_KERNEL_INTERNAL(the_map, TYPE, KeyType, ValueType, num_entries)           \
+    DEFINE_BPF_MAP_EXT(the_map, TYPE, KeyType, ValueType, num_entries, AID_ROOT, AID_ROOT,       \
+                       0000, "fs_bpf_loader", "", PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, \
+                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+
+#define DEFINE_BPF_MAP_UGM(the_map, TYPE, KeyType, ValueType, num_entries, usr, grp, md) \
+    DEFINE_BPF_MAP_EXT(the_map, TYPE, KeyType, ValueType, num_entries, usr, grp, md,     \
+                       DEFAULT_BPF_MAP_SELINUX_CONTEXT, DEFAULT_BPF_MAP_PIN_SUBDIR,      \
+                       PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,                    \
+                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+
+#define DEFINE_BPF_MAP(the_map, TYPE, KeyType, ValueType, num_entries) \
+    DEFINE_BPF_MAP_UGM(the_map, TYPE, KeyType, ValueType, num_entries, \
+                       DEFAULT_BPF_MAP_UID, AID_ROOT, 0600)
+
+#define DEFINE_BPF_MAP_RO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_UGM(the_map, TYPE, KeyType, ValueType, num_entries, \
+                       DEFAULT_BPF_MAP_UID, gid, 0440)
+
+#define DEFINE_BPF_MAP_GWO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_UGM(the_map, TYPE, KeyType, ValueType, num_entries, \
+                       DEFAULT_BPF_MAP_UID, gid, 0620)
+
+#define DEFINE_BPF_MAP_GRO(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_UGM(the_map, TYPE, KeyType, ValueType, num_entries, \
+                       DEFAULT_BPF_MAP_UID, gid, 0640)
+
+#define DEFINE_BPF_MAP_GRW(the_map, TYPE, KeyType, ValueType, num_entries, gid) \
+    DEFINE_BPF_MAP_UGM(the_map, TYPE, KeyType, ValueType, num_entries, \
+                       DEFAULT_BPF_MAP_UID, gid, 0660)
+
+// LLVM eBPF builtins: they directly generate BPF_LD_ABS/BPF_LD_IND (skb may be ignored?)
+unsigned long long load_byte(void* skb, unsigned long long off) asm("llvm.bpf.load.byte");
+unsigned long long load_half(void* skb, unsigned long long off) asm("llvm.bpf.load.half");
+unsigned long long load_word(void* skb, unsigned long long off) asm("llvm.bpf.load.word");
+
+static int (*bpf_probe_read)(void* dst, int size, void* unsafe_ptr) = (void*) BPF_FUNC_probe_read;
+static int (*bpf_probe_read_str)(void* dst, int size, void* unsafe_ptr) = (void*) BPF_FUNC_probe_read_str;
+static int (*bpf_probe_read_user)(void* dst, int size, const void* unsafe_ptr) = (void*)BPF_FUNC_probe_read_user;
+static int (*bpf_probe_read_user_str)(void* dst, int size, const void* unsafe_ptr) = (void*) BPF_FUNC_probe_read_user_str;
+static unsigned long long (*bpf_ktime_get_ns)(void) = (void*) BPF_FUNC_ktime_get_ns;
+static unsigned long long (*bpf_ktime_get_boot_ns)(void) = (void*)BPF_FUNC_ktime_get_boot_ns;
+static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void*) BPF_FUNC_get_current_pid_tgid;
+static unsigned long long (*bpf_get_current_uid_gid)(void) = (void*) BPF_FUNC_get_current_uid_gid;
+static unsigned long long (*bpf_get_smp_processor_id)(void) = (void*) BPF_FUNC_get_smp_processor_id;
+static long (*bpf_get_stackid)(void* ctx, void* map, uint64_t flags) = (void*) BPF_FUNC_get_stackid;
+static long (*bpf_get_current_comm)(void* buf, uint32_t buf_size) = (void*) BPF_FUNC_get_current_comm;
+
+// GPL only:
+static int (*bpf_trace_printk)(const char* fmt, int fmt_size, ...) = (void*) BPF_FUNC_trace_printk;
+#define bpf_printf(s, n...) bpf_trace_printk(s, sizeof(s), ## n)
+// Note: bpf only supports up to 3 arguments, log via: bpf_printf("msg %d %d %d", 1, 2, 3);
+// and read via the blocking: sudo cat /sys/kernel/debug/tracing/trace_pipe
+
+#define DEFINE_BPF_PROG_EXT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, max_kv,  \
+                            min_loader, max_loader, opt, selinux, pindir, ignore_eng,    \
+                            ignore_user, ignore_userdebug)                               \
+    const struct bpf_prog_def SECTION("progs") the_prog##_def = {                        \
+        .uid = (prog_uid),                                                               \
+        .gid = (prog_gid),                                                               \
+        .min_kver = (min_kv).kver,                                                       \
+        .max_kver = (max_kv).kver,                                                       \
+        .optional = (opt).optional,                                                      \
+        .bpfloader_min_ver = (min_loader),                                               \
+        .bpfloader_max_ver = (max_loader),                                               \
+        .selinux_context = (selinux),                                                    \
+        .pin_subdir = (pindir),                                                          \
+        .ignore_on_eng = (ignore_eng).ignore_on_eng,                                     \
+        .ignore_on_user = (ignore_user).ignore_on_user,                                  \
+        .ignore_on_userdebug = (ignore_userdebug).ignore_on_userdebug,                   \
+    };                                                                                   \
+    SECTION(SECTION_NAME)                                                                \
+    int the_prog
+
+#define DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, max_kv, \
+                                       opt)                                                        \
+    DEFINE_BPF_PROG_EXT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, max_kv,                \
+                        BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, opt, "", "",                         \
+                        LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+
+// Programs (here used in the sense of functions/sections) marked optional are allowed to fail
+// to load (for example due to missing kernel patches).
+// The bpfloader will just ignore these failures and continue processing the next section.
+//
+// A non-optional program (function/section) failing to load causes a failure and aborts
+// processing of the entire .o, if the .o is additionally marked critical, this will result
+// in the entire bpfloader process terminating with a failure and not setting the bpf.progs_loaded
+// system property.  This in turn results in waitForProgsLoaded() never finishing.
+//
+// ie. a non-optional program in a critical .o is mandatory for kernels matching the min/max kver.
+
+// programs requiring a kernel version >= min_kv && < max_kv
+#define DEFINE_BPF_PROG_KVER_RANGE(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, max_kv) \
+    DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, max_kv, \
+                                   MANDATORY)
+#define DEFINE_OPTIONAL_BPF_PROG_KVER_RANGE(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, \
+                                            max_kv)                                             \
+    DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, max_kv, \
+                                   OPTIONAL)
+
+// programs requiring a kernel version >= min_kv
+#define DEFINE_BPF_PROG_KVER(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv)                 \
+    DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, KVER_INF, \
+                                   MANDATORY)
+#define DEFINE_OPTIONAL_BPF_PROG_KVER(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv)        \
+    DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, min_kv, KVER_INF, \
+                                   OPTIONAL)
+
+// programs with no kernel version requirements
+#define DEFINE_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog) \
+    DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, KVER_NONE, KVER_INF, \
+                                   MANDATORY)
+#define DEFINE_OPTIONAL_BPF_PROG(SECTION_NAME, prog_uid, prog_gid, the_prog) \
+    DEFINE_BPF_PROG_KVER_RANGE_OPT(SECTION_NAME, prog_uid, prog_gid, the_prog, KVER_NONE, KVER_INF, \
+                                   OPTIONAL)
diff --git a/src/bpf/headers/include/bpf_map_def.h b/src/bpf/headers/include/bpf_map_def.h
new file mode 100644
index 0000000..2d6736c
--- /dev/null
+++ b/src/bpf/headers/include/bpf_map_def.h
@@ -0,0 +1,261 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+#pragma once
+
+/* This file is separate because it's included both by eBPF programs (via include
+ * in bpf_helpers.h) and directly by the boot time bpfloader (Loader.cpp).
+ */
+
+#include <linux/bpf.h>
+
+// Pull in AID_* constants from //system/core/libcutils/include/private/android_filesystem_config.h
+#include <cutils/android_filesystem_config.h>
+
+/******************************************************************************
+ *                                                                            *
+ *                          ! ! ! W A R N I N G ! ! !                         *
+ *                                                                            *
+ * CHANGES TO THESE STRUCTURE DEFINITIONS OUTSIDE OF AOSP/MAIN *WILL* BREAK   *
+ * MAINLINE MODULE COMPATIBILITY                                              *
+ *                                                                            *
+ * AND THUS MAY RESULT IN YOUR DEVICE BRICKING AT SOME ARBITRARY POINT IN     *
+ * THE FUTURE                                                                 *
+ *                                                                            *
+ * (and even in aosp/master you may only append new fields at the very end,   *
+ *  you may *never* delete fields, change their types, ordering, insert in    *
+ *  the middle, etc.  If a mainline module using the old definition has       *
+ *  already shipped (which happens roughly monthly), then it's set in stone)  *
+ *                                                                            *
+ ******************************************************************************/
+
+/*
+ * The bpf_{map,prog}_def structures are compiled for different architectures.
+ * Once by the BPF compiler for the BPF architecture, and once by a C++
+ * compiler for the native Android architecture for the bpfloader.
+ *
+ * For things to work, their layout must be the same between the two.
+ * The BPF architecture is platform independent ('64-bit LSB bpf').
+ * So this effectively means these structures must be the same layout
+ * on 5 architectures, all of them little endian:
+ *   64-bit BPF, x86_64, arm  and  32-bit x86 and arm
+ *
+ * As such for any types we use inside of these structs we must make sure that
+ * the size and alignment are the same, so the same amount of padding is used.
+ *
+ * Currently we only use: bool, enum bpf_map_type and unsigned int.
+ * Additionally we use char for padding.
+ *
+ * !!! WARNING: HERE BE DRAGONS !!!
+ *
+ * Be particularly careful with 64-bit integers.
+ * You will need to manually override their alignment to 8 bytes.
+ *
+ * To quote some parts of https://gcc.gnu.org/bugzilla/show_bug.cgi?id=69560
+ *
+ * Some types have weaker alignment requirements when they are structure members.
+ *
+ * unsigned long long on x86 is such a type.
+ *
+ * C distinguishes C11 _Alignof (the minimum alignment the type is guaranteed
+ * to have in all contexts, so 4, see min_align_of_type) from GNU C __alignof
+ * (the normal alignment of the type, so 8).
+ *
+ * alignof / _Alignof == minimum alignment required by target ABI
+ * __alignof / __alignof__ == preferred alignment
+ *
+ * When in a struct, apparently the minimum alignment is used.
+ */
+
+_Static_assert(sizeof(bool) == 1, "sizeof bool != 1");
+_Static_assert(__alignof__(bool) == 1, "__alignof__ bool != 1");
+_Static_assert(_Alignof(bool) == 1, "_Alignof bool != 1");
+
+_Static_assert(sizeof(char) == 1, "sizeof char != 1");
+_Static_assert(__alignof__(char) == 1, "__alignof__ char != 1");
+_Static_assert(_Alignof(char) == 1, "_Alignof char != 1");
+
+// This basically verifies that an enum is 'just' a 32-bit int
+_Static_assert(sizeof(enum bpf_map_type) == 4, "sizeof enum bpf_map_type != 4");
+_Static_assert(__alignof__(enum bpf_map_type) == 4, "__alignof__ enum bpf_map_type != 4");
+_Static_assert(_Alignof(enum bpf_map_type) == 4, "_Alignof enum bpf_map_type != 4");
+
+// Linux kernel requires sizeof(int) == 4, sizeof(void*) == sizeof(long), sizeof(long long) == 8
+_Static_assert(sizeof(unsigned int) == 4, "sizeof unsigned int != 4");
+_Static_assert(__alignof__(unsigned int) == 4, "__alignof__ unsigned int != 4");
+_Static_assert(_Alignof(unsigned int) == 4, "_Alignof unsigned int != 4");
+
+// We don't currently use any 64-bit types in these structs, so this is purely to document issue.
+// Here sizeof & __alignof__ are consistent, but _Alignof is not: compile for 'aosp_cf_x86_phone'
+_Static_assert(sizeof(unsigned long long) == 8, "sizeof unsigned long long != 8");
+_Static_assert(__alignof__(unsigned long long) == 8, "__alignof__ unsigned long long != 8");
+// BPF wants 8, but 32-bit x86 wants 4
+//_Static_assert(_Alignof(unsigned long long) == 8, "_Alignof unsigned long long != 8");
+
+
+// for maps:
+struct shared_bool { bool shared; };
+#define PRIVATE ((struct shared_bool){ .shared = false })
+#define SHARED ((struct shared_bool){ .shared = true })
+
+// for programs:
+struct optional_bool { bool optional; };
+#define MANDATORY ((struct optional_bool){ .optional = false })
+#define OPTIONAL ((struct optional_bool){ .optional = true })
+
+// for both maps and programs:
+struct ignore_on_eng_bool { bool ignore_on_eng; };
+#define LOAD_ON_ENG ((struct ignore_on_eng_bool){ .ignore_on_eng = false })
+#define IGNORE_ON_ENG ((struct ignore_on_eng_bool){ .ignore_on_eng = true })
+
+struct ignore_on_user_bool { bool ignore_on_user; };
+#define LOAD_ON_USER ((struct ignore_on_user_bool){ .ignore_on_user = false })
+#define IGNORE_ON_USER ((struct ignore_on_user_bool){ .ignore_on_user = true })
+
+struct ignore_on_userdebug_bool { bool ignore_on_userdebug; };
+#define LOAD_ON_USERDEBUG ((struct ignore_on_userdebug_bool){ .ignore_on_userdebug = false })
+#define IGNORE_ON_USERDEBUG ((struct ignore_on_userdebug_bool){ .ignore_on_userdebug = true })
+
+
+// Length of strings (incl. selinux_context and pin_subdir)
+// in the bpf_map_def and bpf_prog_def structs.
+//
+// WARNING: YOU CANNOT *EVER* CHANGE THESE
+// as this would affect the structure size in backwards incompatible ways
+// and break mainline module loading on older Android T devices
+#define BPF_SELINUX_CONTEXT_CHAR_ARRAY_SIZE 32
+#define BPF_PIN_SUBDIR_CHAR_ARRAY_SIZE 32
+
+/*
+ * Map structure to be used by Android eBPF C programs. The Android eBPF loader
+ * uses this structure from eBPF object to create maps at boot time.
+ *
+ * The eBPF C program should define structure in the maps section using
+ * SECTION("maps") otherwise it will be ignored by the eBPF loader.
+ *
+ * For example:
+ *   const struct bpf_map_def SECTION("maps") mymap { .type=... , .key_size=... }
+ *
+ * See 'bpf_helpers.h' for helpful macros for eBPF program use.
+ */
+struct bpf_map_def {
+    enum bpf_map_type type;
+    unsigned int key_size;
+    unsigned int value_size;
+    unsigned int max_entries;
+    unsigned int map_flags;
+
+    // The following are not supported by the Android bpfloader:
+    //   unsigned int inner_map_idx;
+    //   unsigned int numa_node;
+
+    unsigned int zero;  // uid_t, for compat with old (buggy) bpfloader must be AID_ROOT == 0
+    unsigned int gid;   // gid_t
+    unsigned int mode;  // mode_t
+
+    // The following fields were added in version 0.1
+    unsigned int bpfloader_min_ver;  // if missing, defaults to 0, ie. v0.0
+    unsigned int bpfloader_max_ver;  // if missing, defaults to 0x10000, ie. v1.0
+
+    // The following fields were added in version 0.2 (S)
+    // kernelVersion() must be >= min_kver and < max_kver
+    unsigned int min_kver;
+    unsigned int max_kver;
+
+    // The following fields were added in version 0.18 (T)
+    //
+    // These are fixed length strings, padded with null bytes
+    //
+    // Warning: supported values depend on .o location
+    // (additionally a newer Android OS and/or bpfloader may support more values)
+    //
+    // overrides default selinux context (which is based on pin subdir)
+    char selinux_context[BPF_SELINUX_CONTEXT_CHAR_ARRAY_SIZE];
+    //
+    // overrides default prefix (which is based on .o location)
+    char pin_subdir[BPF_PIN_SUBDIR_CHAR_ARRAY_SIZE];
+
+    bool shared;  // use empty string as 'file' component of pin path - allows cross .o map sharing
+
+    // The following 3 ignore_on_* fields were added in version 0.32 (U). These are ignored in
+    // older bpfloader versions, and zero in programs compiled before 0.32.
+    bool ignore_on_eng:1;
+    bool ignore_on_user:1;
+    bool ignore_on_userdebug:1;
+    // The following 5 ignore_on_* fields were added in version 0.38 (U). These are ignored in
+    // older bpfloader versions, and zero in programs compiled before 0.38.
+    // These are tests on the kernel architecture, ie. they ignore userspace bit-ness.
+    bool ignore_on_arm32:1;
+    bool ignore_on_aarch64:1;
+    bool ignore_on_x86_32:1;
+    bool ignore_on_x86_64:1;
+    bool ignore_on_riscv64:1;
+
+    char pad0[2];  // manually pad up to 4 byte alignment, may be used for extensions in the future
+
+    unsigned int uid;   // uid_t
+};
+
+_Static_assert(sizeof(((struct bpf_map_def *)0)->selinux_context) == 32, "must be 32 bytes");
+_Static_assert(sizeof(((struct bpf_map_def *)0)->pin_subdir) == 32, "must be 32 bytes");
+
+// This needs to be updated whenever the above structure definition is expanded.
+_Static_assert(sizeof(struct bpf_map_def) == 120, "sizeof struct bpf_map_def != 120");
+_Static_assert(__alignof__(struct bpf_map_def) == 4, "__alignof__ struct bpf_map_def != 4");
+_Static_assert(_Alignof(struct bpf_map_def) == 4, "_Alignof struct bpf_map_def != 4");
+
+struct bpf_prog_def {
+    unsigned int uid;
+    unsigned int gid;
+
+    // kernelVersion() must be >= min_kver and < max_kver
+    unsigned int min_kver;
+    unsigned int max_kver;
+
+    bool optional;  // program section (ie. function) may fail to load, continue onto next func.
+
+    // The following 3 ignore_on_* fields were added in version 0.33 (U). These are ignored in
+    // older bpfloader versions, and zero in programs compiled before 0.33.
+    bool ignore_on_eng:1;
+    bool ignore_on_user:1;
+    bool ignore_on_userdebug:1;
+    // The following 5 ignore_on_* fields were added in version 0.38 (U). These are ignored in
+    // older bpfloader versions, and zero in programs compiled before 0.38.
+    // These are tests on the kernel architecture, ie. they ignore userspace bit-ness.
+    bool ignore_on_arm32:1;
+    bool ignore_on_aarch64:1;
+    bool ignore_on_x86_32:1;
+    bool ignore_on_x86_64:1;
+    bool ignore_on_riscv64:1;
+
+    char pad0[2];  // manually pad up to 4 byte alignment, may be used for extensions in the future
+
+    // The following fields were added in version 0.1
+    unsigned int bpfloader_min_ver;  // if missing, defaults to 0, ie. v0.0
+    unsigned int bpfloader_max_ver;  // if missing, defaults to 0x10000, ie. v1.0
+
+    // The following fields were added in version 0.18, see description up above in bpf_map_def
+    char selinux_context[BPF_SELINUX_CONTEXT_CHAR_ARRAY_SIZE];
+    char pin_subdir[BPF_PIN_SUBDIR_CHAR_ARRAY_SIZE];
+};
+
+_Static_assert(sizeof(((struct bpf_prog_def *)0)->selinux_context) == 32, "must be 32 bytes");
+_Static_assert(sizeof(((struct bpf_prog_def *)0)->pin_subdir) == 32, "must be 32 bytes");
+
+// This needs to be updated whenever the above structure definition is expanded.
+_Static_assert(sizeof(struct bpf_prog_def) == 92, "sizeof struct bpf_prog_def != 92");
+_Static_assert(__alignof__(struct bpf_prog_def) == 4, "__alignof__ struct bpf_prog_def != 4");
+_Static_assert(_Alignof(struct bpf_prog_def) == 4, "_Alignof struct bpf_prog_def != 4");
diff --git a/src/bpf/syscall_wrappers/Android.bp b/src/bpf/syscall_wrappers/Android.bp
new file mode 100644
index 0000000..a5c20ba
--- /dev/null
+++ b/src/bpf/syscall_wrappers/Android.bp
@@ -0,0 +1,37 @@
+// Copyright (C) 2021 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_performance",
+}
+
+cc_library_headers {
+    name: "uprobestats_bpf_syscall_wrappers",
+    vendor_available: true,
+    recovery_available: true,
+    host_supported: true,
+    native_bridge_supported: true,
+    export_include_dirs: ["include"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    sdk_version: "35",
+    min_sdk_version: "35",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.uprobestats",
+    ],
+}
diff --git a/src/bpf/syscall_wrappers/include/BpfSyscallWrappers.h b/src/bpf/syscall_wrappers/include/BpfSyscallWrappers.h
new file mode 100644
index 0000000..73cef89
--- /dev/null
+++ b/src/bpf/syscall_wrappers/include/BpfSyscallWrappers.h
@@ -0,0 +1,301 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+#pragma once
+
+#include <stdlib.h>
+#include <unistd.h>
+#include <linux/bpf.h>
+#include <linux/unistd.h>
+#include <sys/file.h>
+
+#ifdef BPF_FD_JUST_USE_INT
+  #define BPF_FD_TYPE int
+  #define BPF_FD_TO_U32(x) static_cast<__u32>(x)
+#else
+  #include <android-base/unique_fd.h>
+  #define BPF_FD_TYPE base::unique_fd&
+  #define BPF_FD_TO_U32(x) static_cast<__u32>((x).get())
+#endif
+
+namespace android {
+namespace bpf {
+
+inline uint64_t ptr_to_u64(const void * const x) {
+    return (uint64_t)(uintptr_t)x;
+}
+
+/* Note: bpf_attr is a union which might have a much larger size then the anonymous struct portion
+ * of it that we are using.  The kernel's bpf() system call will perform a strict check to ensure
+ * all unused portions are zero.  It will fail with E2BIG if we don't fully zero bpf_attr.
+ */
+
+inline int bpf(enum bpf_cmd cmd, const bpf_attr& attr) {
+    return syscall(__NR_bpf, cmd, &attr, sizeof(attr));
+}
+
+// this version is meant for use with cmd's which mutate the argument
+inline int bpf(enum bpf_cmd cmd, bpf_attr *attr) {
+    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
+}
+
+inline int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size,
+                     uint32_t max_entries, uint32_t map_flags) {
+    return bpf(BPF_MAP_CREATE, {
+                                       .map_type = map_type,
+                                       .key_size = key_size,
+                                       .value_size = value_size,
+                                       .max_entries = max_entries,
+                                       .map_flags = map_flags,
+                               });
+}
+
+// Note:
+//   'map_type' must be one of BPF_MAP_TYPE_{ARRAY,HASH}_OF_MAPS
+//   'value_size' must be sizeof(u32), ie. 4
+//   'inner_map_fd' is basically a template specifying {map_type, key_size, value_size, max_entries, map_flags}
+//   of the inner map type (and possibly only key_size/value_size actually matter?).
+inline int createOuterMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size,
+                          uint32_t max_entries, uint32_t map_flags, const BPF_FD_TYPE inner_map_fd) {
+    return bpf(BPF_MAP_CREATE, {
+                                       .map_type = map_type,
+                                       .key_size = key_size,
+                                       .value_size = value_size,
+                                       .max_entries = max_entries,
+                                       .map_flags = map_flags,
+                                       .inner_map_fd = BPF_FD_TO_U32(inner_map_fd),
+                               });
+}
+
+inline int writeToMapEntry(const BPF_FD_TYPE map_fd, const void* key, const void* value,
+                           uint64_t flags) {
+    return bpf(BPF_MAP_UPDATE_ELEM, {
+                                            .map_fd = BPF_FD_TO_U32(map_fd),
+                                            .key = ptr_to_u64(key),
+                                            .value = ptr_to_u64(value),
+                                            .flags = flags,
+                                    });
+}
+
+inline int findMapEntry(const BPF_FD_TYPE map_fd, const void* key, void* value) {
+    return bpf(BPF_MAP_LOOKUP_ELEM, {
+                                            .map_fd = BPF_FD_TO_U32(map_fd),
+                                            .key = ptr_to_u64(key),
+                                            .value = ptr_to_u64(value),
+                                    });
+}
+
+inline int deleteMapEntry(const BPF_FD_TYPE map_fd, const void* key) {
+    return bpf(BPF_MAP_DELETE_ELEM, {
+                                            .map_fd = BPF_FD_TO_U32(map_fd),
+                                            .key = ptr_to_u64(key),
+                                    });
+}
+
+inline int getNextMapKey(const BPF_FD_TYPE map_fd, const void* key, void* next_key) {
+    return bpf(BPF_MAP_GET_NEXT_KEY, {
+                                             .map_fd = BPF_FD_TO_U32(map_fd),
+                                             .key = ptr_to_u64(key),
+                                             .next_key = ptr_to_u64(next_key),
+                                     });
+}
+
+inline int getFirstMapKey(const BPF_FD_TYPE map_fd, void* firstKey) {
+    return getNextMapKey(map_fd, NULL, firstKey);
+}
+
+inline int bpfFdPin(const BPF_FD_TYPE map_fd, const char* pathname) {
+    return bpf(BPF_OBJ_PIN, {
+                                    .pathname = ptr_to_u64(pathname),
+                                    .bpf_fd = BPF_FD_TO_U32(map_fd),
+                            });
+}
+
+inline int bpfFdGet(const char* pathname, uint32_t flag) {
+    return bpf(BPF_OBJ_GET, {
+                                    .pathname = ptr_to_u64(pathname),
+                                    .file_flags = flag,
+                            });
+}
+
+int bpfGetFdMapId(const BPF_FD_TYPE map_fd);
+
+inline int bpfLock(int fd, short type) {
+    if (fd < 0) return fd;  // pass any errors straight through
+#ifdef BPF_MAP_LOCKLESS_FOR_TEST
+    return fd;
+#endif
+#ifdef BPF_FD_JUST_USE_INT
+    int mapId = bpfGetFdMapId(fd);
+    int saved_errno = errno;
+#else
+    base::unique_fd ufd(fd);
+    int mapId = bpfGetFdMapId(ufd);
+    int saved_errno = errno;
+    (void)ufd.release();
+#endif
+    // 4.14+ required to fetch map id, but we don't want to call isAtLeastKernelVersion
+    if (mapId == -1 && saved_errno == EINVAL) return fd;
+    if (mapId <= 0) abort();  // should not be possible
+
+    // on __LP64__ (aka. 64-bit userspace) 'struct flock64' is the same as 'struct flock'
+    struct flock64 fl = {
+        .l_type = type,        // short: F_{RD,WR,UN}LCK
+        .l_whence = SEEK_SET,  // short: SEEK_{SET,CUR,END}
+        .l_start = mapId,      // off_t: start offset
+        .l_len = 1,            // off_t: number of bytes
+    };
+
+    // see: bionic/libc/bionic/fcntl.cpp: iff !__LP64__ this uses fcntl64
+    int ret = fcntl(fd, F_OFD_SETLK, &fl);
+    if (!ret) return fd;  // success
+    close(fd);
+    return ret;  // most likely -1 with errno == EAGAIN, due to already held lock
+}
+
+inline int mapRetrieveLocklessRW(const char* pathname) {
+    return bpfFdGet(pathname, 0);
+}
+
+inline int mapRetrieveExclusiveRW(const char* pathname) {
+    return bpfLock(mapRetrieveLocklessRW(pathname), F_WRLCK);
+}
+
+inline int mapRetrieveRW(const char* pathname) {
+    return bpfLock(mapRetrieveLocklessRW(pathname), F_RDLCK);
+}
+
+inline int mapRetrieveRO(const char* pathname) {
+    return bpfFdGet(pathname, BPF_F_RDONLY);
+}
+
+// WARNING: it's impossible to grab a shared (ie. read) lock on a write-only fd,
+// so we instead choose to grab an exclusive (ie. write) lock.
+inline int mapRetrieveWO(const char* pathname) {
+    return bpfLock(bpfFdGet(pathname, BPF_F_WRONLY), F_WRLCK);
+}
+
+inline int retrieveProgram(const char* pathname) {
+    return bpfFdGet(pathname, BPF_F_RDONLY);
+}
+
+inline bool usableProgram(const char* pathname) {
+    int fd = retrieveProgram(pathname);
+    bool ok = (fd >= 0);
+    if (ok) close(fd);
+    return ok;
+}
+
+inline int attachProgram(bpf_attach_type type, const BPF_FD_TYPE prog_fd,
+                         const BPF_FD_TYPE cg_fd, uint32_t flags = 0) {
+    return bpf(BPF_PROG_ATTACH, {
+                                        .target_fd = BPF_FD_TO_U32(cg_fd),
+                                        .attach_bpf_fd = BPF_FD_TO_U32(prog_fd),
+                                        .attach_type = type,
+                                        .attach_flags = flags,
+                                });
+}
+
+inline int detachProgram(bpf_attach_type type, const BPF_FD_TYPE cg_fd) {
+    return bpf(BPF_PROG_DETACH, {
+                                        .target_fd = BPF_FD_TO_U32(cg_fd),
+                                        .attach_type = type,
+                                });
+}
+
+inline int queryProgram(const BPF_FD_TYPE cg_fd,
+                        enum bpf_attach_type attach_type,
+                        __u32 query_flags = 0,
+                        __u32 attach_flags = 0) {
+    int prog_id = -1;  // equivalent to an array of one integer.
+    bpf_attr arg = {
+            .query = {
+                    .target_fd = BPF_FD_TO_U32(cg_fd),
+                    .attach_type = attach_type,
+                    .query_flags = query_flags,
+                    .attach_flags = attach_flags,
+                    .prog_ids = ptr_to_u64(&prog_id),  // pointer to output array
+                    .prog_cnt = 1,  // in: space - nr of ints in the array, out: used
+            }
+    };
+    int v = bpf(BPF_PROG_QUERY, &arg);
+    if (v) return v;  // error case
+    if (!arg.query.prog_cnt) return 0;  // no program, kernel never returns zero id
+    return prog_id;  // return actual id
+}
+
+inline int detachSingleProgram(bpf_attach_type type, const BPF_FD_TYPE prog_fd,
+                               const BPF_FD_TYPE cg_fd) {
+    return bpf(BPF_PROG_DETACH, {
+                                        .target_fd = BPF_FD_TO_U32(cg_fd),
+                                        .attach_bpf_fd = BPF_FD_TO_U32(prog_fd),
+                                        .attach_type = type,
+                                });
+}
+
+// Available in 4.12 and later kernels.
+inline int runProgram(const BPF_FD_TYPE prog_fd, const void* data,
+                      const uint32_t data_size) {
+    return bpf(BPF_PROG_RUN, {
+                                     .test = {
+                                             .prog_fd = BPF_FD_TO_U32(prog_fd),
+                                             .data_size_in = data_size,
+                                             .data_in = ptr_to_u64(data),
+                                     },
+                             });
+}
+
+// BPF_OBJ_GET_INFO_BY_FD requires 4.14+ kernel
+//
+// Note: some fields are only defined in newer kernels (ie. the map_info struct grows
+// over time), so we need to check that the field we're interested in is actually
+// supported/returned by the running kernel.  We do this by checking it is fully
+// within the bounds of the struct size as reported by the kernel.
+#define DEFINE_BPF_GET_FD(TYPE, NAME, FIELD) \
+inline int bpfGetFd ## NAME(const BPF_FD_TYPE fd) { \
+    struct bpf_ ## TYPE ## _info info = {}; \
+    union bpf_attr attr = { .info = { \
+        .bpf_fd = BPF_FD_TO_U32(fd), \
+        .info_len = sizeof(info), \
+        .info = ptr_to_u64(&info), \
+    }}; \
+    int rv = bpf(BPF_OBJ_GET_INFO_BY_FD, attr); \
+    if (rv) return rv; \
+    if (attr.info.info_len < offsetof(bpf_ ## TYPE ## _info, FIELD) + sizeof(info.FIELD)) { \
+        errno = EOPNOTSUPP; \
+        return -1; \
+    }; \
+    return info.FIELD; \
+}
+
+// All 7 of these fields are already present in Linux v4.14 (even ACK 4.14-P)
+// while BPF_OBJ_GET_INFO_BY_FD is not implemented at all in v4.9 (even ACK 4.9-Q)
+DEFINE_BPF_GET_FD(map, MapType, type)            // int bpfGetFdMapType(const BPF_FD_TYPE map_fd)
+DEFINE_BPF_GET_FD(map, MapId, id)                // int bpfGetFdMapId(const BPF_FD_TYPE map_fd)
+DEFINE_BPF_GET_FD(map, KeySize, key_size)        // int bpfGetFdKeySize(const BPF_FD_TYPE map_fd)
+DEFINE_BPF_GET_FD(map, ValueSize, value_size)    // int bpfGetFdValueSize(const BPF_FD_TYPE map_fd)
+DEFINE_BPF_GET_FD(map, MaxEntries, max_entries)  // int bpfGetFdMaxEntries(const BPF_FD_TYPE map_fd)
+DEFINE_BPF_GET_FD(map, MapFlags, map_flags)      // int bpfGetFdMapFlags(const BPF_FD_TYPE map_fd)
+DEFINE_BPF_GET_FD(prog, ProgId, id)              // int bpfGetFdProgId(const BPF_FD_TYPE prog_fd)
+
+#undef DEFINE_BPF_GET_FD
+
+}  // namespace bpf
+}  // namespace android
+
+#undef BPF_FD_TO_U32
+#undef BPF_FD_TYPE
+#undef BPF_FD_JUST_USE_INT
diff --git a/src/bpf_progs/ProcessManagement.c b/src/bpf_progs/ProcessManagement.c
index b8623d6..7288642 100644
--- a/src/bpf_progs/ProcessManagement.c
+++ b/src/bpf_progs/ProcessManagement.c
@@ -22,7 +22,8 @@
 // TODO: import this struct from generic header, access registers via generic
 // function
 struct pt_regs {
-  unsigned long regs[16];
+  unsigned long regs[31];
+  unsigned long sp;
   unsigned long pc;
   unsigned long pr;
   unsigned long sr;
@@ -54,4 +55,87 @@ DEFINE_BPF_PROG("uprobe/set_uid_temp_allowlist_state", AID_UPROBESTATS,
   return 0;
 }
 
+struct jstring {
+  __u64 dummy;
+  __u32 count;
+  __u32 hash_code;
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
+DEFINE_BPF_RINGBUF_EXT(update_device_idle_temp_allowlist_records,
+                       struct UpdateDeviceIdleTempAllowlistRecord, 4096,
+                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
+                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
+                       LOAD_ON_USER, LOAD_ON_USERDEBUG);
+
+// Copies the string content of a Java String object located at <jstring> to
+// <dest>.
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
+// Copies the content of a Java String object to <dest>, where the Java String
+// is located at <position> in the method invocation argument list (0-based).
+// This only works for the 0th - the 5th arguments. Rest of the arguments need
+// to be accessed via stack pointer using the recordStringArgFromSp() function.
+void recordStringArg(struct pt_regs *ctx, unsigned int max_length, int position,
+                     char *dest) {
+  recordString((void *)ctx->regs[2 + position], max_length, dest);
+}
+
+// Copies the content of a Java String object to <dest>, where the Java String
+// address is located in stack frame.
+void recordStringArgFromSp(struct pt_regs *ctx, unsigned int max_length,
+                           int sp_offset, char *dest) {
+  void *jstring = NULL;
+  bpf_probe_read_user(&jstring, 4, (void *)ctx->sp + sp_offset);
+  recordString(jstring, max_length, dest);
+}
+
+DEFINE_BPF_PROG("uprobe/update_device_idle_temp_allowlist", AID_UPROBESTATS,
+                AID_UPROBESTATS, BPF_KPROBE3)
+(struct pt_regs *ctx) {
+  struct UpdateDeviceIdleTempAllowlistRecord *output =
+      bpf_update_device_idle_temp_allowlist_records_reserve();
+  if (output == NULL)
+    return 1;
+
+  // changing_uid is the 2nd argument, which is located in regs[3].
+  output->changing_uid = ctx->regs[3];
+  output->adding = ctx->regs[4];
+  output->duration_ms = ctx->regs[5];
+  output->type = ctx->regs[6];
+  output->reason_code = ctx->regs[7];
+
+  // The <reason> argument is located at offset=40 in stack frame. This is
+  // calculated as 12 + sizeof(previous arguments). There are 6 preceding
+  // arguments all of which is 4 bytes each except for <long durationMs> which
+  // is 8 bytes. Therefore the offset is 12 + 5 * 4 + 8 = 40
+  recordStringArgFromSp(ctx, 256, 40, output->reason);
+
+  // The <calling_uid> argument follows <reason> immediately and therefore has
+  // an offset that's 4 more bytes larger.
+  bpf_probe_read_user(&output->calling_uid, 4, (void *)ctx->sp + 44);
+
+  bpf_update_device_idle_temp_allowlist_records_submit(output);
+  return 0;
+}
+
 LICENSE("GPL");
diff --git a/src/bpfloader/Android.bp b/src/bpfloader/Android.bp
new file mode 100644
index 0000000..183ece7
--- /dev/null
+++ b/src/bpfloader/Android.bp
@@ -0,0 +1,25 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_performance",
+}
+
+cc_binary {
+    name: "uprobestatsbpfload",
+    srcs: ["UprobeStatsBpfLoad.cpp"],
+
+    defaults: ["bpf_cc_defaults"],
+    sanitize: {
+        integer_overflow: true,
+    },
+    header_libs: ["uprobestats_bpf_headers"],
+
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    apex_available: [
+        "com.android.uprobestats",
+    ],
+    min_sdk_version: "35",
+    installable: false,
+}
diff --git a/src/bpfloader/UprobeStatsBpfLoad.cpp b/src/bpfloader/UprobeStatsBpfLoad.cpp
new file mode 100644
index 0000000..f38e868
--- /dev/null
+++ b/src/bpfloader/UprobeStatsBpfLoad.cpp
@@ -0,0 +1,1104 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#define LOG_TAG "UprobeStatsBpfLoad"
+
+#include <errno.h>
+#include <fcntl.h>
+#include <linux/bpf.h>
+#include <linux/elf.h>
+#include <log/log.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/stat.h>
+#include <sys/utsname.h>
+#include <sys/wait.h>
+#include <sysexits.h>
+#include <unistd.h>
+
+#include "BpfSyscallWrappers.h"
+#include "bpf/BpfUtils.h"
+#include "bpf_map_def.h"
+
+#include <cstdlib>
+#include <fstream>
+#include <iostream>
+#include <optional>
+#include <string>
+#include <unordered_map>
+#include <vector>
+
+#include <android-base/cmsg.h>
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/strings.h>
+#include <android-base/unique_fd.h>
+
+#define BPF_FS_PATH "/sys/fs/bpf/"
+
+// Size of the BPF log buffer for verifier logging
+#define BPF_LOAD_LOG_SZ 0xfffff
+
+using android::base::EndsWith;
+using android::base::StartsWith;
+using android::base::unique_fd;
+using std::ifstream;
+using std::ios;
+using std::optional;
+using std::strerror;
+using std::string;
+using std::vector;
+
+namespace android {
+namespace bpf {
+
+static unsigned int page_size = static_cast<unsigned int>(getpagesize());
+
+static string pathToObjName(const string &path) {
+  // extract everything after the final slash, ie. this is the filename
+  // 'foo@1.o' or 'bar.o'
+  string filename = android::base::Split(path, "/").back();
+  // strip off everything from the final period onwards (strip '.o' suffix), ie.
+  // 'foo@1' or 'bar'
+  string name = filename.substr(0, filename.find_last_of('.'));
+  // strip any potential @1 suffix, this will leave us with just 'foo' or 'bar'
+  // this can be used to provide duplicate programs (mux based on the bpfloader
+  // version)
+  return name.substr(0, name.find_last_of('@'));
+}
+
+typedef struct {
+  const char *name;
+  enum bpf_prog_type type;
+} sectionType;
+
+/*
+ * Map section name prefixes to program types, the section name will be:
+ *   SECTION(<prefix>/<name-of-program>)
+ * For example:
+ *   SECTION("tracepoint/sched_switch_func") where sched_switch_funcs
+ * is the name of the program, and tracepoint is the type.
+ *
+ * However, be aware that you should not be directly using the SECTION() macro.
+ * Instead use the DEFINE_(BPF|XDP)_(PROG|MAP)... & LICENSE/CRITICAL macros.
+ */
+sectionType sectionNameTypes[] = {
+    {"kprobe/", BPF_PROG_TYPE_KPROBE},
+    {"kretprobe/", BPF_PROG_TYPE_KPROBE},
+    {"perf_event/", BPF_PROG_TYPE_PERF_EVENT},
+    {"skfilter/", BPF_PROG_TYPE_SOCKET_FILTER},
+    {"tracepoint/", BPF_PROG_TYPE_TRACEPOINT},
+    {"uprobe/", BPF_PROG_TYPE_KPROBE},
+    {"uretprobe/", BPF_PROG_TYPE_KPROBE},
+};
+
+typedef struct {
+  enum bpf_prog_type type;
+  string name;
+  vector<char> data;
+  vector<char> rel_data;
+  optional<struct bpf_prog_def> prog_def;
+
+  unique_fd prog_fd; /* fd after loading */
+} codeSection;
+
+static int readElfHeader(ifstream &elfFile, Elf64_Ehdr *eh) {
+  elfFile.seekg(0);
+  if (elfFile.fail())
+    return -1;
+
+  if (!elfFile.read((char *)eh, sizeof(*eh)))
+    return -1;
+
+  return 0;
+}
+
+/* Reads all section header tables into an Shdr array */
+static int readSectionHeadersAll(ifstream &elfFile,
+                                 vector<Elf64_Shdr> &shTable) {
+  Elf64_Ehdr eh;
+  int ret = 0;
+
+  ret = readElfHeader(elfFile, &eh);
+  if (ret)
+    return ret;
+
+  elfFile.seekg(eh.e_shoff);
+  if (elfFile.fail())
+    return -1;
+
+  /* Read shdr table entries */
+  shTable.resize(eh.e_shnum);
+
+  if (!elfFile.read((char *)shTable.data(), (eh.e_shnum * eh.e_shentsize)))
+    return -ENOMEM;
+
+  return 0;
+}
+
+/* Read a section by its index - for ex to get sec hdr strtab blob */
+static int readSectionByIdx(ifstream &elfFile, int id, vector<char> &sec) {
+  vector<Elf64_Shdr> shTable;
+  int ret = readSectionHeadersAll(elfFile, shTable);
+  if (ret)
+    return ret;
+
+  elfFile.seekg(shTable[id].sh_offset);
+  if (elfFile.fail())
+    return -1;
+
+  sec.resize(shTable[id].sh_size);
+  if (!elfFile.read(sec.data(), shTable[id].sh_size))
+    return -1;
+
+  return 0;
+}
+
+/* Read whole section header string table */
+static int readSectionHeaderStrtab(ifstream &elfFile, vector<char> &strtab) {
+  Elf64_Ehdr eh;
+  int ret = readElfHeader(elfFile, &eh);
+  if (ret)
+    return ret;
+
+  ret = readSectionByIdx(elfFile, eh.e_shstrndx, strtab);
+  if (ret)
+    return ret;
+
+  return 0;
+}
+
+/* Get name from offset in strtab */
+static int getSymName(ifstream &elfFile, int nameOff, string &name) {
+  int ret;
+  vector<char> secStrTab;
+
+  ret = readSectionHeaderStrtab(elfFile, secStrTab);
+  if (ret)
+    return ret;
+
+  if (nameOff >= (int)secStrTab.size())
+    return -1;
+
+  name = string((char *)secStrTab.data() + nameOff);
+  return 0;
+}
+
+/* Reads a full section by name - example to get the GPL license */
+static int readSectionByName(const char *name, ifstream &elfFile,
+                             vector<char> &data) {
+  vector<char> secStrTab;
+  vector<Elf64_Shdr> shTable;
+  int ret;
+
+  ret = readSectionHeadersAll(elfFile, shTable);
+  if (ret)
+    return ret;
+
+  ret = readSectionHeaderStrtab(elfFile, secStrTab);
+  if (ret)
+    return ret;
+
+  for (int i = 0; i < (int)shTable.size(); i++) {
+    char *secname = secStrTab.data() + shTable[i].sh_name;
+    if (!secname)
+      continue;
+
+    if (!strcmp(secname, name)) {
+      vector<char> dataTmp;
+      dataTmp.resize(shTable[i].sh_size);
+
+      elfFile.seekg(shTable[i].sh_offset);
+      if (elfFile.fail())
+        return -1;
+
+      if (!elfFile.read((char *)dataTmp.data(), shTable[i].sh_size))
+        return -1;
+
+      data = dataTmp;
+      return 0;
+    }
+  }
+  return -2;
+}
+
+unsigned int readSectionUint(const char *name, ifstream &elfFile,
+                             unsigned int defVal) {
+  vector<char> theBytes;
+  int ret = readSectionByName(name, elfFile, theBytes);
+  if (ret) {
+    ALOGV("Couldn't find section %s (defaulting to %u [0x%x]).", name, defVal,
+          defVal);
+    return defVal;
+  } else if (theBytes.size() < sizeof(unsigned int)) {
+    ALOGE("Section %s too short (defaulting to %u [0x%x]).", name, defVal,
+          defVal);
+    return defVal;
+  } else {
+    // decode first 4 bytes as LE32 uint, there will likely be more bytes due to
+    // alignment.
+    unsigned int value = static_cast<unsigned char>(theBytes[3]);
+    value <<= 8;
+    value += static_cast<unsigned char>(theBytes[2]);
+    value <<= 8;
+    value += static_cast<unsigned char>(theBytes[1]);
+    value <<= 8;
+    value += static_cast<unsigned char>(theBytes[0]);
+    ALOGV("Section %s value is %u [0x%x]", name, value, value);
+    return value;
+  }
+}
+
+static int readSectionByType(ifstream &elfFile, int type, vector<char> &data) {
+  int ret;
+  vector<Elf64_Shdr> shTable;
+
+  ret = readSectionHeadersAll(elfFile, shTable);
+  if (ret)
+    return ret;
+
+  for (int i = 0; i < (int)shTable.size(); i++) {
+    if ((int)shTable[i].sh_type != type)
+      continue;
+
+    vector<char> dataTmp;
+    dataTmp.resize(shTable[i].sh_size);
+
+    elfFile.seekg(shTable[i].sh_offset);
+    if (elfFile.fail())
+      return -1;
+
+    if (!elfFile.read((char *)dataTmp.data(), shTable[i].sh_size))
+      return -1;
+
+    data = dataTmp;
+    return 0;
+  }
+  return -2;
+}
+
+static bool symCompare(Elf64_Sym a, Elf64_Sym b) {
+  return (a.st_value < b.st_value);
+}
+
+static int readSymTab(ifstream &elfFile, int sort, vector<Elf64_Sym> &data) {
+  int ret, numElems;
+  Elf64_Sym *buf;
+  vector<char> secData;
+
+  ret = readSectionByType(elfFile, SHT_SYMTAB, secData);
+  if (ret)
+    return ret;
+
+  buf = (Elf64_Sym *)secData.data();
+  numElems = (secData.size() / sizeof(Elf64_Sym));
+  data.assign(buf, buf + numElems);
+
+  if (sort)
+    std::sort(data.begin(), data.end(), symCompare);
+  return 0;
+}
+
+static enum bpf_prog_type getFuseProgType() {
+  int result = BPF_PROG_TYPE_UNSPEC;
+  ifstream("/sys/fs/fuse/bpf_prog_type_fuse") >> result;
+  return static_cast<bpf_prog_type>(result);
+}
+
+static enum bpf_prog_type getSectionType(string &name) {
+  for (auto &snt : sectionNameTypes)
+    if (StartsWith(name, snt.name))
+      return snt.type;
+
+  // TODO Remove this code when fuse-bpf is upstream and this BPF_PROG_TYPE_FUSE
+  // is fixed
+  if (StartsWith(name, "fuse/"))
+    return getFuseProgType();
+
+  return BPF_PROG_TYPE_UNSPEC;
+}
+
+static string getSectionName(enum bpf_prog_type type) {
+  for (auto &snt : sectionNameTypes)
+    if (snt.type == type)
+      return string(snt.name);
+
+  return "UNKNOWN SECTION NAME " + std::to_string(type);
+}
+
+static int readProgDefs(ifstream &elfFile, vector<struct bpf_prog_def> &pd) {
+  vector<char> pdData;
+  int ret = readSectionByName("progs", elfFile, pdData);
+  if (ret)
+    return ret;
+
+  if (pdData.size() % sizeof(struct bpf_prog_def)) {
+    ALOGE("readProgDefs failed due to improper sized progs section, %zu %% %zu "
+          "!= 0",
+          pdData.size(), sizeof(struct bpf_prog_def));
+    return -1;
+  };
+
+  pd.resize(pdData.size() / sizeof(struct bpf_prog_def));
+  memcpy(pd.data(), pdData.data(), pdData.size());
+  return 0;
+}
+
+static int getSectionSymNames(ifstream &elfFile, const string &sectionName,
+                              vector<string> &names,
+                              optional<unsigned> symbolType = std::nullopt) {
+  int ret;
+  string name;
+  vector<Elf64_Sym> symtab;
+  vector<Elf64_Shdr> shTable;
+
+  ret = readSymTab(elfFile, 1 /* sort */, symtab);
+  if (ret)
+    return ret;
+
+  /* Get index of section */
+  ret = readSectionHeadersAll(elfFile, shTable);
+  if (ret)
+    return ret;
+
+  int sec_idx = -1;
+  for (int i = 0; i < (int)shTable.size(); i++) {
+    ret = getSymName(elfFile, shTable[i].sh_name, name);
+    if (ret)
+      return ret;
+
+    if (!name.compare(sectionName)) {
+      sec_idx = i;
+      break;
+    }
+  }
+
+  /* No section found with matching name*/
+  if (sec_idx == -1) {
+    ALOGW("No %s section could be found in elf object", sectionName.c_str());
+    return -1;
+  }
+
+  for (int i = 0; i < (int)symtab.size(); i++) {
+    if (symbolType.has_value() && ELF_ST_TYPE(symtab[i].st_info) != symbolType)
+      continue;
+
+    if (symtab[i].st_shndx == sec_idx) {
+      string s;
+      ret = getSymName(elfFile, symtab[i].st_name, s);
+      if (ret)
+        return ret;
+      names.push_back(s);
+    }
+  }
+
+  return 0;
+}
+
+static bool IsAllowed(bpf_prog_type type, const bpf_prog_type *allowed,
+                      size_t numAllowed) {
+  if (allowed == nullptr)
+    return true;
+
+  for (size_t i = 0; i < numAllowed; i++) {
+    if (allowed[i] == BPF_PROG_TYPE_UNSPEC) {
+      if (type == getFuseProgType())
+        return true;
+    } else if (type == allowed[i])
+      return true;
+  }
+
+  return false;
+}
+
+/* Read a section by its index - for ex to get sec hdr strtab blob */
+static int readCodeSections(ifstream &elfFile, vector<codeSection> &cs,
+                            const bpf_prog_type *allowed, size_t numAllowed) {
+  vector<Elf64_Shdr> shTable;
+  int entries, ret = 0;
+
+  ret = readSectionHeadersAll(elfFile, shTable);
+  if (ret)
+    return ret;
+  entries = shTable.size();
+
+  vector<struct bpf_prog_def> pd;
+  ret = readProgDefs(elfFile, pd);
+  if (ret)
+    return ret;
+  vector<string> progDefNames;
+  ret = getSectionSymNames(elfFile, "progs", progDefNames);
+  if (!pd.empty() && ret)
+    return ret;
+
+  for (int i = 0; i < entries; i++) {
+    string name;
+    codeSection cs_temp;
+    cs_temp.type = BPF_PROG_TYPE_UNSPEC;
+
+    ret = getSymName(elfFile, shTable[i].sh_name, name);
+    if (ret)
+      return ret;
+
+    enum bpf_prog_type ptype = getSectionType(name);
+
+    if (ptype == BPF_PROG_TYPE_UNSPEC)
+      continue;
+
+    if (!IsAllowed(ptype, allowed, numAllowed)) {
+      ALOGE("Program type %s not permitted here",
+            getSectionName(ptype).c_str());
+      return -1;
+    }
+
+    string oldName = name;
+
+    // convert all slashes to underscores
+    std::replace(name.begin(), name.end(), '/', '_');
+
+    cs_temp.type = ptype;
+    cs_temp.name = name;
+
+    ret = readSectionByIdx(elfFile, i, cs_temp.data);
+    if (ret)
+      return ret;
+    ALOGV("Loaded code section %d (%s)", i, name.c_str());
+
+    vector<string> csSymNames;
+    ret = getSectionSymNames(elfFile, oldName, csSymNames, STT_FUNC);
+    if (ret || !csSymNames.size())
+      return ret;
+    for (size_t i = 0; i < progDefNames.size(); ++i) {
+      if (!progDefNames[i].compare(csSymNames[0] + "_def")) {
+        cs_temp.prog_def = pd[i];
+        break;
+      }
+    }
+
+    /* Check for rel section */
+    if (cs_temp.data.size() > 0 && i < entries) {
+      ret = getSymName(elfFile, shTable[i + 1].sh_name, name);
+      if (ret)
+        return ret;
+
+      if (name == (".rel" + oldName)) {
+        ret = readSectionByIdx(elfFile, i + 1, cs_temp.rel_data);
+        if (ret)
+          return ret;
+        ALOGV("Loaded relo section %d (%s)", i, name.c_str());
+      }
+    }
+
+    if (cs_temp.data.size() > 0) {
+      cs.push_back(std::move(cs_temp));
+      ALOGV("Adding section %d to cs list", i);
+    }
+  }
+  return 0;
+}
+
+static int getSymNameByIdx(ifstream &elfFile, int index, string &name) {
+  vector<Elf64_Sym> symtab;
+  int ret = 0;
+
+  ret = readSymTab(elfFile, 0 /* !sort */, symtab);
+  if (ret)
+    return ret;
+
+  if (index >= (int)symtab.size())
+    return -1;
+
+  return getSymName(elfFile, symtab[index].st_name, name);
+}
+
+static bool mapMatchesExpectations(const unique_fd &fd, const string &mapName,
+                                   const struct bpf_map_def &mapDef,
+                                   const enum bpf_map_type type) {
+  // Assuming fd is a valid Bpf Map file descriptor then
+  // all the following should always succeed on a 4.14+ kernel.
+  // If they somehow do fail, they'll return -1 (and set errno),
+  // which should then cause (among others) a key_size mismatch.
+  int fd_type = bpfGetFdMapType(fd);
+  int fd_key_size = bpfGetFdKeySize(fd);
+  int fd_value_size = bpfGetFdValueSize(fd);
+  int fd_max_entries = bpfGetFdMaxEntries(fd);
+  int fd_map_flags = bpfGetFdMapFlags(fd);
+
+  // DEVMAPs are readonly from the bpf program side's point of view, as such
+  // the kernel in kernel/bpf/devmap.c dev_map_init_map() will set the flag
+  int desired_map_flags = (int)mapDef.map_flags;
+  if (type == BPF_MAP_TYPE_DEVMAP || type == BPF_MAP_TYPE_DEVMAP_HASH)
+    desired_map_flags |= BPF_F_RDONLY_PROG;
+
+  // The .h file enforces that this is a power of two, and page size will
+  // also always be a power of two, so this logic is actually enough to
+  // force it to be a multiple of the page size, as required by the kernel.
+  unsigned int desired_max_entries = mapDef.max_entries;
+  if (type == BPF_MAP_TYPE_RINGBUF) {
+    if (desired_max_entries < page_size)
+      desired_max_entries = page_size;
+  }
+
+  // The following checks should *never* trigger, if one of them somehow does,
+  // it probably means a bpf .o file has been changed/replaced at runtime
+  // and bpfloader was manually rerun (normally it should only run *once*
+  // early during the boot process).
+  // Another possibility is that something is misconfigured in the code:
+  // most likely a shared map is declared twice differently.
+  // But such a change should never be checked into the source tree...
+  if ((fd_type == type) && (fd_key_size == (int)mapDef.key_size) &&
+      (fd_value_size == (int)mapDef.value_size) &&
+      (fd_max_entries == (int)desired_max_entries) &&
+      (fd_map_flags == desired_map_flags)) {
+    return true;
+  }
+
+  ALOGE("bpf map name %s mismatch: desired/found: "
+        "type:%d/%d key:%u/%d value:%u/%d entries:%u/%d flags:%u/%d",
+        mapName.c_str(), type, fd_type, mapDef.key_size, fd_key_size,
+        mapDef.value_size, fd_value_size, mapDef.max_entries, fd_max_entries,
+        desired_map_flags, fd_map_flags);
+  return false;
+}
+
+static int createMaps(const char *elfPath, ifstream &elfFile,
+                      vector<unique_fd> &mapFds, const char *prefix) {
+  int ret;
+  vector<char> mdData;
+  vector<struct bpf_map_def> md;
+  vector<string> mapNames;
+  string objName = pathToObjName(string(elfPath));
+
+  ret = readSectionByName("maps", elfFile, mdData);
+  if (ret == -2)
+    return 0; // no maps to read
+  if (ret)
+    return ret;
+
+  if (mdData.size() % sizeof(struct bpf_map_def)) {
+    ALOGE(
+        "createMaps failed due to improper sized maps section, %zu %% %zu != 0",
+        mdData.size(), sizeof(struct bpf_map_def));
+    return -1;
+  }
+  md.resize(mdData.size() / sizeof(struct bpf_map_def));
+  memcpy(md.data(), mdData.data(), mdData.size());
+
+  ret = getSectionSymNames(elfFile, "maps", mapNames);
+  if (ret)
+    return ret;
+
+  unsigned kvers = kernelVersion();
+
+  for (int i = 0; i < (int)mapNames.size(); i++) {
+    if (md[i].zero != 0)
+      abort();
+
+    if (kvers < md[i].min_kver) {
+      ALOGD("skipping map %s which requires kernel version 0x%x >= 0x%x",
+            mapNames[i].c_str(), kvers, md[i].min_kver);
+      mapFds.push_back(unique_fd());
+      continue;
+    }
+
+    if (kvers >= md[i].max_kver) {
+      ALOGD("skipping map %s which requires kernel version 0x%x < 0x%x",
+            mapNames[i].c_str(), kvers, md[i].max_kver);
+      mapFds.push_back(unique_fd());
+      continue;
+    }
+
+    enum bpf_map_type type = md[i].type;
+    if (type == BPF_MAP_TYPE_DEVMAP_HASH && !isAtLeastKernelVersion(5, 4, 0)) {
+      // On Linux Kernels older than 5.4 this map type doesn't exist, but it can
+      // kind of be approximated: HASH has the same userspace visible api.
+      // However it cannot be used by ebpf programs in the same way.
+      // Since bpf_redirect_map() only requires 4.14, a program using a
+      // DEVMAP_HASH map would fail to load (due to trying to redirect to a HASH
+      // instead of DEVMAP_HASH). One must thus tag any BPF_MAP_TYPE_DEVMAP_HASH
+      // + bpf_redirect_map() using programs as being 5.4+...
+      type = BPF_MAP_TYPE_HASH;
+    }
+
+    // The .h file enforces that this is a power of two, and page size will
+    // also always be a power of two, so this logic is actually enough to
+    // force it to be a multiple of the page size, as required by the kernel.
+    unsigned int max_entries = md[i].max_entries;
+    if (type == BPF_MAP_TYPE_RINGBUF) {
+      if (max_entries < page_size)
+        max_entries = page_size;
+    }
+
+    // Format of pin location is /sys/fs/bpf/<prefix>map_<objName>_<mapName>
+    // except that maps shared across .o's have empty <objName>
+    // Note: <objName> refers to the extension-less basename of the .o file
+    // (without @ suffix).
+    string mapPinLoc = string(BPF_FS_PATH) + prefix + "map_" +
+                       (md[i].shared ? "" : objName) + "_" + mapNames[i];
+    bool reuse = false;
+    unique_fd fd;
+    int saved_errno;
+
+    if (access(mapPinLoc.c_str(), F_OK) == 0) {
+      fd.reset(mapRetrieveRO(mapPinLoc.c_str()));
+      saved_errno = errno;
+      ALOGV("bpf_create_map reusing map %s, ret: %d", mapNames[i].c_str(),
+            fd.get());
+      reuse = true;
+    } else {
+      union bpf_attr req = {
+          .map_type = type,
+          .key_size = md[i].key_size,
+          .value_size = md[i].value_size,
+          .max_entries = max_entries,
+          .map_flags = md[i].map_flags,
+      };
+      strlcpy(req.map_name, mapNames[i].c_str(), sizeof(req.map_name));
+      fd.reset(bpf(BPF_MAP_CREATE, req));
+      saved_errno = errno;
+      ALOGV("bpf_create_map name %s, ret: %d", mapNames[i].c_str(), fd.get());
+    }
+
+    if (!fd.ok())
+      return -saved_errno;
+
+    // When reusing a pinned map, we need to check the map type/sizes/etc match,
+    // but for safety (since reuse code path is rare) run these checks even if
+    // we just created it. We assume failure is due to pinned map mismatch,
+    // hence the 'NOT UNIQUE' return code.
+    if (!mapMatchesExpectations(fd, mapNames[i], md[i], type))
+      return -ENOTUNIQ;
+
+    if (!reuse) {
+      ret = bpfFdPin(fd, mapPinLoc.c_str());
+      if (ret) {
+        int err = errno;
+        ALOGE("pin %s -> %d [%d:%s]", mapPinLoc.c_str(), ret, err,
+              strerror(err));
+        return -err;
+      }
+      ret = chmod(mapPinLoc.c_str(), md[i].mode);
+      if (ret) {
+        int err = errno;
+        ALOGE("chmod(%s, 0%o) = %d [%d:%s]", mapPinLoc.c_str(), md[i].mode, ret,
+              err, strerror(err));
+        return -err;
+      }
+      ret = chown(mapPinLoc.c_str(), (uid_t)md[i].uid, (gid_t)md[i].gid);
+      if (ret) {
+        int err = errno;
+        ALOGE("chown(%s, %u, %u) = %d [%d:%s]", mapPinLoc.c_str(), md[i].uid,
+              md[i].gid, ret, err, strerror(err));
+        return -err;
+      }
+    }
+
+    int mapId = bpfGetFdMapId(fd);
+    if (mapId == -1) {
+      ALOGE("bpfGetFdMapId failed, ret: %d [%d]", mapId, errno);
+    } else {
+      ALOGD("map %s id %d", mapPinLoc.c_str(), mapId);
+    }
+
+    mapFds.push_back(std::move(fd));
+  }
+
+  return ret;
+}
+
+static void applyRelo(void *insnsPtr, Elf64_Addr offset, int fd) {
+  int insnIndex;
+  struct bpf_insn *insn, *insns;
+
+  insns = (struct bpf_insn *)(insnsPtr);
+
+  insnIndex = offset / sizeof(struct bpf_insn);
+  insn = &insns[insnIndex];
+
+  // Occasionally might be useful for relocation debugging, but pretty spammy
+  if (0) {
+    ALOGV("applying relo to instruction at byte offset: %llu, "
+          "insn offset %d, insn %llx",
+          (unsigned long long)offset, insnIndex, *(unsigned long long *)insn);
+  }
+
+  if (insn->code != (BPF_LD | BPF_IMM | BPF_DW)) {
+    ALOGE("invalid relo for insn %d: code 0x%x", insnIndex, insn->code);
+    return;
+  }
+
+  insn->imm = fd;
+  insn->src_reg = BPF_PSEUDO_MAP_FD;
+}
+
+static void applyMapRelo(ifstream &elfFile, vector<unique_fd> &mapFds,
+                         vector<codeSection> &cs) {
+  vector<string> mapNames;
+
+  int ret = getSectionSymNames(elfFile, "maps", mapNames);
+  if (ret)
+    return;
+
+  for (int k = 0; k != (int)cs.size(); k++) {
+    Elf64_Rel *rel = (Elf64_Rel *)(cs[k].rel_data.data());
+    int n_rel = cs[k].rel_data.size() / sizeof(*rel);
+
+    for (int i = 0; i < n_rel; i++) {
+      int symIndex = ELF64_R_SYM(rel[i].r_info);
+      string symName;
+
+      ret = getSymNameByIdx(elfFile, symIndex, symName);
+      if (ret)
+        return;
+
+      /* Find the map fd and apply relo */
+      for (int j = 0; j < (int)mapNames.size(); j++) {
+        if (!mapNames[j].compare(symName)) {
+          applyRelo(cs[k].data.data(), rel[i].r_offset, mapFds[j]);
+          break;
+        }
+      }
+    }
+  }
+}
+
+static int loadCodeSections(const char *elfPath, vector<codeSection> &cs,
+                            const string &license, const char *prefix) {
+  unsigned kvers = kernelVersion();
+
+  if (!kvers) {
+    ALOGE("unable to get kernel version");
+    return -EINVAL;
+  }
+
+  string objName = pathToObjName(string(elfPath));
+
+  for (int i = 0; i < (int)cs.size(); i++) {
+    unique_fd &fd = cs[i].prog_fd;
+    int ret;
+    string name = cs[i].name;
+
+    if (!cs[i].prog_def.has_value()) {
+      ALOGE("[%d] '%s' missing program definition! bad bpf.o build?", i,
+            name.c_str());
+      return -EINVAL;
+    }
+
+    unsigned min_kver = cs[i].prog_def->min_kver;
+    unsigned max_kver = cs[i].prog_def->max_kver;
+    if (kvers < min_kver || kvers >= max_kver) {
+      ALOGD(
+          "skipping program cs[%d].name:%s min_kver:%x max_kver:%x (kvers:%x)",
+          i, name.c_str(), min_kver, max_kver, kvers);
+      continue;
+    }
+
+    // strip any potential $foo suffix
+    // this can be used to provide duplicate programs
+    // conditionally loaded based on running kernel version
+    name = name.substr(0, name.find_last_of('$'));
+
+    bool reuse = false;
+    // Format of pin location is
+    // /sys/fs/bpf/<prefix>prog_<objName>_<progName>
+    string progPinLoc =
+        string(BPF_FS_PATH) + prefix + "prog_" + objName + '_' + string(name);
+    if (access(progPinLoc.c_str(), F_OK) == 0) {
+      fd.reset(retrieveProgram(progPinLoc.c_str()));
+      ALOGV("New bpf prog load reusing prog %s, ret: %d (%s)",
+            progPinLoc.c_str(), fd.get(),
+            (!fd.ok() ? std::strerror(errno) : "no error"));
+      reuse = true;
+    } else {
+      vector<char> log_buf(BPF_LOAD_LOG_SZ, 0);
+
+      union bpf_attr req = {
+          .prog_type = cs[i].type,
+          .kern_version = kvers,
+          .license = ptr_to_u64(license.c_str()),
+          .insns = ptr_to_u64(cs[i].data.data()),
+          .insn_cnt =
+              static_cast<__u32>(cs[i].data.size() / sizeof(struct bpf_insn)),
+          .log_level = 1,
+          .log_buf = ptr_to_u64(log_buf.data()),
+          .log_size = static_cast<__u32>(log_buf.size()),
+      };
+      strlcpy(req.prog_name, cs[i].name.c_str(), sizeof(req.prog_name));
+      fd.reset(bpf(BPF_PROG_LOAD, req));
+
+      if (!fd.ok()) {
+        ALOGW("BPF_PROG_LOAD call for %s (%s) returned fd: %d (%s)", elfPath,
+              cs[i].name.c_str(), fd.get(), std::strerror(errno));
+
+        vector<string> lines = android::base::Split(log_buf.data(), "\n");
+
+        ALOGW("BPF_PROG_LOAD - BEGIN log_buf contents:");
+        for (const auto &line : lines)
+          ALOGW("%s", line.c_str());
+        ALOGW("BPF_PROG_LOAD - END log_buf contents.");
+
+        if (cs[i].prog_def->optional) {
+          ALOGW("failed program is marked optional - continuing...");
+          continue;
+        }
+        ALOGE("non-optional program failed to load.");
+      }
+    }
+
+    if (!fd.ok())
+      return fd.get();
+
+    if (!reuse) {
+      ret = bpfFdPin(fd, progPinLoc.c_str());
+      if (ret) {
+        int err = errno;
+        ALOGE("create %s -> %d [%d:%s]", progPinLoc.c_str(), ret, err,
+              strerror(err));
+        return -err;
+      }
+      if (chmod(progPinLoc.c_str(), 0440)) {
+        int err = errno;
+        ALOGE("chmod %s 0440 -> [%d:%s]", progPinLoc.c_str(), err,
+              strerror(err));
+        return -err;
+      }
+      if (chown(progPinLoc.c_str(), (uid_t)cs[i].prog_def->uid,
+                (gid_t)cs[i].prog_def->gid)) {
+        int err = errno;
+        ALOGE("chown %s %d %d -> [%d:%s]", progPinLoc.c_str(),
+              cs[i].prog_def->uid, cs[i].prog_def->gid, err, strerror(err));
+        return -err;
+      }
+    }
+
+    int progId = bpfGetFdProgId(fd);
+    if (progId == -1) {
+      ALOGE("bpfGetFdProgId failed, ret: %d [%d]", progId, errno);
+    } else {
+      ALOGD("prog %s id %d", progPinLoc.c_str(), progId);
+    }
+  }
+
+  return 0;
+}
+
+struct Location {
+  const char *const dir = "";
+  const char *const prefix = "";
+  const bpf_prog_type *allowedProgTypes = nullptr;
+  size_t allowedProgTypesLength = 0;
+};
+
+int loadProg(const char *elfPath, bool *isCritical, const Location &location) {
+  vector<char> license;
+  vector<char> critical;
+  vector<codeSection> cs;
+  vector<unique_fd> mapFds;
+  int ret;
+
+  if (!isCritical)
+    return -1;
+  *isCritical = false;
+
+  ifstream elfFile(elfPath, ios::in | ios::binary);
+  if (!elfFile.is_open())
+    return -1;
+
+  ret = readSectionByName("critical", elfFile, critical);
+  *isCritical = !ret;
+
+  ret = readSectionByName("license", elfFile, license);
+  if (ret) {
+    ALOGE("Couldn't find license in %s", elfPath);
+    return ret;
+  }
+
+  ALOGI("UprobeStatsBpfLoad loading %s%s ELF object %s with license %s",
+        *isCritical ? "critical for " : "optional",
+        *isCritical ? (char *)critical.data() : "", elfPath,
+        (char *)license.data());
+
+  ret = readCodeSections(elfFile, cs, location.allowedProgTypes,
+                         location.allowedProgTypesLength);
+  if (ret) {
+    ALOGE("Couldn't read all code sections in %s", elfPath);
+    return ret;
+  }
+
+  ret = createMaps(elfPath, elfFile, mapFds, location.prefix);
+  if (ret) {
+    ALOGE("Failed to create maps: (ret=%d) in %s", ret, elfPath);
+    return ret;
+  }
+
+  for (int i = 0; i < (int)mapFds.size(); i++)
+    ALOGV("map_fd found at %d is %d in %s", i, mapFds[i].get(), elfPath);
+
+  applyMapRelo(elfFile, mapFds, cs);
+
+  ret = loadCodeSections(elfPath, cs, string(license.data()), location.prefix);
+  if (ret)
+    ALOGE("Failed to load programs, loadCodeSections ret=%d", ret);
+
+  return ret;
+}
+
+// Networking-related program types are limited to the Tethering Apex
+// to prevent things from breaking due to conflicts on mainline updates
+// (exception made for socket filters, ie. xt_bpf for potential use in iptables,
+// or for attaching to sockets directly)
+constexpr bpf_prog_type kPlatformAllowedProgTypes[] = {
+    BPF_PROG_TYPE_KPROBE,        BPF_PROG_TYPE_PERF_EVENT,
+    BPF_PROG_TYPE_SOCKET_FILTER, BPF_PROG_TYPE_TRACEPOINT,
+    BPF_PROG_TYPE_UNSPEC, // Will be replaced with fuse bpf program type
+};
+
+constexpr bpf_prog_type kMemEventsAllowedProgTypes[] = {
+    BPF_PROG_TYPE_TRACEPOINT,
+    BPF_PROG_TYPE_SOCKET_FILTER,
+};
+
+constexpr bpf_prog_type kUprobestatsAllowedProgTypes[] = {
+    BPF_PROG_TYPE_KPROBE,
+};
+
+// see b/162057235. For arbitrary program types, the concern is that due to the
+// lack of SELinux access controls over BPF program attachpoints, we have no way
+// to control the attachment of programs to shared resources (or to detect when
+// a shared resource has one BPF program replace another that is attached there)
+constexpr bpf_prog_type kVendorAllowedProgTypes[] = {
+    BPF_PROG_TYPE_SOCKET_FILTER,
+};
+
+const Location locations[] = {
+    // uprobestats
+    {
+        .dir = "/apex/com.android.uprobestats/etc/bpf/uprobestats/",
+        .prefix = "uprobestats/",
+        .allowedProgTypes = kUprobestatsAllowedProgTypes,
+        .allowedProgTypesLength = arraysize(kUprobestatsAllowedProgTypes),
+    },
+};
+
+int loadAllElfObjects(const Location &location) {
+  int retVal = 0;
+  DIR *dir;
+  struct dirent *ent;
+
+  if ((dir = opendir(location.dir)) != NULL) {
+    while ((ent = readdir(dir)) != NULL) {
+      string s = ent->d_name;
+      if (!EndsWith(s, ".o"))
+        continue;
+
+      string progPath(location.dir);
+      progPath += s;
+
+      bool critical;
+      int ret = loadProg(progPath.c_str(), &critical, location);
+      if (ret) {
+        if (critical)
+          retVal = ret;
+        ALOGE("Failed to load object: %s, ret: %s", progPath.c_str(),
+              strerror(-ret));
+      } else {
+        ALOGV("Loaded object: %s", progPath.c_str());
+      }
+    }
+    closedir(dir);
+  }
+  return retVal;
+}
+
+int createSysFsBpfSubDir(const char *const prefix) {
+  if (*prefix) {
+    mode_t prevUmask = umask(0);
+
+    string s = "/sys/fs/bpf/";
+    s += prefix;
+
+    errno = 0;
+    int ret = mkdir(s.c_str(), S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);
+    if (ret && errno != EEXIST) {
+      const int err = errno;
+      ALOGE("Failed to create directory: %s, ret: %s", s.c_str(),
+            strerror(err));
+      return -err;
+    }
+
+    umask(prevUmask);
+  }
+  return 0;
+}
+
+} // namespace bpf
+} // namespace android
+
+// ----- extern C stuff for rust below here -----
+
+void initLogging() {
+  // since we only ever get called from mainline NetBpfLoad
+  // (see packages/modules/Connectivity/netbpfload/NetBpfLoad.cpp around line
+  // 516) and there no arguments, so we can just pretend/assume this is the
+  // case.
+  const char *argv[] = {"/system/bin/bpfloader", NULL};
+  android::base::InitLogging(const_cast<char **>(argv),
+                             &android::base::KernelLogger);
+}
+
+bool createBpfFsSubDirectories() {
+  for (const auto &location : android::bpf::locations) {
+    if (android::bpf::createSysFsBpfSubDir(location.prefix)) {
+      ALOGE("=== Failed to create subdir %s ===", location.prefix);
+      return true;
+    }
+  }
+  return false;
+}
+
+void legacyBpfLoader() {
+  // Load all ELF objects, create programs and maps, and pin them
+  for (const auto &location : android::bpf::locations) {
+    if (android::bpf::loadAllElfObjects(location)) {
+      ALOGE("=== FAILURE LOADING BPF PROGRAMS FROM %s ===", location.dir);
+    }
+  }
+}
+
+void load() {
+  if (createBpfFsSubDirectories()) {
+    return;
+  }
+  legacyBpfLoader();
+}
+
+const char *const platformBpfLoader = "/system/bin/bpfloader";
+
+int main(int, char **, char *const envp[]) {
+  initLogging();
+  load();
+
+  const char *args[] = {
+      platformBpfLoader,
+      NULL,
+  };
+  execve(args[0], (char **)args, envp);
+  ALOGE("FATAL: execve('%s'): %d[%s]", platformBpfLoader, errno,
+        strerror(errno));
+  return 1;
+}
diff --git a/src/config.proto b/src/config.proto
index 7ffcd09..79e532e 100644
--- a/src/config.proto
+++ b/src/config.proto
@@ -23,11 +23,24 @@ message UprobestatsConfig {
       // re-compiled by ART and stored in a different location. uprobestats
       // would try to place the probe on each of the paths in the order
       // specified here until the probe is successfully placed.
+      // Superseded by `fully_qualified_class_name`, `method_name`, and `fully_qualified_parameters`.
       repeated string file_paths = 2;
 
       // Full method signature. E.g.
       // void android.content.pm.PackageManagerInternal.finishPackageInstall(int, boolean)
+      // Superseded by `fully_qualified_class_name`, `method_name`, and `fully_qualified_parameters`.
       optional string method_signature = 3;
+
+      // Fully qualified class name of the method being targeted. E.g.
+      // "android.content.pm.PackageManagerInternal"
+      // Supersedes `file_paths` and `method_signature`
+      optional string fully_qualified_class_name = 4;
+      // Method name of the method being targeted. E.g. "finishPackageInstall"
+      // Supersedes `file_paths` and `method_signature`
+      optional string method_name = 5;
+      // Fully qualified parameters list of the method being targeted. E.g. ["int", "boolean"]
+      // Supersedes `file_paths` and `method_signature`
+      repeated string fully_qualified_parameters = 6;
     }
 
     repeated ProbeConfig probe_configs = 1;
diff --git a/src/flag.aconfig b/src/flag.aconfig
index 3a05449..7895996 100644
--- a/src/flag.aconfig
+++ b/src/flag.aconfig
@@ -8,3 +8,19 @@ flag {
     bug: "296108553"
     is_fixed_read_only: true
 }
+
+flag {
+    name: "uprobestats_support_update_device_idle_temp_allowlist"
+    namespace: "system_performance"
+    description: "Whether to enable uprobestats support of logging update_device_idle_temp_allowlist."
+    bug: "296108553"
+    is_fixed_read_only: true
+}
+
+flag {
+    name: "executable_method_file_offsets"
+    namespace: "system_performance"
+    bug: "296108553"
+    description: "Whether the ART executable method file offsets API is available. Mirrors identical flag in com.android.art."
+    is_fixed_read_only: true
+}
diff --git a/src/lib/Android.bp b/src/lib/Android.bp
index 574066a..8ddac2c 100644
--- a/src/lib/Android.bp
+++ b/src/lib/Android.bp
@@ -12,38 +12,51 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-cc_library_shared {
-    name: "libuprobestats_client",
+soong_config_module_type {
+    name: "libuprobestats_client_cc_library_shared",
+    module_type: "cc_library_shared",
+    config_namespace: "ANDROID",
+    bool_variables: [
+        "release_uprobestats_module",
+    ],
+    properties: [
+        "stubs",
+        "min_sdk_version",
+        "apex_available",
+    ],
+}
+
+soong_config_bool_variable {
+    name: "release_uprobestats_module",
+}
 
+libuprobestats_client_cc_library_shared {
+    name: "libuprobestats_client",
+    soong_config_variables: {
+        release_uprobestats_module: {
+            stubs: {
+                symbol_file: "libcom.android.uprobestats.client.map.txt",
+            },
+            min_sdk_version: "35",
+            apex_available: [
+                "com.android.uprobestats",
+            ],
+            conditions_default: {
+                stubs: {
+                    symbol_file: "libuprobestats_client.map.txt",
+                    versions: ["35"],
+                },
+            },
+        },
+    },
     cflags: [
         "-Wall",
         "-Werror",
         "-Wno-enum-compare",
         "-Wno-unused-function",
     ],
-
-    shared_libs: [
-        "libbase",
-    ],
-
-    srcs: [
-        "uprobestats_client.cpp",
-    ],
-
-    export_include_dirs: [
-        "include",
-    ],
-
-    stubs: {
-        symbol_file: "libuprobestats_client.map.txt",
-        versions: ["35"],
-    },
-
-    header_libs: [
-        "libcutils_headers",
-    ],
-
-    ldflags: [
-        "-Wl,-rpath,/system/${LIB}",
-    ],
+    srcs: ["uprobestats_client.cpp"],
+    shared_libs: ["libbase"],
+    export_include_dirs: ["include"],
+    header_libs: ["libcutils_headers"],
 }
diff --git a/src/lib/libcom.android.uprobestats.client.map.txt b/src/lib/libcom.android.uprobestats.client.map.txt
new file mode 100644
index 0000000..c25ebbf
--- /dev/null
+++ b/src/lib/libcom.android.uprobestats.client.map.txt
@@ -0,0 +1,6 @@
+LIBUPROBESTATS_CLIENT {
+  global:
+    AUprobestatsClient_startUprobestats; # apex
+  local:
+    *;
+};
diff --git a/src/lib/uprobestats_client.cpp b/src/lib/uprobestats_client.cpp
index 69da019..cd97524 100644
--- a/src/lib/uprobestats_client.cpp
+++ b/src/lib/uprobestats_client.cpp
@@ -26,5 +26,5 @@ void AUprobestatsClient_startUprobestats(const uint8_t* config, int64_t size) {
     android::base::WriteStringToFile(
             std::string(reinterpret_cast<const char*>(config), size), filename);
     chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
-    android::base::SetProperty("uprobestats.start_with_config", "config");
+    android::base::SetProperty("ctl.start", "uprobestats");
 }
diff --git a/src/mainline-flag.aconfig b/src/mainline-flag.aconfig
new file mode 100644
index 0000000..2b334d8
--- /dev/null
+++ b/src/mainline-flag.aconfig
@@ -0,0 +1,26 @@
+package: "android.uprobestats.mainline.flags"
+container: "com.android.uprobestats"
+
+flag {
+    name: "enable_uprobestats"
+    namespace: "system_performance"
+    description: "Whether to enable uprobestats."
+    bug: "296108553"
+    is_fixed_read_only: true
+}
+
+flag {
+    name: "uprobestats_support_update_device_idle_temp_allowlist"
+    namespace: "system_performance"
+    description: "Whether to enable uprobestats support of logging update_device_idle_temp_allowlist."
+    bug: "296108553"
+    is_fixed_read_only: true
+}
+
+flag {
+    name: "executable_method_file_offsets"
+    namespace: "system_performance"
+    bug: "296108553"
+    description: "Whether the ART executable method file offsets API is available. Mirrors identical flag in com.android.art."
+    is_fixed_read_only: true
+}
diff --git a/src/test/SmokeTest.java b/src/test/SmokeTest.java
index eb56018..e26d166 100644
--- a/src/test/SmokeTest.java
+++ b/src/test/SmokeTest.java
@@ -16,24 +16,42 @@
 
 package test;
 
+import static android.uprobestats.flags.Flags.FLAG_ENABLE_UPROBESTATS;
+import static android.uprobestats.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS;
+
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assume.assumeTrue;
+
 import android.cts.statsdatom.lib.AtomTestUtils;
 import android.cts.statsdatom.lib.ConfigUtils;
 import android.cts.statsdatom.lib.DeviceUtils;
 import android.cts.statsdatom.lib.ReportUtils;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.host.HostFlagsValueProvider;
 
+import com.android.compatibility.common.util.CpuFeatures;
 import com.android.internal.os.StatsdConfigProto;
 import com.android.os.StatsLog;
+import com.android.os.framework.FrameworkExtensionAtoms;
+import com.android.os.framework.FrameworkExtensionAtoms.DeviceIdleTempAllowlistUpdated;
 import com.android.os.uprobestats.TestUprobeStatsAtomReported;
 import com.android.os.uprobestats.UprobestatsExtensionAtoms;
 import com.android.tradefed.device.ITestDevice;
-import com.android.tradefed.testtype.DeviceTestCase;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.tradefed.util.RunUtil;
 
 import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.TextFormat;
 
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
 import uprobestats.protos.Config.UprobestatsConfig;
 
 import java.io.File;
@@ -41,25 +59,41 @@ import java.nio.file.Files;
 import java.util.List;
 import java.util.Scanner;
 
-public class SmokeTest extends DeviceTestCase {
-
-    private static final String BATTERY_STATS_CONFIG = "test_bss_setBatteryState.textproto";
-    private static final String CONFIG_NAME = "test";
-    private static final String CMD_SETPROP_UPROBESTATS = "setprop uprobestats.start_with_config ";
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class SmokeTest extends BaseHostJUnit4Test {
+
+    private static final String BATTERY_STATS_CONFIG_OATDUMP =
+            "test_bss_setBatteryState_oatdump.textproto";
+    private static final String BATTERY_STATS_CONFIG_ART =
+            "test_bss_setBatteryState_artApi.textproto";
+    private static final String TEMP_ALLOWLIST_CONFIG =
+            "test_updateDeviceIdleTempAllowlist.textproto";
+    private static final String CONFIG_NAME = "config";
+    private static final String CMD_SETPROP_UPROBESTATS = "setprop ctl.start uprobestats";
     private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";
 
-    @Override
-    protected void setUp() throws Exception {
+    private ExtensionRegistry mRegistry;
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);
+
+    @Before
+    public void setUp() throws Exception {
         ConfigUtils.removeConfig(getDevice());
         ReportUtils.clearReports(getDevice());
         getDevice().deleteFile(CONFIG_DIR + CONFIG_NAME);
         RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+        getDevice().executeShellCommand("killall uprobestats");
+        mRegistry = ExtensionRegistry.newInstance();
+        UprobestatsExtensionAtoms.registerAllExtensions(mRegistry);
+        FrameworkExtensionAtoms.registerAllExtensions(mRegistry);
     }
 
-    public void testBatteryStats() throws Exception {
+    void startUprobeStats(String textprotoFilename, int atomId) throws Exception {
         // 1. Parse config from resources
         String textProto =
-                new Scanner(this.getClass().getResourceAsStream(BATTERY_STATS_CONFIG))
+                new Scanner(this.getClass().getResourceAsStream(textprotoFilename))
                         .useDelimiter("\\A")
                         .next();
         UprobestatsConfig.Builder builder = UprobestatsConfig.newBuilder();
@@ -68,28 +102,48 @@ public class SmokeTest extends DeviceTestCase {
 
         // 2. Write config to a file and drop it on the device
         File tmp = File.createTempFile("uprobestats", CONFIG_NAME);
-        assertTrue(tmp.setWritable(true));
+        assertThat(tmp.setWritable(true)).isTrue();
         Files.write(tmp.toPath(), config.toByteArray());
         ITestDevice device = getDevice();
-        assertTrue(getDevice().enableAdbRoot());
-        assertTrue(getDevice().pushFile(tmp, CONFIG_DIR + CONFIG_NAME));
+        assertThat(getDevice().enableAdbRoot()).isTrue();
+        assertThat(getDevice().pushFile(tmp, CONFIG_DIR + CONFIG_NAME)).isTrue();
 
         // 3. Configure StatsD
-        ExtensionRegistry registry = ExtensionRegistry.newInstance();
-        UprobestatsExtensionAtoms.registerAllExtensions(registry);
         StatsdConfigProto.StatsdConfig.Builder configBuilder =
                 ConfigUtils.createConfigBuilder("AID_UPROBESTATS");
-        ConfigUtils.addEventMetric(
-                configBuilder,
-                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);
+        ConfigUtils.addEventMetric(configBuilder, atomId);
         ConfigUtils.uploadConfig(getDevice(), configBuilder);
 
         // 4. Start UprobeStats
-        device.executeShellCommand(CMD_SETPROP_UPROBESTATS + CONFIG_NAME);
+        device.executeShellCommand(CMD_SETPROP_UPROBESTATS);
         // Allow UprobeStats time to attach probe
         RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+    }
+
+    @Test
+    @RequiresFlagsDisabled(FLAG_EXECUTABLE_METHOD_FILE_OFFSETS)
+    @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
+    public void batteryStats_oatdump() throws Exception {
+        batteryStats(BATTERY_STATS_CONFIG_OATDUMP);
+    }
+
+    @Test
+    @RequiresFlagsEnabled({FLAG_ENABLE_UPROBESTATS, FLAG_EXECUTABLE_METHOD_FILE_OFFSETS})
+    public void batteryStats_artApi() throws Exception {
+        batteryStats(BATTERY_STATS_CONFIG_ART);
+    }
+
+    @Test
+    @RequiresFlagsEnabled({FLAG_ENABLE_UPROBESTATS, FLAG_EXECUTABLE_METHOD_FILE_OFFSETS})
+    public void batteryStats_oatdump_fallback() throws Exception {
+        batteryStats(BATTERY_STATS_CONFIG_OATDUMP);
+    }
+
+    private void batteryStats(String config) throws Exception {
+        startUprobeStats(
+                config, UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);
 
-        // 5. Set charging state, which should invoke BatteryStatsService#setBatteryState.
+        // Set charging state, which should invoke BatteryStatsService#setBatteryState.
         // Assumptions:
         //   - uprobestats flag is enabled
         //   - userdebug build
@@ -99,9 +153,9 @@ public class SmokeTest extends DeviceTestCase {
         // Allow UprobeStats/StatsD time to collect metric
         RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
 
-        // 6. See if the atom made it
+        // See if the atom made it
         List<StatsLog.EventMetricData> data =
-                ReportUtils.getEventMetricDataList(getDevice(), registry);
+                ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
         assertThat(data.size()).isEqualTo(1);
         TestUprobeStatsAtomReported reported =
                 data.get(0)
@@ -111,4 +165,28 @@ public class SmokeTest extends DeviceTestCase {
         assertThat(reported.getSecondField()).isGreaterThan(0);
         assertThat(reported.getThirdField()).isEqualTo(0);
     }
+
+    @Test
+    @RequiresFlagsEnabled(FLAG_ENABLE_UPROBESTATS)
+    public void updateDeviceIdleTempAllowlist() throws Exception {
+        assumeTrue(CpuFeatures.isArm64(getDevice()));
+        startUprobeStats(
+                TEMP_ALLOWLIST_CONFIG,
+                FrameworkExtensionAtoms.DEVICE_IDLE_TEMP_ALLOWLIST_UPDATED_FIELD_NUMBER);
+
+        // Set tempallowlist
+        getDevice().executeShellCommand("cmd deviceidle tempwhitelist com.google.android.tts");
+        // Allow UprobeStats/StatsD time to collect metric
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+
+        // See if the atom made it
+        List<StatsLog.EventMetricData> data =
+                ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
+        assertThat(data.size()).isEqualTo(1);
+        DeviceIdleTempAllowlistUpdated reported =
+                data.get(0)
+                        .getAtom()
+                        .getExtension(FrameworkExtensionAtoms.deviceIdleTempAllowlistUpdated);
+        assertThat(reported.getReason()).isEqualTo("shell");
+    }
 }
diff --git a/src/test/test_bss_setBatteryState_artApi.textproto b/src/test/test_bss_setBatteryState_artApi.textproto
new file mode 100644
index 0000000..ac5c671
--- /dev/null
+++ b/src/test/test_bss_setBatteryState_artApi.textproto
@@ -0,0 +1,17 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs {
+        bpf_name: "prog_GenericInstrumentation_uprobe_call_timestamp_1"
+        fully_qualified_class_name: "com.android.server.am.BatteryStatsService"
+        method_name: "setBatteryState"
+        fully_qualified_parameters: ["int", "int", "int", "int", "int", "int", "int", "int", "long"]
+    }
+    bpf_maps: "map_GenericInstrumentation_call_timestamp_buf"
+    target_process_name: "system_server"
+    duration_seconds: 60
+    statsd_logging_config {
+        atom_id: 915
+    }
+}
diff --git a/src/test/test_bss_setBatteryState.textproto b/src/test/test_bss_setBatteryState_oatdump.textproto
similarity index 100%
rename from src/test/test_bss_setBatteryState.textproto
rename to src/test/test_bss_setBatteryState_oatdump.textproto
diff --git a/src/test/test_updateDeviceIdleTempAllowlist.textproto b/src/test/test_updateDeviceIdleTempAllowlist.textproto
new file mode 100644
index 0000000..dc4a9f1
--- /dev/null
+++ b/src/test/test_updateDeviceIdleTempAllowlist.textproto
@@ -0,0 +1,16 @@
+# proto-file: config.proto
+# proto-message: UprobestatsConfig
+
+tasks {
+    probe_configs: {
+        bpf_name: "prog_ProcessManagement_uprobe_update_device_idle_temp_allowlist"
+        file_paths: "/system/framework/oat/arm64/services.odex"
+        method_signature: "void com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist(int[], int, boolean, long, int, int, java.lang.String, int)"
+    }
+    bpf_maps: "map_ProcessManagement_update_device_idle_temp_allowlist_records"
+    target_process_name: "system_server"
+    duration_seconds: 180
+    statsd_logging_config {
+      atom_id: 940
+    }
+}
```

