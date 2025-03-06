```diff
diff --git a/Android.bp b/Android.bp
index 20a2098e..0b4fefb8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -49,18 +49,30 @@ license {
     ],
 }
 
-cc_defaults {
-    name: "recovery_defaults",
-
-    cflags: [
-        "-D_FILE_OFFSET_BITS=64",
+soong_config_module_type {
+    name: "recovery_cc_defaults",
+    module_type: "cc_defaults",
+    config_namespace: "recovery",
+    value_variables: ["recovery_api_version"],
+    properties: [
+        "cflags",
+    ],
+}
 
-        // Must be the same as RECOVERY_API_VERSION.
-        "-DRECOVERY_API_VERSION=3",
+recovery_cc_defaults {
+    name: "recovery_defaults",
 
-        "-Wall",
-        "-Werror",
-    ],
+    soong_config_variables: {
+        recovery_api_version: {
+            cflags: [
+                "-D_FILE_OFFSET_BITS=64",
+                // Must be the same as RECOVERY_API_VERSION.
+                "-DRECOVERY_API_VERSION=%s",
+                "-Wall",
+                "-Werror",
+            ],
+        },
+    },
 }
 
 cc_library_static {
@@ -164,7 +176,7 @@ cc_binary {
     ],
 
     shared_libs: [
-        "android.hardware.health-V3-ndk", // from librecovery_utils
+        "android.hardware.health-V4-ndk", // from librecovery_utils
         "android.hardware.boot-V1-ndk",
         "librecovery_ui",
     ],
@@ -245,3 +257,56 @@ filegroup {
         "res-*/images/*_text.png",
     ],
 }
+
+// recovery_deps: A phony target that's depended on by `recovery`, which
+// builds additional modules conditionally based on Makefile variables.
+phony {
+    name: "recovery_deps",
+    recovery: true,
+    required: [
+        "mkfs.erofs.recovery",
+        "dump.erofs.recovery",
+        "fsck.erofs.recovery",
+        // On A/B devices recovery-persist reads the recovery related file from the persist storage and
+        // copies them into /data/misc/recovery. Then, for both A/B and non-A/B devices, recovery-persist
+        // parses the last_install file and reports the embedded update metrics. Also, the last_install file
+        // will be deteleted after the report.
+        "recovery-persist",
+    ] + select(soong_config_variable("recovery", "target_userimages_use_f2fs"), {
+        true: [
+            "make_f2fs.recovery",
+            "fsck.f2fs.recovery",
+            "sload_f2fs.recovery",
+        ],
+        default: [],
+    }) + select(soong_config_variable("recovery", "has_board_cacheimage_partition_size"), {
+        false: ["recovery-refresh"],
+        default: [],
+    }),
+}
+
+cc_library_shared {
+    name: "librecovery_ui_ext",
+    recovery: true,
+    install_in_root: true,
+    multilib: {
+        lib32: {
+            relative_install_path: "system/lib",
+        },
+        lib64: {
+            relative_install_path: "system/lib64",
+        },
+    },
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "librecovery_ui",
+    ],
+    // TARGET_RECOVERY_UI_LIB should be one of librecovery_ui_{default,wear,vr,ethernet} or a
+    // device-specific module that defines make_device() and the exact RecoveryUI class for the
+    // target. It defaults to librecovery_ui_default, which uses ScreenRecoveryUI.
+    whole_static_libs: select(soong_config_variable("recovery", "target_recovery_ui_lib"), {
+        any @ libs: libs,
+        default: ["librecovery_ui_default"],
+    }),
+}
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index 85c3a901..00000000
--- a/Android.mk
+++ /dev/null
@@ -1,87 +0,0 @@
-# Copyright (C) 2007 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-LOCAL_PATH := $(call my-dir)
-
-# Needed by build/make/core/Makefile. Must be consistent with the value in Android.bp.
-RECOVERY_API_VERSION := 3
-RECOVERY_FSTAB_VERSION := 2
-
-# TARGET_RECOVERY_UI_LIB should be one of librecovery_ui_{default,wear,vr,ethernet} or a
-# device-specific module that defines make_device() and the exact RecoveryUI class for the
-# target. It defaults to librecovery_ui_default, which uses ScreenRecoveryUI.
-TARGET_RECOVERY_UI_LIB ?= librecovery_ui_default
-
-# librecovery_ui_ext (shared library)
-# ===================================
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := librecovery_ui_ext
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-MIT SPDX-license-identifier-OFL
-LOCAL_LICENSE_CONDITIONS := by_exception_only notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-
-# LOCAL_MODULE_PATH for shared libraries is unsupported in multiarch builds.
-LOCAL_MULTILIB := first
-
-ifeq ($(TARGET_IS_64_BIT),true)
-LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/lib64
-else
-LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/lib
-endif
-
-LOCAL_WHOLE_STATIC_LIBRARIES := \
-    $(TARGET_RECOVERY_UI_LIB)
-
-LOCAL_SHARED_LIBRARIES := \
-    libbase.recovery \
-    libboot_control_client.recovery \
-    liblog.recovery \
-    librecovery_ui.recovery
-
-include $(BUILD_SHARED_LIBRARY)
-
-# recovery_deps: A phony target that's depended on by `recovery`, which
-# builds additional modules conditionally based on Makefile variables.
-# ======================================================================
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := recovery_deps
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-MIT SPDX-license-identifier-OFL
-LOCAL_LICENSE_CONDITIONS := by_exception_only notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-
-ifeq ($(TARGET_USERIMAGES_USE_F2FS),true)
-LOCAL_REQUIRED_MODULES += \
-    make_f2fs.recovery \
-    fsck.f2fs.recovery \
-    sload_f2fs.recovery
-endif
-
-LOCAL_REQUIRED_MODULES += \
-    mkfs.erofs.recovery \
-    dump.erofs.recovery \
-    fsck.erofs.recovery
-
-# On A/B devices recovery-persist reads the recovery related file from the persist storage and
-# copies them into /data/misc/recovery. Then, for both A/B and non-A/B devices, recovery-persist
-# parses the last_install file and reports the embedded update metrics. Also, the last_install file
-# will be deteleted after the report.
-LOCAL_REQUIRED_MODULES += recovery-persist
-ifeq ($(BOARD_CACHEIMAGE_PARTITION_SIZE),)
-LOCAL_REQUIRED_MODULES += recovery-refresh
-endif
-
-include $(BUILD_PHONY_PACKAGE)
-
diff --git a/bootloader_message/Android.bp b/bootloader_message/Android.bp
index dcb6c3c2..383152ab 100644
--- a/bootloader_message/Android.bp
+++ b/bootloader_message/Android.bp
@@ -58,6 +58,7 @@ cc_library {
     recovery_available: true,
     vendor_available: true,
     host_supported: true,
+    ramdisk_available: true,
 
     target: {
         host: {
diff --git a/minadbd/Android.bp b/minadbd/Android.bp
index 91407f98..4f5bf357 100644
--- a/minadbd/Android.bp
+++ b/minadbd/Android.bp
@@ -98,7 +98,7 @@ cc_binary {
     ],
 
     shared_libs: [
-        "android.hardware.health-V3-ndk", // from librecovery_utils
+        "android.hardware.health-V4-ndk", // from librecovery_utils
         "libbase",
         "libcrypto",
     ],
@@ -130,7 +130,7 @@ cc_test {
     ],
 
     static_libs: [
-        "android.hardware.health-V3-ndk", // from librecovery_utils
+        "android.hardware.health-V4-ndk", // from librecovery_utils
         "libminadbd_services",
         "libfusesideload",
         "librecovery_utils",
diff --git a/recovery.cpp b/recovery.cpp
index fbfe6468..7dd005f7 100644
--- a/recovery.cpp
+++ b/recovery.cpp
@@ -187,6 +187,7 @@ static InstallResult prompt_and_wipe_data(Device* device) {
     "If you continue to get this message, you may need to "
     "perform a factory data reset and erase all user data "
     "stored on this device.",
+    "Reason: " + device->GetReason().value_or(""),
   };
   // clang-format off
   std::vector<std::string> wipe_data_menu_items {
diff --git a/recovery_utils/Android.bp b/recovery_utils/Android.bp
index a48ce002..00f34fdf 100644
--- a/recovery_utils/Android.bp
+++ b/recovery_utils/Android.bp
@@ -75,11 +75,11 @@ cc_library_static {
 
     shared_libs: [
         // The following cannot be placed in librecovery_utils_defaults,
-        // because at the time of writing, android.hardware.health-V3-ndk.so
+        // because at the time of writing, android.hardware.health-V4-ndk.so
         // is not installed to the system image yet. (It is installed
         // to the recovery ramdisk.) Hence, minadbd_test must link to it
         // statically.
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
     ],
 
     export_include_dirs: [
@@ -98,6 +98,6 @@ cc_library_static {
         "//bootable/recovery/install",
         "//bootable/recovery/minadbd",
         "//bootable/recovery/tests",
-		"//bootable/deprecated-ota:__subpackages__",
+        "//bootable/deprecated-ota:__subpackages__",
     ],
 }
diff --git a/res-hdpi/Android.bp b/res-hdpi/Android.bp
new file mode 100644
index 00000000..0cf3a5ba
--- /dev/null
+++ b/res-hdpi/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+//
+
+prebuilt_res {
+    name: "recovery-resources-common-hdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "images/*.png",
+    ],
+    no_full_install: true,
+}
diff --git a/res-mdpi/Android.bp b/res-mdpi/Android.bp
new file mode 100644
index 00000000..efdbbe1c
--- /dev/null
+++ b/res-mdpi/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+//
+
+prebuilt_res {
+    name: "recovery-resources-common-mdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "images/*.png",
+    ],
+    no_full_install: true,
+}
diff --git a/res-xhdpi/Android.bp b/res-xhdpi/Android.bp
new file mode 100644
index 00000000..cdddc5d1
--- /dev/null
+++ b/res-xhdpi/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+//
+
+prebuilt_res {
+    name: "recovery-resources-common-xhdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "images/*.png",
+    ],
+    no_full_install: true,
+}
diff --git a/res-xxhdpi/Android.bp b/res-xxhdpi/Android.bp
new file mode 100644
index 00000000..f1608b3f
--- /dev/null
+++ b/res-xxhdpi/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+//
+
+prebuilt_res {
+    name: "recovery-resources-common-xxhdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "images/*.png",
+    ],
+    no_full_install: true,
+}
diff --git a/res-xxxhdpi/Android.bp b/res-xxxhdpi/Android.bp
new file mode 100644
index 00000000..6e062692
--- /dev/null
+++ b/res-xxxhdpi/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+//
+
+prebuilt_res {
+    name: "recovery-resources-common-xxxhdpi",
+    recovery: true,
+    install_in_root: true,
+    relative_install_path: "images",
+    srcs: [
+        "images/*.png",
+    ],
+    no_full_install: true,
+}
diff --git a/tests/Android.bp b/tests/Android.bp
index 99f6a8de..b8991b01 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -121,7 +121,7 @@ cc_test {
 
     static_libs: librecovery_static_libs + [
         "android.hardware.health-translate-ndk",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libhealthshim",
         "librecovery_ui",
         "libfusesideload",
```

