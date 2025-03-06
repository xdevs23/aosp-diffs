```diff
diff --git a/libril/Android.bp b/libril/Android.bp
new file mode 100644
index 0000000..1a8cbec
--- /dev/null
+++ b/libril/Android.bp
@@ -0,0 +1,80 @@
+// Copyright (C) 2006 The Android Open Source Project
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_ril_libril_license",
+    ],
+}
+
+license {
+    name: "hardware_ril_libril_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_library_shared {
+    name: "libril",
+    vendor: true,
+    srcs: [
+        "ril.cpp",
+        "ril_event.cpp",
+        "ril_service.cpp",
+        "RilSapSocket.cpp",
+        "sap_service.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.radio@1.0",
+        "android.hardware.radio@1.1",
+        "libcutils",
+        "libhardware_legacy",
+        "libhidlbase",
+        "liblog",
+        "librilutils",
+        "libutils",
+    ],
+    static_libs: ["libprotobuf-c-nano-enable_malloc-32bit"],
+    cflags: [
+        "-Wall",
+        "-Wextra",
+        "-Wno-unused-parameter",
+        "-Werror",
+        "-DPB_FIELD_32BIT",
+    ] + select(soong_config_variable("ril", "sim_count"), {
+        "2": [
+            "-DANDROID_MULTI_SIM",
+            "-DDSDA_RILD1",
+            "-DANDROID_SIM_COUNT_2",
+        ],
+        default: [],
+    }) + select(soong_config_variable("ril", "disable_rild_oem_hook"), {
+        true: [
+            "-DOEM_HOOK_DISABLED",
+        ],
+        default: [],
+    }),
+    include_dirs: ["external/nanopb-c"],
+    header_libs: [
+        "ril_headers",
+    ],
+    sanitize: {
+        misc_undefined: ["integer"],
+    },
+}
diff --git a/libril/Android.mk b/libril/Android.mk
deleted file mode 100644
index 12b58cf..0000000
--- a/libril/Android.mk
+++ /dev/null
@@ -1,50 +0,0 @@
-# Copyright 2006 The Android Open Source Project
-
-LOCAL_PATH:= $(call my-dir)
-include $(CLEAR_VARS)
-
-LOCAL_VENDOR_MODULE := true
-
-LOCAL_SRC_FILES:= \
-    ril.cpp \
-    ril_event.cpp\
-    RilSapSocket.cpp \
-    ril_service.cpp \
-    sap_service.cpp
-
-LOCAL_SHARED_LIBRARIES := \
-    liblog \
-    libutils \
-    libcutils \
-    libhardware_legacy \
-    librilutils \
-    android.hardware.radio@1.0 \
-    android.hardware.radio@1.1 \
-    libhidlbase \
-
-LOCAL_STATIC_LIBRARIES := \
-    libprotobuf-c-nano-enable_malloc-32bit \
-
-LOCAL_CFLAGS += -Wall -Wextra -Wno-unused-parameter -Werror
-LOCAL_CFLAGS += -DPB_FIELD_32BIT
-
-ifeq ($(SIM_COUNT), 2)
-    LOCAL_CFLAGS += -DANDROID_MULTI_SIM -DDSDA_RILD1
-    LOCAL_CFLAGS += -DANDROID_SIM_COUNT_2
-endif
-
-ifneq ($(DISABLE_RILD_OEM_HOOK),)
-    LOCAL_CFLAGS += -DOEM_HOOK_DISABLED
-endif
-
-LOCAL_C_INCLUDES += external/nanopb-c
-LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include
-LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../include
-
-LOCAL_MODULE:= libril
-LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS:= notice
-LOCAL_NOTICE_FILE:= $(LOCAL_PATH)/NOTICE
-LOCAL_SANITIZE := integer
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/reference-ril/Android.bp b/reference-ril/Android.bp
new file mode 100644
index 0000000..9abd997
--- /dev/null
+++ b/reference-ril/Android.bp
@@ -0,0 +1,59 @@
+// Copyright (C) 2006 The Android Open Source Project
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_ril_reference-ril_license",
+    ],
+}
+
+license {
+    name: "hardware_ril_reference-ril_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_library_shared {
+    name: "libreference-ril",
+    srcs: [
+        "reference-ril.c",
+        "atchannel.c",
+        "misc.c",
+        "at_tok.c",
+    ],
+    shared_libs: [
+        "liblog",
+        "libcutils",
+        "libutils",
+        "libril",
+        "librilutils",
+    ],
+    static_libs: ["libbase"],
+    cflags: [
+        "-D_GNU_SOURCE", // for asprinf
+        "-Wall",
+        "-Wextra",
+        "-Wno-unused-variable",
+        "-Wno-unused-function",
+        "-Werror",
+        "-DRIL_SHLIB",
+    ],
+    vendor: true,
+}
diff --git a/reference-ril/Android.mk b/reference-ril/Android.mk
deleted file mode 100644
index 8aeba23..0000000
--- a/reference-ril/Android.mk
+++ /dev/null
@@ -1,58 +0,0 @@
-# Copyright 2006 The Android Open Source Project
-
-# XXX using libutils for simulator build only...
-#
-LOCAL_PATH:= $(call my-dir)
-include $(CLEAR_VARS)
-
-LOCAL_SRC_FILES:= \
-    reference-ril.c \
-    atchannel.c \
-    misc.c \
-    at_tok.c
-
-LOCAL_SHARED_LIBRARIES := \
-    liblog libcutils libutils libril librilutils
-
-LOCAL_STATIC_LIBRARIES := libbase
-
-# for asprinf
-LOCAL_CFLAGS := -D_GNU_SOURCE
-LOCAL_CFLAGS += -Wall -Wextra -Wno-unused-variable -Wno-unused-function -Werror
-
-LOCAL_C_INCLUDES :=
-
-ifeq ($(TARGET_DEVICE),sooner)
-  LOCAL_CFLAGS += -DUSE_TI_COMMANDS
-endif
-
-ifeq ($(TARGET_DEVICE),surf)
-  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
-endif
-
-ifeq ($(TARGET_DEVICE),dream)
-  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
-endif
-
-LOCAL_VENDOR_MODULE:= true
-
-ifeq (foo,foo)
-  #build shared library
-  LOCAL_SHARED_LIBRARIES += \
-      libcutils libutils
-  LOCAL_CFLAGS += -DRIL_SHLIB
-  LOCAL_MODULE:= libreference-ril
-  LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0
-  LOCAL_LICENSE_CONDITIONS:= notice
-  LOCAL_NOTICE_FILE:= $(LOCAL_PATH)/NOTICE
-  include $(BUILD_SHARED_LIBRARY)
-else
-  #build executable
-  LOCAL_SHARED_LIBRARIES += \
-      libril
-  LOCAL_MODULE:= reference-ril
-  LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0
-  LOCAL_LICENSE_CONDITIONS:= notice
-  LOCAL_NOTICE_FILE:= $(LOCAL_PATH)/NOTICE
-  include $(BUILD_EXECUTABLE)
-endif
diff --git a/rild/Android.bp b/rild/Android.bp
new file mode 100644
index 0000000..8a14786
--- /dev/null
+++ b/rild/Android.bp
@@ -0,0 +1,66 @@
+// Copyright (C) 2006 The Android Open Source Project
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_ril_rild_license",
+    ],
+}
+
+license {
+    name: "hardware_ril_rild_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_binary {
+    name: "rild",
+    srcs: ["rild.c"],
+
+    shared_libs: [
+        "libcutils",
+        "libdl",
+        "liblog",
+        "libril",
+    ],
+
+    // Temporary hack for broken vendor RILs.
+    whole_static_libs: ["librilutils"],
+    cflags: [
+        "-DRIL_SHLIB",
+        "-Wall",
+        "-Wextra",
+        "-Werror",
+        "-DPRODUCT_COMPATIBLE_PROPERTY",
+    ] + select(soong_config_variable("ril", "sim_count"), {
+        "2": [
+            "-DANDROID_MULTI_SIM",
+            "-DANDROID_SIM_COUNT_2",
+        ],
+        default: [],
+    }),
+    relative_install_path: "hw",
+    proprietary: true,
+    init_rc: ["rild.rc"],
+    enabled: select(soong_config_variable("ril", "use_aosp_rild"), {
+        true: true,
+        default: false,
+    }),
+}
diff --git a/rild/Android.mk b/rild/Android.mk
deleted file mode 100644
index d1c1b95..0000000
--- a/rild/Android.mk
+++ /dev/null
@@ -1,44 +0,0 @@
-# Copyright 2006 The Android Open Source Project
-
-ifndef ENABLE_VENDOR_RIL_SERVICE
-
-LOCAL_PATH:= $(call my-dir)
-include $(CLEAR_VARS)
-
-LOCAL_SRC_FILES:= \
-	rild.c
-
-LOCAL_SHARED_LIBRARIES := \
-	libcutils \
-	libdl \
-	liblog \
-	libril
-
-# Temporary hack for broken vendor RILs.
-LOCAL_WHOLE_STATIC_LIBRARIES := \
-	librilutils
-
-LOCAL_CFLAGS := -DRIL_SHLIB
-LOCAL_CFLAGS += -Wall -Wextra -Werror
-
-ifeq ($(SIM_COUNT), 2)
-    LOCAL_CFLAGS += -DANDROID_MULTI_SIM
-    LOCAL_CFLAGS += -DANDROID_SIM_COUNT_2
-endif
-
-LOCAL_MODULE_RELATIVE_PATH := hw
-LOCAL_PROPRIETARY_MODULE := true
-LOCAL_MODULE:= rild
-LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS:= notice
-LOCAL_NOTICE_FILE:= $(LOCAL_PATH)/NOTICE
-ifeq ($(PRODUCT_COMPATIBLE_PROPERTY),true)
-LOCAL_INIT_RC := rild.rc
-LOCAL_CFLAGS += -DPRODUCT_COMPATIBLE_PROPERTY
-else
-LOCAL_INIT_RC := rild.legacy.rc
-endif
-
-include $(BUILD_EXECUTABLE)
-
-endif
```

