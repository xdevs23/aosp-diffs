```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 7193d26..40aac18 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -25,12 +25,7 @@
       "name": "hidl_test"
     },
     {
-       "name": "CtsOsTestCases",
-       "options": [
-           {
-              "include-filter": "android.os.cts.HwBinderTest"
-           }
-       ]
+      "name": "CtsOsTestCases_cts_hwbindertest"
     }
   ]
 }
diff --git a/transport/allocator/1.0/default/Android.bp b/transport/allocator/1.0/default/Android.bp
index d739cd8..7389a96 100644
--- a/transport/allocator/1.0/default/Android.bp
+++ b/transport/allocator/1.0/default/Android.bp
@@ -21,16 +21,22 @@ package {
     default_applicable_licenses: ["system_libhidl_license"],
 }
 
+vintf_fragment {
+    name: "android.hidl.allocator@1.0-service.xml",
+    src: "android.hidl.allocator@1.0-service.xml",
+    system_ext_specific: true,
+}
+
 cc_binary {
     name: "android.hidl.allocator@1.0-service",
     relative_install_path: "hw",
     defaults: ["libhidl-defaults"],
     srcs: [
         "AshmemAllocator.cpp",
-        "service.cpp"
+        "service.cpp",
     ],
     init_rc: ["android.hidl.allocator@1.0-service.rc"],
-    vintf_fragments: ["android.hidl.allocator@1.0-service.xml"],
+    vintf_fragment_modules: ["android.hidl.allocator@1.0-service.xml"],
     system_ext_specific: true,
 
     shared_libs: [
diff --git a/vintfdata/Android.bp b/vintfdata/Android.bp
new file mode 100644
index 0000000..cde04fb
--- /dev/null
+++ b/vintfdata/Android.bp
@@ -0,0 +1,60 @@
+// Copyright 2018 Google Inc. All rights reserved.
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
+package {
+    default_applicable_licenses: ["system_libhidl_license"],
+}
+
+vintf_data {
+    name: "vendor_compatibility_matrix.xml",
+    type: "device_cm",
+    filename: "compatibility_matrix.xml",
+    vendor: true,
+}
+
+vintf_data {
+    name: "system_manifest.xml",
+    type: "system_manifest",
+    filename: "manifest.xml",
+}
+
+vintf_data {
+    name: "product_manifest.xml",
+    type: "product_manifest",
+    filename: "manifest.xml",
+    product_specific: true,
+}
+
+vintf_data {
+    name: "system_ext_manifest.xml",
+    type: "system_ext_manifest",
+    filename: "manifest.xml",
+    system_ext_specific: true,
+}
+
+// Device Manifest
+vintf_data {
+    name: "vendor_manifest.xml",
+    type: "vendor_manifest",
+    filename: "manifest.xml",
+    vendor: true,
+}
+
+// Odm Manifest
+vintf_data {
+    name: "odm_manifest.xml",
+    type: "odm_manifest",
+    filename: "manifest.xml",
+    device_specific: true,
+}
diff --git a/vintfdata/Android.mk b/vintfdata/Android.mk
deleted file mode 100644
index ed8f506..0000000
--- a/vintfdata/Android.mk
+++ /dev/null
@@ -1,152 +0,0 @@
-#
-# Copyright (C) 2018 The Android Open Source Project
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
-#
-
-LOCAL_PATH := $(call my-dir)
-
-# DEVICE_FRAMEWORK_MANIFEST_FILE is a device-specific framework manifest file
-# that installed to the system image. HALs entries should be written to
-# DEVICE_FRAMEWORK_MANIFEST_FILE or PRODUCT_MANIFEST_FILES depend on the path of
-# the module. It is recommended that such device-specific modules to be
-# installed on product partition.
-
-SYSTEM_MANIFEST_INPUT_FILES := $(LOCAL_PATH)/manifest.xml
-ifdef DEVICE_FRAMEWORK_MANIFEST_FILE
-  SYSTEM_MANIFEST_INPUT_FILES += $(DEVICE_FRAMEWORK_MANIFEST_FILE)
-endif
-
-SYSTEM_EXT_MANIFEST_INPUT_FILES := $(LOCAL_PATH)/system_ext_manifest.default.xml
-
-ifeq ($(PRODUCT_HIDL_ENABLED),true)
-ifneq ($(filter hwservicemanager,$(PRODUCT_PACKAGES)),)
-SYSTEM_EXT_MANIFEST_INPUT_FILES += $(TOPDIR)system/hwservicemanager/hwservicemanager_no_max.xml
-else
-$(error If PRODUCT_HIDL_ENABLED is set, hwservicemanager must be added to PRODUCT_PACKAGES explicitly)
-endif
-else
-ifneq ($(filter hwservicemanager,$(PRODUCT_PACKAGES)),)
-SYSTEM_EXT_MANIFEST_INPUT_FILES += $(TOPDIR)system/hwservicemanager/hwservicemanager.xml
-else ifneq ($(filter hwservicemanager,$(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34)),)
-SYSTEM_EXT_MANIFEST_INPUT_FILES += $(TOPDIR)system/hwservicemanager/hwservicemanager.xml
-endif
-endif
-
-ifdef SYSTEM_EXT_MANIFEST_FILES
-  SYSTEM_EXT_MANIFEST_INPUT_FILES += $(SYSTEM_EXT_MANIFEST_FILES)
-endif
-
-# Device Compatibility Matrix
-ifdef DEVICE_MATRIX_FILE
-DEVICE_MATRIX_INPUT_FILE := $(DEVICE_MATRIX_FILE)
-else
-DEVICE_MATRIX_INPUT_FILE := $(LOCAL_PATH)/device_compatibility_matrix.default.xml
-endif
-
-include $(CLEAR_VARS)
-LOCAL_MODULE        := vendor_compatibility_matrix.xml
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE   := $(LOCAL_PATH)/../NOTICE
-LOCAL_MODULE_STEM   := compatibility_matrix.xml
-LOCAL_MODULE_CLASS  := ETC
-LOCAL_MODULE_PATH   := $(TARGET_OUT_VENDOR)/etc/vintf
-
-GEN := $(local-generated-sources-dir)/compatibility_matrix.xml
-
-$(GEN): PRIVATE_DEVICE_MATRIX_INPUT_FILE := $(DEVICE_MATRIX_INPUT_FILE)
-
-$(GEN): $(DEVICE_MATRIX_INPUT_FILE) $(HOST_OUT_EXECUTABLES)/assemble_vintf
-	BOARD_SYSTEMSDK_VERSIONS="$(BOARD_SYSTEMSDK_VERSIONS)" \
-		$(HOST_OUT_EXECUTABLES)/assemble_vintf \
-		-i $(call normalize-path-list,$(PRIVATE_DEVICE_MATRIX_INPUT_FILE)) \
-		-o $@
-
-LOCAL_PREBUILT_MODULE_FILE := $(GEN)
-include $(BUILD_PREBUILT)
-
-# System Manifest
-include $(CLEAR_VARS)
-LOCAL_MODULE        := system_manifest.xml
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE   := $(LOCAL_PATH)/../NOTICE
-LOCAL_MODULE_STEM   := manifest.xml
-LOCAL_MODULE_CLASS  := ETC
-LOCAL_MODULE_PATH   := $(TARGET_OUT)/etc/vintf
-
-GEN := $(local-generated-sources-dir)/manifest.xml
-
-$(GEN): PRIVATE_SYSTEM_MANIFEST_INPUT_FILES := $(SYSTEM_MANIFEST_INPUT_FILES)
-$(GEN): $(SYSTEM_MANIFEST_INPUT_FILES) $(HOST_OUT_EXECUTABLES)/assemble_vintf
-	PLATFORM_SYSTEMSDK_VERSIONS="$(PLATFORM_SYSTEMSDK_VERSIONS)" \
-		$(HOST_OUT_EXECUTABLES)/assemble_vintf \
-		-i $(call normalize-path-list,$(PRIVATE_SYSTEM_MANIFEST_INPUT_FILES)) \
-		-o $@
-
-LOCAL_PREBUILT_MODULE_FILE := $(GEN)
-include $(BUILD_PREBUILT)
-
-# Product Manifest
-ifneq ($(PRODUCT_MANIFEST_FILES),)
-include $(CLEAR_VARS)
-LOCAL_MODULE := product_manifest.xml
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../NOTICE
-LOCAL_MODULE_STEM := manifest.xml
-LOCAL_MODULE_CLASS := ETC
-LOCAL_PRODUCT_MODULE := true
-LOCAL_MODULE_RELATIVE_PATH := vintf
-GEN := $(local-generated-sources-dir)/manifest.xml
-$(GEN): PRIVATE_PRODUCT_MANIFEST_FILES := $(PRODUCT_MANIFEST_FILES)
-$(GEN): $(PRODUCT_MANIFEST_FILES) $(HOST_OUT_EXECUTABLES)/assemble_vintf
-	$(HOST_OUT_EXECUTABLES)/assemble_vintf \
-		-i $(call normalize-path-list,$(PRIVATE_PRODUCT_MANIFEST_FILES)) \
-		-o $@
-
-LOCAL_PREBUILT_MODULE_FILE := $(GEN)
-include $(BUILD_PREBUILT)
-endif
-
-# System_ext Manifest
-include $(CLEAR_VARS)
-LOCAL_MODULE := system_ext_manifest.xml
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../NOTICE
-LOCAL_MODULE_STEM := manifest.xml
-LOCAL_MODULE_CLASS := ETC
-LOCAL_SYSTEM_EXT_MODULE := true
-LOCAL_MODULE_RELATIVE_PATH := vintf
-GEN := $(local-generated-sources-dir)/manifest.xml
-$(GEN): PRIVATE_SYSTEM_EXT_MANIFEST_FILES := $(SYSTEM_EXT_MANIFEST_INPUT_FILES)
-$(GEN): PRIVATE_PROVIDED_VNDK_VERSIONS := \
-  $(sort $(PRODUCT_EXTRA_VNDK_VERSIONS))
-
-$(GEN): $(SYSTEM_EXT_MANIFEST_INPUT_FILES) $(HOST_OUT_EXECUTABLES)/assemble_vintf
-	PROVIDED_VNDK_VERSIONS="$(PRIVATE_PROVIDED_VNDK_VERSIONS)" \
-	$(HOST_OUT_EXECUTABLES)/assemble_vintf \
-		-i $(call normalize-path-list,$(PRIVATE_SYSTEM_EXT_MANIFEST_FILES)) \
-		-o $@
-
-LOCAL_PREBUILT_MODULE_FILE := $(GEN)
-include $(BUILD_PREBUILT)
-
-SYSTEM_MANIFEST_INPUT_FILES :=
-SYSTEM_EXT_MANIFEST_INPUT_FILES :=
-DEVICE_MATRIX_INPUT_FILE :=
-PRODUCT_MANIFEST_INPUT_FILES :=
-
-VINTF_FRAMEWORK_MANIFEST_FROZEN_DIR := $(LOCAL_PATH)/frozen
```

