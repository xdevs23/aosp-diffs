```diff
diff --git a/secure_element/aidl/Android.bp b/secure_element/aidl/Android.bp
index 150c7d9..0f227ea 100644
--- a/secure_element/aidl/Android.bp
+++ b/secure_element/aidl/Android.bp
@@ -8,15 +8,17 @@ package {
     default_applicable_licenses: ["hardware_st_secure_element2_license"],
 }
 
-cc_binary {
-    name: "android.hardware.secure_element-service.thales",
-    relative_install_path: "hw",
-    init_rc: ["android.hardware.secure_element_gto.rc"],
-    vintf_fragments: ["android.hardware.secure_element_gto.xml"],
-    vendor: true,
-    srcs: [
-        "SecureElement.cpp",
-        "GtoService.cpp",
+cc_defaults {
+    name: "thales_aidl_defaults",
+
+    cflags: [
+        "-DANDROID",
+        "-DENABLE_LOGGING=1",
+        "-DENABLE_DEBUG=1",
+        "-Wno-unused-parameter",
+        "-Wno-unused-private-field",
+        "-Wno-error",
+        "-Wreturn-type",
     ],
 
     shared_libs: [
@@ -29,20 +31,26 @@ cc_binary {
         "liblog",
         "libutils",
     ],
+}
 
-    cflags: [
-        "-DANDROID",
-        "-DENABLE_LOGGING=1",
-        "-DENABLE_DEBUG=1",
-        "-Wno-unused-parameter",
-        "-Wno-unused-private-field",
-        "-Wno-error",
-        "-Wreturn-type",
+cc_binary {
+    name: "android.hardware.secure_element-service.thales",
+    relative_install_path: "hw",
+    init_rc: ["android.hardware.secure_element_gto.rc"],
+    vintf_fragments: ["android.hardware.secure_element_gto.xml"],
+    vendor: true,
+    srcs: [
+        "SecureElement.cpp",
+        "GtoService.cpp",
     ],
 
+    defaults: ["thales_aidl_defaults"],
+
     arch: {
-        arm: { cflags: ["-DST_LIB_32"] },
-    }
+        arm: {
+            cflags: ["-DST_LIB_32"],
+        },
+    },
 }
 
 cc_binary {
@@ -56,28 +64,25 @@ cc_binary {
         "GtoService-ese2.cpp",
     ],
 
-    cflags: [
-        "-DANDROID",
-        "-DENABLE_LOGGING=1",
-        "-DENABLE_DEBUG=1",
-        "-Wno-unused-parameter",
-        "-Wno-unused-private-field",
-        "-Wno-error",
-        "-Wreturn-type",
-    ],
+    defaults: ["thales_aidl_defaults"],
 
-    shared_libs: [
-        "libbinder_ndk",
-        "android.hardware.secure_element-V1-ndk",
-        "android.hardware.secure_element.thales.libse",
-        "libbase",
-        "libcutils",
-        "libhardware",
-        "liblog",
-        "libutils",
+    arch: {
+        arm: {
+            cflags: ["-DST_LIB_32"],
+        },
+    },
+}
+
+cc_binary {
+    name: "android.hardware.secure_element-service.thales-st33",
+    relative_install_path: "hw",
+    init_rc: ["android.hardware.secure_element_gto-st33.rc"],
+    vintf_fragments: ["android.hardware.secure_element_gto-st33.xml"],
+    vendor: true,
+    srcs: [
+        "SecureElement.cpp",
+        "GtoService-st33.cpp",
     ],
 
-    arch: {
-        arm: { cflags: ["-DST_LIB_32"] },
-    }
+    defaults: ["thales_aidl_defaults"],
 }
diff --git a/secure_element/aidl/GtoService-st33.cpp b/secure_element/aidl/GtoService-st33.cpp
new file mode 100644
index 0000000..80ce89b
--- /dev/null
+++ b/secure_element/aidl/GtoService-st33.cpp
@@ -0,0 +1,48 @@
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
+#include <dlfcn.h>
+#include <log/log.h>
+
+#include "SecureElement.h"
+#include <aidl/android/hardware/secure_element/BnSecureElement.h>
+#include <android-base/hex.h>
+#include <android-base/logging.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+
+using android::OK;
+
+using aidl::android::hardware::secure_element::BnSecureElement;
+using aidl::android::hardware::secure_element::ISecureElementCallback;
+using aidl::android::hardware::secure_element::LogicalChannelResponse;
+using android::base::HexString;
+using ndk::ScopedAStatus;
+
+int main() {
+  ALOGD("android.hardware.secure_element-service.thales-st33 is starting.");
+  ALOGD("Thales Secure Element AIDL for eSE1 Service 1.6.0 is starting. libse-gto v1.13");
+
+  ABinderProcess_setThreadPoolMaxThreadCount(0);
+
+  auto se_service = ndk::SharedRefBase::make<se::SecureElement>("eSE1");
+  const std::string name = std::string() + BnSecureElement::descriptor + "/eSE1";
+  binder_status_t status = AServiceManager_addService(se_service->asBinder().get(), name.c_str());
+  CHECK_EQ(status, STATUS_OK);
+
+  ABinderProcess_joinThreadPool();
+  return EXIT_FAILURE;  // should not reach
+
+}
diff --git a/secure_element/aidl/android.hardware.secure_element_gto-st33.rc b/secure_element/aidl/android.hardware.secure_element_gto-st33.rc
new file mode 100644
index 0000000..2e5fe4f
--- /dev/null
+++ b/secure_element/aidl/android.hardware.secure_element_gto-st33.rc
@@ -0,0 +1,3 @@
+service gto_secure_element_aidl_service-st33 /vendor/bin/hw/android.hardware.secure_element-service.thales-st33
+    class hal
+    user secure_element
diff --git a/secure_element/aidl/android.hardware.secure_element_gto-st33.xml b/secure_element/aidl/android.hardware.secure_element_gto-st33.xml
new file mode 100644
index 0000000..96ab2e7
--- /dev/null
+++ b/secure_element/aidl/android.hardware.secure_element_gto-st33.xml
@@ -0,0 +1,7 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl">
+        <name>android.hardware.secure_element</name>
+        <version>1</version>
+        <fqname>ISecureElement/eSE1</fqname>
+    </hal>
+</manifest>
```

