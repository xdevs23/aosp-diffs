```diff
diff --git a/automotive/packagemanagerproxy/OWNERS b/automotive/packagemanagerproxy/OWNERS
new file mode 100644
index 0000000..681e0e1
--- /dev/null
+++ b/automotive/packagemanagerproxy/OWNERS
@@ -0,0 +1,5 @@
+briandaniels@google.com
+hnandagopal@google.com
+radsaggi@google.com
+sgurun@google.com
+vill@google.com
diff --git a/automotive/packagemanagerproxy/aidl/Android.bp b/automotive/packagemanagerproxy/aidl/Android.bp
new file mode 100644
index 0000000..1503386
--- /dev/null
+++ b/automotive/packagemanagerproxy/aidl/Android.bp
@@ -0,0 +1,49 @@
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// Audomotive Telemetry interfaces.
+//
+// Depend on "google.sdv.packagemanagerproxy-V1-ndk". Change "V1" to desired version (it
+// must be always provided), and "ndk" to a desired AIDL back-end.
+aidl_interface {
+    name: "google.sdv.packagemanagerproxy",
+    owner: "google",
+    srcs: [
+        "google/sdv/packagemanagerproxy/*.aidl",
+    ],
+    vendor_available: true,
+    stability: "vintf",
+    backend: {
+        ndk: {
+            enabled: true,
+        },
+    },
+    versions_with_info: [
+        {
+            version: "1",
+            imports: [],
+        },
+    ],
+    frozen: true,
+
+    // Run "m google.sdv.packagemanagerproxy-freeze-api" to bump the version. Freeze the
+    // version only during the release.
+    // Run "m google.sdv.packagemanagerproxy-update-api" to update the
+    // "aidl_api/.../current/" dir.
+
+}
diff --git a/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/1/.hash b/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/1/.hash
new file mode 100644
index 0000000..8f79d9b
--- /dev/null
+++ b/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/1/.hash
@@ -0,0 +1 @@
+87424dbf5fdf6387a379d28989dbc8329828d7e6
diff --git a/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/1/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl b/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/1/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl
new file mode 100644
index 0000000..5cf4ae7
--- /dev/null
+++ b/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/1/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (c) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package google.sdv.packagemanagerproxy;
+/* @hide */
+@VintfStability
+interface IPackageManagerProxy {
+  @utf8InCpp String[] getNamesForUids(in int[] uids);
+  int getPackageUid(@utf8InCpp String packageName, long flags, int userId);
+  long getVersionCodeForPackage(@utf8InCpp String packageName);
+}
diff --git a/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/current/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl b/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/current/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl
new file mode 100644
index 0000000..5cf4ae7
--- /dev/null
+++ b/automotive/packagemanagerproxy/aidl/aidl_api/google.sdv.packagemanagerproxy/current/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (c) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package google.sdv.packagemanagerproxy;
+/* @hide */
+@VintfStability
+interface IPackageManagerProxy {
+  @utf8InCpp String[] getNamesForUids(in int[] uids);
+  int getPackageUid(@utf8InCpp String packageName, long flags, int userId);
+  long getVersionCodeForPackage(@utf8InCpp String packageName);
+}
diff --git a/automotive/packagemanagerproxy/aidl/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl b/automotive/packagemanagerproxy/aidl/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl
new file mode 100644
index 0000000..dbe11f0
--- /dev/null
+++ b/automotive/packagemanagerproxy/aidl/google/sdv/packagemanagerproxy/IPackageManagerProxy.aidl
@@ -0,0 +1,53 @@
+/*
+ * Copyright (c) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package google.sdv.packagemanagerproxy;
+
+/**
+ * A proxy interface for the corresponding IPackageManagerNative APIs.
+ * The Package Manager team has agreed to expose these interfaces as
+ * stable in the future. This is an interim solution until they are
+ * exposed.
+ * @hide
+ */
+@VintfStability
+interface IPackageManagerProxy {
+    /**
+     * Returns a set of names for the given UIDs.
+     * IMPORTANT: Unlike the Java version of this API, unknown UIDs are
+     * not represented by 'null's. Instead, they are represented by empty
+     * strings.
+     */
+    @utf8InCpp String[] getNamesForUids(in int[] uids);
+
+    /**
+     * Return the UID associated with the given package name.
+     * Note that the same package will have different UIDs under different UserHandle on
+     * the same device.
+     * @param packageName The full name (i.e. com.google.apps.contacts) of the desired package.
+     * @param flags Additional option flags to modify the data returned.
+     * @param userId The user handle identifier to look up the package under.
+     * @return Returns an integer UID who owns the given package name, or -1 if no such package is
+     *            available to the caller.
+     */
+    int getPackageUid(@utf8InCpp String packageName, long flags, int userId);
+
+    /**
+     * Returns the version code of the named package.
+     * Unknown or unknowable versions are returned as 0.
+     */
+    long getVersionCodeForPackage(@utf8InCpp String packageName);
+}
diff --git a/cameraservice/vts/functional/Android.bp b/cameraservice/vts/functional/Android.bp
index 7b77d36..e430479 100644
--- a/cameraservice/vts/functional/Android.bp
+++ b/cameraservice/vts/functional/Android.bp
@@ -24,9 +24,54 @@ filegroup {
     srcs: ["cameraservice_vts_default.map"],
 }
 
+// VTS tests must link to HAL definition libraries statically.
+// We have a defaults that is separate from VtsHalTargetTestDefaults
+// since most VTS tests aren't vendor: true, so we'd still want to have
+// shared lib deps (libcutils, libutils etc) for them.
+cc_defaults {
+    name: "CameraServiceHalVtsTargetTestDefaults",
+    defaults: [
+        "hidl_defaults",
+    ],
+
+    // Lists all dependencies that can *not* be expected on the device.
+    static_libs: [
+        "VtsHalHidlTestUtils",
+        "libbase",
+        "libhidlbase",
+        "libcutils",
+        "libhidl-gen-utils",
+        "libutils",
+    ],
+
+    header_libs: [
+        "libhidl_gtest_helper",
+    ],
+
+    // Lists all system dependencies that can be expected on the device.
+    shared_libs: [
+        // All the following are dependencies of any HAL definition library.
+        "liblog",
+    ],
+    cflags: [
+        "-O0",
+        "-g",
+    ],
+
+    target: {
+        android: {
+            shared_libs: [
+                "libvndksupport",
+            ],
+        },
+    },
+
+    require_root: true,
+}
+
 cc_test {
     name: "VtsHalCameraServiceV2_0TargetTest",
-    defaults: ["VtsHalTargetTestDefaults"],
+    defaults: ["CameraServiceHalVtsTargetTestDefaults"],
 
     vendor: true,
     srcs: ["VtsHalCameraServiceV2_0TargetTest.cpp"],
@@ -62,7 +107,7 @@ cc_test {
 cc_test {
     name: "VtsAidlCameraServiceTargetTest",
     defaults: [
-        "VtsHalTargetTestDefaults",
+        "CameraServiceHalVtsTargetTestDefaults",
     ],
 
     vendor: true,
diff --git a/sensorservice/libsensorndkbridge/ASensorManager.cpp b/sensorservice/libsensorndkbridge/ASensorManager.cpp
index a7180ed..2438700 100644
--- a/sensorservice/libsensorndkbridge/ASensorManager.cpp
+++ b/sensorservice/libsensorndkbridge/ASensorManager.cpp
@@ -31,6 +31,7 @@
 
 using aidl::android::frameworks::sensorservice::IEventQueue;
 using aidl::android::frameworks::sensorservice::ISensorManager;
+using aidl::android::hardware::sensors::ISensors;
 using aidl::android::hardware::sensors::SensorInfo;
 using aidl::android::hardware::sensors::SensorType;
 using android::BAD_VALUE;
@@ -402,28 +403,58 @@ int ASensor_getHandle(ASensor const* sensor) {
     return reinterpret_cast<const SensorInfo*>(sensor)->sensorHandle;
 }
 
-#if 0
 int ASensor_getReportingMode(ASensor const* sensor) {
     RETURN_IF_SENSOR_IS_NULL(AREPORTING_MODE_INVALID);
-    return 0;
+    int32_t flags = reinterpret_cast<const SensorInfo*>(sensor)->flags;
+    switch (flags & SensorInfo::SENSOR_FLAG_BITS_MASK_REPORTING_MODE) {
+        case SensorInfo::SENSOR_FLAG_BITS_CONTINUOUS_MODE:
+            return AREPORTING_MODE_CONTINUOUS;
+        case SensorInfo::SENSOR_FLAG_BITS_ON_CHANGE_MODE:
+            return AREPORTING_MODE_ON_CHANGE;
+        case SensorInfo::SENSOR_FLAG_BITS_ONE_SHOT_MODE:
+            return AREPORTING_MODE_ONE_SHOT;
+        case SensorInfo::SENSOR_FLAG_BITS_SPECIAL_REPORTING_MODE:
+            return AREPORTING_MODE_SPECIAL_TRIGGER;
+        default:
+            return AREPORTING_MODE_INVALID;
+    }
 }
 
 bool ASensor_isWakeUpSensor(ASensor const* sensor) {
     RETURN_IF_SENSOR_IS_NULL(false);
-    return false;
+    return reinterpret_cast<const SensorInfo*>(sensor)->flags &
+           SensorInfo::SENSOR_FLAG_BITS_WAKE_UP;
 }
 
 bool ASensor_isDirectChannelTypeSupported(
         ASensor const* sensor, int channelType) {
     RETURN_IF_SENSOR_IS_NULL(false);
+    int32_t flags = reinterpret_cast<const SensorInfo*>(sensor)->flags;
+    if (channelType == ASENSOR_DIRECT_CHANNEL_TYPE_SHARED_MEMORY) {
+        return flags & SensorInfo::SENSOR_FLAG_BITS_DIRECT_CHANNEL_ASHMEM;
+    } else if (channelType == ASENSOR_DIRECT_CHANNEL_TYPE_HARDWARE_BUFFER) {
+        return flags & SensorInfo::SENSOR_FLAG_BITS_DIRECT_CHANNEL_GRALLOC;
+    }
     return false;
 }
 
 int ASensor_getHighestDirectReportRateLevel(ASensor const* sensor) {
     RETURN_IF_SENSOR_IS_NULL(ASENSOR_DIRECT_RATE_STOP);
-    return 0;
+    int32_t flags = reinterpret_cast<const SensorInfo*>(sensor)->flags;
+    flags &= SensorInfo::SENSOR_FLAG_BITS_MASK_DIRECT_REPORT;
+    switch (flags >> SENSOR_FLAG_SHIFT_DIRECT_REPORT) {
+        case static_cast<int32_t>(ISensors::RateLevel::STOP):
+            return ASENSOR_DIRECT_RATE_STOP;
+        case static_cast<int32_t>(ISensors::RateLevel::NORMAL):
+            return ASENSOR_DIRECT_RATE_NORMAL;
+        case static_cast<int32_t>(ISensors::RateLevel::FAST):
+            return ASENSOR_DIRECT_RATE_FAST;
+        case static_cast<int32_t>(ISensors::RateLevel::VERY_FAST):
+            return ASENSOR_DIRECT_RATE_VERY_FAST;
+        default:
+            return ASENSOR_DIRECT_RATE_STOP;
+    }
 }
-#endif
 
 static ALooper *getTheLooper() {
     static ALooper *sLooper = NULL;
diff --git a/stats/aidl/Android.bp b/stats/aidl/Android.bp
index 3fd3296..825e4ea 100644
--- a/stats/aidl/Android.bp
+++ b/stats/aidl/Android.bp
@@ -28,7 +28,6 @@ aidl_interface {
         },
         java: {
             enabled: true,
-            platform_apis: true,
         },
         ndk: {
             enabled: true,
diff --git a/stats/aidl/vts/java/apps/vtsistatsapp/Android.bp b/stats/aidl/vts/java/apps/vtsistatsapp/Android.bp
index b028eba..530cf16 100644
--- a/stats/aidl/vts/java/apps/vtsistatsapp/Android.bp
+++ b/stats/aidl/vts/java/apps/vtsistatsapp/Android.bp
@@ -31,6 +31,6 @@ android_test {
         "compatibility-device-util-axt",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
     ],
 }
```

