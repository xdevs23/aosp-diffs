```diff
diff --git a/automotive/display/aidl/vts/functional/VtsHalCarDisplayTargetTest.cpp b/automotive/display/aidl/vts/functional/VtsHalCarDisplayTargetTest.cpp
index b3e4b5b..454d962 100644
--- a/automotive/display/aidl/vts/functional/VtsHalCarDisplayTargetTest.cpp
+++ b/automotive/display/aidl/vts/functional/VtsHalCarDisplayTargetTest.cpp
@@ -27,6 +27,7 @@
 #include <android/binder_process.h>
 #include <android/binder_status.h>
 #include <bufferqueueconverter/BufferQueueConverter.h>
+#include <hidl/ServiceManagement.h>
 
 namespace {
 
@@ -84,6 +85,11 @@ class CarDisplayAidlTest : public ::testing::TestWithParam<std::string> {
 TEST_P(CarDisplayAidlTest, getIGBPObject) {
     LOG(INFO) << "Test getHGraphicBufferProducer method";
 
+    if (!android::hardware::isHidlSupported()) {
+        // This test assumes that HIDL is supported on the target device.
+        GTEST_SKIP() << "Assumption failed; HIDL is not supported.";
+    }
+
     for (const auto& id : mDisplayIds) {
         // Get a display info.
         DisplayDesc desc;
@@ -112,6 +118,10 @@ TEST_P(CarDisplayAidlTest, getIGBPObject) {
 TEST_P(CarDisplayAidlTest, showWindow) {
     LOG(INFO) << "Test showWindow method";
     for (const auto& id : mDisplayIds) {
+        // Get a Surface object to register a target device.
+        aidl::android::view::Surface shimSurface;
+        ASSERT_TRUE(mDisplayProxy->getSurface(id, &shimSurface).isOk());
+
         ASSERT_TRUE(mDisplayProxy->showWindow(id).isOk());
     }
 }
@@ -120,6 +130,10 @@ TEST_P(CarDisplayAidlTest, hideWindow) {
     LOG(INFO) << "Test hideWindow method";
 
     for (const auto& id : mDisplayIds) {
+        // Get a Surface object to register a target device.
+        aidl::android::view::Surface shimSurface;
+        ASSERT_TRUE(mDisplayProxy->getSurface(id, &shimSurface).isOk());
+
         ASSERT_TRUE(mDisplayProxy->hideWindow(id).isOk());
     }
 }
diff --git a/automotive/packagemanagerproxy/aidl/Android.bp b/automotive/packagemanagerproxy/aidl/Android.bp
index 1503386..a5026d5 100644
--- a/automotive/packagemanagerproxy/aidl/Android.bp
+++ b/automotive/packagemanagerproxy/aidl/Android.bp
@@ -16,7 +16,7 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-// Audomotive Telemetry interfaces.
+// Automotive Telemetry interfaces.
 //
 // Depend on "google.sdv.packagemanagerproxy-V1-ndk". Change "V1" to desired version (it
 // must be always provided), and "ndk" to a desired AIDL back-end.
@@ -28,6 +28,7 @@ aidl_interface {
     ],
     vendor_available: true,
     stability: "vintf",
+    min_sdk_version: "35",
     backend: {
         ndk: {
             enabled: true,
diff --git a/automotive/powerpolicy/aidl/Android.bp b/automotive/power/aidl/Android.bp
similarity index 69%
rename from automotive/powerpolicy/aidl/Android.bp
rename to automotive/power/aidl/Android.bp
index f583879..7bbb2ae 100644
--- a/automotive/powerpolicy/aidl/Android.bp
+++ b/automotive/power/aidl/Android.bp
@@ -88,3 +88,38 @@ aidl_interface {
     ],
     frozen: true,
 }
+
+aidl_interface {
+    name: "android.frameworks.automotive.power",
+    vendor_available: true,
+    srcs: [
+        "android/frameworks/automotive/power/CarPowerState.aidl",
+        "android/frameworks/automotive/power/ICarPowerServer.aidl",
+        "android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl",
+        "android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl",
+        "android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl",
+    ],
+    stability: "vintf",
+    imports: [
+        "android.frameworks.automotive.powerpolicy-V3",
+    ],
+    backend: {
+        java: {
+            sdk_version: "module_current",
+            min_sdk_version: "35", // TODO(b/383348133): Make 36 once that version is available
+            apex_available: [
+                "//apex_available:platform",
+                "com.android.car.framework",
+            ],
+            enabled: true,
+        },
+    },
+    frozen: true,
+    versions_with_info: [
+        {
+            version: "1",
+            imports: ["android.frameworks.automotive.powerpolicy-V3"],
+        },
+    ],
+
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/.hash b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/.hash
new file mode 100644
index 0000000..1826d13
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/.hash
@@ -0,0 +1 @@
+11f3dffe11d2453b17c50a4967b705b6747c96e1
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/CarPowerState.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/CarPowerState.aidl
new file mode 100644
index 0000000..b79540d
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/CarPowerState.aidl
@@ -0,0 +1,51 @@
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
+package android.frameworks.automotive.power;
+@Backing(type="int") @VintfStability
+enum CarPowerState {
+  INVALID = 0,
+  WAIT_FOR_VHAL = 1,
+  SUSPEND_ENTER = 2,
+  SUSPEND_EXIT = 3,
+  SHUTDOWN_ENTER = 5,
+  ON = 6,
+  SHUTDOWN_PREPARE = 7,
+  SHUTDOWN_CANCELLED = 8,
+  HIBERNATION_ENTER = 9,
+  HIBERNATION_EXIT = 10,
+  PRE_SHUTDOWN_PREPARE = 11,
+  POST_SUSPEND_ENTER = 12,
+  POST_SHUTDOWN_ENTER = 13,
+  POST_HIBERNATION_ENTER = 14,
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerServer.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerServer.aidl
new file mode 100644
index 0000000..397511c
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerServer.aidl
@@ -0,0 +1,47 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICarPowerServer {
+  android.frameworks.automotive.powerpolicy.CarPowerPolicy getCurrentPowerPolicy();
+  boolean getPowerComponentState(in android.frameworks.automotive.powerpolicy.PowerComponent componentId);
+  void registerPowerPolicyChangeCallback(in android.frameworks.automotive.powerpolicy.ICarPowerPolicyChangeCallback callback, in android.frameworks.automotive.powerpolicy.CarPowerPolicyFilter filter);
+  void unregisterPowerPolicyChangeCallback(in android.frameworks.automotive.powerpolicy.ICarPowerPolicyChangeCallback callback);
+  void applyPowerPolicy(in @utf8InCpp String policyId);
+  void setPowerPolicyGroup(in @utf8InCpp String policyGroupId);
+  void registerPowerStateListener(in android.frameworks.automotive.power.ICarPowerStateChangeListener listener);
+  void unregisterPowerStateListener(in android.frameworks.automotive.power.ICarPowerStateChangeListener listener);
+  void registerPowerStateListenerWithCompletion(in android.frameworks.automotive.power.ICarPowerStateChangeListenerWithCompletion listener);
+  void unregisterPowerStateListenerWithCompletion(in android.frameworks.automotive.power.ICarPowerStateChangeListenerWithCompletion listener);
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl
new file mode 100644
index 0000000..f03bfc5
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICarPowerStateChangeListener {
+  oneway void onStateChanged(in android.frameworks.automotive.power.CarPowerState state);
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl
new file mode 100644
index 0000000..3ae0986
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICarPowerStateChangeListenerWithCompletion {
+  oneway void onStateChanged(in android.frameworks.automotive.power.CarPowerState state, long expirationTimeMs, in android.frameworks.automotive.power.ICompletablePowerStateChangeFuture future);
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl
new file mode 100644
index 0000000..c586b5b
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/1/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICompletablePowerStateChangeFuture {
+  void complete();
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/CarPowerState.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/CarPowerState.aidl
new file mode 100644
index 0000000..b79540d
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/CarPowerState.aidl
@@ -0,0 +1,51 @@
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
+package android.frameworks.automotive.power;
+@Backing(type="int") @VintfStability
+enum CarPowerState {
+  INVALID = 0,
+  WAIT_FOR_VHAL = 1,
+  SUSPEND_ENTER = 2,
+  SUSPEND_EXIT = 3,
+  SHUTDOWN_ENTER = 5,
+  ON = 6,
+  SHUTDOWN_PREPARE = 7,
+  SHUTDOWN_CANCELLED = 8,
+  HIBERNATION_ENTER = 9,
+  HIBERNATION_EXIT = 10,
+  PRE_SHUTDOWN_PREPARE = 11,
+  POST_SUSPEND_ENTER = 12,
+  POST_SHUTDOWN_ENTER = 13,
+  POST_HIBERNATION_ENTER = 14,
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerServer.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerServer.aidl
new file mode 100644
index 0000000..397511c
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerServer.aidl
@@ -0,0 +1,47 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICarPowerServer {
+  android.frameworks.automotive.powerpolicy.CarPowerPolicy getCurrentPowerPolicy();
+  boolean getPowerComponentState(in android.frameworks.automotive.powerpolicy.PowerComponent componentId);
+  void registerPowerPolicyChangeCallback(in android.frameworks.automotive.powerpolicy.ICarPowerPolicyChangeCallback callback, in android.frameworks.automotive.powerpolicy.CarPowerPolicyFilter filter);
+  void unregisterPowerPolicyChangeCallback(in android.frameworks.automotive.powerpolicy.ICarPowerPolicyChangeCallback callback);
+  void applyPowerPolicy(in @utf8InCpp String policyId);
+  void setPowerPolicyGroup(in @utf8InCpp String policyGroupId);
+  void registerPowerStateListener(in android.frameworks.automotive.power.ICarPowerStateChangeListener listener);
+  void unregisterPowerStateListener(in android.frameworks.automotive.power.ICarPowerStateChangeListener listener);
+  void registerPowerStateListenerWithCompletion(in android.frameworks.automotive.power.ICarPowerStateChangeListenerWithCompletion listener);
+  void unregisterPowerStateListenerWithCompletion(in android.frameworks.automotive.power.ICarPowerStateChangeListenerWithCompletion listener);
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl
new file mode 100644
index 0000000..f03bfc5
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICarPowerStateChangeListener {
+  oneway void onStateChanged(in android.frameworks.automotive.power.CarPowerState state);
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl
new file mode 100644
index 0000000..3ae0986
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICarPowerStateChangeListenerWithCompletion {
+  oneway void onStateChanged(in android.frameworks.automotive.power.CarPowerState state, long expirationTimeMs, in android.frameworks.automotive.power.ICompletablePowerStateChangeFuture future);
+}
diff --git a/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl
new file mode 100644
index 0000000..c586b5b
--- /dev/null
+++ b/automotive/power/aidl/aidl_api/android.frameworks.automotive.power/current/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.automotive.power;
+@VintfStability
+interface ICompletablePowerStateChangeFuture {
+  void complete();
+}
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/.hash b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/.hash
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/.hash
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/.hash
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/1/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/.hash b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/.hash
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/.hash
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/.hash
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/2/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy.internal/current/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/.hash b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/.hash
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/.hash
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/.hash
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/PowerComponent.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/1/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/.hash b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/.hash
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/.hash
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/.hash
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/PowerComponent.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/2/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/.hash b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/.hash
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/.hash
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/.hash
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/PowerComponent.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/3/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
diff --git a/automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/PowerComponent.aidl b/automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
rename to automotive/power/aidl/aidl_api/android.frameworks.automotive.powerpolicy/current/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
diff --git a/automotive/power/aidl/android/frameworks/automotive/power/CarPowerState.aidl b/automotive/power/aidl/android/frameworks/automotive/power/CarPowerState.aidl
new file mode 100644
index 0000000..bd4556e
--- /dev/null
+++ b/automotive/power/aidl/android/frameworks/automotive/power/CarPowerState.aidl
@@ -0,0 +1,40 @@
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
+package android.frameworks.automotive.power;
+
+/**
+ * Representation of power states, matching those defined in CarPowerManager.
+ */
+
+@VintfStability
+@Backing(type="int")
+enum CarPowerState {
+    INVALID = 0, // State is unavailable, unknown, or invalid
+    WAIT_FOR_VHAL = 1, // Android is up, but waiting for vendor to give signal to start main functionality
+    SUSPEND_ENTER = 2, // System is entering deep sleep (suspend to RAM)
+    SUSPEND_EXIT = 3, // System waking up from suspend
+    SHUTDOWN_ENTER = 5, // System entering shutdown
+    ON = 6,
+    SHUTDOWN_PREPARE = 7, // System getting ready for shutdown or suspend, application expect to cleanup and be ready to suspend
+    SHUTDOWN_CANCELLED = 8, // Shutdown cancelled, returning to normal state
+    HIBERNATION_ENTER = 9, // System entering hibernation (suspend to disk)
+    HIBERNATION_EXIT = 10, // System waking up from hibernation
+    PRE_SHUTDOWN_PREPARE = 11, // Shutdown initiated, but display on
+    POST_SUSPEND_ENTER = 12, // Car power service and VHAL finish processing to enter deep sleep, device about to sleep
+    POST_SHUTDOWN_ENTER = 13, // Car power service and VHAL finish processing to shutdown, device about to power off
+    POST_HIBERNATION_ENTER = 14, // Car power service and VHAL finish processing to enter hibernation, device about to hibernate
+}
diff --git a/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerServer.aidl b/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerServer.aidl
new file mode 100644
index 0000000..909229d
--- /dev/null
+++ b/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerServer.aidl
@@ -0,0 +1,141 @@
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
+package android.frameworks.automotive.power;
+
+import android.frameworks.automotive.power.ICarPowerStateChangeListener;
+import android.frameworks.automotive.power.ICarPowerStateChangeListenerWithCompletion;
+import android.frameworks.automotive.powerpolicy.CarPowerPolicy;
+import android.frameworks.automotive.powerpolicy.CarPowerPolicyFilter;
+import android.frameworks.automotive.powerpolicy.ICarPowerPolicyChangeCallback;
+import android.frameworks.automotive.powerpolicy.PowerComponent;
+
+/**
+ * ICarPowerServer is an interface implemented by the car power daemon.
+ *
+ * <p>VHAL changes the power policy and the power policy daemon notifies the change to registered
+ * subscribers. When subscribing to policy changes, a filter can be specified so that the registered
+ * callbacks can listen only to a specific power component's change.
+ *
+ * <p>CarService changes the power state and the power daemon notifies the change to registered
+ * listeners. Listeners can be with or without completion. With completion means that the power
+ * state change can be paused (up to a certain amount of time) while listeners' processes finish up
+ * tasks.
+ */
+
+@VintfStability
+interface ICarPowerServer {
+  /**
+   * Gets the current power policy.
+   * @throws IllegalStateException if the current policy is not set.
+   */
+  CarPowerPolicy getCurrentPowerPolicy();
+
+  /**
+   * Gets whether the power component is turned on or off.
+   *
+   * @param componentId Power component ID defined in PowerComponent.aidl to check power state.
+   * @return True if the component's power state is on.
+   * @throws IllegalArgumentException if the componentId is invalid.
+   */
+  boolean getPowerComponentState(in PowerComponent componentId);
+
+  /**
+   * Subscribes to power policy change.
+   * Notification is sent to the registered callback when the power policy changes and the power
+   * state of the components which the callback is interested in changes.
+   *
+   * @param callback Callback that is invoked when the power policy changes.
+   * @param filter The list of components which the callback is interested in.
+   * @throws IllegalArgumentException if the callback is already registered.
+   * @throws IllegalStateException if the callback is dead.
+   */
+  void registerPowerPolicyChangeCallback(in ICarPowerPolicyChangeCallback callback,
+      in CarPowerPolicyFilter filter);
+
+  /**
+   * Unsubscribes from power policy change.
+   *
+   * @param callback Callback that doesn't want to receive power policy change.
+   * @throws IllegalArgumentException if the callback is not registered.
+   */
+  void unregisterPowerPolicyChangeCallback(in ICarPowerPolicyChangeCallback callback);
+
+  /**
+   * Applies the power policy.
+   *
+   * <p>{@code policyId} should be one of power policy IDs defined in
+   * {@code /vendor/etc/automotive/power_policy.xml} or predefined system power policies.
+   *
+   * @param policyId ID of power policy.
+   * @throws IllegalArgumentException if {@code policyId} is invalid.
+   */
+  void applyPowerPolicy(in @utf8InCpp String policyId);
+
+  /**
+   * Sets the current power policy group.
+   *
+   * <p>{@code policyGroupId} should be one of power policy group IDs defined in
+   * {@code /vendor/etc/automotive/power_policy.xml}.
+   *
+   * @param policyGroupId ID of power policy group.
+   * @throws IllegalArgumentException if {@code policyGroupId} is invalid.
+   */
+  void setPowerPolicyGroup(in @utf8InCpp String policyGroupId);
+
+  /**
+   * Register a power state change listener with the car power daemon.
+   *
+   * <p>Multiple listeners are allowed to be registered to one client.
+   *
+   * @param listener Listener to register.
+   * @throws IllegalArgumentException if the listener is already registered.
+   * @throws IllegalStateException if the listener is dead.
+   */
+  void registerPowerStateListener(in ICarPowerStateChangeListener listener);
+
+  /**
+   * Unregister a power state change listener with the car power daemon.
+   *
+   * @param listener Listener to unregister.
+   * @throws IllegalArgumentException if the listener is not registered.
+   */
+  void unregisterPowerStateListener(in ICarPowerStateChangeListener listener);
+
+  /**
+   * Register a power state change listener with completion with the car power daemon.
+   *
+   * <p>Listeners with completion are able to halt the system's power state transition (within a
+   * time limit) while their process completes needed work before the power state changes.
+   *
+   * <p>Multiple listeners are allowed to be registered to one client.
+   *
+   * @param listener Listener to register.
+   * @throws IllegalArgumentException if the listener is already registered.
+   * @throws IllegalStateException if the listener is dead.
+   */
+  void registerPowerStateListenerWithCompletion(
+    in ICarPowerStateChangeListenerWithCompletion listener);
+
+  /**
+   * Unregister a power state change listener with completion with the car power daemon.
+   *
+   * @param listener Listener to unregister.
+   * @throws IllegalArgumentException if the listener is not registered.
+   */
+  void unregisterPowerStateListenerWithCompletion(
+    in ICarPowerStateChangeListenerWithCompletion listener);
+}
diff --git a/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl b/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl
new file mode 100644
index 0000000..6f2d597
--- /dev/null
+++ b/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerStateChangeListener.aidl
@@ -0,0 +1,34 @@
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
+package android.frameworks.automotive.power;
+
+import android.frameworks.automotive.power.CarPowerState;
+
+/**
+ * ICarPowerStateChangeListener is notified when the power state changes.
+ */
+
+@VintfStability
+oneway interface ICarPowerStateChangeListener {
+
+  /**
+   * Called when the power state begins changing.
+   *
+   * @param newState The power state the system is changing to.
+   */
+  void onStateChanged(in CarPowerState state);
+}
diff --git a/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl b/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl
new file mode 100644
index 0000000..12bc57d
--- /dev/null
+++ b/automotive/power/aidl/android/frameworks/automotive/power/ICarPowerStateChangeListenerWithCompletion.aidl
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
+
+package android.frameworks.automotive.power;
+
+import android.frameworks.automotive.power.CarPowerState;
+import android.frameworks.automotive.power.ICompletablePowerStateChangeFuture;
+
+/**
+ * ICarPowerStateChangeListenerWithCompletion is notified when the power state changes.
+ *
+ * Listeners with completion are able to halt the system's power state transition (within a
+ * specified time limit) while the listener's process finishes up tasks needed before power state
+ * changes.
+ */
+
+@VintfStability
+oneway interface ICarPowerStateChangeListenerWithCompletion {
+
+  /**
+   * Called when the power state begins changing.
+   *
+   * @param newState The power state the system is changing to.
+   * @param expirationTimeMs The timestamp (system elapsed time in milliseconds) that listeners with
+   *        completion must complete by and after which, power state transition progresses.
+   * @param future The future used by the listener to notify car power daemon that listener is
+   *        ready to move on to the next step of the power state transition. The car power daemon
+   *        halts power state progression until the listeners call {@link android.frameworks.
+   *        automotive.power.ICompletablePowerStateChangeFuture#complete()} or timeout occurs. In
+   *        the case that {@code state} doesn't allow for completion, {@code future} is
+   *        {@code null}.
+   */
+  void onStateChanged(in CarPowerState state, long expirationTimeMs,
+    in ICompletablePowerStateChangeFuture future);
+}
diff --git a/automotive/power/aidl/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl b/automotive/power/aidl/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl
new file mode 100644
index 0000000..9e54170
--- /dev/null
+++ b/automotive/power/aidl/android/frameworks/automotive/power/ICompletablePowerStateChangeFuture.aidl
@@ -0,0 +1,33 @@
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
+package android.frameworks.automotive.power;
+
+/**
+ * ICompletablePowerStateChangeFuture is an interface passed from native car power state change
+ * listeners with completion.
+ *
+ * <p>The listener uses this interface to tell car power deamon that it completed the task
+ * relevant to the power state change.
+ */
+
+@VintfStability
+interface ICompletablePowerStateChangeFuture {
+  /**
+   * Tells car power daemon that the listener completed the task to handle the power state change.
+   */
+  void complete();
+}
\ No newline at end of file
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicy.aidl
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.aidl
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyChangeCallback.aidl
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.aidl
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/PowerComponent.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/PowerComponent.aidl
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/internal/ICarPowerPolicySystemNotification.aidl
diff --git a/automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl b/automotive/power/aidl/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
similarity index 100%
rename from automotive/powerpolicy/aidl/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
rename to automotive/power/aidl/android/frameworks/automotive/powerpolicy/internal/PolicyState.aidl
diff --git a/automotive/powerpolicy/aidl/vts/Android.bp b/automotive/power/aidl/vts/Android.bp
similarity index 60%
rename from automotive/powerpolicy/aidl/vts/Android.bp
rename to automotive/power/aidl/vts/Android.bp
index a382bc0..fb50176 100644
--- a/automotive/powerpolicy/aidl/vts/Android.bp
+++ b/automotive/power/aidl/vts/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_aaos_power_triage",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -32,10 +33,36 @@ cc_test {
         "libbinder_ndk",
     ],
     static_libs: [
-        "android.frameworks.automotive.powerpolicy-V2-ndk",
+        "android.frameworks.automotive.powerpolicy-V3-ndk",
         "libgmock",
     ],
     test_suites: [
+        "automotive-general-tests",
+        "general-tests",
+        "vts",
+    ],
+}
+
+cc_test {
+    name: "VtsAidlPowerServerTargetTest",
+    defaults: [
+        "VtsHalTargetTestDefaults",
+        "use_libaidlvintf_gtest_helper_static",
+    ],
+    srcs: [
+        "VtsAidlPowerServerTargetTest.cpp",
+    ],
+    shared_libs: [
+        "libbinder",
+        "libbinder_ndk",
+    ],
+    static_libs: [
+        "android.frameworks.automotive.power-V1-ndk",
+        "android.frameworks.automotive.powerpolicy-V3-ndk",
+        "libgmock",
+    ],
+    test_suites: [
+        "automotive-general-tests",
         "general-tests",
         "vts",
     ],
diff --git a/automotive/power/aidl/vts/PowerPolicyInterfaceTest.h b/automotive/power/aidl/vts/PowerPolicyInterfaceTest.h
new file mode 100644
index 0000000..2d2a01c
--- /dev/null
+++ b/automotive/power/aidl/vts/PowerPolicyInterfaceTest.h
@@ -0,0 +1,126 @@
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
+#include <aidl/Gtest.h>
+#include <aidl/android/frameworks/automotive/powerpolicy/BnCarPowerPolicyChangeCallback.h>
+#include <aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicy.h>
+#include <aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.h>
+#include <aidl/android/frameworks/automotive/powerpolicy/PowerComponent.h>
+#include <android-base/stringprintf.h>
+#include <android/binder_auto_utils.h>
+#include <android/binder_manager.h>
+#include <android/binder_status.h>
+
+namespace aafap = aidl::android::frameworks::automotive::powerpolicy;
+
+class MockPowerPolicyChangeCallback : public aafap::BnCarPowerPolicyChangeCallback {
+   public:
+    MockPowerPolicyChangeCallback() {}
+
+    ndk::ScopedAStatus onPolicyChanged(
+        [[maybe_unused]] const aafap::CarPowerPolicy& policy) override {
+        return ndk::ScopedAStatus::ok();
+    }
+};
+
+template <typename T>
+class PowerPolicyInterfaceTest {
+   public:
+    void SetUp(const std::string& serviceName) {
+        ndk::SpAIBinder binder(AServiceManager_getService(serviceName.c_str()));
+        if (binder.get() == nullptr) {
+            GTEST_SKIP() << "Service " << serviceName << " not found";
+        }
+        powerPolicyServer = T::fromBinder(binder);
+    }
+
+    void TestGetCurrentPowerPolicy() {
+        aafap::CarPowerPolicy policy;
+
+        ndk::ScopedAStatus status = powerPolicyServer->getCurrentPowerPolicy(&policy);
+
+        ASSERT_TRUE(status.isOk() || status.getServiceSpecificError() == EX_ILLEGAL_STATE);
+    }
+
+    void TestGetPowerComponentState() {
+        bool state;
+        for (const auto componentId : ndk::enum_range<aafap::PowerComponent>()) {
+            if (componentId >= aafap::PowerComponent::MINIMUM_CUSTOM_COMPONENT_VALUE) {
+                continue;
+            }
+            ndk::ScopedAStatus status =
+                powerPolicyServer->getPowerComponentState(componentId, &state);
+            std::string errMsg =
+                android::base::StringPrintf("Getting state of component(%d) fails", componentId);
+            ASSERT_TRUE(status.isOk()) << errMsg;
+        }
+    }
+
+    void TestGetPowerComponentState_invalidComponent() {
+        bool state;
+        aafap::PowerComponent invalidComponent = static_cast<aafap::PowerComponent>(-1);
+
+        ndk::ScopedAStatus status =
+            powerPolicyServer->getPowerComponentState(invalidComponent, &state);
+
+        ASSERT_FALSE(status.isOk());
+    }
+
+    void TestRegisterPowerPolicyCallback() {
+        std::shared_ptr<MockPowerPolicyChangeCallback> callback =
+            ndk::SharedRefBase::make<MockPowerPolicyChangeCallback>();
+        aafap::CarPowerPolicyFilter filter;
+        filter.components.push_back(aafap::PowerComponent::AUDIO);
+
+        ndk::ScopedAStatus status =
+            powerPolicyServer->registerPowerPolicyChangeCallback(callback, filter);
+
+        ASSERT_TRUE(status.isOk());
+
+        status = powerPolicyServer->unregisterPowerPolicyChangeCallback(callback);
+
+        ASSERT_TRUE(status.isOk());
+    }
+
+    void TestRegisterPowerPolicyCallback_doubleRegistering() {
+        std::shared_ptr<MockPowerPolicyChangeCallback> callback =
+            ndk::SharedRefBase::make<MockPowerPolicyChangeCallback>();
+        aafap::CarPowerPolicyFilter filter;
+        filter.components.push_back(aafap::PowerComponent::AUDIO);
+
+        ndk::ScopedAStatus status =
+            powerPolicyServer->registerPowerPolicyChangeCallback(callback, filter);
+
+        ASSERT_TRUE(status.isOk());
+
+        status = powerPolicyServer->registerPowerPolicyChangeCallback(callback, filter);
+
+        ASSERT_FALSE(status.isOk());
+        ASSERT_EQ(status.getServiceSpecificError(), EX_ILLEGAL_ARGUMENT);
+    }
+
+    void TestUnegisterNotRegisteredPowerPolicyCallback() {
+        std::shared_ptr<MockPowerPolicyChangeCallback> callback =
+            ndk::SharedRefBase::make<MockPowerPolicyChangeCallback>();
+
+        ndk::ScopedAStatus status =
+            powerPolicyServer->unregisterPowerPolicyChangeCallback(callback);
+
+        ASSERT_FALSE(status.isOk());
+    }
+
+    std::shared_ptr<T> powerPolicyServer;
+};
diff --git a/automotive/power/aidl/vts/TEST_MAPPING b/automotive/power/aidl/vts/TEST_MAPPING
new file mode 100644
index 0000000..aa020e9
--- /dev/null
+++ b/automotive/power/aidl/vts/TEST_MAPPING
@@ -0,0 +1,10 @@
+{
+  "auto-presubmit": [
+    {
+      "name": "VtsAidlPowerPolicyTargetTest"
+    },
+    {
+      "name": "VtsAidlPowerServerTargetTest"
+    }
+  ]
+}
diff --git a/automotive/power/aidl/vts/VtsAidlPowerPolicyTargetTest.cpp b/automotive/power/aidl/vts/VtsAidlPowerPolicyTargetTest.cpp
new file mode 100644
index 0000000..fa745b6
--- /dev/null
+++ b/automotive/power/aidl/vts/VtsAidlPowerPolicyTargetTest.cpp
@@ -0,0 +1,72 @@
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
+#include <aidl/Vintf.h>
+#include <aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.h>
+#include <binder/ProcessState.h>
+
+#include "PowerPolicyInterfaceTest.h"
+
+namespace {
+
+using ::aidl::android::frameworks::automotive::powerpolicy::ICarPowerPolicyServer;
+using ::android::ProcessState;
+
+}  // namespace
+
+class PowerPolicyAidlTest : public ::testing::TestWithParam<std::string> {
+   public:
+    virtual void SetUp() override { powerPolicyTest.SetUp(GetParam()); }
+
+    PowerPolicyInterfaceTest<ICarPowerPolicyServer> powerPolicyTest;
+};
+
+TEST_P(PowerPolicyAidlTest, TestGetCurrentPowerPolicy) {
+    powerPolicyTest.TestGetCurrentPowerPolicy();
+}
+
+TEST_P(PowerPolicyAidlTest, TestGetPowerComponentState) {
+    powerPolicyTest.TestGetPowerComponentState();
+}
+
+TEST_P(PowerPolicyAidlTest, TestGetPowerComponentState_invalidComponent) {
+    powerPolicyTest.TestGetPowerComponentState_invalidComponent();
+}
+
+TEST_P(PowerPolicyAidlTest, TestRegisterPowerPolicyCallback) {
+    powerPolicyTest.TestRegisterPowerPolicyCallback();
+}
+
+TEST_P(PowerPolicyAidlTest, TestRegisterPowerPolicyCallback_doubleRegistering) {
+    powerPolicyTest.TestRegisterPowerPolicyCallback_doubleRegistering();
+}
+
+TEST_P(PowerPolicyAidlTest, TestUnegisterNotRegisteredPowerPolicyCallback) {
+    powerPolicyTest.TestUnegisterNotRegisteredPowerPolicyCallback();
+}
+
+GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(PowerPolicyAidlTest);
+INSTANTIATE_TEST_SUITE_P(
+    CarPowerPolicyServer, PowerPolicyAidlTest,
+    ::testing::ValuesIn(android::getAidlHalInstanceNames(ICarPowerPolicyServer::descriptor)),
+    android::PrintInstanceNameToString);
+
+int main(int argc, char** argv) {
+    ::testing::InitGoogleTest(&argc, argv);
+    ProcessState::self()->setThreadPoolMaxThreadCount(1);
+    ProcessState::self()->startThreadPool();
+    return RUN_ALL_TESTS();
+}
diff --git a/automotive/power/aidl/vts/VtsAidlPowerServerTargetTest.cpp b/automotive/power/aidl/vts/VtsAidlPowerServerTargetTest.cpp
new file mode 100644
index 0000000..a104344
--- /dev/null
+++ b/automotive/power/aidl/vts/VtsAidlPowerServerTargetTest.cpp
@@ -0,0 +1,127 @@
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
+#include <aidl/Vintf.h>
+#include <aidl/android/frameworks/automotive/power/BnCarPowerStateChangeListener.h>
+#include <aidl/android/frameworks/automotive/power/ICarPowerServer.h>
+#include <android/binder_ibinder.h>
+#include <android/binder_manager.h>
+#include <binder/ProcessState.h>
+
+#include "PowerPolicyInterfaceTest.h"
+
+namespace {
+
+using ::aidl::android::frameworks::automotive::power::BnCarPowerStateChangeListener;
+using ::aidl::android::frameworks::automotive::power::CarPowerState;
+using ::aidl::android::frameworks::automotive::power::ICarPowerServer;
+using ::android::ProcessState;
+
+class MockPowerStateChangeListener : public BnCarPowerStateChangeListener {
+   public:
+    MockPowerStateChangeListener() {}
+
+    ndk::ScopedAStatus onStateChanged([[maybe_unused]] CarPowerState state) override {
+        return ndk::ScopedAStatus::ok();
+    }
+};
+
+}  // namespace
+
+class CarPowerServerAidlTest : public ::testing::TestWithParam<std::string> {
+   public:
+    virtual void SetUp() override {
+        powerPolicyTest.SetUp(GetParam());
+    }
+
+    PowerPolicyInterfaceTest<ICarPowerServer> powerPolicyTest;
+};
+
+TEST_P(CarPowerServerAidlTest, TestGetCurrentPowerPolicy) {
+    powerPolicyTest.TestGetCurrentPowerPolicy();
+}
+
+TEST_P(CarPowerServerAidlTest, TestGetPowerComponentState) {
+    powerPolicyTest.TestGetPowerComponentState();
+}
+
+TEST_P(CarPowerServerAidlTest, TestGetPowerComponentState_invalidComponent) {
+    powerPolicyTest.TestGetPowerComponentState_invalidComponent();
+}
+
+TEST_P(CarPowerServerAidlTest, TestRegisterPowerPolicyCallback) {
+    powerPolicyTest.TestRegisterPowerPolicyCallback();
+}
+
+TEST_P(CarPowerServerAidlTest, TestRegisterPowerPolicyCallback_doubleRegistering) {
+    powerPolicyTest.TestRegisterPowerPolicyCallback_doubleRegistering();
+}
+
+TEST_P(CarPowerServerAidlTest, TestUnegisterNotRegisteredPowerPolicyCallback) {
+    powerPolicyTest.TestUnegisterNotRegisteredPowerPolicyCallback();
+}
+
+TEST_P(CarPowerServerAidlTest, TestRegisterPowerStateListener) {
+    std::shared_ptr<MockPowerStateChangeListener> listener =
+        ndk::SharedRefBase::make<MockPowerStateChangeListener>();
+    std::shared_ptr<ICarPowerServer> powerServer = powerPolicyTest.powerPolicyServer;
+
+    ndk::ScopedAStatus status = powerServer->registerPowerStateListener(listener);
+
+    ASSERT_TRUE(status.isOk());
+
+    status = powerServer->unregisterPowerStateListener(listener);
+
+    ASSERT_TRUE(status.isOk());
+}
+
+TEST_P(CarPowerServerAidlTest, TestRegisterPowerStateListener_doubleRegistering) {
+    std::shared_ptr<MockPowerStateChangeListener> listener =
+        ndk::SharedRefBase::make<MockPowerStateChangeListener>();
+    std::shared_ptr<ICarPowerServer> powerServer = powerPolicyTest.powerPolicyServer;
+
+    ndk::ScopedAStatus status = powerServer->registerPowerStateListener(listener);
+
+    ASSERT_TRUE(status.isOk());
+
+    status = powerServer->registerPowerStateListener(listener);
+
+    ASSERT_FALSE(status.isOk());
+    ASSERT_EQ(status.getServiceSpecificError(), EX_ILLEGAL_ARGUMENT);
+}
+
+TEST_P(CarPowerServerAidlTest, TestUnegisterNotRegisteredPowerStateListener) {
+    std::shared_ptr<MockPowerStateChangeListener> listener =
+        ndk::SharedRefBase::make<MockPowerStateChangeListener>();
+    std::shared_ptr<ICarPowerServer> powerServer = powerPolicyTest.powerPolicyServer;
+
+    ndk::ScopedAStatus status = powerServer->unregisterPowerStateListener(listener);
+
+    ASSERT_FALSE(status.isOk());
+}
+
+GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(CarPowerServerAidlTest);
+INSTANTIATE_TEST_SUITE_P(
+    CarPowerServer, CarPowerServerAidlTest,
+    ::testing::ValuesIn(android::getAidlHalInstanceNames(ICarPowerServer::descriptor)),
+    android::PrintInstanceNameToString);
+
+int main(int argc, char** argv) {
+    ::testing::InitGoogleTest(&argc, argv);
+    ProcessState::self()->setThreadPoolMaxThreadCount(1);
+    ProcessState::self()->startThreadPool();
+    return RUN_ALL_TESTS();
+}
diff --git a/automotive/powerpolicy/aidl/vts/VtsAidlPowerPolicyTargetTest.cpp b/automotive/powerpolicy/aidl/vts/VtsAidlPowerPolicyTargetTest.cpp
deleted file mode 100644
index 454c3f1..0000000
--- a/automotive/powerpolicy/aidl/vts/VtsAidlPowerPolicyTargetTest.cpp
+++ /dev/null
@@ -1,150 +0,0 @@
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
-#include <aidl/Gtest.h>
-#include <aidl/Vintf.h>
-#include <aidl/android/frameworks/automotive/powerpolicy/BnCarPowerPolicyChangeCallback.h>
-#include <aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicy.h>
-#include <aidl/android/frameworks/automotive/powerpolicy/CarPowerPolicyFilter.h>
-#include <aidl/android/frameworks/automotive/powerpolicy/ICarPowerPolicyServer.h>
-#include <aidl/android/frameworks/automotive/powerpolicy/PowerComponent.h>
-#include <android-base/stringprintf.h>
-#include <android/binder_auto_utils.h>
-#include <android/binder_manager.h>
-#include <android/binder_status.h>
-#include <binder/IBinder.h>
-#include <binder/IServiceManager.h>
-#include <binder/ProcessState.h>
-
-namespace {
-
-using ::aidl::android::frameworks::automotive::powerpolicy::BnCarPowerPolicyChangeCallback;
-using ::aidl::android::frameworks::automotive::powerpolicy::CarPowerPolicy;
-using ::aidl::android::frameworks::automotive::powerpolicy::CarPowerPolicyFilter;
-using ::aidl::android::frameworks::automotive::powerpolicy::ICarPowerPolicyServer;
-using ::aidl::android::frameworks::automotive::powerpolicy::PowerComponent;
-using ::android::OK;
-using ::android::ProcessState;
-using ::android::status_t;
-using ::android::String16;
-using ::android::UNKNOWN_ERROR;
-using ::android::base::StringPrintf;
-using ::ndk::ScopedAStatus;
-using ::ndk::SpAIBinder;
-
-class MockPowerPolicyChangeCallback : public BnCarPowerPolicyChangeCallback {
-   public:
-    MockPowerPolicyChangeCallback() {}
-
-    ScopedAStatus onPolicyChanged([[maybe_unused]] const CarPowerPolicy& policy) override {
-        return ScopedAStatus::ok();
-    }
-};
-
-}  // namespace
-
-class PowerPolicyAidlTest : public ::testing::TestWithParam<std::string> {
-   public:
-    virtual void SetUp() override {
-        SpAIBinder binder(AServiceManager_getService(GetParam().c_str()));
-        ASSERT_NE(binder.get(), nullptr);
-        powerPolicyServer = ICarPowerPolicyServer::fromBinder(binder);
-    }
-
-    std::shared_ptr<ICarPowerPolicyServer> powerPolicyServer;
-};
-
-TEST_P(PowerPolicyAidlTest, TestGetCurrentPowerPolicy) {
-    CarPowerPolicy policy;
-
-    ScopedAStatus status = powerPolicyServer->getCurrentPowerPolicy(&policy);
-
-    ASSERT_TRUE(status.isOk() || status.getServiceSpecificError() == EX_ILLEGAL_STATE);
-}
-
-TEST_P(PowerPolicyAidlTest, TestGetPowerComponentState) {
-    bool state;
-    for (const auto componentId : ndk::enum_range<PowerComponent>()) {
-        if (componentId >= PowerComponent::MINIMUM_CUSTOM_COMPONENT_VALUE) {
-            continue;
-        }
-        ScopedAStatus status = powerPolicyServer->getPowerComponentState(componentId, &state);
-        std::string errMsg = StringPrintf("Getting state of component(%d) fails", componentId);
-        ASSERT_TRUE(status.isOk()) << errMsg;
-    }
-}
-
-TEST_P(PowerPolicyAidlTest, TestGetPowerComponentState_invalidComponent) {
-    bool state;
-    PowerComponent invalidComponent = static_cast<PowerComponent>(-1);
-
-    ScopedAStatus status = powerPolicyServer->getPowerComponentState(invalidComponent, &state);
-
-    ASSERT_FALSE(status.isOk());
-}
-
-TEST_P(PowerPolicyAidlTest, TestRegisterCallback) {
-    std::shared_ptr<MockPowerPolicyChangeCallback> callback =
-        ndk::SharedRefBase::make<MockPowerPolicyChangeCallback>();
-    CarPowerPolicyFilter filter;
-    filter.components.push_back(PowerComponent::AUDIO);
-
-    ScopedAStatus status = powerPolicyServer->registerPowerPolicyChangeCallback(callback, filter);
-
-    ASSERT_TRUE(status.isOk());
-
-    status = powerPolicyServer->unregisterPowerPolicyChangeCallback(callback);
-
-    ASSERT_TRUE(status.isOk());
-}
-
-TEST_P(PowerPolicyAidlTest, TestRegisterCallback_doubleRegistering) {
-    std::shared_ptr<MockPowerPolicyChangeCallback> callback =
-        ndk::SharedRefBase::make<MockPowerPolicyChangeCallback>();
-    CarPowerPolicyFilter filter;
-    filter.components.push_back(PowerComponent::AUDIO);
-
-    ScopedAStatus status = powerPolicyServer->registerPowerPolicyChangeCallback(callback, filter);
-
-    ASSERT_TRUE(status.isOk());
-
-    status = powerPolicyServer->registerPowerPolicyChangeCallback(callback, filter);
-
-    ASSERT_FALSE(status.isOk());
-    ASSERT_EQ(status.getServiceSpecificError(), EX_ILLEGAL_ARGUMENT);
-}
-
-TEST_P(PowerPolicyAidlTest, TestUnegisterNotRegisteredCallback) {
-    std::shared_ptr<MockPowerPolicyChangeCallback> callback =
-        ndk::SharedRefBase::make<MockPowerPolicyChangeCallback>();
-
-    ScopedAStatus status = powerPolicyServer->unregisterPowerPolicyChangeCallback(callback);
-
-    ASSERT_FALSE(status.isOk());
-}
-
-GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(PowerPolicyAidlTest);
-INSTANTIATE_TEST_SUITE_P(
-    CarPowerPolicyServer, PowerPolicyAidlTest,
-    ::testing::ValuesIn(android::getAidlHalInstanceNames(ICarPowerPolicyServer::descriptor)),
-    android::PrintInstanceNameToString);
-
-int main(int argc, char** argv) {
-    ::testing::InitGoogleTest(&argc, argv);
-    ProcessState::self()->setThreadPoolMaxThreadCount(1);
-    ProcessState::self()->startThreadPool();
-    return RUN_ALL_TESTS();
-}
diff --git a/automotive/telemetry/OWNERS b/automotive/telemetry/OWNERS
index 80794e1..65b926c 100644
--- a/automotive/telemetry/OWNERS
+++ b/automotive/telemetry/OWNERS
@@ -1,3 +1 @@
 sgurun@google.com
-zhomart@google.com
-mdashouk@google.com
diff --git a/cameraservice/OWNERS b/cameraservice/OWNERS
new file mode 100644
index 0000000..f48a95c
--- /dev/null
+++ b/cameraservice/OWNERS
@@ -0,0 +1 @@
+include platform/frameworks/av:/camera/OWNERS
diff --git a/cameraservice/device/aidl/Android.bp b/cameraservice/device/aidl/Android.bp
index cc6b829..6a48a25 100644
--- a/cameraservice/device/aidl/Android.bp
+++ b/cameraservice/device/aidl/Android.bp
@@ -15,7 +15,7 @@ aidl_interface {
     include_dirs: [
         "frameworks/native/aidl/gui",
     ],
-    frozen: false,
+    frozen: true,
     backend: {
         cpp: {
             enabled: false,
@@ -49,6 +49,14 @@ aidl_interface {
                 "android.hardware.common-V2",
             ],
         },
+        {
+            version: "3",
+            imports: [
+                "android.frameworks.cameraservice.common-V1",
+                "android.hardware.common.fmq-V1",
+                "android.hardware.common-V2",
+            ],
+        },
 
     ],
 
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/.hash b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/.hash
new file mode 100644
index 0000000..c3c3db7
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/.hash
@@ -0,0 +1 @@
+13cba7bae30a44929033a233e97489d980a4f058
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CameraMetadata.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CameraMetadata.aidl
new file mode 100644
index 0000000..08a1310
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CameraMetadata.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable CameraMetadata {
+  byte[] metadata;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureMetadataInfo.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureMetadataInfo.aidl
new file mode 100644
index 0000000..c1d1761
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureMetadataInfo.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+union CaptureMetadataInfo {
+  long fmqMetadataSize;
+  android.frameworks.cameraservice.device.CameraMetadata metadata;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureRequest.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureRequest.aidl
new file mode 100644
index 0000000..a19dd10
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureRequest.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable CaptureRequest {
+  android.frameworks.cameraservice.device.PhysicalCameraSettings[] physicalCameraSettings;
+  android.frameworks.cameraservice.device.StreamAndWindowId[] streamAndWindowIds;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureResultExtras.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureResultExtras.aidl
new file mode 100644
index 0000000..2bd2253
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/CaptureResultExtras.aidl
@@ -0,0 +1,43 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable CaptureResultExtras {
+  int requestId;
+  int burstId;
+  long frameNumber;
+  int partialResultCount;
+  int errorStreamId;
+  String errorPhysicalCameraId;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ErrorCode.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ErrorCode.aidl
new file mode 100644
index 0000000..9c361f0
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ErrorCode.aidl
@@ -0,0 +1,46 @@
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
+package android.frameworks.cameraservice.device;
+@Backing(type="int") @VintfStability
+enum ErrorCode {
+  CAMERA_INVALID_ERROR = (-1) /* -1 */,
+  CAMERA_DISCONNECTED = 0,
+  CAMERA_DEVICE = 1,
+  CAMERA_SERVICE = 2,
+  CAMERA_REQUEST = 3,
+  CAMERA_RESULT = 4,
+  CAMERA_BUFFER = 5,
+  CAMERA_DISABLED = 6,
+  CAMERA_UNKNOWN_ERROR = 7,
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
new file mode 100644
index 0000000..e168173
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
@@ -0,0 +1,44 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+interface ICameraDeviceCallback {
+  oneway void onCaptureStarted(in android.frameworks.cameraservice.device.CaptureResultExtras resultExtras, in long timestamp);
+  oneway void onDeviceError(in android.frameworks.cameraservice.device.ErrorCode errorCode, in android.frameworks.cameraservice.device.CaptureResultExtras resultExtras);
+  oneway void onDeviceIdle();
+  oneway void onPrepared(in int streamId);
+  oneway void onRepeatingRequestError(in long lastFrameNumber, in int repeatingRequestId);
+  oneway void onResultReceived(in android.frameworks.cameraservice.device.CaptureMetadataInfo result, in android.frameworks.cameraservice.device.CaptureResultExtras resultExtras, in android.frameworks.cameraservice.device.PhysicalCaptureResultInfo[] physicalCaptureResultInfos);
+  oneway void onClientSharedAccessPriorityChanged(boolean primaryClient);
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
new file mode 100644
index 0000000..12f001c
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
@@ -0,0 +1,54 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+interface ICameraDeviceUser {
+  void beginConfigure();
+  long cancelRepeatingRequest();
+  android.frameworks.cameraservice.device.CameraMetadata createDefaultRequest(in android.frameworks.cameraservice.device.TemplateId templateId);
+  int createStream(in android.frameworks.cameraservice.device.OutputConfiguration outputConfiguration);
+  void deleteStream(in int streamId);
+  void disconnect();
+  void endConfigure(in android.frameworks.cameraservice.device.StreamConfigurationMode operatingMode, in android.frameworks.cameraservice.device.CameraMetadata sessionParams, in long startTimeNs);
+  long flush();
+  android.hardware.common.fmq.MQDescriptor<byte,android.hardware.common.fmq.SynchronizedReadWrite> getCaptureRequestMetadataQueue();
+  android.hardware.common.fmq.MQDescriptor<byte,android.hardware.common.fmq.SynchronizedReadWrite> getCaptureResultMetadataQueue();
+  boolean isSessionConfigurationSupported(in android.frameworks.cameraservice.device.SessionConfiguration sessionConfiguration);
+  void prepare(in int streamId);
+  android.frameworks.cameraservice.device.SubmitInfo submitRequestList(in android.frameworks.cameraservice.device.CaptureRequest[] requestList, in boolean isRepeating);
+  void updateOutputConfiguration(in int streamId, in android.frameworks.cameraservice.device.OutputConfiguration outputConfiguration);
+  void waitUntilIdle();
+  boolean isPrimaryClient();
+  android.frameworks.cameraservice.device.SubmitInfo startStreaming(in int[] streamIdxArray, in int[] surfaceIdxArray);
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/OutputConfiguration.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/OutputConfiguration.aidl
new file mode 100644
index 0000000..9546948
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/OutputConfiguration.aidl
@@ -0,0 +1,59 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable OutputConfiguration {
+  /**
+   * @deprecated Use surfaces instead.
+   */
+  android.hardware.common.NativeHandle[] windowHandles;
+  android.frameworks.cameraservice.device.OutputConfiguration.Rotation rotation;
+  int windowGroupId;
+  String physicalCameraId;
+  int width;
+  int height;
+  boolean isDeferred;
+  android.view.Surface[] surfaces = {};
+  @Backing(type="int") @VintfStability
+  enum Rotation {
+    R0 = 0,
+    R90 = 1,
+    R180 = 2,
+    R270 = 3,
+  }
+  @Backing(type="int") @VintfStability
+  enum WindowGroupId {
+    NONE = (-1) /* -1 */,
+  }
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/PhysicalCameraSettings.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/PhysicalCameraSettings.aidl
new file mode 100644
index 0000000..622b3a1
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/PhysicalCameraSettings.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable PhysicalCameraSettings {
+  String id;
+  android.frameworks.cameraservice.device.CaptureMetadataInfo settings;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/PhysicalCaptureResultInfo.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/PhysicalCaptureResultInfo.aidl
new file mode 100644
index 0000000..7d1b1a9
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/PhysicalCaptureResultInfo.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable PhysicalCaptureResultInfo {
+  String physicalCameraId;
+  android.frameworks.cameraservice.device.CaptureMetadataInfo physicalCameraMetadata;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/SessionConfiguration.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/SessionConfiguration.aidl
new file mode 100644
index 0000000..f6f3773
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/SessionConfiguration.aidl
@@ -0,0 +1,42 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable SessionConfiguration {
+  android.frameworks.cameraservice.device.OutputConfiguration[] outputStreams;
+  int inputWidth;
+  int inputHeight;
+  int inputFormat;
+  android.frameworks.cameraservice.device.StreamConfigurationMode operationMode;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/StreamAndWindowId.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/StreamAndWindowId.aidl
new file mode 100644
index 0000000..23da63a
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/StreamAndWindowId.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable StreamAndWindowId {
+  int streamId;
+  int windowId;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/StreamConfigurationMode.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/StreamConfigurationMode.aidl
new file mode 100644
index 0000000..ff888f5
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/StreamConfigurationMode.aidl
@@ -0,0 +1,47 @@
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
+package android.frameworks.cameraservice.device;
+@Backing(type="int") @VintfStability
+enum StreamConfigurationMode {
+  NORMAL_MODE = 0,
+  CONSTRAINED_HIGH_SPEED_MODE = 1,
+  VENDOR_MODE_0 = 0x8000,
+  VENDOR_MODE_1,
+  VENDOR_MODE_2,
+  VENDOR_MODE_3,
+  VENDOR_MODE_4,
+  VENDOR_MODE_5,
+  VENDOR_MODE_6,
+  VENDOR_MODE_7,
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/SubmitInfo.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/SubmitInfo.aidl
new file mode 100644
index 0000000..5154ed3
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/SubmitInfo.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.device;
+@VintfStability
+parcelable SubmitInfo {
+  int requestId;
+  long lastFrameNumber;
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/TemplateId.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/TemplateId.aidl
new file mode 100644
index 0000000..89c5d68
--- /dev/null
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/3/android/frameworks/cameraservice/device/TemplateId.aidl
@@ -0,0 +1,43 @@
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
+package android.frameworks.cameraservice.device;
+@Backing(type="int") @VintfStability
+enum TemplateId {
+  PREVIEW = 1,
+  STILL_CAPTURE = 2,
+  RECORD = 3,
+  VIDEO_SNAPSHOT = 4,
+  ZERO_SHUTTER_LAG = 5,
+  MANUAL = 6,
+}
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
index 5248882..12f001c 100644
--- a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
@@ -50,4 +50,5 @@ interface ICameraDeviceUser {
   void updateOutputConfiguration(in int streamId, in android.frameworks.cameraservice.device.OutputConfiguration outputConfiguration);
   void waitUntilIdle();
   boolean isPrimaryClient();
+  android.frameworks.cameraservice.device.SubmitInfo startStreaming(in int[] streamIdxArray, in int[] surfaceIdxArray);
 }
diff --git a/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl b/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
index 3eccc71..5e6d14f 100644
--- a/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
+++ b/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
@@ -270,4 +270,18 @@ interface ICameraDeviceUser {
      *         false if another higher priority client with primary access is also using the camera.
      */
     boolean isPrimaryClient();
+
+    /**
+     * For shared capture session, send request to start streaming on the surfaces provided.
+     *
+     * @param streamIdxArray The list of stream ids
+     * @param surfaceIdxArray The list of surface ids
+     *
+     * @throws ServiceSpecificException on failure with error code set to Status corresponding to
+     *         the specific failure.
+     * @return SubmitInfo data structure containing the request id of the capture request and the
+     *         frame number of the last request, of the previous batch of repeating requests, if
+     *         any. If there is no previous  batch, the frame number returned will be -1.
+     */
+    SubmitInfo startStreaming(in int[] streamIdxArray, in int[] surfaceIdxArray);
 }
diff --git a/cameraservice/service/aidl/Android.bp b/cameraservice/service/aidl/Android.bp
index c69cf62..3aaa463 100644
--- a/cameraservice/service/aidl/Android.bp
+++ b/cameraservice/service/aidl/Android.bp
@@ -11,7 +11,7 @@ aidl_interface {
         "android.frameworks.cameraservice.common-V1",
         "android.frameworks.cameraservice.device-V3",
     ],
-    frozen: false,
+    frozen: true,
     backend: {
         cpp: {
             enabled: false,
@@ -43,6 +43,13 @@ aidl_interface {
                 "android.frameworks.cameraservice.device-V2",
             ],
         },
+        {
+            version: "3",
+            imports: [
+                "android.frameworks.cameraservice.common-V1",
+                "android.frameworks.cameraservice.device-V3",
+            ],
+        },
 
     ],
 
diff --git a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/.hash b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/.hash
new file mode 100644
index 0000000..eb96fff
--- /dev/null
+++ b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/.hash
@@ -0,0 +1 @@
+61fdb4c4ec535a1d0fce2fffb8696f5ab0976460
diff --git a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/CameraDeviceStatus.aidl b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/CameraDeviceStatus.aidl
new file mode 100644
index 0000000..a809751
--- /dev/null
+++ b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/CameraDeviceStatus.aidl
@@ -0,0 +1,42 @@
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
+package android.frameworks.cameraservice.service;
+@Backing(type="int") @VintfStability
+enum CameraDeviceStatus {
+  STATUS_NOT_AVAILABLE = (-2) /* -2 */,
+  STATUS_UNKNOWN = (-1) /* -1 */,
+  STATUS_NOT_PRESENT = 0,
+  STATUS_PRESENT = 1,
+  STATUS_ENUMERATING = 2,
+}
diff --git a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/CameraStatusAndId.aidl b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/CameraStatusAndId.aidl
new file mode 100644
index 0000000..4a92a45
--- /dev/null
+++ b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/CameraStatusAndId.aidl
@@ -0,0 +1,40 @@
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
+package android.frameworks.cameraservice.service;
+@VintfStability
+parcelable CameraStatusAndId {
+  android.frameworks.cameraservice.service.CameraDeviceStatus deviceStatus;
+  String cameraId;
+  String[] unavailPhysicalCameraIds;
+}
diff --git a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/ICameraService.aidl b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/ICameraService.aidl
new file mode 100644
index 0000000..14f381f
--- /dev/null
+++ b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/ICameraService.aidl
@@ -0,0 +1,43 @@
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
+package android.frameworks.cameraservice.service;
+@VintfStability
+interface ICameraService {
+  android.frameworks.cameraservice.service.CameraStatusAndId[] addListener(in android.frameworks.cameraservice.service.ICameraServiceListener listener);
+  android.frameworks.cameraservice.device.ICameraDeviceUser connectDevice(in android.frameworks.cameraservice.device.ICameraDeviceCallback callback, in String cameraId);
+  android.frameworks.cameraservice.device.CameraMetadata getCameraCharacteristics(in String cameraId);
+  android.frameworks.cameraservice.common.ProviderIdAndVendorTagSections[] getCameraVendorTagSections();
+  void removeListener(in android.frameworks.cameraservice.service.ICameraServiceListener listener);
+  android.frameworks.cameraservice.device.ICameraDeviceUser connectDeviceV2(in android.frameworks.cameraservice.device.ICameraDeviceCallback callback, in String cameraId, in boolean sharedMode);
+}
diff --git a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/ICameraServiceListener.aidl b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/ICameraServiceListener.aidl
new file mode 100644
index 0000000..fcce780
--- /dev/null
+++ b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/3/android/frameworks/cameraservice/service/ICameraServiceListener.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.cameraservice.service;
+@VintfStability
+interface ICameraServiceListener {
+  oneway void onPhysicalCameraStatusChanged(in android.frameworks.cameraservice.service.CameraDeviceStatus status, in String cameraId, in String physicalCameraId);
+  oneway void onStatusChanged(in android.frameworks.cameraservice.service.CameraDeviceStatus status, in String cameraId);
+}
diff --git a/cameraservice/vts/functional/Android.bp b/cameraservice/vts/functional/Android.bp
index e430479..2e44fdf 100644
--- a/cameraservice/vts/functional/Android.bp
+++ b/cameraservice/vts/functional/Android.bp
@@ -117,8 +117,8 @@ cc_test {
         "android.hardware.common.fmq-V1-ndk",
         "android.hardware.camera.common-helper",
         "android.frameworks.cameraservice.common-V1-ndk",
-        "android.frameworks.cameraservice.device-V2-ndk",
-        "android.frameworks.cameraservice.service-V2-ndk",
+        "android.frameworks.cameraservice.device-V3-ndk",
+        "android.frameworks.cameraservice.service-V3-ndk",
         "libaidlcommonsupport",
         "libfmq",
         "libarect",
@@ -132,7 +132,6 @@ cc_test {
         "libnativewindow",
         "liblog",
     ],
-
     test_config: "VtsAidlCameraServiceTargetTest.xml",
     test_suites: ["vts"],
 }
diff --git a/cameraservice/vts/functional/VtsAidlCameraServiceTargetTest.cpp b/cameraservice/vts/functional/VtsAidlCameraServiceTargetTest.cpp
index e0b9e67..5c24303 100644
--- a/cameraservice/vts/functional/VtsAidlCameraServiceTargetTest.cpp
+++ b/cameraservice/vts/functional/VtsAidlCameraServiceTargetTest.cpp
@@ -83,6 +83,8 @@ static constexpr int kVGAImageWidth = 640;
 static constexpr int kVGAImageHeight = 480;
 static constexpr int kNumRequests = 4;
 
+static const char kCameraServiceDisabledProperty[] = "config.disable_cameraservice";
+
 #define IDLE_TIMEOUT 2000000000  // ns
 
 using scoped_unique_image_reader = std::unique_ptr<AImageReader, decltype(&AImageReader_delete)>;
@@ -139,7 +141,6 @@ class CameraServiceListener : public BnCameraServiceListener {
 class CameraDeviceCallback : public BnCameraDeviceCallback {
    public:
     enum LocalCameraDeviceStatus {
-        IDLE,
         ERROR,
         RUNNING,
         RESULT_RECEIVED,
@@ -148,6 +149,8 @@ class CameraDeviceCallback : public BnCameraDeviceCallback {
     };
 
    protected:
+    bool mSupportsPartialResults = false;
+    int32_t mPartialResultCount = 0;
     bool mError = false;
     LocalCameraDeviceStatus mLastStatus = UNINITIALIZED;
     mutable std::vector<LocalCameraDeviceStatus> mStatusesHit;
@@ -156,9 +159,11 @@ class CameraDeviceCallback : public BnCameraDeviceCallback {
     mutable Mutex mLock;
     mutable Condition mStatusCondition;
     mutable Condition mPreparedCondition;
+    mutable bool mIsIdle = false;
 
    public:
-    CameraDeviceCallback() {}
+    CameraDeviceCallback(bool supportsPartialResults, int32_t partialResultCount) :
+        mSupportsPartialResults(supportsPartialResults), mPartialResultCount(partialResultCount) {}
 
     ndk::ScopedAStatus onDeviceError(ErrorCode in_errorCode,
                                      const CaptureResultExtras& /*in_resultExtras*/) override {
@@ -173,8 +178,7 @@ class CameraDeviceCallback : public BnCameraDeviceCallback {
 
     ndk::ScopedAStatus onDeviceIdle() override {
         Mutex::Autolock l(mLock);
-        mLastStatus = IDLE;
-        mStatusesHit.push_back(mLastStatus);
+        mIsIdle = true;
         mStatusCondition.broadcast();
         return ndk::ScopedAStatus::ok();
     }
@@ -183,14 +187,21 @@ class CameraDeviceCallback : public BnCameraDeviceCallback {
                                         int64_t /*in_timestamp*/) override {
         Mutex::Autolock l(mLock);
         mLastStatus = RUNNING;
+        mIsIdle = false;
         mStatusesHit.push_back(mLastStatus);
         mStatusCondition.broadcast();
         return ndk::ScopedAStatus::ok();
     }
 
     ndk::ScopedAStatus onResultReceived(
-        const CaptureMetadataInfo& /*in_result*/, const CaptureResultExtras& /*in_resultExtras*/,
+        const CaptureMetadataInfo& /*in_result*/, const CaptureResultExtras& in_resultExtras,
         const std::vector<PhysicalCaptureResultInfo>& /*in_physicalCaptureResultInfos*/) override {
+        if (mSupportsPartialResults &&
+                (in_resultExtras.partialResultCount != mPartialResultCount)) {
+            ALOGV("%s: Ignoring requestId: %d parial count: %d", __FUNCTION__,
+                    in_resultExtras.requestId, in_resultExtras.partialResultCount);
+            return ndk::ScopedAStatus::ok();
+        }
         Mutex::Autolock l(mLock);
         mLastStatus = RESULT_RECEIVED;
         mStatusesHit.push_back(mLastStatus);
@@ -217,6 +228,10 @@ class CameraDeviceCallback : public BnCameraDeviceCallback {
         return ndk::ScopedAStatus::ok();
     }
 
+    ndk::ScopedAStatus onClientSharedAccessPriorityChanged(bool /*isPrimaryClient*/) override {
+        return ndk::ScopedAStatus::ok();
+    }
+
     bool waitForPreparedCount(int streamId, int count) const {
         Mutex::Autolock l(mLock);
         if ((mStreamsPreparedCount.find(streamId) != mStreamsPreparedCount.end()) &&
@@ -234,26 +249,36 @@ class CameraDeviceCallback : public BnCameraDeviceCallback {
     }
 
     // Test helper functions:
-    bool waitForStatus(LocalCameraDeviceStatus status) const {
+    bool waitForStatus(LocalCameraDeviceStatus status, int count) const {
         Mutex::Autolock l(mLock);
-        if (mLastStatus == status) {
-            return true;
-        }
-
-        while (std::find(mStatusesHit.begin(), mStatusesHit.end(), status) == mStatusesHit.end()) {
+        while (std::count(mStatusesHit.begin(), mStatusesHit.end(), status) < count) {
             if (mStatusCondition.waitRelative(mLock, IDLE_TIMEOUT) != android::OK) {
                 mStatusesHit.clear();
                 return false;
             }
         }
         mStatusesHit.clear();
-
         return true;
     }
 
-    bool waitForIdle() const { return waitForStatus(IDLE); }
+    // There is a *very* slim change of onCaptureStarted gets delayed after onIdle in
+    // cameraserver. If that happens, this wait will become invalid.
+    bool waitForIdle() const {
+        Mutex::Autolock l(mLock);
+        while (!mIsIdle) {
+            if (mStatusCondition.waitRelative(mLock, IDLE_TIMEOUT) != android::OK) {
+                return false;
+            }
+        }
+
+        return true;
+    }
 };
 
+static bool isCameraServiceDisabled() {
+    return ::android::base::GetBoolProperty(kCameraServiceDisabledProperty, false);
+}
+
 static bool convertFromAidlCloned(const AidlCameraMetadata& metadata, CameraMetadata* rawMetadata) {
     const camera_metadata* buffer = (camera_metadata_t*)(metadata.metadata.data());
     size_t expectedSize = metadata.metadata.size();
@@ -275,6 +300,11 @@ struct StreamConfiguration {
 class VtsAidlCameraServiceTargetTest : public ::testing::TestWithParam<std::string> {
    public:
     void SetUp() override {
+        if (isCameraServiceDisabled()) {
+            ALOGI("Camera service is disabled on the device");
+            GTEST_SKIP() << "Camera service disabled, skipping this test";
+        }
+
         bool success = ABinderProcess_setThreadPoolMaxThreadCount(5);
         ASSERT_TRUE(success);
         ABinderProcess_startThreadPool();
@@ -405,8 +435,17 @@ class VtsAidlCameraServiceTargetTest : public ::testing::TestWithParam<std::stri
             EXPECT_TRUE(cStatus);
             EXPECT_FALSE(rawMetadata.isEmpty());
 
+            bool partialResultSupported = false;
+            int32_t partialResultCount = 0;
+            auto entry = rawMetadata.find(ANDROID_REQUEST_PARTIAL_RESULT_COUNT);
+            if (entry.count > 0) {
+                partialResultCount = entry.data.i32[0];
+                partialResultSupported = true;
+            }
+
             std::shared_ptr<CameraDeviceCallback> callbacks =
-                ndk::SharedRefBase::make<CameraDeviceCallback>();
+                ndk::SharedRefBase::make<CameraDeviceCallback>(partialResultSupported,
+                        partialResultCount);
             std::shared_ptr<ICameraDeviceUser> deviceRemote = nullptr;
             ret = mCameraService->connectDevice(callbacks, it.cameraId, &deviceRemote);
             EXPECT_TRUE(ret.isOk());
@@ -515,7 +554,7 @@ class VtsAidlCameraServiceTargetTest : public ::testing::TestWithParam<std::stri
             EXPECT_TRUE(ret.isOk());
             EXPECT_GE(info.requestId, 0);
             EXPECT_TRUE(callbacks->waitForStatus(
-                CameraDeviceCallback::LocalCameraDeviceStatus::RESULT_RECEIVED));
+                CameraDeviceCallback::LocalCameraDeviceStatus::RESULT_RECEIVED, kNumRequests));
             EXPECT_TRUE(callbacks->waitForIdle());
 
             // Test repeating requests
@@ -531,7 +570,7 @@ class VtsAidlCameraServiceTargetTest : public ::testing::TestWithParam<std::stri
             ret = deviceRemote->submitRequestList({captureRequest}, true, &info);
             EXPECT_TRUE(ret.isOk());
             EXPECT_TRUE(callbacks->waitForStatus(
-                CameraDeviceCallback::LocalCameraDeviceStatus::RESULT_RECEIVED));
+                CameraDeviceCallback::LocalCameraDeviceStatus::RESULT_RECEIVED, 1));
 
             int64_t lastFrameNumber = -1;
             ret = deviceRemote->cancelRepeatingRequest(&lastFrameNumber);
@@ -635,6 +674,139 @@ TEST_P(VtsAidlCameraServiceTargetTest, CameraServiceListenerTest) {
     EXPECT_TRUE(ret.isOk());
 }
 
+TEST_P(VtsAidlCameraServiceTargetTest, SharedCameraTest) {
+    if (mCameraService == nullptr) {
+        ALOGE("Cameraservice is not available");
+        return;
+    }
+
+    std::shared_ptr<CameraServiceListener> listener =
+        ::ndk::SharedRefBase::make<CameraServiceListener>();
+    std::vector<CameraStatusAndId> cameraStatuses;
+    ndk::ScopedAStatus ret = mCameraService->addListener(listener, &cameraStatuses);
+    EXPECT_TRUE(ret.isOk());
+    listener->initializeStatuses(cameraStatuses);
+    for (const auto& it : cameraStatuses) {
+        if (it.deviceStatus != CameraDeviceStatus::STATUS_PRESENT) {
+            continue;
+        }
+        AidlCameraMetadata aidlMetadata;
+        CameraMetadata rawMetadata;
+        ret = mCameraService->getCameraCharacteristics(it.cameraId, &aidlMetadata);
+        EXPECT_TRUE(ret.isOk());
+        bool cStatus = convertFromAidlCloned(aidlMetadata, &rawMetadata);
+        EXPECT_TRUE(cStatus);
+        EXPECT_FALSE(rawMetadata.isEmpty());
+
+        // Shared camera is only supported for system cameras.
+        bool isSystemCamera =
+            doesCapabilityExist(rawMetadata, ANDROID_REQUEST_AVAILABLE_CAPABILITIES_SYSTEM_CAMERA);
+        if (!isSystemCamera) {
+            continue;
+        }
+
+        auto entry = rawMetadata.find(ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS);
+        if (entry.count <= 0) {
+            continue;
+        }
+        int32_t width, height, format, physicalCamIdLen;
+        width = -1;
+
+        // From frameworks/av/camera/include/camera/camera2/OutputConfiguration.h
+        const int SURFACE_TYPE_IMAGE_READER = 4;
+        for (size_t i = 0; i < entry.count;) {
+            if (entry.data.i64[i] == SURFACE_TYPE_IMAGE_READER) {
+                width = entry.data.i64[i + 1];
+                height = entry.data.i64[i + 2];
+                format = entry.data.i64[i + 3];
+                break;
+            }
+            physicalCamIdLen = i + 10;
+            i += 11 + physicalCamIdLen;
+        }
+
+        if (width == -1) {
+            continue;
+        }
+
+        bool partialResultSupported = false;
+        int32_t partialResultCount = 0;
+        entry = rawMetadata.find(ANDROID_REQUEST_PARTIAL_RESULT_COUNT);
+        if (entry.count > 0) {
+            partialResultCount = entry.data.i32[0];
+            partialResultSupported = true;
+        }
+
+        std::shared_ptr<CameraDeviceCallback> callbacks =
+            ndk::SharedRefBase::make<CameraDeviceCallback>(partialResultSupported,
+                                                           partialResultCount);
+        std::shared_ptr<ICameraDeviceUser> deviceRemote = nullptr;
+        ret = mCameraService->connectDeviceV2(callbacks, it.cameraId, /*sharedMode*/ true,
+                                              &deviceRemote);
+        EXPECT_TRUE(ret.isOk());
+        EXPECT_TRUE(deviceRemote != nullptr);
+        bool isPrimaryClient;
+        ret = deviceRemote->isPrimaryClient(&isPrimaryClient);
+        EXPECT_TRUE(ret.isOk());
+        // Since this is the only client, it should be the primary client.
+        EXPECT_TRUE(isPrimaryClient);
+        status_t status = OK;
+        AImageReader* reader = nullptr;
+        const int NUM_TEST_IMAGES = 10;
+        status = AImageReader_new(width, height, format, NUM_TEST_IMAGES, &reader);
+        EXPECT_EQ(status, AMEDIA_OK);
+        scoped_unique_image_reader readerPtr =
+            scoped_unique_image_reader(reader, AImageReader_delete);
+        ANativeWindow* anw = nullptr;
+        status = AImageReader_getWindow(readerPtr.get(), &anw);
+        EXPECT_TRUE(status == AMEDIA_OK && anw != nullptr);
+
+        OutputConfiguration output = createOutputConfiguration({anw});
+
+        ret = deviceRemote->beginConfigure();
+        EXPECT_TRUE(ret.isOk());
+
+        int32_t streamId = -1;
+        ret = deviceRemote->createStream(output, &streamId);
+        EXPECT_TRUE(ret.isOk());
+        EXPECT_TRUE(streamId >= 0);
+
+        AidlCameraMetadata sessionParams;
+        ret = deviceRemote->endConfigure(StreamConfigurationMode::NORMAL_MODE, sessionParams,
+                                         systemTime());
+        EXPECT_TRUE(ret.isOk());
+
+        SubmitInfo info;
+        std::vector<int> streamIds;
+        std::vector<int> surfaceIds;
+        streamIds.push_back(streamId);
+        surfaceIds.push_back(0);
+        ret = deviceRemote->startStreaming(streamIds, surfaceIds, &info);
+        EXPECT_TRUE(ret.isOk());
+        EXPECT_GE(info.requestId, 0);
+        EXPECT_TRUE(callbacks->waitForStatus(
+            CameraDeviceCallback::LocalCameraDeviceStatus::RESULT_RECEIVED, 1));
+
+        int64_t lastFrameNumber = -1;
+        ret = deviceRemote->cancelRepeatingRequest(&lastFrameNumber);
+        EXPECT_TRUE(ret.isOk());
+        EXPECT_GE(lastFrameNumber, 0);
+
+        // Test waitUntilIdle()
+        ret = deviceRemote->waitUntilIdle();
+        EXPECT_TRUE(ret.isOk());
+
+        // Test deleteStream()
+        ret = deviceRemote->deleteStream(streamId);
+        EXPECT_TRUE(ret.isOk());
+
+        ret = deviceRemote->disconnect();
+        EXPECT_TRUE(ret.isOk());
+    }
+    ret = mCameraService->removeListener(listener);
+    EXPECT_TRUE(ret.isOk());
+}
+
 GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(VtsAidlCameraServiceTargetTest);
 INSTANTIATE_TEST_SUITE_P(PerInstance, VtsAidlCameraServiceTargetTest,
                          testing::ValuesIn({std::string(ICameraService::descriptor) + "/default"}),
diff --git a/devicestate/aidl/Android.bp b/devicestate/aidl/Android.bp
index cb7b228..a3d2b7c 100644
--- a/devicestate/aidl/Android.bp
+++ b/devicestate/aidl/Android.bp
@@ -36,5 +36,12 @@ aidl_interface {
             enabled: true,
         },
     },
-    frozen: false,
+    frozen: true,
+    versions_with_info: [
+        {
+            version: "1",
+            imports: [],
+        },
+    ],
+
 }
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/.hash b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/.hash
new file mode 100644
index 0000000..cd3300b
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/.hash
@@ -0,0 +1 @@
+be9013fedb7fc3886980eca0e588bce998d315d2
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/DeviceStateConfiguration.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/DeviceStateConfiguration.aidl
new file mode 100644
index 0000000..0e89570
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/DeviceStateConfiguration.aidl
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
+package android.frameworks.devicestate;
+@VintfStability
+parcelable DeviceStateConfiguration {
+  long deviceProperties;
+  @Backing(type="long") @VintfStability
+  enum DeviceStatePropertyValue {
+    FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED = (1 << 0) /* 1 */,
+    FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN = (1 << 1) /* 2 */,
+    FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN = (1 << 2) /* 4 */,
+    FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY = (1 << 3) /* 8 */,
+    FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY = (1 << 4) /* 16 */,
+    FEATURE_REAR_DISPLAY = (1 << 5) /* 32 */,
+    FEATURE_DUAL_DISPLAY = (1 << 6) /* 64 */,
+  }
+}
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/ErrorCode.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/ErrorCode.aidl
new file mode 100644
index 0000000..21df404
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/ErrorCode.aidl
@@ -0,0 +1,40 @@
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
+package android.frameworks.devicestate;
+@Backing(type="int") @VintfStability
+enum ErrorCode {
+  OK,
+  BAD_INPUT,
+  ALREADY_EXISTS,
+}
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/IDeviceStateListener.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/IDeviceStateListener.aidl
new file mode 100644
index 0000000..309eaf5
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/IDeviceStateListener.aidl
@@ -0,0 +1,38 @@
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
+package android.frameworks.devicestate;
+@VintfStability
+interface IDeviceStateListener {
+  oneway void onDeviceStateChanged(in android.frameworks.devicestate.DeviceStateConfiguration deviceState);
+}
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/IDeviceStateService.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/IDeviceStateService.aidl
new file mode 100644
index 0000000..b1046a6
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/1/android/frameworks/devicestate/IDeviceStateService.aidl
@@ -0,0 +1,39 @@
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
+package android.frameworks.devicestate;
+@VintfStability
+interface IDeviceStateService {
+  void registerListener(in android.frameworks.devicestate.IDeviceStateListener listener);
+  void unregisterListener(in android.frameworks.devicestate.IDeviceStateListener listener);
+}
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl
index 2a1cbb1..21df404 100644
--- a/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl
@@ -34,7 +34,7 @@
 package android.frameworks.devicestate;
 @Backing(type="int") @VintfStability
 enum ErrorCode {
-  OK = 0,
-  BAD_INPUT = 1,
-  ALREADY_EXISTS = 1,
+  OK,
+  BAD_INPUT,
+  ALREADY_EXISTS,
 }
diff --git a/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl b/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl
index c410d35..1a91b9c 100644
--- a/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl
+++ b/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl
@@ -19,18 +19,18 @@ package android.frameworks.devicestate;
 @VintfStability
 @Backing(type="int")
 enum ErrorCode {
-     /**
+    /**
      * Successful call
      */
-    OK = 0,
+    OK,
 
     /**
      * Invalid argument
      */
-    BAD_INPUT = 1,
+    BAD_INPUT,
 
     /**
      * Trying to register a second listener from the same process
      */
-    ALREADY_EXISTS = 1,
+    ALREADY_EXISTS,
 }
diff --git a/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl b/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl
index 9717af1..662c1e8 100644
--- a/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl
+++ b/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl
@@ -20,7 +20,7 @@ import android.frameworks.devicestate.IDeviceStateListener;
 
 @VintfStability
 interface IDeviceStateService {
-     /**
+    /**
      * Registers a listener to receive notifications from the device state manager.
      * <p>Note that only one callback can be registered per-process.</p>
      *
diff --git a/displayservice/1.0/vts/functional/Android.bp b/displayservice/1.0/vts/functional/Android.bp
index 02f7c73..e9ccbc1 100644
--- a/displayservice/1.0/vts/functional/Android.bp
+++ b/displayservice/1.0/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_core_graphics_stack",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/location/altitude/aidl/vts/functional/Android.bp b/location/altitude/aidl/vts/functional/Android.bp
index a16f9d8..9aae9aa 100644
--- a/location/altitude/aidl/vts/functional/Android.bp
+++ b/location/altitude/aidl/vts/functional/Android.bp
@@ -15,6 +15,7 @@
  */
 
 package {
+    default_team: "trendy_team_location_time",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/sensorservice/1.0/vts/OWNERS b/sensorservice/1.0/vts/OWNERS
index 90c2330..4929b3f 100644
--- a/sensorservice/1.0/vts/OWNERS
+++ b/sensorservice/1.0/vts/OWNERS
@@ -1,3 +1 @@
-arthuri@google.com
-bduddie@google.com
-stange@google.com
+include platform/frameworks/native:/services/sensorservice/OWNERS
\ No newline at end of file
diff --git a/sensorservice/OWNERS b/sensorservice/OWNERS
index bf318f0..aa55b21 100644
--- a/sensorservice/OWNERS
+++ b/sensorservice/OWNERS
@@ -1 +1,2 @@
 # Bug component:151862
+include platform/frameworks/native:/services/sensorservice/OWNERS
\ No newline at end of file
diff --git a/sensorservice/aidl/vts/Android.bp b/sensorservice/aidl/vts/Android.bp
index 4a98e73..b550fbb 100644
--- a/sensorservice/aidl/vts/Android.bp
+++ b/sensorservice/aidl/vts/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_sensors",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -23,10 +24,13 @@ cc_test {
     defaults: [
         "VtsHalTargetTestDefaults",
         "use_libaidlvintf_gtest_helper_static",
+        "android.hardware.graphics.allocator-ndk_shared",
+        "android.hardware.graphics.common-ndk_shared",
     ],
     tidy_timeout_srcs: ["VtsHalSensorManagerTargetTest.cpp"],
     srcs: ["VtsHalSensorManagerTargetTest.cpp"],
     shared_libs: [
+        "libui",
         "libcutils",
         "libbinder_ndk",
         "android.hardware.sensors-V3-ndk",
diff --git a/sensorservice/aidl/vts/VtsHalSensorManagerTargetTest.cpp b/sensorservice/aidl/vts/VtsHalSensorManagerTargetTest.cpp
index 1897264..d8d22bf 100644
--- a/sensorservice/aidl/vts/VtsHalSensorManagerTargetTest.cpp
+++ b/sensorservice/aidl/vts/VtsHalSensorManagerTargetTest.cpp
@@ -18,6 +18,10 @@
 #include <aidl/Gtest.h>
 #include <aidl/Vintf.h>
 #include <aidl/android/frameworks/sensorservice/ISensorManager.h>
+#include <aidl/android/frameworks/sensorservice/BnEventQueueCallback.h>
+#include <aidl/android/frameworks/sensorservice/IEventQueue.h>
+#include <aidl/android/hardware/graphics/common/BufferUsage.h>
+#include <aidl/android/hardware/graphics/common/PixelFormat.h>
 #include <aidl/sensors/convert.h>
 #include <android-base/logging.h>
 #include <android-base/result.h>
@@ -28,13 +32,18 @@
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 #include <sys/mman.h>
-
+#include <ui/GraphicBufferAllocator.h>
+#include <ui/GraphicBuffer.h>
 #include <chrono>
 #include <thread>
 
+using aidl::android::frameworks::sensorservice::BnEventQueueCallback;
+using aidl::android::frameworks::sensorservice::IEventQueue;
 using aidl::android::frameworks::sensorservice::IDirectReportChannel;
 using aidl::android::frameworks::sensorservice::ISensorManager;
 using aidl::android::hardware::common::Ashmem;
+using aidl::android::hardware::graphics::common::BufferUsage;
+using aidl::android::hardware::graphics::common::PixelFormat;
 using aidl::android::hardware::sensors::Event;
 using aidl::android::hardware::sensors::ISensors;
 using aidl::android::hardware::sensors::SensorInfo;
@@ -44,6 +53,29 @@ using ndk::ScopedAStatus;
 using ndk::ScopedFileDescriptor;
 using ::testing::Contains;
 
+class EventCallback : public BnEventQueueCallback {
+   public:
+    EventCallback() {}
+    ~EventCallback() {}
+    ndk::ScopedAStatus onEvent(const Event &e) override {
+        std::unique_lock<std::mutex> lck(mtx);
+        if (e.sensorType == SensorType::ACCELEROMETER && !eventReceived) {
+            eventReceived = true;
+            cv.notify_all();
+        }
+        return ndk::ScopedAStatus::ok();
+    }
+    void waitForEvent() {
+        std::unique_lock<std::mutex> lck(mtx);
+        cv.wait_for(lck, std::chrono::seconds(10), [this](){ return eventReceived; });
+        EXPECT_TRUE(eventReceived) << "wait event timeout";
+    }
+   private:
+    std::mutex mtx;
+    std::condition_variable_any cv;
+    bool eventReceived = false;
+};
+
 static inline ::testing::AssertionResult isOk(const ScopedAStatus& status) {
     return status.isOk() ? ::testing::AssertionSuccess()
                          : ::testing::AssertionFailure() << status.getDescription();
@@ -254,6 +286,57 @@ TEST_P(SensorManagerTest, Accelerometer) {
     }
 }
 
+TEST_P(SensorManagerTest, DISABLED_CreateGrallocDirectChannel) {
+    std::vector<SensorInfo> sensorList;
+    auto res = GetSensorList(&sensorList, [](const auto& info) {
+        return info.flags & SensorInfo::SENSOR_FLAG_BITS_DIRECT_CHANNEL_GRALLOC;
+    });
+    ASSERT_OK(res);
+    if (sensorList.empty()) {
+        GTEST_SKIP() << "DIRECT_CHANNEL_GRALLOC not supported by HAL, skipping";
+    }
+    static constexpr uint64_t kBufferUsage =
+        static_cast<uint64_t>(BufferUsage::SENSOR_DIRECT_DATA) |
+        static_cast<uint64_t>(BufferUsage::CPU_READ_OFTEN) |
+        static_cast<uint64_t>(BufferUsage::CPU_WRITE_RARELY);
+    uint32_t stride = 0;
+    buffer_handle_t bufferHandle;
+    android::status_t status = android::GraphicBufferAllocator::get().allocate(
+        ISensors::DIRECT_REPORT_SENSOR_EVENT_TOTAL_LENGTH, 1,
+        static_cast<int>(PixelFormat::BLOB), 1, kBufferUsage, &bufferHandle, &stride,
+        "sensorservice_vts");
+    ASSERT_TRUE(status == android::OK) << "failed to allocate memory";
+
+    std::shared_ptr<IDirectReportChannel> chan;
+    res = manager_->createGrallocDirectChannel(ScopedFileDescriptor(bufferHandle->data[0]),
+        ISensors::DIRECT_REPORT_SENSOR_EVENT_TOTAL_LENGTH, &chan);
+    EXPECT_OK(res);
+    ASSERT_NE(chan, nullptr);
+}
+
+TEST_P(SensorManagerTest, DISABLED_EnableAndDisableSensor) {
+    std::vector<SensorInfo> sensorList;
+    auto res = GetSensorList(
+        &sensorList, [](const auto& info) { return info.type == SensorType::ACCELEROMETER; });
+    ASSERT_OK(res);
+
+    SensorInfo info;
+    res = manager_->getDefaultSensor(SensorType::ACCELEROMETER, &info);
+    if (sensorList.empty()) {
+        GTEST_SKIP() << "No accelerometer sensor, skipping";
+    } else {
+        ASSERT_OK(res);
+        ASSERT_THAT(sensorList, Contains(info));
+    }
+    std::shared_ptr<EventCallback> mSensorEventCallback =
+        ndk::SharedRefBase::make<EventCallback>();
+    std::shared_ptr<IEventQueue> mSensorEventQueue;
+    ASSERT_OK(manager_->createEventQueue(mSensorEventCallback, &mSensorEventQueue));
+    ASSERT_OK(mSensorEventQueue->enableSensor(info.sensorHandle, info.minDelayUs, 0));
+    mSensorEventCallback->waitForEvent();
+    ASSERT_OK(mSensorEventQueue->disableSensor(info.sensorHandle));
+}
+
 GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(SensorManagerTest);
 INSTANTIATE_TEST_SUITE_P(
     PerInstance, SensorManagerTest,
diff --git a/sensorservice/libsensorndkbridge/OWNERS b/sensorservice/libsensorndkbridge/OWNERS
index 90c2330..4929b3f 100644
--- a/sensorservice/libsensorndkbridge/OWNERS
+++ b/sensorservice/libsensorndkbridge/OWNERS
@@ -1,3 +1 @@
-arthuri@google.com
-bduddie@google.com
-stange@google.com
+include platform/frameworks/native:/services/sensorservice/OWNERS
\ No newline at end of file
diff --git a/stats/1.0/test_client/OWNERS b/stats/1.0/test_client/OWNERS
index a95492a..e69de29 100644
--- a/stats/1.0/test_client/OWNERS
+++ b/stats/1.0/test_client/OWNERS
@@ -1,2 +0,0 @@
-maggiewhite@google.com
-yro@google.com
diff --git a/stats/aidl/test_client/AidlStatsClient.cpp b/stats/aidl/test_client/AidlStatsClient.cpp
index 3d4085b..fe003ab 100644
--- a/stats/aidl/test_client/AidlStatsClient.cpp
+++ b/stats/aidl/test_client/AidlStatsClient.cpp
@@ -16,7 +16,6 @@
 #include <aidl/android/frameworks/stats/IStats.h>
 #include <android/binder_manager.h>
 #include <getopt.h>
-#include <statslog.h>
 
 #include <iostream>
 
@@ -124,7 +123,7 @@ int main(int argc, char* argv[]) {
     // get instance of the aidl version
     const std::string instance = std::string() + IStats::descriptor + "/default";
     std::shared_ptr<IStats> service =
-        IStats::fromBinder(ndk::SpAIBinder(AServiceManager_getService(instance.c_str())));
+        IStats::fromBinder(ndk::SpAIBinder(AServiceManager_waitForService(instance.c_str())));
     if (!service) {
         std::cerr << "No Stats aidl HAL";
         return 1;
diff --git a/stats/aidl/test_client/Android.bp b/stats/aidl/test_client/Android.bp
index 5698619..d972e49 100644
--- a/stats/aidl/test_client/Android.bp
+++ b/stats/aidl/test_client/Android.bp
@@ -35,6 +35,5 @@ cc_binary {
         "libbase",
         "libbinder_ndk",
         "libutils",
-        "libstatslog",
     ],
 }
```

