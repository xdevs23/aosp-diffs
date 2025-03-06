```diff
diff --git a/Android.bp b/Android.bp
index 8ab10a5..3ac6938 100644
--- a/Android.bp
+++ b/Android.bp
@@ -5,3 +5,9 @@ package {
 hidl_package_root {
     name: "android.frameworks",
 }
+
+dirgroup {
+    name: "trusty_dirgroup_frameworks_hardware_interfaces",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/automotive/display/1.0/vts/functional/Android.bp b/automotive/display/1.0/vts/functional/Android.bp
index 7e14e58..e480029 100644
--- a/automotive/display/1.0/vts/functional/Android.bp
+++ b/automotive/display/1.0/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_perception_virtualization",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/automotive/display/aidl/vts/functional/Android.bp b/automotive/display/aidl/vts/functional/Android.bp
index 657e47b..a3d2211 100644
--- a/automotive/display/aidl/vts/functional/Android.bp
+++ b/automotive/display/aidl/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_perception_virtualization",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/automotive/telemetry/aidl/vts/functional/Android.bp b/automotive/telemetry/aidl/vts/functional/Android.bp
index 82009bd..3e0662e 100644
--- a/automotive/telemetry/aidl/vts/functional/Android.bp
+++ b/automotive/telemetry/aidl/vts/functional/Android.bp
@@ -14,6 +14,7 @@
 //
 
 package {
+    default_team: "trendy_team_connectivity_telemetry",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/cameraservice/device/aidl/Android.bp b/cameraservice/device/aidl/Android.bp
index 0265f77..cc6b829 100644
--- a/cameraservice/device/aidl/Android.bp
+++ b/cameraservice/device/aidl/Android.bp
@@ -15,7 +15,7 @@ aidl_interface {
     include_dirs: [
         "frameworks/native/aidl/gui",
     ],
-    frozen: true,
+    frozen: false,
     backend: {
         cpp: {
             enabled: false,
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
index 093ff80..e168173 100644
--- a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
@@ -40,4 +40,5 @@ interface ICameraDeviceCallback {
   oneway void onPrepared(in int streamId);
   oneway void onRepeatingRequestError(in long lastFrameNumber, in int repeatingRequestId);
   oneway void onResultReceived(in android.frameworks.cameraservice.device.CaptureMetadataInfo result, in android.frameworks.cameraservice.device.CaptureResultExtras resultExtras, in android.frameworks.cameraservice.device.PhysicalCaptureResultInfo[] physicalCaptureResultInfos);
+  oneway void onClientSharedAccessPriorityChanged(boolean primaryClient);
 }
diff --git a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
index 1b9b2c2..5248882 100644
--- a/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
+++ b/cameraservice/device/aidl/aidl_api/android.frameworks.cameraservice.device/current/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
@@ -49,4 +49,5 @@ interface ICameraDeviceUser {
   android.frameworks.cameraservice.device.SubmitInfo submitRequestList(in android.frameworks.cameraservice.device.CaptureRequest[] requestList, in boolean isRepeating);
   void updateOutputConfiguration(in int streamId, in android.frameworks.cameraservice.device.OutputConfiguration outputConfiguration);
   void waitUntilIdle();
+  boolean isPrimaryClient();
 }
diff --git a/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl b/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
index a6f1898..91972fd 100644
--- a/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
+++ b/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceCallback.aidl
@@ -83,4 +83,15 @@ oneway interface ICameraDeviceCallback {
      */
     void onResultReceived(in CaptureMetadataInfo result, in CaptureResultExtras resultExtras,
         in PhysicalCaptureResultInfo[] physicalCaptureResultInfos);
+
+    /**
+     * Notify registered clients about client access priority changes for the camera device
+     * opened in shared mode.
+     * If the client priority changed from secondary to primary,then it can now
+     * create capture request and change the capture request parameters. If client priority
+     * changed from primary to secondary, that implies that a higher priority client has also
+     * opened the camera in shared mode and the new client is now a primary client.
+     */
+    void onClientSharedAccessPriorityChanged(boolean primaryClient);
+
 }
diff --git a/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl b/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
index 2cf9a08..3eccc71 100644
--- a/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
+++ b/cameraservice/device/aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.aidl
@@ -262,4 +262,12 @@ interface ICameraDeviceUser {
      *      Status::INVALID_OPERATION if there are active repeating requests.
      */
     void waitUntilIdle();
+
+    /**
+     * Get the client status as primary or secondary when camera is opened in shared mode.
+     *
+     * @return true if this is primary client when camera is opened in shared mode.
+     *         false if another higher priority client with primary access is also using the camera.
+     */
+    boolean isPrimaryClient();
 }
diff --git a/cameraservice/service/aidl/Android.bp b/cameraservice/service/aidl/Android.bp
index c239057..c69cf62 100644
--- a/cameraservice/service/aidl/Android.bp
+++ b/cameraservice/service/aidl/Android.bp
@@ -9,9 +9,9 @@ aidl_interface {
     stability: "vintf",
     imports: [
         "android.frameworks.cameraservice.common-V1",
-        "android.frameworks.cameraservice.device-V2",
+        "android.frameworks.cameraservice.device-V3",
     ],
-    frozen: true,
+    frozen: false,
     backend: {
         cpp: {
             enabled: false,
diff --git a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/current/android/frameworks/cameraservice/service/ICameraService.aidl b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/current/android/frameworks/cameraservice/service/ICameraService.aidl
index 9bca528..14f381f 100644
--- a/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/current/android/frameworks/cameraservice/service/ICameraService.aidl
+++ b/cameraservice/service/aidl/aidl_api/android.frameworks.cameraservice.service/current/android/frameworks/cameraservice/service/ICameraService.aidl
@@ -39,4 +39,5 @@ interface ICameraService {
   android.frameworks.cameraservice.device.CameraMetadata getCameraCharacteristics(in String cameraId);
   android.frameworks.cameraservice.common.ProviderIdAndVendorTagSections[] getCameraVendorTagSections();
   void removeListener(in android.frameworks.cameraservice.service.ICameraServiceListener listener);
+  android.frameworks.cameraservice.device.ICameraDeviceUser connectDeviceV2(in android.frameworks.cameraservice.device.ICameraDeviceCallback callback, in String cameraId, in boolean sharedMode);
 }
diff --git a/cameraservice/service/aidl/android/frameworks/cameraservice/service/ICameraService.aidl b/cameraservice/service/aidl/android/frameworks/cameraservice/service/ICameraService.aidl
index ed5bc62..8b07740 100644
--- a/cameraservice/service/aidl/android/frameworks/cameraservice/service/ICameraService.aidl
+++ b/cameraservice/service/aidl/android/frameworks/cameraservice/service/ICameraService.aidl
@@ -108,4 +108,25 @@ interface ICameraService {
      *         the specific failure.
      */
     void removeListener(in ICameraServiceListener listener);
+
+    /**
+     * connectDeviceV2
+     *
+     * Return an ICameraDeviceUser interface for the requested cameraId.
+     *
+     * Note: The client must have camera permissions to call this method
+     *       successfully.
+     *
+     * @param callback the ICameraDeviceCallback interface which will get called
+     *        the cameraserver when capture is started, results are received
+     *        etc.
+     * @param cameraId the cameraId of the camera device to connect to.
+     * @param sharedMode set to true to open the camera in shared mode.
+     *
+     * @throws ServiceSpecificException on failure with error code set to Status corresponding to
+     *         the specific failure.
+     * @return ICameraDeviceUser interface to the camera device requested.
+     */
+    ICameraDeviceUser connectDeviceV2(in ICameraDeviceCallback callback,
+        in String cameraId, in boolean sharedMode);
 }
diff --git a/devicestate/OWNERS b/devicestate/OWNERS
new file mode 100644
index 0000000..ce90713
--- /dev/null
+++ b/devicestate/OWNERS
@@ -0,0 +1,2 @@
+include platform/frameworks/base:/services/core/java/com/android/server/devicestate/OWNERS
+epeev@google.com
diff --git a/devicestate/aidl/Android.bp b/devicestate/aidl/Android.bp
new file mode 100644
index 0000000..cb7b228
--- /dev/null
+++ b/devicestate/aidl/Android.bp
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
+package {
+    default_team: "trendy_team_camera_framework",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aidl_interface {
+    name: "android.frameworks.devicestate",
+    srcs: ["android/frameworks/devicestate/*.aidl"],
+    vendor_available: true,
+    host_supported: true,
+    stability: "vintf",
+    backend: {
+        java: {
+            platform_apis: true,
+        },
+        ndk: {
+            enabled: true,
+        },
+        cpp: {
+            enabled: true,
+        },
+    },
+    frozen: false,
+}
diff --git a/devicestate/aidl/TEST_MAPPING b/devicestate/aidl/TEST_MAPPING
new file mode 100644
index 0000000..b51c4c7
--- /dev/null
+++ b/devicestate/aidl/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "VtsHalDeviceStateServiceTargetTest"
+    }
+  ]
+}
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/DeviceStateConfiguration.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/DeviceStateConfiguration.aidl
new file mode 100644
index 0000000..0e89570
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/DeviceStateConfiguration.aidl
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
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl
new file mode 100644
index 0000000..2a1cbb1
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/ErrorCode.aidl
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
+  OK = 0,
+  BAD_INPUT = 1,
+  ALREADY_EXISTS = 1,
+}
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/IDeviceStateListener.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/IDeviceStateListener.aidl
new file mode 100644
index 0000000..309eaf5
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/IDeviceStateListener.aidl
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
diff --git a/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/IDeviceStateService.aidl b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/IDeviceStateService.aidl
new file mode 100644
index 0000000..b1046a6
--- /dev/null
+++ b/devicestate/aidl/aidl_api/android.frameworks.devicestate/current/android/frameworks/devicestate/IDeviceStateService.aidl
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
diff --git a/devicestate/aidl/android/frameworks/devicestate/DeviceStateConfiguration.aidl b/devicestate/aidl/android/frameworks/devicestate/DeviceStateConfiguration.aidl
new file mode 100644
index 0000000..cf032ee
--- /dev/null
+++ b/devicestate/aidl/android/frameworks/devicestate/DeviceStateConfiguration.aidl
@@ -0,0 +1,94 @@
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
+package android.frameworks.devicestate;
+
+/**
+ * Detailed description of a device state that includes separated lists of
+ * {@link DeviceStateSystemPropertyValue} and {@link DeviceStatePhysicalPropertyValue} for
+ *  properties that correspond to the state of the system when the device is in this state, as well
+ *  as physical properties that describe this state.
+ *
+ * @see android.hardware.devicestate.DeviceState
+ */
+@VintfStability
+parcelable DeviceStateConfiguration {
+    /**
+     * For more information about how these properties were defined
+     * @see android.hardware.devicestate.DeviceState
+     */
+    @VintfStability
+    @Backing(type="long")
+    enum DeviceStatePropertyValue {
+        /**
+         * Property that indicates that a fold-in style foldable device is currently in a fully closed
+         * configuration.
+         */
+        FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED = 1 << 0,
+
+        /**
+         * Property that indicates that a fold-in style foldable device is currently in a half-opened
+         * configuration.
+         * <p>This signifies that the device's hinge is positioned somewhere around 90
+         * degrees. Checking for display configuration properties as well can provide information
+         * on which display is currently active.</p>
+         */
+        FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN = 1 << 1,
+
+        /**
+         * Property that indicates that a fold-in style foldable device is currently in a fully open
+         * configuration.
+         */
+        FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN = 1 << 2,
+
+        /**
+         * Property that indicates that the outer display area of a foldable device is currently the
+         * primary display area.
+         *
+         * <p>Note: This does not necessarily mean that the outer display area is the
+         * default display. </p>
+         */
+        FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY = 1 << 3,
+
+        /**
+         * Property that indicates that the inner display area of a foldable device is currently the
+         * primary display area.
+         *
+         * <p>Note: This does not necessarily mean that the inner display area is the
+         * default display.</p>
+         */
+        FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY = 1 << 4,
+
+        /**
+         * Property that indicates that this state corresponds to the device state for rear display
+         * mode.
+         * <p>This means that the active display is facing the same direction as the rear camera.</p>
+         */
+        FEATURE_REAR_DISPLAY = 1 << 5,
+
+        /**
+         * Property that indicates that this state corresponds to the device state where both displays
+         * on a foldable are active, with the internal display being the default display.
+         */
+        FEATURE_DUAL_DISPLAY = 1 << 6,
+    }
+
+    /**
+    * The device properties is a bitfield of potential states, and some physical configurations
+    * could plausibly correspond to multiple different combinations of state bits.
+    */
+    long deviceProperties;
+}
diff --git a/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl b/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl
new file mode 100644
index 0000000..c410d35
--- /dev/null
+++ b/devicestate/aidl/android/frameworks/devicestate/ErrorCode.aidl
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
+package android.frameworks.devicestate;
+
+@VintfStability
+@Backing(type="int")
+enum ErrorCode {
+     /**
+     * Successful call
+     */
+    OK = 0,
+
+    /**
+     * Invalid argument
+     */
+    BAD_INPUT = 1,
+
+    /**
+     * Trying to register a second listener from the same process
+     */
+    ALREADY_EXISTS = 1,
+}
diff --git a/devicestate/aidl/android/frameworks/devicestate/IDeviceStateListener.aidl b/devicestate/aidl/android/frameworks/devicestate/IDeviceStateListener.aidl
new file mode 100644
index 0000000..f2d6273
--- /dev/null
+++ b/devicestate/aidl/android/frameworks/devicestate/IDeviceStateListener.aidl
@@ -0,0 +1,31 @@
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
+package android.frameworks.devicestate;
+
+import android.frameworks.devicestate.DeviceStateConfiguration;
+
+@VintfStability
+interface IDeviceStateListener {
+    /**
+     * Called in response to a change in {@link DeviceStateConfiguration}.
+     * <p>Guaranteed to be called once
+     * after successful registration of the callback with the initial value. </p>
+     *
+     * @param deviceState Current device state configuration
+     */
+    oneway void onDeviceStateChanged(in DeviceStateConfiguration deviceState);
+}
diff --git a/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl b/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl
new file mode 100644
index 0000000..9717af1
--- /dev/null
+++ b/devicestate/aidl/android/frameworks/devicestate/IDeviceStateService.aidl
@@ -0,0 +1,45 @@
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
+package android.frameworks.devicestate;
+
+import android.frameworks.devicestate.IDeviceStateListener;
+
+@VintfStability
+interface IDeviceStateService {
+     /**
+     * Registers a listener to receive notifications from the device state manager.
+     * <p>Note that only one callback can be registered per-process.</p>
+     *
+     * @param listener Device state listener
+     *
+     * @throws ServiceSpecificException with {@link ErrorCode#ALREADY_EXISTS}
+     *         if the client tries to register more than one listener
+     */
+    void registerListener(in IDeviceStateListener listener);
+
+    /**
+     * Removes a previously registered listener from the device state manager.
+     * <p>Registered listeners will also be automatically removed in case the client drops and
+     * the binder connection becomes invalid.</p>
+     *
+     * @param listener Device state listener
+     *
+     * @throws ServiceSpecificException with {@link ErrorCode#BAD_INPUT} if listener was not
+     *         registered
+     */
+    void unregisterListener(in IDeviceStateListener listener);
+}
diff --git a/devicestate/aidl/vts/functional/Android.bp b/devicestate/aidl/vts/functional/Android.bp
new file mode 100644
index 0000000..e09a697
--- /dev/null
+++ b/devicestate/aidl/vts/functional/Android.bp
@@ -0,0 +1,45 @@
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
+package {
+    default_team: "trendy_team_camera_framework",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "VtsHalDeviceStateServiceTargetTest",
+    defaults: [
+        "VtsHalTargetTestDefaults",
+        "use_libaidlvintf_gtest_helper_static",
+    ],
+    tidy_timeout_srcs: [
+        "VtsHalDeviceStateServiceTargetTest.cpp",
+    ],
+    srcs: [
+        "VtsHalDeviceStateServiceTargetTest.cpp",
+    ],
+    static_libs: [
+        "android.frameworks.devicestate-V1-ndk",
+        "libgmock",
+    ],
+    shared_libs: [
+        "libbinder_ndk",
+    ],
+    test_suites: [
+        "general-tests",
+        "vts",
+    ],
+}
diff --git a/devicestate/aidl/vts/functional/VtsHalDeviceStateServiceTargetTest.cpp b/devicestate/aidl/vts/functional/VtsHalDeviceStateServiceTargetTest.cpp
new file mode 100644
index 0000000..68645d0
--- /dev/null
+++ b/devicestate/aidl/vts/functional/VtsHalDeviceStateServiceTargetTest.cpp
@@ -0,0 +1,137 @@
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
+#include "aidl/android/frameworks/devicestate/DeviceStateConfiguration.h"
+#define LOG_TAG "VtsHalDeviceStateServiceTest"
+
+#include <unordered_set>
+
+#include "aidl/android/frameworks/devicestate/ErrorCode.h"
+
+#include <aidl/Gtest.h>
+#include <aidl/Vintf.h>
+#include <aidl/android/frameworks/devicestate/BnDeviceStateListener.h>
+#include <aidl/android/frameworks/devicestate/BnDeviceStateService.h>
+#include <android-base/logging.h>
+#include <android/binder_auto_utils.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+#include <utils/Condition.h>
+#include <utils/Log.h>
+#include <utils/Mutex.h>
+
+#include <memory>
+
+#include "aidl/android/frameworks/devicestate/IDeviceStateListener.h"
+#include "aidl/android/frameworks/devicestate/IDeviceStateService.h"
+
+#define NOTIFY_TIMEOUT_NS 2000000000
+
+namespace android {
+
+using ::aidl::android::frameworks::devicestate::BnDeviceStateListener;
+using ::aidl::android::frameworks::devicestate::DeviceStateConfiguration;
+using ::aidl::android::frameworks::devicestate::ErrorCode;
+using ::aidl::android::frameworks::devicestate::IDeviceStateService;
+using ::android::getAidlHalInstanceNames;
+using ::android::PrintInstanceNameToString;
+using ::ndk::enum_range;
+using ::ndk::SpAIBinder;
+using ::testing::InitGoogleTest;
+using ::testing::TestWithParam;
+
+class DeviceStateServiceTest : public ::testing::TestWithParam<std::string> {
+   public:
+    void SetUp() override {
+        bool ret = ABinderProcess_setThreadPoolMaxThreadCount(/* numThreads= */ 5);
+        ASSERT_TRUE(ret);
+        ABinderProcess_startThreadPool();
+        SpAIBinder binder(AServiceManager_waitForService(GetParam().c_str()));
+        service = IDeviceStateService::fromBinder(binder);
+        ASSERT_NE(service, nullptr);
+    }
+
+    std::shared_ptr<IDeviceStateService> service;
+};
+
+class DeviceStateListener : public BnDeviceStateListener {
+   public:
+    DeviceStateListener() : mInitialNotification(false) {
+        mPublicPropertyMask = 0;
+        for (const auto& it : enum_range<DeviceStateConfiguration::DeviceStatePropertyValue>()) {
+            mPublicPropertyMask |= static_cast<unsigned long>(it);
+        }
+        mPublicPropertyMask = ~mPublicPropertyMask;
+    }
+
+    ::ndk::ScopedAStatus onDeviceStateChanged(
+        const ::aidl::android::frameworks::devicestate::DeviceStateConfiguration& in_deviceState)
+        override {
+        Mutex::Autolock l(mLock);
+        EXPECT_TRUE((in_deviceState.deviceProperties & mPublicPropertyMask) == 0);
+        mInitialNotification = true;
+        mNotifyCondition.broadcast();
+        return ::ndk::ScopedAStatus::ok();
+    }
+
+    bool waitForDeviceStateChange() {
+        Mutex::Autolock l(mLock);
+        if (!mInitialNotification &&
+            (mNotifyCondition.waitRelative(mLock, NOTIFY_TIMEOUT_NS) != android::OK)) {
+            return false;
+        }
+
+        return mInitialNotification;
+    }
+
+   private:
+    unsigned long mPublicPropertyMask;
+
+    mutable Mutex mLock;
+    mutable Condition mNotifyCondition;
+    bool mInitialNotification;
+};
+
+TEST_P(DeviceStateServiceTest, RegisterAndUnregisterDeviceStateTest) {
+    auto listener = ::ndk::SharedRefBase::make<DeviceStateListener>();
+    EXPECT_TRUE(service->registerListener(listener).isOk());
+    EXPECT_TRUE(listener->waitForDeviceStateChange());
+
+    auto secondListener = ::ndk::SharedRefBase::make<DeviceStateListener>();
+    auto ret = service->registerListener(secondListener);
+    EXPECT_TRUE(!ret.isOk());
+    EXPECT_TRUE(static_cast<ErrorCode>(ret.getServiceSpecificError()) == ErrorCode::ALREADY_EXISTS);
+
+    ret = service->unregisterListener(listener);
+    EXPECT_TRUE(ret.isOk());
+
+    ret = service->unregisterListener(listener);
+    EXPECT_TRUE(!ret.isOk());
+    EXPECT_TRUE(static_cast<ErrorCode>(ret.getServiceSpecificError()) == ErrorCode::BAD_INPUT);
+}
+
+GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(DeviceStateServiceTest);
+
+INSTANTIATE_TEST_SUITE_P(
+    PerInstance, DeviceStateServiceTest,
+    testing::ValuesIn(getAidlHalInstanceNames(IDeviceStateService::descriptor)),
+    PrintInstanceNameToString);
+
+int main(int argc, char** argv) {
+    InitGoogleTest(&argc, argv);
+    return RUN_ALL_TESTS();
+}
+}  // namespace android
diff --git a/sensorservice/1.0/vts/functional/Android.bp b/sensorservice/1.0/vts/functional/Android.bp
index a465c8a..96bd389 100644
--- a/sensorservice/1.0/vts/functional/Android.bp
+++ b/sensorservice/1.0/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_sensors",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/sensorservice/aidl/Android.bp b/sensorservice/aidl/Android.bp
index 35eea3e..43bc9a8 100644
--- a/sensorservice/aidl/Android.bp
+++ b/sensorservice/aidl/Android.bp
@@ -9,7 +9,7 @@ aidl_interface {
     srcs: ["android/frameworks/sensorservice/*.aidl"],
     stability: "vintf",
     imports: [
-        "android.hardware.sensors-V2",
+        "android.hardware.sensors-V3",
         "android.hardware.common-V2",
     ],
     backend: {
@@ -24,7 +24,7 @@ aidl_interface {
         {
             version: "1",
             imports: [
-                "android.hardware.sensors-V2",
+                "android.hardware.sensors-V3",
                 "android.hardware.common-V2",
             ],
         },
diff --git a/sensorservice/aidl/vts/Android.bp b/sensorservice/aidl/vts/Android.bp
index 0d7c34a..4a98e73 100644
--- a/sensorservice/aidl/vts/Android.bp
+++ b/sensorservice/aidl/vts/Android.bp
@@ -29,7 +29,7 @@ cc_test {
     shared_libs: [
         "libcutils",
         "libbinder_ndk",
-        "android.hardware.sensors-V2-ndk",
+        "android.hardware.sensors-V3-ndk",
         "android.frameworks.sensorservice-V1-ndk",
     ],
     static_libs: [
diff --git a/sensorservice/libsensorndkbridge/Android.bp b/sensorservice/libsensorndkbridge/Android.bp
index f5de01c..1783cb5 100644
--- a/sensorservice/libsensorndkbridge/Android.bp
+++ b/sensorservice/libsensorndkbridge/Android.bp
@@ -33,7 +33,7 @@ cc_library_shared {
         "libbinder_ndk",
         "libutils",
         "android.frameworks.sensorservice-V1-ndk",
-        "android.hardware.sensors-V2-ndk",
+        "android.hardware.sensors-V3-ndk",
     ],
     static_libs: [
         "android.hardware.sensors-V1-convert",
diff --git a/stats/1.0/vts/functional/Android.bp b/stats/1.0/vts/functional/Android.bp
index 4259123..87a2d2b 100644
--- a/stats/1.0/vts/functional/Android.bp
+++ b/stats/1.0/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_telemetry",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -27,3 +28,10 @@ cc_test {
     ],
     test_suites: ["general-tests", "vts"],
 }
+
+team {
+    name: "trendy_team_android_telemetry",
+
+    // go/trendy/manage/engineers/5170851122348032
+    trendy_team_id: "5170851122348032",
+}
diff --git a/stats/OWNERS b/stats/OWNERS
new file mode 100644
index 0000000..6e97551
--- /dev/null
+++ b/stats/OWNERS
@@ -0,0 +1,2 @@
+# Bug component: 366902
+file:platform/packages/modules/StatsD:/OWNERS
diff --git a/stats/aidl/vts/OWNERS b/stats/aidl/vts/OWNERS
deleted file mode 100644
index 68ab54c..0000000
--- a/stats/aidl/vts/OWNERS
+++ /dev/null
@@ -1,9 +0,0 @@
-# Bug component: 366902
-jeffreyhuang@google.com
-monicamwang@google.com
-muhammadq@google.com
-rayhdez@google.com
-sharaienko@google.com
-singhtejinder@google.com
-tsaichristine@google.com
-yaochen@google.com
diff --git a/stats/aidl/vts/functional/Android.bp b/stats/aidl/vts/functional/Android.bp
index f530f00..d0416d0 100644
--- a/stats/aidl/vts/functional/Android.bp
+++ b/stats/aidl/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_telemetry_client_infra",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/stats/aidl/vts/java/Android.bp b/stats/aidl/vts/java/Android.bp
index 73f60ef..b87dc0d 100644
--- a/stats/aidl/vts/java/Android.bp
+++ b/stats/aidl/vts/java/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_telemetry_client_infra",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -40,7 +41,7 @@ java_test_host {
     static_libs: [
         "cts-statsd-atom-host-test-utils",
     ],
-    data: [
+    device_common_data: [
         ":VtsVendorAtomJavaTest",
     ],
     proto: {
```

