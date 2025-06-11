```diff
diff --git a/OWNERS b/OWNERS
index 92b6ed7..bbac03f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,5 +2,4 @@ elsk@google.com
 maco@google.com
 malchev@google.com
 smoreland@google.com
-tstrudel@google.com
 wvw@google.com
diff --git a/bluetooth/bt_channel_avoidance/aidl/Android.bp b/bluetooth/bt_channel_avoidance/aidl/Android.bp
index 9895232..45941f1 100644
--- a/bluetooth/bt_channel_avoidance/aidl/Android.bp
+++ b/bluetooth/bt_channel_avoidance/aidl/Android.bp
@@ -22,7 +22,7 @@ aidl_interface {
         ndk: {
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "33",
         },
diff --git a/bluetooth/bt_channel_avoidance/aidl/OWNERS b/bluetooth/bt_channel_avoidance/aidl/OWNERS
index e406ad5..b254b79 100644
--- a/bluetooth/bt_channel_avoidance/aidl/OWNERS
+++ b/bluetooth/bt_channel_avoidance/aidl/OWNERS
@@ -1,2 +1 @@
 # Bug component: 27441
-tiand@google.com
diff --git a/bluetooth/bt_channel_avoidance/aidl/vts/Android.bp b/bluetooth/bt_channel_avoidance/aidl/vts/Android.bp
index be2a6f6..5ea551f 100644
--- a/bluetooth/bt_channel_avoidance/aidl/vts/Android.bp
+++ b/bluetooth/bt_channel_avoidance/aidl/vts/Android.bp
@@ -17,9 +17,6 @@ cc_test {
         "libutils",
         "//hardware/google/interfaces:hardware.google.bluetooth.bt_channel_avoidance-V1-ndk",
     ],
-    static_libs: [
-        "libbluetooth-types",
-    ],
     test_config: "VtsHalBTChannelAvoidanceTargetTest.xml",
     test_suites: [
         "general-tests",
diff --git a/bluetooth/ccc/aidl/Android.bp b/bluetooth/ccc/aidl/Android.bp
index affe46b..896e9d8 100644
--- a/bluetooth/ccc/aidl/Android.bp
+++ b/bluetooth/ccc/aidl/Android.bp
@@ -20,7 +20,7 @@ aidl_interface {
         ndk: {
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "33",
         },
diff --git a/bluetooth/ccc/aidl/hardware/google/bluetooth/ccc/IBluetoothCcc.aidl b/bluetooth/ccc/aidl/hardware/google/bluetooth/ccc/IBluetoothCcc.aidl
index a05e51e..16be194 100644
--- a/bluetooth/ccc/aidl/hardware/google/bluetooth/ccc/IBluetoothCcc.aidl
+++ b/bluetooth/ccc/aidl/hardware/google/bluetooth/ccc/IBluetoothCcc.aidl
@@ -18,7 +18,6 @@ package hardware.google.bluetooth.ccc;
 
 import hardware.google.bluetooth.ccc.IBluetoothCccCallback;
 import hardware.google.bluetooth.ccc.LmpEventId;
-import hardware.google.bluetooth.ccc.IBluetoothCccCallback;
 
 @VintfStability
 interface IBluetoothCcc {
diff --git a/bluetooth/ccc/aidl/vts/Android.bp b/bluetooth/ccc/aidl/vts/Android.bp
index e348939..89d1494 100644
--- a/bluetooth/ccc/aidl/vts/Android.bp
+++ b/bluetooth/ccc/aidl/vts/Android.bp
@@ -34,7 +34,6 @@ cc_test {
     ],
     static_libs: [
         "//hardware/google/interfaces:hardware.google.bluetooth.ccc-V1-ndk",
-        "libbluetooth-types",
     ],
     test_config: "VtsHalBluetoothCccTargetTest.xml",
     test_suites: [
diff --git a/bluetooth/ewp/aidl/Android.bp b/bluetooth/ewp/aidl/Android.bp
index faa79ff..79832be 100644
--- a/bluetooth/ewp/aidl/Android.bp
+++ b/bluetooth/ewp/aidl/Android.bp
@@ -22,7 +22,7 @@ aidl_interface {
         ndk: {
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "33",
         },
diff --git a/bluetooth/ewp/aidl/OWNERS b/bluetooth/ewp/aidl/OWNERS
index e406ad5..b254b79 100644
--- a/bluetooth/ewp/aidl/OWNERS
+++ b/bluetooth/ewp/aidl/OWNERS
@@ -1,2 +1 @@
 # Bug component: 27441
-tiand@google.com
diff --git a/bluetooth/ewp/aidl/vts/Android.bp b/bluetooth/ewp/aidl/vts/Android.bp
index e77c527..6d78f4a 100644
--- a/bluetooth/ewp/aidl/vts/Android.bp
+++ b/bluetooth/ewp/aidl/vts/Android.bp
@@ -17,9 +17,6 @@ cc_test {
         "libutils",
         "//hardware/google/interfaces:hardware.google.bluetooth.ewp-V1-ndk",
     ],
-    static_libs: [
-        "libbluetooth-types",
-    ],
     test_config: "VtsHalBluetoothEwpTargetTest.xml",
     test_suites: [
         "general-tests",
diff --git a/bluetooth/ext/aidl/Android.bp b/bluetooth/ext/aidl/Android.bp
index 00debbb..421eda8 100644
--- a/bluetooth/ext/aidl/Android.bp
+++ b/bluetooth/ext/aidl/Android.bp
@@ -22,7 +22,7 @@ aidl_interface {
         ndk: {
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "33",
         },
diff --git a/bluetooth/ext/aidl/OWNERS b/bluetooth/ext/aidl/OWNERS
index e406ad5..b254b79 100644
--- a/bluetooth/ext/aidl/OWNERS
+++ b/bluetooth/ext/aidl/OWNERS
@@ -1,2 +1 @@
 # Bug component: 27441
-tiand@google.com
diff --git a/bluetooth/ext/aidl/vts/Android.bp b/bluetooth/ext/aidl/vts/Android.bp
index 983424f..0d04aea 100644
--- a/bluetooth/ext/aidl/vts/Android.bp
+++ b/bluetooth/ext/aidl/vts/Android.bp
@@ -16,9 +16,6 @@ cc_test {
         "libutils",
         "//hardware/google/interfaces:hardware.google.bluetooth.ext-V1-ndk",
     ],
-    static_libs: [
-        "libbluetooth-types",
-    ],
     test_config: "VtsHalBluetoothExtTargetTest.xml",
     test_suites: [
         "general-tests",
diff --git a/bluetooth/sar/aidl/Android.bp b/bluetooth/sar/aidl/Android.bp
index 66f7f12..a3b2e94 100644
--- a/bluetooth/sar/aidl/Android.bp
+++ b/bluetooth/sar/aidl/Android.bp
@@ -20,7 +20,7 @@ aidl_interface {
         ndk: {
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "33",
         },
diff --git a/bluetooth/sar/aidl/OWNERS b/bluetooth/sar/aidl/OWNERS
index e406ad5..b254b79 100644
--- a/bluetooth/sar/aidl/OWNERS
+++ b/bluetooth/sar/aidl/OWNERS
@@ -1,2 +1 @@
 # Bug component: 27441
-tiand@google.com
diff --git a/bluetooth/sar/aidl/vts/Android.bp b/bluetooth/sar/aidl/vts/Android.bp
index ace79d3..851f209 100644
--- a/bluetooth/sar/aidl/vts/Android.bp
+++ b/bluetooth/sar/aidl/vts/Android.bp
@@ -17,9 +17,6 @@ cc_test {
         "libutils",
         "//hardware/google/interfaces:hardware.google.bluetooth.sar-V1-ndk",
     ],
-    static_libs: [
-        "libbluetooth-types",
-    ],
     test_config: "VtsHalBluetoothSarTargetTest.xml",
     test_suites: [
         "general-tests",
diff --git a/display/Android.bp b/display/Android.bp
index d5537b7..8efb7d6 100644
--- a/display/Android.bp
+++ b/display/Android.bp
@@ -120,6 +120,20 @@ aidl_interface {
                 "android.hardware.graphics.common-V6",
             ],
         },
+        {
+            version: "14",
+            imports: [
+                "android.hardware.graphics.common-V6",
+                "android.hardware.common-V2",
+            ],
+        },
+        {
+            version: "15",
+            imports: [
+                "android.hardware.graphics.common-V6",
+                "android.hardware.common-V2",
+            ],
+        },
 
     ],
     frozen: true,
diff --git a/display/OWNERS b/display/OWNERS
new file mode 100644
index 0000000..b9064d7
--- /dev/null
+++ b/display/OWNERS
@@ -0,0 +1,2 @@
+chiungfu@google.com
+shiyongli@google.com
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/.hash b/display/aidl_api/com.google.hardware.pixel.display/14/.hash
new file mode 100644
index 0000000..00da266
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/.hash
@@ -0,0 +1 @@
+3e81b599d4f25adb803a682c1afed7375d3215e9
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/DisplayStats.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/DisplayStats.aidl
new file mode 100644
index 0000000..1d0f756
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/DisplayStats.aidl
@@ -0,0 +1,41 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+union DisplayStats {
+  double brightnessNits;
+  int brightnessDbv;
+  int operationRate;
+  double[3] opr;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HbmState.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HbmState.aidl
new file mode 100644
index 0000000..76af8b3
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HbmState.aidl
@@ -0,0 +1,40 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HbmState {
+  OFF = 0,
+  HDR = 1,
+  SUNLIGHT = 2,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramCapability.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramCapability.aidl
new file mode 100644
index 0000000..80c66d1
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramCapability.aidl
@@ -0,0 +1,44 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+parcelable HistogramCapability {
+  boolean supportMultiChannel;
+  int channelCount;
+  int fullResolutionWidth;
+  int fullResolutionHeight;
+  com.google.hardware.pixel.display.HistogramSamplePos[] supportSamplePosList;
+  boolean supportBlockingRoi;
+  boolean supportQueryOpr;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramConfig.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramConfig.aidl
new file mode 100644
index 0000000..a5fe1d4
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramConfig.aidl
@@ -0,0 +1,41 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+parcelable HistogramConfig {
+  android.hardware.graphics.common.Rect roi;
+  com.google.hardware.pixel.display.Weight weights;
+  com.google.hardware.pixel.display.HistogramSamplePos samplePos;
+  @nullable android.hardware.graphics.common.Rect blockingRoi;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramErrorCode.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramErrorCode.aidl
new file mode 100644
index 0000000..52fbe1f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramErrorCode.aidl
@@ -0,0 +1,52 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HistogramErrorCode {
+  NONE = 0,
+  BAD_ROI = 1,
+  BAD_WEIGHT = 2,
+  BAD_POSITION = 3,
+  BAD_PRIORITY = 4,
+  ENABLE_HIST_ERROR = 5,
+  DISABLE_HIST_ERROR = 6,
+  BAD_HIST_DATA = 7,
+  DRM_PLAYING = 8,
+  DISPLAY_POWEROFF = 9,
+  API_DEPRECATED = 10,
+  BAD_TOKEN = 11,
+  CONFIG_HIST_ERROR = 12,
+  NO_CHANNEL_AVAILABLE = 13,
+  TRY_AGAIN = 14,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramPos.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramPos.aidl
new file mode 100644
index 0000000..20b8160
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramPos.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HistogramPos {
+  POST = 0,
+  PRE = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramSamplePos.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramSamplePos.aidl
new file mode 100644
index 0000000..0acc055
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/HistogramSamplePos.aidl
@@ -0,0 +1,39 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HistogramSamplePos {
+  POST_POSTPROC = 0,
+  PRE_POSTPROC = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/IDisplay.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/IDisplay.aidl
new file mode 100644
index 0000000..1049b09
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/IDisplay.aidl
@@ -0,0 +1,68 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+interface IDisplay {
+  boolean isHbmSupported();
+  void setHbmState(in com.google.hardware.pixel.display.HbmState state);
+  com.google.hardware.pixel.display.HbmState getHbmState();
+  boolean isLbeSupported();
+  void setLbeState(in com.google.hardware.pixel.display.LbeState state);
+  void setLbeAmbientLight(in int ambientLux);
+  com.google.hardware.pixel.display.LbeState getLbeState();
+  boolean isLhbmSupported();
+  void setLhbmState(in boolean enabled);
+  boolean getLhbmState();
+  int setCompensationImageHandle(in android.hardware.common.NativeHandle native_handle, in String imageName);
+  int setMinIdleRefreshRate(in int fps);
+  int setRefreshRateThrottle(in int delayMs);
+  com.google.hardware.pixel.display.HistogramErrorCode histogramSample(in android.hardware.graphics.common.Rect roi, in com.google.hardware.pixel.display.Weight weight, in com.google.hardware.pixel.display.HistogramPos pos, in com.google.hardware.pixel.display.Priority pri, out char[] histogrambuffer);
+  com.google.hardware.pixel.display.PanelCalibrationStatus getPanelCalibrationStatus();
+  boolean isDbmSupported();
+  void setDbmState(in boolean enabled);
+  void setPeakRefreshRate(in int rate);
+  void setLowPowerMode(in boolean enabled);
+  boolean isOperationRateSupported();
+  com.google.hardware.pixel.display.HistogramCapability getHistogramCapability();
+  com.google.hardware.pixel.display.HistogramErrorCode registerHistogram(in IBinder token, in com.google.hardware.pixel.display.HistogramConfig histogramConfig);
+  com.google.hardware.pixel.display.HistogramErrorCode queryHistogram(in IBinder token, out char[] histogramBuffer);
+  com.google.hardware.pixel.display.HistogramErrorCode reconfigHistogram(in IBinder token, in com.google.hardware.pixel.display.HistogramConfig histogramConfig);
+  com.google.hardware.pixel.display.HistogramErrorCode unregisterHistogram(in IBinder token);
+  int setFixedTe2Rate(in int rateHz);
+  @nullable com.google.hardware.pixel.display.DisplayStats queryStats(in com.google.hardware.pixel.display.DisplayStats.Tag tag);
+  boolean isProximitySensorStateCallbackSupported();
+  void registerProximitySensorStateChangeCallback(in com.google.hardware.pixel.display.IDisplayProximitySensorCallback callback);
+  int setFixedTe2Frequency(in int freqHz);
+  void setPwmMode(in com.google.hardware.pixel.display.PwmMode mode);
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
new file mode 100644
index 0000000..e675731
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
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
+package com.google.hardware.pixel.display;
+@VintfStability
+interface IDisplayProximitySensorCallback {
+  oneway void onProximitySensorStateChanged(in boolean active);
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/LbeState.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/LbeState.aidl
new file mode 100644
index 0000000..8c8b53e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/LbeState.aidl
@@ -0,0 +1,42 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum LbeState {
+  OFF = 0,
+  NORMAL = 1,
+  HIGH_BRIGHTNESS = 2,
+  POWER_SAVE = 3,
+  HIGH_BRIGHTNESS_ENHANCE = 4,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
new file mode 100644
index 0000000..55271d0
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum PanelCalibrationStatus {
+  ORIGINAL = 0,
+  GOLDEN = 1,
+  UNCALIBRATED = 2,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/Priority.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/Priority.aidl
new file mode 100644
index 0000000..2b2c957
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/Priority.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum Priority {
+  NORMAL = 0,
+  PRIORITY = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/PwmMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/PwmMode.aidl
new file mode 100644
index 0000000..48e8f21
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/PwmMode.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum PwmMode {
+  STANDARD = 0,
+  HIGH = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/Weight.aidl b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/Weight.aidl
new file mode 100644
index 0000000..e25da1e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/14/com/google/hardware/pixel/display/Weight.aidl
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
+package com.google.hardware.pixel.display;
+@VintfStability
+parcelable Weight {
+  char weightR;
+  char weightG;
+  char weightB;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/.hash b/display/aidl_api/com.google.hardware.pixel.display/15/.hash
new file mode 100644
index 0000000..4e22b3e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/.hash
@@ -0,0 +1 @@
+56472c1ed51da797b7f5177b7405ea81e3a435a4
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/DisplayStats.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/DisplayStats.aidl
new file mode 100644
index 0000000..1d0f756
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/DisplayStats.aidl
@@ -0,0 +1,41 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+union DisplayStats {
+  double brightnessNits;
+  int brightnessDbv;
+  int operationRate;
+  double[3] opr;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/DozeType.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/DozeType.aidl
new file mode 100644
index 0000000..0a93b43
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/DozeType.aidl
@@ -0,0 +1,39 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum DozeType {
+  LP_DOZE = 0,
+  MP_DOZE = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HbmState.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HbmState.aidl
new file mode 100644
index 0000000..76af8b3
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HbmState.aidl
@@ -0,0 +1,40 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HbmState {
+  OFF = 0,
+  HDR = 1,
+  SUNLIGHT = 2,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramCapability.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramCapability.aidl
new file mode 100644
index 0000000..80c66d1
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramCapability.aidl
@@ -0,0 +1,44 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+parcelable HistogramCapability {
+  boolean supportMultiChannel;
+  int channelCount;
+  int fullResolutionWidth;
+  int fullResolutionHeight;
+  com.google.hardware.pixel.display.HistogramSamplePos[] supportSamplePosList;
+  boolean supportBlockingRoi;
+  boolean supportQueryOpr;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramConfig.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramConfig.aidl
new file mode 100644
index 0000000..a5fe1d4
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramConfig.aidl
@@ -0,0 +1,41 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+parcelable HistogramConfig {
+  android.hardware.graphics.common.Rect roi;
+  com.google.hardware.pixel.display.Weight weights;
+  com.google.hardware.pixel.display.HistogramSamplePos samplePos;
+  @nullable android.hardware.graphics.common.Rect blockingRoi;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramErrorCode.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramErrorCode.aidl
new file mode 100644
index 0000000..52fbe1f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramErrorCode.aidl
@@ -0,0 +1,52 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HistogramErrorCode {
+  NONE = 0,
+  BAD_ROI = 1,
+  BAD_WEIGHT = 2,
+  BAD_POSITION = 3,
+  BAD_PRIORITY = 4,
+  ENABLE_HIST_ERROR = 5,
+  DISABLE_HIST_ERROR = 6,
+  BAD_HIST_DATA = 7,
+  DRM_PLAYING = 8,
+  DISPLAY_POWEROFF = 9,
+  API_DEPRECATED = 10,
+  BAD_TOKEN = 11,
+  CONFIG_HIST_ERROR = 12,
+  NO_CHANNEL_AVAILABLE = 13,
+  TRY_AGAIN = 14,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramPos.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramPos.aidl
new file mode 100644
index 0000000..20b8160
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramPos.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HistogramPos {
+  POST = 0,
+  PRE = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramSamplePos.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramSamplePos.aidl
new file mode 100644
index 0000000..0acc055
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/HistogramSamplePos.aidl
@@ -0,0 +1,39 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum HistogramSamplePos {
+  POST_POSTPROC = 0,
+  PRE_POSTPROC = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IDisplay.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IDisplay.aidl
new file mode 100644
index 0000000..80c075f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IDisplay.aidl
@@ -0,0 +1,71 @@
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
+package com.google.hardware.pixel.display;
+@VintfStability
+interface IDisplay {
+  boolean isHbmSupported();
+  void setHbmState(in com.google.hardware.pixel.display.HbmState state);
+  com.google.hardware.pixel.display.HbmState getHbmState();
+  boolean isLbeSupported();
+  void setLbeState(in com.google.hardware.pixel.display.LbeState state);
+  void setLbeAmbientLight(in int ambientLux);
+  com.google.hardware.pixel.display.LbeState getLbeState();
+  boolean isLhbmSupported();
+  void setLhbmState(in boolean enabled);
+  boolean getLhbmState();
+  int setCompensationImageHandle(in android.hardware.common.NativeHandle native_handle, in String imageName);
+  int setMinIdleRefreshRate(in int fps);
+  int setRefreshRateThrottle(in int delayMs);
+  com.google.hardware.pixel.display.HistogramErrorCode histogramSample(in android.hardware.graphics.common.Rect roi, in com.google.hardware.pixel.display.Weight weight, in com.google.hardware.pixel.display.HistogramPos pos, in com.google.hardware.pixel.display.Priority pri, out char[] histogrambuffer);
+  com.google.hardware.pixel.display.PanelCalibrationStatus getPanelCalibrationStatus();
+  boolean isDbmSupported();
+  void setDbmState(in boolean enabled);
+  void setPeakRefreshRate(in int rate);
+  void setLowPowerMode(in boolean enabled);
+  boolean isOperationRateSupported();
+  com.google.hardware.pixel.display.HistogramCapability getHistogramCapability();
+  com.google.hardware.pixel.display.HistogramErrorCode registerHistogram(in IBinder token, in com.google.hardware.pixel.display.HistogramConfig histogramConfig);
+  com.google.hardware.pixel.display.HistogramErrorCode queryHistogram(in IBinder token, out char[] histogramBuffer);
+  com.google.hardware.pixel.display.HistogramErrorCode reconfigHistogram(in IBinder token, in com.google.hardware.pixel.display.HistogramConfig histogramConfig);
+  com.google.hardware.pixel.display.HistogramErrorCode unregisterHistogram(in IBinder token);
+  int setFixedTe2Rate(in int rateHz);
+  @nullable com.google.hardware.pixel.display.DisplayStats queryStats(in com.google.hardware.pixel.display.DisplayStats.Tag tag);
+  boolean isProximitySensorStateCallbackSupported();
+  void registerProximitySensorStateChangeCallback(in com.google.hardware.pixel.display.IDisplayProximitySensorCallback callback);
+  int setFixedTe2Frequency(in int freqHz);
+  void setPwmMode(in com.google.hardware.pixel.display.PwmMode mode);
+  com.google.hardware.pixel.display.ScreenPartStatus getPanelReplacementStatus();
+  int setDozeType(in com.google.hardware.pixel.display.DozeType type);
+  void setIrcMode(in com.google.hardware.pixel.display.IrcMode mode);
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
new file mode 100644
index 0000000..e675731
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
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
+package com.google.hardware.pixel.display;
+@VintfStability
+interface IDisplayProximitySensorCallback {
+  oneway void onProximitySensorStateChanged(in boolean active);
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IrcMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IrcMode.aidl
new file mode 100644
index 0000000..28c6e27
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/IrcMode.aidl
@@ -0,0 +1,39 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum IrcMode {
+  FLAT_DEFAULT = 0,
+  OFF = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/LbeState.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/LbeState.aidl
new file mode 100644
index 0000000..8c8b53e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/LbeState.aidl
@@ -0,0 +1,42 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum LbeState {
+  OFF = 0,
+  NORMAL = 1,
+  HIGH_BRIGHTNESS = 2,
+  POWER_SAVE = 3,
+  HIGH_BRIGHTNESS_ENHANCE = 4,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
new file mode 100644
index 0000000..55271d0
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum PanelCalibrationStatus {
+  ORIGINAL = 0,
+  GOLDEN = 1,
+  UNCALIBRATED = 2,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/Priority.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/Priority.aidl
new file mode 100644
index 0000000..2b2c957
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/Priority.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum Priority {
+  NORMAL = 0,
+  PRIORITY = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/PwmMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/PwmMode.aidl
new file mode 100644
index 0000000..48e8f21
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/PwmMode.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum PwmMode {
+  STANDARD = 0,
+  HIGH = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/ScreenPartStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/ScreenPartStatus.aidl
new file mode 100644
index 0000000..a07fa8f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/ScreenPartStatus.aidl
@@ -0,0 +1,40 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="int") @VintfStability
+enum ScreenPartStatus {
+  UNSUPPORTED = 0,
+  ORIGINAL = 1,
+  REPLACED = 2,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/Weight.aidl b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/Weight.aidl
new file mode 100644
index 0000000..e25da1e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/15/com/google/hardware/pixel/display/Weight.aidl
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
+package com.google.hardware.pixel.display;
+@VintfStability
+parcelable Weight {
+  char weightR;
+  char weightG;
+  char weightB;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DozeType.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DozeType.aidl
new file mode 100644
index 0000000..0a93b43
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DozeType.aidl
@@ -0,0 +1,39 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum DozeType {
+  LP_DOZE = 0,
+  MP_DOZE = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl
index b22c1e5..80c075f 100644
--- a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl
@@ -63,4 +63,9 @@ interface IDisplay {
   @nullable com.google.hardware.pixel.display.DisplayStats queryStats(in com.google.hardware.pixel.display.DisplayStats.Tag tag);
   boolean isProximitySensorStateCallbackSupported();
   void registerProximitySensorStateChangeCallback(in com.google.hardware.pixel.display.IDisplayProximitySensorCallback callback);
+  int setFixedTe2Frequency(in int freqHz);
+  void setPwmMode(in com.google.hardware.pixel.display.PwmMode mode);
+  com.google.hardware.pixel.display.ScreenPartStatus getPanelReplacementStatus();
+  int setDozeType(in com.google.hardware.pixel.display.DozeType type);
+  void setIrcMode(in com.google.hardware.pixel.display.IrcMode mode);
 }
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IrcMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IrcMode.aidl
new file mode 100644
index 0000000..28c6e27
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IrcMode.aidl
@@ -0,0 +1,39 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum IrcMode {
+  FLAT_DEFAULT = 0,
+  OFF = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/PwmMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/PwmMode.aidl
new file mode 100644
index 0000000..48e8f21
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/PwmMode.aidl
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
+package com.google.hardware.pixel.display;
+@Backing(type="byte") @VintfStability
+enum PwmMode {
+  STANDARD = 0,
+  HIGH = 1,
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/ScreenPartStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/ScreenPartStatus.aidl
new file mode 100644
index 0000000..a07fa8f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/ScreenPartStatus.aidl
@@ -0,0 +1,40 @@
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
+package com.google.hardware.pixel.display;
+@Backing(type="int") @VintfStability
+enum ScreenPartStatus {
+  UNSUPPORTED = 0,
+  ORIGINAL = 1,
+  REPLACED = 2,
+}
diff --git a/display/com/google/hardware/pixel/display/DozeType.aidl b/display/com/google/hardware/pixel/display/DozeType.aidl
new file mode 100644
index 0000000..cf305dc
--- /dev/null
+++ b/display/com/google/hardware/pixel/display/DozeType.aidl
@@ -0,0 +1,27 @@
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
+package com.google.hardware.pixel.display;
+
+@VintfStability
+@Backing(type="byte")
+/**
+ * DozeType for Always on Display
+ */
+enum DozeType {
+    LP_DOZE = 0,
+    MP_DOZE = 1,
+}
diff --git a/display/com/google/hardware/pixel/display/IDisplay.aidl b/display/com/google/hardware/pixel/display/IDisplay.aidl
index 2482c10..5f89bd8 100644
--- a/display/com/google/hardware/pixel/display/IDisplay.aidl
+++ b/display/com/google/hardware/pixel/display/IDisplay.aidl
@@ -18,15 +18,19 @@ package com.google.hardware.pixel.display;
 import android.hardware.common.NativeHandle;
 import android.hardware.graphics.common.Rect;
 import com.google.hardware.pixel.display.DisplayStats;
+import com.google.hardware.pixel.display.DozeType;
 import com.google.hardware.pixel.display.HbmState;
 import com.google.hardware.pixel.display.HistogramCapability;
 import com.google.hardware.pixel.display.HistogramConfig;
 import com.google.hardware.pixel.display.HistogramErrorCode;
 import com.google.hardware.pixel.display.HistogramPos;
 import com.google.hardware.pixel.display.IDisplayProximitySensorCallback;
+import com.google.hardware.pixel.display.IrcMode;
 import com.google.hardware.pixel.display.LbeState;
 import com.google.hardware.pixel.display.PanelCalibrationStatus;
 import com.google.hardware.pixel.display.Priority;
+import com.google.hardware.pixel.display.PwmMode;
+import com.google.hardware.pixel.display.ScreenPartStatus;
 import com.google.hardware.pixel.display.Weight;
 
 @VintfStability
@@ -336,4 +340,44 @@ interface IDisplay {
      * @param callback instance of the IDisplayProximitySensorCallback
      */
     void registerProximitySensorStateChangeCallback(in IDisplayProximitySensorCallback callback);
+
+    /**
+     * Set the TE2 frequency while fixed TE2 is used.
+     *
+     * @param freqHz the TE2 frequency in Hz
+     * @return errno if there was a problem with the request, zero if successful
+     */
+    int setFixedTe2Frequency(in int freqHz);
+
+    /**
+     * Set Display PWM mode.
+     *
+     * @param mode the PWM mode.
+     */
+    void setPwmMode(in PwmMode mode);
+
+    /**
+     * Get the panel replacement status.
+     *
+     * @return status of panel replacement.
+     */
+    ScreenPartStatus getPanelReplacementStatus();
+
+    /**
+     * Set Doze Type
+     *
+     * @param DozeType
+     * @return errno if there was a problem with the request, zero if successful
+     */
+    int setDozeType(in DozeType type);
+
+    /**
+     * Set IRC Mode
+     *
+     * @param mode.
+     * enum irc_mode - possible IRC states
+     *                 @IRC_FLAT_DEFAULT: IR compensation on (default configuration)
+     *                 @IRC_OFF: IR compensation off, to allow for maximum brightness in outdoor sun
+     */
+    void setIrcMode(in IrcMode mode);
 }
diff --git a/display/com/google/hardware/pixel/display/IrcMode.aidl b/display/com/google/hardware/pixel/display/IrcMode.aidl
new file mode 100644
index 0000000..2cd77d7
--- /dev/null
+++ b/display/com/google/hardware/pixel/display/IrcMode.aidl
@@ -0,0 +1,24 @@
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
+package com.google.hardware.pixel.display;
+
+@VintfStability
+@Backing(type="byte")
+enum IrcMode {
+  FLAT_DEFAULT = 0,
+  OFF = 1,
+}
diff --git a/display/com/google/hardware/pixel/display/PwmMode.aidl b/display/com/google/hardware/pixel/display/PwmMode.aidl
new file mode 100644
index 0000000..015acd5
--- /dev/null
+++ b/display/com/google/hardware/pixel/display/PwmMode.aidl
@@ -0,0 +1,28 @@
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
+package com.google.hardware.pixel.display;
+
+@VintfStability
+@Backing(type="byte")
+/**
+ * Use different Pulse Width Modulation (PWM) modes to have
+ * different frequencies in the display.
+ */
+enum PwmMode {
+    STANDARD = 0,
+    HIGH = 1,
+}
diff --git a/display/com/google/hardware/pixel/display/ScreenPartStatus.aidl b/display/com/google/hardware/pixel/display/ScreenPartStatus.aidl
new file mode 100644
index 0000000..5736416
--- /dev/null
+++ b/display/com/google/hardware/pixel/display/ScreenPartStatus.aidl
@@ -0,0 +1,33 @@
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
+package com.google.hardware.pixel.display;
+
+/*
+ *  Ideally IDisplay AIDL should directly use ScreenPartStatus
+ *  from android.hardware.graphics.composer3. However, IDispaly
+ *  AIDL enables java backend, but composer3 does not. Since we
+ *  do not want composer3 to enable java backend, we will simply
+ *  redefine an enum with some static asserts to keep the two
+ *  ScreenPartStatus aligned.
+ */
+@VintfStability
+@Backing(type="int")
+enum ScreenPartStatus {
+    UNSUPPORTED = 0,
+    ORIGINAL = 1,
+    REPLACED = 2,
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl
index a6e4eeb..0d62bdf 100644
--- a/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl
@@ -37,5 +37,6 @@ package google.hardware.image;
 @VintfStability
 parcelable QueryResult {
   android.hardware.graphics.common.PixelFormat[] supportedColorFormats;
-  long usageHardwareBuffer;
+  long usageSrcBuf;
+  long usageDstBuf;
 }
diff --git a/image/google/hardware/image/QueryResult.aidl b/image/google/hardware/image/QueryResult.aidl
index 0208db0..be139df 100644
--- a/image/google/hardware/image/QueryResult.aidl
+++ b/image/google/hardware/image/QueryResult.aidl
@@ -31,8 +31,14 @@ parcelable QueryResult {
     PixelFormat[] supportedColorFormats;
     /**
      * Usage value required for HardwareBuffer creation. The client will use
-     * this usage value when allocating the image buffer/bitstream buffer using
-     * gralloc. A buffer created without this usage bit will be rejected.
+     * this usage value when allocating the source buffer using gralloc. A
+     * buffer created without this usage bit will be rejected.
      */
-    long usageHardwareBuffer;
+    long usageSrcBuf;
+    /**
+     * Usage value required for HardwareBuffer creation. The client will use
+     * this usage value when allocating the destination buffer using gralloc.
+     * A buffer created without this usage bit will be rejected.
+     */
+    long usageDstBuf;
 }
```

