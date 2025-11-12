```diff
diff --git a/display/Android.bp b/display/Android.bp
index 8efb7d6..b84f9fe 100644
--- a/display/Android.bp
+++ b/display/Android.bp
@@ -33,104 +33,111 @@ aidl_interface {
             version: "1",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "2",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "3",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "4",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "5",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "6",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "7",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "8",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "9",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "10",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "11",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "12",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "13",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
             ],
         },
         {
             version: "14",
             imports: [
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
                 "android.hardware.common-V2",
             ],
         },
         {
             version: "15",
             imports: [
-                "android.hardware.graphics.common-V6",
+                "android.hardware.graphics.common-V7",
+                "android.hardware.common-V2",
+            ],
+        },
+        {
+            version: "16",
+            imports: [
+                "android.hardware.graphics.common-V7",
                 "android.hardware.common-V2",
             ],
         },
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/.hash b/display/aidl_api/com.google.hardware.pixel.display/16/.hash
new file mode 100644
index 0000000..99e2ecb
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/.hash
@@ -0,0 +1 @@
+05d59b8e468a7505e5deda1aec0b22d22b146580
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/DisplayStats.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/DisplayStats.aidl
new file mode 100644
index 0000000..386dd79
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/DisplayStats.aidl
@@ -0,0 +1,44 @@
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
+  int[2] resolution;
+  double[2] dpi;
+  double refreshRate;
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/DozeType.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/DozeType.aidl
new file mode 100644
index 0000000..0a93b43
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/DozeType.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HbmState.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HbmState.aidl
new file mode 100644
index 0000000..76af8b3
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HbmState.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramCapability.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramCapability.aidl
new file mode 100644
index 0000000..80c66d1
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramCapability.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramConfig.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramConfig.aidl
new file mode 100644
index 0000000..a5fe1d4
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramConfig.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramErrorCode.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramErrorCode.aidl
new file mode 100644
index 0000000..52fbe1f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramErrorCode.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramPos.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramPos.aidl
new file mode 100644
index 0000000..20b8160
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramPos.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramSamplePos.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramSamplePos.aidl
new file mode 100644
index 0000000..0acc055
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/HistogramSamplePos.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IDisplay.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IDisplay.aidl
new file mode 100644
index 0000000..80c075f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IDisplay.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
new file mode 100644
index 0000000..e675731
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IrcMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IrcMode.aidl
new file mode 100644
index 0000000..28c6e27
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/IrcMode.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/LbeState.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/LbeState.aidl
new file mode 100644
index 0000000..8c8b53e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/LbeState.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
new file mode 100644
index 0000000..55271d0
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/Priority.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/Priority.aidl
new file mode 100644
index 0000000..2b2c957
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/Priority.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/PwmMode.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/PwmMode.aidl
new file mode 100644
index 0000000..48e8f21
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/PwmMode.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/ScreenPartStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/ScreenPartStatus.aidl
new file mode 100644
index 0000000..a07fa8f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/ScreenPartStatus.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/Weight.aidl b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/Weight.aidl
new file mode 100644
index 0000000..e25da1e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/16/com/google/hardware/pixel/display/Weight.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DisplayStats.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DisplayStats.aidl
index 1d0f756..386dd79 100644
--- a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DisplayStats.aidl
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/DisplayStats.aidl
@@ -38,4 +38,7 @@ union DisplayStats {
   int brightnessDbv;
   int operationRate;
   double[3] opr;
+  int[2] resolution;
+  double[2] dpi;
+  double refreshRate;
 }
diff --git a/display/com/google/hardware/pixel/display/DisplayStats.aidl b/display/com/google/hardware/pixel/display/DisplayStats.aidl
index 2477eb6..7f0a232 100644
--- a/display/com/google/hardware/pixel/display/DisplayStats.aidl
+++ b/display/com/google/hardware/pixel/display/DisplayStats.aidl
@@ -34,4 +34,16 @@ union DisplayStats {
      * Get OPR in RGB channels as [OPR_r, OPR_g, OPR_b]
      */
     double[3] opr;
+    /**
+     * Get current resolution [width, height]
+     */
+    int[2] resolution;
+    /**
+     * Get dots per inch [dpi_x, dpi_y]
+     */
+    double[2] dpi;
+    /**
+     * Get current refresh rate
+     */
+    double refreshRate;
 }
diff --git a/image/OWNERS b/image/OWNERS
new file mode 100644
index 0000000..2fb8f80
--- /dev/null
+++ b/image/OWNERS
@@ -0,0 +1,2 @@
+anastasiayoung@google.com
+vinaykalia@google.com
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl
index 34de053..1defecb 100644
--- a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl
@@ -36,8 +36,8 @@
 package google.hardware.image;
 @VintfStability
 interface IComponent {
-  int encode(in android.hardware.HardwareBuffer src);
-  void decode(in android.hardware.HardwareBuffer src);
+  int encode(in android.hardware.HardwareBuffer src, in int id);
+  void decode(in android.hardware.HardwareBuffer src, in int id);
   google.hardware.image.QueryResult queryComponentConstraints();
   void setParams(in google.hardware.image.Params params);
 }
diff --git a/image/google/hardware/image/IComponent.aidl b/image/google/hardware/image/IComponent.aidl
index de3c8b0..1e71913 100644
--- a/image/google/hardware/image/IComponent.aidl
+++ b/image/google/hardware/image/IComponent.aidl
@@ -35,10 +35,13 @@ interface IComponent {
      *
      * @params src HardwareBuffer containing a YUV image. The format must be
      * one of the supported PixelFormats returned by queryComponentConstraints().
+     * @param id identifies this encoding operation. This will be the srcId value
+     * in the IComponentCallback::allocateLinearBuffer call to identify which
+     * encoding the callback is coming from.
      * @return size of the encoded output bitstream.
      * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
-    int encode(in HardwareBuffer src);
+    int encode(in HardwareBuffer src, in int id);
 
     /**
      * Decodes an image with the component. This is a blocking call and will
@@ -47,9 +50,12 @@ interface IComponent {
      *
      * @param src HardwareBuffer containing an encoded image bitstream. The
      * format must be BLOB.
+     * @param id identifies this decoding operation. This will be the srcId value
+     * in the IComponentCallback::allocateGraphicBuffer call to identify which
+     * decoding the callback is coming from.
      * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
-    void decode(in HardwareBuffer src);
+    void decode(in HardwareBuffer src, in int id);
 
     /**
      * Queries for general information about the component.
diff --git a/image/google/hardware/image/IComponentCallback.aidl b/image/google/hardware/image/IComponentCallback.aidl
index fc29298..48dbd87 100644
--- a/image/google/hardware/image/IComponentCallback.aidl
+++ b/image/google/hardware/image/IComponentCallback.aidl
@@ -32,8 +32,8 @@ interface IComponentCallback {
      * destination buffer during image encoding.
      *
      * @param size The length of the linear buffer to be returned.
-     * @param srcId The unique AHardwareBuffer ID for the source buffer associated
-     * with this encoding operation.
+     * @param srcId The id value identifying the encoding operation this
+     * callback is coming from. This is set to the id param in IComponent::encode.
      * @return HardwareBuffer To be filled with encode output. The client implementation
      * of this function should call reset(...) on the HardwareBuffer to reset it
      * with an AHardwareBuffer allocated by the client.
@@ -61,8 +61,8 @@ interface IComponentCallback {
      * @param height The height of the graphic buffer to be returned.
      * @param colorFormat The colour format of the image that this buffer will
      * be used for.
-     * @param srcId The unique AHardwareBuffer ID for the source buffer associated
-     * with this encoding operation.
+     * @param srcId The id value identifying the decoding operation this
+     * callback is coming from. This is set to the id param in IComponent::decode.
      * @return HardwareBuffer To be filled with decode output. The client implementation
      * of this function should call reset(...) on the HardwareBuffer to reset it
      * with an AHardwareBuffer allocated by the client.
```

