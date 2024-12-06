```diff
diff --git a/display/Android.bp b/display/Android.bp
index 4840ce8..5741b37 100644
--- a/display/Android.bp
+++ b/display/Android.bp
@@ -111,6 +111,13 @@ aidl_interface {
                 "android.hardware.graphics.common-V5",
             ],
         },
+        {
+            version: "13",
+            imports: [
+                "android.hardware.common-V2",
+                "android.hardware.graphics.common-V5",
+            ],
+        },
 
     ],
     frozen: true,
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/.hash b/display/aidl_api/com.google.hardware.pixel.display/13/.hash
new file mode 100644
index 0000000..b5a25d2
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/.hash
@@ -0,0 +1 @@
+07cab8b806b3d8107140ec635c347c41561b014a
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/DisplayStats.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/DisplayStats.aidl
new file mode 100644
index 0000000..1d0f756
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/DisplayStats.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HbmState.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HbmState.aidl
new file mode 100644
index 0000000..76af8b3
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HbmState.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramCapability.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramCapability.aidl
new file mode 100644
index 0000000..80c66d1
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramCapability.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramConfig.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramConfig.aidl
new file mode 100644
index 0000000..a5fe1d4
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramConfig.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramErrorCode.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramErrorCode.aidl
new file mode 100644
index 0000000..52fbe1f
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramErrorCode.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramPos.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramPos.aidl
new file mode 100644
index 0000000..20b8160
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramPos.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramSamplePos.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramSamplePos.aidl
new file mode 100644
index 0000000..0acc055
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/HistogramSamplePos.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/IDisplay.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/IDisplay.aidl
new file mode 100644
index 0000000..b22c1e5
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/IDisplay.aidl
@@ -0,0 +1,66 @@
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
+}
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
new file mode 100644
index 0000000..e675731
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/LbeState.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/LbeState.aidl
new file mode 100644
index 0000000..8c8b53e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/LbeState.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
new file mode 100644
index 0000000..55271d0
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/PanelCalibrationStatus.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/Priority.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/Priority.aidl
new file mode 100644
index 0000000..2b2c957
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/Priority.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/Weight.aidl b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/Weight.aidl
new file mode 100644
index 0000000..e25da1e
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/13/com/google/hardware/pixel/display/Weight.aidl
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
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl
index 20ec725..b22c1e5 100644
--- a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplay.aidl
@@ -61,4 +61,6 @@ interface IDisplay {
   com.google.hardware.pixel.display.HistogramErrorCode unregisterHistogram(in IBinder token);
   int setFixedTe2Rate(in int rateHz);
   @nullable com.google.hardware.pixel.display.DisplayStats queryStats(in com.google.hardware.pixel.display.DisplayStats.Tag tag);
+  boolean isProximitySensorStateCallbackSupported();
+  void registerProximitySensorStateChangeCallback(in com.google.hardware.pixel.display.IDisplayProximitySensorCallback callback);
 }
diff --git a/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
new file mode 100644
index 0000000..e675731
--- /dev/null
+++ b/display/aidl_api/com.google.hardware.pixel.display/current/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
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
diff --git a/display/com/google/hardware/pixel/display/IDisplay.aidl b/display/com/google/hardware/pixel/display/IDisplay.aidl
index 709d3c7..2482c10 100644
--- a/display/com/google/hardware/pixel/display/IDisplay.aidl
+++ b/display/com/google/hardware/pixel/display/IDisplay.aidl
@@ -23,6 +23,7 @@ import com.google.hardware.pixel.display.HistogramCapability;
 import com.google.hardware.pixel.display.HistogramConfig;
 import com.google.hardware.pixel.display.HistogramErrorCode;
 import com.google.hardware.pixel.display.HistogramPos;
+import com.google.hardware.pixel.display.IDisplayProximitySensorCallback;
 import com.google.hardware.pixel.display.LbeState;
 import com.google.hardware.pixel.display.PanelCalibrationStatus;
 import com.google.hardware.pixel.display.Priority;
@@ -320,4 +321,19 @@ interface IDisplay {
      *                          NULL, upon failure.
      */
     @nullable DisplayStats queryStats(in DisplayStats.Tag tag);
+
+    /**
+     * Query whether the callback of proximity sensor state is supported.
+     *
+     * @return true if the callback of proximity sensor state is supported
+     *         false if not supported.
+     */
+    boolean isProximitySensorStateCallbackSupported();
+
+    /**
+     * Register the callback function for proximity sensor state change (active/inactive)
+     *
+     * @param callback instance of the IDisplayProximitySensorCallback
+     */
+    void registerProximitySensorStateChangeCallback(in IDisplayProximitySensorCallback callback);
 }
diff --git a/display/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl b/display/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
new file mode 100644
index 0000000..b2af1a1
--- /dev/null
+++ b/display/com/google/hardware/pixel/display/IDisplayProximitySensorCallback.aidl
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
+package com.google.hardware.pixel.display;
+
+import com.google.hardware.pixel.display.IDisplay;
+
+@VintfStability
+interface IDisplayProximitySensorCallback {
+    /**
+     * Callback when the proximity sensor state is changed (active/inactive).
+     *
+     * @param active whether the proximity sensor is active
+     */
+    oneway void onProximitySensorStateChanged(in boolean active);
+}
diff --git a/image/Android.bp b/image/Android.bp
new file mode 100644
index 0000000..3563883
--- /dev/null
+++ b/image/Android.bp
@@ -0,0 +1,39 @@
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aidl_interface {
+    name: "google.hardware.image",
+    owner: "google",
+    vendor_available: true,
+    srcs: [
+        "google/hardware/image/*.aidl",
+    ],
+    headers: ["HardwareBuffer_aidl"],
+    imports: ["android.hardware.graphics.common-V5"],
+    include_dirs: ["frameworks/base/core/java"],
+
+    stability: "vintf",
+
+    backend: {
+        cpp: {
+            enabled: false,
+        },
+        java: {
+            enabled: false,
+        },
+        rust: {
+            enabled: false,
+        },
+        ndk: {
+            apex_available: [
+                "//apex_available:platform",
+            ],
+            additional_shared_libraries: [
+                "libnativewindow",
+            ],
+            min_sdk_version: "29",
+        },
+    },
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/ComponentType.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/ComponentType.aidl
new file mode 100644
index 0000000..ff959c5
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/ComponentType.aidl
@@ -0,0 +1,41 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@Backing(type="int") @VintfStability
+enum ComponentType {
+  JPEG_ENC,
+  JPEG_DEC,
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/EncodeParams.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/EncodeParams.aidl
new file mode 100644
index 0000000..50b5f26
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/EncodeParams.aidl
@@ -0,0 +1,43 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+parcelable EncodeParams {
+  int picWidth;
+  int picHeight;
+  int qualityFactor;
+  google.hardware.image.Metadata[] meta;
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl
new file mode 100644
index 0000000..34de053
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponent.aidl
@@ -0,0 +1,43 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+interface IComponent {
+  int encode(in android.hardware.HardwareBuffer src);
+  void decode(in android.hardware.HardwareBuffer src);
+  google.hardware.image.QueryResult queryComponentConstraints();
+  void setParams(in google.hardware.image.Params params);
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentCallback.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentCallback.aidl
new file mode 100644
index 0000000..643f597
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentCallback.aidl
@@ -0,0 +1,41 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+interface IComponentCallback {
+  android.hardware.HardwareBuffer allocateLinearBuffer(in int size, in int srcId);
+  android.hardware.HardwareBuffer allocateGraphicBuffer(in int width, in int height, in android.hardware.graphics.common.PixelFormat colorFormat, in int srcId);
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl
new file mode 100644
index 0000000..f4101fb
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl
@@ -0,0 +1,40 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+interface IComponentStore {
+  google.hardware.image.IComponent createComponent(in String name, in google.hardware.image.ComponentType type, in google.hardware.image.IComponentCallback callback);
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/Metadata.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/Metadata.aidl
new file mode 100644
index 0000000..85848e2
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/Metadata.aidl
@@ -0,0 +1,41 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+parcelable Metadata {
+  byte[] metaBuf;
+  int marker;
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/MirrorDirection.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/MirrorDirection.aidl
new file mode 100644
index 0000000..c0fb5d3
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/MirrorDirection.aidl
@@ -0,0 +1,43 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@Backing(type="int") @VintfStability
+enum MirrorDirection {
+  NONE,
+  VER,
+  HOR,
+  HOR_VER,
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/Params.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/Params.aidl
new file mode 100644
index 0000000..77dd290
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/Params.aidl
@@ -0,0 +1,40 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+union Params {
+  google.hardware.image.EncodeParams encodeParams;
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl
new file mode 100644
index 0000000..a6e4eeb
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/QueryResult.aidl
@@ -0,0 +1,41 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@VintfStability
+parcelable QueryResult {
+  android.hardware.graphics.common.PixelFormat[] supportedColorFormats;
+  long usageHardwareBuffer;
+}
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/RotationDegree.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/RotationDegree.aidl
new file mode 100644
index 0000000..3323858
--- /dev/null
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/RotationDegree.aidl
@@ -0,0 +1,43 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
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
+package google.hardware.image;
+@Backing(type="int") @VintfStability
+enum RotationDegree {
+  R_NONE,
+  R_90,
+  R_180,
+  R_270,
+}
diff --git a/image/google/hardware/image/ComponentType.aidl b/image/google/hardware/image/ComponentType.aidl
new file mode 100644
index 0000000..26d7690
--- /dev/null
+++ b/image/google/hardware/image/ComponentType.aidl
@@ -0,0 +1,23 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+/**
+ * Specifies whether a component is an encoder or decoder.
+ */
+@VintfStability @Backing(type="int") enum ComponentType { JPEG_ENC, JPEG_DEC }
diff --git a/image/google/hardware/image/EncodeParams.aidl b/image/google/hardware/image/EncodeParams.aidl
new file mode 100644
index 0000000..9ac1af0
--- /dev/null
+++ b/image/google/hardware/image/EncodeParams.aidl
@@ -0,0 +1,33 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import google.hardware.image.Metadata;
+import google.hardware.image.MirrorDirection;
+import google.hardware.image.RotationDegree;
+
+/**
+ * Parameters required to encode an image.
+ */
+@VintfStability
+parcelable EncodeParams {
+    int picWidth;
+    int picHeight;
+    int qualityFactor;
+    Metadata[] meta;
+}
diff --git a/image/google/hardware/image/IComponent.aidl b/image/google/hardware/image/IComponent.aidl
new file mode 100644
index 0000000..08c768c
--- /dev/null
+++ b/image/google/hardware/image/IComponent.aidl
@@ -0,0 +1,68 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import android.hardware.HardwareBuffer;
+import google.hardware.image.Metadata;
+import google.hardware.image.Params;
+import google.hardware.image.QueryResult;
+
+/**
+ * Interface for an image codec component. Components have two functionalities:
+ * encode and decode.
+ */
+@VintfStability
+interface IComponent {
+    /**
+     * Encodes an image with the component. This is a blocking call and will
+     * return when the encoding is complete. The dst buffer is provided through
+     * the IComponentCallback call during the encoding.
+     *
+     * @params src HardwareBuffer containing a YUV image. The format must be
+     * one of the supported PixelFormats returned by queryComponentConstraints().
+     * @return size of the encoded output bitstream.
+     */
+    int encode(in HardwareBuffer src);
+
+    /**
+     * Decodes an image with the component. This is a blocking call and will
+     * return when the decoding is complete. The dst buffer is provided through
+     * the IComponentCallback call during the decoding.
+     *
+     * @param src HardwareBuffer containing an encoded image bitstream. The
+     * format must be BLOB.
+     */
+    void decode(in HardwareBuffer src);
+
+    /**
+     * Queries for general information about the component.
+     *
+     * @return QueryResult object with all entries filled.
+     */
+    QueryResult queryComponentConstraints();
+
+    /**
+     * Sets component parameters before encoding/decoding.
+     *
+     * @param params The parameters needed from the client for encoding/decoding.
+     * @param meta List of Metadata objects representing JPEG APP segments. This
+     * list can be empty if there is no metadata associated with the image to
+     * be encoded.
+     */
+    void setParams(in Params params);
+}
diff --git a/image/google/hardware/image/IComponentCallback.aidl b/image/google/hardware/image/IComponentCallback.aidl
new file mode 100644
index 0000000..3175dba
--- /dev/null
+++ b/image/google/hardware/image/IComponentCallback.aidl
@@ -0,0 +1,58 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import android.hardware.HardwareBuffer;
+import android.hardware.graphics.common.PixelFormat;
+
+/**
+ * Interface for an image codec component callback mechanism.
+ * Notifies the client that they must return a newly allocated or previously
+ * allocated buffer that fits the specified parameters.
+ */
+@VintfStability
+interface IComponentCallback {
+    /**
+     * Creates or fetches an existing linear buffer, which will be used as the
+     * destination buffer during image encoding.
+     *
+     * @param size The length of the linear buffer to be returned.
+     * @param srcId The unique AHardwareBuffer ID for the source buffer associated
+     * with this encoding operation.
+     * @return HardwareBuffer to be filled with encode output. The format of the
+     * buffer must be BLOB.
+     */
+    HardwareBuffer allocateLinearBuffer(in int size, in int srcId);
+
+    /**
+     * Creates or fetches an existing graphic buffer, which will be used as the
+     * destination buffer during image decoding.
+     *
+     * @param width The width of the graphic buffer to be returned.
+     * @param height The height of the graphic buffer to be returned.
+     * @param colorFormat The colour format of the image that this buffer will
+     * be used for.
+     * @param srcId The unique AHardwareBuffer ID for the source buffer associated
+     * with this encoding operation.
+     * @return HardwareBuffer to be filled with decode output. The format of the
+     * buffer must be one of the supported colour formats from
+     * IComponent::queryComponentConstraints.
+     */
+    HardwareBuffer allocateGraphicBuffer(
+            in int width, in int height, in PixelFormat colorFormat, in int srcId);
+}
diff --git a/image/google/hardware/image/IComponentStore.aidl b/image/google/hardware/image/IComponentStore.aidl
new file mode 100644
index 0000000..b24b071
--- /dev/null
+++ b/image/google/hardware/image/IComponentStore.aidl
@@ -0,0 +1,44 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import google.hardware.image.ComponentType;
+import google.hardware.image.IComponent;
+import google.hardware.image.IComponentCallback;
+
+/**
+ * Interface that creates image codec component interfaces when requested.
+ * The google.hardware.image-V1-service service creates an instance of this
+ * interface.
+ */
+@VintfStability
+interface IComponentStore {
+    /**
+     * Creates and returns a new instance of an image codec component interface.
+     * This component interface can be used to encode and decode images.
+     *
+     * @param name Component identifier.
+     * @param type Specifies the component is for encoding or decoding.
+     * @param callback Method for backwards communication from image HAL to
+     * client app. Used to tell the client the size of the output buffer
+     * required for encode/decode.
+     * @return The created component.
+     */
+    IComponent createComponent(
+            in String name, in ComponentType type, in IComponentCallback callback);
+}
diff --git a/image/google/hardware/image/Metadata.aidl b/image/google/hardware/image/Metadata.aidl
new file mode 100644
index 0000000..9efa533
--- /dev/null
+++ b/image/google/hardware/image/Metadata.aidl
@@ -0,0 +1,35 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import android.hardware.HardwareBuffer;
+
+/**
+ * Metadata for a JPEG image. This structure represents an APP segment.
+ */
+@VintfStability
+parcelable Metadata {
+    /**
+     * The data of the APP segment.
+     */
+    byte[] metaBuf;
+    /**
+     * The APP marker for the segment.
+     */
+    int marker;
+}
diff --git a/image/google/hardware/image/MirrorDirection.aidl b/image/google/hardware/image/MirrorDirection.aidl
new file mode 100644
index 0000000..a43412c
--- /dev/null
+++ b/image/google/hardware/image/MirrorDirection.aidl
@@ -0,0 +1,23 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+/**
+ * Options for image mirroring during encoding.
+ */
+@VintfStability @Backing(type="int") enum MirrorDirection { NONE, VER, HOR, HOR_VER }
diff --git a/image/google/hardware/image/Params.aidl b/image/google/hardware/image/Params.aidl
new file mode 100644
index 0000000..ac1b863
--- /dev/null
+++ b/image/google/hardware/image/Params.aidl
@@ -0,0 +1,30 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import google.hardware.image.EncodeParams;
+
+/**
+ * Params required to encode or decode an image.
+ * Currently, for the existing image codec, only encoding requires parameters.
+ * This 'Params' structure allows for future decoding parameters.
+ */
+@VintfStability
+union Params {
+    EncodeParams encodeParams;
+}
diff --git a/image/google/hardware/image/QueryResult.aidl b/image/google/hardware/image/QueryResult.aidl
new file mode 100644
index 0000000..0208db0
--- /dev/null
+++ b/image/google/hardware/image/QueryResult.aidl
@@ -0,0 +1,38 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+import android.hardware.graphics.common.PixelFormat;
+
+/**
+ * List of image codec constraints. This is filled in the HAL when the client
+ * queries for this information.
+ */
+@VintfStability
+parcelable QueryResult {
+    /**
+     * Colour formats that are supported by image codec.
+     */
+    PixelFormat[] supportedColorFormats;
+    /**
+     * Usage value required for HardwareBuffer creation. The client will use
+     * this usage value when allocating the image buffer/bitstream buffer using
+     * gralloc. A buffer created without this usage bit will be rejected.
+     */
+    long usageHardwareBuffer;
+}
diff --git a/image/google/hardware/image/RotationDegree.aidl b/image/google/hardware/image/RotationDegree.aidl
new file mode 100644
index 0000000..d5ba122
--- /dev/null
+++ b/image/google/hardware/image/RotationDegree.aidl
@@ -0,0 +1,23 @@
+/******************************************************************************
+ *
+ *  Copyright (C) 2024 Google LLC.
+ *
+ *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  you may not use this file except in compliance with the License.
+ *  You may obtain a copy of the License at:
+ *
+ *  http://www.apache.org/licenses/LICENSE-2.0
+ *
+ *  Unless required by applicable law or agreed to in writing, software
+ *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  See the License for the specific language governing permissions and
+ *  limitations under the License.
+ *
+ ******************************************************************************/
+package google.hardware.image;
+
+/**
+ * Options for image rotation during encoding.
+ */
+@VintfStability @Backing(type="int") enum RotationDegree { R_NONE, R_90, R_180, R_270 }
```

