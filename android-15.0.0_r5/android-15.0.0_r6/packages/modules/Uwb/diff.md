```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index d251bea9..7e469b93 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -15,5 +15,10 @@
     {
       "name": "libuwb_uci_jni_rust_tests"
     }
+  ],
+  "postsubmit": [
+    {
+      "name": "UwbFusionLibTests"
+    }
   ]
 }
diff --git a/androidx_backend/Android.bp b/androidx_backend/Android.bp
index b452d019..638a25bb 100644
--- a/androidx_backend/Android.bp
+++ b/androidx_backend/Android.bp
@@ -40,7 +40,13 @@ aidl_interface {
             version: "1",
             imports: [],
         },
+        {
+            version: "2",
+            imports: [],
+        },
+
     ],
+    frozen: true,
 
 }
 
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/.hash b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/.hash
new file mode 100644
index 00000000..9fd5d480
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/.hash
@@ -0,0 +1 @@
+00e289c83c4665e3f7e579022bcae1393e55795f
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IRangingSessionCallback.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IRangingSessionCallback.aidl
new file mode 100644
index 00000000..86629bcd
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IRangingSessionCallback.aidl
@@ -0,0 +1,45 @@
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
+package androidx.core.uwb.backend;
+interface IRangingSessionCallback {
+  oneway void onRangingInitialized(in androidx.core.uwb.backend.UwbDevice device);
+  oneway void onRangingResult(in androidx.core.uwb.backend.UwbDevice device, in androidx.core.uwb.backend.RangingPosition position);
+  oneway void onRangingSuspended(in androidx.core.uwb.backend.UwbDevice device, int reason);
+  const int UNKNOWN = 0;
+  const int WRONG_PARAMETERS = 1;
+  const int FAILED_TO_START = 2;
+  const int STOPPED_BY_PEER = 3;
+  const int STOP_RANGING_CALLED = 4;
+  const int MAX_RANGING_ROUND_RETRY_REACHED = 5;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IUwb.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IUwb.aidl
new file mode 100644
index 00000000..d1334cfd
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IUwb.aidl
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
+package androidx.core.uwb.backend;
+interface IUwb {
+  androidx.core.uwb.backend.IUwbClient getControleeClient();
+  androidx.core.uwb.backend.IUwbClient getControllerClient();
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IUwbClient.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IUwbClient.aidl
new file mode 100644
index 00000000..cbdda626
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/IUwbClient.aidl
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
+package androidx.core.uwb.backend;
+interface IUwbClient {
+  boolean isAvailable();
+  androidx.core.uwb.backend.RangingCapabilities getRangingCapabilities();
+  androidx.core.uwb.backend.UwbAddress getLocalAddress();
+  androidx.core.uwb.backend.UwbComplexChannel getComplexChannel();
+  void startRanging(in androidx.core.uwb.backend.RangingParameters parameters, in androidx.core.uwb.backend.IRangingSessionCallback callback);
+  void stopRanging(in androidx.core.uwb.backend.IRangingSessionCallback callback);
+  void addControlee(in androidx.core.uwb.backend.UwbAddress address);
+  void addControleeWithSessionParams(in androidx.core.uwb.backend.RangingControleeParameters params);
+  void removeControlee(in androidx.core.uwb.backend.UwbAddress address);
+  void reconfigureRangingInterval(in int intervalSkipCount);
+  void reconfigureRangeDataNtf(in int configType, in int proximityNearCm, in int proximityFarCm);
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingCapabilities.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingCapabilities.aidl
new file mode 100644
index 00000000..5762da88
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingCapabilities.aidl
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
+package androidx.core.uwb.backend;
+parcelable RangingCapabilities {
+  boolean supportsDistance;
+  boolean supportsAzimuthalAngle;
+  boolean supportsElevationAngle;
+  int minRangingInterval;
+  int[] supportedChannels;
+  int[] supportedNtfConfigs;
+  int[] supportedConfigIds;
+  @nullable int[] supportedSlotDurations;
+  @nullable int[] supportedRangingUpdateRates;
+  boolean supportsRangingIntervalReconfigure;
+  boolean hasBackgroundRangingSupport;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingControleeParameters.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingControleeParameters.aidl
new file mode 100644
index 00000000..0e6e9a72
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingControleeParameters.aidl
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
+package androidx.core.uwb.backend;
+parcelable RangingControleeParameters {
+  androidx.core.uwb.backend.UwbAddress address;
+  int subSessionId;
+  byte[] subSessionKey;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingMeasurement.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingMeasurement.aidl
new file mode 100644
index 00000000..4c842505
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingMeasurement.aidl
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
+package androidx.core.uwb.backend;
+parcelable RangingMeasurement {
+  int confidence;
+  float value;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingParameters.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingParameters.aidl
new file mode 100644
index 00000000..eef5efe8
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingParameters.aidl
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
+package androidx.core.uwb.backend;
+parcelable RangingParameters {
+  int uwbConfigId;
+  int sessionId;
+  int subSessionId;
+  byte[] sessionKeyInfo;
+  byte[] subSessionKeyInfo;
+  androidx.core.uwb.backend.UwbComplexChannel complexChannel;
+  List<androidx.core.uwb.backend.UwbDevice> peerDevices;
+  int rangingUpdateRate;
+  @nullable androidx.core.uwb.backend.UwbRangeDataNtfConfig uwbRangeDataNtfConfig;
+  int slotDuration;
+  boolean isAoaDisabled;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingPosition.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingPosition.aidl
new file mode 100644
index 00000000..6a1d8bd7
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/RangingPosition.aidl
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
+package androidx.core.uwb.backend;
+parcelable RangingPosition {
+  androidx.core.uwb.backend.RangingMeasurement distance;
+  androidx.core.uwb.backend.RangingMeasurement azimuth;
+  androidx.core.uwb.backend.RangingMeasurement elevation;
+  long elapsedRealtimeNanos;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbAddress.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbAddress.aidl
new file mode 100644
index 00000000..bf4e6e30
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbAddress.aidl
@@ -0,0 +1,37 @@
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
+package androidx.core.uwb.backend;
+parcelable UwbAddress {
+  byte[] address;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbComplexChannel.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbComplexChannel.aidl
new file mode 100644
index 00000000..99316af5
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbComplexChannel.aidl
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
+package androidx.core.uwb.backend;
+parcelable UwbComplexChannel {
+  int channel;
+  int preambleIndex;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbDevice.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbDevice.aidl
new file mode 100644
index 00000000..1493f13e
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbDevice.aidl
@@ -0,0 +1,37 @@
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
+package androidx.core.uwb.backend;
+parcelable UwbDevice {
+  androidx.core.uwb.backend.UwbAddress address;
+}
diff --git a/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbRangeDataNtfConfig.aidl b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbRangeDataNtfConfig.aidl
new file mode 100644
index 00000000..81df4226
--- /dev/null
+++ b/androidx_backend/aidl_api/androidx.core.uwb.backend.aidl_interface/2/androidx/core/uwb/backend/UwbRangeDataNtfConfig.aidl
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
+package androidx.core.uwb.backend;
+parcelable UwbRangeDataNtfConfig {
+  int rangeDataNtfConfigType;
+  int ntfProximityNearCm;
+  int ntfProximityFarCm;
+}
diff --git a/androidx_backend/src/androidx/core/uwb/backend/impl/internal/RangingDevice.java b/androidx_backend/src/androidx/core/uwb/backend/impl/internal/RangingDevice.java
index 86165a77..825a0ad2 100644
--- a/androidx_backend/src/androidx/core/uwb/backend/impl/internal/RangingDevice.java
+++ b/androidx_backend/src/androidx/core/uwb/backend/impl/internal/RangingDevice.java
@@ -53,6 +53,7 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.concurrent.Executor;
 import java.util.concurrent.ExecutorService;
+import java.util.concurrent.atomic.AtomicBoolean;
 
 /** Implements start/stop ranging operations. */
 public abstract class RangingDevice {
@@ -87,7 +88,7 @@ public abstract class RangingDevice {
     @Nullable
     private RangingSession mRangingSession;
 
-    private boolean mIsRanging = false;
+    private AtomicBoolean mIsRanging = new AtomicBoolean(false);
 
     /** If true, local address and complex channel will be hardcoded */
     private Boolean mForTesting = false;
@@ -210,7 +211,7 @@ public abstract class RangingDevice {
      * session can be open but not ranging
      */
     public boolean isRanging() {
-        return mIsRanging;
+        return mIsRanging.get();
     }
 
     protected boolean isKnownPeer(UwbAddress address) {
@@ -309,7 +310,7 @@ public abstract class RangingDevice {
             @Override
             public void onStarted(PersistableBundle sessionInfo) {
                 callback.onRangingInitialized(getUwbDevice());
-                mIsRanging = true;
+                mIsRanging.set(true);
                 mOpAsyncCallbackRunner.complete(true);
             }
 
@@ -350,9 +351,7 @@ public abstract class RangingDevice {
                 UwbDevice device = getUwbDevice();
                 runOnBackendCallbackThread(
                         () -> {
-                            synchronized (RangingDevice.this) {
-                                mIsRanging = false;
-                            }
+                            mIsRanging.set(false);
                             callback.onRangingSuspended(device, suspendedReason);
                         });
                 if (suspendedReason == REASON_STOP_RANGING_CALLED
@@ -370,6 +369,14 @@ public abstract class RangingDevice {
             @WorkerThread
             @Override
             public void onClosed(int reason, PersistableBundle parameters) {
+                UwbDevice device = getUwbDevice();
+                runOnBackendCallbackThread(
+                        () -> {
+                            if (mIsRanging.compareAndSet(true, false)) {
+                                callback.onRangingSuspended(device,
+                                        RangingSessionCallback.REASON_SYSTEM_POLICY);
+                            }
+                        });
                 mRangingSession = null;
                 mOpAsyncCallbackRunner.completeIfActive(true);
             }
@@ -529,7 +536,7 @@ public abstract class RangingDevice {
             return INVALID_API_CALL;
         }
         mRangingReportedAllowed = false;
-        if (mIsRanging) {
+        if (mIsRanging.get()) {
             mOpAsyncCallbackRunner.execOperation(
                     () -> requireNonNull(mRangingSession).stop(), "Stop Ranging");
         } else {
diff --git a/androidx_backend/src/androidx/core/uwb/backend/impl/internal/UwbServiceImpl.java b/androidx_backend/src/androidx/core/uwb/backend/impl/internal/UwbServiceImpl.java
index f879212e..6cc563a3 100644
--- a/androidx_backend/src/androidx/core/uwb/backend/impl/internal/UwbServiceImpl.java
+++ b/androidx_backend/src/androidx/core/uwb/backend/impl/internal/UwbServiceImpl.java
@@ -48,6 +48,7 @@ import com.google.uwb.support.fira.FiraSpecificationParams;
 import com.google.uwb.support.multichip.ChipInfoParams;
 
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.EnumSet;
 import java.util.List;
 import java.util.Set;
@@ -236,7 +237,7 @@ public class UwbServiceImpl {
             supportedConfigIds.add(CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF);
         }
         int minSlotDurationUs = specificationParams.getMinSlotDurationUs();
-        List<Integer> supportedSlotDurations = new ArrayList<>(Utils.DURATION_2_MS);
+        List<Integer> supportedSlotDurations = new ArrayList<>(Arrays.asList(Utils.DURATION_2_MS));
         if (minSlotDurationUs <= 1000) {
             supportedSlotDurations.add(Utils.DURATION_1_MS);
         }
diff --git a/androidx_backend/tests/Android.bp b/androidx_backend/tests/Android.bp
index 7e0a3b52..82a35175 100644
--- a/androidx_backend/tests/Android.bp
+++ b/androidx_backend/tests/Android.bp
@@ -46,9 +46,9 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "framework-annotations-lib",
     ],
 
diff --git a/apex/Android.bp b/apex/Android.bp
index 09cd15ba..1cbd4832 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -66,10 +66,34 @@ sdk {
     ],
 }
 
+soong_config_module_type {
+    name: "custom_bootclasspath_fragment",
+    module_type: "bootclasspath_fragment",
+    config_namespace: "bootclasspath",
+    bool_variables: [
+        "release_ranging_stack",
+    ],
+    properties: [
+        "contents",
+    ],
+}
+
 // Encapsulate the contributions made by the com.android.uwb to the bootclasspath.
-bootclasspath_fragment {
+custom_bootclasspath_fragment {
     name: "com.android.uwb-bootclasspath-fragment",
-    contents: ["framework-uwb"],
+    soong_config_variables: {
+        release_ranging_stack: {
+            contents: [
+                "framework-uwb",
+                "framework-ranging",
+            ],
+            conditions_default: {
+                contents: [
+                    "framework-uwb",
+                ],
+            },
+        },
+    },
     apex_available: ["com.android.uwb"],
 
     // The bootclasspath_fragments that provide APIs on which this depends.
@@ -96,6 +120,7 @@ bootclasspath_fragment {
         // API.
         split_packages: [
             "android.uwb",
+            "android.ranging",
         ],
 
         // The following packages and all their subpackages currently only
@@ -111,8 +136,32 @@ bootclasspath_fragment {
     },
 }
 
-systemserverclasspath_fragment {
+soong_config_module_type {
+    name: "custom_systemserverclasspath_fragment",
+    module_type: "systemserverclasspath_fragment",
+    config_namespace: "bootclasspath",
+    bool_variables: [
+        "release_ranging_stack",
+    ],
+    properties: [
+        "standalone_contents",
+    ],
+}
+
+custom_systemserverclasspath_fragment {
     name: "com.android.uwb-systemserverclasspath-fragment",
-    standalone_contents: ["service-uwb"],
+    soong_config_variables: {
+        release_ranging_stack: {
+            standalone_contents: [
+                "service-uwb",
+                "service-ranging",
+            ],
+            conditions_default: {
+                standalone_contents: [
+                    "service-uwb",
+                ],
+            },
+        },
+    },
     apex_available: ["com.android.uwb"],
 }
diff --git a/framework/Android.bp b/framework/Android.bp
index 71671cec..ef74192b 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -75,6 +75,9 @@ java_library {
     sdk_version: "module_current",
     libs: ["framework-annotations-lib"],
     installable: false,
+    lint: {
+        baseline_filename: "lint-baseline.xml",
+    },
 }
 
 // post-jarjar version of framework-uwb
@@ -112,6 +115,7 @@ java_sdk_library {
     ],
     lint: {
         strict_updatability_linting: true,
+        baseline_filename: "lint-baseline.xml",
     },
 }
 
diff --git a/framework/lint-baseline.xml b/framework/lint-baseline.xml
new file mode 100644
index 00000000..39db8ce8
--- /dev/null
+++ b/framework/lint-baseline.xml
@@ -0,0 +1,829 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<issues format="6" by="lint 8.4.0-alpha08" type="baseline" client="" dependencies="true" name="" variant="all" version="8.4.0-alpha08">
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="430"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="430"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="438"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="438"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="477"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="477"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="486"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="486"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="496"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="496"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="505"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="505"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="833"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="907"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="936"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.query_timestamp_micros&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="564"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="759"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="786"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="815"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="430"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="430"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="438"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="438"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="477"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="477"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="486"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="486"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="496"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="496"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="505"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="505"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="833"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="907"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="936"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.query_timestamp_micros&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="564"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="759"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="786"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="815"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.reason_inband_session_stop&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="200"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="430"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="430"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="438"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="438"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="477"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="477"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="486"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="486"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="496"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="496"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="505"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="505"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.data_transfer_phase_config&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="833"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="907"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hybrid_session_support&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/RangingSession.java"
+            line="936"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="        @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="153"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.query_timestamp_micros&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="564"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="759"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="786"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="@FlaggedApi should specify an actual flag constant; raw strings are discouraged (and more importantly, **not enforced**)"
+        errorLine1="    @FlaggedApi(&quot;com.android.uwb.flags.hw_state&quot;)"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/modules/Uwb/framework/java/android/uwb/UwbManager.java"
+            line="815"
+            column="17"/>
+    </issue>
+
+</issues>
diff --git a/framework/tests/Android.bp b/framework/tests/Android.bp
index c99e497e..197c9efb 100644
--- a/framework/tests/Android.bp
+++ b/framework/tests/Android.bp
@@ -49,8 +49,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
 
     test_suites: [
diff --git a/generic_ranging/Android.bp b/generic_ranging/Android.bp
index 454cb50b..0d6663d2 100644
--- a/generic_ranging/Android.bp
+++ b/generic_ranging/Android.bp
@@ -40,7 +40,8 @@ java_library {
         "framework-annotations-lib",
         "guava",
         "multi-sensor-finder-configuration-java-proto",
-        "uwb_androidx_backend",
+        "com.uwb.fusion",
+        "ranging_uwb_backend",
     ],
     visibility: [
         ":__subpackages__",
diff --git a/generic_ranging/proto/Android.bp b/generic_ranging/proto/Android.bp
index 4c08354a..2d475e85 100644
--- a/generic_ranging/proto/Android.bp
+++ b/generic_ranging/proto/Android.bp
@@ -25,11 +25,7 @@ java_library {
     },
     sdk_version: "system_current",
     min_sdk_version: "34",
-    srcs: [
-        "src/estimate.proto",
-        "src/debug_log.proto",
-        "src/multi_sensor_finder_configuration.proto",
-    ],
+    srcs: ["src/**/*.proto"],
     apex_available: [
         "com.android.uwb",
     ],
diff --git a/generic_ranging/proto/src/debug_log.proto b/generic_ranging/proto/src/debug_log.proto
index 6946eff1..0bf3a6a2 100644
--- a/generic_ranging/proto/src/debug_log.proto
+++ b/generic_ranging/proto/src/debug_log.proto
@@ -16,11 +16,11 @@
 
 syntax = "proto3";
 
-package com.android.ranging.generic.proto;
+package com.android.ranging.proto;
 
 import "packages/modules/Uwb/generic_ranging/proto/src/estimate.proto";
 
-option java_package = "com.android.ranging.generic.proto";
+option java_package = "com.android.ranging.proto";
 option java_multiple_files = true;
 
 message Event {
@@ -55,7 +55,7 @@ message InputContainer {
 }
 
 message LeanEstimate {
-  com.android.ranging.generic.proto.Estimate.Status status = 1;
+  com.android.ranging.proto.Estimate.Status status = 1;
   float range_m = 2;
   float bearing_rad = 3;
   float estimated_beacon_position_error_std_dev_m = 4;
diff --git a/generic_ranging/proto/src/estimate.proto b/generic_ranging/proto/src/estimate.proto
index 8d86f294..67a863a0 100644
--- a/generic_ranging/proto/src/estimate.proto
+++ b/generic_ranging/proto/src/estimate.proto
@@ -16,9 +16,9 @@
 
 syntax = "proto3";
 
-package com.android.ranging.generic.proto;
+package com.android.ranging.proto;
 
-option java_package = "com.android.ranging.generic.proto";
+option java_package = "com.android.ranging.proto";
 option java_multiple_files = true;
 
  // Next ID: 14
diff --git a/generic_ranging/proto/src/multi_sensor_finder_configuration.proto b/generic_ranging/proto/src/multi_sensor_finder_configuration.proto
index 985bcead..4a8e9be7 100644
--- a/generic_ranging/proto/src/multi_sensor_finder_configuration.proto
+++ b/generic_ranging/proto/src/multi_sensor_finder_configuration.proto
@@ -16,9 +16,9 @@
 
 syntax = "proto3";
 
-package com.android.ranging.generic.proto;
+package com.android.ranging.proto;
 
-option java_package = "com.android.ranging.generic.proto";
+option java_package = "com.android.ranging.proto";
 option java_multiple_files = true;
 
 enum ConfidenceLevel {
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/DefaultFusionConfig.java b/generic_ranging/src/com/android/ranging/DefaultFusionConfig.java
similarity index 83%
rename from generic_ranging/src/com/android/ranging/generic/ranging/DefaultFusionConfig.java
rename to generic_ranging/src/com/android/ranging/DefaultFusionConfig.java
index e4de35a2..e71fdec2 100644
--- a/generic_ranging/src/com/android/ranging/generic/ranging/DefaultFusionConfig.java
+++ b/generic_ranging/src/com/android/ranging/DefaultFusionConfig.java
@@ -14,24 +14,24 @@
  * limitations under the License.
  */
 
-package com.android.ranging.generic.ranging;
+package com.android.ranging;
 
-import com.android.ranging.generic.proto.ConfidenceLevel;
-import com.android.ranging.generic.proto.DebugLoggerConfiguration;
-import com.android.ranging.generic.proto.DistanceTraveledCheckConfig;
-import com.android.ranging.generic.proto.ExponentiallyWeightedGaussianModelConfig;
-import com.android.ranging.generic.proto.FuzzyUpdateSchedulerConfig;
-import com.android.ranging.generic.proto.InitialStateSamplerConfig;
-import com.android.ranging.generic.proto.ModelConfigContainer;
-import com.android.ranging.generic.proto.MultiSensorFinderConfig;
-import com.android.ranging.generic.proto.NisDivergenceDetectorConfig;
-import com.android.ranging.generic.proto.OdometryBasedEstimatePropagatorConfig;
-import com.android.ranging.generic.proto.OdometryNoiseAdderConfig;
-import com.android.ranging.generic.proto.OdometryThrottlerConfig;
-import com.android.ranging.generic.proto.ParticleFilterConfig;
-import com.android.ranging.generic.proto.RangeMeasurementConfig;
-import com.android.ranging.generic.proto.RangeMeasurementConfig.RangeSensorModelType;
-import com.android.ranging.generic.proto.VarianceBasedSwitchingMeasurementModelConfig;
+import com.android.ranging.proto.ConfidenceLevel;
+import com.android.ranging.proto.DebugLoggerConfiguration;
+import com.android.ranging.proto.DistanceTraveledCheckConfig;
+import com.android.ranging.proto.ExponentiallyWeightedGaussianModelConfig;
+import com.android.ranging.proto.FuzzyUpdateSchedulerConfig;
+import com.android.ranging.proto.InitialStateSamplerConfig;
+import com.android.ranging.proto.ModelConfigContainer;
+import com.android.ranging.proto.MultiSensorFinderConfig;
+import com.android.ranging.proto.NisDivergenceDetectorConfig;
+import com.android.ranging.proto.OdometryBasedEstimatePropagatorConfig;
+import com.android.ranging.proto.OdometryNoiseAdderConfig;
+import com.android.ranging.proto.OdometryThrottlerConfig;
+import com.android.ranging.proto.ParticleFilterConfig;
+import com.android.ranging.proto.RangeMeasurementConfig;
+import com.android.ranging.proto.RangeMeasurementConfig.RangeSensorModelType;
+import com.android.ranging.proto.VarianceBasedSwitchingMeasurementModelConfig;
 
 /** Default configuration for the Fusion algorithm. */
 public final class DefaultFusionConfig {
diff --git a/generic_ranging/src/com/android/ranging/RangingAdapter.java b/generic_ranging/src/com/android/ranging/RangingAdapter.java
new file mode 100644
index 00000000..0dcfebac
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/RangingAdapter.java
@@ -0,0 +1,85 @@
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
+package com.android.ranging;
+
+import androidx.annotation.IntDef;
+
+import com.android.ranging.RangingParameters.TechnologyParameters;
+
+import com.google.common.util.concurrent.ListenableFuture;
+
+/** RangingAdapter representing a common ranging class for multiple ranging technologies. */
+public interface RangingAdapter {
+
+    /** Returns {@link RangingTechnology} of this adapter. */
+    RangingTechnology getType();
+
+    /**
+     * @return true if ranging with this ranging technology is currently enabled, or false
+     * otherwise. When this returns false it's most likely because of not being enabled in settings,
+     * airplane mode being on, etc.
+     */
+    ListenableFuture<Boolean> isEnabled();
+
+    /**
+     * Start ranging. Does nothing if the ranging technology is not enabled on device or if ranging
+     * has already been started. In the latter case, this method will not overwrite the existing
+     * callback.
+     * @param parameters to range with.
+     * @param callback to be called on the occurrence of ranging events.
+     */
+    void start(TechnologyParameters parameters, Callback callback);
+
+    /** Stop ranging. */
+    void stop();
+
+    /** Callback for getting notified when ranging starts or stops. */
+    interface Callback {
+        /**
+         * Notifies the caller that ranging has started on this device. onStarted will not be called
+         * after start if API failed to initialize, in that case onStopped with an appropriate error
+         * code will be called.
+         */
+        void onStarted();
+
+        /** Notifies the caller that ranging has stopped on this device. */
+        void onStopped(@StoppedReason int reason);
+
+        /**
+         * Notifies the caller on each instance of ranging data received from the ranging
+         * technology.
+         */
+        void onRangingData(RangingData data);
+
+        @IntDef({
+                StoppedReason.UNKNOWN,
+                StoppedReason.FAILED_TO_START,
+                StoppedReason.REQUESTED,
+                StoppedReason.LOST_CONNECTION,
+                StoppedReason.SYSTEM_POLICY,
+                StoppedReason.ERROR,
+        })
+        @interface StoppedReason {
+            int UNKNOWN = 0;
+            int ERROR = 1;
+            int FAILED_TO_START = 2;
+            int REQUESTED = 3;
+            int LOST_CONNECTION = 4;
+            int SYSTEM_POLICY = 5;
+        }
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRangingConfig.java b/generic_ranging/src/com/android/ranging/RangingConfig.java
similarity index 54%
rename from generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRangingConfig.java
rename to generic_ranging/src/com/android/ranging/RangingConfig.java
index 12dd5660..d647fe3d 100644
--- a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRangingConfig.java
+++ b/generic_ranging/src/com/android/ranging/RangingConfig.java
@@ -14,72 +14,60 @@
  * limitations under the License.
  */
 
-package com.android.ranging.generic.ranging;
+package com.android.ranging;
 
-import com.android.ranging.generic.RangingTechnology;
-import com.android.ranging.generic.proto.MultiSensorFinderConfig;
+import com.android.ranging.proto.MultiSensorFinderConfig;
 
 import com.google.auto.value.AutoValue;
 import com.google.common.base.Preconditions;
-import com.google.common.collect.ImmutableList;
 
 import java.time.Duration;
 import java.util.Optional;
 
-/** Configuration for Precision Ranging. */
+/** Configuration for multi-tecnology ranging */
 @AutoValue
-public abstract class PrecisionRangingConfig {
-
-    /** Returns the list of ranging technologies that were requested for this ranging session. */
-    public abstract ImmutableList<RangingTechnology> getRangingTechnologiesToRangeWith();
+public abstract class RangingConfig {
 
     /** Returns whether to use the fusing algorithm or not. */
     public abstract boolean getUseFusingAlgorithm();
 
     /**
      * Returns the max interval at which data will be reported back. If set to 0 data will be
-     * reported
-     * immediately on reception. If set to non zero value, only latest received data that hasn't
-     * been
-     * yet reported will be reported, so there's a chance that some data doesn't get reported if
-     * multiple data points were received during the same update interval.
+     * reported immediately on reception. If set to non zero value, only latest received data that
+     * hasn't yet been reported will be reported, so there's a chance that some data doesn't get
+     * reported if multiple data points were received during the same update interval.
      */
     public abstract Duration getMaxUpdateInterval();
 
     /**
      * Returns the timeout after which precision ranging will be stopped if no data was produced
-     * since
-     * precision ranging started.
+     * since precision ranging started.
      */
     public abstract Duration getInitTimeout();
 
     /**
-     * Returns the timeout to stop reporting back new data if fusion algorithm wasn't feeded ranging
+     * Returns the timeout to stop reporting back new data if fusion algorithm wasn't fed ranging
      * data in that amount of time. Checked only if useFusingAlgorithm is set to true.
      */
     public abstract Duration getFusionAlgorithmDriftTimeout();
 
     /**
-     * Returns the timeout to stop precision ranging if there were no new precision data updates
-     * sent
-     * in that time period.
+     * Returns the timeout to stop ranging if there were no new data updates sent in that time
+     * period.
      */
     public abstract Duration getNoUpdateTimeout();
 
     /** Returns the fusion algorithm configuration if present. */
     public abstract Optional<MultiSensorFinderConfig> getFusionAlgorithmConfig();
 
-    /** Returns a builder for {@link PrecisionRangingConfig}. */
+    /** Returns a builder for {@link RangingConfig}. */
     public static Builder builder() {
-        return new AutoValue_PrecisionRangingConfig.Builder();
+        return new AutoValue_RangingConfig.Builder();
     }
 
-    /** Builder for {@link PrecisionRangingConfig}. */
+    /** Builder for {@link RangingConfig}. */
     @AutoValue.Builder
     public abstract static class Builder {
-        public abstract Builder setRangingTechnologiesToRangeWith(
-                ImmutableList<RangingTechnology> rangingTechnologiesToRangeWith);
-
         public abstract Builder setUseFusingAlgorithm(boolean useFusingAlgorithm);
 
         public abstract Builder setMaxUpdateInterval(Duration maxUpdateInterval);
@@ -93,26 +81,15 @@ public abstract class PrecisionRangingConfig {
         public abstract Builder setFusionAlgorithmConfig(MultiSensorFinderConfig
                 fusionAlgorithmConfig);
 
-        abstract PrecisionRangingConfig autoBuild();
+        abstract RangingConfig autoBuild();
 
-        public PrecisionRangingConfig build() {
-            PrecisionRangingConfig config = autoBuild();
-            Preconditions.checkArgument(
-                    !config.getRangingTechnologiesToRangeWith().isEmpty(),
-                    "Ranging technologies to range with must contain at least one ranging "
-                            + "technology.");
+        public RangingConfig build() {
+            RangingConfig config = autoBuild();
             Preconditions.checkArgument(
                     config.getUseFusingAlgorithm() == config.getFusionAlgorithmConfig()
                     .isPresent(),
                     "Fusion algorithm config must be set when and only when useFusingAlgorithm"
-                    + "is set to");
-            if (config.getUseFusingAlgorithm()
-                    && config.getRangingTechnologiesToRangeWith().contains(RangingTechnology
-                    .UWB)) {
-                Preconditions.checkArgument(
-                        config.getFusionAlgorithmConfig().get().getUseUwbMeasurements(),
-                        "Fusion algorithm should accept UWB measurements since UWB was requested.");
-            }
+                    + "is set too");
             return config;
         }
     }
diff --git a/generic_ranging/src/com/android/ranging/RangingData.java b/generic_ranging/src/com/android/ranging/RangingData.java
new file mode 100644
index 00000000..ee64916e
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/RangingData.java
@@ -0,0 +1,179 @@
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
+package com.android.ranging;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.google.common.base.Preconditions;
+
+import java.time.Duration;
+import java.util.Optional;
+import java.util.OptionalDouble;
+import java.util.OptionalInt;
+
+public class RangingData {
+    private final RangingTechnology mTechnology;
+    private final double mRangeDistance;
+    private final double mAzimuth;
+    private final double mElevation;
+    private final int mRssi;
+    private final Duration mTimestamp;
+    private final byte[] mPeerAddress;
+
+    /**
+     * @return the ranging technology that produced this data, or {@code Optional.empty()} if the
+     * data was fused from multiple technologies.
+     */
+    public Optional<RangingTechnology> getTechnology() {
+        return Optional.ofNullable(mTechnology);
+    }
+
+    /** @return range distance in meters */
+    public double getRangeMeters() {
+        return mRangeDistance;
+    }
+
+    /** @return azimuth angle in radians. */
+    public OptionalDouble getAzimuthRadians() {
+        if (Double.isNaN(mAzimuth)) {
+            return OptionalDouble.empty();
+        } else {
+            return OptionalDouble.of(mAzimuth);
+        }
+    }
+
+    /** @return elevation angle in degrees, if provided. */
+    public OptionalDouble getElevationRadians() {
+        if (Double.isNaN(mElevation)) {
+            return OptionalDouble.empty();
+        } else {
+            return OptionalDouble.of(mElevation);
+        }
+    }
+
+    /** @return rssi in dBm, if provided. */
+    public OptionalInt getRssi() {
+        if (mRssi == Integer.MIN_VALUE) {
+            return OptionalInt.empty();
+        } else {
+            return OptionalInt.of(mRssi);
+        }
+    }
+
+    /** @return the timestamp when this data was received, measured as duration since boot. */
+    public @NonNull Duration getTimestamp() {
+        return mTimestamp;
+    }
+
+    /** @return a copy of the sender's address. */
+    public byte[] getPeerAddress() {
+        return mPeerAddress.clone();
+    }
+
+    private RangingData(Builder builder) {
+        Preconditions.checkArgument(builder.mRangeDistance != Integer.MIN_VALUE,
+                "Range distance is required but was not provided");
+        Preconditions.checkArgument(!builder.mTimestamp.isZero(),
+                "Timestamp is required but was not provided");
+        Preconditions.checkArgument(builder.mPeerAddress != null,
+                "Peer address is required but was not provided");
+
+        mTechnology = builder.mTechnology;
+        mRangeDistance = builder.mRangeDistance;
+        mRssi = builder.mRssi;
+        mTimestamp = builder.mTimestamp;
+        mPeerAddress = builder.mPeerAddress;
+        mAzimuth = builder.mAzimuth;
+        mElevation = builder.mElevation;
+    }
+
+    /**
+     * Builder for {@link RangingData}.
+     */
+    public static class Builder {
+        private RangingTechnology mTechnology = null;
+        private double mRangeDistance = Double.NaN;
+        private double mAzimuth = Double.NaN;
+        private double mElevation = Double.NaN;
+        private int mRssi = Integer.MIN_VALUE;
+        private Duration mTimestamp = Duration.ZERO;
+        private byte[] mPeerAddress = null;
+
+        public Builder() {
+        }
+
+        /**
+         * Construct a builder from ranging data that has already been built.
+         * @param data to copy fields from.
+         */
+        public static Builder fromBuilt(RangingData data) {
+            return new Builder()
+                    .setTechnology(data.mTechnology).setRangeDistance(data.mRangeDistance)
+                    .setRssi(data.mRssi).setTimestamp(data.mTimestamp)
+                    .setPeerAddress(data.getPeerAddress()).setAzimuthRadians(data.mAzimuth)
+                    .setElevationRadians(data.mElevation);
+        }
+
+        /** @return the built {@link RangingData}. */
+        public RangingData build() {
+            return new RangingData(this);
+        }
+
+        /** @param technology that produced this data. */
+        public Builder setTechnology(@Nullable RangingTechnology technology) {
+            mTechnology = technology;
+            return this;
+        }
+
+        /** @param distance - measured distance in meters. */
+        public Builder setRangeDistance(double distance) {
+            mRangeDistance = distance;
+            return this;
+        }
+
+        /** @param azimuth angle in radians */
+        public Builder setAzimuthRadians(double azimuth) {
+            mAzimuth = azimuth;
+            return this;
+        }
+
+        /** @param elevation angle in radians. */
+        public Builder setElevationRadians(double elevation) {
+            mElevation = elevation;
+            return this;
+        }
+
+        /** @param rssi in dBm. */
+        public Builder setRssi(int rssi) {
+            mRssi = rssi;
+            return this;
+        }
+
+        /** @param timestamp measured as a duration since device boot. */
+        public Builder setTimestamp(Duration timestamp) {
+            mTimestamp = timestamp;
+            return this;
+        }
+
+        /** @param peerAddress as a byte array. */
+        public Builder setPeerAddress(byte[] peerAddress) {
+            mPeerAddress = peerAddress;
+            return this;
+        }
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/RangingParameters.java b/generic_ranging/src/com/android/ranging/RangingParameters.java
new file mode 100644
index 00000000..5d9d9c7b
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/RangingParameters.java
@@ -0,0 +1,122 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging;
+
+import androidx.annotation.NonNull;
+
+import com.android.ranging.cs.CsParameters;
+import com.android.ranging.uwb.UwbParameters;
+
+import java.util.EnumMap;
+import java.util.Optional;
+
+/** Parameters for a generic ranging session. */
+public class RangingParameters {
+    /** Parameters for a specific generic ranging technology. */
+    public interface TechnologyParameters { }
+
+    public enum DeviceRole {
+        /**
+         * The device is a controlee within the session.
+         */
+        CONTROLEE,
+        /**
+         * The device is the session controller. It decides when the session is started or stopped,
+         * ranging technology preferences, etc.
+         */
+        CONTROLLER
+    }
+
+    private final DeviceRole mRole;
+    private final EnumMap<RangingTechnology, TechnologyParameters> mParameters;
+
+    private RangingParameters(@NonNull RangingParameters.Builder builder) {
+        mRole = builder.mRole;
+        mParameters = new EnumMap<>(RangingTechnology.class);
+
+        if (builder.mUwbParameters != null) {
+            mParameters.put(RangingTechnology.UWB, builder.mUwbParameters);
+        }
+        if (builder.mCsParameters != null) {
+            mParameters.put(RangingTechnology.CS, builder.mCsParameters);
+        }
+    }
+
+    /**
+     * @return The configured device role.
+     */
+    public DeviceRole getRole() {
+        return mRole;
+    }
+
+    /**
+     * @return UWB parameters, or {@code Optional.empty()} if they were never set.
+     */
+    public Optional<UwbParameters> getUwbParameters() {
+        return Optional.ofNullable(mParameters.get(RangingTechnology.UWB))
+                .map(params -> (UwbParameters) params);
+    }
+
+    /**
+     * @return channel sounding parameters, or {@code Optional.empty()} if they were never set.
+     */
+    public Optional<CsParameters> getCsParameters() {
+        return Optional.ofNullable(mParameters.get(RangingTechnology.CS))
+                .map(params -> (CsParameters) params);
+    }
+
+    /** @return A map between technologies and their corresponding generic parameters object. */
+    public @NonNull EnumMap<RangingTechnology, TechnologyParameters> asMap() {
+        return mParameters.clone();
+    }
+
+    public static class Builder {
+        private final DeviceRole mRole;
+        private UwbParameters mUwbParameters = null;
+        private CsParameters mCsParameters = null;
+
+        /**
+         @param role of the device within the session.
+         */
+        public Builder(DeviceRole role) {
+            mRole = role;
+        }
+
+        /** Build the {@link RangingParameters object} */
+        public RangingParameters build() {
+            return new RangingParameters(this);
+        }
+
+        /**
+         * Range with UWB in this session.
+         * @param uwbParameters containing a configuration for UWB ranging.
+         */
+        public Builder useUwb(@NonNull UwbParameters uwbParameters) {
+            mUwbParameters = uwbParameters;
+            return this;
+        }
+
+        /**
+         * Range with Bluetooth Channel Sounding in this session.
+         * @param csParameters containing a configuration for CS ranging.
+         */
+        public Builder useCs(@NonNull CsParameters csParameters) {
+            mCsParameters = csParameters;
+            return this;
+        }
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/RangingSession.java b/generic_ranging/src/com/android/ranging/RangingSession.java
new file mode 100644
index 00000000..2678a0d8
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/RangingSession.java
@@ -0,0 +1,116 @@
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
+package com.android.ranging;
+
+import android.os.RemoteException;
+
+import androidx.annotation.IntDef;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.ranging.uwb.backend.internal.RangingCapabilities;
+import com.android.ranging.uwb.backend.internal.UwbAddress;
+
+import com.google.common.util.concurrent.ListenableFuture;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.EnumMap;
+
+/** A multi-technology ranging session in the Android generic ranging service */
+public interface RangingSession {
+
+    /** Starts ranging with all technologies specified, providing results via the given callback. */
+    void start(@NonNull RangingParameters parameters, @NonNull Callback callback);
+
+    /** Stops ranging. */
+    void stop();
+
+    /**
+     * Returns a map that describes the {@link TechnologyStatus} of every {@link RangingTechnology}
+     */
+    ListenableFuture<EnumMap<RangingTechnology, Integer>> getTechnologyStatus();
+
+    /** Returns UWB capabilities if UWB was requested. */
+    ListenableFuture<RangingCapabilities> getUwbCapabilities();
+
+    /** Returns UWB address if UWB was requested. */
+    ListenableFuture<UwbAddress> getUwbAddress() throws RemoteException;
+
+    /** Returns CS capabilities if CS was requested. */
+    void getCsCapabilities();
+
+    /** State of an individual {@link RangingTechnology}. */
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef({
+            /* Ranging technology is not part of this session. */
+            TechnologyStatus.UNUSED,
+            /* Ranging technology is disabled due to a device condition or user switch. */
+            TechnologyStatus.DISABLED,
+            /* Ranging technology is enabled. */
+            TechnologyStatus.ENABLED,
+    })
+    @interface TechnologyStatus {
+        int UNUSED = 0;
+        int DISABLED = 1;
+        int ENABLED = 2;
+    }
+
+    /** Callback for {@link RangingSession} events. */
+    interface Callback {
+        /**
+         * Callback method for reporting when ranging has started for a particular technology or
+         * for the entire session.
+         * @param technology that was started, or {@code null} to indicate that the entire session
+         *                   has started.
+         */
+        void onStarted(@Nullable RangingTechnology technology);
+
+        /**
+         * Callback method for reporting when ranging has stopped for a particular technology or for
+         * @param technology that was stopped, or {@code null} to indicate that the entire session
+         *                   has stopped.
+         * @param reason why the technology or session was stopped.
+         */
+        void onStopped(@Nullable RangingTechnology technology, @StoppedReason int reason);
+
+        /**
+         * Callback for reporting ranging data.
+         * @param data to be reported.
+         */
+        void onData(@NonNull RangingData data);
+
+        /** Reason why ranging was stopped. */
+        @Retention(RetentionPolicy.SOURCE)
+        @IntDef({
+                RangingAdapter.Callback.StoppedReason.UNKNOWN,
+                RangingAdapter.Callback.StoppedReason.FAILED_TO_START,
+                RangingAdapter.Callback.StoppedReason.REQUESTED,
+                RangingAdapter.Callback.StoppedReason.LOST_CONNECTION,
+                RangingAdapter.Callback.StoppedReason.SYSTEM_POLICY,
+                RangingAdapter.Callback.StoppedReason.ERROR,
+                StoppedReason.NO_INITIAL_DATA_TIMEOUT,
+                StoppedReason.NO_UPDATED_DATA_TIMEOUT,
+        })
+        @interface StoppedReason {
+            /** The session failed to report data before the initial data timeout expired. */
+            int NO_INITIAL_DATA_TIMEOUT = 6;
+            /** The session had no new data to report before the data update timeout expired. */
+            int NO_UPDATED_DATA_TIMEOUT = 7;
+        }
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/RangingSessionImpl.java b/generic_ranging/src/com/android/ranging/RangingSessionImpl.java
new file mode 100644
index 00000000..9534c80d
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/RangingSessionImpl.java
@@ -0,0 +1,360 @@
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
+package com.android.ranging;
+
+import static com.google.common.util.concurrent.Futures.immediateFailedFuture;
+
+import android.content.Context;
+import android.os.RemoteException;
+import android.util.Log;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.ranging.RangingParameters.DeviceRole;
+import com.android.ranging.RangingUtils.StateMachine;
+import com.android.ranging.cs.CsAdapter;
+import com.android.ranging.fusion.FusionEngine;
+import com.android.ranging.uwb.UwbAdapter;
+import com.android.ranging.uwb.backend.internal.RangingCapabilities;
+import com.android.ranging.uwb.backend.internal.UwbAddress;
+
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.errorprone.annotations.DoNotCall;
+
+import java.time.Duration;
+import java.util.Collections;
+import java.util.EnumMap;
+import java.util.List;
+import java.util.Map;
+import java.util.concurrent.ScheduledExecutorService;
+import java.util.concurrent.ScheduledFuture;
+import java.util.concurrent.TimeUnit;
+import java.util.stream.Collectors;
+
+/**  Implementation of the Android multi-technology ranging layer */
+public final class RangingSessionImpl implements RangingSession {
+
+    private static final String TAG = RangingSessionImpl.class.getSimpleName();
+
+    private final Context mContext;
+    private final RangingConfig mConfig;
+
+    /** Callback for session events. Invariant: Non-null while a session is ongoing. */
+    private RangingSession.Callback mCallback;
+
+    /** Keeps track of state of the ranging session. <b>Must be synchronized.</b> */
+    private final StateMachine<State> mStateMachine;
+
+    /**
+     * Ranging adapters used for this session. <b>Must be synchronized</b>.
+     * {@code mStateMachine} lock must be acquired first if mutual synchronization is necessary.
+     */
+    private final Map<RangingTechnology, RangingAdapter> mAdapters;
+
+    /** Fusion engine to use for this session. */
+    private final FusionEngine mFusionEngine;
+
+    /** Executor for ranging technology adapters. */
+    private final ListeningExecutorService mAdapterExecutor;
+
+    /** Executor for session timeout handlers. */
+    private final ScheduledExecutorService mTimeoutExecutor;
+
+    /** Future that stops the session due to a timeout. */
+    private ScheduledFuture<?> mPendingTimeout;
+
+    public RangingSessionImpl(
+            @NonNull Context context,
+            @NonNull RangingConfig config,
+            @NonNull FusionEngine fusionEngine,
+            @NonNull ScheduledExecutorService timeoutExecutor,
+            @NonNull ListeningExecutorService rangingAdapterExecutor
+    ) {
+        mContext = context;
+        mConfig = config;
+
+        mStateMachine = new StateMachine<>(State.STOPPED);
+        mCallback = null;
+
+        mAdapters = Collections.synchronizedMap(new EnumMap<>(RangingTechnology.class));
+        mFusionEngine = fusionEngine;
+
+        mTimeoutExecutor = timeoutExecutor;
+        mAdapterExecutor = rangingAdapterExecutor;
+
+        mPendingTimeout = null;
+    }
+
+    private @NonNull RangingAdapter newAdapter(
+            @NonNull RangingTechnology technology, DeviceRole role
+    ) {
+        switch (technology) {
+            case UWB:
+                return new UwbAdapter(mContext, mAdapterExecutor, role);
+            case CS:
+                return new CsAdapter();
+            default:
+                throw new IllegalArgumentException(
+                        "Tried to create adapter for unknown technology" + technology);
+        }
+    }
+
+    @Override
+    public void start(@NonNull RangingParameters parameters, @NonNull Callback callback) {
+        EnumMap<RangingTechnology, RangingParameters.TechnologyParameters> paramsMap =
+                parameters.asMap();
+        mAdapters.keySet().retainAll(paramsMap.keySet());
+
+        Log.i(TAG, "Start Precision Ranging called.");
+        if (!mStateMachine.transition(State.STOPPED, State.STARTING)) {
+            Log.w(TAG, "Failed transition STOPPED -> STARTING");
+            return;
+        }
+        mCallback = callback;
+
+        for (RangingTechnology technology : paramsMap.keySet()) {
+            if (!technology.isSupported(mContext)) {
+                Log.w(TAG, "Attempted to range with unsupported technology " + technology
+                        + ", skipping");
+                continue;
+            }
+
+            synchronized (mAdapters) {
+                // Do not overwrite any adapters that were supplied for testing
+                if (!mAdapters.containsKey(technology)) {
+                    mAdapters.put(technology, newAdapter(technology, parameters.getRole()));
+                }
+
+                mAdapters.get(technology).start(paramsMap.get(technology),
+                        new AdapterListener(technology));
+            }
+        }
+
+        mFusionEngine.start(new FusionEngineListener());
+        scheduleTimeout(mConfig.getInitTimeout(), Callback.StoppedReason.NO_INITIAL_DATA_TIMEOUT);
+    }
+
+    @Override
+    public void stop() {
+        stopForReason(RangingAdapter.Callback.StoppedReason.REQUESTED);
+    }
+
+    /**
+     * Stop all ranging adapters and reset internal state.
+     * @param reason why the session was stopped.
+     */
+    private void stopForReason(@Callback.StoppedReason int reason) {
+        Log.i(TAG, "stopPrecisionRanging with reason: " + reason);
+        synchronized (mStateMachine) {
+            if (mStateMachine.getState() == State.STOPPED) {
+                Log.v(TAG, "Ranging already stopped, skipping");
+                return;
+            }
+            mStateMachine.setState(State.STOPPED);
+
+            // Stop all ranging technologies.
+            synchronized (mAdapters) {
+                for (RangingTechnology technology : mAdapters.keySet()) {
+                    mAdapters.get(technology).stop();
+                    mCallback.onStopped(technology, reason);
+                }
+            }
+
+            // Reset internal state.
+            mFusionEngine.stop();
+            mAdapters.clear();
+            mCallback.onStopped(null, reason);
+            mCallback = null;
+        }
+    }
+
+    @Override
+    public ListenableFuture<RangingCapabilities> getUwbCapabilities() {
+        if (!mAdapters.containsKey(RangingTechnology.UWB)) {
+            return immediateFailedFuture(
+                    new IllegalStateException("UWB was not requested for this session."));
+        }
+        UwbAdapter uwbAdapter = (UwbAdapter) mAdapters.get(RangingTechnology.UWB);
+        try {
+            return uwbAdapter.getCapabilities();
+        } catch (RemoteException e) {
+            Log.e(TAG, "Failed to get Uwb capabilities");
+            return null;
+        }
+    }
+
+    @Override
+    public ListenableFuture<UwbAddress> getUwbAddress() throws RemoteException {
+        if (!mAdapters.containsKey(RangingTechnology.UWB)) {
+            return immediateFailedFuture(
+                    new IllegalStateException("UWB was not requested for this session."));
+        }
+        UwbAdapter uwbAdapter = (UwbAdapter) mAdapters.get(RangingTechnology.UWB);
+        return uwbAdapter.getLocalAddress();
+    }
+
+    @DoNotCall("Not implemented")
+    @Override
+    public void getCsCapabilities() {
+        throw new UnsupportedOperationException("Not implemented");
+    }
+
+    @Override
+    public ListenableFuture<EnumMap<RangingTechnology, Integer>> getTechnologyStatus() {
+        // Combine all isEnabled futures for each technology into a single future. The resulting
+        // future contains a list of technologies grouped with their corresponding
+        // enabled state.
+        ListenableFuture<List<Map.Entry<RangingTechnology, Boolean>>> enabledStatesFuture;
+        synchronized (mAdapters) {
+            enabledStatesFuture = Futures.allAsList(mAdapters.entrySet().stream()
+                    .map((var entry) -> Futures.transform(
+                            entry.getValue().isEnabled(),
+                            (Boolean isEnabled) -> Map.entry(entry.getKey(), isEnabled),
+                            mAdapterExecutor)
+                    )
+                    .collect(Collectors.toList())
+            );
+        }
+
+        // Transform the list of enabled states into a technology status map.
+        return Futures.transform(
+                enabledStatesFuture,
+                (List<Map.Entry<RangingTechnology, Boolean>> enabledStates) -> {
+                    EnumMap<RangingTechnology, Integer> statuses =
+                            new EnumMap<>(RangingTechnology.class);
+                    for (RangingTechnology technology : RangingTechnology.values()) {
+                        statuses.put(technology, TechnologyStatus.UNUSED);
+                    }
+
+                    for (Map.Entry<RangingTechnology, Boolean> enabledState : enabledStates) {
+                        RangingTechnology technology = enabledState.getKey();
+                        if (enabledState.getValue()) {
+                            statuses.put(technology, TechnologyStatus.ENABLED);
+                        } else {
+                            statuses.put(technology, TechnologyStatus.DISABLED);
+                        }
+                    }
+                    return statuses;
+                },
+                mAdapterExecutor
+        );
+    }
+
+    /* If there is a pending timeout, cancel it. */
+    private synchronized void cancelScheduledTimeout() {
+        if (mPendingTimeout != null) {
+            mPendingTimeout.cancel(false);
+            mPendingTimeout = null;
+        }
+    }
+
+    /**
+     * Schedule a future that stops the session.
+     *
+     * @param timeout after which the session should be stopped.
+     * @param reason  for stopping the session.
+     */
+    private synchronized void scheduleTimeout(
+            @NonNull Duration timeout, @Callback.StoppedReason int reason
+    ) {
+        cancelScheduledTimeout();
+        mPendingTimeout = mTimeoutExecutor.schedule(
+                () -> {
+                    Log.w(TAG, "Reached scheduled timeout of " + timeout.toMillis());
+                    stopForReason(reason);
+                },
+                mConfig.getNoUpdateTimeout().toMillis(), TimeUnit.MILLISECONDS
+        );
+    }
+
+    /* Listener implementation for ranging adapter callback. */
+    private class AdapterListener implements RangingAdapter.Callback {
+        private final RangingTechnology mTechnology;
+
+        AdapterListener(RangingTechnology technology) {
+            this.mTechnology = technology;
+        }
+
+        @Override
+        public void onStarted() {
+            synchronized (mStateMachine) {
+                if (mStateMachine.getState() == State.STOPPED) {
+                    Log.w(TAG, "Received adapter onStarted but ranging session is stopped");
+                    return;
+                }
+                mFusionEngine.addDataSource(mTechnology);
+                mCallback.onStarted(mTechnology);
+            }
+        }
+
+        @Override
+        public void onStopped(@RangingAdapter.Callback.StoppedReason int reason) {
+            synchronized (mStateMachine) {
+                if (mStateMachine.getState() != State.STOPPED) {
+                    mAdapters.remove(mTechnology);
+                    mFusionEngine.removeDataSource(mTechnology);
+                    mCallback.onStopped(mTechnology, reason);
+                }
+            }
+        }
+
+        @Override
+        public void onRangingData(RangingData data) {
+            synchronized (mStateMachine) {
+                if (mStateMachine.getState() != State.STOPPED) {
+                    mFusionEngine.feed(data);
+                }
+            }
+        }
+    }
+
+    /* Listener implementation for fusion engine callback. */
+    private class FusionEngineListener implements FusionEngine.Callback {
+
+        @Override
+        public void onData(@NonNull RangingData data) {
+            synchronized (mStateMachine) {
+                if (mStateMachine.getState() == State.STOPPED) {
+                    return;
+                }
+                cancelScheduledTimeout();
+                if (mStateMachine.transition(State.STARTING, State.STARTED)) {
+                    // This is the first ranging data instance reported by the session, so start it.
+                    mCallback.onStarted(null);
+                }
+                mCallback.onData(data);
+                scheduleTimeout(
+                        mConfig.getNoUpdateTimeout(),
+                        Callback.StoppedReason.NO_UPDATED_DATA_TIMEOUT);
+            }
+        }
+    }
+
+    @VisibleForTesting
+    public void useAdapterForTesting(RangingTechnology technology, RangingAdapter adapter) {
+        mAdapters.put(technology, adapter);
+    }
+
+    private enum State {
+        STARTING,
+        STARTED,
+        STOPPED,
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/generic/RangingTechnology.java b/generic_ranging/src/com/android/ranging/RangingTechnology.java
similarity index 76%
rename from generic_ranging/src/com/android/ranging/generic/RangingTechnology.java
rename to generic_ranging/src/com/android/ranging/RangingTechnology.java
index c70c24ba..83b60649 100644
--- a/generic_ranging/src/com/android/ranging/generic/RangingTechnology.java
+++ b/generic_ranging/src/com/android/ranging/RangingTechnology.java
@@ -14,7 +14,12 @@
  * limitations under the License.
  */
 
-package com.android.ranging.generic;
+package com.android.ranging;
+
+import android.content.Context;
+
+import com.android.ranging.cs.CsAdapter;
+import com.android.ranging.uwb.UwbAdapter;
 
 import com.google.common.collect.ImmutableList;
 
@@ -40,6 +45,21 @@ public enum RangingTechnology {
         return (byte) (1 << value);
     }
 
+    /**
+     * Check whether this technology is available given the provided context.
+     * @return true if the technology is supported, false otherwise.
+     */
+    public boolean isSupported(Context context) {
+        switch (this) {
+            case UWB:
+                return UwbAdapter.isSupported(context);
+            case CS:
+                return CsAdapter.isSupported(context);
+            default:
+                return false;
+        }
+    }
+
     public static ImmutableList<RangingTechnology> parseByte(byte technologiesByte) {
         BitSet bitset = BitSet.valueOf(new byte[]{technologiesByte});
         ImmutableList.Builder<RangingTechnology> technologies = ImmutableList.builder();
diff --git a/generic_ranging/src/com/android/ranging/RangingUtils.java b/generic_ranging/src/com/android/ranging/RangingUtils.java
new file mode 100644
index 00000000..de1568b8
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/RangingUtils.java
@@ -0,0 +1,70 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging;
+
+/**
+ * Utilities for {@link com.android.ranging}.
+ */
+public class RangingUtils {
+    /**
+     * A basic synchronized state machine.
+     * @param <E> enum representing the different states of the machine.
+     */
+    public static class StateMachine<E extends Enum<E>> {
+        private E mState;
+
+        public StateMachine(E start) {
+            mState = start;
+        }
+
+        /** Gets the current state */
+        public synchronized E getState() {
+            return mState;
+        }
+
+        /** Sets the current state */
+        public synchronized void setState(E state) {
+            mState = state;
+        }
+
+        /**
+         * Sets the current state.
+         * @return true if the state was successfully changed, false if the current state is
+         * already {@code state}.
+         */
+        public synchronized boolean changeStateTo(E state) {
+            if (mState == state) {
+                return false;
+            }
+            setState(state);
+            return true;
+        }
+
+        /**
+         * If the current state is {@code from}, sets it to {@code to}.
+         * @return true if the current state is {@code from}, false otherwise.
+         */
+        public synchronized boolean transition(E from, E to) {
+            if (mState != from) {
+                return false;
+            }
+            mState = to;
+            return true;
+        }
+    }
+
+}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/CsAdapter.java b/generic_ranging/src/com/android/ranging/cs/CsAdapter.java
similarity index 65%
rename from generic_ranging/src/com/android/ranging/generic/ranging/CsAdapter.java
rename to generic_ranging/src/com/android/ranging/cs/CsAdapter.java
index 2b50e810..24bad90e 100644
--- a/generic_ranging/src/com/android/ranging/generic/ranging/CsAdapter.java
+++ b/generic_ranging/src/com/android/ranging/cs/CsAdapter.java
@@ -14,34 +14,40 @@
  * limitations under the License.
  */
 
-package com.android.ranging.generic.ranging;
+package com.android.ranging.cs;
 
-import static com.google.common.util.concurrent.Futures.immediateFuture;
+import android.content.Context;
 
-import com.android.ranging.generic.RangingTechnology;
+import com.android.ranging.RangingAdapter;
+import com.android.ranging.RangingParameters.TechnologyParameters;
+import com.android.ranging.RangingTechnology;
 
+import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
 
 /** Channel Sounding adapter for ranging. */
-class CsAdapter implements RangingAdapter {
+public class CsAdapter implements RangingAdapter {
 
-    @Override
-    public RangingTechnology getType() {
-        return RangingTechnology.CS;
+    public static boolean isSupported(Context context) {
+        return false;
+    }
+
+    public CsAdapter() {
+        throw new UnsupportedOperationException("Not implemented.");
     }
 
     @Override
-    public boolean isPresent() {
-        return false;
+    public RangingTechnology getType() {
+        return RangingTechnology.CS;
     }
 
     @Override
     public ListenableFuture<Boolean> isEnabled() {
-        return immediateFuture(false);
+        return Futures.immediateFuture(false);
     }
 
     @Override
-    public void start(Callback callback) {
+    public void start(TechnologyParameters parameters, Callback callback) {
         throw new UnsupportedOperationException("Not implemented.");
     }
 
@@ -49,4 +55,4 @@ class CsAdapter implements RangingAdapter {
     public void stop() {
         throw new UnsupportedOperationException("Not implemented.");
     }
-}
\ No newline at end of file
+}
diff --git a/generic_ranging/src/com/android/ranging/cs/CsParameters.java b/generic_ranging/src/com/android/ranging/cs/CsParameters.java
new file mode 100644
index 00000000..4973e49b
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/cs/CsParameters.java
@@ -0,0 +1,27 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.cs;
+
+import com.android.ranging.RangingParameters;
+
+/** Parameters for Bluetooth channel sounding ranging. */
+public class CsParameters implements RangingParameters.TechnologyParameters {
+    public CsParameters() {
+        throw new UnsupportedOperationException("Not implemented!");
+    }
+}
+
diff --git a/generic_ranging/src/com/android/ranging/fusion/DataFusers.java b/generic_ranging/src/com/android/ranging/fusion/DataFusers.java
new file mode 100644
index 00000000..1d67b84c
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/fusion/DataFusers.java
@@ -0,0 +1,76 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.fusion;
+
+import androidx.annotation.NonNull;
+
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingTechnology;
+
+import java.util.Optional;
+import java.util.Set;
+
+public class DataFusers {
+    /**
+     * A data fuser that passes through all provided data as fused data.
+     */
+    public static class PassthroughDataFuser implements FusionEngine.DataFuser {
+
+        @Override
+        public Optional<RangingData> fuse(
+                @NonNull RangingData data, final @NonNull Set<RangingTechnology> sources
+        ) {
+            return Optional.of(data);
+        }
+    }
+
+    /**
+     * A data fuser that prefers a particular technology according to the following rules:
+     * <ul>
+     *     <li> If the preferred technology is active, all data it produces is produced by the
+     *     engine. All data from any other technology is ignored.
+     *     <li> If the preferred technology is inactive, report all data received from any
+     *     technology.
+     * </ul>
+     */
+    public static class PreferentialDataFuser implements FusionEngine.DataFuser {
+        private final RangingTechnology mPreferred;
+
+        /**
+         * @param preferred technology. Data from other technologies will be ignored while this one
+         *                  is active.
+         */
+        public PreferentialDataFuser(@NonNull RangingTechnology preferred) {
+            mPreferred = preferred;
+        }
+
+        @Override
+        public Optional<RangingData> fuse(
+                @NonNull RangingData data, final @NonNull Set<RangingTechnology> sources
+        ) {
+            if (sources.contains(mPreferred)) {
+                if (data.getTechnology().isPresent() && mPreferred == data.getTechnology().get()) {
+                    return Optional.of(data);
+                } else {
+                    return Optional.empty();
+                }
+            } else {
+                return Optional.of(data);
+            }
+        }
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/fusion/FilteringFusionEngine.java b/generic_ranging/src/com/android/ranging/fusion/FilteringFusionEngine.java
new file mode 100644
index 00000000..7055601f
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/fusion/FilteringFusionEngine.java
@@ -0,0 +1,118 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.fusion;
+
+import androidx.annotation.NonNull;
+
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingTechnology;
+import com.android.uwb.fusion.UwbFilterEngine;
+import com.android.uwb.fusion.math.SphericalVector;
+
+import java.util.EnumMap;
+import java.util.Set;
+
+/**
+ * A fusion engine that filters and corrects data from each technology before fusing it.
+ */
+public class FilteringFusionEngine extends FusionEngine {
+
+    private static final String TAG = FilteringFusionEngine.class.getSimpleName();
+
+    private final EnumMap<RangingTechnology, UwbFilterEngine> mFilters;
+
+    public FilteringFusionEngine(@NonNull DataFuser fuser) {
+        super(fuser);
+        mFilters = new EnumMap<>(RangingTechnology.class);
+    }
+
+    /**
+     * Construct a filter engine configured for the provided technology.
+     */
+    private @NonNull UwbFilterEngine newFilter(@NonNull RangingTechnology unused) {
+        // TODO(365631954): Build a properly configured filter depending on the technology.
+        return new UwbFilterEngine.Builder().build();
+    }
+
+    @Override
+    public void start(@NonNull Callback callback) {
+        super.start(callback);
+    }
+
+    @Override
+    public void stop() {
+        for (UwbFilterEngine filter : mFilters.values()) {
+            filter.close();
+        }
+        mFilters.clear();
+    }
+
+    @Override
+    public void feed(@NonNull RangingData data) {
+        if (data.getTechnology().isEmpty()) {
+            return;
+        }
+
+        SphericalVector.Annotated in = SphericalVector.fromRadians(
+                (float) data.getAzimuthRadians().orElse(0.0),
+                (float) data.getElevationRadians().orElse(0.0),
+                (float) data.getRangeMeters()
+        ).toAnnotated(
+                data.getAzimuthRadians().isPresent(),
+                data.getElevationRadians().isPresent(),
+                true
+        );
+
+        UwbFilterEngine engine = mFilters.get(data.getTechnology().get());
+        engine.add(in, data.getTimestamp().toMillis());
+        SphericalVector.Annotated out = engine.compute(data.getTimestamp().toMillis());
+        if (out == null) {
+            return;
+        }
+
+        RangingData.Builder filteredData = RangingData.Builder.fromBuilt(data);
+        filteredData.setRangeDistance(out.distance);
+        if (data.getAzimuthRadians().isPresent()) {
+            filteredData.setAzimuthRadians(out.azimuth);
+        }
+        if (data.getElevationRadians().isPresent()) {
+            filteredData.setElevationRadians(out.elevation);
+        }
+
+        super.feed(filteredData.build());
+    }
+
+    @Override
+    protected @NonNull Set<RangingTechnology> getDataSources() {
+        return mFilters.keySet();
+    }
+
+    @Override
+    public void addDataSource(@NonNull RangingTechnology technology) {
+        if (!mFilters.containsKey(technology)) {
+            mFilters.put(technology, newFilter(technology));
+        }
+    }
+
+    @Override
+    public void removeDataSource(@NonNull RangingTechnology technology) {
+        UwbFilterEngine removed = mFilters.remove(technology);
+        if (removed != null) {
+            removed.close();
+        }
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/fusion/FusionEngine.java b/generic_ranging/src/com/android/ranging/fusion/FusionEngine.java
new file mode 100644
index 00000000..6753a54c
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/fusion/FusionEngine.java
@@ -0,0 +1,117 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.fusion;
+
+import androidx.annotation.NonNull;
+
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingTechnology;
+
+import java.util.Optional;
+import java.util.Set;
+
+/**
+ * Enhances and combines raw data from multiple ranging technologies and/or on-device sensors to
+ * produce more accurate distance measurements.
+ */
+public abstract class FusionEngine {
+    /**
+     * Incrementally combines data from multiple ranging technologies.
+     */
+    public interface DataFuser {
+        /**
+         * Provide data to the fuser.
+         *
+         * @param data    produced from a ranging technology.
+         * @param sources of ranging data. <b>Implementations of this method must not mutate this
+         *                parameter.</b>
+         * @return fused data if the provided data makes any available.
+         */
+        Optional<RangingData> fuse(
+                @NonNull RangingData data, final @NonNull Set<RangingTechnology> sources
+        );
+    }
+
+    /**
+     * Callbacks to notify on fusion events.
+     */
+    public interface Callback {
+        /**
+         * Called when the engine produces fused data.
+         *
+         * @param data produced by the engine.
+         */
+        void onData(@NonNull RangingData data);
+    }
+
+    protected final DataFuser mFuser;
+    protected Callback mCallback;
+
+    /**
+     * Construct the fusion engine.
+     *
+     * @param fuser to use on data provided to this engine.
+     */
+    protected FusionEngine(@NonNull DataFuser fuser) {
+        mFuser = fuser;
+        mCallback = null;
+    }
+
+    /**
+     * Start the fusion engine.
+     *
+     * @param callback to notify on engine events.
+     */
+    public void start(@NonNull Callback callback) {
+        mCallback = callback;
+    }
+
+    /**
+     * Stop the fusion engine.
+     */
+    public abstract void stop();
+
+    /**
+     * Feed data to the engine.
+     *
+     * @param data produced from a ranging technology.
+     */
+    public void feed(@NonNull RangingData data) {
+        if (mCallback != null) {
+            mFuser.fuse(data, getDataSources()).ifPresent(mCallback::onData);
+        }
+    }
+
+    /**
+     * @return the current set of data sources to the fusion engine.
+     */
+    protected abstract @NonNull Set<RangingTechnology> getDataSources();
+
+    /**
+     * Add a technology as a source of data to the engine.
+     *
+     * @param technology to add.
+     */
+    public abstract void addDataSource(@NonNull RangingTechnology technology);
+
+    /**
+     * Remove a technology as a source of data to the engine.
+     *
+     * @param technology to remove.
+     */
+    public abstract void removeDataSource(@NonNull RangingTechnology technology);
+}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/FusionData.java b/generic_ranging/src/com/android/ranging/generic/ranging/FusionData.java
deleted file mode 100644
index e4133d45..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/FusionData.java
+++ /dev/null
@@ -1,122 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import com.android.sensor.Estimate;
-import com.android.sensor.Status;
-
-import com.google.auto.value.AutoValue;
-
-/**
- * Fusion data represents a fusion of data received from ranging technologies and data received from
- * other sensors such as ArCore and IMU.
- */
-@AutoValue
-public abstract class FusionData {
-
-    /** Returns distance result from fusion in meters. */
-    public abstract double getFusionRange();
-
-    /** Returns standard dev error for distance range. */
-    public abstract double getFusionRangeErrorStdDev();
-
-    /**
-     * Returns the std dev of the error in the estimate of the beacon's position relative to the
-     * user.
-     */
-    public abstract double getFusionEstimatedBeaconPositionErrorStdDevM();
-
-    /** Returns bearing result from fusion in radians. */
-    public abstract double getFusionBearing();
-
-    /** Returns standard dev error for bearing. */
-    public abstract double getFusionBearingErrorStdDev();
-
-    /** Returns the state of ArCore. */
-    public abstract ArCoreState getArCoreState();
-
-    /** Returns a builder for {@link FusionData}. */
-    public static Builder builder() {
-        return new AutoValue_FusionData.Builder();
-    }
-
-    /** Builder for {@link FusionData}. */
-    @AutoValue.Builder
-    public abstract static class Builder {
-        public abstract Builder setFusionRange(double value);
-
-        public abstract Builder setFusionRangeErrorStdDev(double value);
-
-        public abstract Builder setFusionBearing(double value);
-
-        public abstract Builder setFusionBearingErrorStdDev(double value);
-
-        public abstract Builder setFusionEstimatedBeaconPositionErrorStdDevM(double value);
-
-        public abstract Builder setArCoreState(ArCoreState arCoreState);
-
-        public abstract FusionData build();
-    }
-
-    public static FusionData fromFusionAlgorithmEstimate(Estimate estimate) {
-        return FusionData.builder()
-                .setFusionRange(estimate.getRangeM())
-                .setFusionRangeErrorStdDev(estimate.getRangeErrorStdDevM())
-                .setFusionBearing(estimate.getBearingRad())
-                .setFusionBearingErrorStdDev(estimate.getBearingErrorStdDevRad())
-                .setArCoreState(convertToArCoreStateFromStatus(estimate.getStatus()))
-                .setFusionEstimatedBeaconPositionErrorStdDevM(
-                        estimate.getEstimatedBeaconPositionErrorStdDevM())
-                .build();
-    }
-
-    private static ArCoreState convertToArCoreStateFromStatus(Status status) {
-        switch (status) {
-            case OK:
-                return ArCoreState.OK;
-            case RECOVERING_FROM_FAILURE_DUE_TO_INSUFFICIENT_LIGHT:
-                return ArCoreState.POOR_LIGHTNING;
-            case RECOVERING_FROM_FAILURE_DUE_TO_EXCESSIVE_MOTION:
-                return ArCoreState.EXCESSIVE_MOTION;
-            case RECOVERING_FROM_FAILURE_DUE_TO_INSUFFICIENT_FEATURES:
-                return ArCoreState.INSUFFICIENT_FEATURES;
-            case RECOVERING_FROM_FAILURE_DUE_TO_CAMERA_UNAVAILABILITY:
-                return ArCoreState.CAMERA_UNAVAILABLE;
-            case ESTIMATE_NOT_AVAILABLE:
-            case RECOVERING:
-            case RECOVERING_FROM_FAILURE_DUE_TO_BAD_ODOMETRY_STATE:
-            case ODOMETRY_ERROR:
-            case BEACON_MOVING_ERROR:
-            case CONFIGURATION_ERROR:
-            case SENSOR_PERMISSION_DENIED_ERROR:
-            case UNKNOWN_ERROR:
-                return ArCoreState.BAD_STATE;
-        }
-        return ArCoreState.BAD_STATE;
-    }
-
-    /** State of ArCore */
-    public enum ArCoreState {
-        OK,
-        BAD_STATE,
-        POOR_LIGHTNING,
-        EXCESSIVE_MOTION,
-        INSUFFICIENT_FEATURES,
-        CAMERA_UNAVAILABLE,
-        NOT_ENABLED
-    }
-}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionData.java b/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionData.java
deleted file mode 100644
index 7deccd2c..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionData.java
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import com.google.auto.value.AutoValue;
-import com.google.common.collect.ImmutableList;
-
-import java.util.Optional;
-
-/**
- * Precision data represents both data received from ranging technologies and data from the fusion
- * algorithm.
- */
-@AutoValue
-public abstract class PrecisionData {
-
-    /** Returns a list of {@link RangingData} for different ranging technologies if present. */
-    public abstract Optional<ImmutableList<RangingData>> getRangingData();
-
-    /** Returns {@link FusionData} if present. */
-    public abstract Optional<FusionData> getFusionData();
-
-    /** Returns the timestamp for this data. */
-    public abstract long getTimestamp();
-
-    /** Returns a builder for {@link RangingData}. */
-    public static Builder builder() {
-        return new AutoValue_PrecisionData.Builder();
-    }
-
-    /** Builder for {@link RangingData}. */
-    @AutoValue.Builder
-    public abstract static class Builder {
-        public abstract Builder setRangingData(ImmutableList<RangingData> rangingData);
-
-        public abstract Builder setFusionData(FusionData fusionData);
-
-        public abstract Builder setTimestamp(long timestamp);
-
-        public abstract PrecisionData build();
-    }
-}
\ No newline at end of file
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRanging.java b/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRanging.java
deleted file mode 100644
index 20823da1..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRanging.java
+++ /dev/null
@@ -1,133 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import android.os.RemoteException;
-
-import androidx.annotation.IntDef;
-import androidx.core.uwb.backend.impl.internal.RangingCapabilities;
-import androidx.core.uwb.backend.impl.internal.RangingParameters;
-import androidx.core.uwb.backend.impl.internal.UwbAddress;
-import androidx.core.uwb.backend.impl.internal.UwbComplexChannel;
-
-import com.android.ranging.generic.RangingTechnology;
-
-import com.google.common.collect.ImmutableMap;
-import com.google.common.util.concurrent.ListenableFuture;
-
-import java.lang.annotation.Retention;
-import java.lang.annotation.RetentionPolicy;
-
-/**
- * PrecisionRanging provides an API for ranging with multiple ranging technologies such as
- * Ultra-Wide Band (UWB) and Channel Sounding (CS), and fusing the ranging data with additional
- * sensor data such as IMU and ArCore.
- */
-public interface PrecisionRanging {
-
-    /**
-     * Creates a new instance of {@link PrecisionRanging}. Ranging technologies that will be used
-     * are
-     * set through the configuration. Each ranging technology that's used may require additional
-     * setup
-     * through set*RangingTech*Config before start can be called.
-     */
-    interface Factory {
-        PrecisionRanging create(PrecisionRangingConfig config);
-    }
-
-    /** Starts precision ranging, results are provided via the given callback. */
-    void start(Callback callback);
-
-    /** Stops precision ranging. */
-    void stop();
-
-    /**
-     * Returns a map that describes the {@link RangingTechnologyAvailability} for each requested
-     * {@link RangingTechnology} for this session. {@link RangingTechnologyAvailability} is either
-     * NOT_SUPPORTED when the hardware or software doesn't support the technology, DISABLED when
-     * it's
-     * disabled due to a condition or a user switch, or ENABLED when it's available to use.
-     */
-    ListenableFuture<ImmutableMap<RangingTechnology, Integer>> rangingTechnologiesAvailability()
-            throws RemoteException;
-
-    /** Returns UWB capabilities if UWB was requested. */
-    ListenableFuture<RangingCapabilities> getUwbCapabilities();
-
-    /** Returns UWB address if UWB was requested. */
-    ListenableFuture<UwbAddress> getUwbAddress() throws RemoteException;
-
-    /** Sets UWB configuration. No op if UWB was not requested. */
-    void setUwbConfig(RangingParameters rangingParameters);
-
-    /** Get the Uwb complex channel for the controller. */
-    ListenableFuture<UwbComplexChannel> getUwbComplexChannel() throws RemoteException;
-
-    /** Returns CS capabilities if CS was requested. */
-    void getCsCapabilities();
-
-    /** Sets CS configuration. No op if CS was not requested. */
-    void setCsConfig();
-
-    /** State of an individual Ranging Technology on this device. */
-    @Retention(RetentionPolicy.SOURCE)
-    @IntDef({
-            /* Ranging technology is not supported on this device. */
-            RangingTechnologyAvailability.NOT_SUPPORTED,
-            /* Ranging technology is disabled. */
-            RangingTechnologyAvailability.DISABLED,
-            /* Ranging technology is enabled. */
-            RangingTechnologyAvailability.ENABLED,
-    })
-    @interface RangingTechnologyAvailability {
-        int NOT_SUPPORTED = 0;
-        int DISABLED = 1;
-        int ENABLED = 2;
-    }
-
-    /** Callback for {@link PrecisionRanging} operations. */
-    interface Callback {
-        /** Callback method for reporting when precision ranging has started. */
-        void onStarted();
-
-        /** Callback method for reporting when precision ranging has stopped. */
-        void onStopped(@StoppedReason int reason);
-
-        /** Callback for reporting precision data. */
-        void onData(PrecisionData data);
-
-        /** Reason why Precision Finding was stopped. */
-        @Retention(RetentionPolicy.SOURCE)
-        @IntDef({
-                /* Unexpected internal error. */
-                StoppedReason.INTERNAL_ERROR,
-                /* Stopped as a result of calling {@link #stop()}. */
-                StoppedReason.REQUESTED,
-                /* Stopped due to no ranging data received timeout. */
-                StoppedReason.NO_RANGES_TIMEOUT,
-                /* Exceeded drift timeout due to no incoming ranges. */
-                StoppedReason.FUSION_DRIFT_TIMEOUT,
-        })
-        @interface StoppedReason {
-            int INTERNAL_ERROR = 0;
-            int REQUESTED = 1;
-            int NO_RANGES_TIMEOUT = 2;
-            int FUSION_DRIFT_TIMEOUT = 3;
-        }
-    }
-}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRangingImpl.java b/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRangingImpl.java
deleted file mode 100644
index 45b9009b..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/PrecisionRangingImpl.java
+++ /dev/null
@@ -1,763 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import static com.google.common.util.concurrent.Futures.immediateFailedFuture;
-
-import static java.util.concurrent.TimeUnit.MILLISECONDS;
-
-import android.content.Context;
-import android.os.RemoteException;
-import android.util.Log;
-
-import androidx.annotation.VisibleForTesting;
-import androidx.core.uwb.backend.impl.internal.RangingCapabilities;
-import androidx.core.uwb.backend.impl.internal.RangingParameters;
-import androidx.core.uwb.backend.impl.internal.UwbAddress;
-import androidx.core.uwb.backend.impl.internal.UwbComplexChannel;
-
-import com.android.internal.annotations.GuardedBy;
-import com.android.ranging.generic.RangingTechnology;
-import com.android.sensor.Estimate;
-import com.android.sensor.MultiSensorFinderListener;
-
-import com.google.common.base.Preconditions;
-import com.google.common.collect.ImmutableList;
-import com.google.common.collect.ImmutableMap;
-import com.google.common.util.concurrent.Futures;
-import com.google.common.util.concurrent.ListenableFuture;
-import com.google.errorprone.annotations.DoNotCall;
-
-import dagger.Lazy;
-import dagger.assisted.Assisted;
-import dagger.assisted.AssistedFactory;
-import dagger.assisted.AssistedInject;
-
-import java.time.Instant;
-import java.util.ArrayList;
-import java.util.EnumSet;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-import java.util.Optional;
-import java.util.concurrent.ExecutorService;
-import java.util.concurrent.ScheduledExecutorService;
-
-/** Precision Ranging Implementation (Generic Ranging Layer). */
-public final class PrecisionRangingImpl implements PrecisionRanging {
-
-    private static final String TAG = PrecisionRangingImpl.class.getSimpleName();
-
-
-    /**
-     * Default frequency of the task running the periodic update when {@link
-     * PrecisionRangingConfig#getMaxUpdateInterval} is set to 0.
-     */
-    private static final long DEFAULT_INTERNAL_UPDATE_INTERVAL_MS = 100;
-
-    /**
-     * Frequency of the task running the periodic update calculated based on what {@link
-     * PrecisionRangingConfig#getMaxUpdateInterval} is set to, or default when {@link
-     * PrecisionRangingConfig#getMaxUpdateInterval} is 0.
-     */
-    private final long periodicUpdateIntervalMs;
-
-    private final Object lock = new Object();
-
-    /** Keeps the internal state of precision ranging (such as starting, active or stopped). */
-    @GuardedBy("lock")
-    private State internalState;
-
-    /** Keeps the state of each individual ranging adapter (such as starting, active or stopped). */
-    @GuardedBy("lock")
-    private final Map<RangingTechnology, State> rangingAdaptersStateMap;
-
-    private final ImmutableMap<RangingTechnology, RangingAdapter> rangingAdapters;
-    private final Map<RangingTechnology, RangingAdapter.Callback> rangingAdapterListeners;
-
-    /**
-     * Some of the ranging adapters need to be configured before being called. This list keeps track
-     * of all adapters that were configured so we can report an error to the caller if any of them
-     * were not.
-     */
-    private final EnumSet<RangingTechnology> rangingConfigurationsAdded;
-
-    private final Context context;
-    private final PrecisionRangingConfig config;
-    private Optional<PrecisionRanging.Callback> callback;
-
-    /**
-     * In this instance the primary fusion algorithm is the ArCoreMultiSensorFinder algorithm. In
-     * future we could create a common interface that a fusion algorithm should conform to and then
-     * make this generic so the caller can choose which fusion algorithm to use.
-     */
-//    private Optional<ArCoreMultiSensorFinder> fusionAlgorithm;
-//
-//    private Optional<MultiSensorFinderListener> fusionAlgorithmListener;
-
-    // TODO(b/331206299): Check after arcore is integrated.
-    //private final TimeSource timeSource;
-
-    /**
-     * The executor where periodic updater is executed. Periodic updater updates the caller with
-     * new
-     * data if available and stops precision ranging if stopping conditions are met. Periodic
-     * updater
-     * doesn't report new data if config.getMaxUpdateInterval is 0, in that case updates happen
-     * immediately after new data is received.
-     */
-    private final ScheduledExecutorService periodicUpdateExecutorService;
-
-    /**
-     * Executor service for running async tasks such as starting/stopping individual ranging
-     * adapters
-     * and fusion algorithm. Most of the results of running the tasks are received via listeners.
-     */
-    private final ExecutorService internalExecutorService;
-
-    @GuardedBy("lock")
-    private Optional<RangingData> lastUwbRangingDataResult;
-
-    @GuardedBy("lock")
-    private Optional<RangingData> lastCsRangingDataResult;
-
-    @GuardedBy("lock")
-    private Optional<FusionData> lastFusionDataResult;
-
-    /**
-     * Last update time is used to check if we should report new data via the callback if available.
-     * It's not used as a reason to stop precision ranging, last received times are used instead for
-     * that.
-     */
-    private Instant lastUpdateTime;
-
-    /**
-     * Start time is used to check if we're in a grace period right after starting so we don't stop
-     * precision ranging before giving it a chance to start producing data.
-     */
-    private Instant startTime;
-
-    /**
-     * Last Range data received is used to check if precision ranging should be stopped if we didn't
-     * receive any data for too long, or to check if we should stop due to "drifting" in case fusion
-     * algorithm is still reporting data, but we didn't feed any ranging data into for far too long.
-     */
-    private Instant lastRangeDataReceivedTime;
-
-    /**
-     * Last Fusion data received time is used to check if precision ranging should be stopped if we
-     * didn't receive any data for too long.
-     */
-    private Instant lastFusionDataReceivedTime;
-
-    /**
-     * This is used to check if stop is needed in case all ranging adapters are stopped. If we
-     * didn't
-     * previously receive any data from the fusion algorithm then we can stop safely since we know
-     * we
-     * won't be getting any useful results. Otherwise we don't stop immediately but after the drift
-     * timeout period.
-     */
-    private boolean seenSuccessfulFusionData;
-
-    /** Factory for creating {@link PrecisionRangingImpl}. */
-    @AssistedFactory
-    public interface Factory extends PrecisionRanging.Factory {
-        @Override
-        PrecisionRangingImpl create(PrecisionRangingConfig config);
-    }
-
-    /**
-     * Constructs Precision Ranging. Additional setup might be needed depending on the ranging
-     * technologies requested in the configuration.
-     */
-    @AssistedInject
-    public PrecisionRangingImpl(
-            Lazy<UwbAdapter> lazyUwbAdapter,
-            Context context,
-            @Assisted PrecisionRangingConfig config,
-            ScheduledExecutorService scheduledExecutorService) {
-        this(
-                lazyUwbAdapter,
-                context,
-                config,
-                scheduledExecutorService,
-                //TimeSource.system(),
-                //Optional.empty(),
-                Optional.empty());
-    }
-
-    @VisibleForTesting
-    public PrecisionRangingImpl(
-            Lazy<UwbAdapter> lazyUwbAdapter,
-            Context context,
-            PrecisionRangingConfig config,
-            ScheduledExecutorService scheduledExecutorService,
-            //TimeSource timeSource,
-            //Optional<ArCoreMultiSensorFinder> fusionAlgorithm,
-            Optional<ImmutableMap<RangingTechnology, RangingAdapter>> rangingAdapters) {
-        this.context = context;
-        this.config = config;
-        this.periodicUpdateExecutorService = scheduledExecutorService;
-        this.internalExecutorService = scheduledExecutorService;
-        //this.timeSource = timeSource;
-        seenSuccessfulFusionData = false;
-        rangingConfigurationsAdded = EnumSet.noneOf(RangingTechnology.class);
-        rangingAdapterListeners = new HashMap<>();
-        rangingAdaptersStateMap = new HashMap<>();
-        lastUpdateTime = Instant.EPOCH;
-        lastRangeDataReceivedTime = Instant.EPOCH;
-        lastFusionDataReceivedTime = Instant.EPOCH;
-        lastUwbRangingDataResult = Optional.empty();
-        lastCsRangingDataResult = Optional.empty();
-        lastFusionDataResult = Optional.empty();
-        periodicUpdateIntervalMs =
-                config.getMaxUpdateInterval().isZero()
-                        ? DEFAULT_INTERNAL_UPDATE_INTERVAL_MS
-                        : config.getMaxUpdateInterval().toMillis();
-        //this.fusionAlgorithm = fusionAlgorithm;
-        if (rangingAdapters.isPresent()) {
-            this.rangingAdapters = rangingAdapters.get();
-        } else {
-            HashMap<RangingTechnology, RangingAdapter> adapters = new HashMap<>();
-            for (RangingTechnology technology : config.getRangingTechnologiesToRangeWith()) {
-                switch (technology) {
-                    case UWB:
-                        adapters.put(technology, lazyUwbAdapter.get());
-                        break;
-                    case CS:
-                        throw new UnsupportedOperationException("CS support not implemented.");
-                }
-            }
-            this.rangingAdapters = ImmutableMap.copyOf(adapters);
-        }
-        synchronized (lock) {
-            internalState = State.STOPPED;
-        }
-    }
-
-    @Override
-    public void start(PrecisionRanging.Callback callback) {
-        Log.i(TAG, "Start Precision Ranging called.");
-        Preconditions.checkArgument(
-                rangingConfigurationsAdded.containsAll(config.getRangingTechnologiesToRangeWith()),
-                "Missing configuration for some ranging technologies that were requested.");
-        synchronized (lock) {
-            internalState = State.STARTING;
-        }
-        this.callback = Optional.of(callback);
-        for (RangingTechnology technology : config.getRangingTechnologiesToRangeWith()) {
-            synchronized (lock) {
-                rangingAdaptersStateMap.put(technology, State.STARTING);
-            }
-            var listener = new RangingAdapterListener(technology);
-            rangingAdapterListeners.put(technology, listener);
-            internalExecutorService.execute(
-                    () -> {
-                        var adapter = rangingAdapters.get(technology);
-                        if (adapter == null) {
-                            Log.e(TAG,
-                                    "No ranging adapter found when trying to start for "
-                                            + technology);
-                            return;
-                        }
-                        adapter.start(listener);
-                    });
-        }
-        if (config.getUseFusingAlgorithm()) {
-            internalExecutorService.execute(this::startFusingAlgorithm);
-        }
-
-        //startTime = timeSource.now();
-        startTime = Instant.now();
-        Log.i(TAG, "Starting periodic update. Start time: " + startTime);
-        var unused =
-                periodicUpdateExecutorService.scheduleWithFixedDelay(
-                        this::performPeriodicUpdate, 0, periodicUpdateIntervalMs, MILLISECONDS);
-    }
-
-    /* Initiates and starts fusion algorithm. */
-    private void startFusingAlgorithm() {
-        Log.i(TAG, "Starting fusion algorithm.");
-//        if (fusionAlgorithm.isEmpty()) {
-//            fusionAlgorithm =
-//                    Optional.of(
-//                            new ArCoreMultiSensorFinder(
-//                                    Sleeper.defaultSleeper(), timeSource, config
-//                                    .getFusionAlgorithmConfig().get()));
-//        }
-//        fusionAlgorithmListener = Optional.of(new FusionAlgorithmListener());
-//        fusionAlgorithm.get().subscribeToEstimates(fusionAlgorithmListener.get());
-//        var result = fusionAlgorithm.get().start(context);
-//        if (result != Status.OK) {
-//            Log.w(TAG,"Fusion algorithm start failed: %s", result);
-//            return;
-//        }
-    }
-
-    /*
-     * Periodic updater reports new data via the callback and stops precision ranging if
-     * stopping conditions are met.
-     */
-    private void performPeriodicUpdate() {
-        synchronized (lock) {
-            if (internalState == State.STOPPED) {
-                return;
-            }
-        }
-        reportNewDataIfAvailable();
-        checkAndStopIfNeeded();
-    }
-
-    /* Reports new data if available via the callback. */
-    private void reportNewDataIfAvailable() {
-        synchronized (lock) {
-            if (internalState == State.STOPPED) {
-                return;
-            }
-        }
-        // Skip update if it's set to immediate updating (updateInterval == 0), or if not enough
-        // time
-        // has passed since last update.
-        //Instant currentTime = timeSource.now();
-        Instant currentTime = Instant.now();
-        if (config.getMaxUpdateInterval().isZero()
-                || currentTime.isBefore(lastUpdateTime.plus(config.getMaxUpdateInterval()))) {
-            return;
-        }
-        // Skip update if there's no new data to report
-        synchronized (lock) {
-            if (lastUwbRangingDataResult.isEmpty()
-                    && lastCsRangingDataResult.isEmpty()
-                    && lastFusionDataResult.isEmpty()) {
-                return;
-            }
-        }
-
-        PrecisionData.Builder precisionDataBuilder = PrecisionData.builder();
-        ImmutableList.Builder<RangingData> rangingDataBuilder = ImmutableList.builder();
-        synchronized (lock) {
-            if (lastUwbRangingDataResult.isPresent()) {
-                rangingDataBuilder.add(lastUwbRangingDataResult.get());
-            }
-            if (lastCsRangingDataResult.isPresent()) {
-                rangingDataBuilder.add(lastCsRangingDataResult.get());
-            }
-            var rangingData = rangingDataBuilder.build();
-            if (!rangingData.isEmpty()) {
-                precisionDataBuilder.setRangingData(rangingData);
-            }
-            if (lastFusionDataResult.isPresent()) {
-                precisionDataBuilder.setFusionData(lastFusionDataResult.get());
-            }
-            lastUwbRangingDataResult = Optional.empty();
-            lastCsRangingDataResult = Optional.empty();
-            lastFusionDataResult = Optional.empty();
-        }
-        //lastUpdateTime = timeSource.now();
-        lastUpdateTime = Instant.now();
-        precisionDataBuilder.setTimestamp(lastUpdateTime.toEpochMilli());
-        PrecisionData precisionData = precisionDataBuilder.build();
-        synchronized (lock) {
-            if (internalState == State.STOPPED) {
-                return;
-            }
-            callback.get().onData(precisionData);
-        }
-    }
-
-    /* Checks if stopping conditions are met and if so, stops precision ranging. */
-    private void checkAndStopIfNeeded() {
-        boolean noActiveRanging;
-        synchronized (lock) {
-            noActiveRanging =
-                    !rangingAdaptersStateMap.containsValue(State.ACTIVE)
-                            && !rangingAdaptersStateMap.containsValue(State.STARTING);
-        }
-
-        // if only ranging is used and all ranging techs are stopped then stop since we won't be
-        // getting
-        // any new data from this point.
-        if (noActiveRanging && !config.getUseFusingAlgorithm()) {
-            Log.i(TAG,
-                    "stopping precision ranging cause: no active ranging in progress and  not "
-                            + "using fusion"
-                            + " algorithm");
-            stopPrecisionRanging(PrecisionRanging.Callback.StoppedReason.NO_RANGES_TIMEOUT);
-            return;
-        }
-
-        // if both ranging and fusion alg used, but all ranging techs are stopped then stop if there
-        // were no successful fusion alg data up to this point since fusion alg can only work if it
-        // received some ranging data.
-        if (noActiveRanging && config.getUseFusingAlgorithm() && !seenSuccessfulFusionData) {
-            Log.i(TAG,
-                    "stopping precision ranging cause: no active ranging in progress and haven't "
-                            + "seen"
-                            + " successful fusion data");
-            stopPrecisionRanging(PrecisionRanging.Callback.StoppedReason.NO_RANGES_TIMEOUT);
-            return;
-        }
-
-        // if both ranging and fusion alg used but all ranges are stopped and there is successful
-        // arcore
-        // data then check if drift timeout expired.
-        //Instant currentTime = timeSource.now();
-        Instant currentTime = Instant.now();
-        if (noActiveRanging && config.getUseFusingAlgorithm() && seenSuccessfulFusionData) {
-            if (currentTime.isAfter(
-                    lastRangeDataReceivedTime.plus(config.getFusionAlgorithmDriftTimeout()))) {
-                Log.i(TAG,
-                        "stopping precision ranging cause: fusion algorithm drift timeout [" +
-                                config.getFusionAlgorithmDriftTimeout().toMillis() + " ms]");
-                stopPrecisionRanging(PrecisionRanging.Callback.StoppedReason.FUSION_DRIFT_TIMEOUT);
-                return;
-            }
-        }
-
-        // If we're still inside the init timeout don't stop precision ranging for any of the
-        // reasons below this.
-        if (currentTime.isBefore(startTime.plus(config.getInitTimeout()))) {
-            return;
-        }
-
-        // If we didn't receive data from any source for more than the update timeout then stop.
-        Instant lastReceivedDataTime =
-                lastRangeDataReceivedTime.isAfter(lastFusionDataReceivedTime)
-                        ? lastRangeDataReceivedTime
-                        : lastFusionDataReceivedTime;
-        if (currentTime.isAfter(lastReceivedDataTime.plus(config.getNoUpdateTimeout()))) {
-            Log.i(TAG,
-                    "stopping precision ranging cause: no update timeout [" +
-                            config.getNoUpdateTimeout().toMillis() + " ms]");
-            stopPrecisionRanging(PrecisionRanging.Callback.StoppedReason.NO_RANGES_TIMEOUT);
-            return;
-        }
-
-        // None of the stopping conditions met, no stopping needed.
-    }
-
-    /* Feeds ranging adapter data into the fusion algorithm. */
-    private void feedDataToFusionAlgorithm(RangingData rangingData) {
-        switch (rangingData.getRangingTechnology()) {
-            case UWB:
-//                fusionAlgorithm
-//                        .get()
-//                        .updateWithUwbMeasurement(rangingData.getRangeDistance(), rangingData
-//                        .getTimestamp());
-                break;
-            case CS:
-                throw new UnsupportedOperationException(
-                        "CS support not implemented. Can't update fusion alg.");
-        }
-    }
-
-    @Override
-    public void stop() {
-        stopPrecisionRanging(PrecisionRanging.Callback.StoppedReason.REQUESTED);
-    }
-
-    /* Calls stop on all ranging adapters and the fusion algorithm and resets all internal states
-    . */
-    private void stopPrecisionRanging(@PrecisionRanging.Callback.StoppedReason int reason) {
-        synchronized (lock) {
-            if (internalState == State.STOPPED) {
-                return;
-            }
-            internalState = State.STOPPED;
-        }
-        Log.i(TAG, "stopPrecisionRanging with reason: " + reason);
-        callback.get().onStopped(reason);
-        // stop all ranging techs
-        for (RangingTechnology technology : config.getRangingTechnologiesToRangeWith()) {
-            synchronized (lock) {
-                if (rangingAdaptersStateMap.get(technology) == State.STOPPED) {
-                    continue;
-                }
-                rangingAdaptersStateMap.put(technology, State.STOPPED);
-            }
-            internalExecutorService.execute(
-                    () -> {
-                        var adapter = rangingAdapters.get(technology);
-                        if (adapter == null) {
-                            Log.e(TAG,
-                                    "Adapter not found for ranging technology when trying to stop: "
-                                            + technology);
-                            return;
-                        }
-                        adapter.stop();
-                    });
-        }
-        // stop fusion algorithm
-        if (config.getUseFusingAlgorithm()) {
-//            internalExecutorService.execute(
-//                    () -> {
-//                        var status = fusionAlgorithm.get().stop();
-//                        if (status != Status.OK) {
-//                            Log.w(TAG,"Fusion alg stop failed: " + status);
-//                        }
-//                    });
-        }
-
-        // reset internal states and objects
-        synchronized (lock) {
-            lastUwbRangingDataResult = Optional.empty();
-            lastCsRangingDataResult = Optional.empty();
-            lastFusionDataResult = Optional.empty();
-        }
-        lastUpdateTime = Instant.EPOCH;
-        lastRangeDataReceivedTime = Instant.EPOCH;
-        lastFusionDataReceivedTime = Instant.EPOCH;
-        rangingAdapterListeners.clear();
-        rangingConfigurationsAdded.clear();
-        //fusionAlgorithmListener = Optional.empty();
-        callback = Optional.empty();
-        seenSuccessfulFusionData = false;
-    }
-
-    @Override
-    public ListenableFuture<RangingCapabilities> getUwbCapabilities() {
-        if (!rangingAdapters.containsKey(RangingTechnology.UWB)) {
-            return immediateFailedFuture(
-                    new IllegalStateException("UWB was not requested for this session."));
-        }
-        UwbAdapter uwbAdapter = (UwbAdapter) rangingAdapters.get(RangingTechnology.UWB);
-        try {
-            return uwbAdapter.getCapabilities();
-        } catch (RemoteException e) {
-            Log.e(TAG, "Failed to get Uwb capabilities");
-            return null;
-        }
-    }
-
-    @Override
-    public ListenableFuture<UwbAddress> getUwbAddress() throws RemoteException {
-        if (!rangingAdapters.containsKey(RangingTechnology.UWB)) {
-            return immediateFailedFuture(
-                    new IllegalStateException("UWB was not requested for this session."));
-        }
-        UwbAdapter uwbAdapter = (UwbAdapter) rangingAdapters.get(RangingTechnology.UWB);
-        return uwbAdapter.getLocalAddress();
-    }
-
-    @Override
-    public ListenableFuture<UwbComplexChannel> getUwbComplexChannel() throws RemoteException {
-        if (!rangingAdapters.containsKey(RangingTechnology.UWB)) {
-            return immediateFailedFuture(
-                    new IllegalStateException("UWB was not requested for this session."));
-        }
-        UwbAdapter uwbAdapter = (UwbAdapter) rangingAdapters.get(RangingTechnology.UWB);
-        return uwbAdapter.getComplexChannel();
-    }
-
-    @Override
-    public void setUwbConfig(RangingParameters rangingParameters) {
-        if (config.getRangingTechnologiesToRangeWith().contains(RangingTechnology.UWB)) {
-            UwbAdapter uwbAdapter = (UwbAdapter) rangingAdapters.get(RangingTechnology.UWB);
-            if (uwbAdapter == null) {
-                Log.e(TAG,
-                        "UWB adapter not found when setting config even though it was requested.");
-                return;
-            }
-            uwbAdapter.setRangingParameters(rangingParameters);
-        }
-        rangingConfigurationsAdded.add(RangingTechnology.UWB);
-    }
-
-    @DoNotCall("Not implemented")
-    @Override
-    public void getCsCapabilities() {
-        throw new UnsupportedOperationException("Not implemented");
-    }
-
-    /** Sets CS configuration. */
-    @DoNotCall("Not implemented")
-    @Override
-    public void setCsConfig() {
-        throw new UnsupportedOperationException("Not implemented");
-    }
-
-    @Override
-    public ListenableFuture<ImmutableMap<RangingTechnology, Integer>>
-    rangingTechnologiesAvailability() throws RemoteException {
-
-        List<ListenableFuture<Boolean>> enabledFutures = new ArrayList<>();
-        for (RangingTechnology technology : config.getRangingTechnologiesToRangeWith()) {
-            var adapter = rangingAdapters.get(technology);
-            if (adapter == null) {
-                return immediateFailedFuture(
-                        new IllegalStateException(
-                                "Adapter not found for ranging technology: " + technology));
-            }
-            enabledFutures.add(adapter.isEnabled());
-        }
-        var f = Futures.allAsList(enabledFutures);
-        return Futures.transform(
-                f,
-                (List<Boolean> enabledList) -> {
-                    ImmutableMap.Builder<RangingTechnology, Integer>
-                            rangingTechnologiesAvailability =
-                            ImmutableMap.builder();
-                    for (int i = 0; i < config.getRangingTechnologiesToRangeWith().size(); i++) {
-                        var tech = config.getRangingTechnologiesToRangeWith().get(i);
-                        var adapter = rangingAdapters.get(tech);
-                        if (adapter == null) {
-                            Log.e(TAG, "Adapter not found for ranging technology: " + tech);
-                            rangingTechnologiesAvailability.put(
-                                    tech, RangingTechnologyAvailability.NOT_SUPPORTED);
-                        } else if (!adapter.isPresent()) {
-                            rangingTechnologiesAvailability.put(
-                                    tech, RangingTechnologyAvailability.NOT_SUPPORTED);
-                        } else if (!enabledList.get(i)) {
-                            rangingTechnologiesAvailability.put(tech,
-                                    RangingTechnologyAvailability.DISABLED);
-                        } else {
-                            rangingTechnologiesAvailability.put(tech,
-                                    RangingTechnologyAvailability.ENABLED);
-                        }
-                    }
-                    return rangingTechnologiesAvailability.buildOrThrow();
-                },
-                internalExecutorService);
-    }
-
-    @VisibleForTesting
-    public Map<RangingTechnology, RangingAdapter.Callback> getRangingAdapterListeners() {
-        return rangingAdapterListeners;
-    }
-
-//    @VisibleForTesting
-//    public Optional<MultiSensorFinderListener> getFusionAlgorithmListener() {
-//        return fusionAlgorithmListener;
-//    }
-
-    /* Listener implementation for ranging adapter callback. */
-    private class RangingAdapterListener implements RangingAdapter.Callback {
-        private final RangingTechnology technology;
-
-        public RangingAdapterListener(RangingTechnology technology) {
-            this.technology = technology;
-        }
-
-        @Override
-        public void onStarted() {
-            synchronized (lock) {
-                if (internalState == State.STOPPED) {
-                    return;
-                }
-                if (internalState == State.STARTING) {
-                    internalState = State.ACTIVE;
-                    // call started as soon as at least one ranging tech starts or fusion alg
-                    // estimate
-                    // received.
-                    callback.get().onStarted();
-                }
-                rangingAdaptersStateMap.put(technology, State.ACTIVE);
-            }
-        }
-
-        @Override
-        public void onStopped(RangingAdapter.Callback.StoppedReason reason) {
-            synchronized (lock) {
-                if (internalState == State.STOPPED) {
-                    return;
-                }
-                rangingAdaptersStateMap.put(technology, State.STOPPED);
-            }
-        }
-
-        @Override
-        public void onRangingData(RangingData rangingData) {
-            synchronized (lock) {
-                if (internalState == State.STOPPED) {
-                    return;
-                }
-            }
-            //lastRangeDataReceivedTime = timeSource.now();
-            lastRangeDataReceivedTime = Instant.now();
-            feedDataToFusionAlgorithm(rangingData);
-            if (config.getMaxUpdateInterval().isZero()) {
-                PrecisionData precisionData =
-                        PrecisionData.builder()
-                                .setRangingData(ImmutableList.of(rangingData))
-                                .setTimestamp(Instant.now().toEpochMilli())
-                                .build();
-                synchronized (lock) {
-                    if (internalState == State.STOPPED) {
-                        return;
-                    }
-                    callback.get().onData(precisionData);
-                }
-            }
-            switch (rangingData.getRangingTechnology()) {
-                case UWB:
-                    synchronized (lock) {
-                        lastUwbRangingDataResult = Optional.of(rangingData);
-                    }
-                    break;
-                case CS:
-                    throw new UnsupportedOperationException("CS support not implemented.");
-            }
-        }
-    }
-
-    /* Listener implementation for fusion algorithm callback. */
-    private class FusionAlgorithmListener implements MultiSensorFinderListener {
-        @Override
-        public void onUpdatedEstimate(Estimate estimate) {
-            synchronized (lock) {
-                if (internalState == State.STOPPED) {
-                    return;
-                }
-                if (internalState == State.STARTING) {
-                    internalState = State.ACTIVE;
-                    // call started as soon as at least one ranging tech starts or fusion alg
-                    //estimate received.
-                    callback.get().onStarted();
-                }
-            }
-            FusionData fusionData = FusionData.fromFusionAlgorithmEstimate(estimate);
-            if (fusionData.getArCoreState() == FusionData.ArCoreState.OK) {
-                lastFusionDataReceivedTime = Instant.now();
-                seenSuccessfulFusionData = true;
-            }
-            synchronized (lock) {
-                lastFusionDataResult = Optional.of(fusionData);
-            }
-            if (config.getMaxUpdateInterval().isZero()) {
-                PrecisionData precisionData =
-                        PrecisionData.builder()
-                                .setFusionData(fusionData)
-                                .setTimestamp(Instant.now().toEpochMilli())
-                                .build();
-                synchronized (lock) {
-                    if (internalState == State.STOPPED) {
-                        return;
-                    }
-                    callback.get().onData(precisionData);
-                }
-            }
-        }
-    }
-
-    /* Internal states. */
-    private enum State {
-        STARTING,
-        ACTIVE,
-        STOPPED,
-    }
-}
\ No newline at end of file
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/RangingAdapter.java b/generic_ranging/src/com/android/ranging/generic/ranging/RangingAdapter.java
deleted file mode 100644
index 61a8f7d4..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/RangingAdapter.java
+++ /dev/null
@@ -1,84 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import android.os.RemoteException;
-
-import com.android.ranging.generic.RangingTechnology;
-
-import com.google.common.util.concurrent.ListenableFuture;
-
-/** RangingAdapter representing a common ranging interface for different ranging technologies. */
-interface RangingAdapter {
-
-    /** Returns {@link RangingTechnology} of this adapter. */
-    RangingTechnology getType();
-
-    /**
-     * Returns true if this device is capable (has supporting hardware) to range using the ranging
-     * technology it represents, false otherwise.
-     */
-    boolean isPresent();
-
-    /**
-     * Returns true if ranging with this ranging technology is currently enabled, or false
-     * otherwise.
-     * When this returns false it's most likely because of not being enabled in the settings,
-     * airplane
-     * mode being on, etc.
-     */
-    ListenableFuture<Boolean> isEnabled() throws RemoteException;
-
-    /**
-     * Initiate start ranging. The provided callback will notify once ranging has started or
-     * stopped.
-     * Ranging data will be provided via the callback. In case start is called while the API has
-     * previously been started then this is a no op and the previously provided callback will still
-     * be
-     * used instead of the new one if they're different.
-     */
-    void start(Callback callback);
-
-    /** Stop ranging. */
-    void stop();
-
-    /** Callback for getting notified when ranging starts or stops. */
-    public interface Callback {
-        /**
-         * Notifies the caller that ranging has started on this device. onStarted will not be called
-         * after start if API failed to initialize, in that case onStopped with an appropriate error
-         * code will be called.
-         */
-        void onStarted();
-
-        /** Notifies the caller that ranging has stopped on this device. */
-        void onStopped(StoppedReason reason);
-
-        /**
-         * Notifies the caller on each instance of ranging data received from the ranging
-         * technology.
-         */
-        void onRangingData(RangingData rangingData);
-
-        /** Stopped reason for this ranging adapter. */
-        public enum StoppedReason {
-            REQUESTED,
-            NO_PARAMS,
-            ERROR,
-        }
-    }
-}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/RangingData.java b/generic_ranging/src/com/android/ranging/generic/ranging/RangingData.java
deleted file mode 100644
index 3df1646e..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/RangingData.java
+++ /dev/null
@@ -1,57 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import com.android.ranging.generic.RangingTechnology;
-
-import com.google.auto.value.AutoValue;
-
-/** Ranging Data class contains data received from a ranging technology such as UWB or CS. */
-@AutoValue
-public abstract class RangingData {
-
-    /** Returns the ranging technology this data is for. */
-    public abstract RangingTechnology getRangingTechnology();
-
-    /** Returns range distance in meters. */
-    public abstract double getRangeDistance();
-
-    /** Returns rssi. */
-    public abstract int getRssi();
-
-    /** Returns timestamp in nanons. */
-    public abstract long getTimestamp();
-
-    /** Returns a builder for {@link RangingData}. */
-    public static Builder builder() {
-        return new AutoValue_RangingData.Builder();
-    }
-
-    /** Builder for {@link RangingData}. */
-    @AutoValue.Builder
-    public abstract static class Builder {
-        public abstract Builder setRangingTechnology(RangingTechnology rangingTechnology);
-
-        public abstract Builder setRangeDistance(double rangeDistance);
-
-        public abstract Builder setRssi(int rssi);
-
-        public abstract Builder setTimestamp(long timestamp);
-
-        public abstract RangingData build();
-    }
-}
diff --git a/generic_ranging/src/com/android/ranging/generic/ranging/UwbAdapter.java b/generic_ranging/src/com/android/ranging/generic/ranging/UwbAdapter.java
deleted file mode 100644
index 534341b8..00000000
--- a/generic_ranging/src/com/android/ranging/generic/ranging/UwbAdapter.java
+++ /dev/null
@@ -1,375 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.ranging.generic.ranging;
-
-import static com.google.common.util.concurrent.Futures.immediateFailedFuture;
-import static com.google.common.util.concurrent.Futures.immediateFuture;
-
-import android.annotation.SuppressLint;
-import android.content.Context;
-import android.os.Build;
-import android.os.RemoteException;
-import android.util.Log;
-
-import androidx.core.uwb.backend.IUwb;
-import androidx.core.uwb.backend.impl.internal.RangingCapabilities;
-import androidx.core.uwb.backend.impl.internal.RangingController;
-import androidx.core.uwb.backend.impl.internal.RangingDevice;
-import androidx.core.uwb.backend.impl.internal.RangingParameters;
-import androidx.core.uwb.backend.impl.internal.RangingPosition;
-import androidx.core.uwb.backend.impl.internal.RangingSessionCallback;
-import androidx.core.uwb.backend.impl.internal.UwbAddress;
-import androidx.core.uwb.backend.impl.internal.UwbAvailabilityCallback;
-import androidx.core.uwb.backend.impl.internal.UwbComplexChannel;
-import androidx.core.uwb.backend.impl.internal.UwbDevice;
-import androidx.core.uwb.backend.impl.internal.UwbFeatureFlags;
-import androidx.core.uwb.backend.impl.internal.UwbServiceImpl;
-
-import com.android.internal.annotations.GuardedBy;
-import com.android.ranging.generic.RangingTechnology;
-
-import com.google.common.annotations.VisibleForTesting;
-import com.google.common.base.Preconditions;
-import com.google.common.util.concurrent.FutureCallback;
-import com.google.common.util.concurrent.Futures;
-import com.google.common.util.concurrent.ListenableFuture;
-import com.google.common.util.concurrent.ListeningExecutorService;
-
-import java.util.Optional;
-
-/** Ranging Adapter for Ultra-Wide Band (UWB). */
-public class UwbAdapter implements RangingAdapter {
-
-    public static String TAG = UwbAdapter.class.getSimpleName();
-
-    public IUwb mIUwb;
-    private UwbServiceImpl mUwbService;
-
-    private final Optional<RangingDevice> uwbClient;
-    private Optional<RangingSessionCallback> uwbListener;
-    private Optional<RangingParameters> rangingParameters;
-    private Optional<Callback> callback;
-
-    private final Object lock = new Object();
-
-    @GuardedBy("lock")
-    private UwbAdapterState internalState;
-
-    private final ListeningExecutorService executorService;
-
-    public UwbAdapter(Context context, ListeningExecutorService executorServices,
-            DeviceType deviceType)
-            throws RemoteException {
-
-        UwbFeatureFlags uwbFeatureFlags = new UwbFeatureFlags.Builder()
-                .setSkipRangingCapabilitiesCheck(Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2)
-                .setReversedByteOrderFiraParams(
-                        Build.VERSION.SDK_INT <= Build.VERSION_CODES.TIRAMISU)
-                .build();
-        UwbAvailabilityCallback uwbAvailabilityCallback = (isUwbAvailable, reason) -> {
-            // TODO: Implement when adding backend support.
-        };
-        mUwbService = new UwbServiceImpl(context, uwbFeatureFlags, uwbAvailabilityCallback);
-        //TODO(b/331206299): Add support to pick controller or controlee.
-        this.uwbClient =
-                context.getPackageManager().hasSystemFeature("android.hardware.uwb")
-                        ? (deviceType == DeviceType.CONTROLEE) ? Optional.of(
-                        mUwbService.getControlee(context)) : Optional.of(
-                        mUwbService.getController(context))
-                        : Optional.empty();
-        this.rangingParameters = Optional.empty();
-        this.callback = Optional.empty();
-        this.uwbListener = Optional.empty();
-        this.executorService = executorServices;
-        synchronized (lock) {
-            internalState = UwbAdapterState.STOPPED;
-        }
-    }
-
-    @VisibleForTesting
-    public UwbAdapter(
-            Optional<RangingDevice> uwbClient,
-            ListeningExecutorService executorService) {
-        this.uwbClient = uwbClient;
-        this.rangingParameters = Optional.empty();
-        this.callback = Optional.empty();
-        this.uwbListener = Optional.empty();
-        synchronized (lock) {
-            internalState = UwbAdapterState.STOPPED;
-        }
-        this.executorService = executorService;
-    }
-
-    @Override
-    public RangingTechnology getType() {
-        return RangingTechnology.UWB;
-    }
-
-    @Override
-    public boolean isPresent() {
-        return uwbClient.isPresent();
-    }
-
-    @SuppressLint("CheckResult")
-    @Override
-    public ListenableFuture<Boolean> isEnabled() throws RemoteException {
-        if (uwbClient.isEmpty()) {
-            return immediateFuture(false);
-        }
-        return Futures.submit(() -> {
-            return mUwbService.isAvailable();
-        }, executorService);
-    }
-
-    @Override
-    public void start(Callback callback) {
-        Log.i(TAG, "Start UwbAdapter called.");
-        if (uwbClient.isEmpty()) {
-            callback.onStopped(RangingAdapter.Callback.StoppedReason.ERROR);
-            clear();
-            return;
-        }
-        synchronized (lock) {
-            if (internalState != UwbAdapterState.STOPPED) {
-                Log.w(TAG, "Tried to start UWB while it is not in stopped state");
-                return;
-            }
-            internalState = UwbAdapterState.STARTING;
-        }
-        this.callback = Optional.of(callback);
-        startRanging(new UwbListener());
-    }
-
-    @Override
-    public void stop() {
-        Log.i(TAG, "Stop UwbAdapter API called.");
-        if (uwbClient.isEmpty()) {
-            Log.w(TAG, "Tried to stop UWB but it is not available.");
-            clear();
-            return;
-        }
-        synchronized (lock) {
-            if (internalState == UwbAdapterState.STOPPED) {
-                Log.w(TAG, "Tried to stop UWB while it is already in stopped state");
-                return;
-            }
-        }
-        stopRanging();
-    }
-
-    ListenableFuture<UwbAddress> getLocalAddress() throws RemoteException {
-        if (uwbClient.isEmpty()) {
-            clear();
-
-            return immediateFailedFuture(new IllegalStateException("UWB is not available."));
-        }
-        return Futures.submit(() -> {
-            return uwbClient.get().getLocalAddress();
-        }, executorService);
-    }
-
-    ListenableFuture<UwbComplexChannel> getComplexChannel() throws RemoteException {
-        if (uwbClient.isEmpty()) {
-            clear();
-
-            return immediateFailedFuture(new IllegalStateException("UWB is not available."));
-        }
-        if (!(uwbClient.get() instanceof RangingController)) {
-            return immediateFuture(null);
-        }
-        return Futures.submit(() -> {
-            return ((RangingController) uwbClient.get()).getComplexChannel();
-        }, executorService);
-    }
-
-    @VisibleForTesting
-    public void setLocalADdress(UwbAddress uwbAddress) {
-        uwbClient.get().setLocalAddress(uwbAddress);
-    }
-
-    ListenableFuture<RangingCapabilities> getCapabilities() throws RemoteException {
-        if (uwbClient.isEmpty()) {
-            clear();
-            return immediateFailedFuture(new IllegalStateException("UWB is not available."));
-        }
-        return Futures.submit(() -> {
-            return mUwbService.getRangingCapabilities();
-        }, executorService);
-
-    }
-
-    void setRangingParameters(RangingParameters params) {
-        rangingParameters = Optional.of(params);
-    }
-
-    private void startRanging(RangingSessionCallback uwbListener) {
-        if (rangingParameters.isEmpty()) {
-            callback.get().onStopped(RangingAdapter.Callback.StoppedReason.NO_PARAMS);
-            return;
-        }
-        this.uwbListener = Optional.of(uwbListener);
-        uwbClient.get().setRangingParameters(this.rangingParameters.get());
-        var future = Futures.submit(() -> {
-            uwbClient.get().startRanging(uwbListener, executorService);
-        }, executorService);
-        Futures.addCallback(
-                future,
-                new FutureCallback<Void>() {
-                    @Override
-                    public void onSuccess(Void result) {
-                        Log.i(TAG, "UWB startRanging call succeeded.");
-                        // On started will be called after onRangingInitialized is invoked from
-                        // the UWB callback.
-                    }
-
-                    @Override
-                    public void onFailure(Throwable t) {
-                        Log.w(TAG, "Failed UWB startRanging call.", t);
-                        callback.get().onStopped(RangingAdapter.Callback.StoppedReason.ERROR);
-                        synchronized (lock) {
-                            internalState = UwbAdapterState.STOPPED;
-                        }
-                        clear();
-                    }
-                },
-                executorService);
-    }
-
-    private void stopRanging() {
-        Log.i(TAG, "UwbAdapter stopRanging.");
-        var future =
-                Futures.submit(() -> {
-                    uwbClient.get().stopRanging();
-                }, executorService);
-        Futures.addCallback(
-                future,
-                new FutureCallback<Void>() {
-                    @Override
-                    public void onSuccess(Void result) {
-                        // On stopped will be called after onRangingSuspended is invoked from
-                        // the UWB callback.
-                    }
-
-                    @Override
-                    public void onFailure(Throwable t) {
-                        Log.w(TAG, "Failed UWB stopRanging call.", t);
-                        // We failed to stop but there's nothing else we can do.
-                        callback.get().onStopped(RangingAdapter.Callback.StoppedReason.REQUESTED);
-                        synchronized (lock) {
-                            internalState = UwbAdapterState.STOPPED;
-                        }
-                        clear();
-                    }
-                },
-                executorService);
-    }
-
-    private class UwbListener implements RangingSessionCallback {
-
-        public UwbListener() {
-        }
-
-        @Override
-        public void onRangingInitialized(UwbDevice device) {
-            Log.i(TAG, "onRangingInitialized");
-            synchronized (lock) {
-                if (internalState != UwbAdapterState.STARTING) {
-                    Log.e(TAG, "Uwb initialized but wasn't in STARTING state.");
-                    return;
-                }
-                internalState = UwbAdapterState.STARTED;
-            }
-            callback.get().onStarted();
-        }
-
-        @Override
-        public void onRangingResult(UwbDevice device, RangingPosition position) {
-            synchronized (lock) {
-                if (internalState != UwbAdapterState.STARTED) {
-                    Log.e(TAG,
-                            "onRangingResult callback received but UwbAdapter not in STARTED "
-                                    + "state.");
-                    return;
-                }
-            }
-
-            RangingData rangingData =
-                    RangingData.builder()
-                            .setRangingTechnology(RangingTechnology.UWB)
-                            .setRangeDistance(position.getDistance().getValue())
-                            .setRssi(position.getRssiDbm())
-                            .setTimestamp(position.getElapsedRealtimeNanos())
-                            .build();
-            callback.get().onRangingData(rangingData);
-        }
-
-        @Override
-        public void onRangingSuspended(UwbDevice device, @RangingSuspendedReason int reason) {
-            Log.i(TAG, "onRangingSuspended: " + reason);
-            synchronized (lock) {
-                if (internalState == UwbAdapterState.STOPPED) {
-                    Log.e(TAG,
-                            "onRangingSuspended callback received but UwbAdapter was in STOPPED "
-                                    + "state.");
-                    return;
-                }
-                internalState = UwbAdapterState.STOPPED;
-                stopRanging();
-            }
-            if (reason == RangingSessionCallback.REASON_STOP_RANGING_CALLED) {
-                callback.get().onStopped(RangingAdapter.Callback.StoppedReason.REQUESTED);
-            } else {
-                callback.get().onStopped(RangingAdapter.Callback.StoppedReason.ERROR);
-            }
-            clear();
-        }
-    }
-
-    @VisibleForTesting
-    public void setComplexChannelForTesting() {
-        if (uwbClient.get() instanceof RangingController) {
-            uwbClient.get().setForTesting(true);
-        }
-    }
-
-    private void clear() {
-        synchronized (lock) {
-            Preconditions.checkState(
-                    internalState == UwbAdapterState.STOPPED,
-                    "Tried to clear object state while internalState != STOPPED");
-        }
-        this.uwbListener = Optional.empty();
-        this.rangingParameters = Optional.empty();
-        this.callback = Optional.empty();
-    }
-
-    @VisibleForTesting
-    public RangingSessionCallback getListener() {
-        return this.uwbListener.get();
-    }
-
-    public enum DeviceType {
-        CONTROLEE,
-        CONTROLLER,
-    }
-
-    private enum UwbAdapterState {
-        STOPPED,
-        STARTING,
-        STARTED,
-    }
-}
diff --git a/generic_ranging/src/com/android/ranging/uwb/UwbAdapter.java b/generic_ranging/src/com/android/ranging/uwb/UwbAdapter.java
new file mode 100644
index 00000000..71ff8da4
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/uwb/UwbAdapter.java
@@ -0,0 +1,293 @@
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
+package com.android.ranging.uwb;
+
+import static com.google.common.util.concurrent.Futures.immediateFuture;
+
+import android.content.Context;
+import android.content.pm.PackageManager;
+import android.os.Build;
+import android.os.RemoteException;
+import android.util.Log;
+
+import androidx.annotation.NonNull;
+
+import com.android.ranging.RangingAdapter;
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingParameters.DeviceRole;
+import com.android.ranging.RangingParameters.TechnologyParameters;
+import com.android.ranging.RangingTechnology;
+import com.android.ranging.RangingUtils.StateMachine;
+import com.android.ranging.uwb.backend.internal.RangingCapabilities;
+import com.android.ranging.uwb.backend.internal.RangingController;
+import com.android.ranging.uwb.backend.internal.RangingDevice;
+import com.android.ranging.uwb.backend.internal.RangingParameters;
+import com.android.ranging.uwb.backend.internal.RangingPosition;
+import com.android.ranging.uwb.backend.internal.RangingSessionCallback;
+import com.android.ranging.uwb.backend.internal.Utils;
+import com.android.ranging.uwb.backend.internal.UwbAddress;
+import com.android.ranging.uwb.backend.internal.UwbComplexChannel;
+import com.android.ranging.uwb.backend.internal.UwbDevice;
+import com.android.ranging.uwb.backend.internal.UwbFeatureFlags;
+import com.android.ranging.uwb.backend.internal.UwbServiceImpl;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.util.concurrent.FutureCallback;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+import java.time.Duration;
+import java.util.concurrent.Executors;
+
+/** Ranging adapter for Ultra-wideband (UWB). */
+public class UwbAdapter implements RangingAdapter {
+    private static final String TAG = UwbAdapter.class.getSimpleName();
+
+    private final UwbServiceImpl mUwbService;
+    // private IUwb mIUwb;
+
+    private final RangingDevice mUwbClient;
+    private final ListeningExecutorService mExecutorService;
+    private final ExecutorResultHandlers mUwbClientResultHandlers = new ExecutorResultHandlers();
+    private final RangingSessionCallback mUwbListener = new UwbListener();
+    private final StateMachine<State> mStateMachine;
+
+    /** Invariant: non-null while a ranging session is active */
+    private Callback mCallbacks;
+
+    /** @return true if UWB is supported in the provided context, false otherwise */
+    public static boolean isSupported(Context context) {
+        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_UWB);
+    }
+
+    public UwbAdapter(
+            @NonNull Context context, @NonNull ListeningExecutorService executorService,
+            @NonNull DeviceRole role
+    ) {
+        this(context, executorService,
+                new UwbServiceImpl(
+                        context,
+                        new UwbFeatureFlags.Builder()
+                                .setSkipRangingCapabilitiesCheck(
+                                        Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2)
+                                .setReversedByteOrderFiraParams(
+                                        Build.VERSION.SDK_INT <= Build.VERSION_CODES.TIRAMISU)
+                                .build(),
+                        (isUwbAvailable, reason) -> {
+                            // TODO: Implement when adding backend support.
+                        }
+                ),
+                role);
+    }
+
+    @VisibleForTesting
+    public UwbAdapter(
+            @NonNull Context context, @NonNull ListeningExecutorService executorService,
+            @NonNull UwbServiceImpl uwbService, @NonNull DeviceRole role
+    ) {
+        if (!UwbAdapter.isSupported(context)) {
+            throw new IllegalArgumentException("UWB system feature not found.");
+        }
+
+        mStateMachine = new StateMachine<>(State.STOPPED);
+        mUwbService = uwbService;
+        mUwbClient = role == DeviceRole.CONTROLLER
+                ? mUwbService.getController(context)
+                : mUwbService.getControlee(context);
+        mExecutorService = executorService;
+        mCallbacks = null;
+    }
+
+    @Override
+    public RangingTechnology getType() {
+        return RangingTechnology.UWB;
+    }
+
+    @Override
+    public ListenableFuture<Boolean> isEnabled() {
+        return Futures.immediateFuture(mUwbService.isAvailable());
+    }
+
+    @Override
+    public void start(@NonNull TechnologyParameters parameters, @NonNull Callback callbacks) {
+        Log.i(TAG, "Start called.");
+        if (!mStateMachine.transition(State.STOPPED, State.STARTED)) {
+            Log.v(TAG, "Attempted to start adapter when it was already started");
+            return;
+        }
+
+        mCallbacks = callbacks;
+        if (!(parameters instanceof RangingParameters)) {
+            Log.w(TAG, "Tried to start adapter with invalid ranging parameters");
+            mCallbacks.onStopped(Callback.StoppedReason.FAILED_TO_START);
+            return;
+        }
+        mUwbClient.setRangingParameters((RangingParameters) parameters);
+
+        var future = Futures.submit(() -> {
+            mUwbClient.startRanging(mUwbListener, Executors.newSingleThreadExecutor());
+        }, mExecutorService);
+        Futures.addCallback(future, mUwbClientResultHandlers.startRanging, mExecutorService);
+    }
+
+    @Override
+    public void stop() {
+        Log.i(TAG, "Stop called.");
+        if (!mStateMachine.transition(State.STARTED, State.STOPPED)) {
+            Log.v(TAG, "Attempted to stop adapter when it was already stopped");
+            return;
+        }
+
+        var future = Futures.submit(mUwbClient::stopRanging, mExecutorService);
+        Futures.addCallback(future, mUwbClientResultHandlers.stopRanging, mExecutorService);
+    }
+
+    public ListenableFuture<UwbAddress> getLocalAddress() {
+        return Futures.submit(() -> mUwbClient.getLocalAddress(), mExecutorService);
+    }
+
+    public ListenableFuture<UwbComplexChannel> getComplexChannel() {
+        if (!(mUwbClient instanceof RangingController)) {
+            return immediateFuture(null);
+        }
+        return Futures.submit(() -> ((RangingController) mUwbClient).getComplexChannel(),
+                mExecutorService);
+    }
+
+    public ListenableFuture<RangingCapabilities> getCapabilities() throws RemoteException {
+        return Futures.submit(mUwbService::getRangingCapabilities, mExecutorService);
+    }
+
+    private class UwbListener implements RangingSessionCallback {
+
+        @Override
+        public void onRangingInitialized(UwbDevice device) {
+            Log.i(TAG, "onRangingInitialized");
+            synchronized (mStateMachine) {
+                if (mStateMachine.getState() == State.STARTED) {
+                    mCallbacks.onStarted();
+                }
+            }
+        }
+
+        @Override
+        public void onRangingResult(UwbDevice device, RangingPosition position) {
+            RangingData.Builder dataBuilder = new RangingData.Builder()
+                    .setTechnology(RangingTechnology.UWB)
+                    .setRangeDistance(position.getDistance().getValue())
+                    .setRssi(position.getRssiDbm())
+                    .setTimestamp(Duration.ofNanos(position.getElapsedRealtimeNanos()))
+                    .setPeerAddress(device.getAddress().toBytes());
+
+            if (position.getAzimuth() != null) {
+                dataBuilder.setAzimuthRadians(position.getAzimuth().getValue());
+            }
+            if (position.getElevation() != null) {
+                dataBuilder.setElevationRadians(position.getElevation().getValue());
+            }
+            synchronized (mStateMachine) {
+                if (mStateMachine.getState() == State.STARTED) {
+                    mCallbacks.onRangingData(dataBuilder.build());
+                }
+            }
+        }
+
+        private static @Callback.StoppedReason int convertReason(
+                @RangingSessionCallback.RangingSuspendedReason int reason) {
+            switch (reason) {
+                case REASON_WRONG_PARAMETERS:
+                case REASON_FAILED_TO_START:
+                    return Callback.StoppedReason.FAILED_TO_START;
+                case REASON_STOPPED_BY_PEER:
+                case REASON_STOP_RANGING_CALLED:
+                    return Callback.StoppedReason.REQUESTED;
+                case REASON_MAX_RANGING_ROUND_RETRY_REACHED:
+                    return Callback.StoppedReason.LOST_CONNECTION;
+                case REASON_SYSTEM_POLICY:
+                    return Callback.StoppedReason.SYSTEM_POLICY;
+                default:
+                    return Callback.StoppedReason.UNKNOWN;
+            }
+        }
+
+        @Override
+        public void onRangingSuspended(UwbDevice device, @RangingSuspendedReason int reason) {
+            Log.i(TAG, "onRangingSuspended: " + reason);
+
+            synchronized (mStateMachine) {
+                mCallbacks.onStopped(convertReason(reason));
+                clear();
+            }
+        }
+    }
+
+    @VisibleForTesting
+    public void setComplexChannelForTesting() {
+        if (mUwbClient instanceof RangingController) {
+            mUwbClient.setForTesting(true);
+        }
+    }
+
+    @VisibleForTesting
+    public void setLocalAddressForTesting(@NonNull UwbAddress uwbAddress) {
+        mUwbClient.setLocalAddress(uwbAddress);
+    }
+
+    private void clear() {
+        mCallbacks = null;
+    }
+
+    public enum State {
+        STARTED,
+        STOPPED,
+    }
+
+    private class ExecutorResultHandlers {
+        public final FutureCallback<Void> startRanging = new FutureCallback<>() {
+            @Override
+            public void onSuccess(Void v) {
+                Log.i(TAG, "startRanging succeeded.");
+                // On started will be called after onRangingInitialized is invoked from
+                // the UWB callback.
+            }
+
+            @Override
+            public void onFailure(@NonNull Throwable t) {
+                Log.w(TAG, "startRanging failed ", t);
+                mCallbacks.onStopped(RangingAdapter.Callback.StoppedReason.ERROR);
+                clear();
+            }
+        };
+
+        public final FutureCallback<Integer> stopRanging = new FutureCallback<>() {
+            @Override
+            public void onSuccess(@Utils.UwbStatusCodes Integer status) {
+                // On stopped will be called after onRangingSuspended is invoked from
+                // the UWB callback.
+            }
+
+            @Override
+            public void onFailure(@NonNull Throwable t) {
+                Log.w(TAG, "stopRanging failed ", t);
+                // We failed to stop but there's nothing else we can do.
+                mCallbacks.onStopped(RangingAdapter.Callback.StoppedReason.REQUESTED);
+                clear();
+            }
+        };
+    }
+}
diff --git a/generic_ranging/src/com/android/ranging/uwb/UwbParameters.java b/generic_ranging/src/com/android/ranging/uwb/UwbParameters.java
new file mode 100644
index 00000000..f8d6a376
--- /dev/null
+++ b/generic_ranging/src/com/android/ranging/uwb/UwbParameters.java
@@ -0,0 +1,46 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.uwb;
+
+import androidx.annotation.NonNull;
+
+import com.android.ranging.RangingParameters;
+import com.android.ranging.uwb.backend.internal.UwbAddress;
+import com.android.ranging.uwb.backend.internal.UwbComplexChannel;
+import com.android.ranging.uwb.backend.internal.UwbRangeDataNtfConfig;
+
+import java.util.List;
+
+/** Parameters for UWB ranging. */
+public class UwbParameters
+        extends com.android.ranging.uwb.backend.internal.RangingParameters
+        implements RangingParameters.TechnologyParameters {
+
+    public UwbParameters(int uwbConfigId, int sessionId, int subSessionId,
+            byte[] sessionKeyInfo,
+            byte[] subSessionKeyInfo,
+            UwbComplexChannel complexChannel,
+            List<UwbAddress> peerAddresses,
+            int rangingUpdateRate,
+            @NonNull UwbRangeDataNtfConfig uwbRangeDataNtfConfig,
+            int slotDuration, boolean isAoaDisabled) {
+        super(uwbConfigId, sessionId, subSessionId, sessionKeyInfo, subSessionKeyInfo,
+                complexChannel,
+                peerAddresses, rangingUpdateRate, uwbRangeDataNtfConfig, slotDuration,
+                isAoaDisabled);
+    }
+}
diff --git a/generic_ranging/src/com/android/sensor/ArCoreMultiSensorFinder.java b/generic_ranging/src/com/android/sensor/ArCoreMultiSensorFinder.java
index db434775..3c9c851f 100644
--- a/generic_ranging/src/com/android/sensor/ArCoreMultiSensorFinder.java
+++ b/generic_ranging/src/com/android/sensor/ArCoreMultiSensorFinder.java
@@ -27,7 +27,7 @@ import androidx.annotation.GuardedBy;
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
-import com.android.ranging.generic.proto.MultiSensorFinderConfig;
+import com.android.ranging.proto.MultiSensorFinderConfig;
 
 import java.time.Duration;
 import java.time.Instant;
diff --git a/generic_ranging/tests/multidevices/lib/generic_ranging_decorator.py b/generic_ranging/tests/multidevices/lib/generic_ranging_decorator.py
index 8b4ec697..ab1d6392 100644
--- a/generic_ranging/tests/multidevices/lib/generic_ranging_decorator.py
+++ b/generic_ranging/tests/multidevices/lib/generic_ranging_decorator.py
@@ -1,31 +1,109 @@
 import time
-from uwb import uwb_ranging_params
 from typing import List
 from mobly.controllers import android_device
 from mobly.controllers.android_device_lib import jsonrpc_client_base
 from mobly.snippet import errors
+from uwb import uwb_ranging_params
 
 CALLBACK_WAIT_TIME_SEC = 3
 STOP_CALLBACK_WAIT_TIME_SEC = 6
 
 
-class GenericRangingDecorator():
+class GenericRangingDecorator:
 
-    def __init__(self, ad: android_device.AndroidDevice):
-        """Initialize the ranging device.
+  def __init__(self, ad: android_device.AndroidDevice):
+    """Initialize the ranging device.
 
-        Args:
+    Args:
         ad: android device object
-        """
-        self.ad = ad
-        self._callback_keys = {}
-        self._event_handlers = {}
-        self.log = self.ad.log
-
-    def start_uwb_ranging(self, params: uwb_ranging_params.UwbRangingParams):
-        callback_key = "fira_session_%s" % 1
-        handler = self.ad.ranging.startUwbRanging(callback_key, params.to_dict())
-
-    def stop_uwb_ranging(self, params: uwb_ranging_params.UwbRangingParams):
-        callback_key = "fira_session_%s" % 1
-        handler = self.ad.ranging.stopUwbRanging(callback_key)
+    """
+    self.ad = ad
+    self._event_handlers = {}
+    self.log = self.ad.log
+
+  def start_uwb_ranging_session(
+      self, params: uwb_ranging_params.UwbRangingParams
+  ):
+    handler = self.ad.ranging.startUwbRanging(params.to_dict())
+    self._event_handlers[params.session_id] = handler
+    self.verify_ranging_event_received("Started", params.session_id)
+
+  def stop_uwb_ranging_session(self, session_id: int):
+    self.ad.ranging.stopUwbRanging(session_id)
+    self.verify_ranging_event_received("Stopped", session_id)
+    self._event_handlers.pop(session_id)
+
+  def clear_all_uwb_ranging_sessions(self):
+    for session_id in self._event_handlers.keys():
+      self.ad.ranging.stopUwbRanging(session_id)
+      self.clear_ranging_callback_events(session_id)
+
+    self._event_handlers.clear()
+
+  def clear_ranging_callback_events(self, session_id: int):
+    """Clear 'GenericRangingCallback' events from EventCache.
+
+    Args:
+      session_id: ranging session id.
+    """
+    self._event_handlers[session_id].getAll("GenericRangingCallback")
+
+  def verify_ranging_event_received(
+      self,
+      ranging_event: str,
+      session_id: int,
+      timeout_s: int = CALLBACK_WAIT_TIME_SEC,
+  ) -> bool:
+    """Verifies that the expected event is received before a timeout.
+
+    Args:
+      ranging_event: expected ranging event.
+      session: ranging session.
+      timeout_s: timeout in seconds.
+
+    Returns:
+      True if the expected event was received.
+    """
+    handler = self._event_handlers[session_id]
+
+    start_time = time.time()
+    while time.time() - start_time < timeout_s:
+      try:
+        event = handler.waitAndGet("GenericRangingCallback", timeout=timeout_s)
+        event_received = event.data["genericRangingSessionEvent"]
+        self.ad.log.debug("Received event - %s" % event_received)
+        if event_received == ranging_event:
+          self.ad.log.debug(
+              f"Received event {ranging_event} in"
+              f" {round(time.time() - start_time, 2)} secs"
+          )
+          self.clear_ranging_callback_events(session_id)
+          return True
+      except errors.CallbackHandlerTimeoutError:
+        self.log.warn("Failed to receive 'RangingSessionCallback' event")
+
+    return False
+
+  def verify_uwb_peer_found(
+      self,
+      addr: List[int],
+      session_id: int,
+      timeout_s: int = CALLBACK_WAIT_TIME_SEC,
+  ):
+    """Verifies that the UWB peer is found before a timeout.
+
+    Args:
+      addr: peer address.
+      session_id: ranging session id.
+      timeout_s: timeout in seconds.
+
+    Returns:
+      True if the peer was found.
+    """
+    start_time = time.time()
+    while time.time() - start_time < timeout_s:
+      self.verify_ranging_event_received("ReportReceived", session_id)
+      if self.ad.ranging.verifyUwbPeerFound(addr, session_id):
+        return True
+
+    return False
diff --git a/generic_ranging/tests/multidevices/lib/ranging_base_test.py b/generic_ranging/tests/multidevices/lib/ranging_base_test.py
index 966e71b1..9811b5b0 100644
--- a/generic_ranging/tests/multidevices/lib/ranging_base_test.py
+++ b/generic_ranging/tests/multidevices/lib/ranging_base_test.py
@@ -13,47 +13,47 @@
 #  limitations under the License.
 """Ranging base test."""
 
-import logging
 import re
 
 from mobly import base_test
 from mobly import records
 from mobly import test_runner
 from mobly.controllers import android_device
-
 from test_utils import uwb_test_utils
 
 RELEASE_ID_REGEX = re.compile(r"\w+\.\d+\.\d+")
 
 
 class RangingBaseTest(base_test.BaseTestClass):
-    """Base class for Uwb tests."""
-
-    def setup_class(self):
-        """Sets up the Android devices for Uwb test."""
-        super().setup_class()
-        self.android_devices = self.register_controller(android_device,
-                                                        min_number=2)
-        for ad in self.android_devices:
-            ad.load_snippet("ranging", "multidevices.snippet.ranging")
-
-        # for ad in self.android_devices:
-        #     uwb_test_utils.initialize_uwb_country_code_if_not_set(ad)
-
-    def setup_test(self):
-        super().setup_test()
-        for ad in self.android_devices:
-            dev1 = ad.ranging
-            dev1.logInfo("*** TEST START: " + self.current_test_info.name + " ***")
-
-    def teardown_test(self):
-        super().teardown_test()
-        # for ad in self.android_devices:
-        #     ad.ranging.logInfo("*** TEST END: " + self.current_test_info.name + " ***")
-
-    def teardown_class(self):
-        super().teardown_class()
+  """Base class for Uwb tests."""
+
+  def setup_class(self):
+    """Sets up the Android devices for Uwb test."""
+    super().setup_class()
+    self.android_devices = self.register_controller(
+        android_device, min_number=2
+    )
+    for ad in self.android_devices:
+      ad.load_snippet("ranging", "multidevices.snippet.ranging")
+      uwb_test_utils.initialize_uwb_country_code_if_necessary(ad)
+
+  def setup_test(self):
+    super().setup_test()
+    for ad in self.android_devices:
+      ad.ranging.logInfo(
+          "*** TEST START: " + self.current_test_info.name + " ***"
+      )
+
+  def teardown_test(self):
+    super().teardown_test()
+    for ad in self.android_devices:
+      ad.ranging.logInfo(
+          "*** TEST END: " + self.current_test_info.name + " ***"
+      )
+
+  def teardown_class(self):
+    super().teardown_class()
 
 
 if __name__ == "__main__":
-    test_runner.main()
+  test_runner.main()
diff --git a/generic_ranging/tests/multidevices/snippet/GenericRangingSnippet.java b/generic_ranging/tests/multidevices/snippet/GenericRangingSnippet.java
index e7570efc..5d6d8d55 100644
--- a/generic_ranging/tests/multidevices/snippet/GenericRangingSnippet.java
+++ b/generic_ranging/tests/multidevices/snippet/GenericRangingSnippet.java
@@ -18,28 +18,35 @@ package multidevices.snippet.ranging;
 
 import android.app.UiAutomation;
 import android.content.Context;
+import android.net.ConnectivityManager;
 import android.os.RemoteException;
 import android.util.Log;
+import android.uwb.UwbManager;
 
-import androidx.core.uwb.backend.impl.internal.RangingParameters;
-import androidx.core.uwb.backend.impl.internal.UwbAddress;
-import androidx.core.uwb.backend.impl.internal.UwbComplexChannel;
-import androidx.core.uwb.backend.impl.internal.UwbRangeDataNtfConfig;
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 import androidx.test.platform.app.InstrumentationRegistry;
 
-import com.android.ranging.generic.RangingTechnology;
-import com.android.ranging.generic.ranging.PrecisionData;
-import com.android.ranging.generic.ranging.PrecisionRanging;
-import com.android.ranging.generic.ranging.PrecisionRangingConfig;
-import com.android.ranging.generic.ranging.PrecisionRangingImpl;
-import com.android.ranging.generic.ranging.UwbAdapter;
+import com.android.ranging.RangingConfig;
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingParameters;
+import com.android.ranging.RangingParameters.DeviceRole;
+import com.android.ranging.RangingSession;
+import com.android.ranging.RangingSessionImpl;
+import com.android.ranging.RangingTechnology;
+import com.android.ranging.fusion.DataFusers;
+import com.android.ranging.fusion.FilteringFusionEngine;
+import com.android.ranging.uwb.UwbAdapter;
+import com.android.ranging.uwb.UwbParameters;
+import com.android.ranging.uwb.backend.internal.UwbAddress;
+import com.android.ranging.uwb.backend.internal.UwbComplexChannel;
+import com.android.ranging.uwb.backend.internal.UwbRangeDataNtfConfig;
 
 import com.google.android.mobly.snippet.Snippet;
 import com.google.android.mobly.snippet.event.EventCache;
 import com.google.android.mobly.snippet.event.SnippetEvent;
+import com.google.android.mobly.snippet.rpc.AsyncRpc;
 import com.google.android.mobly.snippet.rpc.Rpc;
-import com.google.common.collect.ImmutableList;
-import com.google.common.collect.ImmutableMap;
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
 
@@ -59,18 +66,24 @@ import java.util.Optional;
 import java.util.concurrent.Executors;
 
 public class GenericRangingSnippet implements Snippet {
+    private static final String TAG = "GenericRangingSnippet";
 
-    private static final String TAG = "GenericRangingSnippet: ";
     private final Context mContext;
+    private final ConnectivityManager mConnectivityManager;
+    private final UwbManager mUwbManager;
     private final ListeningExecutorService mExecutor = MoreExecutors.listeningDecorator(
             Executors.newSingleThreadExecutor());
     private final EventCache mEventCache = EventCache.getInstance();
-    private static final HashMap<String, PrecisionRanging> sRangingHashMap =
+    private static final HashMap<String, RangingSessionImpl> sRangingHashMap =
+            new HashMap<>();
+    private static final HashMap<String, GenericRangingCallback> sRangingCallbackHashMap =
             new HashMap<>();
 
     public GenericRangingSnippet() throws Throwable {
         adoptShellPermission();
         mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
+        mConnectivityManager = mContext.getSystemService(ConnectivityManager.class);
+        mUwbManager = mContext.getSystemService(UwbManager.class);
     }
 
     private static class UwbManagerSnippetException extends Exception {
@@ -118,14 +131,18 @@ public class GenericRangingSnippet implements Snippet {
         }
     }
 
-    class GenericRangingCallback implements PrecisionRanging.Callback {
-
-        public String mId;
+    class GenericRangingCallback implements RangingSession.Callback {
+        private String mId;
+        private RangingData mLastDataReceived = null;
 
         GenericRangingCallback(String id, int events) {
             mId = id;
         }
 
+        public Optional<RangingData> getLastDataReceived() {
+            return Optional.ofNullable(mLastDataReceived);
+        }
+
         private void handleEvent(Event e) {
             Log.d(TAG, "GenericRangingCallback#handleEvent() for " + e.toString());
             SnippetEvent event = new SnippetEvent(mId, "GenericRangingCallback");
@@ -134,20 +151,21 @@ public class GenericRangingSnippet implements Snippet {
         }
 
         @Override
-        public void onStarted() {
+        public void onStarted(@Nullable RangingTechnology technology) {
             Log.d(TAG, "GenericRangingCallback#onStarted() called");
             handleEvent(Event.Started);
         }
 
         @Override
-        public void onStopped(int reason) {
+        public void onStopped(@Nullable RangingTechnology technology, @StoppedReason int reason) {
             Log.d(TAG, "GenericRangingCallback#onStopped() called");
             handleEvent(Event.Stopped);
         }
 
         @Override
-        public void onData(PrecisionData data) {
+        public void onData(@NonNull RangingData data) {
             Log.d(TAG, "GenericRangingCallback#onData() called");
+            mLastDataReceived = data;
             handleEvent(Event.ReportReceived);
         }
     }
@@ -157,8 +175,8 @@ public class GenericRangingSnippet implements Snippet {
             return null;
         }
         List<UwbAddress> peerAddresses = new ArrayList<>();
-        if (j.has("destinationAddresses")) {
-            JSONArray jArray = j.getJSONArray("destinationAddresses");
+        if (j.has("peerAddresses")) {
+            JSONArray jArray = j.getJSONArray("peerAddresses");
             UwbAddress[] destinationUwbAddresses = new UwbAddress[jArray.length()];
             for (int i = 0; i < jArray.length(); i++) {
                 destinationUwbAddresses[i] = UwbAddress.fromBytes(
@@ -167,21 +185,28 @@ public class GenericRangingSnippet implements Snippet {
             peerAddresses = Arrays.asList(destinationUwbAddresses);
         }
         UwbComplexChannel uwbComplexChannel = new UwbComplexChannel(9, 11);
-        UwbRangeDataNtfConfig rangeDataNtfConfig = new UwbRangeDataNtfConfig.Builder().build();
+        UwbRangeDataNtfConfig rangeDataNtfConfig = new UwbRangeDataNtfConfig.Builder()
+                .setRangeDataConfigType(j.getInt("rangeDataConfigType"))
+                .build();
 
-        return new RangingParameters(
-                j.getInt("configId"),
+        UwbParameters uwbParams = new UwbParameters(
+                j.getInt("configType"),
                 j.getInt("sessionId"),
                 j.getInt("subSessionId"),
-                convertJSONArrayToByteArray(j.getJSONArray("sessionKey")),
-                null,
+                convertJSONArrayToByteArray(j.getJSONArray("sessionKeyInfo")),
+                j.has("subSessionKeyInfo")
+                        ? convertJSONArrayToByteArray(j.getJSONArray("subSessionKeyInfo"))
+                        : null,
                 uwbComplexChannel,
                 peerAddresses,
-                j.getInt("rangingUpdateRate"),
+                j.getInt("updateRateType"),
                 rangeDataNtfConfig,
-                j.getInt("slotDuration"),
+                j.getInt("slotDurationMillis"),
                 j.getBoolean("isAoaDisabled")
         );
+        DeviceRole role = j.getInt("deviceRole") == 0
+                ? DeviceRole.CONTROLEE : DeviceRole.CONTROLLER;
+        return new RangingParameters.Builder(role).useUwb(uwbParams).build();
     }
 
     private byte[] convertJSONArrayToByteArray(JSONArray jArray) throws JSONException {
@@ -195,52 +220,105 @@ public class GenericRangingSnippet implements Snippet {
         return bArray;
     }
 
-    @Rpc(description = "Start UWB ranging session")
-    public void startUwbRanging(String key, JSONObject config)
+    private static String getUwbSessionKeyFromId(int sessionId) {
+        return "uwb_session_" + sessionId;
+    }
+
+    @AsyncRpc(description = "Start UWB ranging session")
+    public void startUwbRanging(String callbackId, JSONObject config)
             throws JSONException, RemoteException {
-        int deviceType = config.getInt("deviceType");
+        int deviceRole = config.getInt("deviceRole");
         UwbAdapter uwbAdapter = null;
-        if (deviceType == 0) {
+        if (deviceRole == 0) {
             logInfo("Starting controlee session");
-            uwbAdapter = new UwbAdapter(mContext, mExecutor, UwbAdapter.DeviceType.CONTROLEE);
+            uwbAdapter = new UwbAdapter(mContext, mExecutor, DeviceRole.CONTROLEE);
         } else {
             logInfo("Starting controller session");
-            uwbAdapter = new UwbAdapter(mContext, mExecutor, UwbAdapter.DeviceType.CONTROLLER);
+            uwbAdapter = new UwbAdapter(mContext, mExecutor, DeviceRole.CONTROLLER);
+        }
+        uwbAdapter.setLocalAddressForTesting(UwbAddress.fromBytes(
+                convertJSONArrayToByteArray(config.getJSONArray("deviceAddress"))));
+
+        // Test forces channel to 9 and preamble to 11
+        uwbAdapter.setComplexChannelForTesting();
+        try {
+            uwbAdapter.getComplexChannel().get();
+        } catch (Exception e) {
+            Log.w(TAG, "Could not get complex channel for uwb adapter");
+            throw new RuntimeException(e);
         }
 
         //TODO: Make this configurable
         //    private Provider<PrecisionRanging.Factory> mRangingFactory;
-        PrecisionRangingConfig precisionRangingConfig =
-                PrecisionRangingConfig.builder().setRangingTechnologiesToRangeWith(
-                        ImmutableList.of(RangingTechnology.UWB)).setUseFusingAlgorithm(
-                        false).setMaxUpdateInterval(
-                        Duration.ofMillis(200)).setFusionAlgorithmDriftTimeout(
-                        Duration.ofSeconds(1)).setNoUpdateTimeout(
-                        Duration.ofSeconds(2)).setInitTimeout(Duration.ofSeconds(3)).build();
-
-        PrecisionRanging precisionRanging = new PrecisionRangingImpl(
-                new CustomUwbAdapterProvider(uwbAdapter), mContext, precisionRangingConfig,
+        RangingConfig rangingConfig =
+                RangingConfig.builder()
+                        .setUseFusingAlgorithm(false)
+                        .setMaxUpdateInterval(Duration.ofMillis(200))
+                        .setFusionAlgorithmDriftTimeout(Duration.ofSeconds(1))
+                        .setNoUpdateTimeout(Duration.ofSeconds(2))
+                        .setInitTimeout(Duration.ofSeconds(3))
+                        .build();
+
+        FilteringFusionEngine fusionEngine =
+                new FilteringFusionEngine(
+                        new DataFusers.PreferentialDataFuser(RangingTechnology.UWB));
+
+        RangingSessionImpl session = new RangingSessionImpl(
+                mContext, rangingConfig, fusionEngine,
                 Executors.newSingleThreadScheduledExecutor(),
-                Optional.of(ImmutableMap.of(RangingTechnology.UWB, uwbAdapter)));
+                MoreExecutors.listeningDecorator(Executors.newSingleThreadExecutor()));
 
-        precisionRanging.setUwbConfig(generateRangingParameters(config));
-        uwbAdapter.setLocalADdress(UwbAddress.fromBytes(
-                convertJSONArrayToByteArray(config.getJSONArray("deviceAddress"))));
+        session.useAdapterForTesting(RangingTechnology.UWB, uwbAdapter);
 
-        // Test forces channel to 9 and preamble to 11
-        uwbAdapter.setComplexChannelForTesting();
-        precisionRanging.getUwbComplexChannel();
-        GenericRangingCallback genericRangingCallback = new GenericRangingCallback("1",
-                Event.EventAll.getType());
-        sRangingHashMap.put(key, precisionRanging);
-        precisionRanging.start(genericRangingCallback);
+        GenericRangingCallback genericRangingCallback =
+                new GenericRangingCallback(callbackId, Event.EventAll.getType());
+        String uwbSessionKey = getUwbSessionKeyFromId(config.getInt("sessionId"));
+        sRangingHashMap.put(uwbSessionKey, session);
+        session.start(generateRangingParameters(config), genericRangingCallback);
+        sRangingCallbackHashMap.put(uwbSessionKey, genericRangingCallback);
+    }
+
+    @Rpc(description = "Stop UWB ranging session")
+    public void stopUwbRanging(int sessionId) throws JSONException {
+        String uwbSessionKey = getUwbSessionKeyFromId(sessionId);
+        if (sRangingHashMap.containsKey(uwbSessionKey)) {
+            sRangingHashMap.get(uwbSessionKey).stop();
+        }
     }
 
-    @Rpc(description = "Start UWB ranging session")
-    public void stopUwbRanging(String key) throws JSONException {
-        if (sRangingHashMap.containsKey(key)) {
-            sRangingHashMap.get(key).stop();
+    @Rpc(description = "Check whether the last report included UWB data from the specified address")
+    public boolean verifyUwbPeerFound(JSONArray peerAddress, int sessionId)
+            throws JSONException {
+        GenericRangingCallback callback =
+                sRangingCallbackHashMap.get(getUwbSessionKeyFromId(sessionId));
+        if (callback == null) {
+            throw new IllegalArgumentException("Could not find session with id " + sessionId);
         }
+
+        Optional<RangingData> data = callback.getLastDataReceived();
+        if (data.isEmpty()) {
+            Log.i(TAG, "No data has been received yet, or the last data received was empty");
+            return false;
+        }
+
+        byte[] address = convertJSONArrayToByteArray(peerAddress);
+        if (Arrays.equals(data.get().getPeerAddress(), address)) {
+            return true;
+        } else {
+            Log.i(TAG, "Last ranging report did not include any data from peer "
+                    + Arrays.toString(address));
+            return false;
+        }
+    }
+
+    @Rpc(description = "Check whether uwb is enabled")
+    public boolean isUwbEnabled() {
+        return mUwbManager.isUwbEnabled();
+    }
+
+    @Rpc(description = "Set airplane mode")
+    public void setAirplaneMode(boolean enabled) {
+        mConnectivityManager.setAirplaneMode(enabled);
     }
 
     @Rpc(description = "Log info level message to device logcat")
diff --git a/generic_ranging/tests/multidevices/test_utils/uwb_test_utils.py b/generic_ranging/tests/multidevices/test_utils/uwb_test_utils.py
index 89944730..f8b5cd79 100644
--- a/generic_ranging/tests/multidevices/test_utils/uwb_test_utils.py
+++ b/generic_ranging/tests/multidevices/test_utils/uwb_test_utils.py
@@ -14,183 +14,141 @@
 """Test utils for UWB."""
 
 import logging
-import random
 import time
-from typing import List, Optional
+from typing import List
+
 from lib import generic_ranging_decorator
 from mobly import asserts
 from mobly.controllers import android_device
-from mobly.controllers.android_device_lib import adb
-from mobly.controllers.android_device_lib import callback_handler_v2
 
 WAIT_TIME_SEC = 3
 
 
-def verify_uwb_state_callback(
-        ad: android_device.AndroidDevice,
-        uwb_event: str,
-        handler: Optional[callback_handler_v2.CallbackHandlerV2] = None,
-        timeout: int = WAIT_TIME_SEC,
-) -> bool:
-    """Verifies expected UWB callback is received.
-
-    Args:
-      ad: android device object.
-      uwb_event: expected callback event.
-      handler: callback handler.
-      timeout: timeout for callback event.
-
-    Returns:
-      True if expected callback is received, False if not.
-    """
-    callback_status = False
-    callback_key = None
-    start_time = time.time()
-    if handler is None:
-        callback_key = "uwb_state_%s" % random.randint(1, 100)
-        handler = ad.uwb.registerUwbAdapterStateCallback(callback_key)
-    # wait until expected callback is received.
-    while time.time() - start_time < timeout and not callback_status:
-        time.sleep(0.1)
-        events = handler.getAll("UwbAdapterStateCallback")
-        for event in events:
-            event_received = event.data["uwbAdapterStateEvent"]
-            logging.debug("Received event - %s", event_received)
-            if event_received == uwb_event:
-                logging.debug("Received the '%s' callback in %ss", uwb_event,
-                              round(time.time() - start_time, 2))
-                callback_status = True
-                break
-    if callback_key is not None:
-        ad.uwb.unregisterUwbAdapterStateCallback(callback_key)
-    return callback_status
-
-
-def get_uwb_state(ad: android_device.AndroidDevice) -> bool:
-    """Gets the current UWB state.
-
-    Args:
-      ad: android device object.
-
-    Returns:
-      UWB state, True if enabled, False if not.
-    """
-    if ad.build_info["build_id"].startswith("S"):
-        uwb_state = bool(ad.uwb.getAdapterState())
-    else:
-        uwb_state = ad.uwb.isUwbEnabled()
-    return uwb_state
-
-
-def set_uwb_state_and_verify(
-        ad: android_device.AndroidDevice,
-        state: bool,
-        handler: Optional[callback_handler_v2.CallbackHandlerV2] = None,
+def assert_uwb_peer_found(
+    device: generic_ranging_decorator.GenericRangingDecorator,
+    peer_addr: List[int],
+    session_id: int,
+    timeout_s=WAIT_TIME_SEC,
 ):
-    """Sets UWB state to on or off and verifies it.
-
-    Args:
-      ad: android device object.
-      state: bool, True for UWB on, False for off.
-      handler: callback_handler.
-    """
-    failure_msg = "enabled" if state else "disabled"
-    ad.uwb.setUwbEnabled(state)
-    event_str = "Inactive" if state else "Disabled"
-    asserts.assert_true(verify_uwb_state_callback(ad, event_str, handler),
-                        "Uwb is not %s" % failure_msg)
-
-
-def verify_peer_found(ranging_dut: generic_ranging_decorator.GenericRangingDecorator,
-                      peer_addr: List[int], session: int = 0):
-    """Verifies if the UWB peer is found.
-
-    Args:
-      ranging_dut: uwb ranging device.
-      peer_addr: uwb peer device address.
-      session: session id.
-    """
-    ranging_dut.ad.log.info("Look for peer: %s" % peer_addr)
-    start_time = time.time()
-    while not ranging_dut.is_uwb_peer_found(peer_addr, session):
-        if time.time() - start_time > WAIT_TIME_SEC:
-            asserts.fail("UWB peer with address %s not found" % peer_addr)
-    logging.info("Peer %s found in %s seconds", peer_addr,
-                 round(time.time() - start_time, 2))
-
-
-def set_airplane_mode(ad: android_device.AndroidDevice, state: bool):
-    """Sets the airplane mode to the given state.
-
-    Args:
-      ad: android device object.
-      state: bool, True for Airplane mode on, False for off.
-    """
-    ad.uwb.setAirplaneMode(state)
-    start_time = time.time()
-    while get_airplane_mode(ad) != state:
-        time.sleep(0.5)
-        if time.time() - start_time > WAIT_TIME_SEC:
-            asserts.fail("Failed to set airplane mode to: %s" % state)
+  """Asserts that the UWB peer was found.
+
+  Args:
+    device: uwb ranging device.
+    peer_addr: uwb peer device address.
+    session_d: session id.
+    timeout_s: timeout in seconds.
+
+  Throws:
+      TimeoutError if peer could not be found
+  """
+  device.ad.log.info(f"Looking for peer {peer_addr}...")
+  if not device.verify_uwb_peer_found(
+      peer_addr, session_id, timeout_s=timeout_s
+  ):
+    raise TimeoutError(
+        f"Peer {peer_addr} not found before timeout expiry of"
+        f" {timeout_s} seconds"
+    )
 
 
-def get_airplane_mode(ad: android_device.AndroidDevice) -> bool:
-    """Gets the airplane mode.
+def initialize_uwb_country_code_if_necessary(ad: android_device.AndroidDevice):
+  """Sets UWB country code to US if the device does not have it set.
+
+  Note: This intentionally relies on an unstable API (shell command) since we
+  don't want to expose an API that allows users to circumvent the UWB
+  regulatory requirements.
 
-    Args:
-      ad: android device object.
+  Args:
+    ad: android device object.
+    handler: callback handler.
+  """
+  # Wait to see if UWB state is reported as enabled. If not, this could be
+  # because the country code is not set. Try forcing the country code in that
+  # case.
+  if is_uwb_enabled(ad, timeout_s=120):
+    return
 
-    Returns:
-      True if airplane mode On, False for Off.
-    """
-    state = ad.adb.shell(["settings", "get", "global", "airplane_mode_on"])
-    return bool(int(state.decode().strip()))
+  try:
+    ad.adb.shell(["cmd", "uwb", "force-country-code", "enabled", "US"])
+  except adb.AdbError:
+    logging.warning("Unable to force country code")
 
+  # Unable to get UWB enabled even after setting country code, abort!
+  asserts.fail(not is_uwb_enabled(ad, timeout_s=120), "Uwb is not enabled")
 
-def set_screen_rotation(ad: android_device.AndroidDevice, val: int):
-    """Sets screen orientation to landscape or portrait mode.
 
-    Args:
-      ad: android device object.
-      val: False for potrait, True 1 for landscape mode.
-    """
-    ad.adb.shell(["settings", "put", "system", "accelerometer_rotation", "0"])
-    ad.adb.shell(["settings", "put", "system", "user_rotation", str(val)])
+def is_uwb_enabled(
+    ad: android_device.AndroidDevice, timeout_s=WAIT_TIME_SEC
+) -> bool:
+  """Checks if UWB becomes enabled before the provided timeout_s"""
+  start_time = time.time()
+  while not ad.ranging.isUwbEnabled():
+    if time.time() - start_time > timeout_s:
+      return False
 
+  return True
 
-def initialize_uwb_country_code_if_not_set(
-        ad: android_device.AndroidDevice,
-        handler: Optional[callback_handler_v2.CallbackHandlerV2] = None,
-):
-    """Sets UWB country code to US if the device does not have it set.
-
-    Note: This intentionally relies on an unstable API (shell command) since we
-    don't want to expose an API that allows users to circumvent the UWB
-    regulatory requirements.
-
-    Args:
-      ad: android device object.
-      handler: callback handler.
-    """
-    # Wait to see if UWB state is reported as enabled. If not, this could be
-    # because the country code is not set. Try forcing the country code in that
-    # case.
-    state = verify_uwb_state_callback(
-        ad=ad, uwb_event="Inactive", handler=handler, timeout=120
-    )
 
-    # Country code already available, nothing to do.
-    if state:
-        return
-    try:
-        ad.adb.shell(["cmd", "uwb", "force-country-code", "enabled", "US"])
-    except adb.AdbError:
-        logging.warning("Unable to force country code")
-
-    # Unable to get UWB enabled even after setting country code, abort!
-    asserts.fail(
-        not verify_uwb_state_callback(
-            ad=ad, uwb_event="Inactive", handler=handler, timeout=120
-        ),
-        "Uwb is not enabled",
-    )
+def set_airplane_mode(ad: android_device.AndroidDevice, isEnabled: bool):
+  """Sets the airplane mode to the given state.
+
+  Args:
+    ad: android device object.
+    isEnabled: True for Airplane mode enabled, False for disabled.
+  """
+  ad.ranging.setAirplaneMode(isEnabled)
+  start_time = time.time()
+  while get_airplane_mode(ad) != isEnabled:
+    time.sleep(0.5)
+    if time.time() - start_time > WAIT_TIME_SEC:
+      asserts.fail(f"Failed to set airplane mode to: {isEnabled}")
+
+
+def get_airplane_mode(ad: android_device.AndroidDevice) -> bool:
+  """Gets the current airplane mode setting.
+
+  Args:
+    ad: android device object.
+
+  Returns:
+    True if airplane mode On, False for Off.
+  """
+  state = ad.adb.shell(["settings", "get", "global", "airplane_mode_on"])
+  return bool(int(state.decode().strip()))
+
+
+def set_screen_rotation_landscape(
+    ad: android_device.AndroidDevice, isLandscape: bool
+):
+  """Sets screen orientation to landscape or portrait mode.
+
+  Args:
+    ad: android device object.
+    isLandscape: True for landscape mode, False for potrait.
+  """
+  ad.adb.shell(["settings", "put", "system", "accelerometer_rotation", "0"])
+  ad.adb.shell([
+      "settings",
+      "put",
+      "system",
+      "user_rotation",
+      "1" if isLandscape else "0",
+  ])
+
+
+def set_snippet_foreground_state(
+    ad: android_device.AndroidDevice, isForeground: bool
+):
+  """Sets the snippet app's foreground/background state.
+
+  Args:
+    ad: android device object.
+    isForeground: True to move snippet to foreground, False for background.
+  """
+  ad.adb.shell([
+      "cmd",
+      "uwb",
+      "simulate-app-state-change",
+      "multidevices.snippet.ranging",
+      "foreground" if isForeground else "background",
+  ])
diff --git a/generic_ranging/tests/multidevices/uwb/AndroidTest.xml b/generic_ranging/tests/multidevices/uwb/AndroidTest.xml
index f8c04579..731d73cc 100644
--- a/generic_ranging/tests/multidevices/uwb/AndroidTest.xml
+++ b/generic_ranging/tests/multidevices/uwb/AndroidTest.xml
@@ -22,6 +22,11 @@
     <option name="config-descriptor:metadata" key="parameter" value="not_secondary_user" />
     <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.uwb.apex" />
 
+    <object class="com.android.tradefed.testtype.suite.module.DeviceFeatureModuleController"
+            type="module_controller">
+        <option name="required-feature" value="android.hardware.uwb" />
+    </object>
+
     <device name="device1">
         <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
             <option name="test-file-name" value="generic_ranging_snippet.apk" />
diff --git a/generic_ranging/tests/multidevices/uwb/uwb_ranging_params.py b/generic_ranging/tests/multidevices/uwb/uwb_ranging_params.py
index 6de181a6..44d46c28 100644
--- a/generic_ranging/tests/multidevices/uwb/uwb_ranging_params.py
+++ b/generic_ranging/tests/multidevices/uwb/uwb_ranging_params.py
@@ -1,285 +1,167 @@
-"""Class for UWB ranging parameters."""
+"""Class for UWB ranging parameters for testing."""
 
 import dataclasses
+from enum import IntEnum
 from typing import Any, Dict, List, Optional
 
 
-class FiraParamEnums:
-    """Class for Fira parameter constants."""
+class Constants:
+  """Class for ranging parameter constants."""
 
-    # channels
-    UWB_CHANNEL_5 = 5
-    UWB_CHANNEL_9 = 9
+  class DeviceRole(IntEnum):
+    CONTROLEE = 0
+    CONTROLLER = 1
 
-    # preamble codes
-    UWB_PREAMBLE_CODE_INDEX_9 = 9
-    UWB_PREAMBLE_CODE_INDEX_10 = 10
-    UWB_PREAMBLE_CODE_INDEX_11 = 11
-    UWB_PREAMBLE_CODE_INDEX_12 = 12
+  class ConfigType(IntEnum):
+    UNICAST_DS_TWR = 1
+    MULTICAST_DS_TWR = 2
+    PROVISIONED_UNICAST_DS_TWR = 4
+    PROVISIONED_MULTICAST_DS_TWR = 5
+    PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR = 7
 
-    # ranging device types
-    DEVICE_TYPE_CONTROLEE = 0
-    DEVICE_TYPE_CONTROLLER = 1
+  class RangingUpdateRate(IntEnum):
+    AUTOMATIC = 1
+    INFREQUENT = 2
+    FREQUENT = 3
 
-    # ranging device roles
-    DEVICE_ROLE_RESPONDER = 0
-    DEVICE_ROLE_INITIATOR = 1
+  class SlotDuration(IntEnum):
+    MILLIS_1 = 1
+    MILLIS_2 = 2
 
-    # multi node modes
-    MULTI_NODE_MODE_UNICAST = 0
-    MULTI_NODE_MODE_ONE_TO_MANY = 1
+  class RangeDataConfigType(IntEnum):
+    """Distance-based notifications are not supported in tests-- only accepted values are ENABLE or DISABLE."""
 
-    # hopping modes
-    HOPPING_MODE_DISABLE = 0
-    HOPPING_MODE_FIRA_HOPPING_ENABLE = 1
-
-    # ranging round usage
-    RANGING_ROUND_USAGE_SS_TWR_DEFERRED_MODE = 1
-    RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE = 2
-    RANGING_ROUND_USAGE_SS_TWR_NON_DEFERRED_MODE = 3
-    RANGING_ROUND_USAGE_DS_TWR_NON_DEFERRED_MODE = 4
-
-    # mac address mode
-    MAC_ADDRESS_MODE_2_BYTES = 0
-    MAC_ADDRESS_MODE_8_BYTES = 2
-
-    # initiation time in ms
-    INITIATION_TIME_MS = 0
-
-    # slot duration rstu
-    SLOT_DURATION = 2
-
-    # ranging interval ms
-    RANGING_INTERVAL_MS = 200
-
-    # slots per ranging round
-    SLOTS_PER_RR = 30
-
-    # in band termination attempt count
-    IN_BAND_TERMINATION_ATTEMPT_COUNT = 1
-
-    # aoa report request
-    AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT = 0
-    AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS = 1
-
-    # ranging round retries
-    MAX_RANGING_ROUND_RETRIES = 0
-
-    # block stride
-    BLOCK_STRIDE_LENGTH = 0
-
-    # list update actions
-    MULTICAST_LIST_UPDATE_ACTION_ADD = 0
-    MULTICAST_LIST_UPDATE_ACTION_DELETE = 1
-    P_STS_MULTICAST_LIST_UPDATE_ACTION_ADD_16_BYTE = 2
-    P_STS_MULTICAST_LIST_UPDATE_ACTION_ADD_32_BYTE = 3
-
-    # sts config
-    STS_CONFIG_STATIC = 0
-    STS_CONFIG_PROVISIONED = 3
-    STS_CONFIG_PROVISIONED_FOR_CONTROLEE_INDIVIDUAL_KEY = 4
+    DISABLE = 0
+    ENABLE = 1
 
 
+# TODO(b/349419138): Dead code
 @dataclasses.dataclass
-class UwbRangingReconfigureParams():
-    """Class for UWB ranging reconfigure parameters.
-
-    Attributes:
-      action: Type of reconfigure action.
-      address_list: new address list.
-      block_stride_length: block stride length
-      sub_session_id_list: provisioned sts sub session id list.
-      sub_session_key_list: provisioned sts sub session key list.
+class UwbRangingReconfigureParams:
+  """Class for UWB ranging reconfigure parameters.
+
+  Attributes:
+    action: Type of reconfigure action.
+    address_list: new address list.
+    block_stride_length: block stride length
+    sub_session_id_list: provisioned sts sub session id list.
+    sub_session_key_list: provisioned sts sub session key list.
+  """
+
+  action: Optional[int] = None
+  address_list: Optional[List[List[int]]] = None
+  block_stride_length: Optional[int] = None
+  sub_session_id_list: Optional[List[int]] = None
+  sub_session_key_list: Optional[List[int]] = None
+
+  def to_dict(self) -> Dict[str, Any]:
+    """Returns UWB ranging reconfigure parameters in dictionary for sl4a.
+
+    Returns:
+      UWB ranging reconfigure parameters in dictionary.
     """
-    action: Optional[int] = None
-    address_list: Optional[List[List[int]]] = None
-    block_stride_length: Optional[int] = None
-    sub_session_id_list: Optional[List[int]] = None
-    sub_session_key_list: Optional[List[int]] = None
-
-    def to_dict(self) -> Dict[str, Any]:
-        """Returns UWB ranging reconfigure parameters in dictionary for sl4a.
-
-        Returns:
-          UWB ranging reconfigure parameters in dictionary.
-        """
-        reconfigure_params = {}
-        if self.address_list is not None:
-            reconfigure_params["action"] = self.action
-            reconfigure_params["addressList"] = self.address_list
-            if self.sub_session_id_list is not None:
-                reconfigure_params["subSessionIdList"] = self.sub_session_id_list
-            if self.sub_session_key_list is not None:
-                reconfigure_params["subSessionKeyList"] = self.sub_session_key_list
-        elif self.block_stride_length is not None:
-            reconfigure_params["blockStrideLength"] = self.block_stride_length
-        return reconfigure_params
-
-
+    reconfigure_params = {}
+    if self.address_list is not None:
+      reconfigure_params["action"] = self.action
+      reconfigure_params["addressList"] = self.address_list
+      if self.sub_session_id_list is not None:
+        reconfigure_params["subSessionIdList"] = self.sub_session_id_list
+      if self.sub_session_key_list is not None:
+        reconfigure_params["subSessionKeyList"] = self.sub_session_key_list
+    elif self.block_stride_length is not None:
+      reconfigure_params["blockStrideLength"] = self.block_stride_length
+    return reconfigure_params
+
+
+# TODO(b/349419138): Dead code
 @dataclasses.dataclass
-class UwbRangingControleeParams():
-    """Class for UWB ranging controlee parameters.
-
-    Attributes:
-      action: Type of reconfigure action.
-      address_list: new address list.
-      sub_session_id_list: provisioned sts sub session id list.
-      sub_session_key_list: provisioned sts sub session key list.
+class UwbRangingControleeParams:
+  """Class for UWB ranging controlee parameters.
+
+  Attributes:
+    action: Type of reconfigure action.
+    address_list: new address list.
+    sub_session_id_list: provisioned sts sub session id list.
+    sub_session_key_list: provisioned sts sub session key list.
+  """
+
+  action: Optional[int] = None
+  address_list: Optional[List[List[int]]] = None
+  sub_session_id_list: Optional[List[int]] = None
+  sub_session_key_list: Optional[List[int]] = None
+
+  def to_dict(self) -> Dict[str, Any]:
+    """Returns UWB ranging controlee parameters in dictionary for sl4a.
+
+    Returns:
+      UWB ranging controlee parameters in dictionary.
     """
-    action: Optional[int] = None
-    address_list: Optional[List[List[int]]] = None
-    sub_session_id_list: Optional[List[int]] = None
-    sub_session_key_list: Optional[List[int]] = None
-
-    def to_dict(self) -> Dict[str, Any]:
-        """Returns UWB ranging controlee parameters in dictionary for sl4a.
-
-        Returns:
-          UWB ranging controlee parameters in dictionary.
-        """
-        controlee_params = {}
-        if self.action is not None:
-            controlee_params["action"] = self.action
-        if self.address_list is not None:
-            controlee_params["addressList"] = self.address_list
-        if self.sub_session_id_list is not None:
-            controlee_params["subSessionIdList"] = self.sub_session_id_list
-        if self.sub_session_key_list is not None:
-            controlee_params["subSessionKeyList"] = self.sub_session_key_list
-        return controlee_params
-
-
-@dataclasses.dataclass
-class UwbRangingParams():
-    """Class for Uwb ranging parameters.
-
-    Attributes:
-      device_type: Type of ranging device - Controller or Controlee.
-      device_role: Role of ranging device - Initiator or Responder.
-      device_address: Address of the UWB device.
-      destination_addresses: List of UWB peer addresses.
-      channel: Channel for ranging. Possible values 5 or 9.
-      preamble: Preamble for ranging.
-      ranging_round_usage : Ranging Round Usage values.
-      hopping_mode : Hopping modes.
-      mac_address_mode : MAC address modes.
-      initiation_time_ms : Initiation Time in ms.
-      slot_duration_rstu : Slot duration RSTU.
-      ranging_interval_ms : Ranging interval in ms.
-      slots_per_ranging_round : Slots per Ranging Round.
-      in_band_termination_attempt_count : In Band Termination Attempt count.
-      aoa_result_request : AOA report request.
-      max_ranging_round_retries : Max Ranging round retries.
-      block_stride_length: Block Stride Length
-      session_id: Ranging session ID.
-      multi_node_mode: Ranging mode. Possible values 1 to 1 or 1 to many.
-      vendor_id: Ranging device vendor ID.
-      static_sts_iv: Static STS value.
-      sts_config: STS config.
-      session_key: Provisioned sts session key.
-      sub_session_id: Ranging sub session ID.
-      sub_session_key: Ranging sub session key.
-
-    Example:
-        An example of UWB ranging parameters passed to sl4a is below.
-
-        self.initiator_params = {
-          "sessionId": 10,
-          "deviceType": FiraParamEnums.RANGING_DEVICE_TYPE_CONTROLLER,
-          "deviceRole": FiraParamEnums.RANGING_DEVICE_ROLE_INITIATOR,
-          "multiNodeMode": FiraParamEnums.MULTI_NODE_MODE_ONE_TO_MANY,
-          "channel": FiraParamEnums.UWB_CHANNEL_9,
-          "deviceAddress": [1, 2],
-          "destinationAddresses": [[3, 4],],
-          "vendorId": [5, 6],
-          "staticStsIV": [5, 6, 7, 8, 9, 10],
-        }
-
-        The UwbRangingParams are passed to UwbManagerFacade#openRaningSession()
-        from the open_ranging() method as a JSONObject.
-        These are converted to FiraOpenSessionParams using
-        UwbManagerFacade#generateFiraOpenSessionParams().
-        If some of the values are skipped in the params, default values are used.
-        Please see com/google/uwb/support/fira/FiraParams.java for more details
-        on the default values.
-
-        If the passed params are invalid, then open_ranging() will fail.
+    controlee_params = {}
+    if self.action is not None:
+      controlee_params["action"] = self.action
+    if self.address_list is not None:
+      controlee_params["addressList"] = self.address_list
+    if self.sub_session_id_list is not None:
+      controlee_params["subSessionIdList"] = self.sub_session_id_list
+    if self.sub_session_key_list is not None:
+      controlee_params["subSessionKeyList"] = self.sub_session_key_list
+    return controlee_params
+
+
+@dataclasses.dataclass(kw_only=True)
+class UwbRangingParams:
+  """Class for Uwb ranging parameters."""
+
+  config_type: Constants.ConfigType
+  session_id: int
+  sub_session_id: int = 0
+  session_key_info: List[int] = dataclasses.field(
+      default_factory=lambda: [1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1]
+  )
+  sub_session_key_info: Optional[List[int]] = None
+  peer_addresses: List[List[int]]
+  update_rate_type: Constants.RangingUpdateRate = (
+      Constants.RangingUpdateRate.AUTOMATIC
+  )
+  range_data_config_type: Constants.RangeDataConfigType = (
+      Constants.RangeDataConfigType.ENABLE
+  )
+  slot_duration_millis: Constants.SlotDuration = Constants.SlotDuration.MILLIS_2
+  is_aoa_disabled: bool = False
+  device_address: List[int]
+  device_role: Constants.DeviceRole
+
+  def to_dict(self) -> Dict[str, Any]:
+    """Returns UWB ranging parameters in dictionary for sl4a.
+
+    Returns:
+      UWB ranging parameters in dictionary.
     """
-
-    config_id: int
-    device_type: int
-    device_role: int
-    device_address: List[int]
-    destination_addresses: List[List[int]]
-    session_id: int = 10
-    channel: int = FiraParamEnums.UWB_CHANNEL_9
-    preamble: int = FiraParamEnums.UWB_PREAMBLE_CODE_INDEX_11
-    multi_node_mode: int = FiraParamEnums.MULTI_NODE_MODE_ONE_TO_MANY
-    ranging_round_usage: int = (
-        FiraParamEnums.RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE
-    )
-    mac_address_mode: int = FiraParamEnums.MAC_ADDRESS_MODE_2_BYTES
-    initiation_time_ms: int = FiraParamEnums.INITIATION_TIME_MS
-    slot_duration: int = FiraParamEnums.SLOT_DURATION
-    ranging_update_rate: int = 1
-    slots_per_ranging_round: int = FiraParamEnums.SLOTS_PER_RR
-    in_band_termination_attempt_count: int = (
-        FiraParamEnums.IN_BAND_TERMINATION_ATTEMPT_COUNT
-    )
-    aoa_result_request: int = (
-        FiraParamEnums.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS
-    )
-    hopping_mode: int = FiraParamEnums.HOPPING_MODE_FIRA_HOPPING_ENABLE
-    max_ranging_round_retries: int = FiraParamEnums.MAX_RANGING_ROUND_RETRIES
-    block_stride_length: int = FiraParamEnums.BLOCK_STRIDE_LENGTH
-    vendor_id: List[int] = dataclasses.field(default_factory=lambda: [5, 6])
-    static_sts_iv: List[int] = dataclasses.field(
-        default_factory=lambda: [5, 6, 7, 8, 9, 10])
-    sts_config: int = FiraParamEnums.STS_CONFIG_STATIC
-    session_key: List[int] = dataclasses.field(
-        default_factory=lambda: [1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1]
-    )
-    sub_session_id: Optional[int] = None
-    sub_session_key: Optional[List[int]] = None
-    is_aoa_disabled: bool = False
-
-    def to_dict(self) -> Dict[str, Any]:
-        """Returns UWB ranging parameters in dictionary for sl4a.
-
-        Returns:
-          UWB ranging parameters in dictionary.
-        """
-        dict = {
-            "configId": self.config_id,
-            "deviceType": self.device_type,
-            "deviceRole": self.device_role,
-            "deviceAddress": self.device_address,
-            "destinationAddresses": self.destination_addresses,
-            "channel": self.channel,
-            "preamble": self.preamble,
-            "slotDuration": self.slot_duration,
-            "rangingUpdateRate": self.ranging_update_rate,
-            "sessionId": self.session_id,
-            "subSessionId": self.sub_session_id,
-            "multiNodeMode": self.multi_node_mode,
-            "vendorId": self.vendor_id,
-            "staticStsIV": self.static_sts_iv,
-            "stsConfig": self.sts_config,
-            "sessionKey": self.session_key,
-            "isAoaDisabled": self.is_aoa_disabled,
-        }
-        if self.sub_session_id is not None:
-            dict["subSessionId"] = self.sub_session_id
-        if self.sub_session_key is not None:
-            dict["subSessionKey"] = self.sub_session_key
-        return dict
-
-    def update(self, **kwargs: Any):
-        """Updates the UWB parameters with the new values.
-
-        Args:
-          **kwargs: uwb attributes with new values.
-        """
-        for key, value in kwargs.items():
-            if hasattr(self, key):
-                setattr(self, key, value)
+    dict = {
+        "configType": self.config_type,
+        "sessionId": self.session_id,
+        "subSessionId": self.sub_session_id,
+        "sessionKeyInfo": self.session_key_info,
+        "peerAddresses": self.peer_addresses,
+        "updateRateType": self.update_rate_type,
+        "rangeDataConfigType": self.range_data_config_type,
+        "slotDurationMillis": self.slot_duration_millis,
+        "isAoaDisabled": self.is_aoa_disabled,
+        "deviceAddress": self.device_address,
+        "deviceRole": self.device_role,
+    }
+
+    if self.sub_session_key_info is not None:
+      dict["subSessionKeyInfo"] = self.sub_session_key_info
+
+    return dict
+
+  def update(self, **kwargs: Any):
+    """Updates the UWB parameters with the new values.
+
+    Args:
+      **kwargs: uwb attributes with new values.
+    """
+    for key, value in kwargs.items():
+      if hasattr(self, key):
+        setattr(self, key, value)
diff --git a/generic_ranging/tests/multidevices/uwb/uwb_tests.py b/generic_ranging/tests/multidevices/uwb/uwb_tests.py
index caa31ccb..fa516f4f 100644
--- a/generic_ranging/tests/multidevices/uwb/uwb_tests.py
+++ b/generic_ranging/tests/multidevices/uwb/uwb_tests.py
@@ -11,105 +11,194 @@
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions and
 #  limitations under the License.
-import random
 import sys
-import threading
 import time
-from typing import List, Optional
 
-from uwb import uwb_ranging_params
-from lib import ranging_base_test
 from lib import generic_ranging_decorator
+from lib import ranging_base_test
 from mobly import asserts
 from mobly import config_parser
-from mobly import signals
 from mobly import suite_runner
 from test_utils import uwb_test_utils
+from uwb import uwb_ranging_params as params
 
 RESPONDER_STOP_CALLBACK_TIMEOUT = 60
 
 _TEST_CASES = (
     "test_one_to_one_ranging",
+    "test_one_to_one_ranging_provisioned_sts",
+    "test_one_to_one_ranging_disable_range_data_ntf",
 )
 
 
 class RangingTest(ranging_base_test.RangingBaseTest):
-    """Tests for UWB Ranging APIs.
+  """Tests for UWB Ranging APIs.
 
-    Attributes:
-    android_devices: list of android device objects.
-    """
+  Attributes:
+
+  android_devices: list of android device objects.
+  """
 
-    def __init__(self, configs: config_parser.TestRunConfig):
-        """Init method for the test class.
-
-        Args:
-        configs: A config_parser.TestRunConfig object.
-        """
-        super().__init__(configs)
-        self.tests = _TEST_CASES
-
-    def setup_class(self):
-        super().setup_class()
-        self.uwb_devices = [
-            generic_ranging_decorator.GenericRangingDecorator(ad)
-            for ad in self.android_devices
-        ]
-        self.initiator, self.responder = self.uwb_devices
-        self.device_addresses = self.user_params.get("device_addresses",
-                                                     [[1, 2], [3, 4]])
-        self.initiator_addr, self.responder_addr = self.device_addresses
-        self.new_responder_addr = [4, 5]
-        # self.p_sts_sub_session_id = 11
-        # self.p_sts_sub_session_key = [
-        #     8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8]
-        # self.block_stride_length = random.randint(1, 10)
-
-    def setup_test(self):
-        super().setup_test()
-        # for uwb_device in self.uwb_devices:
-        #     try:
-        #         uwb_device.close_ranging()
-        #     except TimeoutError:
-        #         uwb_device.log.warn("Failed to cleanup ranging sessions")
-        # for uwb_device in self.uwb_devices:
-        #     uwb_test_utils.set_airplane_mode(uwb_device.ad, False)
-        #     self._reset_snippet_fg_bg_state(uwb_device)
-
-    def teardown_test(self):
-        super().teardown_test()
-
-    ### Test Cases ###
-
-    def test_one_to_one_ranging(self):
-        initiator_params = uwb_ranging_params.UwbRangingParams(
-            config_id=1,
-            session_id=5,
-            sub_session_id=1,
-            device_role=uwb_ranging_params.FiraParamEnums.DEVICE_ROLE_INITIATOR,
-            device_type=uwb_ranging_params.FiraParamEnums.DEVICE_TYPE_CONTROLLER,
-            device_address=self.initiator_addr,
-            destination_addresses=[self.responder_addr],
-        )
-        responder_params = uwb_ranging_params.UwbRangingParams(
-            config_id=1,
-            session_id=5,
-            sub_session_id=1,
-            device_role=uwb_ranging_params.FiraParamEnums.DEVICE_ROLE_RESPONDER,
-            device_type=uwb_ranging_params.FiraParamEnums.DEVICE_TYPE_CONTROLEE,
-            device_address=self.responder_addr,
-            destination_addresses=[self.initiator_addr],
-        )
-        self.initiator.start_uwb_ranging(initiator_params)
-        self.responder.start_uwb_ranging(responder_params)
-
-        time.sleep(20)
-        self.initiator.stop_uwb_ranging(initiator_params)
-        self.responder.stop_uwb_ranging(responder_params)
+  def __init__(self, configs: config_parser.TestRunConfig):
+    """Init method for the test class.
+
+    Args:
+
+    configs: A config_parser.TestRunConfig object.
+    """
+    super().__init__(configs)
+    self.tests = _TEST_CASES
+
+  def setup_class(self):
+    super().setup_class()
+    self.uwb_devices = [
+        generic_ranging_decorator.GenericRangingDecorator(ad)
+        for ad in self.android_devices
+    ]
+    self.initiator, self.responder = self.uwb_devices
+    self.device_addresses = self.user_params.get(
+        "device_addresses", [[1, 2], [3, 4]]
+    )
+    self.initiator_addr, self.responder_addr = self.device_addresses
+    self.new_responder_addr = [4, 5]
+    # self.p_sts_sub_session_id = 11
+    # self.p_sts_sub_session_key = [
+    #     8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8]
+    # self.block_stride_length = random.randint(1, 10)
+
+  def setup_test(self):
+    super().setup_test()
+    for uwb_device in self.uwb_devices:
+      uwb_test_utils.set_airplane_mode(uwb_device.ad, isEnabled=False)
+      uwb_test_utils.set_snippet_foreground_state(
+          uwb_device.ad, isForeground=True
+      )
+
+  def teardown_test(self):
+    super().teardown_test()
+    for uwb_device in self.uwb_devices:
+      uwb_device.clear_all_uwb_ranging_sessions()
+
+  ### Helpers ###
+
+  def _start_and_verify_mutual_ranging(
+      self,
+      initiator_params: params.UwbRangingParams,
+      responder_params: params.UwbRangingParams,
+      session_id: int,
+  ):
+    """Starts one-to-one ranging session between initiator and responder.
+
+    Args:
+        session_id: id to use for the ranging session.
+    """
+    self.initiator.start_uwb_ranging_session(initiator_params)
+    self.responder.start_uwb_ranging_session(responder_params)
+
+    uwb_test_utils.assert_uwb_peer_found(
+        self.initiator, self.responder_addr, session_id
+    )
+    uwb_test_utils.assert_uwb_peer_found(
+        self.responder, self.initiator_addr, session_id
+    )
+
+  ### Test Cases ###
+
+  def test_one_to_one_ranging(self):
+    """Verifies ranging with peer device, devices range for 10 seconds."""
+    initiator_params = params.UwbRangingParams(
+        config_type=params.Constants.ConfigType.UNICAST_DS_TWR,
+        session_id=5,
+        peer_addresses=[self.responder_addr],
+        device_address=self.initiator_addr,
+        device_role=params.Constants.DeviceRole.CONTROLLER,
+    )
+    responder_params = params.UwbRangingParams(
+        config_type=params.Constants.ConfigType.UNICAST_DS_TWR,
+        session_id=5,
+        peer_addresses=[self.initiator_addr],
+        device_address=self.responder_addr,
+        device_role=params.Constants.DeviceRole.CONTROLEE,
+    )
+    self._start_and_verify_mutual_ranging(
+        initiator_params, responder_params, session_id=5
+    )
+
+    time.sleep(10)
+
+    uwb_test_utils.assert_uwb_peer_found(
+        self.initiator, self.responder_addr, session_id=5
+    )
+    uwb_test_utils.assert_uwb_peer_found(
+        self.responder, self.initiator_addr, session_id=5
+    )
+
+    self.initiator.stop_uwb_ranging_session(session_id=5)
+    self.responder.stop_uwb_ranging_session(session_id=5)
+
+  def test_one_to_one_ranging_provisioned_sts(self):
+    """Verifies ranging with peer device using provisioned sts"""
+    initiator_params = params.UwbRangingParams(
+        config_type=params.Constants.ConfigType.PROVISIONED_UNICAST_DS_TWR,
+        session_id=5,
+        peer_addresses=[self.responder_addr],
+        device_address=self.initiator_addr,
+        device_role=params.Constants.DeviceRole.CONTROLLER,
+    )
+    responder_params = params.UwbRangingParams(
+        config_type=params.Constants.ConfigType.PROVISIONED_UNICAST_DS_TWR,
+        session_id=5,
+        peer_addresses=[self.initiator_addr],
+        device_address=self.responder_addr,
+        device_role=params.Constants.DeviceRole.CONTROLEE,
+    )
+
+    self._start_and_verify_mutual_ranging(
+        initiator_params, responder_params, session_id=5
+    )
+
+    self.initiator.stop_uwb_ranging_session(session_id=5)
+    self.responder.stop_uwb_ranging_session(session_id=5)
+
+  def test_one_to_one_ranging_disable_range_data_ntf(self):
+    """Verifies device does not receive range data after disabling range data notifications"""
+    initiator_params = params.UwbRangingParams(
+        config_type=params.Constants.ConfigType.UNICAST_DS_TWR,
+        session_id=5,
+        peer_addresses=[self.responder_addr],
+        device_address=self.initiator_addr,
+        device_role=params.Constants.DeviceRole.CONTROLLER,
+        range_data_config_type=params.Constants.RangeDataConfigType.DISABLE,
+    )
+    responder_params = params.UwbRangingParams(
+        config_type=params.Constants.ConfigType.UNICAST_DS_TWR,
+        session_id=5,
+        peer_addresses=[self.initiator_addr],
+        device_address=self.responder_addr,
+        device_role=params.Constants.DeviceRole.CONTROLEE,
+        range_data_config_type=params.Constants.RangeDataConfigType.ENABLE,
+    )
+
+    self.initiator.start_uwb_ranging_session(initiator_params)
+    self.responder.start_uwb_ranging_session(responder_params)
+
+    try:
+      uwb_test_utils.assert_uwb_peer_found(
+          self.initiator, self.responder_addr, session_id=5
+      )
+      asserts.fail((
+          "Initiator found responder even though initiator has range data"
+          "notifications disabled"
+      ))
+    except TimeoutError:
+      pass
+    uwb_test_utils.assert_uwb_peer_found(
+        self.responder, self.initiator_addr, session_id=5
+    )
 
 
 if __name__ == "__main__":
-    if "--" in sys.argv:
-        index = sys.argv.index("--")
-        sys.argv = sys.argv[:1] + sys.argv[index + 1:]
-    suite_runner.run_suite([RangingTest])
+  if "--" in sys.argv:
+    index = sys.argv.index("--")
+    sys.argv = sys.argv[:1] + sys.argv[index + 1 :]
+  suite_runner.run_suite([RangingTest])
diff --git a/generic_ranging/tests/units/Android.bp b/generic_ranging/tests/units/Android.bp
new file mode 100644
index 00000000..90367bba
--- /dev/null
+++ b/generic_ranging/tests/units/Android.bp
@@ -0,0 +1,36 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "GenericRangingTests",
+    srcs: ["src/**/*.java"],
+    sdk_version: "34",
+    certificate: "platform",
+    static_libs: [
+        "generic_ranging",
+        "framework-uwb.stubs.module_lib",
+        "androidx.test.rules",
+        "androidx.test.ext.junit",
+        "androidx.test.runner",
+        "mockito-target-minus-junit4",
+    ],
+    test_suites: ["device-tests"],
+}
diff --git a/generic_ranging/tests/units/AndroidManifest.xml b/generic_ranging/tests/units/AndroidManifest.xml
new file mode 100644
index 00000000..b763a898
--- /dev/null
+++ b/generic_ranging/tests/units/AndroidManifest.xml
@@ -0,0 +1,33 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2024 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+
+<manifest
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.ranging.tests" >
+
+    <uses-sdk android:minSdkVersion="34" android:targetSdkVersion="34" />
+
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation
+        android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:targetPackage="com.android.ranging.tests"
+        android:label="Generic Ranging Unit Tests" >
+    </instrumentation>
+</manifest>
\ No newline at end of file
diff --git a/generic_ranging/tests/units/AndroidTest.xml b/generic_ranging/tests/units/AndroidTest.xml
new file mode 100644
index 00000000..172c8c63
--- /dev/null
+++ b/generic_ranging/tests/units/AndroidTest.xml
@@ -0,0 +1,37 @@
+<?xml version="1.0" encoding="utf-8"?>
+
+<!--
+  Copyright 2024 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+
+<configuration description="Configuration for Generic Ranging unit tests">
+    <option name="test-suite-tag" value="apct" />
+    <option name="config-descriptor:metadata" key="component" value="systems" />
+    <option name="config-descriptor:metadata" key="parameter" value="instant_app" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
+    <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.uwb.apex" />
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="GenericRangingTests.apk" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="com.android.ranging.tests" />
+    </test>
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
+        <option name="mainline-module-package-name" value="com.google.android.uwb" />
+    </object>
+</configuration>
\ No newline at end of file
diff --git a/generic_ranging/tests/units/OWNERS b/generic_ranging/tests/units/OWNERS
new file mode 100644
index 00000000..4c4edca9
--- /dev/null
+++ b/generic_ranging/tests/units/OWNERS
@@ -0,0 +1 @@
+include platform/packages/modules/Uwb:/OWNERS
diff --git a/generic_ranging/tests/units/src/com/android/ranging/tests/RangingSessionTest.java b/generic_ranging/tests/units/src/com/android/ranging/tests/RangingSessionTest.java
new file mode 100644
index 00000000..5c52fd92
--- /dev/null
+++ b/generic_ranging/tests/units/src/com/android/ranging/tests/RangingSessionTest.java
@@ -0,0 +1,264 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.tests;
+
+import static com.android.ranging.RangingTechnology.CS;
+import static com.android.ranging.RangingTechnology.UWB;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.content.pm.PackageManager;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.ranging.RangingAdapter;
+import com.android.ranging.RangingConfig;
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingParameters;
+import com.android.ranging.RangingParameters.DeviceRole;
+import com.android.ranging.RangingSession;
+import com.android.ranging.RangingSessionImpl;
+import com.android.ranging.RangingTechnology;
+import com.android.ranging.cs.CsParameters;
+import com.android.ranging.fusion.DataFusers;
+import com.android.ranging.fusion.FilteringFusionEngine;
+import com.android.ranging.uwb.UwbParameters;
+
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Before;
+import org.junit.Ignore;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Answers;
+import org.mockito.ArgumentCaptor;
+import org.mockito.InOrder;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+
+import java.time.Duration;
+import java.util.EnumMap;
+import java.util.concurrent.ScheduledExecutorService;
+
+@RunWith(JUnit4.class)
+@SmallTest
+public class RangingSessionTest {
+    @Rule public final MockitoRule mMockito = MockitoJUnit.rule();
+
+    @Mock(answer = Answers.RETURNS_DEEP_STUBS) private Context mMockContext;
+    @Mock private RangingConfig mMockConfig;
+    @Mock
+    private ScheduledExecutorService mMockTimeoutExecutor;
+
+    @Mock private RangingSession.Callback mMockCallback;
+    private final EnumMap<RangingTechnology, RangingAdapter> mMockAdapters =
+            new EnumMap<>(RangingTechnology.class);
+
+    private RangingSessionImpl mSession;
+
+    /**
+     * Starts a ranging session with the provided parameters.
+     * @param params to use for the session.
+     * @return {@link RangingAdapter.Callback} for each of the provided technologies' adapters.
+     * These callbacks are captured from underlying {@link RangingAdapter} mock for each technology.
+     */
+    private EnumMap<RangingTechnology, RangingAdapter.Callback> startSession(
+            RangingParameters params
+    ) {
+        EnumMap<RangingTechnology, RangingAdapter.Callback> adapterCallbacks =
+                new EnumMap<>(RangingTechnology.class);
+
+        mSession.start(params, mMockCallback);
+
+        for (RangingTechnology technology : params.asMap().keySet()) {
+            ArgumentCaptor<RangingAdapter.Callback> callbackCaptor =
+                    ArgumentCaptor.forClass(RangingAdapter.Callback.class);
+            verify(mMockAdapters.get(technology)).start(any(), callbackCaptor.capture());
+            callbackCaptor.getValue().onStarted();
+            adapterCallbacks.put(technology, callbackCaptor.getValue());
+        }
+
+        return adapterCallbacks;
+    }
+
+    /** @param technology to generate data for */
+    private RangingData generateData(RangingTechnology technology) {
+        return new RangingData.Builder()
+                .setTechnology(technology)
+                .setRangeDistance(123)
+                .setTimestamp(Duration.ofSeconds(1))
+                .setPeerAddress(new byte[]{0x1, 0x2})
+                .build();
+    }
+
+    @Before
+    public void setup() {
+        when(mMockContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_UWB))
+                .thenReturn(true);
+        when(mMockConfig.getInitTimeout()).thenReturn(Duration.ZERO);
+        when(mMockConfig.getNoUpdateTimeout()).thenReturn(Duration.ZERO);
+        when(mMockConfig.getUseFusingAlgorithm()).thenReturn(true);
+
+        mSession = new RangingSessionImpl(
+                mMockContext, mMockConfig,
+                new FilteringFusionEngine(new DataFusers.PassthroughDataFuser()),
+                mMockTimeoutExecutor,
+                MoreExecutors.newDirectExecutorService());
+
+        for (RangingTechnology technology : RangingTechnology.values()) {
+            RangingAdapter adapter = mock(RangingAdapter.class);
+            mMockAdapters.put(technology, adapter);
+            mSession.useAdapterForTesting(technology, adapter);
+        }
+    }
+
+    @Test
+    public void start_startsTechnologyThenSession() {
+        InOrder inOrder = Mockito.inOrder(mMockCallback);
+
+        EnumMap<RangingTechnology, RangingAdapter.Callback> adapterCallbacks =
+                startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                        .useUwb(mock(UwbParameters.class))
+                        .build());
+
+        inOrder.verify(mMockCallback).onStarted(eq(UWB));
+        verify(mMockCallback, never()).onStarted(eq(null));
+
+        adapterCallbacks.get(UWB).onRangingData(generateData(UWB));
+        inOrder.verify(mMockCallback).onStarted(eq(null));
+    }
+
+    @Test
+    @Ignore("TODO: Add support for technologies other than UWB")
+    public void start_startsMultipleTechnologies() {
+        startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                        .useUwb(mock(UwbParameters.class))
+                        .useCs(mock(CsParameters.class))
+                        .build());
+
+//        verify(mMockCallback).onStarted(eq(null));
+        verify(mMockCallback).onStarted(eq(UWB));
+        verify(mMockCallback).onStarted(eq(CS));
+    }
+
+    @Test
+    public void start_doesNotStartUnsupportedTechnologies() {
+        when(mMockContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_UWB))
+                .thenReturn(false);
+
+        mSession.start(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                        .useUwb(mock(UwbParameters.class))
+                        .build(),
+                mMockCallback);
+
+        verify(mMockAdapters.get(UWB), never()).start(any(), any());
+        verify(mMockCallback, never()).onStarted(any());
+    }
+
+    @Test
+    public void start_doesNotStartUnusedTechnologies() {
+        startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                .useUwb(mock(UwbParameters.class))
+                .build());
+
+        verify(mMockAdapters.get(CS), never()).start(any(), any());
+        verify(mMockCallback, never()).onStarted(eq(CS));
+    }
+
+    @Test
+    public void stop_stopsTechnologyAndSession() {
+        InOrder inOrder = Mockito.inOrder(mMockCallback);
+
+        startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                .useUwb(mock(UwbParameters.class))
+                .build());
+
+        mSession.stop();
+
+        verify(mMockAdapters.get(UWB)).stop();
+        inOrder.verify(mMockCallback).onStopped(UWB,
+                RangingAdapter.Callback.StoppedReason.REQUESTED);
+        inOrder.verify(mMockCallback).onStopped(null,
+                RangingAdapter.Callback.StoppedReason.REQUESTED);
+    }
+
+    @Test
+    @Ignore("TODO: Add support for technologies other than UWB")
+    public void stop_stopsMultipleTechnologies() {
+        startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                .useUwb(mock(UwbParameters.class))
+                .useCs(mock(CsParameters.class))
+                .build());
+
+        mSession.stop();
+
+        verify(mMockAdapters.get(UWB)).stop();
+        verify(mMockAdapters.get(CS)).stop();
+        verify(mMockCallback).onStopped(UWB, RangingAdapter.Callback.StoppedReason.REQUESTED);
+        verify(mMockCallback).onStopped(CS, RangingAdapter.Callback.StoppedReason.REQUESTED);
+        verify(mMockCallback).onStopped(null, RangingAdapter.Callback.StoppedReason.REQUESTED);
+    }
+
+    @Test
+    public void shouldStop_whenAdapterStops() {
+        EnumMap<RangingTechnology, RangingAdapter.Callback> adapterCallbacks =
+                startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                        .useUwb(mock(UwbParameters.class))
+                        .build());
+
+        adapterCallbacks.get(UWB).onStopped(RangingAdapter.Callback.StoppedReason.LOST_CONNECTION);
+
+        verify(mMockCallback).onStopped(UWB, RangingAdapter.Callback.StoppedReason.LOST_CONNECTION);
+    }
+
+    @Test
+    public void shouldStop_whenNoInitialDataIsReported() {
+        startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER).build());
+
+        ArgumentCaptor<Runnable> onTimeoutCaptor = ArgumentCaptor.forClass(Runnable.class);
+        verify(mMockTimeoutExecutor).scheduleWithFixedDelay(onTimeoutCaptor.capture(),
+                anyLong(), anyLong(), any());
+
+        onTimeoutCaptor.getValue().run();
+
+        verify(mMockCallback).onStopped(eq(null),
+                eq(RangingSession.Callback.StoppedReason.NO_INITIAL_DATA_TIMEOUT));
+    }
+
+    @Test
+    public void shouldReportData_fromAdapter() {
+        EnumMap<RangingTechnology, RangingAdapter.Callback> adapterCallbacks =
+                startSession(new RangingParameters.Builder(DeviceRole.CONTROLLER)
+                        .useUwb(mock(UwbParameters.class))
+                        .build());
+
+        adapterCallbacks.get(UWB).onRangingData(generateData(UWB));
+
+        verify(mMockCallback).onData(any(RangingData.class));
+    }
+}
diff --git a/generic_ranging/tests/units/src/com/android/ranging/uwb/tests/UwbAdapterTest.java b/generic_ranging/tests/units/src/com/android/ranging/uwb/tests/UwbAdapterTest.java
new file mode 100644
index 00000000..aab30194
--- /dev/null
+++ b/generic_ranging/tests/units/src/com/android/ranging/uwb/tests/UwbAdapterTest.java
@@ -0,0 +1,154 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.ranging.uwb.tests;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.content.pm.PackageManager;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.ranging.RangingAdapter;
+import com.android.ranging.RangingData;
+import com.android.ranging.RangingParameters.DeviceRole;
+import com.android.ranging.RangingTechnology;
+import com.android.ranging.cs.CsParameters;
+import com.android.ranging.uwb.UwbAdapter;
+import com.android.ranging.uwb.UwbParameters;
+import com.android.ranging.uwb.backend.internal.RangingController;
+import com.android.ranging.uwb.backend.internal.RangingPosition;
+import com.android.ranging.uwb.backend.internal.RangingSessionCallback;
+import com.android.ranging.uwb.backend.internal.UwbDevice;
+import com.android.ranging.uwb.backend.internal.UwbServiceImpl;
+
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Answers;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+
+import java.util.concurrent.ExecutionException;
+
+@RunWith(JUnit4.class)
+@SmallTest
+public class UwbAdapterTest {
+    @Rule public final MockitoRule mMockito = MockitoJUnit.rule();
+
+    @Mock(answer = Answers.RETURNS_DEEP_STUBS) private Context mMockContext;
+    @Mock private UwbServiceImpl mMockUwbService;
+    @Mock private RangingController mMockUwbClient;
+
+    @Mock private RangingAdapter.Callback mMockCallback;
+
+    /** Class under test */
+    private UwbAdapter mUwbAdapter;
+
+    @Before
+    public void setup() {
+        when(mMockContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_UWB))
+                .thenReturn(true);
+        when(mMockUwbService.getController(any())).thenReturn(mMockUwbClient);
+        mUwbAdapter = new UwbAdapter(mMockContext, MoreExecutors.newDirectExecutorService(),
+                mMockUwbService, DeviceRole.CONTROLLER);
+    }
+
+    @Test
+    public void getType_returnsUwb() {
+        Assert.assertEquals(RangingTechnology.UWB, mUwbAdapter.getType());
+    }
+
+    @Test
+    public void isEnabled_checksServiceIsAvailable()
+            throws InterruptedException, ExecutionException {
+        when(mMockUwbService.isAvailable()).thenReturn(true);
+        Assert.assertTrue(mUwbAdapter.isEnabled().get());
+    }
+
+    @Test
+    public void start_failsWhenParamsInvalid() {
+        mUwbAdapter.start(mock(CsParameters.class), mMockCallback);
+        verify(mMockCallback).onStopped(eq(RangingAdapter.Callback.StoppedReason.FAILED_TO_START));
+        verify(mMockCallback, never()).onStarted();
+    }
+
+    @Test
+    public void start_startsUwbClientWithCallbacks() {
+        mUwbAdapter.start(mock(UwbParameters.class), mMockCallback);
+
+        ArgumentCaptor<RangingSessionCallback> callbackCaptor =
+                ArgumentCaptor.forClass(RangingSessionCallback.class);
+        verify(mMockUwbClient).startRanging(callbackCaptor.capture(), any());
+
+        UwbDevice mockUwbdevice = mock(UwbDevice.class, Answers.RETURNS_DEEP_STUBS);
+        callbackCaptor.getValue().onRangingInitialized(mockUwbdevice);
+        verify(mMockCallback).onStarted();
+
+        callbackCaptor.getValue().onRangingSuspended(mockUwbdevice, anyInt());
+        verify(mMockCallback).onStopped(anyInt());
+    }
+
+    @Test
+    public void stop_stopsUwbClient() {
+        mUwbAdapter.start(mock(UwbParameters.class), mMockCallback);
+        mUwbAdapter.stop();
+        verify(mMockUwbClient).stopRanging();
+    }
+
+    @Test
+    public void shouldReportData_onRangingResult() {
+        mUwbAdapter.start(mock(UwbParameters.class), mMockCallback);
+
+        ArgumentCaptor<RangingSessionCallback> callbackCaptor =
+                ArgumentCaptor.forClass(RangingSessionCallback.class);
+        verify(mMockUwbClient).startRanging(callbackCaptor.capture(), any());
+
+        UwbDevice mockDevice = mock(UwbDevice.class, Answers.RETURNS_DEEP_STUBS);
+        when(mockDevice.getAddress().toBytes()).thenReturn(new byte[]{0x1, 0x2});
+
+        RangingPosition mockPosition = mock(RangingPosition.class, Answers.RETURNS_DEEP_STUBS);
+        when(mockPosition.getDistance().getValue()).thenReturn(12F);
+        when(mockPosition.getElapsedRealtimeNanos()).thenReturn(1234L);
+
+        callbackCaptor.getValue().onRangingInitialized(mockDevice);
+        verify(mMockCallback).onStarted();
+
+        ArgumentCaptor<RangingData> dataCaptor = ArgumentCaptor.forClass(RangingData.class);
+        callbackCaptor.getValue().onRangingResult(mockDevice, mockPosition);
+        verify(mMockCallback).onRangingData(dataCaptor.capture());
+
+        RangingData data = dataCaptor.getValue();
+        Assert.assertEquals(RangingTechnology.UWB, data.getTechnology().get());
+        Assert.assertEquals(mockPosition.getDistance().getValue(), data.getRangeMeters(), 0.1);
+        Assert.assertArrayEquals(mockDevice.getAddress().toBytes(), data.getPeerAddress());
+        Assert.assertEquals(mockPosition.getElapsedRealtimeNanos(), data.getTimestamp().getNano());
+    }
+}
diff --git a/generic_ranging/uwb_backend/Android.bp b/generic_ranging/uwb_backend/Android.bp
new file mode 100644
index 00000000..e7ef3d7a
--- /dev/null
+++ b/generic_ranging/uwb_backend/Android.bp
@@ -0,0 +1,46 @@
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
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "ranging_uwb_backend",
+    sdk_version: "system_UpsideDownCake",
+    min_sdk_version: "34",
+    installable: false,
+    srcs: [
+        "src/**/*.java",
+    ],
+    libs: ["android-support-annotations"],
+    static_libs: [
+        "androidx.annotation_annotation",
+        "androidx.concurrent_concurrent-futures",
+        "com.uwb.support.fira",
+        "com.uwb.support.multichip",
+        "com.uwb.support.dltdoa",
+        "guava",
+    ],
+    apex_available: [
+        "com.android.tethering",
+        "//apex_available:platform",
+    ],
+    visibility: [
+        ":__subpackages__",
+        "//packages/modules/Uwb/generic_ranging:__subpackages__",
+        "//packages/modules/Connectivity/remoteauth:__subpackages__",
+    ],
+}
diff --git a/generic_ranging/uwb_backend/AndroidManifest.xml b/generic_ranging/uwb_backend/AndroidManifest.xml
new file mode 100644
index 00000000..14c36f43
--- /dev/null
+++ b/generic_ranging/uwb_backend/AndroidManifest.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<manifest
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.ranging.uwb.backend">
+
+  <uses-permission android:name="android.permission.UWB_PRIVILEGED"/>
+  <uses-permission android:name="android.permission.UWB_RANGING"/>
+
+  <application
+         android:persistent="true"
+         android:directBootAware="true"
+         android:defaultToDeviceProtectedStorage="true">
+    <service android:name=".impl.UwbService"
+            android:exported="true"
+            android:process=":remote">
+        <intent-filter>
+          <action android:name="com.android.ranging.uwb.backend"></action>
+        </intent-filter>
+    </service>
+  </application>
+</manifest>
diff --git a/generic_ranging/uwb_backend/com.android.ranging.uwb.backend.xml b/generic_ranging/uwb_backend/com.android.ranging.uwb.backend.xml
new file mode 100644
index 00000000..c9bb6d0e
--- /dev/null
+++ b/generic_ranging/uwb_backend/com.android.ranging.uwb.backend.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2023 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License
+  -->
+<permissions>
+    <privapp-permissions package="com.android.ranging.uwb.backend">
+        <permission name="android.permission.UWB_PRIVILEGED"/>
+        <permission name="android.permission.UWB_RANGING"/>
+    </privapp-permissions>
+</permissions>
+
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/ConfigurationManager.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/ConfigurationManager.java
new file mode 100644
index 00000000..13cf3d36
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/ConfigurationManager.java
@@ -0,0 +1,675 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_DL_TDOA_DT_TAG;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR_NO_AOA;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_UNICAST_DS_TWR_NO_AOA;
+import static com.android.ranging.uwb.backend.internal.Utils.STATIC_STS_SESSION_KEY_INFO_SIZE;
+import static com.android.ranging.uwb.backend.internal.Utils.VENDOR_ID_SIZE;
+import static com.android.ranging.uwb.backend.internal.Utils.getRangingTimingParams;
+
+import static com.google.uwb.support.fira.FiraParams.AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT;
+import static com.google.uwb.support.fira.FiraParams.FILTER_TYPE_NONE;
+import static com.google.uwb.support.fira.FiraParams.HOPPING_MODE_FIRA_HOPPING_ENABLE;
+import static com.google.uwb.support.fira.FiraParams.MAC_ADDRESS_MODE_2_BYTES;
+import static com.google.uwb.support.fira.FiraParams.MULTI_NODE_MODE_ONE_TO_MANY;
+import static com.google.uwb.support.fira.FiraParams.MULTI_NODE_MODE_UNICAST;
+import static com.google.uwb.support.fira.FiraParams.PRF_MODE_HPRF;
+import static com.google.uwb.support.fira.FiraParams.PROTOCOL_VERSION_1_1;
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG;
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_LEVEL_TRIG;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_DT_TAG;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_ROLE_INITIATOR;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_ROLE_RESPONDER;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_TYPE_CONTROLEE;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_TYPE_CONTROLLER;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_TYPE_DT_TAG;
+import static com.google.uwb.support.fira.FiraParams.RANGING_ROUND_USAGE_DL_TDOA;
+import static com.google.uwb.support.fira.FiraParams.RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+import static com.google.uwb.support.fira.FiraParams.RFRAME_CONFIG_SP1;
+import static com.google.uwb.support.fira.FiraParams.STS_CONFIG_PROVISIONED;
+import static com.google.uwb.support.fira.FiraParams.STS_CONFIG_PROVISIONED_FOR_CONTROLEE_INDIVIDUAL_KEY;
+
+import android.util.ArrayMap;
+
+import androidx.annotation.Nullable;
+
+import com.google.uwb.support.fira.FiraControleeParams;
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.fira.FiraParams;
+import com.google.uwb.support.fira.FiraRangingReconfigureParams;
+
+import java.util.Arrays;
+import java.util.Map;
+
+/**
+ * Creates the session-opening bundles for a FiRa session. The default parameters are
+ * profile-dependent.
+ */
+public final class ConfigurationManager {
+
+    private static final Map<Integer, UwbConfiguration> sConfigs = new ArrayMap<>();
+
+    static {
+        // ID_1 properties.
+        sConfigs.put(
+                CONFIG_UNICAST_DS_TWR,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_UNICAST_DS_TWR;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_UNICAST;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return FiraParams.STS_CONFIG_STATIC;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_2 properties.
+        sConfigs.put(
+                CONFIG_MULTICAST_DS_TWR,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_MULTICAST_DS_TWR;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_ONE_TO_MANY;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return FiraParams.STS_CONFIG_STATIC;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_3 properties.
+        sConfigs.put(
+                CONFIG_UNICAST_DS_TWR_NO_AOA,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_UNICAST_DS_TWR_NO_AOA;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_UNICAST;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return FiraParams.STS_CONFIG_STATIC;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_4 properties.
+        sConfigs.put(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_PROVISIONED_UNICAST_DS_TWR;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_UNICAST;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return STS_CONFIG_PROVISIONED;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_5 properties.
+        sConfigs.put(
+                CONFIG_PROVISIONED_MULTICAST_DS_TWR,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_PROVISIONED_MULTICAST_DS_TWR;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_ONE_TO_MANY;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return STS_CONFIG_PROVISIONED;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_6 properties.
+        sConfigs.put(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA,
+                new UwbConfiguration() {
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_UNICAST;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return STS_CONFIG_PROVISIONED;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_7 properties.
+        sConfigs.put(
+                CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_ONE_TO_MANY;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return FiraParams.STS_CONFIG_PROVISIONED_FOR_CONTROLEE_INDIVIDUAL_KEY;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_1001 properties.
+        sConfigs.put(
+                CONFIG_DL_TDOA_DT_TAG,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_DL_TDOA_DT_TAG;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_ONE_TO_MANY;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return FiraParams.STS_CONFIG_STATIC;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DL_TDOA;
+                    }
+                });
+
+        // ID_1000 properties.
+        sConfigs.put(
+                CONFIG_MULTICAST_DS_TWR_NO_AOA,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_UNICAST_DS_TWR_NO_AOA;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_ONE_TO_MANY;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return FiraParams.STS_CONFIG_STATIC;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_1002 properties.
+        sConfigs.put(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_UNICAST;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return STS_CONFIG_PROVISIONED;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+
+        // ID_1003 properties.
+        sConfigs.put(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF,
+                new UwbConfiguration() {
+
+                    @Override
+                    public int getConfigId() {
+                        return CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF;
+                    }
+
+                    @Override
+                    public int getMultiNodeMode() {
+                        return MULTI_NODE_MODE_UNICAST;
+                    }
+
+                    @Override
+                    public int getStsConfig() {
+                        return STS_CONFIG_PROVISIONED;
+                    }
+
+                    @Override
+                    public int getAoaResultRequestMode() {
+                        return FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+                    }
+
+                    @Override
+                    public boolean isControllerTheInitiator() {
+                        return true;
+                    }
+
+                    @Override
+                    public int getRangingRoundUsage() {
+                        return RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE;
+                    }
+                });
+    }
+
+    private ConfigurationManager() {
+    }
+
+    /** Creates a {@link FiraOpenSessionParams}. */
+    public static FiraOpenSessionParams createOpenSessionParams(
+            @FiraParams.RangingDeviceType int deviceType,
+            UwbAddress localAddress,
+            RangingParameters rangingParameters,
+            UwbFeatureFlags featureFlags) {
+        RangingTimingParams timingParams =
+                getRangingTimingParams(rangingParameters.getUwbConfigId());
+        UwbConfiguration configuration = sConfigs.get(rangingParameters.getUwbConfigId());
+        int deviceRole;
+        switch (deviceType) {
+            case RANGING_DEVICE_TYPE_CONTROLLER:
+                deviceRole =
+                        configuration.isControllerTheInitiator()
+                                ? RANGING_DEVICE_ROLE_INITIATOR
+                                : RANGING_DEVICE_ROLE_RESPONDER;
+                break;
+            case RANGING_DEVICE_TYPE_CONTROLEE:
+                deviceRole =
+                        configuration.isControllerTheInitiator()
+                                ? RANGING_DEVICE_ROLE_RESPONDER
+                                : RANGING_DEVICE_ROLE_INITIATOR;
+                break;
+            case RANGING_DEVICE_TYPE_DT_TAG:
+                deviceRole = RANGING_DEVICE_DT_TAG;
+                break;
+            default:
+                deviceRole = RANGING_DEVICE_ROLE_RESPONDER;
+                break;
+        }
+
+        // Remove this when we add support for ranging device type Dt-TAG.
+        if (configuration.getConfigId() == CONFIG_DL_TDOA_DT_TAG) {
+            deviceRole = RANGING_DEVICE_DT_TAG;
+        }
+
+        FiraOpenSessionParams.Builder builder =
+                new FiraOpenSessionParams.Builder()
+                        .setProtocolVersion(PROTOCOL_VERSION_1_1)
+                        .setRangingRoundUsage(configuration.getRangingRoundUsage())
+                        .setMultiNodeMode(configuration.getMultiNodeMode())
+                        .setMacAddressMode(MAC_ADDRESS_MODE_2_BYTES)
+                        .setDeviceType(deviceType)
+                        .setDeviceRole(deviceRole)
+                        .setSessionId(rangingParameters.getSessionId())
+                        .setDeviceAddress(Conversions.convertUwbAddress(localAddress,
+                                featureFlags.isReversedByteOrderFiraParams()))
+                        .setAoaResultRequest(rangingParameters.isAoaDisabled()
+                                ? AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT :
+                                configuration.getAoaResultRequestMode())
+                        .setChannelNumber(rangingParameters.getComplexChannel().getChannel())
+                        .setPreambleCodeIndex(
+                                rangingParameters.getComplexChannel().getPreambleIndex())
+                        .setInitiationTime(timingParams.getInitiationTimeMs())
+                        .setSlotDurationRstu(
+                                Utils.convertMsToRstu(rangingParameters.getSlotDuration()))
+                        .setSlotsPerRangingRound(timingParams.getSlotPerRangingRound())
+                        .setRangingIntervalMs(
+                                timingParams.getRangingInterval(
+                                        rangingParameters.getRangingUpdateRate()))
+                        .setRangeDataNtfConfig(
+                                Utils.convertToFiraNtfConfig(
+                                        rangingParameters
+                                                .getUwbRangeDataNtfConfig()
+                                                .getRangeDataNtfConfigType()))
+                        .setRangeDataNtfProximityNear(
+                                rangingParameters.getUwbRangeDataNtfConfig().getNtfProximityNear())
+                        .setRangeDataNtfProximityFar(
+                                rangingParameters.getUwbRangeDataNtfConfig().getNtfProximityFar())
+                        .setInBandTerminationAttemptCount(3)
+                        .setStsConfig(configuration.getStsConfig())
+                        .setRangingErrorStreakTimeoutMs(10_000L)
+                        .setFilterType(FILTER_TYPE_NONE);
+
+        if (configuration.getStsConfig() == FiraParams.STS_CONFIG_STATIC) {
+            byte[] staticStsIv =
+                    Arrays.copyOfRange(
+                            rangingParameters.getSessionKeyInfo(),
+                            VENDOR_ID_SIZE,
+                            STATIC_STS_SESSION_KEY_INFO_SIZE);
+            builder.setVendorId(
+                            featureFlags.isReversedByteOrderFiraParams()
+                                    ? Conversions.getReverseBytes(
+                                    Arrays.copyOf(rangingParameters.getSessionKeyInfo(),
+                                            VENDOR_ID_SIZE)) :
+                                    Arrays.copyOf(rangingParameters.getSessionKeyInfo(),
+                                            VENDOR_ID_SIZE))
+                    .setStaticStsIV(staticStsIv);
+        } else if (configuration.getStsConfig() == STS_CONFIG_PROVISIONED) {
+            builder.setSessionKey(rangingParameters.getSessionKeyInfo())
+                    .setIsKeyRotationEnabled(true)
+                    .setKeyRotationRate(0);
+        } else if (configuration.getStsConfig()
+                == STS_CONFIG_PROVISIONED_FOR_CONTROLEE_INDIVIDUAL_KEY) {
+            builder.setSessionKey(rangingParameters.getSessionKeyInfo())
+                    .setSubSessionId(rangingParameters.getSubSessionId())
+                    .setSubsessionKey(rangingParameters.getSubSessionKeyInfo());
+        }
+
+        if (timingParams.isHoppingEnabled()) {
+            builder.setHoppingMode(HOPPING_MODE_FIRA_HOPPING_ENABLE);
+        }
+
+        if (deviceRole != RANGING_DEVICE_DT_TAG) {
+            builder.setDestAddressList(Conversions.convertUwbAddressList(
+                    rangingParameters.getPeerAddresses().toArray(new UwbAddress[0]),
+                    featureFlags.isReversedByteOrderFiraParams()));
+        } else {
+            builder.setRframeConfig(RFRAME_CONFIG_SP1);
+        }
+
+        if (configuration.getConfigId()
+                == CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF) {
+            builder.setPrfMode(PRF_MODE_HPRF);
+        }
+
+        if (configuration.getConfigId() == CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE
+                || configuration.getConfigId()
+                    == CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF) {
+            builder.setHasRangingResultReportMessage(false);
+        }
+
+        return builder.build();
+    }
+
+    /** Creates a {@link FiraRangingReconfigureParams}. */
+    public static FiraRangingReconfigureParams createReconfigureParams(
+            @Utils.UwbConfigId int configId,
+            @FiraParams.MulticastListUpdateAction int action,
+            UwbAddress[] peerAddresses,
+            @Nullable int[] subSessionIdList,
+            @Nullable byte[] subSessionKey,
+            UwbFeatureFlags uwbFeatureFlags) {
+        UwbConfiguration configuration = sConfigs.get(configId);
+        FiraRangingReconfigureParams.Builder builder =
+                new FiraRangingReconfigureParams.Builder()
+                        .setAction(action)
+                        .setAddressList(
+                                Conversions.convertUwbAddressList(peerAddresses,
+                                                uwbFeatureFlags.isReversedByteOrderFiraParams())
+                                        .toArray(new android.uwb.UwbAddress[0]));
+        if (configuration.getStsConfig()
+                == FiraParams.STS_CONFIG_DYNAMIC_FOR_CONTROLEE_INDIVIDUAL_KEY) {
+            builder.setSubSessionIdList(subSessionIdList).setSubSessionKeyList(subSessionKey);
+        }
+        return builder.build();
+    }
+
+    /** Creates a {@link FiraControleeParams}. */
+    public static FiraControleeParams createControleeParams(
+            @Utils.UwbConfigId int configId,
+            @FiraParams.MulticastListUpdateAction int action,
+            UwbAddress[] peerAddresses,
+            @Nullable int[] subSessionIdList,
+            @Nullable byte[] subSessionKey,
+            UwbFeatureFlags uwbFeatureFlags) {
+        UwbConfiguration configuration = sConfigs.get(configId);
+        FiraControleeParams.Builder builder = new FiraControleeParams.Builder();
+        builder.setAction(action);
+        builder.setAddressList(
+                Conversions.convertUwbAddressList(
+                                peerAddresses, uwbFeatureFlags.isReversedByteOrderFiraParams())
+                        .toArray(new android.uwb.UwbAddress[0]));
+        if (configuration.getStsConfig()
+                == FiraParams.STS_CONFIG_DYNAMIC_FOR_CONTROLEE_INDIVIDUAL_KEY) {
+            builder.setSubSessionIdList(subSessionIdList).setSubSessionKeyList(subSessionKey);
+        }
+        return builder.build();
+    }
+
+    /** Creates a {@link FiraRangingReconfigureParams} with block striding set. */
+    public static FiraRangingReconfigureParams createReconfigureParamsBlockStriding(
+            int blockStridingLength) {
+        return new FiraRangingReconfigureParams.Builder()
+                .setBlockStrideLength(blockStridingLength)
+                .build();
+    }
+
+    /** Creates a {@link FiraRangingReconfigureParams} with range data notification configured. */
+    public static FiraRangingReconfigureParams createReconfigureParamsRangeDataNtf(
+            UwbRangeDataNtfConfig rangeDataNtfConfig) {
+        int configType = Utils.convertToFiraNtfConfig(
+                rangeDataNtfConfig.getRangeDataNtfConfigType());
+        FiraRangingReconfigureParams.Builder builder =
+                new FiraRangingReconfigureParams.Builder().setRangeDataNtfConfig(configType);
+
+        if (configType == RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_LEVEL_TRIG
+                || configType == RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG) {
+            builder
+                    .setRangeDataProximityNear(rangeDataNtfConfig.getNtfProximityNear())
+                    .setRangeDataProximityFar(rangeDataNtfConfig.getNtfProximityFar());
+        }
+        return builder.build();
+    }
+
+    /** Indicates if the ID presents an unicast configuration. */
+    public static boolean isUnicast(@Utils.UwbConfigId int configId) {
+        return sConfigs.get(configId).getMultiNodeMode() == MULTI_NODE_MODE_UNICAST;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Conversions.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Conversions.java
new file mode 100644
index 00000000..619a8829
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Conversions.java
@@ -0,0 +1,208 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static android.uwb.UwbManager.AdapterStateCallback.STATE_CHANGED_REASON_SYSTEM_POLICY;
+import static android.uwb.UwbManager.AdapterStateCallback.STATE_CHANGED_REASON_SYSTEM_REGULATION;
+
+import android.os.Build;
+import android.os.Build.VERSION_CODES;
+import android.uwb.AngleMeasurement;
+import android.uwb.AngleOfArrivalMeasurement;
+import android.uwb.DistanceMeasurement;
+import android.uwb.RangingSession;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/** Utility class to help convert results from system API to GMSCore API */
+@RequiresApi(api = VERSION_CODES.S)
+final class Conversions {
+
+    private static RangingMeasurement createMeasurement(double value, double confidence,
+            boolean valid) {
+        @RangingMeasurement.Confidence int confidenceLevel;
+        if (confidence > 0.9) {
+            confidenceLevel = RangingMeasurement.CONFIDENCE_HIGH;
+        } else if (confidence > 0.5) {
+            confidenceLevel = RangingMeasurement.CONFIDENCE_MEDIUM;
+        } else {
+            confidenceLevel = RangingMeasurement.CONFIDENCE_LOW;
+        }
+        return new RangingMeasurement(confidenceLevel, (float) value, valid);
+    }
+
+    public static boolean isDlTdoaMeasurement(android.uwb.RangingMeasurement measurement) {
+        if (Build.VERSION.SDK_INT <= VERSION_CODES.TIRAMISU) {
+            return false;
+        }
+        try {
+            return com.google.uwb.support.dltdoa.DlTDoAMeasurement.isDlTDoAMeasurement(
+                    measurement.getRangingMeasurementMetadata());
+        } catch (NoSuchMethodError e) {
+            return false;
+        }
+    }
+
+    /** Convert system API's {@link android.uwb.RangingMeasurement} to {@link RangingPosition} */
+    @Nullable
+    static RangingPosition convertToPosition(android.uwb.RangingMeasurement measurement) {
+        RangingMeasurement distance;
+        DlTdoaMeasurement dlTdoaMeasurement = null;
+        if (isDlTdoaMeasurement(measurement)) {
+            com.google.uwb.support.dltdoa.DlTDoAMeasurement
+                    dlTDoAMeasurement = com.google.uwb.support.dltdoa.DlTDoAMeasurement.fromBundle(
+                    measurement.getRangingMeasurementMetadata());
+            // Return null if Dl-TDoA measurement is not valid.
+            if (dlTDoAMeasurement.getMessageControl() == 0) {
+                return null;
+            }
+            dlTdoaMeasurement = new DlTdoaMeasurement(
+                    dlTDoAMeasurement.getMessageType(),
+                    dlTDoAMeasurement.getMessageControl(),
+                    dlTDoAMeasurement.getBlockIndex(),
+                    dlTDoAMeasurement.getRoundIndex(),
+                    dlTDoAMeasurement.getNLoS(),
+                    dlTDoAMeasurement.getTxTimestamp(),
+                    dlTDoAMeasurement.getRxTimestamp(),
+                    dlTDoAMeasurement.getAnchorCfo(),
+                    dlTDoAMeasurement.getCfo(),
+                    dlTDoAMeasurement.getInitiatorReplyTime(),
+                    dlTDoAMeasurement.getResponderReplyTime(),
+                    dlTDoAMeasurement.getInitiatorResponderTof(),
+                    dlTDoAMeasurement.getAnchorLocation(),
+                    dlTDoAMeasurement.getActiveRangingRounds()
+            );
+            // No distance measurement for DL-TDoa, make it invalid.
+            distance = createMeasurement(0.0, 0.0, false);
+        } else {
+            DistanceMeasurement distanceMeasurement = measurement.getDistanceMeasurement();
+            if (distanceMeasurement == null) {
+                return null;
+            }
+            distance = createMeasurement(
+                    distanceMeasurement.getMeters(),
+                    distanceMeasurement.getConfidenceLevel(),
+                    true);
+        }
+        AngleOfArrivalMeasurement aoaMeasurement = measurement.getAngleOfArrivalMeasurement();
+
+        RangingMeasurement azimuth = null;
+        RangingMeasurement altitude = null;
+        if (aoaMeasurement != null) {
+            AngleMeasurement azimuthMeasurement = aoaMeasurement.getAzimuth();
+            if (azimuthMeasurement != null && !isMeasurementAllZero(azimuthMeasurement)) {
+                azimuth =
+                        createMeasurement(
+                                azimuthMeasurement.getRadians(),
+                                azimuthMeasurement.getConfidenceLevel(),
+                                true);
+            }
+            AngleMeasurement altitudeMeasurement = aoaMeasurement.getAltitude();
+            if (altitudeMeasurement != null && !isMeasurementAllZero(altitudeMeasurement)) {
+                altitude =
+                        createMeasurement(
+                                altitudeMeasurement.getRadians(),
+                                altitudeMeasurement.getConfidenceLevel(),
+                                true);
+            }
+        }
+        if (Build.VERSION.SDK_INT >= VERSION_CODES.TIRAMISU) {
+            return new RangingPosition(
+                    distance,
+                    azimuth,
+                    altitude,
+                    dlTdoaMeasurement,
+                    measurement.getElapsedRealtimeNanos(),
+                    measurement.getRssiDbm());
+        }
+        return new RangingPosition(
+                distance, azimuth, altitude, measurement.getElapsedRealtimeNanos());
+    }
+
+    private static boolean isMeasurementAllZero(AngleMeasurement measurement) {
+        return measurement.getRadians() == 0
+                && measurement.getErrorRadians() == 0
+                && measurement.getConfidenceLevel() == 0;
+    }
+
+    @RangingSessionCallback.RangingSuspendedReason
+    static int convertReason(int reason) {
+        if (reason == RangingSession.Callback.REASON_BAD_PARAMETERS) {
+            return RangingSessionCallback.REASON_WRONG_PARAMETERS;
+        }
+
+        if (reason == RangingSession.Callback.REASON_LOCAL_REQUEST) {
+            return RangingSessionCallback.REASON_STOP_RANGING_CALLED;
+        }
+
+        if (reason == RangingSession.Callback.REASON_REMOTE_REQUEST) {
+            return RangingSessionCallback.REASON_STOPPED_BY_PEER;
+        }
+
+        if (reason == RangingSession.Callback.REASON_MAX_SESSIONS_REACHED) {
+            return RangingSessionCallback.REASON_FAILED_TO_START;
+        }
+
+        if (reason == RangingSession.Callback.REASON_PROTOCOL_SPECIFIC_ERROR) {
+            return RangingSessionCallback.REASON_MAX_RANGING_ROUND_RETRY_REACHED;
+        }
+
+        if (reason == RangingSession.Callback.REASON_SYSTEM_POLICY) {
+            return RangingSessionCallback.REASON_SYSTEM_POLICY;
+        }
+
+        return RangingSessionCallback.REASON_UNKNOWN;
+    }
+
+    @UwbAvailabilityCallback.UwbStateChangeReason
+    static int convertAdapterStateReason(int reason) {
+        return switch (reason) {
+            case STATE_CHANGED_REASON_SYSTEM_POLICY -> UwbAvailabilityCallback.REASON_SYSTEM_POLICY;
+            case STATE_CHANGED_REASON_SYSTEM_REGULATION ->
+                    UwbAvailabilityCallback.REASON_COUNTRY_CODE_ERROR;
+            default -> UwbAvailabilityCallback.REASON_UNKNOWN;
+        };
+    }
+    static android.uwb.UwbAddress convertUwbAddress(UwbAddress address, boolean reverseMacAddress) {
+        return reverseMacAddress
+                ? android.uwb.UwbAddress.fromBytes(getReverseBytes(address.toBytes()))
+                : android.uwb.UwbAddress.fromBytes(address.toBytes());
+    }
+
+    static List<android.uwb.UwbAddress> convertUwbAddressList(
+            UwbAddress[] addressList, boolean reverseMacAddress) {
+        List<android.uwb.UwbAddress> list = new ArrayList<>();
+        for (UwbAddress address : addressList) {
+            list.add(convertUwbAddress(address, reverseMacAddress));
+        }
+        return list;
+    }
+
+    static byte[] getReverseBytes(byte[] data) {
+        byte[] buffer = new byte[data.length];
+        for (int i = 0; i < data.length; i++) {
+            buffer[i] = data[data.length - 1 - i];
+        }
+        return buffer;
+    }
+
+    private Conversions() {}
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/DlTdoaMeasurement.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/DlTdoaMeasurement.java
new file mode 100644
index 00000000..0c3d6902
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/DlTdoaMeasurement.java
@@ -0,0 +1,137 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import java.util.Arrays;
+import java.util.Locale;
+
+/** Downlink-TDoA measurements */
+public class DlTdoaMeasurement {
+    private final int mMessageType;
+    private final int mMessageControl;
+    private final int mBlockIndex;
+    private final int mRoundIndex;
+    private final int mNLoS;
+    private final long mTxTimestamp;
+    private final long mRxTimestamp;
+    private final float mAnchorCfo;
+    private final float mCfo;
+    private final long mInitiatorReplyTime;
+    private final long mResponderReplyTime;
+    private final int mInitiatorResponderTof;
+    private final byte[] mAnchorLocation;
+    private final byte[] mActiveRangingRounds;
+
+    public DlTdoaMeasurement(int messageType, int messageControl, int blockIndex, int roundIndex,
+            int nLoS, long txTimestamp, long rxTimestamp, float anchorCfo, float cfo,
+            long initiatorReplyTime, long responderReplyTime, int initiatorResponderTof,
+            byte[] anchorLocation, byte[] activeRangingRounds) {
+        mMessageType = messageType;
+        mMessageControl = messageControl;
+        mBlockIndex = blockIndex;
+        mRoundIndex = roundIndex;
+        mNLoS = nLoS;
+        mTxTimestamp = txTimestamp;
+        mRxTimestamp = rxTimestamp;
+        mAnchorCfo = anchorCfo;
+        mCfo = cfo;
+        mInitiatorReplyTime = initiatorReplyTime;
+        mResponderReplyTime = responderReplyTime;
+        mInitiatorResponderTof = initiatorResponderTof;
+        mAnchorLocation = anchorLocation;
+        mActiveRangingRounds = activeRangingRounds;
+    }
+
+    public int getMessageType() {
+        return mMessageType;
+    }
+
+    public int getMessageControl() {
+        return mMessageControl;
+    }
+
+    public int getBlockIndex() {
+        return mBlockIndex;
+    }
+
+    public int getRoundIndex() {
+        return mRoundIndex;
+    }
+
+    public int getNLoS() {
+        return mNLoS;
+    }
+
+    public long getTxTimestamp() {
+        return mTxTimestamp;
+    }
+
+    public long getRxTimestamp() {
+        return mRxTimestamp;
+    }
+
+    public float getAnchorCfo() {
+        return mAnchorCfo;
+    }
+
+    public float getCfo() {
+        return mCfo;
+    }
+
+    public long getInitiatorReplyTime() {
+        return mInitiatorReplyTime;
+    }
+
+    public long getResponderReplyTime() {
+        return mResponderReplyTime;
+    }
+
+    public int getInitiatorResponderTof() {
+        return mInitiatorResponderTof;
+    }
+
+    public byte[] getAnchorLocation() {
+        return mAnchorLocation;
+    }
+
+    public byte[] getActiveRangingRounds() {
+        return mActiveRangingRounds;
+    }
+
+
+    @Override
+    public String toString() {
+        return String.format(Locale.US, " | messageType : %d", mMessageType)
+                + String.format(Locale.US, " | messageControl : %d", mMessageControl)
+                + String.format(Locale.US, " | blockIndex : %d", mBlockIndex)
+                + String.format(Locale.US, " | roundIndex : %d", mRoundIndex)
+                + String.format(Locale.US, " | nLoS : %d", mNLoS)
+                + String.format(Locale.US, " | txTimestamp : %d", mTxTimestamp)
+                + String.format(Locale.US, " | rxTimestamp : %d", mRxTimestamp)
+                + String.format(Locale.US, " | anchorCfo : %f", mAnchorCfo)
+                + String.format(Locale.US, " | cfo : %f", mCfo)
+                + String.format(Locale.US, " | initiatorReplyTime : %d", mInitiatorReplyTime)
+                + String.format(Locale.US, " | responderReplyTime : %d", mResponderReplyTime)
+                + String.format(Locale.US, " | initiatorResponderTof : %d",
+                                mInitiatorResponderTof)
+                + String.format(Locale.US, " | anchorLocation : %s",
+                Arrays.toString(mAnchorLocation))
+                + String.format(
+                Locale.US, " | activeRangingRounds : %s",
+                                Arrays.toString(mActiveRangingRounds));
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Errors.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Errors.java
new file mode 100644
index 00000000..6e66e3e6
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Errors.java
@@ -0,0 +1,90 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static android.uwb.RangingSession.Callback.REASON_BAD_PARAMETERS;
+import static android.uwb.RangingSession.Callback.REASON_GENERIC_ERROR;
+import static android.uwb.RangingSession.Callback.REASON_LOCAL_REQUEST;
+import static android.uwb.RangingSession.Callback.REASON_MAX_RR_RETRY_REACHED;
+import static android.uwb.RangingSession.Callback.REASON_MAX_SESSIONS_REACHED;
+import static android.uwb.RangingSession.Callback.REASON_PROTOCOL_SPECIFIC_ERROR;
+import static android.uwb.RangingSession.Callback.REASON_REMOTE_REQUEST;
+import static android.uwb.RangingSession.Callback.REASON_SERVICE_CONNECTION_FAILURE;
+import static android.uwb.RangingSession.Callback.REASON_SERVICE_DISCOVERY_FAILURE;
+import static android.uwb.RangingSession.Callback.REASON_SE_INTERACTION_FAILURE;
+import static android.uwb.RangingSession.Callback.REASON_SE_NOT_SUPPORTED;
+import static android.uwb.RangingSession.Callback.REASON_SYSTEM_POLICY;
+
+import java.util.Locale;
+
+/** Error code to human readable string conversion */
+public final class Errors {
+
+    private Errors() {}
+
+    /** Reason codes used in UWB session callback */
+    public static final class RangingSession {
+
+        private RangingSession() {}
+
+        /** Convert error codes used in RangingSession callback to human readable string */
+        public static String toString(int reason) {
+            String msg;
+            switch (reason) {
+                case REASON_BAD_PARAMETERS:
+                    msg = "REASON_BAD_PARAMETERS";
+                    break;
+                case REASON_GENERIC_ERROR:
+                    msg = "REASON_GENERIC_ERROR";
+                    break;
+                case REASON_LOCAL_REQUEST:
+                    msg = "REASON_LOCAL_REQUEST";
+                    break;
+                case REASON_MAX_RR_RETRY_REACHED:
+                    msg = "REASON_MAX_RR_RETRY_REACHED";
+                    break;
+                case REASON_MAX_SESSIONS_REACHED:
+                    msg = "REASON_MAX_SESSIONS_REACHED";
+                    break;
+                case REASON_PROTOCOL_SPECIFIC_ERROR:
+                    msg = "REASON_PROTOCOL_SPECIFIC_ERROR";
+                    break;
+                case REASON_REMOTE_REQUEST:
+                    msg = "REASON_REMOTE_REQUEST";
+                    break;
+                case REASON_SERVICE_CONNECTION_FAILURE:
+                    msg = "REASON_SERVICE_CONNECTION_FAILURE";
+                    break;
+                case REASON_SERVICE_DISCOVERY_FAILURE:
+                    msg = "REASON_SERVICE_DISCOVERY_FAILURE";
+                    break;
+                case REASON_SE_INTERACTION_FAILURE:
+                    msg = "REASON_SE_INTERACTION_FAILURE";
+                    break;
+                case REASON_SE_NOT_SUPPORTED:
+                    msg = "REASON_SE_NOT_SUPPORTED";
+                    break;
+                case REASON_SYSTEM_POLICY:
+                    msg = "REASON_SYSTEM_POLICY";
+                    break;
+                default:
+                    msg = "REASON_UNKNOWN";
+            }
+            return String.format(Locale.ENGLISH, "[%d]%s", reason, msg);
+        }
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/OpAsyncCallbackRunner.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/OpAsyncCallbackRunner.java
new file mode 100644
index 00000000..45f268d0
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/OpAsyncCallbackRunner.java
@@ -0,0 +1,129 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.Utils.TAG;
+
+import static java.util.concurrent.TimeUnit.MILLISECONDS;
+
+import android.util.Log;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.WorkerThread;
+import androidx.concurrent.futures.CallbackToFutureAdapter;
+import androidx.concurrent.futures.CallbackToFutureAdapter.Completer;
+
+import com.google.common.util.concurrent.ListenableFuture;
+
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.TimeoutException;
+
+/**
+ * Execute an operation and wait for its completion.
+ *
+ * <p>Typical usage: Execute an operation that should trigger an asynchronous callback. When the
+ * callback is invoked, inside the callback the opCompleter is set and unblocks the execution.
+ *
+ * @param <T> T is the type of the value that sets in operation's completion.
+ */
+public class OpAsyncCallbackRunner<T> {
+
+    /** Default timeout value of an operation */
+    private static final int DEFAULT_OPERATION_TIMEOUT_MILLIS = 3000;
+
+    private int mOperationTimeoutMillis = DEFAULT_OPERATION_TIMEOUT_MILLIS;
+
+    @Nullable private Completer<T> mOpCompleter;
+
+    @Nullable private T mResult;
+
+    private boolean mActive = false;
+
+    /** Set the timeout value in Millis */
+    public void setOperationTimeoutMillis(int timeoutMillis) {
+        mOperationTimeoutMillis = timeoutMillis;
+    }
+
+    /** Completes the operation and set the result */
+    public void complete(T result) {
+        if (!mActive) {
+            throw new IllegalStateException("Calling complete() without active operation.");
+        }
+        Completer<T> opCompleter = this.mOpCompleter;
+        if (opCompleter != null) {
+            opCompleter.set(result);
+            this.mResult = result;
+        }
+    }
+
+    /** Complete the operation if active, useful for unexpected callback. */
+    public synchronized void completeIfActive(T result) {
+        if (!mActive) {
+            return;
+        }
+        Completer<T> opCompleter = this.mOpCompleter;
+        if (opCompleter != null) {
+            opCompleter.set(result);
+            this.mResult = result;
+        }
+    }
+
+    @Nullable
+    public T getResult() {
+        return mResult;
+    }
+
+    /**
+     * Execute op in current thread and wait until the completer is set. Since this is a blocking
+     * operation, make sure it's not running on main thread.
+     */
+    @WorkerThread
+    public boolean execOperation(Runnable op, String opDescription) {
+        mResult = null;
+        if (mActive) {
+            throw new IllegalStateException("Calling execOperation() while operation is running.");
+        }
+        mActive = true;
+        ListenableFuture<T> opFuture =
+                CallbackToFutureAdapter.getFuture(
+                        completer -> {
+                            mOpCompleter = completer;
+                            op.run();
+                            return "Async " + opDescription;
+                        });
+        try {
+            mResult = opFuture.get(mOperationTimeoutMillis, MILLISECONDS);
+            return mResult != null;
+        } catch (TimeoutException e) {
+            Log.w(TAG, String.format("Callback timeout in Op %s", opDescription), e);
+            return false;
+        } catch (InterruptedException e) {
+            Thread.currentThread().interrupt();
+            return false;
+        } catch (ExecutionException e) {
+            Log.w(TAG, String.format("ExecutionException in Op %s", opDescription), e);
+            return false;
+        } finally {
+            mOpCompleter = null;
+            mActive = false;
+        }
+    }
+
+    public boolean isActive() {
+        return mActive;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingCapabilities.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingCapabilities.java
new file mode 100644
index 00000000..2364f3cc
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingCapabilities.java
@@ -0,0 +1,173 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_DL_TDOA_DT_TAG;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR_NO_AOA;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_UNICAST_DS_TWR_NO_AOA;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE;
+
+import androidx.annotation.IntRange;
+
+import com.google.common.collect.ImmutableList;
+
+import java.util.ArrayList;
+import java.util.List;
+
+/** Describes UWB ranging capabilities for the current device. */
+public class RangingCapabilities {
+    /** Default minimum ranging interval if the system API doesn't provide it. */
+    public static final int FIRA_DEFAULT_RANGING_INTERVAL_MS = 200;
+    /** Default supported channel if the system API doesn't provide it. */
+    public static final int FIRA_DEFAULT_SUPPORTED_CHANNEL = 9;
+    /** Default supported config id if the system API doesn't provide it. */
+    public static final ImmutableList<Integer> FIRA_DEFAULT_SUPPORTED_CONFIG_IDS =
+            ImmutableList.of(
+                    CONFIG_UNICAST_DS_TWR,
+                    CONFIG_MULTICAST_DS_TWR,
+                    CONFIG_UNICAST_DS_TWR_NO_AOA,
+                    CONFIG_MULTICAST_DS_TWR_NO_AOA,
+                    CONFIG_DL_TDOA_DT_TAG,
+                    CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE);
+    /** Ranging interval reconfigure is not supported if the system API doesn't provide. */
+    public static final boolean DEFAULT_SUPPORTS_RANGING_INTERVAL_RECONFIGURE = false;
+    /** Default supported slot duration if the system API doesn't provide it. */
+    public static final ImmutableList<Integer> DEFAULT_SUPPORTED_SLOT_DURATIONS =
+            ImmutableList.of(Utils.DURATION_2_MS);
+    /** Default supported ranging interval if the system API doesn't provide it. */
+    public static final ImmutableList<Integer> DEFAULT_SUPPORTED_RANGING_UPDATE_RATE =
+            ImmutableList.of(Utils.NORMAL, Utils.INFREQUENT);
+
+
+    private final boolean mSupportsDistance;
+    private final boolean mSupportsAzimuthalAngle;
+    private final boolean mSupportsElevationAngle;
+    private final boolean mSupportsRangingIntervalReconfigure;
+    private final int mMinRangingInterval;
+    private final List<Integer> mSupportedChannels;
+    private final List<Integer> mSupportedNtfConfigs;
+    private final List<Integer> mSupportedConfigIds;
+    private final List<Integer> mSupportedSlotDurations;
+    private final List<Integer> mSupportedRangingUpdateRates;
+    private final boolean mHasBackgroundRangingSupport;
+
+    public RangingCapabilities(
+            boolean supportsDistance,
+            boolean supportsAzimuthalAngle,
+            boolean supportsElevationAngle) {
+        this(
+                supportsDistance,
+                supportsAzimuthalAngle,
+                supportsElevationAngle,
+                DEFAULT_SUPPORTS_RANGING_INTERVAL_RECONFIGURE,
+                FIRA_DEFAULT_RANGING_INTERVAL_MS,
+                new ArrayList<>(FIRA_DEFAULT_SUPPORTED_CHANNEL),
+                new ArrayList<>(RANGE_DATA_NTF_ENABLE),
+                FIRA_DEFAULT_SUPPORTED_CONFIG_IDS,
+                DEFAULT_SUPPORTED_SLOT_DURATIONS,
+                DEFAULT_SUPPORTED_RANGING_UPDATE_RATE,
+                false);
+    }
+
+    public RangingCapabilities(
+            boolean supportsDistance,
+            boolean supportsAzimuthalAngle,
+            boolean supportsElevationAngle,
+            boolean supportsRangingIntervalReconfigure,
+            int minRangingInterval,
+            List<Integer> supportedChannels,
+            List<Integer> supportedNtfConfigs,
+            List<Integer> supportedConfigIds,
+            ImmutableList<Integer> supportedSlotDurations,
+            ImmutableList<Integer> supportedRangingUpdateRates,
+            boolean hasBackgroundRangingSupport) {
+        this.mSupportsDistance = supportsDistance;
+        this.mSupportsAzimuthalAngle = supportsAzimuthalAngle;
+        this.mSupportsElevationAngle = supportsElevationAngle;
+        this.mSupportsRangingIntervalReconfigure = supportsRangingIntervalReconfigure;
+        this.mMinRangingInterval = minRangingInterval;
+        this.mSupportedChannels = supportedChannels;
+        this.mSupportedNtfConfigs = supportedNtfConfigs;
+        this.mSupportedConfigIds = supportedConfigIds;
+        this.mSupportedSlotDurations = supportedSlotDurations;
+        this.mSupportedRangingUpdateRates = supportedRangingUpdateRates;
+        this.mHasBackgroundRangingSupport = hasBackgroundRangingSupport;
+    }
+
+    /** Whether distance ranging is supported. */
+    public boolean supportsDistance() {
+        return mSupportsDistance;
+    }
+
+    /** Whether azimuthal angle of arrival is supported. */
+    public boolean supportsAzimuthalAngle() {
+        return mSupportsAzimuthalAngle;
+    }
+
+    /** Whether elevation angle of arrival is supported. */
+    public boolean supportsElevationAngle() {
+        return mSupportsElevationAngle;
+    }
+
+    /** Whether ranging interval reconfigure is supported. */
+    public boolean supportsRangingIntervalReconfigure() {
+        return mSupportsRangingIntervalReconfigure;
+    }
+
+    /** Gets the minimum supported ranging interval in milliseconds. */
+    @IntRange(from = 0)
+    public int getMinRangingInterval() {
+        return mMinRangingInterval;
+    }
+
+    /** Gets the supported channel number. */
+    public List<Integer> getSupportedChannels() {
+        return mSupportedChannels;
+    }
+
+    /**
+     * Gets the supported range data notification configs.
+     *
+     * @hide
+     */
+    public List<Integer> getSupportedNtfConfigs() {
+        return mSupportedNtfConfigs;
+    }
+
+    /** Gets the supported config ids. */
+    public List<Integer> getSupportedConfigIds() {
+        return mSupportedConfigIds;
+    }
+
+    /** Gets the supported slot durations. */
+    public List<Integer> getSupportedSlotDurations() {
+        return mSupportedSlotDurations;
+    }
+
+    /** Gets the supported ranging intervals. */
+    public List<Integer> getSupportedRangingUpdateRates() {
+        return mSupportedRangingUpdateRates;
+    }
+
+    /** Whether background ranging is supported. */
+    public boolean hasBackgroundRangingSupport() {
+        return mHasBackgroundRangingSupport;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingControlee.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingControlee.java
new file mode 100644
index 00000000..18c17aa1
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingControlee.java
@@ -0,0 +1,53 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static java.util.Objects.requireNonNull;
+
+import android.os.Build.VERSION_CODES;
+import android.uwb.UwbManager;
+
+import androidx.annotation.RequiresApi;
+
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.fira.FiraParams;
+
+import java.util.concurrent.Executor;
+
+/** Represents a UWB ranging controlee. */
+@RequiresApi(api = VERSION_CODES.S)
+public class RangingControlee extends RangingDevice {
+
+    RangingControlee(UwbManager manager, Executor executor,
+            OpAsyncCallbackRunner<Boolean> opAsyncCallbackRunner, UwbFeatureFlags uwbFeatureFlags) {
+        super(manager, executor, opAsyncCallbackRunner, uwbFeatureFlags);
+    }
+
+    @Override
+    protected FiraOpenSessionParams getOpenSessionParams() {
+        requireNonNull(mRangingParameters);
+        return ConfigurationManager.createOpenSessionParams(
+                FiraParams.RANGING_DEVICE_TYPE_CONTROLEE, getLocalAddress(), mRangingParameters,
+                mUwbFeatureFlags);
+    }
+
+    @Override
+    protected int hashSessionId(RangingParameters rangingParameters) {
+        UwbAddress controllerAddress = rangingParameters.getPeerAddresses().get(0);
+        return calculateHashedSessionId(controllerAddress, rangingParameters.getComplexChannel());
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingControleeParameters.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingControleeParameters.java
new file mode 100644
index 00000000..f531a54e
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingControleeParameters.java
@@ -0,0 +1,48 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+/** Ranging parameters provided by controlee when a controller adds a controlee. */
+public class RangingControleeParameters {
+    private final UwbAddress mAddress;
+    private final int mSubSessionId;
+    private final byte[] mSubSessionKey;
+
+    public RangingControleeParameters(UwbAddress address, int subSessionId, byte[] subSessionKey) {
+        this.mAddress = address;
+        this.mSubSessionId = subSessionId;
+        this.mSubSessionKey = subSessionKey;
+    }
+
+    public RangingControleeParameters(UwbAddress address) {
+        this.mAddress = address;
+        this.mSubSessionId = 0;
+        this.mSubSessionKey = null;
+    }
+
+    public UwbAddress getAddress() {
+        return mAddress;
+    }
+
+    public int getSubSessionId() {
+        return mSubSessionId;
+    }
+
+    public byte[] getSubSessionKey() {
+        return mSubSessionKey;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingController.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingController.java
new file mode 100644
index 00000000..8c226de9
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingController.java
@@ -0,0 +1,388 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_FAILED_TO_START;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_STOP_RANGING_CALLED;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.INVALID_API_CALL;
+import static com.android.ranging.uwb.backend.internal.Utils.STATUS_OK;
+import static com.android.ranging.uwb.backend.internal.Utils.SUPPORTED_BPRF_PREAMBLE_INDEX;
+import static com.android.ranging.uwb.backend.internal.Utils.TAG;
+import static com.android.ranging.uwb.backend.internal.Utils.UWB_RECONFIGURATION_FAILURE;
+import static com.android.ranging.uwb.backend.internal.Utils.UWB_SYSTEM_CALLBACK_FAILURE;
+
+import static com.google.uwb.support.fira.FiraParams.UWB_CHANNEL_9;
+
+import static java.util.Objects.requireNonNull;
+
+import android.annotation.SuppressLint;
+import android.os.Build.VERSION;
+import android.os.Build.VERSION_CODES;
+import android.util.Log;
+import android.uwb.UwbManager;
+
+import androidx.annotation.Nullable;
+import androidx.annotation.RequiresApi;
+
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.fira.FiraParams;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Random;
+import java.util.concurrent.Executor;
+import java.util.concurrent.ExecutorService;
+
+/** Represents a UWB ranging controller */
+@RequiresApi(api = VERSION_CODES.S)
+public class RangingController extends RangingDevice {
+
+    private final List<UwbAddress> mDynamicallyAddedPeers = new ArrayList<>();
+
+    @Nullable
+    private RangingSessionCallback mRangingSessionCallback;
+
+    RangingController(UwbManager manager, Executor executor,
+            OpAsyncCallbackRunner<Boolean> opAsyncCallbackRunner, UwbFeatureFlags uwbFeatureFlags) {
+        super(manager, executor, opAsyncCallbackRunner, uwbFeatureFlags);
+    }
+
+    @Override
+    protected FiraOpenSessionParams getOpenSessionParams() {
+        requireNonNull(mRangingParameters);
+        return ConfigurationManager.createOpenSessionParams(
+                FiraParams.RANGING_DEVICE_TYPE_CONTROLLER, getLocalAddress(), mRangingParameters,
+                mUwbFeatureFlags);
+    }
+
+    /**
+     * gets complex channel. if it's the first time that this function is called, it will check the
+     * driver and try to get the best-available settings.
+     */
+    @SuppressLint("WrongConstant")
+    public UwbComplexChannel getComplexChannel() {
+        if (isForTesting()) {
+            mComplexChannel =
+                    new UwbComplexChannel(Utils.channelForTesting, Utils.preambleIndexForTesting);
+        }
+        if (mComplexChannel == null) {
+            mComplexChannel = getBestAvailableComplexChannel();
+        }
+        return mComplexChannel;
+    }
+
+    /** Sets complex channel. */
+    public void setComplexChannel(UwbComplexChannel complexChannel) {
+        mComplexChannel = complexChannel;
+    }
+
+    /**
+     * Update the complex channel, even if the complex channel has been set before. Channel 9 is
+     * mandatory to all devices. Since system API hasn't implemented capability check yet, channel 9
+     * is the best guess for now.
+     *
+     * @return The complex channel most suitable for this ranging session.
+     */
+    public UwbComplexChannel getBestAvailableComplexChannel() {
+        int preambleIndex =
+                SUPPORTED_BPRF_PREAMBLE_INDEX.get(
+                        new Random().nextInt(SUPPORTED_BPRF_PREAMBLE_INDEX.size()));
+        UwbComplexChannel availableChannel = new UwbComplexChannel(UWB_CHANNEL_9, preambleIndex);
+        Log.i(TAG, String.format("set complexChannel to %s", availableChannel));
+        return availableChannel;
+    }
+
+    @Override
+    protected int hashSessionId(RangingParameters rangingParameters) {
+        return calculateHashedSessionId(getLocalAddress(), getComplexChannel());
+    }
+
+    @Override
+    protected boolean isKnownPeer(UwbAddress address) {
+        return super.isKnownPeer(address) || mDynamicallyAddedPeers.contains(address);
+    }
+
+    @Override
+    public synchronized int startRanging(
+            RangingSessionCallback callback, ExecutorService backendCallbackExecutor) {
+        requireNonNull(mRangingParameters);
+        if (mComplexChannel == null) {
+            Log.w(TAG, "Need to call getComplexChannel() first");
+            return INVALID_API_CALL;
+        }
+
+        if (ConfigurationManager.isUnicast(mRangingParameters.getUwbConfigId())
+                && mRangingParameters.getPeerAddresses().size() > 1) {
+            Log.w(
+                    TAG,
+                    String.format(
+                            "Config ID %d doesn't support one-to-many",
+                            mRangingParameters.getUwbConfigId()));
+            return INVALID_API_CALL;
+        }
+
+        int status = super.startRanging(callback, backendCallbackExecutor);
+        if (isAlive()) {
+            mRangingSessionCallback = callback;
+        }
+        return status;
+    }
+
+    @Override
+    public synchronized int stopRanging() {
+        int status = super.stopRanging();
+        mDynamicallyAddedPeers.clear();
+        mRangingSessionCallback = null;
+        return status;
+    }
+
+    /**
+     * Add a new controlee to the controller. If the controleer is added successfully, {@link
+     * RangingSessionCallback#onRangingInitialized(UwbDevice)} will be called. If the adding
+     * operation failed, {@link RangingSessionCallback#onRangingSuspended(UwbDevice, int)} will be
+     * called.
+     *
+     * @return {@link Utils#INVALID_API_CALL} if this is a unicast session but multiple peers are
+     * configured.
+     */
+    public synchronized int addControlee(UwbAddress controleeAddress) {
+        Log.i(TAG, String.format("Add UWB peer: %s", controleeAddress));
+        if (!isAlive()) {
+            return INVALID_API_CALL;
+        }
+        if (ConfigurationManager.isUnicast(mRangingParameters.getUwbConfigId())) {
+            return INVALID_API_CALL;
+        }
+        if (isKnownPeer(controleeAddress) || mDynamicallyAddedPeers.contains(controleeAddress)) {
+            return STATUS_OK;
+        }
+        // Reconfigure the session.
+        int[] subSessionIdList = mRangingParameters.getUwbConfigId()
+                == CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR
+                ? new int[]{mRangingParameters.getSubSessionId()}
+                : null;
+        byte[] subSessionKeyInfo = mRangingParameters.getUwbConfigId()
+                == CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR
+                ? mRangingParameters.getSubSessionKeyInfo()
+                : null;
+        boolean success =
+                addControleeAdapter(
+                        new UwbAddress[] {controleeAddress}, subSessionIdList, subSessionKeyInfo);
+
+        RangingSessionCallback callback = mRangingSessionCallback;
+        if (success) {
+            if (callback != null) {
+                runOnBackendCallbackThread(
+                        () ->
+                                callback.onRangingInitialized(
+                                        UwbDevice.createForAddress(controleeAddress.toBytes())));
+            }
+            mDynamicallyAddedPeers.add(controleeAddress);
+        } else {
+            if (callback != null) {
+                runOnBackendCallbackThread(
+                        () ->
+                                callback.onRangingSuspended(
+                                        UwbDevice.createForAddress(controleeAddress.toBytes()),
+                                        REASON_FAILED_TO_START));
+            }
+        }
+
+        return STATUS_OK;
+    }
+
+    /**
+     * Add a new controlee to the controller. If the controlee is added successfully, {@link
+     * RangingSessionCallback#onRangingInitialized(UwbDevice)} will be called. If the adding
+     * operation failed, {@link RangingSessionCallback#onRangingSuspended(UwbDevice, int)} will be
+     * called.
+     *
+     * @return {@link Utils#INVALID_API_CALL} if this is a unicast session but multiple peers are
+     * configured.
+     */
+    public synchronized int addControleeWithSessionParams(RangingControleeParameters params) {
+        UwbAddress controleeAddress = params.getAddress();
+        Log.i(TAG, String.format("Add UWB peer: %s", controleeAddress));
+        if (!isAlive()) {
+            return INVALID_API_CALL;
+        }
+        if (ConfigurationManager.isUnicast(mRangingParameters.getUwbConfigId())) {
+            return INVALID_API_CALL;
+        }
+        if (isKnownPeer(controleeAddress) || mDynamicallyAddedPeers.contains(controleeAddress)) {
+            return STATUS_OK;
+        }
+        // Reconfigure the session.
+        int[] subSessionIdList = mRangingParameters.getUwbConfigId()
+                == CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR
+                ? new int[]{params.getSubSessionId()}
+                : null;
+        byte[] subSessionKeyInfo = mRangingParameters.getUwbConfigId()
+                == CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR
+                ? params.getSubSessionKey()
+                : null;
+        boolean success =
+                addControleeAdapter(
+                        new UwbAddress[] {controleeAddress}, subSessionIdList, subSessionKeyInfo);
+
+        RangingSessionCallback callback = mRangingSessionCallback;
+        if (success) {
+            if (callback != null) {
+                runOnBackendCallbackThread(
+                        () ->
+                                callback.onRangingInitialized(
+                                        UwbDevice.createForAddress(controleeAddress.toBytes())));
+            }
+            mDynamicallyAddedPeers.add(controleeAddress);
+        } else {
+            if (callback != null) {
+                runOnBackendCallbackThread(
+                        () ->
+                                callback.onRangingSuspended(
+                                        UwbDevice.createForAddress(controleeAddress.toBytes()),
+                                        REASON_FAILED_TO_START));
+            }
+        }
+
+        return STATUS_OK;
+    }
+
+    /**
+     * Adapter method for to add controlee, via addControlee() api call for versions T an above.
+     *
+     * @return true if addControlee() was successful.
+     */
+    private synchronized boolean addControleeAdapter(
+            UwbAddress[] controleeAddress,
+            @Nullable int[] subSessionIdList,
+            @Nullable byte[] subSessionKeyInfo) {
+        if (VERSION.SDK_INT < VERSION_CODES.TIRAMISU) {
+            return reconfigureRanging(
+                    ConfigurationManager.createReconfigureParams(
+                                    mRangingParameters.getUwbConfigId(),
+                                    FiraParams.MULTICAST_LIST_UPDATE_ACTION_ADD,
+                                    controleeAddress,
+                                    subSessionIdList,
+                                    subSessionKeyInfo,
+                                    mUwbFeatureFlags)
+                            .toBundle());
+        }
+        return addControlee(
+                ConfigurationManager.createControleeParams(
+                                mRangingParameters.getUwbConfigId(),
+                                FiraParams.MULTICAST_LIST_UPDATE_ACTION_ADD,
+                                controleeAddress,
+                                subSessionIdList,
+                                subSessionKeyInfo,
+                                mUwbFeatureFlags)
+                        .toBundle());
+    }
+
+    /**
+     * Remove a controlee from current session.
+     *
+     * @return returns {@link Utils#STATUS_OK} if the controlee is removed successfully. returns
+     * {@link Utils#INVALID_API_CALL} if:
+     * <ul>
+     *   <li>Provided address is not in the controller's peer list
+     *   <li>The active profile is unicast
+     * </ul>
+     */
+    public synchronized int removeControlee(UwbAddress controleeAddress) {
+        Log.i(TAG, String.format("Remove UWB peer: %s", controleeAddress));
+        if (!isAlive()) {
+            Log.w(TAG, "Attempt to remove controlee while session is not active.");
+            return INVALID_API_CALL;
+        }
+        if (!isKnownPeer(controleeAddress)) {
+            Log.w(TAG, "Attempt to remove non-existing controlee.");
+            return INVALID_API_CALL;
+        }
+
+        // Reconfigure the session.
+        boolean success = removeControleeAdapter(new UwbAddress[] {controleeAddress});
+        if (!success) {
+            return UWB_SYSTEM_CALLBACK_FAILURE;
+        }
+
+        RangingSessionCallback callback = mRangingSessionCallback;
+        if (callback != null) {
+            runOnBackendCallbackThread(
+                    () ->
+                            callback.onRangingSuspended(
+                                    UwbDevice.createForAddress(controleeAddress.toBytes()),
+                                    REASON_STOP_RANGING_CALLED));
+        }
+        mDynamicallyAddedPeers.remove(controleeAddress);
+        return STATUS_OK;
+    }
+
+    /**
+     * Adapter method to remove controlee, via removeControlee() api call for versions T and above.
+     *
+     * @return true if removeControlee() was successful.
+     */
+    private synchronized boolean removeControleeAdapter(UwbAddress[] controleeAddress) {
+        if (VERSION.SDK_INT < VERSION_CODES.TIRAMISU) {
+            return reconfigureRanging(
+                    ConfigurationManager.createReconfigureParams(
+                                    mRangingParameters.getUwbConfigId(),
+                                    FiraParams.MULTICAST_LIST_UPDATE_ACTION_DELETE,
+                                    controleeAddress,
+                                    /* subSessionIdList= */ null,
+                                    /* subSessionKey= */ null,
+                                    mUwbFeatureFlags)
+                            .toBundle());
+        }
+        return removeControlee(
+                ConfigurationManager.createControleeParams(
+                                mRangingParameters.getUwbConfigId(),
+                                FiraParams.MULTICAST_LIST_UPDATE_ACTION_DELETE,
+                                controleeAddress,
+                                /* subSessionIdList= */ null,
+                                /* subSessionKey= */ null,
+                                mUwbFeatureFlags)
+                        .toBundle());
+    }
+
+    /**
+     * Reconfigures ranging interval for an ongoing session
+     *
+     * @return STATUS_OK if reconfigure was successful.
+     *         UWB_RECONFIGURATION_FAILURE if reconfigure failed.
+     *         INVALID_API_CALL if ranging session is not active.
+     */
+    public synchronized int setBlockStriding(int blockStridingLength) {
+        if (!isAlive()) {
+            Log.w(TAG, "Attempt to set block striding while session is not active.");
+            return INVALID_API_CALL;
+        }
+
+        boolean success =
+                reconfigureRanging(
+                        ConfigurationManager.createReconfigureParamsBlockStriding(
+                                        blockStridingLength)
+                                .toBundle());
+
+        if (!success) {
+            Log.w(TAG, "Reconfiguring ranging interval failed");
+            return UWB_RECONFIGURATION_FAILURE;
+        }
+        return STATUS_OK;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingDevice.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingDevice.java
new file mode 100644
index 00000000..0ecfdf67
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingDevice.java
@@ -0,0 +1,645 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_FAILED_TO_START;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_STOP_RANGING_CALLED;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_WRONG_PARAMETERS;
+import static com.android.ranging.uwb.backend.internal.Utils.INVALID_API_CALL;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGING_ALREADY_STARTED;
+import static com.android.ranging.uwb.backend.internal.Utils.STATUS_OK;
+import static com.android.ranging.uwb.backend.internal.Utils.TAG;
+import static com.android.ranging.uwb.backend.internal.Utils.UWB_RECONFIGURATION_FAILURE;
+import static com.android.ranging.uwb.backend.internal.Utils.UWB_SYSTEM_CALLBACK_FAILURE;
+
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_DT_TAG;
+
+import static java.util.Objects.requireNonNull;
+
+import android.os.Build.VERSION;
+import android.os.Build.VERSION_CODES;
+import android.os.PersistableBundle;
+import android.util.Log;
+import android.uwb.RangingMeasurement;
+import android.uwb.RangingReport;
+import android.uwb.RangingSession;
+import android.uwb.UwbManager;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.annotation.WorkerThread;
+
+import com.google.common.hash.Hashing;
+import com.google.uwb.support.dltdoa.DlTDoARangingRoundsUpdate;
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.multichip.ChipInfoParams;
+
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.List;
+import java.util.concurrent.Executor;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.atomic.AtomicBoolean;
+
+/** Implements start/stop ranging operations. */
+public abstract class RangingDevice {
+
+    public static final int SESSION_ID_UNSET = 0;
+    private static final String NO_MULTICHIP_SUPPORT = "NO_MULTICHIP_SUPPORT";
+
+    /** Timeout value after ranging start call */
+    private static final int RANGING_START_TIMEOUT_MILLIS = 3100;
+
+    protected final UwbManager mUwbManager;
+
+    private final OpAsyncCallbackRunner<Boolean> mOpAsyncCallbackRunner;
+
+    @Nullable
+    private UwbAddress mLocalAddress;
+
+    @Nullable
+    protected UwbComplexChannel mComplexChannel;
+
+    @Nullable
+    protected RangingParameters mRangingParameters;
+
+    /** A serial thread used by System API to handle session callbacks. */
+    private Executor mSystemCallbackExecutor;
+
+    /** A serial thread used in system API callbacks to handle Backend callbacks */
+    @Nullable
+    private ExecutorService mBackendCallbackExecutor;
+
+    /** NotNull when session opening is successful. Set to Null when session is closed. */
+    @Nullable
+    private RangingSession mRangingSession;
+
+    private AtomicBoolean mIsRanging = new AtomicBoolean(false);
+
+    /** If true, local address and complex channel will be hardcoded */
+    private Boolean mForTesting = false;
+
+    @Nullable
+    private RangingRoundFailureCallback mRangingRoundFailureCallback = null;
+
+    private boolean mRangingReportedAllowed = false;
+
+    @Nullable
+    private String mChipId = null;
+
+    @NonNull
+    protected final UwbFeatureFlags mUwbFeatureFlags;
+
+    private final HashMap<String, UwbAddress> mMultiChipMap;
+
+    RangingDevice(UwbManager manager, Executor executor,
+            OpAsyncCallbackRunner<Boolean> opAsyncCallbackRunner, UwbFeatureFlags uwbFeatureFlags) {
+        mUwbManager = manager;
+        this.mSystemCallbackExecutor = executor;
+        mOpAsyncCallbackRunner = opAsyncCallbackRunner;
+        mOpAsyncCallbackRunner.setOperationTimeoutMillis(RANGING_START_TIMEOUT_MILLIS);
+        mUwbFeatureFlags = uwbFeatureFlags;
+        this.mMultiChipMap = new HashMap<>();
+        initializeUwbAddress();
+    }
+
+    /** Sets the chip ID. By default, the default chip is used. */
+    public void setChipId(String chipId) {
+        mChipId = chipId;
+    }
+
+    public Boolean isForTesting() {
+        return mForTesting;
+    }
+
+    public void setForTesting(Boolean forTesting) {
+        mForTesting = forTesting;
+    }
+
+    /** Gets local address. The first call will return a randomized short address. */
+    public UwbAddress getLocalAddress() {
+        if (isLocalAddressSet()) {
+            return mLocalAddress;
+        }
+        // UwbManager#getDefaultChipId is supported from Android T.
+        if (VERSION.SDK_INT < VERSION_CODES.TIRAMISU) {
+            return getLocalAddress(NO_MULTICHIP_SUPPORT);
+        }
+        String defaultChipId = mUwbManager.getDefaultChipId();
+        return getLocalAddress(defaultChipId);
+    }
+
+    /** Gets local address given chip ID. The first call will return a randomized short address. */
+    public UwbAddress getLocalAddress(String chipId) {
+        if (mMultiChipMap.get(chipId) == null) {
+            mMultiChipMap.put(chipId, getRandomizedLocalAddress());
+        }
+        mLocalAddress = mMultiChipMap.get(chipId);
+        return mLocalAddress;
+    }
+
+    /** Check whether local address was previously set. */
+    public boolean isLocalAddressSet() {
+        return mLocalAddress != null;
+    }
+
+    /** Sets local address. */
+    public void setLocalAddress(UwbAddress localAddress) {
+        mLocalAddress = localAddress;
+    }
+
+    /** Gets a randomized short address. */
+    private UwbAddress getRandomizedLocalAddress() {
+        return UwbAddress.getRandomizedShortAddress();
+    }
+
+    protected abstract int hashSessionId(RangingParameters rangingParameters);
+
+    static int calculateHashedSessionId(
+            UwbAddress controllerAddress, UwbComplexChannel complexChannel) {
+        return Hashing.sha256()
+                .newHasher()
+                .putBytes(controllerAddress.toBytes())
+                .putInt(complexChannel.encode())
+                .hash()
+                .asInt();
+    }
+
+    /** Sets the ranging parameter for this session. */
+    public synchronized void setRangingParameters(RangingParameters rangingParameters) {
+        if (rangingParameters.getSessionId() == SESSION_ID_UNSET) {
+            int sessionId = hashSessionId(rangingParameters);
+            mRangingParameters =
+                    new RangingParameters(
+                            rangingParameters.getUwbConfigId(),
+                            sessionId,
+                            rangingParameters.getSubSessionId(),
+                            rangingParameters.getSessionKeyInfo(),
+                            rangingParameters.getSubSessionKeyInfo(),
+                            rangingParameters.getComplexChannel(),
+                            rangingParameters.getPeerAddresses(),
+                            rangingParameters.getRangingUpdateRate(),
+                            rangingParameters.getUwbRangeDataNtfConfig(),
+                            rangingParameters.getSlotDuration(),
+                            rangingParameters.isAoaDisabled());
+        } else {
+            mRangingParameters = rangingParameters;
+        }
+    }
+
+    /** Alive means the session is open. */
+    public boolean isAlive() {
+        return mRangingSession != null;
+    }
+
+    /**
+     * Is the ranging ongoing or not. Since the device can be stopped by peer or scheduler, the
+     * session can be open but not ranging
+     */
+    public boolean isRanging() {
+        return mIsRanging.get();
+    }
+
+    protected boolean isKnownPeer(UwbAddress address) {
+        requireNonNull(mRangingParameters);
+        return mRangingParameters.getPeerAddresses().contains(address);
+    }
+
+    /**
+     * Converts the {@link RangingReport} to {@link RangingPosition} and invokes the GMSCore
+     * callback.
+     */
+    // Null-guard prevents this from being null
+    private synchronized void onRangingDataReceived(
+            RangingReport rangingReport, RangingSessionCallback callback) {
+        List<RangingMeasurement> measurements = rangingReport.getMeasurements();
+        for (RangingMeasurement measurement : measurements) {
+            byte[] remoteAddressBytes = measurement.getRemoteDeviceAddress().toBytes();
+            if (mUwbFeatureFlags.isReversedByteOrderFiraParams()) {
+                remoteAddressBytes = Conversions.getReverseBytes(remoteAddressBytes);
+            }
+
+
+            UwbAddress peerAddress = UwbAddress.fromBytes(remoteAddressBytes);
+            if (!isKnownPeer(peerAddress) && !Conversions.isDlTdoaMeasurement(measurement)) {
+                Log.w(TAG,
+                        String.format("Received ranging data from unknown peer %s.", peerAddress));
+                continue;
+            }
+
+            if (measurement.getStatus() != RangingMeasurement.RANGING_STATUS_SUCCESS
+                    && mRangingRoundFailureCallback != null) {
+                mRangingRoundFailureCallback.onRangingRoundFailed(peerAddress);
+            }
+
+            RangingPosition currentPosition = Conversions.convertToPosition(measurement);
+            if (currentPosition == null) {
+                continue;
+            }
+            UwbDevice uwbDevice = UwbDevice.createForAddress(peerAddress.toBytes());
+            callback.onRangingResult(uwbDevice, currentPosition);
+        }
+    }
+
+    /**
+     * Run callbacks in {@link RangingSessionCallback} on this thread. Make sure that no lock is
+     * acquired when the callbacks are called since the code is out of this class.
+     */
+    protected void runOnBackendCallbackThread(Runnable action) {
+        requireNonNull(mBackendCallbackExecutor);
+        mBackendCallbackExecutor.execute(action);
+    }
+
+    private UwbDevice getUwbDevice() {
+        return UwbDevice.createForAddress(getLocalAddress().toBytes());
+    }
+
+    private void initializeUwbAddress() {
+        // UwbManager#getChipInfos is supported from Android T.
+        if (VERSION.SDK_INT >= VERSION_CODES.TIRAMISU) {
+            List<PersistableBundle> chipInfoBundles = mUwbManager.getChipInfos();
+            for (PersistableBundle chipInfo : chipInfoBundles) {
+                mMultiChipMap.put(ChipInfoParams.fromBundle(chipInfo).getChipId(),
+                        getRandomizedLocalAddress());
+            }
+        } else {
+            mMultiChipMap.put(NO_MULTICHIP_SUPPORT, getRandomizedLocalAddress());
+        }
+    }
+
+    protected RangingSession.Callback convertCallback(RangingSessionCallback callback) {
+        return new RangingSession.Callback() {
+
+            @WorkerThread
+            @Override
+            public void onOpened(RangingSession session) {
+                mRangingSession = session;
+                mOpAsyncCallbackRunner.complete(true);
+            }
+
+            @WorkerThread
+            @Override
+            public void onOpenFailed(int reason, PersistableBundle params) {
+                Log.i(TAG, String.format("Session open failed: reason %s", reason));
+                int suspendedReason = Conversions.convertReason(reason);
+                if (suspendedReason == REASON_UNKNOWN) {
+                    suspendedReason = REASON_FAILED_TO_START;
+                }
+                int finalSuspendedReason = suspendedReason;
+                runOnBackendCallbackThread(
+                        () -> callback.onRangingSuspended(getUwbDevice(), finalSuspendedReason));
+                mRangingSession = null;
+                mOpAsyncCallbackRunner.complete(false);
+            }
+
+            @WorkerThread
+            @Override
+            public void onStarted(PersistableBundle sessionInfo) {
+                callback.onRangingInitialized(getUwbDevice());
+                mIsRanging.set(true);
+                mOpAsyncCallbackRunner.complete(true);
+            }
+
+            @WorkerThread
+            @Override
+            public void onStartFailed(int reason, PersistableBundle params) {
+
+                int suspendedReason = Conversions.convertReason(reason);
+                if (suspendedReason != REASON_WRONG_PARAMETERS) {
+                    suspendedReason = REASON_FAILED_TO_START;
+                }
+                int finalSuspendedReason = suspendedReason;
+                runOnBackendCallbackThread(
+                        () -> callback.onRangingSuspended(getUwbDevice(), finalSuspendedReason));
+                if (mRangingSession != null) {
+                    mRangingSession.close();
+                }
+                mRangingSession = null;
+                mOpAsyncCallbackRunner.complete(false);
+            }
+
+            @WorkerThread
+            @Override
+            public void onReconfigured(PersistableBundle params) {
+                mOpAsyncCallbackRunner.completeIfActive(true);
+            }
+
+            @WorkerThread
+            @Override
+            public void onReconfigureFailed(int reason, PersistableBundle params) {
+                mOpAsyncCallbackRunner.completeIfActive(false);
+            }
+
+            @WorkerThread
+            @Override
+            public void onStopped(int reason, PersistableBundle params) {
+                int suspendedReason = Conversions.convertReason(reason);
+                UwbDevice device = getUwbDevice();
+                runOnBackendCallbackThread(
+                        () -> {
+                            mIsRanging.set(false);
+                            callback.onRangingSuspended(device, suspendedReason);
+                        });
+                if (suspendedReason == REASON_STOP_RANGING_CALLED
+                        && mOpAsyncCallbackRunner.isActive()) {
+                    mOpAsyncCallbackRunner.complete(true);
+                }
+            }
+
+            @WorkerThread
+            @Override
+            public void onStopFailed(int reason, PersistableBundle params) {
+                mOpAsyncCallbackRunner.completeIfActive(false);
+            }
+
+            @WorkerThread
+            @Override
+            public void onClosed(int reason, PersistableBundle parameters) {
+                UwbDevice device = getUwbDevice();
+                runOnBackendCallbackThread(
+                        () -> {
+                            if (mIsRanging.compareAndSet(true, false)) {
+                                callback.onRangingSuspended(device,
+                                        RangingSessionCallback.REASON_SYSTEM_POLICY);
+                            }
+                        });
+                mRangingSession = null;
+                mOpAsyncCallbackRunner.completeIfActive(true);
+            }
+
+            @WorkerThread
+            @Override
+            public void onReportReceived(RangingReport rangingReport) {
+                if (mRangingReportedAllowed) {
+                    runOnBackendCallbackThread(
+                            () -> onRangingDataReceived(rangingReport, callback));
+                }
+            }
+
+            @WorkerThread
+            @Override
+            public void onRangingRoundsUpdateDtTagStatus(PersistableBundle params) {
+                // Failure to set ranging rounds is not handled.
+                mOpAsyncCallbackRunner.complete(true);
+            }
+
+            @WorkerThread
+            @Override
+            public void onControleeAdded(PersistableBundle params) {
+                mOpAsyncCallbackRunner.complete(true);
+            }
+
+            @WorkerThread
+            @Override
+            public void onControleeAddFailed(int reason, PersistableBundle params) {
+                mOpAsyncCallbackRunner.complete(false);
+            }
+
+            @WorkerThread
+            @Override
+            public void onControleeRemoved(PersistableBundle params) {
+                if (mOpAsyncCallbackRunner.isActive()) {
+                    mOpAsyncCallbackRunner.complete(true);
+                }
+            }
+
+            @WorkerThread
+            @Override
+            public void onControleeRemoveFailed(int reason, PersistableBundle params) {
+                mOpAsyncCallbackRunner.complete(false);
+            }
+        };
+    }
+
+    protected abstract FiraOpenSessionParams getOpenSessionParams();
+
+    private String getString(@Nullable Object o) {
+        if (o == null) {
+            return "null";
+        }
+        if (o instanceof int[]) {
+            return Arrays.toString((int[]) o);
+        }
+
+        if (o instanceof byte[]) {
+            return Arrays.toString((byte[]) o);
+        }
+
+        if (o instanceof long[]) {
+            return Arrays.toString((long[]) o);
+        }
+
+        return o.toString();
+    }
+
+    private void printStartRangingParameters(PersistableBundle parameters) {
+        Log.i(TAG, "Opens UWB session with bundle parameters:");
+        for (String key : parameters.keySet()) {
+            Log.i(TAG, String.format(
+                    "UWB parameter: %s, value: %s", key, getString(parameters.get(key))));
+        }
+    }
+
+    /**
+     * Starts ranging. if an active ranging session exists, return {@link
+     * RangingSessionCallback#REASON_FAILED_TO_START}
+     */
+    @Utils.UwbStatusCodes
+    public synchronized int startRanging(
+            RangingSessionCallback callback, ExecutorService backendCallbackExecutor) {
+        if (isAlive()) {
+            return RANGING_ALREADY_STARTED;
+        }
+
+        if (getLocalAddress() == null) {
+            return INVALID_API_CALL;
+        }
+
+        FiraOpenSessionParams openSessionParams = getOpenSessionParams();
+        printStartRangingParameters(openSessionParams.toBundle());
+        mBackendCallbackExecutor = backendCallbackExecutor;
+        boolean success =
+                mOpAsyncCallbackRunner.execOperation(
+                        () -> {
+                            if (mChipId != null) {
+                                mUwbManager.openRangingSession(
+                                        openSessionParams.toBundle(),
+                                        mSystemCallbackExecutor,
+                                        convertCallback(callback),
+                                        mChipId);
+                            } else {
+                                mUwbManager.openRangingSession(
+                                        openSessionParams.toBundle(),
+                                        mSystemCallbackExecutor,
+                                        convertCallback(callback));
+                            }
+                        },
+                        "Open session");
+
+        Boolean result = mOpAsyncCallbackRunner.getResult();
+        if (!success || result == null || !result) {
+            requireNonNull(mBackendCallbackExecutor);
+            mBackendCallbackExecutor.shutdown();
+            mBackendCallbackExecutor = null;
+            // onRangingSuspended should have been called in the callback.
+            return STATUS_OK;
+        }
+
+        if (openSessionParams.getDeviceRole() == RANGING_DEVICE_DT_TAG) {
+            // Setting default ranging rounds value.
+            DlTDoARangingRoundsUpdate rangingRounds =
+                    new DlTDoARangingRoundsUpdate.Builder()
+                            .setSessionId(openSessionParams.getSessionId())
+                            .setNoOfRangingRounds(1)
+                            .setRangingRoundIndexes(new byte[]{0})
+                            .build();
+            success =
+                    mOpAsyncCallbackRunner.execOperation(
+                            () -> mRangingSession.updateRangingRoundsDtTag(
+                                    rangingRounds.toBundle()),
+                            "Update ranging rounds for Dt Tag");
+        }
+
+        success =
+                mOpAsyncCallbackRunner.execOperation(
+                        () -> mRangingSession.start(new PersistableBundle()), "Start ranging");
+
+        result = mOpAsyncCallbackRunner.getResult();
+        requireNonNull(mBackendCallbackExecutor);
+        if (!success || result == null || !result) {
+            mBackendCallbackExecutor.shutdown();
+            mBackendCallbackExecutor = null;
+        } else {
+            mRangingReportedAllowed = true;
+        }
+        return STATUS_OK;
+    }
+
+    /** Stops ranging if the session is ranging. */
+    public synchronized int stopRanging() {
+        if (!isAlive()) {
+            Log.w(TAG, "UWB stopRanging called without an active session.");
+            return INVALID_API_CALL;
+        }
+        mRangingReportedAllowed = false;
+        if (mIsRanging.get()) {
+            mOpAsyncCallbackRunner.execOperation(
+                    () -> requireNonNull(mRangingSession).stop(), "Stop Ranging");
+        } else {
+            Log.i(TAG, "UWB stopRanging called but isRanging is false.");
+        }
+
+        boolean success =
+                mOpAsyncCallbackRunner.execOperation(
+                        () -> requireNonNull(mRangingSession).close(), "Close Session");
+
+        if (mBackendCallbackExecutor != null) {
+            mBackendCallbackExecutor.shutdown();
+            mBackendCallbackExecutor = null;
+        }
+        mLocalAddress = null;
+        mComplexChannel = null;
+        Boolean result = mOpAsyncCallbackRunner.getResult();
+        if (!success || result == null || !result) {
+            return UWB_SYSTEM_CALLBACK_FAILURE;
+        }
+        return STATUS_OK;
+    }
+
+    /**
+     * Supports ranging configuration change. For example, a new peer is added to the active ranging
+     * session.
+     *
+     * @return returns true if the session is not active or reconfiguration is successful.
+     */
+    protected synchronized boolean reconfigureRanging(PersistableBundle bundle) {
+        boolean success =
+                mOpAsyncCallbackRunner.execOperation(
+                        () -> mRangingSession.reconfigure(bundle), "Reconfigure Ranging");
+        Boolean result = mOpAsyncCallbackRunner.getResult();
+        return success && result != null && result;
+    }
+
+    /**
+     * Adds a controlee to the active UWB ranging session.
+     *
+     * @return true if controlee was successfully added.
+     */
+    protected synchronized boolean addControlee(PersistableBundle bundle) {
+        boolean success =
+                mOpAsyncCallbackRunner.execOperation(
+                        () -> mRangingSession.addControlee(bundle), "Add controlee");
+        Boolean result = mOpAsyncCallbackRunner.getResult();
+        return success && result != null && result;
+    }
+
+    /**
+     * Removes a controlee from active UWB ranging session.
+     *
+     * @return true if controlee was successfully removed.
+     */
+    protected synchronized boolean removeControlee(PersistableBundle bundle) {
+        boolean success =
+                mOpAsyncCallbackRunner.execOperation(
+                        () -> mRangingSession.removeControlee(bundle), "Remove controlee");
+        Boolean result = mOpAsyncCallbackRunner.getResult();
+        return success && result != null && result;
+    }
+
+
+    /**
+     * Reconfigures range data notification for an ongoing session.
+     *
+     * @return STATUS_OK if reconfigure was successful.
+     *         UWB_RECONFIGURATION_FAILURE if reconfigure failed.
+     *         INVALID_API_CALL if ranging session is not active.
+     */
+    public synchronized int reconfigureRangeDataNtfConfig(UwbRangeDataNtfConfig config) {
+        if (!isAlive()) {
+            Log.w(TAG, "Attempt to set range data notification while session is not active.");
+            return INVALID_API_CALL;
+        }
+
+        boolean success =
+                reconfigureRanging(
+                        ConfigurationManager.createReconfigureParamsRangeDataNtf(
+                                config).toBundle());
+
+        if (!success) {
+            Log.w(TAG, "Reconfiguring range data notification config failed.");
+            return UWB_RECONFIGURATION_FAILURE;
+        }
+        return STATUS_OK;
+    }
+
+    /** Notifies that a ranging round failed. We collect this info for Analytics only. */
+    public interface RangingRoundFailureCallback {
+        /** Reports ranging round failed. */
+        void onRangingRoundFailed(UwbAddress peerAddress);
+    }
+
+    /** Sets RangingRoundFailureCallback. */
+    public void setRangingRoundFailureCallback(
+            @Nullable RangingRoundFailureCallback rangingRoundFailureCallback) {
+        this.mRangingRoundFailureCallback = rangingRoundFailureCallback;
+    }
+
+    /** Sets the system callback executor. */
+    public void setSystemCallbackExecutor(Executor executor) {
+        this.mSystemCallbackExecutor = executor;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingMeasurement.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingMeasurement.java
new file mode 100644
index 00000000..8379bffe
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingMeasurement.java
@@ -0,0 +1,57 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.IntDef;
+
+/** Measurement providing the value and confidence of the ranging. */
+public class RangingMeasurement {
+
+    @Confidence private final int mConfidence;
+    private final float mValue;
+    private final boolean mValid;
+
+    public RangingMeasurement(@Confidence int confidence, float value, boolean valid) {
+        this.mConfidence = confidence;
+        this.mValue = value;
+        mValid = valid;
+    }
+
+    /** Gets Confidence of this measurement. */
+    @Confidence
+    public int getConfidence() {
+        return mConfidence;
+    }
+
+    /** Gets value of this measurement. */
+    public float getValue() {
+        return mValue;
+    }
+
+    /** Gets validity of this measurement. */
+    public boolean isValid() {
+        return mValid;
+    }
+
+    /** Possible confidence values for a {@link RangingMeasurement}. */
+    @IntDef({CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH})
+    public @interface Confidence {}
+
+    public static final int CONFIDENCE_LOW = 0;
+    public static final int CONFIDENCE_MEDIUM = 1;
+    public static final int CONFIDENCE_HIGH = 2;
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingParameters.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingParameters.java
new file mode 100644
index 00000000..1955d8cf
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingParameters.java
@@ -0,0 +1,113 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.NonNull;
+
+import com.google.common.collect.ImmutableList;
+
+import java.util.List;
+
+/** Ranging parameters that exposed through public API. */
+public class RangingParameters {
+    @Utils.UwbConfigId
+    private final int mUwbConfigId;
+    private final int mSessionId;
+    private final int mSubSessionId;
+    private final byte[] mSessionKeyInfo;
+    private final byte[] mSubSessionKeyInfo;
+    private final UwbComplexChannel mComplexChannel;
+    private final ImmutableList<UwbAddress> mPeerAddresses;
+    @Utils.RangingUpdateRate
+    private final int mRangingUpdateRate;
+    @NonNull
+    private final UwbRangeDataNtfConfig mUwbRangeDataNtfConfig;
+    @Utils.SlotDuration
+    private final int mSlotDuration;
+    private final boolean mIsAoaDisabled;
+
+    public RangingParameters(
+            @Utils.UwbConfigId int uwbConfigId,
+            int sessionId,
+            int subSessionId,
+            byte[] sessionKeyInfo,
+            byte[] subSessionKeyInfo,
+            UwbComplexChannel complexChannel,
+            List<UwbAddress> peerAddresses,
+            @Utils.RangingUpdateRate int rangingUpdateRate,
+            @NonNull UwbRangeDataNtfConfig uwbRangeDataNtfConfig,
+            @Utils.SlotDuration int slotDuration,
+            boolean isAoaDisabled) {
+        mUwbConfigId = uwbConfigId;
+        mSessionId = sessionId;
+        mSubSessionId = subSessionId;
+        mSessionKeyInfo = sessionKeyInfo;
+        mSubSessionKeyInfo = subSessionKeyInfo;
+        mComplexChannel = complexChannel;
+        mPeerAddresses = ImmutableList.copyOf(peerAddresses);
+        mRangingUpdateRate = rangingUpdateRate;
+        mUwbRangeDataNtfConfig = uwbRangeDataNtfConfig;
+        mSlotDuration = slotDuration;
+        mIsAoaDisabled = isAoaDisabled;
+    }
+
+    public int getSessionId() {
+        return mSessionId;
+    }
+
+    public int getSubSessionId() {
+        return mSubSessionId;
+    }
+
+    @Utils.UwbConfigId
+    public int getUwbConfigId() {
+        return mUwbConfigId;
+    }
+
+    public byte[] getSessionKeyInfo() {
+        return mSessionKeyInfo;
+    }
+
+    public byte[] getSubSessionKeyInfo() {
+        return mSubSessionKeyInfo;
+    }
+
+    public UwbComplexChannel getComplexChannel() {
+        return mComplexChannel;
+    }
+
+    public ImmutableList<UwbAddress> getPeerAddresses() {
+        return mPeerAddresses;
+    }
+
+    public int getRangingUpdateRate() {
+        return mRangingUpdateRate;
+    }
+
+    public UwbRangeDataNtfConfig getUwbRangeDataNtfConfig() {
+        return mUwbRangeDataNtfConfig;
+    }
+
+    @Utils.SlotDuration
+    public int getSlotDuration() {
+        return mSlotDuration;
+    }
+
+    public boolean isAoaDisabled() {
+        return mIsAoaDisabled;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingPosition.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingPosition.java
new file mode 100644
index 00000000..c33aa6f9
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingPosition.java
@@ -0,0 +1,125 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.IntRange;
+import androidx.annotation.Nullable;
+
+import java.util.Locale;
+
+/** Position of a device during ranging. */
+public class RangingPosition {
+    public static final int RSSI_UNKNOWN = -128;
+    public static final int RSSI_MIN = -127;
+    public static final int RSSI_MAX = -1;
+
+    private final RangingMeasurement mDistance;
+    @Nullable private final RangingMeasurement mAzimuth;
+    @Nullable private final RangingMeasurement mElevation;
+    @Nullable private final DlTdoaMeasurement mDlTdoaMeasurement;
+    private final long mElapsedRealtimeNanos;
+    private final int mRssi;
+
+    public RangingPosition(
+            RangingMeasurement distance,
+            @Nullable RangingMeasurement azimuth,
+            @Nullable RangingMeasurement elevation,
+            long elapsedRealtimeNanos) {
+        this(distance,
+                azimuth,
+                elevation,
+                null, // DlTdoaMeasurement
+                elapsedRealtimeNanos,
+                RSSI_UNKNOWN);
+    }
+
+    public RangingPosition(
+            RangingMeasurement distance,
+            @Nullable RangingMeasurement azimuth,
+            @Nullable RangingMeasurement elevation,
+            @Nullable DlTdoaMeasurement dlTdoaMeasurement,
+            long elapsedRealtimeNanos,
+            int rssi) {
+        this.mDistance = distance;
+        this.mAzimuth = azimuth;
+        this.mElevation = elevation;
+        this.mDlTdoaMeasurement = dlTdoaMeasurement;
+        this.mElapsedRealtimeNanos = elapsedRealtimeNanos;
+        this.mRssi = rssi;
+    }
+
+    /** Gets the distance in meters of the ranging device, or null if not available. */
+    public RangingMeasurement getDistance() {
+        return mDistance;
+    }
+
+    /**
+     * Gets the azimuth angle in radians of the ranging device, or null if not available.
+     */
+    @Nullable
+    public RangingMeasurement getAzimuth() {
+        return mAzimuth;
+    }
+
+    /**
+     * Gets the elevation angle in radians of the ranging device, or null if not available.
+     */
+    @Nullable
+    public RangingMeasurement getElevation() {
+        return mElevation;
+    }
+
+    /** Returns nanoseconds since boot when the ranging position was taken. */
+    public long getElapsedRealtimeNanos() {
+        return mElapsedRealtimeNanos;
+    }
+
+    /** Returns the measured RSSI in dBm. */
+    @IntRange(from = RSSI_UNKNOWN, to = RSSI_MAX)
+    public int getRssiDbm() {
+        return mRssi;
+    }
+
+    /**
+     * Gets {@link DlTdoaMeasurement} related to Dl-TDoA, or null if not available
+     */
+    @Nullable
+    public DlTdoaMeasurement getDlTdoaMeasurement() {
+        return mDlTdoaMeasurement;
+    }
+
+    @Override
+    public String toString() {
+        String formatted =
+                String.format(
+                        Locale.US,
+                        "elapsedRealtime (ms) %d | distance (m) %f",
+                        mElapsedRealtimeNanos / 1000000,
+                        mDistance.getValue());
+        if (mAzimuth != null) {
+            formatted += String.format(Locale.US, " | azimuth: %f", mAzimuth.getValue());
+        }
+        if (mElevation != null) {
+            formatted += String.format(Locale.US, " | elevation: %f", mElevation.getValue());
+        }
+        formatted += String.format(Locale.US, " | rssi: %d", mRssi);
+        if (mDlTdoaMeasurement != null) {
+            formatted += String.format(Locale.US, " | dlTdoa: %s", mDlTdoaMeasurement);
+        }
+        return formatted;
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingSessionCallback.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingSessionCallback.java
new file mode 100644
index 00000000..1152092d
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingSessionCallback.java
@@ -0,0 +1,53 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.IntDef;
+
+/** Callbacks used by startRanging. */
+public interface RangingSessionCallback {
+
+    /** Callback when a ranging session has been initiated. */
+    void onRangingInitialized(UwbDevice device);
+
+    /** Callback when a ranging device's position is received. */
+    void onRangingResult(UwbDevice device, RangingPosition position);
+
+    /** Callback when a session has been suspended. */
+    void onRangingSuspended(UwbDevice device, @RangingSuspendedReason int reason);
+
+    /** Reason why ranging was stopped. */
+    @IntDef({
+            REASON_UNKNOWN,
+            REASON_WRONG_PARAMETERS,
+            REASON_FAILED_TO_START,
+            REASON_STOPPED_BY_PEER,
+            REASON_STOP_RANGING_CALLED,
+            REASON_MAX_RANGING_ROUND_RETRY_REACHED,
+            REASON_SYSTEM_POLICY,
+    })
+    @interface RangingSuspendedReason {
+    }
+
+    int REASON_UNKNOWN = 0;
+    int REASON_WRONG_PARAMETERS = 1;
+    int REASON_FAILED_TO_START = 2;
+    int REASON_STOPPED_BY_PEER = 3;
+    int REASON_STOP_RANGING_CALLED = 4;
+    int REASON_MAX_RANGING_ROUND_RETRY_REACHED = 5;
+    int REASON_SYSTEM_POLICY = 6;
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingTimingParams.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingTimingParams.java
new file mode 100644
index 00000000..cc516be4
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/RangingTimingParams.java
@@ -0,0 +1,88 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+/** Timing-related parameters. */
+public class RangingTimingParams {
+
+    private final int mRangingIntervalNormal;
+    private final int mRangingIntervalFast;
+    private final int mRangingIntervalInfrequent;
+    private final int mSlotPerRangingRound;
+    private final int mSlotDurationRstu;
+    private final int mInitiationTimeMs;
+    private final boolean mHoppingEnabled;
+
+    RangingTimingParams(
+            int rangingIntervalNormal,
+            int rangingIntervalFast,
+            int rangingIntervalInfrequent,
+            int slotPerRangingRound,
+            int slotDurationRstu,
+            int initiationTimeMs,
+            boolean hoppingEnabled) {
+        mRangingIntervalNormal = rangingIntervalNormal;
+        mRangingIntervalFast = rangingIntervalFast;
+        mRangingIntervalInfrequent = rangingIntervalInfrequent;
+        mSlotPerRangingRound = slotPerRangingRound;
+        mSlotDurationRstu = slotDurationRstu;
+        mInitiationTimeMs = initiationTimeMs;
+        mHoppingEnabled = hoppingEnabled;
+    }
+
+    public int getRangingIntervalNormal() {
+        return mRangingIntervalNormal;
+    }
+
+    public int getRangingIntervalFast() {
+        return mRangingIntervalFast;
+    }
+
+    public int getRangingIntervalInfrequent() {
+        return mRangingIntervalInfrequent;
+    }
+
+    public int getSlotPerRangingRound() {
+        return mSlotPerRangingRound;
+    }
+
+    public int getSlotDurationRstu() {
+        return mSlotDurationRstu;
+    }
+
+    public int getInitiationTimeMs() {
+        return mInitiationTimeMs;
+    }
+
+    public boolean isHoppingEnabled() {
+        return mHoppingEnabled;
+    }
+
+    /** Converts updateRate to numerical ranging interval value. */
+    public int getRangingInterval(@Utils.RangingUpdateRate int updateRate) {
+        switch (updateRate) {
+            case Utils.NORMAL:
+                return mRangingIntervalNormal;
+            case Utils.INFREQUENT:
+                return mRangingIntervalInfrequent;
+            case Utils.FAST:
+                return mRangingIntervalFast;
+            default:
+                throw new IllegalArgumentException("Argument updateRate is invalid.");
+        }
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Utils.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Utils.java
new file mode 100644
index 00000000..af65c7df
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/Utils.java
@@ -0,0 +1,387 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_DISABLE;
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_ENABLE;
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG;
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_LEVEL_TRIG;
+
+import android.util.ArrayMap;
+
+import androidx.annotation.IntDef;
+
+import com.google.common.collect.ImmutableList;
+import com.google.uwb.support.fira.FiraParams;
+
+import java.util.Map;
+
+/** Definitions that are common for all classes. */
+public final class Utils {
+
+    public static final String TAG = "UwbBackend";
+
+    /** Supported Ranging configurations. */
+    @IntDef({
+        CONFIG_UNICAST_DS_TWR,
+        CONFIG_MULTICAST_DS_TWR,
+        CONFIG_UNICAST_DS_TWR_NO_AOA,
+        CONFIG_PROVISIONED_UNICAST_DS_TWR,
+        CONFIG_PROVISIONED_MULTICAST_DS_TWR,
+        CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA,
+        CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR,
+        CONFIG_MULTICAST_DS_TWR_NO_AOA,
+        CONFIG_DL_TDOA_DT_TAG,
+        CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE,
+        CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF
+    })
+    public @interface UwbConfigId {}
+
+    /**
+     * FiRa-defined unicast {@code STATIC STS DS-TWR} ranging, deferred mode, ranging interval 240
+     * ms.
+     *
+     * <p>Typical use case: device tracking tags.
+     */
+    public static final int CONFIG_UNICAST_DS_TWR = 1;
+
+    public static final int CONFIG_MULTICAST_DS_TWR = 2;
+
+    /** Same as {@code CONFIG_ID_1}, except Angle-of-arrival (AoA) data is not reported. */
+    public static final int CONFIG_UNICAST_DS_TWR_NO_AOA = 3;
+
+    /** Same as {@code CONFIG_ID_1}, except P-STS security mode is enabled. */
+    public static final int CONFIG_PROVISIONED_UNICAST_DS_TWR = 4;
+
+    /** Same as {@code CONFIG_ID_2}, except P-STS security mode is enabled. */
+    public static final int CONFIG_PROVISIONED_MULTICAST_DS_TWR = 5;
+
+    /** Same as {@code CONFIG_ID_3}, except P-STS security mode is enabled. */
+    public static final int CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA = 6;
+
+    /** Same as {@code CONFIG_ID_2}, except P-STS individual controlee key mode is enabled. */
+    public static final int CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR = 7;
+
+    /** Same as {@code CONFIG_ID_3}, except not unicast @Hide */
+    public static final int CONFIG_MULTICAST_DS_TWR_NO_AOA = 1000;
+
+    /** FiRa- defined Downlink-TDoA for DT-Tag ranging */
+    public static final int CONFIG_DL_TDOA_DT_TAG = 1001;
+
+    /**
+     * Same as {@code CONFIG_ID_4}, except result report phase is disabled, fast ranging interval 96
+     * ms, filtering disabled, @Hide
+     */
+    public static final int CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE = 1002;
+
+    /** Same as {@code CONFIG_ID_1002}, except PRF mode is HPRF, @Hide */
+    public static final int CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF = 1003;
+
+    @IntDef({
+        INFREQUENT,
+        NORMAL,
+        FAST,
+    })
+    public @interface RangingUpdateRate {}
+
+    /**
+     * Reports ranging data in hundreds of milliseconds (depending on the ranging interval setting
+     * of the config)
+     */
+    public static final int NORMAL = 1;
+
+    /** Reports ranging data in a couple of seconds (default to 4 seconds). */
+    public static final int INFREQUENT = 2;
+
+    /** Reports ranging data as fast as possible (depending on the device's capability). */
+    public static final int FAST = 3;
+
+    /**
+     * FiRa-defined one-to-many {@code STATIC STS DS-TWR} ranging, deferred mode, ranging interval
+     * 200 ms
+     *
+     * <p>Typical use case: smart phone interacts with many smart devices.
+     */
+    public static final int VENDOR_ID_SIZE = 2;
+
+    public static final int STATIC_STS_IV_SIZE = 6;
+    public static final int STATIC_STS_SESSION_KEY_INFO_SIZE = VENDOR_ID_SIZE + STATIC_STS_IV_SIZE;
+
+    // A map that stores the ranging interval values. The key is config ID.
+    private static final Map<Integer, RangingTimingParams> CONFIG_RANGING_INTERVAL_MAP =
+            new ArrayMap<>();
+
+    /** Sets the default {@link RangingTimingParams} for given config ID. */
+    public static void setRangingTimingParams(
+            @UwbConfigId int configId, RangingTimingParams params) {
+        CONFIG_RANGING_INTERVAL_MAP.put(configId, params);
+    }
+
+    /** Gets the default {@link RangingTimingParams} of given config ID. */
+    public static RangingTimingParams getRangingTimingParams(@UwbConfigId int configId) {
+        return CONFIG_RANGING_INTERVAL_MAP.get(configId);
+    }
+
+    @IntDef({
+        STATUS_OK,
+        STATUS_ERROR,
+        INVALID_API_CALL,
+        RANGING_ALREADY_STARTED,
+        MISSING_PERMISSION_UWB_RANGING,
+        UWB_SYSTEM_CALLBACK_FAILURE
+    })
+    public @interface UwbStatusCodes {}
+
+    // IMPORTANT NOTE: The codes referenced in this file are used on both the client and service
+    // side, and must not be modified after launch. It is fine to add new codes, but previously
+    // existing codes must be left unmodified.
+
+    // Common status codes that may be used by a variety of actions.
+
+    /** The operation was successful. */
+    public static final int STATUS_OK = 0; // 0
+
+    /** The operation failed, without any more information. */
+    public static final int STATUS_ERROR = 1; // 13
+
+    /** The call is not valid. For example, get Complex Channel for the controlee. */
+    public static final int INVALID_API_CALL = 2;
+
+    /** The ranging is already started, this is a duplicated request. */
+    public static final int RANGING_ALREADY_STARTED = 3;
+
+    /** Can't start ranging because the UWB_RANGING permission is not granted. */
+    public static final int MISSING_PERMISSION_UWB_RANGING = 4;
+
+    /** Supported Range Data Notification Config */
+    @androidx.annotation.IntDef(
+            value = {
+                    RANGE_DATA_NTF_DISABLE,
+                    RANGE_DATA_NTF_ENABLE,
+                    RANGE_DATA_NTF_ENABLE_PROXIMITY_LEVEL_TRIG,
+                    RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG,
+            })
+    public @interface RangeDataNtfConfig {}
+
+    public static final int RANGE_DATA_NTF_DISABLE = 0;
+    public static final int RANGE_DATA_NTF_ENABLE = 1;
+    public static final int RANGE_DATA_NTF_ENABLE_PROXIMITY_LEVEL_TRIG = 2;
+    public static final int RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG = 3;
+
+    public static final ImmutableList<Integer> SUPPORTED_NTF_CONFIG =
+            ImmutableList.of(0, 1, 2, 3);
+
+    /** Convert Fira range data Ntf config to Utils range data ntf config.*/
+    public static @Utils.RangeDataNtfConfig int convertFromFiraNtfConfig(
+            @FiraParams.RangeDataNtfConfig int rangeDataConfig) {
+        switch (rangeDataConfig) {
+            case RANGE_DATA_NTF_CONFIG_DISABLE:
+                return RANGE_DATA_NTF_DISABLE;
+            case RANGE_DATA_NTF_CONFIG_ENABLE:
+                return RANGE_DATA_NTF_ENABLE;
+            case RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_LEVEL_TRIG:
+                return RANGE_DATA_NTF_ENABLE_PROXIMITY_LEVEL_TRIG;
+            case RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG :
+                return RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG;
+            default:
+                return RANGE_DATA_NTF_ENABLE;
+        }
+    }
+    /** Convert Utils range data Ntf config to Fira range data ntf config.*/
+    public static @FiraParams.RangeDataNtfConfig int convertToFiraNtfConfig(
+            @Utils.RangeDataNtfConfig int rangeDataConfig) {
+        switch (rangeDataConfig) {
+            case RANGE_DATA_NTF_DISABLE:
+                return RANGE_DATA_NTF_CONFIG_DISABLE;
+            case RANGE_DATA_NTF_ENABLE:
+                return RANGE_DATA_NTF_CONFIG_ENABLE;
+            case RANGE_DATA_NTF_ENABLE_PROXIMITY_LEVEL_TRIG:
+                return RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_LEVEL_TRIG;
+            case RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG :
+                return RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG;
+            default:
+                return RANGE_DATA_NTF_CONFIG_ENABLE;
+        }
+    }
+
+    @IntDef(
+            value = {
+                    DURATION_1_MS,
+                    DURATION_2_MS,
+            }
+    )
+    public @interface SlotDuration {}
+
+    public static final int DURATION_1_MS = 1;
+    public static final int DURATION_2_MS = 2;
+
+    /**
+     * Unusual failures happened in UWB system callback, such as stopping ranging or removing a
+     * known controlee failed.
+     */
+    public static final int UWB_SYSTEM_CALLBACK_FAILURE = 5;
+
+    /** Failed to reconfigure an existing ranging session. */
+    public static final int UWB_RECONFIGURATION_FAILURE = 6;
+
+    static {
+        setRangingTimingParams(
+                CONFIG_UNICAST_DS_TWR,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 240,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 6,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_MULTICAST_DS_TWR,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_UNICAST_DS_TWR_NO_AOA,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 240,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 6,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_PROVISIONED_MULTICAST_DS_TWR,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_DL_TDOA_DT_TAG,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_MULTICAST_DS_TWR_NO_AOA,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 200,
+                        /* rangingIntervalFast= */ 120,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 20,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 240,
+                        /* rangingIntervalFast= */ 96,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 6,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+
+        setRangingTimingParams(
+                CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF,
+                new RangingTimingParams(
+                        /* rangingIntervalNormal= */ 240,
+                        /* rangingIntervalFast= */ 96,
+                        /* rangingIntervalInfrequent= */ 600,
+                        /* slotPerRangingRound= */ 6,
+                        /* slotDurationRstu= */ 2400,
+                        /* initiationTimeMs= */ 0,
+                        /* hoppingEnabled= */ true));
+    }
+
+    public static int channelForTesting = 9;
+    public static int preambleIndexForTesting = 11;
+
+    // Channels defined in FiRa Spec
+    public static final ImmutableList<Integer> SUPPORTED_CHANNELS =
+            ImmutableList.of(5, 6, 8, 9, 10, 12, 13, 14);
+
+    // Preamble index used by BPRF (base pulse repetition frequency) mode. BPRF supports bitrate up
+    // to 6Mb/s, which is good enough for ranging purpose.
+    public static final ImmutableList<Integer> SUPPORTED_BPRF_PREAMBLE_INDEX =
+            ImmutableList.of(9, 10, 11, 12);
+
+    // Preamble index used by HPRF (high pulse repetition frequency) mode. HPRF supports bitrate up
+    // to 31.2 Mbps.
+    public static final ImmutableList<Integer> SUPPORTED_HPRF_PREAMBLE_INDEX =
+            ImmutableList.of(25, 26, 27, 28, 19, 30, 31, 32);
+
+    /** Converts millisecond to RSTU. */
+    public static int convertMsToRstu(int value) {
+        return (int) (value * 499.2 * 1000 / 416);
+    }
+
+    private Utils() {}
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbAddress.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbAddress.java
new file mode 100644
index 00000000..72ab9fe1
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbAddress.java
@@ -0,0 +1,164 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.google.common.base.Objects;
+import com.google.common.primitives.Longs;
+import com.google.common.primitives.Shorts;
+
+import java.security.SecureRandom;
+import java.util.Arrays;
+
+/**
+ * UWB supports two addressing formats: 16-bit short address or 64-bit extended address, This class
+ * provides a way to support both formats in one class.
+ */
+public class UwbAddress {
+
+    public static final int SHORT_ADDRESS_LENGTH = 2;
+    public static final int EXTENDED_ADDRESS_LENGTH = 8;
+
+    /** SHORT means 16-bit address EXTENDED means 64-bit address */
+    public enum AddressingMode {
+        SHORT,
+        EXTENDED
+    }
+
+    private final AddressingMode mAddressingMode;
+    private final byte[] mAddressBytes;
+
+    private UwbAddress(AddressingMode mode, byte[] addressBytes) {
+        this.mAddressingMode = mode;
+        this.mAddressBytes = addressBytes;
+    }
+
+    /** 2 bytes will be converted to short address, 8 bytes to full */
+    public static UwbAddress fromBytes(byte[] address) {
+        if (address.length == SHORT_ADDRESS_LENGTH) {
+            return new UwbAddress(AddressingMode.SHORT, address);
+        }
+
+        if (address.length == EXTENDED_ADDRESS_LENGTH) {
+            return new UwbAddress(AddressingMode.EXTENDED, address);
+        }
+
+        throw new IllegalArgumentException(
+                String.format(
+                        "the address length only can be 2 bytes (SHORT) or 8 bytes (EXTENDED),"
+                                + " passed in %d bytes",
+                        address.length));
+    }
+
+    /** This method provides a way to convert short to/from short address bytes */
+    public static UwbAddress fromShort(short address) {
+        return new UwbAddress(AddressingMode.SHORT, Shorts.toByteArray(address));
+    }
+
+    /** Convert the short address to a short */
+    public static short toShort(UwbAddress address) {
+        if (address.getAddressingMode() != AddressingMode.SHORT) {
+            throw new IllegalArgumentException();
+        }
+
+        return Shorts.fromByteArray(address.mAddressBytes);
+    }
+
+    /** This method provides a way to convert long to/from extended address bytes */
+    public static UwbAddress fromLong(long address) {
+        return new UwbAddress(AddressingMode.EXTENDED, Longs.toByteArray(address));
+    }
+
+    /** Convert the extended address to a long */
+    public static long toLong(UwbAddress address) {
+        if (address.getAddressingMode() != AddressingMode.EXTENDED) {
+            throw new IllegalArgumentException();
+        }
+
+        return Longs.fromByteArray(address.mAddressBytes);
+    }
+
+    private static byte[] generateRandomByteArray(int len, SecureRandom secureRandom) {
+        byte[] bytes = new byte[len];
+        secureRandom.nextBytes(bytes);
+        return bytes;
+    }
+
+    /** Get a randomized short address */
+    public static UwbAddress getRandomizedShortAddress() {
+        SecureRandom secureRandom = new SecureRandom();
+        return fromBytes(generateRandomByteArray(SHORT_ADDRESS_LENGTH, secureRandom));
+    }
+
+    /** Get a randomized extended address */
+    public static UwbAddress getRandomizedExtendedAddress() {
+        SecureRandom secureRandom = new SecureRandom();
+        return fromBytes(generateRandomByteArray(EXTENDED_ADDRESS_LENGTH, secureRandom));
+    }
+
+    public AddressingMode getAddressingMode() {
+        return mAddressingMode;
+    }
+
+    /** Get the address byte array */
+    public byte[] toBytes() {
+        return mAddressBytes.clone();
+    }
+
+    /** How many bytes the address takes */
+    public int size() {
+        if (mAddressingMode == AddressingMode.SHORT) {
+            return SHORT_ADDRESS_LENGTH;
+        }
+
+        return EXTENDED_ADDRESS_LENGTH;
+    }
+
+    /** return the address in hex format */
+    public String toHexString() {
+        StringBuilder stringBuilder = new StringBuilder("0X");
+        for (byte b : mAddressBytes) {
+            stringBuilder.append(String.format("%02X", b));
+        }
+
+        return stringBuilder.toString();
+    }
+
+    @NonNull
+    @Override
+    public String toString() {
+        return toHexString();
+    }
+
+    @Override
+    public boolean equals(@Nullable Object obj) {
+        if (obj instanceof UwbAddress) {
+            UwbAddress that = (UwbAddress) obj;
+            return Objects.equal(mAddressingMode, that.getAddressingMode())
+                    && Arrays.equals(mAddressBytes, that.toBytes());
+        }
+
+        return false;
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hashCode(mAddressingMode, Arrays.hashCode(mAddressBytes));
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbAvailabilityCallback.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbAvailabilityCallback.java
new file mode 100644
index 00000000..c15c4b64
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbAvailabilityCallback.java
@@ -0,0 +1,47 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.IntDef;
+
+/** Callback for UWB availability change events. */
+public interface UwbAvailabilityCallback {
+    void onUwbAvailabilityChanged(boolean isUwbAvailable, int reason);
+
+    /** Reason why UWB state changed */
+    @IntDef({
+            /* The state has changed because of an unknown reason */
+            REASON_UNKNOWN,
+
+            /* The state has changed because UWB is turned on/off */
+            REASON_SYSTEM_POLICY,
+
+            /*
+             * The state has changed either because no country code has been configured or due to
+             *  UWB being
+             * unavailable as a result of regulatory constraints.
+             */
+            REASON_COUNTRY_CODE_ERROR,
+    })
+    @interface UwbStateChangeReason {
+    }
+
+    int REASON_UNKNOWN = 0;
+    int REASON_SYSTEM_POLICY = 1;
+    int REASON_COUNTRY_CODE_ERROR = 2;
+}
+
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbComplexChannel.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbComplexChannel.java
new file mode 100644
index 00000000..33d5016e
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbComplexChannel.java
@@ -0,0 +1,106 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.Utils.SUPPORTED_BPRF_PREAMBLE_INDEX;
+import static com.android.ranging.uwb.backend.internal.Utils.SUPPORTED_CHANNELS;
+import static com.android.ranging.uwb.backend.internal.Utils.SUPPORTED_HPRF_PREAMBLE_INDEX;
+
+import static com.google.common.base.Preconditions.checkArgument;
+
+import com.google.common.primitives.Ints;
+import com.google.uwb.support.fira.FiraParams;
+
+import java.util.Arrays;
+import java.util.Objects;
+
+/** Complex channel used by UWB ranging. */
+public class UwbComplexChannel {
+
+    @FiraParams.UwbChannel private final int mChannel;
+    @FiraParams.UwbPreambleCodeIndex private final int mPreambleIndex;
+
+    public UwbComplexChannel(
+            @FiraParams.UwbChannel int channel,
+            @FiraParams.UwbPreambleCodeIndex int preambleIndex) {
+        checkArgument(SUPPORTED_CHANNELS.contains(channel), "Invalid channel number.");
+        checkArgument(
+                SUPPORTED_BPRF_PREAMBLE_INDEX.contains(preambleIndex)
+                    || SUPPORTED_HPRF_PREAMBLE_INDEX.contains(preambleIndex),
+                "Invalid preamble index.");
+        mChannel = channel;
+        mPreambleIndex = preambleIndex;
+    }
+
+    @FiraParams.UwbChannel
+    public int getChannel() {
+        return mChannel;
+    }
+
+    @FiraParams.UwbPreambleCodeIndex
+    public int getPreambleIndex() {
+        return mPreambleIndex;
+    }
+
+    /**
+     * Pack channel/Preamble Index to a 8-bit integer.
+     *
+     * @return packed 5-bit integer. [4:6] is the channel index [1:3] is the index of the preamble
+     *     index, [0] indicates BPRF (0) or HPRF (1).
+     */
+    public int encode() {
+        int indexOfPreambleInArray = 0;
+        int encodedPrfType = 0;
+        if (mPreambleIndex <= 12) {
+            // BPRF.
+            indexOfPreambleInArray =
+                Arrays.binarySearch(Ints.toArray(SUPPORTED_BPRF_PREAMBLE_INDEX), mPreambleIndex);
+        } else {
+            // HPRF.
+            indexOfPreambleInArray =
+                Arrays.binarySearch(Ints.toArray(SUPPORTED_HPRF_PREAMBLE_INDEX), mPreambleIndex);
+            encodedPrfType = 1;
+        }
+
+        return (Arrays.binarySearch(Ints.toArray(SUPPORTED_CHANNELS), mChannel << 4)
+            | indexOfPreambleInArray << 1
+            | encodedPrfType);
+    }
+
+    @Override
+    public String toString() {
+        return "UwbComplexChannel{"
+                + "mChannel="
+                + mChannel
+                + ", mPreambleIndex="
+                + mPreambleIndex
+                + '}';
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof UwbComplexChannel)) return false;
+        UwbComplexChannel that = (UwbComplexChannel) o;
+        return getChannel() == that.getChannel() && getPreambleIndex() == that.getPreambleIndex();
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(getChannel(), getPreambleIndex());
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbConfiguration.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbConfiguration.java
new file mode 100644
index 00000000..44ad3d4f
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbConfiguration.java
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import com.google.uwb.support.fira.FiraParams;
+
+/** UWB configuration supported by UWB API. */
+public interface UwbConfiguration {
+
+    /** Gets the ID of given configuration. */
+    @Utils.UwbConfigId
+    int getConfigId();
+
+    /** Gets the multi-node mode of given configuration. */
+    @FiraParams.MultiNodeMode
+    int getMultiNodeMode();
+
+    /** Gets the STS config of this configuration. */
+    @FiraParams.StsConfig
+    int getStsConfig();
+
+    /** Gets the AoA result request mode of this configuration. */
+    @FiraParams.AoaResultRequestMode
+    int getAoaResultRequestMode();
+
+    /** Indicates if controller is the initiator. */
+    boolean isControllerTheInitiator();
+
+    /** Gets the Ranging round usage of this configuration. */
+    @FiraParams.RangingRoundUsage
+    int getRangingRoundUsage();
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbDevice.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbDevice.java
new file mode 100644
index 00000000..cac6330a
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbDevice.java
@@ -0,0 +1,63 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import androidx.annotation.Nullable;
+
+import java.util.Objects;
+
+/** Represents a UWB device. */
+public class UwbDevice {
+
+    private final UwbAddress mAddress;
+
+    /** Creates a new UwbDevice from a given address. */
+    public static UwbDevice createForAddress(byte[] address) {
+        return new UwbDevice(UwbAddress.fromBytes(address));
+    }
+
+    private UwbDevice(UwbAddress address) {
+        this.mAddress = address;
+    }
+
+    /** The device address (eg, MAC address). */
+    public UwbAddress getAddress() {
+        return mAddress;
+    }
+
+    @Override
+    public boolean equals(@Nullable Object o) {
+        if (this == o) {
+            return true;
+        }
+        if (!(o instanceof UwbDevice)) {
+            return false;
+        }
+        UwbDevice uwbDevice = (UwbDevice) o;
+        return Objects.equals(mAddress, uwbDevice.mAddress);
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hashCode(mAddress);
+    }
+
+    @Override
+    public String toString() {
+        return String.format("UwbDevice {%s}", mAddress);
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbFeatureFlags.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbFeatureFlags.java
new file mode 100644
index 00000000..92d89e25
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbFeatureFlags.java
@@ -0,0 +1,87 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+/** Uwb feature support flags */
+public class UwbFeatureFlags {
+    private final boolean mSkipRangingCapabilitiesCheck;
+    private final boolean mAzimuthSupport;
+    private final boolean mElevationSupport;
+    private final boolean mReversedByteOrderFiraParams;
+
+    private UwbFeatureFlags(boolean skipRangingCapabilitiesCheck, boolean azimuthSupport,
+            boolean elevationSupport, boolean reversedByteOrderFiraParams) {
+        mSkipRangingCapabilitiesCheck = skipRangingCapabilitiesCheck;
+        mAzimuthSupport = azimuthSupport;
+        mElevationSupport = elevationSupport;
+        mReversedByteOrderFiraParams = reversedByteOrderFiraParams;
+    }
+
+    public boolean skipRangingCapabilitiesCheck() {
+        return mSkipRangingCapabilitiesCheck;
+    }
+
+    public boolean hasAzimuthSupport() {
+        return mAzimuthSupport;
+    }
+
+    public boolean hasElevationSupport() {
+        return mElevationSupport;
+    }
+
+    public boolean isReversedByteOrderFiraParams() {
+        return mReversedByteOrderFiraParams;
+    }
+
+    /** Builder */
+    public static class Builder {
+        private boolean mSkipRangingCapabilitiesCheck = false;
+        private boolean mAzimuthSupport = false;
+        private boolean mElevationSupport = false;
+        private boolean mReversedByteOrderFiraParams = false;
+
+        public UwbFeatureFlags.Builder setSkipRangingCapabilitiesCheck(
+                boolean skipRangingCapabilitiesCheck) {
+            mSkipRangingCapabilitiesCheck = skipRangingCapabilitiesCheck;
+            return this;
+        }
+
+        public UwbFeatureFlags.Builder setAzimuthSupport(boolean azimuthSupport) {
+            mAzimuthSupport = azimuthSupport;
+            return this;
+        }
+
+        public UwbFeatureFlags.Builder setElevationSupport(boolean elevationSupport) {
+            mElevationSupport = elevationSupport;
+            return this;
+        }
+
+        public UwbFeatureFlags.Builder setReversedByteOrderFiraParams(
+                boolean reversedByteOrderFiraParams) {
+            mReversedByteOrderFiraParams = reversedByteOrderFiraParams;
+            return this;
+        }
+
+        public UwbFeatureFlags build() {
+            return new UwbFeatureFlags(
+                    mSkipRangingCapabilitiesCheck,
+                    mAzimuthSupport,
+                    mElevationSupport,
+                    mReversedByteOrderFiraParams);
+        }
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbRangeDataNtfConfig.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbRangeDataNtfConfig.java
new file mode 100644
index 00000000..994b0289
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbRangeDataNtfConfig.java
@@ -0,0 +1,111 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE;
+import static com.android.ranging.uwb.backend.internal.Utils.SUPPORTED_NTF_CONFIG;
+
+import static com.google.common.base.Preconditions.checkArgument;
+
+import java.util.Objects;
+
+import javax.annotation.Nonnegative;
+
+/** Configurable Range Data Ntf reports for a UWB session */
+public class UwbRangeDataNtfConfig {
+
+    @Utils.RangeDataNtfConfig
+    private final int mRangeDataNtfConfigType;
+    private final int mNtfProximityNear;
+    private final int mNtfProximityFar;
+
+    private UwbRangeDataNtfConfig(
+            @Utils.RangeDataNtfConfig int rangeDataNtfConfigType,
+            @Nonnegative int ntfProximityNear,
+            @Nonnegative int ntfProximityFar) {
+        checkArgument(SUPPORTED_NTF_CONFIG.contains(rangeDataNtfConfigType),
+                "Invalid/Unsupported Range Data Ntf config");
+        checkArgument(ntfProximityNear <= ntfProximityFar,
+                "Ntf proximity near cannot be greater than Ntf proximity far");
+        mRangeDataNtfConfigType = rangeDataNtfConfigType;
+        mNtfProximityNear = ntfProximityNear;
+        mNtfProximityFar = ntfProximityFar;
+    }
+
+    public int getRangeDataNtfConfigType() {
+        return mRangeDataNtfConfigType;
+    }
+
+    public int getNtfProximityNear() {
+        return mNtfProximityNear;
+    }
+
+    public int getNtfProximityFar() {
+        return mNtfProximityFar;
+    }
+
+    /** Builder for UwbRangeDataNtfConfig */
+    public static class Builder {
+        private int mRangeDataConfigType = RANGE_DATA_NTF_ENABLE;
+        private int mNtfProximityNear = 0;
+        private int mNtfProximityFar = 20_000;
+
+        public Builder setRangeDataConfigType(int rangeDataConfig) {
+            mRangeDataConfigType = rangeDataConfig;
+            return this;
+        }
+
+        public Builder setNtfProximityNear(int ntfProximityNear) {
+            mNtfProximityNear = ntfProximityNear;
+            return this;
+        }
+
+        public Builder setNtfProximityFar(int ntfProximityFar) {
+            mNtfProximityFar = ntfProximityFar;
+            return this;
+        }
+
+        public UwbRangeDataNtfConfig build() {
+            return new UwbRangeDataNtfConfig(mRangeDataConfigType, mNtfProximityNear,
+                    mNtfProximityFar);
+        }
+    }
+
+    @Override
+    public String toString() {
+        return "UwbRangeDataNtfConfig{"
+                + "mRangeDataNtfConfigType=" + mRangeDataNtfConfigType
+                + ", mNtfProximityNear=" + mNtfProximityNear
+                + ", mNtfProximityFar=" + mNtfProximityFar
+                + '}';
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof UwbRangeDataNtfConfig)) return false;
+        UwbRangeDataNtfConfig that = (UwbRangeDataNtfConfig) o;
+        return mRangeDataNtfConfigType == that.mRangeDataNtfConfigType
+                && mNtfProximityNear == that.mNtfProximityNear
+                && mNtfProximityFar == that.mNtfProximityFar;
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mRangeDataNtfConfigType, mNtfProximityNear, mNtfProximityFar);
+    }
+}
diff --git a/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbServiceImpl.java b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbServiceImpl.java
new file mode 100644
index 00000000..b53f90b4
--- /dev/null
+++ b/generic_ranging/uwb_backend/src/com/android/ranging/uwb/backend/internal/UwbServiceImpl.java
@@ -0,0 +1,268 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static android.content.pm.PackageManager.FEATURE_UWB;
+import static android.uwb.UwbManager.AdapterStateCallback.STATE_DISABLED;
+
+import static com.android.ranging.uwb.backend.internal.RangingCapabilities.DEFAULT_SUPPORTED_RANGING_UPDATE_RATE;
+import static com.android.ranging.uwb.backend.internal.RangingCapabilities.DEFAULT_SUPPORTED_SLOT_DURATIONS;
+import static com.android.ranging.uwb.backend.internal.RangingCapabilities.FIRA_DEFAULT_SUPPORTED_CONFIG_IDS;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_DL_TDOA_DT_TAG;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE;
+import static com.android.ranging.uwb.backend.internal.UwbAvailabilityCallback.REASON_UNKNOWN;
+
+import static java.util.Objects.requireNonNull;
+
+import android.content.Context;
+import android.os.Build.VERSION;
+import android.os.Build.VERSION_CODES;
+import android.os.PersistableBundle;
+import android.uwb.UwbManager;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.google.common.collect.ImmutableList;
+import com.google.uwb.support.fira.FiraParams;
+import com.google.uwb.support.fira.FiraSpecificationParams;
+import com.google.uwb.support.multichip.ChipInfoParams;
+
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.EnumSet;
+import java.util.List;
+import java.util.Set;
+import java.util.TreeSet;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+
+/** Implements UWB session creation, adaptor state tracking and ranging capability reporting. */
+public class UwbServiceImpl {
+
+    private static final String FIRA_SPECIFICATION_BUNDLE_KEY = "fira";
+
+    private int mAdapterState = STATE_DISABLED;
+    private final boolean mHasUwbFeature;
+    @Nullable
+    private final UwbManager mUwbManager;
+    @NonNull
+    private final UwbFeatureFlags mUwbFeatureFlags;
+    @NonNull
+    private final UwbAvailabilityCallback mUwbAvailabilityCallback;
+
+
+    /** A serial thread used to handle session callback */
+    private final ExecutorService mSerialExecutor = Executors.newSingleThreadExecutor();
+
+    /** Adapter State callback used to update adapterState field */
+    private final UwbManager.AdapterStateCallback mAdapterStateCallback;
+    @UwbAvailabilityCallback.UwbStateChangeReason
+    private int mLastStateChangeReason = REASON_UNKNOWN;
+
+    public UwbServiceImpl(Context context, @NonNull UwbFeatureFlags uwbFeatureFlags,
+            UwbAvailabilityCallback uwbAvailabilityCallback) {
+        mHasUwbFeature = context.getPackageManager().hasSystemFeature(FEATURE_UWB);
+        mUwbFeatureFlags = uwbFeatureFlags;
+        mUwbAvailabilityCallback = uwbAvailabilityCallback;
+        this.mAdapterStateCallback =
+                (newState, reason) -> {
+                    mLastStateChangeReason = Conversions.convertAdapterStateReason(reason);
+                    // Send update only if old or new state is disabled, ignore if state
+                    // changed from active
+                    // to inactive and vice-versa.
+                    int oldState = mAdapterState;
+                    mAdapterState = newState;
+                    if (newState == STATE_DISABLED || oldState == STATE_DISABLED) {
+                        mSerialExecutor.execute(
+                                () -> mUwbAvailabilityCallback.onUwbAvailabilityChanged(
+                                        isAvailable(), mLastStateChangeReason));
+                    }
+                };
+        if (mHasUwbFeature) {
+            mUwbManager = context.getSystemService(UwbManager.class);
+            requireNonNull(mUwbManager);
+            // getAdapterState was added in Android T.
+            if (VERSION.SDK_INT >= VERSION_CODES.TIRAMISU) {
+                mAdapterState = mUwbManager.getAdapterState();
+            }
+            mUwbManager.registerAdapterStateCallback(mSerialExecutor, mAdapterStateCallback);
+        } else {
+            mUwbManager = null;
+        }
+    }
+
+    /** Gets a Ranging Controller session with given context. */
+    public RangingController getController(Context context) {
+        UwbManager uwbManagerWithContext = context.getSystemService(UwbManager.class);
+        return new RangingController(
+                uwbManagerWithContext, mSerialExecutor, new OpAsyncCallbackRunner<>(),
+                mUwbFeatureFlags);
+    }
+
+    /** Gets a Ranging Controlee session with given context. */
+    public RangingControlee getControlee(Context context) {
+        UwbManager uwbManagerWithContext = context.getSystemService(UwbManager.class);
+        return new RangingControlee(
+                uwbManagerWithContext, mSerialExecutor, new OpAsyncCallbackRunner<>(),
+                mUwbFeatureFlags);
+    }
+
+    /** Returns multi-chip information. */
+    public List<ChipInfoParams> getChipInfos() {
+        List<PersistableBundle> chipInfoBundles = mUwbManager.getChipInfos();
+        List<ChipInfoParams> chipInfos = new ArrayList<>();
+        for (PersistableBundle chipInfo : chipInfoBundles) {
+            chipInfos.add(ChipInfoParams.fromBundle(chipInfo));
+        }
+        return chipInfos;
+    }
+
+    /** Gets the default chip of the system. */
+    String getDefaultChipId() {
+        return mUwbManager.getDefaultChipId();
+    }
+
+    /**
+     * Cleans up any resource such as threads, registered listeners, receivers or any cached data,
+     * called when the service destroyed.
+     */
+    public void shutdown() {
+        mSerialExecutor.shutdown();
+        if (mUwbManager != null) {
+            mUwbManager.unregisterAdapterStateCallback(mAdapterStateCallback);
+        }
+    }
+
+    /** True if UWB is available. */
+    public boolean isAvailable() {
+        return mHasUwbFeature && mAdapterState != STATE_DISABLED;
+    }
+
+    /** Gets the reason code for last state change. */
+    public int getLastStateChangeReason() {
+        return mLastStateChangeReason;
+    }
+
+    /** Gets ranging capabilities of the device. */
+    public RangingCapabilities getRangingCapabilities() {
+        requireNonNull(mUwbManager);
+        requireNonNull(mUwbFeatureFlags);
+
+        if (mUwbFeatureFlags.skipRangingCapabilitiesCheck()
+                && VERSION.SDK_INT < VERSION_CODES.TIRAMISU) {
+            return new RangingCapabilities(
+                    /* supportsDistance= */ true,
+                    mUwbFeatureFlags.hasAzimuthSupport(),
+                    mUwbFeatureFlags.hasElevationSupport(),
+                    /* supportsRangingIntervalReconfigure */ false,
+                    /* minRangingInterval= */ RangingCapabilities.FIRA_DEFAULT_RANGING_INTERVAL_MS,
+                    new ArrayList<Integer>(RangingCapabilities.FIRA_DEFAULT_SUPPORTED_CHANNEL),
+                    new ArrayList<>(RANGE_DATA_NTF_ENABLE),
+                    FIRA_DEFAULT_SUPPORTED_CONFIG_IDS,
+                    DEFAULT_SUPPORTED_SLOT_DURATIONS,
+                    DEFAULT_SUPPORTED_RANGING_UPDATE_RATE,
+                    /* hasBackgroundRangingSupport */ false);
+        }
+
+        PersistableBundle bundle = mUwbManager.getSpecificationInfo();
+        if (bundle.keySet().contains(FIRA_SPECIFICATION_BUNDLE_KEY)) {
+            bundle = requireNonNull(bundle.getPersistableBundle(FIRA_SPECIFICATION_BUNDLE_KEY));
+        }
+        FiraSpecificationParams specificationParams = FiraSpecificationParams.fromBundle(bundle);
+        int minRangingInterval = specificationParams.getMinRangingInterval();
+        EnumSet<FiraParams.AoaCapabilityFlag> aoaCapabilityFlags =
+                specificationParams.getAoaCapabilities();
+        List<Integer> supportedChannels = specificationParams.getSupportedChannels();
+        if (minRangingInterval <= 0) {
+            minRangingInterval = RangingCapabilities.FIRA_DEFAULT_RANGING_INTERVAL_MS;
+        }
+        List<Integer> supportedRangingUpdateRates = new ArrayList<>(
+                DEFAULT_SUPPORTED_RANGING_UPDATE_RATE);
+        if (minRangingInterval <= 120) {
+            supportedRangingUpdateRates.add(Utils.FAST);
+        }
+        if (supportedChannels == null || supportedChannels.isEmpty()) {
+            supportedChannels =
+                    new ArrayList<>(RangingCapabilities.FIRA_DEFAULT_SUPPORTED_CHANNEL);
+        }
+
+        Set<Integer> supportedNtfConfigsSet = new TreeSet<>();
+        for (FiraParams.RangeDataNtfConfigCapabilityFlag e :
+                specificationParams.getRangeDataNtfConfigCapabilities()) {
+            supportedNtfConfigsSet.add(Utils.convertFromFiraNtfConfig(e.ordinal()));
+        }
+        List<Integer> supportedNtfConfigs = new ArrayList<>(supportedNtfConfigsSet);
+
+        List<Integer> supportedConfigIds = new ArrayList<>(FIRA_DEFAULT_SUPPORTED_CONFIG_IDS);
+        EnumSet<FiraParams.StsCapabilityFlag> stsCapabilityFlags =
+                specificationParams.getStsCapabilities();
+        if (stsCapabilityFlags.contains(FiraParams.StsCapabilityFlag.HAS_PROVISIONED_STS_SUPPORT)) {
+            supportedConfigIds.add(CONFIG_PROVISIONED_UNICAST_DS_TWR);
+            supportedConfigIds.add(CONFIG_PROVISIONED_MULTICAST_DS_TWR);
+            supportedConfigIds.add(CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_AOA);
+        }
+        if (stsCapabilityFlags.contains(FiraParams.StsCapabilityFlag
+                .HAS_PROVISIONED_STS_INDIVIDUAL_CONTROLEE_KEY_SUPPORT)) {
+            supportedConfigIds.add(CONFIG_PROVISIONED_INDIVIDUAL_MULTICAST_DS_TWR);
+        }
+        EnumSet<FiraParams.RangingRoundCapabilityFlag> rangingRoundCapabilityFlags =
+                specificationParams.getRangingRoundCapabilities();
+        if (rangingRoundCapabilityFlags.contains(FiraParams.RangingRoundCapabilityFlag
+                .HAS_OWR_DL_TDOA_SUPPORT)) {
+            supportedConfigIds.add(CONFIG_DL_TDOA_DT_TAG);
+        }
+        EnumSet<FiraParams.PrfCapabilityFlag> prfModeCapabilityFlags =
+                specificationParams.getPrfCapabilities();
+        if (prfModeCapabilityFlags.contains(FiraParams.PrfCapabilityFlag.HAS_HPRF_SUPPORT)) {
+            supportedConfigIds.add(CONFIG_PROVISIONED_UNICAST_DS_TWR_NO_RESULT_REPORT_PHASE_HPRF);
+        }
+        int minSlotDurationUs = specificationParams.getMinSlotDurationUs();
+        List<Integer> supportedSlotDurations = new ArrayList<>(Arrays.asList(Utils.DURATION_2_MS));
+        if (minSlotDurationUs <= 1000) {
+            supportedSlotDurations.add(Utils.DURATION_1_MS);
+        }
+
+        return new RangingCapabilities(
+                true,
+                aoaCapabilityFlags.contains(FiraParams.AoaCapabilityFlag.HAS_AZIMUTH_SUPPORT),
+                aoaCapabilityFlags.contains(FiraParams.AoaCapabilityFlag.HAS_ELEVATION_SUPPORT),
+                specificationParams.hasBlockStridingSupport(),
+                minRangingInterval,
+                ImmutableList.copyOf(supportedChannels),
+                ImmutableList.copyOf(supportedNtfConfigs),
+                ImmutableList.copyOf(supportedConfigIds),
+                ImmutableList.copyOf(supportedSlotDurations),
+                ImmutableList.copyOf(supportedRangingUpdateRates),
+                specificationParams.hasBackgroundRangingSupport()
+        );
+    }
+
+    /**
+     * Update the callback executor of the given ranging device.
+     *
+     * <p>If previous service is shut down, the ranging device may hold a stale serial executor.
+     */
+    public void updateRangingDevice(RangingDevice device) {
+        device.setSystemCallbackExecutor(mSerialExecutor);
+    }
+}
diff --git a/generic_ranging/uwb_backend/tests/Android.bp b/generic_ranging/uwb_backend/tests/Android.bp
new file mode 100644
index 00000000..292d7b33
--- /dev/null
+++ b/generic_ranging/uwb_backend/tests/Android.bp
@@ -0,0 +1,66 @@
+// Copyright (C) 2021 The Android Open Source Project
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
+// Make test APK
+// ============================================================
+package {
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "GenericRangingUwbBackendTests",
+
+    srcs: [
+        "**/*.java",
+    ],
+
+    dxflags: ["--multi-dex"],
+
+    java_version: "1.9",
+
+    static_libs: [
+        "androidx.test.rules",
+        "collector-device-lib",
+        "hamcrest-library",
+        "mockito-target-extended-minus-junit4",
+        "platform-test-annotations",
+        "frameworks-base-testutils",
+        "truth",
+        "com.uwb.support.fira",
+        "com.uwb.support.multichip",
+        "guava",
+        "ranging_uwb_backend",
+    ],
+
+    libs: [
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "framework-annotations-lib",
+    ],
+
+    jni_libs: [
+        // these are needed for Extended Mockito
+        "libdexmakerjvmtiagent",
+        "libstaticjvmtiagent",
+    ],
+    compile_multilib: "both",
+
+    min_sdk_version: "Tiramisu",
+
+    test_suites: [
+        "general-tests",
+    ],
+}
diff --git a/generic_ranging/uwb_backend/tests/AndroidManifest.xml b/generic_ranging/uwb_backend/tests/AndroidManifest.xml
new file mode 100644
index 00000000..1fcb53f9
--- /dev/null
+++ b/generic_ranging/uwb_backend/tests/AndroidManifest.xml
@@ -0,0 +1,40 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2022 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.ranging.uwb.backend">
+
+    <application android:debuggable="true"
+         android:largeHeap="true">
+        <uses-library android:name="android.test.runner"/>
+        <activity android:label="UwbTestDummyLabel"
+             android:name="UwbTestDummyName"
+             android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.LAUNCHER"/>
+            </intent-filter>
+        </activity>
+    </application>
+
+    <!-- This is a self-instrumenting test package. -->
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:targetPackage="com.android.ranging.uwb.backend"
+        android:label="Tests for the generic ranging UWB backend">
+    </instrumentation>
+
+</manifest>
diff --git a/generic_ranging/uwb_backend/tests/AndroidTest.xml b/generic_ranging/uwb_backend/tests/AndroidTest.xml
new file mode 100644
index 00000000..1b3d722a
--- /dev/null
+++ b/generic_ranging/uwb_backend/tests/AndroidTest.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2022 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<configuration description="Tests for the generic ranging UWB backend">
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="test-file-name" value="GenericRangingUwbBackendTests.apk" />
+    </target_preparer>
+
+    <option name="test-suite-tag" value="apct" />
+    <option name="test-tag" value="GenericRangingUwbBackendTests" />
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="com.android.ranging.uwb.backend" />
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+        <option name="hidden-api-checks" value="false"/>
+    </test>
+</configuration>
\ No newline at end of file
diff --git a/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/ConfigurationManagerTest.java b/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/ConfigurationManagerTest.java
new file mode 100644
index 00000000..bc33086a
--- /dev/null
+++ b/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/ConfigurationManagerTest.java
@@ -0,0 +1,189 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_PROVISIONED_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.INFREQUENT;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG;
+import static com.android.ranging.uwb.backend.internal.Utils.convertMsToRstu;
+
+import static com.google.uwb.support.fira.FiraParams.AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS;
+import static com.google.uwb.support.fira.FiraParams.FILTER_TYPE_NONE;
+import static com.google.uwb.support.fira.FiraParams.MULTICAST_LIST_UPDATE_ACTION_ADD;
+import static com.google.uwb.support.fira.FiraParams.RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_ROLE_INITIATOR;
+import static com.google.uwb.support.fira.FiraParams.RANGING_DEVICE_TYPE_CONTROLLER;
+import static com.google.uwb.support.fira.FiraParams.STS_CONFIG_PROVISIONED;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.Mockito.when;
+
+import android.platform.test.annotations.Presubmit;
+
+import androidx.test.filters.SmallTest;
+import androidx.test.runner.AndroidJUnit4;
+
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.fira.FiraRangingReconfigureParams;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.ArrayList;
+import java.util.List;
+
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+@Presubmit
+public class ConfigurationManagerTest {
+    private static final int TEST_DEVICE_TYPE = RANGING_DEVICE_TYPE_CONTROLLER;
+    private static final UwbAddress TEST_LOCAL_ADDRESS = UwbAddress.getRandomizedShortAddress();
+    private UwbRangeDataNtfConfig mUwbRangeDataNtfConfig =
+            new UwbRangeDataNtfConfig.Builder()
+                    .setRangeDataConfigType(RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG)
+                    .setNtfProximityNear(100)
+                    .build();
+    private RangingParameters mRangingParameters;
+    @Mock
+    private UwbComplexChannel mComplexChannel;
+
+    @Before
+    public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
+
+        mRangingParameters =
+                new RangingParameters(
+                        CONFIG_UNICAST_DS_TWR,
+                        1,
+                        1,
+                        new byte[]{1, 2},
+                        new byte[]{1, 2},
+                        mComplexChannel,
+                        new ArrayList<>(List.of(UwbAddress.getRandomizedShortAddress())),
+                        INFREQUENT,
+                        mUwbRangeDataNtfConfig,
+                        Utils.DURATION_2_MS,
+                        false);
+        when(mComplexChannel.getChannel()).thenReturn(1);
+        when(mComplexChannel.getPreambleIndex()).thenReturn(1);
+    }
+
+    @Test
+    public void testCreateOpenSessionParams() {
+        FiraOpenSessionParams params =
+                ConfigurationManager.createOpenSessionParams(
+                        TEST_DEVICE_TYPE, TEST_LOCAL_ADDRESS, mRangingParameters,
+                        new UwbFeatureFlags.Builder().build());
+        assertEquals(params.getDeviceRole(), RANGING_DEVICE_ROLE_INITIATOR);
+        assertFalse(params.isKeyRotationEnabled());
+        assertEquals(params.getKeyRotationRate(), 0);
+    }
+
+    @Test
+    public void testCreateOpenSessionParams_ProvisionedSts() {
+        byte[] sessionKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
+        RangingParameters rangingParameters =
+                new RangingParameters(
+                        CONFIG_PROVISIONED_UNICAST_DS_TWR,
+                        2,
+                        2,
+                        sessionKey,
+                        new byte[]{3, 4},
+                        mComplexChannel,
+                        new ArrayList<>(List.of(UwbAddress.getRandomizedShortAddress())),
+                        INFREQUENT,
+                        mUwbRangeDataNtfConfig,
+                        Utils.DURATION_2_MS,
+                        false);
+        FiraOpenSessionParams params =
+                ConfigurationManager.createOpenSessionParams(
+                        TEST_DEVICE_TYPE, TEST_LOCAL_ADDRESS, rangingParameters,
+                        new UwbFeatureFlags.Builder().build());
+        assertEquals(params.getStsConfig(), STS_CONFIG_PROVISIONED);
+        assertArrayEquals(params.getSessionKey(), sessionKey);
+        assertTrue(params.isKeyRotationEnabled());
+        assertEquals(params.getKeyRotationRate(), 0);
+        assertEquals(params.getSlotDurationRstu(), convertMsToRstu(Utils.DURATION_2_MS));
+        assertEquals(params.getAoaResultRequest(), AOA_RESULT_REQUEST_MODE_REQ_AOA_RESULTS);
+        assertEquals(params.getFilterType(), FILTER_TYPE_NONE);
+    }
+
+    @Test
+    public void testCreateReconfigureParams() {
+        FiraRangingReconfigureParams params =
+                ConfigurationManager.createReconfigureParams(
+                        CONFIG_UNICAST_DS_TWR,
+                        MULTICAST_LIST_UPDATE_ACTION_ADD,
+                        new UwbAddress[]{UwbAddress.getRandomizedShortAddress()},
+                        new int[]{0, 1},
+                        new byte[]{0, 1},
+                        new UwbFeatureFlags.Builder().build());
+        assertNotNull(params.getAction());
+        assertEquals(params.getAction().intValue(), MULTICAST_LIST_UPDATE_ACTION_ADD);
+        assertNull(params.getSubSessionIdList());
+    }
+
+    @Test
+    public void testIsUnicast() {
+        assertTrue(ConfigurationManager.isUnicast(CONFIG_UNICAST_DS_TWR));
+        assertFalse(ConfigurationManager.isUnicast(CONFIG_MULTICAST_DS_TWR));
+    }
+
+    @Test
+    public void testCreateReconfigureParamsBlockStriding() {
+        int blockStrideLength = 5;
+        FiraRangingReconfigureParams params =
+                ConfigurationManager.createReconfigureParamsBlockStriding(blockStrideLength);
+        assertNull(params.getAction());
+        assertEquals((int) params.getBlockStrideLength(), blockStrideLength);
+        assertNull(params.getAddressList());
+        assertNull(params.getRangeDataNtfConfig());
+        assertNull(params.getSubSessionIdList());
+    }
+
+    @Test
+    public void testCreateReconfigureParamsRangeDataNtf() {
+        int proximityNear = 50;
+        int proximityFar = 100;
+        FiraRangingReconfigureParams params =
+                ConfigurationManager.createReconfigureParamsRangeDataNtf(
+                        new UwbRangeDataNtfConfig.Builder()
+                                .setRangeDataConfigType(RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG)
+                                .setNtfProximityNear(proximityNear)
+                                .setNtfProximityFar(proximityFar)
+                                .build());
+
+        assertNull(params.getAction());
+        assertEquals((int) params.getRangeDataNtfConfig(),
+                RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_EDGE_TRIG);
+        assertEquals((int) params.getRangeDataProximityNear(), proximityNear);
+        assertEquals((int) params.getRangeDataProximityFar(), proximityFar);
+        assertNull(params.getBlockStrideLength());
+        assertNull(params.getAddressList());
+        assertNull(params.getSubSessionIdList());
+    }
+}
diff --git a/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/RangingControleeTest.java b/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/RangingControleeTest.java
new file mode 100644
index 00000000..373f7bad
--- /dev/null
+++ b/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/RangingControleeTest.java
@@ -0,0 +1,372 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_FAILED_TO_START;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_STOP_RANGING_CALLED;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_UNKNOWN;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_WRONG_PARAMETERS;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_UNICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.INFREQUENT;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_DISABLE;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG;
+import static com.android.ranging.uwb.backend.internal.Utils.STATUS_OK;
+
+import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+
+import android.os.CancellationSignal;
+import android.os.PersistableBundle;
+import android.platform.test.annotations.Presubmit;
+import android.uwb.RangingSession;
+import android.uwb.UwbManager;
+
+import androidx.test.filters.SmallTest;
+import androidx.test.runner.AndroidJUnit4;
+
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.fira.FiraParams;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.Executor;
+import java.util.concurrent.ExecutorService;
+
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+@Presubmit
+public class RangingControleeTest {
+    @Mock
+    private UwbManager mUwbManager;
+    @Mock
+    private UwbComplexChannel mComplexChannel;
+    private final OpAsyncCallbackRunner<Boolean> mOpAsyncCallbackRunner =
+            new OpAsyncCallbackRunner<>();
+    @Mock
+    private ExecutorService mBackendCallbackExecutor;
+    @Captor
+    private ArgumentCaptor<PersistableBundle> mBundleArgumentCaptor;
+    private RangingControlee mRangingControlee;
+
+    private static Executor getExecutor() {
+        return new Executor() {
+            @Override
+            public void execute(Runnable command) {
+                command.run();
+            }
+        };
+    }
+
+    private static class Mutable<E> {
+        public E value;
+    }
+
+    @Before
+    public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
+
+        doAnswer(
+                invocation -> {
+                    Runnable t = invocation.getArgument(0);
+                    t.run();
+                    return true;
+                })
+                .when(mBackendCallbackExecutor)
+                .execute(any(Runnable.class));
+
+        mRangingControlee =
+                new RangingControlee(mUwbManager, getExecutor(), mOpAsyncCallbackRunner,
+                        new UwbFeatureFlags.Builder().build());
+        UwbRangeDataNtfConfig uwbRangeDataNtfConfig =
+                new UwbRangeDataNtfConfig.Builder()
+                        .setRangeDataConfigType(RANGE_DATA_NTF_DISABLE)
+                        .build();
+        RangingParameters rangingParameters =
+                new RangingParameters(
+                        CONFIG_UNICAST_DS_TWR,
+                        1,
+                        1,
+                        new byte[]{1, 2},
+                        new byte[]{1, 2},
+                        mComplexChannel,
+                        new ArrayList<>(List.of(UwbAddress.getRandomizedShortAddress())),
+                        INFREQUENT,
+                        uwbRangeDataNtfConfig,
+                        Utils.DURATION_2_MS,
+                        false);
+        mRangingControlee.setRangingParameters(rangingParameters);
+    }
+
+    @Test
+    public void testSetRangingParameterWithSessionIdUnset() {
+        UwbRangeDataNtfConfig uwbRangeDataNtfConfig =
+                new UwbRangeDataNtfConfig.Builder()
+                        .setRangeDataConfigType(RANGE_DATA_NTF_DISABLE)
+                        .build();
+        RangingParameters rangingParameters =
+                new RangingParameters(
+                        CONFIG_MULTICAST_DS_TWR,
+                        0,
+                        0,
+                        new byte[]{1, 2},
+                        new byte[]{1, 2},
+                        mComplexChannel,
+                        List.of(UwbAddress.fromBytes(new byte[]{3, 4})),
+                        INFREQUENT,
+                        uwbRangeDataNtfConfig,
+                        Utils.DURATION_2_MS,
+                        false);
+
+        mRangingControlee.setRangingParameters(rangingParameters);
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        mRangingControlee.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+
+        verify(mUwbManager).openRangingSession(mBundleArgumentCaptor.capture(), any(), any());
+        assertEquals(
+                RangingDevice.calculateHashedSessionId(
+                        rangingParameters.getPeerAddresses().get(0),
+                        rangingParameters.getComplexChannel()),
+                mBundleArgumentCaptor.getValue().getInt("session_id"));
+    }
+
+    @Test
+    public void testGetOpenSessionParams() {
+        FiraOpenSessionParams params = mRangingControlee.getOpenSessionParams();
+        assertEquals(params.getDeviceType(), FiraParams.RANGING_DEVICE_TYPE_CONTROLEE);
+    }
+
+    @Test
+    public void testStartRangingSession() {
+        UwbAddress deviceAddress = mRangingControlee.getLocalAddress();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        assertEquals(
+                mRangingControlee.startRanging(rangingSessionCallback, mBackendCallbackExecutor),
+                STATUS_OK);
+        verify(mUwbManager).openRangingSession(any(), any(), any());
+        verify(pfRangingSession).start(any());
+        verify(rangingSessionCallback)
+                .onRangingInitialized(UwbDevice.createForAddress(deviceAddress.toBytes()));
+    }
+
+    @Test
+    public void testStartRanging_openSessionFailed_onRangingSuspendedInvoked() {
+        UwbAddress deviceAddress = mRangingControlee.getLocalAddress();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpenFailed(REASON_UNKNOWN,
+                            new PersistableBundle());
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        assertEquals(
+                mRangingControlee.startRanging(rangingSessionCallback, mBackendCallbackExecutor),
+                STATUS_OK);
+        verify(rangingSessionCallback)
+                .onRangingSuspended(UwbDevice.createForAddress(deviceAddress.toBytes()),
+                        REASON_FAILED_TO_START);
+    }
+
+    @Test
+    public void testStartRanging_ranginStartFailed() {
+        UwbAddress deviceAddress = mRangingControlee.getLocalAddress();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStartFailed(REASON_WRONG_PARAMETERS,
+                            new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        assertEquals(
+                mRangingControlee.startRanging(rangingSessionCallback, mBackendCallbackExecutor),
+                STATUS_OK);
+        verify(mUwbManager).openRangingSession(any(), any(), any());
+        verify(pfRangingSession).start(any());
+        verify(rangingSessionCallback)
+                .onRangingSuspended(UwbDevice.createForAddress(deviceAddress.toBytes()),
+                        REASON_FAILED_TO_START);
+    }
+
+    @Test
+    public void testStopRanging() {
+        UwbAddress deviceAddress = mRangingControlee.getLocalAddress();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStopped(
+                            RangingSession.Callback.REASON_LOCAL_REQUEST,
+                            new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .stop();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onClosed(
+                            RangingSession.Callback.REASON_LOCAL_REQUEST,
+                            new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .close();
+
+        mRangingControlee.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        assertEquals(mRangingControlee.stopRanging(), STATUS_OK);
+        verify(pfRangingSession).stop();
+        verify(pfRangingSession).close();
+        verify(rangingSessionCallback)
+                .onRangingSuspended(
+                        UwbDevice.createForAddress(deviceAddress.toBytes()),
+                        REASON_STOP_RANGING_CALLED);
+    }
+
+    @Test
+    public void testReconfigureRangeDataNtf() {
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onReconfigured(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .reconfigure(any(PersistableBundle.class));
+
+        mRangingControlee.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        UwbRangeDataNtfConfig params = new UwbRangeDataNtfConfig.Builder()
+                .setRangeDataConfigType(RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG)
+                .setNtfProximityNear(50)
+                .setNtfProximityFar(100)
+                .build();
+        assertEquals(mRangingControlee.reconfigureRangeDataNtfConfig(params), STATUS_OK);
+
+        verify(pfRangingSession, times(1)).reconfigure(any(PersistableBundle.class));
+    }
+}
diff --git a/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/RangingControllerTest.java b/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/RangingControllerTest.java
new file mode 100644
index 00000000..a26213b3
--- /dev/null
+++ b/generic_ranging/uwb_backend/tests/src/com/android/ranging/uwb/backend/internal/RangingControllerTest.java
@@ -0,0 +1,554 @@
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
+
+package com.android.ranging.uwb.backend.internal;
+
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_FAILED_TO_START;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_STOP_RANGING_CALLED;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_UNKNOWN;
+import static com.android.ranging.uwb.backend.internal.RangingSessionCallback.REASON_WRONG_PARAMETERS;
+import static com.android.ranging.uwb.backend.internal.Utils.CONFIG_MULTICAST_DS_TWR;
+import static com.android.ranging.uwb.backend.internal.Utils.INFREQUENT;
+import static com.android.ranging.uwb.backend.internal.Utils.INVALID_API_CALL;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_DISABLE;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG;
+import static com.android.ranging.uwb.backend.internal.Utils.RANGE_DATA_NTF_ENABLE_PROXIMITY_LEVEL_TRIG;
+import static com.android.ranging.uwb.backend.internal.Utils.STATUS_OK;
+
+import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+
+import android.os.CancellationSignal;
+import android.os.PersistableBundle;
+import android.platform.test.annotations.Presubmit;
+import android.uwb.RangingSession;
+import android.uwb.UwbManager;
+
+import androidx.test.filters.SmallTest;
+import androidx.test.runner.AndroidJUnit4;
+
+import com.google.uwb.support.fira.FiraOpenSessionParams;
+import com.google.uwb.support.fira.FiraParams;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.Executor;
+import java.util.concurrent.ExecutorService;
+
+@RunWith(AndroidJUnit4.class)
+@SmallTest
+@Presubmit
+public class RangingControllerTest {
+    @Mock
+    private UwbManager mUwbManager;
+    @Mock
+    private UwbComplexChannel mComplexChannel;
+    private final OpAsyncCallbackRunner<Boolean> mOpAsyncCallbackRunner =
+            new OpAsyncCallbackRunner<>();
+    @Mock
+    private ExecutorService mBackendCallbackExecutor;
+
+    @Captor
+    private ArgumentCaptor<PersistableBundle> mBundleArgumentCaptor;
+
+    private RangingController mRangingController;
+    private UwbAddress mRangingParamsKnownPeerAddress;
+
+    private static Executor getExecutor() {
+        return new Executor() {
+            @Override
+            public void execute(Runnable command) {
+                command.run();
+            }
+        };
+    }
+
+    private static class Mutable<E> {
+        public E value;
+    }
+
+    @Before
+    public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
+        doAnswer(
+                invocation -> {
+                    Runnable t = invocation.getArgument(0);
+                    t.run();
+                    return true;
+                })
+                .when(mBackendCallbackExecutor)
+                .execute(any(Runnable.class));
+        UwbRangeDataNtfConfig uwbRangeDataNtfConfig =
+                new UwbRangeDataNtfConfig.Builder()
+                        .setRangeDataConfigType(RANGE_DATA_NTF_ENABLE_PROXIMITY_LEVEL_TRIG)
+                        .setNtfProximityNear(100)
+                        .setNtfProximityFar(300)
+                        .build();
+        mRangingParamsKnownPeerAddress = UwbAddress.getRandomizedShortAddress();
+        RangingParameters rangingParameters =
+                new RangingParameters(
+                        CONFIG_MULTICAST_DS_TWR,
+                        1,
+                        0,
+                        new byte[]{1, 2},
+                        new byte[]{1, 2},
+                        mComplexChannel,
+                        new ArrayList<>(List.of(mRangingParamsKnownPeerAddress)),
+                        INFREQUENT,
+                        uwbRangeDataNtfConfig,
+                        Utils.DURATION_2_MS,
+                        false);
+        mRangingController =
+                new RangingController(mUwbManager, getExecutor(), mOpAsyncCallbackRunner,
+                        new UwbFeatureFlags.Builder().build());
+        mRangingController.setRangingParameters(rangingParameters);
+        mRangingController.setForTesting(true);
+    }
+
+    @Test
+    public void testGetOpenSessionParams() {
+        FiraOpenSessionParams params = mRangingController.getOpenSessionParams();
+        assertEquals(params.getDeviceType(), FiraParams.RANGING_DEVICE_TYPE_CONTROLLER);
+    }
+
+    @Test
+    public void testGetComplexChannel() {
+        UwbComplexChannel channel = mRangingController.getComplexChannel();
+        assertEquals(channel.getChannel(), Utils.channelForTesting);
+        assertEquals(channel.getPreambleIndex(), Utils.preambleIndexForTesting);
+    }
+
+    @Test
+    public void testSetComplexChannel() {
+        UwbComplexChannel complexChannel = new UwbComplexChannel(9, 10);
+        mRangingController.setComplexChannel(complexChannel);
+        assertEquals(complexChannel.getChannel(), 9);
+        assertEquals(complexChannel.getPreambleIndex(), 10);
+    }
+
+    @Test
+    public void testSetRangingParameterWithSessionIdUnset() {
+        UwbAddress deviceAddress = mRangingController.getLocalAddress();
+        UwbComplexChannel complexChannel = mRangingController.getComplexChannel();
+        UwbRangeDataNtfConfig uwbRangeDataNtfConfig =
+                new UwbRangeDataNtfConfig.Builder()
+                        .setRangeDataConfigType(RANGE_DATA_NTF_DISABLE)
+                        .build();
+        RangingParameters rangingParameters =
+                new RangingParameters(
+                        CONFIG_MULTICAST_DS_TWR,
+                        0,
+                        0,
+                        new byte[]{1, 2},
+                        new byte[]{1, 2},
+                        mComplexChannel,
+                        List.of(UwbAddress.fromBytes(new byte[]{3, 4})),
+                        INFREQUENT,
+                        uwbRangeDataNtfConfig,
+                        Utils.DURATION_2_MS,
+                        false);
+
+        mRangingController.setRangingParameters(rangingParameters);
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+
+        verify(mUwbManager).openRangingSession(mBundleArgumentCaptor.capture(), any(), any());
+        assertEquals(
+                RangingDevice.calculateHashedSessionId(deviceAddress, complexChannel),
+                mBundleArgumentCaptor.getValue().getInt("session_id"));
+    }
+
+    @Test
+    public void testGetBestAvailableComplexChannel() {
+        UwbComplexChannel channel = mRangingController.getBestAvailableComplexChannel();
+        assertEquals(channel.getChannel(), Utils.channelForTesting);
+    }
+
+    @Test
+    public void testStartRanging() {
+        UwbAddress deviceAddress = mRangingController.getLocalAddress();
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        assertEquals(
+                mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor),
+                STATUS_OK);
+        verify(mUwbManager).openRangingSession(any(), any(), any());
+        verify(pfRangingSession).start(any());
+        verify(rangingSessionCallback)
+                .onRangingInitialized(UwbDevice.createForAddress(deviceAddress.toBytes()));
+    }
+
+    @Test
+    public void testStartRanging_openSessionFailed_onRangingSuspendedInvoked() {
+        UwbAddress deviceAddress = mRangingController.getLocalAddress();
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpenFailed(REASON_UNKNOWN,
+                            new PersistableBundle());
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        assertEquals(
+                mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor),
+                STATUS_OK);
+        verify(rangingSessionCallback)
+                .onRangingSuspended(UwbDevice.createForAddress(deviceAddress.toBytes()),
+                        REASON_FAILED_TO_START);
+    }
+
+    @Test
+    public void testStartRanging_ranginStartFailed() {
+        UwbAddress deviceAddress = mRangingController.getLocalAddress();
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStartFailed(REASON_WRONG_PARAMETERS,
+                            new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        assertEquals(
+                mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor),
+                STATUS_OK);
+        verify(mUwbManager).openRangingSession(any(), any(), any());
+        verify(pfRangingSession).start(any());
+        verify(rangingSessionCallback)
+                .onRangingSuspended(UwbDevice.createForAddress(deviceAddress.toBytes()),
+                        REASON_FAILED_TO_START);
+    }
+
+
+    @Test
+    public void testStopRanging() {
+        UwbAddress deviceAddress = mRangingController.getLocalAddress();
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStopped(
+                            RangingSession.Callback.REASON_LOCAL_REQUEST,
+                            new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .stop();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onClosed(
+                            RangingSession.Callback.REASON_LOCAL_REQUEST,
+                            new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .close();
+
+        mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        assertEquals(mRangingController.stopRanging(), STATUS_OK);
+        verify(pfRangingSession).stop();
+        verify(pfRangingSession).close();
+        verify(rangingSessionCallback)
+                .onRangingSuspended(
+                        UwbDevice.createForAddress(deviceAddress.toBytes()),
+                        REASON_STOP_RANGING_CALLED);
+    }
+
+    @Test
+    public void testAddControlee() {
+        UwbAddress peerAddress = UwbAddress.getRandomizedShortAddress();
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onControleeAdded(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .addControlee(any(PersistableBundle.class));
+
+        mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        assertEquals(mRangingController.addControleeWithSessionParams(
+                new RangingControleeParameters(
+                        peerAddress, 0, null)), STATUS_OK);
+        verify(pfRangingSession).addControlee(any(PersistableBundle.class));
+        verify(rangingSessionCallback)
+                .onRangingInitialized(UwbDevice.createForAddress(peerAddress.toBytes()));
+    }
+
+    @Test
+    public void testRemoveControlee() {
+        UwbAddress peerAddress = UwbAddress.getRandomizedShortAddress();
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onControleeAdded(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .addControlee(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onControleeRemoved(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .removeControlee(any(PersistableBundle.class));
+
+        mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        mRangingController.addControleeWithSessionParams(
+                new RangingControleeParameters(peerAddress, 0, null));
+        assertEquals(mRangingController.removeControlee(peerAddress), STATUS_OK);
+        assertEquals(mRangingController.removeControlee(mRangingParamsKnownPeerAddress), STATUS_OK);
+        assertEquals(mRangingController.removeControlee(UwbAddress.getRandomizedShortAddress()),
+                INVALID_API_CALL);
+        verify(pfRangingSession, times(1)).addControlee(any(PersistableBundle.class));
+        verify(pfRangingSession, times(2)).removeControlee(any(PersistableBundle.class));
+        verify(rangingSessionCallback)
+                .onRangingSuspended(
+                        UwbDevice.createForAddress(peerAddress.toBytes()),
+                        REASON_STOP_RANGING_CALLED);
+    }
+
+    @Test
+    public void testReconfigureRangingInterval() {
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onReconfigured(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .reconfigure(any(PersistableBundle.class));
+
+        mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        assertEquals(mRangingController.setBlockStriding(5), STATUS_OK);
+
+        verify(pfRangingSession, times(1)).reconfigure(any(PersistableBundle.class));
+    }
+
+    @Test
+    public void testReconfigureRangeDataNtf() {
+        mRangingController.getComplexChannel();
+
+        final RangingSessionCallback rangingSessionCallback = mock(RangingSessionCallback.class);
+        final RangingSession pfRangingSession = mock(RangingSession.class);
+        final Mutable<RangingSession.Callback> pfRangingSessionCallback = new Mutable<>();
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value = invocation.getArgument(2);
+                    pfRangingSessionCallback.value.onOpened(pfRangingSession);
+                    return new CancellationSignal();
+                })
+                .when(mUwbManager)
+                .openRangingSession(
+                        any(PersistableBundle.class),
+                        any(Executor.class),
+                        any(RangingSession.Callback.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onStarted(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .start(any(PersistableBundle.class));
+
+        doAnswer(
+                invocation -> {
+                    pfRangingSessionCallback.value.onReconfigured(new PersistableBundle());
+                    return true;
+                })
+                .when(pfRangingSession)
+                .reconfigure(any(PersistableBundle.class));
+
+        mRangingController.startRanging(rangingSessionCallback, mBackendCallbackExecutor);
+        UwbRangeDataNtfConfig params = new UwbRangeDataNtfConfig.Builder()
+                .setRangeDataConfigType(RANGE_DATA_NTF_ENABLE_PROXIMITY_EDGE_TRIG)
+                .setNtfProximityNear(50)
+                .setNtfProximityFar(100)
+                .build();
+        assertEquals(mRangingController.reconfigureRangeDataNtfConfig(params), STATUS_OK);
+
+        verify(pfRangingSession, times(1)).reconfigure(any(PersistableBundle.class));
+    }
+}
diff --git a/ranging/flags/Android.bp b/ranging/flags/Android.bp
new file mode 100644
index 00000000..cecc7725
--- /dev/null
+++ b/ranging/flags/Android.bp
@@ -0,0 +1,59 @@
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
+package {
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "ranging_aconfig_flags",
+    package: "com.android.ranging.flags",
+    container: "com.android.ranging",
+    srcs: ["ranging_flags.aconfig"],
+    visibility: [
+        "//packages/modules/Uwb/ranging:__subpackages__",
+        "//frameworks/base:__subpackages__",
+    ],
+}
+
+java_aconfig_library {
+    name: "ranging_aconfig_flags_lib",
+    aconfig_declarations: "ranging_aconfig_flags",
+    min_sdk_version: "33",
+    apex_available: [
+        "com.android.uwb",
+    ],
+}
+
+java_library {
+    name: "ranging_flags_lib",
+    sdk_version: "system_current",
+    min_sdk_version: "33",
+    srcs: [
+        "lib/**/*.java",
+    ],
+    static_libs: [
+        "ranging_aconfig_flags_lib",
+    ],
+    apex_available: [
+        "com.android.uwb",
+    ],
+    installable: false,
+    visibility: [
+        "//packages/modules/Uwb/ranging:__subpackages__",
+    ],
+}
diff --git a/ranging/flags/ranging_flags.aconfig b/ranging/flags/ranging_flags.aconfig
new file mode 100644
index 00000000..4de30349
--- /dev/null
+++ b/ranging/flags/ranging_flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.ranging.flags"
+container: "com.android.ranging"
+
+flag {
+    name: "ranging_stack_enabled"
+    is_exported: true
+    namespace: "ranging"
+    description: "This flags controls generic ranging feature"
+    bug: "331206299"
+}
\ No newline at end of file
diff --git a/ranging/framework/Android.bp b/ranging/framework/Android.bp
new file mode 100644
index 00000000..cb90bbba
--- /dev/null
+++ b/ranging/framework/Android.bp
@@ -0,0 +1,125 @@
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
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_defaults {
+    name: "ranging-module-sdk-version-defaults",
+    min_sdk_version: "current",
+}
+
+filegroup {
+    name: "framework-ranging-updatable-exported-aidl-sources",
+    srcs: ["aidl-export/**/*.aidl"],
+    path: "aidl-export",
+    visibility: ["//visibility:private"],
+}
+
+filegroup {
+    name: "framework-ranging-updatable-java-sources",
+    srcs: [
+        "java/**/*.java",
+        "java/**/*.aidl",
+    ],
+    path: "java",
+    visibility: ["//visibility:private"],
+}
+
+filegroup {
+    name: "framework-ranging-updatable-sources",
+    defaults: ["framework-sources-module-defaults"],
+    srcs: [
+        ":framework-ranging-updatable-java-sources",
+        ":framework-ranging-updatable-exported-aidl-sources",
+    ],
+}
+
+// defaults shared between `framework-ranging` & `framework-ranging-pre-jarjar`
+// java_sdk_library `framework-ranging` needs sources to generate stubs, so it cannot reuse
+// `framework-ranging-pre-jarjar`
+java_defaults {
+    name: "framework-ranging-defaults",
+    defaults: ["ranging-module-sdk-version-defaults"],
+    static_libs: [
+        //"modules-utils-preconditions",
+        "modules-utils-build",
+    ],
+    libs: [
+        "androidx.annotation_annotation",
+        "unsupportedappusage", // for android.compat.annotation.UnsupportedAppUsage
+    ],
+    srcs: [
+        ":framework-ranging-updatable-sources",
+    ],
+}
+
+// ranging-service needs pre-jarjared version of framework-ranging so it can reference copied utility
+// classes before they are renamed.
+java_library {
+    name: "framework-ranging-pre-jarjar",
+    defaults: ["framework-ranging-defaults"],
+    sdk_version: "module_current",
+    libs: ["framework-annotations-lib"],
+    installable: false,
+}
+
+// post-jarjar version of framework-ranging
+java_sdk_library {
+    name: "framework-ranging",
+    defaults: [
+        "framework-module-defaults",
+        "framework-ranging-defaults",
+    ],
+    jarjar_rules: ":ranging-jarjar-rules",
+    installable: true,
+    optimize: {
+        enabled: false,
+    },
+    hostdex: true, // for hiddenapi check
+
+    impl_library_visibility: [
+        "//external/sl4a/Common:__subpackages__",
+        "//packages/modules/Uwb/ranging:__subpackages__",
+    ],
+
+    apex_available: [
+        "com.android.uwb",
+    ],
+    permitted_packages: [
+        "android.ranging",
+        // Created by jarjar rules.
+        "com.android.x.ranging",
+    ],
+}
+
+// defaults for tests that need to build against framework-ranging's @hide APIs
+java_defaults {
+    name: "framework-ranging-test-defaults",
+    sdk_version: "module_current",
+    libs: [
+        "framework-ranging.impl",
+    ],
+    //defaults_visibility: [
+    // "//packages/modules/Uwb/framework/tests:__subpackages__",
+    // "//packages/modules/Uwb/service/tests:__subpackages__",
+    //],
+}
+
+filegroup {
+    name: "ranging-jarjar-rules",
+    srcs: ["jarjar-rules.txt"],
+}
diff --git a/ranging/framework/api/current.txt b/ranging/framework/api/current.txt
new file mode 100644
index 00000000..d802177e
--- /dev/null
+++ b/ranging/framework/api/current.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/ranging/framework/api/module-lib-current.txt b/ranging/framework/api/module-lib-current.txt
new file mode 100644
index 00000000..ed33736f
--- /dev/null
+++ b/ranging/framework/api/module-lib-current.txt
@@ -0,0 +1,8 @@
+// Signature format: 2.0
+package android.ranging {
+
+  @FlaggedApi("com.android.ranging.flags.ranging_stack_enabled") public class RangingFrameworkInitializer {
+  }
+
+}
+
diff --git a/ranging/framework/api/module-lib-removed.txt b/ranging/framework/api/module-lib-removed.txt
new file mode 100644
index 00000000..d802177e
--- /dev/null
+++ b/ranging/framework/api/module-lib-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/ranging/framework/api/removed.txt b/ranging/framework/api/removed.txt
new file mode 100644
index 00000000..d802177e
--- /dev/null
+++ b/ranging/framework/api/removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/ranging/framework/api/system-current.txt b/ranging/framework/api/system-current.txt
new file mode 100644
index 00000000..d802177e
--- /dev/null
+++ b/ranging/framework/api/system-current.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/ranging/framework/api/system-removed.txt b/ranging/framework/api/system-removed.txt
new file mode 100644
index 00000000..d802177e
--- /dev/null
+++ b/ranging/framework/api/system-removed.txt
@@ -0,0 +1 @@
+// Signature format: 2.0
diff --git a/ranging/framework/api/test-current.txt b/ranging/framework/api/test-current.txt
new file mode 100644
index 00000000..e69de29b
diff --git a/ranging/framework/api/test-removed.txt b/ranging/framework/api/test-removed.txt
new file mode 100644
index 00000000..e69de29b
diff --git a/ranging/framework/jarjar-rules.txt b/ranging/framework/jarjar-rules.txt
new file mode 100644
index 00000000..54088a52
--- /dev/null
+++ b/ranging/framework/jarjar-rules.txt
@@ -0,0 +1,3 @@
+## used by both framework-uwb and service-uwb ##
+# Statically included module utils.
+rule com.android.modules.utils.** com.android.x.ranging.@0
\ No newline at end of file
diff --git a/ranging/framework/java/android/ranging/IRangingAdapter.aidl b/ranging/framework/java/android/ranging/IRangingAdapter.aidl
new file mode 100644
index 00000000..ca593f86
--- /dev/null
+++ b/ranging/framework/java/android/ranging/IRangingAdapter.aidl
@@ -0,0 +1,23 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.ranging;
+
+/**
+*  @hide
+*/
+interface IRangingAdapter {
+}
\ No newline at end of file
diff --git a/ranging/framework/java/android/ranging/RangingFrameworkInitializer.java b/ranging/framework/java/android/ranging/RangingFrameworkInitializer.java
new file mode 100644
index 00000000..db37be28
--- /dev/null
+++ b/ranging/framework/java/android/ranging/RangingFrameworkInitializer.java
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
+
+package android.ranging;
+
+import android.annotation.FlaggedApi;
+import android.annotation.Hide;
+import android.annotation.SystemApi;
+import android.app.SystemServiceRegistry;
+import android.content.Context;
+
+
+/**
+ * Class for performing registration for Ranging service.
+ *
+ * @hide
+ */
+@FlaggedApi("com.android.ranging.flags.ranging_stack_enabled")
+@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
+public class RangingFrameworkInitializer {
+    private RangingFrameworkInitializer() {}
+
+    /**
+     * @hide
+     */
+    @Hide
+    @FlaggedApi("com.android.ranging.flags.ranging_stack_enabled")
+    public static void registerServiceWrappers() {
+        SystemServiceRegistry.registerContextAwareService(
+                Context.RANGING_SERVICE,
+                RangingManager.class,
+                (context, serviceBinder) -> {
+                    IRangingAdapter adapter = IRangingAdapter.Stub.asInterface(serviceBinder);
+                    return new RangingManager(context, adapter);
+                }
+        );
+    }
+}
diff --git a/ranging/framework/java/android/ranging/RangingManager.java b/ranging/framework/java/android/ranging/RangingManager.java
new file mode 100644
index 00000000..1ff11f33
--- /dev/null
+++ b/ranging/framework/java/android/ranging/RangingManager.java
@@ -0,0 +1,59 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.ranging;
+
+import android.annotation.FlaggedApi;
+import android.annotation.Hide;
+import android.annotation.NonNull;
+import android.content.Context;
+
+
+/**
+ * This class provides a way to perform ranging operations such as querying the
+ * device's capabilities and determining the distance and angle between the local device and a
+ * remote device.
+ *
+ * <p>To get a {@link RangingManager}, call the
+ * <code>Context.getSystemService(RangingManager.class)</code>.
+ *
+ * @hide
+ */
+//@SystemApi
+//@SystemService(Context.UWB_SERVICE)
+
+/**
+ * @hide
+ */
+@Hide
+@FlaggedApi("com.android.ranging.flags.ranging_stack_enabled")
+public final class RangingManager {
+    private static final String TAG = "RangingManager";
+
+    public RangingManager(@NonNull Context context, IRangingAdapter adapter) {
+
+    }
+
+    /**
+     * @hide
+     */
+    @Hide
+    @NonNull
+    @FlaggedApi("com.android.ranging.flags.ranging_stack_enabled")
+    RangingSession createRangingSession() {
+        return new RangingSession();
+    }
+}
diff --git a/ranging/framework/java/android/ranging/RangingSession.java b/ranging/framework/java/android/ranging/RangingSession.java
new file mode 100644
index 00000000..5cf2b487
--- /dev/null
+++ b/ranging/framework/java/android/ranging/RangingSession.java
@@ -0,0 +1,29 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.ranging;
+
+import android.annotation.FlaggedApi;
+import android.annotation.Hide;
+
+
+/**
+ * @hide
+ */
+@Hide
+@FlaggedApi("com.android.ranging.flags.ranging_stack_enabled")
+public class RangingSession {
+}
diff --git a/ranging/service/Android.bp b/ranging/service/Android.bp
new file mode 100644
index 00000000..f85cdb81
--- /dev/null
+++ b/ranging/service/Android.bp
@@ -0,0 +1,106 @@
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
+package {
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_defaults {
+    name: "service-ranging-common-defaults",
+    defaults: ["ranging-module-sdk-version-defaults"],
+    errorprone: {
+        javacflags: ["-Xep:CheckReturnValue:ERROR"],
+    },
+}
+
+filegroup {
+    name: "service-ranging-srcs",
+    srcs: [
+        "java/**/*.java",
+    ],
+}
+
+// pre-jarjar version of service-ranging that builds against pre-jarjar version of framework-uwb
+java_library {
+    name: "service-ranging-pre-jarjar",
+    min_sdk_version: "33",
+    installable: false,
+    defaults: ["service-ranging-common-defaults"],
+    srcs: [":service-ranging-srcs"],
+    sdk_version: "system_server_current",
+
+    libs: [
+        "androidx.annotation_annotation",
+        "framework-annotations-lib",
+        "framework-configinfrastructure.stubs.module_lib",
+        "framework-ranging-pre-jarjar",
+        "framework-statsd.stubs.module_lib",
+        "framework-wifi.stubs.module_lib",
+        "framework-bluetooth.stubs.module_lib",
+        "framework-location.stubs.module_lib",
+    ],
+
+    static_libs: [
+        "guava",
+        "modules-utils-shell-command-handler",
+        "modules-utils-handlerexecutor",
+        //"modules-utils-preconditions",
+        //"modules-utils-build",
+    ],
+
+    apex_available: [
+        "com.android.uwb",
+    ],
+}
+
+// service-ranging static library
+// ============================================================
+java_library {
+    name: "service-ranging",
+    min_sdk_version: "33",
+    defaults: [
+        "service-ranging-common-defaults",
+        "standalone-system-server-module-optimize-defaults",
+    ],
+    installable: true,
+    static_libs: ["service-ranging-pre-jarjar"],
+
+    // Need to include `libs` so that Soong doesn't complain about missing classes after jarjaring
+    // The below libraries are not actually needed to build since no source is compiled
+    // but they are necessary so that R8 has the right references to optimize the code.
+    // Without these, there will be missing class warnings and code may be wrongly optimized.
+    // TODO(b/242088131): remove libraries that aren't used directly
+    libs: [
+        "framework-ranging.impl",
+        "framework-statsd.stubs.module_lib",
+        "framework-wifi.stubs.module_lib",
+        "framework-bluetooth.stubs.module_lib",
+        "framework-connectivity.stubs.module_lib",
+    ],
+
+    sdk_version: "system_server_current",
+
+    jarjar_rules: ":ranging-jarjar-rules",
+    //optimize: {
+    //proguard_flags_files: ["proguard.flags"],
+    //},
+    visibility: [
+        "//packages/modules/Uwb/apex",
+    ],
+    apex_available: [
+        "com.android.uwb",
+    ],
+}
diff --git a/ranging/service/java/com/android/server/ranging/RangingService.java b/ranging/service/java/com/android/server/ranging/RangingService.java
new file mode 100644
index 00000000..8d790810
--- /dev/null
+++ b/ranging/service/java/com/android/server/ranging/RangingService.java
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
+package com.android.server.ranging;
+
+import android.content.Context;
+import android.util.Log;
+
+import com.android.server.SystemService;
+
+public class RangingService extends SystemService {
+    private static final String TAG = "RangingService";
+    public RangingService(Context context) {
+        super(context);
+    }
+
+    @Override
+    public void onStart() {
+        Log.i(TAG, "Registering Ranging service");
+    }
+}
diff --git a/service/Android.bp b/service/Android.bp
index 70aa3562..3b715391 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -47,7 +47,7 @@ java_library {
     libs: [
         "androidx.annotation_annotation",
         "framework-annotations-lib",
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
         "framework-uwb-pre-jarjar",
         "ServiceUwbResources",
         "framework-statsd.stubs.module_lib",
@@ -67,6 +67,7 @@ java_library {
         "com.uwb.support.oemextension",
         "com.uwb.support.dltdoa",
         "com.uwb.support.radar",
+        "com.uwb.fusion",
         "guava",
         "modules-utils-shell-command-handler",
         "modules-utils-handlerexecutor",
diff --git a/service/ServiceUwbResources/res/values/config.xml b/service/ServiceUwbResources/res/values/config.xml
index b4963d19..9925fa8b 100644
--- a/service/ServiceUwbResources/res/values/config.xml
+++ b/service/ServiceUwbResources/res/values/config.xml
@@ -215,6 +215,12 @@
     -->
     <bool name = "hw_idle_turn_off_enabled">false</bool>
 
+    <!-- Whether fused country code provider is enabled or not.
+    If enabled, when APM is disabled or boot with a clear cache, a fused provider is enabled until
+    a valid country code is resolved.
+    -->
+    <bool name = "fused_country_code_provider_enabled">false</bool>
+
      <!-- Whether multicast list update notification v2 is supported or not.
      If enabled, the notification will be parsed into version 2 if uci major version is 2.0. -->
     <bool name = "is_multicast_list_update_ntf_v2_supported">false</bool>
diff --git a/service/ServiceUwbResources/res/values/overlayable.xml b/service/ServiceUwbResources/res/values/overlayable.xml
index f1339b3e..b44f405f 100644
--- a/service/ServiceUwbResources/res/values/overlayable.xml
+++ b/service/ServiceUwbResources/res/values/overlayable.xml
@@ -53,6 +53,7 @@
             <item name="ccc_supported_range_data_ntf_config" type="bool" />
             <item name="persistent_cache_use_for_country_code_enabled" type="bool" />
             <item name="hw_idle_turn_off_enabled" type="bool" />
+            <item name="fused_country_code_provider_enabled" type="bool" />
             <item name="is_multicast_list_update_ntf_v2_supported" type="bool" />
             <item name="is_multicast_list_update_rsp_v2_supported" type="bool" />
             <item name="is_antenna_mode_config_supported" type="bool" />
diff --git a/service/fusion_lib/Android.bp b/service/fusion_lib/Android.bp
new file mode 100644
index 00000000..e4496236
--- /dev/null
+++ b/service/fusion_lib/Android.bp
@@ -0,0 +1,40 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "com.uwb.fusion",
+    srcs: ["src/**/*.java"],
+    sdk_version: "system_31",
+    libs: [
+        "androidx.annotation_annotation",
+        "framework-annotations-lib",
+    ],
+    static_libs: [
+        "guava",
+    ],
+    visibility: [
+        "//packages/modules/Uwb/service:__subpackages__",
+        "//packages/modules/Uwb/generic_ranging:__subpackages__",
+    ],
+    apex_available: [
+        "com.android.uwb",
+    ],
+}
diff --git a/service/java/com/android/server/uwb/correction/UwbFilterEngine.java b/service/fusion_lib/src/com/android/uwb/fusion/UwbFilterEngine.java
similarity index 95%
rename from service/java/com/android/server/uwb/correction/UwbFilterEngine.java
rename to service/fusion_lib/src/com/android/uwb/fusion/UwbFilterEngine.java
index bc3dbdb3..3dedf799 100644
--- a/service/java/com/android/server/uwb/correction/UwbFilterEngine.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/UwbFilterEngine.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction;
+package com.android.uwb.fusion;
 
 import android.os.Build;
 import android.util.Log;
@@ -21,12 +21,12 @@ import android.util.Log;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.filtering.IPositionFilter;
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.pose.IPoseSource;
-import com.android.server.uwb.correction.pose.PoseEventListener;
-import com.android.server.uwb.correction.primers.IPrimer;
+import com.android.uwb.fusion.filtering.IPositionFilter;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.pose.IPoseSource;
+import com.android.uwb.fusion.pose.PoseEventListener;
+import com.android.uwb.fusion.primers.IPrimer;
 
 import java.util.ArrayList;
 import java.util.List;
diff --git a/service/java/com/android/server/uwb/correction/filtering/IFilter.java b/service/fusion_lib/src/com/android/uwb/fusion/filtering/IFilter.java
similarity index 97%
rename from service/java/com/android/server/uwb/correction/filtering/IFilter.java
rename to service/fusion_lib/src/com/android/uwb/fusion/filtering/IFilter.java
index cef5d095..a3b10dae 100644
--- a/service/java/com/android/server/uwb/correction/filtering/IFilter.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/filtering/IFilter.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import androidx.annotation.NonNull;
 
diff --git a/service/java/com/android/server/uwb/correction/filtering/IPositionFilter.java b/service/fusion_lib/src/com/android/uwb/fusion/filtering/IPositionFilter.java
similarity index 89%
rename from service/java/com/android/server/uwb/correction/filtering/IPositionFilter.java
rename to service/fusion_lib/src/com/android/uwb/fusion/filtering/IPositionFilter.java
index a0cf87d5..66b95f1d 100644
--- a/service/java/com/android/server/uwb/correction/filtering/IPositionFilter.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/filtering/IPositionFilter.java
@@ -13,14 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
-import static com.android.server.uwb.correction.math.SphericalVector.Annotated;
+import static com.android.uwb.fusion.math.SphericalVector.Annotated;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 /**
  * Interface for a filter that operates on a UwbPosition.
diff --git a/service/java/com/android/server/uwb/correction/filtering/MedAvgFilter.java b/service/fusion_lib/src/com/android/uwb/fusion/filtering/MedAvgFilter.java
similarity index 99%
rename from service/java/com/android/server/uwb/correction/filtering/MedAvgFilter.java
rename to service/fusion_lib/src/com/android/uwb/fusion/filtering/MedAvgFilter.java
index c66ac467..2fba9cf4 100644
--- a/service/java/com/android/server/uwb/correction/filtering/MedAvgFilter.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/filtering/MedAvgFilter.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import androidx.annotation.NonNull;
 
diff --git a/service/java/com/android/server/uwb/correction/filtering/MedAvgRotationFilter.java b/service/fusion_lib/src/com/android/uwb/fusion/filtering/MedAvgRotationFilter.java
similarity index 93%
rename from service/java/com/android/server/uwb/correction/filtering/MedAvgRotationFilter.java
rename to service/fusion_lib/src/com/android/uwb/fusion/filtering/MedAvgRotationFilter.java
index 38327215..ced72df8 100644
--- a/service/java/com/android/server/uwb/correction/filtering/MedAvgRotationFilter.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/filtering/MedAvgRotationFilter.java
@@ -13,16 +13,16 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
-import static com.android.server.uwb.correction.math.MathHelper.normalizeRadians;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.normalizeRadians;
 
 import static java.lang.Math.atan2;
 import static java.lang.Math.cos;
 import static java.lang.Math.sin;
 
-import com.android.server.uwb.correction.math.MathHelper;
+import com.android.uwb.fusion.math.MathHelper;
 
 import java.util.ArrayList;
 import java.util.Collection;
diff --git a/service/java/com/android/server/uwb/correction/filtering/PositionFilterImpl.java b/service/fusion_lib/src/com/android/uwb/fusion/filtering/PositionFilterImpl.java
similarity index 94%
rename from service/java/com/android/server/uwb/correction/filtering/PositionFilterImpl.java
rename to service/fusion_lib/src/com/android/uwb/fusion/filtering/PositionFilterImpl.java
index 9604978d..442e9c52 100644
--- a/service/java/com/android/server/uwb/correction/filtering/PositionFilterImpl.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/filtering/PositionFilterImpl.java
@@ -13,16 +13,16 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.math.Vector3;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.math.Vector3;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 import java.util.Objects;
 
diff --git a/service/java/com/android/server/uwb/correction/filtering/Sample.java b/service/fusion_lib/src/com/android/uwb/fusion/filtering/Sample.java
similarity index 97%
rename from service/java/com/android/server/uwb/correction/filtering/Sample.java
rename to service/fusion_lib/src/com/android/uwb/fusion/filtering/Sample.java
index a9b7ffcb..a2b860c5 100644
--- a/service/java/com/android/server/uwb/correction/filtering/Sample.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/filtering/Sample.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import androidx.annotation.NonNull;
 
diff --git a/service/java/com/android/server/uwb/correction/math/AoaVector.java b/service/fusion_lib/src/com/android/uwb/fusion/math/AoaVector.java
similarity index 98%
rename from service/java/com/android/server/uwb/correction/math/AoaVector.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/AoaVector.java
index 1cd6633f..ab1b2cd0 100644
--- a/service/java/com/android/server/uwb/correction/math/AoaVector.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/AoaVector.java
@@ -13,10 +13,10 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static java.lang.Math.abs;
 import static java.lang.Math.acos;
diff --git a/service/java/com/android/server/uwb/correction/math/MathHelper.java b/service/fusion_lib/src/com/android/uwb/fusion/math/MathHelper.java
similarity index 98%
rename from service/java/com/android/server/uwb/correction/math/MathHelper.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/MathHelper.java
index 22e41450..f206b1e6 100644
--- a/service/java/com/android/server/uwb/correction/math/MathHelper.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/MathHelper.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import static java.lang.Math.PI;
 import static java.lang.Math.abs;
diff --git a/service/java/com/android/server/uwb/correction/math/Matrix.java b/service/fusion_lib/src/com/android/uwb/fusion/math/Matrix.java
similarity index 99%
rename from service/java/com/android/server/uwb/correction/math/Matrix.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/Matrix.java
index a92a042f..bb4b38bf 100644
--- a/service/java/com/android/server/uwb/correction/math/Matrix.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/Matrix.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import androidx.annotation.NonNull;
 
diff --git a/service/java/com/android/server/uwb/correction/math/Pose.java b/service/fusion_lib/src/com/android/uwb/fusion/math/Pose.java
similarity index 98%
rename from service/java/com/android/server/uwb/correction/math/Pose.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/Pose.java
index 73de76a1..e69bd1f1 100644
--- a/service/java/com/android/server/uwb/correction/math/Pose.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/Pose.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import androidx.annotation.NonNull;
 
diff --git a/service/java/com/android/server/uwb/correction/math/Quaternion.java b/service/fusion_lib/src/com/android/uwb/fusion/math/Quaternion.java
similarity index 98%
rename from service/java/com/android/server/uwb/correction/math/Quaternion.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/Quaternion.java
index b74e55ea..75bc53b0 100644
--- a/service/java/com/android/server/uwb/correction/math/Quaternion.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/Quaternion.java
@@ -13,10 +13,10 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static java.lang.Math.acos;
 import static java.lang.Math.asin;
diff --git a/service/java/com/android/server/uwb/correction/math/SphericalVector.java b/service/fusion_lib/src/com/android/uwb/fusion/math/SphericalVector.java
similarity index 98%
rename from service/java/com/android/server/uwb/correction/math/SphericalVector.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/SphericalVector.java
index bd5f6952..4d4eb2c3 100644
--- a/service/java/com/android/server/uwb/correction/math/SphericalVector.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/SphericalVector.java
@@ -13,10 +13,10 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static java.lang.Math.abs;
 import static java.lang.Math.acos;
diff --git a/service/java/com/android/server/uwb/correction/math/Vector3.java b/service/fusion_lib/src/com/android/uwb/fusion/math/Vector3.java
similarity index 99%
rename from service/java/com/android/server/uwb/correction/math/Vector3.java
rename to service/fusion_lib/src/com/android/uwb/fusion/math/Vector3.java
index ad969522..1f3c6440 100644
--- a/service/java/com/android/server/uwb/correction/math/Vector3.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/math/Vector3.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import static java.lang.Math.acos;
 import static java.lang.Math.sqrt;
diff --git a/service/java/com/android/server/uwb/correction/pose/ApplicationPoseSource.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/ApplicationPoseSource.java
similarity index 91%
rename from service/java/com/android/server/uwb/correction/pose/ApplicationPoseSource.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/ApplicationPoseSource.java
index 39faaef0..e5a55cf1 100644
--- a/service/java/com/android/server/uwb/correction/pose/ApplicationPoseSource.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/ApplicationPoseSource.java
@@ -13,14 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Matrix;
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.Matrix;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.Vector3;
 
 import com.google.common.primitives.Doubles;
 import com.google.common.primitives.Floats;
diff --git a/service/java/com/android/server/uwb/correction/pose/GyroPoseSource.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/GyroPoseSource.java
similarity index 94%
rename from service/java/com/android/server/uwb/correction/pose/GyroPoseSource.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/GyroPoseSource.java
index bc944e88..3411a7be 100644
--- a/service/java/com/android/server/uwb/correction/pose/GyroPoseSource.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/GyroPoseSource.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
 import android.content.Context;
 import android.hardware.Sensor;
@@ -23,10 +23,10 @@ import android.hardware.SensorManager;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.MathHelper;
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.MathHelper;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.Vector3;
 
 import java.security.InvalidParameterException;
 import java.time.Instant;
diff --git a/service/java/com/android/server/uwb/correction/pose/IPoseSource.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/IPoseSource.java
similarity index 96%
rename from service/java/com/android/server/uwb/correction/pose/IPoseSource.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/IPoseSource.java
index 274f2aed..8ffa3e36 100644
--- a/service/java/com/android/server/uwb/correction/pose/IPoseSource.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/IPoseSource.java
@@ -13,11 +13,11 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
+import com.android.uwb.fusion.math.Pose;
 
 import java.util.EnumSet;
 
diff --git a/service/java/com/android/server/uwb/correction/pose/IntegPoseSource.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/IntegPoseSource.java
similarity index 95%
rename from service/java/com/android/server/uwb/correction/pose/IntegPoseSource.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/IntegPoseSource.java
index 6dcaa7fb..5c9d2c39 100644
--- a/service/java/com/android/server/uwb/correction/pose/IntegPoseSource.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/IntegPoseSource.java
@@ -13,9 +13,9 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
 
 import static java.lang.Math.abs;
 import static java.lang.Math.min;
@@ -29,9 +29,9 @@ import android.hardware.SensorManager;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.Vector3;
 
 import java.security.InvalidParameterException;
 import java.time.Instant;
diff --git a/service/java/com/android/server/uwb/correction/pose/PoseEventListener.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/PoseEventListener.java
similarity index 92%
rename from service/java/com/android/server/uwb/correction/pose/PoseEventListener.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/PoseEventListener.java
index 3447988b..08ca6e6f 100644
--- a/service/java/com/android/server/uwb/correction/pose/PoseEventListener.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/PoseEventListener.java
@@ -13,11 +13,11 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
+import com.android.uwb.fusion.math.Pose;
 
 /**
  * Used for receiving notifications from a PoseSource when there is new pose data.
diff --git a/service/java/com/android/server/uwb/correction/pose/PoseSourceBase.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/PoseSourceBase.java
similarity index 97%
rename from service/java/com/android/server/uwb/correction/pose/PoseSourceBase.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/PoseSourceBase.java
index 763681c4..5212157d 100644
--- a/service/java/com/android/server/uwb/correction/pose/PoseSourceBase.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/PoseSourceBase.java
@@ -13,14 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
 import android.util.Log;
 
 import androidx.annotation.GuardedBy;
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
+import com.android.uwb.fusion.math.Pose;
 
 import java.util.ArrayList;
 import java.util.List;
diff --git a/service/java/com/android/server/uwb/correction/pose/RotationPoseSource.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/RotationPoseSource.java
similarity index 93%
rename from service/java/com/android/server/uwb/correction/pose/RotationPoseSource.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/RotationPoseSource.java
index 737ad74d..d7ece112 100644
--- a/service/java/com/android/server/uwb/correction/pose/RotationPoseSource.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/RotationPoseSource.java
@@ -13,9 +13,9 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
 
 import android.content.Context;
 import android.hardware.Sensor;
@@ -25,9 +25,9 @@ import android.hardware.SensorManager;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.Vector3;
 
 import java.security.InvalidParameterException;
 import java.util.EnumSet;
diff --git a/service/java/com/android/server/uwb/correction/pose/SixDofPoseSource.java b/service/fusion_lib/src/com/android/uwb/fusion/pose/SixDofPoseSource.java
similarity index 93%
rename from service/java/com/android/server/uwb/correction/pose/SixDofPoseSource.java
rename to service/fusion_lib/src/com/android/uwb/fusion/pose/SixDofPoseSource.java
index 69db50ba..323062d7 100644
--- a/service/java/com/android/server/uwb/correction/pose/SixDofPoseSource.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/pose/SixDofPoseSource.java
@@ -13,9 +13,9 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
 
 import android.content.Context;
 import android.hardware.Sensor;
@@ -25,9 +25,9 @@ import android.hardware.SensorManager;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.Vector3;
 
 import java.security.InvalidParameterException;
 import java.util.EnumSet;
diff --git a/service/java/com/android/server/uwb/correction/primers/AoaPrimer.java b/service/fusion_lib/src/com/android/uwb/fusion/primers/AoaPrimer.java
similarity index 89%
rename from service/java/com/android/server/uwb/correction/primers/AoaPrimer.java
rename to service/fusion_lib/src/com/android/uwb/fusion/primers/AoaPrimer.java
index 40a82586..87240641 100644
--- a/service/java/com/android/server/uwb/correction/primers/AoaPrimer.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/primers/AoaPrimer.java
@@ -13,15 +13,15 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.AoaVector;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.AoaVector;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 /**
  * Converts a PDoA azimuth value to a spherical coordinate azimuth by accounting for elevation.
diff --git a/service/java/com/android/server/uwb/correction/primers/BackAzimuthPrimer.java b/service/fusion_lib/src/com/android/uwb/fusion/primers/BackAzimuthPrimer.java
similarity index 96%
rename from service/java/com/android/server/uwb/correction/primers/BackAzimuthPrimer.java
rename to service/fusion_lib/src/com/android/uwb/fusion/primers/BackAzimuthPrimer.java
index 8a48d5d8..8297ab80 100644
--- a/service/java/com/android/server/uwb/correction/primers/BackAzimuthPrimer.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/primers/BackAzimuthPrimer.java
@@ -13,12 +13,12 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
-import static com.android.server.uwb.correction.math.MathHelper.MS_PER_SEC;
-import static com.android.server.uwb.correction.math.MathHelper.normalizeRadians;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.MS_PER_SEC;
+import static com.android.uwb.fusion.math.MathHelper.normalizeRadians;
 
 import static java.lang.Math.abs;
 import static java.lang.Math.exp;
@@ -33,11 +33,11 @@ import android.util.Log;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.MathHelper;
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.MathHelper;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 import java.util.ArrayDeque;
 import java.util.Queue;
diff --git a/service/java/com/android/server/uwb/correction/primers/ElevationPrimer.java b/service/fusion_lib/src/com/android/uwb/fusion/primers/ElevationPrimer.java
similarity index 91%
rename from service/java/com/android/server/uwb/correction/primers/ElevationPrimer.java
rename to service/fusion_lib/src/com/android/uwb/fusion/primers/ElevationPrimer.java
index 1a8ad063..3146161c 100644
--- a/service/java/com/android/server/uwb/correction/primers/ElevationPrimer.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/primers/ElevationPrimer.java
@@ -13,15 +13,15 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.pose.IPoseSource;
-import com.android.server.uwb.correction.pose.IPoseSource.Capabilities;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.pose.IPoseSource;
+import com.android.uwb.fusion.pose.IPoseSource.Capabilities;
 
 /**
  * Applies a default pose-based elevation to a UWB reading. A basic "assumption" about what the
diff --git a/service/java/com/android/server/uwb/correction/primers/FovPrimer.java b/service/fusion_lib/src/com/android/uwb/fusion/primers/FovPrimer.java
similarity index 92%
rename from service/java/com/android/server/uwb/correction/primers/FovPrimer.java
rename to service/fusion_lib/src/com/android/uwb/fusion/primers/FovPrimer.java
index 7e78edc3..c953b2d3 100644
--- a/service/java/com/android/server/uwb/correction/primers/FovPrimer.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/primers/FovPrimer.java
@@ -13,9 +13,9 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static java.lang.Math.abs;
 import static java.lang.Math.cos;
@@ -23,9 +23,9 @@ import static java.lang.Math.cos;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 /**
  * Limits the field view of incoming UWB readings by replacing angles outside the defined limits
diff --git a/service/java/com/android/server/uwb/correction/primers/IPrimer.java b/service/fusion_lib/src/com/android/uwb/fusion/primers/IPrimer.java
similarity index 91%
rename from service/java/com/android/server/uwb/correction/primers/IPrimer.java
rename to service/fusion_lib/src/com/android/uwb/fusion/primers/IPrimer.java
index 4883abc2..decbbc53 100644
--- a/service/java/com/android/server/uwb/correction/primers/IPrimer.java
+++ b/service/fusion_lib/src/com/android/uwb/fusion/primers/IPrimer.java
@@ -13,13 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 /**
  * Given known data about a UWB reading, applies corrections that correct for nonlinearities,
diff --git a/service/fusion_lib/tests/Android.bp b/service/fusion_lib/tests/Android.bp
new file mode 100644
index 00000000..16e102e2
--- /dev/null
+++ b/service/fusion_lib/tests/Android.bp
@@ -0,0 +1,36 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+    default_team: "trendy_team_fwk_uwb",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "UwbFusionLibTests",
+    srcs: ["**/*.java"],
+    certificate: "platform",
+    static_libs: [
+        "com.uwb.fusion",
+        "androidx.test.rules",
+        "androidx.test.ext.junit",
+        "androidx.test.runner",
+        "mockito-target-minus-junit4",
+        "truth",
+        "platform-test-annotations",
+    ],
+    test_suites: ["device-tests"],
+}
diff --git a/service/fusion_lib/tests/AndroidManifest.xml b/service/fusion_lib/tests/AndroidManifest.xml
new file mode 100644
index 00000000..de11f7a1
--- /dev/null
+++ b/service/fusion_lib/tests/AndroidManifest.xml
@@ -0,0 +1,31 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  Copyright 2024 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+
+<manifest
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.uwb.fusion">
+
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <!-- This is a self-instrumenting test package. -->
+    <instrumentation
+        android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:targetPackage="com.android.uwb.fusion"
+        android:label="UWB fusion lib tests" />
+</manifest>
\ No newline at end of file
diff --git a/service/fusion_lib/tests/AndroidTest.xml b/service/fusion_lib/tests/AndroidTest.xml
new file mode 100644
index 00000000..52192022
--- /dev/null
+++ b/service/fusion_lib/tests/AndroidTest.xml
@@ -0,0 +1,35 @@
+<?xml version="1.0" encoding="utf-8"?>
+
+<!--
+  Copyright 2024 The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+-->
+
+<configuration description="Configuration for UWB Fusion Lib unit tests">
+    <option name="test-suite-tag" value="apct" />
+    <option name="test-suite-tag" value="apct-instrumentation" />
+
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="UwbFusionLibTests.apk" />
+    </target_preparer>
+
+    <option name="test-tag" value="UwbFusionLibTests"/>
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="com.android.uwb.fusion" />
+        <option name="hidden-api-checks" value="false"/>
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner"/>
+    </test>
+</configuration>
\ No newline at end of file
diff --git a/service/tests/src/com/android/server/uwb/correction/TestHelpers.java b/service/fusion_lib/tests/com/android/uwb/fusion/TestHelpers.java
similarity index 87%
rename from service/tests/src/com/android/server/uwb/correction/TestHelpers.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/TestHelpers.java
index 4f964009..e9d1bd66 100644
--- a/service/tests/src/com/android/server/uwb/correction/TestHelpers.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/TestHelpers.java
@@ -14,13 +14,13 @@
  * limitations under the License.
  */
 
-package com.android.server.uwb.correction;
+package com.android.uwb.fusion;
 
 import static java.lang.Math.abs;
 
-import com.android.server.uwb.correction.math.AoaVector;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.AoaVector;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.Vector3;
 
 import org.junit.Assert;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/UwbFilterEngineTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/UwbFilterEngineTest.java
similarity index 89%
rename from service/tests/src/com/android/server/uwb/correction/UwbFilterEngineTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/UwbFilterEngineTest.java
index 7810d1ad..457259f0 100644
--- a/service/tests/src/com/android/server/uwb/correction/UwbFilterEngineTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/UwbFilterEngineTest.java
@@ -13,23 +13,23 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction;
+package com.android.uwb.fusion;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import android.platform.test.annotations.Presubmit;
 
-import com.android.server.uwb.correction.filtering.NullFilter;
-import com.android.server.uwb.correction.filtering.PositionFilterImpl;
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.math.Vector3;
-import com.android.server.uwb.correction.pose.NullPoseSource;
-import com.android.server.uwb.correction.primers.NullPrimer;
+import com.android.uwb.fusion.filtering.NullFilter;
+import com.android.uwb.fusion.filtering.PositionFilterImpl;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.math.Vector3;
+import com.android.uwb.fusion.pose.NullPoseSource;
+import com.android.uwb.fusion.primers.NullPrimer;
 
 import org.junit.Test;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/filtering/MedAvgFilterTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/MedAvgFilterTest.java
similarity index 98%
rename from service/tests/src/com/android/server/uwb/correction/filtering/MedAvgFilterTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/filtering/MedAvgFilterTest.java
index 813f2d2a..988ecdac 100644
--- a/service/tests/src/com/android/server/uwb/correction/filtering/MedAvgFilterTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/MedAvgFilterTest.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/filtering/MedAvgRotationFilterFilterTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/MedAvgRotationFilterFilterTest.java
similarity index 87%
rename from service/tests/src/com/android/server/uwb/correction/filtering/MedAvgRotationFilterFilterTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/filtering/MedAvgRotationFilterFilterTest.java
index 604f4d9b..b353fc8d 100644
--- a/service/tests/src/com/android/server/uwb/correction/filtering/MedAvgRotationFilterFilterTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/MedAvgRotationFilterFilterTest.java
@@ -13,11 +13,11 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static java.lang.Math.toRadians;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/filtering/NullFilter.java b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/NullFilter.java
similarity index 97%
rename from service/tests/src/com/android/server/uwb/correction/filtering/NullFilter.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/filtering/NullFilter.java
index 68ad4aa4..5d094c4a 100644
--- a/service/tests/src/com/android/server/uwb/correction/filtering/NullFilter.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/NullFilter.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import android.platform.test.annotations.Presubmit;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/filtering/NullPositionFilter.java b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/NullPositionFilter.java
similarity index 92%
rename from service/tests/src/com/android/server/uwb/correction/filtering/NullPositionFilter.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/filtering/NullPositionFilter.java
index 858de9b8..156cf253 100644
--- a/service/tests/src/com/android/server/uwb/correction/filtering/NullPositionFilter.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/filtering/NullPositionFilter.java
@@ -13,15 +13,15 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.filtering;
+package com.android.uwb.fusion.filtering;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.Vector3;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.Vector3;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 import java.util.Objects;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/AoaVectorTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/AoaVectorTest.java
similarity index 97%
rename from service/tests/src/com/android/server/uwb/correction/math/AoaVectorTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/AoaVectorTest.java
index 25c22116..95851d33 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/AoaVectorTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/AoaVectorTest.java
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/MathHelperTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/MathHelperTest.java
similarity index 86%
rename from service/tests/src/com/android/server/uwb/correction/math/MathHelperTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/MathHelperTest.java
index bfa7671c..2f0e09c7 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/MathHelperTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/MathHelperTest.java
@@ -14,14 +14,14 @@
  * limitations under the License.
  */
 
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
-import static com.android.server.uwb.correction.math.MathHelper.clamp;
-import static com.android.server.uwb.correction.math.MathHelper.lerp;
-import static com.android.server.uwb.correction.math.MathHelper.normalizeDegrees;
-import static com.android.server.uwb.correction.math.MathHelper.normalizeRadians;
-import static com.android.server.uwb.correction.math.MathHelper.rsqrt;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
+import static com.android.uwb.fusion.math.MathHelper.clamp;
+import static com.android.uwb.fusion.math.MathHelper.lerp;
+import static com.android.uwb.fusion.math.MathHelper.normalizeDegrees;
+import static com.android.uwb.fusion.math.MathHelper.normalizeRadians;
+import static com.android.uwb.fusion.math.MathHelper.rsqrt;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/MatrixTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/MatrixTest.java
similarity index 98%
rename from service/tests/src/com/android/server/uwb/correction/math/MatrixTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/MatrixTest.java
index 8bc615a3..6682f29f 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/MatrixTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/MatrixTest.java
@@ -13,13 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static com.google.common.truth.Truth.assertThat;
 
-import com.android.server.uwb.correction.TestHelpers;
+import com.android.uwb.fusion.TestHelpers;
 
 import org.junit.Test;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/PoseTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/PoseTest.java
similarity index 97%
rename from service/tests/src/com/android/server/uwb/correction/math/PoseTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/PoseTest.java
index 0a867adb..fa878994 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/PoseTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/PoseTest.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/QuaternionTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/QuaternionTest.java
similarity index 89%
rename from service/tests/src/com/android/server/uwb/correction/math/QuaternionTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/QuaternionTest.java
index f3202f06..3fe974ef 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/QuaternionTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/QuaternionTest.java
@@ -14,10 +14,10 @@
  * limitations under the License.
  */
 
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
 
 import static org.junit.Assert.assertTrue;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/RandomTestData.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/RandomTestData.java
similarity index 97%
rename from service/tests/src/com/android/server/uwb/correction/math/RandomTestData.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/RandomTestData.java
index ed54f25f..a0c9a530 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/RandomTestData.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/RandomTestData.java
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import java.util.Random;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/SphericalVectorTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/SphericalVectorTest.java
similarity index 98%
rename from service/tests/src/com/android/server/uwb/correction/math/SphericalVectorTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/SphericalVectorTest.java
index 90c0b2d0..fc5948fa 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/SphericalVectorTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/SphericalVectorTest.java
@@ -13,9 +13,9 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/Vector3Test.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/Vector3Test.java
similarity index 90%
rename from service/tests/src/com/android/server/uwb/correction/math/Vector3Test.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/Vector3Test.java
index afde036a..eae1f267 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/Vector3Test.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/Vector3Test.java
@@ -13,11 +13,11 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
 
 import static org.junit.Assert.assertEquals;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/math/Vector3Tests.java b/service/fusion_lib/tests/com/android/uwb/fusion/math/Vector3Tests.java
similarity index 97%
rename from service/tests/src/com/android/server/uwb/correction/math/Vector3Tests.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/math/Vector3Tests.java
index 200b4623..fc60c7c0 100644
--- a/service/tests/src/com/android/server/uwb/correction/math/Vector3Tests.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/math/Vector3Tests.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.uwb.correction.math;
+package com.android.uwb.fusion.math;
 
 import static com.google.common.truth.Truth.assertThat;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/pose/NullPoseSource.java b/service/fusion_lib/tests/com/android/uwb/fusion/pose/NullPoseSource.java
similarity index 94%
rename from service/tests/src/com/android/server/uwb/correction/pose/NullPoseSource.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/pose/NullPoseSource.java
index 572d76e9..03e1fee1 100644
--- a/service/tests/src/com/android/server/uwb/correction/pose/NullPoseSource.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/pose/NullPoseSource.java
@@ -13,13 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.pose;
+package com.android.uwb.fusion.pose;
 
 import android.platform.test.annotations.Presubmit;
 
 import androidx.annotation.NonNull;
 
-import com.android.server.uwb.correction.math.Pose;
+import com.android.uwb.fusion.math.Pose;
 
 import java.util.EnumSet;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/primers/AoaPrimerTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/primers/AoaPrimerTest.java
similarity index 91%
rename from service/tests/src/com/android/server/uwb/correction/primers/AoaPrimerTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/primers/AoaPrimerTest.java
index 8d19a85d..c0ab1c89 100644
--- a/service/tests/src/com/android/server/uwb/correction/primers/AoaPrimerTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/primers/AoaPrimerTest.java
@@ -13,13 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
 import static java.lang.Math.toRadians;
 
-import com.android.server.uwb.correction.TestHelpers;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.TestHelpers;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
 
 import com.google.common.truth.Truth;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/primers/BackAzimuthPrimerTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/primers/BackAzimuthPrimerTest.java
similarity index 80%
rename from service/tests/src/com/android/server/uwb/correction/primers/BackAzimuthPrimerTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/primers/BackAzimuthPrimerTest.java
index d95619a4..bfacce44 100644
--- a/service/tests/src/com/android/server/uwb/correction/primers/BackAzimuthPrimerTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/primers/BackAzimuthPrimerTest.java
@@ -13,11 +13,11 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
-import static com.android.server.uwb.correction.math.MathHelper.F_HALF_PI;
-import static com.android.server.uwb.correction.math.MathHelper.F_PI;
-import static com.android.server.uwb.correction.math.MathHelper.normalizeRadians;
+import static com.android.uwb.fusion.math.MathHelper.F_HALF_PI;
+import static com.android.uwb.fusion.math.MathHelper.F_PI;
+import static com.android.uwb.fusion.math.MathHelper.normalizeRadians;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -25,15 +25,15 @@ import static java.lang.Math.abs;
 import static java.lang.Math.signum;
 import static java.lang.Math.toRadians;
 
-import com.android.server.uwb.correction.UwbFilterEngine;
-import com.android.server.uwb.correction.filtering.NullPositionFilter;
-import com.android.server.uwb.correction.math.MathHelper;
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.Vector3;
-import com.android.server.uwb.correction.pose.IPoseSource.Capabilities;
-import com.android.server.uwb.correction.pose.NullPoseSource;
+import com.android.uwb.fusion.UwbFilterEngine;
+import com.android.uwb.fusion.filtering.NullPositionFilter;
+import com.android.uwb.fusion.math.MathHelper;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.Vector3;
+import com.android.uwb.fusion.pose.IPoseSource.Capabilities;
+import com.android.uwb.fusion.pose.NullPoseSource;
 
 import org.junit.Test;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/primers/ElevationPrimerTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/primers/ElevationPrimerTest.java
similarity index 86%
rename from service/tests/src/com/android/server/uwb/correction/primers/ElevationPrimerTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/primers/ElevationPrimerTest.java
index d7e5ca60..38988f62 100644
--- a/service/tests/src/com/android/server/uwb/correction/primers/ElevationPrimerTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/primers/ElevationPrimerTest.java
@@ -13,19 +13,19 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
-import static com.android.server.uwb.correction.TestHelpers.assertClose;
+import static com.android.uwb.fusion.TestHelpers.assertClose;
 
 import static com.google.common.truth.Truth.assertThat;
 
-import com.android.server.uwb.correction.math.Pose;
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.math.Vector3;
-import com.android.server.uwb.correction.pose.IPoseSource.Capabilities;
-import com.android.server.uwb.correction.pose.NullPoseSource;
+import com.android.uwb.fusion.math.Pose;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.math.Vector3;
+import com.android.uwb.fusion.pose.IPoseSource.Capabilities;
+import com.android.uwb.fusion.pose.NullPoseSource;
 
 import org.junit.Test;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/primers/FoVPrimerTest.java b/service/fusion_lib/tests/com/android/uwb/fusion/primers/FoVPrimerTest.java
similarity index 93%
rename from service/tests/src/com/android/server/uwb/correction/primers/FoVPrimerTest.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/primers/FoVPrimerTest.java
index e8932a9e..27926cc1 100644
--- a/service/tests/src/com/android/server/uwb/correction/primers/FoVPrimerTest.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/primers/FoVPrimerTest.java
@@ -13,16 +13,16 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
 import static com.google.common.truth.Truth.assertThat;
 
 import static java.lang.Math.toRadians;
 
-import com.android.server.uwb.correction.math.Quaternion;
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.math.Vector3;
+import com.android.uwb.fusion.math.Quaternion;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.math.Vector3;
 
 import org.junit.Test;
 
diff --git a/service/tests/src/com/android/server/uwb/correction/primers/NullPrimer.java b/service/fusion_lib/tests/com/android/uwb/fusion/primers/NullPrimer.java
similarity index 89%
rename from service/tests/src/com/android/server/uwb/correction/primers/NullPrimer.java
rename to service/fusion_lib/tests/com/android/uwb/fusion/primers/NullPrimer.java
index 4039b686..f106b438 100644
--- a/service/tests/src/com/android/server/uwb/correction/primers/NullPrimer.java
+++ b/service/fusion_lib/tests/com/android/uwb/fusion/primers/NullPrimer.java
@@ -13,14 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.uwb.correction.primers;
+package com.android.uwb.fusion.primers;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
-import com.android.server.uwb.correction.math.SphericalVector;
-import com.android.server.uwb.correction.math.SphericalVector.Annotated;
-import com.android.server.uwb.correction.pose.IPoseSource;
+import com.android.uwb.fusion.math.SphericalVector;
+import com.android.uwb.fusion.math.SphericalVector.Annotated;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 public class NullPrimer implements IPrimer {
 
diff --git a/service/java/com/android/server/uwb/DeviceConfigFacade.java b/service/java/com/android/server/uwb/DeviceConfigFacade.java
index a7bd78eb..6320a283 100644
--- a/service/java/com/android/server/uwb/DeviceConfigFacade.java
+++ b/service/java/com/android/server/uwb/DeviceConfigFacade.java
@@ -101,6 +101,7 @@ public class DeviceConfigFacade {
     private boolean mCccSupportedRangeDataNtfConfig;
     private boolean mPersistentCacheUseForCountryCodeEnabled;
     private boolean mHwIdleTurnOffEnabled;
+    private boolean mFusedCountryCodeProviderEnabled;
     private boolean mIsAntennaModeConfigSupported;
 
     public DeviceConfigFacade(Handler handler, Context context) {
@@ -120,9 +121,9 @@ public class DeviceConfigFacade {
         mRangingResultLogIntervalMs = DeviceConfig.getInt(DeviceConfig.NAMESPACE_UWB,
                 "ranging_result_log_interval_ms", DEFAULT_RANGING_RESULT_LOG_INTERVAL_MS);
         mDeviceErrorBugreportEnabled = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_UWB,
-                "device_error_bugreport_enabled", false);
+                "device_error_bugreport_enabled", true);
         mSessionInitErrorBugreportEnabled = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_UWB,
-                "session_init_error_bugreport_enabled", false);
+                "session_init_error_bugreport_enabled", true);
         mBugReportMinIntervalMs = DeviceConfig.getInt(DeviceConfig.NAMESPACE_UWB,
                 "bug_report_min_interval_ms", DEFAULT_BUG_REPORT_MIN_INTERVAL_MS);
 
@@ -315,6 +316,12 @@ public class DeviceConfigFacade {
                 mContext.getResources().getBoolean(R.bool.hw_idle_turn_off_enabled)
         );
 
+        mFusedCountryCodeProviderEnabled = DeviceConfig.getBoolean(
+                DeviceConfig.NAMESPACE_UWB,
+                "fused_country_code_provider_enabled",
+                mContext.getResources().getBoolean(R.bool.fused_country_code_provider_enabled)
+        );
+
         mIsAntennaModeConfigSupported = DeviceConfig.getBoolean(
                 DeviceConfig.NAMESPACE_UWB,
                 "is_antenna_mode_config_supported",
@@ -626,6 +633,13 @@ public class DeviceConfigFacade {
         return mHwIdleTurnOffEnabled;
     }
 
+    /**
+     * Returns whether used country code provider is enabled or not.
+     */
+    public boolean isFusedCountryCodeProviderEnabled() {
+        return mFusedCountryCodeProviderEnabled;
+    }
+
     /**
      * Returns whether antenna mode configuration is supported or not.
      */
diff --git a/service/java/com/android/server/uwb/UwbControlee.java b/service/java/com/android/server/uwb/UwbControlee.java
index e9d4f0f8..e7fa3e3b 100644
--- a/service/java/com/android/server/uwb/UwbControlee.java
+++ b/service/java/com/android/server/uwb/UwbControlee.java
@@ -24,8 +24,8 @@ import android.uwb.DistanceMeasurement;
 import android.uwb.RangingMeasurement;
 import android.uwb.UwbAddress;
 
-import com.android.server.uwb.correction.UwbFilterEngine;
-import com.android.server.uwb.correction.math.SphericalVector;
+import com.android.uwb.fusion.UwbFilterEngine;
+import com.android.uwb.fusion.math.SphericalVector;
 
 /**
  * Represents a remote controlee that is involved in a session.
diff --git a/service/java/com/android/server/uwb/UwbCountryCode.java b/service/java/com/android/server/uwb/UwbCountryCode.java
index 277ece51..165e594f 100644
--- a/service/java/com/android/server/uwb/UwbCountryCode.java
+++ b/service/java/com/android/server/uwb/UwbCountryCode.java
@@ -19,6 +19,8 @@ package com.android.server.uwb;
 import static com.android.server.uwb.data.UwbUciConstants.STATUS_CODE_OK;
 
 import android.annotation.NonNull;
+import android.app.AlarmManager;
+import android.app.PendingIntent;
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.ContextParams;
@@ -28,10 +30,12 @@ import android.content.pm.PackageManager;
 import android.location.Address;
 import android.location.Geocoder;
 import android.location.Location;
+import android.location.LocationListener;
 import android.location.LocationManager;
 import android.net.wifi.WifiManager;
 import android.net.wifi.WifiManager.ActiveCountryCodeChangedCallback;
 import android.os.Handler;
+import android.provider.Settings;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
@@ -64,7 +68,7 @@ import java.util.stream.Collectors;
 /**
  * Provide functions for making changes to UWB country code.
  * This Country Code is from MCC or phone default setting. This class sends Country Code
- * to UWB venodr via the HAL.
+ * to UWB vendor via the HAL.
  */
 public class UwbCountryCode {
     private static final String TAG = "UwbCountryCode";
@@ -81,6 +85,9 @@ public class UwbCountryCode {
     public static final String EXTRA_LAST_KNOWN_NETWORK_COUNTRY =
             "android.telephony.extra.LAST_KNOWN_NETWORK_COUNTRY";
 
+    public static final String GEOCODER_RETRY_TIMEOUT_INTENT =
+            "com.android.uwb.uwbcountrycode.GEOCODE_RETRY";
+
     // Wait 1 hour between updates
     private static final long TIME_BETWEEN_UPDATES_MS = 1000L * 60 * 60 * 1;
     // Minimum distance before an update is triggered, in meters. We don't need this to be too
@@ -91,6 +98,13 @@ public class UwbCountryCode {
     // country code has the lowest priority (in the sorted mTelephonyCountryCodeInfoPerSlot map).
     private static final int LAST_SIM_SLOT_INDEX = Integer.MAX_VALUE;
 
+    // Wait between Fused updates
+    public static final long FUSED_TIME_BETWEEN_UPDATES_MS = 1000L * 60 * 1;
+
+    // Geocode Resolver timer timeout
+    public static final long GEOCODE_RESOLVER_FIRST_TIMEOUT_MS = 1000L * 5 * 1;
+    public static final long GEOCODE_RESOLVER_RETRY_TIMEOUT_MS = 1000L * 60 * 1;
+
     private final Context mContext;
     private final Handler mHandler;
     private final TelephonyManager mTelephonyManager;
@@ -101,6 +115,11 @@ public class UwbCountryCode {
     private final UwbInjector mUwbInjector;
     private final Set<CountryCodeChangedListener> mListeners = new ArraySet<>();
 
+    private AlarmManager mGeocodeRetryTimer = null;
+    private Intent mRetryTimerIntent = new Intent(GEOCODER_RETRY_TIMEOUT_INTENT);
+    private BroadcastReceiver mRetryTimeoutReceiver;
+    private boolean mGeocoderRetryTimerActive = false;
+    private boolean mFusedLocationProviderActive = false;
     private Map<Integer, TelephonyCountryCodeSlotInfo> mTelephonyCountryCodeInfoPerSlot =
             new ConcurrentSkipListMap();
     private String mWifiCountryCode = null;
@@ -156,6 +175,7 @@ public class UwbCountryCode {
         mNativeUwbManager = nativeUwbManager;
         mHandler = handler;
         mUwbInjector = uwbInjector;
+        mGeocodeRetryTimer = mContext.getSystemService(AlarmManager.class);
     }
 
     @Keep
@@ -266,12 +286,18 @@ public class UwbCountryCode {
                         LAST_SIM_SLOT_INDEX, countryCode, null);
             }
         }
-
         if (mUwbInjector.getDeviceConfigFacade().isLocationUseForCountryCodeEnabled() &&
                 mUwbInjector.isGeocoderPresent()) {
             setCountryCodeFromGeocodingLocation(
                     mLocationManager.getLastKnownLocation(LocationManager.FUSED_PROVIDER));
         }
+        if (mUwbInjector.getDeviceConfigFacade().isLocationUseForCountryCodeEnabled()
+                && mUwbInjector.isGeocoderPresent() && !isValid(mCachedCountryCode)
+                && mUwbInjector.getDeviceConfigFacade().isPersistentCacheUseForCountryCodeEnabled()
+                && (mUwbInjector.getGlobalSettingsInt(
+                    Settings.Global.AIRPLANE_MODE_ON, 0) == 0)) {
+            startFusedLocationManager();
+        }
         // Current Wifi country code update is sent immediately on registration.
     }
 
@@ -279,6 +305,77 @@ public class UwbCountryCode {
         mListeners.add(listener);
     }
 
+    /** Start Fused Provider Country Code Resolver */
+    private void startFusedLocationManager() {
+        if (mFusedLocationProviderActive || !mUwbInjector
+                .getDeviceConfigFacade().isFusedCountryCodeProviderEnabled()) {
+            return;
+        }
+        Log.d(TAG, "Start Fused Country Code Resolver");
+        mLocationManager.requestLocationUpdates(LocationManager.FUSED_PROVIDER,
+                FUSED_TIME_BETWEEN_UPDATES_MS, DISTANCE_BETWEEN_UPDATES_METERS,
+                mFusedLocationListener, mUwbInjector.getUwbServiceLooper());
+        mFusedLocationProviderActive = true;
+    }
+
+    /** Stop Fused Provider Country Code Resolver */
+    private void stopFusedLocationManager() {
+        if (mFusedLocationProviderActive) {
+            Log.d(TAG, "Stopping Fused Country Code Resolver");
+            mLocationManager.removeUpdates(mFusedLocationListener);
+            mFusedLocationProviderActive = false;
+        }
+    }
+
+    private final LocationListener mFusedLocationListener = new LocationListener() {
+        @Override
+        public void onLocationChanged(Location location) {
+            synchronized (UwbCountryCode.this) {
+                Log.d(TAG, "Fused Provider onLocationChanged: " + location);
+                if (location.isComplete()) {
+                    setCountryCodeFromGeocodingLocation(location);
+                    startRetryRequest();
+                    stopFusedLocationManager();
+                }
+            }
+        }
+    };
+
+    /** Start retry timer in case Geocode Resolver fails */
+    private void startRetryRequest() {
+        if (mGeocoderRetryTimerActive) return;
+
+        Log.d(TAG, "Starting Geocode Resolver Timer");
+        mRetryTimeoutReceiver = new BroadcastReceiver() {
+            @Override public void onReceive(Context context, Intent intent) {
+                Log.d(TAG, "Geocode Resolver Retry Timeout onReceive");
+                setCountryCodeFromGeocodingLocation(
+                        mLocationManager.getLastKnownLocation(LocationManager.FUSED_PROVIDER));
+            }
+        };
+        mContext.registerReceiver(mRetryTimeoutReceiver,
+                new IntentFilter(GEOCODER_RETRY_TIMEOUT_INTENT));
+        mGeocodeRetryTimer.setInexactRepeating(AlarmManager.ELAPSED_REALTIME,
+                mUwbInjector.getElapsedSinceBootMillis() + GEOCODE_RESOLVER_FIRST_TIMEOUT_MS,
+                GEOCODE_RESOLVER_RETRY_TIMEOUT_MS, getRetryTimerBroadcast());
+        mGeocoderRetryTimerActive = true;
+    }
+
+    /** Stop retry timer in case Geocode Resolver fails */
+    private void stopRetryRequest() {
+        if (mGeocoderRetryTimerActive) {
+            Log.d(TAG, "Stop Geocode Resolver timer");
+            mGeocodeRetryTimer.cancel(getRetryTimerBroadcast());
+            mContext.unregisterReceiver(mRetryTimeoutReceiver);
+            mGeocoderRetryTimerActive = false;
+        }
+    }
+
+    private PendingIntent getRetryTimerBroadcast() {
+        return PendingIntent.getBroadcast(mContext, 0, mRetryTimerIntent,
+                PendingIntent.FLAG_IMMUTABLE);
+    }
+
     private void setTelephonyCountryCodeAndLastKnownCountryCode(int slotIdx, String countryCode,
             String lastKnownCountryCode) {
         Log.d(TAG, "Set telephony country code to: " + countryCode
@@ -398,6 +495,10 @@ public class UwbCountryCode {
             Log.i(TAG, "No valid country code, reset to " + DEFAULT_COUNTRY_CODE);
             country = DEFAULT_COUNTRY_CODE;
         }
+        if (isValid(country)) {
+            stopFusedLocationManager();
+            stopRetryRequest();
+        }
         if (!forceUpdate && Objects.equals(country, mCountryCode)) {
             Log.i(TAG, "Ignoring already set country code: " + country);
             return new Pair<>(STATUS_CODE_OK, mCountryCode);
@@ -487,6 +588,11 @@ public class UwbCountryCode {
             mUwbInjector.getUwbSettingsStore().put(
                     UwbSettingsStore.SETTINGS_CACHED_COUNTRY_CODE, "");
         }
+        if (mUwbInjector.getGlobalSettingsInt(Settings.Global.AIRPLANE_MODE_ON, 0) == 1) {
+            stopFusedLocationManager();
+        } else {
+            startFusedLocationManager();
+        }
     }
 
     /**
diff --git a/service/java/com/android/server/uwb/UwbInjector.java b/service/java/com/android/server/uwb/UwbInjector.java
index 9a765439..7a4baf16 100644
--- a/service/java/com/android/server/uwb/UwbInjector.java
+++ b/service/java/com/android/server/uwb/UwbInjector.java
@@ -48,25 +48,25 @@ import android.util.AtomicFile;
 import android.util.Log;
 
 import com.android.server.uwb.advertisement.UwbAdvertiseManager;
-import com.android.server.uwb.correction.UwbFilterEngine;
-import com.android.server.uwb.correction.filtering.IFilter;
-import com.android.server.uwb.correction.filtering.MedAvgFilter;
-import com.android.server.uwb.correction.filtering.MedAvgRotationFilter;
-import com.android.server.uwb.correction.filtering.PositionFilterImpl;
-import com.android.server.uwb.correction.pose.GyroPoseSource;
-import com.android.server.uwb.correction.pose.IPoseSource;
-import com.android.server.uwb.correction.pose.IntegPoseSource;
-import com.android.server.uwb.correction.pose.RotationPoseSource;
-import com.android.server.uwb.correction.pose.SixDofPoseSource;
-import com.android.server.uwb.correction.primers.AoaPrimer;
-import com.android.server.uwb.correction.primers.BackAzimuthPrimer;
-import com.android.server.uwb.correction.primers.ElevationPrimer;
-import com.android.server.uwb.correction.primers.FovPrimer;
 import com.android.server.uwb.data.ServiceProfileData;
 import com.android.server.uwb.jni.NativeUwbManager;
 import com.android.server.uwb.multchip.UwbMultichipData;
 import com.android.server.uwb.pm.ProfileManager;
 import com.android.uwb.flags.FeatureFlags;
+import com.android.uwb.fusion.UwbFilterEngine;
+import com.android.uwb.fusion.filtering.IFilter;
+import com.android.uwb.fusion.filtering.MedAvgFilter;
+import com.android.uwb.fusion.filtering.MedAvgRotationFilter;
+import com.android.uwb.fusion.filtering.PositionFilterImpl;
+import com.android.uwb.fusion.pose.GyroPoseSource;
+import com.android.uwb.fusion.pose.IPoseSource;
+import com.android.uwb.fusion.pose.IntegPoseSource;
+import com.android.uwb.fusion.pose.RotationPoseSource;
+import com.android.uwb.fusion.pose.SixDofPoseSource;
+import com.android.uwb.fusion.primers.AoaPrimer;
+import com.android.uwb.fusion.primers.BackAzimuthPrimer;
+import com.android.uwb.fusion.primers.ElevationPrimer;
+import com.android.uwb.fusion.primers.FovPrimer;
 
 import java.io.File;
 import java.util.HashMap;
diff --git a/service/java/com/android/server/uwb/UwbMetrics.java b/service/java/com/android/server/uwb/UwbMetrics.java
index 7c6a262b..831503b5 100644
--- a/service/java/com/android/server/uwb/UwbMetrics.java
+++ b/service/java/com/android/server/uwb/UwbMetrics.java
@@ -167,10 +167,16 @@ public class UwbMetrics {
         private void parseFiraParams(FiraOpenSessionParams params) {
             if (params.getStsConfig() == FiraParams.STS_CONFIG_STATIC) {
                 mStsType = UwbStatsLog.UWB_SESSION_INITIATED__STS__STATIC;
-            } else if (params.getStsConfig() == FiraParams.STS_CONFIG_DYNAMIC) {
+            } else if (params.getStsConfig() == FiraParams.STS_CONFIG_DYNAMIC
+                    || params.getStsConfig()
+                            == FiraParams.STS_CONFIG_DYNAMIC_FOR_CONTROLEE_INDIVIDUAL_KEY) {
                 mStsType = UwbStatsLog.UWB_SESSION_INITIATED__STS__DYNAMIC;
-            } else {
+            } else if (params.getStsConfig() == FiraParams.STS_CONFIG_PROVISIONED
+                    || params.getStsConfig()
+                            == FiraParams.STS_CONFIG_PROVISIONED_FOR_CONTROLEE_INDIVIDUAL_KEY) {
                 mStsType = UwbStatsLog.UWB_SESSION_INITIATED__STS__PROVISIONED;
+            } else {
+                mStsType = UwbStatsLog.UWB_SESSION_INITIATED__STS__UNKNOWN_STS;
             }
 
             mIsInitiator = params.getDeviceRole() == FiraParams.RANGING_DEVICE_ROLE_INITIATOR;
@@ -180,10 +186,12 @@ public class UwbMetrics {
         }
 
         private void parseCccParams(CccOpenRangingParams params) {
+            mStsType = UwbStatsLog.UWB_SESSION_INITIATED__STS__DYNAMIC;
             mChannel = params.getChannel();
         }
 
         private void parseAliroParams(AliroOpenRangingParams params) {
+            mStsType = UwbStatsLog.UWB_SESSION_INITIATED__STS__PROVISIONED;
             mChannel = params.getChannel();
         }
 
diff --git a/service/java/com/android/server/uwb/UwbServiceCore.java b/service/java/com/android/server/uwb/UwbServiceCore.java
index ee5a44ba..2b667f94 100644
--- a/service/java/com/android/server/uwb/UwbServiceCore.java
+++ b/service/java/com/android/server/uwb/UwbServiceCore.java
@@ -365,6 +365,7 @@ public class UwbServiceCore implements INativeUwbManager.DeviceNotification,
                 ret = "ACTIVE";
                 break;
             case UwbUciConstants.DEVICE_STATE_ERROR:
+            case UwbUciConstants.DEVICE_STATE_INIT_ERROR:
                 ret = "ERROR";
                 break;
         }
@@ -1155,7 +1156,7 @@ public class UwbServiceCore implements INativeUwbManager.DeviceNotification,
                             takBugReportAfterDeviceError("UWB Bugreport: error enabling UWB");
                         }
                         for (String chipId : mUwbInjector.getMultichipData().getChipIds()) {
-                            updateDeviceState(UwbUciConstants.DEVICE_STATE_ERROR, chipId);
+                            updateDeviceState(UwbUciConstants.DEVICE_STATE_INIT_ERROR, chipId);
                         }
                         for (InitializationFailureListener listener : mListeners) {
                             listener.onFailure();
diff --git a/service/java/com/android/server/uwb/UwbSessionManager.java b/service/java/com/android/server/uwb/UwbSessionManager.java
index d4138c8a..ba145b0c 100644
--- a/service/java/com/android/server/uwb/UwbSessionManager.java
+++ b/service/java/com/android/server/uwb/UwbSessionManager.java
@@ -18,6 +18,7 @@ package com.android.server.uwb;
 import static android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE;
 
 import static com.android.server.uwb.data.UwbUciConstants.DEVICE_TYPE_CONTROLLER;
+import static com.android.server.uwb.data.UwbUciConstants.FIRA_VERSION_MAJOR_2;
 import static com.android.server.uwb.data.UwbUciConstants.MAC_ADDRESSING_MODE_EXTENDED;
 import static com.android.server.uwb.data.UwbUciConstants.MAC_ADDRESSING_MODE_SHORT;
 import static com.android.server.uwb.data.UwbUciConstants.RANGING_DEVICE_ROLE_OBSERVER;
@@ -62,9 +63,6 @@ import androidx.annotation.VisibleForTesting;
 
 import com.android.modules.utils.build.SdkLevel;
 import com.android.server.uwb.advertisement.UwbAdvertiseManager;
-import com.android.server.uwb.correction.UwbFilterEngine;
-import com.android.server.uwb.correction.pose.ApplicationPoseSource;
-import com.android.server.uwb.correction.pose.IPoseSource;
 import com.android.server.uwb.data.DtTagUpdateRangingRoundsStatus;
 import com.android.server.uwb.data.UwbDeviceInfoResponse;
 import com.android.server.uwb.data.UwbDlTDoAMeasurement;
@@ -82,6 +80,9 @@ import com.android.server.uwb.util.ArrayUtils;
 import com.android.server.uwb.util.DataTypeConversionUtil;
 import com.android.server.uwb.util.LruList;
 import com.android.server.uwb.util.UwbUtil;
+import com.android.uwb.fusion.UwbFilterEngine;
+import com.android.uwb.fusion.pose.ApplicationPoseSource;
+import com.android.uwb.fusion.pose.IPoseSource;
 
 import com.google.uwb.support.aliro.AliroOpenRangingParams;
 import com.google.uwb.support.aliro.AliroParams;
@@ -103,7 +104,7 @@ import com.google.uwb.support.fira.FiraDataTransferPhaseConfig;
 import com.google.uwb.support.fira.FiraDataTransferPhaseConfig.FiraDataTransferPhaseManagementList;
 import com.google.uwb.support.fira.FiraHybridSessionControleeConfig;
 import com.google.uwb.support.fira.FiraHybridSessionControllerConfig;
-import com.google.uwb.support.fira.FiraOnControleeRemovedParams;
+import com.google.uwb.support.fira.FiraOnControleeAddRemoveParams;
 import com.google.uwb.support.fira.FiraOpenSessionParams;
 import com.google.uwb.support.fira.FiraParams;
 import com.google.uwb.support.fira.FiraPoseUpdateParams;
@@ -505,9 +506,31 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
             Log.d(TAG, "onMulticastListUpdateNotificationReceived - invalid session");
             return;
         }
+
         uwbSession.setMulticastListUpdateStatus(multicastListUpdateStatus);
-        synchronized (uwbSession.getWaitObj()) {
-            uwbSession.getWaitObj().blockingNotify();
+
+        int actionStatus = UwbUciConstants.STATUS_CODE_OK;
+        for (int i = 0; i < multicastListUpdateStatus.getNumOfControlee(); i++) {
+            actionStatus = multicastListUpdateStatus.getStatus()[i];
+            // Action - delete controlee, State - Active
+            if (actionStatus == UwbUciConstants.STATUS_CODE_OK) {
+                if (uwbSession.getOperationType() == SESSION_RECONFIG_RANGING) {
+                    synchronized (uwbSession.getWaitObj()) {
+                        uwbSession.getWaitObj().blockingNotify();
+                    }
+                    break;
+                }
+            } else {
+                // Handle the failure case for adding a controlee
+                mSessionNotificationManager.onControleeAddFailed(
+                        uwbSession, multicastListUpdateStatus.getControleeUwbAddresses()[i],
+                                actionStatus);
+            }
+
+        }
+        if (actionStatus !=  UwbUciConstants.STATUS_CODE_OK) {
+            mSessionNotificationManager.onRangingReconfigureFailed(
+                    uwbSession, actionStatus);
         }
     }
 
@@ -1178,6 +1201,8 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                     && (!sessionUpdateMulticastListCmdPreconditioncheck(uwbSession,
                         rangingReconfigureParams.getAction(),
                         rangingReconfigureParams.getSubSessionKeyList()))) {
+                mSessionNotificationManager.onRangingReconfigureFailed(
+                                uwbSession, UwbUciConstants.STATUS_CODE_INVALID_PARAM);
                 return UwbUciConstants.STATUS_CODE_REJECTED;
             }
             // Do not update mParams if this was triggered by framework.
@@ -1402,9 +1427,8 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
         int sessionType = uwbSession.getSessionType();
         if (UwbUciConstants.DEVICE_TYPE_CONTROLLER != deviceType
                 || UwbUciConstants.HYBRID_SCHEDULED_RANGING != scheduleMode
-                || (FiraParams.SESSION_TYPE_RANGING_ONLY_PHASE != sessionType
-                && FiraParams.SESSION_TYPE_IN_BAND_DATA_PHASE != sessionType
-                && FiraParams.SESSION_TYPE_RANGING_WITH_DATA_PHASE != sessionType)) {
+                || (UwbUciConstants.SESSION_TYPE_RANGING != sessionType
+                        && UwbUciConstants.SESSION_TYPE_DATA_TRANSFER != sessionType)) {
             Log.e(TAG, "SetHybridSessionControllerConfiguration() failed: device type: "
                     + deviceType + " schedule mode: "
                     + scheduleMode + " sessionType: " + sessionType);
@@ -1505,9 +1529,8 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
         int sessionType = uwbSession.getSessionType();
         if (UwbUciConstants.DEVICE_TYPE_CONTROLEE != deviceType
                 || UwbUciConstants.HYBRID_SCHEDULED_RANGING != scheduleMode
-                || (FiraParams.SESSION_TYPE_RANGING_ONLY_PHASE != sessionType
-                && FiraParams.SESSION_TYPE_IN_BAND_DATA_PHASE != sessionType
-                && FiraParams.SESSION_TYPE_RANGING_WITH_DATA_PHASE != sessionType)) {
+                || (UwbUciConstants.SESSION_TYPE_RANGING != sessionType
+                        && UwbUciConstants.SESSION_TYPE_DATA_TRANSFER != sessionType)) {
             Log.e(TAG, "handleSetHybridSessionControleeConfiguration() failed: device type: "
                     + deviceType + " schedule mode: " + scheduleMode
                     + " sessionType: " + sessionType);
@@ -1750,14 +1773,14 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
              * Use this for {@link FiraParams.MULTICAST_LIST_UPDATE_ACTION_DELETE} actions.
              * @return the reason for controlee removal.
              */
-            public @FiraOnControleeRemovedParams.Reason int asControleeRemovedReason() {
+            public @FiraOnControleeAddRemoveParams.Reason int asControleeRemovedReason() {
                 switch (this) {
                     case LOST_CONNECTION:
-                        return FiraOnControleeRemovedParams.Reason.LOST_CONNECTION;
+                        return FiraOnControleeAddRemoveParams.Reason.LOST_CONNECTION;
                     case REQUESTED_BY_API:
-                        return FiraOnControleeRemovedParams.Reason.REQUESTED_BY_API;
+                        return FiraOnControleeAddRemoveParams.Reason.REQUESTED_BY_API;
                     default:
-                        return FiraOnControleeRemovedParams.Reason.UNKNOWN;
+                        return FiraOnControleeAddRemoveParams.Reason.UNKNOWN;
                 }
             }
         }
@@ -2183,14 +2206,13 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
             int actionStatus = UwbUciConstants.STATUS_CODE_OK;
             for (int i = 0; i < multicastList.getNumOfControlee(); i++) {
                 actionStatus = multicastList.getStatus()[i];
+                final UwbAddress address = multicastList.getControleeUwbAddresses()[i];
                 if (actionStatus == UwbUciConstants.STATUS_CODE_OK) {
                     if (isMulticastActionAdd(action)) {
-                        uwbSession.addControlee(
-                                multicastList.getControleeUwbAddresses()[i]);
+                        uwbSession.addControlee(address);
                         mSessionNotificationManager.onControleeAdded(
-                                uwbSession);
+                                uwbSession, address);
                     } else if (action == MULTICAST_LIST_UPDATE_ACTION_DELETE) {
-                        final UwbAddress address = multicastList.getControleeUwbAddresses()[i];
                         uwbSession.removeControlee(address);
                         mSessionNotificationManager.onControleeRemoved(uwbSession, address,
                                 reason.asControleeRemovedReason());
@@ -2198,10 +2220,11 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                 } else {
                     if (isMulticastActionAdd(action)) {
                         mSessionNotificationManager.onControleeAddFailed(
-                                uwbSession, actionStatus);
+                                uwbSession, address, actionStatus);
                     } else if (action == MULTICAST_LIST_UPDATE_ACTION_DELETE) {
                         mSessionNotificationManager.onControleeRemoveFailed(
-                                uwbSession, actionStatus);
+                                uwbSession, address,
+                                actionStatus, reason.asControleeRemovedReason());
                     }
                 }
             }
@@ -2226,6 +2249,7 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
             FutureTask<Integer> cmdTask = new FutureTask<>(
                     () -> {
                         int status = UwbUciConstants.STATUS_CODE_FAILED;
+                        int ntfStatus = UwbUciConstants.STATUS_CODE_OK;
                         synchronized (uwbSession.getWaitObj()) {
                             // Handle SESSION_UPDATE_CONTROLLER_MULTICAST_LIST_CMD
                             UwbAddress[] addrList = null;
@@ -2275,6 +2299,7 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                                 status = (multicastListUpdateStatus.getNumOfControlee() == 0)
                                         ? UwbUciConstants.STATUS_CODE_OK :
                                         UwbUciConstants.STATUS_CODE_FAILED;
+
                                 if (status != UwbUciConstants.STATUS_CODE_OK) {
                                     Log.e(TAG, "Unable to update controller multicast list.");
                                     int i = 0;
@@ -2285,7 +2310,7 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                                             if (isMulticastActionAdd(action)) {
                                                 uwbSession.addControlee(addresses[i]);
                                                 mSessionNotificationManager.onControleeAdded(
-                                                          uwbSession);
+                                                                  uwbSession, addresses[i]);
                                             } else if (action
                                                     == MULTICAST_LIST_UPDATE_ACTION_DELETE) {
                                                 uwbSession.removeControlee(addresses[i]);
@@ -2296,40 +2321,62 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                                         } else {
                                             if (isMulticastActionAdd(action)) {
                                                 mSessionNotificationManager.onControleeAddFailed(
-                                                          uwbSession, st);
+                                                          uwbSession, addresses[i], st);
                                             } else if (action
                                                     == MULTICAST_LIST_UPDATE_ACTION_DELETE) {
                                                 mSessionNotificationManager.onControleeRemoveFailed(
-                                                          uwbSession, st);
+                                                        uwbSession, addresses[i], st,
+                                                                reason.asControleeRemovedReason());
                                             }
+                                            status = st;
                                         }
                                         i++;
                                     }
-                                    return status;
+                                    if (getUwbsFiraProtocolVersion(uwbSession.getChipId())
+                                                .getMajor() != FIRA_VERSION_MAJOR_2
+                                            || (uwbSession.getSessionState()
+                                                == UwbUciConstants.UWB_SESSION_STATE_IDLE)
+                                            || (multicastListUpdateStatus.getNumOfControlee()
+                                                == subSessionIdList.length)) {
+                                        return status;
+                                    }
                                 }
                                 //Fira 2.0
                                 if (getUwbsFiraProtocolVersion(
-                                        uwbSession.getChipId()).getMajor() == 2) {
+                                        uwbSession.getChipId()).getMajor()
+                                            == FIRA_VERSION_MAJOR_2) {
+                                    // Action - Add, Status - STATUS_OK
                                     if (isMulticastActionAdd(action)) {
                                         for (UwbAddress address : addrList) {
                                             Log.i(TAG, "address: " + address + " added");
                                             uwbSession.addControlee(address);
                                             mSessionNotificationManager.onControleeAdded(
-                                                    uwbSession);
+                                                    uwbSession, address);
                                         }
                                     } else {
-                                        //wait for NTF for delete op only
-                                        uwbSession.getWaitObj().blockingWait();
-
-                                        UwbMulticastListUpdateStatus multicastList =
+                                        if (uwbSession.getSessionState()
+                                                == UwbUciConstants.UWB_SESSION_STATE_ACTIVE) {
+                                            //wait for NTF for delete action only
+                                            uwbSession.getWaitObj().blockingWait();
+                                            UwbMulticastListUpdateStatus multicastList =
                                                 uwbSession.getMulticastListUpdateStatus();
 
-                                        if (multicastList == null) {
-                                            Log.e(TAG, "controller multicast list is empty!");
-                                            return status;
+                                            if (multicastList == null) {
+                                                Log.e(TAG, "controller multicast list is empty!");
+                                                return status;
+                                            }
+                                            ntfStatus = updateAddRemoveCallbacks(uwbSession,
+                                                    multicastList, action, reason);
+                                        } else {
+                                            // Action - Delete, State - Idle, Status - STATUS_OK
+                                            for (UwbAddress address : addrList) {
+                                                Log.i(TAG, "address: " + address + " removed");
+                                                uwbSession.removeControlee(address);
+                                                mSessionNotificationManager.onControleeRemoved(
+                                                        uwbSession, address,
+                                                        reason.asControleeRemovedReason());
+                                            }
                                         }
-                                        status = updateAddRemoveCallbacks(uwbSession, multicastList,
-                                                action, reason);
                                     }
                                 } else {
                                     //Fira 1.1
@@ -2361,7 +2408,8 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                                             uwbSession);
                                 }
                             }
-                            if (status == UwbUciConstants.STATUS_CODE_OK) {
+                            if (status == UwbUciConstants.STATUS_CODE_OK
+                                    && ntfStatus == UwbUciConstants.STATUS_CODE_OK) {
                                 // only call this if all controlees succeeded otherwise the
                                 //  fail status cause a onRangingReconfigureFailed later.
                                 if (reason != Reconfiguration.Reason.FG_STATE_CHANGE) {
@@ -2698,6 +2746,7 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
             this.mNonPrivilegedAppInAttributionSource =
                     getAnyNonPrivilegedAppInAttributionSourceInternal();
             this.mStackSessionPriority = calculateSessionPriority();
+            this.mControlees = new ConcurrentHashMap<>();
 
             if (params instanceof FiraOpenSessionParams) {
                 FiraOpenSessionParams firaParams = (FiraOpenSessionParams) params;
@@ -2715,7 +2764,6 @@ public class UwbSessionManager implements INativeUwbManager.SessionNotification,
                         break;
                 }
 
-                mControlees = new ConcurrentHashMap<>();
                 if (firaParams.getDestAddressList() != null) {
                     // Set up list of all controlees involved.
                     for (UwbAddress address : firaParams.getDestAddressList()) {
diff --git a/service/java/com/android/server/uwb/UwbSessionNotificationHelper.java b/service/java/com/android/server/uwb/UwbSessionNotificationHelper.java
index 7e66619e..13ce1e2b 100644
--- a/service/java/com/android/server/uwb/UwbSessionNotificationHelper.java
+++ b/service/java/com/android/server/uwb/UwbSessionNotificationHelper.java
@@ -119,6 +119,32 @@ public class UwbSessionNotificationHelper {
         return rangingChangeReason;
     }
 
+    /**
+     * Convert Multicast list update status codes to an API reason code.
+     */
+    public static int convertMulticastListUpdateStatusToApiReasonCode(
+            int multicastListUpdateStatus) {
+        int rangingChangeReason = RangingChangeReason.UNKNOWN;
+        switch (multicastListUpdateStatus) {
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_OK:
+                rangingChangeReason = RangingChangeReason.LOCAL_API;
+                break;
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_FULL:
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_KEY_FETCH_FAIL:
+                rangingChangeReason = RangingChangeReason.PROTOCOL_SPECIFIC;
+                break;
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_SUB_SESSION_ID_NOT_FOUND:
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_SUB_SESSION_KEY_NOT_FOUND:
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_SUB_SESSION_KEY_NOT_APPLICABLE:
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_SESSION_KEY_NOT_FOUND:
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_ADDRESS_NOT_FOUND:
+            case UwbUciConstants.MULTICAST_LIST_UPDATE_STATUS_ERROR_ADDRESS_ALREADY_PRESENT:
+                rangingChangeReason = RangingChangeReason.BAD_PARAMETERS;
+                break;
+        }
+        return rangingChangeReason;
+    }
+
     /**
      * Convert UCI reason code values to UCI status code, as some of the callbacks expect to get
      * the latter.
diff --git a/service/java/com/android/server/uwb/UwbSessionNotificationManager.java b/service/java/com/android/server/uwb/UwbSessionNotificationManager.java
index 80293f29..220dbef6 100644
--- a/service/java/com/android/server/uwb/UwbSessionNotificationManager.java
+++ b/service/java/com/android/server/uwb/UwbSessionNotificationManager.java
@@ -48,7 +48,7 @@ import com.google.uwb.support.ccc.CccParams;
 import com.google.uwb.support.ccc.CccRangingReconfiguredParams;
 import com.google.uwb.support.dltdoa.DlTDoAMeasurement;
 import com.google.uwb.support.fira.FiraDataTransferPhaseConfigStatusCode;
-import com.google.uwb.support.fira.FiraOnControleeRemovedParams;
+import com.google.uwb.support.fira.FiraOnControleeAddRemoveParams;
 import com.google.uwb.support.fira.FiraOpenSessionParams;
 import com.google.uwb.support.fira.FiraParams;
 import com.google.uwb.support.oemextension.RangingReportMetadata;
@@ -272,8 +272,8 @@ public class UwbSessionNotificationManager {
         IUwbRangingCallbacks uwbRangingCallbacks = uwbSession.getIUwbRangingCallbacks();
         try {
             uwbRangingCallbacks.onRangingReconfigureFailed(sessionHandle,
-                    UwbSessionNotificationHelper.convertUciStatusToApiReasonCode(
-                            status),
+                    UwbSessionNotificationHelper.convertMulticastListUpdateStatusToApiReasonCode(
+                        status),
                     UwbSessionNotificationHelper.convertUciStatusToParam(
                             uwbSession.getProtocolName(), status));
             Log.i(TAG, "IUwbRangingCallbacks - onRangingReconfigureFailed");
@@ -283,11 +283,14 @@ public class UwbSessionNotificationManager {
         }
     }
 
-    public void onControleeAdded(UwbSession uwbSession) {
+    public void onControleeAdded(UwbSession uwbSession, UwbAddress controleeAddress) {
         SessionHandle sessionHandle = uwbSession.getSessionHandle();
         IUwbRangingCallbacks uwbRangingCallbacks = uwbSession.getIUwbRangingCallbacks();
         try {
-            uwbRangingCallbacks.onControleeAdded(sessionHandle, new PersistableBundle());
+            uwbRangingCallbacks.onControleeAdded(sessionHandle,
+                new FiraOnControleeAddRemoveParams.Builder(controleeAddress)
+                    .setReason(FiraOnControleeAddRemoveParams.Reason.REQUESTED_BY_API)
+                    .build().toBundle());
             Log.i(TAG, "IUwbRangingCallbacks - onControleeAdded");
         } catch (Exception e) {
             Log.e(TAG, "IUwbRangingCallbacks - onControleeAdded: Failed");
@@ -295,15 +298,16 @@ public class UwbSessionNotificationManager {
         }
     }
 
-    public void onControleeAddFailed(UwbSession uwbSession, int status) {
+    public void onControleeAddFailed(
+            UwbSession uwbSession, UwbAddress controleeAddress, int status) {
         SessionHandle sessionHandle = uwbSession.getSessionHandle();
         IUwbRangingCallbacks uwbRangingCallbacks = uwbSession.getIUwbRangingCallbacks();
         try {
             uwbRangingCallbacks.onControleeAddFailed(sessionHandle,
-                    UwbSessionNotificationHelper.convertUciStatusToApiReasonCode(
-                            status),
-                    UwbSessionNotificationHelper.convertUciStatusToParam(
-                            uwbSession.getProtocolName(), status));
+                    status,
+                    new FiraOnControleeAddRemoveParams.Builder(controleeAddress)
+                        .setReason(FiraOnControleeAddRemoveParams.Reason.REQUESTED_BY_API)
+                        .build().toBundle());
             Log.i(TAG, "IUwbRangingCallbacks - onControleeAddFailed");
         } catch (Exception e) {
             Log.e(TAG, "IUwbRangingCallbacks - onControleeAddFailed : Failed");
@@ -312,12 +316,12 @@ public class UwbSessionNotificationManager {
     }
 
     public void onControleeRemoved(UwbSession uwbSession, UwbAddress controleeAddress,
-            @FiraOnControleeRemovedParams.Reason int reason) {
+            @FiraOnControleeAddRemoveParams.Reason int reason) {
         SessionHandle sessionHandle = uwbSession.getSessionHandle();
         IUwbRangingCallbacks uwbRangingCallbacks = uwbSession.getIUwbRangingCallbacks();
         try {
             uwbRangingCallbacks.onControleeRemoved(sessionHandle,
-                    new FiraOnControleeRemovedParams.Builder(controleeAddress).setReason(reason)
+                    new FiraOnControleeAddRemoveParams.Builder(controleeAddress).setReason(reason)
                             .build().toBundle());
             Log.i(TAG, "IUwbRangingCallbacks - onControleeRemoved");
         } catch (Exception e) {
@@ -326,15 +330,15 @@ public class UwbSessionNotificationManager {
         }
     }
 
-    public void onControleeRemoveFailed(UwbSession uwbSession, int status) {
+    public void onControleeRemoveFailed(UwbSession uwbSession, UwbAddress controleeAddress,
+            int status, int reason) {
         SessionHandle sessionHandle = uwbSession.getSessionHandle();
         IUwbRangingCallbacks uwbRangingCallbacks = uwbSession.getIUwbRangingCallbacks();
         try {
             uwbRangingCallbacks.onControleeRemoveFailed(sessionHandle,
-                    UwbSessionNotificationHelper.convertUciStatusToApiReasonCode(
-                            status),
-                    UwbSessionNotificationHelper.convertUciStatusToParam(
-                            uwbSession.getProtocolName(), status));
+                    status,
+                    new FiraOnControleeAddRemoveParams.Builder(controleeAddress).setReason(reason)
+                            .build().toBundle());
             Log.i(TAG, "IUwbRangingCallbacks - onControleeRemoveFailed");
         } catch (Exception e) {
             Log.e(TAG, "IUwbRangingCallbacks - onControleeRemoveFailed : Failed");
diff --git a/service/java/com/android/server/uwb/UwbShellCommand.java b/service/java/com/android/server/uwb/UwbShellCommand.java
index 505d022b..62875cb6 100644
--- a/service/java/com/android/server/uwb/UwbShellCommand.java
+++ b/service/java/com/android/server/uwb/UwbShellCommand.java
@@ -459,16 +459,16 @@ public class UwbShellCommand extends BasicShellCommandHandler {
         boolean aoaResultReqEnabled = false;
         String option = getNextOption();
         while (option != null) {
-            if (option.equals("-b")) {
+            if (option.equals("-b") || option.equals("--blocking")) {
                 shouldBlockCall = true;
             }
-            if (option.equals("-i")) {
+            if (option.equals("-i") || option.equals("--session-id")) {
                 builder.setSessionId(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-c")) {
+            if (option.equals("-c") || option.equals("--channel")) {
                 builder.setChannelNumber(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-t")) {
+            if (option.equals("-t") || option.equals("--device-type")) {
                 String type = getNextArgRequired();
                 if (type.equals("controller")) {
                     builder.setDeviceType(RANGING_DEVICE_TYPE_CONTROLLER);
@@ -478,7 +478,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("Unknown device type: " + type);
                 }
             }
-            if (option.equals("-r")) {
+            if (option.equals("-r") || option.equals("--device-role")) {
                 String role = getNextArgRequired();
                 if (role.equals("initiator")) {
                     builder.setDeviceRole(RANGING_DEVICE_ROLE_INITIATOR);
@@ -488,14 +488,14 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("Unknown device role: " + role);
                 }
             }
-            if (option.equals("-a")) {
+            if (option.equals("-a") || option.equals("--device-address")) {
                 builder.setDeviceAddress(
                         UwbAddress.fromBytes(
                                 ByteBuffer.allocate(SHORT_ADDRESS_BYTE_LENGTH)
                                         .putShort(Short.parseShort(getNextArgRequired()))
                                         .array()));
             }
-            if (option.equals("-d")) {
+            if (option.equals("-d") || option.equals("--dest-addresses")) {
                 String[] destAddressesString = getNextArgRequired().split(",");
                 List<UwbAddress> destAddresses = new ArrayList<>();
                 for (String destAddressString : destAddressesString) {
@@ -509,7 +509,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                         ? MULTI_NODE_MODE_ONE_TO_MANY
                         : MULTI_NODE_MODE_UNICAST);
             }
-            if (option.equals("-m")) {
+            if (option.equals("-m") || option.equals("--multi-node-mode")) {
                 String mode = getNextArgRequired();
                 if (mode.equals("unicast")) {
                     builder.setMultiNodeMode(MULTI_NODE_MODE_UNICAST);
@@ -518,10 +518,10 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                 } else if (mode.equals("many-to-many")) {
                     builder.setMultiNodeMode(MULTI_NODE_MODE_MANY_TO_MANY);
                 } else {
-                    throw new IllegalArgumentException("Unknown multi-node mode: " + mode);
+                    throw new IllegalArgumentException("Unknown multi-node-mode: " + mode);
                 }
             }
-            if (option.equals("-u")) {
+            if (option.equals("-u") || option.equals("--round-usage")) {
                 String usage = getNextArgRequired();
                 if (usage.equals("ds-twr")) {
                     builder.setRangingRoundUsage(RANGING_ROUND_USAGE_DS_TWR_DEFERRED_MODE);
@@ -535,13 +535,13 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("Unknown round usage: " + usage);
                 }
             }
-            if (option.equals("-l")) {
+            if (option.equals("-l") || option.equals("--ranging-interval-ms")) {
                 builder.setRangingIntervalMs(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-s")) {
+            if (option.equals("-s") || option.equals("--slots-per-ranging-round")) {
                 builder.setSlotsPerRangingRound(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-x")) {
+            if (option.equals("-x") || option.equals("--range-data-ntf-proximity")) {
                 String[] rangeDataNtfProximityString = getNextArgRequired().split(",");
                 if (rangeDataNtfProximityString.length != 2) {
                     throw new IllegalArgumentException("Unexpected range data ntf proximity range:"
@@ -555,7 +555,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                 builder.setRangeDataNtfProximityNear(rangeDataNtfProximityNearCm);
                 builder.setRangeDataNtfProximityFar(rangeDataNtfProximityFarCm);
             }
-            if (option.equals("-R")) {
+            if (option.equals("-R") || option.equals("--range-data-notification")) {
                 // enable / disable range data NTFs
                 // range-data-notification
                 String range_data_ntf = getNextArgRequired();
@@ -568,7 +568,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                         + range_data_ntf);
                 }
             }
-            if (option.equals("-z")) {
+            if (option.equals("-z") || option.equals("--interleaving-ratio")) {
                 String[] interleaveRatioString = getNextArgRequired().split(",");
                 if (interleaveRatioString.length != 3) {
                     throw new IllegalArgumentException("Unexpected interleaving ratio: "
@@ -586,7 +586,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                         numOfAoaElevationMrmts);
                 interleavingEnabled = true;
             }
-            if (option.equals("-e")) {
+            if (option.equals("-e") || option.equals("--aoa-result-request")) {
                 String aoaType = getNextArgRequired();
                 if (aoaType.equals("none")) {
                     builder.setAoaResultRequest(AOA_RESULT_REQUEST_MODE_NO_AOA_REPORT);
@@ -603,7 +603,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                 }
                 aoaResultReqEnabled = true;
             }
-            if (option.equals("-f")) {
+            if (option.equals("-f") || option.equals("--result-report-config")) {
                 String[] resultReportConfigs = getNextArgRequired().split(",");
                 for (String resultReportConfig : resultReportConfigs) {
                     if (resultReportConfig.equals("tof")) {
@@ -620,7 +620,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     }
                 }
             }
-            if (option.equals("-g")) {
+            if (option.equals("-g") || option.equals("--sts-iv")) {
                 String staticSTSIV = getNextArgRequired();
                 if (staticSTSIV.length() == 12) {
                     builder.setStaticStsIV(BaseEncoding.base16().decode(staticSTSIV.toUpperCase()));
@@ -628,7 +628,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("staticSTSIV expecting 6 bytes");
                 }
             }
-            if (option.equals("-v")) {
+            if (option.equals("-v") || option.equals("--vendor-id")) {
                 String vendorId = getNextArgRequired();
                 if (vendorId.length() == 4) {
                     builder.setVendorId(BaseEncoding.base16().decode(vendorId.toUpperCase()));
@@ -636,24 +636,24 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("vendorId expecting 2 bytes");
                 }
             }
-            if (option.equals("-h")) {
+            if (option.equals("-h") || option.equals("--slot-duration-rstu")) {
                 int slotDurationRstu = Integer.parseInt(getNextArgRequired());
                 builder.setSlotDurationRstu(slotDurationRstu);
             }
-            if (option.equals("-w")) {
+            if (option.equals("-w") || option.equals("--has-result-report-phase")) {
                 boolean hasRangingResultReportMessage =
                         getNextArgRequiredTrueOrFalse("enabled", "disabled");
                 builder.setHasRangingResultReportMessage(hasRangingResultReportMessage);
             }
-            if (option.equals("-y")) {
+            if (option.equals("-y") || option.equals("--hopping-mode")) {
                 boolean hoppingEnabled = getNextArgRequiredTrueOrFalse("enabled", "disabled");
                 builder.setHoppingMode(hoppingEnabled ? 1 : 0);
             }
-            if (option.equals("-p")) {
+            if (option.equals("-p") || option.equals("--preamble-code-index")) {
                 int preambleCodeIndex = Integer.parseInt(getNextArgRequired());
                 builder.setPreambleCodeIndex(preambleCodeIndex);
             }
-            if (option.equals("-o")) {
+            if (option.equals("-o") || option.equals("--sts-config-type")) {
                 String stsConfigType = getNextArgRequired();
                 if (stsConfigType.equals("static")) {
                     builder.setStsConfig(STS_CONFIG_STATIC);
@@ -663,7 +663,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("unknown sts config type");
                 }
             }
-            if (option.equals("-n")) {
+            if (option.equals("-n") || option.equals("--session-key")) {
                 String sessionKey = getNextArgRequired();
                 if (sessionKey.length() == 32 || sessionKey.length() == 64) {
                     builder.setSessionKey(BaseEncoding.base16().decode(sessionKey));
@@ -671,7 +671,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("sessionKey expecting 16 or 32 bytes");
                 }
             }
-            if (option.equals("-k")) {
+            if (option.equals("-k") || option.equals("--sub-session-key")) {
                 String subSessionKey = getNextArgRequired();
                 if (subSessionKey.length() == 32 || subSessionKey.length() == 64) {
                     builder.setSubsessionKey(BaseEncoding.base16().decode(subSessionKey));
@@ -679,11 +679,11 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException(("subSessionKey expecting 16 or 32 bytes"));
                 }
             }
-            if (option.equals("-j")) {
+            if (option.equals("-j") || option.equals("--error-streak-timeout-ms")) {
                 int errorStreakTimeoutMs = Integer.parseInt(getNextArgRequired());
                 builder.setRangingErrorStreakTimeoutMs(errorStreakTimeoutMs);
             }
-            if (option.equals("-q")) {
+            if (option.equals("-q") || option.equals("--session-priority")) {
                 int sessionPriority = Integer.parseInt(getNextArgRequired());
                 if (sessionPriority < 1 || sessionPriority > 100 || sessionPriority == 50) {
                     throw new IllegalArgumentException(
@@ -692,7 +692,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                 }
                 builder.setSessionPriority(sessionPriority);
             }
-            if (option.equals("-P")) {
+            if (option.equals("-P") || option.equals("--prf-mode")) {
                 String prfMode = getNextArgRequired();
                 if (prfMode.equals("bprf")) {
                     builder.setPrfMode(PRF_MODE_BPRF);
@@ -702,7 +702,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("Wrong arguments for prmMode");
                 }
             }
-            if (option.equals("-D")) {
+            if (option.equals("-D") || option.equals("--psdu-data-rate")) {
                 String psduDataRate = getNextArgRequired();
                 if (psduDataRate.equals("6m81")) {
                     builder.setPsduDataRate(PSDU_DATA_RATE_6M81);
@@ -716,7 +716,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("Wrong arguments for psduDataRate");
                 }
             }
-            if (option.equals("-B")) {
+            if (option.equals("-B") || option.equals("--bprf-phr-data-rate")) {
                 String bprfPhrDataRate = getNextArgRequired();
                 if (bprfPhrDataRate.equals("850k")) {
                     builder.setBprfPhrDataRate(BPRF_PHR_DATA_RATE_850K);
@@ -726,11 +726,11 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                     throw new IllegalArgumentException("Wrong arguments for bprfPhrDataRate");
                 }
             }
-            if (option.equals("-A")) {
+            if (option.equals("-A") || option.equals("--tx-adaptive-power")) {
                 builder.setIsTxAdaptivePayloadPowerEnabled(
                         getNextArgRequiredTrueOrFalse("enabled", "disabled"));
             }
-            if (option.equals("-S")) {
+            if (option.equals("-S") || option.equals("--sfd-id")) {
                 int sfd_id = Integer.parseInt(getNextArgRequired());
                 if (sfd_id < 0 || sfd_id > 4) {
                     throw new IllegalArgumentException("SFD_ID should be in range 0-4");
@@ -795,13 +795,13 @@ public class UwbShellCommand extends BasicShellCommandHandler {
         boolean shouldBlockCall = false;
         String option = getNextOption();
         while (option != null) {
-            if (option.equals("-b")) {
+            if (option.equals("-b") || option.equals("--blocking")) {
                 shouldBlockCall = true;
             }
-            if (option.equals("-u")) {
+            if (option.equals("-u") || option.equals("--uwb-config")) {
                 builder.setUwbConfig(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-p")) {
+            if (option.equals("-p") || option.equals("--pulse-shape-combo")) {
                 String[] pulseComboString = getNextArgRequired().split(",");
                 if (pulseComboString.length != 2) {
                     throw new IllegalArgumentException("Erroneous pulse combo: "
@@ -811,28 +811,28 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                         Integer.parseInt(pulseComboString[0]),
                         Integer.parseInt(pulseComboString[1])));
             }
-            if (option.equals("-i")) {
+            if (option.equals("-i") || option.equals("--session-id")) {
                 builder.setSessionId(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-r")) {
+            if (option.equals("-r") || option.equals("--ran-multiplier")) {
                 builder.setRanMultiplier(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-c")) {
+            if (option.equals("-c") || option.equals("--channel")) {
                 builder.setChannel(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-m")) {
+            if (option.equals("-m") || option.equals("--num-chaps-per-slot")) {
                 builder.setNumChapsPerSlot(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-n")) {
+            if (option.equals("-n") || option.equals("--num-responder-nodes")) {
                 builder.setNumResponderNodes(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-o")) {
+            if (option.equals("-o") || option.equals("--num-slots-per-round")) {
                 builder.setNumSlotsPerRound(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-s")) {
+            if (option.equals("-s") || option.equals("--sync-code-index")) {
                 builder.setSyncCodeIndex(Integer.parseInt(getNextArgRequired()));
             }
-            if (option.equals("-h")) {
+            if (option.equals("-h") || option.equals("--hopping-config-mode")) {
                 String hoppingConfigMode = getNextArgRequired();
                 if (hoppingConfigMode.equals("none")) {
                     builder.setHoppingConfigMode(HOPPING_MODE_DISABLE);
@@ -845,7 +845,7 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                             + hoppingConfigMode);
                 }
             }
-            if (option.equals("-a")) {
+            if (option.equals("-a") || option.equals("--hopping-sequence")) {
                 String hoppingSequence = getNextArgRequired();
                 if (hoppingSequence.equals("default")) {
                     builder.setHoppingSequence(HOPPING_SEQUENCE_DEFAULT);
@@ -856,6 +856,10 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                             + hoppingSequence);
                 }
             }
+            if (option.equals("-S") || option.equals("--sts-index")) {
+                Integer sts_index = Integer.parseInt(getNextArgRequired());
+                builder.setStsIndex(sts_index);
+            }
             option = getNextOption();
         }
         // TODO: Add remaining params if needed.
@@ -1487,32 +1491,32 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                 + " [-r initiator|responder](device-role)"
                 + " [-a <deviceAddress>](device-address)"
                 + " [-d <destAddress-1, destAddress-2,...>](dest-addresses)"
-                + " [-m <unicast|one-to-many|many-to-many>](multi-node mode)"
+                + " [-m <unicast|one-to-many|many-to-many>](multi-node-mode)"
                 + " [-u ds-twr|ss-twr|ds-twr-non-deferred|ss-twr-non-deferred](round-usage)"
                 + " [-l <ranging-interval-ms>](ranging-interval-ms)"
                 + " [-s <slots-per-ranging-round>](slots-per-ranging-round)"
                 + " [-x <proximity-near-cm, proximity-far-cm>](range-data-ntf-proximity)"
+                + " [-R enabled|disabled](range-data-notification)"
                 + " [-z <numRangeMrmts, numAoaAzimuthMrmts, numAoaElevationMrmts>"
                 + "(interleaving-ratio)"
-                + " [-e none|enabled|azimuth-only|elevation-only](aoa type)"
+                + " [-e none|enabled|azimuth-only|elevation-only](aoa-result-request)"
                 + " [-f <tof,azimuth,elevation,aoa-fom>(result-report-config)"
-                + " [-g <staticStsIV>(staticStsIV 6-bytes)"
-                + " [-v <staticStsVendorId>(staticStsVendorId 2-bytes)"
+                + " [-g <staticStsIV>(sts-iv: staticStsIV 6-bytes)"
+                + " [-v <staticStsVendorId>(vendor-id: staticStsVendorId 2-bytes)"
+                + " [-h <slot-duration-rstu>(slot-duration-rstu, default=2400)"
                 + " [-w enabled|disabled](has-result-report-phase)"
                 + " [-y enabled|disabled](hopping-mode, default = disabled)"
                 + " [-p <preamble-code-index>](preamble-code-index, default = 10)"
-                + " [-h <slot-duration-rstu>(slot-duration-rstu, default=2400)"
                 + " [-o static|provisioned](sts-config-type)"
-                + " [-n <sessionKey>](sessionKey 16 or 32 bytes)"
-                + " [-k <subSessionKey>](subSessionKey 16 or 32 bytes)"
-                + " [-j <errorStreakTimeoutMs>](error streak timeout in millis, default=30000)"
-                + " [-q <sessionPriority>](sessionPriority 1-49 or 51-100)"
-                + " [-P bprf|hprf](prfMode)"
-                + " [-D 6m81|7m80|27m2|31m2](psduDataRate)"
-                + " [-B 850k|6m81](bprfPhrDataRate)"
-                + " [-A enabled|disabled](TX adaptive power, default = disabled)"
-                + " [-S <sfd_id>](sfd_id 0-4, default = 2)"
-                + " [-R enabled|disabled](range-data-notification)");
+                + " [-n <sessionKey>](session-key 16 or 32 bytes)"
+                + " [-k <subSessionKey>](sub-session-key 16 or 32 bytes)"
+                + " [-j <errorStreakTimeoutMs>](error-streak-timeout-ms in millis, default=30000)"
+                + " [-q <sessionPriority>](session-priority 1-49 or 51-100)"
+                + " [-P bprf|hprf](prf-mode)"
+                + " [-D 6m81|7m80|27m2|31m2](psdu-data-rate)"
+                + " [-B 850k|6m81](bprf-phr-data-rate)"
+                + " [-A enabled|disabled](tx-adaptive-power, default = disabled)"
+                + " [-S <sfd_id>](sfd-id 0-4, default = 2)");
         pw.println("    Starts a FIRA ranging session with the provided params."
                 + " Note: default behavior is to cache the latest ranging reports which can be"
                 + " retrieved using |get-ranging-session-reports|");
@@ -1532,7 +1536,8 @@ public class UwbShellCommand extends BasicShellCommandHandler {
                 + " [-o <num-slots-per-round>](num-slots-per-round)"
                 + " [-s <sync-code-index>](sync-code-index)"
                 + " [-h none|continuous|adaptive](hopping-config-mode)"
-                + " [-a default|aes](hopping-sequence)");
+                + " [-a default|aes](hopping-sequence)"
+                + " [-S <stsIndex>](sts-index)");
         pw.println("    Starts a CCC ranging session with the provided params."
                 + " Note: default behavior is to cache the latest ranging reports which can be"
                 + " retrieved using |get-ranging-session-reports|");
diff --git a/service/java/com/android/server/uwb/config/CapabilityParam.java b/service/java/com/android/server/uwb/config/CapabilityParam.java
index f72e60ff..135f981a 100644
--- a/service/java/com/android/server/uwb/config/CapabilityParam.java
+++ b/service/java/com/android/server/uwb/config/CapabilityParam.java
@@ -239,9 +239,18 @@ public class CapabilityParam {
     public static final int CCC_HOPPING_SEQUENCE_DEFAULT =
             (int) UwbVendorCapabilityTlvValues.HOPPING_SEQUENCE_DEFAULT;
 
+    // Protocol Agnostic
     public static final int SUPPORTED_POWER_STATS_QUERY =
             UwbVendorCapabilityTlvTypes.SUPPORTED_POWER_STATS_QUERY;
 
+    public static final int SUPPORTED_ANTENNA_MODES =
+            UwbVendorCapabilityTlvTypes.SUPPORTED_ANTENNA_MODES;
+
+    public static final int ANTENNA_MODE_OMNI =
+            (int) UwbVendorCapabilityTlvValues.ANTENNA_MODE_OMNI;
+    public static final int ANTENNA_MODE_DIRECTIONAL =
+            (int) UwbVendorCapabilityTlvValues.ANTENNA_MODE_DIRECTIONAL;
+
     public static final int RANGE_DATA_NTF_CONFIG_ENABLE = 1 << 0;
     public static final int RANGE_DATA_NTF_CONFIG_DISABLE = 1 << 1;
     public static final int RANGE_DATA_NTF_CONFIG_ENABLE_PROXIMITY_LEVEL_TRIG = 1 << 2;
diff --git a/service/java/com/android/server/uwb/data/UwbMulticastListUpdateStatus.java b/service/java/com/android/server/uwb/data/UwbMulticastListUpdateStatus.java
index 34c3e9f3..c0308c39 100644
--- a/service/java/com/android/server/uwb/data/UwbMulticastListUpdateStatus.java
+++ b/service/java/com/android/server/uwb/data/UwbMulticastListUpdateStatus.java
@@ -45,7 +45,7 @@ public class UwbMulticastListUpdateStatus {
 
         Log.d(TAG, "Controlee count: " + numOfControlees + " mac addresses: "
                 + Arrays.toString(controleeMacAddresses));
-        if (controleeMacAddresses != null) {
+        if ((controleeMacAddresses != null) && (numOfControlees > 0)) {
             // Precache mac addresses in a more usable and universal form.
             mControleeUwbAddresses = getUwbAddresses(mControleeMacAddresses, mNumOfControlees,
                     mControleeMacAddresses.length / mNumOfControlees);
diff --git a/service/java/com/android/server/uwb/data/UwbUciConstants.java b/service/java/com/android/server/uwb/data/UwbUciConstants.java
index b33bbe21..a48fb913 100644
--- a/service/java/com/android/server/uwb/data/UwbUciConstants.java
+++ b/service/java/com/android/server/uwb/data/UwbUciConstants.java
@@ -32,6 +32,11 @@ public class UwbUciConstants {
     public static final byte DEVICE_STATE_OFF = 0x00; //NOT defined in the UCI spec
     public static final byte DEVICE_STATE_READY = 0x01;
     public static final byte DEVICE_STATE_ACTIVE = 0x02;
+    /**
+     * This is NOT defined in the UCI spec. It exists so that OEMs can trace initialization
+     * failures from IUwbOemExtensionCallback#onDeviceStatusNotificationReceived.
+     */
+    public static final byte DEVICE_STATE_INIT_ERROR = (byte) 0xFE;
     public static final byte DEVICE_STATE_ERROR = (byte) 0xFF;
 
     public static final byte UWBS_RESET = 0x00;
diff --git a/service/java/com/android/server/uwb/params/GenericDecoder.java b/service/java/com/android/server/uwb/params/GenericDecoder.java
index 74db9907..c85ccf84 100644
--- a/service/java/com/android/server/uwb/params/GenericDecoder.java
+++ b/service/java/com/android/server/uwb/params/GenericDecoder.java
@@ -16,6 +16,7 @@
 
 package com.android.server.uwb.params;
 
+import static com.android.server.uwb.config.CapabilityParam.SUPPORTED_ANTENNA_MODES;
 import static com.android.server.uwb.config.CapabilityParam.SUPPORTED_POWER_STATS_QUERY;
 
 import android.util.Log;
@@ -24,12 +25,14 @@ import com.android.server.uwb.UwbInjector;
 
 import com.google.uwb.support.aliro.AliroParams;
 import com.google.uwb.support.aliro.AliroSpecificationParams;
+import com.google.uwb.support.base.FlagEnum;
 import com.google.uwb.support.base.Params;
 import com.google.uwb.support.base.ProtocolVersion;
 import com.google.uwb.support.ccc.CccParams;
 import com.google.uwb.support.ccc.CccSpecificationParams;
 import com.google.uwb.support.fira.FiraParams;
 import com.google.uwb.support.fira.FiraSpecificationParams;
+import com.google.uwb.support.generic.GenericParams;
 import com.google.uwb.support.generic.GenericSpecificationParams;
 import com.google.uwb.support.radar.RadarParams;
 import com.google.uwb.support.radar.RadarSpecificationParams;
@@ -94,6 +97,13 @@ public class GenericDecoder extends TlvDecoder {
         } catch (IllegalArgumentException e) {
             // Do nothing. By default, hasPowerStatsSupport() returns false.
         }
+        try {
+            builder.setAntennaModeCapabilities(
+                    FlagEnum.toEnumSet(tlvs.getByte(SUPPORTED_ANTENNA_MODES),
+                            GenericParams.AntennaModeCapabilityFlag.values()));
+        } catch (IllegalArgumentException e) {
+            // Do nothing. Mask is set to 0 by default in builder.
+        }
         return builder.build();
     }
 }
diff --git a/service/support_lib/src/com/google/uwb/support/fira/FiraOnControleeRemovedParams.java b/service/support_lib/src/com/google/uwb/support/fira/FiraOnControleeAddRemoveParams.java
similarity index 85%
rename from service/support_lib/src/com/google/uwb/support/fira/FiraOnControleeRemovedParams.java
rename to service/support_lib/src/com/google/uwb/support/fira/FiraOnControleeAddRemoveParams.java
index 1f5f5ebb..8f2489ad 100644
--- a/service/support_lib/src/com/google/uwb/support/fira/FiraOnControleeRemovedParams.java
+++ b/service/support_lib/src/com/google/uwb/support/fira/FiraOnControleeAddRemoveParams.java
@@ -28,7 +28,7 @@ import androidx.annotation.NonNull;
 /**
  * UWB parameters for removing a controlee from a FiRa session.
  */
-public class FiraOnControleeRemovedParams {
+public class FiraOnControleeAddRemoveParams {
     @IntDef(
         value = {
             Reason.UNKNOWN,
@@ -48,7 +48,7 @@ public class FiraOnControleeRemovedParams {
     private final @NonNull UwbAddress mAddress;
     private final @Reason int mReason;
 
-    private FiraOnControleeRemovedParams(@NonNull UwbAddress address, @Reason int reason) {
+    private FiraOnControleeAddRemoveParams(@NonNull UwbAddress address, @Reason int reason) {
         mAddress = address;
         mReason = reason;
     }
@@ -69,7 +69,7 @@ public class FiraOnControleeRemovedParams {
      * @return the parameters stored within the bundle.
      */
     @SuppressWarnings("NewApi")
-    public static FiraOnControleeRemovedParams fromBundle(PersistableBundle bundle) {
+    public static FiraOnControleeAddRemoveParams fromBundle(PersistableBundle bundle) {
         int addressMode = bundle.getInt(KEY_MAC_ADDRESS_MODE);
         UwbAddress uwbAddress = longToUwbAddress(
                 bundle.getLong(KEY_ADDRESS),
@@ -104,17 +104,17 @@ public class FiraOnControleeRemovedParams {
         /**
          * @param reason for removal.
          */
-        public FiraOnControleeRemovedParams.Builder setReason(@Reason int reason) {
+        public FiraOnControleeAddRemoveParams.Builder setReason(@Reason int reason) {
             mReason = reason;
             return this;
         }
 
         /**
-         * @return a {@link FiraOnControleeRemovedParams} containing the provided params.
+         * @return a {@link FiraOnControleeAddRemoveParams} containing the provided params.
          * @throws IllegalArgumentException if an address was not provided.
          */
-        public FiraOnControleeRemovedParams build() throws IllegalArgumentException {
-            return new FiraOnControleeRemovedParams(mAddress, mReason);
+        public FiraOnControleeAddRemoveParams build() throws IllegalArgumentException {
+            return new FiraOnControleeAddRemoveParams(mAddress, mReason);
         }
     }
 }
diff --git a/service/support_lib/src/com/google/uwb/support/fira/FiraOpenSessionParams.java b/service/support_lib/src/com/google/uwb/support/fira/FiraOpenSessionParams.java
index 2070aa93..d4ec5f08 100644
--- a/service/support_lib/src/com/google/uwb/support/fira/FiraOpenSessionParams.java
+++ b/service/support_lib/src/com/google/uwb/support/fira/FiraOpenSessionParams.java
@@ -862,8 +862,8 @@ public class FiraOpenSessionParams extends FiraParams {
         // Always store address as long in bundle.
         bundle.putLong(KEY_DEVICE_ADDRESS, uwbAddressToLong(mDeviceAddress));
 
-        if (mDeviceRole != RANGING_DEVICE_DT_TAG &&
-            mScheduledMode != CONTENTION_BASED_RANGING) {
+        if (mScheduledMode != CONTENTION_BASED_RANGING
+                && mDestAddressList != null) {
             // Dest Address list needs to be converted to long array.
             long[] destAddressList = new long[mDestAddressList.size()];
             int i = 0;
@@ -871,7 +871,10 @@ public class FiraOpenSessionParams extends FiraParams {
                 destAddressList[i++] = uwbAddressToLong(destAddress);
             }
             bundle.putLongArray(KEY_DEST_ADDRESS_LIST, destAddressList);
-        } else {
+        }
+
+        if (mRangingRoundUsage == RANGING_ROUND_USAGE_DL_TDOA
+                && mDeviceRole == RANGING_DEVICE_DT_TAG) {
             bundle.putInt(KEY_DLTDOA_BLOCK_STRIDING, mDlTdoaBlockStriding);
         }
 
diff --git a/service/support_lib/src/com/google/uwb/support/fira/FiraParams.java b/service/support_lib/src/com/google/uwb/support/fira/FiraParams.java
index 955ee22e..4558943b 100644
--- a/service/support_lib/src/com/google/uwb/support/fira/FiraParams.java
+++ b/service/support_lib/src/com/google/uwb/support/fira/FiraParams.java
@@ -1166,14 +1166,14 @@ public abstract class FiraParams extends Params {
     /** The patch antenna is used for both Tx and Rx. **/
     public static final int ANTENNA_MODE_DIRECTIONAL = 1;
 
-    // Helper functions
-    protected static UwbAddress longToUwbAddress(long value, int length) {
+    /** Helper function to covert long value to UwbAddress. */
+    public static UwbAddress longToUwbAddress(long value, int length) {
         ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
         buffer.putLong(value);
         return UwbAddress.fromBytes(Arrays.copyOf(buffer.array(), length));
     }
 
-    /** Helper functions to convert UwbAdrress in long value. */
+    /** Helper functions to convert UwbAddress in long value. */
     public static long uwbAddressToLong(UwbAddress address) {
         ByteBuffer buffer = ByteBuffer.wrap(Arrays.copyOf(address.toBytes(), Long.BYTES));
         return buffer.getLong();
diff --git a/service/support_lib/src/com/google/uwb/support/generic/GenericParams.java b/service/support_lib/src/com/google/uwb/support/generic/GenericParams.java
index 1a6e3ea2..d212b168 100644
--- a/service/support_lib/src/com/google/uwb/support/generic/GenericParams.java
+++ b/service/support_lib/src/com/google/uwb/support/generic/GenericParams.java
@@ -21,6 +21,7 @@ import android.os.PersistableBundle;
 
 import androidx.annotation.RequiresApi;
 
+import com.google.uwb.support.base.FlagEnum;
 import com.google.uwb.support.base.Params;
 
 @RequiresApi(VERSION_CODES.LOLLIPOP)
@@ -35,4 +36,20 @@ public abstract class GenericParams extends Params {
     public static boolean isCorrectProtocol(PersistableBundle bundle) {
         return isProtocol(bundle, PROTOCOL_NAME);
     }
+
+    public enum AntennaModeCapabilityFlag implements FlagEnum {
+        HAS_OMNI_MODE_SUPPORT(1),
+        HAS_DIRECTIONAL_MODE_SUPPORT(1 << 1);
+
+        private final long mValue;
+
+        AntennaModeCapabilityFlag(long value) {
+            mValue = value;
+        }
+
+        @Override
+        public long getValue() {
+            return mValue;
+        }
+    }
 }
diff --git a/service/support_lib/src/com/google/uwb/support/generic/GenericSpecificationParams.java b/service/support_lib/src/com/google/uwb/support/generic/GenericSpecificationParams.java
index feaaea40..7da3dac2 100644
--- a/service/support_lib/src/com/google/uwb/support/generic/GenericSpecificationParams.java
+++ b/service/support_lib/src/com/google/uwb/support/generic/GenericSpecificationParams.java
@@ -24,6 +24,7 @@ import androidx.annotation.Nullable;
 
 import com.google.uwb.support.aliro.AliroParams;
 import com.google.uwb.support.aliro.AliroSpecificationParams;
+import com.google.uwb.support.base.FlagEnum;
 import com.google.uwb.support.ccc.CccParams;
 import com.google.uwb.support.ccc.CccSpecificationParams;
 import com.google.uwb.support.fira.FiraParams;
@@ -31,6 +32,8 @@ import com.google.uwb.support.fira.FiraSpecificationParams;
 import com.google.uwb.support.radar.RadarParams;
 import com.google.uwb.support.radar.RadarSpecificationParams;
 
+import java.util.Collection;
+import java.util.EnumSet;
 import java.util.Objects;
 
 /**
@@ -47,24 +50,22 @@ public class GenericSpecificationParams extends GenericParams {
     private final AliroSpecificationParams mAliroSpecificationParams;
     private final RadarSpecificationParams mRadarSpecificationParams;
     private final boolean mHasPowerStatsSupport;
+    private final EnumSet<AntennaModeCapabilityFlag> mAntennaModeCapabilities;
 
     private static final String KEY_FIRA_SPECIFICATION_PARAMS = FiraParams.PROTOCOL_NAME;
     private static final String KEY_ALIRO_SPECIFICATION_PARAMS = AliroParams.PROTOCOL_NAME;
     private static final String KEY_CCC_SPECIFICATION_PARAMS = CccParams.PROTOCOL_NAME;
     private static final String KEY_RADAR_SPECIFICATION_PARAMS = RadarParams.PROTOCOL_NAME;
     private static final String KEY_POWER_STATS_QUERY_SUPPORT = "power_stats_query";
-
-    private GenericSpecificationParams(
-            FiraSpecificationParams firaSpecificationParams,
-            CccSpecificationParams cccSpecificationParams,
-            AliroSpecificationParams aliroSpecificationParams,
-            RadarSpecificationParams radarSpecificationParams,
-            boolean hasPowerStatsSupport) {
-        mFiraSpecificationParams = firaSpecificationParams;
-        mCccSpecificationParams = cccSpecificationParams;
-        mAliroSpecificationParams = aliroSpecificationParams;
-        mRadarSpecificationParams = radarSpecificationParams;
-        mHasPowerStatsSupport = hasPowerStatsSupport;
+    private static final String KEY_SUPPORTED_ANTENNA_MODES = "supported_antenna_modes";
+
+    private GenericSpecificationParams(Builder builder) {
+        mFiraSpecificationParams = builder.mFiraSpecificationParams;
+        mCccSpecificationParams = builder.mCccSpecificationParams;
+        mAliroSpecificationParams = builder.mAliroSpecificationParams;
+        mRadarSpecificationParams = builder.mRadarSpecificationParams;
+        mHasPowerStatsSupport = builder.mHasPowerStatsSupport;
+        mAntennaModeCapabilities = builder.mAntennaModeCapabilities;
     }
 
     @Override
@@ -99,6 +100,11 @@ public class GenericSpecificationParams extends GenericParams {
         return mHasPowerStatsSupport;
     }
 
+    /** @return antenna mode capabilities. */
+    public EnumSet<AntennaModeCapabilityFlag> getAntennaModeCapabilities() {
+        return mAntennaModeCapabilities;
+    }
+
     public void setFiraSpecificationParams(FiraSpecificationParams params) {
         mFiraSpecificationParams = params;
     }
@@ -121,6 +127,7 @@ public class GenericSpecificationParams extends GenericParams {
                     mRadarSpecificationParams.toBundle());
         }
         bundle.putBoolean(KEY_POWER_STATS_QUERY_SUPPORT, mHasPowerStatsSupport);
+        bundle.putInt(KEY_SUPPORTED_ANTENNA_MODES, FlagEnum.toInt(mAntennaModeCapabilities));
         return bundle;
     }
 
@@ -135,11 +142,16 @@ public class GenericSpecificationParams extends GenericParams {
     }
 
     private static GenericSpecificationParams parseVersion1(PersistableBundle bundle) {
-        GenericSpecificationParams.Builder builder = new GenericSpecificationParams.Builder();
+        GenericSpecificationParams.Builder builder = new GenericSpecificationParams.Builder()
+                .setAntennaModeCapabilities(FlagEnum.toEnumSet(
+                        bundle.getInt(KEY_SUPPORTED_ANTENNA_MODES, 0),
+                        AntennaModeCapabilityFlag.values()))
+                .hasPowerStatsSupport(bundle.getBoolean(KEY_POWER_STATS_QUERY_SUPPORT));
+
         builder = builder.setFiraSpecificationParams(
                 FiraSpecificationParams.fromBundle(
-                        bundle.getPersistableBundle(KEY_FIRA_SPECIFICATION_PARAMS)))
-                .hasPowerStatsSupport(bundle.getBoolean(KEY_POWER_STATS_QUERY_SUPPORT));
+                        bundle.getPersistableBundle(KEY_FIRA_SPECIFICATION_PARAMS)));
+
         PersistableBundle cccBundle = bundle.getPersistableBundle(KEY_CCC_SPECIFICATION_PARAMS);
         if (cccBundle != null) {
             builder = builder.setCccSpecificationParams(
@@ -167,7 +179,10 @@ public class GenericSpecificationParams extends GenericParams {
         private CccSpecificationParams mCccSpecificationParams = null;
         private AliroSpecificationParams mAliroSpecificationParams = null;
         private RadarSpecificationParams mRadarSpecificationParams = null;
+
         private boolean mHasPowerStatsSupport = false;
+        private EnumSet<AntennaModeCapabilityFlag> mAntennaModeCapabilities =
+                EnumSet.noneOf(AntennaModeCapabilityFlag.class);
 
         /**
          * Set FIRA specification params
@@ -213,16 +228,20 @@ public class GenericSpecificationParams extends GenericParams {
             return this;
         }
 
+        /**
+         * Set antenna mode capabilities.
+         */
+        public Builder setAntennaModeCapabilities(
+                Collection<AntennaModeCapabilityFlag> antennaModeCapabilities) {
+            mAntennaModeCapabilities.addAll(antennaModeCapabilities);
+            return this;
+        }
+
         /**
          * Build {@link GenericSpecificationParams}
          */
         public GenericSpecificationParams build() {
-            return new GenericSpecificationParams(
-                    mFiraSpecificationParams,
-                    mCccSpecificationParams,
-                    mAliroSpecificationParams,
-                    mRadarSpecificationParams,
-                    mHasPowerStatsSupport);
+            return new GenericSpecificationParams(this);
         }
     }
 }
diff --git a/service/tests/Android.bp b/service/tests/Android.bp
index 34092f42..ac247075 100644
--- a/service/tests/Android.bp
+++ b/service/tests/Android.bp
@@ -46,6 +46,7 @@ android_test {
         // Then, the jarjar_rules here will perform the rename for the entire APK
         // i.e. service-uwb + test code
         "service-uwb-pre-jarjar",
+        "com.uwb.fusion",
         "flag-junit",
         "platform-test-annotations",
     ],
@@ -53,9 +54,9 @@ android_test {
     jarjar_rules: ":uwb-jarjar-rules",
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "framework-annotations-lib",
         "framework-uwb-pre-jarjar",
         "ServiceUwbResources",
diff --git a/service/tests/src/com/android/server/uwb/DeviceConfigFacadeTest.java b/service/tests/src/com/android/server/uwb/DeviceConfigFacadeTest.java
index 2ec9b130..9d7a4e83 100644
--- a/service/tests/src/com/android/server/uwb/DeviceConfigFacadeTest.java
+++ b/service/tests/src/com/android/server/uwb/DeviceConfigFacadeTest.java
@@ -157,6 +157,8 @@ public class DeviceConfigFacadeTest {
                 .thenReturn(false);
         when(mResources.getBoolean(R.bool.hw_idle_turn_off_enabled))
                 .thenReturn(false);
+        when(mResources.getBoolean(R.bool.fused_country_code_provider_enabled))
+                .thenReturn(false);
         when(mResources.getBoolean(R.bool.is_antenna_mode_config_supported))
                 .thenReturn(false);
 
@@ -184,8 +186,8 @@ public class DeviceConfigFacadeTest {
     public void testDefaultValue() throws Exception {
         assertEquals(DeviceConfigFacade.DEFAULT_RANGING_RESULT_LOG_INTERVAL_MS,
                 mDeviceConfigFacade.getRangingResultLogIntervalMs());
-        assertEquals(false, mDeviceConfigFacade.isDeviceErrorBugreportEnabled());
-        assertEquals(false, mDeviceConfigFacade.isSessionInitErrorBugreportEnabled());
+        assertEquals(true, mDeviceConfigFacade.isDeviceErrorBugreportEnabled());
+        assertEquals(true, mDeviceConfigFacade.isSessionInitErrorBugreportEnabled());
         assertEquals(DeviceConfigFacade.DEFAULT_BUG_REPORT_MIN_INTERVAL_MS,
                 mDeviceConfigFacade.getBugReportMinIntervalMs());
 
@@ -239,6 +241,7 @@ public class DeviceConfigFacadeTest {
         assertEquals(false, mDeviceConfigFacade.isUwbDisabledUntilFirstToggle());
         assertEquals(false, mDeviceConfigFacade.isPersistentCacheUseForCountryCodeEnabled());
         assertEquals(false, mDeviceConfigFacade.isHwIdleTurnOffEnabled());
+        assertEquals(false, mDeviceConfigFacade.isFusedCountryCodeProviderEnabled());
         assertEquals(false, mDeviceConfigFacade.isAntennaModeConfigSupported());
     }
 
@@ -354,6 +357,8 @@ public class DeviceConfigFacadeTest {
                 anyBoolean())).thenReturn(true);
         when(DeviceConfig.getBoolean(anyString(), eq("hw_idle_turn_off_enabled"),
                 anyBoolean())).thenReturn(true);
+        when(DeviceConfig.getBoolean(anyString(), eq("fused_country_code_provider_enabled"),
+                anyBoolean())).thenReturn(true);
         when(DeviceConfig.getBoolean(anyString(), eq("is_antenna_mode_config_supported"),
                 anyBoolean())).thenReturn(true);
 
@@ -377,6 +382,7 @@ public class DeviceConfigFacadeTest {
         assertEquals(true, mDeviceConfigFacade.isUwbDisabledUntilFirstToggle());
         assertEquals(true, mDeviceConfigFacade.isPersistentCacheUseForCountryCodeEnabled());
         assertEquals(true, mDeviceConfigFacade.isHwIdleTurnOffEnabled());
+        assertEquals(true, mDeviceConfigFacade.isFusedCountryCodeProviderEnabled());
         assertEquals(true, mDeviceConfigFacade.isAntennaModeConfigSupported());
         when(DeviceConfig.getString(anyString(), eq("pose_source_type"),
                 anyString())).thenReturn("NONE");
diff --git a/service/tests/src/com/android/server/uwb/UwbControleeTest.java b/service/tests/src/com/android/server/uwb/UwbControleeTest.java
index 388d6aa0..2579fee2 100644
--- a/service/tests/src/com/android/server/uwb/UwbControleeTest.java
+++ b/service/tests/src/com/android/server/uwb/UwbControleeTest.java
@@ -29,8 +29,7 @@ import android.uwb.DistanceMeasurement;
 import android.uwb.RangingMeasurement;
 import android.uwb.UwbAddress;
 
-import com.android.server.uwb.correction.TestHelpers;
-import com.android.server.uwb.correction.UwbFilterEngine;
+import com.android.uwb.fusion.UwbFilterEngine;
 
 import org.junit.After;
 import org.junit.Before;
@@ -88,8 +87,8 @@ public class UwbControleeTest {
         mControlee.filterMeasurement(rm);
 
         RangingMeasurement newMeasure = rm.build();
-        TestHelpers.assertClose(newMeasure.getAngleOfArrivalMeasurement().getAzimuth()
-                .getRadians(), testRads);
+        assertThat(newMeasure.getAngleOfArrivalMeasurement().getAzimuth().getRadians())
+                .isWithin(0.001).of(testRads);
     }
 
     @Test
diff --git a/service/tests/src/com/android/server/uwb/UwbCountryCodeTest.java b/service/tests/src/com/android/server/uwb/UwbCountryCodeTest.java
index 0bce3da1..b3977425 100644
--- a/service/tests/src/com/android/server/uwb/UwbCountryCodeTest.java
+++ b/service/tests/src/com/android/server/uwb/UwbCountryCodeTest.java
@@ -29,15 +29,19 @@ import static org.mockito.Mockito.anyLong;
 import static org.mockito.Mockito.anyString;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doThrow;
+import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
 
+import android.app.AlarmManager;
+import android.app.PendingIntent;
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
+import android.content.IntentFilter;
 import android.content.pm.PackageManager;
 import android.location.Address;
 import android.location.Geocoder;
@@ -47,7 +51,10 @@ import android.location.LocationManager;
 import android.net.wifi.WifiManager;
 import android.net.wifi.WifiManager.ActiveCountryCodeChangedCallback;
 import android.os.Handler;
+import android.os.Looper;
+import android.os.UserHandle;
 import android.os.test.TestLooper;
+import android.provider.Settings;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
@@ -95,6 +102,13 @@ public class UwbCountryCodeTest {
     @Mock DeviceConfigFacade mDeviceConfigFacade;
     @Mock FeatureFlags mFeatureFlags;
     @Mock UwbSettingsStore mUwbSettingsStore;
+    @Mock AlarmManager mGeocodeRetryTimer;
+    @Mock IntentFilter mGeocoderRetryIntentFilter;
+    @Mock PendingIntent mGeocodeRetryPendingIntent;
+    @Mock LocationListener mFusedLocationListener;
+    @Mock Intent mLocalIntent;
+    @Mock UserHandle mUserHandle;
+    @Mock Looper mLooper;
 
     private TestLooper mTestLooper;
     private UwbCountryCode mUwbCountryCode;
@@ -106,6 +120,8 @@ public class UwbCountryCodeTest {
     @Captor
     private ArgumentCaptor<LocationListener> mLocationListenerCaptor;
     @Captor
+    private ArgumentCaptor<LocationListener> mFusedLocationListenerCaptor;
+    @Captor
     private ArgumentCaptor<Geocoder.GeocodeListener> mGeocodeListenerCaptor;
 
     /**
@@ -148,9 +164,14 @@ public class UwbCountryCodeTest {
         when(mDeviceConfigFacade.isLocationUseForCountryCodeEnabled()).thenReturn(true);
         when(mUwbInjector.getDeviceConfigFacade()).thenReturn(mDeviceConfigFacade);
         when(mUwbInjector.getUwbSettingsStore()).thenReturn(mUwbSettingsStore);
+        when(mUwbInjector.getUwbServiceLooper()).thenReturn(mLooper);
         when(mPackageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)).thenReturn(true);
         when(mNativeUwbManager.setCountryCode(any())).thenReturn(
                 (byte) STATUS_CODE_OK);
+
+        when(mLocalIntent.getAction()).thenReturn(UwbCountryCode.GEOCODER_RETRY_TIMEOUT_INTENT);
+        when(mContext.getSystemService(AlarmManager.class)).thenReturn(mGeocodeRetryTimer);
+
         mUwbCountryCode = new UwbCountryCode(
                 mContext, mNativeUwbManager, new Handler(mTestLooper.getLooper()), mUwbInjector);
 
@@ -553,8 +574,45 @@ public class UwbCountryCodeTest {
                 .thenReturn(TEST_COUNTRY_CODE);
         mUwbCountryCode.initialize();
         verify(mUwbSettingsStore).get(UwbSettingsStore.SETTINGS_CACHED_COUNTRY_CODE);
-        verify(mNativeUwbManager).setCountryCode(
-                TEST_COUNTRY_CODE.getBytes(StandardCharsets.UTF_8));
+        verify(mNativeUwbManager)
+                .setCountryCode(TEST_COUNTRY_CODE.getBytes(StandardCharsets.UTF_8));
         verify(mListener).onCountryCodeChanged(STATUS_CODE_OK, TEST_COUNTRY_CODE);
     }
+
+    @Test
+    public void testAirplaneModeDisableTriggeredFusedProviderResolving() {
+        when(mLocation.getLongitude()).thenReturn(0.0);
+        when(mDeviceConfigFacade.isFusedCountryCodeProviderEnabled()).thenReturn(true);
+        when(mUwbInjector.getGlobalSettingsInt(Settings.Global.AIRPLANE_MODE_ON, 0))
+                .thenReturn(0);
+        mUwbCountryCode.initialize();
+
+        // Now clear the cache and ensure we reset the country code.
+        mUwbCountryCode.clearCachedCountryCode();
+
+        verify(mLocationManager).requestLocationUpdates(eq(LocationManager.FUSED_PROVIDER),
+                anyLong(), anyFloat(), mFusedLocationListenerCaptor.capture(),
+                        eq(mLooper));
+
+        //TODO: b/350063314: Update with behaviour upon receiving Location Update
+    }
+
+    @Test
+    public void testAirplaneModeEnableTriggeredFusedProviderStop() {
+        when(mDeviceConfigFacade.isFusedCountryCodeProviderEnabled()).thenReturn(true);
+        when(mUwbInjector.getGlobalSettingsInt(Settings.Global.AIRPLANE_MODE_ON, 0))
+                .thenReturn(0);
+
+        mUwbCountryCode.initialize();
+        mUwbCountryCode.clearCachedCountryCode();
+
+        // Simulate user disabled APM
+        when(mUwbInjector.getGlobalSettingsInt(Settings.Global.AIRPLANE_MODE_ON, 0))
+                .thenReturn(1);
+
+        // Now clear the cache and ensure we reset the country code.
+        mUwbCountryCode.clearCachedCountryCode();
+
+        verify(mLocationManager).removeUpdates(mLocationListenerCaptor.capture());
+    }
 }
diff --git a/service/tests/src/com/android/server/uwb/UwbSessionManagerTest.java b/service/tests/src/com/android/server/uwb/UwbSessionManagerTest.java
index 957d828f..10868418 100644
--- a/service/tests/src/com/android/server/uwb/UwbSessionManagerTest.java
+++ b/service/tests/src/com/android/server/uwb/UwbSessionManagerTest.java
@@ -919,14 +919,22 @@ public class UwbSessionManagerTest {
         when(mockUwbSession.getOperationType())
                 .thenReturn(UwbSessionManager.SESSION_RECONFIG_RANGING);
         doReturn(mockUwbSession)
-                .when(mUwbSessionManager).getUwbSession(anyInt());
+                        .when(mUwbSessionManager).getUwbSession(anyInt());
+        when(mockUwbMulticastListUpdateStatus.getNumOfControlee())
+                .thenReturn(2);
+        when(mockUwbMulticastListUpdateStatus.getStatus())
+                        .thenReturn(new int[] {
+                                UwbUciConstants.STATUS_CODE_OK, UwbUciConstants.STATUS_CODE_OK });
 
         mUwbSessionManager.onMulticastListUpdateNotificationReceived(
                 mockUwbMulticastListUpdateStatus);
 
         verify(mockUwbSession, times(2)).getWaitObj();
         verify(mockUwbSession)
-                .setMulticastListUpdateStatus(eq(mockUwbMulticastListUpdateStatus));
+                        .setMulticastListUpdateStatus(eq(mockUwbMulticastListUpdateStatus));
+        verify(mUwbSessionNotificationManager, never())
+                .onControleeAddFailed(any(), any(), anyInt());
+        verify(mUwbSessionNotificationManager, never()).onRangingReconfigureFailed(any(), anyInt());
     }
 
     @Test
@@ -4188,7 +4196,8 @@ public class UwbSessionManagerTest {
                 uwbSession.getSessionId(), reconfigureParams.getAction(), 1,
                 dstAddress, reconfigureParams.getSubSessionIdList(), null,
                 uwbSession.getChipId());
-        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession));
+        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession),
+                        eq(UWB_DEST_ADDRESS_2));
         verify(mUwbSessionNotificationManager).onRangingReconfigured(eq(uwbSession));
     }
 
@@ -4308,7 +4317,8 @@ public class UwbSessionManagerTest {
                 uwbSession.getSessionId(), reconfigureParams.getAction(), 1,
                 dstAddress, reconfigureParams.getSubSessionIdList(),
                 reconfigureParams.getSubSessionKeyList(), uwbSession.getChipId());
-        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession));
+        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession),
+                        eq(UWB_DEST_ADDRESS_2));
         verify(mUwbSessionNotificationManager).onRangingReconfigured(eq(uwbSession));
     }
 
@@ -4358,7 +4368,8 @@ public class UwbSessionManagerTest {
                 uwbSession.getSessionId(), reconfigureParams.getAction(), 1,
                 dstAddress, reconfigureParams.getSubSessionIdList(),
                 reconfigureParams.getSubSessionKeyList(), uwbSession.getChipId());
-        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession));
+        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession),
+                        eq(UWB_DEST_ADDRESS_2));
         verify(mUwbSessionNotificationManager).onRangingReconfigured(eq(uwbSession));
     }
 
@@ -4430,7 +4441,7 @@ public class UwbSessionManagerTest {
         mTestLooper.dispatchNext();
 
         verify(mUwbSessionNotificationManager).onControleeAddFailed(eq(uwbSession),
-                eq(UwbUciConstants.STATUS_CODE_FAILED));
+                        eq(UWB_DEST_ADDRESS_2), eq(UwbUciConstants.STATUS_CODE_FAILED));
         verify(mUwbSessionNotificationManager).onRangingReconfigureFailed(
                 eq(uwbSession), eq(UwbUciConstants.STATUS_CODE_FAILED));
     }
@@ -4466,9 +4477,10 @@ public class UwbSessionManagerTest {
 
         // Fail callback for the first one.
         verify(mUwbSessionNotificationManager).onControleeAddFailed(eq(uwbSession),
-                eq(UwbUciConstants.STATUS_CODE_FAILED));
+                eq(UWB_DEST_ADDRESS_2), eq(UwbUciConstants.STATUS_CODE_FAILED));
         // Success callback for the second.
-        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession));
+        verify(mUwbSessionNotificationManager).onControleeAdded(eq(uwbSession),
+                        eq(UWB_DEST_ADDRESS_3));
 
         // Make sure the failed address was not added.
         assertThat(uwbSession.getControleeList().stream()
@@ -4500,6 +4512,8 @@ public class UwbSessionManagerTest {
         UwbMulticastListUpdateStatus uwbMulticastListUpdateStatus =
                 mock(UwbMulticastListUpdateStatus.class);
         when(uwbMulticastListUpdateStatus.getNumOfControlee()).thenReturn(1);
+        when(uwbMulticastListUpdateStatus.getControleeUwbAddresses()).thenReturn(
+                new UwbAddress[] { UWB_DEST_ADDRESS_2 });
         when(uwbMulticastListUpdateStatus.getStatus()).thenReturn(
                 new int[] { UwbUciConstants.STATUS_CODE_FAILED });
         doReturn(uwbMulticastListUpdateStatus).when(uwbSession).getMulticastListUpdateStatus();
@@ -4508,7 +4522,7 @@ public class UwbSessionManagerTest {
         mTestLooper.dispatchNext();
 
         verify(mUwbSessionNotificationManager).onControleeAddFailed(eq(uwbSession),
-                eq(UwbUciConstants.STATUS_CODE_FAILED));
+                eq(UWB_DEST_ADDRESS_2), eq(UwbUciConstants.STATUS_CODE_FAILED));
         verify(mUwbSessionNotificationManager).onRangingReconfigureFailed(
                 eq(uwbSession), eq(UwbUciConstants.STATUS_CODE_FAILED));
     }
@@ -4877,7 +4891,7 @@ public class UwbSessionManagerTest {
                         UWB_DEST_ADDRESS))
                 .setProtocolVersion(new FiraProtocolVersion(1, 0))
                 .setSessionId(10)
-                .setSessionType(FiraParams.SESSION_TYPE_IN_BAND_DATA_PHASE)
+                .setSessionType(FiraParams.SESSION_TYPE_RANGING)
                 .setDeviceType(FiraParams.RANGING_DEVICE_TYPE_CONTROLLER)
                 .setDeviceRole(FiraParams.RANGING_DEVICE_ROLE_INITIATOR)
                 .setMultiNodeMode(FiraParams.MULTI_NODE_MODE_UNICAST)
@@ -4886,7 +4900,7 @@ public class UwbSessionManagerTest {
                 .setDataRepetitionCount(0)
                 .build();
         UwbSession uwbSession = prepareExistingUwbSessionWithSessionType(
-                (byte) FiraParams.SESSION_TYPE_IN_BAND_DATA_PHASE, params);
+                (byte) FiraParams.SESSION_TYPE_RANGING, params);
 
         byte messageControl = 0;
         int noOfPhases = 2;
@@ -4937,7 +4951,7 @@ public class UwbSessionManagerTest {
                         UWB_DEST_ADDRESS))
                 .setProtocolVersion(new FiraProtocolVersion(1, 0))
                 .setSessionId(10)
-                .setSessionType(FiraParams.SESSION_TYPE_RANGING_ONLY_PHASE)
+                .setSessionType(FiraParams.SESSION_TYPE_RANGING)
                 .setDeviceType(FiraParams.RANGING_DEVICE_TYPE_CONTROLLER)
                 .setDeviceRole(FiraParams.RANGING_DEVICE_ROLE_INITIATOR)
                 .setMultiNodeMode(FiraParams.MULTI_NODE_MODE_UNICAST)
@@ -4946,7 +4960,7 @@ public class UwbSessionManagerTest {
                 .setDataRepetitionCount(0)
                 .build();
         UwbSession uwbSession = prepareExistingUwbSessionWithSessionType(
-                (byte) FiraParams.SESSION_TYPE_RANGING_ONLY_PHASE, params);
+                (byte) FiraParams.SESSION_TYPE_RANGING, params);
 
         byte[] updateTime = new byte[8];
         int noOfPhases = 2;
@@ -5017,7 +5031,7 @@ public class UwbSessionManagerTest {
                         UWB_DEST_ADDRESS))
                 .setProtocolVersion(new FiraProtocolVersion(1, 0))
                 .setSessionId(10)
-                .setSessionType(FiraParams.SESSION_TYPE_RANGING)
+                .setSessionType(FiraParams.SESSION_TYPE_RANGING_ONLY_PHASE)
                 .setDeviceType(FiraParams.RANGING_DEVICE_TYPE_CONTROLLER)
                 .setDeviceRole(FiraParams.RANGING_DEVICE_ROLE_INITIATOR)
                 .setMultiNodeMode(FiraParams.MULTI_NODE_MODE_UNICAST)
@@ -5026,7 +5040,7 @@ public class UwbSessionManagerTest {
                 .setDataRepetitionCount(0)
                 .build();
         UwbSession uwbSession = prepareExistingUwbSessionWithSessionType(
-                (byte) FiraParams.SESSION_TYPE_RANGING, params);
+                (byte) FiraParams.SESSION_TYPE_RANGING_ONLY_PHASE, params);
 
 
         // Expected to fail due to invalid session type
@@ -5131,7 +5145,7 @@ public class UwbSessionManagerTest {
                         UWB_DEST_ADDRESS))
                 .setProtocolVersion(new FiraProtocolVersion(1, 0))
                 .setSessionId(10)
-                .setSessionType(FiraParams.SESSION_TYPE_RANGING_WITH_DATA_PHASE)
+                .setSessionType(FiraParams.SESSION_TYPE_RANGING)
                 .setDeviceType(FiraParams.RANGING_DEVICE_TYPE_CONTROLEE)
                 .setDeviceRole(FiraParams.RANGING_DEVICE_ROLE_INITIATOR)
                 .setMultiNodeMode(FiraParams.MULTI_NODE_MODE_UNICAST)
@@ -5140,7 +5154,7 @@ public class UwbSessionManagerTest {
                 .setDataRepetitionCount(0)
                 .build();
         UwbSession uwbSession = prepareExistingUwbSessionWithSessionType(
-                (byte) FiraParams.SESSION_TYPE_RANGING_WITH_DATA_PHASE, params);
+                (byte) FiraParams.SESSION_TYPE_RANGING, params);
 
         int noOfPhases = 2;
         byte phaseParticipation = 0;
diff --git a/service/tests/src/com/android/server/uwb/UwbSessionNotificationManagerTest.java b/service/tests/src/com/android/server/uwb/UwbSessionNotificationManagerTest.java
index 5e7fe145..7f99669d 100644
--- a/service/tests/src/com/android/server/uwb/UwbSessionNotificationManagerTest.java
+++ b/service/tests/src/com/android/server/uwb/UwbSessionNotificationManagerTest.java
@@ -64,7 +64,7 @@ import com.android.server.uwb.data.UwbRangingData;
 import com.android.server.uwb.data.UwbUciConstants;
 import com.android.uwb.flags.Flags;
 
-import com.google.uwb.support.fira.FiraOnControleeRemovedParams;
+import com.google.uwb.support.fira.FiraOnControleeAddRemoveParams;
 import com.google.uwb.support.fira.FiraOpenSessionParams;
 import com.google.uwb.support.fira.FiraParams;
 import com.google.uwb.support.radar.RadarData;
@@ -571,7 +571,8 @@ public class UwbSessionNotificationManagerTest {
 
     @Test
     public void testOnControleeAdded() throws Exception {
-        mUwbSessionNotificationManager.onControleeAdded(mUwbSession);
+        mUwbSessionNotificationManager.onControleeAdded(mUwbSession,
+                        UwbTestUtils.PEER_SHORT_UWB_ADDRESS);
 
         verify(mIUwbRangingCallbacks).onControleeAdded(eq(mSessionHandle), any());
     }
@@ -579,17 +580,28 @@ public class UwbSessionNotificationManagerTest {
     @Test
     public void testOnControleeAddFailed() throws Exception {
         int status =  UwbUciConstants.STATUS_CODE_INVALID_MESSAGE_SIZE;
-        mUwbSessionNotificationManager.onControleeAddFailed(mUwbSession, status);
+        mUwbSessionNotificationManager.onControleeAddFailed(mUwbSession,
+                UwbTestUtils.PEER_SHORT_UWB_ADDRESS, status);
 
         verify(mIUwbRangingCallbacks).onControleeAddFailed(eq(mSessionHandle),
                 eq(UwbSessionNotificationHelper.convertUciStatusToApiReasonCode(status)),
-                argThat(p -> (p.getInt("status_code")) == status));
+                argThat(bundle -> {
+                        int addressMode = bundle.getInt("mac_address_mode");
+                        UwbAddress address = FiraParams.longToUwbAddress(
+                                bundle.getLong("address"),
+                                addressMode == FiraParams.MAC_ADDRESS_MODE_2_BYTES
+                                        ? UwbAddress.SHORT_ADDRESS_BYTE_LENGTH
+                                        : UwbAddress.EXTENDED_ADDRESS_BYTE_LENGTH);
+                        int reason = bundle.getInt("reason");
+                        return address.equals(UwbTestUtils.PEER_SHORT_UWB_ADDRESS)
+                                && FiraOnControleeAddRemoveParams.Reason.REQUESTED_BY_API == reason;
+                }));
     }
 
     @Test
     public void testOnControleeRemoved() throws Exception {
         UwbAddress address = UwbTestUtils.PEER_EXTENDED_UWB_ADDRESS;
-        int reason = FiraOnControleeRemovedParams.Reason.LOST_CONNECTION;
+        int reason = FiraOnControleeAddRemoveParams.Reason.LOST_CONNECTION;
 
         ArgumentCaptor<PersistableBundle> bundleCaptor =
                 ArgumentCaptor.forClass(PersistableBundle.class);
@@ -598,8 +610,8 @@ public class UwbSessionNotificationManagerTest {
         verify(mIUwbRangingCallbacks).onControleeRemoved(eq(mSessionHandle),
                 bundleCaptor.capture());
 
-        FiraOnControleeRemovedParams params =
-                FiraOnControleeRemovedParams.fromBundle(bundleCaptor.getValue());
+        FiraOnControleeAddRemoveParams params =
+                FiraOnControleeAddRemoveParams.fromBundle(bundleCaptor.getValue());
         assertThat(params.getAddress()).isEqualTo(address);
         assertThat(params.getReason()).isEqualTo(reason);
     }
@@ -607,11 +619,23 @@ public class UwbSessionNotificationManagerTest {
     @Test
     public void testOnControleeRemoveFailed() throws Exception {
         int status =  UwbUciConstants.STATUS_CODE_INVALID_MESSAGE_SIZE;
-        mUwbSessionNotificationManager.onControleeRemoveFailed(mUwbSession, status);
+        mUwbSessionNotificationManager.onControleeRemoveFailed(mUwbSession,
+                UwbTestUtils.PEER_SHORT_UWB_ADDRESS, status,
+                FiraOnControleeAddRemoveParams.Reason.LOST_CONNECTION);
 
         verify(mIUwbRangingCallbacks).onControleeRemoveFailed(eq(mSessionHandle),
                 eq(UwbSessionNotificationHelper.convertUciStatusToApiReasonCode(status)),
-                argThat(p -> (p.getInt("status_code")) == status));
+                argThat(bundle -> {
+                        int addressMode = bundle.getInt("mac_address_mode");
+                        UwbAddress address = FiraParams.longToUwbAddress(
+                                bundle.getLong("address"),
+                                addressMode == FiraParams.MAC_ADDRESS_MODE_2_BYTES
+                                        ? UwbAddress.SHORT_ADDRESS_BYTE_LENGTH
+                                        : UwbAddress.EXTENDED_ADDRESS_BYTE_LENGTH);
+                        int reason = bundle.getInt("reason");
+                        return address.equals(UwbTestUtils.PEER_SHORT_UWB_ADDRESS)
+                                && FiraOnControleeAddRemoveParams.Reason.LOST_CONNECTION == reason;
+                }));
     }
 
     @Test
diff --git a/service/tests/src/com/android/server/uwb/params/GenericDecoderTest.java b/service/tests/src/com/android/server/uwb/params/GenericDecoderTest.java
index dd2abd40..000e46a8 100644
--- a/service/tests/src/com/android/server/uwb/params/GenericDecoderTest.java
+++ b/service/tests/src/com/android/server/uwb/params/GenericDecoderTest.java
@@ -40,6 +40,7 @@ import com.android.server.uwb.UwbInjector;
 import com.android.server.uwb.util.UwbUtil;
 import com.android.uwb.flags.FeatureFlags;
 
+import com.google.uwb.support.generic.GenericParams;
 import com.google.uwb.support.generic.GenericSpecificationParams;
 
 import org.junit.Before;
@@ -54,28 +55,25 @@ import org.mockito.MockitoAnnotations;
 @Presubmit
 public class GenericDecoderTest {
     private static final byte[] TEST_GENERIC_SPECIFICATION_TLV_DATA_VER_1 =
-            UwbUtil.getByteArray(
-                    "C00101" // SUPPORTED_POWER_STATS_QUERY
+            UwbUtil.getByteArray("C00101" // SUPPORTED_POWER_STATS_QUERY
                             + TEST_FIRA_SPECIFICATION_TLV_STRING_VER_1
                             + TEST_CCC_SPECIFICATION_TLV_DATA_STRING
                             + TEST_RADAR_SPECIFICATION_TLV_DATA_STRING);
-    private static final int TEST_GENERIC_SPECIFICATION_TLV_NUM_PARAMS_VER_1 =
-            1
+    private static final int TEST_GENERIC_SPECIFICATION_TLV_NUM_PARAMS_VER_1 = 1
                     + TEST_FIRA_SPECIFICATION_TLV_NUM_PARAMS_VER_1
                     + TEST_CCC_SPECIFICATION_TLV_NUM_PARAMS
                     + TEST_RADAR_SPECIFICATION_TLV_NUM_PARAMS;
 
     private static final byte[] TEST_GENERIC_SPECIFICATION_TLV_DATA_VER_2 =
-            UwbUtil.getByteArray(
-                    "C00101" // SUPPORTED_POWER_STATS_QUERY
+            UwbUtil.getByteArray("C00101" // SUPPORTED_POWER_STATS_QUERY
+                            + "C10103" // ANTENNA MODE CAPABILITIES
                             + FiraDecoderTest.TEST_FIRA_SPECIFICATION_TLV_STRING_VER_2
                             + TEST_CCC_SPECIFICATION_TLV_DATA_STRING
                             + TEST_RADAR_SPECIFICATION_TLV_DATA_STRING);
-    private static final int TEST_GENERIC_SPECIFICATION_TLV_NUM_PARAMS_VER_2 =
-            1
-                    + TEST_FIRA_SPECIFICATION_TLV_NUM_PARAMS_VER_2
-                    + TEST_CCC_SPECIFICATION_TLV_NUM_PARAMS
-                    + TEST_RADAR_SPECIFICATION_TLV_NUM_PARAMS;
+    private static final int TEST_GENERIC_SPECIFICATION_TLV_NUM_PARAMS_VER_2 = 2
+            + TEST_FIRA_SPECIFICATION_TLV_NUM_PARAMS_VER_2
+            + TEST_CCC_SPECIFICATION_TLV_NUM_PARAMS
+            + TEST_RADAR_SPECIFICATION_TLV_NUM_PARAMS;
 
     @Mock private UwbInjector mUwbInjector;
     @Mock private DeviceConfigFacade mDeviceConfigFacade;
@@ -107,6 +105,7 @@ public class GenericDecoderTest {
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                            PROTOCOL_VERSION_1_1);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isTrue();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).isEmpty();
         FiraDecoderTest.verifyFiraSpecificationVersion1(
                 genericSpecificationParams.getFiraSpecificationParams());
         CccDecoderTest.verifyCccSpecification(
@@ -127,6 +126,7 @@ public class GenericDecoderTest {
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                             PROTOCOL_VERSION_1_1);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isTrue();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).isEmpty();
         FiraDecoderTest.verifyFiraSpecificationVersion1(
                 genericSpecificationParams.getFiraSpecificationParams());
         CccDecoderTest.verifyCccSpecification(
@@ -147,6 +147,9 @@ public class GenericDecoderTest {
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                             PROTOCOL_VERSION_2_0);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isTrue();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).containsExactly(
+                GenericParams.AntennaModeCapabilityFlag.HAS_OMNI_MODE_SUPPORT,
+                GenericParams.AntennaModeCapabilityFlag.HAS_DIRECTIONAL_MODE_SUPPORT);
         FiraDecoderTest.verifyFiraSpecificationVersion2(
                 genericSpecificationParams.getFiraSpecificationParams());
         CccDecoderTest.verifyCccSpecification(
@@ -167,6 +170,9 @@ public class GenericDecoderTest {
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                             PROTOCOL_VERSION_2_0);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isTrue();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).containsExactly(
+                GenericParams.AntennaModeCapabilityFlag.HAS_OMNI_MODE_SUPPORT,
+                GenericParams.AntennaModeCapabilityFlag.HAS_DIRECTIONAL_MODE_SUPPORT);
         FiraDecoderTest.verifyFiraSpecificationVersion2(
                 genericSpecificationParams.getFiraSpecificationParams());
         CccDecoderTest.verifyCccSpecification(
@@ -185,11 +191,11 @@ public class GenericDecoderTest {
                         TEST_FIRA_SPECIFICATION_TLV_NUM_PARAMS_VER_1
                                 + TEST_RADAR_SPECIFICATION_TLV_NUM_PARAMS);
         assertThat(tlvDecoderBuffer.parse()).isTrue();
-
         GenericSpecificationParams genericSpecificationParams =
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                             PROTOCOL_VERSION_1_1);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isFalse();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).isEmpty();
         FiraDecoderTest.verifyFiraSpecificationVersion1(
                 genericSpecificationParams.getFiraSpecificationParams());
         RadarDecoderTest.verifyRadarSpecification(
@@ -212,6 +218,7 @@ public class GenericDecoderTest {
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                             PROTOCOL_VERSION_1_1);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isFalse();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).isEmpty();
         CccDecoderTest.verifyCccSpecification(
                 genericSpecificationParams.getCccSpecificationParams());
         RadarDecoderTest.verifyRadarSpecification(
@@ -234,6 +241,7 @@ public class GenericDecoderTest {
                 mGenericDecoder.getParams(tlvDecoderBuffer, GenericSpecificationParams.class,
                             PROTOCOL_VERSION_1_1);
         assertThat(genericSpecificationParams.hasPowerStatsSupport()).isFalse();
+        assertThat(genericSpecificationParams.getAntennaModeCapabilities()).isEmpty();
         FiraDecoderTest.verifyFiraSpecificationVersion1(
                 genericSpecificationParams.getFiraSpecificationParams());
         CccDecoderTest.verifyCccSpecification(
diff --git a/service/uci/jni/Android.bp b/service/uci/jni/Android.bp
index ef03cf2c..74e9680f 100644
--- a/service/uci/jni/Android.bp
+++ b/service/uci/jni/Android.bp
@@ -13,7 +13,6 @@ rust_defaults {
     rustlibs: [
         "libbinder_rs",
         "libjni_legacy",
-        "liblazy_static",
         "liblog_rust",
         "liblogger",
         "libnum_traits",
diff --git a/service/uci/jni/src/dispatcher.rs b/service/uci/jni/src/dispatcher.rs
index 4fc650e1..44287ce0 100644
--- a/service/uci/jni/src/dispatcher.rs
+++ b/service/uci/jni/src/dispatcher.rs
@@ -22,7 +22,6 @@ use std::sync::{Arc, RwLock, RwLockReadGuard};
 
 use jni::objects::{GlobalRef, JObject, JString};
 use jni::{JNIEnv, JavaVM, MonitorGuard};
-use lazy_static::lazy_static;
 use log::error;
 use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
 use uci_hal_android::uci_hal_android::UciHalAndroid;
@@ -33,10 +32,8 @@ use uwb_core::uci::uci_logger_factory::UciLoggerFactory;
 use uwb_core::uci::uci_manager_sync::UciManagerSync;
 use uwb_core::uci::UciManagerImpl;
 
-lazy_static! {
-    /// Shared unique dispatcher that may be created and deleted during runtime.
-    static ref DISPATCHER: RwLock<Option<Dispatcher>> = RwLock::new(None);
-}
+/// Shared unique dispatcher that may be created and deleted during runtime.
+static DISPATCHER: RwLock<Option<Dispatcher>> = RwLock::new(None);
 
 /// Dispatcher is managed by Java side. Construction and Destruction are provoked by JNI function
 /// nativeDispatcherNew and nativeDispatcherDestroy respectively.
diff --git a/service/uci/jni/src/helper.rs b/service/uci/jni/src/helper.rs
index faf67807..868b4f97 100644
--- a/service/uci/jni/src/helper.rs
+++ b/service/uci/jni/src/helper.rs
@@ -37,9 +37,8 @@ pub(crate) fn byte_result_helper<T>(result: Result<T>, error_msg: &str) -> jbyte
 
 /// helper function to convert Result to StatusCode
 fn result_to_status_code<T>(result: Result<T>, error_msg: &str) -> StatusCode {
-    let result = result.map_err(|e| {
+    let result = result.inspect_err(|e| {
         error!("{} failed with {:?}", error_msg, &e);
-        e
     });
     match result {
         Ok(_) => StatusCode::UciStatusOk,
@@ -54,9 +53,8 @@ fn result_to_status_code<T>(result: Result<T>, error_msg: &str) -> StatusCode {
 
 pub(crate) fn option_result_helper<T>(result: Result<T>, error_msg: &str) -> Option<T> {
     result
-        .map_err(|e| {
+        .inspect_err(|e| {
             error!("{} failed with {:?}", error_msg, &e);
-            e
         })
         .ok()
 }
diff --git a/service/uci/jni/src/notification_manager_android.rs b/service/uci/jni/src/notification_manager_android.rs
index d7cb982e..50586d7c 100644
--- a/service/uci/jni/src/notification_manager_android.rs
+++ b/service/uci/jni/src/notification_manager_android.rs
@@ -1039,7 +1039,10 @@ impl NotificationManager for NotificationManagerAndroid {
                 ),
             }
         })
-        .map_err(|_| UwbError::ForeignFunctionInterface)?;
+        .map_err(|e| {
+            error!("on_core_notification error: {:?}", e);
+            UwbError::ForeignFunctionInterface
+        })?;
 
         Ok(())
     }
@@ -1129,7 +1132,10 @@ impl NotificationManager for NotificationManagerAndroid {
                 }
             }
         })
-        .map_err(|_| UwbError::ForeignFunctionInterface)?;
+        .map_err(|e| {
+            error!("on_session_notification error {:?}", e);
+            UwbError::ForeignFunctionInterface
+        })?;
         Ok(())
     }
 
@@ -1166,7 +1172,10 @@ impl NotificationManager for NotificationManagerAndroid {
                 ],
             )
         })
-        .map_err(|_| UwbError::ForeignFunctionInterface)?;
+        .map_err(|e| {
+            error!("on_vendor_notification error: {:?}", e);
+            UwbError::ForeignFunctionInterface
+        })?;
         Ok(())
     }
 
@@ -1200,7 +1209,10 @@ impl NotificationManager for NotificationManagerAndroid {
                 ],
             )
         })
-        .map_err(|_| UwbError::ForeignFunctionInterface)?;
+        .map_err(|e| {
+            error!("on_data_rcv_notification error: {:?}", e);
+            UwbError::ForeignFunctionInterface
+        })?;
         Ok(())
     }
 
@@ -1344,7 +1356,10 @@ impl NotificationManager for NotificationManagerAndroid {
                 &[jvalue::from(JValue::Object(radar_data_jobject))],
             )
         })
-        .map_err(|_| UwbError::ForeignFunctionInterface)?;
+        .map_err(|e| {
+            error!("on_radar_data_rcv_notification error: {:?}", e);
+            UwbError::ForeignFunctionInterface
+        })?;
         Ok(())
     }
 }
diff --git a/service/uci/jni/src/uci_jni_android_new.rs b/service/uci/jni/src/uci_jni_android_new.rs
index 134bfe87..e612d2af 100644
--- a/service/uci/jni/src/uci_jni_android_new.rs
+++ b/service/uci/jni/src/uci_jni_android_new.rs
@@ -128,9 +128,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeDo
     debug!("{}: enter", function_name!());
     match option_result_helper(native_do_initialize(env, obj, chip_id), function_name!()) {
         Some(rsp) => create_device_info_response(rsp, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -456,9 +455,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeSe
         function_name!(),
     ) {
         Some(config_response) => create_set_config_response(config_response, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -504,9 +502,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeSe
         function_name!(),
     ) {
         Some(config_response) => create_radar_config_response(config_response, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -766,9 +763,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeGe
         function_name!(),
     ) {
         Some(v) => create_get_config_response(v, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -835,9 +831,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeGe
     debug!("{}: enter", function_name!());
     match option_result_helper(native_get_caps_info(env, obj, chip_id), function_name!()) {
         Some(v) => create_cap_response(v, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -938,9 +933,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeCo
         function_name!(),
     ) {
         Some(v) => create_session_update_controller_multicast_response(v, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -1211,9 +1205,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeSe
         // native_send_raw_vendor_cmd.
         Some(msg) => unsafe {
             create_vendor_response(msg, env)
-                .map_err(|e| {
+                .inspect_err(|e| {
                     error!("{} failed with {:?}", function_name!(), &e);
-                    e
                 })
                 .unwrap_or_else(|_| create_invalid_vendor_response(env).unwrap())
         },
@@ -1264,9 +1257,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeGe
     debug!("{}: enter", function_name!());
     match option_result_helper(native_get_power_stats(env, obj, chip_id), function_name!()) {
         Some(ps) => create_power_stats(ps, env)
-            .map_err(|e| {
+            .inspect_err(|e| {
                 error!("{} failed with {:?}", function_name!(), &e);
-                e
             })
             .unwrap_or(*JObject::null()),
         None => *JObject::null(),
@@ -1302,9 +1294,8 @@ pub extern "system" fn Java_com_android_server_uwb_jni_NativeUwbManager_nativeSe
         // Safety: rr is safely returned from native_set_ranging_rounds_dt_tag
         Some(rr) => unsafe {
             create_ranging_round_status(rr, env)
-                .map_err(|e| {
+                .inspect_err(|e| {
                     error!("{} failed with {:?}", function_name!(), &e);
-                    e
                 })
                 .unwrap_or(*JObject::null())
         },
diff --git a/tests/cts/hostsidetests/multidevices/uwb/snippet/AndroidManifest.xml b/tests/cts/hostsidetests/multidevices/uwb/snippet/AndroidManifest.xml
index 6b28be9b..3fb77441 100644
--- a/tests/cts/hostsidetests/multidevices/uwb/snippet/AndroidManifest.xml
+++ b/tests/cts/hostsidetests/multidevices/uwb/snippet/AndroidManifest.xml
@@ -13,6 +13,11 @@
     <meta-data
         android:name="mobly-snippets"
         android:value="com.google.snippet.uwb.UwbManagerSnippet" />
+     <!-- Optional: tag which will be used for logs through the snippet lib's logger.
+          If not specified, full class name of the snippet will be used. -->
+     <meta-data
+        android:name="mobly-log-tag"
+        android:value="uwb_snippet" />
   </application>
   <!-- Add an instrumentation tag so that the app can be launched through an
        instrument command. The runner `com.google.android.mobly.snippet.SnippetRunner`
diff --git a/tests/cts/hostsidetests/multidevices/uwb/snippet/UwbManagerSnippet.java b/tests/cts/hostsidetests/multidevices/uwb/snippet/UwbManagerSnippet.java
index 27e05736..1aaf77dd 100644
--- a/tests/cts/hostsidetests/multidevices/uwb/snippet/UwbManagerSnippet.java
+++ b/tests/cts/hostsidetests/multidevices/uwb/snippet/UwbManagerSnippet.java
@@ -703,6 +703,15 @@ public class UwbManagerSnippet implements Snippet {
         if (j.has("filterType")) {
             builder.setFilterType(j.getInt("filterType"));
         }
+        if (j.has("rangeDataNtfConfig")) {
+            builder.setRangeDataNtfConfig(j.getInt("rangeDataNtfConfig"));
+        }
+        if (j.has("errorStreakTimeoutInMs")) {
+            builder.setRangingErrorStreakTimeoutMs(j.getInt("errorStreakTimeoutInMs"));
+        }
+        if (j.has("hasRangingResultReportMessage")) {
+            builder.setHasRangingResultReportMessage(j.getBoolean("hasRangingResultReportMessage"));
+        }
 
         return builder.build();
     }
diff --git a/tests/cts/tests/Android.bp b/tests/cts/tests/Android.bp
index 5133be55..72b16a3b 100644
--- a/tests/cts/tests/Android.bp
+++ b/tests/cts/tests/Android.bp
@@ -29,7 +29,7 @@ android_test {
         "mts-uwb",
         "mcts-uwb",
     ],
-    libs: ["android.test.runner"],
+    libs: ["android.test.runner.stubs.system"],
     static_libs: [
         "androidx.test.ext.junit",
         "ctstestrunner-axt",
diff --git a/tests/cts/tests/src/android/uwb/cts/UwbManagerTest.java b/tests/cts/tests/src/android/uwb/cts/UwbManagerTest.java
index a2833ce4..7386a1d1 100644
--- a/tests/cts/tests/src/android/uwb/cts/UwbManagerTest.java
+++ b/tests/cts/tests/src/android/uwb/cts/UwbManagerTest.java
@@ -1127,6 +1127,7 @@ public class UwbManagerTest {
     @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
     @RequiresFlagsEnabled("com.android.uwb.flags.query_timestamp_micros")
     public void testQueryMaxDataSizeBytesWithNoPermission() throws Exception {
+        assumeTrue(SdkLevel.isAtLeastU());
         FiraOpenSessionParams firaOpenSessionParams = makeOpenSessionBuilder()
                 .build();
         verifyFiraRangingSession(
@@ -1237,6 +1238,39 @@ public class UwbManagerTest {
                 });
     }
 
+    @Test
+    @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
+    public void testUpdateRangingRoundsDtTagWithNoPermissions() throws Exception {
+        assumeTrue(SdkLevel.isAtLeastU());
+        FiraOpenSessionParams firaOpenSessionParams = makeOpenSessionBuilder().build();
+        verifyFiraRangingSession(
+                firaOpenSessionParams,
+                null,
+                (rangingSessionCallback) -> {
+                    CountDownLatch countDownLatch = new CountDownLatch(1);
+                    rangingSessionCallback.replaceCtrlCountDownLatch(countDownLatch);
+                    UiAutomation uiAutomation = getInstrumentation().getUiAutomation();
+                    uiAutomation.dropShellPermissionIdentity();
+
+                    DlTDoARangingRoundsUpdate rangingRoundsUpdate =
+                            new DlTDoARangingRoundsUpdate.Builder()
+                                    .setSessionId(1)
+                                    .setNoOfRangingRounds(1)
+                                    .setRangingRoundIndexes(new byte[]{0})
+                                    .build();
+                    try {
+                        rangingSessionCallback.rangingSession.updateRangingRoundsDtTag(
+                                rangingRoundsUpdate.toBundle());
+                        fail();
+                    } catch (SecurityException e) {
+                        /* pass */
+                        Log.i(TAG, "Failed with expected security exception: " + e);
+                    } finally {
+                        uiAutomation.adoptShellPermissionIdentity();
+                    }
+                });
+    }
+
     @Ignore // Disabled in U as FiRa 2.0 is not fully formalized.
     @Test
     @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
@@ -1288,6 +1322,35 @@ public class UwbManagerTest {
                 });
     }
 
+    @Test
+    @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
+    public void testSendDataWithNoPermission() throws Exception {
+        FiraOpenSessionParams firaOpenSessionParams = makeOpenSessionBuilder().build();
+        verifyFiraRangingSession(
+                firaOpenSessionParams,
+                null,
+                (rangingSessionCallback) -> {
+                    CountDownLatch countDownLatch = new CountDownLatch(1);
+                    rangingSessionCallback.replaceCtrlCountDownLatch(countDownLatch);
+                    UiAutomation uiAutomation = getInstrumentation().getUiAutomation();
+                    uiAutomation.dropShellPermissionIdentity();
+
+                    try {
+                        rangingSessionCallback.rangingSession.sendData(
+                                UwbAddress.fromBytes(new byte[]{0x1, 0x2}),
+                                new PersistableBundle(),
+                                new byte[]{0x01, 0x02, 0x03, 0x04}
+                        );
+                        fail();
+                    } catch (SecurityException e) {
+                        /* pass */
+                        Log.i(TAG, "Failed with expected security exception: " + e);
+                    } finally {
+                        uiAutomation.adoptShellPermissionIdentity();
+                    }
+                });
+    }
+
     @Ignore // Disabled in U as FiRa 2.0 is not fully formalized.
     @Test
     @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
@@ -1513,6 +1576,15 @@ public class UwbManagerTest {
                     assertThat(rangingSessionCallback.onControleeAddCalled).isTrue();
                     assertThat(rangingSessionCallback.onControleeAddFailedCalled).isFalse();
 
+                    // Wait for a little over a ranging round to see if there are any
+                    // ranging timeouts, and remove this controlee if it was not
+                    // found in UWB Range.
+                    countDownLatch = new CountDownLatch(1);
+                    rangingSessionCallback.replaceResultCountDownLatch(countDownLatch);
+                    assertThat(countDownLatch.await(
+                        firaOpenSessionParams.getRangingIntervalMs() + 10,
+                        TimeUnit.MILLISECONDS)).isTrue();
+
                     // Remove controlee
                     countDownLatch = new CountDownLatch(2);
                     rangingSessionCallback.replaceCtrlCountDownLatch(countDownLatch);
@@ -1531,6 +1603,68 @@ public class UwbManagerTest {
                 });
     }
 
+    @Test
+    @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
+    public void testFiraRangingSessionPauseWithNoPermission() throws Exception {
+        FiraOpenSessionParams firaOpenSessionParams = makeOpenSessionBuilder()
+                .setMultiNodeMode(FiraParams.MULTI_NODE_MODE_ONE_TO_MANY)
+                .build();
+        verifyFiraRangingSession(
+                firaOpenSessionParams,
+                null,
+                (rangingSessionCallback) -> {
+                    CountDownLatch countDownLatch = new CountDownLatch(1);
+                    rangingSessionCallback.replaceCtrlCountDownLatch(countDownLatch);
+                    UiAutomation uiAutomation = getInstrumentation().getUiAutomation();
+                    uiAutomation.dropShellPermissionIdentity();
+
+                    FiraSuspendRangingParams pauseParams =
+                            new FiraSuspendRangingParams.Builder()
+                                    .setSuspendRangingRounds(FiraParams.SUSPEND_RANGING_ENABLED)
+                                    .build();
+                    try {
+                        rangingSessionCallback.rangingSession.pause(pauseParams.toBundle());
+                        fail();
+                    } catch (SecurityException e) {
+                        /* pass */
+                        Log.i(TAG, "Failed with expected security exception: " + e);
+                    } finally {
+                        uiAutomation.adoptShellPermissionIdentity();
+                    }
+                });
+    }
+
+    @Test
+    @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
+    public void testFiraRangingSessionResumeWithNoPermission() throws Exception {
+        FiraOpenSessionParams firaOpenSessionParams = makeOpenSessionBuilder()
+                .setMultiNodeMode(FiraParams.MULTI_NODE_MODE_ONE_TO_MANY)
+                .build();
+        verifyFiraRangingSession(
+                firaOpenSessionParams,
+                null,
+                (rangingSessionCallback) -> {
+                    CountDownLatch countDownLatch = new CountDownLatch(1);
+                    rangingSessionCallback.replaceCtrlCountDownLatch(countDownLatch);
+                    UiAutomation uiAutomation = getInstrumentation().getUiAutomation();
+                    uiAutomation.dropShellPermissionIdentity();
+
+                    FiraSuspendRangingParams resumeParams =
+                            new FiraSuspendRangingParams.Builder()
+                                    .setSuspendRangingRounds(FiraParams.SUSPEND_RANGING_DISABLED)
+                                    .build();
+                    try {
+                        rangingSessionCallback.rangingSession.resume(resumeParams.toBundle());
+                        fail();
+                    } catch (SecurityException e) {
+                        /* pass */
+                        Log.i(TAG, "Failed with expected security exception: " + e);
+                    } finally {
+                        uiAutomation.adoptShellPermissionIdentity();
+                    }
+                });
+    }
+
     @Ignore // b/316828112
     @Test
     @CddTest(requirements = {"7.3.13/C-1-1,C-1-2,C-1-5"})
```

