```diff
diff --git a/Android.bp b/Android.bp
index 3712ba6e..8f4997c6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,32 +14,6 @@
 // limitations under the License.
 //
 
-// The network stack can be compiled using system_current (non-finalized) SDK, or finalized system_X
-// SDK. There is also a variant that uses system_current SDK and runs in the system process
-// (InProcessNetworkStack). The following structure is used to create the build rules:
-//
-//                          NetworkStackAndroidLibraryDefaults <-- common defaults for android libs
-//                                            /    \
-//           +NetworkStackApiStableShims --> /      \ <-- +NetworkStackApiCurrentShims
-//           +NetworkStackReleaseApiLevel   /        \    +NetworkStackDevApiLevel
-//           +jarjar apishim.api[latest].* /          \
-//            to apishim.*                /            \
-//                                       /              \
-//                                      /                \
-//                                     /                  \               android libs w/ all code
-//                                    / <- +module src/ -> \              (also used in unit tests)
-//                                   /                      \                        |
-//               NetworkStackApiStableLib               NetworkStackApiCurrentLib <--*
-//                          |                                     |
-//                          | <--   +NetworkStackAppDefaults  --> |
-//                          |          (APK build params)         |
-//                          |                                     |
-//                          | <-- +NetworkStackReleaseApiLevel    | <-- +NetworkStackDevApiLevel
-//                          |                                     |
-//                          |                                     |
-//                NetworkStackApiStable          NetworkStack, InProcessNetworkStack, <-- APKs
-//                                                         TestNetworkStack
-
 // Common defaults to define SDK level
 package {
     default_team: "trendy_team_fwk_core_networking",
@@ -56,23 +30,6 @@ java_defaults {
     enabled: true,
 }
 
-// This is a placeholder comment to avoid merge conflicts
-// as the above target may have different "enabled" values
-// depending on the branch
-
-java_defaults {
-    name: "NetworkStackDevApiLevel",
-    min_sdk_version: "30",
-    sdk_version: "module_current",
-    libs: [
-        "framework-configinfrastructure",
-        "framework-connectivity",
-        "framework-connectivity-t",
-        "framework-statsd",
-        "framework-wifi",
-    ],
-}
-
 // Common defaults for NetworkStack integration tests, root tests and coverage tests
 // to keep tests always running against the same target sdk version with NetworkStack.
 java_defaults {
@@ -86,11 +43,12 @@ java_defaults {
     defaults: ["NetworkStackReleaseTargetSdk"],
     sdk_version: "module_current",
     libs: [
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
         "framework-connectivity.stubs.module_lib",
-        "framework-connectivity-t",
-        "framework-statsd",
-        "framework-wifi",
+        "framework-connectivity-t.stubs.module_lib",
+        "framework-statsd.stubs.module_lib",
+        "framework-tethering.stubs.module_lib",
+        "framework-wifi.stubs.module_lib",
     ],
 }
 
@@ -171,8 +129,8 @@ java_library {
         "NetworkStackShimsCommon",
         "NetworkStackApi29Shims",
         "NetworkStackApi30Shims",
-        "framework-connectivity",
-        "framework-wifi",
+        "framework-connectivity.impl",
+        "sdk_module-lib_31_framework-wifi",
     ],
     sdk_version: "module_31",
     visibility: ["//visibility:private"],
@@ -189,11 +147,11 @@ java_library {
         "NetworkStackApi29Shims",
         "NetworkStackApi30Shims",
         "NetworkStackApi31Shims",
-        "framework-bluetooth",
-        "framework-connectivity",
+        "sdk_module-lib_33_framework-bluetooth",
+        "framework-connectivity.impl",
         "framework-connectivity-t.stubs.module_lib",
-        "framework-tethering",
-        "framework-wifi",
+        "framework-tethering.impl",
+        "sdk_module-lib_33_framework-wifi",
     ],
     sdk_version: "module_33",
     visibility: ["//visibility:private"],
@@ -211,11 +169,11 @@ java_library {
         "NetworkStackApi30Shims",
         "NetworkStackApi31Shims",
         "NetworkStackApi33Shims",
-        "framework-bluetooth",
-        "framework-connectivity",
+        "sdk_module-lib_34_framework-bluetooth",
+        "framework-connectivity.impl",
         "framework-connectivity-t.stubs.module_lib",
-        "framework-tethering",
-        "framework-wifi",
+        "framework-tethering.impl",
+        "sdk_module-lib_34_framework-wifi",
     ],
     sdk_version: "module_34",
     visibility: ["//visibility:private"],
@@ -244,11 +202,11 @@ java_library {
         "NetworkStackApi31Shims",
         "NetworkStackApi33Shims",
         "NetworkStackApi34Shims",
-        "framework-bluetooth",
-        "framework-connectivity",
+        "framework-bluetooth.stubs.module_lib",
+        "framework-connectivity.impl",
         "framework-connectivity-t.stubs.module_lib",
-        "framework-tethering",
-        "framework-wifi",
+        "framework-tethering.impl",
+        "framework-wifi.stubs.module_lib",
         "android.net.ipsec.ike.stubs.module_lib",
     ],
     sdk_version: "module_current",
@@ -262,7 +220,7 @@ java_library {
     name: "NetworkStackApiCurrentShims",
     defaults: [
         "NetworkStackShimsDefaults",
-        "NetworkStackDevApiLevel",
+        "NetworkStackReleaseApiLevel",
         "ConnectivityNextEnableDefaults",
     ],
     static_libs: [
@@ -343,7 +301,7 @@ java_defaults {
 android_library {
     name: "NetworkStackApiCurrentLib",
     defaults: [
-        "NetworkStackDevApiLevel",
+        "NetworkStackReleaseApiLevel",
         "NetworkStackAndroidLibraryDefaults",
         "ConnectivityNextEnableDefaults",
     ],
@@ -484,7 +442,7 @@ android_app {
     name: "InProcessNetworkStack",
     defaults: [
         "NetworkStackAppDefaults",
-        "NetworkStackDevApiLevel",
+        "NetworkStackReleaseApiLevel",
         "ConnectivityNextEnableDefaults",
     ],
     static_libs: ["NetworkStackApiCurrentLib"],
@@ -507,7 +465,7 @@ android_library {
     name: "NetworkStackNextManifestBase",
     defaults: [
         "NetworkStackAppDefaults",
-        "NetworkStackDevApiLevel",
+        "NetworkStackReleaseApiLevel",
         "ConnectivityNextEnableDefaults",
     ],
     static_libs: ["NetworkStackApiCurrentLib"],
@@ -519,7 +477,7 @@ android_app {
     name: "NetworkStackNext",
     defaults: [
         "NetworkStackAppDefaults",
-        "NetworkStackDevApiLevel",
+        "NetworkStackReleaseApiLevel",
         "ConnectivityNextEnableDefaults",
     ],
     static_libs: ["NetworkStackNextManifestBase"],
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 151be7ef..ee063029 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,3 +1,12 @@
+[Builtin Hooks]
+bpfmt = true
+clang_format = true
+ktfmt = true
+
+[Builtin Hooks Options]
+clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp,hpp
+ktfmt = --kotlinlang-style
+
 [Hook Scripts]
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
-ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py -f ${PREUPLOAD_FILES}
+ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES}
diff --git a/common/networkstackclient/Android.bp b/common/networkstackclient/Android.bp
index a5d7230c..983f1b73 100644
--- a/common/networkstackclient/Android.bp
+++ b/common/networkstackclient/Android.bp
@@ -97,8 +97,13 @@ aidl_interface {
             version: "10",
             imports: [],
         },
+        {
+            version: "11",
+            imports: [],
+        },
 
     ],
+    frozen: true,
 
 }
 
@@ -167,7 +172,7 @@ aidl_interface {
             enabled: false,
         },
     },
-    imports: ["ipmemorystore-aidl-interfaces-V10"],
+    imports: ["ipmemorystore-aidl-interfaces-V11"],
     // TODO: have tethering depend on networkstack-client and set visibility to private
     visibility: [
         "//system/tools/aidl/build",
@@ -178,39 +183,43 @@ aidl_interface {
         // Remove old networkstack aidl interface version info that is no longer used.
         {
             version: "13",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "14",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "15",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "16",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "17",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "18",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "19",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "20",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
         {
             version: "21",
-            imports: ["ipmemorystore-aidl-interfaces-V10"],
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
+        },
+        {
+            version: "22",
+            imports: ["ipmemorystore-aidl-interfaces-V11"],
         },
 
     ],
@@ -222,8 +231,8 @@ java_library {
     sdk_version: "system_current",
     min_sdk_version: "30",
     static_libs: [
-        "ipmemorystore-aidl-interfaces-V10-java",
-        "networkstack-aidl-interfaces-V21-java",
+        "ipmemorystore-aidl-interfaces-V11-java",
+        "networkstack-aidl-interfaces-V22-java",
     ],
     visibility: ["//packages/modules/NetworkStack:__subpackages__"],
     apex_available: [
@@ -251,9 +260,9 @@ java_library {
         "src/android/net/util/**/*.java",
     ],
     libs: [
-        // Since this library is sdk_version: "module_current", "framework-connectivity" is just
+        // Since this library is sdk_version: "module_current", "framework-connectivity.stubs.module_lib" is just
         // the module_current API stubs of framework-connectivity
-        "framework-connectivity",
+        "framework-connectivity.stubs.module_lib",
         "framework-annotations-lib",
     ],
     static_libs: [
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/.hash b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/.hash
new file mode 100644
index 00000000..bd4b7439
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/.hash
@@ -0,0 +1 @@
+b24ee617afb80799cb35b6241f5847d786c649f3
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/IIpMemoryStore.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/IIpMemoryStore.aidl
new file mode 100644
index 00000000..e2c94a26
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/IIpMemoryStore.aidl
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net;
+/* @hide */
+interface IIpMemoryStore {
+  oneway void storeNetworkAttributes(String l2Key, in android.net.ipmemorystore.NetworkAttributesParcelable attributes, android.net.ipmemorystore.IOnStatusListener listener);
+  oneway void storeBlob(String l2Key, String clientId, String name, in android.net.ipmemorystore.Blob data, android.net.ipmemorystore.IOnStatusListener listener);
+  oneway void findL2Key(in android.net.ipmemorystore.NetworkAttributesParcelable attributes, android.net.ipmemorystore.IOnL2KeyResponseListener listener);
+  oneway void isSameNetwork(String l2Key1, String l2Key2, android.net.ipmemorystore.IOnSameL3NetworkResponseListener listener);
+  oneway void retrieveNetworkAttributes(String l2Key, android.net.ipmemorystore.IOnNetworkAttributesRetrievedListener listener);
+  oneway void retrieveBlob(String l2Key, String clientId, String name, android.net.ipmemorystore.IOnBlobRetrievedListener listener);
+  oneway void factoryReset();
+  oneway void delete(String l2Key, boolean needWipe, android.net.ipmemorystore.IOnStatusAndCountListener listener);
+  oneway void deleteCluster(String cluster, boolean needWipe, android.net.ipmemorystore.IOnStatusAndCountListener listener);
+  oneway void storeNetworkEvent(String cluster, long timestamp, long expiry, int eventType, android.net.ipmemorystore.IOnStatusListener listener);
+  oneway void retrieveNetworkEventCount(String cluster, in long[] sinceTimes, in int[] eventTypes, android.net.ipmemorystore.IOnNetworkEventCountRetrievedListener listener);
+  const int NETWORK_EVENT_NUD_FAILURE_ROAM = 0;
+  const int NETWORK_EVENT_NUD_FAILURE_CONFIRM = 1;
+  const int NETWORK_EVENT_NUD_FAILURE_ORGANIC = 2;
+  const int NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED = 3;
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/IIpMemoryStoreCallbacks.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/IIpMemoryStoreCallbacks.aidl
new file mode 100644
index 00000000..7dbbc984
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/IIpMemoryStoreCallbacks.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+package android.net;
+/* @hide */
+interface IIpMemoryStoreCallbacks {
+  oneway void onIpMemoryStoreFetched(in android.net.IIpMemoryStore ipMemoryStore);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/Blob.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/Blob.aidl
new file mode 100644
index 00000000..4300c834
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/Blob.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+parcelable Blob {
+  byte[] data;
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnBlobRetrievedListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnBlobRetrievedListener.aidl
new file mode 100644
index 00000000..3a263e2b
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnBlobRetrievedListener.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnBlobRetrievedListener {
+  oneway void onBlobRetrieved(in android.net.ipmemorystore.StatusParcelable status, in String l2Key, in String name, in android.net.ipmemorystore.Blob data);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnL2KeyResponseListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnL2KeyResponseListener.aidl
new file mode 100644
index 00000000..c663ccfc
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnL2KeyResponseListener.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnL2KeyResponseListener {
+  oneway void onL2KeyResponse(in android.net.ipmemorystore.StatusParcelable status, in String l2Key);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnNetworkAttributesRetrievedListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnNetworkAttributesRetrievedListener.aidl
new file mode 100644
index 00000000..3740e157
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnNetworkAttributesRetrievedListener.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnNetworkAttributesRetrievedListener {
+  oneway void onNetworkAttributesRetrieved(in android.net.ipmemorystore.StatusParcelable status, in String l2Key, in android.net.ipmemorystore.NetworkAttributesParcelable attributes);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl
new file mode 100644
index 00000000..29d7781e
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnNetworkEventCountRetrievedListener {
+  oneway void onNetworkEventCountRetrieved(in android.net.ipmemorystore.StatusParcelable status, in int[] counts);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnSameL3NetworkResponseListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnSameL3NetworkResponseListener.aidl
new file mode 100644
index 00000000..9d87fbbc
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnSameL3NetworkResponseListener.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnSameL3NetworkResponseListener {
+  oneway void onSameL3NetworkResponse(in android.net.ipmemorystore.StatusParcelable status, in android.net.ipmemorystore.SameL3NetworkResponseParcelable response);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnStatusAndCountListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnStatusAndCountListener.aidl
new file mode 100644
index 00000000..1e6a41cd
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnStatusAndCountListener.aidl
@@ -0,0 +1,38 @@
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnStatusAndCountListener {
+  oneway void onComplete(in android.net.ipmemorystore.StatusParcelable status, int count);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnStatusListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnStatusListener.aidl
new file mode 100644
index 00000000..dccdf271
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/IOnStatusListener.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnStatusListener {
+  oneway void onComplete(in android.net.ipmemorystore.StatusParcelable status);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/NetworkAttributesParcelable.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/NetworkAttributesParcelable.aidl
new file mode 100644
index 00000000..85af005d
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/NetworkAttributesParcelable.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+ */// Blob[] is used to represent an array of byte[], as structured AIDL does not support arrays
+// of arrays.
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
+package android.net.ipmemorystore;
+/* @hide */
+@JavaDerive(toString=true)
+parcelable NetworkAttributesParcelable {
+  byte[] assignedV4Address;
+  long assignedV4AddressExpiry;
+  String cluster;
+  android.net.ipmemorystore.Blob[] dnsAddresses;
+  int mtu;
+  @nullable android.net.networkstack.aidl.quirks.IPv6ProvisioningLossQuirkParcelable ipv6ProvisioningLossQuirk;
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/SameL3NetworkResponseParcelable.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/SameL3NetworkResponseParcelable.aidl
new file mode 100644
index 00000000..377a3ece
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/SameL3NetworkResponseParcelable.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+@JavaDerive(toString=true)
+parcelable SameL3NetworkResponseParcelable {
+  String l2Key1;
+  String l2Key2;
+  float confidence;
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/StatusParcelable.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/StatusParcelable.aidl
new file mode 100644
index 00000000..59b96cd0
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/ipmemorystore/StatusParcelable.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.ipmemorystore;
+/* @hide */
+@JavaDerive(toString=true)
+parcelable StatusParcelable {
+  int resultCode;
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/networkstack/aidl/quirks/IPv6ProvisioningLossQuirkParcelable.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/networkstack/aidl/quirks/IPv6ProvisioningLossQuirkParcelable.aidl
new file mode 100644
index 00000000..c01564b3
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/11/android/net/networkstack/aidl/quirks/IPv6ProvisioningLossQuirkParcelable.aidl
@@ -0,0 +1,39 @@
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
+package android.net.networkstack.aidl.quirks;
+@JavaDerive(toString=true)
+parcelable IPv6ProvisioningLossQuirkParcelable {
+  int detectionCount;
+  long quirkExpiry;
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/IIpMemoryStore.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/IIpMemoryStore.aidl
index 048e84cf..e2c94a26 100644
--- a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/IIpMemoryStore.aidl
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/IIpMemoryStore.aidl
@@ -43,4 +43,10 @@ interface IIpMemoryStore {
   oneway void factoryReset();
   oneway void delete(String l2Key, boolean needWipe, android.net.ipmemorystore.IOnStatusAndCountListener listener);
   oneway void deleteCluster(String cluster, boolean needWipe, android.net.ipmemorystore.IOnStatusAndCountListener listener);
+  oneway void storeNetworkEvent(String cluster, long timestamp, long expiry, int eventType, android.net.ipmemorystore.IOnStatusListener listener);
+  oneway void retrieveNetworkEventCount(String cluster, in long[] sinceTimes, in int[] eventTypes, android.net.ipmemorystore.IOnNetworkEventCountRetrievedListener listener);
+  const int NETWORK_EVENT_NUD_FAILURE_ROAM = 0;
+  const int NETWORK_EVENT_NUD_FAILURE_CONFIRM = 1;
+  const int NETWORK_EVENT_NUD_FAILURE_ORGANIC = 2;
+  const int NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED = 3;
 }
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl
new file mode 100644
index 00000000..29d7781e
--- /dev/null
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl
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
+package android.net.ipmemorystore;
+/* @hide */
+interface IOnNetworkEventCountRetrievedListener {
+  oneway void onNetworkEventCountRetrieved(in android.net.ipmemorystore.StatusParcelable status, in int[] counts);
+}
diff --git a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/NetworkAttributesParcelable.aidl b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/NetworkAttributesParcelable.aidl
index 227785df..85af005d 100644
--- a/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/NetworkAttributesParcelable.aidl
+++ b/common/networkstackclient/aidl_api/ipmemorystore-aidl-interfaces/current/android/net/ipmemorystore/NetworkAttributesParcelable.aidl
@@ -12,7 +12,8 @@
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
- */
+ */// Blob[] is used to represent an array of byte[], as structured AIDL does not support arrays
+// of arrays.
 ///////////////////////////////////////////////////////////////////////////////
 // THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
 ///////////////////////////////////////////////////////////////////////////////
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/.hash b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/.hash
new file mode 100644
index 00000000..c5e74538
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/.hash
@@ -0,0 +1 @@
+653a7f7fd2390682f0c3739b4d82d9477d1d79f9
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/DataStallReportParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/DataStallReportParcelable.aidl
new file mode 100644
index 00000000..771deda4
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/DataStallReportParcelable.aidl
@@ -0,0 +1,42 @@
+/**
+ * Copyright (c) 2020, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable DataStallReportParcelable {
+  long timestampMillis = 0;
+  int detectionMethod = 1;
+  int tcpPacketFailRate = 2;
+  int tcpMetricsCollectionPeriodMillis = 3;
+  int dnsConsecutiveTimeouts = 4;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/DhcpResultsParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/DhcpResultsParcelable.aidl
new file mode 100644
index 00000000..31f2194a
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/DhcpResultsParcelable.aidl
@@ -0,0 +1,44 @@
+/**
+ * Copyright (c) 2019, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable DhcpResultsParcelable {
+  android.net.StaticIpConfiguration baseConfiguration;
+  int leaseDuration;
+  int mtu;
+  String serverAddress;
+  String vendorInfo;
+  @nullable String serverHostName;
+  @nullable String captivePortalApiUrl;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkMonitor.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkMonitor.aidl
new file mode 100644
index 00000000..fb13c0cb
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkMonitor.aidl
@@ -0,0 +1,60 @@
+/**
+ * Copyright (c) 2018, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net;
+/* @hide */
+interface INetworkMonitor {
+  oneway void start();
+  oneway void launchCaptivePortalApp();
+  oneway void notifyCaptivePortalAppFinished(int response);
+  oneway void setAcceptPartialConnectivity();
+  oneway void forceReevaluation(int uid);
+  oneway void notifyPrivateDnsChanged(in android.net.PrivateDnsConfigParcel config);
+  oneway void notifyDnsResponse(int returnCode);
+  oneway void notifyNetworkConnected(in android.net.LinkProperties lp, in android.net.NetworkCapabilities nc);
+  oneway void notifyNetworkDisconnected();
+  oneway void notifyLinkPropertiesChanged(in android.net.LinkProperties lp);
+  oneway void notifyNetworkCapabilitiesChanged(in android.net.NetworkCapabilities nc);
+  oneway void notifyNetworkConnectedParcel(in android.net.networkstack.aidl.NetworkMonitorParameters params);
+  const int NETWORK_TEST_RESULT_VALID = 0;
+  const int NETWORK_TEST_RESULT_INVALID = 1;
+  const int NETWORK_TEST_RESULT_PARTIAL_CONNECTIVITY = 2;
+  const int NETWORK_VALIDATION_RESULT_VALID = 0x01;
+  const int NETWORK_VALIDATION_RESULT_PARTIAL = 0x02;
+  const int NETWORK_VALIDATION_RESULT_SKIPPED = 0x04;
+  const int NETWORK_VALIDATION_PROBE_DNS = 0x04;
+  const int NETWORK_VALIDATION_PROBE_HTTP = 0x08;
+  const int NETWORK_VALIDATION_PROBE_HTTPS = 0x10;
+  const int NETWORK_VALIDATION_PROBE_FALLBACK = 0x20;
+  const int NETWORK_VALIDATION_PROBE_PRIVDNS = 0x40;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkMonitorCallbacks.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkMonitorCallbacks.aidl
new file mode 100644
index 00000000..36eda8e7
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkMonitorCallbacks.aidl
@@ -0,0 +1,46 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net;
+/* @hide */
+interface INetworkMonitorCallbacks {
+  oneway void onNetworkMonitorCreated(in android.net.INetworkMonitor networkMonitor) = 0;
+  oneway void notifyNetworkTested(int testResult, @nullable String redirectUrl) = 1;
+  oneway void notifyPrivateDnsConfigResolved(in android.net.PrivateDnsConfigParcel config) = 2;
+  oneway void showProvisioningNotification(String action, String packageName) = 3;
+  oneway void hideProvisioningNotification() = 4;
+  oneway void notifyProbeStatusChanged(int probesCompleted, int probesSucceeded) = 5;
+  oneway void notifyNetworkTestedWithExtras(in android.net.NetworkTestResultParcelable result) = 6;
+  oneway void notifyDataStallSuspected(in android.net.DataStallReportParcelable report) = 7;
+  oneway void notifyCaptivePortalDataChanged(in android.net.CaptivePortalData data) = 8;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkStackConnector.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkStackConnector.aidl
new file mode 100644
index 00000000..8120ffc3
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkStackConnector.aidl
@@ -0,0 +1,42 @@
+/**
+ * Copyright (c) 2018, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net;
+/* @hide */
+interface INetworkStackConnector {
+  oneway void makeDhcpServer(in String ifName, in android.net.dhcp.DhcpServingParamsParcel params, in android.net.dhcp.IDhcpServerCallbacks cb);
+  oneway void makeNetworkMonitor(in android.net.Network network, String name, in android.net.INetworkMonitorCallbacks cb);
+  oneway void makeIpClient(in String ifName, in android.net.ip.IIpClientCallbacks callbacks);
+  oneway void fetchIpMemoryStore(in android.net.IIpMemoryStoreCallbacks cb);
+  oneway void allowTestUid(int uid, in android.net.INetworkStackStatusCallback cb);
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkStackStatusCallback.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkStackStatusCallback.aidl
new file mode 100644
index 00000000..0b6b7788
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/INetworkStackStatusCallback.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net;
+/* @hide */
+interface INetworkStackStatusCallback {
+  oneway void onStatusAvailable(int statusCode);
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/InformationElementParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/InformationElementParcelable.aidl
new file mode 100644
index 00000000..61037749
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/InformationElementParcelable.aidl
@@ -0,0 +1,39 @@
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable InformationElementParcelable {
+  int id;
+  byte[] payload;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/InitialConfigurationParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/InitialConfigurationParcelable.aidl
new file mode 100644
index 00000000..6a597e65
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/InitialConfigurationParcelable.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable InitialConfigurationParcelable {
+  android.net.LinkAddress[] ipAddresses;
+  android.net.IpPrefix[] directlyConnectedRoutes;
+  String[] dnsServers;
+  String gateway;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/Layer2InformationParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/Layer2InformationParcelable.aidl
new file mode 100644
index 00000000..83796ee8
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/Layer2InformationParcelable.aidl
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable Layer2InformationParcelable {
+  String l2Key;
+  String cluster;
+  android.net.MacAddress bssid;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/Layer2PacketParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/Layer2PacketParcelable.aidl
new file mode 100644
index 00000000..4b3fff52
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/Layer2PacketParcelable.aidl
@@ -0,0 +1,39 @@
+/**
+ * Copyright (c) 2019, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable Layer2PacketParcelable {
+  android.net.MacAddress dstMacAddress;
+  byte[] payload;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/NattKeepalivePacketDataParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/NattKeepalivePacketDataParcelable.aidl
new file mode 100644
index 00000000..18cf954a
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/NattKeepalivePacketDataParcelable.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable NattKeepalivePacketDataParcelable {
+  byte[] srcAddress;
+  int srcPort;
+  byte[] dstAddress;
+  int dstPort;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/NetworkTestResultParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/NetworkTestResultParcelable.aidl
new file mode 100644
index 00000000..4d6d5a23
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/NetworkTestResultParcelable.aidl
@@ -0,0 +1,42 @@
+/**
+ * Copyright (c) 2020, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable NetworkTestResultParcelable {
+  long timestampMillis;
+  int result;
+  int probesSucceeded;
+  int probesAttempted;
+  String redirectUrl;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/PrivateDnsConfigParcel.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/PrivateDnsConfigParcel.aidl
new file mode 100644
index 00000000..b624ee41
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/PrivateDnsConfigParcel.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net;
+@JavaDerive(equals=true, toString=true)
+parcelable PrivateDnsConfigParcel {
+  String hostname;
+  String[] ips;
+  int privateDnsMode = (-1) /* -1 */;
+  String dohName = "";
+  String[] dohIps = {};
+  String dohPath = "";
+  int dohPort = (-1) /* -1 */;
+  boolean ddrEnabled = false;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ProvisioningConfigurationParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ProvisioningConfigurationParcelable.aidl
new file mode 100644
index 00000000..0ce91f05
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ProvisioningConfigurationParcelable.aidl
@@ -0,0 +1,65 @@
+/*
+**
+** Copyright (C) 2019 The Android Open Source Project
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable ProvisioningConfigurationParcelable {
+  /**
+   * @deprecated use ipv4ProvisioningMode instead.
+   */
+  boolean enableIPv4;
+  /**
+   * @deprecated use ipv6ProvisioningMode instead.
+   */
+  boolean enableIPv6;
+  boolean usingMultinetworkPolicyTracker;
+  boolean usingIpReachabilityMonitor;
+  int requestedPreDhcpActionMs;
+  android.net.InitialConfigurationParcelable initialConfig;
+  android.net.StaticIpConfiguration staticIpConfig;
+  android.net.apf.ApfCapabilities apfCapabilities;
+  int provisioningTimeoutMs;
+  int ipv6AddrGenMode;
+  android.net.Network network;
+  String displayName;
+  boolean enablePreconnection;
+  @nullable android.net.ScanResultInfoParcelable scanResultInfo;
+  @nullable android.net.Layer2InformationParcelable layer2Info;
+  @nullable List<android.net.networkstack.aidl.dhcp.DhcpOption> options;
+  int ipv4ProvisioningMode;
+  int ipv6ProvisioningMode;
+  boolean uniqueEui64AddressesOnly;
+  int creatorUid;
+  int hostnameSetting;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ScanResultInfoParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ScanResultInfoParcelable.aidl
new file mode 100644
index 00000000..94fc27ff
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ScanResultInfoParcelable.aidl
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable ScanResultInfoParcelable {
+  String ssid;
+  String bssid;
+  android.net.InformationElementParcelable[] informationElements;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/TcpKeepalivePacketDataParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/TcpKeepalivePacketDataParcelable.aidl
new file mode 100644
index 00000000..0e1c21c9
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/TcpKeepalivePacketDataParcelable.aidl
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+package android.net;
+@JavaDerive(toString=true)
+parcelable TcpKeepalivePacketDataParcelable {
+  byte[] srcAddress;
+  int srcPort;
+  byte[] dstAddress;
+  int dstPort;
+  int seq;
+  int ack;
+  int rcvWnd;
+  int rcvWndScale;
+  int tos;
+  int ttl;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/DhcpLeaseParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/DhcpLeaseParcelable.aidl
new file mode 100644
index 00000000..3cd8860e
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/DhcpLeaseParcelable.aidl
@@ -0,0 +1,43 @@
+/**
+ * Copyright (c) 2020, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.dhcp;
+@JavaDerive(toString=true)
+parcelable DhcpLeaseParcelable {
+  byte[] clientId;
+  byte[] hwAddr;
+  int netAddr;
+  int prefixLength;
+  long expTime;
+  String hostname;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/DhcpServingParamsParcel.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/DhcpServingParamsParcel.aidl
new file mode 100644
index 00000000..7997936e
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/DhcpServingParamsParcel.aidl
@@ -0,0 +1,49 @@
+/**
+ *
+ * Copyright (C) 2018 The Android Open Source Project
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
+package android.net.dhcp;
+@JavaDerive(toString=true)
+parcelable DhcpServingParamsParcel {
+  int serverAddr;
+  int serverAddrPrefixLength;
+  int[] defaultRouters;
+  int[] dnsServers;
+  int[] excludedAddrs;
+  long dhcpLeaseTimeSecs;
+  int linkMtu;
+  boolean metered;
+  int singleClientAddr = 0;
+  boolean changePrefixOnDecline = false;
+  int leasesSubnetPrefixLength = 0;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpEventCallbacks.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpEventCallbacks.aidl
new file mode 100644
index 00000000..9312f47a
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpEventCallbacks.aidl
@@ -0,0 +1,38 @@
+/**
+ * Copyright (c) 2020, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.dhcp;
+interface IDhcpEventCallbacks {
+  oneway void onLeasesChanged(in List<android.net.dhcp.DhcpLeaseParcelable> newLeases);
+  oneway void onNewPrefixRequest(in android.net.IpPrefix currentPrefix);
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpServer.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpServer.aidl
new file mode 100644
index 00000000..1109f35f
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpServer.aidl
@@ -0,0 +1,45 @@
+/**
+ * Copyright (c) 2018, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.dhcp;
+/* @hide */
+interface IDhcpServer {
+  oneway void start(in android.net.INetworkStackStatusCallback cb) = 0;
+  oneway void startWithCallbacks(in android.net.INetworkStackStatusCallback statusCb, in android.net.dhcp.IDhcpEventCallbacks eventCb) = 3;
+  oneway void updateParams(in android.net.dhcp.DhcpServingParamsParcel params, in android.net.INetworkStackStatusCallback cb) = 1;
+  oneway void stop(in android.net.INetworkStackStatusCallback cb) = 2;
+  const int STATUS_UNKNOWN = 0;
+  const int STATUS_SUCCESS = 1;
+  const int STATUS_INVALID_ARGUMENT = 2;
+  const int STATUS_UNKNOWN_ERROR = 3;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpServerCallbacks.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpServerCallbacks.aidl
new file mode 100644
index 00000000..ab8577c6
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/dhcp/IDhcpServerCallbacks.aidl
@@ -0,0 +1,38 @@
+/**
+ * Copyright (c) 2018, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.dhcp;
+/* @hide */
+interface IDhcpServerCallbacks {
+  oneway void onDhcpServerCreated(int statusCode, in android.net.dhcp.IDhcpServer server);
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ip/IIpClient.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ip/IIpClient.aidl
new file mode 100644
index 00000000..87de4a61
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ip/IIpClient.aidl
@@ -0,0 +1,62 @@
+/**
+ * Copyright (c) 2019, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.ip;
+/* @hide */
+interface IIpClient {
+  oneway void completedPreDhcpAction();
+  oneway void confirmConfiguration();
+  oneway void readPacketFilterComplete(in byte[] data);
+  oneway void shutdown();
+  oneway void startProvisioning(in android.net.ProvisioningConfigurationParcelable req);
+  oneway void stop();
+  oneway void setTcpBufferSizes(in String tcpBufferSizes);
+  oneway void setHttpProxy(in android.net.ProxyInfo proxyInfo);
+  oneway void setMulticastFilter(boolean enabled);
+  oneway void addKeepalivePacketFilter(int slot, in android.net.TcpKeepalivePacketDataParcelable pkt);
+  oneway void removeKeepalivePacketFilter(int slot);
+  oneway void setL2KeyAndGroupHint(in String l2Key, in String cluster);
+  oneway void addNattKeepalivePacketFilter(int slot, in android.net.NattKeepalivePacketDataParcelable pkt);
+  oneway void notifyPreconnectionComplete(boolean success);
+  oneway void updateLayer2Information(in android.net.Layer2InformationParcelable info);
+  oneway void updateApfCapabilities(in android.net.apf.ApfCapabilities apfCapabilities);
+  const int PROV_IPV4_DISABLED = 0x00;
+  const int PROV_IPV4_STATIC = 0x01;
+  const int PROV_IPV4_DHCP = 0x02;
+  const int PROV_IPV6_DISABLED = 0x00;
+  const int PROV_IPV6_SLAAC = 0x01;
+  const int PROV_IPV6_LINKLOCAL = 0x02;
+  const int HOSTNAME_SETTING_UNSET = 0x00;
+  const int HOSTNAME_SETTING_SEND = 0x01;
+  const int HOSTNAME_SETTING_DO_NOT_SEND = 0x02;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ip/IIpClientCallbacks.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ip/IIpClientCallbacks.aidl
new file mode 100644
index 00000000..9d364195
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/ip/IIpClientCallbacks.aidl
@@ -0,0 +1,54 @@
+/**
+ * Copyright (c) 2019, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.ip;
+/* @hide */
+interface IIpClientCallbacks {
+  oneway void onIpClientCreated(in android.net.ip.IIpClient ipClient);
+  oneway void onPreDhcpAction();
+  oneway void onPostDhcpAction();
+  oneway void onNewDhcpResults(in android.net.DhcpResultsParcelable dhcpResults);
+  oneway void onProvisioningSuccess(in android.net.LinkProperties newLp);
+  oneway void onProvisioningFailure(in android.net.LinkProperties newLp);
+  oneway void onLinkPropertiesChange(in android.net.LinkProperties newLp);
+  oneway void onReachabilityLost(in String logMsg);
+  oneway void onQuit();
+  oneway void installPacketFilter(in byte[] filter);
+  oneway void startReadPacketFilter();
+  oneway void setFallbackMulticastFilter(boolean enabled);
+  oneway void setNeighborDiscoveryOffload(boolean enable);
+  oneway void onPreconnectionStart(in List<android.net.Layer2PacketParcelable> packets);
+  oneway void onReachabilityFailure(in android.net.networkstack.aidl.ip.ReachabilityLossInfoParcelable lossInfo);
+  oneway void setMaxDtimMultiplier(int multiplier);
+  const int DTIM_MULTIPLIER_RESET = 0;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/NetworkMonitorParameters.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/NetworkMonitorParameters.aidl
new file mode 100644
index 00000000..2ab9db06
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/NetworkMonitorParameters.aidl
@@ -0,0 +1,41 @@
+/**
+ *
+ * Copyright (C) 2022 The Android Open Source Project
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
+package android.net.networkstack.aidl;
+@JavaDerive(equals=true, toString=true)
+parcelable NetworkMonitorParameters {
+  android.net.NetworkAgentConfig networkAgentConfig;
+  android.net.NetworkCapabilities networkCapabilities;
+  android.net.LinkProperties linkProperties;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/dhcp/DhcpOption.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/dhcp/DhcpOption.aidl
new file mode 100644
index 00000000..eea3e0d6
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/dhcp/DhcpOption.aidl
@@ -0,0 +1,39 @@
+/**
+ * Copyright (c) 2020, The Android Open Source Project
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
+ * See the License for the specific language governing perNmissions and
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
+package android.net.networkstack.aidl.dhcp;
+@JavaDerive(toString=true)
+parcelable DhcpOption {
+  byte type;
+  @nullable byte[] value;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/ip/ReachabilityLossInfoParcelable.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/ip/ReachabilityLossInfoParcelable.aidl
new file mode 100644
index 00000000..bb88434b
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/ip/ReachabilityLossInfoParcelable.aidl
@@ -0,0 +1,39 @@
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
+package android.net.networkstack.aidl.ip;
+@JavaDerive(equals=true, toString=true) @JavaOnlyImmutable
+parcelable ReachabilityLossInfoParcelable {
+  String message;
+  android.net.networkstack.aidl.ip.ReachabilityLossReason reason;
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/ip/ReachabilityLossReason.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/ip/ReachabilityLossReason.aidl
new file mode 100644
index 00000000..f9bb3c4a
--- /dev/null
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/22/android/net/networkstack/aidl/ip/ReachabilityLossReason.aidl
@@ -0,0 +1,40 @@
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
+package android.net.networkstack.aidl.ip;
+@Backing(type="int")
+enum ReachabilityLossReason {
+  ROAM,
+  CONFIRM,
+  ORGANIC,
+}
diff --git a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/current/android/net/PrivateDnsConfigParcel.aidl b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/current/android/net/PrivateDnsConfigParcel.aidl
index ab62fe77..b624ee41 100644
--- a/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/current/android/net/PrivateDnsConfigParcel.aidl
+++ b/common/networkstackclient/aidl_api/networkstack-aidl-interfaces/current/android/net/PrivateDnsConfigParcel.aidl
@@ -41,4 +41,5 @@ parcelable PrivateDnsConfigParcel {
   String[] dohIps = {};
   String dohPath = "";
   int dohPort = (-1) /* -1 */;
+  boolean ddrEnabled = false;
 }
diff --git a/common/networkstackclient/src/android/net/IIpMemoryStore.aidl b/common/networkstackclient/src/android/net/IIpMemoryStore.aidl
index 3bb58bff..e294f54a 100644
--- a/common/networkstackclient/src/android/net/IIpMemoryStore.aidl
+++ b/common/networkstackclient/src/android/net/IIpMemoryStore.aidl
@@ -21,6 +21,7 @@ import android.net.ipmemorystore.NetworkAttributesParcelable;
 import android.net.ipmemorystore.IOnBlobRetrievedListener;
 import android.net.ipmemorystore.IOnL2KeyResponseListener;
 import android.net.ipmemorystore.IOnNetworkAttributesRetrievedListener;
+import android.net.ipmemorystore.IOnNetworkEventCountRetrievedListener;
 import android.net.ipmemorystore.IOnSameL3NetworkResponseListener;
 import android.net.ipmemorystore.IOnStatusAndCountListener;
 import android.net.ipmemorystore.IOnStatusListener;
@@ -152,4 +153,48 @@ oneway interface IIpMemoryStore {
      * @return (through the listener) A status to indicate success and the number of deleted records
      */
     void deleteCluster(String cluster, boolean needWipe, IOnStatusAndCountListener listener);
+
+    /**
+     * The network event types related to Neighbor Unreachability Detection(NUD) probe failure
+     * including probe fails due to L2 roam, low Wi-Fi RSSI checks, periodic kernel organic checks,
+     * or a neighbor's MAC address changing during a probe.
+     */
+    const int NETWORK_EVENT_NUD_FAILURE_ROAM = 0;
+    const int NETWORK_EVENT_NUD_FAILURE_CONFIRM = 1;
+    const int NETWORK_EVENT_NUD_FAILURE_ORGANIC = 2;
+    const int NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED = 3;
+
+    /**
+     * Store a specific network event to database for a given cluster.
+     *
+     * @param cluster The cluster representing a notion of network group (e.g., BSSIDs with the
+     *                same SSID).
+     * @param timestamp The timestamp {@link System.currentTimeMillis} when a specific network
+     *                  event occurred.
+     * @param expiry The timestamp {@link System.currentTimeMillis} when a specific network
+     *               event stored in the database expires, e.g. it might be one week from now.
+     * @param eventType One of the NETWORK_EVENT constants above.
+     * @param listener A listener that will be invoked to inform of the completion of this call.
+     * @return (through the listener) A status to indicate success or failure.
+     */
+    void storeNetworkEvent(String cluster, long timestamp, long expiry, int eventType,
+            IOnStatusListener listener);
+
+    /**
+     * Retrieve the specific network event counts for a given cluster and event type since one or
+     * more timestamps in the past.
+     *
+     * @param cluster The cluster to query.
+     * @param sinceTimes An array of timestamps in the past. The query will return an array of
+     *                   equal size. Each element in the array will contain the number of network
+     *                   events between the corresponding timestamp and the current time, e.g. query
+     *                   since the last week and/or the last day.
+     * @param eventTypes An array of network event types to query, which can be one or more of the
+     *                   above NETWORK_EVENT constants.
+     * @param listener The listener that will be invoked to return the answer.
+     * @return (through the listener) The event counts associated with the query, or an empty array
+     *                                if the query failed.
+     */
+    void retrieveNetworkEventCount(String cluster, in long[] sinceTimes, in int[] eventTypes,
+            IOnNetworkEventCountRetrievedListener listener);
 }
diff --git a/common/networkstackclient/src/android/net/IpMemoryStoreClient.java b/common/networkstackclient/src/android/net/IpMemoryStoreClient.java
index a1c56941..8b931248 100644
--- a/common/networkstackclient/src/android/net/IpMemoryStoreClient.java
+++ b/common/networkstackclient/src/android/net/IpMemoryStoreClient.java
@@ -25,6 +25,7 @@ import android.net.ipmemorystore.OnBlobRetrievedListener;
 import android.net.ipmemorystore.OnDeleteStatusListener;
 import android.net.ipmemorystore.OnL2KeyResponseListener;
 import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener;
+import android.net.ipmemorystore.OnNetworkEventCountRetrievedListener;
 import android.net.ipmemorystore.OnSameL3NetworkResponseListener;
 import android.net.ipmemorystore.OnStatusListener;
 import android.net.ipmemorystore.Status;
@@ -289,4 +290,64 @@ public abstract class IpMemoryStoreClient {
             Log.e(TAG, "Error executing factory reset", m);
         }
     }
+
+    /**
+     * Retrieve the specific network event counts for a given cluster and event type since one or
+     * more timestamps in the past.
+     *
+     * @param cluster The cluster to query.
+     * @param sinceTimes An array of timestamps in the past. The query will return an array of
+     *                   equal size. Each element in the array will contain the number of network
+     *                   events between the corresponding timestamp and the current time, e.g. query
+     *                   since the last week and/or the last day.
+     * @param eventTypes An array of network event types to query, which can be one or more of the
+     *                   above NETWORK_EVENT constants.
+     * @param listener The listener that will be invoked to return the answer.
+     * returns (through the listener) The event counts associated with the query, or an empty array
+     *                                if the query failed.
+     */
+    public void retrieveNetworkEventCount(@NonNull final String cluster,
+            @NonNull final long[] sinceTimes,
+            @NonNull final int[] eventTypes,
+            @Nullable final OnNetworkEventCountRetrievedListener listener) {
+        try {
+            runWhenServiceReady(service -> ignoringRemoteException(
+                    () -> service.retrieveNetworkEventCount(cluster, sinceTimes, eventTypes,
+                            OnNetworkEventCountRetrievedListener.toAIDL(listener))));
+        } catch (ExecutionException m) {
+            ignoringRemoteException("Error retrieving network event count",
+                    () -> listener.onNetworkEventCountRetrieved(
+                            new Status(Status.ERROR_UNKNOWN),
+                            new int[0]) /* empty counts */);
+        }
+    }
+
+    /**
+     * Store a specific network event to database for a given cluster.
+     *
+     * @param cluster The cluster representing a notion of network group (e.g., BSSIDs with the
+     *                same SSID).
+     * @param timestamp The timestamp {@link System.currentTimeMillis} when a specific network
+     *                  event occurred.
+     * @param expiry The timestamp {@link System.currentTimeMillis} when a specific network
+     *               event stored in the database expires, e.g. it might be one week from now.
+     * @param eventType One of the NETWORK_EVENT constants above.
+     * @param listener A listener that will be invoked to inform of the completion of this call.
+     * returns (through the listener) A status to indicate success or failure.
+     */
+    public void storeNetworkEvent(@NonNull final String cluster,
+            final long timestamp,
+            final long expiry,
+            final int eventType,
+            @Nullable final OnStatusListener listener) {
+        try {
+            runWhenServiceReady(service -> ignoringRemoteException(
+                    () -> service.storeNetworkEvent(cluster, timestamp, expiry, eventType,
+                            OnStatusListener.toAIDL(listener))));
+        } catch (ExecutionException m) {
+            if (null == listener) return;
+            ignoringRemoteException("Error storing network event",
+                    () -> listener.onComplete(new Status(Status.ERROR_UNKNOWN)));
+        }
+    }
 }
diff --git a/common/networkstackclient/src/android/net/PrivateDnsConfigParcel.aidl b/common/networkstackclient/src/android/net/PrivateDnsConfigParcel.aidl
index e747d617..2b4bc3f5 100644
--- a/common/networkstackclient/src/android/net/PrivateDnsConfigParcel.aidl
+++ b/common/networkstackclient/src/android/net/PrivateDnsConfigParcel.aidl
@@ -72,4 +72,12 @@ parcelable PrivateDnsConfigParcel {
      * The port used to reach the DoH servers.
      */
     int dohPort = -1;
+
+    /**
+     * Whether DDR discovery is enabled. If DDR is enabled, DoH servers will only be discovered
+     * using DDR. If DDR is not enabled, DoH servers will only be discovered using the list of
+     * known providers hardcoded in DnsResolver.
+     */
+    boolean ddrEnabled = false;
+
 }
diff --git a/common/networkstackclient/src/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl b/common/networkstackclient/src/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl
new file mode 100644
index 00000000..b5ef0a1c
--- /dev/null
+++ b/common/networkstackclient/src/android/net/ipmemorystore/IOnNetworkEventCountRetrievedListener.aidl
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
+package android.net.ipmemorystore;
+
+import android.net.ipmemorystore.StatusParcelable;
+
+/**
+ * A listener for the IpMemoryStore to return the counts of network event that matches the query.
+ * {@hide}
+ */
+oneway interface IOnNetworkEventCountRetrievedListener {
+    /**
+     * The network event counts were fetched for a specified cluster and network event types
+     * (IIpMemoryStore#NETWORK_EVENT_* constants) since one or more timestamps in the past.
+     *
+     * See {@link IIpMemoryStore#retrieveNetworkEventCount} parameter description for more details.
+     */
+    void onNetworkEventCountRetrieved(in StatusParcelable status, in int[] counts);
+}
diff --git a/common/networkstackclient/src/android/net/ipmemorystore/OnNetworkEventCountRetrievedListener.java b/common/networkstackclient/src/android/net/ipmemorystore/OnNetworkEventCountRetrievedListener.java
new file mode 100644
index 00000000..1c301504
--- /dev/null
+++ b/common/networkstackclient/src/android/net/ipmemorystore/OnNetworkEventCountRetrievedListener.java
@@ -0,0 +1,57 @@
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
+package android.net.ipmemorystore;
+
+import android.annotation.NonNull;
+
+/**
+ * A listener for the IpMemoryStore to return specific network event counts.
+ * @hide
+ */
+public interface OnNetworkEventCountRetrievedListener {
+    /**
+     * The memory store has come up with the answer to a query that was sent.
+     */
+    void onNetworkEventCountRetrieved(Status status, int[] counts);
+
+    /** Converts this OnNetworkEventCountRetrievedListener to a parcelable object */
+    @NonNull
+    static IOnNetworkEventCountRetrievedListener toAIDL(
+            @NonNull final OnNetworkEventCountRetrievedListener listener) {
+        return new IOnNetworkEventCountRetrievedListener.Stub() {
+            @Override
+            public void onNetworkEventCountRetrieved(
+                    final StatusParcelable statusParcelable,
+                    final int[] counts) {
+                // NonNull, but still don't crash the system server if null
+                if (null != listener) {
+                    listener.onNetworkEventCountRetrieved(new Status(statusParcelable), counts);
+                }
+            }
+
+            @Override
+            public int getInterfaceVersion() {
+                return this.VERSION;
+            }
+
+            @Override
+            public String getInterfaceHash() {
+                return this.HASH;
+            }
+        };
+    }
+}
diff --git a/common/networkstackclient/src/android/net/shared/PrivateDnsConfig.java b/common/networkstackclient/src/android/net/shared/PrivateDnsConfig.java
index 632d1d62..9752bae3 100644
--- a/common/networkstackclient/src/android/net/shared/PrivateDnsConfig.java
+++ b/common/networkstackclient/src/android/net/shared/PrivateDnsConfig.java
@@ -41,6 +41,12 @@ public class PrivateDnsConfig {
     @NonNull
     public final InetAddress[] ips;
 
+    // Whether DDR discovery is enabled.
+    // If DDR is enabled, then empty dohName / dohIps indicate that DoH is disabled.
+    // If DDR is disabled, then empty dohName / dohIps indicate that DNS resolver should attempt to
+    // enable DoH based on using its hardcoded list of known providers.
+    public final boolean ddrEnabled;
+
     // These fields store the DoH information discovered from SVCB lookups.
     @NonNull
     public final String dohName;
@@ -67,8 +73,8 @@ public class PrivateDnsConfig {
      */
     public PrivateDnsConfig(boolean useTls) {
         this(useTls ? PRIVATE_DNS_MODE_OPPORTUNISTIC : PRIVATE_DNS_MODE_OFF, null /* hostname */,
-                null /* ips */, null /* dohName */, null /* dohIps */, null /* dohPath */,
-                -1 /* dohPort */);
+                null /* ips */, false /* ddrEnabled */, null /* dohName */, null /* dohIps */,
+                null /* dohPath */, -1 /* dohPort */);
     }
 
     /**
@@ -78,8 +84,8 @@ public class PrivateDnsConfig {
      */
     public PrivateDnsConfig(@Nullable String hostname, @Nullable InetAddress[] ips) {
         this(TextUtils.isEmpty(hostname) ? PRIVATE_DNS_MODE_OFF :
-                PRIVATE_DNS_MODE_PROVIDER_HOSTNAME, hostname, ips, null /* dohName */,
-                null /* dohIps */, null /* dohPath */, -1 /* dohPort */);
+                PRIVATE_DNS_MODE_PROVIDER_HOSTNAME, hostname, ips, false /* ddrEnabled */,
+                null /* dohName */, null /* dohIps */, null /* dohPath */, -1 /* dohPort */);
     }
 
     /**
@@ -88,11 +94,12 @@ public class PrivateDnsConfig {
      * and empty arrays as equivalent.
      */
     public PrivateDnsConfig(int mode, @Nullable String hostname, @Nullable InetAddress[] ips,
-            @Nullable String dohName, @Nullable InetAddress[] dohIps, @Nullable String dohPath,
-            int dohPort) {
+            boolean ddrEnabled,  @Nullable String dohName, @Nullable InetAddress[] dohIps,
+            @Nullable String dohPath, int dohPort) {
         this.mode = mode;
         this.hostname = (hostname != null) ? hostname : "";
         this.ips = (ips != null) ? ips.clone() : new InetAddress[0];
+        this.ddrEnabled = ddrEnabled;
         this.dohName = (dohName != null) ? dohName : "";
         this.dohIps = (dohIps != null) ? dohIps.clone() : new InetAddress[0];
         this.dohPath = (dohPath != null) ? dohPath : "";
@@ -103,6 +110,7 @@ public class PrivateDnsConfig {
         mode = cfg.mode;
         hostname = cfg.hostname;
         ips = cfg.ips;
+        ddrEnabled = cfg.ddrEnabled;
         dohName = cfg.dohName;
         dohIps = cfg.dohIps;
         dohPath = cfg.dohPath;
@@ -123,6 +131,13 @@ public class PrivateDnsConfig {
         return mode == PRIVATE_DNS_MODE_OPPORTUNISTIC;
     }
 
+    /**
+     * Returns whether the fields related to private DNS settings are the same.
+     */
+    public boolean areSettingsSameAs(PrivateDnsConfig other) {
+        return mode == other.mode && TextUtils.equals(hostname, other.hostname);
+    }
+
     @Override
     public String toString() {
         return PrivateDnsConfig.class.getSimpleName()
@@ -158,6 +173,7 @@ public class PrivateDnsConfig {
                 Arrays.asList(dohIps), IpConfigurationParcelableUtil::parcelAddress, String.class);
         parcel.dohPath = dohPath;
         parcel.dohPort = dohPort;
+        parcel.ddrEnabled = ddrEnabled;
         return parcel;
     }
 
@@ -187,7 +203,7 @@ public class PrivateDnsConfig {
         InetAddress[] dohIps = new InetAddress[parcel.dohIps.length];
         dohIps = fromParcelableArray(parcel.dohIps,
                 IpConfigurationParcelableUtil::unparcelAddress).toArray(dohIps);
-        return new PrivateDnsConfig(parcel.privateDnsMode, parcel.hostname, ips, parcel.dohName,
-                dohIps, parcel.dohPath, parcel.dohPort);
+        return new PrivateDnsConfig(parcel.privateDnsMode, parcel.hostname, ips,
+                parcel.ddrEnabled, parcel.dohName, dohIps, parcel.dohPath, parcel.dohPort);
     }
 }
diff --git a/proguard.flags b/proguard.flags
index 511a6b3f..5a96d5a1 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -1,4 +1,4 @@
--keepclassmembers class com.android.networkstack.android.net.ip.IpClient {
+-keepclassmembers class com.android.networkstack.android.net.ip.IpClient$IpClientCommands {
     static final int CMD_*;
     static final int EVENT_*;
 }
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index b99fab88..83da635c 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -21,6 +21,6 @@
     <string name="notification_channel_name_network_venue_info" msgid="6526543187249265733">"Información sobre el lugar de la red"</string>
     <string name="notification_channel_description_network_venue_info" msgid="5131499595382733605">"Notificaciones que se muestran para indicar que la red tiene una página de información sobre el lugar"</string>
     <string name="connected" msgid="4563643884927480998">"Conectado"</string>
-    <string name="tap_for_info" msgid="6849746325626883711">"Conectado: toca para ver el sitio web"</string>
+    <string name="tap_for_info" msgid="6849746325626883711">"Te has conectado: toca para ver el sitio web"</string>
     <string name="application_label" msgid="1322847171305285454">"Administrador de redes"</string>
 </resources>
diff --git a/src/android/net/apf/AndroidPacketFilter.java b/src/android/net/apf/AndroidPacketFilter.java
index 8c7ff05f..c88587b3 100644
--- a/src/android/net/apf/AndroidPacketFilter.java
+++ b/src/android/net/apf/AndroidPacketFilter.java
@@ -15,7 +15,6 @@
  */
 package android.net.apf;
 
-import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.net.LinkProperties;
 import android.net.NattKeepalivePacketDataParcelable;
@@ -104,7 +103,21 @@ public interface AndroidPacketFilter {
      * Determines whether the APF interpreter advertises support for the data buffer access
      * opcodes LDDW (LoaD Data Word) and STDW (STore Data Word).
      */
-    default boolean hasDataAccess(@NonNull ApfCapabilities capabilities) {
-        return capabilities.apfVersionSupported > 2;
+    default boolean hasDataAccess(int apfVersionSupported) {
+        return apfVersionSupported > 2;
+    }
+
+    /**
+     * Whether the ApfFilter supports generating ND offload code.
+     */
+    default boolean supportNdOffload() {
+        return false;
+    }
+
+    /**
+     * Return if the ApfFilter should enable mDNS offload.
+     */
+    default boolean shouldEnableMdnsOffload() {
+        return false;
     }
 }
diff --git a/src/android/net/apf/ApfConstants.java b/src/android/net/apf/ApfConstants.java
index fe2cfd87..a23e9705 100644
--- a/src/android/net/apf/ApfConstants.java
+++ b/src/android/net/apf/ApfConstants.java
@@ -65,7 +65,42 @@ public final class ApfConstants {
     public static final int ICMP6_CHECKSUM_OFFSET = ETH_HEADER_LEN + IPV6_HEADER_LEN + 2;
     public static final int ICMP6_NS_TARGET_IP_OFFSET = ICMP6_TYPE_OFFSET + 8;
     public static final int ICMP6_NS_OPTION_TYPE_OFFSET = ICMP6_NS_TARGET_IP_OFFSET + 16;
+    // From RFC4861:
+    public static final int ICMP6_RA_HEADER_LEN = 16;
+    public static final int ICMP6_RA_CHECKSUM_OFFSET =
+            ETH_HEADER_LEN + IPV6_HEADER_LEN + 2;
+    public static final int ICMP6_RA_CHECKSUM_LEN = 2;
+    public static final int ICMP6_RA_OPTION_OFFSET =
+            ETH_HEADER_LEN + IPV6_HEADER_LEN + ICMP6_RA_HEADER_LEN;
+    public static final int ICMP6_RA_ROUTER_LIFETIME_OFFSET =
+            ETH_HEADER_LEN + IPV6_HEADER_LEN + 6;
+    public static final int ICMP6_RA_ROUTER_LIFETIME_LEN = 2;
+    // Prefix information option.
+    public static final int ICMP6_PREFIX_OPTION_TYPE = 3;
+    public static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET = 4;
+    public static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN = 4;
+    public static final int ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN = 4;
 
+    // From RFC4861: source link-layer address
+    public static final int ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE = 1;
+    // From RFC4861: mtu size option
+    public static final int ICMP6_MTU_OPTION_TYPE = 5;
+    // From RFC6106: Recursive DNS Server option
+    public static final int ICMP6_RDNSS_OPTION_TYPE = 25;
+    // From RFC5175: RA Flags Extension option
+    public static final int ICMP6_RA_FLAGS_EXTENSION_OPTION_TYPE = 26;
+    // From RFC6106: DNS Search List option
+    public static final int ICMP6_DNSSL_OPTION_TYPE = 31;
+    // From RFC8910: Captive-Portal option
+    public static final int ICMP6_CAPTIVE_PORTAL_OPTION_TYPE = 37;
+    // From RFC8781: PREF64 option
+    public static final int ICMP6_PREF64_OPTION_TYPE = 38;
+
+    // From RFC4191: Route Information option
+    public static final int ICMP6_ROUTE_INFO_OPTION_TYPE = 24;
+    // Above three options all have the same format:
+    public static final int ICMP6_4_BYTE_LIFETIME_OFFSET = 4;
+    public static final int ICMP6_4_BYTE_LIFETIME_LEN = 4;
     public static final int IPPROTO_HOPOPTS = 0;
 
     // NOTE: this must be added to the IPv4 header length in MemorySlot.IPV4_HEADER_SIZE
diff --git a/src/android/net/apf/ApfCounterTracker.java b/src/android/net/apf/ApfCounterTracker.java
index e86aab1f..9700b5bc 100644
--- a/src/android/net/apf/ApfCounterTracker.java
+++ b/src/android/net/apf/ApfCounterTracker.java
@@ -50,6 +50,7 @@ public class ApfCounterTracker {
         APF_VERSION,
         APF_PROGRAM_ID,
         // TODO: removing PASSED_ARP after remove LegacyApfFilter.java
+        // The counter sequence should keep the same as ApfSessionInfoMetrics.java
         PASSED_ARP,  // see also MIN_PASS_COUNTER below.
         PASSED_ARP_BROADCAST_REPLY,
         // TODO: removing PASSED_ARP_NON_IPV4 after remove LegacyApfFilter.java
@@ -58,13 +59,16 @@ public class ApfCounterTracker {
         PASSED_ARP_UNICAST_REPLY,
         PASSED_ARP_UNKNOWN,
         PASSED_DHCP,
+        PASSED_ETHER_OUR_SRC_MAC,
         PASSED_IPV4,
         PASSED_IPV4_FROM_DHCPV4_SERVER,
         PASSED_IPV4_UNICAST,
         PASSED_IPV6_ICMP,
         PASSED_IPV6_NON_ICMP,
-        PASSED_IPV6_NS_MULTIPLE_OPTIONS,
+        PASSED_IPV6_NS_DAD,
         PASSED_IPV6_NS_NO_ADDRESS,
+        PASSED_IPV6_NS_NO_SLLA_OPTION,
+        PASSED_IPV6_NS_TENTATIVE,
         PASSED_IPV6_UNICAST_NON_ICMP,
         PASSED_NON_IP_UNICAST,
         PASSED_MDNS,
@@ -83,6 +87,7 @@ public class ApfCounterTracker {
         DROPPED_IPV6_NON_ICMP_MULTICAST,
         DROPPED_IPV6_NS_INVALID,
         DROPPED_IPV6_NS_OTHER_HOST,
+        DROPPED_IPV6_NS_REPLIED_NON_DAD,
         DROPPED_802_3_FRAME,
         DROPPED_ETHERTYPE_NOT_ALLOWED,
         DROPPED_IPV4_KEEPALIVE_ACK,
@@ -199,7 +204,7 @@ public class ApfCounterTracker {
                 value = 0;
             }
             long oldValue = mCounters.getOrDefault(counter, 0L);
-            // All counters are increamental
+            // All counters are incremental
             if (value > oldValue) {
                 mCounters.put(counter, value);
             }
@@ -212,4 +217,11 @@ public class ApfCounterTracker {
     public Map<Counter, Long> getCounters() {
         return mCounters;
     }
+
+    /**
+     * Clear all counters.
+     */
+    public void clearCounters() {
+        mCounters.clear();
+    }
 }
diff --git a/src/android/net/apf/ApfFilter.java b/src/android/net/apf/ApfFilter.java
index c877fc68..90bd8324 100644
--- a/src/android/net/apf/ApfFilter.java
+++ b/src/android/net/apf/ApfFilter.java
@@ -36,10 +36,29 @@ import static android.net.apf.ApfConstants.ETH_MULTICAST_MDNS_V6_MAC_ADDRESS;
 import static android.net.apf.ApfConstants.ETH_TYPE_MAX;
 import static android.net.apf.ApfConstants.ETH_TYPE_MIN;
 import static android.net.apf.ApfConstants.FIXED_ARP_REPLY_HEADER;
+import static android.net.apf.ApfConstants.ICMP6_4_BYTE_LIFETIME_LEN;
+import static android.net.apf.ApfConstants.ICMP6_4_BYTE_LIFETIME_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_CAPTIVE_PORTAL_OPTION_TYPE;
 import static android.net.apf.ApfConstants.ICMP6_CHECKSUM_OFFSET;
 import static android.net.apf.ApfConstants.ICMP6_CODE_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_DNSSL_OPTION_TYPE;
+import static android.net.apf.ApfConstants.ICMP6_MTU_OPTION_TYPE;
 import static android.net.apf.ApfConstants.ICMP6_NS_OPTION_TYPE_OFFSET;
 import static android.net.apf.ApfConstants.ICMP6_NS_TARGET_IP_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_PREF64_OPTION_TYPE;
+import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN;
+import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_TYPE;
+import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN;
+import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_RA_CHECKSUM_LEN;
+import static android.net.apf.ApfConstants.ICMP6_RA_CHECKSUM_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_RA_FLAGS_EXTENSION_OPTION_TYPE;
+import static android.net.apf.ApfConstants.ICMP6_RA_OPTION_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_RA_ROUTER_LIFETIME_LEN;
+import static android.net.apf.ApfConstants.ICMP6_RA_ROUTER_LIFETIME_OFFSET;
+import static android.net.apf.ApfConstants.ICMP6_RDNSS_OPTION_TYPE;
+import static android.net.apf.ApfConstants.ICMP6_ROUTE_INFO_OPTION_TYPE;
+import static android.net.apf.ApfConstants.ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE;
 import static android.net.apf.ApfConstants.ICMP6_TYPE_OFFSET;
 import static android.net.apf.ApfConstants.IPPROTO_HOPOPTS;
 import static android.net.apf.ApfConstants.IPV4_ANY_HOST_ADDRESS;
@@ -60,22 +79,29 @@ import static android.net.apf.ApfConstants.IPV6_NEXT_HEADER_OFFSET;
 import static android.net.apf.ApfConstants.IPV6_PAYLOAD_LEN_OFFSET;
 import static android.net.apf.ApfConstants.IPV6_SOLICITED_NODES_PREFIX;
 import static android.net.apf.ApfConstants.IPV6_SRC_ADDR_OFFSET;
+import static android.net.apf.ApfConstants.IPV6_UNSPECIFIED_ADDRESS;
 import static android.net.apf.ApfConstants.MDNS_PORT;
 import static android.net.apf.ApfConstants.TCP_HEADER_SIZE_OFFSET;
 import static android.net.apf.ApfConstants.TCP_UDP_DESTINATION_PORT_OFFSET;
 import static android.net.apf.ApfConstants.TCP_UDP_SOURCE_PORT_OFFSET;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID;
 import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST;
-import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_MULTIPLE_OPTIONS;
+import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_16384THS;
+import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_SECONDS;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ETHER_OUR_SRC_MAC;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE;
 import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS;
 import static android.net.apf.BaseApfGenerator.MemorySlot;
 import static android.net.apf.BaseApfGenerator.Register.R0;
 import static android.net.apf.BaseApfGenerator.Register.R1;
+import static android.net.nsd.OffloadEngine.OFFLOAD_CAPABILITY_BYPASS_MULTICAST_LOCK;
+import static android.net.nsd.OffloadEngine.OFFLOAD_TYPE_REPLY;
 import static android.net.util.SocketUtils.makePacketSocketAddress;
 import static android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED;
 import static android.os.PowerManager.ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED;
 import static android.system.OsConstants.AF_PACKET;
-import static android.system.OsConstants.ARPHRD_ETHER;
 import static android.system.OsConstants.ETH_P_ARP;
 import static android.system.OsConstants.ETH_P_IP;
 import static android.system.OsConstants.ETH_P_IPV6;
@@ -84,6 +110,7 @@ import static android.system.OsConstants.IPPROTO_ICMPV6;
 import static android.system.OsConstants.IPPROTO_TCP;
 import static android.system.OsConstants.IPPROTO_UDP;
 import static android.system.OsConstants.SOCK_CLOEXEC;
+import static android.system.OsConstants.SOCK_NONBLOCK;
 import static android.system.OsConstants.SOCK_RAW;
 
 import static com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN;
@@ -92,6 +119,7 @@ import static com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN
 import static com.android.net.module.util.NetworkStackConstants.ETHER_SRC_ADDR_OFFSET;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQUEST_TYPE;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NA_HEADER_LEN;
+import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_SLLA;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_TLLA;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_TLLA_LEN;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NEIGHBOR_ADVERTISEMENT;
@@ -101,8 +129,10 @@ import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_SO
 import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_LEN;
 import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_LEN;
 
+import android.annotation.ChecksSdkIntAtLeast;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.annotation.RequiresApi;
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
@@ -115,6 +145,11 @@ import android.net.TcpKeepalivePacketDataParcelable;
 import android.net.apf.ApfCounterTracker.Counter;
 import android.net.apf.BaseApfGenerator.IllegalInstructionException;
 import android.net.ip.IpClient.IpClientCallbacksWrapper;
+import android.net.nsd.NsdManager;
+import android.net.nsd.OffloadEngine;
+import android.net.nsd.OffloadServiceInfo;
+import android.os.Build;
+import android.os.Handler;
 import android.os.PowerManager;
 import android.os.SystemClock;
 import android.stats.connectivity.NetworkQuirkEvent;
@@ -135,14 +170,13 @@ import com.android.modules.utils.build.SdkLevel;
 import com.android.net.module.util.CollectionUtils;
 import com.android.net.module.util.ConnectivityUtils;
 import com.android.net.module.util.InterfaceParams;
-import com.android.net.module.util.SocketUtils;
+import com.android.net.module.util.PacketReader;
 import com.android.networkstack.metrics.ApfSessionInfoMetrics;
 import com.android.networkstack.metrics.IpClientRaInfoMetrics;
 import com.android.networkstack.metrics.NetworkQuirkMetrics;
 import com.android.networkstack.util.NetworkStackUtils;
 
 import java.io.FileDescriptor;
-import java.io.IOException;
 import java.net.Inet4Address;
 import java.net.Inet6Address;
 import java.net.InetAddress;
@@ -163,16 +197,8 @@ import java.util.Set;
  * listens for IPv6 ICMPv6 router advertisements (RAs) and generates APF programs to
  * filter out redundant duplicate ones.
  * <p>
- * Threading model:
- * A collection of RAs we've received is kept in mRas. Generating APF programs uses mRas to
- * know what RAs to filter for, thus generating APF programs is dependent on mRas.
- * mRas can be accessed by multiple threads:
- * - ReceiveThread, which listens for RAs and adds them to mRas, and generates APF programs.
- * - callers of:
- *    - setMulticastFilter(), which can cause an APF program to be generated.
- *    - dump(), which dumps mRas among other things.
- *    - shutdown(), which clears mRas.
- * So access to mRas is synchronized.
+ * Threading model: this class is not thread-safe and can only be accessed from IpClient's
+ * handler thread.
  *
  * @hide
  */
@@ -180,60 +206,39 @@ public class ApfFilter implements AndroidPacketFilter {
 
     // Helper class for specifying functional filter parameters.
     public static class ApfConfiguration {
-        public ApfCapabilities apfCapabilities;
+        public int apfVersionSupported;
+        public int apfRamSize;
         public int installableProgramSizeClamp = Integer.MAX_VALUE;
         public boolean multicastFilter;
         public boolean ieee802_3Filter;
         public int[] ethTypeBlackList;
         public int minRdnssLifetimeSec;
         public int acceptRaMinLft;
-        public boolean shouldHandleLightDoze;
         public long minMetricsSessionDurationMs;
         public boolean hasClatInterface;
         public boolean shouldHandleArpOffload;
+        public boolean shouldHandleNdOffload;
+        public boolean shouldHandleMdnsOffload;
     }
 
-    /** A wrapper class of {@link SystemClock} to be mocked in unit tests. */
-    public static class Clock {
-        /**
-         * @see SystemClock#elapsedRealtime
-         */
-        public long elapsedRealtime() {
-            return SystemClock.elapsedRealtime();
-        }
-    }
-
-    // Thread to listen for RAs.
-    @VisibleForTesting
-    public class ReceiveThread extends Thread {
-        private final byte[] mPacket = new byte[1514];
-        private final FileDescriptor mSocket;
 
-        private volatile boolean mStopped;
+    private class RaPacketReader extends PacketReader {
+        private static final int RECEIVE_BUFFER_SIZE = 1514;
+        private final int mIfIndex;
 
-        public ReceiveThread(FileDescriptor socket) {
-            mSocket = socket;
+        RaPacketReader(Handler handler, int ifIndex) {
+            super(handler, RECEIVE_BUFFER_SIZE);
+            mIfIndex = ifIndex;
         }
 
-        public void halt() {
-            mStopped = true;
-            // Interrupts the read() call the thread is blocked in.
-            SocketUtils.closeSocketQuietly(mSocket);
+        @Override
+        protected FileDescriptor createFd() {
+            return mDependencies.createPacketReaderSocket(mIfIndex);
         }
 
         @Override
-        public void run() {
-            log("begin monitoring");
-            while (!mStopped) {
-                try {
-                    int length = Os.read(mSocket, mPacket, 0, mPacket.length);
-                    processRa(mPacket, length);
-                } catch (IOException|ErrnoException e) {
-                    if (!mStopped) {
-                        Log.e(TAG, "Read error", e);
-                    }
-                }
-            }
+        protected void handlePacket(byte[] recvbuf, int length) {
+            processRa(recvbuf, length);
         }
     }
 
@@ -241,17 +246,20 @@ public class ApfFilter implements AndroidPacketFilter {
     private static final boolean DBG = true;
     private static final boolean VDBG = false;
 
-    private final ApfCapabilities mApfCapabilities;
+    private final int mApfRamSize;
+    private final int mMaximumApfProgramSize;
     private final int mInstallableProgramSizeClamp;
     private final IpClientCallbacksWrapper mIpClientCallback;
     private final InterfaceParams mInterfaceParams;
     private final TokenBucket mTokenBucket;
 
     @VisibleForTesting
-    @NonNull
-    public byte[] mHardwareAddress;
+    public final int mApfVersionSupported;
     @VisibleForTesting
-    public ReceiveThread mReceiveThread;
+    @NonNull
+    public final byte[] mHardwareAddress;
+    private final RaPacketReader mRaPacketReader;
+    private final Handler mHandler;
     @GuardedBy("this")
     private long mUniqueCounter;
     @GuardedBy("this")
@@ -261,7 +269,6 @@ public class ApfFilter implements AndroidPacketFilter {
     private final boolean mDrop802_3Frames;
     private final int[] mEthTypeBlackList;
 
-    private final Clock mClock;
     private final ApfCounterTracker mApfCounterTracker = new ApfCounterTracker();
     @GuardedBy("this")
     private final long mSessionStartMs;
@@ -287,12 +294,17 @@ public class ApfFilter implements AndroidPacketFilter {
     // Tracks the value of /proc/sys/ipv6/conf/$iface/accept_ra_min_lft which affects router, RIO,
     // and PIO valid lifetimes.
     private final int mAcceptRaMinLft;
-    private final boolean mShouldHandleLightDoze;
     private final boolean mShouldHandleArpOffload;
+    private final boolean mShouldHandleNdOffload;
+    private final boolean mShouldHandleMdnsOffload;
 
     private final NetworkQuirkMetrics mNetworkQuirkMetrics;
     private final IpClientRaInfoMetrics mIpClientRaInfoMetrics;
     private final ApfSessionInfoMetrics mApfSessionInfoMetrics;
+    private final NsdManager mNsdManager;
+    @VisibleForTesting
+    final List<OffloadServiceInfo> mOffloadServiceInfos = new ArrayList<>();
+    private OffloadEngine mOffloadEngine;
 
     private static boolean isDeviceIdleModeChangedAction(Intent intent) {
         return ACTION_DEVICE_IDLE_MODE_CHANGED.equals(intent.getAction());
@@ -305,9 +317,6 @@ public class ApfFilter implements AndroidPacketFilter {
         if (!SdkLevel.isAtLeastT()) {
             return false;
         }
-        if (!mShouldHandleLightDoze) {
-            return false;
-        }
         return ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED.equals(intent.getAction());
     }
 
@@ -318,9 +327,6 @@ public class ApfFilter implements AndroidPacketFilter {
         if (!SdkLevel.isAtLeastT()) {
             return false;
         }
-        if (!mShouldHandleLightDoze) {
-            return false;
-        }
 
         return powerManager.isDeviceLightIdleMode();
     }
@@ -329,16 +335,21 @@ public class ApfFilter implements AndroidPacketFilter {
     private final BroadcastReceiver mDeviceIdleReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
-            final PowerManager powerManager = context.getSystemService(PowerManager.class);
-            if (isDeviceIdleModeChangedAction(intent)
-                    || isDeviceLightIdleModeChangedAction(intent)) {
-                final boolean deviceIdle = powerManager.isDeviceIdleMode()
-                        || isDeviceLightIdleMode(powerManager);
-                setDozeMode(deviceIdle);
-            }
+            mHandler.post(() -> {
+                if (mIsApfShutdown) return;
+                final PowerManager powerManager = context.getSystemService(PowerManager.class);
+                if (isDeviceIdleModeChangedAction(intent)
+                        || isDeviceLightIdleModeChangedAction(intent)) {
+                    final boolean deviceIdle = powerManager.isDeviceIdleMode()
+                            || isDeviceLightIdleMode(powerManager);
+                    setDozeMode(deviceIdle);
+                }
+            });
         }
     };
 
+    private boolean mIsApfShutdown;
+
     // Our IPv4 address, if we have just one, otherwise null.
     @GuardedBy("this")
     private byte[] mIPv4Address;
@@ -365,43 +376,96 @@ public class ApfFilter implements AndroidPacketFilter {
 
     private final Dependencies mDependencies;
 
-    public ApfFilter(Context context, ApfConfiguration config, InterfaceParams ifParams,
-            IpClientCallbacksWrapper ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics) {
-        this(context, config, ifParams, ipClientCallback, networkQuirkMetrics,
-                new Dependencies(context), new Clock());
+    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
+    private void registerOffloadEngine() {
+        if (mOffloadEngine != null) {
+            Log.wtf(TAG,
+                    "registerOffloadEngine called twice without calling unregisterOffloadEngine");
+            return;
+        }
+        mOffloadEngine = new OffloadEngine() {
+            @Override
+            public void onOffloadServiceUpdated(@NonNull OffloadServiceInfo info) {
+                mOffloadServiceInfos.removeIf(i -> i.getKey().equals(info.getKey()));
+                mOffloadServiceInfos.add(info);
+            }
+
+            @Override
+            public void onOffloadServiceRemoved(@NonNull OffloadServiceInfo info) {
+                mOffloadServiceInfos.removeIf(i -> i.getKey().equals(info.getKey()));
+            }
+        };
+        mNsdManager.registerOffloadEngine(mInterfaceParams.name,
+                OFFLOAD_TYPE_REPLY,
+                OFFLOAD_CAPABILITY_BYPASS_MULTICAST_LOCK,
+                mHandler::post, mOffloadEngine);
     }
 
-    @VisibleForTesting
-    public ApfFilter(Context context, ApfConfiguration config, InterfaceParams ifParams,
-            IpClientCallbacksWrapper ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
-            Dependencies dependencies) {
-        this(context, config, ifParams, ipClientCallback, networkQuirkMetrics, dependencies,
-                new Clock());
+    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
+    private void unregisterOffloadEngine() {
+        if (mOffloadEngine != null) {
+            mNsdManager.unregisterOffloadEngine(mOffloadEngine);
+            mOffloadServiceInfos.clear();
+            mOffloadEngine = null;
+        }
+    }
+
+    public ApfFilter(Handler handler, Context context, ApfConfiguration config,
+            InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
+            NetworkQuirkMetrics networkQuirkMetrics) {
+        this(handler, context, config, ifParams, ipClientCallback, networkQuirkMetrics,
+                new Dependencies(context));
+    }
+
+    private synchronized void maybeCleanUpApfRam() {
+        // Clear the APF memory to reset all counters upon connecting to the first AP
+        // in an SSID. This is limited to APFv3 devices because this large write triggers
+        // a crash on some older devices (b/78905546).
+        if (hasDataAccess(mApfVersionSupported)) {
+            byte[] zeroes = new byte[mApfRamSize];
+            if (!mIpClientCallback.installPacketFilter(zeroes)) {
+                sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
+            }
+        }
     }
 
     @VisibleForTesting
-    public ApfFilter(Context context, ApfConfiguration config, InterfaceParams ifParams,
-            IpClientCallbacksWrapper ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
-            Dependencies dependencies, Clock clock) {
-        mApfCapabilities = config.apfCapabilities;
+    public ApfFilter(Handler handler, Context context, ApfConfiguration config,
+            InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
+            NetworkQuirkMetrics networkQuirkMetrics, Dependencies dependencies) {
+        mHandler = handler;
+        mApfVersionSupported = config.apfVersionSupported;
+        mApfRamSize = config.apfRamSize;
         mInstallableProgramSizeClamp = config.installableProgramSizeClamp;
+        int maximumApfProgramSize = mApfRamSize;
+        if (hasDataAccess(mApfVersionSupported)) {
+            // Reserve space for the counters.
+            maximumApfProgramSize -= Counter.totalSize();
+        }
+        // Prevent generating (and thus installing) larger programs
+        if (maximumApfProgramSize > mInstallableProgramSizeClamp) {
+            maximumApfProgramSize = mInstallableProgramSizeClamp;
+        }
+        mMaximumApfProgramSize = maximumApfProgramSize;
         mIpClientCallback = ipClientCallback;
         mInterfaceParams = ifParams;
         mMulticastFilter = config.multicastFilter;
         mDrop802_3Frames = config.ieee802_3Filter;
         mMinRdnssLifetimeSec = config.minRdnssLifetimeSec;
         mAcceptRaMinLft = config.acceptRaMinLft;
-        mShouldHandleLightDoze = config.shouldHandleLightDoze;
         mShouldHandleArpOffload = config.shouldHandleArpOffload;
+        mShouldHandleNdOffload = config.shouldHandleNdOffload;
+        mShouldHandleMdnsOffload = config.shouldHandleMdnsOffload;
         mDependencies = dependencies;
         mNetworkQuirkMetrics = networkQuirkMetrics;
         mIpClientRaInfoMetrics = dependencies.getIpClientRaInfoMetrics();
         mApfSessionInfoMetrics = dependencies.getApfSessionInfoMetrics();
-        mClock = clock;
-        mSessionStartMs = mClock.elapsedRealtime();
+        mSessionStartMs = dependencies.elapsedRealtime();
         mMinMetricsSessionDurationMs = config.minMetricsSessionDurationMs;
         mHasClat = config.hasClatInterface;
 
+        mIsApfShutdown = false;
+
         // Now fill the black list from the passed array
         mEthTypeBlackList = filterEthTypeBlackList(config.ethTypeBlackList);
 
@@ -414,15 +478,27 @@ public class ApfFilter implements AndroidPacketFilter {
         // 3 seconds.
         mTokenBucket = new TokenBucket(3_000 /* deltaMs */, 20 /* capacity */, 20 /* tokens */);
 
+        mHardwareAddress = mInterfaceParams.macAddr.toByteArray();
         // TODO: ApfFilter should not generate programs until IpClient sends provisioning success.
-        maybeStartFilter();
+        synchronized (this) {
+            maybeCleanUpApfRam();
+            // Install basic filters
+            installNewProgramLocked();
+        }
+
+        mRaPacketReader = new RaPacketReader(mHandler, mInterfaceParams.index);
+        // The class constructor must be called from the IpClient's handler thread
+        if (!mRaPacketReader.start()) {
+            Log.wtf(TAG, "Failed to start RaPacketReader");
+        }
 
         // Listen for doze-mode transition changes to enable/disable the IPv6 multicast filter.
-        mDependencies.addDeviceIdleReceiver(mDeviceIdleReceiver, mShouldHandleLightDoze);
+        mDependencies.addDeviceIdleReceiver(mDeviceIdleReceiver);
 
-        mDependencies.onApfFilterCreated(this);
-        // mReceiveThread is created in maybeStartFilter() and halted in shutdown().
-        mDependencies.onThreadCreated(mReceiveThread);
+        mNsdManager = context.getSystemService(NsdManager.class);
+        if (shouldEnableMdnsOffload()) {
+            registerOffloadEngine();
+        }
     }
 
     /**
@@ -435,11 +511,35 @@ public class ApfFilter implements AndroidPacketFilter {
             mContext = context;
         }
 
+        /**
+         * Create a socket to read RAs.
+         */
+        @Nullable
+        public FileDescriptor createPacketReaderSocket(int ifIndex) {
+            FileDescriptor socket;
+            try {
+                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
+                NetworkStackUtils.attachRaFilter(socket);
+                SocketAddress addr = makePacketSocketAddress(ETH_P_IPV6, ifIndex);
+                Os.bind(socket, addr);
+            } catch (SocketException | ErrnoException e) {
+                Log.wtf(TAG, "Error starting filter", e);
+                return null;
+            }
+            return socket;
+        }
+
+        /**
+         * Get elapsedRealtime.
+         */
+        public long elapsedRealtime() {
+            return SystemClock.elapsedRealtime();
+        }
+
         /** Add receiver for detecting doze mode change */
-        public void addDeviceIdleReceiver(@NonNull final BroadcastReceiver receiver,
-                boolean shouldHandleLightDoze) {
+        public void addDeviceIdleReceiver(@NonNull final BroadcastReceiver receiver) {
             final IntentFilter intentFilter = new IntentFilter(ACTION_DEVICE_IDLE_MODE_CHANGED);
-            if (SdkLevel.isAtLeastT() && shouldHandleLightDoze) {
+            if (SdkLevel.isAtLeastT()) {
                 intentFilter.addAction(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED);
             }
             mContext.registerReceiver(receiver, intentFilter);
@@ -569,45 +669,10 @@ public class ApfFilter implements AndroidPacketFilter {
         return bl.stream().mapToInt(Integer::intValue).toArray();
     }
 
-    /**
-     * Attempt to start listening for RAs and, if RAs are received, generating and installing
-     * filters to ignore useless RAs.
-     */
-    @VisibleForTesting
-    public void maybeStartFilter() {
-        FileDescriptor socket;
-        try {
-            mHardwareAddress = mInterfaceParams.macAddr.toByteArray();
-            synchronized(this) {
-                // Clear the APF memory to reset all counters upon connecting to the first AP
-                // in an SSID. This is limited to APFv4 devices because this large write triggers
-                // a crash on some older devices (b/78905546).
-                if (mIsRunning && hasDataAccess(mApfCapabilities)) {
-                    byte[] zeroes = new byte[mApfCapabilities.maximumApfProgramSize];
-                    if (!mIpClientCallback.installPacketFilter(zeroes)) {
-                        sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
-                    }
-                }
-
-                // Install basic filters
-                installNewProgramLocked();
-            }
-            socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
-            NetworkStackUtils.attachRaFilter(socket);
-            SocketAddress addr = makePacketSocketAddress(ETH_P_IPV6, mInterfaceParams.index);
-            Os.bind(socket, addr);
-        } catch(SocketException|ErrnoException e) {
-            Log.e(TAG, "Error starting filter", e);
-            return;
-        }
-        mReceiveThread = new ReceiveThread(socket);
-        mReceiveThread.start();
-    }
-
     // Returns seconds since device boot.
     @VisibleForTesting
     protected int secondsSinceBoot() {
-        return (int) (mClock.elapsedRealtime() / DateUtils.SECOND_IN_MILLIS);
+        return (int) (mDependencies.elapsedRealtime() / DateUtils.SECOND_IN_MILLIS);
     }
 
     public static class InvalidRaException extends Exception {
@@ -669,41 +734,6 @@ public class ApfFilter implements AndroidPacketFilter {
     // A class to hold information about an RA.
     @VisibleForTesting
     public class Ra {
-        // From RFC4861:
-        private static final int ICMP6_RA_HEADER_LEN = 16;
-        private static final int ICMP6_RA_CHECKSUM_OFFSET =
-                ETH_HEADER_LEN + IPV6_HEADER_LEN + 2;
-        private static final int ICMP6_RA_CHECKSUM_LEN = 2;
-        private static final int ICMP6_RA_OPTION_OFFSET =
-                ETH_HEADER_LEN + IPV6_HEADER_LEN + ICMP6_RA_HEADER_LEN;
-        private static final int ICMP6_RA_ROUTER_LIFETIME_OFFSET =
-                ETH_HEADER_LEN + IPV6_HEADER_LEN + 6;
-        private static final int ICMP6_RA_ROUTER_LIFETIME_LEN = 2;
-        // Prefix information option.
-        private static final int ICMP6_PREFIX_OPTION_TYPE = 3;
-        private static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET = 4;
-        private static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN = 4;
-        private static final int ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN = 4;
-
-        // From RFC4861: source link-layer address
-        private static final int ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE = 1;
-        // From RFC4861: mtu size option
-        private static final int ICMP6_MTU_OPTION_TYPE = 5;
-        // From RFC6106: Recursive DNS Server option
-        private static final int ICMP6_RDNSS_OPTION_TYPE = 25;
-        // From RFC6106: DNS Search List option
-        private static final int ICMP6_DNSSL_OPTION_TYPE = 31;
-        // From RFC8910: Captive-Portal option
-        private static final int ICMP6_CAPTIVE_PORTAL_OPTION_TYPE = 37;
-        // From RFC8781: PREF64 option
-        private static final int ICMP6_PREF64_OPTION_TYPE = 38;
-
-        // From RFC4191: Route Information option
-        private static final int ICMP6_ROUTE_INFO_OPTION_TYPE = 24;
-        // Above three options all have the same format:
-        private static final int ICMP6_4_BYTE_LIFETIME_OFFSET = 4;
-        private static final int ICMP6_4_BYTE_LIFETIME_LEN = 4;
-
         // Note: mPacket's position() cannot be assumed to be reset.
         private final ByteBuffer mPacket;
 
@@ -1025,6 +1055,7 @@ public class ApfFilter implements AndroidPacketFilter {
                     case ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE:
                     case ICMP6_MTU_OPTION_TYPE:
                     case ICMP6_PREF64_OPTION_TYPE:
+                    case ICMP6_RA_FLAGS_EXTENSION_OPTION_TYPE:
                         addMatchSection(optionLength);
                         break;
                     case ICMP6_CAPTIVE_PORTAL_OPTION_TYPE: // unlikely to ever change.
@@ -1693,7 +1724,14 @@ public class ApfFilter implements AndroidPacketFilter {
             // Check 1) it's not a fragment. 2) it's UDP.
             // Load 16 bit frag flags/offset field, 8 bit ttl, 8 bit protocol
             gen.addLoad32(R0, IPV4_FRAGMENT_OFFSET_OFFSET);
-            gen.addAnd(0x3FFF00FF);
+            // Mask out the reserved and don't fragment bits, plus the TTL field.
+            // Because:
+            //   IPV4_FRAGMENT_OFFSET_MASK = 0x1fff
+            //   IPV4_FRAGMENT_MORE_FRAGS_MASK = 0x2000
+            // hence this constant ends up being 0x3FFF00FF.
+            // We want the more flag bit and offset to be 0 (ie. not a fragment),
+            // so after this masking we end up with just the ip protocol (hopefully UDP).
+            gen.addAnd((IPV4_FRAGMENT_MORE_FRAGS_MASK | IPV4_FRAGMENT_OFFSET_MASK) << 16 | 0xFF);
             gen.addCountAndDropIfR0NotEquals(IPPROTO_UDP, Counter.DROPPED_IPV4_NON_DHCP4);
             // Check it's addressed to DHCP client port.
             gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
@@ -1711,7 +1749,8 @@ public class ApfFilter implements AndroidPacketFilter {
             // Check 1) it's not a fragment. 2) it's UDP.
             // Load 16 bit frag flags/offset field, 8 bit ttl, 8 bit protocol
             gen.addLoad32(R0, IPV4_FRAGMENT_OFFSET_OFFSET);
-            gen.addAnd(0x3FFF00FF);
+            // see above for explanation of this constant
+            gen.addAnd((IPV4_FRAGMENT_MORE_FRAGS_MASK | IPV4_FRAGMENT_OFFSET_MASK) << 16 | 0xFF);
             gen.addJumpIfR0NotEquals(IPPROTO_UDP, skipDhcpv4Filter);
             // Check it's addressed to DHCP client port.
             gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
@@ -1934,22 +1973,63 @@ public class ApfFilter implements AndroidPacketFilter {
         v6Gen.addLoad8(R0, ICMP6_CODE_OFFSET)
                 .addCountAndDropIfR0NotEquals(0, DROPPED_IPV6_NS_INVALID);
 
-        // target address (ICMPv6 NS/NA payload) is not interface addresses -> drop
-        v6Gen.addLoadImmediate(R0, ICMP6_NS_TARGET_IP_OFFSET)
-                .addCountAndDropIfBytesAtR0EqualsNoneOf(allIPv6Addrs, DROPPED_IPV6_NS_OTHER_HOST);
-
-        // Only offload the following cases:
-        //   1) NS packet with no options.
-        //   2) NS packet with only one option: nonce.
-        //   3) NS packet with only one option: SLLA.
-        // For packets containing more than one option,
-        // pass the packet to the CPU for processing.
-        // payload length > 32
-        //   (8 bytes ICMP6 header + 16 bytes target address + 8 bytes option) -> pass
-        v6Gen.addLoad16(R0, IPV6_PAYLOAD_LEN_OFFSET)
-                .addCountAndPassIfR0GreaterThan(32, PASSED_IPV6_NS_MULTIPLE_OPTIONS);
+        // target address (ICMPv6 NS payload)
+        //   1) is one of tentative addresses -> pass
+        //   2) is none of {non-tentative, anycast} addresses -> drop
+        final List<byte[]> tentativeIPv6Addrs = getIpv6Addresses(
+                false, /* includeNonTentative */
+                true, /* includeTentative */
+                false /* includeAnycast */
+        );
+        v6Gen.addLoadImmediate(R0, ICMP6_NS_TARGET_IP_OFFSET);
+        if (!tentativeIPv6Addrs.isEmpty()) {
+            v6Gen.addCountAndPassIfBytesAtR0EqualsAnyOf(
+                    tentativeIPv6Addrs, PASSED_IPV6_NS_TENTATIVE);
+        }
 
-        v6Gen.addCountAndPass(Counter.PASSED_IPV6_ICMP);
+        final List<byte[]> nonTentativeIpv6Addrs = getIpv6Addresses(
+                true, /* includeNonTentative */
+                false, /* includeTentative */
+                true /* includeAnycast */
+        );
+        if (nonTentativeIpv6Addrs.isEmpty()) {
+            v6Gen.addCountAndDrop(DROPPED_IPV6_NS_OTHER_HOST);
+            return;
+        }
+        v6Gen.addCountAndDropIfBytesAtR0EqualsNoneOf(
+                nonTentativeIpv6Addrs, DROPPED_IPV6_NS_OTHER_HOST);
+
+        // if source ip is unspecified (::), it's DAD request -> pass
+        v6Gen.addLoadImmediate(R0, IPV6_SRC_ADDR_OFFSET)
+                .addCountAndPassIfBytesAtR0Equal(IPV6_UNSPECIFIED_ADDRESS, PASSED_IPV6_NS_DAD);
+
+        // Only offload NUD/Address resolution packets that have SLLA as the their first option.
+        // For option-less NUD packets or NUD/Address resolution packets where
+        // the first option is not SLLA, pass them to the kernel for handling.
+        // if payload len < 32 -> pass
+        v6Gen.addLoad16(R0, IPV6_PAYLOAD_LEN_OFFSET)
+                .addCountAndPassIfR0LessThan(32, PASSED_IPV6_NS_NO_SLLA_OPTION);
+
+        // if the first option is not SLLA -> pass
+        // 0                   1                   2                   3
+        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+        // |     Type      |    Length     |Link-Layer Addr  |
+        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+        v6Gen.addLoad8(R0, ICMP6_NS_OPTION_TYPE_OFFSET)
+                .addCountAndPassIfR0NotEquals(ICMPV6_ND_OPTION_SLLA,
+                        PASSED_IPV6_NS_NO_SLLA_OPTION);
+
+        // Src IPv6 address check:
+        // if multicast address (FF::/8) or loopback address (00::/8) -> drop
+        v6Gen.addLoad8(R0, IPV6_SRC_ADDR_OFFSET)
+                .addCountAndDropIfR0IsOneOf(Set.of(0L, 0xffL), DROPPED_IPV6_NS_INVALID);
+
+        // if multicast MAC in SLLA option -> drop
+        v6Gen.addLoad8(R0, ICMP6_NS_OPTION_TYPE_OFFSET + 2)
+                .addCountAndDropIfR0AnyBitsSet(1, DROPPED_IPV6_NS_INVALID);
+        generateNonDadNaTransmitLocked(v6Gen);
+        v6Gen.addCountAndDrop(Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD);
     }
 
     /**
@@ -1966,7 +2046,7 @@ public class ApfFilter implements AndroidPacketFilter {
         // if there is a hop-by-hop option present (e.g. MLD query)
         //   pass
         // if we're dropping multicast
-        //   if it's not IPCMv6 or it's ICMPv6 but we're in doze mode:
+        //   if it's not ICMPv6 or it's ICMPv6 but we're in doze mode:
         //     if it's multicast:
         //       drop
         //     pass
@@ -1986,10 +2066,19 @@ public class ApfFilter implements AndroidPacketFilter {
         //     drop
         //   if ICMPv6 code is not 0:
         //     drop
-        //   if target IP is none of interface unicast IPv6 addresses (incl. anycast):
+        //   if target IP is one of tentative IPv6 addresses:
+        //     pass
+        //   if target IP is none of non-tentative IPv6 addresses (incl. anycast):
         //     drop
-        //   if payload len > 32 (8 bytes ICMP6 header + 16 bytes target address + 8 bytes option):
+        //   if IPv6 src is unspecified (::):
+        //     pass
+        //   if payload len < 32 (8 bytes ICMP6 header + 16 bytes target address + 8 bytes option):
         //     pass
+        //   if IPv6 src is multicast address (FF::/8) or loopback address (00::/8):
+        //     drop
+        //   if multicast MAC in SLLA option:
+        //     drop
+        //   transmit NA and drop
         // if it's ICMPv6 RS to any:
         //   drop
         // if it's ICMPv6 NA to anything in ff02::/120
@@ -2041,7 +2130,7 @@ public class ApfFilter implements AndroidPacketFilter {
         // Not ICMPv6 NS -> skip.
         gen.addLoad8(R0, ICMP6_TYPE_OFFSET); // warning: also used further below.
         final ApfV6Generator v6Gen = tryToConvertToApfV6Generator(gen);
-        if (v6Gen != null) {
+        if (v6Gen != null && mShouldHandleNdOffload) {
             final String skipNsPacketFilter = v6Gen.getUniqueLabel();
             v6Gen.addJumpIfR0NotEquals(ICMPV6_NEIGHBOR_SOLICITATION, skipNsPacketFilter);
             generateNsFilterLocked(v6Gen);
@@ -2202,17 +2291,18 @@ public class ApfFilter implements AndroidPacketFilter {
      */
     @GuardedBy("this")
     @VisibleForTesting
-    protected ApfV4GeneratorBase<?> emitPrologueLocked() throws IllegalInstructionException {
+    public ApfV4GeneratorBase<?> emitPrologueLocked() throws IllegalInstructionException {
         // This is guaranteed to succeed because of the check in maybeCreate.
         ApfV4GeneratorBase<?> gen;
-        if (SdkLevel.isAtLeastV()
-                && ApfV6Generator.supportsVersion(mApfCapabilities.apfVersionSupported)) {
-            gen = new ApfV6Generator(mApfCapabilities.maximumApfProgramSize);
+        if (shouldUseApfV6Generator()) {
+            gen = new ApfV6Generator(mApfVersionSupported, mApfRamSize,
+                    mInstallableProgramSizeClamp);
         } else {
-            gen = new ApfV4Generator(mApfCapabilities.apfVersionSupported);
+            gen = new ApfV4Generator(mApfVersionSupported, mApfRamSize,
+                    mInstallableProgramSizeClamp);
         }
 
-        if (hasDataAccess(mApfCapabilities)) {
+        if (hasDataAccess(mApfVersionSupported)) {
             if (gen instanceof ApfV4Generator) {
                 // Increment TOTAL_PACKETS.
                 // Only needed in APFv4.
@@ -2238,6 +2328,8 @@ public class ApfFilter implements AndroidPacketFilter {
 
         // Here's a basic summary of what the initial program does:
         //
+        // if it is a loopback (src mac is nic's primary mac) packet
+        //    pass
         // if it's a 802.3 Frame (ethtype < 0x0600):
         //    drop or pass based on configurations
         // if it has a ether-type that belongs to the black list
@@ -2252,6 +2344,9 @@ public class ApfFilter implements AndroidPacketFilter {
         //   pass
         // insert IPv6 filter to drop, pass, or fall off the end for ICMPv6 packets
 
+        gen.addLoadImmediate(R0, ETHER_SRC_ADDR_OFFSET);
+        gen.addCountAndPassIfBytesAtR0Equal(mHardwareAddress, PASSED_ETHER_OUR_SRC_MAC);
+
         gen.addLoad16(R0, ETH_ETHERTYPE_OFFSET);
         if (SdkLevel.isAtLeastV()) {
             // IPv4, ARP, IPv6, EAPOL, WAPI
@@ -2333,20 +2428,11 @@ public class ApfFilter implements AndroidPacketFilter {
         ArrayList<Ra> rasToFilter = new ArrayList<>();
         final byte[] program;
         int programMinLft = Integer.MAX_VALUE;
-        int maximumApfProgramSize = mApfCapabilities.maximumApfProgramSize;
-        if (hasDataAccess(mApfCapabilities)) {
-            // Reserve space for the counters.
-            maximumApfProgramSize -= Counter.totalSize();
-        }
-
-        // Prevent generating (and thus installing) larger programs
-        if (maximumApfProgramSize > mInstallableProgramSizeClamp) {
-            maximumApfProgramSize = mInstallableProgramSizeClamp;
-        }
 
-        // Ensure the entire APF program uses the same time base.
-        int timeSeconds = secondsSinceBoot();
         try {
+            // Ensure the entire APF program uses the same time base.
+            final int timeSeconds = secondsSinceBoot();
+            mLastTimeInstalledProgram = timeSeconds;
             // Step 1: Determine how many RA filters we can fit in the program.
             ApfV4GeneratorBase<?> gen = emitPrologueLocked();
 
@@ -2355,8 +2441,8 @@ public class ApfFilter implements AndroidPacketFilter {
             emitEpilogue(gen);
 
             // Can't fit the program even without any RA filters?
-            if (gen.programLengthOverEstimate() > maximumApfProgramSize) {
-                Log.e(TAG, "Program exceeds maximum size " + maximumApfProgramSize);
+            if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
+                Log.e(TAG, "Program exceeds maximum size " + mMaximumApfProgramSize);
                 sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
                 return;
             }
@@ -2366,7 +2452,7 @@ public class ApfFilter implements AndroidPacketFilter {
                 if (ra.getRemainingFilterLft(timeSeconds) <= 0) continue;
                 ra.generateFilterLocked(gen, timeSeconds);
                 // Stop if we get too big.
-                if (gen.programLengthOverEstimate() > maximumApfProgramSize) {
+                if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
                     if (VDBG) Log.d(TAG, "Past maximum program size, skipping RAs");
                     sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
                     break;
@@ -2395,7 +2481,6 @@ public class ApfFilter implements AndroidPacketFilter {
                 sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
             }
         }
-        mLastTimeInstalledProgram = timeSeconds;
         mLastInstalledProgramMinLifetime = programMinLft;
         mLastInstalledProgram = program;
         mNumProgramUpdates++;
@@ -2505,31 +2590,25 @@ public class ApfFilter implements AndroidPacketFilter {
      * Create an {@link ApfFilter} if {@code apfCapabilities} indicates support for packet
      * filtering using APF programs.
      */
-    public static ApfFilter maybeCreate(Context context, ApfConfiguration config,
+    public static ApfFilter maybeCreate(Handler handler, Context context, ApfConfiguration config,
             InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
             NetworkQuirkMetrics networkQuirkMetrics) {
         if (context == null || config == null || ifParams == null) return null;
-        ApfCapabilities apfCapabilities =  config.apfCapabilities;
-        if (apfCapabilities == null) return null;
-        if (apfCapabilities.apfVersionSupported < 2) return null;
-        if (apfCapabilities.maximumApfProgramSize < 512) {
-            Log.e(TAG, "Unacceptably small APF limit: " + apfCapabilities.maximumApfProgramSize);
+        if (!ApfV4Generator.supportsVersion(config.apfVersionSupported)) {
             return null;
         }
-        // For now only support generating programs for Ethernet frames. If this restriction is
-        // lifted the program generator will need its offsets adjusted.
-        if (apfCapabilities.apfPacketFormat != ARPHRD_ETHER) return null;
-        if (!ApfV4Generator.supportsVersion(apfCapabilities.apfVersionSupported)) {
-            Log.e(TAG, "Unsupported APF version: " + apfCapabilities.apfVersionSupported);
+        if (config.apfRamSize < 512) {
+            Log.e(TAG, "Unacceptably small APF limit: " + config.apfRamSize);
             return null;
         }
 
-        return new ApfFilter(context, config, ifParams, ipClientCallback, networkQuirkMetrics);
+        return new ApfFilter(handler, context, config, ifParams, ipClientCallback,
+                networkQuirkMetrics);
     }
 
     private synchronized void collectAndSendMetrics() {
         if (mIpClientRaInfoMetrics == null || mApfSessionInfoMetrics == null) return;
-        final long sessionDurationMs = mClock.elapsedRealtime() - mSessionStartMs;
+        final long sessionDurationMs = mDependencies.elapsedRealtime() - mSessionStartMs;
         if (sessionDurationMs < mMinMetricsSessionDurationMs) return;
 
         // Collect and send IpClientRaInfoMetrics.
@@ -2543,8 +2622,8 @@ public class ApfFilter implements AndroidPacketFilter {
         mIpClientRaInfoMetrics.statsWrite();
 
         // Collect and send ApfSessionInfoMetrics.
-        mApfSessionInfoMetrics.setVersion(mApfCapabilities.apfVersionSupported);
-        mApfSessionInfoMetrics.setMemorySize(mApfCapabilities.maximumApfProgramSize);
+        mApfSessionInfoMetrics.setVersion(mApfVersionSupported);
+        mApfSessionInfoMetrics.setMemorySize(mApfRamSize);
         mApfSessionInfoMetrics.setApfSessionDurationSeconds(
                 (int) (sessionDurationMs / DateUtils.SECOND_IN_MILLIS));
         mApfSessionInfoMetrics.setNumOfTimesApfProgramUpdated(mNumProgramUpdates);
@@ -2559,13 +2638,14 @@ public class ApfFilter implements AndroidPacketFilter {
 
     public synchronized void shutdown() {
         collectAndSendMetrics();
-        if (mReceiveThread != null) {
-            log("shutting down");
-            mReceiveThread.halt();  // Also closes socket.
-            mReceiveThread = null;
-        }
+        // The shutdown() must be called from the IpClient's handler thread
+        mRaPacketReader.stop();
         mRas.clear();
         mDependencies.removeBroadcastReceiver(mDeviceIdleReceiver);
+        mIsApfShutdown = true;
+        if (shouldEnableMdnsOffload()) {
+            unregisterOffloadEngine();
+        }
     }
 
     public synchronized void setMulticastFilter(boolean isEnabled) {
@@ -2658,6 +2738,22 @@ public class ApfFilter implements AndroidPacketFilter {
         installNewProgramLocked();
     }
 
+    @Override
+    public boolean supportNdOffload() {
+        return shouldUseApfV6Generator() && mShouldHandleNdOffload;
+    }
+
+    @ChecksSdkIntAtLeast(api = 35 /* Build.VERSION_CODES.VanillaIceCream */, codename =
+            "VanillaIceCream")
+    @Override
+    public boolean shouldEnableMdnsOffload() {
+        return shouldUseApfV6Generator() && mShouldHandleMdnsOffload;
+    }
+
+    private boolean shouldUseApfV6Generator() {
+        return SdkLevel.isAtLeastV() && ApfV6Generator.supportsVersion(mApfVersionSupported);
+    }
+
     /**
      * Add TCP keepalive ack packet filter.
      * This will add a filter to drop acks to the keepalive packet passed as an argument.
@@ -2713,17 +2809,48 @@ public class ApfFilter implements AndroidPacketFilter {
     }
 
     public synchronized void dump(IndentingPrintWriter pw) {
-        pw.println("Capabilities: " + mApfCapabilities);
+        // TODO: use HandlerUtils.runWithScissors() to dump APF on the handler thread.
+        pw.println(String.format(
+                "Capabilities: { apfVersionSupported: %d, maximumApfProgramSize: %d }",
+                mApfVersionSupported, mApfRamSize));
         pw.println("InstallableProgramSizeClamp: " + mInstallableProgramSizeClamp);
         pw.println("Filter update status: " + (mIsRunning ? "RUNNING" : "PAUSED"));
-        pw.println("Receive thread: " + (mReceiveThread != null ? "RUNNING" : "STOPPED"));
         pw.println("Multicast: " + (mMulticastFilter ? "DROP" : "ALLOW"));
         pw.println("Minimum RDNSS lifetime: " + mMinRdnssLifetimeSec);
+        pw.println("Interface MAC address: " + MacAddress.fromBytes(mHardwareAddress));
+        pw.println("Multicast MAC addresses: ");
+        pw.increaseIndent();
+        for (byte[] addr : mDependencies.getEtherMulticastAddresses(mInterfaceParams.name)) {
+            pw.println(MacAddress.fromBytes(addr));
+        }
+        pw.decreaseIndent();
         try {
             pw.println("IPv4 address: " + InetAddress.getByAddress(mIPv4Address).getHostAddress());
-            pw.println("IPv6 addresses: ");
+            pw.println("IPv6 non-tentative addresses: ");
+            pw.increaseIndent();
+            for (Inet6Address addr : mIPv6NonTentativeAddresses) {
+                pw.println(addr.getHostAddress());
+            }
+            pw.decreaseIndent();
+            pw.println("IPv6 tentative addresses: ");
+            pw.increaseIndent();
+            for (Inet6Address addr : mIPv6TentativeAddresses) {
+                pw.println(addr.getHostAddress());
+            }
+            pw.decreaseIndent();
+            pw.println("IPv6 anycast addresses:");
+            pw.increaseIndent();
+            final List<Inet6Address> anycastAddrs =
+                    ProcfsParsingUtils.getAnycast6Addresses(mInterfaceParams.name);
+            for (Inet6Address addr : anycastAddrs) {
+                pw.println(addr.getHostAddress());
+            }
+            pw.decreaseIndent();
+            pw.println("IPv6 multicast addresses:");
             pw.increaseIndent();
-            for (Inet6Address addr: mIPv6NonTentativeAddresses) {
+            final List<Inet6Address> multicastAddrs =
+                    ProcfsParsingUtils.getIpv6MulticastAddresses(mInterfaceParams.name);
+            for (Inet6Address addr : multicastAddrs) {
                 pw.println(addr.getHostAddress());
             }
             pw.decreaseIndent();
@@ -2796,7 +2923,7 @@ public class ApfFilter implements AndroidPacketFilter {
 
         pw.println("APF packet counters: ");
         pw.increaseIndent();
-        if (!hasDataAccess(mApfCapabilities)) {
+        if (!hasDataAccess(mApfVersionSupported)) {
             pw.println("APF counters not supported");
         } else if (mDataSnapshot == null) {
             pw.println("No last snapshot.");
@@ -2810,10 +2937,17 @@ public class ApfFilter implements AndroidPacketFilter {
                         pw.println(c.toString() + ": " + value);
                     }
 
-                    // If the counter's value decreases, it may have been cleaned up or there may be
-                    // a bug.
-                    if (value < mApfCounterTracker.getCounters().getOrDefault(c, 0L)) {
-                        Log.e(TAG, "Error: Counter value unexpectedly decreased.");
+                    final Set<Counter> skipCheckCounters = Set.of(FILTER_AGE_SECONDS,
+                            FILTER_AGE_16384THS);
+                    if (!skipCheckCounters.contains(c)) {
+                        // If the counter's value decreases, it may have been cleaned up or there
+                        // may be a bug.
+                        long oldValue = mApfCounterTracker.getCounters().getOrDefault(c, 0L);
+                        if (value < oldValue) {
+                            Log.e(TAG, String.format(
+                                    "Apf Counter: %s unexpectedly decreased. oldValue: %d. "
+                                            + "newValue: %d", c.toString(), oldValue, value));
+                        }
                     }
                 }
             } catch (ArrayIndexOutOfBoundsException e) {
@@ -2839,6 +2973,11 @@ public class ApfFilter implements AndroidPacketFilter {
 
     /** Resume ApfFilter updates for testing purposes. */
     public void resume() {
+        maybeCleanUpApfRam();
+        // Since the resume() function and cleanup process invalidate previous counter
+        // snapshots, the ApfCounterTracker needs to be reset to maintain reliable, incremental
+        // counter tracking.
+        mApfCounterTracker.clearCounters();
         mIsRunning = true;
     }
 
diff --git a/src/android/net/apf/ApfMdnsUtils.java b/src/android/net/apf/ApfMdnsUtils.java
new file mode 100644
index 00000000..7666864f
--- /dev/null
+++ b/src/android/net/apf/ApfMdnsUtils.java
@@ -0,0 +1,173 @@
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
+package android.net.apf;
+
+import static com.android.net.module.util.NetworkStackConstants.TYPE_A;
+import static com.android.net.module.util.NetworkStackConstants.TYPE_AAAA;
+import static com.android.net.module.util.NetworkStackConstants.TYPE_PTR;
+import static com.android.net.module.util.NetworkStackConstants.TYPE_SRV;
+import static com.android.net.module.util.NetworkStackConstants.TYPE_TXT;
+
+import android.annotation.NonNull;
+import android.annotation.RequiresApi;
+import android.net.nsd.OffloadServiceInfo;
+import android.os.Build;
+import android.util.ArraySet;
+
+import com.android.net.module.util.DnsUtils;
+
+import java.io.ByteArrayOutputStream;
+import java.io.IOException;
+import java.nio.charset.StandardCharsets;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Set;
+
+/**
+ * Collection of utilities for APF mDNS functionalities.
+ *
+ * @hide
+ */
+public class ApfMdnsUtils {
+
+    private static final int MAX_SUPPORTED_SUBTYPES = 3;
+    private ApfMdnsUtils() {}
+
+    private static void addMatcherIfNotExist(@NonNull Set<MdnsOffloadRule.Matcher> allMatchers,
+            @NonNull List<MdnsOffloadRule.Matcher> matcherGroup,
+            @NonNull MdnsOffloadRule.Matcher matcher) {
+        if (allMatchers.contains(matcher)) {
+            return;
+        }
+        matcherGroup.add(matcher);
+        allMatchers.add(matcher);
+    }
+
+    private static String[] prepend(String[] suffix, String... prefixes) {
+        String[] result = new String[prefixes.length + suffix.length];
+        System.arraycopy(prefixes, 0, result, 0, prefixes.length);
+        System.arraycopy(suffix, 0, result, prefixes.length, suffix.length);
+        return result;
+    }
+
+
+    /**
+     * Extract the offload rules from the list of offloadServiceInfos. The rules are returned in
+     * priority order (most important first). If there are too many rules, APF could decide only
+     * offload the rules with the higher priority.
+     */
+    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
+    @NonNull
+    public static List<MdnsOffloadRule> extractOffloadReplyRule(
+            @NonNull List<OffloadServiceInfo> offloadServiceInfos) throws IOException {
+        final List<OffloadServiceInfo> sortedOffloadServiceInfos = new ArrayList<>(
+                offloadServiceInfos);
+        sortedOffloadServiceInfos.sort((a, b) -> {
+            int priorityA = a.getPriority();
+            int priorityB = b.getPriority();
+            return Integer.compare(priorityA, priorityB);
+        });
+        final List<MdnsOffloadRule> rules = new ArrayList<>();
+        final Set<MdnsOffloadRule.Matcher> allMatchers = new ArraySet<>();
+        for (OffloadServiceInfo info : sortedOffloadServiceInfos) {
+            // Don't offload the records if the priority is not configured.
+            int priority = info.getPriority();
+            if (priority == Integer.MAX_VALUE) {
+                continue;
+            }
+            List<MdnsOffloadRule.Matcher> matcherGroup = new ArrayList<>();
+            final OffloadServiceInfo.Key key = info.getKey();
+            final String[] serviceTypeLabels = key.getServiceType().split("\\.", 0);
+            final String[] fullQualifiedName = prepend(serviceTypeLabels, key.getServiceName());
+            final byte[] replyPayload = info.getOffloadPayload();
+            final byte[] encodedServiceType = encodeQname(serviceTypeLabels);
+           // If (QTYPE == PTR) and (QNAME == mServiceName + mServiceType), then reply.
+            MdnsOffloadRule.Matcher ptrMatcher = new MdnsOffloadRule.Matcher(
+                    encodedServiceType,
+                    TYPE_PTR
+            );
+            addMatcherIfNotExist(allMatchers, matcherGroup, ptrMatcher);
+            final List<String> subTypes = info.getSubtypes();
+            // If subtype list is less than MAX_SUPPORTED_SUBTYPES, then matching each subtype.
+            // Otherwise, use wildcard matching and fail open.
+            boolean tooManySubtypes = subTypes.size() > MAX_SUPPORTED_SUBTYPES;
+            if (tooManySubtypes) {
+                // If (QTYPE == PTR) and (QNAME == wildcard + _sub + mServiceType), then fail open.
+                final String[] serviceTypeSuffix = prepend(serviceTypeLabels, "_sub");
+                final ByteArrayOutputStream buf = new ByteArrayOutputStream();
+                // byte = 0xff is used as a wildcard.
+                buf.write(-1);
+                final byte[] encodedFullServiceType = encodeQname(buf, serviceTypeSuffix);
+                final MdnsOffloadRule.Matcher subtypePtrMatcher = new MdnsOffloadRule.Matcher(
+                        encodedFullServiceType, TYPE_PTR);
+                addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
+            } else {
+                // If (QTYPE == PTR) and (QNAME == subType + _sub + mServiceType), then reply.
+                for (String subType : subTypes) {
+                    final String[] fullServiceType = prepend(serviceTypeLabels, subType, "_sub");
+                    final byte[] encodedFullServiceType = encodeQname(fullServiceType);
+                    // If (QTYPE == PTR) and (QNAME == subType + "_sub" + mServiceType), then reply.
+                    final MdnsOffloadRule.Matcher subtypePtrMatcher = new MdnsOffloadRule.Matcher(
+                            encodedFullServiceType, TYPE_PTR);
+                    addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
+                }
+            }
+            final byte[] encodedFullQualifiedNameQname = encodeQname(fullQualifiedName);
+            // If (QTYPE == SRV) and (QNAME == mServiceName + mServiceType), then reply.
+            addMatcherIfNotExist(allMatchers, matcherGroup,
+                    new MdnsOffloadRule.Matcher(encodedFullQualifiedNameQname, TYPE_SRV));
+            // If (QTYPE == TXT) and (QNAME == mServiceName + mServiceType), then reply.
+            addMatcherIfNotExist(allMatchers, matcherGroup,
+                    new MdnsOffloadRule.Matcher(encodedFullQualifiedNameQname, TYPE_TXT));
+            // If (QTYPE == A or AAAA) and (QNAME == mDeviceHostName), then reply.
+            final String[] hostNameLabels = info.getHostname().split("\\.", 0);
+            final byte[] encodedHostName = encodeQname(hostNameLabels);
+            addMatcherIfNotExist(allMatchers, matcherGroup,
+                    new MdnsOffloadRule.Matcher(encodedHostName, TYPE_A));
+            addMatcherIfNotExist(allMatchers, matcherGroup,
+                    new MdnsOffloadRule.Matcher(encodedHostName, TYPE_AAAA));
+            if (!matcherGroup.isEmpty()) {
+                rules.add(new MdnsOffloadRule(matcherGroup, tooManySubtypes ? null : replyPayload));
+            }
+        }
+        return rules;
+    }
+
+    private static byte[] encodeQname(@NonNull ByteArrayOutputStream buf, @NonNull String[] labels)
+            throws IOException {
+        final String[] upperCaseLabel = DnsUtils.toDnsLabelsUpperCase(labels);
+        for (final String label : upperCaseLabel) {
+            int labelLength = label.length();
+            if (labelLength < 1 || labelLength > 63) {
+                throw new IOException("Label is too long: " + label);
+            }
+            buf.write(labelLength);
+            buf.write(label.getBytes(StandardCharsets.UTF_8));
+        }
+        // APF take array of qnames as input, each qname is terminated by a 0 byte.
+        // A 0 byte is required to mark the end of the list.
+        // This method always writes 1-item lists, as there isn't currently a use-case for
+        // multiple qnames of the same type using the same offload packet.
+        buf.write(0);
+        buf.write(0);
+        return buf.toByteArray();
+    }
+
+    private static byte[] encodeQname(@NonNull String[] labels) throws IOException {
+        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
+        return encodeQname(buf, labels);
+    }
+}
diff --git a/src/android/net/apf/ApfV4Generator.java b/src/android/net/apf/ApfV4Generator.java
index a41f033f..f9918b23 100644
--- a/src/android/net/apf/ApfV4Generator.java
+++ b/src/android/net/apf/ApfV4Generator.java
@@ -61,10 +61,10 @@ public final class ApfV4Generator extends ApfV4GeneratorBase<ApfV4Generator> {
      * the requested version is unsupported.
      */
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
-    public ApfV4Generator(int version, boolean disableCounterRangeCheck)
+    public ApfV4Generator(int version, int ramSize, int clampSize, boolean disableCounterRangeCheck)
             throws IllegalInstructionException {
         // make sure mVersion is not greater than 4 when using this class
-        super(version > 4 ? 4 : version, disableCounterRangeCheck);
+        super(version > 4 ? 4 : version, ramSize, clampSize, disableCounterRangeCheck);
         mCountAndDropLabel = version > 2 ? COUNT_AND_DROP_LABEL : DROP_LABEL;
         mCountAndPassLabel = version > 2 ? COUNT_AND_PASS_LABEL : PASS_LABEL;
     }
@@ -74,8 +74,9 @@ public final class ApfV4Generator extends ApfV4GeneratorBase<ApfV4Generator> {
      * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
      * the requested version is unsupported.
      */
-    public ApfV4Generator(int version) throws IllegalInstructionException {
-        this(version, false);
+    public ApfV4Generator(int version, int ramSize, int clampSize)
+            throws IllegalInstructionException {
+        this(version, ramSize, clampSize, false);
     }
 
     @Override
@@ -201,20 +202,6 @@ public final class ApfV4Generator extends ApfV4GeneratorBase<ApfV4Generator> {
                 mCountAndPassLabel);
     }
 
-    @Override
-    public ApfV4Generator addCountAndDropIfBytesAtR0Equal(byte[] bytes,
-            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
-        final String tgt = getUniqueLabel();
-        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
-    }
-
-    @Override
-    public ApfV4Generator addCountAndPassIfBytesAtR0Equal(byte[] bytes,
-            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
-        final String tgt = getUniqueLabel();
-        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
-    }
-
     @Override
     public ApfV4Generator addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
             ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
diff --git a/src/android/net/apf/ApfV4GeneratorBase.java b/src/android/net/apf/ApfV4GeneratorBase.java
index ced1d687..a00aa2fa 100644
--- a/src/android/net/apf/ApfV4GeneratorBase.java
+++ b/src/android/net/apf/ApfV4GeneratorBase.java
@@ -52,9 +52,9 @@ public abstract class ApfV4GeneratorBase<Type extends ApfV4GeneratorBase<Type>>
      * the requested version is unsupported.
      */
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
-    public ApfV4GeneratorBase(int version, boolean disableCounterRangeCheck)
-            throws IllegalInstructionException {
-        super(version, disableCounterRangeCheck);
+    public ApfV4GeneratorBase(int version, int ramSize, int clampSize,
+            boolean disableCounterRangeCheck) throws IllegalInstructionException {
+        super(version, ramSize, clampSize, disableCounterRangeCheck);
         requireApfVersion(APF_VERSION_2);
     }
 
@@ -504,16 +504,23 @@ public abstract class ApfV4GeneratorBase<Type extends ApfV4GeneratorBase<Type>>
      * bytes of the packet at an offset specified by register0 match {@code bytes}.
      * WARNING: may modify R1
      */
-    public abstract Type addCountAndDropIfBytesAtR0Equal(byte[] bytes,
-            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;
+    public final Type addCountAndDropIfBytesAtR0Equal(byte[] bytes,
+            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
+        final String tgt = getUniqueLabel();
+        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
+    }
+
 
     /**
      * Add instructions to the end of the program to increase counter and pass packet if the
      * bytes of the packet at an offset specified by register0 match {@code bytes}.
      * WARNING: may modify R1
      */
-    public abstract Type addCountAndPassIfBytesAtR0Equal(byte[] bytes,
-            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;
+    public final Type addCountAndPassIfBytesAtR0Equal(byte[] bytes,
+            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
+        final String tgt = getUniqueLabel();
+        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
+    }
 
     /**
      * Add instructions to the end of the program to increase counter and pass packet if the
diff --git a/src/android/net/apf/ApfV6Generator.java b/src/android/net/apf/ApfV6Generator.java
index d4259073..f943bedb 100644
--- a/src/android/net/apf/ApfV6Generator.java
+++ b/src/android/net/apf/ApfV6Generator.java
@@ -35,14 +35,15 @@ public final class ApfV6Generator extends ApfV6GeneratorBase<ApfV6Generator> {
     /**
      * Creates an ApfV6Generator instance which emits instructions for APFv6.
      */
-    public ApfV6Generator(int maximumApfProgramSize) throws IllegalInstructionException {
-        this(new byte[0], maximumApfProgramSize);
+    public ApfV6Generator(int version, int ramSize, int clampSize)
+            throws IllegalInstructionException {
+        this(new byte[0], version, ramSize, clampSize);
     }
 
     @Override
     void updateExceptionBufferSize(int programSize) throws IllegalInstructionException {
         mInstructions.get(1).updateExceptionBufferSize(
-                mMaximumApfProgramSize - ApfCounterTracker.Counter.totalSize() - programSize);
+                mRamSize - ApfCounterTracker.Counter.totalSize() - programSize);
     }
 
     /**
@@ -50,9 +51,9 @@ public final class ApfV6Generator extends ApfV6GeneratorBase<ApfV6Generator> {
      * Initializes the data region with {@code bytes}.
      */
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
-    public ApfV6Generator(byte[] bytes, int maximumApfProgramSize)
+    public ApfV6Generator(byte[] bytes, int version, int ramSize, int clampSize)
             throws IllegalInstructionException {
-        super(maximumApfProgramSize);
+        super(version, ramSize, clampSize);
         Objects.requireNonNull(bytes);
         addData(bytes);
         addExceptionBuffer(0);
diff --git a/src/android/net/apf/ApfV6GeneratorBase.java b/src/android/net/apf/ApfV6GeneratorBase.java
index a9abed64..17629d19 100644
--- a/src/android/net/apf/ApfV6GeneratorBase.java
+++ b/src/android/net/apf/ApfV6GeneratorBase.java
@@ -40,17 +40,15 @@ import java.util.Set;
 public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>> extends
         ApfV4GeneratorBase<Type> {
 
-    final int mMaximumApfProgramSize;
-
     /**
      * Creates an ApfV6GeneratorBase instance which is able to emit instructions for the specified
      * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
      * the requested version is unsupported.
      *
      */
-    public ApfV6GeneratorBase(int maximumApfProgramSize) throws IllegalInstructionException {
-        super(APF_VERSION_6, false);
-        this.mMaximumApfProgramSize = maximumApfProgramSize;
+    public ApfV6GeneratorBase(int version, int ramSize, int clampSize)
+            throws IllegalInstructionException {
+        super(version, ramSize, clampSize, false);
     }
 
     /**
@@ -711,20 +709,6 @@ public abstract class ApfV6GeneratorBase<Type extends ApfV6GeneratorBase<Type>>
         return addJumpIfBytesAtR0Equal(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
     }
 
-    @Override
-    public final Type addCountAndDropIfBytesAtR0Equal(byte[] bytes,
-            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
-        final String tgt = getUniqueLabel();
-        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
-    }
-
-    @Override
-    public final Type addCountAndPassIfBytesAtR0Equal(byte[] bytes,
-            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
-        final String tgt = getUniqueLabel();
-        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
-    }
-
     @Override
     public Type addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
             ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
diff --git a/src/android/net/apf/BaseApfGenerator.java b/src/android/net/apf/BaseApfGenerator.java
index 55521657..2eab5abb 100644
--- a/src/android/net/apf/BaseApfGenerator.java
+++ b/src/android/net/apf/BaseApfGenerator.java
@@ -22,6 +22,7 @@ import static android.net.apf.BaseApfGenerator.Register.R0;
 
 import android.annotation.NonNull;
 
+import com.android.internal.annotations.VisibleForTesting;
 import com.android.net.module.util.ByteUtils;
 import com.android.net.module.util.CollectionUtils;
 import com.android.net.module.util.HexDump;
@@ -39,9 +40,12 @@ import java.util.Objects;
  */
 public abstract class BaseApfGenerator {
 
-    public BaseApfGenerator(int mVersion, boolean mDisableCounterRangeCheck) {
-        this.mVersion = mVersion;
-        this.mDisableCounterRangeCheck = mDisableCounterRangeCheck;
+    public BaseApfGenerator(int version, int ramSize, int clampSize,
+            boolean disableCounterRangeCheck) {
+        mVersion = version;
+        mRamSize = ramSize;
+        mClampSize = clampSize;
+        mDisableCounterRangeCheck = disableCounterRangeCheck;
     }
 
     /**
@@ -851,7 +855,8 @@ public abstract class BaseApfGenerator {
     /**
      * Return a unique label string.
      */
-    protected String getUniqueLabel() {
+    @VisibleForTesting
+    public String getUniqueLabel() {
         return "LABEL_" + mLabelCount++;
     }
 
@@ -954,6 +959,8 @@ public abstract class BaseApfGenerator {
     private final Instruction mDropLabel = new Instruction(Opcodes.LABEL);
     private final Instruction mPassLabel = new Instruction(Opcodes.LABEL);
     public final int mVersion;
+    public final int mRamSize;
+    public final int mClampSize;
     public boolean mGenerated;
     private final boolean mDisableCounterRangeCheck;
 }
diff --git a/src/android/net/apf/LegacyApfFilter.java b/src/android/net/apf/LegacyApfFilter.java
index e4f709bf..2cd0eec2 100644
--- a/src/android/net/apf/LegacyApfFilter.java
+++ b/src/android/net/apf/LegacyApfFilter.java
@@ -21,7 +21,6 @@ import static android.net.apf.BaseApfGenerator.Register.R0;
 import static android.net.apf.BaseApfGenerator.Register.R1;
 import static android.net.util.SocketUtils.makePacketSocketAddress;
 import static android.system.OsConstants.AF_PACKET;
-import static android.system.OsConstants.ARPHRD_ETHER;
 import static android.system.OsConstants.ETH_P_ARP;
 import static android.system.OsConstants.ETH_P_IP;
 import static android.system.OsConstants.ETH_P_IPV6;
@@ -54,6 +53,7 @@ import android.net.metrics.ApfStats;
 import android.net.metrics.IpConnectivityLog;
 import android.net.metrics.RaEvent;
 import android.os.PowerManager;
+import android.os.SystemClock;
 import android.stats.connectivity.NetworkQuirkEvent;
 import android.system.ErrnoException;
 import android.system.Os;
@@ -126,7 +126,7 @@ public class LegacyApfFilter implements AndroidPacketFilter {
      * When APFv4 is supported, loads R1 with the offset of the specified counter.
      */
     private void maybeSetupCounter(ApfV4Generator gen, Counter c) {
-        if (hasDataAccess(mApfCapabilities)) {
+        if (hasDataAccess(mApfVersionSupported)) {
             gen.addLoadImmediate(R1, c.offset());
         }
     }
@@ -136,6 +136,16 @@ public class LegacyApfFilter implements AndroidPacketFilter {
     private final String mCountAndPassLabel;
     private final String mCountAndDropLabel;
 
+    /** A wrapper class of {@link SystemClock} to be mocked in unit tests. */
+    public static class Clock {
+        /**
+         * @see SystemClock#elapsedRealtime
+         */
+        public long elapsedRealtime() {
+            return SystemClock.elapsedRealtime();
+        }
+    }
+
     // Thread to listen for RAs.
     @VisibleForTesting
     public class ReceiveThread extends Thread {
@@ -214,7 +224,7 @@ public class LegacyApfFilter implements AndroidPacketFilter {
                         .setZeroLifetimeRas(mZeroLifetimeRas)
                         .setProgramUpdates(mProgramUpdates)
                         .setDurationMs(nowMs - mStart)
-                        .setMaxProgramSize(mApfCapabilities.maximumApfProgramSize)
+                        .setMaxProgramSize(mMaximumApfProgramSize)
                         .setProgramUpdatesAll(mNumProgramUpdates)
                         .setProgramUpdatesAllowingMulticast(mNumProgramUpdatesAllowingMulticast)
                         .build();
@@ -306,7 +316,8 @@ public class LegacyApfFilter implements AndroidPacketFilter {
             ETH_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN;
 
 
-    private final ApfCapabilities mApfCapabilities;
+    public final int mApfVersionSupported;
+    public final int mMaximumApfProgramSize;
     private final IpClientCallbacksWrapper mIpClientCallback;
     private final InterfaceParams mInterfaceParams;
     private final IpConnectivityLog mMetricsLog;
@@ -346,7 +357,7 @@ public class LegacyApfFilter implements AndroidPacketFilter {
     // Minimum session time for metrics, duration less than this time will not be logged.
     private final long mMinMetricsSessionDurationMs;
 
-    private final ApfFilter.Clock mClock;
+    private final Clock mClock;
     private final NetworkQuirkMetrics mNetworkQuirkMetrics;
     private final IpClientRaInfoMetrics mIpClientRaInfoMetrics;
     private final ApfSessionInfoMetrics mApfSessionInfoMetrics;
@@ -385,15 +396,16 @@ public class LegacyApfFilter implements AndroidPacketFilter {
             InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
             IpConnectivityLog log, NetworkQuirkMetrics networkQuirkMetrics) {
         this(context, config, ifParams, ipClientCallback, log, networkQuirkMetrics,
-                new ApfFilter.Dependencies(context), new ApfFilter.Clock());
+                new ApfFilter.Dependencies(context), new Clock());
     }
 
     @VisibleForTesting
     public LegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
             InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
             IpConnectivityLog log, NetworkQuirkMetrics networkQuirkMetrics,
-            ApfFilter.Dependencies dependencies, ApfFilter.Clock clock) {
-        mApfCapabilities = config.apfCapabilities;
+            ApfFilter.Dependencies dependencies, Clock clock) {
+        mApfVersionSupported = config.apfVersionSupported;
+        mMaximumApfProgramSize = config.apfRamSize;
         mIpClientCallback = ipClientCallback;
         mInterfaceParams = ifParams;
         mMulticastFilter = config.multicastFilter;
@@ -408,7 +420,7 @@ public class LegacyApfFilter implements AndroidPacketFilter {
         mSessionStartMs = mClock.elapsedRealtime();
         mMinMetricsSessionDurationMs = config.minMetricsSessionDurationMs;
 
-        if (hasDataAccess(mApfCapabilities)) {
+        if (hasDataAccess(mApfVersionSupported)) {
             mCountAndPassLabel = "countAndPass";
             mCountAndDropLabel = "countAndDrop";
         } else {
@@ -494,8 +506,8 @@ public class LegacyApfFilter implements AndroidPacketFilter {
                 // Clear the APF memory to reset all counters upon connecting to the first AP
                 // in an SSID. This is limited to APFv4 devices because this large write triggers
                 // a crash on some older devices (b/78905546).
-                if (mIsRunning && hasDataAccess(mApfCapabilities)) {
-                    byte[] zeroes = new byte[mApfCapabilities.maximumApfProgramSize];
+                if (mIsRunning && hasDataAccess(mApfVersionSupported)) {
+                    byte[] zeroes = new byte[mMaximumApfProgramSize];
                     if (!mIpClientCallback.installPacketFilter(zeroes)) {
                         sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
                     }
@@ -1728,9 +1740,10 @@ public class LegacyApfFilter implements AndroidPacketFilter {
     @GuardedBy("this")
     protected ApfV4Generator emitPrologueLocked() throws IllegalInstructionException {
         // This is guaranteed to succeed because of the check in maybeCreate.
-        ApfV4Generator gen = new ApfV4Generator(mApfCapabilities.apfVersionSupported);
+        ApfV4Generator gen = new ApfV4Generator(mApfVersionSupported, mMaximumApfProgramSize,
+                mMaximumApfProgramSize);
 
-        if (hasDataAccess(mApfCapabilities)) {
+        if (hasDataAccess(mApfVersionSupported)) {
             // Increment TOTAL_PACKETS
             maybeSetupCounter(gen, Counter.TOTAL_PACKETS);
             gen.addLoadData(R0, 0);  // load counter
@@ -1833,7 +1846,7 @@ public class LegacyApfFilter implements AndroidPacketFilter {
     private void emitEpilogue(ApfV4Generator gen) throws IllegalInstructionException {
         // If APFv4 is unsupported, no epilogue is necessary: if execution reached this far, it
         // will just fall-through to the PASS label.
-        if (!hasDataAccess(mApfCapabilities)) return;
+        if (!hasDataAccess(mApfVersionSupported)) return;
 
         // Execution will reach the bottom of the program if none of the filters match,
         // which will pass the packet to the application processor.
@@ -1868,8 +1881,8 @@ public class LegacyApfFilter implements AndroidPacketFilter {
         ArrayList<Ra> rasToFilter = new ArrayList<>();
         final byte[] program;
         long programMinLifetime = Long.MAX_VALUE;
-        long maximumApfProgramSize = mApfCapabilities.maximumApfProgramSize;
-        if (hasDataAccess(mApfCapabilities)) {
+        long maximumApfProgramSize = mMaximumApfProgramSize;
+        if (hasDataAccess(mApfVersionSupported)) {
             // Reserve space for the counters.
             maximumApfProgramSize -= Counter.totalSize();
         }
@@ -2071,20 +2084,11 @@ public class LegacyApfFilter implements AndroidPacketFilter {
             InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
             NetworkQuirkMetrics networkQuirkMetrics) {
         if (context == null || config == null || ifParams == null) return null;
-        ApfCapabilities apfCapabilities =  config.apfCapabilities;
-        if (apfCapabilities == null) return null;
-        if (apfCapabilities.apfVersionSupported == 0) return null;
-        if (apfCapabilities.maximumApfProgramSize < 512) {
-            Log.e(TAG, "Unacceptably small APF limit: " + apfCapabilities.maximumApfProgramSize);
+        if (!ApfV4Generator.supportsVersion(config.apfVersionSupported)) {
             return null;
         }
-        // For now only support generating programs for Ethernet frames. If this restriction is
-        // lifted:
-        //   1. the program generator will need its offsets adjusted.
-        //   2. the packet filter attached to our packet socket will need its offset adjusted.
-        if (apfCapabilities.apfPacketFormat != ARPHRD_ETHER) return null;
-        if (!ApfV4Generator.supportsVersion(apfCapabilities.apfVersionSupported)) {
-            Log.e(TAG, "Unsupported APF version: " + apfCapabilities.apfVersionSupported);
+        if (config.apfRamSize < 512) {
+            Log.e(TAG, "Unacceptably small APF limit: " + config.apfRamSize);
             return null;
         }
 
@@ -2108,8 +2112,8 @@ public class LegacyApfFilter implements AndroidPacketFilter {
         mIpClientRaInfoMetrics.statsWrite();
 
         // Collect and send ApfSessionInfoMetrics.
-        mApfSessionInfoMetrics.setVersion(mApfCapabilities.apfVersionSupported);
-        mApfSessionInfoMetrics.setMemorySize(mApfCapabilities.maximumApfProgramSize);
+        mApfSessionInfoMetrics.setVersion(mApfVersionSupported);
+        mApfSessionInfoMetrics.setMemorySize(mMaximumApfProgramSize);
         mApfSessionInfoMetrics.setApfSessionDurationSeconds(
                 (int) (sessionDurationMs / DateUtils.SECOND_IN_MILLIS));
         mApfSessionInfoMetrics.setNumOfTimesApfProgramUpdated(mNumProgramUpdates);
@@ -2249,7 +2253,9 @@ public class LegacyApfFilter implements AndroidPacketFilter {
     }
 
     public synchronized void dump(IndentingPrintWriter pw) {
-        pw.println("Capabilities: " + mApfCapabilities);
+        pw.println(String.format(
+                "Capabilities: { apfVersionSupported: %d, maximumApfProgramSize: %d }",
+                mApfVersionSupported, mMaximumApfProgramSize));
         pw.println("Filter update status: " + (mIsRunning ? "RUNNING" : "PAUSED"));
         pw.println("Receive thread: " + (mReceiveThread != null ? "RUNNING" : "STOPPED"));
         pw.println("Multicast: " + (mMulticastFilter ? "DROP" : "ALLOW"));
@@ -2325,7 +2331,7 @@ public class LegacyApfFilter implements AndroidPacketFilter {
 
         pw.println("APF packet counters: ");
         pw.increaseIndent();
-        if (!hasDataAccess(mApfCapabilities)) {
+        if (!hasDataAccess(mApfVersionSupported)) {
             pw.println("APF counters not supported");
         } else if (mDataSnapshot == null) {
             pw.println("No last snapshot.");
diff --git a/src/android/net/apf/MdnsOffloadRule.java b/src/android/net/apf/MdnsOffloadRule.java
new file mode 100644
index 00000000..454f35a8
--- /dev/null
+++ b/src/android/net/apf/MdnsOffloadRule.java
@@ -0,0 +1,120 @@
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
+package android.net.apf;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
+import com.android.net.module.util.HexDump;
+
+import java.util.Arrays;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * Represents a rule for offloading mDNS service.
+ *
+ * @hide
+ */
+public class MdnsOffloadRule {
+
+    /**
+     * The payload data to be sent in the mDNS offload reply.
+     * If the payload is empty, the APF must let the query through so that host can respond.
+     */
+    @Nullable
+    public final byte[] mOffloadPayload;
+
+    @NonNull
+    public final List<Matcher> mMatchers;
+
+    /**
+     * Construct an mDNS offload rule.
+     */
+    public MdnsOffloadRule(@NonNull List<Matcher> matchers, @Nullable byte[] offloadPayload) {
+        mMatchers = matchers;
+        mOffloadPayload = offloadPayload;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (!(o instanceof MdnsOffloadRule that)) return false;
+        return Arrays.equals(mOffloadPayload, that.mOffloadPayload)
+                && Objects.equals(mMatchers, that.mMatchers);
+    }
+
+    @Override
+    public int hashCode() {
+        int result = Objects.hash(mMatchers);
+        result = 31 * result + Arrays.hashCode(mOffloadPayload);
+        return result;
+    }
+
+    @Override
+    public String toString() {
+        return "MdnsOffloadRule{" + "mOffloadPayload="
+                + ((mOffloadPayload == null) ? "(null)" : HexDump.toHexString(mOffloadPayload))
+                + ", mMatchers=" + mMatchers + '}';
+    }
+
+    /**
+     * The matcher class.
+     * <p>
+     * A matcher encapsulates the following information:
+     *   mQnames: The QNAME(s) (query names) to match in the mDNS query.
+     *   mQtype: The QTYPE (query type) to match in the mDNS query.
+     */
+    public static class Matcher {
+        /**
+         * The QNAME(s) from the mDNS query that this rule matches.
+         */
+        public final byte[] mQnames;
+        /**
+         * The QTYPE from the mDNS query that this rule matches.
+         */
+        public final int mQtype;
+
+        /**
+         * Creates a new Matcher.
+         */
+        public Matcher(byte[] qnames, int qtype) {
+            mQnames = qnames;
+            mQtype = qtype;
+        }
+
+        @Override
+        public boolean equals(Object o) {
+            if (this == o) return true;
+            if (!(o instanceof Matcher that)) return false;
+            return mQtype == that.mQtype && Arrays.equals(mQnames, that.mQnames);
+        }
+
+        @Override
+        public int hashCode() {
+            int result = Objects.hash(mQtype);
+            result = 31 * result + Arrays.hashCode(mQnames);
+            return result;
+        }
+
+        @Override
+        public String toString() {
+            return "Matcher{" + "mQnames=" + HexDump.toHexString(mQnames) + ", mQtype="
+                    + mQtype + '}';
+        }
+    }
+
+}
diff --git a/src/android/net/dhcp/DhcpPacket.java b/src/android/net/dhcp/DhcpPacket.java
index 595c63a0..8e327e1d 100644
--- a/src/android/net/dhcp/DhcpPacket.java
+++ b/src/android/net/dhcp/DhcpPacket.java
@@ -16,7 +16,6 @@
 
 package android.net.dhcp;
 
-import static com.android.modules.utils.build.SdkLevel.isAtLeastR;
 import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ALL;
 import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ANY;
 
@@ -25,7 +24,6 @@ import android.net.LinkAddress;
 import android.net.metrics.DhcpErrorEvent;
 import android.net.networkstack.aidl.dhcp.DhcpOption;
 import android.os.Build;
-import android.os.SystemProperties;
 import android.system.OsConstants;
 import android.text.TextUtils;
 
@@ -807,9 +805,6 @@ public abstract class DhcpPacket {
      */
     @VisibleForTesting
     public String getHostname() {
-        if (mHostName == null && !isAtLeastR()) {
-            return SystemProperties.get("net.hostname");
-        }
         return mHostName;
     }
 
diff --git a/src/android/net/ip/ConnectivityPacketTracker.java b/src/android/net/ip/ConnectivityPacketTracker.java
index 51fb428b..ce4f6ae5 100644
--- a/src/android/net/ip/ConnectivityPacketTracker.java
+++ b/src/android/net/ip/ConnectivityPacketTracker.java
@@ -16,12 +16,15 @@
 
 package android.net.ip;
 
+import static android.net.util.SocketUtils.closeSocket;
 import static android.net.util.SocketUtils.makePacketSocketAddress;
 import static android.system.OsConstants.AF_PACKET;
 import static android.system.OsConstants.ETH_P_ALL;
 import static android.system.OsConstants.SOCK_NONBLOCK;
 import static android.system.OsConstants.SOCK_RAW;
 
+import static com.android.internal.annotations.VisibleForTesting.Visibility.PRIVATE;
+
 import android.net.util.ConnectivityPacketSummary;
 import android.os.Handler;
 import android.os.SystemClock;
@@ -30,7 +33,12 @@ import android.system.Os;
 import android.text.TextUtils;
 import android.util.LocalLog;
 import android.util.Log;
+import android.util.LruCache;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
+import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.HexDump;
 import com.android.internal.util.TokenBucket;
 import com.android.net.module.util.InterfaceParams;
@@ -39,6 +47,8 @@ import com.android.networkstack.util.NetworkStackUtils;
 
 import java.io.FileDescriptor;
 import java.io.IOException;
+import java.util.Arrays;
+import java.util.Objects;
 
 
 /**
@@ -58,6 +68,49 @@ import java.io.IOException;
  * @hide
  */
 public class ConnectivityPacketTracker {
+    /**
+     * Dependencies class for testing.
+     */
+    @VisibleForTesting(visibility = PRIVATE)
+    public static class Dependencies {
+        private final LocalLog mLog;
+        public Dependencies(final LocalLog log) {
+            mLog = log;
+        }
+
+        /**
+         * Create a socket to read RAs.
+         */
+        @Nullable
+        public FileDescriptor createPacketReaderSocket(int ifIndex) {
+            FileDescriptor socket = null;
+            try {
+                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
+                NetworkStackUtils.attachControlPacketFilter(socket);
+                Os.bind(socket, makePacketSocketAddress(ETH_P_ALL, ifIndex));
+            } catch (ErrnoException | IOException e) {
+                final String msg = "Failed to create packet tracking socket: ";
+                Log.e(TAG, msg, e);
+                mLog.log(msg + e);
+                closeFd(socket);
+                return null;
+            }
+            return socket;
+        }
+
+        public int getMaxCapturePktSize() {
+            return MAX_CAPTURE_PACKET_SIZE;
+        }
+
+        private void closeFd(FileDescriptor fd) {
+            try {
+                closeSocket(fd);
+            } catch (IOException e) {
+                Log.e(TAG, "failed to close socket");
+            }
+        }
+    }
+
     private static final String TAG = ConnectivityPacketTracker.class.getSimpleName();
     private static final boolean DBG = false;
     private static final String MARK_START = "--- START ---";
@@ -67,21 +120,51 @@ public class ConnectivityPacketTracker {
     // Use a TokenBucket to limit CPU usage of logging packets in steady state.
     private static final int TOKEN_FILL_RATE = 50;   // Maximum one packet every 20ms.
     private static final int MAX_BURST_LENGTH = 100; // Maximum burst 100 packets.
+    private static final int MAX_CAPTURE_PACKET_SIZE = 100; // Maximum capture packet size
 
     private final String mTag;
     private final LocalLog mLog;
     private final PacketReader mPacketListener;
     private final TokenBucket mTokenBucket = new TokenBucket(TOKEN_FILL_RATE, MAX_BURST_LENGTH);
+    // store packet hex string in uppercase as key, receive packet count as value
+    private final LruCache<String, Integer> mPacketCache;
+    private final Dependencies mDependencies;
     private long mLastRateLimitLogTimeMs = 0;
     private boolean mRunning;
+    private boolean mCapturing;
     private String mDisplayName;
 
     public ConnectivityPacketTracker(Handler h, InterfaceParams ifParams, LocalLog log) {
-        if (ifParams == null) throw new IllegalArgumentException("null InterfaceParams");
+        this(h, ifParams, log, new Dependencies(log));
+    }
 
-        mTag = TAG + "." + ifParams.name;
-        mLog = log;
-        mPacketListener = new PacketListener(h, ifParams);
+    /**
+     * Sets the capture state.
+     *
+     * <p>This method controls whether packet capture is enabled. If capture is disabled,
+     * the internal packet map is cleared.</p>
+     *
+     * @param isCapture {@code true} to enable capture, {@code false} to disable capture
+     */
+    public void setCapture(boolean isCapture) {
+        mCapturing = isCapture;
+        if (!isCapture) {
+            mPacketCache.evictAll();
+        }
+    }
+
+    /**
+     * Gets the count of matched packets for a given pattern.
+     *
+     * <p>This method searches the internal packet map for packets matching the specified pattern
+     * and returns the count of such packets.</p>
+     *
+     * @param packet The hex string pattern to match against
+     * @return The count of packets matching the pattern, or 0 if no matches are found
+     */
+    public int getMatchedPacketCount(String packet) {
+        final Integer count = mPacketCache.get(packet);
+        return (count != null) ? count : 0;
     }
 
     public void start(String displayName) {
@@ -96,6 +179,24 @@ public class ConnectivityPacketTracker {
         mDisplayName = null;
     }
 
+    @VisibleForTesting(visibility = PRIVATE)
+    public int getCapturePacketTypeCount() {
+        return mPacketCache.size();
+    }
+
+    @VisibleForTesting(visibility = PRIVATE)
+    public ConnectivityPacketTracker(
+            @NonNull Handler handler,
+            @NonNull InterfaceParams ifParams,
+            @NonNull LocalLog log,
+            @NonNull Dependencies dependencies) {
+        mTag = TAG + "." + Objects.requireNonNull(ifParams).name;
+        mLog = log;
+        mPacketListener = new PacketListener(handler, ifParams);
+        mDependencies = dependencies;
+        mPacketCache = new LruCache<>(mDependencies.getMaxCapturePktSize());
+    }
+
     private final class PacketListener extends PacketReader {
         private final InterfaceParams mInterface;
 
@@ -106,21 +207,13 @@ public class ConnectivityPacketTracker {
 
         @Override
         protected FileDescriptor createFd() {
-            FileDescriptor s = null;
-            try {
-                s = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
-                NetworkStackUtils.attachControlPacketFilter(s);
-                Os.bind(s, makePacketSocketAddress(ETH_P_ALL, mInterface.index));
-            } catch (ErrnoException | IOException e) {
-                logError("Failed to create packet tracking socket: ", e);
-                closeFd(s);
-                return null;
-            }
-            return s;
+            return mDependencies.createPacketReaderSocket(mInterface.index);
         }
 
         @Override
         protected void handlePacket(byte[] recvbuf, int length) {
+            capturePacket(recvbuf, length);
+
             if (!mTokenBucket.get()) {
                 // Rate limited. Log once every second so the user knows packets are missing.
                 final long now = SystemClock.elapsedRealtime();
@@ -171,5 +264,21 @@ public class ConnectivityPacketTracker {
         private void addLogEntry(String entry) {
             mLog.log(entry);
         }
+
+        private void capturePacket(byte[] recvbuf, int length) {
+            if (!mCapturing) {
+                return;
+            }
+
+            byte[] pkt = Arrays.copyOfRange(
+                    recvbuf, 0, Math.min(recvbuf.length, length));
+            final String pktHexString = HexDump.toHexString(pkt);
+            final Integer pktCnt = mPacketCache.get(pktHexString);
+            if (pktCnt == null) {
+                mPacketCache.put(pktHexString, 1);
+            } else {
+                mPacketCache.put(pktHexString, pktCnt + 1);
+            }
+        }
     }
 }
diff --git a/src/android/net/ip/IpClient.java b/src/android/net/ip/IpClient.java
index deaabaca..0c90fe60 100644
--- a/src/android/net/ip/IpClient.java
+++ b/src/android/net/ip/IpClient.java
@@ -16,6 +16,10 @@
 
 package android.net.ip;
 
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_CONFIRM;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED;
 import static android.net.RouteInfo.RTN_UNICAST;
 import static android.net.RouteInfo.RTN_UNREACHABLE;
 import static android.net.dhcp.DhcpResultsParcelableUtil.toStableParcelable;
@@ -24,13 +28,43 @@ import static android.net.ip.IIpClient.PROV_IPV6_DISABLED;
 import static android.net.ip.IIpClient.PROV_IPV6_LINKLOCAL;
 import static android.net.ip.IIpClient.PROV_IPV6_SLAAC;
 import static android.net.ip.IIpClientCallbacks.DTIM_MULTIPLIER_RESET;
+import static android.net.ip.IpClient.IpClientCommands.CMD_ADDRESSES_CLEARED;
+import static android.net.ip.IpClient.IpClientCommands.CMD_ADD_KEEPALIVE_PACKET_FILTER_TO_APF;
+import static android.net.ip.IpClient.IpClientCommands.CMD_COMPLETE_PRECONNECTION;
+import static android.net.ip.IpClient.IpClientCommands.CMD_CONFIRM;
+import static android.net.ip.IpClient.IpClientCommands.CMD_JUMP_RUNNING_TO_STOPPING;
+import static android.net.ip.IpClient.IpClientCommands.CMD_JUMP_STOPPING_TO_STOPPED;
+import static android.net.ip.IpClient.IpClientCommands.CMD_REMOVE_KEEPALIVE_PACKET_FILTER_FROM_APF;
+import static android.net.ip.IpClient.IpClientCommands.CMD_SET_DTIM_MULTIPLIER_AFTER_DELAY;
+import static android.net.ip.IpClient.IpClientCommands.CMD_SET_MULTICAST_FILTER;
+import static android.net.ip.IpClient.IpClientCommands.CMD_START;
+import static android.net.ip.IpClient.IpClientCommands.CMD_STOP;
+import static android.net.ip.IpClient.IpClientCommands.CMD_TERMINATE_AFTER_STOP;
+import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_APF_CAPABILITIES;
+import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_APF_DATA_SNAPSHOT;
+import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_HTTP_PROXY;
+import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_L2INFORMATION;
+import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_L2KEY_CLUSTER;
+import static android.net.ip.IpClient.IpClientCommands.CMD_UPDATE_TCP_BUFFER_SIZES;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_DHCPACTION_TIMEOUT;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_IPV6_AUTOCONF_TIMEOUT;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_NETLINK_LINKPROPERTIES_CHANGED;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_FAILURE;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_SUCCESS;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_NUD_FAILURE_QUERY_TIMEOUT;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_PRE_DHCP_ACTION_COMPLETE;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_PROVISIONING_TIMEOUT;
+import static android.net.ip.IpClient.IpClientCommands.EVENT_READ_PACKET_FILTER_COMPLETE;
 import static android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor;
 import static android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor.INetlinkMessageProcessor;
 import static android.net.ip.IpReachabilityMonitor.INVALID_REACHABILITY_LOSS_TYPE;
 import static android.net.ip.IpReachabilityMonitor.nudEventTypeToInt;
 import static android.net.util.SocketUtils.makePacketSocketAddress;
 import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
+import static android.stats.connectivity.NetworkQuirkEvent.QE_DHCP6_HEURISTIC_TRIGGERED;
+import static android.stats.connectivity.NetworkQuirkEvent.QE_DHCP6_PD_PROVISIONED;
 import static android.system.OsConstants.AF_PACKET;
+import static android.system.OsConstants.ARPHRD_ETHER;
 import static android.system.OsConstants.ETH_P_ARP;
 import static android.system.OsConstants.ETH_P_IPV6;
 import static android.system.OsConstants.IFA_F_NODAD;
@@ -46,14 +80,15 @@ import static com.android.net.module.util.NetworkStackConstants.RFC7421_PREFIX_L
 import static com.android.net.module.util.NetworkStackConstants.VENDOR_SPECIFIC_IE_ID;
 import static com.android.networkstack.apishim.ConstantsShim.IFA_F_MANAGETEMPADDR;
 import static com.android.networkstack.apishim.ConstantsShim.IFA_F_NOPREFIXROUTE;
-import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ARP_OFFLOAD_FORCE_DISABLE;
-import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_LIGHT_DOZE_FORCE_DISABLE;
+import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ARP_OFFLOAD;
+import static com.android.networkstack.util.NetworkStackUtils.APF_HANDLE_ND_OFFLOAD;
 import static com.android.networkstack.util.NetworkStackUtils.APF_NEW_RA_FILTER_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.APF_POLLING_COUNTERS_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_DHCPV6_PREFIX_DELEGATION_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_GARP_NA_ROAMING_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_IGNORE_LOW_RA_LIFETIME_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_POPULATE_LINK_ADDRESS_LIFETIME_VERSION;
+import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.createInet6AddressFromEui64;
 import static com.android.networkstack.util.NetworkStackUtils.macAddressToEui64;
 import static com.android.server.util.PermissionUtil.enforceNetworkStackCallingPermission;
@@ -87,6 +122,8 @@ import android.net.apf.LegacyApfFilter;
 import android.net.dhcp.DhcpClient;
 import android.net.dhcp.DhcpPacket;
 import android.net.dhcp6.Dhcp6Client;
+import android.net.ipmemorystore.OnNetworkEventCountRetrievedListener;
+import android.net.ipmemorystore.Status;
 import android.net.metrics.IpConnectivityLog;
 import android.net.metrics.IpManagerEvent;
 import android.net.networkstack.aidl.dhcp.DhcpOption;
@@ -133,6 +170,7 @@ import com.android.modules.utils.build.SdkLevel;
 import com.android.net.module.util.CollectionUtils;
 import com.android.net.module.util.ConnectivityUtils;
 import com.android.net.module.util.DeviceConfigUtils;
+import com.android.net.module.util.HandlerUtils;
 import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.LinkPropertiesUtils;
 import com.android.net.module.util.SharedLog;
@@ -203,7 +241,7 @@ public class IpClient extends StateMachine {
     private final boolean mApfDebug;
 
     // For message logging.
-    private static final Class[] sMessageClasses = { IpClient.class, DhcpClient.class };
+    private static final Class[] sMessageClasses = { IpClientCommands.class, DhcpClient.class };
     private static final SparseArray<String> sWhatToString =
             MessageUtils.findMessageNames(sMessageClasses);
     // Static concurrent hashmaps of interface name to logging classes.
@@ -537,40 +575,52 @@ public class IpClient extends StateMachine {
     static final String ACCEPT_RA_MIN_LFT = "accept_ra_min_lft";
     private static final String DAD_TRANSMITS = "dad_transmits";
 
-    // Below constants are picked up by MessageUtils and exempt from ProGuard optimization.
-    private static final int CMD_TERMINATE_AFTER_STOP             = 1;
-    private static final int CMD_STOP                             = 2;
-    private static final int CMD_START                            = 3;
-    private static final int CMD_CONFIRM                          = 4;
-    private static final int EVENT_PRE_DHCP_ACTION_COMPLETE       = 5;
-    // Triggered by IpClientLinkObserver to communicate netlink events.
-    private static final int EVENT_NETLINK_LINKPROPERTIES_CHANGED = 6;
-    private static final int CMD_UPDATE_TCP_BUFFER_SIZES          = 7;
-    private static final int CMD_UPDATE_HTTP_PROXY                = 8;
-    private static final int CMD_SET_MULTICAST_FILTER             = 9;
-    private static final int EVENT_PROVISIONING_TIMEOUT           = 10;
-    private static final int EVENT_DHCPACTION_TIMEOUT             = 11;
-    private static final int EVENT_READ_PACKET_FILTER_COMPLETE    = 12;
-    private static final int CMD_ADD_KEEPALIVE_PACKET_FILTER_TO_APF = 13;
-    private static final int CMD_REMOVE_KEEPALIVE_PACKET_FILTER_FROM_APF = 14;
-    private static final int CMD_UPDATE_L2KEY_CLUSTER = 15;
-    private static final int CMD_COMPLETE_PRECONNECTION = 16;
-    private static final int CMD_UPDATE_L2INFORMATION = 17;
-    private static final int CMD_SET_DTIM_MULTIPLIER_AFTER_DELAY = 18;
-    private static final int CMD_UPDATE_APF_CAPABILITIES = 19;
-    private static final int EVENT_IPV6_AUTOCONF_TIMEOUT = 20;
-    private static final int CMD_UPDATE_APF_DATA_SNAPSHOT = 21;
+    /**
+     * The IpClientCommands constant values.
+     *
+     * @hide
+     */
+    public static class IpClientCommands {
+        private IpClientCommands() {
+        }
+
+        // Below constants are picked up by MessageUtils and exempt from ProGuard optimization.
+        static final int CMD_TERMINATE_AFTER_STOP = 1;
+        static final int CMD_STOP = 2;
+        static final int CMD_START = 3;
+        static final int CMD_CONFIRM = 4;
+        static final int EVENT_PRE_DHCP_ACTION_COMPLETE = 5;
+        // Triggered by IpClientLinkObserver to communicate netlink events.
+        static final int EVENT_NETLINK_LINKPROPERTIES_CHANGED = 6;
+        static final int CMD_UPDATE_TCP_BUFFER_SIZES = 7;
+        static final int CMD_UPDATE_HTTP_PROXY = 8;
+        static final int CMD_SET_MULTICAST_FILTER = 9;
+        static final int EVENT_PROVISIONING_TIMEOUT = 10;
+        static final int EVENT_DHCPACTION_TIMEOUT = 11;
+        static final int EVENT_READ_PACKET_FILTER_COMPLETE = 12;
+        static final int CMD_ADD_KEEPALIVE_PACKET_FILTER_TO_APF = 13;
+        static final int CMD_REMOVE_KEEPALIVE_PACKET_FILTER_FROM_APF = 14;
+        static final int CMD_UPDATE_L2KEY_CLUSTER = 15;
+        static final int CMD_COMPLETE_PRECONNECTION = 16;
+        static final int CMD_UPDATE_L2INFORMATION = 17;
+        static final int CMD_SET_DTIM_MULTIPLIER_AFTER_DELAY = 18;
+        static final int CMD_UPDATE_APF_CAPABILITIES = 19;
+        static final int EVENT_IPV6_AUTOCONF_TIMEOUT = 20;
+        static final int CMD_UPDATE_APF_DATA_SNAPSHOT = 21;
+        static final int EVENT_NUD_FAILURE_QUERY_TIMEOUT = 22;
+        static final int EVENT_NUD_FAILURE_QUERY_SUCCESS = 23;
+        static final int EVENT_NUD_FAILURE_QUERY_FAILURE = 24;
+        // Internal commands to use instead of trying to call transitionTo() inside
+        // a given State's enter() method. Calling transitionTo() from enter/exit
+        // encounters a Log.wtf() that can cause trouble on eng builds.
+        static final int CMD_ADDRESSES_CLEARED = 100;
+        static final int CMD_JUMP_RUNNING_TO_STOPPING = 101;
+        static final int CMD_JUMP_STOPPING_TO_STOPPED = 102;
+    }
 
     private static final int ARG_LINKPROP_CHANGED_LINKSTATE_DOWN = 0;
     private static final int ARG_LINKPROP_CHANGED_LINKSTATE_UP = 1;
 
-    // Internal commands to use instead of trying to call transitionTo() inside
-    // a given State's enter() method. Calling transitionTo() from enter/exit
-    // encounters a Log.wtf() that can cause trouble on eng builds.
-    private static final int CMD_ADDRESSES_CLEARED                = 100;
-    private static final int CMD_JUMP_RUNNING_TO_STOPPING         = 101;
-    private static final int CMD_JUMP_STOPPING_TO_STOPPED         = 102;
-
     // IpClient shares a handler with DhcpClient: commands must not overlap
     public static final int DHCPCLIENT_CMD_BASE = 1000;
 
@@ -597,7 +647,7 @@ public class IpClient extends StateMachine {
     static final String CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS =
             "ipclient_apf_counter_polling_interval_secs";
     @VisibleForTesting
-    static final int DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS = 300;
+    static final int DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS = 1800;
 
     // Used to wait for the provisioning to complete eventually and then decide the target
     // network type, which gives the accurate hint to set DTIM multiplier. Per current IPv6
@@ -646,6 +696,24 @@ public class IpClient extends StateMachine {
     static final String CONFIG_IPV6_AUTOCONF_TIMEOUT = "ipclient_ipv6_autoconf_timeout";
     private static final int DEFAULT_IPV6_AUTOCONF_TIMEOUT_MS = 5000;
 
+    private static final int IPMEMORYSTORE_TIMEOUT_MS = 1000;
+    @VisibleForTesting
+    static final long SIX_HOURS_IN_MS = 6 * 3600 * 1000L;
+    @VisibleForTesting
+    public static final long ONE_DAY_IN_MS = 4 * SIX_HOURS_IN_MS;
+    @VisibleForTesting
+    public static final long ONE_WEEK_IN_MS = 7 * ONE_DAY_IN_MS;
+    @VisibleForTesting
+    static final String CONFIG_NUD_FAILURE_COUNT_DAILY_THRESHOLD =
+            "nud_failure_count_daily_threshold";
+    @VisibleForTesting
+    static final int DEFAULT_NUD_FAILURE_COUNT_DAILY_THRESHOLD = 10;
+    @VisibleForTesting
+    static final String CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD =
+            "nud_failure_count_weekly_threshold";
+    @VisibleForTesting
+    static final int DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD = 20;
+
     private static final boolean NO_CALLBACKS = false;
     private static final boolean SEND_CALLBACKS = true;
 
@@ -685,12 +753,24 @@ public class IpClient extends StateMachine {
                     "KT GiGA WiFi", "marente"
     ));
 
+    // The NUD failure event types to query. Although only NETWORK_EVENT_NUD_FAILURE_ORGANIC event
+    // is stored in the database currently, this array is still maintained to include other event
+    // types for testing and future expansion.
+    @VisibleForTesting
+    public static final int[] NETWORK_EVENT_NUD_FAILURE_TYPES = new int[] {
+            NETWORK_EVENT_NUD_FAILURE_ROAM,
+            NETWORK_EVENT_NUD_FAILURE_CONFIRM,
+            NETWORK_EVENT_NUD_FAILURE_ORGANIC,
+            NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED
+    };
+
     private final State mStoppedState = new StoppedState();
     private final State mStoppingState = new StoppingState();
     private final State mClearingIpAddressesState = new ClearingIpAddressesState();
     private final State mStartedState = new StartedState();
     private final State mRunningState = new RunningState();
     private final State mPreconnectingState = new PreconnectingState();
+    private final State mNudFailureQueryState = new NudFailureQueryState();
 
     private final String mTag;
     private final Context mContext;
@@ -727,14 +807,19 @@ public class IpClient extends StateMachine {
     // Polling interval to update APF data snapshot
     private final long mApfCounterPollingIntervalMs;
 
+    private final int mNudFailureCountDailyThreshold;
+    private final int mNudFailureCountWeeklyThreshold;
+
     // Experiment flag read from device config.
     private final boolean mDhcp6PrefixDelegationEnabled;
     private final boolean mUseNewApfFilter;
-    private final boolean mEnableIpClientIgnoreLowRaLifetime;
-    private final boolean mApfShouldHandleLightDoze;
+    private final boolean mIsAcceptRaMinLftEnabled;
     private final boolean mEnableApfPollingCounters;
     private final boolean mPopulateLinkAddressLifetime;
     private final boolean mApfShouldHandleArpOffload;
+    private final boolean mApfShouldHandleNdOffload;
+    private final boolean mApfShouldHandleMdnsOffload;
+    private final boolean mIgnoreNudFailureEnabled;
 
     private InterfaceParams mInterfaceParams;
 
@@ -762,6 +847,15 @@ public class IpClient extends StateMachine {
     private int mMaxDtimMultiplier = DTIM_MULTIPLIER_RESET;
     private ApfCapabilities mCurrentApfCapabilities;
     private WakeupMessage mIpv6AutoconfTimeoutAlarm = null;
+    private boolean mIgnoreNudFailure;
+    // An array of NUD failure event count associated with the query database since the timestamps
+    // in the past, and is always initialized to null in StoppedState. Currently supported array
+    // elements are as follows:
+    // element 0: failures in the past week
+    // element 1: failures in the past day
+    // element 2: failures in the past 6h
+    @Nullable
+    private int[] mNudFailureEventCounts = null;
 
     /**
      * Reading the snapshot is an asynchronous operation initiated by invoking
@@ -887,12 +981,13 @@ public class IpClient extends StateMachine {
          * APF programs.
          * @see ApfFilter#maybeCreate
          */
-        public AndroidPacketFilter maybeCreateApfFilter(Context context,
+        public AndroidPacketFilter maybeCreateApfFilter(Handler handler, Context context,
                 ApfFilter.ApfConfiguration config, InterfaceParams ifParams,
                 IpClientCallbacksWrapper cb, NetworkQuirkMetrics networkQuirkMetrics,
                 boolean useNewApfFilter) {
             if (useNewApfFilter) {
-                return ApfFilter.maybeCreate(context, config, ifParams, cb, networkQuirkMetrics);
+                return ApfFilter.maybeCreate(handler, context, config, ifParams, cb,
+                        networkQuirkMetrics);
             } else {
                 return LegacyApfFilter.maybeCreate(context, config, ifParams, cb,
                         networkQuirkMetrics);
@@ -974,20 +1069,29 @@ public class IpClient extends StateMachine {
         mApfCounterPollingIntervalMs = mDependencies.getDeviceConfigPropertyInt(
                 CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS,
                 DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS) * DateUtils.SECOND_IN_MILLIS;
-        mUseNewApfFilter = SdkLevel.isAtLeastV() || mDependencies.isFeatureEnabled(context,
+        mUseNewApfFilter = SdkLevel.isAtLeastV() || mDependencies.isFeatureNotChickenedOut(context,
                 APF_NEW_RA_FILTER_VERSION);
         mEnableApfPollingCounters = mDependencies.isFeatureEnabled(context,
                 APF_POLLING_COUNTERS_VERSION);
-        mEnableIpClientIgnoreLowRaLifetime =
+        mIsAcceptRaMinLftEnabled =
                 SdkLevel.isAtLeastV() || mDependencies.isFeatureEnabled(context,
                         IPCLIENT_IGNORE_LOW_RA_LIFETIME_VERSION);
-        // Light doze mode status checking API is only available at T or later releases.
-        mApfShouldHandleLightDoze = SdkLevel.isAtLeastT() && mDependencies.isFeatureNotChickenedOut(
-                mContext, APF_HANDLE_LIGHT_DOZE_FORCE_DISABLE);
         mApfShouldHandleArpOffload = mDependencies.isFeatureNotChickenedOut(
-                mContext, APF_HANDLE_ARP_OFFLOAD_FORCE_DISABLE);
+                mContext, APF_HANDLE_ARP_OFFLOAD);
+        mApfShouldHandleNdOffload = mDependencies.isFeatureNotChickenedOut(
+                mContext, APF_HANDLE_ND_OFFLOAD);
+        // TODO: turn on APF mDNS offload.
+        mApfShouldHandleMdnsOffload = false;
         mPopulateLinkAddressLifetime = mDependencies.isFeatureEnabled(context,
                 IPCLIENT_POPULATE_LINK_ADDRESS_LIFETIME_VERSION);
+        mIgnoreNudFailureEnabled = mDependencies.isFeatureEnabled(mContext,
+                IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION);
+        mNudFailureCountDailyThreshold = mDependencies.getDeviceConfigPropertyInt(
+                CONFIG_NUD_FAILURE_COUNT_DAILY_THRESHOLD,
+                DEFAULT_NUD_FAILURE_COUNT_DAILY_THRESHOLD);
+        mNudFailureCountWeeklyThreshold = mDependencies.getDeviceConfigPropertyInt(
+                CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD,
+                DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD);
 
         IpClientLinkObserver.Configuration config = new IpClientLinkObserver.Configuration(
                 mMinRdnssLifetimeSec, mPopulateLinkAddressLifetime);
@@ -1022,10 +1126,15 @@ public class IpClient extends StateMachine {
                     public void onClatInterfaceStateUpdate(boolean add) {
                         getHandler().post(() -> {
                             if (mHasSeenClatInterface == add) return;
-                            // Clat interface information is spliced into LinkProperties by
-                            // ConnectivityService, so it cannot be added to the LinkProperties
-                            // here as those propagate back to ConnectivityService.
-                            mCallback.setNeighborDiscoveryOffload(add ? false : true);
+                            // If Apf is not supported or Apf doesn't support ND offload, then
+                            // configure the vendor ND offload feature based on the Clat
+                            // interface state.
+                            if (mApfFilter == null || !mApfFilter.supportNdOffload()) {
+                                // Clat interface information is spliced into LinkProperties by
+                                // ConnectivityService, so it cannot be added to the LinkProperties
+                                // here as those propagate back to ConnectivityService.
+                                mCallback.setNeighborDiscoveryOffload(add ? false : true);
+                            }
                             mHasSeenClatInterface = add;
                             if (mApfFilter != null) {
                                 mApfFilter.updateClatInterfaceState(add);
@@ -1163,6 +1272,7 @@ public class IpClient extends StateMachine {
         addState(mStoppedState);
         addState(mStartedState);
             addState(mPreconnectingState, mStartedState);
+            addState(mNudFailureQueryState, mStartedState);
             addState(mClearingIpAddressesState, mStartedState);
             addState(mRunningState, mStartedState);
         addState(mStoppingState);
@@ -1390,7 +1500,8 @@ public class IpClient extends StateMachine {
         pw.println(mTag + " APF dump:");
         pw.increaseIndent();
         if (apfFilter != null) {
-            if (apfCapabilities != null && apfFilter.hasDataAccess(apfCapabilities)) {
+            if (apfCapabilities != null && apfFilter.hasDataAccess(
+                    apfCapabilities.apfVersionSupported)) {
                 // Request a new snapshot, then wait for it.
                 mApfDataSnapshotComplete.close();
                 mCallback.startReadPacketFilter("dumpsys");
@@ -1398,7 +1509,16 @@ public class IpClient extends StateMachine {
                     pw.print("TIMEOUT: DUMPING STALE APF SNAPSHOT");
                 }
             }
-            apfFilter.dump(pw);
+            final Handler handler = getHandler();
+            if (handler == null) {
+                // This situation is unexpected. The getHandler() function should not return null
+                // unless the IpClient has stopped running. When the IpClient exits the RunningState
+                // , it should have already set apfFilter to null.
+                pw.println("ApfFilter is not null even if IpClient is not running.");
+            } else {
+                HandlerUtils.runWithScissorsForDump(handler, () -> apfFilter.dump(pw),
+                        10_000 /* ms */);
+            }
             pw.println("APF log:");
             pw.println("mApfDebug: " + mApfDebug);
             mApfLog.dump(fd, pw, args);
@@ -2160,17 +2280,20 @@ public class IpClient extends StateMachine {
     // Returns false if we have lost provisioning, true otherwise.
     private boolean handleLinkPropertiesUpdate(boolean sendCallbacks) {
         final LinkProperties newLp = assembleLinkProperties();
-        // LinkProperties.equals just compares if the interface addresses are identical,
-        // it doesn't compare the LinkAddress objects, so it considers two LinkProperties
-        // objects are identical even with different address lifetime. However, we may want
-        // to notify the caller whenever the link address lifetime is updated, especially
-        // after we enable populating the deprecationTime/expirationTime fields. The caller
-        // can get the latest address lifetime from the onLinkPropertiesChange callback.
+
+        // We need to call mApfFilter.setLinkProperties(newLp) every time there is a LinkAddress
+        // change because ApfFilter needs to know when addresses change from tentative to
+        // non-tentative. setLinkProperties() inside IpClient won't be called if the
+        // LinkProperties.equal() check returns true. The LinkProperties.equal() check does not
+        // currently take into account the LinkAddress flag change.
+        // It is OK to call mApfFilter.setLinkProperties() multiple times because if IP
+        // addresses are not updated, ApfFilter won't generate new program.
+        if (mApfFilter != null) {
+            mApfFilter.setLinkProperties(newLp);
+        }
+
         if (Objects.equals(newLp, mLinkProperties)) {
-            if (!mPopulateLinkAddressLifetime) return true;
-            if (LinkPropertiesUtils.isIdenticalAllLinkAddresses(newLp, mLinkProperties)) {
-                return true;
-            }
+            return true;
         }
 
         // Set an alarm to wait for IPv6 autoconf via SLAAC to succeed after receiving an RA,
@@ -2207,6 +2330,13 @@ public class IpClient extends StateMachine {
         // the gratuitous NA to update the first-hop router's neighbor cache entry.
         maybeSendMulticastNSes(newLp);
 
+        final boolean gainedV6 = !mLinkProperties.isIpv6Provisioned() && newLp.isIpv6Provisioned();
+        // mDelegatedPrefixes is updated as part of the call to assembleLinkProperties() above.
+        if (gainedV6 && !mDelegatedPrefixes.isEmpty()) {
+            mNetworkQuirkMetrics.setEvent(QE_DHCP6_PD_PROVISIONED);
+            mNetworkQuirkMetrics.statsWrite();
+        }
+
         // Either success IPv4 or IPv6 provisioning triggers new LinkProperties update,
         // wait for the provisioning completion and record the latency.
         mIpProvisioningMetrics.setIPv4ProvisionedLatencyOnFirstTime(newLp.isIpv4Provisioned());
@@ -2411,6 +2541,39 @@ public class IpClient extends StateMachine {
         return true;
     }
 
+    // In order to avoid overflowing the database (the maximum is 10MB) in case of a NUD failure
+    // happens frequently (e.g, every 30s in a broken network), we stop writing the NUD failure
+    // event to database if the event count in past 6h has exceeded the daily threshold.
+    private boolean shouldStopWritingNudFailureEventToDatabase() {
+        // NUD failure query has not completed yet.
+        if (mNudFailureEventCounts == null) return true;
+        return mNudFailureEventCounts[2] >= mNudFailureCountDailyThreshold;
+    }
+
+    private void maybeStoreNudFailureToDatabase(final NudEventType type) {
+        if (!mIgnoreNudFailureEnabled) return;
+        final int event = IpReachabilityMonitor.nudEventTypeToNetworkEvent(type);
+        // So far only NUD failure events due to organic kernel check are stored, which can be
+        // expanded to other causes later if necessary.
+        if (event != NETWORK_EVENT_NUD_FAILURE_ORGANIC) return;
+        if (shouldStopWritingNudFailureEventToDatabase()) return;
+
+        final long now = System.currentTimeMillis();
+        final long expiry = now + ONE_WEEK_IN_MS;
+        mIpMemoryStore.storeNetworkEvent(mCluster, now, expiry, event,
+                status -> {
+                    if (!status.isSuccess()) {
+                        Log.e(TAG, "Failed to store NUD failure event");
+                    }
+                });
+        if (DBG) {
+            Log.d(TAG, "store network event " + type
+                    + " at " + now
+                    + " expire at " + expiry
+                    + " with cluster " + mCluster);
+        }
+    }
+
     private boolean startIpReachabilityMonitor() {
         try {
             mIpReachabilityMonitor = mDependencies.getIpReachabilityMonitor(
@@ -2421,6 +2584,8 @@ public class IpClient extends StateMachine {
                     new IpReachabilityMonitor.Callback() {
                         @Override
                         public void notifyLost(String logMsg, NudEventType type) {
+                            maybeStoreNudFailureToDatabase(type);
+                            if (mIgnoreNudFailure) return;
                             final int version = mCallback.getInterfaceVersion();
                             if (version >= VERSION_ADDED_REACHABILITY_FAILURE) {
                                 final int reason = nudEventTypeToInt(type);
@@ -2463,7 +2628,7 @@ public class IpClient extends StateMachine {
         setIpv6Sysctl(ACCEPT_RA, 2);
         setIpv6Sysctl(ACCEPT_RA_DEFRTR, 1);
         maybeRestoreDadTransmits();
-        if (mUseNewApfFilter && mEnableIpClientIgnoreLowRaLifetime
+        if (mUseNewApfFilter && mIsAcceptRaMinLftEnabled
                 && mDependencies.hasIpv6Sysctl(mInterfaceName, ACCEPT_RA_MIN_LFT)) {
             setIpv6Sysctl(ACCEPT_RA_MIN_LFT, 0 /* sysctl default */);
         }
@@ -2556,17 +2721,24 @@ public class IpClient extends StateMachine {
     @Nullable
     private AndroidPacketFilter maybeCreateApfFilter(final ApfCapabilities apfCaps) {
         ApfFilter.ApfConfiguration apfConfig = new ApfFilter.ApfConfiguration();
-        apfConfig.apfCapabilities = apfCaps;
-        if (apfCaps != null && !SdkLevel.isAtLeastS()) {
-            // Due to potential OEM modifications in Android R, reconfigure
-            // apfVersionSupported using apfCapabilities.hasDataAccess() to ensure safe data
-            // region access within ApfFilter.
-            int apfVersionSupported = apfCaps.hasDataAccess() ? 3 : 2;
-            apfConfig.apfCapabilities = new ApfCapabilities(apfVersionSupported,
-                    apfCaps.maximumApfProgramSize, apfCaps.apfPacketFormat);
-        }
-        if (apfConfig.apfCapabilities != null && !SdkLevel.isAtLeastV()
-                && apfConfig.apfCapabilities.apfVersionSupported <= 4) {
+        if (apfCaps == null) {
+            return null;
+        }
+        // For now only support generating programs for Ethernet frames. If this restriction is
+        // lifted the program generator will need its offsets adjusted.
+        if (apfCaps.apfPacketFormat != ARPHRD_ETHER) return null;
+        if (SdkLevel.isAtLeastS()) {
+            apfConfig.apfVersionSupported = apfCaps.apfVersionSupported;
+        } else {
+            // In Android R, ApfCapabilities#hasDataAccess() can be modified by OEMs. The
+            // ApfFilter logic uses ApfCapabilities.apfVersionSupported to determine whether
+            // data region access is supported. Therefore, we need to recalculate
+            // ApfCapabilities.apfVersionSupported based on the return value of
+            // ApfCapabilities#hasDataAccess().
+            apfConfig.apfVersionSupported = apfCaps.hasDataAccess() ? 3 : 2;
+        }
+        apfConfig.apfRamSize = apfCaps.maximumApfProgramSize;
+        if (!SdkLevel.isAtLeastV() && apfConfig.apfVersionSupported <= 4) {
             apfConfig.installableProgramSizeClamp = 1024;
         }
         apfConfig.multicastFilter = mMulticastFiltering;
@@ -2585,7 +2757,7 @@ public class IpClient extends StateMachine {
         // Check the feature flag first before reading IPv6 sysctl, which can prevent from
         // triggering a potential kernel bug about the sysctl.
         // TODO: add unit test to check if the setIpv6Sysctl() is called or not.
-        if (mEnableIpClientIgnoreLowRaLifetime && mUseNewApfFilter
+        if (mIsAcceptRaMinLftEnabled && mUseNewApfFilter
                 && mDependencies.hasIpv6Sysctl(mInterfaceName, ACCEPT_RA_MIN_LFT)) {
             setIpv6Sysctl(ACCEPT_RA_MIN_LFT, mAcceptRaMinLft);
             final Integer acceptRaMinLft = getIpv6Sysctl(ACCEPT_RA_MIN_LFT);
@@ -2593,12 +2765,13 @@ public class IpClient extends StateMachine {
         } else {
             apfConfig.acceptRaMinLft = 0;
         }
-        apfConfig.shouldHandleLightDoze = mApfShouldHandleLightDoze;
         apfConfig.shouldHandleArpOffload = mApfShouldHandleArpOffload;
+        apfConfig.shouldHandleNdOffload = mApfShouldHandleNdOffload;
+        apfConfig.shouldHandleMdnsOffload = mApfShouldHandleMdnsOffload;
         apfConfig.minMetricsSessionDurationMs = mApfCounterPollingIntervalMs;
         apfConfig.hasClatInterface = mHasSeenClatInterface;
-        return mDependencies.maybeCreateApfFilter(mContext, apfConfig, mInterfaceParams,
-                mCallback, mNetworkQuirkMetrics, mUseNewApfFilter);
+        return mDependencies.maybeCreateApfFilter(getHandler(), mContext, apfConfig,
+                mInterfaceParams, mCallback, mNetworkQuirkMetrics, mUseNewApfFilter);
     }
 
     private boolean handleUpdateApfCapabilities(@NonNull final ApfCapabilities apfCapabilities) {
@@ -2627,6 +2800,7 @@ public class IpClient extends StateMachine {
             mGratuitousNaTargetAddresses.clear();
             mMulticastNsSourceAddresses.clear();
             mDelegatedPrefixes.clear();
+            mNudFailureEventCounts = null;
 
             resetLinkProperties();
             if (mStartTimeMillis > 0) {
@@ -2651,7 +2825,9 @@ public class IpClient extends StateMachine {
 
                 case CMD_START:
                     mConfiguration = (android.net.shared.ProvisioningConfiguration) msg.obj;
-                    transitionTo(mClearingIpAddressesState);
+                    transitionTo(mIgnoreNudFailureEnabled
+                            ? mNudFailureQueryState
+                            : mClearingIpAddressesState);
                     break;
 
                 case EVENT_NETLINK_LINKPROPERTIES_CHANGED:
@@ -3078,6 +3254,80 @@ public class IpClient extends StateMachine {
         return mConfiguration.mIPv4ProvisioningMode != PROV_IPV4_DISABLED;
     }
 
+    private boolean shouldIgnoreNudFailure(@NonNull final int[] eventCounts) {
+        if (!mIgnoreNudFailureEnabled) return false;
+        if (eventCounts.length == 0) return false;
+
+        final int countInPastOneWeek = eventCounts[0];
+        final int countInPastOneDay = eventCounts[1];
+        return countInPastOneDay >= mNudFailureCountDailyThreshold
+                || countInPastOneWeek >= mNudFailureCountWeeklyThreshold;
+    }
+
+    class NudFailureQueryState extends State {
+        // This listener runs in a different thread (the Executor used in the IpMemoryStoreService)
+        // and it needs to be volatile to allow access by other threads than the IpClient state
+        // machine handler, which should be fine since it only accesses the mListener and calls
+        // sendMessage.
+        private volatile OnNetworkEventCountRetrievedListener mListener =
+                new OnNetworkEventCountRetrievedListener() {
+                    @Override
+                    public void onNetworkEventCountRetrieved(Status status, int[] counts) {
+                        if (mListener != this) return;
+                        if (counts.length == 0) {
+                            if (!status.isSuccess()) {
+                                Log.e(TAG, "Error retrieving NUD failure event count: " + status);
+                            }
+                            sendMessage(EVENT_NUD_FAILURE_QUERY_FAILURE);
+                            return;
+                        }
+                        sendMessage(EVENT_NUD_FAILURE_QUERY_SUCCESS, counts);
+                    }};
+
+        @Override
+        public void enter() {
+            super.enter();
+            // Set a timeout for retrieving NUD failure event counts.
+            sendMessageDelayed(EVENT_NUD_FAILURE_QUERY_TIMEOUT, IPMEMORYSTORE_TIMEOUT_MS);
+            final long now = System.currentTimeMillis();
+            final long[] sinceTimes = new long[3];
+            sinceTimes[0] = now - ONE_WEEK_IN_MS;
+            sinceTimes[1] = now - ONE_DAY_IN_MS;
+            sinceTimes[2] = now - SIX_HOURS_IN_MS;
+            mIpMemoryStore.retrieveNetworkEventCount(mCluster, sinceTimes,
+                    NETWORK_EVENT_NUD_FAILURE_TYPES, mListener);
+        }
+
+        @Override
+        public boolean processMessage(Message message) {
+            switch (message.what) {
+                case EVENT_NUD_FAILURE_QUERY_FAILURE:
+                case EVENT_NUD_FAILURE_QUERY_TIMEOUT:
+                    // TODO: log query result with metrics.
+                    transitionTo(mClearingIpAddressesState);
+                    return HANDLED;
+
+                case EVENT_NUD_FAILURE_QUERY_SUCCESS:
+                    mNudFailureEventCounts = (int[]) message.obj;
+                    mIgnoreNudFailure = shouldIgnoreNudFailure(mNudFailureEventCounts);
+                    transitionTo(mClearingIpAddressesState);
+                    return HANDLED;
+
+                default:
+                    deferMessage(message); // e.g. LP updated during this state.
+                    return HANDLED;
+            }
+        }
+
+        @Override
+        public void exit() {
+            super.exit();
+            removeMessages(EVENT_NUD_FAILURE_QUERY_FAILURE);
+            removeMessages(EVENT_NUD_FAILURE_QUERY_TIMEOUT);
+            removeMessages(EVENT_NUD_FAILURE_QUERY_SUCCESS);
+        }
+    }
+
     class RunningState extends State {
         private ConnectivityPacketTracker mPacketTracker;
         private boolean mDhcpActionInFlight;
@@ -3092,6 +3342,10 @@ public class IpClient extends StateMachine {
             // at the beginning.
             mHasSeenClatInterface = false;
             mApfFilter = maybeCreateApfFilter(mCurrentApfCapabilities);
+            // If Apf supports ND offload, then turn off the vendor ND offload feature.
+            if (mApfFilter != null && mApfFilter.supportNdOffload()) {
+                mCallback.setNeighborDiscoveryOffload(false);
+            }
             // TODO: investigate the effects of any multicast filtering racing/interfering with the
             // rest of this IP configuration startup.
             if (mApfFilter == null) {
@@ -3413,6 +3667,8 @@ public class IpClient extends StateMachine {
                     if (!hasIpv6Address(mLinkProperties)
                             && mLinkProperties.hasIpv6DefaultRoute()) {
                         Log.d(TAG, "Network supports IPv6 but not autoconf, starting DHCPv6 PD");
+                        mNetworkQuirkMetrics.setEvent(QE_DHCP6_HEURISTIC_TRIGGERED);
+                        mNetworkQuirkMetrics.statsWrite();
                         startDhcp6PrefixDelegation();
                     }
                     break;
@@ -3547,6 +3803,10 @@ public class IpClient extends StateMachine {
                     final ApfCapabilities apfCapabilities = (ApfCapabilities) msg.obj;
                     if (handleUpdateApfCapabilities(apfCapabilities)) {
                         mApfFilter = maybeCreateApfFilter(apfCapabilities);
+                        // If Apf supports ND offload, then turn off the vendor ND offload feature.
+                        if (mApfFilter != null && mApfFilter.supportNdOffload()) {
+                            mCallback.setNeighborDiscoveryOffload(false);
+                        }
                     }
                     break;
 
diff --git a/src/android/net/ip/IpReachabilityMonitor.java b/src/android/net/ip/IpReachabilityMonitor.java
index 4e8185e3..462de907 100644
--- a/src/android/net/ip/IpReachabilityMonitor.java
+++ b/src/android/net/ip/IpReachabilityMonitor.java
@@ -30,6 +30,7 @@ import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_RO
 
 import android.content.Context;
 import android.net.ConnectivityManager;
+import android.net.IIpMemoryStore;
 import android.net.INetd;
 import android.net.LinkProperties;
 import android.net.RouteInfo;
@@ -837,4 +838,25 @@ public class IpReachabilityMonitor {
                 return INVALID_REACHABILITY_LOSS_TYPE;
         }
     }
+
+    /**
+     * Convert the NUD critical failure event type to NETWORK_EVENT constant defined in
+     * IIpMemoryStore.
+     */
+    public static int nudEventTypeToNetworkEvent(final NudEventType type) {
+        switch (type) {
+            case NUD_POST_ROAMING_FAILED_CRITICAL:
+                return IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM;
+            case NUD_CONFIRM_FAILED_CRITICAL:
+                return IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_CONFIRM;
+            case NUD_ORGANIC_FAILED_CRITICAL:
+                return IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC;
+            case NUD_POST_ROAMING_MAC_ADDRESS_CHANGED:
+            case NUD_CONFIRM_MAC_ADDRESS_CHANGED:
+            case NUD_ORGANIC_MAC_ADDRESS_CHANGED:
+                return IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED;
+            default:
+                return INVALID_REACHABILITY_LOSS_TYPE;
+        }
+    }
 }
diff --git a/src/android/net/util/RawSocketUtils.java b/src/android/net/util/RawSocketUtils.java
new file mode 100644
index 00000000..a6c8a40b
--- /dev/null
+++ b/src/android/net/util/RawSocketUtils.java
@@ -0,0 +1,115 @@
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
+package android.net.util;
+
+import static android.Manifest.permission.NETWORK_SETTINGS;
+import static android.system.OsConstants.AF_PACKET;
+import static android.system.OsConstants.SOCK_NONBLOCK;
+import static android.system.OsConstants.SOCK_RAW;
+
+import static com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN;
+import static com.android.net.module.util.NetworkStackConstants.ETHER_DST_ADDR_OFFSET;
+import static com.android.net.module.util.NetworkStackConstants.ETHER_TYPE_LENGTH;
+import static com.android.net.module.util.NetworkStackConstants.ETHER_TYPE_OFFSET;
+
+import android.annotation.RequiresPermission;
+import android.content.Context;
+import android.net.TetheringManager;
+import android.system.Os;
+
+import androidx.annotation.NonNull;
+
+import com.android.internal.util.HexDump;
+
+import java.io.FileDescriptor;
+import java.net.NetworkInterface;
+import java.net.SocketAddress;
+import java.util.Arrays;
+import java.util.List;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.TimeoutException;
+
+public class RawSocketUtils {
+    // For isTetheredInterface, a quick Tethering event callback is expected
+    // since there's no start/stop Tethering involved. This timeout allows
+    // system messages to be handled, preventing flaky test results.
+    private static final int TETHERING_EVENT_CALLBACK_TIMEOUT_MS = 3000;
+
+    /**
+     * Send a raw packet represents in Hex format to the downstream interface.
+     * <p>
+     * Note that the target interface is limited to tethering downstream
+     * for security considerations.
+     */
+    @RequiresPermission(NETWORK_SETTINGS)
+    public static void sendRawPacketDownStream(@NonNull Context context, @NonNull String ifaceName,
+                                     @NonNull String packetInHex) throws Exception {
+        // 1. Verify Tethering Downstream Interface.
+        enforceTetheredInterface(context, ifaceName);
+
+        // 2. Hex to Byte Array Conversion
+        final byte[] packetData = HexDump.hexStringToByteArray(packetInHex);
+        final byte[] destMac = Arrays.copyOfRange(packetData, ETHER_DST_ADDR_OFFSET,
+                ETHER_DST_ADDR_OFFSET + ETHER_ADDR_LEN);
+        final byte[] etherTypeBytes = Arrays.copyOfRange(packetData, ETHER_TYPE_OFFSET,
+                ETHER_TYPE_OFFSET + ETHER_TYPE_LENGTH);
+        final int etherType = ((etherTypeBytes[0] & 0xFF) << 8) | (etherTypeBytes[1] & 0xFF);
+
+        // 3. Obtain Network Interface
+        final NetworkInterface iface = NetworkInterface.getByName(ifaceName);
+        if (iface == null) {
+            throw new IllegalArgumentException("Invalid network interface: " + ifaceName);
+        }
+
+        // 4. Construct and Send Packet.
+        final SocketAddress addr = SocketUtils.makePacketSocketAddress(
+                etherType,
+                iface.getIndex(),
+                destMac
+        );
+        final FileDescriptor sock = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
+        try {
+            Os.sendto(sock, packetData, 0, packetData.length, 0, addr);
+        } finally {
+            SocketUtils.closeSocket(sock);
+        }
+    }
+
+    @RequiresPermission(NETWORK_SETTINGS)
+    private static void enforceTetheredInterface(@NonNull Context context,
+                                               @NonNull String interfaceName)
+            throws ExecutionException, InterruptedException, TimeoutException {
+        final TetheringManager tm = context.getSystemService(TetheringManager.class);
+        final CompletableFuture<List<String>> tetheredInterfaces = new CompletableFuture<>();
+        final TetheringManager.TetheringEventCallback callback =
+                new TetheringManager.TetheringEventCallback() {
+                    @Override
+                    public void onTetheredInterfacesChanged(@NonNull List<String> interfaces) {
+                        tetheredInterfaces.complete(interfaces);
+                    }
+                };
+        tm.registerTetheringEventCallback(c -> c.run() /* executor */, callback);
+        final List<String> tetheredIfaces = tetheredInterfaces.get(
+                TETHERING_EVENT_CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+        if (!tetheredIfaces.contains(interfaceName)) {
+            throw new SecurityException("Only tethered interfaces " + tetheredIfaces
+                    + " are expected, but got " + interfaceName);
+        }
+    }
+}
diff --git a/src/com/android/networkstack/ipmemorystore/IpMemoryStoreDatabase.java b/src/com/android/networkstack/ipmemorystore/IpMemoryStoreDatabase.java
index 9e7df829..b00c03d2 100644
--- a/src/com/android/networkstack/ipmemorystore/IpMemoryStoreDatabase.java
+++ b/src/com/android/networkstack/ipmemorystore/IpMemoryStoreDatabase.java
@@ -35,8 +35,11 @@ import android.util.Log;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.internal.annotations.VisibleForTesting;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
+import java.io.File;
 import java.net.InetAddress;
 import java.net.UnknownHostException;
 import java.util.ArrayList;
@@ -144,6 +147,42 @@ public class IpMemoryStoreDatabase {
         public static final String DROP_TABLE = "DROP TABLE IF EXISTS " + TABLENAME;
     }
 
+    /**
+     * Contract class for the network events table.
+     */
+    public static final class NetworkEventsContract {
+        private NetworkEventsContract() {}
+
+        public static final String TABLENAME = "NetworkEvents";
+
+        public static final String COLNAME_CLUSTER = "cluster";
+        public static final String COLTYPE_CLUSTER = "TEXT NOT NULL";
+
+        public static final String COLNAME_TIMESTAMP = "timestamp";
+        public static final String COLTYPE_TIMESTAMP = "BIGINT";
+
+        public static final String COLNAME_EVENTTYPE = "eventType";
+        public static final String COLTYPE_EVENTTYPE = "INTEGER";
+
+        public static final String COLNAME_EXPIRY = "expiry";
+        // Milliseconds since the Epoch, in true Java style
+        public static final String COLTYPE_EXPIRY = "BIGINT";
+
+        public static final String CREATE_TABLE = "CREATE TABLE IF NOT EXISTS "
+                + TABLENAME           + " ("
+                + COLNAME_CLUSTER     + " " + COLTYPE_CLUSTER    + ", "
+                + COLNAME_TIMESTAMP   + " " + COLTYPE_TIMESTAMP  + ", "
+                + COLNAME_EVENTTYPE   + " " + COLTYPE_EVENTTYPE  + ", "
+                + COLNAME_EXPIRY      + " " + COLTYPE_EXPIRY     + ")";
+        public static final String INDEX_NAME = "idx_" + COLNAME_CLUSTER + "_" + COLNAME_TIMESTAMP
+                + "_" + COLNAME_EVENTTYPE;
+        public static final String CREATE_INDEX = "CREATE INDEX IF NOT EXISTS " + INDEX_NAME
+                + " ON " + TABLENAME
+                + " (" + COLNAME_CLUSTER + ", " + COLNAME_TIMESTAMP + ", " + COLNAME_EVENTTYPE
+                + ")";
+        public static final String DROP_TABLE = "DROP TABLE IF EXISTS " + TABLENAME;
+    }
+
     // To save memory when the DB is not used, close it after 30s of inactivity. This is
     // determined manually based on what feels right.
     private static final long IDLE_CONNECTION_TIMEOUT_MS = 30_000;
@@ -151,22 +190,30 @@ public class IpMemoryStoreDatabase {
     /** The SQLite DB helper */
     public static class DbHelper extends SQLiteOpenHelper {
         // Update this whenever changing the schema.
-        // DO NOT CHANGE without solid testing for downgrades, and checking onDowngrade
-        // below: b/171340630
-        private static final int SCHEMA_VERSION = 4;
-        private static final String DATABASE_FILENAME = "IpMemoryStore.db";
+        @VisibleForTesting
+        static final int SCHEMA_VERSION = 5;
+        private static final String DATABASE_FILENAME = "IpMemoryStoreV2.db";
         private static final String TRIGGER_NAME = "delete_cascade_to_private";
+        private static final String LEGACY_DATABASE_FILENAME = "IpMemoryStore.db";
 
         public DbHelper(@NonNull final Context context) {
             super(context, DATABASE_FILENAME, null, SCHEMA_VERSION);
             setIdleConnectionTimeout(IDLE_CONNECTION_TIMEOUT_MS);
         }
 
+        @VisibleForTesting
+        DbHelper(@NonNull final Context context, int schemaVersion) {
+            super(context, DATABASE_FILENAME, null, schemaVersion);
+            setIdleConnectionTimeout(IDLE_CONNECTION_TIMEOUT_MS);
+        }
+
         /** Called when the database is created */
         @Override
         public void onCreate(@NonNull final SQLiteDatabase db) {
             db.execSQL(NetworkAttributesContract.CREATE_TABLE);
             db.execSQL(PrivateDataContract.CREATE_TABLE);
+            db.execSQL(NetworkEventsContract.CREATE_TABLE);
+            db.execSQL(NetworkEventsContract.CREATE_INDEX);
             createTrigger(db);
         }
 
@@ -192,11 +239,20 @@ public class IpMemoryStoreDatabase {
                 if (oldVersion < 4) {
                     createTrigger(db);
                 }
+
+                if (oldVersion < 5) {
+                    // upgrade from version 4 to version 5, the NetworkEventsTable doesn't exist
+                    // on previous version and onCreate won't be called during upgrade, therefore,
+                    // create the table manually.
+                    db.execSQL(NetworkEventsContract.CREATE_TABLE);
+                    db.execSQL(NetworkEventsContract.CREATE_INDEX);
+                }
             } catch (SQLiteException e) {
                 Log.e(TAG, "Could not upgrade to the new version", e);
                 // create database with new version
                 db.execSQL(NetworkAttributesContract.DROP_TABLE);
                 db.execSQL(PrivateDataContract.DROP_TABLE);
+                db.execSQL(NetworkEventsContract.DROP_TABLE);
                 onCreate(db);
             }
         }
@@ -208,11 +264,7 @@ public class IpMemoryStoreDatabase {
             // Downgrades always nuke all data and recreate an empty table.
             db.execSQL(NetworkAttributesContract.DROP_TABLE);
             db.execSQL(PrivateDataContract.DROP_TABLE);
-            // TODO: add test for downgrades. Triggers should already be dropped
-            // when the table is dropped, so this may be a bug.
-            // Note that fixing this code does not affect how older versions
-            // will handle downgrades.
-            db.execSQL("DROP TRIGGER " + TRIGGER_NAME);
+            db.execSQL(NetworkEventsContract.DROP_TABLE);
             onCreate(db);
         }
 
@@ -226,6 +278,33 @@ public class IpMemoryStoreDatabase {
                     + "; END;";
             db.execSQL(createTrigger);
         }
+
+        /**
+         * Renames the database file to prevent crashes during downgrades.
+         * <p>
+         * Previous versions (before 5) has a bug(b/171340630) that would cause a crash when
+         * onDowngrade is triggered. We cannot just bump the schema version without
+         * renaming the database filename, because only bumping the schema version still causes
+         * crash when downgrading to an older version.
+         * <p>
+         * After rename the db file, if the module is rolled back, the legacy file is not present.
+         * The code will create a new legacy database, and will trigger onCreate path. The new
+         * database will continue to exist, but the legacy code does not know about it.
+         * <p>
+         * In later stage, if the module is rolled forward again, the legacy database will overwrite
+         * the new database, the user's data will be preserved.
+         */
+        public static void maybeRenameDatabaseFile(Context context) {
+            final File legacyDb = context.getDatabasePath(LEGACY_DATABASE_FILENAME);
+            if (legacyDb.exists()) {
+                final File newDb = context.getDatabasePath(DATABASE_FILENAME);
+                final boolean result = legacyDb.renameTo(newDb);
+                if (!result) {
+                    Log.w(TAG, "failed to rename the IP Memory store database to "
+                            + DATABASE_FILENAME);
+                }
+            }
+        }
     }
 
     @NonNull
@@ -304,6 +383,22 @@ public class IpMemoryStoreDatabase {
         return values;
     }
 
+    /**
+     * Convert a network event (including cluster, timestamp of when it happened, expiry and
+     * event type) into content values to store them in a table compliant with the ontract defined
+     * in NetworkEventsContract.
+     */
+    @NonNull
+    private static ContentValues toContentValues(@NonNull final String cluster,
+            final long timestamp, final long expiry, final int eventType) {
+        final ContentValues values = new ContentValues();
+        values.put(NetworkEventsContract.COLNAME_CLUSTER, cluster);
+        values.put(NetworkEventsContract.COLNAME_TIMESTAMP, timestamp);
+        values.put(NetworkEventsContract.COLNAME_EVENTTYPE, eventType);
+        values.put(NetworkEventsContract.COLNAME_EXPIRY, expiry);
+        return values;
+    }
+
     @Nullable
     private static NetworkAttributes readNetworkAttributesLine(@NonNull final Cursor cursor) {
         // Make sure the data hasn't expired
@@ -455,6 +550,7 @@ public class IpMemoryStoreDatabase {
             try {
                 db.delete(NetworkAttributesContract.TABLENAME, null, null);
                 db.delete(PrivateDataContract.TABLENAME, null, null);
+                db.delete(NetworkEventsContract.TABLENAME, null, null);
                 try (Cursor cursorNetworkAttributes = db.query(
                         // table name
                         NetworkAttributesContract.TABLENAME,
@@ -481,6 +577,19 @@ public class IpMemoryStoreDatabase {
                         "1")) { // limit
                     if (0 != cursorPrivateData.getCount()) continue;
                 }
+                try (Cursor cursorNetworkEvents = db.query(
+                        // table name
+                        NetworkEventsContract.TABLENAME,
+                        // column name
+                        new String[] { NetworkEventsContract.COLNAME_CLUSTER },
+                        null, // selection
+                        null, // selectionArgs
+                        null, // groupBy
+                        null, // having
+                        null, // orderBy
+                        "1")) { // limit
+                    if (0 != cursorNetworkEvents.getCount()) continue;
+                }
                 db.setTransactionSuccessful();
             } catch (SQLiteException e) {
                 Log.e(TAG, "Could not wipe the data in database", e);
@@ -665,10 +774,15 @@ public class IpMemoryStoreDatabase {
     static int dropAllExpiredRecords(@NonNull final SQLiteDatabase db) {
         db.beginTransaction();
         try {
+            final long currentTimestamp = System.currentTimeMillis();
             // Deletes NetworkAttributes that have expired.
             db.delete(NetworkAttributesContract.TABLENAME,
                     NetworkAttributesContract.COLNAME_EXPIRYDATE + " < ?",
-                    new String[]{Long.toString(System.currentTimeMillis())});
+                    new String[]{Long.toString(currentTimestamp)});
+            // Deletes NetworkEvents that have expired.
+            db.delete(NetworkEventsContract.TABLENAME,
+                    NetworkEventsContract.COLNAME_EXPIRY + " < ?",
+                    new String[]{Long.toString(currentTimestamp)});
             db.setTransactionSuccessful();
         } catch (SQLiteException e) {
             Log.e(TAG, "Could not delete data from memory store", e);
@@ -749,6 +863,66 @@ public class IpMemoryStoreDatabase {
         }
     }
 
+    static int storeNetworkEvent(@NonNull final SQLiteDatabase db, @NonNull final String cluster,
+            final long timestamp, final long expiry, final int eventType) {
+        final ContentValues cv = toContentValues(cluster, timestamp, expiry, eventType);
+        db.beginTransaction();
+        try {
+            final long resultId = db.insertOrThrow(NetworkEventsContract.TABLENAME,
+                    null /* nullColumnHack */, cv);
+            if (resultId < 0) {
+                // Should not fail to insert a row to NetworkEvents table which doesn't have
+                // uniqueness constraint.
+                return Status.ERROR_STORAGE;
+            }
+            db.setTransactionSuccessful();
+            return Status.SUCCESS;
+        } catch (SQLiteException e) {
+            // No space left on disk or something
+            Log.e(TAG, "Could not write to the memory store", e);
+        } finally {
+            db.endTransaction();
+        }
+        return Status.ERROR_STORAGE;
+    }
+
+    static int[] retrieveNetworkEventCount(@NonNull final SQLiteDatabase db,
+            @NonNull final String cluster, @NonNull final long[] sinceTimes,
+            @NonNull final int[] eventTypes) {
+        final int[] counts = new int[sinceTimes.length];
+        for (int i = 0; i < counts.length; i++) {
+            final String[] selectionArgs = new String[eventTypes.length + 2];
+            selectionArgs[0] = cluster;
+            selectionArgs[1] = String.valueOf(sinceTimes[i]);
+            for (int j = 0; j < eventTypes.length; j++) {
+                selectionArgs[j + 2] = String.valueOf(eventTypes[j]);
+            }
+            final StringBuilder selectionBuilder =
+                    new StringBuilder(NetworkEventsContract.COLNAME_CLUSTER + " = ? " + "AND "
+                            + NetworkEventsContract.COLNAME_TIMESTAMP + " >= ? " + "AND "
+                            + NetworkEventsContract.COLNAME_EVENTTYPE + " IN (");
+            for (int k = 0; k < eventTypes.length; k++) {
+                selectionBuilder.append("?");
+                if (k < eventTypes.length - 1) {
+                    selectionBuilder.append(",");
+                }
+            }
+            selectionBuilder.append(")");
+            try (Cursor cursor = db.query(
+                    NetworkEventsContract.TABLENAME,
+                    new String[] {"COUNT(*)"}, // columns
+                    selectionBuilder.toString(),
+                    selectionArgs,
+                    null, // groupBy
+                    null, // having
+                    null)) { // orderBy
+                cursor.moveToFirst();
+                counts[i] = cursor.getInt(0);
+            }
+        }
+        return counts;
+    }
+
     // Helper methods
     private static String getString(final Cursor cursor, final String columnName) {
         final int columnIndex = cursor.getColumnIndex(columnName);
diff --git a/src/com/android/networkstack/ipmemorystore/IpMemoryStoreService.java b/src/com/android/networkstack/ipmemorystore/IpMemoryStoreService.java
index 76ed56c4..de06b64b 100644
--- a/src/com/android/networkstack/ipmemorystore/IpMemoryStoreService.java
+++ b/src/com/android/networkstack/ipmemorystore/IpMemoryStoreService.java
@@ -32,6 +32,7 @@ import android.net.ipmemorystore.Blob;
 import android.net.ipmemorystore.IOnBlobRetrievedListener;
 import android.net.ipmemorystore.IOnL2KeyResponseListener;
 import android.net.ipmemorystore.IOnNetworkAttributesRetrievedListener;
+import android.net.ipmemorystore.IOnNetworkEventCountRetrievedListener;
 import android.net.ipmemorystore.IOnSameL3NetworkResponseListener;
 import android.net.ipmemorystore.IOnStatusAndCountListener;
 import android.net.ipmemorystore.IOnStatusListener;
@@ -86,6 +87,9 @@ public class IpMemoryStoreService extends IIpMemoryStore.Stub {
      * @param context the context to access storage with.
      */
     public IpMemoryStoreService(@NonNull final Context context) {
+        // Before doing anything at all, rename the legacy database if necessary.
+        IpMemoryStoreDatabase.DbHelper.maybeRenameDatabaseFile(context);
+
         // Note that constructing the service will access the disk and block
         // for some time, but it should make no difference to the clients. Because
         // the interface is one-way, clients fire and forget requests, and the callback
@@ -484,6 +488,100 @@ public class IpMemoryStoreService extends IIpMemoryStore.Stub {
         });
     }
 
+    /**
+     * Retrieve the specific network event counts for a given cluster and event type since one or
+     * more timestamps in the past.
+     *
+     * @param cluster The cluster to query.
+     * @param sinceTimes An array of timestamps in the past. The query will return an array of
+     *                   equal size. Each element in the array will contain the number of network
+     *                   events between the corresponding timestamp and the current time, e.g. query
+     *                   since the last week and/or the last day.
+     * @param eventTypes An array of network event types to query, which can be one or more of the
+     *                   above NETWORK_EVENT constants.
+     * @param listener The listener that will be invoked to return the answer.
+     * returns (through the listener) The event counts associated with the query, or an empty array
+     *                                if the query failed.
+     */
+    @Override
+    public void retrieveNetworkEventCount(@NonNull final String cluster,
+            @NonNull final long[] sinceTimes,
+            @NonNull final int[] eventTypes,
+            @Nullable final IOnNetworkEventCountRetrievedListener listener) {
+        if (null == listener) return;
+        mExecutor.execute(() -> {
+            try {
+                if (null == cluster) {
+                    listener.onNetworkEventCountRetrieved(
+                            makeStatus(ERROR_ILLEGAL_ARGUMENT), new int[0] /* counts */);
+                    return;
+                }
+                if (0 == sinceTimes.length) {
+                    listener.onNetworkEventCountRetrieved(
+                            makeStatus(ERROR_ILLEGAL_ARGUMENT), new int[0] /* counts */);
+                    return;
+                }
+                if (null == mDb) {
+                    listener.onNetworkEventCountRetrieved(
+                            makeStatus(ERROR_DATABASE_CANNOT_BE_OPENED), new int[0] /* counts */);
+                    return;
+                }
+                try {
+                    final int[] counts = IpMemoryStoreDatabase.retrieveNetworkEventCount(mDb,
+                            cluster, sinceTimes, eventTypes);
+                    listener.onNetworkEventCountRetrieved(makeStatus(SUCCESS), counts);
+                } catch (final Exception e) {
+                    listener.onNetworkEventCountRetrieved(makeStatus(ERROR_GENERIC),
+                            new int[0] /* counts */);
+                }
+            } catch (final RemoteException e) {
+                // Client at the other end died
+            }
+        });
+    }
+
+    /**
+     * Store a specific network event to database for a given cluster.
+     *
+     * @param cluster The cluster representing a notion of network group (e.g., BSSIDs with the
+     *                same SSID).
+     * @param timestamp The timestamp {@link System.currentTimeMillis} when a specific network
+     *                  event occurred.
+     * @param expiry The timestamp {@link System.currentTimeMillis} when a specific network
+     *               event stored in the database expires, e.g. it might be one week from now.
+     * @param eventType One of the NETWORK_EVENT constants above.
+     * @param listener A listener that will be invoked to inform of the completion of this call.
+     * returns (through the listener) A status to indicate success or failure.
+     */
+    @Override
+    public void storeNetworkEvent(@NonNull final String cluster,
+            final long timestamp,
+            final long expiry,
+            final int eventType,
+            @Nullable final IOnStatusListener listener) {
+        mExecutor.execute(() -> {
+            try {
+                if (null == cluster) {
+                    listener.onComplete(makeStatus(ERROR_ILLEGAL_ARGUMENT));
+                    return;
+                }
+                if (null == mDb) {
+                    listener.onComplete(makeStatus(ERROR_DATABASE_CANNOT_BE_OPENED));
+                    return;
+                }
+                try {
+                    final int code = IpMemoryStoreDatabase.storeNetworkEvent(mDb, cluster,
+                            timestamp, expiry, eventType);
+                    if (null != listener) listener.onComplete(makeStatus(code));
+                } catch (final Exception e) {
+                    if (null != listener) listener.onComplete(makeStatus(ERROR_GENERIC));
+                }
+            } catch (final RemoteException e) {
+                // Client at the other end died
+            }
+        });
+    }
+
     /** Get db size threshold. */
     @VisibleForTesting
     protected int getDbSizeThreshold() {
diff --git a/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java b/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java
index d1776c90..c2c51f6f 100644
--- a/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java
+++ b/src/com/android/networkstack/metrics/ApfSessionInfoMetrics.java
@@ -16,11 +16,115 @@
 
 package com.android.networkstack.metrics;
 
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_802_3_FRAME;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_NON_IPV4;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_OTHER_HOST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REPLY_SPA_NO_HOST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_ANYHOST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_UNKNOWN;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_V6_ONLY;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETH_BROADCAST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_GARP_REPLY;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_ADDR;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_NET;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_KEEPALIVE_ACK;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_L2_BROADCAST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_MULTICAST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NATT_KEEPALIVE;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_TCP_PORT7_UNICAST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_KEEPALIVE_ACK;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_NA;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_PING;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NON_ICMP_MULTICAST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_ROUTER_SOLICITATION;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS;
+import static android.net.apf.ApfCounterTracker.Counter.DROPPED_RA;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_NON_IPV4;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNKNOWN;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_DHCP;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_UNICAST;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_UNICAST_NON_ICMP;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_MDNS;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_MLD;
+import static android.net.apf.ApfCounterTracker.Counter.PASSED_NON_IP_UNICAST;
+import static android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS;
+import static android.stats.connectivity.CounterName.CN_DROPPED_802_3_FRAME;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_NON_IPV4;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_OTHER_HOST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_REPLY_SPA_NO_HOST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_REQUEST_ANYHOST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_REQUEST_REPLIED;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_UNKNOWN;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_V6_ONLY;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ETHERTYPE_NOT_ALLOWED;
+import static android.stats.connectivity.CounterName.CN_DROPPED_ETH_BROADCAST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_GARP_REPLY;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_BROADCAST_ADDR;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_BROADCAST_NET;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_KEEPALIVE_ACK;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_L2_BROADCAST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_MULTICAST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_NATT_KEEPALIVE;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_NON_DHCP4;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_KEEPALIVE_ACK;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_MULTICAST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_MULTICAST_NA;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_MULTICAST_PING;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NON_ICMP_MULTICAST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_INVALID;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_OTHER_HOST;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_REPLIED_NON_DAD;
+import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_ROUTER_SOLICITATION;
+import static android.stats.connectivity.CounterName.CN_DROPPED_MDNS;
+import static android.stats.connectivity.CounterName.CN_DROPPED_RA;
+import static android.stats.connectivity.CounterName.CN_PASSED_ARP;
+import static android.stats.connectivity.CounterName.CN_PASSED_ARP_BROADCAST_REPLY;
+import static android.stats.connectivity.CounterName.CN_PASSED_ARP_REQUEST;
+import static android.stats.connectivity.CounterName.CN_PASSED_ARP_UNICAST_REPLY;
+import static android.stats.connectivity.CounterName.CN_PASSED_DHCP;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV4;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV4_FROM_DHCPV4_SERVER;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV4_UNICAST;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_ICMP;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NON_ICMP;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_DAD;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_NO_ADDRESS;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_NO_SLLA_OPTION;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_TENTATIVE;
+import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_UNICAST_NON_ICMP;
+import static android.stats.connectivity.CounterName.CN_PASSED_MDNS;
+import static android.stats.connectivity.CounterName.CN_PASSED_MLD;
+import static android.stats.connectivity.CounterName.CN_PASSED_NON_IP_UNICAST;
+import static android.stats.connectivity.CounterName.CN_TOTAL_PACKETS;
+import static android.stats.connectivity.CounterName.CN_UNKNOWN;
+
 import android.net.apf.ApfCounterTracker.Counter;
 import android.stats.connectivity.CounterName;
 
 import androidx.annotation.VisibleForTesting;
 
+import java.util.EnumMap;
+import java.util.Map;
+
 /**
  * Class to record the network stack ApfSessionInfo metrics into statsd.
  *
@@ -31,6 +135,65 @@ import androidx.annotation.VisibleForTesting;
 public class ApfSessionInfoMetrics {
     // Define the maximum size of the counter list
     public static final int MAX_NUM_OF_COUNTERS = Counter.class.getEnumConstants().length - 1;
+    private static final EnumMap<Counter, CounterName> apfCounterMetricsMap = new EnumMap<>(
+            Map.ofEntries(
+                Map.entry(TOTAL_PACKETS, CN_TOTAL_PACKETS),
+                // The counter sequence should be keep the same in ApfCounterTracker.java
+                Map.entry(PASSED_ARP, CN_PASSED_ARP),
+                Map.entry(PASSED_ARP_BROADCAST_REPLY, CN_PASSED_ARP_BROADCAST_REPLY),
+                // deprecated in ApfFilter, PASSED_ARP_NON_IPV4 ==> DROPPED_ARP_NON_IPV4
+                Map.entry(PASSED_ARP_NON_IPV4, CN_UNKNOWN),
+                Map.entry(PASSED_ARP_REQUEST, CN_PASSED_ARP_REQUEST),
+                Map.entry(PASSED_ARP_UNICAST_REPLY, CN_PASSED_ARP_UNICAST_REPLY),
+                // deprecated in ApfFilter, PASSED_ARP_UNKNOWN  ==> DROPPED_ARP_UNKNOWN
+                Map.entry(PASSED_ARP_UNKNOWN, CN_UNKNOWN),
+                Map.entry(PASSED_DHCP, CN_PASSED_DHCP),
+                Map.entry(PASSED_IPV4, CN_PASSED_IPV4),
+                Map.entry(PASSED_IPV4_FROM_DHCPV4_SERVER, CN_PASSED_IPV4_FROM_DHCPV4_SERVER),
+                Map.entry(PASSED_IPV4_UNICAST, CN_PASSED_IPV4_UNICAST),
+                Map.entry(PASSED_IPV6_ICMP, CN_PASSED_IPV6_ICMP),
+                Map.entry(PASSED_IPV6_NON_ICMP, CN_PASSED_IPV6_NON_ICMP),
+                Map.entry(PASSED_IPV6_NS_DAD, CN_PASSED_IPV6_NS_DAD),
+                Map.entry(PASSED_IPV6_NS_NO_ADDRESS, CN_PASSED_IPV6_NS_NO_ADDRESS),
+                Map.entry(PASSED_IPV6_NS_NO_SLLA_OPTION, CN_PASSED_IPV6_NS_NO_SLLA_OPTION),
+                Map.entry(PASSED_IPV6_NS_TENTATIVE, CN_PASSED_IPV6_NS_TENTATIVE),
+                Map.entry(PASSED_IPV6_UNICAST_NON_ICMP, CN_PASSED_IPV6_UNICAST_NON_ICMP),
+                Map.entry(PASSED_NON_IP_UNICAST, CN_PASSED_NON_IP_UNICAST),
+                Map.entry(PASSED_MDNS, CN_PASSED_MDNS),
+                Map.entry(PASSED_MLD, CN_PASSED_MLD),
+                Map.entry(DROPPED_ETH_BROADCAST, CN_DROPPED_ETH_BROADCAST),
+                Map.entry(DROPPED_RA, CN_DROPPED_RA),
+                Map.entry(DROPPED_IPV4_L2_BROADCAST, CN_DROPPED_IPV4_L2_BROADCAST),
+                Map.entry(DROPPED_IPV4_BROADCAST_ADDR, CN_DROPPED_IPV4_BROADCAST_ADDR),
+                Map.entry(DROPPED_IPV4_BROADCAST_NET, CN_DROPPED_IPV4_BROADCAST_NET),
+                Map.entry(DROPPED_IPV4_MULTICAST, CN_DROPPED_IPV4_MULTICAST),
+                Map.entry(DROPPED_IPV4_NON_DHCP4, CN_DROPPED_IPV4_NON_DHCP4),
+                Map.entry(DROPPED_IPV6_ROUTER_SOLICITATION, CN_DROPPED_IPV6_ROUTER_SOLICITATION),
+                Map.entry(DROPPED_IPV6_MULTICAST_NA, CN_DROPPED_IPV6_MULTICAST_NA),
+                Map.entry(DROPPED_IPV6_MULTICAST, CN_DROPPED_IPV6_MULTICAST),
+                Map.entry(DROPPED_IPV6_MULTICAST_PING, CN_DROPPED_IPV6_MULTICAST_PING),
+                Map.entry(DROPPED_IPV6_NON_ICMP_MULTICAST, CN_DROPPED_IPV6_NON_ICMP_MULTICAST),
+                Map.entry(DROPPED_IPV6_NS_INVALID, CN_DROPPED_IPV6_NS_INVALID),
+                Map.entry(DROPPED_IPV6_NS_OTHER_HOST, CN_DROPPED_IPV6_NS_OTHER_HOST),
+                Map.entry(DROPPED_IPV6_NS_REPLIED_NON_DAD, CN_DROPPED_IPV6_NS_REPLIED_NON_DAD),
+                Map.entry(DROPPED_802_3_FRAME, CN_DROPPED_802_3_FRAME),
+                Map.entry(DROPPED_ETHERTYPE_NOT_ALLOWED, CN_DROPPED_ETHERTYPE_NOT_ALLOWED),
+                Map.entry(DROPPED_IPV4_KEEPALIVE_ACK, CN_DROPPED_IPV4_KEEPALIVE_ACK),
+                Map.entry(DROPPED_IPV6_KEEPALIVE_ACK, CN_DROPPED_IPV6_KEEPALIVE_ACK),
+                Map.entry(DROPPED_IPV4_NATT_KEEPALIVE, CN_DROPPED_IPV4_NATT_KEEPALIVE),
+                Map.entry(DROPPED_MDNS, CN_DROPPED_MDNS),
+                // TODO: Not supported yet in the metrics backend.
+                Map.entry(DROPPED_IPV4_TCP_PORT7_UNICAST, CN_UNKNOWN),
+                Map.entry(DROPPED_ARP_NON_IPV4, CN_DROPPED_ARP_NON_IPV4),
+                Map.entry(DROPPED_ARP_OTHER_HOST, CN_DROPPED_ARP_OTHER_HOST),
+                Map.entry(DROPPED_ARP_REPLY_SPA_NO_HOST, CN_DROPPED_ARP_REPLY_SPA_NO_HOST),
+                Map.entry(DROPPED_ARP_REQUEST_ANYHOST, CN_DROPPED_ARP_REQUEST_ANYHOST),
+                Map.entry(DROPPED_ARP_REQUEST_REPLIED, CN_DROPPED_ARP_REQUEST_REPLIED),
+                Map.entry(DROPPED_ARP_UNKNOWN, CN_DROPPED_ARP_UNKNOWN),
+                Map.entry(DROPPED_ARP_V6_ONLY, CN_DROPPED_ARP_V6_ONLY),
+                Map.entry(DROPPED_GARP_REPLY, CN_DROPPED_GARP_REPLY)
+            )
+    );
     private final ApfSessionInfoReported.Builder mStatsBuilder =
             ApfSessionInfoReported.newBuilder();
     private final ApfCounterList.Builder mApfCounterListBuilder = ApfCounterList.newBuilder();
@@ -104,85 +267,6 @@ public class ApfSessionInfoMetrics {
      */
     @VisibleForTesting
     public static CounterName apfFilterCounterToEnum(final Counter counter) {
-        switch(counter) {
-            case TOTAL_PACKETS:
-                return CounterName.CN_TOTAL_PACKETS;
-            case PASSED_ARP:
-                return CounterName.CN_PASSED_ARP;
-            case PASSED_DHCP:
-                return CounterName.CN_PASSED_DHCP;
-            case PASSED_IPV4:
-                return CounterName.CN_PASSED_IPV4;
-            case PASSED_IPV6_NON_ICMP:
-                return CounterName.CN_PASSED_IPV6_NON_ICMP;
-            case PASSED_IPV4_UNICAST:
-                return CounterName.CN_PASSED_IPV4_UNICAST;
-            case PASSED_IPV6_ICMP:
-                return CounterName.CN_PASSED_IPV6_ICMP;
-            case PASSED_IPV6_UNICAST_NON_ICMP:
-                return CounterName.CN_PASSED_IPV6_UNICAST_NON_ICMP;
-            // PASSED_ARP_NON_IPV4 and PASSED_ARP_UNKNOWN were deprecated in ApfFilter:
-            //     PASSED_ARP_NON_IPV4 ==> DROPPED_ARP_NON_IPV4
-            //     PASSED_ARP_UNKNOWN  ==> DROPPED_ARP_UNKNOWN
-            // They are not supported in the metrics.
-            case PASSED_ARP_NON_IPV4:
-            case PASSED_ARP_UNKNOWN:
-                return CounterName.CN_UNKNOWN;
-            case PASSED_ARP_UNICAST_REPLY:
-                return CounterName.CN_PASSED_ARP_UNICAST_REPLY;
-            case PASSED_NON_IP_UNICAST:
-                return CounterName.CN_PASSED_NON_IP_UNICAST;
-            case PASSED_MDNS:
-                return CounterName.CN_PASSED_MDNS;
-            case DROPPED_ETH_BROADCAST:
-                return CounterName.CN_DROPPED_ETH_BROADCAST;
-            case DROPPED_RA:
-                return CounterName.CN_DROPPED_RA;
-            case DROPPED_GARP_REPLY:
-                return CounterName.CN_DROPPED_GARP_REPLY;
-            case DROPPED_ARP_OTHER_HOST:
-                return CounterName.CN_DROPPED_ARP_OTHER_HOST;
-            case DROPPED_IPV4_L2_BROADCAST:
-                return CounterName.CN_DROPPED_IPV4_L2_BROADCAST;
-            case DROPPED_IPV4_BROADCAST_ADDR:
-                return CounterName.CN_DROPPED_IPV4_BROADCAST_ADDR;
-            case DROPPED_IPV4_BROADCAST_NET:
-                return CounterName.CN_DROPPED_IPV4_BROADCAST_NET;
-            case DROPPED_IPV4_MULTICAST:
-                return CounterName.CN_DROPPED_IPV4_MULTICAST;
-            case DROPPED_IPV6_ROUTER_SOLICITATION:
-                return CounterName.CN_DROPPED_IPV6_ROUTER_SOLICITATION;
-            case DROPPED_IPV6_MULTICAST_NA:
-                return CounterName.CN_DROPPED_IPV6_MULTICAST_NA;
-            case DROPPED_IPV6_MULTICAST:
-                return CounterName.CN_DROPPED_IPV6_MULTICAST;
-            case DROPPED_IPV6_MULTICAST_PING:
-                return CounterName.CN_DROPPED_IPV6_MULTICAST_PING;
-            case DROPPED_IPV6_NON_ICMP_MULTICAST:
-                return CounterName.CN_DROPPED_IPV6_NON_ICMP_MULTICAST;
-            case DROPPED_802_3_FRAME:
-                return CounterName.CN_DROPPED_802_3_FRAME;
-            case DROPPED_ETHERTYPE_NOT_ALLOWED:
-                return CounterName.CN_DROPPED_ETHERTYPE_DENYLISTED;
-            case DROPPED_ARP_REPLY_SPA_NO_HOST:
-                return CounterName.CN_DROPPED_ARP_REPLY_SPA_NO_HOST;
-            case DROPPED_IPV4_KEEPALIVE_ACK:
-                return CounterName.CN_DROPPED_IPV4_KEEPALIVE_ACK;
-            case DROPPED_IPV6_KEEPALIVE_ACK:
-                return CounterName.CN_DROPPED_IPV6_KEEPALIVE_ACK;
-            case DROPPED_IPV4_NATT_KEEPALIVE:
-                return CounterName.CN_DROPPED_IPV4_NATT_KEEPALIVE;
-            case DROPPED_MDNS:
-                return CounterName.CN_DROPPED_MDNS;
-            case DROPPED_IPV4_TCP_PORT7_UNICAST:
-                // TODO: Not supported yet in the metrics backend.
-                return CounterName.CN_UNKNOWN;
-            case DROPPED_ARP_NON_IPV4:
-                return CounterName.CN_DROPPED_ARP_NON_IPV4;
-            case DROPPED_ARP_UNKNOWN:
-                return CounterName.CN_DROPPED_ARP_UNKNOWN;
-            default:
-                return CounterName.CN_UNKNOWN;
-        }
+        return apfCounterMetricsMap.getOrDefault(counter, CN_UNKNOWN);
     }
 }
diff --git a/src/com/android/networkstack/util/NetworkStackUtils.java b/src/com/android/networkstack/util/NetworkStackUtils.java
index ac2832ba..fce06e49 100755
--- a/src/com/android/networkstack/util/NetworkStackUtils.java
+++ b/src/com/android/networkstack/util/NetworkStackUtils.java
@@ -274,13 +274,19 @@ public class NetworkStackUtils {
     public static final String IPCLIENT_DHCPV6_PD_PREFERRED_FLAG_VERSION =
             "ipclient_dhcpv6_pd_preferred_flag_version";
 
-    /**** BEGIN Feature Kill Switch Flags ****/
+    /**
+     * Experiment flag to enable Discovery of Designated Resolvers (DDR).
+     * This flag requires networkmonitor_async_privdns_resolution flag.
+     */
+    public static final String DNS_DDR_VERSION = "dns_ddr_version";
 
     /**
-     * Kill switch flag to disable the feature of handle light doze mode in Apf.
+     * Experiment flag to ignore all NUD failures if we've seen too many NUD failure in a network.
      */
-    public static final String APF_HANDLE_LIGHT_DOZE_FORCE_DISABLE =
-            "apf_handle_light_doze_force_disable";
+    public static final String IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION =
+            "ip_reachability_ignore_nud_failure_version";
+
+    /**** BEGIN Feature Kill Switch Flags ****/
 
     /**
      * Kill switch flag to disable the feature of skipping Tcp socket info polling when light
@@ -302,9 +308,15 @@ public class NetworkStackUtils {
 
     /**
      * Kill switch flag to disable the feature of handle arp offload in Apf.
+     * Warning: the following flag String is incorrect. The feature that is not chickened out is
+     * "ARP offload" not "ARP offload force disabled".
+     */
+    public static final String APF_HANDLE_ARP_OFFLOAD = "apf_handle_arp_offload_force_disable";
+
+    /**
+     * Kill switch flag to disable the feature of handle nd offload in Apf.
      */
-    public static final String APF_HANDLE_ARP_OFFLOAD_FORCE_DISABLE =
-            "apf_handle_arp_offload_force_disable";
+    public static final String APF_HANDLE_ND_OFFLOAD = "apf_handle_nd_offload";
 
     static {
         System.loadLibrary("networkstackutilsjni");
diff --git a/src/com/android/server/NetworkStackService.java b/src/com/android/server/NetworkStackService.java
index aa8f3faa..4d10c3b2 100644
--- a/src/com/android/server/NetworkStackService.java
+++ b/src/com/android/server/NetworkStackService.java
@@ -19,6 +19,7 @@ package com.android.server;
 import static android.net.dhcp.IDhcpServer.STATUS_INVALID_ARGUMENT;
 import static android.net.dhcp.IDhcpServer.STATUS_SUCCESS;
 import static android.net.dhcp.IDhcpServer.STATUS_UNKNOWN_ERROR;
+import static android.net.util.RawSocketUtils.sendRawPacketDownStream;
 
 import static com.android.net.module.util.DeviceConfigUtils.getResBooleanConfig;
 import static com.android.net.module.util.FeatureVersions.FEATURE_IS_UID_NETWORKING_BLOCKED;
@@ -549,6 +550,23 @@ public class NetworkStackService extends Service {
                                 mContext.getSystemService(ConnectivityManager.class);
                         pw.println(cm.isUidNetworkingBlocked(uid, metered /* isNetworkMetered */));
                         return 0;
+                    case "send-raw-packet-downstream": {
+                        // Usage : cmd network_stack send-raw-packet-downstream
+                        //         <interface> <packet-in-hex>
+                        // If no argument, get and display the usage help.
+                        if (getRemainingArgsCount() != 2) {
+                            onHelp();
+                            throw new IllegalArgumentException("Incorrect number of arguments");
+                        }
+                        final String iface = getNextArg();
+                        final String packetInHex = getNextArg();
+                        try {
+                            sendRawPacketDownStream(mContext, iface, packetInHex);
+                        } catch (Exception e) {
+                            throw new RuntimeException(e);
+                        }
+                        return 0;
+                    }
                     case "apf":
                         // Usage: cmd network_stack apf <iface> <cmd>
                         final String iface = getNextArg();
@@ -585,6 +603,12 @@ public class NetworkStackService extends Service {
                 pw.println("    Get whether the networking is blocked for given uid and metered.");
                 pw.println("    <uid>: The target uid.");
                 pw.println("    <metered>: [true|false], Whether the target network is metered.");
+                pw.println("  send-raw-packet-downstream <interface> <packet-in-hex>");
+                pw.println("    Send raw packet for testing purpose.");
+                pw.println("    <interface>: Target interface name, note that this is limited");
+                pw.println("      to tethering downstream for security considerations.");
+                pw.println("    <packet_in_hex>: A valid hexadecimal representation of ");
+                pw.println("      a packet starting from L2 header.");
                 pw.println("  apf <iface> <cmd>");
                 pw.println("    APF utility commands for integration tests.");
                 pw.println("    <iface>: the network interface the provided command operates on.");
diff --git a/src/com/android/server/connectivity/DdrTracker.java b/src/com/android/server/connectivity/DdrTracker.java
new file mode 100644
index 00000000..81d881dd
--- /dev/null
+++ b/src/com/android/server/connectivity/DdrTracker.java
@@ -0,0 +1,462 @@
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
+package com.android.server.connectivity;
+
+import static android.net.DnsResolver.CLASS_IN;
+
+import static com.android.net.module.util.CollectionUtils.isEmpty;
+import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_OFF;
+import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_OPPORTUNISTIC;
+import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;
+import static com.android.net.module.util.DnsPacket.TYPE_SVCB;
+
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.net.DnsResolver;
+import android.net.LinkProperties;
+import android.net.Network;
+import android.net.shared.PrivateDnsConfig;
+import android.os.CancellationSignal;
+import android.text.TextUtils;
+import android.util.Log;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.net.module.util.DnsPacket;
+import com.android.net.module.util.DnsSvcbPacket;
+import com.android.net.module.util.SharedLog;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.net.InetAddress;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collections;
+import java.util.List;
+import java.util.concurrent.Executor;
+
+/**
+ * A class to perform DDR on a given network.
+ *
+ * Caller can use startSvcbLookup() to perform DNS SVCB lookup asynchronously. The result of the
+ * lookup will be passed to callers through the callback onSvcbLookupComplete(). If the result is
+ * stale, the callback won't be invoked. A result becomes stale once there's a new call to
+ * startSvcbLookup().
+ *
+ * Threading:
+ *
+ * 1. DdrTracker is not thread-safe. All public methods must be executed on the same thread to
+ *    guarantee that all DdrTracker members are synchronized.
+ * 2. In DdrTracker constructor, an Executor is provided as the execution thread on which the
+ *    callback onSvcbLookupComplete() will be executed. The execution thread must be the same
+ *    as the thread mentioned in 1.
+ */
+class DdrTracker {
+    private static final String TAG = "DDR";
+    private static final boolean DBG  = true;
+
+    @IntDef(prefix = { "PRIVATE_DNS_MODE_" }, value = {
+        PRIVATE_DNS_MODE_OFF,
+        PRIVATE_DNS_MODE_OPPORTUNISTIC,
+        PRIVATE_DNS_MODE_PROVIDER_HOSTNAME
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    private @interface PrivateDnsMode {}
+
+    @VisibleForTesting
+    static final String DDR_HOSTNAME = "_dns.resolver.arpa";
+
+    private static final String ALPN_DOH3 = "h3";
+
+    interface Callback {
+        /**
+         * Called on a given execution thread `mExecutor` when a SVCB lookup finishes, unless
+         * the lookup result is stale.
+         * The parameter `result` contains the aggregated result that contains both DoH and DoT
+         * information.
+         */
+        void onSvcbLookupComplete(@NonNull PrivateDnsConfig result);
+    }
+
+    @NonNull
+    private final Network mCleartextDnsNetwork;
+    @NonNull
+    private final DnsResolver mDnsResolver;
+    @NonNull
+    private final Callback mCallback;
+
+    // The execution thread the callback will be executed on.
+    @NonNull
+    private final Executor mExecutor;
+
+    // Stores the DNS information that is synced with current DNS configuration.
+    @NonNull
+    private DnsInfo mDnsInfo;
+
+    // Stores the DoT servers discovered from strict mode hostname resolution.
+    @NonNull
+    private final List<InetAddress> mDotServers;
+
+    // Stores the result of latest SVCB lookup.
+    // It is set to null if the result is invalid, for example, lookup timeout or invalid
+    // SVCB responses.
+    @Nullable
+    private DnsSvcbPacket mLatestSvcbPacket = null;
+
+    // Used to check whether a DDR result is stale.
+    // Given the Threading section documented near the beginning of this file, `mTokenId` ensures
+    // that mLatestSvcbRecord is always fresh.
+    @NonNull
+    private int mTokenId;
+
+    // Used to cancel the in-progress SVCB lookup.
+    @NonNull
+    CancellationSignal mCancelSignal;
+
+    private final SharedLog mValidationLogs;
+
+    DdrTracker(@NonNull Network cleartextDnsNetwork, @NonNull DnsResolver dnsResolver,
+            @NonNull Executor executor, @NonNull Callback callback, SharedLog validationLog) {
+        mCleartextDnsNetwork = cleartextDnsNetwork;
+        mDnsResolver = dnsResolver;
+        mExecutor = executor;
+        mCallback = callback;
+        final PrivateDnsConfig privateDnsDisabled = new PrivateDnsConfig(PRIVATE_DNS_MODE_OFF,
+                null /* hostname */, null /* ips */, true /* ddrEnabled */, null /* dohName */,
+                null /* dohIps */, null /* dohPath */, -1 /* dohPort */);
+        mDnsInfo = new DnsInfo(privateDnsDisabled, new ArrayList<>());
+        mDotServers = new ArrayList<>();
+        mCancelSignal = new CancellationSignal();
+        mValidationLogs = validationLog.forSubComponent(TAG);
+    }
+
+    /**
+     * If the private DNS settings on the network has changed, this function updates
+     * the DnsInfo and returns true; otherwise, the DnsInfo remains the same and this function
+     * returns false.
+     */
+    boolean notifyPrivateDnsSettingsChanged(@NonNull PrivateDnsConfig cfg) {
+        if (mDnsInfo.cfg.areSettingsSameAs(cfg)) return false;
+
+        ++mTokenId;
+        mDnsInfo = new DnsInfo(cfg, getDnsServers());
+        resetStrictModeHostnameResolutionResult();
+        return true;
+    }
+
+    /**
+     * If the unencrypted DNS server list on the network has changed (even if only the order has
+     * changed), this function updates the DnsInfo and returns true; otherwise, the DnsInfo remains
+     * unchanged and this function returns false.
+     *
+     * The reason that this method returns true even if only the order has changed is that
+     * DnsResolver returns a DNS answer to app side as soon as it receives a DNS response from
+     * a DNS server. Therefore, the DNS response from the first DNS server that supports DDR
+     * determines the DDR result.
+     */
+    boolean notifyLinkPropertiesChanged(@NonNull LinkProperties lp) {
+        final List<InetAddress> servers = lp.getDnsServers();
+
+        if (servers.equals(getDnsServers())) return false;
+
+        ++mTokenId;
+        mDnsInfo = new DnsInfo(mDnsInfo.cfg, servers);
+        return true;
+    }
+
+    void setStrictModeHostnameResolutionResult(@NonNull InetAddress[] ips) {
+        resetStrictModeHostnameResolutionResult();
+        mDotServers.addAll(Arrays.asList(ips));
+    }
+
+    void resetStrictModeHostnameResolutionResult() {
+        mDotServers.clear();
+    }
+
+    @VisibleForTesting
+    @PrivateDnsMode int getPrivateDnsMode() {
+        return mDnsInfo.cfg.mode;
+    }
+
+    // Returns a non-empty string (strict mode) or an empty string (off/opportunistic mode) .
+    @VisibleForTesting
+    @NonNull
+    String getStrictModeHostname() {
+        return mDnsInfo.cfg.hostname;
+    }
+
+    @VisibleForTesting
+    @NonNull
+    List<InetAddress> getDnsServers() {
+        return mDnsInfo.dnsServers;
+    }
+
+    private boolean hasSvcbAnswer(@NonNull String alpn) {
+        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.isSupported(alpn) : false;
+    }
+
+    @Nullable
+    private String getTargetNameFromSvcbAnswer(@NonNull String alpn) {
+        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getTargetName(alpn) : null;
+    }
+
+    // Returns a list of IP addresses for the target name from the latest SVCB packet.
+    // These may be either from the A/AAAA records in the additional section or from the
+    // ipv4hint/ipv6hint keys in the SVCB record.
+    private List<InetAddress> getServersFromSvcbAnswer(@NonNull String alpn) {
+        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getAddresses(alpn)
+                : Collections.emptyList();
+    }
+
+    private int getPortFromSvcbAnswer(@NonNull String alpn) {
+        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getPort(alpn) : -1;
+    }
+
+    @Nullable
+    private String getDohPathFromSvcbAnswer(@NonNull String alpn) {
+        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getDohPath(alpn) : null;
+    }
+
+    @NonNull
+    private String createHostnameForSvcbQuery() {
+        final String hostname = getStrictModeHostname();
+        if (!TextUtils.isEmpty(hostname)) {
+            return "_dns." + hostname;
+        }
+        return DDR_HOSTNAME;
+    }
+
+    /** Performs a DNS SVCB Lookup asynchronously. */
+    void startSvcbLookup() {
+        if (getPrivateDnsMode() == PRIVATE_DNS_MODE_OFF) {
+            // Ensure getResultForReporting returns reasonable results.
+            mLatestSvcbPacket = null;
+            // We do not need to increment the token. The token is used to ignore stale results.
+            // But there can only be lookups in flight if the mode was previously on. Because the
+            // mode is now off,  that means the mode changed, and that incremented the token.
+            return;
+        }
+        // There are some cases where startSvcbLookup() is called twice in a row that
+        // are likely to lead to the same result, for example:
+        //   1. A network is connected when private DNS mode is strict mode.
+        //   2. Private DNS mode is switched to strict mode.
+        // To avoid duplicate lookups, cancel the in-progress SVCB lookup (if any).
+        //
+        // Note that cancelling is not currently very useful because the DNS resolver still
+        // continues to retry until the query completes or fails. It does prevent the query callback
+        // from being called, but that's not necessary because the token will not match.
+        // We still do attempt to cancel the query so future improvements to the DNS resolver could
+        // use that to do less work.
+        mCancelSignal.cancel();
+        mCancelSignal = new CancellationSignal();
+
+        // Increment the token ID to stale all in-flight lookups.
+        // This is for network revalidation in strict mode that a SVCB lookup can be performed
+        // and its result can be accepted even if there is no DNS configuration change.
+        final int token = ++mTokenId;
+        final String hostname = createHostnameForSvcbQuery();
+        final DnsResolver.Callback<byte[]> callback = new DnsResolver.Callback<byte[]>() {
+            boolean isResultFresh() {
+                return token == mTokenId;
+            }
+
+            void updateSvcbAnswerAndInvokeUserCallback(@Nullable DnsSvcbPacket result) {
+                mLatestSvcbPacket = result;
+                mCallback.onSvcbLookupComplete(getResultForReporting());
+            }
+
+            @Override
+            public void onAnswer(@NonNull byte[] answer, int rcode) {
+                if (!isResultFresh()) {
+                    validationLog("Ignoring stale SVCB answer");
+                    return;
+                }
+
+                if (rcode != 0 || answer.length == 0) {
+                    validationLog("Ignoring invalid SVCB answer: rcode=" + rcode
+                            + " len=" + answer.length);
+                    updateSvcbAnswerAndInvokeUserCallback(null);
+                    return;
+                }
+
+                final DnsSvcbPacket pkt;
+                try {
+                    pkt = DnsSvcbPacket.fromResponse(answer);
+                } catch (DnsPacket.ParseException e) {
+                    validationLog("Ignoring malformed SVCB answer: " + e);
+                    updateSvcbAnswerAndInvokeUserCallback(null);
+                    return;
+                }
+
+                validationLog("Processing SVCB response: " + pkt);
+                updateSvcbAnswerAndInvokeUserCallback(pkt);
+            }
+
+            @Override
+            public void onError(@NonNull DnsResolver.DnsException e) {
+                validationLog("DNS error resolving SVCB record for " + hostname + ": " + e);
+                if (isResultFresh()) {
+                    updateSvcbAnswerAndInvokeUserCallback(null);
+                }
+            }
+        };
+        sendDnsSvcbQuery(hostname, mCancelSignal, callback);
+    }
+
+    /**
+     * Returns candidate IP addresses to use for DoH.
+     *
+     * These can come from A/AAAA records returned by strict mode hostname resolution, from A/AAAA
+     * records in the additional section of the SVCB response, or from the ipv4hint/ipv6hint keys in
+     * the H3 ALPN of the SVCB record itself.
+     *
+     * RFC 9460 §7.3 says that if A and AAAA records for TargetName are locally available, the
+     * client SHOULD ignore the hints.
+     *
+     * - In opportunistic mode, strict name hostname resolution does not happen, so always use the
+     *   addresses in the SVCB response
+     * - In strict mode:
+     *   - If the target name in the H3 ALPN matches the strict mode hostname, prefer the result of
+     *     strict mode hostname resolution.
+     *   - If not, prefer the addresses from the SVCB response, but fall back to A/AAAA records if
+     *     there are none. This ensures that:
+     *     - If the strict mode hostname has A/AAAA addresses, those are used even if there are no
+     *       addresses in the SVCB record.
+     *
+     * Note that in strict mode, this class always uses the user-specified hostname and ignores the
+     * target hostname in the SVCB record (see getResultForReporting). In this case, preferring the
+     * addresses in the SVCB record at ensures that those addresses are used, even if the target
+     * hostname is not.
+     */
+    private List<InetAddress> getTargetNameIpAddresses(@NonNull String alpn) {
+        final List<InetAddress> serversFromSvcbAnswer = getServersFromSvcbAnswer(alpn);
+        final String hostname = getStrictModeHostname();
+        if (TextUtils.isEmpty(hostname)) {
+            return serversFromSvcbAnswer;
+        }
+        // Strict mode can use either A/AAAA records coming from strict mode resolution or the
+        // addresses from the SVCB response (which could be A/AAAA records in the additional section
+        // or the hints in the SVCB record itself).
+        final String targetName = getTargetNameFromSvcbAnswer(alpn);
+        if (TextUtils.equals(targetName, hostname) && !mDotServers.isEmpty()) {
+            return mDotServers;
+        }
+        if (isEmpty(serversFromSvcbAnswer)) {
+            return mDotServers;
+        }
+        return serversFromSvcbAnswer;
+    }
+
+    /**
+     * To follow the design of private DNS opportunistic mode, which is similar to RFC 9462 §4.3,
+     * don't use a designated resolver if its IP address differs from all the unencrypted resolvers'
+     * IP addresses.
+     *
+     * TODO: simplify the code by merging this method with getTargetNameIpAddresses above.
+     */
+    private InetAddress[] getDohServers(@NonNull String alpn) {
+        final List<InetAddress> candidates = getTargetNameIpAddresses(alpn);
+        if (isEmpty(candidates)) return null;
+        if (getPrivateDnsMode() == PRIVATE_DNS_MODE_PROVIDER_HOSTNAME) return toArray(candidates);
+
+        candidates.retainAll(getDnsServers());
+        return toArray(candidates);
+    }
+
+    /**
+     * Returns the aggregated private DNS discovery result as a PrivateDnsConfig.
+     * getResultForReporting() is called in the following cases:
+     * 1. when the hostname lookup completes.
+     * 2. when the SVCB lookup completes.
+     *
+     * There is no guarantee which lookup will complete first. Therefore, depending on the private
+     * DNS mode and the SVCB answer, the return PrivateDnsConfig might be set with DoT, DoH,
+     * DoT+DoH, or even no servers.
+     */
+    @NonNull
+    PrivateDnsConfig getResultForReporting() {
+        final String strictModeHostname = getStrictModeHostname();
+        final InetAddress[] dotIps = toArray(mDotServers);
+        final PrivateDnsConfig candidateResultWithDotOnly =
+                new PrivateDnsConfig(getPrivateDnsMode(), strictModeHostname, dotIps,
+                        true /* ddrEnabled */, null /* dohName */, null /* dohIps */,
+                        null /* dohPath */, -1 /* dohPort */);
+
+        if (!hasSvcbAnswer(ALPN_DOH3)) {
+            // TODO(b/240259333): Consider not invoking notifyPrivateDnsConfigResolved() if
+            // DoT server list is empty.
+            return candidateResultWithDotOnly;
+        }
+
+        // The SVCB answer should be fresh.
+
+        final String dohName = (getPrivateDnsMode() == PRIVATE_DNS_MODE_PROVIDER_HOSTNAME)
+                ? strictModeHostname : getTargetNameFromSvcbAnswer(ALPN_DOH3);
+        final InetAddress[] dohIps = getDohServers(ALPN_DOH3);
+        final String dohPath = getDohPathFromSvcbAnswer(ALPN_DOH3);
+        final int dohPort = getPortFromSvcbAnswer(ALPN_DOH3);
+
+        return new PrivateDnsConfig(getPrivateDnsMode(), strictModeHostname, dotIps, true,
+                dohName, dohIps, dohPath, dohPort);
+    }
+
+    private void validationLog(String s) {
+        log(s);
+        mValidationLogs.log(s);
+    }
+
+    private void log(String s) {
+        if (DBG) Log.d(TAG + "/" + mCleartextDnsNetwork.toString(), s);
+    }
+
+    /**
+     * A non-blocking call doing DNS SVCB lookup.
+     */
+    private void sendDnsSvcbQuery(String host, @NonNull CancellationSignal cancelSignal,
+            @NonNull DnsResolver.Callback<byte[]> callback) {
+        // Note: the even though this code does not pass FLAG_NO_CACHE_LOOKUP, the query is
+        // currently not cached, because the DNS resolver cache does not cache SVCB records.
+        // TODO: support caching SVCB records in the DNS resolver cache.
+        // This should just work but will need testing.
+        mDnsResolver.rawQuery(mCleartextDnsNetwork, host, CLASS_IN, TYPE_SVCB, 0 /* flags */,
+                mExecutor, cancelSignal, callback);
+    }
+
+    private static InetAddress[] toArray(List<InetAddress> list) {
+        if (list == null) {
+            return null;
+        }
+        return list.toArray(new InetAddress[0]);
+    }
+
+    /**
+     * A class to store current DNS configuration. Only the information relevant to DDR is stored.
+     *   1. Private DNS setting.
+     *   2. A list of Unencrypted DNS servers.
+     */
+    private static class DnsInfo {
+        @NonNull
+        public final PrivateDnsConfig cfg;
+        @NonNull
+        public final List<InetAddress> dnsServers;
+
+        DnsInfo(@NonNull PrivateDnsConfig cfg, @NonNull List<InetAddress> dnsServers) {
+            this.cfg = cfg;
+            this.dnsServers = dnsServers;
+        }
+    }
+}
diff --git a/src/com/android/server/connectivity/NetworkMonitor.java b/src/com/android/server/connectivity/NetworkMonitor.java
index 895fc54d..60bb9279 100755
--- a/src/com/android/server/connectivity/NetworkMonitor.java
+++ b/src/com/android/server/connectivity/NetworkMonitor.java
@@ -65,6 +65,8 @@ import static com.android.modules.utils.build.SdkLevel.isAtLeastU;
 import static com.android.net.module.util.CollectionUtils.isEmpty;
 import static com.android.net.module.util.ConnectivityUtils.isIPv6ULA;
 import static com.android.net.module.util.DeviceConfigUtils.getResBooleanConfig;
+import static com.android.net.module.util.FeatureVersions.FEATURE_DDR_IN_CONNECTIVITY;
+import static com.android.net.module.util.FeatureVersions.FEATURE_DDR_IN_DNSRESOLVER;
 import static com.android.net.module.util.NetworkStackConstants.TEST_CAPTIVE_PORTAL_HTTPS_URL;
 import static com.android.net.module.util.NetworkStackConstants.TEST_CAPTIVE_PORTAL_HTTP_URL;
 import static com.android.net.module.util.NetworkStackConstants.TEST_URL_EXPIRATION_TIME;
@@ -462,6 +464,9 @@ public class NetworkMonitor extends StateMachine {
     @VisibleForTesting
     static final int MAX_PROBE_THREAD_POOL_SIZE = 5;
     private String mPrivateDnsProviderHostname = "";
+    private final boolean mDdrEnabled;
+    @NonNull
+    private final DdrTracker mDdrTracker;
 
     private final Context mContext;
     private final INetworkMonitorCallbacks mCallback;
@@ -679,6 +684,10 @@ public class NetworkMonitor extends StateMachine {
                 context, NetworkStackUtils.REEVALUATE_WHEN_RESUME);
         mAsyncPrivdnsResolutionEnabled = deps.isFeatureEnabled(context,
                 NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION);
+        mDdrEnabled = mAsyncPrivdnsResolutionEnabled
+                && deps.isFeatureEnabled(context, NetworkStackUtils.DNS_DDR_VERSION)
+                && deps.isFeatureSupported(mContext, FEATURE_DDR_IN_CONNECTIVITY)
+                && deps.isFeatureSupported(mContext, FEATURE_DDR_IN_DNSRESOLVER);
         mUseHttps = getUseHttpsValidation();
         mCaptivePortalUserAgent = getCaptivePortalUserAgent();
         mCaptivePortalFallbackSpecs =
@@ -714,6 +723,17 @@ public class NetworkMonitor extends StateMachine {
         mLinkProperties = new LinkProperties();
         mNetworkCapabilities = new NetworkCapabilities(null);
         mNetworkAgentConfig = NetworkAgentConfigShimImpl.newInstance(null);
+
+        // For DdrTracker that can safely update SVCB lookup results itself when the lookup
+        // completes. The callback is called inline from onAnswer, which is already posted to
+        // the handler. This ensures that strict mode hostname resolution (which calls
+        // onQueryDone when processing CMD_PRIVATE_DNS_PROBE_COMPLETED) and SVCB lookup (which calls
+        // DdrTracker#updateSvcbAnswerAndInvokeUserCallback by posting onAnswer to the Runnable)
+        // run in order: both of them post exactly once to the handler.
+        mDdrTracker = new DdrTracker(mCleartextDnsNetwork, mDependencies.getDnsResolver(),
+                getHandler()::post,
+                result -> notifyPrivateDnsConfigResolved(result),  // Run inline on handler.
+                mValidationLogs);
     }
 
     /**
@@ -1084,6 +1104,10 @@ public class NetworkMonitor extends StateMachine {
                 case CMD_PRIVATE_DNS_SETTINGS_CHANGED: {
                     final PrivateDnsConfig cfg = (PrivateDnsConfig) message.obj;
                     final TcpSocketTracker tst = getTcpSocketTracker();
+                    if (mDdrEnabled) {
+                        mDdrTracker.notifyPrivateDnsSettingsChanged(cfg);
+                    }
+
                     if (!isPrivateDnsValidationRequired() || !cfg.inStrictMode()) {
                         // No DNS resolution required.
                         //
@@ -1158,6 +1182,12 @@ public class NetworkMonitor extends StateMachine {
                     if (tst != null) {
                         tst.setLinkProperties(mLinkProperties);
                     }
+                    final boolean dnsInfoUpdated = mDdrEnabled
+                            && mDdrTracker.notifyLinkPropertiesChanged(mLinkProperties);
+                    if (dnsInfoUpdated) {
+                        removeMessages(CMD_EVALUATE_PRIVATE_DNS);
+                        sendMessage(CMD_EVALUATE_PRIVATE_DNS);
+                    }
                     break;
                 case EVENT_NETWORK_CAPABILITIES_CHANGED:
                     handleCapabilitiesChanged((NetworkCapabilities) message.obj,
@@ -1641,12 +1671,15 @@ public class NetworkMonitor extends StateMachine {
 
     private class EvaluatingPrivateDnsState extends State {
         private int mPrivateDnsReevalDelayMs;
-        private PrivateDnsConfig mPrivateDnsConfig;
+        private PrivateDnsConfig mSyncOnlyPrivateDnsConfig;
 
         @Override
         public void enter() {
             mPrivateDnsReevalDelayMs = INITIAL_REEVALUATE_DELAY_MS;
-            mPrivateDnsConfig = null;
+            mSyncOnlyPrivateDnsConfig = null;
+            if (mDdrEnabled) {
+                mDdrTracker.resetStrictModeHostnameResolutionResult();
+            }
             sendMessage(CMD_EVALUATE_PRIVATE_DNS);
         }
 
@@ -1654,6 +1687,10 @@ public class NetworkMonitor extends StateMachine {
         public boolean processMessage(Message msg) {
             switch (msg.what) {
                 case CMD_EVALUATE_PRIVATE_DNS: {
+                    if (mDdrEnabled) {
+                        mDdrTracker.startSvcbLookup();
+                    }
+
                     if (mAsyncPrivdnsResolutionEnabled) {
                         // Cancel any previously scheduled retry attempt
                         removeMessages(CMD_EVALUATE_PRIVATE_DNS);
@@ -1669,12 +1706,13 @@ public class NetworkMonitor extends StateMachine {
                         break;
                     }
 
+                    // Async resolution not enabled, do a blocking DNS lookup.
                     if (inStrictMode()) {
-                        if (!isStrictModeHostnameResolved(mPrivateDnsConfig)) {
+                        if (!isStrictModeHostnameResolved(mSyncOnlyPrivateDnsConfig)) {
                             resolveStrictModeHostname();
 
-                            if (isStrictModeHostnameResolved(mPrivateDnsConfig)) {
-                                notifyPrivateDnsConfigResolved(mPrivateDnsConfig);
+                            if (isStrictModeHostnameResolved(mSyncOnlyPrivateDnsConfig)) {
+                                notifyPrivateDnsConfigResolved(mSyncOnlyPrivateDnsConfig);
                             } else {
                                 handlePrivateDnsEvaluationFailure();
                                 // The private DNS probe fails-fast if the server hostname cannot
@@ -1733,9 +1771,9 @@ public class NetworkMonitor extends StateMachine {
                 final InetAddress[] ips = DnsUtils.getAllByName(mDependencies.getDnsResolver(),
                         mCleartextDnsNetwork, mPrivateDnsProviderHostname, getDnsProbeTimeout(),
                         str -> validationLog("Strict mode hostname resolution " + str));
-                mPrivateDnsConfig = new PrivateDnsConfig(mPrivateDnsProviderHostname, ips);
+                mSyncOnlyPrivateDnsConfig = new PrivateDnsConfig(mPrivateDnsProviderHostname, ips);
             } catch (UnknownHostException uhe) {
-                mPrivateDnsConfig = null;
+                mSyncOnlyPrivateDnsConfig = null;
             }
         }
 
@@ -1960,11 +1998,16 @@ public class NetworkMonitor extends StateMachine {
 
             if (!answer.isEmpty()) {
                 final InetAddress[] ips = answer.toArray(new InetAddress[0]);
-                final PrivateDnsConfig config =
-                        new PrivateDnsConfig(mPrivateDnsProviderHostname, ips);
-                notifyPrivateDnsConfigResolved(config);
+                if (mDdrEnabled) {
+                    mDdrTracker.setStrictModeHostnameResolutionResult(ips);
+                    notifyPrivateDnsConfigResolved(mDdrTracker.getResultForReporting());
+                } else {
+                    notifyPrivateDnsConfigResolved(
+                            new PrivateDnsConfig(mPrivateDnsProviderHostname, ips));
+                }
 
-                validationLog("Strict mode hostname resolution " + elapsedNanos + "ns OK "
+                validationLog("Strict mode hostname resolution "
+                        + TimeUnit.NANOSECONDS.toMillis(elapsedNanos) + "ms OK "
                         + answer + " for " + mPrivateDnsProviderHostname);
                 transitionTo(mProbingForPrivateDnsState);
             } else {
@@ -2027,7 +2070,7 @@ public class NetworkMonitor extends StateMachine {
 
             final String strIps = Objects.toString(answer);
             validationLog(PROBE_PRIVDNS, queryName,
-                    String.format("%dus: %s", elapsedNanos / 1000, strIps));
+                    String.format("%dms: %s", TimeUnit.NANOSECONDS.toMillis(elapsedNanos), strIps));
 
             mEvaluationState.noteProbeResult(NETWORK_VALIDATION_PROBE_PRIVDNS, success);
             if (success) {
@@ -3718,6 +3761,10 @@ public class NetworkMonitor extends StateMachine {
             return DeviceConfigUtils.isNetworkStackFeatureNotChickenedOut(context, name);
         }
 
+        boolean isFeatureSupported(@NonNull Context context, long feature) {
+            return DeviceConfigUtils.isFeatureSupported(context, feature);
+        }
+
         /**
          * Collect data stall detection level information for each transport type. Write metrics
          * data to statsd pipeline.
diff --git a/tests/integration/Android.bp b/tests/integration/Android.bp
index 65a94f3e..d728c6b5 100644
--- a/tests/integration/Android.bp
+++ b/tests/integration/Android.bp
@@ -51,9 +51,9 @@ java_defaults {
         "testables",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs",
+        "android.test.base.stubs",
+        "android.test.mock.stubs",
     ],
     visibility: ["//visibility:private"],
 }
diff --git a/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java b/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
index 84bf7e61..f7e1c4d0 100644
--- a/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
+++ b/tests/integration/common/android/net/ip/IpClientIntegrationTestCommon.java
@@ -41,8 +41,15 @@ import static android.net.ip.IIpClientCallbacks.DTIM_MULTIPLIER_RESET;
 import static android.net.ip.IpClient.CONFIG_IPV6_AUTOCONF_TIMEOUT;
 import static android.net.ip.IpClient.CONFIG_ACCEPT_RA_MIN_LFT;
 import static android.net.ip.IpClient.CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS;
+import static android.net.ip.IpClient.CONFIG_NUD_FAILURE_COUNT_DAILY_THRESHOLD;
+import static android.net.ip.IpClient.CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD;
 import static android.net.ip.IpClient.DEFAULT_ACCEPT_RA_MIN_LFT;
 import static android.net.ip.IpClient.DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS;
+import static android.net.ip.IpClient.DEFAULT_NUD_FAILURE_COUNT_DAILY_THRESHOLD;
+import static android.net.ip.IpClient.DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD;
+import static android.net.ip.IpClient.ONE_DAY_IN_MS;
+import static android.net.ip.IpClient.ONE_WEEK_IN_MS;
+import static android.net.ip.IpClient.SIX_HOURS_IN_MS;
 import static android.net.ip.IpClientLinkObserver.CLAT_PREFIX;
 import static android.net.ip.IpClientLinkObserver.CONFIG_SOCKET_RECV_BUFSIZE;
 import static android.net.ip.IpReachabilityMonitor.NUD_MCAST_RESOLICIT_NUM;
@@ -83,6 +90,7 @@ import static com.android.networkstack.util.NetworkStackUtils.IPCLIENT_POPULATE_
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DEFAULT_ROUTER_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_INCOMPLETE_IPV6_DNS_SERVER_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_NEVER_REACHABLE_NEIGHBOR_VERSION;
+import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_IGNORE_ORGANIC_NUD_FAILURE_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.IP_REACHABILITY_ROUTER_MAC_CHANGE_FAILURE_ONLY_AFTER_ROAM_VERSION;
 import static com.android.testutils.MiscAsserts.assertThrows;
@@ -133,6 +141,7 @@ import android.content.pm.PackageManager;
 import android.content.res.Resources;
 import android.net.ConnectivityManager;
 import android.net.DhcpResultsParcelable;
+import android.net.IIpMemoryStore;
 import android.net.INetd;
 import android.net.InetAddresses;
 import android.net.InterfaceConfigurationParcel;
@@ -167,6 +176,7 @@ import android.net.dhcp6.Dhcp6RequestPacket;
 import android.net.dhcp6.Dhcp6SolicitPacket;
 import android.net.ipmemorystore.NetworkAttributes;
 import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener;
+import android.net.ipmemorystore.OnNetworkEventCountRetrievedListener;
 import android.net.ipmemorystore.Status;
 import android.net.networkstack.TestNetworkStackServiceClient;
 import android.net.networkstack.aidl.dhcp.DhcpOption;
@@ -190,6 +200,7 @@ import android.stats.connectivity.NudEventType;
 import android.system.ErrnoException;
 import android.system.Os;
 import android.util.Log;
+import android.util.Pair;
 
 import androidx.annotation.NonNull;
 import androidx.test.InstrumentationRegistry;
@@ -372,6 +383,7 @@ public abstract class IpClientIntegrationTestCommon {
 
     protected IpClient mIpc;
     protected Dependencies mDependencies;
+    protected List<Pair<String, Pair<Long, Integer>>> mNetworkEvents = new ArrayList<>();
 
     /***** END signature required test members *****/
 
@@ -691,6 +703,11 @@ public abstract class IpClientIntegrationTestCommon {
 
     protected abstract int readNudSolicitNumPostRoamingFromResource();
 
+    protected abstract void storeNetworkEvent(String cluster, long now, long expiry, int eventType);
+
+    protected abstract int[] getStoredNetworkEventCount(String cluster, long[] sinceTimes,
+            int[] eventType, long timeout);
+
     protected final boolean testSkipped() {
         if (!useNetworkStackSignature() && !TestNetworkStackServiceClient.isSupported()) {
             fail("Device running root tests doesn't support TestNetworkStackServiceClient.");
@@ -821,6 +838,19 @@ public abstract class IpClientIntegrationTestCommon {
         when(mPackageManager.getPackagesForUid(TEST_DEVICE_OWNER_APP_UID)).thenReturn(
                 new String[] { TEST_DEVICE_OWNER_APP_PACKAGE });
 
+        // Retrieve the network event count.
+        doAnswer(invocation -> {
+            final String cluster = invocation.getArgument(0);
+            final long[] sinceTimes = invocation.getArgument(1);
+            final int[] eventType = invocation.getArgument(2);
+            ((OnNetworkEventCountRetrievedListener) invocation.getArgument(3))
+                    .onNetworkEventCountRetrieved(
+                            new Status(SUCCESS),
+                            getStoredNetworkEventCount(cluster, sinceTimes, eventType,
+                                    0 /* timeout not used */));
+            return null;
+        }).when(mIpMemoryStore).retrieveNetworkEventCount(eq(TEST_CLUSTER), any(), any(), any());
+
         setDeviceConfigProperty(IpClient.CONFIG_MIN_RDNSS_LIFETIME, 67);
         setDeviceConfigProperty(DhcpClient.DHCP_RESTART_CONFIG_DELAY, 10);
         setDeviceConfigProperty(DhcpClient.ARP_FIRST_PROBE_DELAY_MS, 10);
@@ -844,6 +874,12 @@ public abstract class IpClientIntegrationTestCommon {
         // Set the polling interval to update APF data snapshot.
         setDeviceConfigProperty(CONFIG_APF_COUNTER_POLLING_INTERVAL_SECS,
                 DEFAULT_APF_COUNTER_POLLING_INTERVAL_SECS);
+
+        // Set the NUD failure event count daily and weekly thresholds.
+        setDeviceConfigProperty(CONFIG_NUD_FAILURE_COUNT_DAILY_THRESHOLD,
+                DEFAULT_NUD_FAILURE_COUNT_DAILY_THRESHOLD);
+        setDeviceConfigProperty(CONFIG_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD,
+                DEFAULT_NUD_FAILURE_COUNT_WEEKLY_THRESHOLD);
     }
 
     private void awaitIpClientShutdown() throws Exception {
@@ -2855,17 +2891,6 @@ public abstract class IpClientIntegrationTestCommon {
                 (byte) 0x06, data);
     }
 
-    private void assertDhcpResultsParcelable(final DhcpResultsParcelable lease) {
-        assertNotNull(lease);
-        assertEquals(CLIENT_ADDR, lease.baseConfiguration.getIpAddress().getAddress());
-        assertEquals(SERVER_ADDR, lease.baseConfiguration.getGateway());
-        assertEquals(1, lease.baseConfiguration.getDnsServers().size());
-        assertTrue(lease.baseConfiguration.getDnsServers().contains(SERVER_ADDR));
-        assertEquals(SERVER_ADDR, InetAddresses.parseNumericAddress(lease.serverAddress));
-        assertEquals(TEST_DEFAULT_MTU, lease.mtu);
-        assertEquals(TEST_LEASE_DURATION_S, lease.leaseDuration);
-    }
-
     private void doUpstreamHotspotDetectionTest(final int id, final String displayName,
             final String ssid, final byte[] oui, final byte type, final byte[] data,
             final boolean expectMetered) throws Exception {
@@ -2884,7 +2909,13 @@ public abstract class IpClientIntegrationTestCommon {
                 ArgumentCaptor.forClass(DhcpResultsParcelable.class);
         verify(mCb, timeout(TEST_TIMEOUT_MS)).onNewDhcpResults(captor.capture());
         final DhcpResultsParcelable lease = captor.getValue();
-        assertDhcpResultsParcelable(lease);
+        assertNotNull(lease);
+        assertEquals(CLIENT_ADDR, lease.baseConfiguration.getIpAddress().getAddress());
+        assertEquals(SERVER_ADDR, lease.baseConfiguration.getGateway());
+        assertEquals(1, lease.baseConfiguration.getDnsServers().size());
+        assertTrue(lease.baseConfiguration.getDnsServers().contains(SERVER_ADDR));
+        assertEquals(SERVER_ADDR, InetAddresses.parseNumericAddress(lease.serverAddress));
+        assertEquals(TEST_DEFAULT_MTU, lease.mtu);
 
         if (expectMetered) {
             assertEquals(lease.vendorInfo, DhcpPacket.VENDOR_INFO_ANDROID_METERED);
@@ -4312,6 +4343,9 @@ public abstract class IpClientIntegrationTestCommon {
                 // neighbor reachability checking relevant test cases, that guarantees
                 // avoidingBadLinks() always returns true which is expected.
                 .withoutMultinetworkPolicyTracker()
+                // Make cluster as non-null to test the NUD failure event count query logic.
+                .withLayer2Information(new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
+                       MacAddress.fromString(TEST_DEFAULT_BSSID)))
                 .build();
         startIpClientProvisioning(config);
         verify(mCb, timeout(TEST_TIMEOUT_MS)).setFallbackMulticastFilter(true);
@@ -5874,7 +5908,7 @@ public abstract class IpClientIntegrationTestCommon {
         final ProvisioningConfiguration cfg = new ProvisioningConfiguration.Builder()
                 .withoutIPv6()
                 .build();
-        setDeviceConfigProperty(CONFIG_MINIMUM_LEASE,  5 /* default minimum lease */);
+        setDeviceConfigProperty(CONFIG_MINIMUM_LEASE,  5/* default minimum lease */);
         startIpClientProvisioning(cfg);
         handleDhcpPackets(true /* isSuccessLease */, 4 /* lease duration */,
                 false /* shouldReplyRapidCommitAck */, TEST_DEFAULT_MTU,
@@ -5889,8 +5923,6 @@ public abstract class IpClientIntegrationTestCommon {
         sendArpReply(request.senderHwAddress.toByteArray() /* dst */, ROUTER_MAC_BYTES /* srcMac */,
                 request.senderIp /* target IP */, SERVER_ADDR /* sender IP */);
 
-        clearInvocations(mCb);
-
         // Then client sends unicast DHCPREQUEST to extend the IPv4 address lifetime, and we reply
         // with DHCPACK to refresh the DHCP lease.
         final DhcpPacket packet = getNextDhcpPacket();
@@ -5900,32 +5932,12 @@ public abstract class IpClientIntegrationTestCommon {
                 TEST_LEASE_DURATION_S, (short) TEST_DEFAULT_MTU,
                 false /* rapidCommit */, null /* captivePortalApiUrl */));
 
-        // The IPv4 link address lifetime should be also updated after a success DHCP renew, check
-        // that we should never see provisioning failure.
-        verify(mCb, after(100).never()).onProvisioningFailure(any());
-
-        final ArgumentCaptor<DhcpResultsParcelable> dhcpResultsCaptor =
-                ArgumentCaptor.forClass(DhcpResultsParcelable.class);
-        verify(mCb, timeout(TEST_TIMEOUT_MS)).onNewDhcpResults(dhcpResultsCaptor.capture());
-        final DhcpResultsParcelable lease = dhcpResultsCaptor.getValue();
-        assertDhcpResultsParcelable(lease);
-
-        // Check if the IPv4 address lifetime has updated along with a success DHCP renew.
-        verify(mCb, timeout(TEST_TIMEOUT_MS)).onLinkPropertiesChange(argThat(x -> {
-            for (LinkAddress la : x.getLinkAddresses()) {
-                if (la.isIpv4()) {
-                    final long now = SystemClock.elapsedRealtime();
-                    final long when = now + 3600 * 1000;
-                    return (la.getDeprecationTime() != LinkAddress.LIFETIME_UNKNOWN)
-                            && (la.getExpirationTime() != LinkAddress.LIFETIME_UNKNOWN)
-                            && (la.getDeprecationTime() < when + TEST_LIFETIME_TOLERANCE_MS)
-                            && (la.getDeprecationTime() > when - TEST_LIFETIME_TOLERANCE_MS)
-                            && (la.getExpirationTime() < when + TEST_LIFETIME_TOLERANCE_MS)
-                            && (la.getExpirationTime() > when - TEST_LIFETIME_TOLERANCE_MS);
-                }
-            }
-            return false;
-        }));
+        // Once the IPCLIENT_POPULATE_LINK_ADDRESS_LIFETIME_VERSION flag is enabled, the IP
+        // lease will be refreshed as well as the link address lifetime by transiting to
+        // ConfiguringInterfaceState, where IpClient sends a new RTM_NEWADDR message to kernel
+        // to update the IPv4 address, therefore, we should never see provisioning failure any
+        // more.
+        verify(mCb, never()).onProvisioningFailure(any());
     }
 
     private void doDhcpHostnameSettingTest(int hostnameSetting,
@@ -6013,4 +6025,159 @@ public abstract class IpClientIntegrationTestCommon {
         doDhcpHostnameSettingTest(IIpClient.HOSTNAME_SETTING_DO_NOT_SEND,
                 false /* isHostnameConfigurationEnabled */, false /* expectSendHostname */);
     }
+
+    // Store the network event to database multiple times.
+    private void storeNudFailureEvents(long when, long expiry, int times, int eventType) {
+        for (int i = 0; i < times; i++) {
+            storeNetworkEvent(TEST_CLUSTER, when, expiry, eventType);
+            when += 60 * 1000; // event interval is 1min
+            expiry += 60 * 1000; // expiry also delays 1min
+        }
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastDay() throws Exception {
+        // // NUD failure event count exceeds daily threshold nor weekly.
+        final long when = System.currentTimeMillis() - ONE_DAY_IN_MS / 2; // 12h ago
+        final long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 10, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        runIpReachabilityMonitorProbeFailedTest();
+        assertNeverNotifyNeighborLost();
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = false)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastDay_flagOff() throws Exception {
+        // NUD failure event count exceeds daily threshold nor weekly.
+        final long when = System.currentTimeMillis() - ONE_DAY_IN_MS / 2; // 12h ago
+        final long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 19, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        runIpReachabilityMonitorProbeFailedTest();
+        assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
+                NudEventType.NUD_POST_ROAMING_FAILED_CRITICAL);
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastDay_notUpToThreshold()
+            throws Exception {
+        // NUD failure event count doesn't exceed either weekly threshold nor daily.
+        final long when = System.currentTimeMillis() - ONE_DAY_IN_MS / 2; // 12h ago
+        final long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 9, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        runIpReachabilityMonitorProbeFailedTest();
+        assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
+                NudEventType.NUD_POST_ROAMING_FAILED_CRITICAL);
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastWeek() throws Exception {
+        // NUD failure event count exceeds the weekly threshold, but not daily threshold in the past
+        // day.
+        long when = System.currentTimeMillis() - ONE_WEEK_IN_MS / 2; // half a week ago
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 11, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        when = System.currentTimeMillis() - ONE_DAY_IN_MS / 2; // 12h ago
+        expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 9, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        runIpReachabilityMonitorProbeFailedTest();
+        assertNeverNotifyNeighborLost();
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = false)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastWeek_flagOff() throws Exception {
+        // NUD failure event count exceeds the weekly threshold, but not daily threshold in the past
+        // day.
+        long when = System.currentTimeMillis() - ONE_WEEK_IN_MS / 2; // half a week ago
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 11, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        when = System.currentTimeMillis() - ONE_DAY_IN_MS / 2; // 12h ago
+        expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 9, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        runIpReachabilityMonitorProbeFailedTest();
+        assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
+                NudEventType.NUD_POST_ROAMING_FAILED_CRITICAL);
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastWeek_notUpToThreshold() throws Exception {
+        // NUD failure event count doesn't exceed either weekly threshold nor daily.
+        long when = System.currentTimeMillis() - ONE_WEEK_IN_MS / 2; // half a week ago
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 10, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        when = System.currentTimeMillis() - ONE_DAY_IN_MS / 2; // 12h ago
+        expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 9, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM);
+
+        runIpReachabilityMonitorProbeFailedTest();
+        assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
+                NudEventType.NUD_POST_ROAMING_FAILED_CRITICAL);
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastWeek_stopWritingEvent() throws Exception {
+        long when = (long) (System.currentTimeMillis() - SIX_HOURS_IN_MS * 0.9);
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 10, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+
+        runIpReachabilityMonitorAddressResolutionTest(IPV6_OFF_LINK_DNS_SERVER,
+                ROUTER_LINK_LOCAL /* targetIp */,
+                false /* expectNeighborLost */);
+        verify(mIpMemoryStore, never()).storeNetworkEvent(any(), anyLong(), anyLong(),
+                eq(IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC), any());
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = false)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastWeek_stopWritingEvent_flagOff()
+            throws Exception {
+        long when = (long) (System.currentTimeMillis() - SIX_HOURS_IN_MS * 0.9);
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 10, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+
+        runIpReachabilityMonitorAddressResolutionTest(IPV6_OFF_LINK_DNS_SERVER,
+                ROUTER_LINK_LOCAL /* targetIp */,
+                true /* expectNeighborLost */);
+        verify(mIpMemoryStore, never()).storeNetworkEvent(any(), anyLong(), anyLong(),
+                eq(IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC), any());
+    }
+
+    @Test
+    @Flag(name = IP_REACHABILITY_IGNORE_NUD_FAILURE_VERSION, enabled = true)
+    @SignatureRequiredTest(reason = "need to delete cluster from real db in tearDown")
+    public void testIgnoreNudFailuresIfTooManyInPastWeek_stopWritingEvent_notUpToThreshold()
+            throws Exception {
+        long when = (long) (System.currentTimeMillis() - SIX_HOURS_IN_MS * 0.9);
+        long expiry = when + ONE_WEEK_IN_MS;
+        storeNudFailureEvents(when, expiry, 9, IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+
+        runIpReachabilityMonitorAddressResolutionTest(IPV6_OFF_LINK_DNS_SERVER,
+                ROUTER_LINK_LOCAL /* targetIp */,
+                true /* expectNeighborLost */);
+        assertNotifyNeighborLost(ROUTER_LINK_LOCAL /* targetIp */,
+                NudEventType.NUD_ORGANIC_FAILED_CRITICAL);
+        verify(mIpMemoryStore).storeNetworkEvent(any(), anyLong(), anyLong(),
+                eq(IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC), any());
+    }
 }
diff --git a/tests/integration/common/android/net/networkstack/TestNetworkStackServiceClient.kt b/tests/integration/common/android/net/networkstack/TestNetworkStackServiceClient.kt
index 3bba529c..ac78b7a2 100644
--- a/tests/integration/common/android/net/networkstack/TestNetworkStackServiceClient.kt
+++ b/tests/integration/common/android/net/networkstack/TestNetworkStackServiceClient.kt
@@ -23,6 +23,7 @@ import android.content.ServiceConnection
 import android.content.pm.PackageManager.MATCH_SYSTEM_ONLY
 import android.net.INetworkStackConnector
 import android.os.IBinder
+import android.os.UserHandle
 import android.util.Log
 import androidx.test.platform.app.InstrumentationRegistry
 import kotlin.test.fail
@@ -82,7 +83,15 @@ class TestNetworkStackServiceClient private constructor() : NetworkStackClientBa
     private fun init() {
         val bindIntent = Intent(testNetworkStackServiceAction)
         bindIntent.component = getNetworkStackComponent(bindIntent.action)
-        context.bindService(bindIntent, serviceConnection, Context.BIND_AUTO_CREATE)
+        // Use UserHandle.SYSTEM to bind to the test network stack service as user 0. Otherwise on a
+        // multi-user device where current user is not user 0, this intent will start another test
+        // service for the current user which is not expected.
+        context.bindServiceAsUser(
+            bindIntent,
+            serviceConnection,
+            Context.BIND_AUTO_CREATE,
+            UserHandle.SYSTEM
+        )
     }
 
     fun disconnect() {
diff --git a/tests/integration/root/android/net/ip/IpClientRootTest.kt b/tests/integration/root/android/net/ip/IpClientRootTest.kt
index 715e27d5..3a56139f 100644
--- a/tests/integration/root/android/net/ip/IpClientRootTest.kt
+++ b/tests/integration/root/android/net/ip/IpClientRootTest.kt
@@ -16,6 +16,7 @@
 
 package android.net.ip
 
+import android.Manifest.permission.INTERACT_ACROSS_USERS_FULL
 import android.Manifest.permission.NETWORK_SETTINGS
 import android.Manifest.permission.READ_DEVICE_CONFIG
 import android.Manifest.permission.WRITE_DEVICE_CONFIG
@@ -24,6 +25,7 @@ import android.net.IIpMemoryStoreCallbacks
 import android.net.NetworkStackIpMemoryStore
 import android.net.ipmemorystore.NetworkAttributes
 import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener
+import android.net.ipmemorystore.OnNetworkEventCountRetrievedListener
 import android.net.ipmemorystore.Status
 import android.net.networkstack.TestNetworkStackServiceClient
 import android.os.Process
@@ -38,6 +40,7 @@ import java.util.concurrent.CompletableFuture
 import java.util.concurrent.CountDownLatch
 import java.util.concurrent.TimeUnit
 import java.util.concurrent.TimeoutException
+import kotlin.test.assertFalse
 import kotlin.test.assertNotNull
 import kotlin.test.assertNull
 import kotlin.test.assertTrue
@@ -83,7 +86,7 @@ class IpClientRootTest : IpClientIntegrationTestCommon() {
             // Connect to the NetworkStack only once, as it is relatively expensive (~50ms plus any
             // polling time waiting for the test UID to be allowed), and there should be minimal
             // side-effects between tests compared to reconnecting every time.
-            automation.adoptShellPermissionIdentity(NETWORK_SETTINGS)
+            automation.adoptShellPermissionIdentity(NETWORK_SETTINGS, INTERACT_ACROSS_USERS_FULL)
             try {
                 automation.executeShellCommand("su root service call network_stack " +
                         "$ALLOW_TEST_UID_INDEX i32 " + Process.myUid())
@@ -249,6 +252,23 @@ class IpClientRootTest : IpClientIntegrationTestCommon() {
         }
     }
 
+    private class TestNetworkEventCountRetrievedListener : OnNetworkEventCountRetrievedListener {
+        private val future = CompletableFuture<IntArray>()
+        override fun onNetworkEventCountRetrieved(
+            status: Status,
+            counts: IntArray
+        ) {
+            if (status.resultCode != Status.SUCCESS) {
+                fail("retrieved the network event count " + " status: " + status.resultCode)
+            }
+            future.complete(counts)
+        }
+
+        fun getBlockingNetworkEventCount(timeout: Long): IntArray {
+            return future.get(timeout, TimeUnit.MILLISECONDS)
+        }
+    }
+
     override fun getStoredNetworkAttributes(l2Key: String, timeout: Long): NetworkAttributes {
         val listener = TestAttributesRetrievedListener()
         mStore.retrieveNetworkAttributes(l2Key, listener)
@@ -267,6 +287,23 @@ class IpClientRootTest : IpClientIntegrationTestCommon() {
         mStore.storeNetworkAttributes(l2Key, na, null /* listener */)
     }
 
+    override fun storeNetworkEvent(cluster: String, now: Long, expiry: Long, eventType: Int) {
+        mStore.storeNetworkEvent(cluster, now, expiry, eventType, null /* listener */)
+    }
+
+    override fun getStoredNetworkEventCount(
+            cluster: String,
+            sinceTimes: LongArray,
+            eventType: IntArray,
+            timeout: Long
+    ): IntArray {
+        val listener = TestNetworkEventCountRetrievedListener()
+        mStore.retrieveNetworkEventCount(cluster, sinceTimes, eventType, listener)
+        val counts = listener.getBlockingNetworkEventCount(timeout)
+        assertFalse(counts.size == 0)
+        return counts
+    }
+
     private fun readNudSolicitNumFromResource(name: String): Int {
         val packageName = nsClient.getNetworkStackPackageName()
         val resource = mContext.createPackageContext(packageName, 0).getResources()
diff --git a/tests/integration/signature/android/net/ip/IpClientSignatureTest.kt b/tests/integration/signature/android/net/ip/IpClientSignatureTest.kt
index f4010730..c3b189a7 100644
--- a/tests/integration/signature/android/net/ip/IpClientSignatureTest.kt
+++ b/tests/integration/signature/android/net/ip/IpClientSignatureTest.kt
@@ -21,6 +21,7 @@ import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener
 import android.net.ipmemorystore.Status
 import android.net.ipmemorystore.Status.SUCCESS
 import android.util.ArrayMap
+import android.util.Pair
 import org.mockito.ArgumentCaptor
 import org.mockito.Mockito.any
 import org.mockito.Mockito.doAnswer
@@ -63,6 +64,7 @@ class IpClientSignatureTest : IpClientIntegrationTestCommon() {
     override fun getDeviceConfigProperty(name: String): String? {
         return mDeviceConfigProperties.get(name)
     }
+
     override fun getStoredNetworkAttributes(l2Key: String, timeout: Long): NetworkAttributes {
         val networkAttributesCaptor = ArgumentCaptor.forClass(NetworkAttributes::class.java)
 
@@ -71,6 +73,30 @@ class IpClientSignatureTest : IpClientIntegrationTestCommon() {
         return networkAttributesCaptor.value
     }
 
+    override fun getStoredNetworkEventCount(
+            cluster: String,
+            sinceTimes: LongArray,
+            eventType: IntArray,
+            timeout: Long
+    ): IntArray {
+        val counts = IntArray(sinceTimes.size)
+        val eventTypesSet = eventType.toSet() // Convert eventType to Set for faster contains check
+
+        sinceTimes.forEachIndexed { index, sinceTime ->
+            var count = 0
+            mNetworkEvents.forEach { event ->
+                val key = event.first
+                val value = event.second
+                if (key == cluster && eventTypesSet.contains(value.second) &&
+                        sinceTime <= value.first) {
+                    count++
+                }
+            }
+            counts[index] = count
+        }
+        return counts
+    }
+
     override fun assertIpMemoryNeverStoreNetworkAttributes(l2Key: String, timeout: Long) {
         verify(mIpMemoryStore, never()).storeNetworkAttributes(eq(l2Key), any(), any())
     }
@@ -83,6 +109,11 @@ class IpClientSignatureTest : IpClientIntegrationTestCommon() {
         }.`when`(mIpMemoryStore).retrieveNetworkAttributes(eq(l2Key), any())
     }
 
+    override fun storeNetworkEvent(cluster: String, now: Long, expiry: Long, eventType: Int) {
+        val event = Pair(cluster, Pair(now, eventType))
+        mNetworkEvents.add(event)
+    }
+
     override fun readNudSolicitNumInSteadyStateFromResource(): Int {
         return DEFAULT_NUD_SOLICIT_NUM_STEADY_STATE
     }
diff --git a/tests/integration/signature/android/net/netlink/InetDiagSocketIntegrationTest.java b/tests/integration/signature/android/net/netlink/InetDiagSocketIntegrationTest.java
index 0329fab4..eb7b1239 100644
--- a/tests/integration/signature/android/net/netlink/InetDiagSocketIntegrationTest.java
+++ b/tests/integration/signature/android/net/netlink/InetDiagSocketIntegrationTest.java
@@ -181,8 +181,6 @@ public class InetDiagSocketIntegrationTest {
 
     @Test
     public void testGetConnectionOwnerUid() throws Exception {
-        // Skip the test for API <= Q, as b/141603906 this was only fixed in Q-QPR2
-        assumeTrue(ShimUtils.isAtLeastR());
         checkGetConnectionOwnerUid("::", null);
         checkGetConnectionOwnerUid("::", "::");
         checkGetConnectionOwnerUid("0.0.0.0", null);
@@ -196,8 +194,6 @@ public class InetDiagSocketIntegrationTest {
     /* Verify fix for b/141603906 */
     @Test
     public void testB141603906() throws Exception {
-        // Skip the test for API <= Q, as b/141603906 this was only fixed in Q-QPR2
-        assumeTrue(ShimUtils.isAtLeastR());
         final InetSocketAddress src = new InetSocketAddress(0);
         final InetSocketAddress dst = new InetSocketAddress(0);
         final int numThreads = 8;
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 91e94a83..7e6de1a3 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -32,13 +32,13 @@ java_defaults {
         "kotlin-reflect",
         "mockito-target-extended-minus-junit4",
         "net-tests-utils",
-        //"net-utils-framework-common",
+        "net-utils-framework-common",
         "testables",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs",
+        "android.test.base.stubs",
+        "android.test.mock.stubs",
     ],
     defaults: [
         "framework-connectivity-test-defaults",
diff --git a/tests/unit/jni/apf_jni.cpp b/tests/unit/jni/apf_jni.cpp
index 279e3399..873b217c 100644
--- a/tests/unit/jni/apf_jni.cpp
+++ b/tests/unit/jni/apf_jni.cpp
@@ -36,7 +36,7 @@ static int run_apf_interpreter(int apf_version, uint32_t* program,
                                uint32_t program_len, uint32_t ram_len,
                                const uint8_t* packet, uint32_t packet_len,
                                uint32_t filter_age) {
-  if (apf_version == 4) {
+  if (apf_version <= 4) {
     return accept_packet((uint8_t*)program, program_len, ram_len, packet, packet_len,
                          filter_age);
   } else {
diff --git a/tests/unit/src/android/net/apf/ApfFilterTest.kt b/tests/unit/src/android/net/apf/ApfFilterTest.kt
new file mode 100644
index 00000000..15ff2241
--- /dev/null
+++ b/tests/unit/src/android/net/apf/ApfFilterTest.kt
@@ -0,0 +1,2146 @@
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
+package android.net.apf
+
+import android.content.Context
+import android.net.LinkAddress
+import android.net.LinkProperties
+import android.net.MacAddress
+import android.net.NattKeepalivePacketDataParcelable
+import android.net.TcpKeepalivePacketDataParcelable
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_NON_IPV4
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_OTHER_HOST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REPLY_SPA_NO_HOST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_UNKNOWN
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_V6_ONLY
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_GARP_REPLY
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_ADDR
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_NET
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_KEEPALIVE_ACK
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_L2_BROADCAST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_MULTICAST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NATT_KEEPALIVE
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_TCP_PORT7_UNICAST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_NA
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NON_ICMP_MULTICAST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST
+import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD
+import android.net.apf.ApfCounterTracker.Counter.PASSED_ETHER_OUR_SRC_MAC
+import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY
+import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST
+import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY
+import android.net.apf.ApfCounterTracker.Counter.PASSED_DHCP
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_UNICAST
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION
+import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE
+import android.net.apf.ApfCounterTracker.Counter.PASSED_MLD
+import android.net.apf.ApfFilter.Dependencies
+import android.net.apf.ApfTestHelpers.Companion.TIMEOUT_MS
+import android.net.apf.ApfTestHelpers.Companion.consumeInstalledProgram
+import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
+import android.net.apf.BaseApfGenerator.APF_VERSION_3
+import android.net.apf.BaseApfGenerator.APF_VERSION_6
+import android.net.ip.IpClient.IpClientCallbacksWrapper
+import android.net.nsd.NsdManager
+import android.net.nsd.OffloadEngine
+import android.net.nsd.OffloadServiceInfo
+import android.os.Build
+import android.os.Handler
+import android.os.HandlerThread
+import android.os.SystemClock
+import android.system.Os
+import android.system.OsConstants.AF_UNIX
+import android.system.OsConstants.IFA_F_TENTATIVE
+import android.system.OsConstants.SOCK_STREAM
+import androidx.test.filters.SmallTest
+import com.android.internal.annotations.GuardedBy
+import com.android.net.module.util.HexDump
+import com.android.net.module.util.InterfaceParams
+import com.android.net.module.util.NetworkStackConstants.ARP_ETHER_IPV4_LEN
+import com.android.net.module.util.NetworkStackConstants.ARP_REPLY
+import com.android.net.module.util.NetworkStackConstants.ARP_REQUEST
+import com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN
+import com.android.net.module.util.NetworkStackConstants.ICMPV6_NA_HEADER_LEN
+import com.android.net.module.util.NetworkStackConstants.ICMPV6_NS_HEADER_LEN
+import com.android.net.module.util.NetworkStackConstants.IPV6_HEADER_LEN
+import com.android.net.module.util.arp.ArpPacket
+import com.android.networkstack.metrics.NetworkQuirkMetrics
+import com.android.networkstack.packets.NeighborAdvertisement
+import com.android.networkstack.packets.NeighborSolicitation
+import com.android.networkstack.util.NetworkStackUtils
+import com.android.testutils.DevSdkIgnoreRule
+import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
+import com.android.testutils.DevSdkIgnoreRunner
+import com.android.testutils.quitResources
+import com.android.testutils.waitForIdle
+import java.io.FileDescriptor
+import java.net.Inet6Address
+import java.net.InetAddress
+import kotlin.test.assertContentEquals
+import kotlin.test.assertEquals
+import libcore.io.IoUtils
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentCaptor
+import org.mockito.ArgumentMatchers.any
+import org.mockito.ArgumentMatchers.anyInt
+import org.mockito.ArgumentMatchers.anyLong
+import org.mockito.ArgumentMatchers.eq
+import org.mockito.Mock
+import org.mockito.Mockito
+import org.mockito.Mockito.doAnswer
+import org.mockito.Mockito.doReturn
+import org.mockito.Mockito.never
+import org.mockito.Mockito.times
+import org.mockito.Mockito.verify
+import org.mockito.MockitoAnnotations
+import org.mockito.invocation.InvocationOnMock
+
+/**
+ * Test for APF filter.
+ */
+@DevSdkIgnoreRunner.MonitorThreadLeak
+@RunWith(DevSdkIgnoreRunner::class)
+@SmallTest
+class ApfFilterTest {
+    companion object {
+        private const val THREAD_QUIT_MAX_RETRY_COUNT = 3
+        private const val TAG = "ApfFilterTest"
+    }
+
+    @get:Rule
+    val ignoreRule = DevSdkIgnoreRule()
+
+    @Mock
+    private lateinit var context: Context
+
+    @Mock private lateinit var metrics: NetworkQuirkMetrics
+
+    @Mock private lateinit var dependencies: Dependencies
+
+    @Mock private lateinit var ipClientCallback: IpClientCallbacksWrapper
+    @Mock private lateinit var nsdManager: NsdManager
+
+    @GuardedBy("mApfFilterCreated")
+    private val mApfFilterCreated = ArrayList<AndroidPacketFilter>()
+    private val loInterfaceParams = InterfaceParams.getByName("lo")
+    private val ifParams =
+        InterfaceParams(
+            "lo",
+            loInterfaceParams.index,
+            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
+            loInterfaceParams.defaultMtu
+        )
+    private val hostIpv4Address = byteArrayOf(10, 0, 0, 1)
+    private val senderIpv4Address = byteArrayOf(10, 0, 0, 2)
+    private val arpBroadcastMacAddress = intArrayOf(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
+        .map { it.toByte() }.toByteArray()
+    private val senderMacAddress = intArrayOf(0x02, 0x22, 0x33, 0x44, 0x55, 0x66)
+        .map { it.toByte() }.toByteArray()
+    private val senderIpv6Address =
+        // 2001::200:1a:1122:3344
+        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x11, 0x22, 0x33, 0x44)
+            .map{ it.toByte() }.toByteArray()
+    private val hostIpv6Addresses = listOf(
+        // 2001::200:1a:3344:1122
+        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x33, 0x44, 0x11, 0x22)
+            .map{ it.toByte() }.toByteArray(),
+        // 2001::100:1b:4455:6677
+        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0x44, 0x55, 0x66, 0x77)
+            .map{ it.toByte() }.toByteArray()
+    )
+    private val hostIpv6TentativeAddresses = listOf(
+        // 2001::200:1a:1234:5678
+        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x12, 0x34, 0x56, 0x78)
+            .map{ it.toByte() }.toByteArray(),
+        // 2001::100:1b:1234:5678
+        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0x12, 0x34, 0x56, 0x78)
+            .map{ it.toByte() }.toByteArray()
+    )
+    private val hostAnycast6Addresses = listOf(
+        // 2001::100:1b:aabb:ccdd
+        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0xaa, 0xbb, 0xcc, 0xdd)
+            .map{ it.toByte() }.toByteArray()
+    )
+    private val hostMulticastMacAddresses = listOf(
+        // 33:33:00:00:00:01
+        intArrayOf(0x33, 0x33, 0, 0, 0, 1).map { it.toByte() }.toByteArray(),
+        // 33:33:ff:44:11:22
+        intArrayOf(0x33, 0x33, 0xff, 0x44, 0x11, 0x22).map { it.toByte() }.toByteArray(),
+        // 33:33:ff:55:66:77
+        intArrayOf(0x33, 0x33, 0xff, 0x55, 0x66, 0x77).map { it.toByte() }.toByteArray(),
+        // 33:33:ff:bb:cc:dd
+        intArrayOf(0x33, 0x33, 0xff, 0xbb, 0xcc, 0xdd).map { it.toByte() }.toByteArray(),
+    )
+
+    private val handlerThread by lazy {
+        HandlerThread("$TAG handler thread").apply { start() }
+    }
+    private val handler by lazy { Handler(handlerThread.looper) }
+    private var writerSocket = FileDescriptor()
+
+    @Before
+    fun setUp() {
+        MockitoAnnotations.initMocks(this)
+        // mock anycast6 address from /proc/net/anycast6
+        doReturn(hostAnycast6Addresses).`when`(dependencies).getAnycast6Addresses(any())
+
+        // mock ether multicast mac address from /proc/net/dev_mcast
+        doReturn(hostMulticastMacAddresses).`when`(dependencies).getEtherMulticastAddresses(any())
+
+        // mock nd traffic class from /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass
+        doReturn(0).`when`(dependencies).getNdTrafficClass(any())
+        doAnswer { invocation: InvocationOnMock ->
+            synchronized(mApfFilterCreated) {
+                mApfFilterCreated.add(invocation.getArgument(0))
+            }
+        }.`when`(dependencies).onApfFilterCreated(any())
+        doReturn(SystemClock.elapsedRealtime()).`when`(dependencies).elapsedRealtime()
+        val readSocket = FileDescriptor()
+        Os.socketpair(AF_UNIX, SOCK_STREAM, 0, writerSocket, readSocket)
+        doReturn(readSocket).`when`(dependencies).createPacketReaderSocket(anyInt())
+        doReturn(nsdManager).`when`(context).getSystemService(NsdManager::class.java)
+    }
+
+    private fun shutdownApfFilters() {
+        quitResources(THREAD_QUIT_MAX_RETRY_COUNT, {
+            synchronized(mApfFilterCreated) {
+                val ret = ArrayList(mApfFilterCreated)
+                mApfFilterCreated.clear()
+                return@quitResources ret
+            }
+        }, { apf: AndroidPacketFilter ->
+            handler.post { apf.shutdown() }
+        })
+
+        synchronized(mApfFilterCreated) {
+            assertEquals(
+                0,
+                mApfFilterCreated.size.toLong(),
+                "ApfFilters did not fully shutdown."
+            )
+        }
+    }
+
+    @After
+    fun tearDown() {
+        IoUtils.closeQuietly(writerSocket)
+        shutdownApfFilters()
+        handler.waitForIdle(TIMEOUT_MS)
+        Mockito.framework().clearInlineMocks()
+        ApfJniUtils.resetTransmittedPacketMemory()
+        handlerThread.quitSafely()
+        handlerThread.join()
+    }
+
+    private fun getDefaultConfig(apfVersion: Int = APF_VERSION_6): ApfFilter.ApfConfiguration {
+        val config = ApfFilter.ApfConfiguration()
+        config.apfVersionSupported = apfVersion
+        // 4K is the highly recommended value in APFv6 for vendor
+        config.apfRamSize = 4096
+        config.multicastFilter = false
+        config.ieee802_3Filter = false
+        config.ethTypeBlackList = IntArray(0)
+        config.shouldHandleArpOffload = true
+        config.shouldHandleNdOffload = true
+        return config
+    }
+
+    private fun getApfFilter(
+            apfCfg: ApfFilter.ApfConfiguration = getDefaultConfig(APF_VERSION_6)
+    ): ApfFilter {
+        lateinit var apfFilter: ApfFilter
+        handler.post {
+            apfFilter = ApfFilter(
+                    handler,
+                    context,
+                    apfCfg,
+                    ifParams,
+                    ipClientCallback,
+                    metrics,
+                    dependencies
+            )
+        }
+        handlerThread.waitForIdle(TIMEOUT_MS)
+        return apfFilter
+    }
+
+    private fun doTestEtherTypeAllowListFilter(apfFilter: ApfFilter) {
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+
+        // Using scapy to generate IPv4 mDNS packet:
+        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
+        //   ip = IP(src="192.168.1.1")
+        //   udp = UDP(sport=5353, dport=5353)
+        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
+        //   p = eth/ip/udp/dns
+        val mdnsPkt = """
+            01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f
+            b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(mdnsPkt),
+            PASSED_IPV4
+        )
+
+        // Using scapy to generate RA packet:
+        //  eth = Ether(src="E8:9F:80:66:60:BB", dst="33:33:00:00:00:01")
+        //  ip6 = IPv6(src="fe80::1", dst="ff02::1")
+        //  icmp6 = ICMPv6ND_RA(routerlifetime=3600, retranstimer=3600)
+        //  p = eth/ip6/icmp6
+        val raPkt = """
+            333300000001e89f806660bb86dd6000000000103afffe800000000000000000000000
+            000001ff0200000000000000000000000000018600600700080e100000000000000e10
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(raPkt),
+            PASSED_IPV6_ICMP
+        )
+
+        // Using scapy to generate ethernet packet with type 0x88A2:
+        //  p = Ether(type=0x88A2)/Raw(load="01")
+        val ethPkt = "ffffffffffff047bcb463fb588a23031"
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(ethPkt),
+            DROPPED_ETHERTYPE_NOT_ALLOWED
+        )
+    }
+
+    private fun generateNsPacket(
+        srcMac: ByteArray,
+        dstMac: ByteArray,
+        srcIp: ByteArray,
+        dstIp: ByteArray,
+        target: ByteArray,
+    ): ByteArray {
+        val nsPacketBuf = NeighborSolicitation.build(
+            MacAddress.fromBytes(srcMac),
+            MacAddress.fromBytes(dstMac),
+            InetAddress.getByAddress(srcIp) as Inet6Address,
+            InetAddress.getByAddress(dstIp) as Inet6Address,
+            InetAddress.getByAddress(target) as Inet6Address
+        )
+
+        val nsPacket = ByteArray(
+            ETHER_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_NS_HEADER_LEN + 8 // option length
+        )
+        nsPacketBuf.get(nsPacket)
+        return nsPacket
+    }
+
+    private fun generateNaPacket(
+        srcMac: ByteArray,
+        dstMac: ByteArray,
+        srcIp: ByteArray,
+        dstIp: ByteArray,
+        flags: Int,
+        target: ByteArray,
+    ): ByteArray {
+        val naPacketBuf = NeighborAdvertisement.build(
+            MacAddress.fromBytes(srcMac),
+            MacAddress.fromBytes(dstMac),
+            InetAddress.getByAddress(srcIp) as Inet6Address,
+            InetAddress.getByAddress(dstIp) as Inet6Address,
+            flags,
+            InetAddress.getByAddress(target) as Inet6Address
+        )
+        val naPacket = ByteArray(
+            ETHER_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_NA_HEADER_LEN + 8 // lla option length
+        )
+
+        naPacketBuf.get(naPacket)
+        return naPacket
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    fun testV4EtherTypeAllowListFilter() {
+        val apfFilter = getApfFilter(getDefaultConfig(APF_VERSION_3))
+        doTestEtherTypeAllowListFilter(apfFilter)
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    fun testV6EtherTypeAllowListFilter() {
+        val apfFilter = getApfFilter(getDefaultConfig(APF_VERSION_6))
+        doTestEtherTypeAllowListFilter(apfFilter)
+    }
+
+    @Test
+    fun testIPv4PacketFilterOnV6OnlyNetwork() {
+        val apfFilter = getApfFilter()
+        apfFilter.updateClatInterfaceState(true)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
+
+        // Using scapy to generate IPv4 mDNS packet:
+        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
+        //   ip = IP(src="192.168.1.1")
+        //   udp = UDP(sport=5353, dport=5353)
+        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
+        //   p = eth/ip/udp/dns
+        val mdnsPkt = """
+            01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f
+            b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(mdnsPkt),
+            DROPPED_IPV4_NON_DHCP4
+        )
+
+        // Using scapy to generate non UDP protocol packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=12)
+        //   pkt = ether/ip
+        val nonUdpPkt = """
+            ffffffffffff00112233445508004500001400010000400cb934c0a80101ffffffff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonUdpPkt),
+            DROPPED_IPV4_NON_DHCP4
+        )
+
+        // Using scapy to generate fragmented UDP protocol packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', flags=1, frag=10, proto=17)
+        //   pkt = ether/ip
+        val fragmentUdpPkt = """
+            ffffffffffff0011223344550800450000140001200a40119925c0a80101ffffffff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(fragmentUdpPkt),
+            DROPPED_IPV4_NON_DHCP4
+        )
+
+        // Using scapy to generate destination port is not DHCP client port packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
+        //   udp = UDP(dport=70)
+        //   pkt = ether/ip/udp
+        val nonDhcpServerPkt = """
+            ffffffffffff00112233445508004500001c000100004011b927c0a80101ffffffff0035004600083dba
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDhcpServerPkt),
+            DROPPED_IPV4_NON_DHCP4
+        )
+
+        // Using scapy to generate DHCP4 offer packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
+        //   udp = UDP(sport=67, dport=68)
+        //   bootp = BOOTP(op=2,
+        //                 yiaddr='192.168.1.100',
+        //                 siaddr='192.168.1.1',
+        //                 chaddr=b'\x00\x11\x22\x33\x44\x55')
+        //   dhcp_options = [('message-type', 'offer'),
+        //                   ('server_id', '192.168.1.1'),
+        //                   ('subnet_mask', '255.255.255.0'),
+        //                   ('router', '192.168.1.1'),
+        //                   ('lease_time', 86400),
+        //                   ('name_server', '8.8.8.8'),
+        //                   'end']
+        //   dhcp = DHCP(options=dhcp_options)
+        //   dhcp_offer_packet = ether/ip/udp/bootp/dhcp
+        val dhcp4Pkt = """
+            ffffffffffff00112233445508004500012e000100004011b815c0a80101ffffffff0043
+            0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000011
+            223344550000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000638253633501023604c0
+            a801010104ffffff000304c0a80101330400015180060408080808ff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(dhcp4Pkt),
+            PASSED_IPV4_FROM_DHCPV4_SERVER
+        )
+
+        // Duplicate of dhcp4Pkt with DF flag set.
+        val dhcp4PktDf = """
+            ffffffffffff00112233445508004500012e000140004011b815c0a80101ffffffff0043
+            0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000011
+            223344550000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000638253633501023604c0
+            a801010104ffffff000304c0a80101330400015180060408080808ff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(dhcp4PktDf),
+            PASSED_IPV4_FROM_DHCPV4_SERVER
+        )
+
+        // Using scapy to generate DHCP4 offer packet:
+        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
+        //   ip = IP(src="192.168.1.10", dst="192.168.1.20")  # IPv4
+        //   udp = UDP(sport=12345, dport=53)
+        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
+        //   pkt = eth / ip / udp / dns
+        //   fragments = fragment(pkt, fragsize=30)
+        //   fragments[1]
+        val fragmentedUdpPkt = """
+            01005e0000fbe89f806660bb08004500001d000100034011f75dc0a8010ac0a8
+            01146f63616c00000c0001
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(fragmentedUdpPkt),
+            DROPPED_IPV4_NON_DHCP4
+        )
+    }
+
+    @Test
+    fun testLoopbackFilter() {
+        val apfConfig = getDefaultConfig()
+        val apfFilter = getApfFilter(apfConfig)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        // Using scapy to generate echo-ed broadcast packet:
+        //   ether = Ether(src=${ifParams.macAddr}, dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=21)
+        //   pkt = ether/ip
+        val nonDhcpBcastPkt = """
+            ffffffffffff020304050607080045000014000100004015b92bc0a80101ffffffff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+                apfFilter.mApfVersionSupported,
+                program,
+                HexDump.hexStringToByteArray(nonDhcpBcastPkt),
+                PASSED_ETHER_OUR_SRC_MAC
+        )
+    }
+
+    @Test
+    fun testIPv4MulticastPacketFilter() {
+        val apfConfig = getDefaultConfig()
+        apfConfig.multicastFilter = true
+        val apfFilter = getApfFilter(apfConfig)
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
+        val lp = LinkProperties()
+        lp.addLinkAddress(linkAddress)
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // Using scapy to generate DHCP4 offer packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
+        //   udp = UDP(sport=67, dport=68)
+        //   bootp = BOOTP(op=2,
+        //                 yiaddr='192.168.1.100',
+        //                 siaddr='192.168.1.1',
+        //                 chaddr=b'\x02\x03\x04\x05\x06\x07')
+        //   dhcp_options = [('message-type', 'offer'),
+        //                   ('server_id', '192.168.1.1'),
+        //                   ('subnet_mask', '255.255.255.0'),
+        //                   ('router', '192.168.1.1'),
+        //                   ('lease_time', 86400),
+        //                   ('name_server', '8.8.8.8'),
+        //                   'end']
+        //   dhcp = DHCP(options=dhcp_options)
+        //   dhcp_offer_packet = ether/ip/udp/bootp/dhcp
+        val dhcp4Pkt = """
+            ffffffffffff00112233445508004500012e000100004011b815c0a80101ffffffff0043
+            0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000203
+            040506070000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000638253633501023604c0
+            a801010104ffffff000304c0a80101330400015180060408080808ff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(dhcp4Pkt),
+            PASSED_DHCP
+        )
+
+        // Using scapy to generate non DHCP multicast packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='224.0.0.1', proto=21)
+        //   pkt = ether/ip
+        val nonDhcpMcastPkt = """
+            ffffffffffff001122334455080045000014000100004015d929c0a80101e0000001
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDhcpMcastPkt),
+            DROPPED_IPV4_MULTICAST
+        )
+
+        // Using scapy to generate non DHCP broadcast packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=21)
+        //   pkt = ether/ip
+        val nonDhcpBcastPkt = """
+            ffffffffffff001122334455080045000014000100004015b92bc0a80101ffffffff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDhcpBcastPkt),
+            DROPPED_IPV4_BROADCAST_ADDR
+        )
+
+        // Using scapy to generate non DHCP subnet broadcast packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='10.0.0.255', proto=21)
+        //   pkt = ether/ip
+        val nonDhcpNetBcastPkt = """
+            ffffffffffff001122334455080045000014000100004015ae2cc0a801010a0000ff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDhcpNetBcastPkt),
+            DROPPED_IPV4_BROADCAST_NET
+        )
+
+        // Using scapy to generate non DHCP unicast packet:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='02:03:04:05:06:07')
+        //   ip = IP(src='192.168.1.1', dst='192.168.1.2', proto=21)
+        //   pkt = ether/ip
+        val nonDhcpUcastPkt = """
+            020304050607001122334455080045000014000100004015f780c0a80101c0a80102
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDhcpUcastPkt),
+            PASSED_IPV4_UNICAST
+        )
+
+        // Using scapy to generate non DHCP unicast packet with broadcast ether destination:
+        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
+        //   ip = IP(src='192.168.1.1', dst='192.168.1.2', proto=21)
+        //   pkt = ether/ip
+        val nonDhcpUcastL2BcastPkt = """
+            ffffffffffff001122334455080045000014000100004015f780c0a80101c0a80102
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDhcpUcastL2BcastPkt),
+            DROPPED_IPV4_L2_BROADCAST
+        )
+    }
+
+    @Test
+    fun testArpFilterDropPktsOnV6OnlyNetwork() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        apfFilter.updateClatInterfaceState(true)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // Drop ARP request packet when clat is enabled
+        // Using scapy to generate ARP request packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP()
+        // pkt = eth/arp
+        val arpPkt = """
+            010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(arpPkt),
+            DROPPED_ARP_V6_ONLY
+        )
+    }
+
+    @Test
+    fun testIPv4TcpKeepaliveFilter() {
+        val srcAddr = byteArrayOf(10, 0, 0, 5)
+        val dstAddr = byteArrayOf(10, 0, 0, 6)
+        val srcPort = 12345
+        val dstPort = 54321
+        val seqNum = 2123456789
+        val ackNum = 1234567890
+
+        // src: 10.0.0.5:12345
+        // dst: 10.0.0.6:54321
+        val parcel = TcpKeepalivePacketDataParcelable()
+        parcel.srcAddress = InetAddress.getByAddress(srcAddr).address
+        parcel.srcPort = srcPort
+        parcel.dstAddress = InetAddress.getByAddress(dstAddr).address
+        parcel.dstPort = dstPort
+        parcel.seq = seqNum
+        parcel.ack = ackNum
+
+        val apfConfig = getDefaultConfig()
+        apfConfig.multicastFilter = true
+        apfConfig.ieee802_3Filter = true
+        val apfFilter = getApfFilter(apfConfig)
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        apfFilter.addTcpKeepalivePacketFilter(1, parcel)
+        var program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // Drop IPv4 keepalive ack
+        // Using scapy to generate IPv4 TCP keepalive ack packet with seq + 1:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // tcp = TCP(sport=54321, dport=12345, flags="A", seq=1234567890, ack=2123456790)
+        // pkt = eth/ip/tcp
+        val keepaliveAckPkt = """
+            01020304050600010203040508004500002800010000400666c50a0000060a000005d4313039499602d2
+            7e916116501020004b4f0000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(keepaliveAckPkt),
+            DROPPED_IPV4_KEEPALIVE_ACK
+        )
+
+        // Pass IPv4 non-keepalive ack from the same source address
+        // Using scapy to generate IPv4 TCP non-keepalive ack from the same source address:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // tcp = TCP(sport=54321, dport=12345, flags="A", seq=1234567990, ack=2123456789)
+        // pkt = eth/ip/tcp
+        val nonKeepaliveAckPkt1 = """
+            01020304050600010203040508004500002800010000400666c50a0000060a000005d431303949960336
+            7e916115501020004aec0000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(nonKeepaliveAckPkt1),
+            PASSED_IPV4_UNICAST
+        )
+
+        // Pass IPv4 non-keepalive ack from the same source address
+        // Using scapy to generate IPv4 TCP non-keepalive ack from the same source address:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // tcp = TCP(sport=54321, dport=12345, flags="A", seq=1234567890, ack=2123456790)
+        // payload = Raw(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
+        // pkt = eth/ip/tcp/payload
+        val nonKeepaliveAckPkt2 = """
+            01020304050600010203040508004500003200010000400666bb0a0000060a000005d4313039499602d27
+            e91611650102000372c000000010203040506070809
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(nonKeepaliveAckPkt2),
+            PASSED_IPV4_UNICAST
+        )
+
+        // Pass IPv4 keepalive ack from another address
+        // Using scapy to generate IPv4 TCP keepalive ack from another address:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.7', dst='10.0.0.5')
+        // tcp = TCP(sport=23456, dport=65432, flags="A", seq=2123456780, ack=1123456789)
+        // pkt = eth/ip/tcp
+        val otherSrcKeepaliveAck = """
+            01020304050600010203040508004500002800010000400666c40a0000070a0000055ba0ff987e91610c4
+            2f697155010200066e60000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(otherSrcKeepaliveAck),
+            PASSED_IPV4_UNICAST
+        )
+
+        // test IPv4 packets when TCP keepalive filter is removed
+        apfFilter.removeKeepalivePacketFilter(1)
+        program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(keepaliveAckPkt),
+            PASSED_IPV4_UNICAST
+        )
+
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(otherSrcKeepaliveAck),
+            PASSED_IPV4_UNICAST
+        )
+    }
+
+    @Test
+    fun testIPv4NattKeepaliveFilter() {
+        val srcAddr = byteArrayOf(10, 0, 0, 5)
+        val dstAddr = byteArrayOf(10, 0, 0, 6)
+        val srcPort = 1024
+        val dstPort = 4500
+
+        // src: 10.0.0.5:1024
+        // dst: 10.0.0.6:4500
+        val parcel = NattKeepalivePacketDataParcelable()
+        parcel.srcAddress = InetAddress.getByAddress(srcAddr).address
+        parcel.srcPort = srcPort
+        parcel.dstAddress = InetAddress.getByAddress(dstAddr).address
+        parcel.dstPort = dstPort
+
+        val apfConfig = getDefaultConfig()
+        apfConfig.multicastFilter = true
+        apfConfig.ieee802_3Filter = true
+        val apfFilter = getApfFilter(apfConfig)
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        apfFilter.addNattKeepalivePacketFilter(1, parcel)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // Drop IPv4 keepalive response packet
+        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xff:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // udp = UDP(sport=4500, dport=1024)
+        // payload = NAT_KEEPALIVE(nat_keepalive=0xff)
+        // pkt = eth/ip/udp/payload
+        val validNattPkt = """
+            01020304050600010203040508004500001d00010000401166c50a0000060a000005119404000009d73cff
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(validNattPkt),
+            DROPPED_IPV4_NATT_KEEPALIVE
+        )
+
+        // Pass IPv4 keepalive response packet with 0xfe payload
+        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xfe:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // udp = UDP(sport=4500, dport=1024)
+        // payload = NAT_KEEPALIVE(nat_keepalive=0xfe)
+        // pkt = eth/ip/udp/payload
+        val invalidNattPkt = """
+            01020304050600010203040508004500001d00010000401166c50a0000060a000005119404000009d83cfe
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(invalidNattPkt),
+            PASSED_IPV4_UNICAST
+        )
+
+        // Pass IPv4 non-keepalive response packet from the same source address
+        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xfe:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // udp = UDP(sport=4500, dport=1024)
+        // payload = Raw(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
+        // pkt = eth/ip/udp/payload
+        val nonNattPkt = """
+            01020304050600010203040508004500002600010000401166bc0a0000060a000005119404000012c2120
+            0010203040506070809
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(nonNattPkt),
+            PASSED_IPV4_UNICAST
+        )
+
+        // Pass IPv4 non-keepalive response packet from other source address
+        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xfe:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.7', dst='10.0.0.5')
+        // udp = UDP(sport=4500, dport=1024)
+        // payload = Raw(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
+        // pkt = eth/ip/udp/payload
+        val otherSrcNonNattPkt = """
+            01020304050600010203040508004500002600010000401166bb0a0000070a000005119404000012c2110
+            0010203040506070809
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(otherSrcNonNattPkt),
+            PASSED_IPV4_UNICAST
+        )
+    }
+
+    @Test
+    fun testIPv4TcpPort7Filter() {
+        val apfFilter = getApfFilter()
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+
+        // Drop IPv4 TCP port 7 packet
+        // Using scapy to generate IPv4 TCP port 7 packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
+        // tcp = TCP(dport=7)
+        // pkt = eth/ip/tcp
+        val tcpPort7Pkt = """
+            01020304050600010203040508004500002800010000400666c50a0000060a00000500140007000000000
+            0000000500220007bbd0000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(tcpPort7Pkt),
+            DROPPED_IPV4_TCP_PORT7_UNICAST
+        )
+
+        // Pass IPv4 TCP initial fragment packet
+        // Using scapy to generate IPv4 TCP initial fragment packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5', flags=1, frag=0)
+        // tcp = TCP()
+        // pkt = eth/ip/tcp
+        val initialFragmentTcpPkt = """
+            01020304050600010203040508004500002800012000400646c50a0000060a00000500140050000000000
+            0000000500220007b740000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(initialFragmentTcpPkt),
+            PASSED_IPV4
+        )
+
+        // Pass IPv4 TCP fragment packet
+        // Using scapy to generate IPv4 TCP fragment packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip = IP(src='10.0.0.6', dst='10.0.0.5', flags=1, frag=100)
+        // tcp = TCP()
+        // pkt = eth/ip/tcp
+        val fragmentTcpPkt = """
+            01020304050600010203040508004500002800012064400646610a0000060a00000500140050000000000
+            0000000500220007b740000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(fragmentTcpPkt),
+            PASSED_IPV4
+        )
+    }
+
+    @Test
+    fun testIPv6MulticastPacketFilterInDozeMode() {
+        val apfConfig = getDefaultConfig()
+        apfConfig.multicastFilter = true
+        val apfFilter = getApfFilter(apfConfig)
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val lp = LinkProperties()
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+        apfFilter.setLinkProperties(lp)
+        apfFilter.setDozeMode(true)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        // Using scapy to generate non ICMPv6 sent to ff00::/8 (multicast prefix) packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff00::1", nh=59)
+        // pkt = eth/ip6
+        val nonIcmpv6McastPkt = """
+            ffffffffffff00112233445586dd6000000000003b4020010000000000000200001a11223344ff00000
+            0000000000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(nonIcmpv6McastPkt),
+            DROPPED_IPV6_NON_ICMP_MULTICAST
+        )
+
+        // Using scapy to generate ICMPv6 echo sent to ff00::/8 (multicast prefix) packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff00::1", hlim=255)
+        // icmp6 = ICMPv6EchoRequest()
+        // pkt = eth/ip6/icmp6
+        val icmpv6EchoPkt = """
+            02030405060700010203040586dd6000000000083aff20010000000000000200001a11223344ff00000
+            000000000000000000000000180001a3a00000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(icmpv6EchoPkt),
+            DROPPED_IPV6_NON_ICMP_MULTICAST
+        )
+    }
+
+    @Test
+    fun testIPv6PacketFilter() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val lp = LinkProperties()
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        // Using scapy to generate non ICMPv6 packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", nh=59)
+        // pkt = eth/ip6
+        val nonIcmpv6Pkt = """
+            ffffffffffff00112233445586dd6000000000003b4020010000000000000200001a112233442001000
+            0000000000200001a33441122
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(nonIcmpv6Pkt),
+            PASSED_IPV6_NON_ICMP
+        )
+
+        // Using scapy to generate ICMPv6 NA sent to ff02::/120 packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1")
+        // icmp6 = ICMPv6ND_NA()
+        // pkt = eth/ip6/icmp6
+        val icmpv6McastNaPkt = """
+            01020304050600010203040586dd6000000000183aff20010000000000000200001a11223344ff02000
+            000000000000000000000000188007227a000000000000000000000000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(icmpv6McastNaPkt),
+            DROPPED_IPV6_MULTICAST_NA
+        )
+
+        // Using scapy to generate IPv6 packet with hop-by-hop option:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", nh=0)
+        // pkt = eth/ip6
+        val ipv6WithHopByHopOptionPkt = """
+            01020304050600010203040586dd600000000000004020010000000000000200001a112233442001000
+            0000000000200001a33441122
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(ipv6WithHopByHopOptionPkt),
+            PASSED_MLD
+        )
+    }
+
+    @Test
+    fun testArpFilterDropPktsNoIPv4() {
+        val apfFilter = getApfFilter()
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+
+        // Drop ARP request packet with invalid hw type
+        // Using scapy to generate ARP request packet with invalid hw type :
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(hwtype=3)
+        // pkt = eth/arp
+        val invalidHwTypePkt = """
+            01020304050600010203040508060003080000040001c0a8012200000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(invalidHwTypePkt),
+            DROPPED_ARP_NON_IPV4
+        )
+
+        // Drop ARP request packet with invalid proto type
+        // Using scapy to generate ARP request packet with invalid proto type:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(ptype=20)
+        // pkt = eth/arp
+        val invalidProtoTypePkt = """
+            010203040506000102030405080600010014060000015c857e3c74e1000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(invalidProtoTypePkt),
+            DROPPED_ARP_NON_IPV4
+        )
+
+        // Drop ARP request packet with invalid hw len
+        // Using scapy to generate ARP request packet with invalid hw len:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(hwlen=20)
+        // pkt = eth/arp
+        val invalidHwLenPkt = """
+            01020304050600010203040508060001080014040001000000000000000000000000
+            0000000000000000c0a8012200000000000000000000000000000000000000000000
+            0000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(invalidHwLenPkt),
+            DROPPED_ARP_NON_IPV4
+        )
+
+        // Drop ARP request packet with invalid proto len
+        // Using scapy to generate ARP request packet with invalid proto len:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(plen=20)
+        // pkt = eth/arp
+        val invalidProtoLenPkt = """
+            010203040506000102030405080600010800061400015c857e3c74e1000000000000
+            00000000000000000000000000000000000000000000000000000000000000000000
+            000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(invalidProtoLenPkt),
+            DROPPED_ARP_NON_IPV4
+        )
+
+        // Drop ARP request packet with invalid opcode
+        // Using scapy to generate ARP request packet with invalid opcode:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(op=5)
+        // pkt = eth/arp
+        val invalidOpPkt = """
+            010203040506000102030405080600010800060400055c857e3c74e1c0a8012200000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(invalidOpPkt),
+            DROPPED_ARP_UNKNOWN
+        )
+
+        // Drop ARP reply packet with zero source protocol address
+        // Using scapy to generate ARP request packet with zero source protocol address:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(op=2, psrc="0.0.0.0)
+        // pkt = eth/arp
+        val noHostArpReplyPkt = """
+            010203040506000102030405080600010800060400025c857e3c74e10000000000000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(noHostArpReplyPkt),
+            DROPPED_ARP_REPLY_SPA_NO_HOST
+        )
+
+        // Drop ARP reply packet with ethernet broadcast destination
+        // Using scapy to generate ARP reply packet with ethernet broadcast destination:
+        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
+        // arp = ARP(op=2, pdst="0.0.0.0")
+        // pkt = eth/arp
+        val garpReplyPkt = """
+            ffffffffffff000102030405080600010800060400025c857e3c74e1c0a8012200000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(garpReplyPkt),
+            DROPPED_GARP_REPLY
+        )
+    }
+
+    @Test
+    fun testArpFilterPassPktsNoIPv4() {
+        val apfFilter = getApfFilter()
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        // Pass non-broadcast ARP reply packet
+        // Using scapy to generate unicast ARP reply packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP(op=2, psrc="1.2.3.4")
+        // pkt = eth/arp
+        val nonBcastArpReplyPkt = """
+            010203040506000102030405080600010800060400025c857e3c74e10102030400000000000000000000
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(nonBcastArpReplyPkt),
+            PASSED_ARP_UNICAST_REPLY
+        )
+
+        // Pass ARP request packet if device doesn't have any IPv4 address
+        // Using scapy to generate ARP request packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
+        // arp = ARP(op=1, pdst="1.2.3.4")
+        // pkt = eth/arp
+        val arpRequestPkt = """
+            ffffffffffff000102030405080600010800060400015c857e3c74e1c0a8012200000000000001020304
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(arpRequestPkt),
+            PASSED_ARP_REQUEST
+        )
+    }
+
+    @Test
+    fun testArpFilterDropPktsWithIPv4() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
+        val lp = LinkProperties()
+        lp.addLinkAddress(linkAddress)
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        // Drop ARP reply packet is not for the device
+        // Using scapy to generate ARP reply packet not for the device:
+        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
+        // arp = ARP(op=2, pdst="1.2.3.4")
+        // pkt = eth/arp
+        val otherHostArpReplyPkt = """
+            ffffffffffff000102030405080600010800060400025c857e3c74e1c0a8012200000000000001020304
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(otherHostArpReplyPkt),
+            DROPPED_ARP_OTHER_HOST
+        )
+
+        // Drop broadcast ARP request packet not for the device
+        // Using scapy to generate ARP broadcast request packet not for the device:
+        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
+        // arp = ARP(op=1, pdst="1.2.3.4")
+        // pkt = eth/arp
+        val otherHostArpRequestPkt = """
+            ffffffffffff000102030405080600010800060400015c857e3c74e1c0a8012200000000000001020304
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(otherHostArpRequestPkt),
+            DROPPED_ARP_OTHER_HOST
+        )
+    }
+
+    @Test
+    fun testArpFilterPassPktsWithIPv4() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
+        val lp = LinkProperties()
+        lp.addLinkAddress(linkAddress)
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // Using scapy to generate ARP broadcast reply packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
+        // arp = ARP(op=2, pdst="10.0.0.1")
+        // pkt = eth/arp
+        val bcastArpReplyPkt = """
+            ffffffffffff000102030405080600010800060400025c857e3c74e1c0a801220000000000000a000001
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            APF_VERSION_6,
+            program,
+            HexDump.hexStringToByteArray(bcastArpReplyPkt),
+            PASSED_ARP_BROADCAST_REPLY
+        )
+    }
+
+    // The APFv6 code path is only turned on in V+
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    @Test
+    fun testArpTransmit() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
+        val lp = LinkProperties()
+        lp.addLinkAddress(linkAddress)
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        val receivedArpPacketBuf = ArpPacket.buildArpPacket(
+            arpBroadcastMacAddress,
+            senderMacAddress,
+            hostIpv4Address,
+            HexDump.hexStringToByteArray("000000000000"),
+            senderIpv4Address,
+            ARP_REQUEST.toShort()
+        )
+        val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
+        receivedArpPacketBuf.get(receivedArpPacket)
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            receivedArpPacket,
+            DROPPED_ARP_REQUEST_REPLIED
+        )
+
+        val transmittedPacket = ApfJniUtils.getTransmittedPacket()
+        val expectedArpReplyBuf = ArpPacket.buildArpPacket(
+            senderMacAddress,
+            apfFilter.mHardwareAddress,
+            senderIpv4Address,
+            senderMacAddress,
+            hostIpv4Address,
+            ARP_REPLY.toShort()
+        )
+        val expectedArpReplyPacket = ByteArray(ARP_ETHER_IPV4_LEN)
+        expectedArpReplyBuf.get(expectedArpReplyPacket)
+        assertContentEquals(
+            expectedArpReplyPacket + ByteArray(18) { 0 },
+            transmittedPacket
+        )
+    }
+
+    @Test
+    fun testArpOffloadDisabled() {
+        val apfConfig = getDefaultConfig()
+        apfConfig.shouldHandleArpOffload = false
+        val apfFilter = getApfFilter(apfConfig)
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
+        val lp = LinkProperties()
+        lp.addLinkAddress(linkAddress)
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        val receivedArpPacketBuf = ArpPacket.buildArpPacket(
+            arpBroadcastMacAddress,
+            senderMacAddress,
+            hostIpv4Address,
+            HexDump.hexStringToByteArray("000000000000"),
+            senderIpv4Address,
+            ARP_REQUEST.toShort()
+        )
+        val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
+        receivedArpPacketBuf.get(receivedArpPacket)
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            receivedArpPacket,
+            PASSED_ARP_REQUEST
+        )
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    fun testNsFilterNoIPv6() {
+        doReturn(listOf<ByteArray>()).`when`(dependencies).getAnycast6Addresses(any())
+        val apfFilter = getApfFilter()
+        // validate NS packet check when there is no IPv6 address
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // pkt = eth/ip6/icmp6
+        val nsPkt = """
+            01020304050600010203040586DD6000000000183AFF200100000000000
+            00200001A1122334420010000000000000200001A334411228700452900
+            00000020010000000000000200001A33441122
+        """.replace("\\s+".toRegex(), "").trim()
+        // when there is no IPv6 addresses -> pass NS packet
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nsPkt),
+            PASSED_IPV6_NS_NO_ADDRESS
+        )
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    fun testNsFilter() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        val lp = LinkProperties()
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+
+        for (addr in hostIpv6TentativeAddresses) {
+            lp.addLinkAddress(
+                LinkAddress(
+                    InetAddress.getByAddress(addr),
+                    64,
+                    IFA_F_TENTATIVE,
+                    0
+                )
+            )
+        }
+
+        apfFilter.setLinkProperties(lp)
+        consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        apfFilter.updateClatInterfaceState(true)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // validate Ethernet dst address check
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="00:05:04:03:02:01")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val nonHostDstMacNsPkt = """
+            00050403020100010203040586DD6000000000203AFF2001000000000000
+            0200001A1122334420010000000000000200001A3344112287003D170000
+            000020010000000000000200001A334411220201000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // invalid unicast ether dst -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonHostDstMacNsPkt),
+            DROPPED_IPV6_NS_OTHER_HOST
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="33:33:ff:03:02:01")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val nonMcastDstMacNsPkt = """
+            3333FF03020100010203040586DD6000000000203AFF20010000000000
+            000200001A1122334420010000000000000200001A3344112287003D17
+            0000000020010000000000000200001A334411220201000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // mcast dst mac is not one of solicited mcast mac derived from one of device's ip -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonMcastDstMacNsPkt),
+            DROPPED_IPV6_NS_OTHER_HOST
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="33:33:ff:44:11:22")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val hostMcastDstMacNsPkt = """
+            3333FF44112200010203040586DD6000000000203AFF20010000000000
+            000200001A1122334420010000000000000200001A3344112287003E17
+            0000000020010000000000000200001A334411220101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // mcast dst mac is one of solicited mcast mac derived from one of device's ip
+        // -> drop and replied
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(hostMcastDstMacNsPkt),
+            DROPPED_IPV6_NS_REPLIED_NON_DAD
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val broadcastNsPkt = """
+            FFFFFFFFFFFF00010203040586DD6000000000203AFF200100000000000002000
+            01A1122334420010000000000000200001A3344112287003E1700000000200100
+            00000000000200001A334411220101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // mcast dst mac is broadcast address -> drop and replied
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(broadcastNsPkt),
+            DROPPED_IPV6_NS_REPLIED_NON_DAD
+        )
+
+        // validate IPv6 dst address check
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val validHostDstIpNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000000
+            00200001A1122334420010000000000000200001A3344112287003E1700
+            00000020010000000000000200001A334411220101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // dst ip is one of device's ip -> drop and replied
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(validHostDstIpNsPkt),
+            DROPPED_IPV6_NS_REPLIED_NON_DAD
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::100:1b:aabb:ccdd", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::100:1b:aabb:ccdd")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val validHostAnycastDstIpNsPkt = """
+            02030405060700010203040586DD6000000000203AFF20010000
+            000000000200001A1122334420010000000000000100001BAABB
+            CCDD8700D9AE0000000020010000000000000100001BAABBCCDD
+            0101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // dst ip is device's anycast address -> drop and replied
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(validHostAnycastDstIpNsPkt),
+            DROPPED_IPV6_NS_REPLIED_NON_DAD
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:4444:5555", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val nonHostUcastDstIpNsPkt = """
+            02030405060700010203040586DD6000000000203AFF2001000000000
+            0000200001A1122334420010000000000000200001A444455558700E8
+            E30000000020010000000000000200001A334411220101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // unicast dst ip is not one of device's ip -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonHostUcastDstIpNsPkt),
+            DROPPED_IPV6_NS_OTHER_HOST
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1133", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val nonHostMcastDstIpNsPkt = """
+            02030405060700010203040586DD6000000000203AFF2001000000000
+            0000200001A11223344FF0200000000000000000001FF441133870095
+            1C0000000020010000000000000200001A334411220101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        // mcast dst ip is not one of solicited mcast ip derived from one of device's ip -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonHostMcastDstIpNsPkt),
+            DROPPED_IPV6_NS_OTHER_HOST
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val hostMcastDstIpNsPkt =
+            "02030405060700010203040586DD6000000000203AFF2001000000000000" +
+                    "0200001A11223344FF0200000000000000000001FF4411228700952D0000" +
+                    "000020010000000000000200001A334411220101000102030405"
+        // mcast dst ip is one of solicited mcast ip derived from one of device's ip
+        //   -> drop and replied
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
+            DROPPED_IPV6_NS_REPLIED_NON_DAD
+        )
+
+        // validate IPv6 NS payload check
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255, plen=20)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val shortNsPkt = """
+            02030405060700010203040586DD6000000000143AFF20010000000000000200001A1
+            122334420010000000000000200001A3344112287003B140000000020010000000000
+            000200001A334411220101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // payload len < 24 -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(shortNsPkt),
+            DROPPED_IPV6_NS_INVALID
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:4444:5555")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val otherHostNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000000002000
+            01A1122334420010000000000000200001A334411228700E5E000000000200100
+            00000000000200001A444455550101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // target ip is not one of device's ip -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(otherHostNsPkt),
+            DROPPED_IPV6_NS_OTHER_HOST
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=20)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val invalidHoplimitNsPkt = """
+            02030405060700010203040586DD6000000000203A14200100000000000
+            00200001A1122334420010000000000000200001A3344112287003B1400
+            00000020010000000000000200001A334411220101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // hoplimit is not 255 -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(invalidHoplimitNsPkt),
+            DROPPED_IPV6_NS_INVALID
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122", code=5)
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val invalidIcmpCodeNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000000
+            00200001A1122334420010000000000000200001A3344112287053B0F00
+            00000020010000000000000200001A334411220101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // icmp6 code is not 0 -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(invalidIcmpCodeNsPkt),
+            DROPPED_IPV6_NS_INVALID
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:1234:5678")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val tentativeTargetIpNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000
+            00000200001A1122334420010000000000000200001A334411228700
+            16CE0000000020010000000000000200001A123456780101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // target ip is one of tentative address -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(tentativeTargetIpNsPkt),
+            PASSED_IPV6_NS_TENTATIVE
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1c:2255:6666")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val invalidTargetIpNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000000
+            00200001A1122334420010000000000000200001A334411228700F6BC00
+            00000020010000000000000200001C225566660101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // target ip is none of {non-tentative, anycast} -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(invalidTargetIpNsPkt),
+            DROPPED_IPV6_NS_OTHER_HOST
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="::", dst="ff02::1:ff44:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="02:03:04:05:06:07")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val dadNsPkt = """
+            02030405060700010203040586DD6000000000203AFF000000000000000000000000000
+            00000FF0200000000000000000001FF4411228700F4A800000000200100000000000002
+            00001A334411220201020304050607
+        """.replace("\\s+".toRegex(), "").trim()
+        // DAD NS request -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(dadNsPkt),
+            PASSED_IPV6_NS_DAD
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // pkt = eth/ip6/icmp6
+        val noOptionNsPkt = """
+            02030405060700010203040586DD6000000000183AFF2001000000000000020000
+            1A1122334420010000000000000200001A33441122870045290000000020010000
+            000000000200001A33441122
+        """.replace("\\s+".toRegex(), "").trim()
+        // payload len < 32 -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(noOptionNsPkt),
+            PASSED_IPV6_NS_NO_SLLA_OPTION
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="ff01::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val nonDadMcastSrcIpPkt = """
+            02030405060700010203040586DD6000000000203AFFFF01000000000000
+            0200001A1122334420010000000000000200001A3344112287005C130000
+            000020010000000000000200001A334411220101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // non-DAD src IPv6 is FF::/8 -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDadMcastSrcIpPkt),
+            DROPPED_IPV6_NS_INVALID
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="0001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val nonDadLoopbackSrcIpPkt = """
+            02030405060700010203040586DD6000000000203AFF0001000000000
+            0000200001A1122334420010000000000000200001A3344112287005B
+            140000000020010000000000000200001A334411220101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // non-DAD src IPv6 is 00::/8 -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(nonDadLoopbackSrcIpPkt),
+            DROPPED_IPV6_NS_INVALID
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt1 = ICMPv6NDOptDstLLAddr(lladdr="01:02:03:04:05:06")
+        // icmp6_opt2 = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt1/icmp6_opt2
+        val sllaNotFirstOptionNsPkt = """
+            02030405060700010203040586DD6000000000283AFF200100000000
+            00000200001A1122334420010000000000000200001A334411228700
+            2FFF0000000020010000000000000200001A33441122020101020304
+            05060101010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // non-DAD with multiple options, SLLA in 2nd option -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(sllaNotFirstOptionNsPkt),
+            PASSED_IPV6_NS_NO_SLLA_OPTION
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val noSllaOptionNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000000002
+            00001A1122334420010000000000000200001A3344112287003A1400000000
+            20010000000000000200001A334411220201010203040506
+        """.replace("\\s+".toRegex(), "").trim()
+        // non-DAD with one option but not SLLA -> pass
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(noSllaOptionNsPkt),
+            PASSED_IPV6_NS_NO_SLLA_OPTION
+        )
+
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val mcastMacSllaOptionNsPkt = """
+            02030405060700010203040586DD6000000000203AFF200100000000
+            00000200001A1122334420010000000000000200001A334411228700
+            3B140000000020010000000000000200001A33441122010101020304
+            0506
+        """.replace("\\s+".toRegex(), "").trim()
+        // non-DAD, SLLA is multicast MAC -> drop
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(mcastMacSllaOptionNsPkt),
+            DROPPED_IPV6_NS_INVALID
+        )
+    }
+
+    // The APFv6 code path is only turned on in V+
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    @Test
+    fun testNaTransmit() {
+        val apfFilter = getApfFilter()
+        val lp = LinkProperties()
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
+        val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
+        for (addr in validIpv6Addresses) {
+            // unicast solicited NS request
+            val receivedUcastNsPacket = generateNsPacket(
+                senderMacAddress,
+                apfFilter.mHardwareAddress,
+                senderIpv6Address,
+                addr,
+                addr
+            )
+
+            verifyProgramRun(
+                apfFilter.mApfVersionSupported,
+                program,
+                receivedUcastNsPacket,
+                DROPPED_IPV6_NS_REPLIED_NON_DAD
+            )
+
+            val transmittedUcastPacket = ApfJniUtils.getTransmittedPacket()
+            val expectedUcastNaPacket = generateNaPacket(
+                apfFilter.mHardwareAddress,
+                senderMacAddress,
+                addr,
+                senderIpv6Address,
+                0xe0000000.toInt(), //  R=1, S=1, O=1
+                addr
+            )
+
+            assertContentEquals(
+                expectedUcastNaPacket,
+                transmittedUcastPacket
+            )
+
+            val solicitedMcastAddr = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(
+                InetAddress.getByAddress(addr) as Inet6Address
+            )!!
+            val mcastDa = NetworkStackUtils.ipv6MulticastToEthernetMulticast(solicitedMcastAddr)
+                .toByteArray()
+
+            // multicast solicited NS request
+            var receivedMcastNsPacket = generateNsPacket(
+                senderMacAddress,
+                mcastDa,
+                senderIpv6Address,
+                solicitedMcastAddr.address,
+                addr
+            )
+
+            verifyProgramRun(
+                apfFilter.mApfVersionSupported,
+                program,
+                receivedMcastNsPacket,
+                DROPPED_IPV6_NS_REPLIED_NON_DAD
+            )
+
+            val transmittedMcastPacket = ApfJniUtils.getTransmittedPacket()
+            val expectedMcastNaPacket = generateNaPacket(
+                apfFilter.mHardwareAddress,
+                senderMacAddress,
+                addr,
+                senderIpv6Address,
+                0xe0000000.toInt(), // R=1, S=1, O=1
+                addr
+            )
+
+            assertContentEquals(
+                expectedMcastNaPacket,
+                transmittedMcastPacket
+            )
+        }
+    }
+
+    // The APFv6 code path is only turned on in V+
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    @Test
+    fun testNaTransmitWithTclass() {
+        // mock nd traffic class from /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass to 20
+        doReturn(20).`when`(dependencies).getNdTrafficClass(any())
+        val apfFilter = getApfFilter()
+        val lp = LinkProperties()
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
+        // Using scapy to generate IPv6 NS packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
+        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255, tc=20)
+        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
+        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val hostMcastDstIpNsPkt = """
+            02030405060700010203040586DD6140000000203AFF2001000000000000
+            0200001A11223344FF0200000000000000000001FF4411228700952D0000
+            000020010000000000000200001A334411220101000102030405
+        """.replace("\\s+".toRegex(), "").trim()
+        verifyProgramRun(
+            apfFilter.mApfVersionSupported,
+            program,
+            HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
+            DROPPED_IPV6_NS_REPLIED_NON_DAD
+        )
+
+        val transmitPkt = ApfJniUtils.getTransmittedPacket()
+        // Using scapy to generate IPv6 NA packet:
+        // eth = Ether(src="02:03:04:05:06:07", dst="00:01:02:03:04:05")
+        // ip6 = IPv6(src="2001::200:1a:3344:1122", dst="2001::200:1a:1122:3344", hlim=255, tc=20)
+        // icmp6 = ICMPv6ND_NA(tgt="2001::200:1a:3344:1122", R=1, S=1, O=1)
+        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="02:03:04:05:06:07")
+        // pkt = eth/ip6/icmp6/icmp6_opt
+        val expectedNaPacket = """
+            00010203040502030405060786DD6140000000203AFF2001000000000000020
+            0001A3344112220010000000000000200001A1122334488005610E000000020
+            010000000000000200001A334411220201020304050607
+        """.replace("\\s+".toRegex(), "").trim()
+        assertContentEquals(
+            HexDump.hexStringToByteArray(expectedNaPacket),
+            transmitPkt
+        )
+    }
+
+    @Test
+    fun testNdOffloadDisabled() {
+        val apfConfig = getDefaultConfig()
+        apfConfig.shouldHandleNdOffload = false
+        val apfFilter = getApfFilter(apfConfig)
+        val lp = LinkProperties()
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+
+        apfFilter.setLinkProperties(lp)
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
+        val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
+        for (addr in validIpv6Addresses) {
+            // unicast solicited NS request
+            val receivedUcastNsPacket = generateNsPacket(
+                senderMacAddress,
+                apfFilter.mHardwareAddress,
+                senderIpv6Address,
+                addr,
+                addr
+            )
+
+            verifyProgramRun(
+                apfFilter.mApfVersionSupported,
+                program,
+                receivedUcastNsPacket,
+                PASSED_IPV6_ICMP
+            )
+
+            val solicitedMcastAddr = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(
+                InetAddress.getByAddress(addr) as Inet6Address
+            )!!
+            val mcastDa = NetworkStackUtils.ipv6MulticastToEthernetMulticast(solicitedMcastAddr)
+                .toByteArray()
+
+            // multicast solicited NS request
+            var receivedMcastNsPacket = generateNsPacket(
+                senderMacAddress,
+                mcastDa,
+                senderIpv6Address,
+                solicitedMcastAddr.address,
+                addr
+            )
+
+            verifyProgramRun(
+                apfFilter.mApfVersionSupported,
+                program,
+                receivedMcastNsPacket,
+                PASSED_IPV6_ICMP
+            )
+        }
+    }
+
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    @Test
+    fun testRegisterOffloadEngine() {
+        val apfConfig = getDefaultConfig()
+        apfConfig.shouldHandleMdnsOffload = true
+        val apfFilter = getApfFilter(apfConfig)
+        val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
+        verify(nsdManager).registerOffloadEngine(
+                eq(ifParams.name),
+                anyLong(),
+                anyLong(),
+                any(),
+                captor.capture()
+        )
+        val offloadEngine = captor.value
+        val info1 = OffloadServiceInfo(
+                OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
+                listOf(),
+                "Android_test.local",
+                byteArrayOf(0x01, 0x02, 0x03, 0x04),
+                0,
+                OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
+        )
+        val info2 = OffloadServiceInfo(
+                OffloadServiceInfo.Key("TestServiceName2", "_advertisertest._tcp"),
+                listOf(),
+                "Android_test.local",
+                byteArrayOf(0x01, 0x02, 0x03, 0x04),
+                0,
+                OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
+        )
+        val updatedInfo1 = OffloadServiceInfo(
+                OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
+                listOf(),
+                "Android_test.local",
+                byteArrayOf(),
+                0,
+                OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
+        )
+        handler.post { offloadEngine.onOffloadServiceUpdated(info1) }
+        handlerThread.waitForIdle(TIMEOUT_MS)
+        assertContentEquals(listOf(info1), apfFilter.mOffloadServiceInfos)
+        handler.post { offloadEngine.onOffloadServiceUpdated(info2) }
+        handlerThread.waitForIdle(TIMEOUT_MS)
+        assertContentEquals(listOf(info1, info2), apfFilter.mOffloadServiceInfos)
+        handler.post { offloadEngine.onOffloadServiceUpdated(updatedInfo1) }
+        handlerThread.waitForIdle(TIMEOUT_MS)
+        assertContentEquals(listOf(info2, updatedInfo1), apfFilter.mOffloadServiceInfos)
+        handler.post { offloadEngine.onOffloadServiceRemoved(updatedInfo1) }
+        handlerThread.waitForIdle(TIMEOUT_MS)
+        assertContentEquals(listOf(info2), apfFilter.mOffloadServiceInfos)
+
+        handler.post { apfFilter.shutdown() }
+        handlerThread.waitForIdle(TIMEOUT_MS)
+        verify(nsdManager).unregisterOffloadEngine(any())
+    }
+
+    @Test
+    fun testApfProgramUpdate() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        // add IPv4 address, expect to have apf program update
+        val lp = LinkProperties()
+        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
+        lp.addLinkAddress(linkAddress)
+        apfFilter.setLinkProperties(lp)
+        consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // add the same IPv4 address, expect to have no apf program update
+        apfFilter.setLinkProperties(lp)
+        verify(ipClientCallback, never()).installPacketFilter(any())
+
+        // add IPv6 addresses, expect to have apf program update
+        for (addr in hostIpv6Addresses) {
+            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
+        }
+
+        apfFilter.setLinkProperties(lp)
+        consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // add the same IPv6 addresses, expect to have no apf program update
+        apfFilter.setLinkProperties(lp)
+        verify(ipClientCallback, never()).installPacketFilter(any())
+
+        // add more tentative IPv6 addresses, expect to have apf program update
+        for (addr in hostIpv6TentativeAddresses) {
+            lp.addLinkAddress(
+                LinkAddress(
+                    InetAddress.getByAddress(addr),
+                    64,
+                    IFA_F_TENTATIVE,
+                    0
+                )
+            )
+        }
+
+        apfFilter.setLinkProperties(lp)
+        consumeInstalledProgram(ipClientCallback, installCnt = 1)
+
+        // add the same IPv6 addresses, expect to have no apf program update
+        apfFilter.setLinkProperties(lp)
+        verify(ipClientCallback, never()).installPacketFilter(any())
+    }
+
+    @Test
+    fun testApfFilterInitializationCleanUpTheApfMemoryRegion() {
+        val apfFilter = getApfFilter()
+        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
+        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
+        val program = programCaptor.allValues.first()
+        assertContentEquals(ByteArray(4096) { 0 }, program)
+    }
+
+    @Test
+    fun testApfFilterResumeWillCleanUpTheApfMemoryRegion() {
+        val apfFilter = getApfFilter()
+        consumeInstalledProgram(ipClientCallback, installCnt = 2)
+        apfFilter.resume()
+        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
+        assertContentEquals(ByteArray(4096) { 0 }, program)
+    }
+}
diff --git a/tests/unit/src/android/net/apf/ApfNewTest.kt b/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
similarity index 62%
rename from tests/unit/src/android/net/apf/ApfNewTest.kt
rename to tests/unit/src/android/net/apf/ApfGeneratorTest.kt
index 6863fb9b..98b2a428 100644
--- a/tests/unit/src/android/net/apf/ApfNewTest.kt
+++ b/tests/unit/src/android/net/apf/ApfGeneratorTest.kt
@@ -15,37 +15,22 @@
  */
 package android.net.apf
 
-import android.content.Context
-import android.net.LinkAddress
-import android.net.LinkProperties
-import android.net.MacAddress
 import android.net.apf.ApfCounterTracker.Counter
-import android.net.apf.ApfCounterTracker.Counter.APF_PROGRAM_ID
-import android.net.apf.ApfCounterTracker.Counter.APF_VERSION
 import android.net.apf.ApfCounterTracker.Counter.CORRUPT_DNS_PACKET
-import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED
 import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED
 import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETH_BROADCAST
-import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4
-import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID
-import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST
 import android.net.apf.ApfCounterTracker.Counter.PASSED_ALLOCATE_FAILURE
 import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP
-import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST
-import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4
-import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER
-import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP
-import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_MULTIPLE_OPTIONS
-import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS
 import android.net.apf.ApfCounterTracker.Counter.PASSED_TRANSMIT_FAILURE
 import android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS
-import android.net.apf.ApfFilter.Dependencies
-import android.net.apf.ApfTestUtils.DROP
-import android.net.apf.ApfTestUtils.MIN_PKT_SIZE
-import android.net.apf.ApfTestUtils.PASS
-import android.net.apf.ApfTestUtils.assertDrop
-import android.net.apf.ApfTestUtils.assertPass
-import android.net.apf.ApfTestUtils.assertVerdict
+import android.net.apf.ApfTestHelpers.Companion.DROP
+import android.net.apf.ApfTestHelpers.Companion.MIN_PKT_SIZE
+import android.net.apf.ApfTestHelpers.Companion.PASS
+import android.net.apf.ApfTestHelpers.Companion.assertDrop
+import android.net.apf.ApfTestHelpers.Companion.assertPass
+import android.net.apf.ApfTestHelpers.Companion.assertVerdict
+import android.net.apf.ApfTestHelpers.Companion.decodeCountersIntoMap
+import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
 import android.net.apf.BaseApfGenerator.APF_VERSION_2
 import android.net.apf.BaseApfGenerator.APF_VERSION_3
 import android.net.apf.BaseApfGenerator.APF_VERSION_6
@@ -55,142 +40,53 @@ import android.net.apf.BaseApfGenerator.MemorySlot
 import android.net.apf.BaseApfGenerator.PASS_LABEL
 import android.net.apf.BaseApfGenerator.Register.R0
 import android.net.apf.BaseApfGenerator.Register.R1
-import android.net.ip.IpClient.IpClientCallbacksWrapper
-import android.os.Build
-import android.system.OsConstants.ARPHRD_ETHER
-import android.system.OsConstants.IFA_F_TENTATIVE
 import androidx.test.filters.SmallTest
 import com.android.net.module.util.HexDump
-import com.android.net.module.util.InterfaceParams
-import com.android.net.module.util.NetworkStackConstants.ARP_ETHER_IPV4_LEN
-import com.android.net.module.util.NetworkStackConstants.ARP_REPLY
-import com.android.net.module.util.NetworkStackConstants.ARP_REQUEST
 import com.android.net.module.util.Struct
-import com.android.net.module.util.arp.ArpPacket
 import com.android.net.module.util.structs.EthernetHeader
 import com.android.net.module.util.structs.Ipv4Header
 import com.android.net.module.util.structs.UdpHeader
-import com.android.networkstack.metrics.NetworkQuirkMetrics
 import com.android.testutils.DevSdkIgnoreRule
-import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
 import com.android.testutils.DevSdkIgnoreRunner
-import java.net.InetAddress
 import java.nio.ByteBuffer
 import kotlin.test.assertContentEquals
 import kotlin.test.assertEquals
 import kotlin.test.assertFailsWith
-import org.junit.After
-import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
-import org.mockito.ArgumentCaptor
-import org.mockito.ArgumentMatchers.any
-import org.mockito.Mock
-import org.mockito.Mockito
 import org.mockito.Mockito.times
-import org.mockito.Mockito.verify
-import org.mockito.Mockito.`when`
-import org.mockito.MockitoAnnotations
 
 const val ETH_HLEN = 14
 const val IPV4_HLEN = 20
 const val IPPROTO_UDP = 17
 
 /**
- * Tests for APF instructions.
+ * Tests for APF generator instructions.
  */
 @RunWith(DevSdkIgnoreRunner::class)
 @SmallTest
-class ApfNewTest {
+class ApfGeneratorTest {
 
     @get:Rule val ignoreRule = DevSdkIgnoreRule()
 
-    @Mock private lateinit var context: Context
-
-    @Mock private lateinit var metrics: NetworkQuirkMetrics
-
-    @Mock private lateinit var dependencies: Dependencies
-
-    @Mock private lateinit var ipClientCallback: IpClientCallbacksWrapper
-
-    private val defaultMaximumApfProgramSize = 2048
-
-    private val loInterfaceParams = InterfaceParams.getByName("lo")
-
-    private val ifParams =
-        InterfaceParams(
-            "lo",
-            loInterfaceParams.index,
-            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
-            loInterfaceParams.defaultMtu
-        )
+    private val ramSize = 2048
+    private val clampSize = 2048
 
     private val testPacket = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
-    private val hostIpv4Address = byteArrayOf(10, 0, 0, 1)
-    private val senderIpv4Address = byteArrayOf(10, 0, 0, 2)
-    private val arpBroadcastMacAddress = intArrayOf(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
-            .map { it.toByte() }.toByteArray()
-    private val senderMacAddress = intArrayOf(0x01, 0x22, 0x33, 0x44, 0x55, 0x66)
-        .map { it.toByte() }.toByteArray()
-    private val hostIpv6Addresses = listOf(
-        // 2001::200:1a:3344:1122
-        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x33, 0x44, 0x11, 0x22)
-            .map{ it.toByte() }.toByteArray(),
-        // 2001::100:1b:4455:6677
-        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0x44, 0x55, 0x66, 0x77)
-            .map{ it.toByte() }.toByteArray()
-    )
-    private val hostIpv6TentativeAddresses = listOf(
-        // 2001::200:1a:1234:5678
-        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x12, 0x34, 0x56, 0x78)
-            .map{ it.toByte() }.toByteArray(),
-        // 2001::100:1b:1234:5678
-        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0x12, 0x34, 0x56, 0x78)
-            .map{ it.toByte() }.toByteArray()
-    )
-    private val hostAnycast6Addresses = listOf(
-        // 2001::100:1b:aabb:ccdd
-        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0xaa, 0xbb, 0xcc, 0xdd)
-            .map{ it.toByte() }.toByteArray()
-    )
-    private val hostMulticastMacAddresses = listOf(
-            // 33:33:00:00:00:01
-            intArrayOf(0x33, 0x33, 0, 0, 0, 1).map { it.toByte() }.toByteArray(),
-            // 33:33:ff:44:11:22
-            intArrayOf(0x33, 0x33, 0xff, 0x44, 0x11, 0x22).map { it.toByte() }.toByteArray(),
-            // 33:33:ff:55:66:77
-            intArrayOf(0x33, 0x33, 0xff, 0x55, 0x66, 0x77).map { it.toByte() }.toByteArray(),
-            // 33:33:ff:bb:cc:dd
-            intArrayOf(0x33, 0x33, 0xff, 0xbb, 0xcc, 0xdd).map { it.toByte() }.toByteArray(),
-    )
-    @Before
-    fun setUp() {
-        MockitoAnnotations.initMocks(this)
-        // mock anycast6 address from /proc/net/anycast6
-        `when`(dependencies.getAnycast6Addresses(any())).thenReturn(hostAnycast6Addresses)
-        // mock host mac address and ethernet multicast addresses from /proc/net/dev_mcast
-        `when`(dependencies.getEtherMulticastAddresses(any())).thenReturn(hostMulticastMacAddresses)
-    }
-
-    @After
-    fun tearDown() {
-        Mockito.framework().clearInlineMocks()
-        ApfJniUtils.resetTransmittedPacketMemory()
-    }
 
     @Test
     fun testDataInstructionMustComeFirst() {
-        var gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addAllocateR0()
         assertFailsWith<IllegalInstructionException> { gen.addData(ByteArray(3) { 0x01 }) }
     }
 
     @Test
     fun testApfInstructionEncodingSizeCheck() {
-        var gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         assertFailsWith<IllegalArgumentException> {
-            ApfV6Generator(ByteArray(65536) { 0x01 }, defaultMaximumApfProgramSize)
+            ApfV6Generator(ByteArray(65536) { 0x01 }, APF_VERSION_6, ramSize, clampSize)
         }
         assertFailsWith<IllegalArgumentException> { gen.addAllocate(65536) }
         assertFailsWith<IllegalArgumentException> { gen.addAllocate(-1) }
@@ -439,7 +335,7 @@ class ApfNewTest {
             )
         }
 
-        val v4gen = ApfV4Generator(APF_VERSION_3)
+        val v4gen = ApfV4Generator(APF_VERSION_3, ramSize, clampSize)
         assertFailsWith<IllegalArgumentException> { v4gen.addCountAndDrop(PASSED_ARP) }
         assertFailsWith<IllegalArgumentException> { v4gen.addCountAndPass(DROPPED_ETH_BROADCAST) }
         assertFailsWith<IllegalArgumentException> {
@@ -517,7 +413,7 @@ class ApfNewTest {
     fun testValidateDnsNames() {
         // '%' is a valid label character in mDNS subtype
         // byte == 0xff means it is a '*' wildcard, which is a valid encoding.
-        val program = ApfV6Generator(defaultMaximumApfProgramSize).addJumpIfPktAtR0ContainDnsQ(
+        val program = ApfV6Generator(ramSize, ramSize, clampSize).addJumpIfPktAtR0ContainDnsQ(
                 byteArrayOf(1, '%'.code.toByte(), 0, 0),
                 1,
                 DROP_LABEL
@@ -529,7 +425,7 @@ class ApfNewTest {
 
     @Test
     fun testApfInstructionsEncoding() {
-        val v4gen = ApfV4Generator(APF_VERSION_2)
+        val v4gen = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
         v4gen.addPass()
         var program = v4gen.generate()
         // encoding PASS opcode: opcode=0, imm_len=0, R=0
@@ -542,7 +438,7 @@ class ApfNewTest {
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        var gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addDrop()
         program = gen.generate().skipDataAndDebug()
         // encoding DROP opcode: opcode=0, imm_len=0, R=1
@@ -555,7 +451,7 @@ class ApfNewTest {
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addCountAndPass(129)
         program = gen.generate().skipDataAndDebug()
         // encoding COUNT(PASS) opcode: opcode=0, imm_len=size_of(imm), R=0, imm=counterNumber
@@ -571,7 +467,7 @@ class ApfNewTest {
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addCountAndDrop(1000)
         program = gen.generate().skipDataAndDebug()
         // encoding COUNT(DROP) opcode: opcode=0, imm_len=size_of(imm), R=1, imm=counterNumber
@@ -588,7 +484,7 @@ class ApfNewTest {
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addCountAndPass(PASSED_ARP)
         program = gen.generate().skipDataAndDebug()
         // encoding COUNT(PASS) opcode: opcode=0, imm_len=size_of(imm), R=0, imm=counterNumber
@@ -604,7 +500,7 @@ class ApfNewTest {
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addCountAndDrop(DROPPED_ETHERTYPE_NOT_ALLOWED)
         program = gen.generate().skipDataAndDebug()
         // encoding COUNT(DROP) opcode: opcode=0, imm_len=size_of(imm), R=1, imm=counterNumber
@@ -616,11 +512,11 @@ class ApfNewTest {
                 program
         )
         assertContentEquals(
-                listOf("0: drop        counter=43"),
+                listOf("0: drop        counter=47"),
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addAllocateR0()
         gen.addAllocate(1500)
         program = gen.generate().skipDataAndDebug()
@@ -642,7 +538,7 @@ class ApfNewTest {
                 "2: allocate    1500"
         ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addTransmitWithoutChecksum()
         gen.addTransmitL4(30, 40, 50, 256, true)
         program = gen.generate().skipDataAndDebug()
@@ -659,25 +555,25 @@ class ApfNewTest {
         ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
         val largeByteArray = ByteArray(256) { 0x01 }
-        gen = ApfV6Generator(largeByteArray, defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(largeByteArray, APF_VERSION_6, ramSize, clampSize)
         program = gen.generate()
         assertContentEquals(
                 byteArrayOf(
                         encodeInstruction(opcode = 14, immLength = 2, register = 1), 1, 0
                 ) + largeByteArray + byteArrayOf(
-                        encodeInstruction(opcode = 21, immLength = 1, register = 0), 48, 6, 25
+                        encodeInstruction(opcode = 21, immLength = 1, register = 0), 48, 6, 9
                 ),
                 program
         )
         assertContentEquals(
                 listOf(
                         "0: data        256, " + "01".repeat(256),
-                        "259: debugbuf    size=1561"
+                        "259: debugbuf    size=1545"
                 ),
                 ApfJniUtils.disassembleApf(program).map { it.trim() }
         )
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addWriteU8(0x01)
         gen.addWriteU16(0x0102)
         gen.addWriteU32(0x01020304)
@@ -718,7 +614,7 @@ class ApfNewTest {
                 "35: write       0xfffefdfc"
         ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addWriteU8(R0)
         gen.addWriteU16(R0)
         gen.addWriteU32(R0)
@@ -743,7 +639,7 @@ class ApfNewTest {
                 "10: ewrite4     r1"
         ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addDataCopy(0, 10)
         gen.addDataCopy(1, 5)
         gen.addPacketCopy(1000, 255)
@@ -760,7 +656,7 @@ class ApfNewTest {
                 "5: pktcopy     src=1000, len=255"
         ), ApfJniUtils.disassembleApf(program).map { it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addDataCopyFromR0(5)
         gen.addPacketCopyFromR0(5)
         gen.addDataCopyFromR0LenR1()
@@ -779,7 +675,7 @@ class ApfNewTest {
                 "8: epktcopy     src=r0, len=r1"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfBytesAtR0Equal(byteArrayOf('a'.code.toByte()), ApfV4Generator.DROP_LABEL)
         program = gen.generate().skipDataAndDebug()
         assertContentEquals(byteArrayOf(
@@ -793,7 +689,7 @@ class ApfNewTest {
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
         val qnames = byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0, 0)
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsQ(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
         gen.addJumpIfPktAtR0ContainDnsQ(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
         program = gen.generate().skipDataAndDebug()
@@ -807,7 +703,7 @@ class ApfNewTest {
                 "10: jdnsqeq     r0, DROP, 12, (1)A(1)B(0)(0)"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsQSafe(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
         gen.addJumpIfPktAtR0ContainDnsQSafe(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
         program = gen.generate().skipDataAndDebug()
@@ -821,7 +717,7 @@ class ApfNewTest {
                 "10: jdnsqeqsafe r0, DROP, 12, (1)A(1)B(0)(0)"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
         gen.addJumpIfPktAtR0ContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
         program = gen.generate().skipDataAndDebug()
@@ -835,7 +731,7 @@ class ApfNewTest {
                 "9: jdnsaeq     r0, DROP, (1)A(1)B(0)(0)"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfPktAtR0DoesNotContainDnsASafe(qnames, ApfV4Generator.DROP_LABEL)
         gen.addJumpIfPktAtR0ContainDnsASafe(qnames, ApfV4Generator.DROP_LABEL)
         program = gen.generate().skipDataAndDebug()
@@ -849,7 +745,7 @@ class ApfNewTest {
                 "9: jdnsaeqsafe r0, DROP, (1)A(1)B(0)(0)"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfOneOf(R1, List(32) { (it + 1).toLong() }.toSet(), DROP_LABEL)
         gen.addJumpIfOneOf(R0, setOf(0, 257, 65536), DROP_LABEL)
         gen.addJumpIfNoneOf(R0, setOf(1, 2, 3), DROP_LABEL)
@@ -863,7 +759,7 @@ class ApfNewTest {
                 encodeInstruction(21, 1, 0), 47, 1, 9, 1, 2, 3
         ), program)
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfOneOf(R0, setOf(0, 128, 256, 65536), DROP_LABEL)
         gen.addJumpIfNoneOf(R1, setOf(0, 128, 256, 65536), DROP_LABEL)
         program = gen.generate().skipDataAndDebug()
@@ -872,7 +768,7 @@ class ApfNewTest {
                 "20: jnoneof     r1, DROP, { 0, 128, 256, 65536 }"
         ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
 
-        gen = ApfV6Generator(defaultMaximumApfProgramSize)
+        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
         gen.addJumpIfBytesAtR0EqualsAnyOf(listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)), DROP_LABEL)
         gen.addJumpIfBytesAtR0EqualNoneOf(listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)), DROP_LABEL)
         gen.addJumpIfBytesAtR0EqualNoneOf(listOf(byteArrayOf(1, 1), byteArrayOf(1, 1)), DROP_LABEL)
@@ -894,7 +790,7 @@ class ApfNewTest {
 
     @Test
     fun testWriteToTxBuffer() {
-        var program = ApfV6Generator(defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addAllocate(14)
                 .addWriteU8(0x01)
                 .addWriteU16(0x0203)
@@ -921,7 +817,7 @@ class ApfNewTest {
 
     @Test
     fun testCopyToTxBuffer() {
-        var program = ApfV6Generator(byteArrayOf(33, 34, 35), defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(byteArrayOf(33, 34, 35), APF_VERSION_6, ramSize, clampSize)
                 .addAllocate(14)
                 .addDataCopy(3, 2) // arg1=src, arg2=len
                 .addDataCopy(5, 1) // arg1=src, arg2=len
@@ -948,7 +844,7 @@ class ApfNewTest {
 
     @Test
     fun testCopyContentToTxBuffer() {
-        val program = ApfV6Generator(defaultMaximumApfProgramSize)
+        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addAllocate(18)
                 .addDataCopy(HexDump.hexStringToByteArray("112233445566"))
                 .addDataCopy(HexDump.hexStringToByteArray("223344"))
@@ -958,7 +854,7 @@ class ApfNewTest {
                 .generate()
         assertContentEquals(listOf(
                 "0: data        9, 112233445566778899",
-                "12: debugbuf    size=1788",
+                "12: debugbuf    size=1772",
                 "16: allocate    18",
                 "20: datacopy    src=3, len=6",
                 "23: datacopy    src=4, len=3",
@@ -973,18 +869,18 @@ class ApfNewTest {
 
     @Test
     fun testPassDrop() {
-        var program = ApfV6Generator(defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addDrop()
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                 .generate()
         verifyProgramRun(APF_VERSION_6, program, testPacket, DROPPED_ETH_BROADCAST)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addCountAndPass(Counter.PASSED_ARP)
                 .generate()
         verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP)
@@ -994,11 +890,11 @@ class ApfNewTest {
     fun testLoadStoreCounter() {
         doTestLoadStoreCounter (
                 { mutableMapOf() },
-                { ApfV4Generator(APF_VERSION_3) }
+                { ApfV4Generator(APF_VERSION_3, ramSize, clampSize) }
         )
         doTestLoadStoreCounter (
                 { mutableMapOf(TOTAL_PACKETS to 1) },
-                { ApfV6Generator(defaultMaximumApfProgramSize) }
+                { ApfV6Generator(APF_VERSION_6, ramSize, clampSize) }
         )
     }
 
@@ -1021,7 +917,7 @@ class ApfNewTest {
     @Test
     fun testV4CountAndPassDropCompareR0() {
         doTestCountAndPassDropCompareR0(
-                getGenerator = { ApfV4Generator(APF_VERSION_3) },
+                getGenerator = { ApfV4Generator(APF_VERSION_3, ramSize, clampSize) },
                 incTotal = false
         )
     }
@@ -1029,7 +925,7 @@ class ApfNewTest {
     @Test
     fun testV6CountAndPassDropCompareR0() {
         doTestCountAndPassDropCompareR0(
-                getGenerator = { ApfV6Generator(defaultMaximumApfProgramSize) },
+                getGenerator = { ApfV6Generator(APF_VERSION_6, ramSize, clampSize) },
                 incTotal = true
         )
     }
@@ -1341,72 +1237,9 @@ class ApfNewTest {
         verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)
     }
 
-    private fun doTestEtherTypeAllowListFilter(apfVersion: Int) {
-        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
-        val apfFilter =
-            ApfFilter(
-                context,
-                getDefaultConfig(apfVersion),
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-            )
-        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
-        val program = programCaptor.allValues.last()
-
-        // Using scapy to generate IPv4 mDNS packet:
-        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
-        //   ip = IP(src="192.168.1.1")
-        //   udp = UDP(sport=5353, dport=5353)
-        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
-        //   p = eth/ip/udp/dns
-        val mdnsPkt = "01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f" +
-                      "b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001"
-        verifyProgramRun(APF_VERSION_6, program, HexDump.hexStringToByteArray(mdnsPkt), PASSED_IPV4)
-
-        // Using scapy to generate RA packet:
-        //  eth = Ether(src="E8:9F:80:66:60:BB", dst="33:33:00:00:00:01")
-        //  ip6 = IPv6(src="fe80::1", dst="ff02::1")
-        //  icmp6 = ICMPv6ND_RA(routerlifetime=3600, retranstimer=3600)
-        //  p = eth/ip6/icmp6
-        val raPkt = "333300000001e89f806660bb86dd6000000000103afffe800000000000000000000000" +
-                    "000001ff0200000000000000000000000000018600600700080e100000000000000e10"
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(raPkt),
-                PASSED_IPV6_ICMP
-        )
-
-        // Using scapy to generate ethernet packet with type 0x88A2:
-        //  p = Ether(type=0x88A2)/Raw(load="01")
-        val ethPkt = "ffffffffffff047bcb463fb588a23031"
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(ethPkt),
-                DROPPED_ETHERTYPE_NOT_ALLOWED
-        )
-
-        apfFilter.shutdown()
-    }
-
-    @Test
-    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
-    fun testV4EtherTypeAllowListFilter() {
-        doTestEtherTypeAllowListFilter(APF_VERSION_3)
-    }
-
-    @Test
-    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
-    fun testV6EtherTypeAllowListFilter() {
-        doTestEtherTypeAllowListFilter(APF_VERSION_6)
-    }
-
     @Test
     fun testV4CountAndPassDrop() {
-        var program = ApfV4Generator(APF_VERSION_3)
+        var program = ApfV4Generator(APF_VERSION_3, ramSize, clampSize)
                 .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                 .addCountTrampoline()
                 .generate()
@@ -1418,7 +1251,7 @@ class ApfNewTest {
                 incTotal = false
         )
 
-        program = ApfV4Generator(APF_VERSION_3)
+        program = ApfV4Generator(APF_VERSION_3, ramSize, clampSize)
                 .addCountAndPass(Counter.PASSED_ARP)
                 .addCountTrampoline()
                 .generate()
@@ -1427,7 +1260,7 @@ class ApfNewTest {
 
     @Test
     fun testV2CountAndPassDrop() {
-        var program = ApfV4Generator(APF_VERSION_2)
+        var program = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
                 .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                 .addCountTrampoline()
                 .generate()
@@ -1435,7 +1268,7 @@ class ApfNewTest {
         assertVerdict(APF_VERSION_6, DROP, program, testPacket, dataRegion)
         assertContentEquals(ByteArray(Counter.totalSize()) { 0 }, dataRegion)
 
-        program = ApfV4Generator(APF_VERSION_2)
+        program = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
                 .addCountAndPass(PASSED_ARP)
                 .addCountTrampoline()
                 .generate()
@@ -1446,7 +1279,7 @@ class ApfNewTest {
 
     @Test
     fun testAllocateFailure() {
-        val program = ApfV6Generator(defaultMaximumApfProgramSize)
+        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 // allocate size: 65535 > sizeof(apf_test_buffer): 1514, trigger allocate failure.
                 .addAllocate(65535)
                 .addDrop()
@@ -1456,7 +1289,7 @@ class ApfNewTest {
 
     @Test
     fun testTransmitFailure() {
-        val program = ApfV6Generator(defaultMaximumApfProgramSize)
+        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addAllocate(14)
                 // len: 13 is less than ETH_HLEN, trigger transmit failure.
                 .addLoadImmediate(R0, 13)
@@ -1492,7 +1325,7 @@ class ApfNewTest {
                 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x01,
                 0x09,
         ).map { it.toByte() }.toByteArray()
-        val program = ApfV6Generator(etherIpv4UdpPacket, defaultMaximumApfProgramSize)
+        val program = ApfV6Generator(etherIpv4UdpPacket, APF_VERSION_6, ramSize, clampSize)
                 .addAllocate(etherIpv4UdpPacket.size)
                 .addDataCopy(3, etherIpv4UdpPacket.size) // arg1=src, arg2=len
                 .addTransmitL4(
@@ -1538,28 +1371,28 @@ class ApfNewTest {
                 0x00, 0x01, 0x00, 0x01 // type = A, class = 0x0001
         ).map { it.toByte() }.toByteArray()
 
-        var program = ApfV6Generator(defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, udpPayload)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL)
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, udpPayload)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
         assertPass(APF_VERSION_6, program, udpPayload)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
@@ -1581,14 +1414,14 @@ class ApfNewTest {
                 0x00, 0x01, 0x00, 0x01 // type = A, class = 0x0001
         ).map { it.toByte() }.toByteArray()
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
                 .generate()
         verifyProgramRun(APF_VERSION_6, program, badUdpPayload, CORRUPT_DNS_PACKET, result = DROP)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                 .addPass()
@@ -1627,28 +1460,28 @@ class ApfNewTest {
                 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09 // rdlengh = 4, rdata = 192.168.1.9
         ).map { it.toByte() }.toByteArray()
 
-        var program = ApfV6Generator(defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsA(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, udpPayload)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsASafe(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, udpPayload)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsA(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
         assertPass(APF_VERSION_6, program, udpPayload)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0DoesNotContainDnsASafe(needlesMatch, DROP_LABEL)
                 .addPass()
@@ -1674,14 +1507,14 @@ class ApfNewTest {
                 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09 // rdlengh = 4, rdata = 192.168.1.9
         ).map { it.toByte() }.toByteArray()
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsA(needlesMatch, DROP_LABEL)
                 .addPass()
                 .generate()
         verifyProgramRun(APF_VERSION_6, program, badUdpPayload, CORRUPT_DNS_PACKET, result = DROP)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfPktAtR0ContainDnsASafe(needlesMatch, DROP_LABEL)
                 .addPass()
@@ -1698,7 +1531,7 @@ class ApfNewTest {
 
     @Test
     fun testJumpMultipleByteSequencesMatch() {
-        var program = ApfV6Generator(defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfBytesAtR0EqualsAnyOf(
                         listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
@@ -1708,7 +1541,7 @@ class ApfNewTest {
                 .generate()
         assertDrop(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 2)
                 .addJumpIfBytesAtR0EqualsAnyOf(
                         listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
@@ -1718,7 +1551,7 @@ class ApfNewTest {
                 .generate()
         assertPass(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 1)
                 .addJumpIfBytesAtR0EqualNoneOf(
                         listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
@@ -1728,7 +1561,7 @@ class ApfNewTest {
                 .generate()
         assertDrop(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 0)
                 .addJumpIfBytesAtR0EqualNoneOf(
                         listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
@@ -1741,28 +1574,28 @@ class ApfNewTest {
 
     @Test
     fun testJumpOneOf() {
-        var program = ApfV6Generator(defaultMaximumApfProgramSize)
+        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 255)
                 .addJumpIfOneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 254)
                 .addJumpIfOneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
         assertPass(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 254)
                 .addJumpIfNoneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
                 .generate()
         assertDrop(APF_VERSION_6, program, testPacket)
 
-        program = ApfV6Generator(defaultMaximumApfProgramSize)
+        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoadImmediate(R0, 255)
                 .addJumpIfNoneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                 .addPass()
@@ -1772,575 +1605,16 @@ class ApfNewTest {
 
     @Test
     fun testDebugBuffer() {
-        val program = ApfV6Generator(defaultMaximumApfProgramSize)
+        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                 .addLoad8(R0, 255)
                 .generate()
-        val dataRegion = ByteArray(defaultMaximumApfProgramSize - program.size) { 0 }
+        val dataRegion = ByteArray(ramSize - program.size) { 0 }
 
         assertVerdict(APF_VERSION_6, PASS, program, testPacket, dataRegion)
         // offset 3 in the data region should contain if the interpreter is APFv6 mode or not
         assertEquals(1, dataRegion[3])
     }
 
-    @Test
-    fun testIPv4PacketFilterOnV6OnlyNetwork() {
-        val apfFilter =
-            ApfFilter(
-                context,
-                getDefaultConfig(),
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-        )
-        apfFilter.updateClatInterfaceState(true)
-        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
-        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
-        val program = programCaptor.allValues.last()
-
-        // Using scapy to generate IPv4 mDNS packet:
-        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
-        //   ip = IP(src="192.168.1.1")
-        //   udp = UDP(sport=5353, dport=5353)
-        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
-        //   p = eth/ip/udp/dns
-        val mdnsPkt = "01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f" +
-                      "b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001"
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(mdnsPkt),
-                DROPPED_IPV4_NON_DHCP4
-        )
-
-        // Using scapy to generate DHCP4 offer packet:
-        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
-        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
-        //   udp = UDP(sport=67, dport=68)
-        //   bootp = BOOTP(op=2,
-        //                 yiaddr='192.168.1.100',
-        //                 siaddr='192.168.1.1',
-        //                 chaddr=b'\x00\x11\x22\x33\x44\x55')
-        //   dhcp_options = [('message-type', 'offer'),
-        //                   ('server_id', '192.168.1.1'),
-        //                   ('subnet_mask', '255.255.255.0'),
-        //                   ('router', '192.168.1.1'),
-        //                   ('lease_time', 86400),
-        //                   ('name_server', '8.8.8.8'),
-        //                   'end']
-        //   dhcp = DHCP(options=dhcp_options)
-        //   dhcp_offer_packet = ether/ip/udp/bootp/dhcp
-        val dhcp4Pkt = "ffffffffffff00112233445508004500012e000100004011b815c0a80101ffffffff0043" +
-                       "0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000011" +
-                       "223344550000000000000000000000000000000000000000000000000000000000000000" +
-                       "000000000000000000000000000000000000000000000000000000000000000000000000" +
-                       "000000000000000000000000000000000000000000000000000000000000000000000000" +
-                       "000000000000000000000000000000000000000000000000000000000000000000000000" +
-                       "000000000000000000000000000000000000000000000000000000000000000000000000" +
-                       "0000000000000000000000000000000000000000000000000000638253633501023604c0" +
-                       "a801010104ffffff000304c0a80101330400015180060408080808ff"
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(dhcp4Pkt),
-                PASSED_IPV4_FROM_DHCPV4_SERVER
-        )
-
-        // Using scapy to generate DHCP4 offer packet:
-        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
-        //   ip = IP(src="192.168.1.10", dst="192.168.1.20")  # IPv4
-        //   udp = UDP(sport=12345, dport=53)
-        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
-        //   pkt = eth / ip / udp / dns
-        //   fragments = fragment(pkt, fragsize=30)
-        //   fragments[1]
-        val fragmentedUdpPkt = "01005e0000fbe89f806660bb08004500001d000100034011f75dc0a8010ac0a8" +
-                               "01146f63616c00000c0001"
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(fragmentedUdpPkt),
-                DROPPED_IPV4_NON_DHCP4
-        )
-        apfFilter.shutdown()
-    }
-
-    // The APFv6 code path is only turned on in V+
-    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
-    @Test
-    fun testArpTransmit() {
-        val apfFilter =
-            ApfFilter(
-                context,
-                getDefaultConfig(),
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-        )
-        verify(ipClientCallback, times(2)).installPacketFilter(any())
-        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
-        val lp = LinkProperties()
-        lp.addLinkAddress(linkAddress)
-        apfFilter.setLinkProperties(lp)
-        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
-        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
-        val program = programCaptor.value
-        val receivedArpPacketBuf = ArpPacket.buildArpPacket(
-                arpBroadcastMacAddress,
-                senderMacAddress,
-                hostIpv4Address,
-                HexDump.hexStringToByteArray("000000000000"),
-                senderIpv4Address,
-                ARP_REQUEST.toShort()
-        )
-        val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
-        receivedArpPacketBuf.get(receivedArpPacket)
-        verifyProgramRun(APF_VERSION_6, program, receivedArpPacket, DROPPED_ARP_REQUEST_REPLIED)
-
-        val transmittedPacket = ApfJniUtils.getTransmittedPacket()
-        val expectedArpReplyBuf = ArpPacket.buildArpPacket(
-                senderMacAddress,
-                apfFilter.mHardwareAddress,
-                senderIpv4Address,
-                senderMacAddress,
-                hostIpv4Address,
-                ARP_REPLY.toShort()
-        )
-        val expectedArpReplyPacket = ByteArray(ARP_ETHER_IPV4_LEN)
-        expectedArpReplyBuf.get(expectedArpReplyPacket)
-        assertContentEquals(
-                expectedArpReplyPacket + ByteArray(18) {0},
-                transmittedPacket
-        )
-        apfFilter.shutdown()
-    }
-
-    @Test
-    fun testArpOffloadDisabled() {
-        val apfConfig = getDefaultConfig()
-        apfConfig.shouldHandleArpOffload = false
-        val apfFilter =
-            ApfFilter(
-                context,
-                apfConfig,
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-            )
-        verify(ipClientCallback, times(2)).installPacketFilter(any())
-        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
-        val lp = LinkProperties()
-        lp.addLinkAddress(linkAddress)
-        apfFilter.setLinkProperties(lp)
-        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
-        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
-        val program = programCaptor.value
-        val receivedArpPacketBuf = ArpPacket.buildArpPacket(
-            arpBroadcastMacAddress,
-            senderMacAddress,
-            hostIpv4Address,
-            HexDump.hexStringToByteArray("000000000000"),
-            senderIpv4Address,
-            ARP_REQUEST.toShort()
-        )
-        val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
-        receivedArpPacketBuf.get(receivedArpPacket)
-        verifyProgramRun(APF_VERSION_6, program, receivedArpPacket, PASSED_ARP_REQUEST)
-        apfFilter.shutdown()
-    }
-
-    @Test
-    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
-    fun testNsFilterNoIPv6() {
-        `when`(dependencies.getAnycast6Addresses(any())).thenReturn(listOf())
-        val apfFilter =
-            ApfFilter(
-                context,
-                getDefaultConfig(),
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-        )
-
-        // validate NS packet check when there is no IPv6 address
-        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
-        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
-        val program = programCaptor.allValues.last()
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val nsPkt = "01020304050600010203040586DD6000000000183AFF200100000000000" +
-                    "00200001A1122334420010000000000000200001A334411228700452900" +
-                    "00000020010000000000000200001A33441122"
-        // when there is no IPv6 addresses -> pass NS packet
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(nsPkt),
-                PASSED_IPV6_NS_NO_ADDRESS
-        )
-
-        apfFilter.shutdown()
-    }
-
-    @Test
-    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
-    fun testNsFilter() {
-        val apfFilter =
-            ApfFilter(
-                context,
-                getDefaultConfig(),
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-        )
-        verify(ipClientCallback, times(2)).installPacketFilter(any())
-
-        // validate Ethernet dst address check
-
-        val lp = LinkProperties()
-        for (addr in hostIpv6Addresses) {
-            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
-        }
-
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(3)).installPacketFilter(any())
-        apfFilter.updateClatInterfaceState(true)
-        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
-        verify(ipClientCallback, times(4)).installPacketFilter(programCaptor.capture())
-        val program = programCaptor.value
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="00:05:04:03:02:01")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val nonHostDstMacNsPkt = "00050403020100010203040586DD6000000000183AFF2001000000000000" +
-                                 "0200001A1122334420010000000000000200001A33441122870045290000" +
-                                 "000020010000000000000200001A33441122"
-        // invalid unicast ether dst -> pass
-        verifyProgramRun(
-            APF_VERSION_6,
-            program,
-            HexDump.hexStringToByteArray(nonHostDstMacNsPkt),
-            DROPPED_IPV6_NS_OTHER_HOST
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="33:33:ff:03:02:01")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val nonMcastDstMacNsPkt = "3333ff03020100010203040586DD6000000000183AFF2001000000000000" +
-                                  "0200001A1122334420010000000000000200001A33441122870045290000" +
-                                  "000020010000000000000200001A33441122"
-        // mcast dst mac is not one of solicited mcast mac derived from one of device's ip -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(nonMcastDstMacNsPkt),
-                DROPPED_IPV6_NS_OTHER_HOST
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="33:33:ff:44:11:22")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val hostMcastDstMacNsPkt = "3333ff44112200010203040586DD6000000000183AFF2001000000000000" +
-                                   "0200001A1122334420010000000000000200001A33441122870045290000" +
-                                   "000020010000000000000200001A33441122"
-        // mcast dst mac is one of solicited mcast mac derived from one of device's ip -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(hostMcastDstMacNsPkt),
-                PASSED_IPV6_ICMP
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val broadcastNsPkt = "FFFFFFFFFFFF00010203040586DD6000000000183AFF2001000000000000" +
-                             "0200001A1122334420010000000000000200001A33441122870045290000" +
-                             "000020010000000000000200001A33441122"
-        // mcast dst mac is broadcast address -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(broadcastNsPkt),
-                PASSED_IPV6_ICMP
-        )
-
-        // validate IPv6 dst address check
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val validHostDstIpNsPkt = "02030405060700010203040586DD6000000000183AFF200100000000000" +
-                                  "00200001A1122334420010000000000000200001A334411228700452900" +
-                                  "00000020010000000000000200001A33441122"
-        // dst ip is one of device's ip -> Pass
-        verifyProgramRun(
-            APF_VERSION_6,
-            program,
-            HexDump.hexStringToByteArray(validHostDstIpNsPkt),
-            PASSED_IPV6_ICMP
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::100:1b:aabb:ccdd", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::100:1b:aabb:ccdd")
-        // pkt = eth/ip6/icmp6
-        val validHostAnycastDstIpNsPkt = "02030405060700010203040586DD6000000000183AFF20010000" +
-                                         "000000000200001A1122334420010000000000000100001BAABB" +
-                                         "CCDD8700E0C00000000020010000000000000100001BAABBCCDD"
-        // dst ip is device's anycast address -> Pass
-        verifyProgramRun(
-            APF_VERSION_6,
-            program,
-            HexDump.hexStringToByteArray(validHostAnycastDstIpNsPkt),
-            PASSED_IPV6_ICMP
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:4444:5555", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val nonHostUcastDstIpNsPkt = "02030405060700010203040586DD6000000000183AFF200100000000" +
-                                     "00000200001A1122334420010000000000000200001A444455558700" +
-                                     "EFF50000000020010000000000000200001A33441122"
-        // unicast dst ip is not one of device's ip -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(nonHostUcastDstIpNsPkt),
-                DROPPED_IPV6_NS_OTHER_HOST
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1133", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val nonHostMcastDstIpNsPkt = "02030405060700010203040586DD6000000000183AFF200100000000" +
-                                     "00000200001A11223344FF0200000000000000000001FF4411338700" +
-                                     "9C2E0000000020010000000000000200001A33441122"
-        // mcast dst ip is not one of solicited mcast ip derived from one of device's ip -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(nonHostMcastDstIpNsPkt),
-                DROPPED_IPV6_NS_OTHER_HOST
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // pkt = eth/ip6/icmp6
-        val hostMcastDstIpNsPkt = "02030405060700010203040586DD6000000000183AFF200100000000" +
-                                  "00000200001A11223344FF0200000000000000000001FF4411228700" +
-                                  "9C2E0000000020010000000000000200001A33441122"
-        // mcast dst ip is one of solicited mcast ip derived from one of device's ip -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
-                PASSED_IPV6_ICMP
-        )
-
-        // validate IPv6 NS payload check
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255, plen=20)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
-        // pkt = eth/ip6/icmp6/icmp6_opt
-        val shortNsPkt = "02030405060700010203040586DD6000000000143AFF20010000000000000200001A1" +
-                         "122334420010000000000000200001A3344112287003B140000000020010000000000" +
-                         "000200001A334411220101010203040506"
-        // payload len < 24 -> drop
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(shortNsPkt),
-                DROPPED_IPV6_NS_INVALID
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // icmp6_opt_1 = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
-        // icmp6_opt_2 = ICMPv6NDOptUnknown(type=14, len=6, data='\x11\x22\x33\x44\x55\x66')
-        // pkt = eth/ip6/icmp6/icmp6_opt_1/icmp6_opt_2
-        val longNsPkt = "02030405060700010203040586DD6000000000283AFF20010000000000000200001A11" +
-                        "22334420010000000000000200001A3344112287009339000000002001000000000000" +
-                        "0200001A3344112201010102030405060E06112233445566"
-        // payload len > 32 -> pass
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(longNsPkt),
-                PASSED_IPV6_NS_MULTIPLE_OPTIONS
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:4444:5555")
-        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
-        // pkt = eth/ip6/icmp6/icmp6_opt
-        val otherHostNsPkt = "02030405060700010203040586DD6000000000203AFF200100000000000002000" +
-                             "01A1122334420010000000000000200001A334411228700E5E000000000200100" +
-                             "00000000000200001A444455550101010203040506"
-        // target ip is not one of device's ip -> drop
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(otherHostNsPkt),
-                DROPPED_IPV6_NS_OTHER_HOST
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=20)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
-        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
-        // pkt = eth/ip6/icmp6/icmp6_opt
-        val invalidHoplimitNsPkt = "02030405060700010203040586DD6000000000203A14200100000000000" +
-                                   "00200001A1122334420010000000000000200001A3344112287003B1400" +
-                                   "00000020010000000000000200001A334411220101010203040506"
-        // hoplimit is not 255 -> drop
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(invalidHoplimitNsPkt),
-                DROPPED_IPV6_NS_INVALID
-        )
-
-        // Using scapy to generate IPv6 NS packet:
-        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
-        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
-        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122", code=5)
-        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
-        // pkt = eth/ip6/icmp6/icmp6_opt
-        val invalidIcmpCodeNsPkt = "02030405060700010203040586DD6000000000203AFF200100000000000" +
-                                   "00200001A1122334420010000000000000200001A3344112287053B0F00" +
-                                   "00000020010000000000000200001A334411220101010203040506"
-        // icmp6 code is not 0 -> drop
-        verifyProgramRun(
-                APF_VERSION_6,
-                program,
-                HexDump.hexStringToByteArray(invalidIcmpCodeNsPkt),
-                DROPPED_IPV6_NS_INVALID
-        )
-
-        apfFilter.shutdown()
-    }
-
-    @Test
-    fun testApfProgramUpdate() {
-        val apfFilter =
-            ApfFilter(
-                context,
-                getDefaultConfig(),
-                ifParams,
-                ipClientCallback,
-                metrics,
-                dependencies
-        )
-
-        verify(ipClientCallback, times(2)).installPacketFilter(any())
-        // add IPv4 address, expect to have apf program update
-        val lp = LinkProperties()
-        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
-        lp.addLinkAddress(linkAddress)
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(3)).installPacketFilter(any())
-
-        // add the same IPv4 address, expect to have no apf program update
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(3)).installPacketFilter(any())
-
-        // add IPv6 addresses, expect to have apf program update
-        for (addr in hostIpv6Addresses) {
-            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
-        }
-
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(4)).installPacketFilter(any())
-
-        // add the same IPv6 addresses, expect to have no apf program update
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(4)).installPacketFilter(any())
-
-        // add more tentative IPv6 addresses, expect to have apf program update
-        for (addr in hostIpv6TentativeAddresses) {
-            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64, IFA_F_TENTATIVE, 0))
-        }
-
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(5)).installPacketFilter(any())
-
-        // add the same IPv6 addresses, expect to have no apf program update
-        apfFilter.setLinkProperties(lp)
-        verify(ipClientCallback, times(5)).installPacketFilter(any())
-        apfFilter.shutdown()
-    }
-
-    private fun verifyProgramRun(
-            version: Int,
-            program: ByteArray,
-            pkt: ByteArray,
-            targetCnt: Counter,
-            cntMap: MutableMap<Counter, Long> = mutableMapOf(),
-            dataRegion: ByteArray = ByteArray(Counter.totalSize()) { 0 },
-            incTotal: Boolean = true,
-            result: Int = if (targetCnt.name.startsWith("PASSED")) PASS else DROP
-    ) {
-        assertVerdict(version, result, program, pkt, dataRegion)
-        cntMap[targetCnt] = cntMap.getOrDefault(targetCnt, 0) + 1
-        if (incTotal) {
-            cntMap[TOTAL_PACKETS] = cntMap.getOrDefault(TOTAL_PACKETS, 0) + 1
-        }
-        val errMsg = "Counter is not increased properly. To debug: \n" +
-                     " apf_run --program ${HexDump.toHexString(program)} " +
-                     "--packet ${HexDump.toHexString(pkt)} " +
-                     "--data ${HexDump.toHexString(dataRegion)} --age 0 " +
-                     "${if (version == APF_VERSION_6) "--v6" else "" } --trace  | less \n"
-        assertEquals(cntMap, decodeCountersIntoMap(dataRegion), errMsg)
-    }
-
-    private fun decodeCountersIntoMap(counterBytes: ByteArray): Map<Counter, Long> {
-        val counters = Counter::class.java.enumConstants
-        val ret = HashMap<Counter, Long>()
-        val skippedCounters = setOf(APF_PROGRAM_ID, APF_VERSION)
-        // starting from index 2 to skip the endianness mark
-        for (c in listOf(*counters).subList(2, counters.size)) {
-            if (c in skippedCounters) continue
-            val value = ApfCounterTracker.getCounterValue(counterBytes, c)
-            if (value != 0L) {
-                ret[c] = value
-            }
-        }
-        return ret
-    }
-
     private fun encodeInstruction(opcode: Int, immLength: Int, register: Int): Byte {
         val immLengthEncoding = if (immLength == 4) 3 else immLength
         return opcode.shl(3).or(immLengthEncoding.shl(1)).or(register).toByte()
@@ -2360,15 +1634,4 @@ class ApfNewTest {
         )
         return this.drop(7).toByteArray()
     }
-
-    private fun getDefaultConfig(apfVersion: Int = APF_VERSION_6): ApfFilter.ApfConfiguration {
-        val config = ApfFilter.ApfConfiguration()
-        config.apfCapabilities =
-                ApfCapabilities(apfVersion, 4096, ARPHRD_ETHER)
-        config.multicastFilter = false
-        config.ieee802_3Filter = false
-        config.ethTypeBlackList = IntArray(0)
-        config.shouldHandleArpOffload = true
-        return config
-    }
 }
diff --git a/tests/unit/src/android/net/apf/ApfMdnsUtilsTest.kt b/tests/unit/src/android/net/apf/ApfMdnsUtilsTest.kt
new file mode 100644
index 00000000..edf4f431
--- /dev/null
+++ b/tests/unit/src/android/net/apf/ApfMdnsUtilsTest.kt
@@ -0,0 +1,155 @@
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
+package android.net.apf
+
+import android.net.apf.ApfMdnsUtils.extractOffloadReplyRule
+import android.net.nsd.OffloadEngine
+import android.net.nsd.OffloadServiceInfo
+import android.net.nsd.OffloadServiceInfo.Key
+import android.os.Build
+import androidx.test.filters.SmallTest
+import com.android.net.module.util.NetworkStackConstants.TYPE_A
+import com.android.net.module.util.NetworkStackConstants.TYPE_AAAA
+import com.android.net.module.util.NetworkStackConstants.TYPE_PTR
+import com.android.net.module.util.NetworkStackConstants.TYPE_SRV
+import com.android.net.module.util.NetworkStackConstants.TYPE_TXT
+import com.android.testutils.DevSdkIgnoreRule
+import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
+import com.android.testutils.DevSdkIgnoreRunner
+import java.io.IOException
+import kotlin.test.assertContentEquals
+import kotlin.test.assertFailsWith
+import kotlin.test.assertTrue
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+/**
+ * Tests for Apf mDNS utility functions.
+ */
+@RunWith(DevSdkIgnoreRunner::class)
+@SmallTest
+@IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+class ApfMdnsUtilsTest {
+    @get:Rule
+    val ignoreRule = DevSdkIgnoreRule()
+
+    private val testServiceName1 = "NsdChat"
+    private val testServiceName2 = "NsdCall"
+    private val testServiceType = "_http._tcp.local"
+    private val testSubType = "tsub"
+    private val testHostName = "Android.local"
+    private val testRawPacket1 = byteArrayOf(1, 2, 3, 4, 5)
+    private val testRawPacket2 = byteArrayOf(6, 7, 8, 9)
+    private val encodedFullServiceName1 = intArrayOf(
+            7, 'N'.code, 'S'.code, 'D'.code, 'C'.code, 'H'.code, 'A'.code, 'T'.code,
+            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
+            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
+            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
+            0, 0).map { it.toByte() }.toByteArray()
+    private val encodedFullServiceName2 = intArrayOf(
+            7, 'N'.code, 'S'.code, 'D'.code, 'C'.code, 'A'.code, 'L'.code, 'L'.code,
+            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
+            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
+            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
+            0, 0).map { it.toByte() }.toByteArray()
+    private val encodedServiceType = intArrayOf(
+            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
+            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
+            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
+            0, 0).map { it.toByte() }.toByteArray()
+    private val encodedServiceTypeWithSub1 = intArrayOf(
+            4, 'T'.code, 'S'.code, 'U'.code, 'B'.code,
+            4, '_'.code, 'S'.code, 'U'.code, 'B'.code,
+            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
+            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
+            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
+            0, 0).map { it.toByte() }.toByteArray()
+    private val encodedServiceTypeWithWildCard = intArrayOf(
+            0xff,
+            4, '_'.code, 'S'.code, 'U'.code, 'B'.code,
+            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
+            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
+            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
+            0, 0).map { it.toByte() }.toByteArray()
+    private val encodedTestHostName = intArrayOf(
+            7, 'A'.code, 'N'.code, 'D'.code, 'R'.code, 'O'.code, 'I'.code, 'D'.code,
+            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
+            0, 0).map { it.toByte() }.toByteArray()
+
+    @Test
+    fun testExtractOffloadReplyRule_noPriorityReturnsEmptySet() {
+        val info = createOffloadServiceInfo(Int.MAX_VALUE)
+        val rules = extractOffloadReplyRule(listOf(info))
+        assertTrue(rules.isEmpty())
+    }
+
+    @Test
+    fun testExtractOffloadReplyRule_extractRulesWithValidPriority() {
+        val info1 = createOffloadServiceInfo(10)
+        val info2 = createOffloadServiceInfo(
+                11,
+                testServiceName2,
+                listOf("a", "b", "c", "d"),
+                testRawPacket2
+        )
+        val rules = extractOffloadReplyRule(listOf(info2, info1))
+        val expectedResult = listOf(
+                MdnsOffloadRule(
+                        listOf(
+                                MdnsOffloadRule.Matcher(encodedServiceType, TYPE_PTR),
+                                MdnsOffloadRule.Matcher(encodedServiceTypeWithSub1, TYPE_PTR),
+                                MdnsOffloadRule.Matcher(encodedFullServiceName1, TYPE_SRV),
+                                MdnsOffloadRule.Matcher(encodedFullServiceName1, TYPE_TXT),
+                                MdnsOffloadRule.Matcher(encodedTestHostName, TYPE_A),
+                                MdnsOffloadRule.Matcher(encodedTestHostName, TYPE_AAAA),
+
+                        ),
+                        testRawPacket1,
+                ),
+                MdnsOffloadRule(
+                        listOf(
+                                MdnsOffloadRule.Matcher(encodedServiceTypeWithWildCard, TYPE_PTR),
+                                MdnsOffloadRule.Matcher(encodedFullServiceName2, TYPE_SRV),
+                                MdnsOffloadRule.Matcher(encodedFullServiceName2, TYPE_TXT),
+
+                        ),
+                        null,
+                )
+        )
+        assertContentEquals(expectedResult, rules)
+    }
+
+    @Test
+    fun testExtractOffloadReplyRule_longLabelThrowsException() {
+        val info = createOffloadServiceInfo(10, "a".repeat(256))
+        assertFailsWith<IOException> { extractOffloadReplyRule(listOf(info)) }
+    }
+
+    private fun createOffloadServiceInfo(
+            priority: Int,
+            serviceName: String = testServiceName1,
+            subTypes: List<String> = listOf(testSubType),
+            rawPacket1: ByteArray = testRawPacket1
+    ): OffloadServiceInfo = OffloadServiceInfo(
+            Key(serviceName, testServiceType),
+            subTypes,
+            testHostName,
+            rawPacket1,
+            priority,
+            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
+        )
+}
diff --git a/tests/unit/src/android/net/apf/ApfStandaloneTest.kt b/tests/unit/src/android/net/apf/ApfStandaloneTest.kt
index 1a2307d8..2a918f8f 100644
--- a/tests/unit/src/android/net/apf/ApfStandaloneTest.kt
+++ b/tests/unit/src/android/net/apf/ApfStandaloneTest.kt
@@ -54,6 +54,8 @@ import org.junit.runner.RunWith
 class ApfStandaloneTest {
 
     private val etherTypeDenyList = listOf(0x88A2, 0x88A4, 0x88B8, 0x88CD, 0x88E1, 0x88E3)
+    private val ramSize = 1024
+    private val clampSize = 1024
 
     fun runApfTest(isSuspendMode: Boolean) {
         val program = generateApfV4Program(isSuspendMode)
@@ -76,9 +78,9 @@ class ApfStandaloneTest {
         val packetBadEtherType =
                 HexDump.hexStringToByteArray("ffffffffffff047bcb463fb588a201")
         val dataRegion = ByteArray(Counter.totalSize()) { 0 }
-        ApfTestUtils.assertVerdict(
+        ApfTestHelpers.assertVerdict(
             APF_VERSION_4,
-            ApfTestUtils.DROP,
+            ApfTestHelpers.DROP,
             program,
             packetBadEtherType,
             dataRegion
@@ -129,17 +131,32 @@ class ApfStandaloneTest {
         //            file      = ''
         //            options   = b'c\x82Sc' (DHCP magic)
         // ###[ DHCP options ]###
-        //               options   = [message-type='request' server_id=192.168.1.1 requested_addr=192.168.1.100 end]
+        //               options   = [message-type='request' server_id=192.168.1.1
+        //                            requested_addr=192.168.1.100 end]
         //
         // raw bytes:
-        // ffffffffffff047bcb463fb508004500011c00010000401179d100000000ffffffff004400430108393b010106000000000b000000000000000000000000000000000000000030343a37623a63623a34363a33663a62000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033604c0a801013204c0a80164ff
-
-        val dhcpRequestPkt = HexDump.hexStringToByteArray(
-            "ffffffffffff047bcb463fb508004500011c00010000401179d100000000ffffffff004400430108393b010106000000000b000000000000000000000000000000000000000030343a37623a63623a34363a33663a62000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033604c0a801013204c0a80164ff"
-        )
-        ApfTestUtils.assertVerdict(
+        // ffffffffffff047bcb463fb508004500011c00010000401179d100000000ffffffff004400430108393
+        // b010106000000000b000000000000000000000000000000000000000030343a37623a63623a34363a33
+        // 663a6200000000000000000000000000000000000000000000000000000000000000000000000000000
+        // 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
+        // 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
+        // 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
+        // 0000000000000000000000000000000000000000000000000000000000638253633501033604c0a8010
+        // 13204c0a80164ff
+        val dhcpRequestPktRawBytes = """
+            ffffffffffff047bcb463fb508004500011c00010000401179d100000000ffffffff00440043010839
+            3b010106000000000b000000000000000000000000000000000000000030343a37623a63623a34363a
+            33663a6200000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000000000000000000000000000000000
+            0000000000000000000000000000000000000000000000000000000000000000638253633501033604
+            c0a801013204c0a80164ff
+        """.replace("\\s+".toRegex(), "").trim()
+        val dhcpRequestPkt = HexDump.hexStringToByteArray(dhcpRequestPktRawBytes)
+        ApfTestHelpers.assertVerdict(
             APF_VERSION_4,
-            ApfTestUtils.DROP,
+            ApfTestHelpers.DROP,
             program,
             dhcpRequestPkt,
             dataRegion
@@ -171,11 +188,14 @@ class ApfStandaloneTest {
         //         res       = 0
         //
         // raw bytes:
-        // ffffffffffff047bcb463fb586dd6000000000083afffe8000000000000030b45e42ef3d36e5ff0200000000000000000000000000028500c81d00000000
-        val rsPkt = HexDump.hexStringToByteArray(
-            "ffffffffffff047bcb463fb586dd6000000000083afffe8000000000000030b45e42ef3d36e5ff0200000000000000000000000000028500c81d00000000"
-        )
-        ApfTestUtils.assertVerdict(APF_VERSION_4, ApfTestUtils.DROP, program, rsPkt, dataRegion)
+        // ffffffffffff047bcb463fb586dd6000000000083afffe8000000000000030b45e42ef3d36e5ff0200000
+        // 000000000000000000000028500c81d00000000
+        val rsPktRawBytes = """
+            ffffffffffff047bcb463fb586dd6000000000083afffe8000000000000030b45e42ef3d36e5ff020000
+            0000000000000000000000028500c81d00000000
+        """.replace("\\s+".toRegex(), "").trim()
+        val rsPkt = HexDump.hexStringToByteArray(rsPktRawBytes)
+        ApfTestHelpers.assertVerdict(APF_VERSION_4, ApfTestHelpers.DROP, program, rsPkt, dataRegion)
         assertEquals(mapOf<Counter, Long>(
                 Counter.TOTAL_PACKETS to 3,
                 Counter.DROPPED_RS to 1,
@@ -211,13 +231,16 @@ class ApfStandaloneTest {
             //         unused    = ''
             //
             // raw bytes: 84
-            // ffffffffffff047bcb463fb508004500001c000100004001a52d644f6154080808080800f7ff00000000
-            val pingRequestPkt = HexDump.hexStringToByteArray(
-                "ffffffffffff047bcb463fb508004500001c000100004001a52d644f6154080808080800f7ff00000000"
-            )
-            ApfTestUtils.assertVerdict(
+            // ffffffffffff047bcb463fb508004500001c000100004001a52d644f6154080808080800f7ff
+            // 00000000
+            val pingRequestPktRawBytes = """
+                ffffffffffff047bcb463fb508004500001c000100004001a52d644f6154080808080800f7ff
+                00000000
+            """.replace("\\s+".toRegex(), "").trim()
+            val pingRequestPkt = HexDump.hexStringToByteArray(pingRequestPktRawBytes)
+            ApfTestHelpers.assertVerdict(
                 APF_VERSION_4,
-                ApfTestUtils.DROP,
+                ApfTestHelpers.DROP,
                 program,
                 pingRequestPkt,
                 dataRegion
@@ -248,7 +271,7 @@ class ApfStandaloneTest {
         val endOfDhcpFilter = "endOfDhcpFilter"
         val endOfRsFilter = "endOfRsFiler"
         val endOfPingFilter = "endOfPingFilter"
-        val gen = ApfV4Generator(APF_VERSION_4)
+        val gen = ApfV4Generator(APF_VERSION_4, ramSize, clampSize)
 
         maybeSetupCounter(gen, Counter.TOTAL_PACKETS)
         gen.addLoadData(R0, 0)
diff --git a/tests/unit/src/android/net/apf/ApfTest.java b/tests/unit/src/android/net/apf/ApfTest.java
index 05e2e392..14e2122d 100644
--- a/tests/unit/src/android/net/apf/ApfTest.java
+++ b/tests/unit/src/android/net/apf/ApfTest.java
@@ -17,7 +17,15 @@
 package android.net.apf;
 
 import static android.net.apf.ApfCounterTracker.Counter.getCounterEnumFromOffset;
+import static android.net.apf.ApfTestHelpers.TIMEOUT_MS;
+import static android.net.apf.ApfTestHelpers.consumeInstalledProgram;
+import static android.net.apf.ApfTestHelpers.DROP;
+import static android.net.apf.ApfTestHelpers.MIN_PKT_SIZE;
+import static android.net.apf.ApfTestHelpers.PASS;
+import static android.net.apf.ApfTestHelpers.assertProgramEquals;
 import static android.net.apf.BaseApfGenerator.APF_VERSION_3;
+import static android.net.apf.BaseApfGenerator.APF_VERSION_4;
+import static android.net.apf.BaseApfGenerator.APF_VERSION_6;
 import static android.net.apf.BaseApfGenerator.DROP_LABEL;
 import static android.net.apf.BaseApfGenerator.MemorySlot;
 import static android.net.apf.BaseApfGenerator.PASS_LABEL;
@@ -26,34 +34,30 @@ import static android.net.apf.BaseApfGenerator.Register.R1;
 import static android.net.apf.ApfJniUtils.compareBpfApf;
 import static android.net.apf.ApfJniUtils.compileToBpf;
 import static android.net.apf.ApfJniUtils.dropsAllPackets;
-import static android.net.apf.ApfTestUtils.DROP;
-import static android.net.apf.ApfTestUtils.MIN_PKT_SIZE;
-import static android.net.apf.ApfTestUtils.PASS;
-import static android.net.apf.ApfTestUtils.assertProgramEquals;
 import static android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED;
 import static android.os.PowerManager.ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED;
-import static android.system.OsConstants.ARPHRD_ETHER;
+import static android.system.OsConstants.AF_UNIX;
 import static android.system.OsConstants.ETH_P_ARP;
 import static android.system.OsConstants.ETH_P_IP;
 import static android.system.OsConstants.ETH_P_IPV6;
 import static android.system.OsConstants.IPPROTO_ICMPV6;
 import static android.system.OsConstants.IPPROTO_IPV6;
-import static android.system.OsConstants.IPPROTO_TCP;
 import static android.system.OsConstants.IPPROTO_UDP;
+import static android.system.OsConstants.SOCK_STREAM;
 
 import static com.android.net.module.util.HexDump.hexStringToByteArray;
 import static com.android.net.module.util.HexDump.toHexString;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQUEST_TYPE;
 
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.any;
+import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
-import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.times;
@@ -67,18 +71,19 @@ import android.net.IpPrefix;
 import android.net.LinkAddress;
 import android.net.LinkProperties;
 import android.net.MacAddress;
-import android.net.NattKeepalivePacketDataParcelable;
-import android.net.TcpKeepalivePacketDataParcelable;
 import android.net.apf.ApfCounterTracker.Counter;
 import android.net.apf.ApfFilter.ApfConfiguration;
-import android.net.apf.ApfTestUtils.MockIpClientCallback;
-import android.net.apf.ApfTestUtils.TestApfFilter;
 import android.net.apf.BaseApfGenerator.IllegalInstructionException;
+import android.net.ip.IpClient;
 import android.net.metrics.IpConnectivityLog;
 import android.os.Build;
+import android.os.Handler;
+import android.os.HandlerThread;
 import android.os.PowerManager;
+import android.os.SystemClock;
 import android.stats.connectivity.NetworkQuirkEvent;
 import android.system.ErrnoException;
+import android.system.Os;
 import android.text.TextUtils;
 import android.text.format.DateUtils;
 import android.util.ArrayMap;
@@ -93,6 +98,7 @@ import com.android.internal.util.HexDump;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.net.module.util.DnsPacket;
 import com.android.net.module.util.Inet4AddressUtils;
+import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.NetworkStackConstants;
 import com.android.net.module.util.PacketBuilder;
 import com.android.networkstack.metrics.ApfSessionInfoMetrics;
@@ -102,7 +108,9 @@ import com.android.server.networkstack.tests.R;
 import com.android.testutils.ConcurrentUtils;
 import com.android.testutils.DevSdkIgnoreRule;
 import com.android.testutils.DevSdkIgnoreRunner;
+import com.android.testutils.HandlerUtils;
 
+import libcore.io.IoUtils;
 import libcore.io.Streams;
 
 import org.junit.After;
@@ -118,9 +126,11 @@ import org.mockito.MockitoAnnotations;
 
 import java.io.ByteArrayOutputStream;
 import java.io.File;
+import java.io.FileDescriptor;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.io.InputStream;
+import java.io.InterruptedIOException;
 import java.io.OutputStream;
 import java.net.Inet4Address;
 import java.net.Inet6Address;
@@ -133,6 +143,7 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Random;
+import java.util.concurrent.atomic.AtomicReference;
 
 /**
  * Tests for APF program generator and interpreter.
@@ -144,6 +155,8 @@ import java.util.Random;
 @SmallTest
 public class ApfTest {
     private static final int APF_VERSION_2 = 2;
+    private int mRamSize = 1024;
+    private int mClampSize = 1024;
 
     @Rule
     public DevSdkIgnoreRule mDevSdkIgnoreRule = new DevSdkIgnoreRule();
@@ -164,11 +177,13 @@ public class ApfTest {
     @Mock private NetworkQuirkMetrics mNetworkQuirkMetrics;
     @Mock private ApfSessionInfoMetrics mApfSessionInfoMetrics;
     @Mock private IpClientRaInfoMetrics mIpClientRaInfoMetrics;
-    @Mock private ApfFilter.Clock mClock;
+    @Mock private IpClient.IpClientCallbacksWrapper mIpClientCb;
     @GuardedBy("mApfFilterCreated")
     private final ArrayList<AndroidPacketFilter> mApfFilterCreated = new ArrayList<>();
-    @GuardedBy("mThreadsToBeCleared")
-    private final ArrayList<Thread> mThreadsToBeCleared = new ArrayList<>();
+    private FileDescriptor mWriteSocket;
+    private HandlerThread mHandlerThread;
+    private Handler mHandler;
+    private long mCurrentTimeMs;
 
     @Before
     public void setUp() throws Exception {
@@ -176,32 +191,22 @@ public class ApfTest {
         doReturn(mPowerManager).when(mContext).getSystemService(PowerManager.class);
         doReturn(mApfSessionInfoMetrics).when(mDependencies).getApfSessionInfoMetrics();
         doReturn(mIpClientRaInfoMetrics).when(mDependencies).getIpClientRaInfoMetrics();
+        FileDescriptor readSocket = new FileDescriptor();
+        mWriteSocket = new FileDescriptor();
+        Os.socketpair(AF_UNIX, SOCK_STREAM, 0, mWriteSocket, readSocket);
+        doReturn(readSocket).when(mDependencies).createPacketReaderSocket(anyInt());
+        mCurrentTimeMs = SystemClock.elapsedRealtime();
+        doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
+        doReturn(true).when(mIpClientCb).installPacketFilter(any());
         doAnswer((invocation) -> {
             synchronized (mApfFilterCreated) {
                 mApfFilterCreated.add(invocation.getArgument(0));
             }
             return null;
         }).when(mDependencies).onApfFilterCreated(any());
-        doAnswer((invocation) -> {
-            synchronized (mThreadsToBeCleared) {
-                mThreadsToBeCleared.add(invocation.getArgument(0));
-            }
-            return null;
-        }).when(mDependencies).onThreadCreated(any());
-    }
-
-    private void quitThreads() throws Exception {
-        ConcurrentUtils.quitThreads(
-                THREAD_QUIT_MAX_RETRY_COUNT,
-                false /* interrupt */,
-                HANDLER_TIMEOUT_MS,
-                () -> {
-                    synchronized (mThreadsToBeCleared) {
-                        final ArrayList<Thread> ret = new ArrayList<>(mThreadsToBeCleared);
-                        mThreadsToBeCleared.clear();
-                        return ret;
-                    }
-                });
+        mHandlerThread = new HandlerThread("ApfTestThread");
+        mHandlerThread.start();
+        mHandler = new Handler(mHandlerThread.getLooper());
     }
 
     private void shutdownApfFilters() throws Exception {
@@ -212,30 +217,26 @@ public class ApfTest {
                 mApfFilterCreated.clear();
                 return ret;
             }
-        }, (apf) -> {
-            apf.shutdown();
-        });
+        }, (apf) -> mHandler.post(apf::shutdown));
         synchronized (mApfFilterCreated) {
             assertEquals("ApfFilters did not fully shutdown.",
                     0, mApfFilterCreated.size());
         }
-        // It's necessary to wait until all ReceiveThreads have finished running because
-        // clearInlineMocks clears all Mock objects, including some privilege frameworks
-        // required by logStats, at the end of ReceiveThread#run.
-        quitThreads();
     }
 
     @After
     public void tearDown() throws Exception {
+        IoUtils.closeQuietly(mWriteSocket);
         shutdownApfFilters();
+        HandlerUtils.waitForIdle(mHandler, TIMEOUT_MS);
         // Clear mocks to prevent from stubs holding instances and cause memory leaks.
         Mockito.framework().clearInlineMocks();
+        mHandlerThread.quitSafely();
+        mHandlerThread.join();
     }
 
     private static final String TAG = "ApfTest";
     // Expected return codes from APF interpreter.
-    private static final ApfCapabilities MOCK_APF_CAPABILITIES =
-            new ApfCapabilities(2, 4096, ARPHRD_ETHER);
 
     private static final boolean DROP_MULTICAST = true;
     private static final boolean ALLOW_MULTICAST = false;
@@ -246,7 +247,7 @@ public class ApfTest {
     private static final int MIN_RDNSS_LIFETIME_SEC = 0;
     private static final int MIN_METRICS_SESSION_DURATIONS_MS = 300_000;
 
-    private static final int HANDLER_TIMEOUT_MS = 1000;
+    private static final int NO_CALLBACK_TIMEOUT_MS = 500;
     private static final int THREAD_QUIT_MAX_RETRY_COUNT = 3;
 
     // Constants for opcode encoding
@@ -259,9 +260,15 @@ public class ApfTest {
     private static final byte SIZE32  = (byte)(3 << 1);
     private static final byte R1_REG = 1;
 
+    private static final byte[] TEST_MAC_ADDR = {2, 3, 4, 5, 6, 7};
+    private static final int TEST_IFACE_IDX = 1234;
+    private static final InterfaceParams TEST_PARAMS = new InterfaceParams("lo", TEST_IFACE_IDX,
+            MacAddress.fromBytes(TEST_MAC_ADDR), 1500 /* defaultMtu */);
+
     private static ApfConfiguration getDefaultConfig() {
         ApfFilter.ApfConfiguration config = new ApfConfiguration();
-        config.apfCapabilities = MOCK_APF_CAPABILITIES;
+        config.apfVersionSupported = 2;
+        config.apfRamSize = 4096;
         config.multicastFilter = ALLOW_MULTICAST;
         config.ieee802_3Filter = ALLOW_802_3_FRAMES;
         config.ethTypeBlackList = new int[0];
@@ -272,58 +279,58 @@ public class ApfTest {
     }
 
     private void assertPass(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertPass(mApfVersion, gen);
+        ApfTestHelpers.assertPass(mApfVersion, gen);
     }
 
     private void assertDrop(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertDrop(mApfVersion, gen);
+        ApfTestHelpers.assertDrop(mApfVersion, gen);
     }
 
     private void assertPass(byte[] program, byte[] packet) {
-        ApfTestUtils.assertPass(mApfVersion, program, packet);
+        ApfTestHelpers.assertPass(mApfVersion, program, packet);
     }
 
     private void assertDrop(byte[] program, byte[] packet) {
-        ApfTestUtils.assertDrop(mApfVersion, program, packet);
+        ApfTestHelpers.assertDrop(mApfVersion, program, packet);
     }
 
     private void assertPass(byte[] program, byte[] packet, int filterAge) {
-        ApfTestUtils.assertPass(mApfVersion, program, packet, filterAge);
+        ApfTestHelpers.assertPass(mApfVersion, program, packet, filterAge);
     }
 
     private void assertDrop(byte[] program, byte[] packet, int filterAge) {
-        ApfTestUtils.assertDrop(mApfVersion, program, packet, filterAge);
+        ApfTestHelpers.assertDrop(mApfVersion, program, packet, filterAge);
     }
 
     private void assertPass(ApfV4Generator gen, byte[] packet, int filterAge)
             throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertPass(mApfVersion, gen, packet, filterAge);
+        ApfTestHelpers.assertPass(mApfVersion, gen, packet, filterAge);
     }
 
     private void assertDrop(ApfV4Generator gen, byte[] packet, int filterAge)
             throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertDrop(mApfVersion, gen, packet, filterAge);
+        ApfTestHelpers.assertDrop(mApfVersion, gen, packet, filterAge);
     }
 
     private void assertDataMemoryContents(int expected, byte[] program, byte[] packet,
             byte[] data, byte[] expectedData) throws Exception {
-        ApfTestUtils.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
+        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                 expectedData, false /* ignoreInterpreterVersion */);
     }
 
     private void assertDataMemoryContentsIgnoreVersion(int expected, byte[] program,
             byte[] packet, byte[] data, byte[] expectedData) throws Exception {
-        ApfTestUtils.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
+        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                 expectedData, true /* ignoreInterpreterVersion */);
     }
 
     private void assertVerdict(String msg, int expected, byte[] program,
             byte[] packet, int filterAge) {
-        ApfTestUtils.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
+        ApfTestHelpers.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
     }
 
     private void assertVerdict(int expected, byte[] program, byte[] packet) {
-        ApfTestUtils.assertVerdict(mApfVersion, expected, program, packet);
+        ApfTestHelpers.assertVerdict(mApfVersion, expected, program, packet);
     }
 
     /**
@@ -336,17 +343,17 @@ public class ApfTest {
         // Empty program should pass because having the program counter reach the
         // location immediately after the program indicates the packet should be
         // passed to the AP.
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         assertPass(gen);
 
         // Test pass opcode
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addPass();
         gen.addJump(DROP_LABEL);
         assertPass(gen);
 
         // Test jumping to pass label.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJump(PASS_LABEL);
         byte[] program = gen.generate();
         assertEquals(1, program.length);
@@ -354,7 +361,7 @@ public class ApfTest {
         assertPass(program, new byte[MIN_PKT_SIZE], 0);
 
         // Test jumping to drop label.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJump(DROP_LABEL);
         program = gen.generate();
         assertEquals(2, program.length);
@@ -363,127 +370,127 @@ public class ApfTest {
         assertDrop(program, new byte[15], 15);
 
         // Test jumping if equal to 0.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0Equals(0, DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if not equal to 0.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0NotEquals(0, DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfR0NotEquals(0, DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if registers equal.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0EqualsR1(DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if registers not equal.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0NotEqualsR1(DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfR0NotEqualsR1(DROP_LABEL);
         assertDrop(gen);
 
         // Test load immediate.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test add.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addAdd(1234567890);
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test add with a small signed negative value.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addAdd(-1);
         gen.addJumpIfR0Equals(-1, DROP_LABEL);
         assertDrop(gen);
 
         // Test subtract.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addAdd(-1234567890);
         gen.addJumpIfR0Equals(-1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test or.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addOr(1234567890);
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test and.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addAnd(123456789);
         gen.addJumpIfR0Equals(1234567890 & 123456789, DROP_LABEL);
         assertDrop(gen);
 
         // Test left shift.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addLeftShift(1);
         gen.addJumpIfR0Equals(1234567890 << 1, DROP_LABEL);
         assertDrop(gen);
 
         // Test right shift.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addRightShift(1);
         gen.addJumpIfR0Equals(1234567890 >> 1, DROP_LABEL);
         assertDrop(gen);
 
         // Test multiply.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 123456789);
         gen.addMul(2);
         gen.addJumpIfR0Equals(123456789 * 2, DROP_LABEL);
         assertDrop(gen);
 
         // Test divide.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addDiv(2);
         gen.addJumpIfR0Equals(1234567890 / 2, DROP_LABEL);
         assertDrop(gen);
 
         // Test divide by zero.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addDiv(0);
         gen.addJump(DROP_LABEL);
         assertPass(gen);
 
         // Test add.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1234567890);
         gen.addAddR1ToR0();
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test subtract.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, -1234567890);
         gen.addAddR1ToR0();
         gen.addJumpIfR0Equals(-1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test or.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1234567890);
         gen.addOrR0WithR1();
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test and.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addLoadImmediate(R1, 123456789);
         gen.addAndR0WithR1();
@@ -491,7 +498,7 @@ public class ApfTest {
         assertDrop(gen);
 
         // Test left shift.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addLoadImmediate(R1, 1);
         gen.addLeftShiftR0ByR1();
@@ -499,7 +506,7 @@ public class ApfTest {
         assertDrop(gen);
 
         // Test right shift.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addLoadImmediate(R1, -1);
         gen.addLeftShiftR0ByR1();
@@ -507,7 +514,7 @@ public class ApfTest {
         assertDrop(gen);
 
         // Test multiply.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 123456789);
         gen.addLoadImmediate(R1, 2);
         gen.addMulR0ByR1();
@@ -515,7 +522,7 @@ public class ApfTest {
         assertDrop(gen);
 
         // Test divide.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addLoadImmediate(R1, 2);
         gen.addDivR0ByR1();
@@ -523,136 +530,136 @@ public class ApfTest {
         assertDrop(gen);
 
         // Test divide by zero.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addDivR0ByR1();
         gen.addJump(DROP_LABEL);
         assertPass(gen);
 
         // Test byte load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoad8(R0, 1);
         gen.addJumpIfR0Equals(45, DROP_LABEL);
         assertDrop(gen, new byte[]{123,45,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test out of bounds load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoad8(R0, 16);
         gen.addJumpIfR0Equals(0, DROP_LABEL);
         assertPass(gen, new byte[]{123,45,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test half-word load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoad16(R0, 1);
         gen.addJumpIfR0Equals((45 << 8) | 67, DROP_LABEL);
         assertDrop(gen, new byte[]{123,45,67,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test word load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoad32(R0, 1);
         gen.addJumpIfR0Equals((45 << 24) | (67 << 16) | (89 << 8) | 12, DROP_LABEL);
         assertDrop(gen, new byte[]{123,45,67,89,12,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test byte indexed load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1);
         gen.addLoad8Indexed(R0, 0);
         gen.addJumpIfR0Equals(45, DROP_LABEL);
         assertDrop(gen, new byte[]{123,45,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test out of bounds indexed load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 8);
         gen.addLoad8Indexed(R0, 8);
         gen.addJumpIfR0Equals(0, DROP_LABEL);
         assertPass(gen, new byte[]{123,45,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test half-word indexed load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1);
         gen.addLoad16Indexed(R0, 0);
         gen.addJumpIfR0Equals((45 << 8) | 67, DROP_LABEL);
         assertDrop(gen, new byte[]{123,45,67,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test word indexed load.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1);
         gen.addLoad32Indexed(R0, 0);
         gen.addJumpIfR0Equals((45 << 24) | (67 << 16) | (89 << 8) | 12, DROP_LABEL);
         assertDrop(gen, new byte[]{123,45,67,89,12,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test jumping if greater than.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0GreaterThan(0, DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfR0GreaterThan(0, DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if less than.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0LessThan(0, DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0LessThan(1, DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if any bits set.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0AnyBitsSet(3, DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfR0AnyBitsSet(3, DROP_LABEL);
         assertDrop(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 3);
         gen.addJumpIfR0AnyBitsSet(3, DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if register greater than.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0GreaterThanR1(DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 2);
         gen.addLoadImmediate(R1, 1);
         gen.addJumpIfR0GreaterThanR1(DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if register less than.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfR0LessThanR1(DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1);
         gen.addJumpIfR0LessThanR1(DROP_LABEL);
         assertDrop(gen);
 
         // Test jumping if any bits set in register.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 3);
         gen.addJumpIfR0AnyBitsSetR1(DROP_LABEL);
         assertPass(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 3);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfR0AnyBitsSetR1(DROP_LABEL);
         assertDrop(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 3);
         gen.addLoadImmediate(R0, 3);
         gen.addJumpIfR0AnyBitsSetR1(DROP_LABEL);
         assertDrop(gen);
 
         // Test load from memory.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadFromMemory(R0, MemorySlot.SLOT_0);
         gen.addJumpIfR0Equals(0, DROP_LABEL);
         assertDrop(gen);
 
         // Test store to memory.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1234567890);
         gen.addStoreToMemory(MemorySlot.RAM_LEN, R1);
         gen.addLoadFromMemory(R0, MemorySlot.RAM_LEN);
@@ -660,63 +667,63 @@ public class ApfTest {
         assertDrop(gen);
 
         // Test filter age pre-filled memory.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_SECONDS);
         gen.addJumpIfR0Equals(123, DROP_LABEL);
         assertDrop(gen, new byte[MIN_PKT_SIZE], 123);
 
         // Test packet size pre-filled memory.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE);
         gen.addJumpIfR0Equals(MIN_PKT_SIZE, DROP_LABEL);
         assertDrop(gen);
 
         // Test IPv4 header size pre-filled memory.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE);
         gen.addJumpIfR0Equals(20, DROP_LABEL);
         assertDrop(gen, new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,8,0,0x45,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0);
 
         // Test not.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addNot(R0);
         gen.addJumpIfR0Equals(~1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test negate.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addNeg(R0);
         gen.addJumpIfR0Equals(-1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test move.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1234567890);
         gen.addMove(R0);
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addMove(R1);
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
 
         // Test swap.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1234567890);
         gen.addSwap();
         gen.addJumpIfR0Equals(1234567890, DROP_LABEL);
         assertDrop(gen);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1234567890);
         gen.addSwap();
         gen.addJumpIfR0Equals(0, DROP_LABEL);
         assertDrop(gen);
 
         // Test jump if bytes not equal.
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfBytesAtR0NotEqual(new byte[]{123}, DROP_LABEL);
         program = gen.generate();
@@ -728,20 +735,20 @@ public class ApfTest {
         assertEquals(1, program[4]);
         assertEquals(123, program[5]);
         assertDrop(program, new byte[MIN_PKT_SIZE], 0);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfBytesAtR0NotEqual(new byte[]{123}, DROP_LABEL);
         byte[] packet123 = {0,123,0,0,0,0,0,0,0,0,0,0,0,0,0};
         assertPass(gen, packet123, 0);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addJumpIfBytesAtR0NotEqual(new byte[]{123}, DROP_LABEL);
         assertDrop(gen, packet123, 0);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfBytesAtR0NotEqual(new byte[]{1, 2, 30, 4, 5}, DROP_LABEL);
         byte[] packet12345 = {0,1,2,3,4,5,0,0,0,0,0,0,0,0,0};
         assertDrop(gen, packet12345, 0);
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 1);
         gen.addJumpIfBytesAtR0NotEqual(new byte[]{1, 2, 3, 4, 5}, DROP_LABEL);
         assertPass(gen, packet12345, 0);
@@ -750,12 +757,12 @@ public class ApfTest {
     @Test(expected = ApfV4Generator.IllegalInstructionException.class)
     public void testApfGeneratorWantsV2OrGreater() throws Exception {
         // The minimum supported APF version is 2.
-        new ApfV4Generator(1);
+        new ApfV4Generator(1, mRamSize, mClampSize);
     }
 
     @Test
     public void testApfDataOpcodesWantApfV3() throws IllegalInstructionException, Exception {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         try {
             gen.addStoreData(R0, 0);
             fail();
@@ -778,22 +785,22 @@ public class ApfTest {
         ApfV4Generator gen;
 
         // 0-byte immediate: li R0, 0
-        gen = new ApfV4Generator(4);
+        gen = new ApfV4Generator(APF_VERSION_4, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 0);
         assertProgramEquals(new byte[]{LI_OP | SIZE0}, gen.generate());
 
         // 1-byte immediate: li R0, 42
-        gen = new ApfV4Generator(4);
+        gen = new ApfV4Generator(APF_VERSION_4, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 42);
         assertProgramEquals(new byte[]{LI_OP | SIZE8, 42}, gen.generate());
 
         // 2-byte immediate: li R1, 0x1234
-        gen = new ApfV4Generator(4);
+        gen = new ApfV4Generator(APF_VERSION_4, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 0x1234);
         assertProgramEquals(new byte[]{LI_OP | SIZE16 | R1_REG, 0x12, 0x34}, gen.generate());
 
         // 4-byte immediate: li R0, 0x12345678
-        gen = new ApfV4Generator(3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 0x12345678);
         assertProgramEquals(
                 new byte[]{LI_OP | SIZE32, 0x12, 0x34, 0x56, 0x78},
@@ -808,18 +815,18 @@ public class ApfTest {
         ApfV4Generator gen;
 
         // 1-byte negative immediate: li R0, -42
-        gen = new ApfV4Generator(3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, -42);
         assertProgramEquals(new byte[]{LI_OP | SIZE8, -42}, gen.generate());
 
         // 2-byte negative immediate: li R1, -0x1122
-        gen = new ApfV4Generator(3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, -0x1122);
         assertProgramEquals(new byte[]{LI_OP | SIZE16 | R1_REG, (byte)0xEE, (byte)0xDE},
                 gen.generate());
 
         // 4-byte negative immediate: li R0, -0x11223344
-        gen = new ApfV4Generator(3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, -0x11223344);
         assertProgramEquals(
                 new byte[]{LI_OP | SIZE32, (byte)0xEE, (byte)0xDD, (byte)0xCC, (byte)0xBC},
@@ -834,23 +841,23 @@ public class ApfTest {
         ApfV4Generator gen;
 
         // Load data with no offset: lddw R0, [0 + r1]
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadData(R0, 0);
         assertProgramEquals(new byte[]{LDDW_OP | SIZE0}, gen.generate());
 
         // Store data with 8bit negative offset: lddw r0, [-42 + r1]
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addStoreData(R0, -42);
         assertProgramEquals(new byte[]{STDW_OP | SIZE8, -42}, gen.generate());
 
         // Store data to R1 with 16bit negative offset: stdw r1, [-0x1122 + r0]
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addStoreData(R1, -0x1122);
         assertProgramEquals(new byte[]{STDW_OP | SIZE16 | R1_REG, (byte)0xEE, (byte)0xDE},
                 gen.generate());
 
         // Load data to R1 with 32bit negative offset: lddw r1, [0xDEADBEEF + r0]
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadData(R1, 0xDEADBEEF);
         assertProgramEquals(
                 new byte[]{LDDW_OP | SIZE32 | R1_REG,
@@ -868,12 +875,12 @@ public class ApfTest {
         byte[] expected_data = data.clone();
 
         // No memory access instructions: should leave the data segment untouched.
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         assertDataMemoryContents(PASS, gen.generate(), packet, data, expected_data);
 
         // Expect value 0x87654321 to be stored starting from address -11 from the end of the
         // data buffer, in big-endian order.
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 0x87654321);
         gen.addLoadImmediate(R1, -5);
         gen.addStoreData(R0, -6);  // -5 + -6 = -11 (offset +5 with data_len=16)
@@ -890,7 +897,7 @@ public class ApfTest {
     @Test
     public void testApfDataRead() throws IllegalInstructionException, Exception {
         // Program that DROPs if address 10 (-6) contains 0x87654321.
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, 1000);
         gen.addLoadData(R0, -1006);  // 1000 + -1006 = -6 (offset +10 with data_len=16)
         gen.addJumpIfR0Equals(0x87654321, DROP_LABEL);
@@ -919,7 +926,7 @@ public class ApfTest {
      */
     @Test
     public void testApfDataReadModifyWrite() throws IllegalInstructionException, Exception {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, -22);
         gen.addLoadData(R0, 0);  // Load from address 32 -22 + 0 = 10
         gen.addAdd(0x78453412);  // 87654321 + 78453412 = FFAA7733
@@ -946,7 +953,7 @@ public class ApfTest {
         byte[] expected_data = data;
 
         // Program that DROPs unconditionally. This is our the baseline.
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 3);
         gen.addLoadData(R1, 7);
         gen.addJump(DROP_LABEL);
@@ -956,7 +963,7 @@ public class ApfTest {
         // 3 instructions, all normal opcodes (LI, LDDW, JMP) with 1 byte immediate = 6 byte program
         // 32 byte data length, for a total of 38 byte ram len.
         // APFv6 needs to round this up to be a multiple of 4, so 40.
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 20);
         if (mApfVersion == 4) {
             gen.addLoadData(R1, 15);  // R0(20)+15+U32[0..3] >= 6 prog + 32 data, so invalid
@@ -967,21 +974,21 @@ public class ApfTest {
         assertDataMemoryContents(PASS, gen.generate(), packet, data, expected_data);
 
         // Subtracting an immediate should work...
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 20);
         gen.addLoadData(R1, -4);
         gen.addJump(DROP_LABEL);
         assertDataMemoryContents(DROP, gen.generate(), packet, data, expected_data);
 
         // ...and underflowing simply wraps around to the end of the buffer...
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 20);
         gen.addLoadData(R1, -30);
         gen.addJump(DROP_LABEL);
         assertDataMemoryContents(DROP, gen.generate(), packet, data, expected_data);
 
         // ...but doesn't allow accesses before the start of the buffer
-        gen = new ApfV4Generator(APF_VERSION_3);
+        gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize);
         gen.addLoadImmediate(R0, 20);
         gen.addLoadData(R1, -1000);
         gen.addJump(DROP_LABEL);  // Not reached.
@@ -1006,6 +1013,20 @@ public class ApfTest {
         }
     }
 
+    private void pretendPacketReceived(byte[] packet)
+            throws InterruptedIOException, ErrnoException {
+        Os.write(mWriteSocket, packet, 0, packet.length);
+    }
+
+    private ApfFilter getApfFilter(ApfFilter.ApfConfiguration config) {
+        AtomicReference<ApfFilter> apfFilter = new AtomicReference<>();
+        mHandler.post(() ->
+                apfFilter.set(new ApfFilter(mHandler, mContext, config, TEST_PARAMS,
+                        mIpClientCb, mNetworkQuirkMetrics, mDependencies)));
+        HandlerUtils.waitForIdle(mHandler, TIMEOUT_MS);
+        return apfFilter.get();
+    }
+
     /**
      * Generate APF program, run pcap file though APF filter, then check all the packets in the file
      * should be dropped.
@@ -1014,20 +1035,19 @@ public class ApfTest {
     public void testApfFilterPcapFile() throws Exception {
         final byte[] MOCK_PCAP_IPV4_ADDR = {(byte) 172, 16, 7, (byte) 151};
         String pcapFilename = stageFile(R.raw.apfPcap);
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         LinkAddress link = new LinkAddress(InetAddress.getByAddress(MOCK_PCAP_IPV4_ADDR), 16);
         LinkProperties lp = new LinkProperties();
         lp.addLinkAddress(link);
 
         ApfConfiguration config = getDefaultConfig();
-        ApfCapabilities MOCK_APF_PCAP_CAPABILITIES = new ApfCapabilities(4, 1700, ARPHRD_ETHER);
-        config.apfCapabilities = MOCK_APF_PCAP_CAPABILITIES;
+        config.apfVersionSupported = 4;
+        config.apfRamSize = 1700;
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 2 /* installCnt */);
         apfFilter.setLinkProperties(lp);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         byte[] data = new byte[Counter.totalSize()];
         final boolean result;
 
@@ -1051,25 +1071,12 @@ public class ApfTest {
     private static final int IP_HEADER_OFFSET = ETH_HEADER_LEN;
 
     private static final int IPV4_HEADER_LEN          = 20;
-    private static final int IPV4_TOTAL_LENGTH_OFFSET = IP_HEADER_OFFSET + 2;
     private static final int IPV4_PROTOCOL_OFFSET     = IP_HEADER_OFFSET + 9;
-    private static final int IPV4_SRC_ADDR_OFFSET     = IP_HEADER_OFFSET + 12;
     private static final int IPV4_DEST_ADDR_OFFSET    = IP_HEADER_OFFSET + 16;
 
-    private static final int IPV4_TCP_HEADER_LEN           = 20;
     private static final int IPV4_TCP_HEADER_OFFSET        = IP_HEADER_OFFSET + IPV4_HEADER_LEN;
-    private static final int IPV4_TCP_SRC_PORT_OFFSET      = IPV4_TCP_HEADER_OFFSET + 0;
-    private static final int IPV4_TCP_DEST_PORT_OFFSET     = IPV4_TCP_HEADER_OFFSET + 2;
-    private static final int IPV4_TCP_SEQ_NUM_OFFSET       = IPV4_TCP_HEADER_OFFSET + 4;
-    private static final int IPV4_TCP_ACK_NUM_OFFSET       = IPV4_TCP_HEADER_OFFSET + 8;
-    private static final int IPV4_TCP_HEADER_LENGTH_OFFSET = IPV4_TCP_HEADER_OFFSET + 12;
-    private static final int IPV4_TCP_HEADER_FLAG_OFFSET   = IPV4_TCP_HEADER_OFFSET + 13;
 
     private static final int IPV4_UDP_HEADER_OFFSET    = IP_HEADER_OFFSET + IPV4_HEADER_LEN;
-    private static final int IPV4_UDP_SRC_PORT_OFFSET  = IPV4_UDP_HEADER_OFFSET + 0;
-    private static final int IPV4_UDP_DEST_PORT_OFFSET = IPV4_UDP_HEADER_OFFSET + 2;
-    private static final int IPV4_UDP_LENGTH_OFFSET    = IPV4_UDP_HEADER_OFFSET + 4;
-    private static final int IPV4_UDP_PAYLOAD_OFFSET   = IPV4_UDP_HEADER_OFFSET + 8;
     private static final byte[] IPV4_BROADCAST_ADDRESS =
             {(byte) 255, (byte) 255, (byte) 255, (byte) 255};
 
@@ -1079,10 +1086,6 @@ public class ApfTest {
     private static final int IPV6_SRC_ADDR_OFFSET        = IP_HEADER_OFFSET + 8;
     private static final int IPV6_DEST_ADDR_OFFSET       = IP_HEADER_OFFSET + 24;
     private static final int IPV6_PAYLOAD_OFFSET = IP_HEADER_OFFSET + IPV6_HEADER_LEN;
-    private static final int IPV6_TCP_SRC_PORT_OFFSET    = IPV6_PAYLOAD_OFFSET + 0;
-    private static final int IPV6_TCP_DEST_PORT_OFFSET   = IPV6_PAYLOAD_OFFSET + 2;
-    private static final int IPV6_TCP_SEQ_NUM_OFFSET     = IPV6_PAYLOAD_OFFSET + 4;
-    private static final int IPV6_TCP_ACK_NUM_OFFSET     = IPV6_PAYLOAD_OFFSET + 8;
     // The IPv6 all nodes address ff02::1
     private static final byte[] IPV6_ALL_NODES_ADDRESS   =
             { (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
@@ -1096,25 +1099,18 @@ public class ApfTest {
     private static final int ICMP6_TYPE_OFFSET           = IP_HEADER_OFFSET + IPV6_HEADER_LEN;
     private static final int ICMP6_ROUTER_SOLICITATION   = 133;
     private static final int ICMP6_ROUTER_ADVERTISEMENT  = 134;
-    private static final int ICMP6_NEIGHBOR_SOLICITATION = 135;
     private static final int ICMP6_NEIGHBOR_ANNOUNCEMENT = 136;
 
     private static final int ICMP6_RA_HEADER_LEN = 16;
     private static final int ICMP6_RA_CHECKSUM_OFFSET =
             IP_HEADER_OFFSET + IPV6_HEADER_LEN + 2;
-    private static final int ICMP6_RA_ROUTER_LIFETIME_OFFSET =
-            IP_HEADER_OFFSET + IPV6_HEADER_LEN + 6;
     private static final int ICMP6_RA_REACHABLE_TIME_OFFSET =
             IP_HEADER_OFFSET + IPV6_HEADER_LEN + 8;
-    private static final int ICMP6_RA_RETRANSMISSION_TIMER_OFFSET =
-            IP_HEADER_OFFSET + IPV6_HEADER_LEN + 12;
     private static final int ICMP6_RA_OPTION_OFFSET =
             IP_HEADER_OFFSET + IPV6_HEADER_LEN + ICMP6_RA_HEADER_LEN;
 
     private static final int ICMP6_PREFIX_OPTION_TYPE                      = 3;
     private static final int ICMP6_PREFIX_OPTION_LEN                       = 32;
-    private static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET     = 4;
-    private static final int ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_OFFSET = 8;
 
     // From RFC6106: Recursive DNS Server option
     private static final int ICMP6_RDNSS_OPTION_TYPE = 25;
@@ -1125,8 +1121,6 @@ public class ApfTest {
     private static final int ICMP6_ROUTE_INFO_OPTION_TYPE = 24;
     // Above three options all have the same format:
     private static final int ICMP6_4_BYTE_OPTION_LEN      = 8;
-    private static final int ICMP6_4_BYTE_LIFETIME_OFFSET = 4;
-    private static final int ICMP6_4_BYTE_LIFETIME_LEN    = 4;
 
     private static final int UDP_HEADER_LEN              = 8;
     private static final int UDP_DESTINATION_PORT_OFFSET = ETH_HEADER_LEN + 22;
@@ -1164,7 +1158,6 @@ public class ApfTest {
     private static final byte[] IPV4_MDNS_MULTICAST_ADDR = {(byte) 224, 0, 0, (byte) 251};
     private static final byte[] IPV6_MDNS_MULTICAST_ADDR =
             {(byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfb};
-    private static final int IPV6_UDP_DEST_PORT_OFFSET = IPV6_PAYLOAD_OFFSET + 2;
     private static final int MDNS_UDP_PORT = 5353;
 
     private static void setIpv4VersionFields(ByteBuffer packet) {
@@ -1193,18 +1186,17 @@ public class ApfTest {
 
     @Test
     public void testApfFilterIPv4() throws Exception {
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         LinkAddress link = new LinkAddress(InetAddress.getByAddress(MOCK_IPV4_ADDR), 19);
         LinkProperties lp = new LinkProperties();
         lp.addLinkAddress(link);
 
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         apfFilter.setLinkProperties(lp);
 
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
         if (SdkLevel.isAtLeastV()) {
@@ -1216,7 +1208,7 @@ public class ApfTest {
         }
 
         // Verify unicast IPv4 packet is passed
-        put(packet, ETH_DEST_ADDR_OFFSET, TestApfFilter.MOCK_MAC_ADDR);
+        put(packet, ETH_DEST_ADDR_OFFSET, TEST_MAC_ADDR);
         packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
         put(packet, IPV4_DEST_ADDR_OFFSET, MOCK_IPV4_ADDR);
         assertPass(program, packet.array());
@@ -1244,21 +1236,19 @@ public class ApfTest {
         assertDrop(program, packet.array());
 
         // Verify broadcast IPv4 DHCP to us is passed
-        put(packet, DHCP_CLIENT_MAC_OFFSET, TestApfFilter.MOCK_MAC_ADDR);
+        put(packet, DHCP_CLIENT_MAC_OFFSET, TEST_MAC_ADDR);
         assertPass(program, packet.array());
 
         // Verify unicast IPv4 DHCP to us is passed
-        put(packet, ETH_DEST_ADDR_OFFSET, TestApfFilter.MOCK_MAC_ADDR);
+        put(packet, ETH_DEST_ADDR_OFFSET, TEST_MAC_ADDR);
         assertPass(program, packet.array());
     }
 
     @Test
     public void testApfFilterIPv6() throws Exception {
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify empty IPv6 packet is passed
         ByteBuffer packet = makeIpv6Packet(IPPROTO_UDP);
@@ -1473,12 +1463,12 @@ public class ApfTest {
 
     @Test
     public void testAddNopAddsOneByte() throws Exception {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addNop();
         assertEquals(1, gen.generate().length);
 
         final int count = 42;
-        gen = new ApfV4Generator(APF_VERSION_2);
+        gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         for (int i = 0; i < count; i++) {
             gen.addNop();
         }
@@ -1486,7 +1476,7 @@ public class ApfTest {
     }
 
     private ApfV4Generator generateDnsFilter(boolean ipv6, String... labels) throws Exception {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_2, mRamSize, mClampSize);
         gen.addLoadImmediate(R1, ipv6 ? IPV6_HEADER_LEN : IPV4_HEADER_LEN);
         DnsUtils.generateFilter(gen, labels);
         return gen;
@@ -1664,18 +1654,17 @@ public class ApfTest {
         final byte[] multicastIpv4Addr = {(byte)224,0,0,1};
         final byte[] multicastIpv6Addr = {(byte)0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,(byte)0xfb};
 
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         LinkAddress link = new LinkAddress(InetAddress.getByAddress(unicastIpv4Addr), 24);
         LinkProperties lp = new LinkProperties();
         lp.addLinkAddress(link);
 
         ApfConfiguration config = getDefaultConfig();
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         apfFilter.setLinkProperties(lp);
 
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Construct IPv4 and IPv6 multicast packets.
         ByteBuffer mcastv4packet = makeIpv4Packet(IPPROTO_UDP);
@@ -1697,7 +1686,7 @@ public class ApfTest {
 
         // Construct IPv4 broadcast with L2 unicast address packet (b/30231088).
         ByteBuffer bcastv4unicastl2packet = makeIpv4Packet(IPPROTO_UDP);
-        bcastv4unicastl2packet.put(TestApfFilter.MOCK_MAC_ADDR);
+        bcastv4unicastl2packet.put(TEST_MAC_ADDR);
         bcastv4unicastl2packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
         put(bcastv4unicastl2packet, IPV4_DEST_ADDR_OFFSET, broadcastIpv4Addr);
 
@@ -1709,9 +1698,8 @@ public class ApfTest {
         assertPass(program, bcastv4unicastl2packet.array());
 
         // Turn on multicast filter and verify it works
-        ipClientCallback.resetApfProgramWait();
         apfFilter.setMulticastFilter(true);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, mcastv4packet.array());
         assertDrop(program, mcastv6packet.array());
         assertDrop(program, bcastv4packet1.array());
@@ -1719,9 +1707,8 @@ public class ApfTest {
         assertDrop(program, bcastv4unicastl2packet.array());
 
         // Turn off multicast filter and verify it's off
-        ipClientCallback.resetApfProgramWait();
         apfFilter.setMulticastFilter(false);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertPass(program, mcastv4packet.array());
         assertPass(program, mcastv6packet.array());
         assertPass(program, bcastv4packet1.array());
@@ -1729,13 +1716,13 @@ public class ApfTest {
         assertPass(program, bcastv4unicastl2packet.array());
 
         // Verify it can be initialized to on
-        ipClientCallback.resetApfProgramWait();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        apfFilter = new TestApfFilter(mContext, config, ipClientCallback, mNetworkQuirkMetrics,
-                mDependencies);
-        apfFilter.setLinkProperties(lp);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        clearInvocations(mIpClientCb);
+        final ApfFilter apfFilter2 = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        apfFilter2.setLinkProperties(lp);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, mcastv4packet.array());
         assertDrop(program, mcastv6packet.array());
         assertDrop(program, bcastv4packet1.array());
@@ -1757,32 +1744,13 @@ public class ApfTest {
         doTestApfFilterMulticastPingWhileDozing(true /* isLightDozing */);
     }
 
-    @Test
-    @DevSdkIgnoreRule.IgnoreUpTo(Build.VERSION_CODES.TIRAMISU)
-    public void testShouldHandleLightDozeKillSwitch() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
-        final ApfConfiguration configuration = getDefaultConfig();
-        configuration.shouldHandleLightDoze = false;
-        final ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback,
-                configuration, mNetworkQuirkMetrics, mDependencies);
-        final ArgumentCaptor<BroadcastReceiver> receiverCaptor =
-                ArgumentCaptor.forClass(BroadcastReceiver.class);
-        verify(mDependencies).addDeviceIdleReceiver(receiverCaptor.capture(), anyBoolean());
-        final BroadcastReceiver receiver = receiverCaptor.getValue();
-        doReturn(true).when(mPowerManager).isDeviceLightIdleMode();
-        receiver.onReceive(mContext, new Intent(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED));
-        assertFalse(apfFilter.isInDozeMode());
-    }
-
     private void doTestApfFilterMulticastPingWhileDozing(boolean isLightDozing) throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration configuration = getDefaultConfig();
-        configuration.shouldHandleLightDoze = true;
-        final ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback,
-                configuration, mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(configuration);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         final ArgumentCaptor<BroadcastReceiver> receiverCaptor =
                 ArgumentCaptor.forClass(BroadcastReceiver.class);
-        verify(mDependencies).addDeviceIdleReceiver(receiverCaptor.capture(), anyBoolean());
+        verify(mDependencies).addDeviceIdleReceiver(receiverCaptor.capture());
         final BroadcastReceiver receiver = receiverCaptor.getValue();
 
         // Construct a multicast ICMPv6 ECHO request.
@@ -1792,7 +1760,7 @@ public class ApfTest {
         put(packet, IPV6_DEST_ADDR_OFFSET, multicastIpv6Addr);
 
         // Normally, we let multicast pings alone...
-        assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
+        assertPass(program, packet.array());
 
         if (isLightDozing) {
             doReturn(true).when(mPowerManager).isDeviceLightIdleMode();
@@ -1801,19 +1769,21 @@ public class ApfTest {
             doReturn(true).when(mPowerManager).isDeviceIdleMode();
             receiver.onReceive(mContext, new Intent(ACTION_DEVICE_IDLE_MODE_CHANGED));
         }
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         // ...and even while dozing...
-        assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
+        assertPass(program, packet.array());
 
         // ...but when the multicast filter is also enabled, drop the multicast pings to save power.
         apfFilter.setMulticastFilter(true);
-        assertDrop(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        assertDrop(program, packet.array());
 
         // However, we should still let through all other ICMPv6 types.
         ByteBuffer raPacket = ByteBuffer.wrap(packet.array().clone());
         setIpv6VersionFields(packet);
         packet.put(IPV6_NEXT_HEADER_OFFSET, (byte) IPPROTO_ICMPV6);
         raPacket.put(ICMP6_TYPE_OFFSET, (byte) NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT);
-        assertPass(ipClientCallback.assertProgramUpdateAndGet(), raPacket.array());
+        assertPass(program, raPacket.array());
 
         // Now wake up from doze mode to ensure that we no longer drop the packets.
         // (The multicast filter is still enabled at this point).
@@ -1824,17 +1794,16 @@ public class ApfTest {
             doReturn(false).when(mPowerManager).isDeviceIdleMode();
             receiver.onReceive(mContext, new Intent(ACTION_DEVICE_IDLE_MODE_CHANGED));
         }
-        assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        assertPass(program, packet.array());
     }
 
     @Test
     @DevSdkIgnoreRule.IgnoreAfter(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
     public void testApfFilter802_3() throws Exception {
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify empty packet of 100 zero bytes is passed
         // Note that eth-type = 0 makes it an IEEE802.3 frame
@@ -1850,11 +1819,9 @@ public class ApfTest {
         assertPass(program, packet.array());
 
         // Now turn on the filter
-        ipClientCallback.resetApfProgramWait();
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        apfFilter = getApfFilter(config);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify that IEEE802.3 frame is dropped
         // In this case ethtype is used for payload length
@@ -1877,11 +1844,9 @@ public class ApfTest {
         final int[] ipv4BlackList = {ETH_P_IP};
         final int[] ipv4Ipv6BlackList = {ETH_P_IP, ETH_P_IPV6};
 
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify empty packet of 100 zero bytes is passed
         // Note that eth-type = 0 makes it an IEEE802.3 frame
@@ -1897,11 +1862,9 @@ public class ApfTest {
         assertPass(program, packet.array());
 
         // Now add IPv4 to the black list
-        ipClientCallback.resetApfProgramWait();
         config.ethTypeBlackList = ipv4BlackList;
-        apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        apfFilter = getApfFilter(config);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify that IPv4 frame will be dropped
         setIpv4VersionFields(packet);
@@ -1912,11 +1875,9 @@ public class ApfTest {
         assertPass(program, packet.array());
 
         // Now let us have both IPv4 and IPv6 in the black list
-        ipClientCallback.resetApfProgramWait();
         config.ethTypeBlackList = ipv4Ipv6BlackList;
-        apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        apfFilter = getApfFilter(config);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify that IPv4 frame will be dropped
         setIpv4VersionFields(packet);
@@ -1927,12 +1888,6 @@ public class ApfTest {
         assertDrop(program, packet.array());
     }
 
-    private byte[] getProgram(MockIpClientCallback cb, ApfFilter filter, LinkProperties lp) {
-        cb.resetApfProgramWait();
-        filter.setLinkProperties(lp);
-        return cb.assertProgramUpdateAndGet();
-    }
-
     private void verifyArpFilter(byte[] program, int filterResult) {
         // Verify ARP request packet
         assertPass(program, arpRequestBroadcast(MOCK_IPV4_ADDR));
@@ -1956,24 +1911,27 @@ public class ApfTest {
 
     @Test
     public void testApfFilterArp() throws Exception {
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Verify initially ARP request filter is off, and GARP filter is on.
-        verifyArpFilter(ipClientCallback.assertProgramUpdateAndGet(), PASS);
+        verifyArpFilter(program, PASS);
 
         // Inform ApfFilter of our address and verify ARP filtering is on
         LinkAddress linkAddress = new LinkAddress(InetAddress.getByAddress(MOCK_IPV4_ADDR), 24);
         LinkProperties lp = new LinkProperties();
         assertTrue(lp.addLinkAddress(linkAddress));
-        verifyArpFilter(getProgram(ipClientCallback, apfFilter, lp), DROP);
+        apfFilter.setLinkProperties(lp);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        verifyArpFilter(program, DROP);
 
+        apfFilter.setLinkProperties(new LinkProperties());
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         // Inform ApfFilter of loss of IP and verify ARP filtering is off
-        verifyArpFilter(getProgram(ipClientCallback, apfFilter, new LinkProperties()), PASS);
+        verifyArpFilter(program, PASS);
     }
 
     private static byte[] arpReply(byte[] sip, byte[] tip) {
@@ -2003,282 +1961,9 @@ public class ApfTest {
         return packet.array();
     }
 
-    private static final byte[] IPV4_KEEPALIVE_SRC_ADDR = {10, 0, 0, 5};
-    private static final byte[] IPV4_KEEPALIVE_DST_ADDR = {10, 0, 0, 6};
-    private static final byte[] IPV4_ANOTHER_ADDR = {10, 0 , 0, 7};
-    private static final byte[] IPV6_KEEPALIVE_SRC_ADDR =
-            {(byte) 0x24, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfa, (byte) 0xf1};
-    private static final byte[] IPV6_KEEPALIVE_DST_ADDR =
-            {(byte) 0x24, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfa, (byte) 0xf2};
     private static final byte[] IPV6_ANOTHER_ADDR =
             {(byte) 0x24, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfa, (byte) 0xf5};
 
-    @Test
-    public void testApfFilterKeepaliveAck() throws Exception {
-        final MockIpClientCallback cb = new MockIpClientCallback();
-        final ApfConfiguration config = getDefaultConfig();
-        config.multicastFilter = DROP_MULTICAST;
-        config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program;
-        final int srcPort = 12345;
-        final int dstPort = 54321;
-        final int seqNum = 2123456789;
-        final int ackNum = 1234567890;
-        final int anotherSrcPort = 23456;
-        final int anotherDstPort = 65432;
-        final int anotherSeqNum = 2123456780;
-        final int anotherAckNum = 1123456789;
-        final int slot1 = 1;
-        final int slot2 = 2;
-        final int window = 14480;
-        final int windowScale = 4;
-
-        // src: 10.0.0.5, port: 12345
-        // dst: 10.0.0.6, port: 54321
-        InetAddress srcAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_SRC_ADDR);
-        InetAddress dstAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_DST_ADDR);
-
-        final TcpKeepalivePacketDataParcelable parcel = new TcpKeepalivePacketDataParcelable();
-        parcel.srcAddress = srcAddr.getAddress();
-        parcel.srcPort = srcPort;
-        parcel.dstAddress = dstAddr.getAddress();
-        parcel.dstPort = dstPort;
-        parcel.seq = seqNum;
-        parcel.ack = ackNum;
-
-        apfFilter.addTcpKeepalivePacketFilter(slot1, parcel);
-        program = cb.assertProgramUpdateAndGet();
-
-        // Verify IPv4 keepalive ack packet is dropped
-        // src: 10.0.0.6, port: 54321
-        // dst: 10.0.0.5, port: 12345
-        assertDrop(program,
-                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, ackNum, seqNum + 1, 0 /* dataLength */));
-        // Verify IPv4 non-keepalive ack packet from the same source address is passed
-        assertPass(program,
-                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, ackNum + 100, seqNum, 0 /* dataLength */));
-        assertPass(program,
-                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, ackNum, seqNum + 1, 10 /* dataLength */));
-        // Verify IPv4 packet from another address is passed
-        assertPass(program,
-                ipv4TcpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR, anotherSrcPort,
-                        anotherDstPort, anotherSeqNum, anotherAckNum, 0 /* dataLength */));
-
-        // Remove IPv4 keepalive filter
-        apfFilter.removeKeepalivePacketFilter(slot1);
-
-        try {
-            // src: 2404:0:0:0:0:0:faf1, port: 12345
-            // dst: 2404:0:0:0:0:0:faf2, port: 54321
-            srcAddr = InetAddress.getByAddress(IPV6_KEEPALIVE_SRC_ADDR);
-            dstAddr = InetAddress.getByAddress(IPV6_KEEPALIVE_DST_ADDR);
-
-            final TcpKeepalivePacketDataParcelable ipv6Parcel =
-                    new TcpKeepalivePacketDataParcelable();
-            ipv6Parcel.srcAddress = srcAddr.getAddress();
-            ipv6Parcel.srcPort = srcPort;
-            ipv6Parcel.dstAddress = dstAddr.getAddress();
-            ipv6Parcel.dstPort = dstPort;
-            ipv6Parcel.seq = seqNum;
-            ipv6Parcel.ack = ackNum;
-
-            apfFilter.addTcpKeepalivePacketFilter(slot1, ipv6Parcel);
-            program = cb.assertProgramUpdateAndGet();
-
-            // Verify IPv6 keepalive ack packet is dropped
-            // src: 2404:0:0:0:0:0:faf2, port: 54321
-            // dst: 2404:0:0:0:0:0:faf1, port: 12345
-            assertDrop(program,
-                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
-                            dstPort, srcPort, ackNum, seqNum + 1));
-            // Verify IPv6 non-keepalive ack packet from the same source address is passed
-            assertPass(program,
-                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
-                            dstPort, srcPort, ackNum + 100, seqNum));
-            // Verify IPv6 packet from another address is passed
-            assertPass(program,
-                    ipv6TcpPacket(IPV6_ANOTHER_ADDR, IPV6_KEEPALIVE_SRC_ADDR, anotherSrcPort,
-                            anotherDstPort, anotherSeqNum, anotherAckNum));
-
-            // Remove IPv6 keepalive filter
-            apfFilter.removeKeepalivePacketFilter(slot1);
-
-            // Verify multiple filters
-            apfFilter.addTcpKeepalivePacketFilter(slot1, parcel);
-            apfFilter.addTcpKeepalivePacketFilter(slot2, ipv6Parcel);
-            program = cb.assertProgramUpdateAndGet();
-
-            // Verify IPv4 keepalive ack packet is dropped
-            // src: 10.0.0.6, port: 54321
-            // dst: 10.0.0.5, port: 12345
-            assertDrop(program,
-                    ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                            dstPort, srcPort, ackNum, seqNum + 1, 0 /* dataLength */));
-            // Verify IPv4 non-keepalive ack packet from the same source address is passed
-            assertPass(program,
-                    ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                            dstPort, srcPort, ackNum + 100, seqNum, 0 /* dataLength */));
-            // Verify IPv4 packet from another address is passed
-            assertPass(program,
-                    ipv4TcpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR, anotherSrcPort,
-                            anotherDstPort, anotherSeqNum, anotherAckNum, 0 /* dataLength */));
-
-            // Verify IPv6 keepalive ack packet is dropped
-            // src: 2404:0:0:0:0:0:faf2, port: 54321
-            // dst: 2404:0:0:0:0:0:faf1, port: 12345
-            assertDrop(program,
-                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
-                            dstPort, srcPort, ackNum, seqNum + 1));
-            // Verify IPv6 non-keepalive ack packet from the same source address is passed
-            assertPass(program,
-                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
-                            dstPort, srcPort, ackNum + 100, seqNum));
-            // Verify IPv6 packet from another address is passed
-            assertPass(program,
-                    ipv6TcpPacket(IPV6_ANOTHER_ADDR, IPV6_KEEPALIVE_SRC_ADDR, anotherSrcPort,
-                            anotherDstPort, anotherSeqNum, anotherAckNum));
-
-            // Remove keepalive filters
-            apfFilter.removeKeepalivePacketFilter(slot1);
-            apfFilter.removeKeepalivePacketFilter(slot2);
-        } catch (UnsupportedOperationException e) {
-            // TODO: support V6 packets
-        }
-
-        program = cb.assertProgramUpdateAndGet();
-
-        // Verify IPv4, IPv6 packets are passed
-        assertPass(program,
-                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, ackNum, seqNum + 1, 0 /* dataLength */));
-        assertPass(program,
-                ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, ackNum, seqNum + 1));
-        assertPass(program,
-                ipv4TcpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR, srcPort,
-                        dstPort, anotherSeqNum, anotherAckNum, 0 /* dataLength */));
-        assertPass(program,
-                ipv6TcpPacket(IPV6_ANOTHER_ADDR, IPV6_KEEPALIVE_SRC_ADDR, srcPort,
-                        dstPort, anotherSeqNum, anotherAckNum));
-    }
-
-    private static byte[] ipv4TcpPacket(byte[] sip, byte[] dip, int sport,
-            int dport, int seq, int ack, int dataLength) {
-        final int totalLength = dataLength + IPV4_HEADER_LEN + IPV4_TCP_HEADER_LEN;
-
-        ByteBuffer packet = ByteBuffer.wrap(new byte[totalLength + ETH_HEADER_LEN]);
-
-        // Ethertype and IPv4 header
-        setIpv4VersionFields(packet);
-        packet.putShort(IPV4_TOTAL_LENGTH_OFFSET, (short) totalLength);
-        packet.put(IPV4_PROTOCOL_OFFSET, (byte) IPPROTO_TCP);
-        put(packet, IPV4_SRC_ADDR_OFFSET, sip);
-        put(packet, IPV4_DEST_ADDR_OFFSET, dip);
-        packet.putShort(IPV4_TCP_SRC_PORT_OFFSET, (short) sport);
-        packet.putShort(IPV4_TCP_DEST_PORT_OFFSET, (short) dport);
-        packet.putInt(IPV4_TCP_SEQ_NUM_OFFSET, seq);
-        packet.putInt(IPV4_TCP_ACK_NUM_OFFSET, ack);
-
-        // TCP header length 5(20 bytes), reserved 3 bits, NS=0
-        packet.put(IPV4_TCP_HEADER_LENGTH_OFFSET, (byte) 0x50);
-        // TCP flags: ACK set
-        packet.put(IPV4_TCP_HEADER_FLAG_OFFSET, (byte) 0x10);
-        return packet.array();
-    }
-
-    private static byte[] ipv6TcpPacket(byte[] sip, byte[] tip, int sport,
-            int dport, int seq, int ack) {
-        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
-        setIpv6VersionFields(packet);
-        packet.put(IPV6_NEXT_HEADER_OFFSET, (byte) IPPROTO_TCP);
-        put(packet, IPV6_SRC_ADDR_OFFSET, sip);
-        put(packet, IPV6_DEST_ADDR_OFFSET, tip);
-        packet.putShort(IPV6_TCP_SRC_PORT_OFFSET, (short) sport);
-        packet.putShort(IPV6_TCP_DEST_PORT_OFFSET, (short) dport);
-        packet.putInt(IPV6_TCP_SEQ_NUM_OFFSET, seq);
-        packet.putInt(IPV6_TCP_ACK_NUM_OFFSET, ack);
-        return packet.array();
-    }
-
-    @Test
-    public void testApfFilterNattKeepalivePacket() throws Exception {
-        final MockIpClientCallback cb = new MockIpClientCallback();
-        final ApfConfiguration config = getDefaultConfig();
-        config.multicastFilter = DROP_MULTICAST;
-        config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program;
-        final int srcPort = 1024;
-        final int dstPort = 4500;
-        final int slot1 = 1;
-        // NAT-T keepalive
-        final byte[] kaPayload = {(byte) 0xff};
-        final byte[] nonKaPayload = {(byte) 0xfe};
-
-        // src: 10.0.0.5, port: 1024
-        // dst: 10.0.0.6, port: 4500
-        InetAddress srcAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_SRC_ADDR);
-        InetAddress dstAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_DST_ADDR);
-
-        final NattKeepalivePacketDataParcelable parcel = new NattKeepalivePacketDataParcelable();
-        parcel.srcAddress = srcAddr.getAddress();
-        parcel.srcPort = srcPort;
-        parcel.dstAddress = dstAddr.getAddress();
-        parcel.dstPort = dstPort;
-
-        apfFilter.addNattKeepalivePacketFilter(slot1, parcel);
-        program = cb.assertProgramUpdateAndGet();
-
-        // Verify IPv4 keepalive packet is dropped
-        // src: 10.0.0.6, port: 4500
-        // dst: 10.0.0.5, port: 1024
-        byte[] pkt = ipv4UdpPacket(IPV4_KEEPALIVE_DST_ADDR,
-                    IPV4_KEEPALIVE_SRC_ADDR, dstPort, srcPort, 1 /* dataLength */);
-        System.arraycopy(kaPayload, 0, pkt, IPV4_UDP_PAYLOAD_OFFSET, kaPayload.length);
-        assertDrop(program, pkt);
-
-        // Verify a packet with payload length 1 byte but it is not 0xff will pass the filter.
-        System.arraycopy(nonKaPayload, 0, pkt, IPV4_UDP_PAYLOAD_OFFSET, nonKaPayload.length);
-        assertPass(program, pkt);
-
-        // Verify IPv4 non-keepalive response packet from the same source address is passed
-        assertPass(program,
-                ipv4UdpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, 10 /* dataLength */));
-
-        // Verify IPv4 non-keepalive response packet from other source address is passed
-        assertPass(program,
-                ipv4UdpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
-                        dstPort, srcPort, 10 /* dataLength */));
-
-        apfFilter.removeKeepalivePacketFilter(slot1);
-    }
-
-    private static byte[] ipv4UdpPacket(byte[] sip, byte[] dip, int sport,
-            int dport, int dataLength) {
-        final int totalLength = dataLength + IPV4_HEADER_LEN + UDP_HEADER_LEN;
-        final int udpLength = UDP_HEADER_LEN + dataLength;
-        ByteBuffer packet = ByteBuffer.wrap(new byte[totalLength + ETH_HEADER_LEN]);
-
-        // Ethertype and IPv4 header
-        setIpv4VersionFields(packet);
-        packet.putShort(IPV4_TOTAL_LENGTH_OFFSET, (short) totalLength);
-        packet.put(IPV4_PROTOCOL_OFFSET, (byte) IPPROTO_UDP);
-        put(packet, IPV4_SRC_ADDR_OFFSET, sip);
-        put(packet, IPV4_DEST_ADDR_OFFSET, dip);
-        packet.putShort(IPV4_UDP_SRC_PORT_OFFSET, (short) sport);
-        packet.putShort(IPV4_UDP_DEST_PORT_OFFSET, (short) dport);
-        packet.putShort(IPV4_UDP_LENGTH_OFFSET, (short) udpLength);
-
-        return packet.array();
-    }
-
     private static class RaPacketBuilder {
         final ByteArrayOutputStream mPacket = new ByteArrayOutputStream();
         int mFlowLabel = 0x12345;
@@ -2458,10 +2143,8 @@ public class ApfTest {
 
     @Test
     public void testRaToString() throws Exception {
-        MockIpClientCallback cb = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb, mNetworkQuirkMetrics,
-                mDependencies);
+        ApfFilter apfFilter = getApfFilter(config);
 
         byte[] packet = buildLargeRa();
         ApfFilter.Ra ra = apfFilter.new Ra(packet, packet.length);
@@ -2511,29 +2194,31 @@ public class ApfTest {
 
     // Test that when ApfFilter is shown the given packet, it generates a program to filter it
     // for the given lifetime.
-    private void verifyRaLifetime(TestApfFilter apfFilter, MockIpClientCallback ipClientCallback,
-            ByteBuffer packet, int lifetime) throws IOException, ErrnoException {
+    private byte[] verifyRaLifetime(ByteBuffer packet, int lifetime)
+            throws IOException, ErrnoException {
         // Verify new program generated if ApfFilter witnesses RA
-        apfFilter.pretendPacketReceived(packet.array());
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        clearInvocations(mIpClientCb);
+        pretendPacketReceived(packet.array());
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         verifyRaLifetime(program, packet, lifetime);
+        return program;
     }
 
-    private void assertInvalidRa(TestApfFilter apfFilter, MockIpClientCallback ipClientCallback,
-            ByteBuffer packet) throws IOException, ErrnoException {
-        apfFilter.pretendPacketReceived(packet.array());
-        ipClientCallback.assertNoProgramUpdate();
+    private void assertInvalidRa(ByteBuffer packet)
+            throws IOException, ErrnoException, InterruptedException {
+        clearInvocations(mIpClientCb);
+        pretendPacketReceived(packet.array());
+        Thread.sleep(NO_CALLBACK_TIMEOUT_MS);
+        verify(mIpClientCb, never()).installPacketFilter(any());
     }
 
     @Test
     public void testApfFilterRa() throws Exception {
-        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         final int ROUTER_LIFETIME = 1000;
         final int PREFIX_VALID_LIFETIME = 200;
@@ -2548,7 +2233,7 @@ public class ApfTest {
         ByteBuffer basePacket = ByteBuffer.wrap(ra.build());
         assertPass(program, basePacket.array());
 
-        verifyRaLifetime(apfFilter, ipClientCallback, basePacket, ROUTER_LIFETIME);
+        verifyRaLifetime(basePacket, ROUTER_LIFETIME);
 
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         // Check that changes are ignored in every byte of the flow label.
@@ -2560,7 +2245,7 @@ public class ApfTest {
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addZeroLengthOption();
         ByteBuffer zeroLengthOptionPacket = ByteBuffer.wrap(ra.build());
-        assertInvalidRa(apfFilter, ipClientCallback, zeroLengthOptionPacket);
+        assertInvalidRa(zeroLengthOptionPacket);
 
         // Generate several RAs with different options and lifetimes, and verify when
         // ApfFilter is shown these packets, it generates programs to filter them for the
@@ -2568,43 +2253,39 @@ public class ApfTest {
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addPioOption(PREFIX_VALID_LIFETIME, PREFIX_PREFERRED_LIFETIME, "2001:db8::/64");
         ByteBuffer prefixOptionPacket = ByteBuffer.wrap(ra.build());
-        verifyRaLifetime(
-                apfFilter, ipClientCallback, prefixOptionPacket, PREFIX_PREFERRED_LIFETIME);
+        verifyRaLifetime(prefixOptionPacket, PREFIX_PREFERRED_LIFETIME);
 
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addRdnssOption(RDNSS_LIFETIME, "2001:4860:4860::8888", "2001:4860:4860::8844");
         ByteBuffer rdnssOptionPacket = ByteBuffer.wrap(ra.build());
-        verifyRaLifetime(apfFilter, ipClientCallback, rdnssOptionPacket, RDNSS_LIFETIME);
+        verifyRaLifetime(rdnssOptionPacket, RDNSS_LIFETIME);
 
         final int lowLifetime = 60;
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addRdnssOption(lowLifetime, "2620:fe::9");
         ByteBuffer lowLifetimeRdnssOptionPacket = ByteBuffer.wrap(ra.build());
-        verifyRaLifetime(apfFilter, ipClientCallback, lowLifetimeRdnssOptionPacket,
-                ROUTER_LIFETIME);
+        verifyRaLifetime(lowLifetimeRdnssOptionPacket, ROUTER_LIFETIME);
 
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addRioOption(ROUTE_LIFETIME, "64:ff9b::/96");
         ByteBuffer routeInfoOptionPacket = ByteBuffer.wrap(ra.build());
-        verifyRaLifetime(apfFilter, ipClientCallback, routeInfoOptionPacket, ROUTE_LIFETIME);
+        program = verifyRaLifetime(routeInfoOptionPacket, ROUTE_LIFETIME);
 
         // Check that RIOs differing only in the first 4 bytes are different.
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addRioOption(ROUTE_LIFETIME, "64:ff9b::/64");
         // Packet should be passed because it is different.
-        program = ipClientCallback.assertProgramUpdateAndGet();
         assertPass(program, ra.build());
 
         ra = new RaPacketBuilder(ROUTER_LIFETIME);
         ra.addDnsslOption(DNSSL_LIFETIME, "test.example.com", "one.more.example.com");
         ByteBuffer dnsslOptionPacket = ByteBuffer.wrap(ra.build());
-        verifyRaLifetime(apfFilter, ipClientCallback, dnsslOptionPacket, ROUTER_LIFETIME);
+        verifyRaLifetime(dnsslOptionPacket, ROUTER_LIFETIME);
 
         ByteBuffer largeRaPacket = ByteBuffer.wrap(buildLargeRa());
-        verifyRaLifetime(apfFilter, ipClientCallback, largeRaPacket, 300);
+        program = verifyRaLifetime(largeRaPacket, 300);
 
         // Verify that current program filters all the RAs (note: ApfFilter.MAX_RAS == 10).
-        program = ipClientCallback.assertProgramUpdateAndGet();
         verifyRaLifetime(program, basePacket, ROUTER_LIFETIME);
         verifyRaLifetime(program, newFlowLabelPacket, ROUTER_LIFETIME);
         verifyRaLifetime(program, prefixOptionPacket, PREFIX_PREFERRED_LIFETIME);
@@ -2617,13 +2298,11 @@ public class ApfTest {
 
     @Test
     public void testRaWithDifferentReachableTimeAndRetransTimer() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        final ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         final int RA_REACHABLE_TIME = 1800;
         final int RA_RETRANSMISSION_TIMER = 1234;
 
@@ -2637,8 +2316,8 @@ public class ApfTest {
         assertPass(program, raPacket);
 
         // Assume apf is shown the given RA, it generates program to filter it.
-        apfFilter.pretendPacketReceived(raPacket);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(raPacket);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, raPacket);
 
         // A packet with different reachable time should be passed.
@@ -2659,13 +2338,11 @@ public class ApfTest {
     @SuppressWarnings("ByteBufferBackingArray")
     @Test
     public void testRaWithProgramInstalledSomeTimeAfterLastSeen() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         final int routerLifetime = 1000;
         final int timePassedSeconds = 12;
@@ -2673,26 +2350,32 @@ public class ApfTest {
         // Verify that when the program is generated and installed some time after RA is last seen
         // it should be installed with the correct remaining lifetime.
         ByteBuffer basePacket = ByteBuffer.wrap(new RaPacketBuilder(routerLifetime).build());
-        verifyRaLifetime(apfFilter, ipClientCallback, basePacket, routerLifetime);
-        apfFilter.increaseCurrentTimeSeconds(timePassedSeconds);
+        verifyRaLifetime(basePacket, routerLifetime);
+
+        mCurrentTimeMs += timePassedSeconds * DateUtils.SECOND_IN_MILLIS;
+        doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
             apfFilter.installNewProgramLocked();
         }
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         verifyRaLifetime(program, basePacket, routerLifetime, timePassedSeconds);
 
         // Packet should be passed if the program is installed after 1/6 * lifetime from last seen
-        apfFilter.increaseCurrentTimeSeconds((int) (routerLifetime / 6) - timePassedSeconds - 1);
+        mCurrentTimeMs +=
+                ((routerLifetime / 6) - timePassedSeconds - 1) * DateUtils.SECOND_IN_MILLIS;
+        doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
             apfFilter.installNewProgramLocked();
         }
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, basePacket.array());
-        apfFilter.increaseCurrentTimeSeconds(1);
+
+        mCurrentTimeMs += DateUtils.SECOND_IN_MILLIS;
+        doReturn(mCurrentTimeMs).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
             apfFilter.installNewProgramLocked();
         }
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertPass(program, basePacket.array());
     }
 
@@ -2727,12 +2410,10 @@ public class ApfTest {
     public void testRaParsing() throws Exception {
         final int maxRandomPacketSize = 512;
         final Random r = new Random();
-        MockIpClientCallback cb = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb, mNetworkQuirkMetrics,
-                mDependencies);
+        ApfFilter apfFilter = getApfFilter(config);
         for (int i = 0; i < 1000; i++) {
             byte[] packet = new byte[r.nextInt(maxRandomPacketSize + 1)];
             r.nextBytes(packet);
@@ -2749,12 +2430,10 @@ public class ApfTest {
     public void testRaProcessing() throws Exception {
         final int maxRandomPacketSize = 512;
         final Random r = new Random();
-        MockIpClientCallback cb = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb, mNetworkQuirkMetrics,
-                mDependencies);
+        ApfFilter apfFilter = getApfFilter(config);
         for (int i = 0; i < 1000; i++) {
             byte[] packet = new byte[r.nextInt(maxRandomPacketSize + 1)];
             r.nextBytes(packet);
@@ -2768,34 +2447,32 @@ public class ApfTest {
 
     @Test
     public void testMatchedRaUpdatesLifetime() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, getDefaultConfig(),
-                ipClientCallback, mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(getDefaultConfig());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // lifetime dropped significantly, assert pass
         ra = new RaPacketBuilder(200 /* router lifetime */).build();
         assertPass(program, ra);
 
         // update program with the new RA
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // assert program was updated and new lifetimes were taken into account.
         assertDrop(program, ra);
     }
-
     @Test
     public void testProcessRaWithInfiniteLifeTimeWithoutCrash() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        TestApfFilter apfFilter;
+        ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         // Template packet:
         // Frame 1: 150 bytes on wire (1200 bits), 150 bytes captured (1200 bits)
         // Ethernet II, Src: Netgear_23:67:2c (28:c6:8e:23:67:2c), Dst: IPv6mcast_01 (33:33:00:00:00:01)
@@ -2843,13 +2520,11 @@ public class ApfTest {
         final String packetStringFmt = "33330000000128C68E23672C86DD60054C6B00603AFFFE800000000000002AC68EFFFE23672CFF02000000000000000000000000000186000ACD40C01B580000000000000000010128C68E23672C05010000000005DC030440C0%s000000002401FA000480F00000000000000000001903000000001B582401FA000480F000000000000000000107010000000927C0";
         final List<String> lifetimes = List.of("FFFFFFFF", "00000000", "00000001", "00001B58");
         for (String lifetime : lifetimes) {
-            apfFilter = new TestApfFilter(mContext, config, ipClientCallback, mNetworkQuirkMetrics,
-                    mDependencies);
             final byte[] ra = hexStringToByteArray(
                     String.format(packetStringFmt, lifetime + lifetime));
             // feed the RA into APF and generate the filter, the filter shouldn't crash.
-            apfFilter.pretendPacketReceived(ra);
-            ipClientCallback.assertProgramUpdateAndGet();
+            pretendPacketReceived(ra);
+            consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         }
     }
 
@@ -2857,20 +2532,19 @@ public class ApfTest {
     // Old lifetime is 0
     @Test
     public void testAcceptRaMinLftCase1a() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */)
                 .addPioOption(1800 /*valid*/, 0 /*preferred*/, "2001:db8::/64")
                 .build();
 
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2886,20 +2560,19 @@ public class ApfTest {
     // Old lifetime is > 0
     @Test
     public void testAcceptRaMinLftCase2a() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */)
                 .addPioOption(1800 /*valid*/, 100 /*preferred*/, "2001:db8::/64")
                 .build();
 
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2922,18 +2595,17 @@ public class ApfTest {
     // Old lifetime is 0
     @Test
     public void testAcceptRaMinLftCase1b() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(0 /* router lifetime */).build();
 
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2947,23 +2619,21 @@ public class ApfTest {
         assertPass(program, ra);
     }
 
-
     // Test for go/apf-ra-filter Case 2b.
     // Old lifetime is < accept_ra_min_lft (but not 0).
     @Test
     public void testAcceptRaMinLftCase2b() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(100 /* router lifetime */).build();
 
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -2989,18 +2659,17 @@ public class ApfTest {
     // Old lifetime is >= accept_ra_min_lft and <= 3 * accept_ra_min_lft
     @Test
     public void testAcceptRaMinLftCase3b() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(200 /* router lifetime */).build();
 
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -3022,18 +2691,17 @@ public class ApfTest {
     // Old lifetime is > 3 * accept_ra_min_lft
     @Test
     public void testAcceptRaMinLftCase4b() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
 
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped
         assertDrop(program, ra);
@@ -3061,17 +2729,16 @@ public class ApfTest {
 
     @Test
     public void testRaFilterIsUpdated() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Create an initial RA and build an APF program
         byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // repeated RA is dropped.
         assertDrop(program, ra);
@@ -3079,38 +2746,38 @@ public class ApfTest {
         // updated RA is passed, repeated RA is dropped after program update.
         ra = new RaPacketBuilder(599 /* router lifetime */).build();
         assertPass(program, ra);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(180 /* router lifetime */).build();
         assertPass(program, ra);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(0 /* router lifetime */).build();
         assertPass(program, ra);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(180 /* router lifetime */).build();
         assertPass(program, ra);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(599 /* router lifetime */).build();
         assertPass(program, ra);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, ra);
 
         ra = new RaPacketBuilder(1800 /* router lifetime */).build();
         assertPass(program, ra);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         assertDrop(program, ra);
     }
 
@@ -3133,18 +2800,12 @@ public class ApfTest {
         assertEquals(want, got);
     }
 
-    private TestAndroidPacketFilter makeTestApfFilter(ApfConfiguration config,
-            MockIpClientCallback ipClientCallback) throws Exception {
-        return new TestApfFilter(mContext, config, ipClientCallback, mNetworkQuirkMetrics,
-                    mDependencies, mClock);
-    }
-
-
     @Test
     public void testInstallPacketFilterFailure() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback(false);
+        doReturn(false).when(mIpClientCb).installPacketFilter(any());
         final ApfConfiguration config = getDefaultConfig();
-        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
+        final ApfFilter apfFilter = getApfFilter(config);
+
         verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
         verify(mNetworkQuirkMetrics).statsWrite();
         reset(mNetworkQuirkMetrics);
@@ -3158,27 +2819,27 @@ public class ApfTest {
 
     @Test
     public void testApfProgramOverSize() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
-        final ApfCapabilities capabilities = new ApfCapabilities(2, 512, ARPHRD_ETHER);
-        config.apfCapabilities = capabilities;
-        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        config.apfVersionSupported = 2;
+        config.apfRamSize = 512;
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         final byte[] ra = buildLargeRa();
-        apfFilter.pretendPacketReceived(ra);
+        pretendPacketReceived(ra);
         // The generated program size will be 529, which is larger than 512
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
         verify(mNetworkQuirkMetrics).statsWrite();
     }
 
     @Test
-    public void testGenerateApfProgramException() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
+    public void testGenerateApfProgramException() {
         final ApfConfiguration config = getDefaultConfig();
-        final TestAndroidPacketFilter apfFilter;
-        apfFilter = new TestApfFilter(mContext, config, ipClientCallback, mNetworkQuirkMetrics,
-                mDependencies, true /* throwsExceptionWhenGeneratesProgram */);
+        ApfFilter apfFilter = getApfFilter(config);
+        // Simulate exception during installNewProgramLocked() by mocking
+        // mDependencies.elapsedRealtime() to throw an exception (this method doesn't throw in
+        // real-world scenarios).
+        doThrow(new IllegalStateException("test exception")).when(mDependencies).elapsedRealtime();
         synchronized (apfFilter) {
             apfFilter.installNewProgramLocked();
         }
@@ -3188,17 +2849,16 @@ public class ApfTest {
 
     @Test
     public void testApfSessionInfoMetrics() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
-        final ApfCapabilities capabilities = new ApfCapabilities(4, 4096, ARPHRD_ETHER);
-        config.apfCapabilities = capabilities;
+        config.apfVersionSupported = 4;
+        config.apfRamSize = 4096;
         final long startTimeMs = 12345;
         final long durationTimeMs = config.minMetricsSessionDurationMs;
-        doReturn(startTimeMs).when(mClock).elapsedRealtime();
-        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
+        doReturn(startTimeMs).when(mDependencies).elapsedRealtime();
+        final ApfFilter apfFilter = getApfFilter(config);
+        byte[] program = consumeInstalledProgram(mIpClientCb, 2 /* installCnt */);
         int maxProgramSize = 0;
         int numProgramUpdated = 0;
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
         maxProgramSize = Math.max(maxProgramSize, program.length);
         numProgramUpdated++;
 
@@ -3215,14 +2875,14 @@ public class ApfTest {
         expectedData[totalPacketsCounterIdx + 3] += 1;
         expectedData[passedIpv6IcmpCounterIdx + 3] += 1;
         assertDataMemoryContentsIgnoreVersion(PASS, program, ra, data, expectedData);
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra);
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         maxProgramSize = Math.max(maxProgramSize, program.length);
         numProgramUpdated++;
 
         apfFilter.setMulticastFilter(true);
         // setMulticastFilter will trigger program installation.
-        program = ipClientCallback.assertProgramUpdateAndGet();
+        program = consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
         maxProgramSize = Math.max(maxProgramSize, program.length);
         numProgramUpdated++;
 
@@ -3239,8 +2899,10 @@ public class ApfTest {
         apfFilter.setDataSnapshot(data);
 
         // Write metrics data to statsd pipeline when shutdown.
-        doReturn(startTimeMs + durationTimeMs).when(mClock).elapsedRealtime();
-        apfFilter.shutdown();
+        doReturn(startTimeMs + durationTimeMs).when(mDependencies).elapsedRealtime();
+        mHandler.post(apfFilter::shutdown);
+        IoUtils.closeQuietly(mWriteSocket);
+        HandlerUtils.waitForIdle(mHandler, TIMEOUT_MS);
         verify(mApfSessionInfoMetrics).setVersion(4);
         verify(mApfSessionInfoMetrics).setMemorySize(4096);
 
@@ -3268,13 +2930,12 @@ public class ApfTest {
 
     @Test
     public void testIpClientRaInfoMetrics() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
         final long startTimeMs = 12345;
         final long durationTimeMs = config.minMetricsSessionDurationMs;
-        doReturn(startTimeMs).when(mClock).elapsedRealtime();
-        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
+        doReturn(startTimeMs).when(mDependencies).elapsedRealtime();
+        final ApfFilter apfFilter = getApfFilter(config);
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         final int routerLifetime = 1000;
         final int prefixValidLifetime = 200;
@@ -3311,24 +2972,27 @@ public class ApfTest {
 
         // Inject RA packets. Calling assertProgramUpdateAndGet()/assertNoProgramUpdate() is to make
         // sure that the RA packet has been processed.
-        apfFilter.pretendPacketReceived(ra1.build());
-        program = ipClientCallback.assertProgramUpdateAndGet();
-        apfFilter.pretendPacketReceived(ra2.build());
-        program = ipClientCallback.assertProgramUpdateAndGet();
-        apfFilter.pretendPacketReceived(raInvalid.build());
-        ipClientCallback.assertNoProgramUpdate();
-        apfFilter.pretendPacketReceived(raZeroRouterLifetime.build());
-        ipClientCallback.assertProgramUpdateAndGet();
-        apfFilter.pretendPacketReceived(raZeroPioValidLifetime.build());
-        ipClientCallback.assertProgramUpdateAndGet();
-        apfFilter.pretendPacketReceived(raZeroRdnssLifetime.build());
-        ipClientCallback.assertProgramUpdateAndGet();
-        apfFilter.pretendPacketReceived(raZeroRioRouteLifetime.build());
-        ipClientCallback.assertProgramUpdateAndGet();
+        pretendPacketReceived(ra1.build());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        pretendPacketReceived(ra2.build());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        pretendPacketReceived(raInvalid.build());
+        Thread.sleep(NO_CALLBACK_TIMEOUT_MS);
+        verify(mIpClientCb, never()).installPacketFilter(any());
+        pretendPacketReceived(raZeroRouterLifetime.build());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        pretendPacketReceived(raZeroPioValidLifetime.build());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        pretendPacketReceived(raZeroRdnssLifetime.build());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
+        pretendPacketReceived(raZeroRioRouteLifetime.build());
+        consumeInstalledProgram(mIpClientCb, 1 /* installCnt */);
 
         // Write metrics data to statsd pipeline when shutdown.
-        doReturn(startTimeMs + durationTimeMs).when(mClock).elapsedRealtime();
-        apfFilter.shutdown();
+        doReturn(startTimeMs + durationTimeMs).when(mDependencies).elapsedRealtime();
+        mHandler.post(apfFilter::shutdown);
+        IoUtils.closeQuietly(mWriteSocket);
+        HandlerUtils.waitForIdle(mHandler, TIMEOUT_MS);
 
         // Verify each metric fields in IpClientRaInfoMetrics.
         verify(mIpClientRaInfoMetrics).setMaxNumberOfDistinctRas(6);
@@ -3341,42 +3005,32 @@ public class ApfTest {
         verify(mIpClientRaInfoMetrics).statsWrite();
     }
 
-    private void verifyNoMetricsWrittenForShortDuration(boolean isLegacy) throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
+    @Test
+    public void testNoMetricsWrittenForShortDuration() throws Exception {
         final ApfConfiguration config = getDefaultConfig();
         final long startTimeMs = 12345;
         final long durationTimeMs = config.minMetricsSessionDurationMs;
 
         // Verify no metrics data written to statsd for duration less than durationTimeMs.
-        doReturn(startTimeMs).when(mClock).elapsedRealtime();
-        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
-        doReturn(startTimeMs + durationTimeMs - 1).when(mClock).elapsedRealtime();
-        apfFilter.shutdown();
+        doReturn(startTimeMs).when(mDependencies).elapsedRealtime();
+        final ApfFilter apfFilter = getApfFilter(config);
+        doReturn(startTimeMs + durationTimeMs - 1).when(mDependencies).elapsedRealtime();
+        mHandler.post(apfFilter::shutdown);
+        HandlerUtils.waitForIdle(mHandler, TIMEOUT_MS);
         verify(mApfSessionInfoMetrics, never()).statsWrite();
         verify(mIpClientRaInfoMetrics, never()).statsWrite();
 
         // Verify metrics data written to statsd for duration greater than or equal to
         // durationTimeMs.
-        ApfFilter.Clock clock = mock(ApfFilter.Clock.class);
-        doReturn(startTimeMs).when(clock).elapsedRealtime();
-        final TestAndroidPacketFilter apfFilter2 = new TestApfFilter(mContext, config,
-                ipClientCallback, mNetworkQuirkMetrics, mDependencies, clock);
-        doReturn(startTimeMs + durationTimeMs).when(clock).elapsedRealtime();
-        apfFilter2.shutdown();
+        doReturn(startTimeMs).when(mDependencies).elapsedRealtime();
+        final ApfFilter apfFilter2 = getApfFilter(config);
+        doReturn(startTimeMs + durationTimeMs).when(mDependencies).elapsedRealtime();
+        mHandler.post(apfFilter2::shutdown);
+        HandlerUtils.waitForIdle(mHandler, TIMEOUT_MS);
         verify(mApfSessionInfoMetrics).statsWrite();
         verify(mIpClientRaInfoMetrics).statsWrite();
     }
 
-    @Test
-    public void testNoMetricsWrittenForShortDuration() throws Exception {
-        verifyNoMetricsWrittenForShortDuration(false /* isLegacy */);
-    }
-
-    @Test
-    public void testNoMetricsWrittenForShortDuration_LegacyApfFilter() throws Exception {
-        verifyNoMetricsWrittenForShortDuration(true /* isLegacy */);
-    }
-
     private int deriveApfGeneratorVersion(ApfV4GeneratorBase<?> gen) {
         if (gen instanceof ApfV4Generator) {
             return 4;
@@ -3388,15 +3042,18 @@ public class ApfTest {
 
     @Test
     public void testApfGeneratorPropagation() throws IllegalInstructionException {
-        ApfV4Generator v4Gen = new ApfV4Generator(APF_VERSION_3);
-        ApfV6Generator v6Gen = new ApfV6Generator(1024);
+        ApfV4Generator v4Gen = new ApfV4Generator(APF_VERSION_3, 1024 /* ramSize */,
+                1024 /* clampSize */);
+        ApfV6Generator v6Gen = new ApfV6Generator(APF_VERSION_6, 1024 /* ramSize */,
+                1024 /* clampSize */);
         assertEquals(4, deriveApfGeneratorVersion(v4Gen));
         assertEquals(6, deriveApfGeneratorVersion(v6Gen));
     }
 
     @Test
     public void testFullApfV4ProgramGenerationIPV6() throws IllegalInstructionException {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, 1024 /* ramSize */,
+                1024 /* clampSize */);
         gen.addLoadImmediate(R1, -4);
         gen.addLoadData(R0, 0);
         gen.addAdd(1);
@@ -3549,7 +3206,8 @@ public class ApfTest {
 
     @Test
     public void testFullApfV4ProgramGenerationIPV4() throws IllegalInstructionException {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, 1024 /* ramSize */,
+                1024 /* clampSize */);
         gen.addLoadImmediate(R1, -4);
         gen.addLoadData(R0, 0);
         gen.addAdd(1);
@@ -3670,7 +3328,7 @@ public class ApfTest {
 
     @Test
     public void testFullApfV4ProgramGenerationNatTKeepAliveV4() throws IllegalInstructionException {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, true);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, mRamSize, mClampSize, true);
         gen.addLoadImmediate(R1, -4);
         gen.addLoadData(R0, 0);
         gen.addAdd(1);
@@ -3785,7 +3443,8 @@ public class ApfTest {
 
     @Test
     public void testInfiniteLifetimeFullApfV4ProgramGeneration() throws IllegalInstructionException {
-        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, true);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, 1024 /* ramSize */,
+                1024 /* clampSize */, true);
         gen.addLoadCounter(R0, getCounterEnumFromOffset(-8));
         gen.addAdd(1);
         gen.addStoreData(R0, 0);
diff --git a/tests/unit/src/android/net/apf/ApfTestHelpers.kt b/tests/unit/src/android/net/apf/ApfTestHelpers.kt
new file mode 100644
index 00000000..6a5688ed
--- /dev/null
+++ b/tests/unit/src/android/net/apf/ApfTestHelpers.kt
@@ -0,0 +1,334 @@
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
+package android.net.apf
+
+import android.net.apf.ApfCounterTracker.Counter
+import android.net.apf.ApfCounterTracker.Counter.APF_PROGRAM_ID
+import android.net.apf.ApfCounterTracker.Counter.APF_VERSION
+import android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS
+import android.net.apf.BaseApfGenerator.APF_VERSION_6
+import android.net.ip.IpClient
+import com.android.net.module.util.HexDump
+import kotlin.test.assertEquals
+import org.mockito.ArgumentCaptor
+import org.mockito.Mockito.clearInvocations
+import org.mockito.Mockito.timeout
+import org.mockito.Mockito.verify
+
+class ApfTestHelpers private constructor() {
+    companion object {
+        const val TIMEOUT_MS: Long = 1000
+        const val PASS: Int = 1
+        const val DROP: Int = 0
+
+        // Interpreter will just accept packets without link layer headers, so pad fake packet to at
+        // least the minimum packet size.
+        const val MIN_PKT_SIZE: Int = 15
+        private fun label(code: Int): String {
+            return when (code) {
+                PASS -> "PASS"
+                DROP -> "DROP"
+                else -> "UNKNOWN"
+            }
+        }
+
+        private fun assertReturnCodesEqual(msg: String, expected: Int, got: Int) {
+            assertEquals(label(expected), label(got), msg)
+        }
+
+        private fun assertReturnCodesEqual(expected: Int, got: Int) {
+            assertEquals(label(expected), label(got))
+        }
+
+        private fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray,
+            packet: ByteArray,
+            filterAge: Int
+        ) {
+            val msg = """Unexpected APF verdict. To debug:
+                apf_run
+                    --program ${HexDump.toHexString(program)}
+                    --packet ${HexDump.toHexString(packet)}
+                    --age $filterAge
+                    ${if (apfVersion > 4) " --v6" else ""}
+                    --trace " + " | less\n
+            """
+            assertReturnCodesEqual(
+                msg,
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
+            )
+        }
+
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        private fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            gen: ApfV4Generator,
+            packet: ByteArray,
+            filterAge: Int
+        ) {
+            assertVerdict(apfVersion, expected, gen.generate(), packet, null, filterAge)
+        }
+
+        private fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray,
+            packet: ByteArray,
+            data: ByteArray?,
+            filterAge: Int
+        ) {
+            val msg = """Unexpected APF verdict. To debug:
+                apf_run
+                    --program ${HexDump.toHexString(program)}
+                    --packet ${HexDump.toHexString(packet)}
+                    ${if (data != null) "--data ${HexDump.toHexString(data)}" else ""}
+                    --age $filterAge
+                    ${if (apfVersion > 4) "--v6" else ""}
+                    --trace | less
+            """
+            assertReturnCodesEqual(
+                msg,
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, data, filterAge)
+            )
+        }
+
+        /**
+         * Runs the APF program with customized data region and checks the return code.
+         */
+        fun assertVerdict(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray,
+            packet: ByteArray,
+            data: ByteArray?
+        ) {
+            assertVerdict(apfVersion, expected, program, packet, data, filterAge = 0)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is equals to expected value. If not, the
+         * customized message is printed.
+         */
+        @JvmStatic
+        fun assertVerdict(
+            apfVersion: Int,
+            msg: String,
+            expected: Int,
+            program: ByteArray?,
+            packet: ByteArray?,
+            filterAge: Int
+        ) {
+            assertReturnCodesEqual(
+                msg,
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
+            )
+        }
+
+        /**
+         * Runs the APF program and checks the return code is equals to expected value.
+         */
+        @JvmStatic
+        fun assertVerdict(apfVersion: Int, expected: Int, program: ByteArray, packet: ByteArray) {
+            assertVerdict(apfVersion, expected, program, packet, 0)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @JvmStatic
+        fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, PASS, program, packet, filterAge)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @JvmStatic
+        fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray) {
+            assertVerdict(apfVersion, PASS, program, packet)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, DROP, program, packet, filterAge)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray) {
+            assertVerdict(apfVersion, DROP, program, packet)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertPass(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, PASS, gen, packet, filterAge)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
+            assertVerdict(apfVersion, DROP, gen, packet, filterAge)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is PASS.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertPass(apfVersion: Int, gen: ApfV4Generator) {
+            assertVerdict(apfVersion, PASS, gen, ByteArray(MIN_PKT_SIZE), 0)
+        }
+
+        /**
+         * Runs the APF program and checks the return code is DROP.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class)
+        @JvmStatic
+        fun assertDrop(apfVersion: Int, gen: ApfV4Generator) {
+            assertVerdict(apfVersion, DROP, gen, ByteArray(MIN_PKT_SIZE), 0)
+        }
+
+        /**
+         * Checks the generated APF program equals to the expected value.
+         */
+        @Throws(AssertionError::class)
+        @JvmStatic
+        fun assertProgramEquals(expected: ByteArray, program: ByteArray?) {
+            // assertArrayEquals() would only print one byte, making debugging difficult.
+            if (!expected.contentEquals(program)) {
+                throw AssertionError(
+                    "\nexpected: " + HexDump.toHexString(expected) +
+                    "\nactual:   " + HexDump.toHexString(program)
+                )
+            }
+        }
+
+        /**
+         * Runs the APF program and checks the return code and data regions
+         * equals to expected value.
+         */
+        @Throws(BaseApfGenerator.IllegalInstructionException::class, Exception::class)
+        @JvmStatic
+        fun assertDataMemoryContents(
+            apfVersion: Int,
+            expected: Int,
+            program: ByteArray?,
+            packet: ByteArray?,
+            data: ByteArray,
+            expectedData: ByteArray,
+            ignoreInterpreterVersion: Boolean
+        ) {
+            assertReturnCodesEqual(
+                expected,
+                ApfJniUtils.apfSimulate(apfVersion, program, packet, data, 0)
+            )
+
+            if (ignoreInterpreterVersion) {
+                val apfVersionIdx = (Counter.totalSize() +
+                        APF_VERSION.offset())
+                val apfProgramIdIdx = (Counter.totalSize() +
+                        APF_PROGRAM_ID.offset())
+                for (i in 0..3) {
+                    data[apfVersionIdx + i] = 0
+                    data[apfProgramIdIdx + i] = 0
+                }
+            }
+            // assertArrayEquals() would only print one byte, making debugging difficult.
+            if (!expectedData.contentEquals(data)) {
+                throw Exception(
+                    ("\nprogram:     " + HexDump.toHexString(program) +
+                     "\ndata memory: " + HexDump.toHexString(data) +
+                     "\nexpected:    " + HexDump.toHexString(expectedData))
+                )
+            }
+        }
+
+        fun verifyProgramRun(
+            version: Int,
+            program: ByteArray,
+            pkt: ByteArray,
+            targetCnt: Counter,
+            cntMap: MutableMap<Counter, Long> = mutableMapOf(),
+            dataRegion: ByteArray = ByteArray(Counter.totalSize()) { 0 },
+            incTotal: Boolean = true,
+            result: Int = if (targetCnt.name.startsWith("PASSED")) PASS else DROP
+        ) {
+            assertVerdict(version, result, program, pkt, dataRegion)
+            cntMap[targetCnt] = cntMap.getOrDefault(targetCnt, 0) + 1
+            if (incTotal) {
+                cntMap[TOTAL_PACKETS] = cntMap.getOrDefault(TOTAL_PACKETS, 0) + 1
+            }
+            val errMsg = "Counter is not increased properly. To debug: \n" +
+                    " apf_run --program ${HexDump.toHexString(program)} " +
+                    "--packet ${HexDump.toHexString(pkt)} " +
+                    "--data ${HexDump.toHexString(dataRegion)} --age 0 " +
+                    "${if (version == APF_VERSION_6) "--v6" else "" } --trace  | less \n"
+            assertEquals(cntMap, decodeCountersIntoMap(dataRegion), errMsg)
+        }
+
+        fun decodeCountersIntoMap(counterBytes: ByteArray): Map<Counter, Long> {
+            val counters = Counter::class.java.enumConstants
+            val ret = HashMap<Counter, Long>()
+            val skippedCounters = setOf(APF_PROGRAM_ID, APF_VERSION)
+            // starting from index 2 to skip the endianness mark
+            if (counters != null) {
+                for (c in listOf(*counters).subList(2, counters.size)) {
+                    if (c in skippedCounters) continue
+                    val value = ApfCounterTracker.getCounterValue(counterBytes, c)
+                    if (value != 0L) {
+                        ret[c] = value
+                    }
+                }
+            }
+            return ret
+        }
+
+        @JvmStatic
+        fun consumeInstalledProgram(
+            ipClientCb: IpClient.IpClientCallbacksWrapper,
+            installCnt: Int
+        ): ByteArray {
+            val programCaptor = ArgumentCaptor.forClass(
+                ByteArray::class.java
+            )
+
+            verify(ipClientCb, timeout(TIMEOUT_MS).times(installCnt)).installPacketFilter(
+                programCaptor.capture()
+            )
+
+            clearInvocations<Any>(ipClientCb)
+            return programCaptor.value
+        }
+    }
+}
diff --git a/tests/unit/src/android/net/apf/ApfTestUtils.java b/tests/unit/src/android/net/apf/ApfTestUtils.java
deleted file mode 100644
index 0b3ea653..00000000
--- a/tests/unit/src/android/net/apf/ApfTestUtils.java
+++ /dev/null
@@ -1,506 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package android.net.apf;
-
-import static android.net.apf.ApfJniUtils.apfSimulate;
-import static android.system.OsConstants.AF_UNIX;
-import static android.system.OsConstants.SOCK_STREAM;
-
-import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
-import static org.junit.Assert.fail;
-import static org.mockito.Mockito.mock;
-
-import android.content.Context;
-import android.net.LinkAddress;
-import android.net.LinkProperties;
-import android.net.apf.BaseApfGenerator.IllegalInstructionException;
-import android.net.ip.IIpClientCallbacks;
-import android.net.ip.IpClient;
-import android.net.metrics.IpConnectivityLog;
-import android.os.ConditionVariable;
-import android.os.SystemClock;
-import android.system.ErrnoException;
-import android.system.Os;
-import android.text.format.DateUtils;
-
-import com.android.internal.annotations.GuardedBy;
-import com.android.internal.util.HexDump;
-import com.android.net.module.util.InterfaceParams;
-import com.android.net.module.util.SharedLog;
-import com.android.networkstack.apishim.NetworkInformationShimImpl;
-import com.android.networkstack.metrics.NetworkQuirkMetrics;
-
-import libcore.io.IoUtils;
-
-import java.io.FileDescriptor;
-import java.io.IOException;
-import java.net.InetAddress;
-import java.util.Arrays;
-
-/**
- * The util class for calling the APF interpreter and check the return value
- */
-public class ApfTestUtils {
-    public static final int TIMEOUT_MS = 500;
-    public static final int PASS = 1;
-    public static final int DROP = 0;
-    // Interpreter will just accept packets without link layer headers, so pad fake packet to at
-    // least the minimum packet size.
-    public static final int MIN_PKT_SIZE = 15;
-
-    private ApfTestUtils() {
-    }
-
-    private static String label(int code) {
-        switch (code) {
-            case PASS:
-                return "PASS";
-            case DROP:
-                return "DROP";
-            default:
-                return "UNKNOWN";
-        }
-    }
-
-    private static void assertReturnCodesEqual(String msg, int expected, int got) {
-        assertEquals(msg, label(expected), label(got));
-    }
-
-    private static void assertReturnCodesEqual(int expected, int got) {
-        assertEquals(label(expected), label(got));
-    }
-
-    private static void assertVerdict(int apfVersion, int expected, byte[] program, byte[] packet,
-            int filterAge) {
-        final String msg = "Unexpected APF verdict. To debug:\n"
-                + "  apf_run --program " + HexDump.toHexString(program)
-                + " --packet " + HexDump.toHexString(packet)
-                + " --age " + filterAge
-                + (apfVersion > 4 ? " --v6" : "")
-                + " --trace "  + " | less\n  ";
-        assertReturnCodesEqual(msg, expected,
-                apfSimulate(apfVersion, program, packet, null, filterAge));
-    }
-
-    /**
-     * Runs the APF program and checks the return code is equals to expected value. If not, the
-     * customized message is printed.
-     */
-    public static void assertVerdict(int apfVersion, String msg, int expected, byte[] program,
-            byte[] packet, int filterAge) {
-        assertReturnCodesEqual(msg, expected,
-                apfSimulate(apfVersion, program, packet, null, filterAge));
-    }
-
-    /**
-     * Runs the APF program and checks the return code is equals to expected value.
-     */
-    public static void assertVerdict(int apfVersion, int expected, byte[] program, byte[] packet) {
-        assertVerdict(apfVersion, expected, program, packet, 0);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    public static void assertPass(int apfVersion, byte[] program, byte[] packet, int filterAge) {
-        assertVerdict(apfVersion, PASS, program, packet, filterAge);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    public static void assertPass(int apfVersion, byte[] program, byte[] packet) {
-        assertVerdict(apfVersion, PASS, program, packet);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    public static void assertDrop(int apfVersion, byte[] program, byte[] packet, int filterAge) {
-        assertVerdict(apfVersion, DROP, program, packet, filterAge);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    public static void assertDrop(int apfVersion, byte[] program, byte[] packet) {
-        assertVerdict(apfVersion, DROP, program, packet);
-    }
-
-    /**
-     * Checks the generated APF program equals to the expected value.
-     */
-    public static void assertProgramEquals(byte[] expected, byte[] program) throws AssertionError {
-        // assertArrayEquals() would only print one byte, making debugging difficult.
-        if (!Arrays.equals(expected, program)) {
-            throw new AssertionError("\nexpected: " + HexDump.toHexString(expected) + "\nactual:   "
-                    + HexDump.toHexString(program));
-        }
-    }
-
-    /**
-     * Runs the APF program and checks the return code and data regions equals to expected value.
-     */
-    public static void assertDataMemoryContents(int apfVersion, int expected, byte[] program,
-            byte[] packet, byte[] data, byte[] expectedData, boolean ignoreInterpreterVersion)
-            throws ApfV4Generator.IllegalInstructionException, Exception {
-        assertReturnCodesEqual(expected,
-                apfSimulate(apfVersion, program, packet, data, 0 /* filterAge */));
-
-        if (ignoreInterpreterVersion) {
-            final int apfVersionIdx = ApfCounterTracker.Counter.totalSize()
-                    + ApfCounterTracker.Counter.APF_VERSION.offset();
-            final int apfProgramIdIdx = ApfCounterTracker.Counter.totalSize()
-                    + ApfCounterTracker.Counter.APF_PROGRAM_ID.offset();
-            for (int i = 0; i < 4; ++i) {
-                data[apfVersionIdx + i] = 0;
-                data[apfProgramIdIdx + i] = 0;
-            }
-        }
-        // assertArrayEquals() would only print one byte, making debugging difficult.
-        if (!Arrays.equals(expectedData, data)) {
-            throw new Exception("\nprogram:     " + HexDump.toHexString(program) + "\ndata memory: "
-                    + HexDump.toHexString(data) + "\nexpected:    " + HexDump.toHexString(
-                    expectedData));
-        }
-    }
-
-    /**
-     * Runs the APF program with customized data region and checks the return code.
-     */
-    public static void assertVerdict(int apfVersion, int expected, byte[] program, byte[] packet,
-            byte[] data) {
-        assertVerdict(apfVersion, expected, program, packet, data, 0 /* filterAge */);
-    }
-
-    private static void assertVerdict(int apfVersion, int expected, ApfV4Generator gen,
-            byte[] packet, int filterAge) throws ApfV4Generator.IllegalInstructionException {
-        assertVerdict(apfVersion, expected, gen.generate(), packet, null, filterAge);
-    }
-
-    private static void assertVerdict(int apfVersion, int expected, byte[] program, byte[] packet,
-            byte[] data, int filterAge) {
-        final String msg = "Unexpected APF verdict. To debug:\n"
-                + "  apf_run --program " + HexDump.toHexString(program)
-                + " --packet " + HexDump.toHexString(packet)
-                + (data != null ? " --data " + HexDump.toHexString(data) : "")
-                + " --age " + filterAge
-                + (apfVersion > 4 ? " --v6" : "")
-                + " --trace "  + " | less\n  ";
-        assertReturnCodesEqual(msg, expected,
-                apfSimulate(apfVersion, program, packet, data, filterAge));
-    }
-
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    public static void assertPass(int apfVersion, ApfV4Generator gen, byte[] packet, int filterAge)
-            throws ApfV4Generator.IllegalInstructionException {
-        assertVerdict(apfVersion, PASS, gen, packet, filterAge);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    public static void assertDrop(int apfVersion, ApfV4Generator gen, byte[] packet, int filterAge)
-            throws ApfV4Generator.IllegalInstructionException {
-        assertVerdict(apfVersion, DROP, gen, packet, filterAge);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is PASS.
-     */
-    public static void assertPass(int apfVersion, ApfV4Generator gen)
-            throws ApfV4Generator.IllegalInstructionException {
-        assertVerdict(apfVersion, PASS, gen, new byte[MIN_PKT_SIZE], 0);
-    }
-
-    /**
-     * Runs the APF program and checks the return code is DROP.
-     */
-    public static void assertDrop(int apfVersion, ApfV4Generator gen)
-            throws ApfV4Generator.IllegalInstructionException {
-        assertVerdict(apfVersion, DROP, gen, new byte[MIN_PKT_SIZE], 0);
-    }
-
-    /**
-     * The Mock ip client callback class.
-     */
-    public static class MockIpClientCallback extends IpClient.IpClientCallbacksWrapper {
-        private final ConditionVariable mGotApfProgram = new ConditionVariable();
-        private byte[] mLastApfProgram;
-        private boolean mInstallPacketFilterReturn = true;
-
-        MockIpClientCallback() {
-            super(mock(IIpClientCallbacks.class), mock(SharedLog.class), mock(SharedLog.class),
-                    NetworkInformationShimImpl.newInstance(), false);
-        }
-
-        MockIpClientCallback(boolean installPacketFilterReturn) {
-            super(mock(IIpClientCallbacks.class), mock(SharedLog.class), mock(SharedLog.class),
-                    NetworkInformationShimImpl.newInstance(), false);
-            mInstallPacketFilterReturn = installPacketFilterReturn;
-        }
-
-        @Override
-        public boolean installPacketFilter(byte[] filter) {
-            mLastApfProgram = filter;
-            mGotApfProgram.open();
-            return mInstallPacketFilterReturn;
-        }
-
-        /**
-         * Reset the apf program and wait for the next update.
-         */
-        public void resetApfProgramWait() {
-            mGotApfProgram.close();
-        }
-
-        /**
-         * Assert the program is update within TIMEOUT_MS and return the program.
-         */
-        public byte[] assertProgramUpdateAndGet() {
-            assertTrue(mGotApfProgram.block(TIMEOUT_MS));
-            return mLastApfProgram;
-        }
-
-        /**
-         * Assert the program is not update within TIMEOUT_MS.
-         */
-        public void assertNoProgramUpdate() {
-            assertFalse(mGotApfProgram.block(TIMEOUT_MS));
-        }
-    }
-
-    /**
-     * The test apf filter class.
-     */
-    public static class TestApfFilter extends ApfFilter implements TestAndroidPacketFilter {
-        public static final byte[] MOCK_MAC_ADDR = {2, 3, 4, 5, 6, 7};
-        private static final byte[] MOCK_IPV4_ADDR = {10, 0, 0, 1};
-
-        private FileDescriptor mWriteSocket;
-        private long mCurrentTimeMs = SystemClock.elapsedRealtime();
-        private final MockIpClientCallback mMockIpClientCb;
-        private final boolean mThrowsExceptionWhenGeneratesProgram;
-
-        public TestApfFilter(Context context, ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
-                Dependencies dependencies) throws Exception {
-            this(context, config, ipClientCallback, networkQuirkMetrics, dependencies,
-                    false /* throwsExceptionWhenGeneratesProgram */, new ApfFilter.Clock());
-        }
-
-        public TestApfFilter(Context context, ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
-                Dependencies dependencies, boolean throwsExceptionWhenGeneratesProgram)
-                throws Exception {
-            this(context, config, ipClientCallback, networkQuirkMetrics, dependencies,
-                    throwsExceptionWhenGeneratesProgram, new ApfFilter.Clock());
-        }
-
-        public TestApfFilter(Context context, ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
-                Dependencies dependencies, ApfFilter.Clock clock) throws Exception {
-            this(context, config, ipClientCallback, networkQuirkMetrics, dependencies,
-                    false /* throwsExceptionWhenGeneratesProgram */, clock);
-        }
-
-        public TestApfFilter(Context context, ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
-                Dependencies dependencies, boolean throwsExceptionWhenGeneratesProgram,
-                ApfFilter.Clock clock) throws Exception {
-            super(context, config, InterfaceParams.getByName("lo"), ipClientCallback,
-                    networkQuirkMetrics, dependencies, clock);
-            mMockIpClientCb = ipClientCallback;
-            mThrowsExceptionWhenGeneratesProgram = throwsExceptionWhenGeneratesProgram;
-        }
-
-        /**
-         * Create a new test ApfFiler.
-         */
-        public static ApfFilter createTestApfFilter(Context context,
-                MockIpClientCallback ipClientCallback, ApfConfiguration config,
-                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies)
-                throws Exception {
-            LinkAddress link = new LinkAddress(InetAddress.getByAddress(MOCK_IPV4_ADDR), 19);
-            LinkProperties lp = new LinkProperties();
-            lp.addLinkAddress(link);
-            TestApfFilter apfFilter = new TestApfFilter(context, config, ipClientCallback,
-                    networkQuirkMetrics, dependencies);
-            apfFilter.setLinkProperties(lp);
-            return apfFilter;
-        }
-
-        /**
-         * Pretend an RA packet has been received and show it to ApfFilter.
-         */
-        public void pretendPacketReceived(byte[] packet) throws IOException, ErrnoException {
-            mMockIpClientCb.resetApfProgramWait();
-            // ApfFilter's ReceiveThread will be waiting to read this.
-            Os.write(mWriteSocket, packet, 0, packet.length);
-        }
-
-        /**
-         * Simulate current time changes.
-         */
-        public void increaseCurrentTimeSeconds(int delta) {
-            mCurrentTimeMs += delta * DateUtils.SECOND_IN_MILLIS;
-        }
-
-        @Override
-        protected int secondsSinceBoot() {
-            return (int) (mCurrentTimeMs / DateUtils.SECOND_IN_MILLIS);
-        }
-
-        @Override
-        public synchronized void maybeStartFilter() {
-            mHardwareAddress = MOCK_MAC_ADDR;
-            installNewProgramLocked();
-
-            // Create two sockets, "readSocket" and "mWriteSocket" and connect them together.
-            FileDescriptor readSocket = new FileDescriptor();
-            mWriteSocket = new FileDescriptor();
-            try {
-                Os.socketpair(AF_UNIX, SOCK_STREAM, 0, mWriteSocket, readSocket);
-            } catch (ErrnoException e) {
-                fail();
-                return;
-            }
-            // Now pass readSocket to ReceiveThread as if it was setup to read raw RAs.
-            // This allows us to pretend RA packets have been received via pretendPacketReceived().
-            mReceiveThread = new ReceiveThread(readSocket);
-            mReceiveThread.start();
-        }
-
-        @Override
-        public synchronized void shutdown() {
-            super.shutdown();
-            if (mReceiveThread != null) {
-                mReceiveThread.halt();
-                mReceiveThread = null;
-            }
-            IoUtils.closeQuietly(mWriteSocket);
-        }
-
-        @Override
-        @GuardedBy("this")
-        protected ApfV4GeneratorBase<?> emitPrologueLocked() throws IllegalInstructionException {
-            if (mThrowsExceptionWhenGeneratesProgram) {
-                throw new IllegalStateException();
-            }
-            return super.emitPrologueLocked();
-        }
-    }
-
-    /**
-     * The test legacy apf filter class.
-     */
-    public static class TestLegacyApfFilter extends LegacyApfFilter
-            implements TestAndroidPacketFilter {
-        public static final byte[] MOCK_MAC_ADDR = {1, 2, 3, 4, 5, 6};
-        private static final byte[] MOCK_IPV4_ADDR = {10, 0, 0, 1};
-
-        private FileDescriptor mWriteSocket;
-        private final MockIpClientCallback mMockIpClientCb;
-        private final boolean mThrowsExceptionWhenGeneratesProgram;
-
-        public TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
-                NetworkQuirkMetrics networkQuirkMetrics) throws Exception {
-            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
-                    new ApfFilter.Dependencies(context),
-                    false /* throwsExceptionWhenGeneratesProgram */, new ApfFilter.Clock());
-        }
-
-        public TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
-                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
-                boolean throwsExceptionWhenGeneratesProgram) throws Exception {
-            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
-                    dependencies, throwsExceptionWhenGeneratesProgram, new ApfFilter.Clock());
-        }
-
-        public TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
-                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
-                ApfFilter.Clock clock) throws Exception {
-            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
-                    dependencies, false /* throwsExceptionWhenGeneratesProgram */, clock);
-        }
-
-        public TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
-                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
-                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
-                boolean throwsExceptionWhenGeneratesProgram, ApfFilter.Clock clock)
-                throws Exception {
-            super(context, config, InterfaceParams.getByName("lo"), ipClientCallback,
-                    ipConnectivityLog, networkQuirkMetrics, dependencies, clock);
-            mMockIpClientCb = ipClientCallback;
-            mThrowsExceptionWhenGeneratesProgram = throwsExceptionWhenGeneratesProgram;
-        }
-
-        /**
-         * Pretend an RA packet has been received and show it to LegacyApfFilter.
-         */
-        public void pretendPacketReceived(byte[] packet) throws IOException, ErrnoException {
-            mMockIpClientCb.resetApfProgramWait();
-            // ApfFilter's ReceiveThread will be waiting to read this.
-            Os.write(mWriteSocket, packet, 0, packet.length);
-        }
-
-        @Override
-        public synchronized void maybeStartFilter() {
-            mHardwareAddress = MOCK_MAC_ADDR;
-            installNewProgramLocked();
-
-            // Create two sockets, "readSocket" and "mWriteSocket" and connect them together.
-            FileDescriptor readSocket = new FileDescriptor();
-            mWriteSocket = new FileDescriptor();
-            try {
-                Os.socketpair(AF_UNIX, SOCK_STREAM, 0, mWriteSocket, readSocket);
-            } catch (ErrnoException e) {
-                fail();
-                return;
-            }
-            // Now pass readSocket to ReceiveThread as if it was setup to read raw RAs.
-            // This allows us to pretend RA packets have been received via pretendPacketReceived().
-            mReceiveThread = new ReceiveThread(readSocket);
-            mReceiveThread.start();
-        }
-
-        @Override
-        public synchronized void shutdown() {
-            super.shutdown();
-            if (mReceiveThread != null) {
-                mReceiveThread.halt();
-                mReceiveThread = null;
-            }
-            IoUtils.closeQuietly(mWriteSocket);
-        }
-
-        @Override
-        @GuardedBy("this")
-        protected ApfV4Generator emitPrologueLocked() throws IllegalInstructionException {
-            if (mThrowsExceptionWhenGeneratesProgram) {
-                throw new IllegalStateException();
-            }
-            return super.emitPrologueLocked();
-        }
-    }
-}
diff --git a/tests/unit/src/android/net/apf/Bpf2Apf.java b/tests/unit/src/android/net/apf/Bpf2Apf.java
index 49c241ef..4dee2f61 100644
--- a/tests/unit/src/android/net/apf/Bpf2Apf.java
+++ b/tests/unit/src/android/net/apf/Bpf2Apf.java
@@ -16,6 +16,7 @@
 
 package android.net.apf;
 
+import static android.net.apf.BaseApfGenerator.APF_VERSION_3;
 import static android.net.apf.BaseApfGenerator.MemorySlot;
 import static android.net.apf.BaseApfGenerator.Register.R0;
 import static android.net.apf.BaseApfGenerator.Register.R1;
@@ -39,6 +40,8 @@ import java.io.InputStreamReader;
  *                                      android.net.apf.Bpf2Apf
  */
 public class Bpf2Apf {
+    private static int sRamSize = 1024;
+    private static int sClampSize = 1024;
     private static int parseImm(String line, String arg) {
         if (!arg.startsWith("#0x")) {
             throw new IllegalArgumentException("Unhandled instruction: " + line);
@@ -316,7 +319,7 @@ public class Bpf2Apf {
      * program and return it.
      */
     public static byte[] convert(String bpf) throws IllegalInstructionException {
-        ApfV4Generator gen = new ApfV4Generator(3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, sRamSize, sClampSize);
         for (String line : bpf.split("\\n")) convertLine(line, gen);
         return gen.generate();
     }
@@ -329,7 +332,7 @@ public class Bpf2Apf {
         BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
         String line = null;
         StringBuilder responseData = new StringBuilder();
-        ApfV4Generator gen = new ApfV4Generator(3);
+        ApfV4Generator gen = new ApfV4Generator(APF_VERSION_3, sRamSize, sClampSize);
         while ((line = in.readLine()) != null) convertLine(line, gen);
         System.out.write(gen.generate());
     }
diff --git a/tests/unit/src/android/net/apf/LegacyApfTest.java b/tests/unit/src/android/net/apf/LegacyApfTest.java
index cb3fbca2..319a997d 100644
--- a/tests/unit/src/android/net/apf/LegacyApfTest.java
+++ b/tests/unit/src/android/net/apf/LegacyApfTest.java
@@ -17,17 +17,17 @@
 package android.net.apf;
 
 import static android.net.apf.ApfJniUtils.dropsAllPackets;
-import static android.net.apf.ApfTestUtils.DROP;
-import static android.net.apf.ApfTestUtils.PASS;
-import static android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED;
-import static android.os.PowerManager.ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED;
-import static android.system.OsConstants.ARPHRD_ETHER;
+import static android.net.apf.ApfTestHelpers.TIMEOUT_MS;
+import static android.system.OsConstants.AF_UNIX;
+import static android.net.apf.ApfTestHelpers.DROP;
+import static android.net.apf.ApfTestHelpers.PASS;
 import static android.system.OsConstants.ETH_P_ARP;
 import static android.system.OsConstants.ETH_P_IP;
 import static android.system.OsConstants.ETH_P_IPV6;
 import static android.system.OsConstants.IPPROTO_ICMPV6;
 import static android.system.OsConstants.IPPROTO_TCP;
 import static android.system.OsConstants.IPPROTO_UDP;
+import static android.system.OsConstants.SOCK_STREAM;
 
 import static com.android.net.module.util.HexDump.hexStringToByteArray;
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQUEST_TYPE;
@@ -35,7 +35,7 @@ import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQU
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.junit.Assert.fail;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
@@ -45,9 +45,7 @@ import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
-import android.content.BroadcastReceiver;
 import android.content.Context;
-import android.content.Intent;
 import android.net.IpPrefix;
 import android.net.LinkAddress;
 import android.net.LinkProperties;
@@ -55,14 +53,15 @@ import android.net.NattKeepalivePacketDataParcelable;
 import android.net.TcpKeepalivePacketDataParcelable;
 import android.net.apf.ApfCounterTracker.Counter;
 import android.net.apf.ApfFilter.ApfConfiguration;
-import android.net.apf.ApfTestUtils.MockIpClientCallback;
-import android.net.apf.ApfTestUtils.TestApfFilter;
-import android.net.apf.ApfTestUtils.TestLegacyApfFilter;
+import android.net.ip.IIpClientCallbacks;
+import android.net.ip.IpClient;
 import android.net.metrics.IpConnectivityLog;
 import android.os.Build;
+import android.os.ConditionVariable;
 import android.os.PowerManager;
 import android.stats.connectivity.NetworkQuirkEvent;
 import android.system.ErrnoException;
+import android.system.Os;
 import android.text.format.DateUtils;
 import android.util.ArrayMap;
 import android.util.Log;
@@ -72,8 +71,10 @@ import androidx.test.filters.SmallTest;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.util.HexDump;
-import com.android.modules.utils.build.SdkLevel;
+import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.NetworkStackConstants;
+import com.android.net.module.util.SharedLog;
+import com.android.networkstack.apishim.NetworkInformationShimImpl;
 import com.android.networkstack.metrics.ApfSessionInfoMetrics;
 import com.android.networkstack.metrics.IpClientRaInfoMetrics;
 import com.android.networkstack.metrics.NetworkQuirkMetrics;
@@ -82,6 +83,7 @@ import com.android.testutils.ConcurrentUtils;
 import com.android.testutils.DevSdkIgnoreRule;
 import com.android.testutils.DevSdkIgnoreRunner;
 
+import libcore.io.IoUtils;
 import libcore.io.Streams;
 
 import org.junit.After;
@@ -97,6 +99,7 @@ import org.mockito.MockitoAnnotations;
 
 import java.io.ByteArrayOutputStream;
 import java.io.File;
+import java.io.FileDescriptor;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.io.InputStream;
@@ -140,7 +143,7 @@ public class LegacyApfTest {
     @Mock private NetworkQuirkMetrics mNetworkQuirkMetrics;
     @Mock private ApfSessionInfoMetrics mApfSessionInfoMetrics;
     @Mock private IpClientRaInfoMetrics mIpClientRaInfoMetrics;
-    @Mock private ApfFilter.Clock mClock;
+    @Mock private LegacyApfFilter.Clock mClock;
     @GuardedBy("mApfFilterCreated")
     private final ArrayList<AndroidPacketFilter> mApfFilterCreated = new ArrayList<>();
     @GuardedBy("mThreadsToBeCleared")
@@ -209,9 +212,6 @@ public class LegacyApfTest {
     }
 
     private static final String TAG = "ApfTest";
-    // Expected return codes from APF interpreter.
-    private static final ApfCapabilities MOCK_APF_CAPABILITIES =
-            new ApfCapabilities(2, 4096, ARPHRD_ETHER);
 
     private static final boolean DROP_MULTICAST = true;
     private static final boolean ALLOW_MULTICAST = false;
@@ -237,7 +237,8 @@ public class LegacyApfTest {
 
     private static ApfConfiguration getDefaultConfig() {
         ApfFilter.ApfConfiguration config = new ApfConfiguration();
-        config.apfCapabilities = MOCK_APF_CAPABILITIES;
+        config.apfVersionSupported = 2;
+        config.apfRamSize = 4096;
         config.multicastFilter = ALLOW_MULTICAST;
         config.ieee802_3Filter = ALLOW_802_3_FRAMES;
         config.ethTypeBlackList = new int[0];
@@ -248,58 +249,58 @@ public class LegacyApfTest {
     }
 
     private void assertPass(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertPass(mApfVersion, gen);
+        ApfTestHelpers.assertPass(mApfVersion, gen);
     }
 
     private void assertDrop(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertDrop(mApfVersion, gen);
+        ApfTestHelpers.assertDrop(mApfVersion, gen);
     }
 
     private void assertPass(byte[] program, byte[] packet) {
-        ApfTestUtils.assertPass(mApfVersion, program, packet);
+        ApfTestHelpers.assertPass(mApfVersion, program, packet);
     }
 
     private void assertDrop(byte[] program, byte[] packet) {
-        ApfTestUtils.assertDrop(mApfVersion, program, packet);
+        ApfTestHelpers.assertDrop(mApfVersion, program, packet);
     }
 
     private void assertPass(byte[] program, byte[] packet, int filterAge) {
-        ApfTestUtils.assertPass(mApfVersion, program, packet, filterAge);
+        ApfTestHelpers.assertPass(mApfVersion, program, packet, filterAge);
     }
 
     private void assertDrop(byte[] program, byte[] packet, int filterAge) {
-        ApfTestUtils.assertDrop(mApfVersion, program, packet, filterAge);
+        ApfTestHelpers.assertDrop(mApfVersion, program, packet, filterAge);
     }
 
     private void assertPass(ApfV4Generator gen, byte[] packet, int filterAge)
             throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertPass(mApfVersion, gen, packet, filterAge);
+        ApfTestHelpers.assertPass(mApfVersion, gen, packet, filterAge);
     }
 
     private void assertDrop(ApfV4Generator gen, byte[] packet, int filterAge)
             throws ApfV4Generator.IllegalInstructionException {
-        ApfTestUtils.assertDrop(mApfVersion, gen, packet, filterAge);
+        ApfTestHelpers.assertDrop(mApfVersion, gen, packet, filterAge);
     }
 
     private void assertDataMemoryContents(int expected, byte[] program, byte[] packet,
             byte[] data, byte[] expectedData) throws Exception {
-        ApfTestUtils.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
+        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                 expectedData, false /* ignoreInterpreterVersion */);
     }
 
     private void assertDataMemoryContentsIgnoreVersion(int expected, byte[] program,
             byte[] packet, byte[] data, byte[] expectedData) throws Exception {
-        ApfTestUtils.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
+        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                 expectedData, true /* ignoreInterpreterVersion */);
     }
 
     private void assertVerdict(String msg, int expected, byte[] program,
             byte[] packet, int filterAge) {
-        ApfTestUtils.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
+        ApfTestHelpers.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
     }
 
     private void assertVerdict(int expected, byte[] program, byte[] packet) {
-        ApfTestUtils.assertVerdict(mApfVersion, expected, program, packet);
+        ApfTestHelpers.assertVerdict(mApfVersion, expected, program, packet);
     }
 
     /**
@@ -316,12 +317,12 @@ public class LegacyApfTest {
         lp.addLinkAddress(link);
 
         ApfConfiguration config = getDefaultConfig();
-        ApfCapabilities MOCK_APF_PCAP_CAPABILITIES = new ApfCapabilities(4, 1700, ARPHRD_ETHER);
-        config.apfCapabilities = MOCK_APF_PCAP_CAPABILITIES;
+        config.apfVersionSupported = 4;
+        config.apfRamSize = 1700;
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         apfFilter.setLinkProperties(lp);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
         byte[] data = new byte[Counter.totalSize()];
@@ -496,23 +497,18 @@ public class LegacyApfTest {
 
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         apfFilter.setLinkProperties(lp);
 
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
 
         ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
-        if (SdkLevel.isAtLeastV()) {
-            // Verify empty packet of 100 zero bytes is dropped
-            assertDrop(program, packet.array());
-        } else {
-            // Verify empty packet of 100 zero bytes is passed
-            assertPass(program, packet.array());
-        }
+        // Verify empty packet of 100 zero bytes is passed
+        assertPass(program, packet.array());
 
         // Verify unicast IPv4 packet is passed
-        put(packet, ETH_DEST_ADDR_OFFSET, TestApfFilter.MOCK_MAC_ADDR);
+        put(packet, ETH_DEST_ADDR_OFFSET, TestLegacyApfFilter.MOCK_MAC_ADDR);
         packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
         put(packet, IPV4_DEST_ADDR_OFFSET, MOCK_IPV4_ADDR);
         assertPass(program, packet.array());
@@ -540,11 +536,11 @@ public class LegacyApfTest {
         assertDrop(program, packet.array());
 
         // Verify broadcast IPv4 DHCP to us is passed
-        put(packet, DHCP_CLIENT_MAC_OFFSET, TestApfFilter.MOCK_MAC_ADDR);
+        put(packet, DHCP_CLIENT_MAC_OFFSET, TestLegacyApfFilter.MOCK_MAC_ADDR);
         assertPass(program, packet.array());
 
         // Verify unicast IPv4 DHCP to us is passed
-        put(packet, ETH_DEST_ADDR_OFFSET, TestApfFilter.MOCK_MAC_ADDR);
+        put(packet, ETH_DEST_ADDR_OFFSET, TestLegacyApfFilter.MOCK_MAC_ADDR);
         assertPass(program, packet.array());
     }
 
@@ -552,8 +548,8 @@ public class LegacyApfTest {
     public void testApfFilterIPv6() throws Exception {
         MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
 
         // Verify empty IPv6 packet is passed
@@ -601,8 +597,8 @@ public class LegacyApfTest {
 
         ApfConfiguration config = getDefaultConfig();
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         apfFilter.setLinkProperties(lp);
 
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
@@ -627,7 +623,7 @@ public class LegacyApfTest {
 
         // Construct IPv4 broadcast with L2 unicast address packet (b/30231088).
         ByteBuffer bcastv4unicastl2packet = makeIpv4Packet(IPPROTO_UDP);
-        bcastv4unicastl2packet.put(TestApfFilter.MOCK_MAC_ADDR);
+        bcastv4unicastl2packet.put(TestLegacyApfFilter.MOCK_MAC_ADDR);
         bcastv4unicastl2packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
         put(bcastv4unicastl2packet, IPV4_DEST_ADDR_OFFSET, broadcastIpv4Addr);
 
@@ -662,8 +658,8 @@ public class LegacyApfTest {
         ipClientCallback.resetApfProgramWait();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        apfFilter = new TestApfFilter(mContext, config, ipClientCallback, mNetworkQuirkMetrics,
-                mDependencies);
+        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         apfFilter.setLinkProperties(lp);
         program = ipClientCallback.assertProgramUpdateAndGet();
         assertDrop(program, mcastv4packet.array());
@@ -678,60 +674,22 @@ public class LegacyApfTest {
 
     @Test
     public void testApfFilterMulticastPingWhileDozing() throws Exception {
-        doTestApfFilterMulticastPingWhileDozing(false /* isLightDozing */);
-    }
-
-    @Test
-    @DevSdkIgnoreRule.IgnoreUpTo(Build.VERSION_CODES.TIRAMISU)
-    public void testApfFilterMulticastPingWhileLightDozing() throws Exception {
-        doTestApfFilterMulticastPingWhileDozing(true /* isLightDozing */);
-    }
-
-    @Test
-    @DevSdkIgnoreRule.IgnoreUpTo(Build.VERSION_CODES.TIRAMISU)
-    public void testShouldHandleLightDozeKillSwitch() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
-        final ApfConfiguration configuration = getDefaultConfig();
-        configuration.shouldHandleLightDoze = false;
-        final ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback,
-                configuration, mNetworkQuirkMetrics, mDependencies);
-        final ArgumentCaptor<BroadcastReceiver> receiverCaptor =
-                ArgumentCaptor.forClass(BroadcastReceiver.class);
-        verify(mDependencies).addDeviceIdleReceiver(receiverCaptor.capture(), anyBoolean());
-        final BroadcastReceiver receiver = receiverCaptor.getValue();
-        doReturn(true).when(mPowerManager).isDeviceLightIdleMode();
-        receiver.onReceive(mContext, new Intent(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED));
-        assertFalse(apfFilter.isInDozeMode());
-    }
-
-    private void doTestApfFilterMulticastPingWhileDozing(boolean isLightDozing) throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
+        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration configuration = getDefaultConfig();
-        configuration.shouldHandleLightDoze = true;
-        final ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback,
-                configuration, mNetworkQuirkMetrics, mDependencies);
-        final ArgumentCaptor<BroadcastReceiver> receiverCaptor =
-                ArgumentCaptor.forClass(BroadcastReceiver.class);
-        verify(mDependencies).addDeviceIdleReceiver(receiverCaptor.capture(), anyBoolean());
-        final BroadcastReceiver receiver = receiverCaptor.getValue();
+        final LegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, configuration,
+                ipClientCallback, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
 
         // Construct a multicast ICMPv6 ECHO request.
         final byte[] multicastIpv6Addr = {(byte)0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,(byte)0xfb};
-        final ByteBuffer packet = makeIpv6Packet(IPPROTO_ICMPV6);
+        ByteBuffer packet = makeIpv6Packet(IPPROTO_ICMPV6);
         packet.put(ICMP6_TYPE_OFFSET, (byte)ICMPV6_ECHO_REQUEST_TYPE);
         put(packet, IPV6_DEST_ADDR_OFFSET, multicastIpv6Addr);
 
         // Normally, we let multicast pings alone...
         assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
 
-        if (isLightDozing) {
-            doReturn(true).when(mPowerManager).isDeviceLightIdleMode();
-            receiver.onReceive(mContext, new Intent(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED));
-        } else {
-            doReturn(true).when(mPowerManager).isDeviceIdleMode();
-            receiver.onReceive(mContext, new Intent(ACTION_DEVICE_IDLE_MODE_CHANGED));
-        }
         // ...and even while dozing...
+        apfFilter.setDozeMode(true);
         assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
 
         // ...but when the multicast filter is also enabled, drop the multicast pings to save power.
@@ -747,14 +705,10 @@ public class LegacyApfTest {
 
         // Now wake up from doze mode to ensure that we no longer drop the packets.
         // (The multicast filter is still enabled at this point).
-        if (isLightDozing) {
-            doReturn(false).when(mPowerManager).isDeviceLightIdleMode();
-            receiver.onReceive(mContext, new Intent(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED));
-        } else {
-            doReturn(false).when(mPowerManager).isDeviceIdleMode();
-            receiver.onReceive(mContext, new Intent(ACTION_DEVICE_IDLE_MODE_CHANGED));
-        }
+        apfFilter.setDozeMode(false);
         assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());
+
+        apfFilter.shutdown();
     }
 
     @Test
@@ -762,8 +716,8 @@ public class LegacyApfTest {
     public void testApfFilter802_3() throws Exception {
         MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
 
         // Verify empty packet of 100 zero bytes is passed
@@ -782,8 +736,8 @@ public class LegacyApfTest {
         // Now turn on the filter
         ipClientCallback.resetApfProgramWait();
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
+        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         program = ipClientCallback.assertProgramUpdateAndGet();
 
         // Verify that IEEE802.3 frame is dropped
@@ -809,8 +763,8 @@ public class LegacyApfTest {
 
         MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         ApfConfiguration config = getDefaultConfig();
-        ApfFilter apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
 
         // Verify empty packet of 100 zero bytes is passed
@@ -829,8 +783,8 @@ public class LegacyApfTest {
         // Now add IPv4 to the black list
         ipClientCallback.resetApfProgramWait();
         config.ethTypeBlackList = ipv4BlackList;
-        apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
+        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         program = ipClientCallback.assertProgramUpdateAndGet();
 
         // Verify that IPv4 frame will be dropped
@@ -844,8 +798,8 @@ public class LegacyApfTest {
         // Now let us have both IPv4 and IPv6 in the black list
         ipClientCallback.resetApfProgramWait();
         config.ethTypeBlackList = ipv4Ipv6BlackList;
-        apfFilter = TestApfFilter.createTestApfFilter(mContext, ipClientCallback, config,
-                mNetworkQuirkMetrics, mDependencies);
+        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         program = ipClientCallback.assertProgramUpdateAndGet();
 
         // Verify that IPv4 frame will be dropped
@@ -857,7 +811,8 @@ public class LegacyApfTest {
         assertDrop(program, packet.array());
     }
 
-    private byte[] getProgram(MockIpClientCallback cb, ApfFilter filter, LinkProperties lp) {
+    private byte[] getProgram(MockIpClientCallback cb, TestLegacyApfFilter filter,
+            LinkProperties lp) {
         cb.resetApfProgramWait();
         filter.setLinkProperties(lp);
         return cb.assertProgramUpdateAndGet();
@@ -867,7 +822,7 @@ public class LegacyApfTest {
         // Verify ARP request packet
         assertPass(program, arpRequestBroadcast(MOCK_IPV4_ADDR));
         assertVerdict(filterResult, program, arpRequestBroadcast(ANOTHER_IPV4_ADDR));
-        assertVerdict(filterResult, program, arpRequestBroadcast(IPV4_ANY_HOST_ADDR));
+        assertVerdict(DROP, program, arpRequestBroadcast(IPV4_ANY_HOST_ADDR));
 
         // Verify ARP reply packets from different source ip
         assertDrop(program, arpReply(IPV4_ANY_HOST_ADDR, IPV4_ANY_HOST_ADDR));
@@ -890,8 +845,8 @@ public class LegacyApfTest {
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
 
         // Verify initially ARP request filter is off, and GARP filter is on.
         verifyArpFilter(ipClientCallback.assertProgramUpdateAndGet(), PASS);
@@ -949,8 +904,8 @@ public class LegacyApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, cb,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program;
         final int srcPort = 12345;
         final int dstPort = 54321;
@@ -1141,8 +1096,8 @@ public class LegacyApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, cb,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program;
         final int srcPort = 1024;
         final int dstPort = 4500;
@@ -1424,16 +1379,18 @@ public class LegacyApfTest {
 
     // Test that when ApfFilter is shown the given packet, it generates a program to filter it
     // for the given lifetime.
-    private void verifyRaLifetime(TestApfFilter apfFilter, MockIpClientCallback ipClientCallback,
-            ByteBuffer packet, int lifetime) throws IOException, ErrnoException {
+    private void verifyRaLifetime(TestLegacyApfFilter apfFilter,
+            MockIpClientCallback ipClientCallback, ByteBuffer packet, int lifetime)
+            throws IOException, ErrnoException {
         // Verify new program generated if ApfFilter witnesses RA
         apfFilter.pretendPacketReceived(packet.array());
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
         verifyRaLifetime(program, packet, lifetime);
     }
 
-    private void assertInvalidRa(TestApfFilter apfFilter, MockIpClientCallback ipClientCallback,
-            ByteBuffer packet) throws IOException, ErrnoException {
+    private void assertInvalidRa(TestLegacyApfFilter apfFilter,
+            MockIpClientCallback ipClientCallback, ByteBuffer packet)
+            throws IOException, ErrnoException {
         apfFilter.pretendPacketReceived(packet.array());
         ipClientCallback.assertNoProgramUpdate();
     }
@@ -1444,8 +1401,8 @@ public class LegacyApfTest {
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
 
         final int ROUTER_LIFETIME = 1000;
@@ -1534,8 +1491,8 @@ public class LegacyApfTest {
         final ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
+        final TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config,
+                ipClientCallback, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
         final int RA_REACHABLE_TIME = 1800;
         final int RA_RETRANSMISSION_TIMER = 1234;
@@ -1568,47 +1525,6 @@ public class LegacyApfTest {
         assertPass(program, raPacket);
     }
 
-    // The ByteBuffer is always created by ByteBuffer#wrap in the helper functions
-    @SuppressWarnings("ByteBufferBackingArray")
-    @Test
-    public void testRaWithProgramInstalledSomeTimeAfterLastSeen() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
-        final ApfConfiguration config = getDefaultConfig();
-        config.multicastFilter = DROP_MULTICAST;
-        config.ieee802_3Filter = DROP_802_3_FRAMES;
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, config, ipClientCallback,
-                mNetworkQuirkMetrics, mDependencies);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
-
-        final int routerLifetime = 1000;
-        final int timePassedSeconds = 12;
-
-        // Verify that when the program is generated and installed some time after RA is last seen
-        // it should be installed with the correct remaining lifetime.
-        ByteBuffer basePacket = ByteBuffer.wrap(new RaPacketBuilder(routerLifetime).build());
-        verifyRaLifetime(apfFilter, ipClientCallback, basePacket, routerLifetime);
-        apfFilter.increaseCurrentTimeSeconds(timePassedSeconds);
-        synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
-        }
-        program = ipClientCallback.assertProgramUpdateAndGet();
-        verifyRaLifetime(program, basePacket, routerLifetime, timePassedSeconds);
-
-        // Packet should be passed if the program is installed after 1/6 * lifetime from last seen
-        apfFilter.increaseCurrentTimeSeconds((int) (routerLifetime / 6) - timePassedSeconds - 1);
-        synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
-        }
-        program = ipClientCallback.assertProgramUpdateAndGet();
-        assertDrop(program, basePacket.array());
-        apfFilter.increaseCurrentTimeSeconds(1);
-        synchronized (apfFilter) {
-            apfFilter.installNewProgramLocked();
-        }
-        program = ipClientCallback.assertProgramUpdateAndGet();
-        assertPass(program, basePacket.array());
-    }
-
     /**
      * Stage a file for testing, i.e. make it native accessible. Given a resource ID,
      * copy that resource into the app's data directory and return the path to it.
@@ -1644,14 +1560,14 @@ public class LegacyApfTest {
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb, mNetworkQuirkMetrics,
-                mDependencies);
+        final TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config,
+                cb, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         for (int i = 0; i < 1000; i++) {
             byte[] packet = new byte[r.nextInt(maxRandomPacketSize + 1)];
             r.nextBytes(packet);
             try {
                 apfFilter.new Ra(packet, packet.length);
-            } catch (ApfFilter.InvalidRaException e) {
+            } catch (LegacyApfFilter.InvalidRaException e) {
             } catch (Exception e) {
                 throw new Exception("bad packet: " + HexDump.toHexString(packet), e);
             }
@@ -1666,8 +1582,8 @@ public class LegacyApfTest {
         ApfConfiguration config = getDefaultConfig();
         config.multicastFilter = DROP_MULTICAST;
         config.ieee802_3Filter = DROP_802_3_FRAMES;
-        TestApfFilter apfFilter = new TestApfFilter(mContext, config, cb, mNetworkQuirkMetrics,
-                mDependencies);
+        final TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config,
+                cb, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
         for (int i = 0; i < 1000; i++) {
             byte[] packet = new byte[r.nextInt(maxRandomPacketSize + 1)];
             r.nextBytes(packet);
@@ -1679,36 +1595,13 @@ public class LegacyApfTest {
         }
     }
 
-    @Test
-    public void testMatchedRaUpdatesLifetime() throws Exception {
-        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
-        final TestApfFilter apfFilter = new TestApfFilter(mContext, getDefaultConfig(),
-                ipClientCallback, mNetworkQuirkMetrics, mDependencies);
-
-        // Create an RA and build an APF program
-        byte[] ra = new RaPacketBuilder(1800 /* router lifetime */).build();
-        apfFilter.pretendPacketReceived(ra);
-        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
-
-        // lifetime dropped significantly, assert pass
-        ra = new RaPacketBuilder(200 /* router lifetime */).build();
-        assertPass(program, ra);
-
-        // update program with the new RA
-        apfFilter.pretendPacketReceived(ra);
-        program = ipClientCallback.assertProgramUpdateAndGet();
-
-        // assert program was updated and new lifetimes were taken into account.
-        assertDrop(program, ra);
-    }
-
     @Test
     public void testProcessRaWithInfiniteLifeTimeWithoutCrash() throws Exception {
         final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         // configure accept_ra_min_lft
         final ApfConfiguration config = getDefaultConfig();
         config.acceptRaMinLft = 180;
-        TestApfFilter apfFilter;
+        TestLegacyApfFilter apfFilter;
         // Template packet:
         // Frame 1: 150 bytes on wire (1200 bits), 150 bytes captured (1200 bits)
         // Ethernet II, Src: Netgear_23:67:2c (28:c6:8e:23:67:2c), Dst: IPv6mcast_01 (33:33:00:00:00:01)
@@ -1754,10 +1647,10 @@ public class LegacyApfTest {
         //     Reserved
         //     Advertisement Interval: 600000
         final String packetStringFmt = "33330000000128C68E23672C86DD60054C6B00603AFFFE800000000000002AC68EFFFE23672CFF02000000000000000000000000000186000ACD40C01B580000000000000000010128C68E23672C05010000000005DC030440C0%s000000002401FA000480F00000000000000000001903000000001B582401FA000480F000000000000000000107010000000927C0";
-        final List<String> lifetimes = List.of("FFFFFFFF", "00000000", "00000001", "00001B58");
+        final List<String> lifetimes = List.of("FFFFFFFF", "00000001", "00001B58");
         for (String lifetime : lifetimes) {
-            apfFilter = new TestApfFilter(mContext, config, ipClientCallback, mNetworkQuirkMetrics,
-                    mDependencies);
+            apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
+                    mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
             final byte[] ra = hexStringToByteArray(
                     String.format(packetStringFmt, lifetime + lifetime));
             // feed the RA into APF and generate the filter, the filter shouldn't crash.
@@ -1792,8 +1685,8 @@ public class LegacyApfTest {
     public void testApfProgramOverSize_LegacyApfFilter() throws Exception {
         final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
-        final ApfCapabilities capabilities = new ApfCapabilities(2, 512, ARPHRD_ETHER);
-        config.apfCapabilities = capabilities;
+        config.apfVersionSupported = 2;
+        config.apfRamSize = 512;
         final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
         byte[] program = ipClientCallback.assertProgramUpdateAndGet();
         final byte[] ra = buildLargeRa();
@@ -1823,8 +1716,8 @@ public class LegacyApfTest {
     public void testApfSessionInfoMetrics_LegacyApfFilter() throws Exception {
         final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
         final ApfConfiguration config = getDefaultConfig();
-        final ApfCapabilities capabilities = new ApfCapabilities(4, 4096, ARPHRD_ETHER);
-        config.apfCapabilities = capabilities;
+        config.apfVersionSupported = 4;
+        config.apfRamSize = 4096;
         final long startTimeMs = 12345;
         final long durationTimeMs = config.minMetricsSessionDurationMs;
         doReturn(startTimeMs).when(mClock).elapsedRealtime();
@@ -1994,13 +1887,159 @@ public class LegacyApfTest {
 
         // Verify metrics data written to statsd for duration greater than or equal to
         // durationTimeMs.
-        ApfFilter.Clock clock = mock(ApfFilter.Clock.class);
+        LegacyApfFilter.Clock clock = mock(LegacyApfFilter.Clock.class);
         doReturn(startTimeMs).when(clock).elapsedRealtime();
-        final TestAndroidPacketFilter apfFilter2 = new TestApfFilter(mContext, config,
-                ipClientCallback, mNetworkQuirkMetrics, mDependencies, clock);
+        final TestAndroidPacketFilter apfFilter2 = new TestLegacyApfFilter(mContext, config,
+                ipClientCallback, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, clock);
         doReturn(startTimeMs + durationTimeMs).when(clock).elapsedRealtime();
         apfFilter2.shutdown();
         verify(mApfSessionInfoMetrics).statsWrite();
         verify(mIpClientRaInfoMetrics).statsWrite();
     }
+
+    /**
+     * The Mock ip client callback class.
+     */
+    private static class MockIpClientCallback extends IpClient.IpClientCallbacksWrapper {
+        private final ConditionVariable mGotApfProgram = new ConditionVariable();
+        private byte[] mLastApfProgram;
+        private boolean mInstallPacketFilterReturn = true;
+
+        MockIpClientCallback() {
+            super(mock(IIpClientCallbacks.class), mock(SharedLog.class), mock(SharedLog.class),
+                    NetworkInformationShimImpl.newInstance(), false);
+        }
+
+        MockIpClientCallback(boolean installPacketFilterReturn) {
+            super(mock(IIpClientCallbacks.class), mock(SharedLog.class), mock(SharedLog.class),
+                    NetworkInformationShimImpl.newInstance(), false);
+            mInstallPacketFilterReturn = installPacketFilterReturn;
+        }
+
+        @Override
+        public boolean installPacketFilter(byte[] filter) {
+            mLastApfProgram = filter;
+            mGotApfProgram.open();
+            return mInstallPacketFilterReturn;
+        }
+
+        /**
+         * Reset the apf program and wait for the next update.
+         */
+        public void resetApfProgramWait() {
+            mGotApfProgram.close();
+        }
+
+        /**
+         * Assert the program is update within TIMEOUT_MS and return the program.
+         */
+        public byte[] assertProgramUpdateAndGet() {
+            assertTrue(mGotApfProgram.block(TIMEOUT_MS));
+            return mLastApfProgram;
+        }
+
+        /**
+         * Assert the program is not update within TIMEOUT_MS.
+         */
+        public void assertNoProgramUpdate() {
+            assertFalse(mGotApfProgram.block(TIMEOUT_MS));
+        }
+    }
+
+    /**
+     * The test legacy apf filter class.
+     */
+    private static class TestLegacyApfFilter extends LegacyApfFilter
+            implements TestAndroidPacketFilter {
+        public static final byte[] MOCK_MAC_ADDR = {1, 2, 3, 4, 5, 6};
+        private static final byte[] MOCK_IPV4_ADDR = {10, 0, 0, 1};
+
+        private FileDescriptor mWriteSocket;
+        private final MockIpClientCallback mMockIpClientCb;
+        private final boolean mThrowsExceptionWhenGeneratesProgram;
+
+        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
+                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
+                NetworkQuirkMetrics networkQuirkMetrics) throws Exception {
+            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
+                    new ApfFilter.Dependencies(context),
+                    false /* throwsExceptionWhenGeneratesProgram */, new Clock());
+        }
+
+        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
+                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
+                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
+                boolean throwsExceptionWhenGeneratesProgram) throws Exception {
+            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
+                    dependencies, throwsExceptionWhenGeneratesProgram, new Clock());
+        }
+
+        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
+                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
+                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
+                Clock clock) throws Exception {
+            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
+                    dependencies, false /* throwsExceptionWhenGeneratesProgram */, clock);
+        }
+
+        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
+                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
+                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
+                boolean throwsExceptionWhenGeneratesProgram, Clock clock)
+                throws Exception {
+            super(context, config, InterfaceParams.getByName("lo"), ipClientCallback,
+                    ipConnectivityLog, networkQuirkMetrics, dependencies, clock);
+            mMockIpClientCb = ipClientCallback;
+            mThrowsExceptionWhenGeneratesProgram = throwsExceptionWhenGeneratesProgram;
+        }
+
+        /**
+         * Pretend an RA packet has been received and show it to LegacyApfFilter.
+         */
+        public void pretendPacketReceived(byte[] packet) throws IOException, ErrnoException {
+            mMockIpClientCb.resetApfProgramWait();
+            // ApfFilter's ReceiveThread will be waiting to read this.
+            Os.write(mWriteSocket, packet, 0, packet.length);
+        }
+
+        @Override
+        public synchronized void maybeStartFilter() {
+            mHardwareAddress = MOCK_MAC_ADDR;
+            installNewProgramLocked();
+
+            // Create two sockets, "readSocket" and "mWriteSocket" and connect them together.
+            FileDescriptor readSocket = new FileDescriptor();
+            mWriteSocket = new FileDescriptor();
+            try {
+                Os.socketpair(AF_UNIX, SOCK_STREAM, 0, mWriteSocket, readSocket);
+            } catch (ErrnoException e) {
+                fail();
+                return;
+            }
+            // Now pass readSocket to ReceiveThread as if it was setup to read raw RAs.
+            // This allows us to pretend RA packets have been received via pretendPacketReceived().
+            mReceiveThread = new ReceiveThread(readSocket);
+            mReceiveThread.start();
+        }
+
+        @Override
+        public synchronized void shutdown() {
+            super.shutdown();
+            if (mReceiveThread != null) {
+                mReceiveThread.halt();
+                mReceiveThread = null;
+            }
+            IoUtils.closeQuietly(mWriteSocket);
+        }
+
+        @Override
+        @GuardedBy("this")
+        protected ApfV4Generator emitPrologueLocked() throws
+                BaseApfGenerator.IllegalInstructionException {
+            if (mThrowsExceptionWhenGeneratesProgram) {
+                throw new IllegalStateException();
+            }
+            return super.emitPrologueLocked();
+        }
+    }
 }
diff --git a/tests/unit/src/android/net/ip/ConnectivityPacketTrackerTest.kt b/tests/unit/src/android/net/ip/ConnectivityPacketTrackerTest.kt
new file mode 100644
index 00000000..51a871dd
--- /dev/null
+++ b/tests/unit/src/android/net/ip/ConnectivityPacketTrackerTest.kt
@@ -0,0 +1,233 @@
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
+package android.net.ip
+
+import android.net.MacAddress
+import android.net.ip.ConnectivityPacketTracker.Dependencies
+import android.os.Handler
+import android.os.HandlerThread
+import android.system.ErrnoException
+import android.system.Os
+import android.system.OsConstants.AF_UNIX
+import android.system.OsConstants.SOCK_NONBLOCK
+import android.system.OsConstants.SOCK_STREAM
+import android.util.LocalLog
+import androidx.test.filters.SmallTest
+import com.android.net.module.util.HexDump
+import com.android.net.module.util.InterfaceParams
+import com.android.testutils.DevSdkIgnoreRunner
+import com.android.testutils.waitForIdle
+import java.io.FileDescriptor
+import java.io.InterruptedIOException
+import java.util.concurrent.CompletableFuture
+import java.util.concurrent.TimeUnit
+import kotlin.test.assertEquals
+import libcore.io.IoUtils
+import org.junit.After
+import org.junit.Before
+import org.junit.Test
+import org.mockito.ArgumentMatchers.anyInt
+import org.mockito.Mock
+import org.mockito.Mockito
+import org.mockito.Mockito.doReturn
+import org.mockito.MockitoAnnotations
+
+/**
+ * Test for ConnectivityPacketTracker.
+ */
+@SmallTest
+@DevSdkIgnoreRunner.MonitorThreadLeak
+class ConnectivityPacketTrackerTest {
+    companion object {
+        private const val TIMEOUT_MS: Long = 10000
+        private const val SLEEP_TIMEOUT_MS: Long = 500
+        private const val TEST_MAX_CAPTURE_PKT_SIZE: Int = 100
+        private const val TAG = "ConnectivityPacketTrackerTest"
+    }
+
+    private val loInterfaceParams = InterfaceParams.getByName("lo")
+    private val ifParams =
+        InterfaceParams(
+            "lo",
+            loInterfaceParams.index,
+            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
+            loInterfaceParams.defaultMtu
+        )
+    private val writeSocket = FileDescriptor()
+    private val handlerThread by lazy {
+        HandlerThread("$TAG-handler-thread").apply { start() }
+    }
+    private val handler by lazy { Handler(handlerThread.looper) }
+    @Mock private lateinit var mDependencies: Dependencies
+    @Mock private lateinit var localLog: LocalLog
+    @Before
+    fun setUp() {
+        MockitoAnnotations.initMocks(this)
+        val readSocket = FileDescriptor()
+        Os.socketpair(AF_UNIX, SOCK_STREAM or SOCK_NONBLOCK, 0, writeSocket, readSocket)
+        doReturn(readSocket).`when`(mDependencies).createPacketReaderSocket(anyInt())
+        doReturn(TEST_MAX_CAPTURE_PKT_SIZE).`when`(mDependencies).maxCapturePktSize
+    }
+
+    @After
+    fun tearDown() {
+        IoUtils.closeQuietly(writeSocket)
+        handler.waitForIdle(10000)
+        Mockito.framework().clearInlineMocks()
+        handlerThread.quitSafely()
+        handlerThread.join()
+    }
+
+    @Test
+    fun testCapturePacket() {
+        val packetTracker = getConnectivityPacketTracker()
+        // Using scapy to generate ARP request packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP()
+        // pkt = eth/arp
+        val arpPkt = """
+            010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
+        """.replace("\\s+".toRegex(), "").trim().uppercase()
+        val arpPktByteArray = HexDump.hexStringToByteArray(arpPkt)
+        assertEquals(0, getCapturePacketTypeCount(packetTracker))
+        assertEquals(0, getMatchedPacketCount(packetTracker, arpPkt))
+
+        // start capture packet
+        setCapture(packetTracker, true)
+
+        for (i in 1..5) {
+            pretendPacketReceive(arpPktByteArray)
+            Thread.sleep(SLEEP_TIMEOUT_MS)
+        }
+
+        assertEquals(1, getCapturePacketTypeCount(packetTracker))
+        assertEquals(5, getMatchedPacketCount(packetTracker, arpPkt))
+
+        // stop capture packet
+        setCapture(packetTracker, false)
+        assertEquals(0, getCapturePacketTypeCount(packetTracker))
+        assertEquals(0, getMatchedPacketCount(packetTracker, arpPkt))
+    }
+
+    @Test
+    fun testMaxCapturePacketSize() {
+        doReturn(3).`when`(mDependencies).maxCapturePktSize
+        val packetTracker = getConnectivityPacketTracker(mDependencies)
+
+        // Using scapy to generate ARP request packet:
+        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
+        // arp = ARP()
+        // pkt = eth/arp
+        val arpPkt = """
+            010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
+        """.replace("\\s+".toRegex(), "").trim().uppercase()
+        val arpPktByteArray = HexDump.hexStringToByteArray(arpPkt)
+        // start capture packet
+        setCapture(packetTracker, true)
+        val pktCnt = 5
+        val pktList = ArrayList<String>()
+        for (i in 0..<pktCnt) {
+            // modify the original packet's last byte
+            val modPkt = arpPktByteArray.copyOf()
+            modPkt[modPkt.size - 1] = i.toByte()
+            pretendPacketReceive(modPkt)
+            pktList.add(HexDump.toHexString(modPkt))
+            Thread.sleep(SLEEP_TIMEOUT_MS)
+        }
+
+        // The old packets are evicted due to LruCache size
+        pktList.take(2).forEach {
+            assertEquals(0, getMatchedPacketCount(packetTracker, it))
+        }
+
+        pktList.drop(2).forEach {
+            assertEquals(1, getMatchedPacketCount(packetTracker, it))
+        }
+
+        assertEquals(mDependencies.maxCapturePktSize, getCapturePacketTypeCount(packetTracker))
+    }
+
+    @Throws(InterruptedIOException::class, ErrnoException::class)
+    private fun pretendPacketReceive(packet: ByteArray) {
+        Os.write(writeSocket, packet, 0, packet.size)
+    }
+
+    private fun getConnectivityPacketTracker(
+        dependencies: Dependencies = mDependencies
+    ): ConnectivityPacketTracker {
+        val result = CompletableFuture<ConnectivityPacketTracker>()
+        handler.post {
+            try {
+                val tracker = ConnectivityPacketTracker(handler, ifParams, localLog, dependencies)
+                tracker.start(TAG)
+                result.complete(tracker)
+            } catch (e: Exception) {
+                result.completeExceptionally(e)
+            }
+        }
+
+        return result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
+    }
+
+    private fun setCapture(
+        packetTracker: ConnectivityPacketTracker,
+        isCapturing: Boolean
+    ) {
+        val result = CompletableFuture<Unit>()
+        handler.post {
+            try {
+                packetTracker.setCapture(isCapturing)
+                result.complete(Unit)
+            } catch (e: Exception) {
+                result.completeExceptionally(e)
+            }
+        }
+
+        result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
+    }
+
+    private fun getMatchedPacketCount(
+        packetTracker: ConnectivityPacketTracker,
+        packet: String
+    ): Int {
+        val result = CompletableFuture<Int>()
+        handler.post {
+            try {
+                result.complete(packetTracker.getMatchedPacketCount(packet))
+            } catch (e: Exception) {
+                result.completeExceptionally(e)
+            }
+        }
+
+        return result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
+    }
+
+    private fun getCapturePacketTypeCount(
+        packetTracker: ConnectivityPacketTracker
+    ): Int {
+        val result = CompletableFuture<Int>()
+        handler.post {
+            try {
+                val totalCnt = packetTracker.capturePacketTypeCount
+                result.complete(totalCnt)
+            } catch (e: Exception) {
+                result.completeExceptionally(e)
+            }
+        }
+
+        return result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
+    }
+}
\ No newline at end of file
diff --git a/tests/unit/src/android/net/ip/IpClientTest.java b/tests/unit/src/android/net/ip/IpClientTest.java
index 00982c7c..3fc843e3 100644
--- a/tests/unit/src/android/net/ip/IpClientTest.java
+++ b/tests/unit/src/android/net/ip/IpClientTest.java
@@ -16,11 +16,17 @@
 
 package android.net.ip;
 
+import static android.net.apf.BaseApfGenerator.APF_VERSION_6;
 import static android.net.ip.IpClientLinkObserver.CONFIG_SOCKET_RECV_BUFSIZE;
 import static android.net.ip.IpClientLinkObserver.SOCKET_RECV_BUFSIZE;
+import static android.system.OsConstants.AF_UNSPEC;
+import static android.system.OsConstants.ARPHRD_ETHER;
+import static android.system.OsConstants.IFA_F_PERMANENT;
+import static android.system.OsConstants.IFA_F_TENTATIVE;
 import static android.system.OsConstants.RT_SCOPE_UNIVERSE;
 
 import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
+import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWLINK;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTPROT_KERNEL;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_DELROUTE;
 import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWADDR;
@@ -44,9 +50,11 @@ import static org.mockito.Mockito.anyString;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
+import static org.mockito.Mockito.inOrder;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.timeout;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
@@ -67,6 +75,7 @@ import android.net.LinkProperties;
 import android.net.MacAddress;
 import android.net.NetworkStackIpMemoryStore;
 import android.net.RouteInfo;
+import android.net.apf.AndroidPacketFilter;
 import android.net.apf.ApfCapabilities;
 import android.net.apf.ApfFilter.ApfConfiguration;
 import android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor;
@@ -87,8 +96,10 @@ import com.android.modules.utils.build.SdkLevel;
 import com.android.net.module.util.InterfaceParams;
 import com.android.net.module.util.netlink.NduseroptMessage;
 import com.android.net.module.util.netlink.RtNetlinkAddressMessage;
+import com.android.net.module.util.netlink.RtNetlinkLinkMessage;
 import com.android.net.module.util.netlink.RtNetlinkRouteMessage;
 import com.android.net.module.util.netlink.StructIfaddrMsg;
+import com.android.net.module.util.netlink.StructIfinfoMsg;
 import com.android.net.module.util.netlink.StructNdOptRdnss;
 import com.android.net.module.util.netlink.StructNlMsgHdr;
 import com.android.net.module.util.netlink.StructRtMsg;
@@ -105,6 +116,7 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
+import org.mockito.InOrder;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
@@ -135,6 +147,8 @@ public class IpClientTest {
     private static final String INVALID = "INVALID";
     private static final String TEST_IFNAME = "test_wlan0";
     private static final int TEST_IFINDEX = 1001;
+    private static final String TEST_CLAT_IFNAME = "v4-" + TEST_IFNAME;
+    private static final int TEST_CLAT_IFINDEX = 1002;
     // See RFC 7042#section-2.1.2 for EUI-48 documentation values.
     private static final MacAddress TEST_MAC = MacAddress.fromString("00:00:5E:00:53:01");
     private static final int TEST_TIMEOUT_MS = 30_000;
@@ -176,6 +190,7 @@ public class IpClientTest {
     @Mock private FileDescriptor mFd;
     @Mock private PrintWriter mWriter;
     @Mock private IpClientNetlinkMonitor mNetlinkMonitor;
+    @Mock private AndroidPacketFilter mApfFilter;
 
     private InterfaceParams mIfParams;
     private INetlinkMessageProcessor mNetlinkMessageProcessor;
@@ -296,6 +311,21 @@ public class IpClientTest {
                 (byte) 0 /* icmp_code */, option, null /* srcaddr */);
     }
 
+    private static RtNetlinkLinkMessage buildRtmLinkMessage(short type, int ifindex,
+            String ifaceName) {
+        final StructNlMsgHdr nlmsghdr =
+                makeNetlinkMessageHeader(type, (short) (NLM_F_REQUEST | NLM_F_ACK));
+        final StructIfinfoMsg ifInfoMsg =
+                new StructIfinfoMsg(
+                        (short) AF_UNSPEC,
+                        ARPHRD_ETHER,
+                        ifindex,
+                        0 /* flags */,
+                        0xffffffffL /* change */);
+
+        return RtNetlinkLinkMessage.build(nlmsghdr, ifInfoMsg, 0 /* mtu */, TEST_MAC, ifaceName);
+    }
+
     private void onInterfaceAddressUpdated(final LinkAddress la, int flags) {
         final RtNetlinkAddressMessage msg =
                 buildRtmAddressMessage(RTM_NEWADDR, la, TEST_IFINDEX, flags);
@@ -317,6 +347,12 @@ public class IpClientTest {
         mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
     }
 
+    private void onInterfaceAdded(int ifaceIndex, String ifaceName) {
+        final RtNetlinkLinkMessage msg = buildRtmLinkMessage(RTM_NEWLINK, ifaceIndex, ifaceName);
+        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
+    }
+
+
     @Test
     public void testNullInterfaceNameMostDefinitelyThrows() throws Exception {
         setTestInterfaceParams(null);
@@ -806,16 +842,21 @@ public class IpClientTest {
                         conf(links(TEST_LOCAL_ADDRESSES), prefixes(TEST_PREFIXES), ips()));
         if (isApfSupported) {
             config.withApfCapabilities(new ApfCapabilities(4 /* version */,
-                    4096 /* maxProgramSize */, 4 /* format */));
+                    4096 /* maxProgramSize */, ARPHRD_ETHER));
         }
 
         ipc.startProvisioning(config.build());
         final ArgumentCaptor<ApfConfiguration> configCaptor = ArgumentCaptor.forClass(
                 ApfConfiguration.class);
-        verify(mDependencies, timeout(TEST_TIMEOUT_MS)).maybeCreateApfFilter(
-                any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
+        if (isApfSupported) {
+            verify(mDependencies, timeout(TEST_TIMEOUT_MS)).maybeCreateApfFilter(
+                    any(), any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
+        } else {
+            verify(mDependencies, never()).maybeCreateApfFilter(
+                    any(), any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
+        }
 
-        return configCaptor.getValue();
+        return isApfSupported ? configCaptor.getValue() : null;
     }
 
     @Test @IgnoreAfter(Build.VERSION_CODES.R)
@@ -872,23 +913,20 @@ public class IpClientTest {
         final IpClient ipc = makeIpClient(TEST_IFNAME);
         final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                 false /* isApfSupported */);
-        assertNull(config.apfCapabilities);
-        clearInvocations(mDependencies);
+        assertNull(config);
 
         ipc.updateApfCapabilities(new ApfCapabilities(4 /* version */, 4096 /* maxProgramSize */,
-                4 /* format */));
+                ARPHRD_ETHER));
         HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
 
         final ArgumentCaptor<ApfConfiguration> configCaptor = ArgumentCaptor.forClass(
                 ApfConfiguration.class);
         verify(mDependencies, timeout(TEST_TIMEOUT_MS)).maybeCreateApfFilter(
-                any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
+                any(), any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
         final ApfConfiguration actual = configCaptor.getValue();
         assertNotNull(actual);
-        int expectedApfVersion = SdkLevel.isAtLeastS() ? 4 : 3;
-        assertEquals(expectedApfVersion, actual.apfCapabilities.apfVersionSupported);
-        assertEquals(4096, actual.apfCapabilities.maximumApfProgramSize);
-        assertEquals(4, actual.apfCapabilities.apfPacketFormat);
+        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, actual.apfVersionSupported);
+        assertEquals(4096, actual.apfRamSize);
 
         verifyShutdown(ipc);
     }
@@ -897,8 +935,9 @@ public class IpClientTest {
     public void testDumpApfFilter_withNoException() throws Exception {
         final IpClient ipc = makeIpClient(TEST_IFNAME);
         final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
-                false /* isApfSupported */);
-        assertNull(config.apfCapabilities);
+                true /* isApfSupported */);
+        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
+        assertEquals(4096, config.apfRamSize);
         clearInvocations(mDependencies);
         ipc.dump(mFd, mWriter, null /* args */);
         verifyShutdown(ipc);
@@ -909,15 +948,16 @@ public class IpClientTest {
         final IpClient ipc = makeIpClient(TEST_IFNAME);
         final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                 true /* isApfSupported */);
-        assertNotNull(config.apfCapabilities);
+        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
+        assertEquals(4096, config.apfRamSize);
         clearInvocations(mDependencies);
 
         final ApfCapabilities newApfCapabilities = new ApfCapabilities(4 /* version */,
-                8192 /* maxProgramSize */, 4 /* format */);
+                8192 /* maxProgramSize */, ARPHRD_ETHER);
         ipc.updateApfCapabilities(newApfCapabilities);
         HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
         verify(mDependencies, never()).maybeCreateApfFilter(any(), any(), any(), any(), any(),
-                anyBoolean());
+                any(), anyBoolean());
         verifyShutdown(ipc);
     }
 
@@ -926,13 +966,113 @@ public class IpClientTest {
         final IpClient ipc = makeIpClient(TEST_IFNAME);
         final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                 true /* isApfSupported */);
-        assertNotNull(config.apfCapabilities);
+        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
+        assertEquals(4096, config.apfRamSize);
         clearInvocations(mDependencies);
 
         ipc.updateApfCapabilities(null /* apfCapabilities */);
         HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
         verify(mDependencies, never()).maybeCreateApfFilter(any(), any(), any(), any(), any(),
-                anyBoolean());
+                any(), anyBoolean());
+        verifyShutdown(ipc);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    public void testVendorNdOffloadDisabledWhenApfV6Supported() throws Exception {
+        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
+                anyBoolean())).thenReturn(mApfFilter);
+        when(mApfFilter.supportNdOffload()).thenReturn(true);
+        final IpClient ipc = makeIpClient(TEST_IFNAME);
+        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
+                .withoutIPv4()
+                .withoutIpReachabilityMonitor()
+                .withApfCapabilities(new ApfCapabilities(APF_VERSION_6,
+                        4096 /* maxProgramSize */, ARPHRD_ETHER))
+                .build();
+        ipc.startProvisioning(config);
+        final InOrder inOrder = inOrder(mCb);
+        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
+        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(false);
+
+        // update clat
+        onInterfaceAdded(TEST_CLAT_IFINDEX, TEST_CLAT_IFNAME);
+        verifyShutdown(ipc);
+        inOrder.verify(mCb, never()).setNeighborDiscoveryOffload(anyBoolean());
+        clearInvocations(mApfFilter);
+        clearInvocations(mCb);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    public void testVendorNdOffloadEnabledWhenApfV6NotSupported() throws Exception {
+        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
+                anyBoolean())).thenReturn(mApfFilter);
+        when(mApfFilter.supportNdOffload()).thenReturn(false);
+        final IpClient ipc = makeIpClient(TEST_IFNAME);
+        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
+                .withoutIPv4()
+                .withoutIpReachabilityMonitor()
+                .withApfCapabilities(new ApfCapabilities(APF_VERSION_6,
+                        4096 /* maxProgramSize */, ARPHRD_ETHER))
+                .build();
+        ipc.startProvisioning(config);
+        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
+
+        // update clat
+        onInterfaceAdded(TEST_CLAT_IFINDEX, TEST_CLAT_IFNAME);
+        verifyShutdown(ipc);
+        verify(mCb, times(1)).setNeighborDiscoveryOffload(true);
+        clearInvocations(mApfFilter);
+        clearInvocations(mCb);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
+    public void testVendorNdOffloadDisabledWhenApfCapabilitiesUpdated() throws Exception {
+        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
+                anyBoolean())).thenReturn(mApfFilter);
+        when(mApfFilter.supportNdOffload()).thenReturn(true);
+        final IpClient ipc = makeIpClient(TEST_IFNAME);
+        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
+                .withoutIPv4()
+                .withoutIpReachabilityMonitor()
+                .build();
+        ipc.startProvisioning(config);
+        ipc.updateApfCapabilities(
+                new ApfCapabilities(APF_VERSION_6, 4096 /* maxProgramSize */, ARPHRD_ETHER));
+        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
+        final InOrder inOrder = inOrder(mCb);
+        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
+        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(false);
+        verifyShutdown(ipc);
+        inOrder.verify(mCb, never()).setNeighborDiscoveryOffload(anyBoolean());
+        clearInvocations(mApfFilter);
+        clearInvocations(mCb);
+    }
+
+    @Test
+    public void testLinkPropertiesUpdate_callSetLinkPropertiesOnApfFilter() throws Exception {
+        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
+                anyBoolean())).thenReturn(mApfFilter);
+        final IpClient ipc = makeIpClient(TEST_IFNAME);
+        verifyApfFilterCreatedOnStart(ipc, true /* isApfSupported */);
+        onInterfaceAddressUpdated(
+                new LinkAddress(TEST_GLOBAL_ADDRESS, IFA_F_TENTATIVE, RT_SCOPE_UNIVERSE),
+                IFA_F_TENTATIVE);
+        // mApfFilter.setLinkProperties() is called both in IpClient#handleLinkPropertiesUpdate()
+        // and IpClient#setLinkProperties().
+        verify(mApfFilter, timeout(TEST_TIMEOUT_MS).times(2)).setLinkProperties(any());
+        // LinkAddress flag change will trigger mApfFilter.setLinkProperties()
+        onInterfaceAddressUpdated(
+                new LinkAddress(TEST_GLOBAL_ADDRESS, IFA_F_PERMANENT, RT_SCOPE_UNIVERSE),
+                IFA_F_PERMANENT);
+        // mApfFilter.setLinkProperties() is called only in IpClient#handleLinkPropertiesUpdate().
+        // IpClient#setLinkProperties() is not called because Objects.equals(newLp,
+        // mLinkProperties) returns true and IpClient#handleLinkPropertiesUpdate() is terminated.
+        verify(mApfFilter, timeout(TEST_TIMEOUT_MS).times(3)).setLinkProperties(any());
+        clearInvocations(mDependencies);
+        clearInvocations(mApfFilter);
         verifyShutdown(ipc);
     }
 
diff --git a/tests/unit/src/android/net/shared/PrivateDnsConfigTest.java b/tests/unit/src/android/net/shared/PrivateDnsConfigTest.java
index 94f04d5c..2320470c 100644
--- a/tests/unit/src/android/net/shared/PrivateDnsConfigTest.java
+++ b/tests/unit/src/android/net/shared/PrivateDnsConfigTest.java
@@ -22,6 +22,8 @@ import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_PROVIDER_
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 
 import android.net.PrivateDnsConfigParcel;
 
@@ -55,6 +57,7 @@ public final class PrivateDnsConfigTest {
         assertEquals(a.mode, b.mode);
         assertEquals(a.hostname, b.hostname);
         assertArrayEquals(a.ips, b.ips);
+        assertEquals(a.ddrEnabled, b.ddrEnabled);
         assertEquals(a.dohName, b.dohName);
         assertArrayEquals(a.dohIps, b.dohIps);
         assertEquals(a.dohPath, b.dohPath);
@@ -65,6 +68,7 @@ public final class PrivateDnsConfigTest {
         assertEquals(parcel.privateDnsMode, cfg.mode);
         assertEquals(parcel.hostname, cfg.hostname);
         assertArrayEquals(parcel.ips, toStringArray(cfg.ips));
+        assertEquals(parcel.ddrEnabled, cfg.ddrEnabled);
         assertEquals(parcel.dohName, cfg.dohName);
         assertEquals(parcel.dohPath, cfg.dohPath);
         assertEquals(parcel.dohPort, cfg.dohPort);
@@ -102,19 +106,23 @@ public final class PrivateDnsConfigTest {
         //                  String dohName, InetAddress[] dohIps, String dohPath, int dohPort)
         for (int mode : new int[] { OFF_MODE, OPPORTUNISTIC_MODE, STRICT_MODE }) {
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, null, null,
-                    null, null, null, -1));
+                    false, null, null, null, -1));
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", null,
-                    null, null, null, -1));
+                    false, null, null, null, -1));
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", TEST_ADDRS,
-                    null, null, null, -1));
+                    false, null, null, null, -1));
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", TEST_ADDRS,
-                    "doh.com", null, null, -1));
+                    true, null, null, null, -1));
+            testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", null,
+                    true, null, null, null, -1));
+            testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", TEST_ADDRS,
+                    true, "doh.com", null, null, -1));
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", TEST_ADDRS,
-                    "doh.com", TEST_ADDRS, null, -1));
+                    true, "doh.com", TEST_ADDRS, null, -1));
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", TEST_ADDRS,
-                    "doh.com", TEST_ADDRS, "dohpath=/some-path{?dns}", -1));
+                    true, "doh.com", TEST_ADDRS, "dohpath=/some-path{?dns}", -1));
             testPrivateDnsConfigConversion(new PrivateDnsConfig(mode, "dns.com", TEST_ADDRS,
-                    "doh.com", TEST_ADDRS, "dohpath=/some-path{?dns}", 443));
+                    true, "doh.com", TEST_ADDRS, "dohpath=/some-path{?dns}", 443));
         }
     }
 
@@ -123,11 +131,30 @@ public final class PrivateDnsConfigTest {
         final InetAddress ip = InetAddress.parseNumericAddress("1.2.3.4");
         final InetAddress[] ipArray = new InetAddress[] { ip };
         final PrivateDnsConfig cfg = new PrivateDnsConfig(OPPORTUNISTIC_MODE, null /* hostname */,
-                ipArray /* ips */, null /* dohName */, ipArray /* dohIps */, null /* dohPath */,
-                -1 /* dohPort */);
+                ipArray /* ips */, false /* ddrEnabled */, null /* dohName */, ipArray /* dohIps */,
+                null /* dohPath */, -1 /* dohPort */);
 
         ipArray[0] = InetAddress.parseNumericAddress("2001:db8::2");
         assertArrayEquals(new InetAddress[] { ip }, cfg.ips);
         assertArrayEquals(new InetAddress[] { ip }, cfg.dohIps);
     }
+
+    @Test
+    public void testSettingsComparison() {
+        final PrivateDnsConfig off = new PrivateDnsConfig(false);
+        final PrivateDnsConfig opportunistic = new PrivateDnsConfig(true);
+        final PrivateDnsConfig strict = new PrivateDnsConfig("dns.com", null);
+
+        assertFalse(opportunistic.areSettingsSameAs(off));
+        assertFalse(opportunistic.areSettingsSameAs(strict));
+        assertTrue(opportunistic.areSettingsSameAs(new PrivateDnsConfig(
+                OPPORTUNISTIC_MODE, null, TEST_ADDRS, false, null, null, null, -1)));
+
+        assertFalse(strict.areSettingsSameAs(off));
+        assertFalse(strict.areSettingsSameAs(opportunistic));
+        assertTrue(strict.areSettingsSameAs(new PrivateDnsConfig(
+                STRICT_MODE, "dns.com", TEST_ADDRS, false, null, null, null, -1)));
+        assertFalse(strict.areSettingsSameAs(new PrivateDnsConfig(
+                STRICT_MODE, "foo.com", TEST_ADDRS, false, null, null, null, -1)));
+    }
 }
diff --git a/tests/unit/src/android/net/testutils/NetworkStatsUtilsTest.kt b/tests/unit/src/android/net/testutils/NetworkStatsUtilsTest.kt
deleted file mode 100644
index 2e76c524..00000000
--- a/tests/unit/src/android/net/testutils/NetworkStatsUtilsTest.kt
+++ /dev/null
@@ -1,70 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-package android.net.testutils
-
-import android.net.NetworkStats
-import android.net.NetworkStats.DEFAULT_NETWORK_NO
-import android.net.NetworkStats.METERED_NO
-import android.net.NetworkStats.ROAMING_NO
-import android.net.NetworkStats.SET_DEFAULT
-import android.net.NetworkStats.TAG_NONE
-import android.os.Build
-import com.android.testutils.DevSdkIgnoreRule
-import com.android.testutils.orderInsensitiveEquals
-import org.junit.Rule
-import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.JUnit4
-import kotlin.test.assertFalse
-import kotlin.test.assertTrue
-
-private const val TEST_IFACE = "test0"
-private const val TEST_IFACE2 = "test2"
-private const val TEST_START = 1194220800000L
-
-@RunWith(JUnit4::class)
-class NetworkStatsUtilsTest {
-    // This is a unit test for a test utility that uses R APIs
-    @Rule @JvmField
-    val ignoreRule = DevSdkIgnoreRule(ignoreClassUpTo = Build.VERSION_CODES.Q)
-
-    @Test
-    fun testOrderInsensitiveEquals() {
-        val testEntry = arrayOf(
-                NetworkStats.Entry(TEST_IFACE, 100, SET_DEFAULT, TAG_NONE, METERED_NO, ROAMING_NO,
-                        DEFAULT_NETWORK_NO, 128L, 8L, 0L, 2L, 20L),
-                NetworkStats.Entry(TEST_IFACE2, 100, SET_DEFAULT, TAG_NONE, METERED_NO, ROAMING_NO,
-                        DEFAULT_NETWORK_NO, 512L, 32L, 0L, 0L, 0L))
-
-        // Verify equals of empty stats regardless of initial capacity.
-        val red = NetworkStats(TEST_START, 0)
-        val blue = NetworkStats(TEST_START, 1)
-        assertTrue(orderInsensitiveEquals(red, blue))
-        assertTrue(orderInsensitiveEquals(blue, red))
-
-        // Verify not equal.
-        red.combineValues(testEntry[1])
-        blue.combineValues(testEntry[0]).combineValues(testEntry[1])
-        assertFalse(orderInsensitiveEquals(red, blue))
-        assertFalse(orderInsensitiveEquals(blue, red))
-
-        // Verify equals even if the order of entries are not the same.
-        red.combineValues(testEntry[0])
-        assertTrue(orderInsensitiveEquals(red, blue))
-        assertTrue(orderInsensitiveEquals(blue, red))
-    }
-}
\ No newline at end of file
diff --git a/tests/unit/src/android/net/util/RawSocketUtilsTest.kt b/tests/unit/src/android/net/util/RawSocketUtilsTest.kt
new file mode 100644
index 00000000..45bee546
--- /dev/null
+++ b/tests/unit/src/android/net/util/RawSocketUtilsTest.kt
@@ -0,0 +1,156 @@
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
+package android.net.util
+
+import android.content.Context
+import android.net.TetheringManager
+import android.system.Os
+import com.android.dx.mockito.inline.extended.ExtendedMockito
+import com.android.net.module.util.HexDump
+import com.android.testutils.DevSdkIgnoreRule
+import com.android.testutils.DevSdkIgnoreRunner
+import java.io.FileDescriptor
+import java.net.NetworkInterface
+import kotlin.test.assertEquals
+import kotlin.test.assertFailsWith
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentCaptor
+import org.mockito.ArgumentMatchers.any
+import org.mockito.ArgumentMatchers.eq
+import org.mockito.Mock
+import org.mockito.Mockito.doAnswer
+import org.mockito.Mockito.doReturn
+import org.mockito.Mockito.framework
+import org.mockito.Mockito.`when`
+import org.mockito.MockitoSession
+import org.mockito.quality.Strictness
+
+@RunWith(DevSdkIgnoreRunner::class)
+class RawSocketUtilsTest {
+    @get:Rule
+    val ignoreRule = DevSdkIgnoreRule()
+    companion object {
+        private const val TEST_IFINDEX = 123
+        private const val TEST_IFACENAME = "wlan0"
+        private const val TEST_SRC_MAC = "FFFFFFFFFFFF"
+        private const val TEST_DST_MAC = "1234567890AB"
+        private const val TEST_INVALID_PACKET_IN_HEX = "DEADBEEF"
+        private const val TEST_PACKET_TYPE_IN_HEX = "88A4"
+        private const val TEST_VALID_PACKET_IN_HEX =
+                TEST_DST_MAC + TEST_SRC_MAC + TEST_PACKET_TYPE_IN_HEX
+    }
+    @Mock
+    private lateinit var mockContext: Context
+    @Mock
+    private lateinit var mockTetheringManager: TetheringManager
+    @Mock
+    private lateinit var mockNetworkInterface: NetworkInterface
+
+    // For mocking static methods.
+    private lateinit var mockitoSession: MockitoSession
+
+    @Before
+    fun setup() {
+        mockitoSession = ExtendedMockito.mockitoSession()
+                .mockStatic(Os::class.java)
+                .mockStatic(NetworkInterface::class.java)
+                .mockStatic(SocketUtils::class.java)
+                .initMocks(this)
+                .strictness(Strictness.LENIENT)
+                .startMocking()
+        doReturn(mockTetheringManager).`when`(mockContext)
+                .getSystemService(eq(TetheringManager::class.java))
+        `when`(NetworkInterface.getByName(any())).thenReturn(mockNetworkInterface)
+        doReturn(TEST_IFINDEX).`when`(mockNetworkInterface).index
+    }
+
+    @After
+    fun teardown() {
+        mockitoSession.finishMocking()
+        // Clear mocks to prevent from stubs holding instances and cause memory leaks.
+        framework().clearInlineMocks()
+    }
+
+    @Test
+    fun sendRawPacketDownStream_invalidTetheredInterface() {
+        doAnswer {
+            val callback = it.arguments[1] as TetheringManager.TetheringEventCallback
+            callback.onTetheredInterfacesChanged(listOf("eth0"))
+        }.`when`(mockTetheringManager).registerTetheringEventCallback(any(), any())
+        assertFailsWith<SecurityException> {
+            RawSocketUtils.sendRawPacketDownStream(
+                mockContext,
+                TEST_IFACENAME,
+                TEST_INVALID_PACKET_IN_HEX
+            )
+        }
+    }
+
+    @Test
+    fun sendRawPacketDownStream_invalidPacket() {
+        doAnswer {
+            val callback = it.arguments[1] as TetheringManager.TetheringEventCallback
+            callback.onTetheredInterfacesChanged(listOf(TEST_IFACENAME))
+        }.`when`(mockTetheringManager).registerTetheringEventCallback(any(), any())
+
+        assertFailsWith<ArrayIndexOutOfBoundsException> {
+            RawSocketUtils.sendRawPacketDownStream(
+                    mockContext,
+                    TEST_IFACENAME,
+                    TEST_INVALID_PACKET_IN_HEX
+            )
+        }
+    }
+
+    @Test
+    fun sendRawPacketDownStream_validPacket() {
+        doAnswer {
+            val callback = it.arguments[1] as TetheringManager.TetheringEventCallback
+            callback.onTetheredInterfacesChanged(listOf(TEST_IFACENAME))
+        }.`when`(mockTetheringManager).registerTetheringEventCallback(any(), any())
+
+        RawSocketUtils.sendRawPacketDownStream(
+            mockContext,
+            TEST_IFACENAME,
+            TEST_VALID_PACKET_IN_HEX
+        )
+
+        // Verify interactions with mocked static methods.
+        val fileDescriptorCaptor = ArgumentCaptor.forClass(FileDescriptor::class.java)
+        val packetDataCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
+        val packetDataLengthCaptor = ArgumentCaptor.forClass(Int::class.java)
+        ExtendedMockito.verify {
+            Os.sendto(
+                fileDescriptorCaptor.capture(),
+                packetDataCaptor.capture(),
+                eq(0),
+                packetDataLengthCaptor.capture(),
+                eq(0),
+                any()
+            )
+        }
+        assertEquals(TEST_VALID_PACKET_IN_HEX, HexDump.toHexString(packetDataCaptor.value))
+        assertEquals(TEST_VALID_PACKET_IN_HEX.length / 2, packetDataLengthCaptor.value)
+        // TODO: Verify ifindex and packetType once the members of PacketSocketAddress
+        //  can be accessed.
+        ExtendedMockito.verify { SocketUtils.closeSocket(eq(fileDescriptorCaptor.value)) }
+    }
+}
diff --git a/tests/unit/src/com/android/networkstack/NetworkStackNotifierTest.kt b/tests/unit/src/com/android/networkstack/NetworkStackNotifierTest.kt
index 9fda1893..efd40694 100644
--- a/tests/unit/src/com/android/networkstack/NetworkStackNotifierTest.kt
+++ b/tests/unit/src/com/android/networkstack/NetworkStackNotifierTest.kt
@@ -50,7 +50,6 @@ import com.android.networkstack.NetworkStackNotifier.CHANNEL_VENUE_INFO
 import com.android.networkstack.NetworkStackNotifier.CONNECTED_NOTIFICATION_TIMEOUT_MS
 import com.android.networkstack.NetworkStackNotifier.Dependencies
 import com.android.networkstack.apishim.NetworkInformationShimImpl
-import com.android.modules.utils.build.SdkLevel.isAtLeastR
 import com.android.modules.utils.build.SdkLevel.isAtLeastS
 import org.junit.Assume.assumeTrue
 import org.junit.Before
@@ -236,8 +235,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testConnectedNotification_WithSsid() {
-        // NetworkCapabilities#getSSID is not available for API <= Q
-        assumeTrue(isAtLeastR())
         val capabilities = NetworkCapabilities(VALIDATED_CAPABILITIES).setSSID(TEST_SSID)
 
         onCapabilitiesChanged(EMPTY_CAPABILITIES)
@@ -253,8 +250,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testConnectedVenueInfoNotification() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         mNotifier.notifyCaptivePortalValidationPending(TEST_NETWORK)
         onLinkPropertiesChanged(mTestCapportLp)
         onDefaultNetworkAvailable(TEST_NETWORK)
@@ -271,8 +266,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testConnectedVenueInfoNotification_VenueInfoDisabled() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         val channel = NotificationChannel(CHANNEL_VENUE_INFO, "test channel", IMPORTANCE_NONE)
         doReturn(channel).`when`(mNotificationChannelsNm).getNotificationChannel(CHANNEL_VENUE_INFO)
         mNotifier.notifyCaptivePortalValidationPending(TEST_NETWORK)
@@ -290,8 +283,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testVenueInfoNotification() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         onLinkPropertiesChanged(mTestCapportLp)
         onDefaultNetworkAvailable(TEST_NETWORK)
         val capabilities = NetworkCapabilities(VALIDATED_CAPABILITIES).setSSID(TEST_SSID)
@@ -308,8 +299,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testVenueInfoNotification_VenueInfoDisabled() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         doReturn(null).`when`(mNm).getNotificationChannel(CHANNEL_VENUE_INFO)
         onLinkPropertiesChanged(mTestCapportLp)
         onDefaultNetworkAvailable(TEST_NETWORK)
@@ -321,8 +310,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testNonDefaultVenueInfoNotification() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         onLinkPropertiesChanged(mTestCapportLp)
         onCapabilitiesChanged(VALIDATED_CAPABILITIES)
         mLooper.processAllMessages()
@@ -332,8 +319,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testEmptyCaptivePortalDataVenueInfoNotification() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         onLinkPropertiesChanged(EMPTY_CAPPORT_LP)
         onCapabilitiesChanged(VALIDATED_CAPABILITIES)
         mLooper.processAllMessages()
@@ -343,8 +328,6 @@ class NetworkStackNotifierTest {
 
     @Test
     fun testUnvalidatedNetworkVenueInfoNotification() {
-        // Venue info (CaptivePortalData) is not available for API <= Q
-        assumeTrue(isAtLeastR())
         onLinkPropertiesChanged(mTestCapportLp)
         onCapabilitiesChanged(EMPTY_CAPABILITIES)
         mLooper.processAllMessages()
diff --git a/tests/unit/src/com/android/networkstack/ipmemorystore/IpMemoryStoreServiceTest.java b/tests/unit/src/com/android/networkstack/ipmemorystore/IpMemoryStoreServiceTest.java
index d1924255..ee6c48bd 100644
--- a/tests/unit/src/com/android/networkstack/ipmemorystore/IpMemoryStoreServiceTest.java
+++ b/tests/unit/src/com/android/networkstack/ipmemorystore/IpMemoryStoreServiceTest.java
@@ -16,6 +16,15 @@
 
 package com.android.networkstack.ipmemorystore;
 
+import static android.net.ip.IpClient.NETWORK_EVENT_NUD_FAILURE_TYPES;
+import static android.net.ip.IpClient.ONE_DAY_IN_MS;
+import static android.net.ip.IpClient.ONE_WEEK_IN_MS;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ROAM;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_CONFIRM;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_ORGANIC;
+import static android.net.IIpMemoryStore.NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED;
+
+import static com.android.networkstack.ipmemorystore.IpMemoryStoreDatabase.DbHelper.SCHEMA_VERSION;
 import static com.android.networkstack.ipmemorystore.RegularMaintenanceJobService.InterruptMaintenance;
 
 import static org.junit.Assert.assertEquals;
@@ -29,10 +38,13 @@ import static org.mockito.Mockito.doReturn;
 
 import android.app.job.JobScheduler;
 import android.content.Context;
+import android.database.sqlite.SQLiteDatabase;
+import android.database.sqlite.SQLiteOpenHelper;
 import android.net.ipmemorystore.Blob;
 import android.net.ipmemorystore.IOnBlobRetrievedListener;
 import android.net.ipmemorystore.IOnL2KeyResponseListener;
 import android.net.ipmemorystore.IOnNetworkAttributesRetrievedListener;
+import android.net.ipmemorystore.IOnNetworkEventCountRetrievedListener;
 import android.net.ipmemorystore.IOnSameL3NetworkResponseListener;
 import android.net.ipmemorystore.IOnStatusAndCountListener;
 import android.net.ipmemorystore.IOnStatusListener;
@@ -89,6 +101,13 @@ public class IpMemoryStoreServiceTest {
     private static final String TEST_CLIENT_ID = "testClientId";
     private static final String TEST_DATA_NAME = "testData";
     private static final String TEST_DATABASE_NAME = "test.db";
+    private static final String TEST_CLUSTER = "testCluster12345";
+    private static final String TEST_CLUSTER_1 = "testCluster01234";
+
+    private static final File FILES_DIR = InstrumentationRegistry.getContext().getFilesDir();
+    private static final String OLD_DB_NAME = "IpMemoryStore.db";
+    private static final File OLD_DB = new File(FILES_DIR, OLD_DB_NAME);
+    private static final File TEST_DB = new File(FILES_DIR, TEST_DATABASE_NAME);
 
     private static final int TEST_DATABASE_SIZE_THRESHOLD = 100 * 1024; //100KB
     private static final int DEFAULT_TIMEOUT_MS = 5000;
@@ -99,8 +118,8 @@ public class IpMemoryStoreServiceTest {
     private static final long UNIX_TIME_MS_2100_01_01 = 4102412400000L;
     private static final int MTU_NULL = -1;
     private static final String[] FAKE_KEYS;
-    private static final byte[] TEST_BLOB_DATA = new byte[] { -3, 6, 8, -9, 12,
-            -128, 0, 89, 112, 91, -34 };
+    private static final byte[] TEST_BLOB_DATA = new byte[]{-3, 6, 8, -9, 12,
+            -128, 0, 89, 112, 91, -34};
     static {
         FAKE_KEYS = new String[FAKE_KEY_COUNT];
         for (int i = 0; i < FAKE_KEYS.length; ++i) {
@@ -116,16 +135,14 @@ public class IpMemoryStoreServiceTest {
 
     private IpMemoryStoreService mService;
 
-    @Before
-    public void setUp() {
-        MockitoAnnotations.initMocks(this);
-        final Context context = InstrumentationRegistry.getContext();
-        final File dir = context.getFilesDir();
-        mDbFile = new File(dir, TEST_DATABASE_NAME);
+    private IpMemoryStoreService createService() {
+        mDbFile = TEST_DB;
         doReturn(mDbFile).when(mMockContext).getDatabasePath(anyString());
+        doReturn(OLD_DB).when(mMockContext).getDatabasePath(OLD_DB_NAME);
+
         doReturn(mMockJobScheduler).when(mMockContext)
                 .getSystemService(Context.JOB_SCHEDULER_SERVICE);
-        mService = new IpMemoryStoreService(mMockContext) {
+        final IpMemoryStoreService service = new IpMemoryStoreService(mMockContext) {
             @Override
             protected int getDbSizeThreshold() {
                 return TEST_DATABASE_SIZE_THRESHOLD;
@@ -139,12 +156,20 @@ public class IpMemoryStoreServiceTest {
                 return super.isDbSizeOverThreshold();
             }
         };
+        return service;
+    }
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mService = createService();
     }
 
     @After
     public void tearDown() {
         mService.shutdown();
         mDbFile.delete();
+        if (OLD_DB.exists()) OLD_DB.delete();
     }
 
     private void copyTestData(final File file) throws Exception {
@@ -235,6 +260,7 @@ public class IpMemoryStoreServiceTest {
     private interface OnBlobRetrievedListener {
         void onBlobRetrieved(Status status, String l2Key, String name, byte[] data);
     }
+
     private IOnBlobRetrievedListener onBlobRetrieved(final OnBlobRetrievedListener functor) {
         return new IOnBlobRetrievedListener() {
             @Override
@@ -262,9 +288,10 @@ public class IpMemoryStoreServiceTest {
     }
 
     /** Helper method to make an IOnNetworkAttributesRetrievedListener */
-    private interface OnNetworkAttributesRetrievedListener  {
+    private interface OnNetworkAttributesRetrievedListener {
         void onNetworkAttributesRetrieved(Status status, String l2Key, NetworkAttributes attr);
     }
+
     private IOnNetworkAttributesRetrievedListener onNetworkAttributesRetrieved(
             final OnNetworkAttributesRetrievedListener functor) {
         return new IOnNetworkAttributesRetrievedListener() {
@@ -297,6 +324,7 @@ public class IpMemoryStoreServiceTest {
     private interface OnSameL3NetworkResponseListener {
         void onSameL3NetworkResponse(Status status, SameL3NetworkResponse answer);
     }
+
     private IOnSameL3NetworkResponseListener onSameResponse(
             final OnSameL3NetworkResponseListener functor) {
         return new IOnSameL3NetworkResponseListener() {
@@ -329,6 +357,7 @@ public class IpMemoryStoreServiceTest {
     private interface OnL2KeyResponseListener {
         void onL2KeyResponse(Status status, String key);
     }
+
     private IOnL2KeyResponseListener onL2KeyResponse(final OnL2KeyResponseListener functor) {
         return new IOnL2KeyResponseListener() {
             @Override
@@ -354,6 +383,37 @@ public class IpMemoryStoreServiceTest {
         };
     }
 
+    /** Helper method to make an IOnNetworkEventCountRetrievedListener */
+    private interface OnNetworkEventCountRetrievedListener {
+        void onNetworkEventCountRetrieved(Status status, int[] counts);
+    }
+
+    private IOnNetworkEventCountRetrievedListener onNetworkEventCountRetrieved(
+            final OnNetworkEventCountRetrievedListener functor) {
+        return new IOnNetworkEventCountRetrievedListener() {
+            @Override
+            public void onNetworkEventCountRetrieved(final StatusParcelable status,
+                    final int[] counts) throws RemoteException {
+                functor.onNetworkEventCountRetrieved(new Status(status), counts);
+            }
+
+            @Override
+            public IBinder asBinder() {
+                return null;
+            }
+
+            @Override
+            public int getInterfaceVersion() {
+                return this.VERSION;
+            }
+
+            @Override
+            public String getInterfaceHash() {
+                return this.HASH;
+            }
+        };
+    }
+
     // Helper method to factorize some boilerplate
     private void doLatched(final String timeoutMessage, final Consumer<CountDownLatch> functor) {
         doLatched(timeoutMessage, functor, DEFAULT_TIMEOUT_MS);
@@ -376,6 +436,7 @@ public class IpMemoryStoreServiceTest {
     private NetworkAttributes storeAttributes(final String l2Key, final NetworkAttributes na) {
         return storeAttributes("Did not complete storing attributes", l2Key, na);
     }
+
     private NetworkAttributes storeAttributes(final String timeoutMessage, final String l2Key,
             final NetworkAttributes na) {
         doLatched(timeoutMessage, latch -> mService.storeNetworkAttributes(l2Key, na.toParcelable(),
@@ -390,6 +451,7 @@ public class IpMemoryStoreServiceTest {
     private void storeBlobOrFail(final String l2Key, final Blob b, final byte[] data) {
         storeBlobOrFail("Did not complete storing private data", l2Key, b, data);
     }
+
     private void storeBlobOrFail(final String timeoutMessage, final String l2Key, final Blob b,
             final byte[] data) {
         b.data = data;
@@ -401,6 +463,23 @@ public class IpMemoryStoreServiceTest {
                 })));
     }
 
+    // Helper method to store network events (NUD failure) to database.
+    private void storeNetworkEventOrFail(final String cluster, final long now,
+            final long expiry, final int eventType) {
+        storeNetworkEventOrFail("Did not complete storing a network event", cluster, now,
+                expiry, eventType);
+    }
+
+    private void storeNetworkEventOrFail(final String timeoutMessage, final String cluster,
+            final long now, final long expiry, final int eventType) {
+        doLatched(timeoutMessage, latch -> mService.storeNetworkEvent(cluster, now, expiry,
+                eventType,
+                onStatus(status -> {
+                    assertTrue("Store not successful : " + status.resultCode, status.isSuccess());
+                    latch.countDown();
+                })));
+    }
+
     /**
      * This method is used to generate test.db file.
      *
@@ -409,8 +488,7 @@ public class IpMemoryStoreServiceTest {
      * 2. Comment out "mDbFile.delete()" in tearDown() method.
      * 3. Run "atest IpMemoryStoreServiceTest#testGenerateDB".
      * 4. Run "adb root; adb pull /data/data/com.android.server.networkstack.tests/files/test.db
-     *    $YOUR_CODE_BASE/package/module/NetworkStack/tests/unit/res/raw/test.db".
-     *
+     * $YOUR_CODE_BASE/package/module/NetworkStack/tests/unit/res/raw/test.db".
      */
     private void generateFakeData() {
         final int fakeDataCount = 1000;
@@ -443,6 +521,22 @@ public class IpMemoryStoreServiceTest {
         }
     }
 
+    private void generateFakeNetworkEvents() {
+        final int fakeEventCount = 1000;
+        final int expiredRecordsCount = 500;
+        final long now = System.currentTimeMillis();
+        for (int i = 0; i < fakeEventCount; i++) {
+            final long timestamp =
+                    i < expiredRecordsCount ? now - ONE_WEEK_IN_MS - i : now + i;
+            final long expiry = timestamp + ONE_WEEK_IN_MS;
+            storeNetworkEventOrFail(
+                    TEST_CLUSTER,
+                    timestamp,
+                    expiry,
+                    NETWORK_EVENT_NUD_FAILURE_TYPES[i % 4]);
+        }
+    }
+
     /** Wait for assigned time. */
     private void waitForMs(long ms) {
         try {
@@ -473,7 +567,7 @@ public class IpMemoryStoreServiceTest {
 
         final NetworkAttributes.Builder na2 = new NetworkAttributes.Builder();
         na.setDnsAddresses(Arrays.asList(
-                new InetAddress[] {Inet6Address.getByName("0A1C:2E40:480A::1CA6")}));
+                new InetAddress[]{Inet6Address.getByName("0A1C:2E40:480A::1CA6")}));
         final NetworkAttributes attributes2 = na2.build();
         storeAttributes("Did not complete storing attributes 2", l2Key, attributes2);
 
@@ -550,22 +644,26 @@ public class IpMemoryStoreServiceTest {
                         })));
     }
 
-    @Test
-    public void testPrivateData() {
-        final String l2Key = FAKE_KEYS[0];
-        final Blob b = new Blob();
-        storeBlobOrFail(l2Key, b, TEST_BLOB_DATA);
-
+    private void assertPrivateDataPresent(IpMemoryStoreService service, String l2Key) {
         doLatched("Did not complete retrieving private data", latch ->
-                mService.retrieveBlob(l2Key, TEST_CLIENT_ID, TEST_DATA_NAME, onBlobRetrieved(
+                service.retrieveBlob(l2Key, TEST_CLIENT_ID, TEST_DATA_NAME, onBlobRetrieved(
                         (status, key, name, data) -> {
                             assertTrue("Retrieve blob status not successful : " + status.resultCode,
                                     status.isSuccess());
                             assertEquals(l2Key, key);
                             assertEquals(name, TEST_DATA_NAME);
-                            assertTrue(Arrays.equals(b.data, data));
+                            assertTrue(Arrays.equals(TEST_BLOB_DATA, data));
                             latch.countDown();
                         })));
+    }
+
+    @Test
+    public void testPrivateData() {
+        final String l2Key = FAKE_KEYS[0];
+        final Blob b = new Blob();
+        storeBlobOrFail(l2Key, b, TEST_BLOB_DATA);
+
+        assertPrivateDataPresent(mService, l2Key);
 
         // Most puzzling error message ever
         doLatched("Did not complete retrieving nothing", latch ->
@@ -587,13 +685,13 @@ public class IpMemoryStoreServiceTest {
         stored.add(storeAttributes(FAKE_KEYS[0], na.build()));
 
         na.setDnsAddresses(Arrays.asList(
-                new InetAddress[] {Inet6Address.getByName("8D56:9AF1::08EE:20F1")}));
+                new InetAddress[]{Inet6Address.getByName("8D56:9AF1::08EE:20F1")}));
         na.setMtu(208);
         stored.add(storeAttributes(FAKE_KEYS[1], na.build()));
         na.setMtu(null);
         na.setAssignedV4Address((Inet4Address) Inet4Address.getByName("1.2.3.4"));
         na.setDnsAddresses(Arrays.asList(
-                new InetAddress[] {Inet6Address.getByName("0A1C:2E40:480A::1CA6")}));
+                new InetAddress[]{Inet6Address.getByName("0A1C:2E40:480A::1CA6")}));
         na.setCluster("cluster1");
         stored.add(storeAttributes(FAKE_KEYS[2], na.build()));
         na.setMtu(219);
@@ -811,6 +909,25 @@ public class IpMemoryStoreServiceTest {
         assertFalse(mService.isDbSizeOverThreshold());
     }
 
+    @Test
+    public void testFullMaintenance_networkEvents() throws Exception {
+        generateFakeNetworkEvents();
+        // After inserting test data, the size of the DB should be larger than the threshold.
+        assertTrue(mService.isDbSizeOverThreshold());
+
+        final InterruptMaintenance im = new InterruptMaintenance(0/* Fake JobId */);
+        // Do full maintenance and then the db should go down in size and be under the threshold.
+        doLatched("Maintenance unexpectedly completed successfully", latch ->
+                mService.fullMaintenance(onStatus((status) -> {
+                    assertTrue("Execute full maintenance failed: "
+                            + status.resultCode, status.isSuccess());
+                    latch.countDown();
+                }), im), LONG_TIMEOUT_MS);
+
+        // If maintenance is successful, the db size shall meet the threshold.
+        assertFalse(mService.isDbSizeOverThreshold());
+    }
+
     @Test
     public void testInterruptMaintenance() throws Exception {
         copyTestData(mDbFile);
@@ -922,13 +1039,13 @@ public class IpMemoryStoreServiceTest {
 
     private final List<Pair<String, byte[]>> mByteArrayTests = List.of(
             new Pair<>("null", null),
-            new Pair<>("[]", new byte[] {}),
+            new Pair<>("[]", new byte[]{}),
             new Pair<>("[0102030405060708090A0B0C]",
-                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }),
-            new Pair<>("[0F1080FF]", new byte[] { 15, 16, -128, -1 }),
+                    new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}),
+            new Pair<>("[0F1080FF]", new byte[]{15, 16, -128, -1}),
             new Pair<>("[0102030405060708090A0B0C0D0E0F10...15161718191A1B1C]",
-                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
-                            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 })
+                    new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
+                            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28})
     );
 
     @Test
@@ -976,4 +1093,447 @@ public class IpMemoryStoreServiceTest {
         //db is null, the db size could not over the threshold.
         assertFalse(ipMemoryStoreService.isDbSizeOverThreshold());
     }
+
+    /**
+     * Setup the NetworkEvents table with multiple NUD failure events before running each testcase.
+     *    times             eventType                               cluster           timestamp
+     *     10    NETWORK_EVENT_NUD_FAILURE_ROAM                  TEST_CLUSTER       1.5 weeks ago
+     *     10    NETWORK_EVENT_NUD_FAILURE_ORGANIC               TEST_CLUSTER_1     1   weeks ago
+     *     10    NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED   TEST_CLUSTER       0.8 weeks ago
+     *     10    NETWORK_EVENT_NUD_FAILURE_CONFIRM               TEST_CLUSTER       0.6 weeks ago
+     *     10    NETWORK_EVENT_NUD_FAILURE_ROAM                  TEST_CLUSTER_1     0.5 weeks ago
+     *     10    NETWORK_EVENT_NUD_FAILURE_ORGANIC               TEST_CLUSTER       6   hours ago
+     */
+    private void storeNetworkEventsForNudFailures(final long now) {
+        // Insert 10 NUD failure events post roam happened 1.5 weeks ago to TEST_CLUSTER.
+        long timestamp = (long) (now - ONE_WEEK_IN_MS * 1.5);
+        long expiry = timestamp + ONE_WEEK_IN_MS;
+        for (int i = 0; i < 10; i++) {
+            storeNetworkEventOrFail(TEST_CLUSTER, timestamp, expiry,
+                    NETWORK_EVENT_NUD_FAILURE_ROAM);
+        }
+
+        // Insert 10 NUD failure events due to organic check happened 1 weeks ago to
+        // TEST_CLUSTER_1.
+        timestamp = now - ONE_WEEK_IN_MS;
+        expiry = timestamp + ONE_WEEK_IN_MS;
+        for (int i = 0; i < 10; i++) {
+            storeNetworkEventOrFail(TEST_CLUSTER_1, timestamp, expiry,
+                    NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+        }
+
+        // Insert 10 NUD failure events due to mac address change happened 0.8 weeks ago to
+        // TEST_CLUSTER.
+        timestamp = (long) (now - ONE_WEEK_IN_MS * 0.8);
+        expiry = timestamp + ONE_WEEK_IN_MS;
+        for (int i = 0; i < 10; i++) {
+            storeNetworkEventOrFail(TEST_CLUSTER, timestamp, expiry,
+                    NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED);
+        }
+
+        // Insert 10 NUD failure events from confirm happened 0.6 weeks ago to TEST_CLUSTER.
+        timestamp = (long) (now - ONE_WEEK_IN_MS * 0.6);
+        expiry = timestamp + ONE_WEEK_IN_MS;
+        for (int i = 0; i < 10; i++) {
+            storeNetworkEventOrFail(TEST_CLUSTER, timestamp, expiry,
+                    NETWORK_EVENT_NUD_FAILURE_CONFIRM);
+        }
+
+        // Insert 10 NUD failure events from confirm happened 0.5 weeks ago to TEST_CLUSTER_1.
+        timestamp = (long) (now - ONE_WEEK_IN_MS * 0.5);
+        expiry = timestamp + ONE_WEEK_IN_MS;
+        for (int i = 0; i < 10; i++) {
+            storeNetworkEventOrFail(TEST_CLUSTER_1, timestamp, expiry,
+                    NETWORK_EVENT_NUD_FAILURE_ROAM);
+        }
+
+        // Insert 10 NUD failure events from organic check 6 hours ago to TEST_CLUSTER.
+        timestamp = now - ONE_DAY_IN_MS / 4;
+        expiry = timestamp + ONE_WEEK_IN_MS;
+        for (int i = 0; i < 10; i++) {
+            storeNetworkEventOrFail(TEST_CLUSTER, timestamp, expiry,
+                    NETWORK_EVENT_NUD_FAILURE_ORGANIC);
+        }
+    }
+
+    @Test
+    public void testNetworkEventsQuery() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        // Query network event counts for NUD failures within TEST_CLUSTER.
+        final long[] sinceTimes = new long[2];
+        sinceTimes[0] = now - ONE_WEEK_IN_MS;
+        sinceTimes[1] = now - ONE_DAY_IN_MS;
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(30, counts[0]);
+                                assertEquals(10, counts[1]);
+                                latch.countDown();
+                            })));
+
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER_1,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(20, counts[0]);
+                                assertEquals(0, counts[1]);
+                                latch.countDown();
+                            })));
+    }
+
+    private int[] eventTypes(final int... eventTypes) {
+        return eventTypes;
+    }
+
+    @Test
+    public void testNetworkEventsQuery_differentEventTypes() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        final long[] sinceTimes = new long[2];
+        sinceTimes[0] = now - ONE_WEEK_IN_MS;
+        sinceTimes[1] = now - ONE_DAY_IN_MS;
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        eventTypes(NETWORK_EVENT_NUD_FAILURE_ROAM,
+                                NETWORK_EVENT_NUD_FAILURE_CONFIRM),
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(10, counts[0]);
+                                assertEquals(0, counts[1]);
+                                latch.countDown();
+                            })));
+
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        eventTypes(NETWORK_EVENT_NUD_FAILURE_ORGANIC,
+                                NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED),
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(20, counts[0]);
+                                assertEquals(10, counts[1]);
+                                latch.countDown();
+                            })));
+
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER_1,
+                        sinceTimes,
+                        eventTypes(NETWORK_EVENT_NUD_FAILURE_ORGANIC,
+                                NETWORK_EVENT_NUD_FAILURE_MAC_ADDRESS_CHANGED),
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(10, counts[0]);
+                                assertEquals(0, counts[1]);
+                                latch.countDown();
+                            })));
+
+    }
+
+    @Test
+    public void testNetworkEventsQuery_querySinceLastOneWeek() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        final long[] sinceTimes = new long[] { now - ONE_WEEK_IN_MS };
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 1);
+                                assertEquals(30, counts[0]);
+                                latch.countDown();
+                            })));
+
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER_1,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 1);
+                                assertEquals(20, counts[0]);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testNetworkEventsQuery_querySinceLastOneDay() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        // Query network event count for NUD failures in past day within the same cluster.
+        final long[] sinceTimes = new long[] { now - ONE_DAY_IN_MS };
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 1);
+                                assertEquals(10, counts[0]);
+                                latch.countDown();
+                            })));
+
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER_1,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 1);
+                                assertEquals(0, counts[0]);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testNetworkEventsQuery_wrongCluster() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        // Query network event count for NUD failures within the same cluster.
+        final long[] sinceTimes = new long[2];
+        sinceTimes[0] = now - ONE_WEEK_IN_MS;
+        sinceTimes[1] = now - ONE_DAY_IN_MS;
+        final int[] eventTypes = new int[] { NETWORK_EVENT_NUD_FAILURE_ROAM };
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount("wrong_cluster_to_query",
+                        sinceTimes,
+                        eventTypes,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(0, counts[0]);
+                                assertEquals(0, counts[1]);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testNetworkEventsQuery_nullCluster() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        // Query network event count for NUD failures within the same cluster.
+        final long[] sinceTimes = new long[2];
+        sinceTimes[0] = now - ONE_WEEK_IN_MS;
+        sinceTimes[1] = now - ONE_DAY_IN_MS;
+        final int[] eventTypes = new int[] { NETWORK_EVENT_NUD_FAILURE_ROAM };
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(null /* cluster */,
+                        sinceTimes,
+                        eventTypes,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertFalse("Success retrieving network event count",
+                                        status.isSuccess());
+                                assertEquals(Status.ERROR_ILLEGAL_ARGUMENT, status.resultCode);
+                                assertTrue(counts.length == 0);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testNetworkEventsQuery_emptyQueryEventType() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        // Query network event count for NUD failure within the same cluster but event type to
+        // be queried is empty, an empty counts should be returned.
+        final long[] sinceTimes = new long[2];
+        sinceTimes[0] = now - ONE_WEEK_IN_MS;
+        sinceTimes[1] = now - ONE_DAY_IN_MS;
+        final int[] eventTypes = new int[0];
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        eventTypes,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(0, counts[0]);
+                                assertEquals(0, counts[1]);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testNetworkEventsQuery_emptySinceTimes() {
+        final long now = System.currentTimeMillis();
+        storeNetworkEventsForNudFailures(now);
+
+        // Query network event count for NUD failure within the same cluster but sinceTimes is
+        // empty, en empty count array will be returned and ERROR_ILLEGAL_ARGUMENT status.
+        final long[] sinceTimes = new long[0];
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertFalse("Success retrieving network event count",
+                                        status.isSuccess());
+                                assertEquals(Status.ERROR_ILLEGAL_ARGUMENT, status.resultCode);
+                                assertTrue(counts.length == 0);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testNetworkEventsQuery_wrongEventType() {
+        final long now = System.currentTimeMillis();
+        final long expiry = now + ONE_WEEK_IN_MS;
+        storeNetworkEventOrFail(TEST_CLUSTER, now, expiry, -1 /* nonexistent event type */);
+
+        // Query network event count for NUD failure within the same cluster but event type doesn't
+        // match.
+        final long[] sinceTimes = new long[2];
+        sinceTimes[0] = now - ONE_WEEK_IN_MS;
+        sinceTimes[1] = now - ONE_DAY_IN_MS;
+        doLatched("Did not complete retrieving network event count", latch ->
+                mService.retrieveNetworkEventCount(TEST_CLUSTER,
+                        sinceTimes,
+                        NETWORK_EVENT_NUD_FAILURE_TYPES,
+                        onNetworkEventCountRetrieved(
+                            (status, counts) -> {
+                                assertTrue("Retrieve network event counts not successful : "
+                                        + status.resultCode, status.isSuccess());
+                                assertTrue(counts.length == 2);
+                                assertEquals(0, counts[0]);
+                                assertEquals(0, counts[1]);
+                                latch.countDown();
+                            })));
+    }
+
+    @Test
+    public void testStoreNetworkEvent_nullCluster() {
+        final long now = System.currentTimeMillis();
+        final long expiry = now + ONE_WEEK_IN_MS;
+        doLatched("Did not complete storing a network event", latch ->
+                mService.storeNetworkEvent(null /* cluster */, now, expiry,
+                        NETWORK_EVENT_NUD_FAILURE_ROAM,
+                        onStatus(status -> {
+                            assertFalse("Success storing a network event with null cluster",
+                                    status.isSuccess());
+                            assertEquals(Status.ERROR_ILLEGAL_ARGUMENT, status.resultCode);
+                            latch.countDown();
+                        })));
+    }
+
+    @Test
+    public void testRenameDb_noExistingDb_newDbCreated() throws Exception {
+        mService.shutdown();
+        TEST_DB.delete();
+        assertFalse(TEST_DB.exists());
+
+        assertFalse(OLD_DB.exists());
+        assertFalse(TEST_DB.exists());
+
+        final IpMemoryStoreService service = createService();
+        service.shutdown();
+        assertFalse(OLD_DB.exists());
+        assertTrue(TEST_DB.exists());
+    }
+
+    @Test
+    public void testRenameDb_existingDb_becomesNewDb() throws Exception {
+        mService.shutdown();
+        TEST_DB.delete();
+        assertFalse(TEST_DB.exists());
+
+        assertFalse(OLD_DB.exists());
+        copyTestData(OLD_DB);
+        assertTrue(OLD_DB.exists());
+
+        final IpMemoryStoreService service = createService();
+        assertPrivateDataPresent(service, FAKE_KEYS[0]);
+        assertFalse(OLD_DB.exists());
+        assertTrue(TEST_DB.exists());
+
+        service.shutdown();
+    }
+
+    @Test
+    public void testRenameDb_existingDb_overwritesNewDb() throws Exception {
+        mService.shutdown();
+        // Replace the new DB with garbage. This lets us check that the data survives the rename.
+        try (FileOutputStream out = new FileOutputStream(TEST_DB, false /* append */)) {
+            out.write(new byte[]{'g', 'a', 'r', 'b', 'a', 'g', 'e'});
+        }
+        assertTrue(TEST_DB.exists());
+
+        assertFalse(OLD_DB.exists());
+        copyTestData(OLD_DB);
+        assertTrue(OLD_DB.exists());
+
+        final IpMemoryStoreService service = createService();
+        assertPrivateDataPresent(service, FAKE_KEYS[0]);
+        assertFalse(OLD_DB.exists());
+        assertTrue(TEST_DB.exists());
+
+        service.shutdown();
+    }
+
+    private void doTestDowngradeAndUpgrade(int downgradeVersion) {
+        SQLiteOpenHelper dbHelper = new IpMemoryStoreDatabase.DbHelper(
+                mMockContext, downgradeVersion);
+        SQLiteDatabase db = dbHelper.getWritableDatabase();
+        assertEquals(downgradeVersion, db.getVersion());
+        db.close();
+
+        dbHelper = new IpMemoryStoreDatabase.DbHelper(mMockContext, SCHEMA_VERSION);
+        db = dbHelper.getWritableDatabase();
+        assertEquals(SCHEMA_VERSION, db.getVersion());
+        db.close();
+    }
+
+    @Test
+    public void testDowngradeClearsTablesAndTriggers() {
+        final String l2Key = FAKE_KEYS[0];
+        final Blob b = new Blob();
+        storeBlobOrFail(l2Key, b, TEST_BLOB_DATA);
+        mService.shutdown();
+
+        for (int version = SCHEMA_VERSION - 1; version >= 1; version--) {
+            doTestDowngradeAndUpgrade(version);
+        }
+    }
 }
diff --git a/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java b/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java
index 8dc3d923..69464cf3 100644
--- a/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java
+++ b/tests/unit/src/com/android/networkstack/metrics/ApfSessionInfoMetricsTest.java
@@ -130,7 +130,7 @@ public class ApfSessionInfoMetricsTest {
                 CounterName.CN_DROPPED_IPV6_NON_ICMP_MULTICAST);
         verifyCounterName(Counter.DROPPED_802_3_FRAME, CounterName.CN_DROPPED_802_3_FRAME);
         verifyCounterName(Counter.DROPPED_ETHERTYPE_NOT_ALLOWED,
-                CounterName.CN_DROPPED_ETHERTYPE_DENYLISTED);
+                CounterName.CN_DROPPED_ETHERTYPE_NOT_ALLOWED);
         verifyCounterName(Counter.DROPPED_ARP_REPLY_SPA_NO_HOST,
                 CounterName.CN_DROPPED_ARP_REPLY_SPA_NO_HOST);
         verifyCounterName(Counter.DROPPED_IPV4_KEEPALIVE_ACK,
@@ -143,5 +143,29 @@ public class ApfSessionInfoMetricsTest {
         verifyCounterName(Counter.DROPPED_IPV4_TCP_PORT7_UNICAST, CounterName.CN_UNKNOWN);
         verifyCounterName(Counter.DROPPED_ARP_NON_IPV4, CounterName.CN_DROPPED_ARP_NON_IPV4);
         verifyCounterName(Counter.DROPPED_ARP_UNKNOWN, CounterName.CN_DROPPED_ARP_UNKNOWN);
+        verifyCounterName(Counter.PASSED_ARP_BROADCAST_REPLY,
+                CounterName.CN_PASSED_ARP_BROADCAST_REPLY);
+        verifyCounterName(Counter.PASSED_ARP_REQUEST, CounterName.CN_PASSED_ARP_REQUEST);
+        verifyCounterName(Counter.PASSED_IPV4_FROM_DHCPV4_SERVER,
+                CounterName.CN_PASSED_IPV4_FROM_DHCPV4_SERVER);
+        verifyCounterName(Counter.PASSED_IPV6_NS_DAD, CounterName.CN_PASSED_IPV6_NS_DAD);
+        verifyCounterName(Counter.PASSED_IPV6_NS_NO_ADDRESS,
+                CounterName.CN_PASSED_IPV6_NS_NO_ADDRESS);
+        verifyCounterName(Counter.PASSED_IPV6_NS_NO_SLLA_OPTION,
+                CounterName.CN_PASSED_IPV6_NS_NO_SLLA_OPTION);
+        verifyCounterName(Counter.PASSED_IPV6_NS_TENTATIVE,
+                CounterName.CN_PASSED_IPV6_NS_TENTATIVE);
+        verifyCounterName(Counter.PASSED_MLD, CounterName.CN_PASSED_MLD);
+        verifyCounterName(Counter.DROPPED_IPV4_NON_DHCP4, CounterName.CN_DROPPED_IPV4_NON_DHCP4);
+        verifyCounterName(Counter.DROPPED_IPV6_NS_INVALID, CounterName.CN_DROPPED_IPV6_NS_INVALID);
+        verifyCounterName(Counter.DROPPED_IPV6_NS_OTHER_HOST,
+                CounterName.CN_DROPPED_IPV6_NS_OTHER_HOST);
+        verifyCounterName(Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD,
+                CounterName.CN_DROPPED_IPV6_NS_REPLIED_NON_DAD);
+        verifyCounterName(Counter.DROPPED_ARP_REQUEST_ANYHOST,
+                CounterName.CN_DROPPED_ARP_REQUEST_ANYHOST);
+        verifyCounterName(Counter.DROPPED_ARP_REQUEST_REPLIED,
+                CounterName.CN_DROPPED_ARP_REQUEST_REPLIED);
+        verifyCounterName(Counter.DROPPED_ARP_V6_ONLY, CounterName.CN_DROPPED_ARP_V6_ONLY);
     }
 }
diff --git a/tests/unit/src/com/android/networkstack/util/DnsUtilsTest.kt b/tests/unit/src/com/android/networkstack/util/DnsUtilsTest.kt
index 59d96bee..e65d69e0 100644
--- a/tests/unit/src/com/android/networkstack/util/DnsUtilsTest.kt
+++ b/tests/unit/src/com/android/networkstack/util/DnsUtilsTest.kt
@@ -21,12 +21,12 @@ import android.net.DnsResolver.FLAG_EMPTY
 import android.net.DnsResolver.TYPE_A
 import android.net.DnsResolver.TYPE_AAAA
 import android.net.Network
-import com.android.testutils.FakeDns
 import androidx.test.filters.SmallTest
 import androidx.test.runner.AndroidJUnit4
 import com.android.networkstack.util.DnsUtils
 import com.android.networkstack.util.DnsUtils.TYPE_ADDRCONFIG
 import com.android.server.connectivity.NetworkMonitor.DnsLogFunc
+import com.android.server.connectivity.FakeDns
 import java.net.InetAddress
 import java.net.UnknownHostException
 import kotlin.test.assertFailsWith
@@ -43,7 +43,8 @@ const val SHORT_TIMEOUT_MS = 200
 @RunWith(AndroidJUnit4::class)
 @SmallTest
 class DnsUtilsTest {
-    val fakeNetwork: Network = Network(1234)
+    @Mock
+    lateinit var mockNetwork: Network
     @Mock
     lateinit var mockLogger: DnsLogFunc
     @Mock
@@ -53,7 +54,7 @@ class DnsUtilsTest {
     @Before
     fun setup() {
         MockitoAnnotations.initMocks(this)
-        fakeDns = FakeDns(mockResolver)
+        fakeDns = FakeDns(mockNetwork, mockResolver)
         fakeDns.startMocking()
     }
 
@@ -71,8 +72,13 @@ class DnsUtilsTest {
     }
 
     private fun verifyGetAllByName(name: String, expected: Array<String>, type: Int) {
-        fakeDns.setAnswer(name, expected, type)
-        DnsUtils.getAllByName(mockResolver, fakeNetwork, name, type, FLAG_EMPTY, DEFAULT_TIMEOUT_MS,
+        if (type == TYPE_ADDRCONFIG) {
+            fakeDns.setAnswer(name, expected.filter({":" in it}).toTypedArray(), TYPE_AAAA)
+            fakeDns.setAnswer(name, expected.filter({"." in it}).toTypedArray(), TYPE_A)
+        } else {
+            fakeDns.setAnswer(name, expected, type)
+        }
+        DnsUtils.getAllByName(mockResolver, mockNetwork, name, type, FLAG_EMPTY, DEFAULT_TIMEOUT_MS,
                 mockLogger).let { assertIpAddressArrayEquals(expected, it) }
     }
 
@@ -85,7 +91,7 @@ class DnsUtilsTest {
 
     private fun verifyGetAllByNameFails(name: String, type: Int) {
         assertFailsWith<UnknownHostException> {
-            DnsUtils.getAllByName(mockResolver, fakeNetwork, name, type,
+            DnsUtils.getAllByName(mockResolver, mockNetwork, name, type,
                     FLAG_EMPTY, SHORT_TIMEOUT_MS, mockLogger)
         }
     }
diff --git a/tests/unit/src/com/android/server/connectivity/DdrTrackerTest.java b/tests/unit/src/com/android/server/connectivity/DdrTrackerTest.java
new file mode 100644
index 00000000..77630c75
--- /dev/null
+++ b/tests/unit/src/com/android/server/connectivity/DdrTrackerTest.java
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
+package com.android.server.connectivity;
+
+import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_OFF;
+import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_OPPORTUNISTIC;
+import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import android.annotation.NonNull;
+import android.net.DnsResolver;
+import android.net.LinkProperties;
+import android.net.Network;
+import android.net.shared.PrivateDnsConfig;
+
+import com.android.net.module.util.SharedLog;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.net.InetAddress;
+import java.util.concurrent.Executor;
+
+@RunWith(JUnit4.class)
+public final class DdrTrackerTest {
+    private static final int OFF_MODE = PRIVATE_DNS_MODE_OFF;
+    private static final int OPPORTUNISTIC_MODE = PRIVATE_DNS_MODE_OPPORTUNISTIC;
+    private static final int STRICT_MODE = PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;
+
+    private DdrTracker mDdrTracker;
+    private @Mock DnsResolver mDnsResolver;
+    private @Mock Network mCleartextDnsNetwork;
+    private @Mock TestCallback mCallback;
+    private @Mock Executor mExecutor;
+    private @Mock SharedLog mValidationLogger;
+
+    // TODO(b/240259333): Fake DNS responses on mDnsResolver to test startSvcbLookup.
+    private static class TestCallback implements DdrTracker.Callback {
+        @Override
+        public void onSvcbLookupComplete(@NonNull PrivateDnsConfig result) {}
+    }
+
+    private static class PrivateDnsConfigBuilder {
+        private int mMode = OFF_MODE;
+        private String mHostname = null;
+        private InetAddress[] mIps = null;
+        private final String mDohName = null;
+        private final InetAddress[] mDohIps = null;
+        private final String mDohPath = null;
+        private final int mDohPort = -1;
+
+        PrivateDnsConfigBuilder setMode(int mode) {
+            mMode = mode;
+            return this;
+        }
+        PrivateDnsConfigBuilder setHostname(String value) {
+            mHostname = value;
+            return this;
+        }
+        PrivateDnsConfigBuilder setIps(InetAddress[] value) {
+            mIps = value;
+            return this;
+        }
+        PrivateDnsConfig build() {
+            return new PrivateDnsConfig(mMode, mHostname, mIps,
+                    false /* ddrEnabled */, mDohName, mDohIps, mDohPath,  mDohPort);
+        }
+    }
+
+    @Before
+    public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
+        mDdrTracker = new DdrTracker(mCleartextDnsNetwork, mDnsResolver, mExecutor, mCallback,
+                mValidationLogger);
+    }
+
+    // TODO: check that if DeviceConfigUtils#isFeatureSupported returns false, DDR is disabled.
+    private void testNotifyPrivateDnsSettingsChangedHelper(int mode, @NonNull String dnsProvider)
+            throws Exception {
+        final PrivateDnsConfig cfg =
+                new PrivateDnsConfigBuilder().setMode(mode).setHostname(dnsProvider).build();
+
+        assertTrue(mDdrTracker.notifyPrivateDnsSettingsChanged(cfg));
+        assertEquals(mode, mDdrTracker.getPrivateDnsMode());
+        assertEquals(dnsProvider, mDdrTracker.getStrictModeHostname());
+        assertFalse(mDdrTracker.notifyPrivateDnsSettingsChanged(cfg));
+    }
+
+    @Test
+    public void testNotifyPrivateDnsSettingsChanged() throws Exception {
+        // Tests the initial private DNS setting in DdrTracker.
+        assertEquals(OFF_MODE, mDdrTracker.getPrivateDnsMode());
+        assertEquals("", mDdrTracker.getStrictModeHostname());
+        assertFalse(mDdrTracker.notifyPrivateDnsSettingsChanged(new PrivateDnsConfigBuilder()
+                .setMode(OFF_MODE).build()));
+
+        testNotifyPrivateDnsSettingsChangedHelper(OPPORTUNISTIC_MODE, "");
+        testNotifyPrivateDnsSettingsChangedHelper(STRICT_MODE, "example1.com");
+        testNotifyPrivateDnsSettingsChangedHelper(STRICT_MODE, "example2.com");
+        testNotifyPrivateDnsSettingsChangedHelper(OFF_MODE, "");
+    }
+
+    private void testNotifyLinkPropertiesChangedHelper(InetAddress[] ips) {
+        final LinkProperties lp = new LinkProperties();
+        for (InetAddress ip : ips) {
+            assertTrue(lp.addDnsServer(ip));
+        }
+        assertTrue(mDdrTracker.notifyLinkPropertiesChanged(lp));
+        assertArrayEquals(ips, mDdrTracker.getDnsServers().toArray());
+        assertFalse(mDdrTracker.notifyLinkPropertiesChanged(lp));
+    }
+
+    @Test
+    public void testNotifyLinkPropertiesChanged() throws Exception {
+        final InetAddress ip1 = InetAddress.parseNumericAddress("1.2.3.4");
+        final InetAddress ip2 = InetAddress.parseNumericAddress("2001:db8::1");
+
+        // Tests the initial value in DdrTracker.
+        assertTrue(mDdrTracker.getDnsServers().isEmpty());
+
+        testNotifyLinkPropertiesChangedHelper(new InetAddress[] {ip1});
+        testNotifyLinkPropertiesChangedHelper(new InetAddress[] {ip1, ip2});
+        testNotifyLinkPropertiesChangedHelper(new InetAddress[] {ip2, ip1});
+    }
+
+    private void assertPrivateDnsConfigEquals(PrivateDnsConfig a, PrivateDnsConfig b) {
+        assertEquals(a.mode, b.mode);
+        assertEquals(a.hostname, b.hostname);
+        assertArrayEquals(a.ips, b.ips);
+        assertEquals(a.dohName, b.dohName);
+        assertArrayEquals(a.dohIps, b.dohIps);
+        assertEquals(a.dohPath, b.dohPath);
+        assertEquals(a.dohPort, b.dohPort);
+    }
+
+    @Test
+    public void testSetStrictModeHostnameResolutionResult() throws Exception {
+        final String dnsProvider = "example1.com";
+        final InetAddress[] ips = new InetAddress[] {
+            InetAddress.parseNumericAddress("1.2.3.4"),
+            InetAddress.parseNumericAddress("2001:db8::1"),
+        };
+        final PrivateDnsConfigBuilder builder =
+                new PrivateDnsConfigBuilder().setMode(STRICT_MODE).setHostname(dnsProvider);
+
+        assertTrue(mDdrTracker.notifyPrivateDnsSettingsChanged(builder.build()));
+        assertPrivateDnsConfigEquals(builder.build(), mDdrTracker.getResultForReporting());
+
+        mDdrTracker.setStrictModeHostnameResolutionResult(ips);
+        assertPrivateDnsConfigEquals(builder.setIps(ips).build(),
+                mDdrTracker.getResultForReporting());
+
+        mDdrTracker.resetStrictModeHostnameResolutionResult();
+        assertPrivateDnsConfigEquals(builder.setIps(new InetAddress[0]).build(),
+                mDdrTracker.getResultForReporting());
+    }
+}
diff --git a/tests/unit/src/com/android/server/connectivity/FakeDns.java b/tests/unit/src/com/android/server/connectivity/FakeDns.java
new file mode 100644
index 00000000..2f16e234
--- /dev/null
+++ b/tests/unit/src/com/android/server/connectivity/FakeDns.java
@@ -0,0 +1,303 @@
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
+package com.android.server.connectivity;
+
+import static android.net.DnsResolver.TYPE_A;
+import static android.net.DnsResolver.TYPE_AAAA;
+import static android.net.InetAddresses.parseNumericAddress;
+
+import static com.android.net.module.util.DnsPacket.TYPE_SVCB;
+
+import static org.mockito.Mockito.any;
+import static org.mockito.Mockito.anyInt;
+import static org.mockito.Mockito.doAnswer;
+
+import android.net.DnsResolver;
+import android.net.Network;
+import android.os.Handler;
+import android.os.Looper;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.testutils.DnsSvcbUtils;
+
+import org.mockito.invocation.InvocationOnMock;
+import org.mockito.stubbing.Answer;
+
+import java.io.IOException;
+import java.net.InetAddress;
+import java.net.UnknownHostException;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Objects;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.TimeoutException;
+
+/**
+ * Fakes DNS responses.
+ *
+ * Allows test methods to configure the IP addresses that will be resolved by
+ * Network#getAllByName and by various DnsResolver query methods.
+ */
+public class FakeDns {
+    private static final int HANDLER_TIMEOUT_MS = 1000;
+
+    @NonNull
+    private final Network mNetwork;
+    @NonNull
+    private final DnsResolver mDnsResolver;
+    private final ArrayList<DnsEntry> mAnswers = new ArrayList<>();
+    private boolean mNonBypassPrivateDnsWorking = true;
+
+    public FakeDns(@NonNull Network network, @NonNull DnsResolver dnsResolver) {
+        mNetwork = Objects.requireNonNull(network);
+        mDnsResolver = Objects.requireNonNull(dnsResolver);
+    }
+
+    /** Data class to record the Dns entry. */
+    private static class DnsEntry {
+        final String mHostname;
+        final int mType;
+        final AnswerSupplier mAnswerSupplier;
+        DnsEntry(String host, int type, AnswerSupplier answerSupplier) {
+            mHostname = host;
+            mType = type;
+            mAnswerSupplier = answerSupplier;
+        }
+        // Full match or partial match that target host contains the entry hostname to support
+        // random private dns probe hostname.
+        private boolean matches(String hostname, int type) {
+            return hostname.endsWith(mHostname) && type == mType;
+        }
+    }
+
+    public interface AnswerSupplier {
+        /** Supplies the answer to one DnsResolver query method call. */
+        @Nullable
+        String[] get() throws DnsResolver.DnsException;
+    }
+
+    private static class InstantAnswerSupplier implements AnswerSupplier {
+        private final String[] mAnswers;
+        InstantAnswerSupplier(String[] answers) {
+            mAnswers = answers;
+        }
+        @Override
+        @Nullable
+        public String[] get() {
+            return mAnswers;
+        }
+    }
+
+    /** Whether DNS queries on mNonBypassPrivateDnsWorking should succeed. */
+    public void setNonBypassPrivateDnsWorking(boolean working) {
+        mNonBypassPrivateDnsWorking = working;
+    }
+
+    /** Clears all DNS entries. */
+    public void clearAll() {
+        synchronized (mAnswers) {
+            mAnswers.clear();
+        }
+    }
+
+    /** Returns the answer for a given name and type on the given mock network. */
+    private CompletableFuture<String[]> getAnswer(Network mockNetwork, String hostname,
+            int type) {
+        if (mNetwork.equals(mockNetwork) && !mNonBypassPrivateDnsWorking) {
+            return CompletableFuture.completedFuture(null);
+        }
+
+        final AnswerSupplier answerSupplier;
+
+        synchronized (mAnswers) {
+            answerSupplier = mAnswers.stream()
+                    .filter(e -> e.matches(hostname, type))
+                    .map(answer -> answer.mAnswerSupplier).findFirst().orElse(null);
+        }
+        if (answerSupplier == null) {
+            return CompletableFuture.completedFuture(null);
+        }
+
+        if (answerSupplier instanceof InstantAnswerSupplier) {
+            // Save latency waiting for a query thread if the answer is hardcoded.
+            return CompletableFuture.completedFuture(
+                    ((InstantAnswerSupplier) answerSupplier).get());
+        }
+        final CompletableFuture<String[]> answerFuture = new CompletableFuture<>();
+        new Thread(() -> {
+            try {
+                answerFuture.complete(answerSupplier.get());
+            } catch (DnsResolver.DnsException e) {
+                answerFuture.completeExceptionally(e);
+            }
+        }).start();
+        return answerFuture;
+    }
+
+    /** Sets the answer for a given name and type. */
+    public void setAnswer(String hostname, String[] answer, int type) {
+        setAnswer(hostname, new InstantAnswerSupplier(answer), type);
+    }
+
+    /** Sets the answer for a given name and type. */
+    public void setAnswer(String hostname, AnswerSupplier answerSupplier, int type) {
+        DnsEntry record = new DnsEntry(hostname, type, answerSupplier);
+        synchronized (mAnswers) {
+            // Remove the existing one.
+            mAnswers.removeIf(entry -> entry.matches(hostname, type));
+            // Add or replace a new record.
+            mAnswers.add(record);
+        }
+    }
+
+    private byte[] makeSvcbResponse(String hostname, String[] answer) {
+        try {
+            return DnsSvcbUtils.makeSvcbResponse(hostname, answer);
+        } catch (IOException e) {
+            throw new AssertionError("Invalid test data building SVCB response for: "
+                    + Arrays.toString(answer));
+        }
+    }
+
+    /** Simulates a getAllByName call for the specified name on the specified mock network. */
+    private InetAddress[] getAllByName(Network mockNetwork, String hostname)
+            throws UnknownHostException {
+        final List<InetAddress> answer;
+        try {
+            answer = stringsToInetAddresses(queryAllTypes(mockNetwork, hostname).get(
+                    HANDLER_TIMEOUT_MS, TimeUnit.MILLISECONDS));
+        } catch (ExecutionException | InterruptedException | TimeoutException e) {
+            throw new AssertionError("No mock DNS reply within timeout", e);
+        }
+        if (answer == null || answer.size() == 0) {
+            throw new UnknownHostException(hostname);
+        }
+        return answer.toArray(new InetAddress[0]);
+    }
+
+    // Regardless of the type, depends on what the responses contained in the network.
+    @SuppressWarnings("FutureReturnValueIgnored")
+    private CompletableFuture<String[]> queryAllTypes(
+            Network mockNetwork, String hostname) {
+        if (mNetwork.equals(mockNetwork) && !mNonBypassPrivateDnsWorking) {
+            return CompletableFuture.completedFuture(null);
+        }
+
+        final CompletableFuture<String[]> aFuture =
+                getAnswer(mockNetwork, hostname, TYPE_A)
+                        .exceptionally(e -> new String[0]);
+        final CompletableFuture<String[]> aaaaFuture =
+                getAnswer(mockNetwork, hostname, TYPE_AAAA)
+                        .exceptionally(e -> new String[0]);
+
+        final CompletableFuture<String[]> combinedFuture = new CompletableFuture<>();
+        aFuture.thenAcceptBoth(aaaaFuture, (res1, res2) -> {
+            final List<String> answerList = new ArrayList<>();
+            if (res1 != null) answerList.addAll(Arrays.asList(res1));
+            if (res2 != null) answerList.addAll(Arrays.asList(res2));
+            combinedFuture.complete(answerList.toArray(new String[0]));
+        });
+        return combinedFuture;
+    }
+
+    /** Starts mocking DNS queries. */
+    public void startMocking() throws UnknownHostException {
+        // Queries on mNetwork using getAllByName.
+        doAnswer(invocation -> {
+            return getAllByName((Network) invocation.getMock(), invocation.getArgument(0));
+        }).when(mNetwork).getAllByName(any());
+
+        // Queries on mCleartextDnsNetwork using DnsResolver#query.
+        doAnswer(invocation -> {
+            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
+                    3 /* posExecutor */, 5 /* posCallback */, -1 /* posType */);
+        }).when(mDnsResolver).query(any(), any(), anyInt(), any(), any(), any());
+
+        // Queries on mCleartextDnsNetwork using DnsResolver#query with QueryType.
+        doAnswer(invocation -> {
+            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
+                    4 /* posExecutor */, 6 /* posCallback */, 2 /* posType */);
+        }).when(mDnsResolver).query(any(), any(), anyInt(), anyInt(), any(), any(), any());
+
+        // Queries using rawQuery. Currently, mockQuery only supports TYPE_SVCB.
+        doAnswer(invocation -> {
+            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
+                    5 /* posExecutor */, 7 /* posCallback */, 3 /* posType */);
+        }).when(mDnsResolver).rawQuery(any(), any(), anyInt(), anyInt(), anyInt(), any(),
+                any(), any());
+    }
+
+    private List<InetAddress> stringsToInetAddresses(String[] addrs) {
+        if (addrs == null) return null;
+        final List<InetAddress> out = new ArrayList<>();
+        for (String addr : addrs) {
+            out.add(parseNumericAddress(addr));
+        }
+        return out;
+    }
+
+    // Mocks all the DnsResolver query methods used in this test.
+    @SuppressWarnings("FutureReturnValueIgnored")
+    private Answer mockQuery(InvocationOnMock invocation, int posNetwork, int posHostname,
+            int posExecutor, int posCallback, int posType) {
+        String hostname = invocation.getArgument(posHostname);
+        Executor executor = invocation.getArgument(posExecutor);
+        Network network = invocation.getArgument(posNetwork);
+        DnsResolver.Callback callback = invocation.getArgument(posCallback);
+
+        final CompletableFuture<String[]> answerFuture = (posType != -1)
+                ? getAnswer(network, hostname, invocation.getArgument(posType))
+                : queryAllTypes(network, hostname);
+
+        answerFuture.whenComplete((answer, exception) -> {
+            new Handler(Looper.getMainLooper()).post(() -> executor.execute(() -> {
+                if (exception != null) {
+                    if (!(exception instanceof DnsResolver.DnsException)) {
+                        throw new AssertionError("Test error building DNS response", exception);
+                    }
+                    callback.onError((DnsResolver.DnsException) exception);
+                    return;
+                }
+                if (answer != null && answer.length > 0) {
+                    final int qtype = (posType != -1)
+                            ? invocation.getArgument(posType) : TYPE_AAAA;
+                    switch (qtype) {
+                        // Assume A and AAAA queries use the List<InetAddress> callback.
+                        case TYPE_A:
+                        case TYPE_AAAA:
+                            callback.onAnswer(stringsToInetAddresses(answer), 0);
+                            break;
+                        case TYPE_SVCB:
+                            callback.onAnswer(makeSvcbResponse(hostname, answer), 0);
+                            break;
+                        default:
+                            throw new UnsupportedOperationException(
+                                    "Unsupported qtype: " + qtype + ", update this fake");
+                    }
+                }
+            }));
+        });
+        // If the future does not complete or has no answer do nothing. The timeout should fire.
+        return null;
+    }
+}
diff --git a/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java b/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
index d5d1c90b..4273d952 100644
--- a/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
+++ b/tests/unit/src/com/android/server/connectivity/NetworkMonitorTest.java
@@ -19,6 +19,7 @@ package com.android.server.connectivity;
 import static android.content.Intent.ACTION_CONFIGURATION_CHANGED;
 import static android.net.CaptivePortal.APP_RETURN_DISMISSED;
 import static android.net.CaptivePortal.APP_RETURN_WANTED_AS_IS;
+import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_OPPORTUNISTIC;
 import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;
 import static android.net.DnsResolver.TYPE_A;
 import static android.net.DnsResolver.TYPE_AAAA;
@@ -53,6 +54,9 @@ import static android.net.util.DataStallUtils.DEFAULT_DATA_STALL_EVALUATION_TYPE
 import static android.os.Build.VERSION_CODES.S_V2;
 import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
 
+import static com.android.net.module.util.DnsPacket.TYPE_SVCB;
+import static com.android.net.module.util.FeatureVersions.FEATURE_DDR_IN_CONNECTIVITY;
+import static com.android.net.module.util.FeatureVersions.FEATURE_DDR_IN_DNSRESOLVER;
 import static com.android.net.module.util.NetworkStackConstants.TEST_CAPTIVE_PORTAL_HTTPS_URL;
 import static com.android.net.module.util.NetworkStackConstants.TEST_CAPTIVE_PORTAL_HTTP_URL;
 import static com.android.net.module.util.NetworkStackConstants.TEST_URL_EXPIRATION_TIME;
@@ -64,7 +68,9 @@ import static com.android.networkstack.util.NetworkStackUtils.CAPTIVE_PORTAL_MOD
 import static com.android.networkstack.util.NetworkStackUtils.CAPTIVE_PORTAL_OTHER_FALLBACK_URLS;
 import static com.android.networkstack.util.NetworkStackUtils.CAPTIVE_PORTAL_USE_HTTPS;
 import static com.android.networkstack.util.NetworkStackUtils.DEFAULT_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT;
+import static com.android.networkstack.util.NetworkStackUtils.DNS_DDR_VERSION;
 import static com.android.networkstack.util.NetworkStackUtils.DNS_PROBE_PRIVATE_IP_NO_INTERNET_VERSION;
+import static com.android.networkstack.util.NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION;
 import static com.android.networkstack.util.NetworkStackUtils.REEVALUATE_WHEN_RESUME;
 import static com.android.server.connectivity.NetworkMonitor.CONFIG_ASYNC_PRIVDNS_PROBE_TIMEOUT_MS;
 import static com.android.server.connectivity.NetworkMonitor.INITIAL_REEVALUATE_DELAY_MS;
@@ -104,7 +110,6 @@ import static org.mockito.Mockito.verify;
 
 import static java.lang.System.currentTimeMillis;
 import static java.util.Collections.singletonList;
-import static java.util.stream.Collectors.toList;
 
 import android.annotation.NonNull;
 import android.annotation.SuppressLint;
@@ -121,7 +126,6 @@ import android.net.DataStallReportParcelable;
 import android.net.DnsResolver;
 import android.net.INetd;
 import android.net.INetworkMonitorCallbacks;
-import android.net.InetAddresses;
 import android.net.LinkProperties;
 import android.net.Network;
 import android.net.NetworkAgentConfig;
@@ -140,9 +144,7 @@ import android.net.wifi.WifiManager;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.ConditionVariable;
-import android.os.Handler;
 import android.os.IBinder;
-import android.os.Looper;
 import android.os.Process;
 import android.os.RemoteException;
 import android.os.SystemClock;
@@ -154,6 +156,7 @@ import android.telephony.CellInfoGsm;
 import android.telephony.CellInfoLte;
 import android.telephony.CellSignalStrength;
 import android.telephony.TelephonyManager;
+import android.text.TextUtils;
 import android.util.ArrayMap;
 
 import androidx.test.filters.SmallTest;
@@ -175,7 +178,6 @@ import com.android.networkstack.apishim.common.UnsupportedApiLevelException;
 import com.android.networkstack.metrics.DataStallDetectionStats;
 import com.android.networkstack.metrics.DataStallStatsUtils;
 import com.android.networkstack.netlink.TcpSocketTracker;
-import com.android.networkstack.util.NetworkStackUtils;
 import com.android.server.NetworkStackService.NetworkStackServiceManager;
 import com.android.server.connectivity.nano.CellularData;
 import com.android.server.connectivity.nano.DnsEvent;
@@ -202,8 +204,6 @@ import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
 import org.mockito.Spy;
-import org.mockito.invocation.InvocationOnMock;
-import org.mockito.stubbing.Answer;
 
 import java.io.ByteArrayInputStream;
 import java.io.IOException;
@@ -225,13 +225,9 @@ import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Random;
-import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CountDownLatch;
-import java.util.concurrent.ExecutionException;
-import java.util.concurrent.Executor;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.TimeUnit;
-import java.util.concurrent.TimeoutException;
 import java.util.function.Predicate;
 
 import javax.net.ssl.SSLHandshakeException;
@@ -377,204 +373,6 @@ public class NetworkMonitorTest {
                 .addCapability(NET_CAPABILITY_OEM_PAID)
                 .removeCapability(NET_CAPABILITY_NOT_RESTRICTED);
 
-    /**
-     * Fakes DNS responses.
-     *
-     * Allows test methods to configure the IP addresses that will be resolved by
-     * Network#getAllByName and by DnsResolver#query.
-     */
-    class FakeDns {
-        /** Data class to record the Dns entry. */
-        class DnsEntry {
-            final String mHostname;
-            final int mType;
-            final AddressSupplier mAddressesSupplier;
-            DnsEntry(String host, int type, AddressSupplier addr) {
-                mHostname = host;
-                mType = type;
-                mAddressesSupplier = addr;
-            }
-            // Full match or partial match that target host contains the entry hostname to support
-            // random private dns probe hostname.
-            private boolean matches(String hostname, int type) {
-                return hostname.endsWith(mHostname) && type == mType;
-            }
-        }
-        interface AddressSupplier {
-            List<InetAddress> get() throws DnsResolver.DnsException;
-        }
-
-        class InstantAddressSupplier implements AddressSupplier {
-            private final List<InetAddress> mAddresses;
-            InstantAddressSupplier(List<InetAddress> addresses) {
-                mAddresses = addresses;
-            }
-            @Override
-            public List<InetAddress> get() {
-                return mAddresses;
-            }
-        }
-
-        private final ArrayList<DnsEntry> mAnswers = new ArrayList<DnsEntry>();
-        private boolean mNonBypassPrivateDnsWorking = true;
-
-        /** Whether DNS queries on mNonBypassPrivateDnsWorking should succeed. */
-        private void setNonBypassPrivateDnsWorking(boolean working) {
-            mNonBypassPrivateDnsWorking = working;
-        }
-
-        /** Clears all DNS entries. */
-        private void clearAll() {
-            synchronized (mAnswers) {
-                mAnswers.clear();
-            }
-        }
-
-        /** Returns the answer for a given name and type on the given mock network. */
-        private CompletableFuture<List<InetAddress>> getAnswer(Network mockNetwork, String hostname,
-                int type) {
-            if (mockNetwork == mNetwork && !mNonBypassPrivateDnsWorking) {
-                return CompletableFuture.completedFuture(null);
-            }
-
-            final AddressSupplier answerSupplier;
-
-            synchronized (mAnswers) {
-                answerSupplier = mAnswers.stream()
-                        .filter(e -> e.matches(hostname, type))
-                        .map(answer -> answer.mAddressesSupplier).findFirst().orElse(null);
-            }
-            if (answerSupplier == null) {
-                return CompletableFuture.completedFuture(null);
-            }
-
-            if (answerSupplier instanceof InstantAddressSupplier) {
-                // Save latency waiting for a query thread if the answer is hardcoded.
-                return CompletableFuture.completedFuture(
-                        ((InstantAddressSupplier) answerSupplier).get());
-            }
-            final CompletableFuture<List<InetAddress>> answerFuture = new CompletableFuture<>();
-            new Thread(() -> {
-                try {
-                    answerFuture.complete(answerSupplier.get());
-                } catch (DnsResolver.DnsException e) {
-                    answerFuture.completeExceptionally(e);
-                }
-            }).start();
-            return answerFuture;
-        }
-
-        /** Sets the answer for a given name and type. */
-        private void setAnswer(String hostname, String[] answer, int type) {
-            setAnswer(hostname, new InstantAddressSupplier(generateAnswer(answer)), type);
-        }
-
-        private void setAnswer(String hostname, AddressSupplier answerSupplier, int type) {
-            DnsEntry record = new DnsEntry(hostname, type, answerSupplier);
-            synchronized (mAnswers) {
-                // Remove the existing one.
-                mAnswers.removeIf(entry -> entry.matches(hostname, type));
-                // Add or replace a new record.
-                mAnswers.add(record);
-            }
-        }
-
-        private List<InetAddress> generateAnswer(String[] answer) {
-            if (answer == null) return new ArrayList<>();
-            return Arrays.stream(answer).map(InetAddresses::parseNumericAddress).collect(toList());
-        }
-
-        /** Simulates a getAllByName call for the specified name on the specified mock network. */
-        private InetAddress[] getAllByName(Network mockNetwork, String hostname)
-                throws UnknownHostException {
-            final List<InetAddress> answer;
-            try {
-                answer = queryAllTypes(mockNetwork, hostname).get(
-                        HANDLER_TIMEOUT_MS, TimeUnit.MILLISECONDS);
-            } catch (ExecutionException | InterruptedException | TimeoutException e) {
-                throw new AssertionError("No mock DNS reply within timeout", e);
-            }
-            if (answer == null || answer.size() == 0) {
-                throw new UnknownHostException(hostname);
-            }
-            return answer.toArray(new InetAddress[0]);
-        }
-
-        // Regardless of the type, depends on what the responses contained in the network.
-        private CompletableFuture<List<InetAddress>> queryAllTypes(
-                Network mockNetwork, String hostname) {
-            if (mockNetwork == mNetwork && !mNonBypassPrivateDnsWorking) {
-                return CompletableFuture.completedFuture(null);
-            }
-
-            final CompletableFuture<List<InetAddress>> aFuture =
-                    getAnswer(mockNetwork, hostname, TYPE_A)
-                            .exceptionally(e -> Collections.emptyList());
-            final CompletableFuture<List<InetAddress>> aaaaFuture =
-                    getAnswer(mockNetwork, hostname, TYPE_AAAA)
-                            .exceptionally(e -> Collections.emptyList());
-
-            final CompletableFuture<List<InetAddress>> combinedFuture = new CompletableFuture<>();
-            aFuture.thenAcceptBoth(aaaaFuture, (res1, res2) -> {
-                final List<InetAddress> answer = new ArrayList<>();
-                if (res1 != null) answer.addAll(res1);
-                if (res2 != null) answer.addAll(res2);
-                combinedFuture.complete(answer);
-            });
-            return combinedFuture;
-        }
-
-        /** Starts mocking DNS queries. */
-        private void startMocking() throws UnknownHostException {
-            // Queries on mNetwork using getAllByName.
-            doAnswer(invocation -> {
-                return getAllByName((Network) invocation.getMock(), invocation.getArgument(0));
-            }).when(mNetwork).getAllByName(any());
-
-            // Queries on mCleartextDnsNetwork using DnsResolver#query.
-            doAnswer(invocation -> {
-                return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
-                        3 /* posExecutor */, 5 /* posCallback */, -1 /* posType */);
-            }).when(mDnsResolver).query(any(), any(), anyInt(), any(), any(), any());
-
-            // Queries on mCleartextDnsNetwork using DnsResolver#query with QueryType.
-            doAnswer(invocation -> {
-                return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
-                        4 /* posExecutor */, 6 /* posCallback */, 2 /* posType */);
-            }).when(mDnsResolver).query(any(), any(), anyInt(), anyInt(), any(), any(), any());
-        }
-
-        // Mocking queries on DnsResolver#query.
-        private Answer mockQuery(InvocationOnMock invocation, int posNetwork, int posHostname,
-                int posExecutor, int posCallback, int posType) {
-            String hostname = (String) invocation.getArgument(posHostname);
-            Executor executor = (Executor) invocation.getArgument(posExecutor);
-            DnsResolver.Callback<List<InetAddress>> callback = invocation.getArgument(posCallback);
-            Network network = invocation.getArgument(posNetwork);
-
-            final CompletableFuture<List<InetAddress>> answerFuture = posType != -1
-                    ? getAnswer(network, hostname, invocation.getArgument(posType))
-                    : queryAllTypes(network, hostname);
-
-            answerFuture.whenComplete((answer, exception) -> {
-                new Handler(Looper.getMainLooper()).post(() -> executor.execute(() -> {
-                    if (exception != null) {
-                        if (!(exception instanceof DnsResolver.DnsException)) {
-                            throw new AssertionError("Test error building DNS response", exception);
-                        }
-                        callback.onError((DnsResolver.DnsException) exception);
-                        return;
-                    }
-                    if (answer != null && answer.size() > 0) {
-                        callback.onAnswer(answer, 0);
-                    }
-                }));
-            });
-            // If the future does not complete or has no answer do nothing. The timeout should fire.
-            return null;
-        }
-    }
-
     private FakeDns mFakeDns;
 
     @GuardedBy("mThreadsToBeCleared")
@@ -608,6 +406,7 @@ public class NetworkMonitorTest {
             }
             return null;
         }).when(mDependencies).onExecutorServiceCreated(any());
+        doReturn(mValidationLogger).when(mValidationLogger).forSubComponent(any());
 
         doReturn(mCleartextDnsNetwork).when(mNetwork).getPrivateDnsBypassingCopy();
 
@@ -676,7 +475,7 @@ public class NetworkMonitorTest {
         initHttpConnection(mFallbackConnection);
         initHttpConnection(mOtherFallbackConnection);
 
-        mFakeDns = new FakeDns();
+        mFakeDns = new FakeDns(mNetwork, mDnsResolver);
         mFakeDns.startMocking();
         // Set private dns suffix answer. sendPrivateDnsProbe() in NetworkMonitor send probe with
         // one time hostname. The hostname will be [random generated UUID] + HOST_SUFFIX differently
@@ -1292,33 +1091,18 @@ public class NetworkMonitorTest {
     private static CellIdentityGsm makeCellIdentityGsm(int lac, int cid, int arfcn, int bsic,
             String mccStr, String mncStr, String alphal, String alphas)
             throws ReflectiveOperationException {
-        if (ShimUtils.isAtLeastR()) {
-            return new CellIdentityGsm(lac, cid, arfcn, bsic, mccStr, mncStr, alphal, alphas,
-                    Collections.emptyList() /* additionalPlmns */);
-        } else {
-            // API <= Q does not have the additionalPlmns parameter
-            final Constructor<CellIdentityGsm> constructor = CellIdentityGsm.class.getConstructor(
-                    int.class, int.class, int.class, int.class, String.class, String.class,
-                    String.class, String.class);
-            return constructor.newInstance(lac, cid, arfcn, bsic, mccStr, mncStr, alphal, alphas);
-        }
+        // TODO: inline this call.
+        return new CellIdentityGsm(lac, cid, arfcn, bsic, mccStr, mncStr, alphal, alphas,
+                Collections.emptyList() /* additionalPlmns */);
     }
 
     private static CellIdentityLte makeCellIdentityLte(int ci, int pci, int tac, int earfcn,
             int bandwidth, String mccStr, String mncStr, String alphal, String alphas)
             throws ReflectiveOperationException {
-        if (ShimUtils.isAtLeastR()) {
-            return new CellIdentityLte(ci, pci, tac, earfcn, new int[] {} /* bands */,
-                    bandwidth, mccStr, mncStr, alphal, alphas,
-                    Collections.emptyList() /* additionalPlmns */, null /* csgInfo */);
-        } else {
-            // API <= Q does not have the additionalPlmns and csgInfo parameters
-            final Constructor<CellIdentityLte> constructor = CellIdentityLte.class.getConstructor(
-                    int.class, int.class, int.class, int.class, int.class, String.class,
-                    String.class, String.class, String.class);
-            return constructor.newInstance(ci, pci, tac, earfcn, bandwidth, mccStr, mncStr, alphal,
-                    alphas);
-        }
+        // TODO: inline this call.
+        return new CellIdentityLte(ci, pci, tac, earfcn, new int[] {} /* bands */,
+                bandwidth, mccStr, mncStr, alphal, alphas,
+                Collections.emptyList() /* additionalPlmns */, null /* csgInfo */);
     }
 
     @Test
@@ -2292,22 +2076,10 @@ public class NetworkMonitorTest {
         assertEquals(expectedUrl, redirectUrl);
     }
 
-
     @Test
-    public void testCaptivePortalLogin_beforeR() throws Exception {
-        assumeFalse(ShimUtils.isAtLeastR());
-        testCaptivePortalLogin(TEST_HTTP_URL);
-    }
-
-    @Test
-    public void testCaptivePortalLogin_AfterR() throws Exception {
-        assumeTrue(ShimUtils.isAtLeastR());
-        testCaptivePortalLogin(TEST_LOGIN_URL);
-    }
-
-    private void testCaptivePortalLogin(String expectedUrl) throws Exception {
+    public void testCaptivePortalLogin() throws Exception {
         final NetworkMonitor nm = makeMonitor(CELL_METERED_CAPABILITIES);
-        setupAndLaunchCaptivePortalApp(nm, expectedUrl);
+        setupAndLaunchCaptivePortalApp(nm, TEST_LOGIN_URL);
 
         // Have the app report that the captive portal is dismissed, and check that we revalidate.
         setStatus(mHttpsConnection, 204);
@@ -2322,20 +2094,9 @@ public class NetworkMonitorTest {
     }
 
     @Test
-    public void testCaptivePortalUseAsIs_beforeR() throws Exception {
-        assumeFalse(ShimUtils.isAtLeastR());
-        testCaptivePortalUseAsIs(TEST_HTTP_URL);
-    }
-
-    @Test
-    public void testCaptivePortalUseAsIs_AfterR() throws Exception {
-        assumeTrue(ShimUtils.isAtLeastR());
-        testCaptivePortalUseAsIs(TEST_LOGIN_URL);
-    }
-
-    private void testCaptivePortalUseAsIs(String expectedUrl) throws Exception {
+    public void testCaptivePortalUseAsIs() throws Exception {
         final NetworkMonitor nm = makeMonitor(CELL_METERED_CAPABILITIES);
-        setupAndLaunchCaptivePortalApp(nm, expectedUrl);
+        setupAndLaunchCaptivePortalApp(nm, TEST_LOGIN_URL);
 
         // The user decides this network is wanted as is, either by encountering an SSL error or
         // encountering an unknown scheme and then deciding to continue through the browser, or by
@@ -2390,14 +2151,14 @@ public class NetworkMonitorTest {
     @Test
     public void testPrivateDnsSuccess_SyncDns() throws Exception {
         doReturn(false).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         runPrivateDnsSuccessTest();
     }
 
     @Test
     public void testPrivateDnsSuccess_AsyncDns() throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         runPrivateDnsSuccessTest();
     }
 
@@ -2426,14 +2187,14 @@ public class NetworkMonitorTest {
     @Test
     public void testProbeStatusChanged_SyncDns() throws Exception {
         doReturn(false).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         runProbeStatusChangedTest();
     }
 
     @Test
     public void testProbeStatusChanged_AsyncDns() throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         runProbeStatusChangedTest();
     }
 
@@ -2484,21 +2245,21 @@ public class NetworkMonitorTest {
     @Test
     public void testPrivateDnsResolutionRetryUpdate_SyncDns() throws Exception {
         doReturn(false).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         runPrivateDnsResolutionRetryUpdateTest();
     }
 
     @Test
     public void testPrivateDnsResolutionRetryUpdate_AsyncDns() throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         runPrivateDnsResolutionRetryUpdateTest();
     }
 
     @Test
     public void testAsyncPrivateDnsResolution_PartialTimeout() throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
 
@@ -2522,7 +2283,7 @@ public class NetworkMonitorTest {
     @Test
     public void testAsyncPrivateDnsResolution_PartialFailure() throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
 
@@ -2551,7 +2312,7 @@ public class NetworkMonitorTest {
     public void testAsyncPrivateDnsResolution_AQuerySucceedsFirst_PrioritizeAAAA()
             throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
 
@@ -2561,7 +2322,7 @@ public class NetworkMonitorTest {
         final ConditionVariable v4Queried = new ConditionVariable();
         mFakeDns.setAnswer("dns.google", () -> {
             v4Queried.open();
-            return List.of(parseNumericAddress("192.0.2.123"));
+            return new String[]{"192.0.2.123"};
         }, TYPE_A);
         mFakeDns.setAnswer("dns.google", () -> {
             // Make sure the v6 query processing is a bit slower than the v6 one. The small delay
@@ -2570,7 +2331,7 @@ public class NetworkMonitorTest {
             // not, the test should pass.
             v4Queried.block(HANDLER_TIMEOUT_MS);
             SystemClock.sleep(10L);
-            return List.of(parseNumericAddress("2001:db8::1"), parseNumericAddress("2001:db8::2"));
+            return new String[]{"2001:db8::1", "2001:db8::2"};
         }, TYPE_AAAA);
 
         notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
@@ -2589,7 +2350,7 @@ public class NetworkMonitorTest {
     public void testAsyncPrivateDnsResolution_ConfigChange_RestartsWithNewConfig()
             throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
 
@@ -2601,12 +2362,12 @@ public class NetworkMonitorTest {
         mFakeDns.setAnswer("v1.google", () -> {
             queriedLatch.countDown();
             blockReplies.block(HANDLER_TIMEOUT_MS);
-            return List.of(parseNumericAddress("192.0.2.123"));
+            return new String[]{"192.0.2.123"};
         }, TYPE_A);
         mFakeDns.setAnswer("v1.google", () -> {
             queriedLatch.countDown();
             blockReplies.block(HANDLER_TIMEOUT_MS);
-            return List.of(parseNumericAddress("2001:db8::1"));
+            return new String[]{"2001:db8::1"};
         }, TYPE_AAAA);
 
         notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
@@ -2637,7 +2398,7 @@ public class NetworkMonitorTest {
     public void testAsyncPrivateDnsResolution_TurnOffStrictMode_SkipsDnsValidation()
             throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
 
@@ -2649,12 +2410,12 @@ public class NetworkMonitorTest {
         mFakeDns.setAnswer("v1.google", () -> {
             queriedLatch.countDown();
             blockReplies.block(HANDLER_TIMEOUT_MS);
-            return List.of(parseNumericAddress("192.0.2.123"));
+            return new String[]{"192.0.2.123"};
         }, TYPE_A);
         mFakeDns.setAnswer("v1.google", () -> {
             queriedLatch.countDown();
             blockReplies.block(HANDLER_TIMEOUT_MS);
-            return List.of(parseNumericAddress("2001:db8::1"));
+            return new String[]{"2001:db8::1"};
         }, TYPE_AAAA);
 
         notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
@@ -2672,6 +2433,210 @@ public class NetworkMonitorTest {
         verify(mCallbacks, never()).notifyPrivateDnsConfigResolved(any());
     }
 
+    private void setDdrEnabledForTest() {
+        doReturn(true).when(mDependencies).isFeatureEnabled(any(),
+                eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+        doReturn(true).when(mDependencies).isFeatureEnabled(any(), eq(DNS_DDR_VERSION));
+        doReturn(true).when(mDependencies).isFeatureSupported(any(),
+                eq(FEATURE_DDR_IN_CONNECTIVITY));
+        doReturn(true).when(mDependencies).isFeatureSupported(any(),
+                eq(FEATURE_DDR_IN_DNSRESOLVER));
+    }
+
+    @Test
+    public void testPrivateDnsDiscoveryWithDdr_dnsServerChange() throws Exception {
+        setDdrEnabledForTest();
+        LinkProperties lp = new LinkProperties(TEST_LINK_PROPERTIES);
+        final String svcb1 = "1 dot.google alpn=dot ipv4hint=192.0.2.1";
+        final String svcb2 = "2 doh.google alpn=h2,h3 port=443 ipv4hint=192.0.2.100 "
+                + "ipv6hint=2001:db8::100 dohpath=/dns-query{?dns}";
+        setStatus(mHttpsConnection, 204);
+        setStatus(mHttpConnection, 204);
+        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb1, svcb2 }, TYPE_SVCB);
+
+        WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
+        notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
+        verifyNetworkTestedValidFromHttps(1);
+        // The network just got connected. Verify the callback.
+        // Expect that `dohIps` is empty since there's no DNS on the network.
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDohOnly("doh.google" /* dohName */,
+                        new String[0] /* dohIps */, "/dns-query{?dns}" /* dohPath */,
+                        443 /* dohPort */));
+
+        // Add some DNS servers. Verify the callback.
+        assertTrue(lp.addDnsServer(InetAddress.parseNumericAddress("192.0.2.100")));
+        assertTrue(lp.addDnsServer(InetAddress.parseNumericAddress("2001:db8::100")));
+        wnm.notifyLinkPropertiesChanged(lp);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDohOnly("doh.google" /* dohName */,
+                        new String[] { "192.0.2.100", "2001:db8::100" } /* dohIps */,
+                        "/dns-query{?dns}" /* dohPath */, 443 /* dohPort */));
+
+        // Verify that the callback is not fired if there is no DNS servers change.
+        // The number of the invoke callbacks remains 2.
+        wnm.notifyLinkPropertiesChanged(lp);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(2))
+                .notifyPrivateDnsConfigResolved(any());
+
+        // Remove a DNS server. Verify the callback.
+        assertTrue(lp.removeDnsServer(InetAddress.parseNumericAddress("2001:db8::100")));
+        wnm.notifyLinkPropertiesChanged(lp);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDohOnly("doh.google" /* dohName */,
+                        new String[] { "192.0.2.100" } /* dohIps */,
+                        "/dns-query{?dns}" /* dohPath */, 443 /* DohPort */));
+    }
+
+    @Test
+    public void testPrivateDnsDiscoveryWithDdr_privateDnsModeChange() throws Exception {
+        setDdrEnabledForTest();
+        final String svcb1 = "1 some.dot.name alpn=dot ipv4hint=192.0.1.100";
+        final String svcb2 = "1 some.doh.name alpn=h3 port=443 ipv4hint=192.0.2.1,192.0.2.100 "
+                + "ipv6hint=2001:db8::1,2001:db8::100 dohpath=/dns-query{?dns}";
+        setStatus(mHttpsConnection, 204);
+        setStatus(mHttpConnection, 204);
+        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb2 }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.dot.google", new String[] { svcb1 }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.doh.google", new String[] { svcb2 }, TYPE_SVCB);
+        mFakeDns.setAnswer("dot.google", new String[] { "2001:db8::853" }, TYPE_AAAA);
+        mFakeDns.setAnswer("doh.google", new String[] { "2001:db8::854" }, TYPE_AAAA);
+
+        WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
+        notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
+        verifyNetworkTestedValidFromHttps(1);
+        // The network just got connected. Verify the callback.
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDohOnly("some.doh.name" /* dohName */,
+                        new String[0] /* dohIps */, "/dns-query{?dns}" /* dohPath */,
+                        443 /* dohPort */));
+
+        // Change the mode to off mode. The callback is not fired.
+        // The number of invoked callbacks remains 1.
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(false));
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
+                .notifyPrivateDnsConfigResolved(any());
+
+        // Change the mode to opportunistic mode. Verify the callback.
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDohOnly("some.doh.name" /* dohName */,
+                        new String[0] /* dohIps */, "/dns-query{?dns}" /* dohPath */,
+                        443 /* dohPort */));
+
+        // Change the mode to strict mode. Verify the callback.
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dot.google", new InetAddress[0]));
+        verifyNetworkTestedValidFromPrivateDns(1);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeast(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDotOnly("dot.google" /* hostname */,
+                        new String[] { "2001:db8::853" } /* dotIps */));
+
+        // Change the hostname of the setting. Verify the callback.
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("doh.google", new InetAddress[0]));
+        verifyNetworkTestedValidFromPrivateDns(2);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeast(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcel("doh.google" /* hostname */,
+                        new String[] { "2001:db8::854" } /* dotIps */,
+                        "doh.google" /* dohName */,
+                        new String[] { "192.0.2.1", "192.0.2.100", "2001:db8::1",
+                                "2001:db8::100" } /* dohIps */,
+                        "/dns-query{?dns}" /* dohPath */, 443 /* dohPort */));
+    }
+
+    @Test
+    public void testPrivateDnsDiscoveryWithDdr_h3NotSupported() throws Exception {
+        setDdrEnabledForTest();
+        final String svcb = "1 doh.google alpn=h2 ipv4hint=192.0.2.100 dohpath=/dns-query{?dns}";
+        setStatus(mHttpsConnection, 204);
+        setStatus(mHttpConnection, 204);
+        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.dns.google", new String[] { svcb }, TYPE_SVCB);
+        mFakeDns.setAnswer("dns.google", new String[] { "2001:db8::853" }, TYPE_AAAA);
+
+        WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google", new InetAddress[0]));
+        notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
+        verifyNetworkTestedValidFromPrivateDns(1);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeast(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDotOnly("dns.google" /* hostname */,
+                        new String[] { "2001:db8::853" } /* dotIps */));
+    }
+
+    @Test
+    public void testPrivateDnsDiscoveryWithDdr_svcbLookupError() throws Exception {
+        setDdrEnabledForTest();
+        setStatus(mHttpsConnection, 204);
+        setStatus(mHttpConnection, 204);
+        mFakeDns.setAnswer("dns.google", new String[] { "2001:db8::1" }, TYPE_AAAA);
+        mFakeDns.setAnswer("_dns.dns.google", () -> {
+            throw mock(DnsResolver.DnsException.class); }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.resolver.arpa", () -> {
+            throw mock(DnsResolver.DnsException.class); }, TYPE_SVCB);
+
+        // In opportunistic mode, DoH is not used if the SVCB lookup fails or times out.
+        WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
+        notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
+        verifyNetworkTestedValidFromHttps(1);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDotOnly("" /* hostname */,
+                        new String[] {} /* dotIps */));
+
+        // In strict mode, DoH not used if the SVCB lookup fails or times out.
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google", new InetAddress[0]));
+        verifyNetworkTestedValidFromPrivateDns(1);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDotOnly("dns.google" /* hostname */,
+                        new String[] { "2001:db8::1" } /* dotIps */));
+    }
+
+    @Test
+    public void testPrivateDnsDiscoveryWithDdr_retryForReevaluation() throws Exception {
+        setDdrEnabledForTest();
+        final String svcb = "1 doh.google alpn=h3 ipv4hint=192.0.2.100 dohpath=/dns-query{?dns}";
+        setStatus(mHttpsConnection, 204);
+        setStatus(mHttpConnection, 204);
+        mFakeDns.setAnswer("_dns.resolver.arpa", new String[] { svcb }, TYPE_SVCB);
+        mFakeDns.setAnswer("_dns.dns.google", new String[] { svcb }, TYPE_SVCB);
+        mFakeDns.setAnswer("dns.google", new String[] { "2001:db8::853" }, TYPE_AAAA);
+
+        // Verify the callback for opportunistic mode.
+        WrappedNetworkMonitor wnm = makeCellNotMeteredNetworkMonitor();
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig(true));
+        notifyNetworkConnected(wnm, CELL_NOT_METERED_CAPABILITIES);
+        verifyNetworkTestedValidFromHttps(1);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcelWithDohOnly("doh.google" /* dohName */,
+                        new String[0] /* dohIps */, "/dns-query{?dns}" /* dohPath */,
+                        -1 /* dohPort */));
+
+        // Re-evaluation triggers DDR even in opportunistic mode.
+        wnm.forceReevaluation(Process.myUid());
+        verifyNetworkTestedValidFromHttps(2);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(2))
+                .notifyPrivateDnsConfigResolved(any());
+
+        // Verify the callback for strict mode.
+        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google", new InetAddress[0]));
+        verifyNetworkTestedValidFromPrivateDns(1);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeast(1)).notifyPrivateDnsConfigResolved(
+                matchPrivateDnsConfigParcel("dns.google" /* hostname */,
+                        new String[] { "2001:db8::853" } /* dotIps */, "dns.google" /* dohName */,
+                        new String[] { "192.0.2.100" } /* dohIps */,
+                        "/dns-query{?dns}" /* dohPath */, -1 /* dohPort */));
+
+        // Reevaluation triggers DDR.
+        wnm.forceReevaluation(Process.myUid());
+        verifyNetworkTestedValidFromPrivateDns(2);
+        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeastOnce())
+                .notifyPrivateDnsConfigResolved(matchPrivateDnsConfigParcel(
+                        "dns.google" /* hostname */, new String[] { "2001:db8::853" } /* dotIps */,
+                        "dns.google" /* dohName */, new String[] { "192.0.2.100" } /* dohIps */,
+                        "/dns-query{?dns}" /* dohPath */, -1 /* dohPort */));
+    }
+
     @Test
     public void testReevaluationInterval_networkResume() throws Exception {
         // Setup nothing and expect validation to fail.
@@ -3141,30 +3106,21 @@ public class NetworkMonitorTest {
 
     @Test
     public void testDismissPortalInValidatedNetworkEnabledOsSupported() throws Exception {
-        assumeTrue(ShimUtils.isAtLeastR());
         testDismissPortalInValidatedNetworkEnabled(TEST_LOGIN_URL, TEST_LOGIN_URL);
     }
 
     @Test
     public void testDismissPortalInValidatedNetworkEnabledOsSupported_NullLocationUrl()
             throws Exception {
-        assumeTrue(ShimUtils.isAtLeastR());
         testDismissPortalInValidatedNetworkEnabled(TEST_HTTP_URL, null /* locationUrl */);
     }
 
     @Test
     public void testDismissPortalInValidatedNetworkEnabledOsSupported_InvalidLocationUrl()
             throws Exception {
-        assumeTrue(ShimUtils.isAtLeastR());
         testDismissPortalInValidatedNetworkEnabled(TEST_HTTP_URL, TEST_RELATIVE_URL);
     }
 
-    @Test
-    public void testDismissPortalInValidatedNetworkEnabledOsNotSupported() throws Exception {
-        assumeFalse(ShimUtils.isAtLeastR());
-        testDismissPortalInValidatedNetworkEnabled(TEST_HTTP_URL, TEST_LOGIN_URL);
-    }
-
     private void testDismissPortalInValidatedNetworkEnabled(String expectedUrl, String locationUrl)
             throws Exception {
         setSslException(mHttpsConnection);
@@ -3262,11 +3218,11 @@ public class NetworkMonitorTest {
         mFakeDns.setAnswer("www.google.com", () -> {
             // Make sure the DNS probes take at least 1ms
             SystemClock.sleep(1);
-            return List.of(parseNumericAddress("2001:db8::443"));
+            return new String[]{"2001:db8::443"};
         }, TYPE_AAAA);
         mFakeDns.setAnswer(PRIVATE_DNS_PROBE_HOST_SUFFIX, () -> {
             SystemClock.sleep(1);
-            return List.of(parseNumericAddress("2001:db8::444"));
+            return new String[]{"2001:db8::444"};
         }, TYPE_AAAA);
         setStatus(mHttpsConnection, 204);
         setStatus(mHttpConnection, 204);
@@ -3342,14 +3298,14 @@ public class NetworkMonitorTest {
     @Test
     public void testLegacyConnectivityLog_SyncDns() throws Exception {
         doReturn(false).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         doLegacyConnectivityLogTest();
     }
 
     @Test
     public void testLegacyConnectivityLog_AsyncDns() throws Exception {
         doReturn(true).when(mDependencies).isFeatureEnabled(
-                any(), eq(NetworkStackUtils.NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
+                any(), eq(NETWORKMONITOR_ASYNC_PRIVDNS_RESOLUTION));
         doLegacyConnectivityLogTest();
     }
 
@@ -3867,6 +3823,26 @@ public class NetworkMonitorTest {
         return argThat(p -> (p.detectionMethod & ConstantsShim.DETECTION_METHOD_TCP_METRICS) != 0);
     }
 
+    private PrivateDnsConfigParcel matchPrivateDnsConfigParcelWithDohOnly(String dohName,
+            String[] dohIps, String dohPath, int dohPort) {
+        return matchPrivateDnsConfigParcel("", new String[0], dohName, dohIps, dohPath, dohPort);
+    }
+
+    private PrivateDnsConfigParcel matchPrivateDnsConfigParcelWithDotOnly(String hostname,
+            String[] dotIps) {
+        return matchPrivateDnsConfigParcel(hostname, dotIps, "", new String[0], "", -1);
+    }
+
+    private PrivateDnsConfigParcel matchPrivateDnsConfigParcel(String hostname,
+            String[] dotIps, String dohName, String[] dohIps, String dohPath, int dohPort) {
+        final int mode = TextUtils.isEmpty(hostname)
+                ? PRIVATE_DNS_MODE_OPPORTUNISTIC : PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;
+        return argThat(p -> (p.privateDnsMode == mode && p.hostname.equals(hostname)
+                && Arrays.equals(p.ips, dotIps) && p.dohName.equals(dohName)
+                && p.dohPath.equals(dohPath) && Arrays.equals(p.dohIps, dohIps)
+                && p.dohPort == dohPort));
+    }
+
     private void assertCaptivePortalAppReceiverRegistered(boolean isPortal) {
         // There will be configuration change receiver registered after NetworkMonitor being
         // started. If captive portal app receiver is registered, then the size of the registered
```

