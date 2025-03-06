```diff
diff --git a/display/Android.bp b/display/Android.bp
index 5741b37..d5537b7 100644
--- a/display/Android.bp
+++ b/display/Android.bp
@@ -13,9 +13,11 @@ aidl_interface {
 
     stability: "vintf",
 
+    defaults: [
+        "android.hardware.graphics.common-latest",
+    ],
     imports: [
         "android.hardware.common-V2",
-        "android.hardware.graphics.common-V5",
     ],
 
     backend: {
@@ -31,91 +33,91 @@ aidl_interface {
             version: "1",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "2",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "3",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "4",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "5",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "6",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "7",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "8",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "9",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "10",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "11",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "12",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
         {
             version: "13",
             imports: [
                 "android.hardware.common-V2",
-                "android.hardware.graphics.common-V5",
+                "android.hardware.graphics.common-V6",
             ],
         },
 
diff --git a/image/Android.bp b/image/Android.bp
index 3563883..c71eb52 100644
--- a/image/Android.bp
+++ b/image/Android.bp
@@ -7,11 +7,13 @@ aidl_interface {
     name: "google.hardware.image",
     owner: "google",
     vendor_available: true,
+    defaults: [
+        "android.hardware.graphics.common-latest",
+    ],
     srcs: [
         "google/hardware/image/*.aidl",
     ],
     headers: ["HardwareBuffer_aidl"],
-    imports: ["android.hardware.graphics.common-V5"],
     include_dirs: ["frameworks/base/core/java"],
 
     stability: "vintf",
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/MirrorDirection.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/ComponentError.aidl
similarity index 58%
rename from image/aidl_api/google.hardware.image/current/google/hardware/image/MirrorDirection.aidl
rename to image/aidl_api/google.hardware.image/current/google/hardware/image/ComponentError.aidl
index c0fb5d3..e9c82c1 100644
--- a/image/aidl_api/google.hardware.image/current/google/hardware/image/MirrorDirection.aidl
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/ComponentError.aidl
@@ -1,20 +1,3 @@
-/******************************************************************************
- *
- *  Copyright (C) 2024 Google LLC.
- *
- *  Licensed under the Apache License, Version 2.0 (the "License");
- *  you may not use this file except in compliance with the License.
- *  You may obtain a copy of the License at:
- *
- *  http://www.apache.org/licenses/LICENSE-2.0
- *
- *  Unless required by applicable law or agreed to in writing, software
- *  distributed under the License is distributed on an "AS IS" BASIS,
- *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- *  See the License for the specific language governing permissions and
- *  limitations under the License.
- *
- ******************************************************************************/
 ///////////////////////////////////////////////////////////////////////////////
 // THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
 ///////////////////////////////////////////////////////////////////////////////
@@ -35,9 +18,9 @@
 
 package google.hardware.image;
 @Backing(type="int") @VintfStability
-enum MirrorDirection {
-  NONE,
-  VER,
-  HOR,
-  HOR_VER,
+enum ComponentError {
+  INVALID_COMMAND,
+  INVALID_PARAM,
+  TIMED_OUT,
+  FAILURE,
 }
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl
index f4101fb..8532133 100644
--- a/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl
+++ b/image/aidl_api/google.hardware.image/current/google/hardware/image/IComponentStore.aidl
@@ -36,5 +36,5 @@
 package google.hardware.image;
 @VintfStability
 interface IComponentStore {
-  google.hardware.image.IComponent createComponent(in String name, in google.hardware.image.ComponentType type, in google.hardware.image.IComponentCallback callback);
+  google.hardware.image.IComponent createComponent(in google.hardware.image.ComponentType type, in google.hardware.image.IComponentCallback callback);
 }
diff --git a/image/aidl_api/google.hardware.image/current/google/hardware/image/RotationDegree.aidl b/image/aidl_api/google.hardware.image/current/google/hardware/image/RotationDegree.aidl
deleted file mode 100644
index 3323858..0000000
--- a/image/aidl_api/google.hardware.image/current/google/hardware/image/RotationDegree.aidl
+++ /dev/null
@@ -1,43 +0,0 @@
-/******************************************************************************
- *
- *  Copyright (C) 2024 Google LLC.
- *
- *  Licensed under the Apache License, Version 2.0 (the "License");
- *  you may not use this file except in compliance with the License.
- *  You may obtain a copy of the License at:
- *
- *  http://www.apache.org/licenses/LICENSE-2.0
- *
- *  Unless required by applicable law or agreed to in writing, software
- *  distributed under the License is distributed on an "AS IS" BASIS,
- *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- *  See the License for the specific language governing permissions and
- *  limitations under the License.
- *
- ******************************************************************************/
-///////////////////////////////////////////////////////////////////////////////
-// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
-///////////////////////////////////////////////////////////////////////////////
-
-// This file is a snapshot of an AIDL file. Do not edit it manually. There are
-// two cases:
-// 1). this is a frozen version file - do not edit this in any case.
-// 2). this is a 'current' file. If you make a backwards compatible change to
-//     the interface (from the latest frozen version), the build system will
-//     prompt you to update this file with `m <name>-update-api`.
-//
-// You must not make a backward incompatible change to any AIDL file built
-// with the aidl_interface module type with versions property set. The module
-// type is used to build AIDL files in a way that they can be used across
-// independently updatable components of the system. If a device is shipped
-// with such a backward incompatible change, it has a high risk of breaking
-// later when a module using the interface is updated, e.g., Mainline modules.
-
-package google.hardware.image;
-@Backing(type="int") @VintfStability
-enum RotationDegree {
-  R_NONE,
-  R_90,
-  R_180,
-  R_270,
-}
diff --git a/image/google/hardware/image/ComponentError.aidl b/image/google/hardware/image/ComponentError.aidl
new file mode 100644
index 0000000..93108f2
--- /dev/null
+++ b/image/google/hardware/image/ComponentError.aidl
@@ -0,0 +1,23 @@
+package google.hardware.image;
+
+@VintfStability
+@Backing(type="int")
+enum ComponentError {
+    /**
+     * Given command is invalid (user error). For example, incorrect sequence of
+     * commands or command not supported with this component type.
+     */
+    INVALID_COMMAND,
+    /**
+     * Given param is invalid (user error).
+     */
+    INVALID_PARAM,
+    /**
+     * Command did not complete within timeout.
+     */
+    TIMED_OUT,
+    /**
+     * Command failed for a reason not listed above.
+     */
+    FAILURE
+}
diff --git a/image/google/hardware/image/EncodeParams.aidl b/image/google/hardware/image/EncodeParams.aidl
index 9ac1af0..a0c23cc 100644
--- a/image/google/hardware/image/EncodeParams.aidl
+++ b/image/google/hardware/image/EncodeParams.aidl
@@ -18,8 +18,6 @@
 package google.hardware.image;
 
 import google.hardware.image.Metadata;
-import google.hardware.image.MirrorDirection;
-import google.hardware.image.RotationDegree;
 
 /**
  * Parameters required to encode an image.
diff --git a/image/google/hardware/image/IComponent.aidl b/image/google/hardware/image/IComponent.aidl
index 08c768c..de3c8b0 100644
--- a/image/google/hardware/image/IComponent.aidl
+++ b/image/google/hardware/image/IComponent.aidl
@@ -36,6 +36,7 @@ interface IComponent {
      * @params src HardwareBuffer containing a YUV image. The format must be
      * one of the supported PixelFormats returned by queryComponentConstraints().
      * @return size of the encoded output bitstream.
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
     int encode(in HardwareBuffer src);
 
@@ -46,6 +47,7 @@ interface IComponent {
      *
      * @param src HardwareBuffer containing an encoded image bitstream. The
      * format must be BLOB.
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
     void decode(in HardwareBuffer src);
 
@@ -53,6 +55,7 @@ interface IComponent {
      * Queries for general information about the component.
      *
      * @return QueryResult object with all entries filled.
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
     QueryResult queryComponentConstraints();
 
@@ -63,6 +66,7 @@ interface IComponent {
      * @param meta List of Metadata objects representing JPEG APP segments. This
      * list can be empty if there is no metadata associated with the image to
      * be encoded.
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
     void setParams(in Params params);
 }
diff --git a/image/google/hardware/image/IComponentCallback.aidl b/image/google/hardware/image/IComponentCallback.aidl
index 3175dba..fc29298 100644
--- a/image/google/hardware/image/IComponentCallback.aidl
+++ b/image/google/hardware/image/IComponentCallback.aidl
@@ -34,8 +34,22 @@ interface IComponentCallback {
      * @param size The length of the linear buffer to be returned.
      * @param srcId The unique AHardwareBuffer ID for the source buffer associated
      * with this encoding operation.
-     * @return HardwareBuffer to be filled with encode output. The format of the
-     * buffer must be BLOB.
+     * @return HardwareBuffer To be filled with encode output. The client implementation
+     * of this function should call reset(...) on the HardwareBuffer to reset it
+     * with an AHardwareBuffer allocated by the client.
+     *
+     * When the AHardwareBuffer is created, ref count = 1. In reset(...), the returned
+     * HardwareBuffer takes ownership of a single ref count. So, before reset, the client
+     * should increment the AHardwareBuffer ref count to 2 (one for client, one for HAL).
+     *
+     * Parameter requirements for client-allocated AHardwareBuffer:
+     * width >= size
+     * height: 1
+     * layers: 1
+     * format: BLOB
+     * usage: usage returned by IComponent::queryComponentConstraints
+     *
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
     HardwareBuffer allocateLinearBuffer(in int size, in int srcId);
 
@@ -49,9 +63,22 @@ interface IComponentCallback {
      * be used for.
      * @param srcId The unique AHardwareBuffer ID for the source buffer associated
      * with this encoding operation.
-     * @return HardwareBuffer to be filled with decode output. The format of the
-     * buffer must be one of the supported colour formats from
-     * IComponent::queryComponentConstraints.
+     * @return HardwareBuffer To be filled with decode output. The client implementation
+     * of this function should call reset(...) on the HardwareBuffer to reset it
+     * with an AHardwareBuffer allocated by the client.
+     *
+     * When the AHardwareBuffer is created, ref count = 1. In reset(...), the returned
+     * HardwareBuffer takes ownership of a single ref count. So, before reset, the client
+     * should increment the AHardwareBuffer ref count to 2 (one for client, one for HAL).
+     *
+     * Parameter requirements for client-allocated AHardwareBuffer:
+     * width: width
+     * height: height
+     * layers: 1
+     * format: one of the formats returned by IComponent::queryComponentConstraints
+     * usage: usage returned by IComponent::queryComponentConstraints
+     *
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
     HardwareBuffer allocateGraphicBuffer(
             in int width, in int height, in PixelFormat colorFormat, in int srcId);
diff --git a/image/google/hardware/image/IComponentStore.aidl b/image/google/hardware/image/IComponentStore.aidl
index b24b071..5852904 100644
--- a/image/google/hardware/image/IComponentStore.aidl
+++ b/image/google/hardware/image/IComponentStore.aidl
@@ -38,7 +38,7 @@ interface IComponentStore {
      * client app. Used to tell the client the size of the output buffer
      * required for encode/decode.
      * @return The created component.
+     * @throws ServiceSpecificException with ComponentError as the code on failure.
      */
-    IComponent createComponent(
-            in String name, in ComponentType type, in IComponentCallback callback);
+    IComponent createComponent(in ComponentType type, in IComponentCallback callback);
 }
diff --git a/image/google/hardware/image/MirrorDirection.aidl b/image/google/hardware/image/MirrorDirection.aidl
deleted file mode 100644
index a43412c..0000000
--- a/image/google/hardware/image/MirrorDirection.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-/******************************************************************************
- *
- *  Copyright (C) 2024 Google LLC.
- *
- *  Licensed under the Apache License, Version 2.0 (the "License");
- *  you may not use this file except in compliance with the License.
- *  You may obtain a copy of the License at:
- *
- *  http://www.apache.org/licenses/LICENSE-2.0
- *
- *  Unless required by applicable law or agreed to in writing, software
- *  distributed under the License is distributed on an "AS IS" BASIS,
- *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- *  See the License for the specific language governing permissions and
- *  limitations under the License.
- *
- ******************************************************************************/
-package google.hardware.image;
-
-/**
- * Options for image mirroring during encoding.
- */
-@VintfStability @Backing(type="int") enum MirrorDirection { NONE, VER, HOR, HOR_VER }
diff --git a/image/google/hardware/image/RotationDegree.aidl b/image/google/hardware/image/RotationDegree.aidl
deleted file mode 100644
index d5ba122..0000000
--- a/image/google/hardware/image/RotationDegree.aidl
+++ /dev/null
@@ -1,23 +0,0 @@
-/******************************************************************************
- *
- *  Copyright (C) 2024 Google LLC.
- *
- *  Licensed under the Apache License, Version 2.0 (the "License");
- *  you may not use this file except in compliance with the License.
- *  You may obtain a copy of the License at:
- *
- *  http://www.apache.org/licenses/LICENSE-2.0
- *
- *  Unless required by applicable law or agreed to in writing, software
- *  distributed under the License is distributed on an "AS IS" BASIS,
- *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- *  See the License for the specific language governing permissions and
- *  limitations under the License.
- *
- ******************************************************************************/
-package google.hardware.image;
-
-/**
- * Options for image rotation during encoding.
- */
-@VintfStability @Backing(type="int") enum RotationDegree { R_NONE, R_90, R_180, R_270 }
```

