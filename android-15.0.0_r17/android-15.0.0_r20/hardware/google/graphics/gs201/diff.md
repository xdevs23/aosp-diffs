```diff
diff --git a/Android.bp b/Android.bp
index a874d56..36abc67 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,5 +1,22 @@
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
 soong_namespace {
-    imports: ["hardware/google/gchips", "hardware/google/graphics/common"]
+    imports: [
+        "hardware/google/gchips",
+        "hardware/google/graphics/common",
+    ],
 }
 
 package {
@@ -16,3 +33,9 @@ license {
     ],
     // large-scale-change unable to identify any license_text files
 }
+
+cc_library_headers {
+    name: "gs201_graphics_histogram_header",
+    export_include_dirs: ["histogram"],
+    vendor: true,
+}
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
new file mode 100644
index 0000000..321bab6
--- /dev/null
+++ b/PREUPLOAD.cfg
@@ -0,0 +1,2 @@
+[Builtin Hooks]
+bpfmt = true
diff --git a/libhwc2.1/Android.bp b/libhwc2.1/Android.bp
new file mode 100644
index 0000000..49b63bc
--- /dev/null
+++ b/libhwc2.1/Android.bp
@@ -0,0 +1,65 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+filegroup {
+    name: "gs201_libhwc2_1_srcs",
+    srcs: [
+        "libdevice/HistogramController.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+        "libresource/ExynosMPPModule.cpp",
+    ],
+}
+
+filegroup {
+    name: "gs201_for_zuma_zumapro_libhwc2_1_srcs",
+    srcs: [
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+        "libresource/ExynosMPPModule.cpp",
+    ],
+}
+
+cc_library_shared {
+    name: "libexynosdisplay",
+    srcs: [
+        "//hardware/google/graphics/gs101/libhwc2.1:gs101_for_gs201_libhwc2_1_srcs",
+        ":gs201_libhwc2_1_srcs",
+    ],
+    cflags: [
+        "-DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"",
+    ],
+    header_libs: [
+        "gs201_graphics_histogram_header",
+        "//hardware/google/graphics/gs101:gs101_graphics_header",
+    ],
+    include_dirs: [
+        // From original common which will use each soc's own folder.
+        "hardware/google/graphics/gs201/libhwc2.1",
+        "hardware/google/graphics/gs201/libhwc2.1/libmaindisplay",
+        "hardware/google/graphics/gs201/libhwc2.1/libexternaldisplay",
+        "hardware/google/graphics/gs201/libhwc2.1/libvirtualdisplay",
+        "hardware/google/graphics/gs201/libhwc2.1/libresource",
+        "hardware/google/graphics/gs201/libhwc2.1/libcolormanager",
+        "hardware/google/graphics/gs201/libhwc2.1/libdevice",
+        "hardware/google/graphics/gs201/libhwc2.1/libresource",
+        "hardware/google/graphics/gs201/libhwc2.1/libdisplayinterface",
+        "hardware/google/graphics/gs201",
+    ],
+    defaults: [
+        "libexynosdisplay_common_cc_default",
+    ],
+}
diff --git a/libhwc2.1/Android.mk b/libhwc2.1/Android.mk
deleted file mode 100644
index 1da94f7..0000000
--- a/libhwc2.1/Android.mk
+++ /dev/null
@@ -1,33 +0,0 @@
-# Copyright (C) 2021 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-LOCAL_SRC_FILES += \
-	../../gs101/libhwc2.1/libcolormanager/ColorManager.cpp \
-	../../gs101/libhwc2.1/libcolormanager/DisplayColorModule.cpp \
-	../../gs101/libhwc2.1/libdevice/ExynosDeviceModule.cpp \
-	../../gs201/libhwc2.1/libdevice/HistogramController.cpp \
-	../../gs101/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp \
-	../../gs101/libhwc2.1/libresource/ExynosMPPModule.cpp \
-	../../gs201/libhwc2.1/libresource/ExynosMPPModule.cpp \
-	../../gs101/libhwc2.1/libresource/ExynosResourceManagerModule.cpp	\
-	../../gs101/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp \
-	../../gs101/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplayModule.cpp \
-	../../gs101/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp \
-	../../gs201/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp
-
-LOCAL_CFLAGS += -DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"
-
-LOCAL_C_INCLUDES += \
-	$(TOP)/hardware/google/graphics/gs201/histogram \
-	$(TOP)/hardware/google/graphics/gs101/include
```

