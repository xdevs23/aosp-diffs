```diff
diff --git a/Android.bp b/Android.bp
index 049eeb4..03a28bb 100644
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
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index c8dbf77..8aa2201 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,5 +1,6 @@
 [Builtin Hooks]
 clang_format = true
+bpfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
diff --git a/libhwc2.1/Android.bp b/libhwc2.1/Android.bp
new file mode 100644
index 0000000..9481876
--- /dev/null
+++ b/libhwc2.1/Android.bp
@@ -0,0 +1,107 @@
+// Copyright (C) 2022 The Android Open Source Project
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
+soong_namespace {
+    imports: [
+        "hardware/google/gchips",
+        "hardware/google/graphics/common",
+    ],
+}
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+filegroup {
+    name: "zuma_libhwc2_1_srcs",
+    srcs: [
+        "libmaindisplay/ExynosPrimaryDisplayModule.cpp",
+        "libresource/ExynosMPPModule.cpp",
+        "libresource/ExynosResourceManagerModule.cpp",
+        "libexternaldisplay/ExynosExternalDisplayModule.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+        "libcolormanager/DisplayColorModule.cpp",
+        "libdevice/ExynosDeviceModule.cpp",
+        "libdevice/HistogramController.cpp",
+    ],
+}
+
+cc_defaults {
+    name: "zuma_libhwc2_1_defaults",
+    srcs: [
+        ":zuma_libhwc2_1_srcs",
+        ":gs101_for_zuma_zumapro_libhwc2_1_srcs",
+        ":gs201_for_zuma_zumapro_libhwc2_1_srcs",
+    ],
+    cflags: [
+        "-DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"",
+    ],
+
+    header_libs: [
+        "gs201_graphics_histogram_header",
+    ],
+
+    include_dirs: [
+        "hardware/google/graphics/gs101/include/gs101",
+        "hardware/google/graphics/zuma/include",
+    ],
+
+}
+
+filegroup {
+    name: "zuma_for_zumapro_libhwc2_1_srcs",
+    srcs: [
+        "libresource/ExynosMPPModule.cpp",
+        "libresource/ExynosResourceManagerModule.cpp",
+        "libexternaldisplay/ExynosExternalDisplayModule.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+        "libcolormanager/DisplayColorModule.cpp",
+        "libdevice/ExynosDeviceModule.cpp",
+        "libdevice/HistogramController.cpp",
+    ],
+}
+
+cc_library_shared {
+    name: "libexynosdisplay",
+    srcs: [
+        ":zuma_libhwc2_1_srcs",
+        "//hardware/google/graphics/gs101/libhwc2.1:gs101_for_zuma_zumapro_libhwc2_1_srcs",
+        "//hardware/google/graphics/gs201/libhwc2.1:gs201_for_zuma_zumapro_libhwc2_1_srcs",
+    ],
+    cflags: [
+        "-DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"",
+    ],
+    header_libs: [
+        "//hardware/google/graphics/gs201:gs201_graphics_histogram_header",
+    ],
+    include_dirs: [
+        "hardware/google/graphics/gs101/include/gs101",
+        "hardware/google/graphics/zuma/include",
+    ] + [
+        // From original common which will use each soc's own folder.
+        "hardware/google/graphics/zuma/libhwc2.1",
+        "hardware/google/graphics/zuma/libhwc2.1/libmaindisplay",
+        "hardware/google/graphics/zuma/libhwc2.1/libexternaldisplay",
+        "hardware/google/graphics/zuma/libhwc2.1/libvirtualdisplay",
+        "hardware/google/graphics/zuma/libhwc2.1/libresource",
+        "hardware/google/graphics/zuma/libhwc2.1/libcolormanager",
+        "hardware/google/graphics/zuma/libhwc2.1/libdevice",
+        "hardware/google/graphics/zuma/libhwc2.1/libresource",
+        "hardware/google/graphics/zuma/libhwc2.1/libdisplayinterface",
+        "hardware/google/graphics/zuma",
+    ],
+    defaults: [
+        "libexynosdisplay_common_cc_default",
+    ],
+}
diff --git a/libhwc2.1/Android.mk b/libhwc2.1/Android.mk
deleted file mode 100644
index 083af9b..0000000
--- a/libhwc2.1/Android.mk
+++ /dev/null
@@ -1,40 +0,0 @@
-# Copyright (C) 2022 The Android Open Source Project
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
-	../../gs101/libhwc2.1/libdevice/ExynosDeviceModule.cpp \
-	../../gs101/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp \
-	../../gs101/libhwc2.1/libresource/ExynosMPPModule.cpp \
-	../../gs201/libhwc2.1/libresource/ExynosMPPModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libresource/ExynosMPPModule.cpp \
-	../../gs101/libhwc2.1/libresource/ExynosResourceManagerModule.cpp	\
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libresource/ExynosResourceManagerModule.cpp \
-	../../gs101/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp \
-	../../gs101/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplayModule.cpp \
-	../../gs101/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp \
-	../../gs201/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp \
-	../../zuma/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp \
-	../../gs101/libhwc2.1/libcolormanager/ColorManager.cpp \
-	../../zuma/libhwc2.1/libcolormanager/DisplayColorModule.cpp \
-	../../zuma/libhwc2.1/libdevice/ExynosDeviceModule.cpp \
-	../../zuma/libhwc2.1/libdevice/HistogramController.cpp
-
-LOCAL_CFLAGS += -DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"
-
-LOCAL_C_INCLUDES += \
-	$(TOP)/hardware/google/graphics/gs201/histogram \
-	$(TOP)/hardware/google/graphics/gs101/include/gs101 \
-	$(TOP)/hardware/google/graphics/zuma/include
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp
index a49dc3c..3049167 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp
@@ -257,7 +257,7 @@ void ExynosPrimaryDisplayModule::checkPreblendingRequirement() {
         if (!colorManager) return false;
         auto& dpp = colorManager->getDppForLayer(mppSrc);
         mppSrc->mNeedPreblending =
-                dpp.EotfLut().enable | dpp.Gm().enable | dpp.Dtm().enable | dpp.OetfLut().enable;
+                dpp.EotfLut().enable || dpp.Gm().enable || dpp.Dtm().enable || dpp.OetfLut().enable;
         if (hwcCheckDebugMessages(eDebugTDM)) {
             log.appendFormat(" i=%d,pb(%d-%d,%d,%d,%d)", idx, mppSrc->mNeedPreblending,
                              dpp.EotfLut().enable, dpp.Gm().enable, dpp.Dtm().enable,
```

