```diff
diff --git a/Android.bp b/Android.bp
index 9d70070..6d50ec8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,8 +1,39 @@
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
-    // See: http://go/android-license-faq
-    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_applicable_licenses: ["hardware_google_graphics_gs101_license"],
+}
+
+// See: http://go/android-license-faq
+license {
+    name: "hardware_google_graphics_gs101_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+}
+
+cc_library_headers {
+    name: "gs101_graphics_header",
+    export_include_dirs: ["include"],
+    vendor: true,
 }
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
index 0000000..4e028e2
--- /dev/null
+++ b/libhwc2.1/Android.bp
@@ -0,0 +1,88 @@
+// Copyright (C) 2019 The Android Open Source Project
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
+    name: "gs101_libhwc2_1_srcs",
+    srcs: [
+        "libcolormanager/ColorManager.cpp",
+        "libcolormanager/DisplayColorModule.cpp",
+        "libdevice/ExynosDeviceModule.cpp",
+        "libdevice/HistogramController.cpp",
+        "libmaindisplay/ExynosPrimaryDisplayModule.cpp",
+        "libresource/ExynosMPPModule.cpp",
+        "libresource/ExynosResourceManagerModule.cpp",
+        "libexternaldisplay/ExynosExternalDisplayModule.cpp",
+        "libvirtualdisplay/ExynosVirtualDisplayModule.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+    ],
+}
+
+filegroup {
+    name: "gs101_for_gs201_libhwc2_1_srcs",
+    srcs: [
+        "libcolormanager/ColorManager.cpp",
+        "libcolormanager/DisplayColorModule.cpp",
+        "libdevice/ExynosDeviceModule.cpp",
+        "libmaindisplay/ExynosPrimaryDisplayModule.cpp",
+        "libresource/ExynosMPPModule.cpp",
+        "libresource/ExynosResourceManagerModule.cpp",
+        "libexternaldisplay/ExynosExternalDisplayModule.cpp",
+        "libvirtualdisplay/ExynosVirtualDisplayModule.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+    ],
+}
+
+filegroup {
+    name: "gs101_for_zuma_zumapro_libhwc2_1_srcs",
+    srcs: [
+        "libcolormanager/ColorManager.cpp",
+        "libdevice/ExynosDeviceModule.cpp",
+        "libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp",
+        "libexternaldisplay/ExynosExternalDisplayModule.cpp",
+        "libmaindisplay/ExynosPrimaryDisplayModule.cpp",
+        "libresource/ExynosMPPModule.cpp",
+        "libresource/ExynosResourceManagerModule.cpp",
+        "libvirtualdisplay/ExynosVirtualDisplayModule.cpp",
+    ],
+}
+
+cc_library_shared {
+    name: "libexynosdisplay",
+    srcs: [
+        ":gs101_libhwc2_1_srcs",
+    ],
+    cflags: [
+        "-DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"",
+    ],
+    include_dirs: ["hardware/google/graphics/gs101/include"] + [
+        // From original common which will use each soc's own folder.
+        "hardware/google/graphics/gs101/libhwc2.1",
+        "hardware/google/graphics/gs101/libhwc2.1/libmaindisplay",
+        "hardware/google/graphics/gs101/libhwc2.1/libexternaldisplay",
+        "hardware/google/graphics/gs101/libhwc2.1/libvirtualdisplay",
+        "hardware/google/graphics/gs101/libhwc2.1/libresource",
+        "hardware/google/graphics/gs101/libhwc2.1/libcolormanager",
+        "hardware/google/graphics/gs101/libhwc2.1/libdevice",
+        "hardware/google/graphics/gs101/libhwc2.1/libresource",
+        "hardware/google/graphics/gs101/libhwc2.1/libdisplayinterface",
+        "hardware/google/graphics/gs101",
+    ],
+    defaults: [
+        "libexynosdisplay_common_cc_default",
+    ],
+}
diff --git a/libhwc2.1/Android.mk b/libhwc2.1/Android.mk
deleted file mode 100644
index 6b6354b..0000000
--- a/libhwc2.1/Android.mk
+++ /dev/null
@@ -1,30 +0,0 @@
-# Copyright (C) 2019 The Android Open Source Project
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
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libcolormanager/DisplayColorModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libdevice/ExynosDeviceModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libdevice/HistogramController.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libresource/ExynosMPPModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libresource/ExynosResourceManagerModule.cpp	\
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libvirtualdisplay/ExynosVirtualDisplayModule.cpp \
-	../../$(TARGET_BOARD_PLATFORM)/libhwc2.1/libdisplayinterface/ExynosDisplayDrmInterfaceModule.cpp
-
-LOCAL_CFLAGS += -DDISPLAY_COLOR_LIB=\"libdisplaycolor.so\"
-
-LOCAL_C_INCLUDES += \
-	$(TOP)/hardware/google/graphics/gs101/include
diff --git a/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp b/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp
index 04420b9..2e153cf 100644
--- a/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp
+++ b/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.cpp
@@ -131,6 +131,17 @@ int ExynosExternalDisplayModule::deliverWinConfigData() {
     return ret;
 }
 
+int32_t ExynosExternalDisplayModule::setPowerMode(int32_t mode) {
+    int32_t ret;
+
+    ret = ExynosExternalDisplay::setPowerMode(mode);
+
+    if (ret == HWC2_ERROR_NONE && mode == HWC_POWER_MODE_NORMAL)
+        setForceColorUpdate(true);
+
+    return ret;
+}
+
 void ExynosExternalDisplayModule::invalidate() {
     ExynosExternalDisplay::invalidate();
 
diff --git a/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.h b/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.h
index 5475094..d8b8152 100644
--- a/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.h
+++ b/libhwc2.1/libexternaldisplay/ExynosExternalDisplayModule.h
@@ -47,11 +47,14 @@ public:
 
     bool mForceColorUpdate = false;
     bool isForceColorUpdate() const { return mForceColorUpdate; }
-    void setForceColorUpdate(bool force) { mForceColorUpdate = force; }
+    void setForceColorUpdate(bool force) override { mForceColorUpdate = force; }
     int deliverWinConfigData() override;
 
     void invalidate() override;
 
+protected:
+    virtual int32_t setPowerMode(int32_t mode) override;
+
 private:
     std::unique_ptr<ColorManager> mColorManager;
 
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.h b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.h
index 69585a4..19dce90 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.h
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.h
@@ -134,6 +134,8 @@ class ExynosPrimaryDisplayModule : public ExynosPrimaryDisplay {
         virtual void setLbeAmbientLight(int value);
         virtual LbeState getLbeState();
 
+        void setForceColorUpdate(bool force) override { mForceColorUpdate = force; }
+
         virtual PanelCalibrationStatus getPanelCalibrationStatus();
 
         bool hasDisplayColor() {
@@ -189,7 +191,6 @@ class ExynosPrimaryDisplayModule : public ExynosPrimaryDisplay {
         }
 
         bool isForceColorUpdate() const { return mForceColorUpdate; }
-        void setForceColorUpdate(bool force) { mForceColorUpdate = force; }
         bool isDisplaySwitched(int32_t mode, int32_t prevMode);
 
         std::map<std::string, atc_mode> mAtcModeSetting;
```

