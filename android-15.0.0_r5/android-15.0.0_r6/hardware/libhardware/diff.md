```diff
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index d7640084..00000000
--- a/Android.mk
+++ /dev/null
@@ -1,3 +0,0 @@
-# Copyright 2006 The Android Open Source Project
-
-include $(call all-named-subdir-makefiles,modules)
diff --git a/modules/Android.mk b/modules/Android.mk
deleted file mode 100644
index 9d934c5f..00000000
--- a/modules/Android.mk
+++ /dev/null
@@ -1,5 +0,0 @@
-hardware_modules := \
-    camera \
-    gralloc \
-    sensors
-include $(call all-named-subdir-makefiles,$(hardware_modules))
diff --git a/modules/camera/3_4/Android.bp b/modules/camera/3_4/Android.bp
new file mode 100644
index 00000000..3e3ba0a5
--- /dev/null
+++ b/modules/camera/3_4/Android.bp
@@ -0,0 +1,132 @@
+//
+// Copyright 2016 The Android Open Source Project
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_libhardware_license",
+    ],
+    default_team: "trendy_team_camera_framework",
+}
+
+v4l2_shared_libs = [
+    "libbase",
+    "libchrome",
+    "libcamera_client",
+    "libcamera_metadata",
+    "libcutils",
+    "libexif",
+    "libhardware",
+    "liblog",
+    "libsync",
+    "libutils",
+]
+
+v4l2_static_libs = [
+    "libyuv_static",
+    "libjpeg_static_ndk",
+]
+
+v4l2_cflags = [
+    "-fno-short-enums",
+    "-Wall",
+    "-Wextra",
+    "-Werror",
+    "-fvisibility=hidden",
+    "-DHAVE_JPEG",
+]
+
+v4l2_c_includes = [
+    "system/media/camera/include",
+]
+
+v4l2_src_files = [
+    "arc/cached_frame.cpp",
+    "arc/exif_utils.cpp",
+    "arc/frame_buffer.cpp",
+    "arc/image_processor.cpp",
+    "arc/jpeg_compressor.cpp",
+    "camera.cpp",
+    "capture_request.cpp",
+    "format_metadata_factory.cpp",
+    "metadata/boottime_state_delegate.cpp",
+    "metadata/enum_converter.cpp",
+    "metadata/metadata.cpp",
+    "metadata/metadata_reader.cpp",
+    "request_tracker.cpp",
+    "static_properties.cpp",
+    "stream_format.cpp",
+    "v4l2_camera.cpp",
+    "v4l2_camera_hal.cpp",
+    "v4l2_metadata_factory.cpp",
+    "v4l2_wrapper.cpp",
+]
+
+v4l2_test_files = [
+    "format_metadata_factory_test.cpp",
+    "metadata/control_test.cpp",
+    "metadata/default_option_delegate_test.cpp",
+    "metadata/enum_converter_test.cpp",
+    "metadata/ignored_control_delegate_test.cpp",
+    "metadata/map_converter_test.cpp",
+    "metadata/menu_control_options_test.cpp",
+    "metadata/metadata_reader_test.cpp",
+    "metadata/metadata_test.cpp",
+    "metadata/no_effect_control_delegate_test.cpp",
+    "metadata/partial_metadata_factory_test.cpp",
+    "metadata/property_test.cpp",
+    "metadata/ranged_converter_test.cpp",
+    "metadata/slider_control_options_test.cpp",
+    "metadata/state_test.cpp",
+    "metadata/tagged_control_delegate_test.cpp",
+    "metadata/tagged_control_options_test.cpp",
+    "metadata/v4l2_control_delegate_test.cpp",
+    "request_tracker_test.cpp",
+    "static_properties_test.cpp",
+]
+
+// V4L2 Camera HAL.
+// ==============================================================================
+cc_library_shared {
+    name: "camera.v4l2",
+    relative_install_path: "hw",
+    cflags: v4l2_cflags,
+    shared_libs: v4l2_shared_libs,
+    header_libs: ["libgtest_prod_headers"],
+    static_libs: v4l2_static_libs,
+
+    include_dirs: v4l2_c_includes,
+    srcs: v4l2_src_files,
+    enabled: select(soong_config_variable("camera", "use_camera_v4l2_hal"), {
+        true: true,
+        default: false,
+    }),
+}
+
+// Unit tests for V4L2 Camera HAL.
+// ==============================================================================
+cc_test {
+    name: "camera.v4l2_test",
+    cflags: v4l2_cflags,
+    shared_libs: v4l2_shared_libs,
+    static_libs: ["libgmock"] + v4l2_static_libs,
+
+    include_dirs: v4l2_c_includes,
+    srcs: v4l2_src_files + v4l2_test_files,
+    enabled: select(soong_config_variable("camera", "use_camera_v4l2_hal"), {
+        true: true,
+        default: false,
+    }),
+}
diff --git a/modules/camera/3_4/Android.mk b/modules/camera/3_4/Android.mk
deleted file mode 100644
index aa230977..00000000
--- a/modules/camera/3_4/Android.mk
+++ /dev/null
@@ -1,124 +0,0 @@
-#
-# Copyright 2016 The Android Open Source Project
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
-#
-
-LOCAL_PATH := $(call my-dir)
-
-# Prevent the HAL from building on devices not specifically
-# requesting to use it.
-ifeq ($(USE_CAMERA_V4L2_HAL), true)
-
-v4l2_shared_libs := \
-  libbase \
-  libchrome \
-  libcamera_client \
-  libcamera_metadata \
-  libcutils \
-  libexif \
-  libhardware \
-  liblog \
-  libsync \
-  libutils \
-
-v4l2_static_libs := \
-  libyuv_static \
-  libjpeg_static_ndk \
-
-v4l2_cflags := -fno-short-enums -Wall -Wextra -Werror -fvisibility=hidden -DHAVE_JPEG
-
-v4l2_c_includes := $(call include-path-for, camera) \
-  external/libyuv/files/include \
-
-v4l2_src_files := \
-  arc/cached_frame.cpp \
-  arc/exif_utils.cpp \
-  arc/frame_buffer.cpp \
-  arc/image_processor.cpp \
-  arc/jpeg_compressor.cpp \
-  camera.cpp \
-  capture_request.cpp \
-  format_metadata_factory.cpp \
-  metadata/boottime_state_delegate.cpp \
-  metadata/enum_converter.cpp \
-  metadata/metadata.cpp \
-  metadata/metadata_reader.cpp \
-  request_tracker.cpp \
-  static_properties.cpp \
-  stream_format.cpp \
-  v4l2_camera.cpp \
-  v4l2_camera_hal.cpp \
-  v4l2_metadata_factory.cpp \
-  v4l2_wrapper.cpp \
-
-v4l2_test_files := \
-  format_metadata_factory_test.cpp \
-  metadata/control_test.cpp \
-  metadata/default_option_delegate_test.cpp \
-  metadata/enum_converter_test.cpp \
-  metadata/ignored_control_delegate_test.cpp \
-  metadata/map_converter_test.cpp \
-  metadata/menu_control_options_test.cpp \
-  metadata/metadata_reader_test.cpp \
-  metadata/metadata_test.cpp \
-  metadata/no_effect_control_delegate_test.cpp \
-  metadata/partial_metadata_factory_test.cpp \
-  metadata/property_test.cpp \
-  metadata/ranged_converter_test.cpp \
-  metadata/slider_control_options_test.cpp \
-  metadata/state_test.cpp \
-  metadata/tagged_control_delegate_test.cpp \
-  metadata/tagged_control_options_test.cpp \
-  metadata/v4l2_control_delegate_test.cpp \
-  request_tracker_test.cpp \
-  static_properties_test.cpp \
-
-# V4L2 Camera HAL.
-# ==============================================================================
-include $(CLEAR_VARS)
-LOCAL_MODULE := camera.v4l2
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-BSD
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../../../NOTICE
-LOCAL_MODULE_RELATIVE_PATH := hw
-LOCAL_CFLAGS += $(v4l2_cflags)
-LOCAL_SHARED_LIBRARIES := $(v4l2_shared_libs)
-LOCAL_HEADER_LIBRARIES := libgtest_prod_headers
-LOCAL_STATIC_LIBRARIES := $(v4l2_static_libs)
-
-LOCAL_C_INCLUDES += $(v4l2_c_includes)
-LOCAL_SRC_FILES := $(v4l2_src_files)
-include $(BUILD_SHARED_LIBRARY)
-
-# Unit tests for V4L2 Camera HAL.
-# ==============================================================================
-include $(CLEAR_VARS)
-LOCAL_MODULE := camera.v4l2_test
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 SPDX-license-identifier-BSD
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../../../NOTICE
-LOCAL_CFLAGS += $(v4l2_cflags)
-LOCAL_SHARED_LIBRARIES := $(v4l2_shared_libs)
-LOCAL_STATIC_LIBRARIES := \
-  libgmock \
-  $(v4l2_static_libs) \
-
-LOCAL_C_INCLUDES += $(v4l2_c_includes)
-LOCAL_SRC_FILES := \
-  $(v4l2_src_files) \
-  $(v4l2_test_files) \
-
-include $(BUILD_NATIVE_TEST)
-
-endif # USE_CAMERA_V4L2_HAL
diff --git a/modules/camera/3_4/format_metadata_factory_test.cpp b/modules/camera/3_4/format_metadata_factory_test.cpp
index 65d44158..165743d0 100644
--- a/modules/camera/3_4/format_metadata_factory_test.cpp
+++ b/modules/camera/3_4/format_metadata_factory_test.cpp
@@ -24,6 +24,7 @@
 #include "v4l2_wrapper_mock.h"
 
 using testing::AtLeast;
+using testing::DoAll;
 using testing::Expectation;
 using testing::Return;
 using testing::SetArgPointee;
diff --git a/modules/camera/3_4/metadata/control_test.cpp b/modules/camera/3_4/metadata/control_test.cpp
index 6284330e..c68958f4 100644
--- a/modules/camera/3_4/metadata/control_test.cpp
+++ b/modules/camera/3_4/metadata/control_test.cpp
@@ -26,6 +26,7 @@
 #include "test_common.h"
 
 using testing::AtMost;
+using testing::DoAll;
 using testing::Expectation;
 using testing::Return;
 using testing::SetArgPointee;
diff --git a/modules/camera/3_4/metadata/map_converter_test.cpp b/modules/camera/3_4/metadata/map_converter_test.cpp
index 03618107..87fbe202 100644
--- a/modules/camera/3_4/metadata/map_converter_test.cpp
+++ b/modules/camera/3_4/metadata/map_converter_test.cpp
@@ -21,6 +21,7 @@
 
 #include "converter_interface_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/metadata/menu_control_options_test.cpp b/modules/camera/3_4/metadata/menu_control_options_test.cpp
index b8eea74a..560d55f2 100644
--- a/modules/camera/3_4/metadata/menu_control_options_test.cpp
+++ b/modules/camera/3_4/metadata/menu_control_options_test.cpp
@@ -23,6 +23,7 @@
 #include <hardware/camera3.h>
 #include "default_option_delegate_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/metadata/partial_metadata_factory_test.cpp b/modules/camera/3_4/metadata/partial_metadata_factory_test.cpp
index f039b54d..433f539e 100644
--- a/modules/camera/3_4/metadata/partial_metadata_factory_test.cpp
+++ b/modules/camera/3_4/metadata/partial_metadata_factory_test.cpp
@@ -26,6 +26,7 @@
 #include "v4l2_wrapper_mock.h"
 
 using testing::AtMost;
+using testing::DoAll;
 using testing::Expectation;
 using testing::Return;
 using testing::SetArgPointee;
diff --git a/modules/camera/3_4/metadata/ranged_converter_test.cpp b/modules/camera/3_4/metadata/ranged_converter_test.cpp
index 2b5ccc63..f4048fec 100644
--- a/modules/camera/3_4/metadata/ranged_converter_test.cpp
+++ b/modules/camera/3_4/metadata/ranged_converter_test.cpp
@@ -21,6 +21,7 @@
 
 #include "converter_interface_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/metadata/slider_control_options_test.cpp b/modules/camera/3_4/metadata/slider_control_options_test.cpp
index 7f3a6436..5c5aec8b 100644
--- a/modules/camera/3_4/metadata/slider_control_options_test.cpp
+++ b/modules/camera/3_4/metadata/slider_control_options_test.cpp
@@ -23,6 +23,7 @@
 #include <hardware/camera3.h>
 #include "default_option_delegate_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/metadata/state_test.cpp b/modules/camera/3_4/metadata/state_test.cpp
index ecc1d154..61333ac0 100644
--- a/modules/camera/3_4/metadata/state_test.cpp
+++ b/modules/camera/3_4/metadata/state_test.cpp
@@ -25,6 +25,7 @@
 #include "test_common.h"
 
 using testing::AtMost;
+using testing::DoAll;
 using testing::Expectation;
 using testing::Return;
 using testing::SetArgPointee;
diff --git a/modules/camera/3_4/metadata/tagged_control_delegate_test.cpp b/modules/camera/3_4/metadata/tagged_control_delegate_test.cpp
index ba29ab7b..73118e24 100644
--- a/modules/camera/3_4/metadata/tagged_control_delegate_test.cpp
+++ b/modules/camera/3_4/metadata/tagged_control_delegate_test.cpp
@@ -21,6 +21,7 @@
 
 #include "control_delegate_interface_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/metadata/tagged_control_options_test.cpp b/modules/camera/3_4/metadata/tagged_control_options_test.cpp
index 845426a9..6ae72a1d 100644
--- a/modules/camera/3_4/metadata/tagged_control_options_test.cpp
+++ b/modules/camera/3_4/metadata/tagged_control_options_test.cpp
@@ -21,6 +21,7 @@
 
 #include "control_options_interface_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/metadata/v4l2_control_delegate_test.cpp b/modules/camera/3_4/metadata/v4l2_control_delegate_test.cpp
index 63ad0f60..6c8bef0c 100644
--- a/modules/camera/3_4/metadata/v4l2_control_delegate_test.cpp
+++ b/modules/camera/3_4/metadata/v4l2_control_delegate_test.cpp
@@ -21,6 +21,7 @@
 #include "converter_interface_mock.h"
 #include "v4l2_wrapper_mock.h"
 
+using testing::DoAll;
 using testing::Return;
 using testing::SetArgPointee;
 using testing::Test;
diff --git a/modules/camera/3_4/static_properties_test.cpp b/modules/camera/3_4/static_properties_test.cpp
index 13b9e964..abbff87b 100644
--- a/modules/camera/3_4/static_properties_test.cpp
+++ b/modules/camera/3_4/static_properties_test.cpp
@@ -24,6 +24,7 @@
 #include "metadata/metadata_reader_mock.h"
 
 using testing::AtMost;
+using testing::DoAll;
 using testing::Expectation;
 using testing::Return;
 using testing::SetArgPointee;
diff --git a/modules/camera/Android.mk b/modules/camera/Android.mk
deleted file mode 100644
index 71388aac..00000000
--- a/modules/camera/Android.mk
+++ /dev/null
@@ -1,15 +0,0 @@
-# Copyright (C) 2016 The Android Open Source Project
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
-include $(call all-subdir-makefiles)
diff --git a/modules/gralloc/Android.bp b/modules/gralloc/Android.bp
new file mode 100644
index 00000000..e352c800
--- /dev/null
+++ b/modules/gralloc/Android.bp
@@ -0,0 +1,45 @@
+// Copyright (C) 2008 The Android Open Source Project
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
+// HAL module implementation stored in
+// hw/<OVERLAY_HARDWARE_MODULE_ID>.<ro.product.board>.so
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_libhardware_license",
+    ],
+}
+
+cc_library_shared {
+    name: "gralloc.default",
+    relative_install_path: "hw",
+    proprietary: true,
+    shared_libs: [
+        "liblog",
+        "libcutils",
+    ],
+    srcs: [
+        "gralloc.cpp",
+        "framebuffer.cpp",
+        "mapper.cpp",
+    ],
+    header_libs: ["libhardware_headers"],
+    cflags: [
+        "-DLOG_TAG=\"gralloc\"",
+        "-Wno-missing-field-initializers",
+    ] + select(soong_config_variable("gralloc", "target_use_pan_display"), {
+        true: ["-DUSE_PAN_DISPLAY=1"],
+        default: [],
+    }),
+}
diff --git a/modules/gralloc/Android.mk b/modules/gralloc/Android.mk
deleted file mode 100644
index 4c4899ea..00000000
--- a/modules/gralloc/Android.mk
+++ /dev/null
@@ -1,45 +0,0 @@
-# Copyright (C) 2008 The Android Open Source Project
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
-
-LOCAL_PATH := $(call my-dir)
-
-# HAL module implemenation stored in
-# hw/<OVERLAY_HARDWARE_MODULE_ID>.<ro.product.board>.so
-include $(CLEAR_VARS)
-
-LOCAL_MODULE_RELATIVE_PATH := hw
-LOCAL_PROPRIETARY_MODULE := true
-LOCAL_SHARED_LIBRARIES := liblog libcutils
-
-LOCAL_SRC_FILES := 	\
-	gralloc.cpp 	\
-	framebuffer.cpp \
-	mapper.cpp
-
-LOCAL_HEADER_LIBRARIES := libhardware_headers
-
-LOCAL_MODULE := gralloc.default
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../../NOTICE
-LOCAL_CFLAGS:= -DLOG_TAG=\"gralloc\" -Wno-missing-field-initializers
-ifeq ($(TARGET_USE_PAN_DISPLAY),true)
-LOCAL_CFLAGS += -DUSE_PAN_DISPLAY=1
-endif
-ifneq ($(GRALLOC_FRAMEBUFFER_NUM),)
-LOCAL_CFLAGS += -DNUM_BUFFERS=$(GRALLOC_FRAMEBUFFER_NUM)
-endif
-
-include $(BUILD_SHARED_LIBRARY)
diff --git a/modules/sensors/Android.mk b/modules/sensors/Android.mk
deleted file mode 100644
index 69889def..00000000
--- a/modules/sensors/Android.mk
+++ /dev/null
@@ -1,48 +0,0 @@
-#
-# Copyright (C) 2013 The Android Open-Source Project
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
-#
-
-LOCAL_PATH := $(call my-dir)
-
-ifeq ($(USE_SENSOR_MULTI_HAL),true)
-
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := sensors.$(TARGET_DEVICE)
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../../NOTICE
-
-LOCAL_MODULE_RELATIVE_PATH := hw
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_CFLAGS := -Wall -Werror -DLOG_TAG=\"MultiHal\"
-
-LOCAL_SRC_FILES := \
-    multihal.cpp \
-    SensorEventQueue.cpp \
-
-LOCAL_HEADER_LIBRARIES := \
-    libhardware_headers \
-
-LOCAL_SHARED_LIBRARIES := \
-    libcutils \
-    libdl \
-    liblog \
-    libutils \
-
-include $(BUILD_SHARED_LIBRARY)
-
-endif # USE_SENSOR_MULTI_HAL
diff --git a/modules/sensors/OWNERS b/modules/sensors/OWNERS
index 90c23303..7347ac74 100644
--- a/modules/sensors/OWNERS
+++ b/modules/sensors/OWNERS
@@ -1,3 +1 @@
-arthuri@google.com
 bduddie@google.com
-stange@google.com
diff --git a/modules/sensors/dynamic_sensor/Android.bp b/modules/sensors/dynamic_sensor/Android.bp
index 8bf28852..dbb3d932 100644
--- a/modules/sensors/dynamic_sensor/Android.bp
+++ b/modules/sensors/dynamic_sensor/Android.bp
@@ -36,6 +36,7 @@ cc_defaults {
 
     shared_libs: [
         "libbase",
+        "liblog",
         "libhidparser",
         "server_configurable_flags",
         "libaconfig_storage_read_api_cc",
```

