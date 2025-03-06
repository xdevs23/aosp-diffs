```diff
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index bfaa0ad..0000000
--- a/Android.mk
+++ /dev/null
@@ -1,24 +0,0 @@
-#
-# Copyright (C) 2012 The Android Open Source Project
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
-ifeq (google,$(TARGET_SOC_NAME))
-
-common_hal_dirs := \
-	libexynosutils \
-	videoapi
-
-include $(call all-named-subdir-makefiles,$(common_hal_dirs))
-endif
diff --git a/gralloc4/src/core/format_info.cpp b/gralloc4/src/core/format_info.cpp
index b9ddbf2..46f23f3 100644
--- a/gralloc4/src/core/format_info.cpp
+++ b/gralloc4/src/core/format_info.cpp
@@ -134,7 +134,7 @@ const format_ip_support_t formats_ip_support[] = {
 	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_RGBX_8888,           .cpu_rd = F_LIN,  .cpu_wr = F_LIN,  .gpu_rd = F_LIN|F_AFBC, .gpu_wr = F_LIN|F_AFBC, .dpu_rd = F_LIN|F_AFBC, .dpu_wr = F_LIN,  .dpu_aeu_wr = F_NONE, .vpu_rd = F_NONE, .vpu_wr = F_NONE, .cam_wr = F_NONE,  },
 	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_RGBA_1010102,        .cpu_rd = F_LIN,  .cpu_wr = F_LIN,  .gpu_rd = F_LIN|F_AFBC, .gpu_wr = F_LIN|F_AFBC, .dpu_rd = F_LIN|F_AFBC, .dpu_wr = F_LIN,  .dpu_aeu_wr = F_AFBC, .vpu_rd = F_LIN,  .vpu_wr = F_NONE, .cam_wr = F_NONE,  },
 	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_RGBA_16161616,       .cpu_rd = F_LIN,  .cpu_wr = F_LIN,  .gpu_rd = F_LIN|F_AFBC, .gpu_wr = F_LIN|F_AFBC, .dpu_rd = F_NONE,       .dpu_wr = F_NONE, .dpu_aeu_wr = F_NONE, .vpu_rd = F_NONE, .vpu_wr = F_NONE, .cam_wr = F_NONE,  },
-	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_Y8,                  .cpu_rd = F_LIN,  .cpu_wr = F_LIN,  .gpu_rd = F_NONE,       .gpu_wr = F_NONE,       .dpu_rd = F_NONE,       .dpu_wr = F_NONE, .dpu_aeu_wr = F_NONE, .vpu_rd = F_NONE, .vpu_wr = F_NONE, .cam_wr = F_LIN,   },
+	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_Y8,                  .cpu_rd = F_LIN,  .cpu_wr = F_LIN,  .gpu_rd = F_LIN,        .gpu_wr = F_NONE,       .dpu_rd = F_NONE,       .dpu_wr = F_NONE, .dpu_aeu_wr = F_NONE, .vpu_rd = F_NONE, .vpu_wr = F_NONE, .cam_wr = F_LIN,   },
 	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_Y16,                 .cpu_rd = F_LIN,  .cpu_wr = F_LIN,  .gpu_rd = F_NONE,       .gpu_wr = F_NONE,       .dpu_rd = F_NONE,       .dpu_wr = F_NONE, .dpu_aeu_wr = F_NONE, .vpu_rd = F_NONE, .vpu_wr = F_NONE, .cam_wr = F_NONE,  },
 	/* 420 (8-bit) */
 	{ .id = MALI_GRALLOC_FORMAT_INTERNAL_YUV420_8BIT_I,       .cpu_rd = F_NONE, .cpu_wr = F_NONE, .gpu_rd = F_AFBC,       .gpu_wr = F_NONE,       .dpu_rd = F_AFBC,       .dpu_wr = F_NONE, .dpu_aeu_wr = F_AFBC, .vpu_rd = F_AFBC, .vpu_wr = F_AFBC, .cam_wr = F_NONE,  },
diff --git a/gralloc4/src/core/mali_gralloc_formats.cpp b/gralloc4/src/core/mali_gralloc_formats.cpp
index e36e27d..5b3bf08 100644
--- a/gralloc4/src/core/mali_gralloc_formats.cpp
+++ b/gralloc4/src/core/mali_gralloc_formats.cpp
@@ -1553,13 +1553,6 @@ uint64_t mali_gralloc_select_format(const uint64_t req_format,
 			MALI_GRALLOC_LOGV("Producer or consumer not identified.");
 		}
 
-		if ((usage & MALI_GRALLOC_USAGE_NO_AFBC) == MALI_GRALLOC_USAGE_NO_AFBC &&
-		    formats[req_fmt_idx].is_yuv)
-		{
-			MALI_GRALLOC_LOGE("ERROR: Invalid usage 'MALI_GRALLOC_USAGE_NO_AFBC' when allocating YUV formats");
-			goto out;
-		}
-
 		uint64_t producer_active_caps = producer_caps;
 		uint64_t consumer_active_caps = consumer_caps;
 
diff --git a/gralloc4/src/hidl_common/Mapper.h b/gralloc4/src/hidl_common/Mapper.h
index 7092678..9fc9040 100644
--- a/gralloc4/src/hidl_common/Mapper.h
+++ b/gralloc4/src/hidl_common/Mapper.h
@@ -29,7 +29,7 @@
 #include "mali_gralloc_error.h"
 
 #include <pixel-gralloc/metadata.h>
-#include <pixel-gralloc/utils.h>
+#include <pixel-gralloc/utils-internal.h>
 
 namespace arm
 {
diff --git a/gralloc4/src/hidl_common/MapperMetadata.cpp b/gralloc4/src/hidl_common/MapperMetadata.cpp
index 45395a2..24dbad9 100644
--- a/gralloc4/src/hidl_common/MapperMetadata.cpp
+++ b/gralloc4/src/hidl_common/MapperMetadata.cpp
@@ -29,7 +29,7 @@
 #include "mali_gralloc_formats.h"
 
 #include <pixel-gralloc/metadata.h>
-#include <pixel-gralloc/utils.h>
+#include <pixel-gralloc/utils-internal.h>
 
 #include <vector>
 
diff --git a/gralloc4/src/stable-c/GrallocMapper.cpp b/gralloc4/src/stable-c/GrallocMapper.cpp
index 2c4c52a..dcd45b3 100644
--- a/gralloc4/src/stable-c/GrallocMapper.cpp
+++ b/gralloc4/src/stable-c/GrallocMapper.cpp
@@ -20,7 +20,7 @@
 #include <cutils/native_handle.h>
 #include <pixel-gralloc/mapper.h>
 #include <pixel-gralloc/metadata.h>
-#include <pixel-gralloc/utils.h>
+#include <pixel-gralloc/utils-internal.h>
 
 #include "allocator/mali_gralloc_ion.h"
 #include "core/format_info.h"
diff --git a/libexynosutils/Android.bp b/libexynosutils/Android.bp
new file mode 100644
index 0000000..3ee02f6
--- /dev/null
+++ b/libexynosutils/Android.bp
@@ -0,0 +1,62 @@
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
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "hardware_google_gchips_libexynosutils_license",
+    ],
+}
+
+license {
+    name: "hardware_google_gchips_libexynosutils_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+    ],
+    license_text: [
+        "NOTICE",
+    ],
+}
+
+cc_library_shared {
+    name: "libexynosutils",
+    shared_libs: [
+        "liblog",
+        "libutils",
+        "libcutils",
+        "libhardware",
+    ],
+    proprietary: true,
+    cflags: [
+        "-DEXYNOS_PLATFORM_ON_ANDROID",
+        "-DUSES_GSCALER", // BOARD_USES_FIMC is never being set, ref hardware/google/gchips/BoardConfigCFlags.mk
+    ],
+    local_include_dirs: [
+        ".",
+    ],
+    include_dirs: [
+        "hardware/google/gchips/include",
+    ],
+    export_include_dirs: ["."],
+    srcs: [
+        "exynos_format_v4l2.c",
+        "ExynosMutex.cpp",
+        "Exynos_log.c",
+    ],
+    header_libs: [
+        "device_kernel_headers",
+        "libnativebase_headers",
+    ],
+}
diff --git a/libexynosutils/Android.mk b/libexynosutils/Android.mk
deleted file mode 100644
index 59f3970..0000000
--- a/libexynosutils/Android.mk
+++ /dev/null
@@ -1,42 +0,0 @@
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
-LOCAL_PATH:= $(call my-dir)
-include $(CLEAR_VARS)
-
-LOCAL_PRELINK_MODULE := false
-LOCAL_SHARED_LIBRARIES := liblog libutils libcutils libhardware
-LOCAL_PROPRIETARY_MODULE := true
-
-LOCAL_CFLAGS += -DEXYNOS_PLATFORM_ON_ANDROID
-
-LOCAL_C_INCLUDES := $(LOCAL_PATH)
-LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include
-LOCAL_C_INCLUDES += framework/base/include
-
-LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
-LOCAL_SRC_FILES := ExynosMutex.cpp \
-		   Exynos_log.c
-
-LOCAL_MODULE := libexynosutils
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-
-LOCAL_SRC_FILES += exynos_format_v4l2.c
-LOCAL_C_INCLUDES += \
-	$(LOCAL_PATH)/../include
-
-include $(TOP)/hardware/google/gchips/BoardConfigCFlags.mk
-include $(BUILD_SHARED_LIBRARY)
```

