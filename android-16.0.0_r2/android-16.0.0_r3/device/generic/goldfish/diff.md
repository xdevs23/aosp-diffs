```diff
diff --git a/Android.bp b/Android.bp
index d7173257..5fff2636 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,11 +14,7 @@
  * limitations under the License.
  */
 
-soong_namespace {
-    imports: [
-        "device/generic/goldfish-opengl",
-    ],
-}
+soong_namespace {}
 
 package {
     default_applicable_licenses: ["device_generic_goldfish_license"],
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index e29be79b..b08139b3 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -11,5 +11,4 @@ PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/64bitonly/product/sdk_phone64_arm64_riscv64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_slim_x86_64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_slim_arm64.mk \
-    $(LOCAL_DIR)/fvpbase/fvp.mk \
-    $(LOCAL_DIR)/fvpbase/fvp_mini.mk
+
diff --git a/board/BoardConfigCommon.mk b/board/BoardConfigCommon.mk
index 4851307e..dcaf11b4 100644
--- a/board/BoardConfigCommon.mk
+++ b/board/BoardConfigCommon.mk
@@ -35,7 +35,7 @@ USE_OPENGL_RENDERER := true
 TARGET_USERIMAGES_SPARSE_EXT_DISABLED := true
 
 # emulator is Non-A/B device
-AB_OTA_UPDATER := false
+AB_OTA_UPDATER := none
 AB_OTA_PARTITIONS :=
 
 BOARD_USES_SYSTEM_OTHER_ODEX :=
diff --git a/board/emu64x/kernel_fstab_32.mk b/board/emu64x/kernel_fstab_32.mk
deleted file mode 100644
index 556f9aaf..00000000
--- a/board/emu64x/kernel_fstab_32.mk
+++ /dev/null
@@ -1,24 +0,0 @@
-# Copyright (C) 2023 The Android Open Source Project
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
-# This file adds the x86_64 kernel and fstab only, it is used on 32bit userspace
-# devices (which is currently ATV only).
-
-include device/generic/goldfish/board/kernel/x86_64.mk
-
-PRODUCT_COPY_FILES += \
-    $(EMULATOR_KERNEL_FILE):kernel-ranchu-64 \
-    device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
-    device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu
diff --git a/board/kernel/arm64.mk b/board/kernel/arm64.mk
index 2ff17bf9..b689fa99 100644
--- a/board/kernel/arm64.mk
+++ b/board/kernel/arm64.mk
@@ -44,8 +44,17 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
     $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
+ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
+EMULATOR_EXCLUDE_KERNEL_MODULES := \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_address_space.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_pipe.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_sync.ko
+else
+EMULATOR_EXCLUDE_KERNEL_MODULES :=
+endif
+
 BOARD_VENDOR_KERNEL_MODULES := \
-    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
+    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES) $(EMULATOR_EXCLUDE_KERNEL_MODULES),\
                  $(wildcard $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/*.ko))
 
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
diff --git a/board/kernel/arm64_16k.mk b/board/kernel/arm64_16k.mk
index 9e91b892..831dfbcc 100644
--- a/board/kernel/arm64_16k.mk
+++ b/board/kernel/arm64_16k.mk
@@ -45,8 +45,17 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
     $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
+ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
+EMULATOR_EXCLUDE_KERNEL_MODULES := \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_address_space.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_pipe.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_sync.ko
+else
+EMULATOR_EXCLUDE_KERNEL_MODULES :=
+endif
+
 BOARD_VENDOR_KERNEL_MODULES := \
-    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
+    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES) $(EMULATOR_EXCLUDE_KERNEL_MODULES),\
                  $(wildcard $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/*.ko))
 
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
diff --git a/board/kernel/x86_64.mk b/board/kernel/x86_64.mk
index 30ee4a54..c5fc1e8f 100644
--- a/board/kernel/x86_64.mk
+++ b/board/kernel/x86_64.mk
@@ -42,8 +42,17 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
     $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
+ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
+EMULATOR_EXCLUDE_KERNEL_MODULES := \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_address_space.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_pipe.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_sync.ko
+else
+EMULATOR_EXCLUDE_KERNEL_MODULES :=
+endif
+
 BOARD_VENDOR_KERNEL_MODULES := \
-    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
+    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES) $(EMULATOR_EXCLUDE_KERNEL_MODULES),\
                  $(wildcard $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/*.ko))
 
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
diff --git a/board/kernel/x86_64_16k.mk b/board/kernel/x86_64_16k.mk
index 2a67e938..ffd2341a 100644
--- a/board/kernel/x86_64_16k.mk
+++ b/board/kernel/x86_64_16k.mk
@@ -44,8 +44,17 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
     $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
+ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
+EMULATOR_EXCLUDE_KERNEL_MODULES := \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_address_space.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_pipe.ko \
+    $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/goldfish_sync.ko
+else
+EMULATOR_EXCLUDE_KERNEL_MODULES :=
+endif
+
 BOARD_VENDOR_KERNEL_MODULES := \
-    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
+    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES) $(EMULATOR_EXCLUDE_KERNEL_MODULES),\
                  $(wildcard $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/*.ko))
 
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
diff --git a/tasks/emu_img_zip.mk b/build/tasks.workaround/emu_img_zip.mk
similarity index 100%
rename from tasks/emu_img_zip.mk
rename to build/tasks.workaround/emu_img_zip.mk
diff --git a/tools/Android.bp b/build/tools/Android.bp
similarity index 100%
rename from tools/Android.bp
rename to build/tools/Android.bp
diff --git a/tools/README.md b/build/tools/README.md
similarity index 100%
rename from tools/README.md
rename to build/tools/README.md
diff --git a/tools/emulator_boot_test.sh b/build/tools/emulator_boot_test.sh
similarity index 100%
rename from tools/emulator_boot_test.sh
rename to build/tools/emulator_boot_test.sh
diff --git a/tools/extract_ext4_image.sh b/build/tools/extract_ext4_image.sh
similarity index 100%
rename from tools/extract_ext4_image.sh
rename to build/tools/extract_ext4_image.sh
diff --git a/tools/extract_head_tail.sh b/build/tools/extract_head_tail.sh
similarity index 100%
rename from tools/extract_head_tail.sh
rename to build/tools/extract_head_tail.sh
diff --git a/tools/mk_combined_img.py b/build/tools/mk_combined_img.py
similarity index 100%
rename from tools/mk_combined_img.py
rename to build/tools/mk_combined_img.py
diff --git a/tools/mk_qemu_image.sh b/build/tools/mk_qemu_image.sh
similarity index 100%
rename from tools/mk_qemu_image.sh
rename to build/tools/mk_qemu_image.sh
diff --git a/tools/mk_qemu_ramdisk.py b/build/tools/mk_qemu_ramdisk.py
similarity index 100%
rename from tools/mk_qemu_ramdisk.py
rename to build/tools/mk_qemu_ramdisk.py
diff --git a/tools/mk_vbmeta_boot_params.sh b/build/tools/mk_vbmeta_boot_params.sh
similarity index 100%
rename from tools/mk_vbmeta_boot_params.sh
rename to build/tools/mk_vbmeta_boot_params.sh
diff --git a/tools/mk_verified_boot_params.sh b/build/tools/mk_verified_boot_params.sh
similarity index 100%
rename from tools/mk_verified_boot_params.sh
rename to build/tools/mk_verified_boot_params.sh
diff --git a/tools/prebuilt/gpt/1_3080/head.img b/build/tools/prebuilt/gpt/1_3080/head.img
similarity index 100%
rename from tools/prebuilt/gpt/1_3080/head.img
rename to build/tools/prebuilt/gpt/1_3080/head.img
diff --git a/tools/prebuilt/gpt/1_3080/tail.img b/build/tools/prebuilt/gpt/1_3080/tail.img
similarity index 100%
rename from tools/prebuilt/gpt/1_3080/tail.img
rename to build/tools/prebuilt/gpt/1_3080/tail.img
diff --git a/codecs/c2/decoders/avcdec/Android.bp b/codecs/c2/decoders/avcdec/Android.bp
new file mode 100644
index 00000000..67ee94bf
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/Android.bp
@@ -0,0 +1,34 @@
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_library_shared {
+    name: "libcodec2_goldfish_avcdec",
+    vendor: true,
+    defaults: [
+        "libcodec2_goldfish-defaults",
+    ],
+
+    srcs: ["C2GoldfishAvcDec.cpp",
+        "GoldfishH264Helper.cpp",
+        "MediaH264Decoder.cpp",
+    ],
+
+    shared_libs: [
+	    "android.hardware.graphics.allocator@3.0",
+		"android.hardware.graphics.mapper@3.0",
+        "libgoldfish_codec2_store",
+    ],
+
+   header_libs: [
+    "libgralloc_cb.ranchu",
+    ],
+
+   static_libs: ["libavcdec",
+   ],
+}
diff --git a/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp b/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
new file mode 100644
index 00000000..6b97caff
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.cpp
@@ -0,0 +1,1178 @@
+/*
+ * Copyright 2017 The Android Open Source Project
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
+//#define LOG_NDEBUG 0
+#define LOG_TAG "C2GoldfishAvcDec"
+#include <inttypes.h>
+#include <log/log.h>
+#include <media/stagefright/foundation/AUtils.h>
+#include <media/stagefright/foundation/MediaDefs.h>
+
+#include <C2AllocatorGralloc.h>
+#include <C2PlatformSupport.h>
+//#include <android/hardware/graphics/common/1.0/types.h>
+
+#include <android/hardware/graphics/allocator/3.0/IAllocator.h>
+#include <android/hardware/graphics/mapper/3.0/IMapper.h>
+#include <hidl/LegacySupport.h>
+
+#include <media/stagefright/foundation/MediaDefs.h>
+
+#include <C2Debug.h>
+#include <C2PlatformSupport.h>
+#include <Codec2Mapper.h>
+#include <SimpleC2Interface.h>
+#include <goldfish_codec2/store/GoldfishComponentStore.h>
+#include <gralloc_cb_bp.h>
+
+#include <color_buffer_utils.h>
+
+#include "C2GoldfishAvcDec.h"
+
+#include <mutex>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+using ::android::hardware::graphics::common::V1_0::BufferUsage;
+using ::android::hardware::graphics::common::V1_2::PixelFormat;
+
+namespace android {
+
+namespace {
+constexpr size_t kMinInputBufferSize = 6 * 1024 * 1024;
+constexpr char COMPONENT_NAME[] = "c2.goldfish.h264.decoder";
+constexpr uint32_t kDefaultOutputDelay = 8;
+/* avc specification allows for a maximum delay of 16 frames.
+   As soft avc decoder supports interlaced, this delay would be 32 fields.
+   And avc decoder implementation has an additional delay of 2 decode calls.
+   So total maximum output delay is 34 */
+constexpr uint32_t kMaxOutputDelay = 34;
+constexpr uint32_t kMinInputBytes = 4;
+
+static std::mutex s_decoder_count_mutex;
+static int s_decoder_count = 0;
+
+int allocateDecoderId() {
+  DDD("calling %s", __func__);
+  std::lock_guard<std::mutex> lock(s_decoder_count_mutex);
+  if (s_decoder_count >= 32 || s_decoder_count < 0) {
+    ALOGE("calling %s failed", __func__);
+    return -1;
+  }
+  ++ s_decoder_count;
+  DDD("calling %s success total decoder %d", __func__, s_decoder_count);
+  return s_decoder_count;;
+}
+
+bool deAllocateDecoderId() {
+  DDD("calling %s", __func__);
+  std::lock_guard<std::mutex> lock(s_decoder_count_mutex);
+  if (s_decoder_count < 1) {
+    ALOGE("calling %s failed ", __func__);
+    return false;
+  }
+  -- s_decoder_count;
+  DDD("calling %s success total decoder %d", __func__, s_decoder_count);
+  return true;
+}
+
+
+} // namespace
+
+class C2GoldfishAvcDec::IntfImpl : public SimpleInterface<void>::BaseParams {
+  public:
+    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
+        : SimpleInterface<void>::BaseParams(
+              helper, COMPONENT_NAME, C2Component::KIND_DECODER,
+              C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_AVC) {
+        noPrivateBuffers(); // TODO: account for our buffers here
+        noInputReferences();
+        noOutputReferences();
+        noInputLatency();
+        noTimeStretch();
+
+        // TODO: Proper support for reorder depth.
+        addParameter(
+            DefineParam(mActualOutputDelay, C2_PARAMKEY_OUTPUT_DELAY)
+                .withDefault(
+                    new C2PortActualDelayTuning::output(kDefaultOutputDelay))
+                .withFields({C2F(mActualOutputDelay, value)
+                                 .inRange(0, kMaxOutputDelay)})
+                .withSetter(
+                    Setter<
+                        decltype(*mActualOutputDelay)>::StrictValueWithNoDeps)
+                .build());
+
+        // TODO: output latency and reordering
+
+        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
+                         .withConstValue(new C2ComponentAttributesSetting(
+                             C2Component::ATTRIB_IS_TEMPORAL))
+                         .build());
+
+        // coded and output picture size is the same for this codec
+        addParameter(
+            DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
+                .withDefault(new C2StreamPictureSizeInfo::output(0u, 320, 240))
+                .withFields({
+                    C2F(mSize, width).inRange(2, 4096, 2),
+                    C2F(mSize, height).inRange(2, 4096, 2),
+                })
+                .withSetter(SizeSetter)
+                .build());
+
+        addParameter(DefineParam(mMaxSize, C2_PARAMKEY_MAX_PICTURE_SIZE)
+                         .withDefault(new C2StreamMaxPictureSizeTuning::output(
+                             0u, 320, 240))
+                         .withFields({
+                             C2F(mSize, width).inRange(2, 4096, 2),
+                             C2F(mSize, height).inRange(2, 4096, 2),
+                         })
+                         .withSetter(MaxPictureSizeSetter, mSize)
+                         .build());
+
+        addParameter(
+            DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
+                .withDefault(new C2StreamProfileLevelInfo::input(
+                    0u, C2Config::PROFILE_AVC_CONSTRAINED_BASELINE,
+                    C2Config::LEVEL_AVC_5_2))
+                .withFields(
+                    {C2F(mProfileLevel, profile)
+                         .oneOf({C2Config::PROFILE_AVC_CONSTRAINED_BASELINE,
+                                 C2Config::PROFILE_AVC_BASELINE,
+                                 C2Config::PROFILE_AVC_MAIN,
+                                 C2Config::PROFILE_AVC_CONSTRAINED_HIGH,
+                                 C2Config::PROFILE_AVC_PROGRESSIVE_HIGH,
+                                 C2Config::PROFILE_AVC_HIGH}),
+                     C2F(mProfileLevel, level)
+                         .oneOf(
+                             {C2Config::LEVEL_AVC_1, C2Config::LEVEL_AVC_1B,
+                              C2Config::LEVEL_AVC_1_1, C2Config::LEVEL_AVC_1_2,
+                              C2Config::LEVEL_AVC_1_3, C2Config::LEVEL_AVC_2,
+                              C2Config::LEVEL_AVC_2_1, C2Config::LEVEL_AVC_2_2,
+                              C2Config::LEVEL_AVC_3, C2Config::LEVEL_AVC_3_1,
+                              C2Config::LEVEL_AVC_3_2, C2Config::LEVEL_AVC_4,
+                              C2Config::LEVEL_AVC_4_1, C2Config::LEVEL_AVC_4_2,
+                              C2Config::LEVEL_AVC_5, C2Config::LEVEL_AVC_5_1,
+                              C2Config::LEVEL_AVC_5_2})})
+                .withSetter(ProfileLevelSetter, mSize)
+                .build());
+
+        addParameter(
+            DefineParam(mMaxInputSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
+                .withDefault(new C2StreamMaxBufferSizeInfo::input(
+                    0u, kMinInputBufferSize))
+                .withFields({
+                    C2F(mMaxInputSize, value).any(),
+                })
+                .calculatedAs(MaxInputSizeSetter, mMaxSize)
+                .build());
+
+        C2ChromaOffsetStruct locations[1] = {
+            C2ChromaOffsetStruct::ITU_YUV_420_0()};
+        std::shared_ptr<C2StreamColorInfo::output> defaultColorInfo =
+            C2StreamColorInfo::output::AllocShared(1u, 0u, 8u /* bitDepth */,
+                                                   C2Color::YUV_420);
+        memcpy(defaultColorInfo->m.locations, locations, sizeof(locations));
+
+        defaultColorInfo = C2StreamColorInfo::output::AllocShared(
+            {C2ChromaOffsetStruct::ITU_YUV_420_0()}, 0u, 8u /* bitDepth */,
+            C2Color::YUV_420);
+        helper->addStructDescriptors<C2ChromaOffsetStruct>();
+
+        addParameter(DefineParam(mColorInfo, C2_PARAMKEY_CODED_COLOR_INFO)
+                         .withConstValue(defaultColorInfo)
+                         .build());
+
+        addParameter(
+            DefineParam(mDefaultColorAspects, C2_PARAMKEY_DEFAULT_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsTuning::output(
+                    0u, C2Color::RANGE_UNSPECIFIED,
+                    C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mDefaultColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mDefaultColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mDefaultColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mDefaultColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(DefaultColorAspectsSetter)
+                .build());
+
+        addParameter(
+            DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsInfo::input(
+                    0u, C2Color::RANGE_LIMITED, C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mCodedColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mCodedColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mCodedColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mCodedColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(CodedColorAspectsSetter)
+                .build());
+
+        addParameter(
+            DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsInfo::output(
+                    0u, C2Color::RANGE_UNSPECIFIED,
+                    C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(ColorAspectsSetter, mDefaultColorAspects,
+                            mCodedColorAspects)
+                .build());
+
+        // TODO: support more formats?
+        addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
+                         .withConstValue(new C2StreamPixelFormatInfo::output(
+                             0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
+                         .build());
+    }
+    static C2R SizeSetter(bool mayBlock,
+                          const C2P<C2StreamPictureSizeInfo::output> &oldMe,
+                          C2P<C2StreamPictureSizeInfo::output> &me) {
+        (void)mayBlock;
+        DDD("calling sizesetter now %d", oldMe.v.height);
+        DDD("new calling sizesetter now %d", me.v.height);
+
+        C2R res = C2R::Ok();
+        if (!me.F(me.v.width).supportsAtAll(me.v.width)) {
+            ALOGW("w %d is not supported, using old one %d", me.v.width, oldMe.v.width);
+            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.width)));
+            me.set().width = oldMe.v.width;
+        }
+        if (!me.F(me.v.height).supportsAtAll(me.v.height)) {
+            ALOGW("h %d is not supported, using old one %d", me.v.height, oldMe.v.height);
+            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.height)));
+            me.set().height = oldMe.v.height;
+        }
+        return res;
+    }
+
+    static C2R
+    MaxPictureSizeSetter(bool mayBlock,
+                         C2P<C2StreamMaxPictureSizeTuning::output> &me,
+                         const C2P<C2StreamPictureSizeInfo::output> &size) {
+        (void)mayBlock;
+        // TODO: get max width/height from the size's field helpers vs.
+        // hardcoding
+        me.set().width = c2_min(c2_max(me.v.width, size.v.width), 4096u);
+        me.set().height = c2_min(c2_max(me.v.height, size.v.height), 4096u);
+        return C2R::Ok();
+    }
+
+    static C2R MaxInputSizeSetter(
+        bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input> &me,
+        const C2P<C2StreamMaxPictureSizeTuning::output> &maxSize) {
+        (void)mayBlock;
+        // assume compression ratio of 2
+        me.set().value = c2_max((((maxSize.v.width + 15) / 16) *
+                                 ((maxSize.v.height + 15) / 16) * 192),
+                                kMinInputBufferSize);
+        return C2R::Ok();
+    }
+
+    static C2R
+    ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input> &me,
+                       const C2P<C2StreamPictureSizeInfo::output> &size) {
+        (void)mayBlock;
+        (void)size;
+        (void)me; // TODO: validate
+        return C2R::Ok();
+    }
+
+    static C2R
+    DefaultColorAspectsSetter(bool mayBlock,
+                              C2P<C2StreamColorAspectsTuning::output> &me) {
+        (void)mayBlock;
+        if (me.v.range > C2Color::RANGE_OTHER) {
+            me.set().range = C2Color::RANGE_OTHER;
+        }
+        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
+            me.set().primaries = C2Color::PRIMARIES_OTHER;
+        }
+        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
+            me.set().transfer = C2Color::TRANSFER_OTHER;
+        }
+        if (me.v.matrix > C2Color::MATRIX_OTHER) {
+            me.set().matrix = C2Color::MATRIX_OTHER;
+        }
+        DDD("default primaries %d default range %d", me.set().primaries,
+            me.set().range);
+        return C2R::Ok();
+    }
+
+    static C2R
+    CodedColorAspectsSetter(bool mayBlock,
+                            C2P<C2StreamColorAspectsInfo::input> &me) {
+        (void)mayBlock;
+        if (me.v.range > C2Color::RANGE_OTHER) {
+            me.set().range = C2Color::RANGE_OTHER;
+        }
+        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
+            me.set().primaries = C2Color::PRIMARIES_OTHER;
+        }
+        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
+            me.set().transfer = C2Color::TRANSFER_OTHER;
+        }
+        if (me.v.matrix > C2Color::MATRIX_OTHER) {
+            me.set().matrix = C2Color::MATRIX_OTHER;
+        }
+        DDD("coded primaries %d coded range %d", me.set().primaries,
+            me.set().range);
+        return C2R::Ok();
+    }
+
+    static C2R
+    ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output> &me,
+                       const C2P<C2StreamColorAspectsTuning::output> &def,
+                       const C2P<C2StreamColorAspectsInfo::input> &coded) {
+        (void)mayBlock;
+        // take default values for all unspecified fields, and coded values for
+        // specified ones
+        DDD("before change primaries %d range %d", me.v.primaries, me.v.range);
+        me.set().range =
+            coded.v.range == RANGE_UNSPECIFIED ? def.v.range : coded.v.range;
+        me.set().primaries = coded.v.primaries == PRIMARIES_UNSPECIFIED
+                                 ? def.v.primaries
+                                 : coded.v.primaries;
+        me.set().transfer = coded.v.transfer == TRANSFER_UNSPECIFIED
+                                ? def.v.transfer
+                                : coded.v.transfer;
+        me.set().matrix = coded.v.matrix == MATRIX_UNSPECIFIED ? def.v.matrix
+                                                               : coded.v.matrix;
+
+        DDD("after change primaries %d range %d", me.v.primaries, me.v.range);
+        return C2R::Ok();
+    }
+
+    std::shared_ptr<C2StreamColorAspectsInfo::output> getColorAspects_l() {
+        return mColorAspects;
+    }
+
+    int width() const { return mSize->width; }
+
+    int height() const { return mSize->height; }
+
+    int primaries() const { return mColorAspects->primaries; }
+
+    int range() const { return mColorAspects->range; }
+
+    int transfer() const { return mColorAspects->transfer; }
+
+   private:
+    std::shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
+    std::shared_ptr<C2StreamPictureSizeInfo::output> mSize;
+    std::shared_ptr<C2StreamMaxPictureSizeTuning::output> mMaxSize;
+    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mMaxInputSize;
+    std::shared_ptr<C2StreamColorInfo::output> mColorInfo;
+    std::shared_ptr<C2StreamColorAspectsInfo::input> mCodedColorAspects;
+    std::shared_ptr<C2StreamColorAspectsTuning::output> mDefaultColorAspects;
+    std::shared_ptr<C2StreamColorAspectsInfo::output> mColorAspects;
+    std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormat;
+};
+
+static void *ivd_aligned_malloc(void *ctxt, uint32_t alignment, uint32_t size) {
+    (void)ctxt;
+    return memalign(alignment, size);
+}
+
+static void ivd_aligned_free(void *ctxt, void *mem) {
+    (void)ctxt;
+    free(mem);
+}
+
+C2GoldfishAvcDec::C2GoldfishAvcDec(const char *name, c2_node_id_t id,
+                                   const std::shared_ptr<IntfImpl> &intfImpl)
+    : SimpleC2Component(
+          std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
+      mIntf(intfImpl), mOutBufferFlush(nullptr), mOutIndex(0u),
+      mWidth(1920), mHeight(1080), mHeaderDecoded(false) {
+    mWidth = mIntf->width();
+    mHeight = mIntf->height();
+    DDD("creating avc decoder now w %d h %d", mWidth, mHeight);
+}
+
+C2GoldfishAvcDec::~C2GoldfishAvcDec() { onRelease(); }
+
+c2_status_t C2GoldfishAvcDec::onInit() {
+    ALOGD("calling onInit");
+    mId = allocateDecoderId();
+    if (mId <= 0) return C2_NO_MEMORY;
+    status_t err = initDecoder();
+    return err == OK ? C2_OK : C2_CORRUPTED;
+}
+
+c2_status_t C2GoldfishAvcDec::onStop() {
+    if (OK != resetDecoder())
+        return C2_CORRUPTED;
+    resetPlugin();
+    return C2_OK;
+}
+
+void C2GoldfishAvcDec::onReset() { (void)onStop(); }
+
+void C2GoldfishAvcDec::onRelease() {
+    DDD("calling onRelease");
+    if (mId > 0) {
+      deAllocateDecoderId();
+      mId = -1;
+    }
+    deleteContext();
+    if (mOutBlock) {
+        mOutBlock.reset();
+    }
+}
+
+void C2GoldfishAvcDec::decodeHeaderAfterFlush() {
+    if (mContext && !mCsd0.empty() && !mCsd1.empty()) {
+        mContext->decodeFrame(&(mCsd0[0]), mCsd0.size(), 0);
+        mContext->decodeFrame(&(mCsd1[0]), mCsd1.size(), 0);
+        DDD("resending csd0 and csd1");
+    }
+}
+
+c2_status_t C2GoldfishAvcDec::onFlush_sm() {
+    if (OK != setFlushMode())
+        return C2_CORRUPTED;
+
+    if (!mContext) {
+        // just ignore if context is not even created
+        return C2_OK;
+    }
+
+    uint32_t bufferSize = mStride * mHeight * 3 / 2;
+    mOutBufferFlush = (uint8_t *)ivd_aligned_malloc(nullptr, 128, bufferSize);
+    if (!mOutBufferFlush) {
+        ALOGE("could not allocate tmp output buffer (for flush) of size %u ",
+              bufferSize);
+        return C2_NO_MEMORY;
+    }
+
+    while (true) {
+        mPts = 0;
+        constexpr bool hasPicture = false;
+        setDecodeArgs(nullptr, nullptr, 0, 0, 0, hasPicture);
+        mImg = mContext->getImage();
+        if (mImg.data == nullptr) {
+            resetPlugin();
+            break;
+        }
+    }
+
+    if (mOutBufferFlush) {
+        ivd_aligned_free(nullptr, mOutBufferFlush);
+        mOutBufferFlush = nullptr;
+    }
+
+    deleteContext();
+    return C2_OK;
+}
+
+void C2GoldfishAvcDec::sendMetadata() {
+    // compare and send if changed
+    MetaDataColorAspects currentMetaData = {1, 0, 0, 0};
+    currentMetaData.primaries = mIntf->primaries();
+    currentMetaData.range = mIntf->range();
+    currentMetaData.transfer = mIntf->transfer();
+
+    DDD("metadata primaries %d range %d transfer %d",
+            (int)(currentMetaData.primaries),
+            (int)(currentMetaData.range),
+            (int)(currentMetaData.transfer)
+       );
+
+    if (mSentMetadata.primaries == currentMetaData.primaries &&
+        mSentMetadata.range == currentMetaData.range &&
+        mSentMetadata.transfer == currentMetaData.transfer) {
+        DDD("metadata is the same, no need to update");
+        return;
+    }
+    std::swap(mSentMetadata, currentMetaData);
+
+    mContext->sendMetadata(&(mSentMetadata));
+}
+
+status_t C2GoldfishAvcDec::createDecoder() {
+
+    DDD("creating avc context now w %d h %d", mWidth, mHeight);
+    if (mEnableAndroidNativeBuffers) {
+        mContext.reset(new MediaH264Decoder(RenderMode::RENDER_BY_HOST_GPU));
+    } else {
+        mContext.reset(new MediaH264Decoder(RenderMode::RENDER_BY_GUEST_CPU));
+    }
+    mContext->initH264Context(mWidth, mHeight, mWidth, mHeight,
+                              MediaH264Decoder::PixelFormat::YUV420P);
+    return OK;
+}
+
+status_t C2GoldfishAvcDec::setParams(size_t stride) {
+    (void)stride;
+    return OK;
+}
+
+status_t C2GoldfishAvcDec::initDecoder() {
+    mStride = ALIGN2(mWidth);
+    mSignalledError = false;
+    resetPlugin();
+
+    return OK;
+}
+
+bool C2GoldfishAvcDec::setDecodeArgs(C2ReadView *inBuffer,
+                                     C2GraphicView *outBuffer, size_t inOffset,
+                                     size_t inSize, uint32_t tsMarker, bool hasPicture) {
+    uint32_t displayStride = mStride;
+    (void)inBuffer;
+    (void)inOffset;
+    (void)inSize;
+    (void)tsMarker;
+    if (outBuffer) {
+        C2PlanarLayout layout;
+        layout = outBuffer->layout();
+        displayStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
+    }
+
+    if (inBuffer) {
+        //= tsMarker;
+        mInPBuffer = const_cast<uint8_t *>(inBuffer->data() + inOffset);
+        mInPBufferSize = inSize;
+        mInTsMarker = tsMarker;
+        if (hasPicture) {
+            insertPts(tsMarker, mPts);
+        }
+    }
+
+    // uint32_t displayHeight = mHeight;
+    // size_t lumaSize = displayStride * displayHeight;
+    // size_t chromaSize = lumaSize >> 2;
+
+    if (mStride != displayStride) {
+        mStride = displayStride;
+        if (OK != setParams(mStride))
+            return false;
+    }
+
+    return true;
+}
+
+status_t C2GoldfishAvcDec::setFlushMode() {
+    if (mContext) {
+        mContext->flush();
+    }
+    mHeaderDecoded = false;
+    return OK;
+}
+
+status_t C2GoldfishAvcDec::resetDecoder() {
+    mStride = 0;
+    mSignalledError = false;
+    mHeaderDecoded = false;
+    deleteContext();
+
+    return OK;
+}
+
+void C2GoldfishAvcDec::resetPlugin() {
+    mSignalledOutputEos = false;
+    gettimeofday(&mTimeStart, nullptr);
+    gettimeofday(&mTimeEnd, nullptr);
+    if (mOutBlock) {
+        mOutBlock.reset();
+    }
+}
+
+void C2GoldfishAvcDec::deleteContext() {
+    if (mContext) {
+        mContext->destroyH264Context();
+        mContext.reset(nullptr);
+        mPts2Index.clear();
+        mOldPts2Index.clear();
+        mIndex2Pts.clear();
+    }
+}
+
+static void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
+    uint32_t flags = 0;
+    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
+        flags |= C2FrameData::FLAG_END_OF_STREAM;
+        DDD("signalling eos");
+    }
+    DDD("fill empty work");
+    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
+    work->worklets.front()->output.buffers.clear();
+    work->worklets.front()->output.ordinal = work->input.ordinal;
+    work->workletsProcessed = 1u;
+}
+
+void C2GoldfishAvcDec::finishWork(uint64_t index,
+                                  const std::unique_ptr<C2Work> &work) {
+    std::shared_ptr<C2Buffer> buffer =
+        createGraphicBuffer(std::move(mOutBlock), C2Rect(mWidth, mHeight));
+    mOutBlock = nullptr;
+    {
+        IntfImpl::Lock lock = mIntf->lock();
+        buffer->setInfo(mIntf->getColorAspects_l());
+    }
+
+    class FillWork {
+      public:
+        FillWork(uint32_t flags, C2WorkOrdinalStruct ordinal,
+                 const std::shared_ptr<C2Buffer> &buffer)
+            : mFlags(flags), mOrdinal(ordinal), mBuffer(buffer) {}
+        ~FillWork() = default;
+
+        void operator()(const std::unique_ptr<C2Work> &work) {
+            work->worklets.front()->output.flags = (C2FrameData::flags_t)mFlags;
+            work->worklets.front()->output.buffers.clear();
+            work->worklets.front()->output.ordinal = mOrdinal;
+            work->workletsProcessed = 1u;
+            work->result = C2_OK;
+            if (mBuffer) {
+                work->worklets.front()->output.buffers.push_back(mBuffer);
+            }
+            DDD("timestamp = %lld, index = %lld, w/%s buffer",
+                mOrdinal.timestamp.peekll(), mOrdinal.frameIndex.peekll(),
+                mBuffer ? "" : "o");
+        }
+
+      private:
+        const uint32_t mFlags;
+        const C2WorkOrdinalStruct mOrdinal;
+        const std::shared_ptr<C2Buffer> mBuffer;
+    };
+
+    auto fillWork = [buffer](const std::unique_ptr<C2Work> &work) {
+        work->worklets.front()->output.flags = (C2FrameData::flags_t)0;
+        work->worklets.front()->output.buffers.clear();
+        work->worklets.front()->output.buffers.push_back(buffer);
+        work->worklets.front()->output.ordinal = work->input.ordinal;
+        work->workletsProcessed = 1u;
+    };
+    if (work && c2_cntr64_t(index) == work->input.ordinal.frameIndex) {
+        bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
+        // TODO: Check if cloneAndSend can be avoided by tracking number of
+        // frames remaining
+        if (eos) {
+            if (buffer) {
+                mOutIndex = index;
+                C2WorkOrdinalStruct outOrdinal = work->input.ordinal;
+                DDD("%s %d: cloneAndSend ", __func__, __LINE__);
+                cloneAndSend(
+                    mOutIndex, work,
+                    FillWork(C2FrameData::FLAG_INCOMPLETE, outOrdinal, buffer));
+                buffer.reset();
+            }
+        } else {
+            DDD("%s %d: fill", __func__, __LINE__);
+            fillWork(work);
+        }
+    } else {
+        DDD("%s %d: finish", __func__, __LINE__);
+        finish(index, fillWork);
+    }
+}
+
+c2_status_t
+C2GoldfishAvcDec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
+    if (mOutBlock && (mOutBlock->width() != ALIGN2(mWidth) ||
+                      mOutBlock->height() != mHeight)) {
+        mOutBlock.reset();
+    }
+    if (!mOutBlock) {
+        const uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
+        const C2MemoryUsage usage = {(uint64_t)(BufferUsage::VIDEO_DECODER),
+                                     C2MemoryUsage::CPU_WRITE | C2MemoryUsage::CPU_READ};
+        c2_status_t err = pool->fetchGraphicBlock(ALIGN2(mWidth), mHeight,
+                                                  format, usage, &mOutBlock);
+        if (err != C2_OK) {
+            ALOGE("fetchGraphicBlock for Output failed with status %d", err);
+            return err;
+        }
+        if (mEnableAndroidNativeBuffers) {
+            auto c2Handle = mOutBlock->handle();
+            native_handle_t *grallocHandle =
+                UnwrapNativeCodec2GrallocHandle(c2Handle);
+            mHostColorBufferId = getColorBufferHandle(grallocHandle);
+            DDD("found handle %d", mHostColorBufferId);
+        }
+        DDD("provided (%dx%d) required (%dx%d)", mOutBlock->width(),
+            mOutBlock->height(), ALIGN2(mWidth), mHeight);
+    }
+
+    return C2_OK;
+}
+
+void C2GoldfishAvcDec::checkMode(const std::shared_ptr<C2BlockPool> &pool) {
+    mWidth = mIntf->width();
+    mHeight = mIntf->height();
+    //const bool isGraphic = (pool->getLocalId() == C2PlatformAllocatorStore::GRALLOC);
+    const bool isGraphic = (pool->getAllocatorId() & C2Allocator::GRAPHIC);
+    DDD("buffer pool allocator id %x",  (int)(pool->getAllocatorId()));
+    if (isGraphic) {
+        uint64_t client_usage = getClientUsage(pool);
+        DDD("client has usage as 0x%llx", client_usage);
+        if (client_usage & BufferUsage::CPU_READ_MASK) {
+            DDD("decoding to guest byte buffer as client has read usage");
+            mEnableAndroidNativeBuffers = false;
+        } else {
+            DDD("decoding to host color buffer");
+            mEnableAndroidNativeBuffers = true;
+        }
+    } else {
+        DDD("decoding to guest byte buffer");
+        mEnableAndroidNativeBuffers = false;
+    }
+}
+
+void C2GoldfishAvcDec::getVuiParams(h264_image_t &img) {
+    VuiColorAspects vuiColorAspects;
+    vuiColorAspects.primaries = img.color_primaries;
+    vuiColorAspects.transfer = img.color_trc;
+    vuiColorAspects.coeffs = img.colorspace;
+    vuiColorAspects.fullRange = img.color_range == 2 ? true : false;
+
+    // convert vui aspects to C2 values if changed
+    if (!(vuiColorAspects == mBitstreamColorAspects)) {
+        mBitstreamColorAspects = vuiColorAspects;
+        ColorAspects sfAspects;
+        C2StreamColorAspectsInfo::input codedAspects = {0u};
+        ColorUtils::convertIsoColorAspectsToCodecAspects(
+            vuiColorAspects.primaries, vuiColorAspects.transfer,
+            vuiColorAspects.coeffs, vuiColorAspects.fullRange, sfAspects);
+        if (!C2Mapper::map(sfAspects.mPrimaries, &codedAspects.primaries)) {
+            codedAspects.primaries = C2Color::PRIMARIES_UNSPECIFIED;
+        }
+        if (!C2Mapper::map(sfAspects.mRange, &codedAspects.range)) {
+            codedAspects.range = C2Color::RANGE_UNSPECIFIED;
+        }
+        if (!C2Mapper::map(sfAspects.mMatrixCoeffs, &codedAspects.matrix)) {
+            codedAspects.matrix = C2Color::MATRIX_UNSPECIFIED;
+        }
+        if (!C2Mapper::map(sfAspects.mTransfer, &codedAspects.transfer)) {
+            codedAspects.transfer = C2Color::TRANSFER_UNSPECIFIED;
+        }
+        std::vector<std::unique_ptr<C2SettingResult>> failures;
+        (void)mIntf->config({&codedAspects}, C2_MAY_BLOCK, &failures);
+    }
+}
+
+void C2GoldfishAvcDec::copyImageData(h264_image_t &img) {
+    getVuiParams(img);
+    if (mEnableAndroidNativeBuffers)
+        return;
+
+    auto writeView = mOutBlock->map().get();
+    if (writeView.error()) {
+        ALOGE("graphic view map failed %d", writeView.error());
+        return;
+    }
+    size_t dstYStride = writeView.layout().planes[C2PlanarLayout::PLANE_Y].rowInc;
+    size_t dstUVStride = writeView.layout().planes[C2PlanarLayout::PLANE_U].rowInc;
+
+    uint8_t *pYBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_Y]);
+    uint8_t *pUBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_U]);
+    uint8_t *pVBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_V]);
+
+    for (int i = 0; i < mHeight; ++i) {
+        memcpy(pYBuffer + i * dstYStride, img.data + i * mWidth, mWidth);
+    }
+    for (int i = 0; i < mHeight / 2; ++i) {
+        memcpy(pUBuffer + i * dstUVStride,
+               img.data + mWidth * mHeight + i * mWidth / 2, mWidth / 2);
+    }
+    for (int i = 0; i < mHeight / 2; ++i) {
+        memcpy(pVBuffer + i * dstUVStride,
+               img.data + mWidth * mHeight * 5 / 4 + i * mWidth / 2,
+               mWidth / 2);
+    }
+}
+
+uint64_t C2GoldfishAvcDec::getWorkIndex(uint64_t pts) {
+    if (!mOldPts2Index.empty()) {
+        auto iter = mOldPts2Index.find(pts);
+        if (iter != mOldPts2Index.end()) {
+            auto index = iter->second;
+            DDD("found index %d for pts %" PRIu64, (int)index, pts);
+            return index;
+        }
+    }
+    auto iter = mPts2Index.find(pts);
+    if (iter != mPts2Index.end()) {
+        auto index = iter->second;
+        DDD("found index %d for pts %" PRIu64, (int)index, pts);
+        return index;
+    }
+    DDD("not found index for pts %" PRIu64, pts);
+    return 0;
+}
+
+void C2GoldfishAvcDec::insertPts(uint32_t work_index, uint64_t pts) {
+    auto iter = mPts2Index.find(pts);
+    if (iter != mPts2Index.end()) {
+        // we have a collision here:
+        // apparently, older session is not done yet,
+        // lets save them
+        DDD("inserted to old pts %" PRIu64 " with index %d", pts, (int)iter->second);
+        mOldPts2Index[iter->first] = iter->second;
+    }
+    DDD("inserted pts %" PRIu64 " with index %d", pts, (int)work_index);
+    mIndex2Pts[work_index] = pts;
+    mPts2Index[pts] = work_index;
+}
+
+void C2GoldfishAvcDec::removePts(uint64_t pts) {
+    bool found = false;
+    uint64_t index = 0;
+    // note: check old pts first to see
+    // if we have some left over, check them
+    if (!mOldPts2Index.empty()) {
+        auto iter = mOldPts2Index.find(pts);
+        if (iter != mOldPts2Index.end()) {
+            index = iter->second;
+            mOldPts2Index.erase(iter);
+            found = true;
+        }
+    } else {
+        auto iter = mPts2Index.find(pts);
+        if (iter != mPts2Index.end()) {
+            index = iter->second;
+            mPts2Index.erase(iter);
+            found = true;
+        }
+    }
+
+    if (!found) return;
+
+    auto iter2 = mIndex2Pts.find(index);
+    if (iter2 == mIndex2Pts.end()) return;
+    mIndex2Pts.erase(iter2);
+}
+
+// TODO: can overall error checking be improved?
+// TODO: allow configuration of color format and usage for graphic buffers
+// instead
+//       of hard coding them to HAL_PIXEL_FORMAT_YV12
+// TODO: pass coloraspects information to surface
+// TODO: test support for dynamic change in resolution
+// TODO: verify if the decoder sent back all frames
+void C2GoldfishAvcDec::process(const std::unique_ptr<C2Work> &work,
+                               const std::shared_ptr<C2BlockPool> &pool) {
+    // Initialize output work
+    work->result = C2_OK;
+    work->workletsProcessed = 0u;
+    work->worklets.front()->output.flags = work->input.flags;
+    if (mSignalledError || mSignalledOutputEos) {
+        work->result = C2_BAD_VALUE;
+        return;
+    }
+
+    DDD("process work");
+    if (!mContext) {
+        DDD("creating decoder context to host in process work");
+        checkMode(pool);
+        createDecoder();
+        decodeHeaderAfterFlush();
+    }
+
+    size_t inOffset = 0u;
+    size_t inSize = 0u;
+    uint32_t workIndex = work->input.ordinal.frameIndex.peeku() & 0xFFFFFFFF;
+    mPts = work->input.ordinal.timestamp.peeku();
+    C2ReadView rView = mDummyReadView;
+    if (!work->input.buffers.empty()) {
+        rView =
+            work->input.buffers[0]->data().linearBlocks().front().map().get();
+        inSize = rView.capacity();
+        if (inSize && rView.error()) {
+            ALOGE("read view map failed %d", rView.error());
+            work->result = rView.error();
+            return;
+        }
+    }
+    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
+    bool hasPicture = (inSize > 0);
+
+    DDD("in buffer attr. size %zu timestamp %d frameindex %d, flags %x", inSize,
+        (int)work->input.ordinal.timestamp.peeku(),
+        (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);
+    size_t inPos = 0;
+    while (inPos < inSize && inSize - inPos >= kMinInputBytes) {
+        if (C2_OK != ensureDecoderState(pool)) {
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            work->result = C2_CORRUPTED;
+            return;
+        }
+
+        {
+            // C2GraphicView wView;// = mOutBlock->map().get();
+            // if (wView.error()) {
+            //    ALOGE("graphic view map failed %d", wView.error());
+            //    work->result = wView.error();
+            //    return;
+            //}
+            if (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) {
+                hasPicture = false;
+            }
+            if (!setDecodeArgs(&rView, nullptr, inOffset + inPos,
+                               inSize - inPos, workIndex, hasPicture)) {
+                mSignalledError = true;
+                work->workletsProcessed = 1u;
+                work->result = C2_CORRUPTED;
+                return;
+            }
+
+            DDD("flag is %x", work->input.flags);
+            if (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) {
+                if (mCsd0.empty()) {
+                    mCsd0.assign(mInPBuffer, mInPBuffer + mInPBufferSize);
+                    DDD("assign to csd0 with %d bytpes", mInPBufferSize);
+                } else if (mCsd1.empty()) {
+                    mCsd1.assign(mInPBuffer, mInPBuffer + mInPBufferSize);
+                    DDD("assign to csd1 with %d bytpes", mInPBufferSize);
+                }
+            }
+
+            bool whChanged = false;
+            if (GoldfishH264Helper::isSpsFrame(mInPBuffer, mInPBufferSize)) {
+                mH264Helper.reset(new GoldfishH264Helper(mWidth, mHeight));
+                whChanged = mH264Helper->decodeHeader(mInPBuffer, mInPBufferSize);
+                if (whChanged) {
+                        DDD("w changed from old %d to new %d\n", mWidth, mH264Helper->getWidth());
+                        DDD("h changed from old %d to new %d\n", mHeight, mH264Helper->getHeight());
+                        if (1) {
+                            drainInternal(DRAIN_COMPONENT_NO_EOS, pool, work);
+                            resetDecoder();
+                            resetPlugin();
+                            work->workletsProcessed = 0u;
+                        }
+                        {
+                            mWidth = mH264Helper->getWidth();
+                            mHeight = mH264Helper->getHeight();
+                            C2StreamPictureSizeInfo::output size(0u, mWidth, mHeight);
+                            std::vector<std::unique_ptr<C2SettingResult>> failures;
+                            c2_status_t err = mIntf->config({&size}, C2_MAY_BLOCK, &failures);
+                            if (err == OK) {
+                                work->worklets.front()->output.configUpdate.push_back(
+                                        C2Param::Copy(size));
+                                ensureDecoderState(pool);
+                            } else {
+                                ALOGE("Cannot set width and height");
+                                mSignalledError = true;
+                                work->workletsProcessed = 1u;
+                                work->result = C2_CORRUPTED;
+                                return;
+                            }
+                        }
+                        if (!mContext) {
+                            DDD("creating decoder context to host in process work");
+                            checkMode(pool);
+                            createDecoder();
+                        }
+                        continue;
+                } // end of whChanged
+            } // end of isSpsFrame
+
+            sendMetadata();
+
+            uint32_t delay;
+            GETTIME(&mTimeStart, nullptr);
+            TIME_DIFF(mTimeEnd, mTimeStart, delay);
+            (void)delay;
+            //(void) ivdec_api_function(mDecHandle, &s_decode_ip, &s_decode_op);
+            DDD("decoding");
+            h264_result_t h264Res =
+                mContext->decodeFrame(mInPBuffer, mInPBufferSize, mPts);
+            mConsumedBytes = h264Res.bytesProcessed;
+            DDD("decoding consumed %d", (int)mConsumedBytes);
+
+            if (mHostColorBufferId > 0) {
+                mImg = mContext->renderOnHostAndReturnImageMetadata(
+                    mHostColorBufferId);
+            } else {
+                mImg = mContext->getImage();
+            }
+            uint32_t decodeTime;
+            GETTIME(&mTimeEnd, nullptr);
+            TIME_DIFF(mTimeStart, mTimeEnd, decodeTime);
+            (void)decodeTime;
+        }
+
+        if (mImg.data != nullptr) {
+            DDD("got data %" PRIu64 " with pts %" PRIu64,  getWorkIndex(mImg.pts), mImg.pts);
+            mHeaderDecoded = true;
+            copyImageData(mImg);
+            finishWork(getWorkIndex(mImg.pts), work);
+            removePts(mImg.pts);
+        } else {
+            work->workletsProcessed = 0u;
+        }
+
+        inPos += mConsumedBytes;
+    }
+    if (eos) {
+        DDD("drain because of eos");
+        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
+        mSignalledOutputEos = true;
+    } else if (!hasPicture) {
+        DDD("no picture, fill empty work");
+        fillEmptyWork(work);
+    }
+
+    work->input.buffers.clear();
+}
+
+c2_status_t
+C2GoldfishAvcDec::drainInternal(uint32_t drainMode,
+                                const std::shared_ptr<C2BlockPool> &pool,
+                                const std::unique_ptr<C2Work> &work) {
+    if (drainMode == NO_DRAIN) {
+        ALOGW("drain with NO_DRAIN: no-op");
+        return C2_OK;
+    }
+    if (drainMode == DRAIN_CHAIN) {
+        ALOGW("DRAIN_CHAIN not supported");
+        return C2_OMITTED;
+    }
+
+    if (OK != setFlushMode())
+        return C2_CORRUPTED;
+    while (true) {
+        if (C2_OK != ensureDecoderState(pool)) {
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            work->result = C2_CORRUPTED;
+            return C2_CORRUPTED;
+        }
+        /*
+        C2GraphicView wView = mOutBlock->map().get();
+        if (wView.error()) {
+            ALOGE("graphic view map failed %d", wView.error());
+            return C2_CORRUPTED;
+        }
+        if (!setDecodeArgs(nullptr, &wView, 0, 0, 0)) {
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            return C2_CORRUPTED;
+        }
+        */
+
+        if (mHostColorBufferId > 0) {
+            mImg = mContext->renderOnHostAndReturnImageMetadata(
+                mHostColorBufferId);
+        } else {
+            mImg = mContext->getImage();
+        }
+
+        // TODO: maybe keep rendering to screen
+        //        mImg = mContext->getImage();
+        if (mImg.data != nullptr) {
+            DDD("got data in drain mode %" PRIu64 " with pts %" PRIu64,  getWorkIndex(mImg.pts), mImg.pts);
+            copyImageData(mImg);
+            finishWork(getWorkIndex(mImg.pts), work);
+            removePts(mImg.pts);
+        } else {
+            fillEmptyWork(work);
+            break;
+        }
+    }
+
+    return C2_OK;
+}
+
+c2_status_t C2GoldfishAvcDec::drain(uint32_t drainMode,
+                                    const std::shared_ptr<C2BlockPool> &pool) {
+    DDD("drainInternal because of drain");
+    return drainInternal(drainMode, pool, nullptr);
+}
+
+class C2GoldfishAvcDecFactory : public C2ComponentFactory {
+  public:
+    C2GoldfishAvcDecFactory()
+        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
+              GoldfishComponentStore::Create()->getParamReflector())) {}
+
+    virtual c2_status_t
+    createComponent(c2_node_id_t id,
+                    std::shared_ptr<C2Component> *const component,
+                    std::function<void(C2Component *)> deleter) override {
+        *component = std::shared_ptr<C2Component>(
+            new C2GoldfishAvcDec(
+                COMPONENT_NAME, id,
+                std::make_shared<C2GoldfishAvcDec::IntfImpl>(mHelper)),
+            deleter);
+        return C2_OK;
+    }
+
+    virtual c2_status_t createInterface(
+        c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *const interface,
+        std::function<void(C2ComponentInterface *)> deleter) override {
+        *interface = std::shared_ptr<C2ComponentInterface>(
+            new SimpleInterface<C2GoldfishAvcDec::IntfImpl>(
+                COMPONENT_NAME, id,
+                std::make_shared<C2GoldfishAvcDec::IntfImpl>(mHelper)),
+            deleter);
+        return C2_OK;
+    }
+
+    virtual ~C2GoldfishAvcDecFactory() override = default;
+
+  private:
+    std::shared_ptr<C2ReflectorHelper> mHelper;
+};
+
+} // namespace android
+
+extern "C" ::C2ComponentFactory *CreateCodec2Factory() {
+    DDD("in %s", __func__);
+    return new ::android::C2GoldfishAvcDecFactory();
+}
+
+extern "C" void DestroyCodec2Factory(::C2ComponentFactory *factory) {
+    DDD("in %s", __func__);
+    delete factory;
+}
diff --git a/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h b/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h
new file mode 100644
index 00000000..33aa2d97
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/C2GoldfishAvcDec.h
@@ -0,0 +1,173 @@
+/*
+ * Copyright 2017 The Android Open Source Project
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
+#ifndef ANDROID_C2_SOFT_AVC_DEC_H_
+#define ANDROID_C2_SOFT_AVC_DEC_H_
+
+#include <sys/time.h>
+
+#include <media/stagefright/foundation/ColorUtils.h>
+
+#include "MediaH264Decoder.h"
+#include "GoldfishH264Helper.h"
+#include <SimpleC2Component.h>
+#include <atomic>
+#include <map>
+
+namespace android {
+
+#define ALIGN2(x) ((((x) + 1) >> 1) << 1)
+#define ALIGN8(x) ((((x) + 7) >> 3) << 3)
+#define ALIGN16(x) ((((x) + 15) >> 4) << 4)
+#define ALIGN32(x) ((((x) + 31) >> 5) << 5)
+#define MAX_NUM_CORES 4
+#define MIN(a, b) (((a) < (b)) ? (a) : (b))
+#define GETTIME(a, b) gettimeofday(a, b);
+#define TIME_DIFF(start, end, diff)                                            \
+    diff = (((end).tv_sec - (start).tv_sec) * 1000000) +                       \
+           ((end).tv_usec - (start).tv_usec);
+
+class C2GoldfishAvcDec : public SimpleC2Component {
+  public:
+    class IntfImpl;
+    C2GoldfishAvcDec(const char *name, c2_node_id_t id,
+                     const std::shared_ptr<IntfImpl> &intfImpl);
+    virtual ~C2GoldfishAvcDec();
+
+    // From SimpleC2Component
+    c2_status_t onInit() override;
+    c2_status_t onStop() override;
+    void onReset() override;
+    void onRelease() override;
+    c2_status_t onFlush_sm() override;
+    void process(const std::unique_ptr<C2Work> &work,
+                 const std::shared_ptr<C2BlockPool> &pool) override;
+    c2_status_t drain(uint32_t drainMode,
+                      const std::shared_ptr<C2BlockPool> &pool) override;
+
+  private:
+    void checkMode(const std::shared_ptr<C2BlockPool> &pool);
+    //    status_t createDecoder();
+    status_t createDecoder();
+    status_t setParams(size_t stride);
+    status_t initDecoder();
+    bool setDecodeArgs(C2ReadView *inBuffer, C2GraphicView *outBuffer,
+                       size_t inOffset, size_t inSize, uint32_t tsMarker, bool hasPicture);
+    c2_status_t ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool);
+    void finishWork(uint64_t index, const std::unique_ptr<C2Work> &work);
+    status_t setFlushMode();
+    c2_status_t drainInternal(uint32_t drainMode,
+                              const std::shared_ptr<C2BlockPool> &pool,
+                              const std::unique_ptr<C2Work> &work);
+    status_t resetDecoder();
+    void resetPlugin();
+    void deleteContext();
+
+
+    void removePts(uint64_t pts);
+    void insertPts(uint32_t work_index, uint64_t pts);
+    uint64_t getWorkIndex(uint64_t pts);
+
+    // TODO:This is not the right place for this enum. These should
+    // be part of c2-vndk so that they can be accessed by all video plugins
+    // until then, make them feel at home
+    enum {
+        kNotSupported,
+        kPreferBitstream,
+        kPreferContainer,
+    };
+
+    // Color aspects. These are ISO values and are meant to detect changes in
+    // aspects to avoid converting them to C2 values for each frame
+    struct VuiColorAspects {
+        uint8_t primaries;
+        uint8_t transfer;
+        uint8_t coeffs;
+        uint8_t fullRange;
+
+        // default color aspects
+        VuiColorAspects()
+            : primaries(2), transfer(2), coeffs(2), fullRange(0) {}
+
+        bool operator==(const VuiColorAspects &o) const {
+            return primaries == o.primaries && transfer == o.transfer &&
+                   coeffs == o.coeffs && fullRange == o.fullRange;
+        }
+    };
+
+    void getVuiParams(h264_image_t &img);
+    void copyImageData(h264_image_t &img);
+
+    void sendMetadata();
+
+    void decodeHeaderAfterFlush();
+
+    std::unique_ptr<MediaH264Decoder> mContext;
+    std::shared_ptr<C2GraphicBlock> mOutBlock;
+    std::unique_ptr<GoldfishH264Helper> mH264Helper;
+
+    std::shared_ptr<IntfImpl> mIntf;
+    uint8_t *mOutBufferFlush{nullptr};
+    uint8_t *mInPBuffer{nullptr};
+
+    // there are same pts matching to different work indices
+    // this happen during csd0/csd1 switching
+    std::map<uint64_t, uint64_t> mOldPts2Index;
+    std::map<uint64_t, uint64_t> mPts2Index;
+    std::map<uint64_t, uint64_t> mIndex2Pts;
+
+    std::vector<uint8_t> mCsd0;
+    std::vector<uint8_t> mCsd1;
+
+    std::atomic_uint64_t mOutIndex;
+    uint64_t  mPts {0};
+
+    h264_image_t mImg{};
+    VuiColorAspects mBitstreamColorAspects;
+    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
+
+
+    uint32_t mConsumedBytes{0};
+    uint32_t mInPBufferSize{0};
+    uint32_t mInTsMarker{0};
+
+    // size_t mNumCores;
+    // uint32_t mOutputDelay;
+    uint32_t mWidth{0};
+    uint32_t mHeight{0};
+    uint32_t mStride{0};
+
+    int mHostColorBufferId{-1};
+    int mId = -1;
+
+    bool mEnableAndroidNativeBuffers{true};
+    bool mSignalledOutputEos{false};
+    bool mSignalledError{false};
+    bool mHeaderDecoded{false};
+
+    // profile
+    struct timeval mTimeStart;
+    struct timeval mTimeEnd;
+#ifdef FILE_DUMP_ENABLE
+    char mInFile[200];
+#endif /* FILE_DUMP_ENABLE */
+
+    C2_DO_NOT_COPY(C2GoldfishAvcDec);
+};
+
+} // namespace android
+
+#endif // ANDROID_C2_SOFT_AVC_DEC_H_
diff --git a/codecs/c2/decoders/avcdec/GoldfishH264Helper.cpp b/codecs/c2/decoders/avcdec/GoldfishH264Helper.cpp
new file mode 100644
index 00000000..c656b90f
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/GoldfishH264Helper.cpp
@@ -0,0 +1,307 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "GoldfishH264Helper.h"
+
+#define LOG_TAG "GoldfishH264Helper"
+#include <log/log.h>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(fmt, ...) ALOGD("%s %d:" fmt, __func__, __LINE__, ##__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+
+#include <Codec2Mapper.h>
+
+#define ivdec_api_function              ih264d_api_function
+#define ivdext_create_ip_t              ih264d_create_ip_t
+#define ivdext_create_op_t              ih264d_create_op_t
+#define ivdext_delete_ip_t              ih264d_delete_ip_t
+#define ivdext_delete_op_t              ih264d_delete_op_t
+#define ivdext_ctl_set_num_cores_ip_t   ih264d_ctl_set_num_cores_ip_t
+#define ivdext_ctl_set_num_cores_op_t   ih264d_ctl_set_num_cores_op_t
+#define ivdext_ctl_get_vui_params_ip_t  ih264d_ctl_get_vui_params_ip_t
+#define ivdext_ctl_get_vui_params_op_t  ih264d_ctl_get_vui_params_op_t
+#define ALIGN128(x)                     ((((x) + 127) >> 7) << 7)
+#define MAX_NUM_CORES                   4
+#define IVDEXT_CMD_CTL_SET_NUM_CORES    \
+        (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_SET_NUM_CORES
+#define MIN(a, b)                       (((a) < (b)) ? (a) : (b))
+
+namespace android {
+
+static void *ivd_aligned_malloc(void *ctxt, WORD32 alignment, WORD32 size) {
+    (void) ctxt;
+    return memalign(alignment, size);
+}
+
+static void ivd_aligned_free(void *ctxt, void *mem) {
+    (void) ctxt;
+    free(mem);
+}
+
+
+GoldfishH264Helper::GoldfishH264Helper(int w, int h):mWidth(w),mHeight(h) { createDecoder(); }
+
+GoldfishH264Helper::~GoldfishH264Helper() {
+    destroyDecoder();
+}
+
+void GoldfishH264Helper::createDecoder() {
+    ivdext_create_ip_t s_create_ip = {};
+    ivdext_create_op_t s_create_op = {};
+
+    s_create_ip.s_ivd_create_ip_t.u4_size = sizeof(ivdext_create_ip_t);
+    s_create_ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
+    s_create_ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
+    s_create_ip.s_ivd_create_ip_t.e_output_format = mIvColorformat;
+    s_create_ip.s_ivd_create_ip_t.pf_aligned_alloc = ivd_aligned_malloc;
+    s_create_ip.s_ivd_create_ip_t.pf_aligned_free = ivd_aligned_free;
+    s_create_ip.s_ivd_create_ip_t.pv_mem_ctxt = nullptr;
+    s_create_op.s_ivd_create_op_t.u4_size = sizeof(ivdext_create_op_t);
+    IV_API_CALL_STATUS_T status =
+        ivdec_api_function(mDecHandle, &s_create_ip, &s_create_op);
+    if (status != IV_SUCCESS) {
+        ALOGE("error in %s: 0x%x", __func__,
+              s_create_op.s_ivd_create_op_t.u4_error_code);
+        return;
+    }
+    mDecHandle = (iv_obj_t *)s_create_op.s_ivd_create_op_t.pv_handle;
+    mDecHandle->pv_fxns = (void *)ivdec_api_function;
+    mDecHandle->u4_size = sizeof(iv_obj_t);
+
+    mStride = ALIGN128(mWidth);
+
+    setNumCores();
+}
+
+void GoldfishH264Helper::destroyDecoder() {
+    if (mDecHandle) {
+        ivdext_delete_ip_t s_delete_ip = {};
+        ivdext_delete_op_t s_delete_op = {};
+
+        s_delete_ip.s_ivd_delete_ip_t.u4_size = sizeof(ivdext_delete_ip_t);
+        s_delete_ip.s_ivd_delete_ip_t.e_cmd = IVD_CMD_DELETE;
+        s_delete_op.s_ivd_delete_op_t.u4_size = sizeof(ivdext_delete_op_t);
+        IV_API_CALL_STATUS_T status =
+            ivdec_api_function(mDecHandle, &s_delete_ip, &s_delete_op);
+        if (status != IV_SUCCESS) {
+            ALOGE("error in %s: 0x%x", __func__,
+                  s_delete_op.s_ivd_delete_op_t.u4_error_code);
+        }
+        mDecHandle = nullptr;
+    }
+}
+
+void GoldfishH264Helper::setNumCores() {
+    ivdext_ctl_set_num_cores_ip_t s_set_num_cores_ip = {};
+    ivdext_ctl_set_num_cores_op_t s_set_num_cores_op = {};
+
+    s_set_num_cores_ip.u4_size = sizeof(ivdext_ctl_set_num_cores_ip_t);
+    s_set_num_cores_ip.e_cmd = IVD_CMD_VIDEO_CTL;
+    s_set_num_cores_ip.e_sub_cmd = IVDEXT_CMD_CTL_SET_NUM_CORES;
+    s_set_num_cores_ip.u4_num_cores = mNumCores;
+    s_set_num_cores_op.u4_size = sizeof(ivdext_ctl_set_num_cores_op_t);
+    IV_API_CALL_STATUS_T status = ivdec_api_function(
+        mDecHandle, &s_set_num_cores_ip, &s_set_num_cores_op);
+    if (IV_SUCCESS != status) {
+        DDD("error in %s: 0x%x", __func__, s_set_num_cores_op.u4_error_code);
+    }
+}
+
+void GoldfishH264Helper::resetDecoder() {
+    ivd_ctl_reset_ip_t s_reset_ip = {};
+    ivd_ctl_reset_op_t s_reset_op = {};
+
+    s_reset_ip.u4_size = sizeof(ivd_ctl_reset_ip_t);
+    s_reset_ip.e_cmd = IVD_CMD_VIDEO_CTL;
+    s_reset_ip.e_sub_cmd = IVD_CMD_CTL_RESET;
+    s_reset_op.u4_size = sizeof(ivd_ctl_reset_op_t);
+    IV_API_CALL_STATUS_T status =
+        ivdec_api_function(mDecHandle, &s_reset_ip, &s_reset_op);
+    if (IV_SUCCESS != status) {
+        ALOGE("error in %s: 0x%x", __func__, s_reset_op.u4_error_code);
+    }
+    setNumCores();
+}
+
+void GoldfishH264Helper::setParams(size_t stride,
+                                   IVD_VIDEO_DECODE_MODE_T dec_mode) {
+    ih264d_ctl_set_config_ip_t s_h264d_set_dyn_params_ip = {};
+    ih264d_ctl_set_config_op_t s_h264d_set_dyn_params_op = {};
+    ivd_ctl_set_config_ip_t *ps_set_dyn_params_ip =
+        &s_h264d_set_dyn_params_ip.s_ivd_ctl_set_config_ip_t;
+    ivd_ctl_set_config_op_t *ps_set_dyn_params_op =
+        &s_h264d_set_dyn_params_op.s_ivd_ctl_set_config_op_t;
+
+    ps_set_dyn_params_ip->u4_size = sizeof(ih264d_ctl_set_config_ip_t);
+    ps_set_dyn_params_ip->e_cmd = IVD_CMD_VIDEO_CTL;
+    ps_set_dyn_params_ip->e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
+    ps_set_dyn_params_ip->u4_disp_wd = (UWORD32) stride;
+    ps_set_dyn_params_ip->e_frm_skip_mode = IVD_SKIP_NONE;
+    ps_set_dyn_params_ip->e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
+    ps_set_dyn_params_ip->e_vid_dec_mode = dec_mode;
+    ps_set_dyn_params_op->u4_size = sizeof(ih264d_ctl_set_config_op_t);
+    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
+                                                     &s_h264d_set_dyn_params_ip,
+                                                     &s_h264d_set_dyn_params_op);
+    if (status != IV_SUCCESS) {
+        ALOGE("error in %s: 0x%x", __func__,
+              ps_set_dyn_params_op->u4_error_code);
+    }
+}
+
+bool GoldfishH264Helper::isSpsFrame(const uint8_t* frame, int inSize) {
+    if (inSize < 5) return false;
+    if (frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == 1) {
+        const bool forbiddenBitIsInvalid = 0x80 & frame[4];
+        if (forbiddenBitIsInvalid) {
+            return false;
+        }
+        // nalu type is the lower 5 bits
+        uint8_t naluType = 0x1f & frame[4];
+        if (naluType == 7
+            || naluType == 8
+                ) return true;
+        else return false;
+    } else {
+        return false;
+    }
+}
+
+bool GoldfishH264Helper::decodeHeader(const uint8_t *frame, int inSize) {
+    DDD("entering");
+    // should we check the header for vps/sps/pps frame ? otherwise
+    // there is no point calling decoder
+    if (!isSpsFrame(frame, inSize)) {
+        DDD("could not find valid vps frame");
+        DDD("leaving with false");
+        return false;
+    } else {
+        DDD("found valid vps frame");
+    }
+
+    ih264d_video_decode_ip_t s_h264d_decode_ip = {};
+    ih264d_video_decode_op_t s_h264d_decode_op = {};
+    ivd_video_decode_ip_t *ps_decode_ip = &s_h264d_decode_ip.s_ivd_video_decode_ip_t;
+    ivd_video_decode_op_t *ps_decode_op = &s_h264d_decode_op.s_ivd_video_decode_op_t;
+
+    // setup input/output arguments to decoder
+    setDecodeArgs(ps_decode_ip, ps_decode_op, frame, mStride,
+            0, // offset
+            inSize, // size
+            0 // time-stamp, does not matter
+            );
+
+    setParams(mStride, IVD_DECODE_HEADER);
+
+    // now kick off the decoding
+    ivdec_api_function(mDecHandle, ps_decode_ip, ps_decode_op);
+
+    if (IVD_RES_CHANGED == (ps_decode_op->u4_error_code & IVD_ERROR_MASK)) {
+        DDD("resolution changed, reset decoder");
+        resetDecoder();
+        setParams(mStride, IVD_DECODE_HEADER);
+        ivdec_api_function(mDecHandle, ps_decode_ip, ps_decode_op);
+    }
+
+    // get the w/h and update
+    if (0 < ps_decode_op->u4_pic_wd && 0 < ps_decode_op->u4_pic_ht) {
+        DDD("success decode w/h %d %d", ps_decode_op->u4_pic_wd , ps_decode_op->u4_pic_ht);
+        DDD("existing w/h %d %d", mWidth, mHeight);
+        if (ps_decode_op->u4_pic_wd != mWidth ||  ps_decode_op->u4_pic_ht != mHeight) {
+            mWidth = ps_decode_op->u4_pic_wd;
+            mHeight = ps_decode_op->u4_pic_ht;
+            DDD("leaving with true");
+            return true;
+        } else {
+            DDD("success decode w/h, but they are the same %d %d", ps_decode_op->u4_pic_wd , ps_decode_op->u4_pic_ht);
+        }
+    }
+
+    // get output delay
+    if (ps_decode_op->i4_reorder_depth >= 0) {
+        if (mOutputDelay != ps_decode_op->i4_reorder_depth) {
+            mOutputDelay = ps_decode_op->i4_reorder_depth;
+            DDD("New Output delay %d ", mOutputDelay);
+        } else {
+            DDD("same Output delay %d ", mOutputDelay);
+        }
+    }
+
+    DDD("leaving with false");
+    return false;
+}
+
+bool GoldfishH264Helper::setDecodeArgs(ivd_video_decode_ip_t *ps_decode_ip,
+                                       ivd_video_decode_op_t *ps_decode_op,
+                                       const uint8_t *inBuffer,
+                                       uint32_t displayStride, size_t inOffset,
+                                       size_t inSize, uint32_t tsMarker) {
+    uint32_t displayHeight = mHeight;
+    size_t lumaSize = displayStride * displayHeight;
+    size_t chromaSize = lumaSize >> 2;
+
+    if (mStride != displayStride) {
+        mStride = displayStride;
+    }
+
+    // force decoder to always decode header and get dimensions,
+    // hope this will be quick and cheap
+    setParams(mStride, IVD_DECODE_HEADER);
+
+    ps_decode_ip->u4_size = sizeof(ih264d_video_decode_ip_t);
+    ps_decode_ip->e_cmd = IVD_CMD_VIDEO_DECODE;
+    if (inBuffer) {
+        ps_decode_ip->u4_ts = tsMarker;
+        ps_decode_ip->pv_stream_buffer = const_cast<uint8_t *>(inBuffer) + inOffset;
+        ps_decode_ip->u4_num_Bytes = inSize;
+    } else {
+        ps_decode_ip->u4_ts = 0;
+        ps_decode_ip->pv_stream_buffer = nullptr;
+        ps_decode_ip->u4_num_Bytes = 0;
+    }
+    DDD("setting pv_stream_buffer 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[0],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[1],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[2],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[3],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[4],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[5],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[6],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[7]
+            );
+    DDD("input bytes %d", ps_decode_ip->u4_num_Bytes);
+
+    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[0] = lumaSize;
+    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[1] = chromaSize;
+    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[2] = chromaSize;
+    {
+        ps_decode_ip->s_out_buffer.pu1_bufs[0] = nullptr;
+        ps_decode_ip->s_out_buffer.pu1_bufs[1] = nullptr;
+        ps_decode_ip->s_out_buffer.pu1_bufs[2] = nullptr;
+    }
+    ps_decode_ip->s_out_buffer.u4_num_bufs = 3;
+    ps_decode_op->u4_size = sizeof(ih264d_video_decode_op_t);
+    ps_decode_op->u4_output_present = 0;
+
+    return true;
+}
+
+} // namespace android
diff --git a/codecs/c2/decoders/avcdec/GoldfishH264Helper.h b/codecs/c2/decoders/avcdec/GoldfishH264Helper.h
new file mode 100644
index 00000000..ec3b3840
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/GoldfishH264Helper.h
@@ -0,0 +1,66 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef GOLDFISH_H264_HELPER_H_
+#define GOLDFISH_H264_HELPER_H_
+
+#include <inttypes.h>
+#include "ih264_typedefs.h"
+#include "ih264d.h"
+
+
+namespace android {
+
+// this class is just to provide some functions to decode header
+// so that we know w/h of each sps
+class GoldfishH264Helper {
+  public:
+    GoldfishH264Helper(int w, int h);
+    ~GoldfishH264Helper();
+
+    // check whether the frame is sps; typical h264 will have
+    // a frame that is sps/pps together
+    static bool isSpsFrame(const uint8_t* frame, int inSize);
+  public:
+    // return true if decoding finds out w/h changed;
+    // otherwise false
+    bool decodeHeader(const uint8_t *frame, int inSize);
+    int getWidth() const { return mWidth; }
+    int getHeight() const { return mHeight; }
+
+  private:
+    void createDecoder();
+    void destroyDecoder();
+    void resetDecoder();
+    void setNumCores();
+    void setParams(size_t stride, IVD_VIDEO_DECODE_MODE_T dec_mode);
+    bool setDecodeArgs(ivd_video_decode_ip_t *ps_decode_ip,
+                       ivd_video_decode_op_t *ps_decode_op,
+                       const uint8_t *inBuffer, uint32_t displayStride,
+                       size_t inOffset, size_t inSize, uint32_t tsMarker);
+
+  private:
+    iv_obj_t *mDecHandle = nullptr;
+    int mWidth = 320;
+    int mHeight = 240;
+    int mNumCores = 1;
+    int mStride = 16;
+    int mOutputDelay = 8; // default
+    IV_COLOR_FORMAT_T mIvColorformat = IV_YUV_420P;
+};
+
+} // namespace android
+#endif
diff --git a/codecs/c2/decoders/avcdec/MediaH264Decoder.cpp b/codecs/c2/decoders/avcdec/MediaH264Decoder.cpp
new file mode 100644
index 00000000..65607722
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/MediaH264Decoder.cpp
@@ -0,0 +1,229 @@
+/*
+ * Copyright 2015 The Android Open Source Project
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
+#include <utils/Log.h>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+#include "MediaH264Decoder.h"
+#include "goldfish_media_utils.h"
+#include <string.h>
+
+MediaH264Decoder::MediaH264Decoder(RenderMode renderMode)
+    : mRenderMode(renderMode) {
+    if (renderMode == RenderMode::RENDER_BY_HOST_GPU) {
+        mVersion = 200;
+    } else if (renderMode == RenderMode::RENDER_BY_GUEST_CPU) {
+        mVersion = 100;
+    }
+}
+
+void MediaH264Decoder::initH264Context(unsigned int width, unsigned int height,
+                                       unsigned int outWidth,
+                                       unsigned int outHeight,
+                                       PixelFormat pixFmt) {
+    auto transport = GoldfishMediaTransport::getInstance();
+    if (!mHasAddressSpaceMemory) {
+        int slot = transport->getMemorySlot();
+        if (slot < 0) {
+            ALOGE("ERROR: Failed to initH264Context: cannot get memory slot");
+            return;
+        }
+        mSlot = slot;
+        mAddressOffSet = static_cast<unsigned int>(mSlot) * (1 << 20);
+        DDD("got memory lot %d addrr %lu", mSlot, mAddressOffSet);
+        mHasAddressSpaceMemory = true;
+    }
+    transport->writeParam(mVersion, 0, mAddressOffSet);
+    transport->writeParam(width, 1, mAddressOffSet);
+    transport->writeParam(height, 2, mAddressOffSet);
+    transport->writeParam(outWidth, 3, mAddressOffSet);
+    transport->writeParam(outHeight, 4, mAddressOffSet);
+    transport->writeParam(static_cast<uint64_t>(pixFmt), 5, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec,
+                             MediaOperation::InitContext, mAddressOffSet);
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    mHostHandle = *(uint64_t *)(retptr);
+    DDD("initH264Context: got handle to host %lu", mHostHandle);
+}
+
+void MediaH264Decoder::resetH264Context(unsigned int width, unsigned int height,
+                                        unsigned int outWidth,
+                                        unsigned int outHeight,
+                                        PixelFormat pixFmt) {
+    auto transport = GoldfishMediaTransport::getInstance();
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return;
+    }
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(width, 1, mAddressOffSet);
+    transport->writeParam(height, 2, mAddressOffSet);
+    transport->writeParam(outWidth, 3, mAddressOffSet);
+    transport->writeParam(outHeight, 4, mAddressOffSet);
+    transport->writeParam(static_cast<uint64_t>(pixFmt), 5, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec, MediaOperation::Reset,
+                             mAddressOffSet);
+    DDD("resetH264Context: done");
+}
+
+void MediaH264Decoder::destroyH264Context() {
+
+    DDD("return memory lot %d addrr %lu", (int)(mAddressOffSet >> 23),
+        mAddressOffSet);
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec,
+                             MediaOperation::DestroyContext, mAddressOffSet);
+    transport->returnMemorySlot(mSlot);
+    mHasAddressSpaceMemory = false;
+}
+
+h264_result_t MediaH264Decoder::decodeFrame(uint8_t *img, size_t szBytes,
+                                            uint64_t pts) {
+    DDD("decode frame: use handle to host %lu", mHostHandle);
+    h264_result_t res = {0, 0};
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return res;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    uint8_t *hostSrc = transport->getInputAddr(mAddressOffSet);
+    if (img != nullptr && szBytes > 0) {
+        memcpy(hostSrc, img, szBytes);
+    }
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(transport->offsetOf((uint64_t)(hostSrc)) -
+                              mAddressOffSet,
+                          1, mAddressOffSet);
+    transport->writeParam((uint64_t)szBytes, 2, mAddressOffSet);
+    transport->writeParam((uint64_t)pts, 3, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec,
+                             MediaOperation::DecodeImage, mAddressOffSet);
+
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    res.bytesProcessed = *(uint64_t *)(retptr);
+    res.ret = *(int *)(retptr + 8);
+
+    return res;
+}
+
+void MediaH264Decoder::sendMetadata(MetaDataColorAspects *ptr) {
+    DDD("send metadata to host %p", ptr);
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return;
+    }
+    MetaDataColorAspects& meta = *ptr;
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(meta.type, 1, mAddressOffSet);
+    transport->writeParam(meta.primaries, 2, mAddressOffSet);
+    transport->writeParam(meta.range, 3, mAddressOffSet);
+    transport->writeParam(meta.transfer, 4, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec, MediaOperation::SendMetadata, mAddressOffSet);
+}
+
+void MediaH264Decoder::flush() {
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return;
+    }
+    DDD("flush: use handle to host %lu", mHostHandle);
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec, MediaOperation::Flush,
+                             mAddressOffSet);
+}
+
+h264_image_t MediaH264Decoder::getImage() {
+    DDD("getImage: use handle to host %lu", mHostHandle);
+    h264_image_t res{};
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return res;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    uint8_t *dst = transport->getInputAddr(
+        mAddressOffSet); // Note: reuse the same addr for input and output
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(transport->offsetOf((uint64_t)(dst)) - mAddressOffSet,
+                          1, mAddressOffSet);
+    transport->writeParam(-1, 2, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec,
+                             MediaOperation::GetImage, mAddressOffSet);
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    res.ret = *(int *)(retptr);
+    if (res.ret >= 0) {
+        res.data = dst;
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+        res.pts = *(uint64_t *)(retptr + 24);
+        res.color_primaries = *(uint32_t *)(retptr + 32);
+        res.color_range = *(uint32_t *)(retptr + 40);
+        res.color_trc = *(uint32_t *)(retptr + 48);
+        res.colorspace = *(uint32_t *)(retptr + 56);
+    } else if (res.ret == (int)(Err::DecoderRestarted)) {
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+    }
+    return res;
+}
+
+h264_image_t
+MediaH264Decoder::renderOnHostAndReturnImageMetadata(int hostColorBufferId) {
+    DDD("%s: use handle to host %lu", __func__, mHostHandle);
+    h264_image_t res{};
+    if (hostColorBufferId < 0) {
+        ALOGE("%s negative color buffer id %d", __func__, hostColorBufferId);
+        return res;
+    }
+    DDD("%s send color buffer id %d", __func__, hostColorBufferId);
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return res;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    uint8_t *dst = transport->getInputAddr(
+        mAddressOffSet); // Note: reuse the same addr for input and output
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(transport->offsetOf((uint64_t)(dst)) - mAddressOffSet,
+                          1, mAddressOffSet);
+    transport->writeParam((uint64_t)hostColorBufferId, 2, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::H264Codec,
+                             MediaOperation::GetImage, mAddressOffSet);
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    res.ret = *(int *)(retptr);
+    if (res.ret >= 0) {
+        res.data = dst; // note: the data could be junk
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+        res.pts = *(uint64_t *)(retptr + 24);
+        res.color_primaries = *(uint32_t *)(retptr + 32);
+        res.color_range = *(uint32_t *)(retptr + 40);
+        res.color_trc = *(uint32_t *)(retptr + 48);
+        res.colorspace = *(uint32_t *)(retptr + 56);
+    } else if (res.ret == (int)(Err::DecoderRestarted)) {
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+    }
+    return res;
+}
diff --git a/codecs/c2/decoders/avcdec/MediaH264Decoder.h b/codecs/c2/decoders/avcdec/MediaH264Decoder.h
new file mode 100644
index 00000000..e184cbd0
--- /dev/null
+++ b/codecs/c2/decoders/avcdec/MediaH264Decoder.h
@@ -0,0 +1,104 @@
+/*
+ * Copyright 2015 The Android Open Source Project
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
+#ifndef GOLDFISH_MEDIA_H264_DEC_H_
+#define GOLDFISH_MEDIA_H264_DEC_H_
+
+#include "goldfish_media_utils.h"
+
+struct h264_init_result_t {
+    uint64_t host_handle;
+    int ret;
+};
+
+struct h264_result_t {
+    int ret;
+    uint64_t bytesProcessed;
+};
+
+struct h264_image_t {
+    const uint8_t *data;
+    uint32_t width;
+    uint32_t height;
+    uint64_t pts; // presentation time stamp
+    uint64_t color_primaries;
+    uint64_t color_range;
+    uint64_t color_trc;
+    uint64_t colorspace;
+    // on success, |ret| will indicate the size of |data|.
+    // If failed, |ret| will contain some negative error code.
+    int ret;
+};
+
+enum class RenderMode {
+    RENDER_BY_HOST_GPU = 1,
+    RENDER_BY_GUEST_CPU = 2,
+};
+
+class MediaH264Decoder {
+    uint64_t mHostHandle = 0;
+    uint32_t mVersion = 100;
+    RenderMode mRenderMode = RenderMode::RENDER_BY_GUEST_CPU;
+
+    bool mHasAddressSpaceMemory = false;
+    uint64_t mAddressOffSet = 0;
+    int mSlot = -1;
+
+  public:
+    MediaH264Decoder(RenderMode renderMode);
+    virtual ~MediaH264Decoder() = default;
+
+    enum class PixelFormat : uint8_t {
+        YUV420P = 0,
+        UYVY422 = 1,
+        BGRA8888 = 2,
+    };
+
+    enum class Err : int {
+        NoErr = 0,
+        NoDecodedFrame = -1,
+        InitContextFailed = -2,
+        DecoderRestarted = -3,
+        NALUIgnored = -4,
+    };
+
+    bool getAddressSpaceMemory();
+    void initH264Context(unsigned int width, unsigned int height,
+                         unsigned int outWidth, unsigned int outHeight,
+                         PixelFormat pixFmt);
+    void resetH264Context(unsigned int width, unsigned int height,
+                          unsigned int outWidth, unsigned int outHeight,
+                          PixelFormat pixFmt);
+    void destroyH264Context();
+    h264_result_t decodeFrame(uint8_t *img, size_t szBytes, uint64_t pts);
+    void flush();
+    // ask host to copy image data back to guest, with image metadata
+    // to guest as well
+    h264_image_t getImage();
+    // ask host to render to hostColorBufferId, return only image metadata back
+    // to guest
+    h264_image_t renderOnHostAndReturnImageMetadata(int hostColorBufferId);
+
+    // send metadata about the bitstream to host, such as color aspects that
+    // are set by the framework, e.g., color primaries (601, 709 etc), range
+    // (full range or limited range), transfer etc. given metadata could be
+    // of all kinds of types, the convention is that the first field server as
+    // metadata type id. host will check the type id to decide what to do with
+    // it; unrecognized typeid will be discarded by host side.
+
+    void sendMetadata(MetaDataColorAspects *ptr);
+};
+#endif
diff --git a/codecs/c2/decoders/base/Android.bp b/codecs/c2/decoders/base/Android.bp
new file mode 100644
index 00000000..a605fe43
--- /dev/null
+++ b/codecs/c2/decoders/base/Android.bp
@@ -0,0 +1,88 @@
+// DO NOT DEPEND ON THIS DIRECTLY
+// use libcodec2_soft-defaults instead
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_library_shared {
+    name: "libcodec2_goldfish_common",
+    defaults: ["libcodec2-impl-defaults"],
+    vendor: true,
+
+    srcs: [
+        "SimpleC2Component.cpp",
+        "SimpleC2Interface.cpp",
+        "goldfish_media_utils.cpp",
+        "color_buffer_utils.cpp",
+    ],
+
+    export_include_dirs: [
+        "include",
+    ],
+
+    export_shared_lib_headers: [
+        "libsfplugin_ccodec_utils",
+        "libgoldfish_codec2_store", // for goldfish store
+    ],
+
+    shared_libs: [
+        "libcutils", // for properties
+        "liblog",    // for ALOG
+        "libdrm",    // for ALOG
+        "libbase",   // for properties, parseint
+        "libsfplugin_ccodec_utils", // for ImageCopy
+        "libstagefright_foundation", // for Mutexed
+        "libgoldfish_codec2_store", // for goldfish store
+    ],
+
+    static_libs: [
+        "mesa_platform_virtgpu",
+        "mesa_goldfish_address_space",
+        "mesa_util",
+    ],
+
+    header_libs: [
+        "libgralloc_cb.ranchu",
+    ],
+
+    sanitize: {
+        misc_undefined: [
+            "unsigned-integer-overflow",
+            "signed-integer-overflow",
+        ],
+        cfi: true,
+    },
+
+
+    ldflags: ["-Wl,-Bsymbolic"],
+}
+
+// public dependency for software codec implementation
+// to be used by code under media/codecs/* only as its stability is not guaranteed
+cc_defaults {
+    name: "libcodec2_goldfish-defaults",
+    defaults: ["libcodec2-impl-defaults"],
+    export_shared_lib_headers: [
+        "libsfplugin_ccodec_utils",
+    ],
+
+    shared_libs: [
+        "libcodec2_goldfish_common",
+        "libcutils", // for properties
+        "liblog", // for ALOG
+        "libsfplugin_ccodec_utils", // for ImageCopy
+        "libstagefright_foundation", // for ColorUtils and MIME
+    ],
+
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+
+    ldflags: ["-Wl,-Bsymbolic"],
+}
diff --git a/codecs/c2/decoders/base/SimpleC2Component.cpp b/codecs/c2/decoders/base/SimpleC2Component.cpp
new file mode 100644
index 00000000..662fce50
--- /dev/null
+++ b/codecs/c2/decoders/base/SimpleC2Component.cpp
@@ -0,0 +1,627 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+//#define LOG_NDEBUG 0
+#define LOG_TAG "SimpleC2Component"
+#include <log/log.h>
+
+#include <cutils/properties.h>
+#include <media/stagefright/foundation/AMessage.h>
+
+#include <inttypes.h>
+
+#include <C2Config.h>
+#include <C2Debug.h>
+#include <C2PlatformSupport.h>
+#include <SimpleC2Component.h>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+namespace android {
+
+std::unique_ptr<C2Work> SimpleC2Component::WorkQueue::pop_front() {
+    std::unique_ptr<C2Work> work = std::move(mQueue.front().work);
+    mQueue.pop_front();
+    return work;
+}
+
+void SimpleC2Component::WorkQueue::push_back(std::unique_ptr<C2Work> work) {
+    mQueue.push_back({std::move(work), NO_DRAIN});
+}
+
+bool SimpleC2Component::WorkQueue::empty() const { return mQueue.empty(); }
+
+void SimpleC2Component::WorkQueue::clear() { mQueue.clear(); }
+
+uint32_t SimpleC2Component::WorkQueue::drainMode() const {
+    return mQueue.front().drainMode;
+}
+
+void SimpleC2Component::WorkQueue::markDrain(uint32_t drainMode) {
+    mQueue.push_back({nullptr, drainMode});
+}
+
+////////////////////////////////////////////////////////////////////////////////
+
+SimpleC2Component::WorkHandler::WorkHandler() : mRunning(false) {}
+
+void SimpleC2Component::WorkHandler::setComponent(
+    const std::shared_ptr<SimpleC2Component> &thiz) {
+    mThiz = thiz;
+}
+
+static void Reply(const sp<AMessage> &msg, int32_t *err = nullptr) {
+    sp<AReplyToken> replyId;
+    CHECK(msg->senderAwaitsResponse(&replyId));
+    sp<AMessage> reply = new AMessage;
+    if (err) {
+        reply->setInt32("err", *err);
+    }
+    reply->postReply(replyId);
+}
+
+void SimpleC2Component::WorkHandler::onMessageReceived(
+    const sp<AMessage> &msg) {
+    std::shared_ptr<SimpleC2Component> thiz = mThiz.lock();
+    if (!thiz) {
+        ALOGD("component not yet set; msg = %s", msg->debugString().c_str());
+        sp<AReplyToken> replyId;
+        if (msg->senderAwaitsResponse(&replyId)) {
+            sp<AMessage> reply = new AMessage;
+            reply->setInt32("err", C2_CORRUPTED);
+            reply->postReply(replyId);
+        }
+        return;
+    }
+
+    switch (msg->what()) {
+    case kWhatProcess: {
+        if (mRunning) {
+            if (thiz->processQueue()) {
+                (new AMessage(kWhatProcess, this))->post();
+            }
+        } else {
+            DDD("Ignore process message as we're not running");
+        }
+        break;
+    }
+    case kWhatInit: {
+        int32_t err = thiz->onInit();
+        Reply(msg, &err);
+        [[fallthrough]];
+    }
+    case kWhatStart: {
+        mRunning = true;
+        break;
+    }
+    case kWhatStop: {
+        int32_t err = thiz->onStop();
+        thiz->mOutputBlockPool.reset();
+        Reply(msg, &err);
+        break;
+    }
+    case kWhatReset: {
+        thiz->onReset();
+        thiz->mOutputBlockPool.reset();
+        mRunning = false;
+        Reply(msg);
+        break;
+    }
+    case kWhatRelease: {
+        thiz->onRelease();
+        thiz->mOutputBlockPool.reset();
+        mRunning = false;
+        Reply(msg);
+        break;
+    }
+    default: {
+        ALOGD("Unrecognized msg: %d", msg->what());
+        break;
+    }
+    }
+}
+
+class SimpleC2Component::BlockingBlockPool : public C2BlockPool {
+  public:
+    BlockingBlockPool(const std::shared_ptr<C2BlockPool> &base) : mBase{base} {}
+
+    virtual local_id_t getLocalId() const override {
+        return mBase->getLocalId();
+    }
+
+    virtual C2Allocator::id_t getAllocatorId() const override {
+        return mBase->getAllocatorId();
+    }
+
+    virtual c2_status_t
+    fetchLinearBlock(uint32_t capacity, C2MemoryUsage usage,
+                     std::shared_ptr<C2LinearBlock> *block) {
+        c2_status_t status;
+        do {
+            status = mBase->fetchLinearBlock(capacity, usage, block);
+        } while (status == C2_BLOCKING);
+        return status;
+    }
+
+    virtual c2_status_t
+    fetchCircularBlock(uint32_t capacity, C2MemoryUsage usage,
+                       std::shared_ptr<C2CircularBlock> *block) {
+        c2_status_t status;
+        do {
+            status = mBase->fetchCircularBlock(capacity, usage, block);
+        } while (status == C2_BLOCKING);
+        return status;
+    }
+
+    virtual c2_status_t
+    fetchGraphicBlock(uint32_t width, uint32_t height, uint32_t format,
+                      C2MemoryUsage usage,
+                      std::shared_ptr<C2GraphicBlock> *block) {
+        c2_status_t status;
+        do {
+            status =
+                mBase->fetchGraphicBlock(width, height, format, usage, block);
+        } while (status == C2_BLOCKING);
+        return status;
+    }
+
+  private:
+    std::shared_ptr<C2BlockPool> mBase;
+};
+
+////////////////////////////////////////////////////////////////////////////////
+
+namespace {
+
+struct DummyReadView : public C2ReadView {
+    DummyReadView() : C2ReadView(C2_NO_INIT) {}
+};
+
+} // namespace
+
+SimpleC2Component::SimpleC2Component(
+    const std::shared_ptr<C2ComponentInterface> &intf)
+    : mDummyReadView(DummyReadView()), mIntf(intf), mLooper(new ALooper),
+      mHandler(new WorkHandler) {
+    mLooper->setName(intf->getName().c_str());
+    (void)mLooper->registerHandler(mHandler);
+    mLooper->start(false, false, ANDROID_PRIORITY_VIDEO);
+}
+
+SimpleC2Component::~SimpleC2Component() {
+    mLooper->unregisterHandler(mHandler->id());
+    (void)mLooper->stop();
+}
+
+c2_status_t SimpleC2Component::setListener_vb(
+    const std::shared_ptr<C2Component::Listener> &listener,
+    c2_blocking_t mayBlock) {
+    mHandler->setComponent(shared_from_this());
+
+    Mutexed<ExecState>::Locked state(mExecState);
+    if (state->mState == RUNNING) {
+        if (listener) {
+            return C2_BAD_STATE;
+        } else if (!mayBlock) {
+            return C2_BLOCKING;
+        }
+    }
+    state->mListener = listener;
+    // TODO: wait for listener change to have taken place before returning
+    // (e.g. if there is an ongoing listener callback)
+    return C2_OK;
+}
+
+c2_status_t
+SimpleC2Component::queue_nb(std::list<std::unique_ptr<C2Work>> *const items) {
+    {
+        Mutexed<ExecState>::Locked state(mExecState);
+        if (state->mState != RUNNING) {
+            return C2_BAD_STATE;
+        }
+    }
+    bool queueWasEmpty = false;
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        queueWasEmpty = queue->empty();
+        while (!items->empty()) {
+            queue->push_back(std::move(items->front()));
+            items->pop_front();
+        }
+    }
+    if (queueWasEmpty) {
+        (new AMessage(WorkHandler::kWhatProcess, mHandler))->post();
+    }
+    return C2_OK;
+}
+
+c2_status_t
+SimpleC2Component::announce_nb(const std::vector<C2WorkOutline> &items) {
+    (void)items;
+    return C2_OMITTED;
+}
+
+c2_status_t SimpleC2Component::flush_sm(
+    flush_mode_t flushMode,
+    std::list<std::unique_ptr<C2Work>> *const flushedWork) {
+    (void)flushMode;
+    {
+        Mutexed<ExecState>::Locked state(mExecState);
+        if (state->mState != RUNNING) {
+            return C2_BAD_STATE;
+        }
+    }
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        queue->incGeneration();
+        // TODO: queue->splicedBy(flushedWork, flushedWork->end());
+        while (!queue->empty()) {
+            std::unique_ptr<C2Work> work = queue->pop_front();
+            if (work) {
+                flushedWork->push_back(std::move(work));
+            }
+        }
+        while (!queue->pending().empty()) {
+            flushedWork->push_back(std::move(queue->pending().begin()->second));
+            queue->pending().erase(queue->pending().begin());
+        }
+    }
+
+    return C2_OK;
+}
+
+c2_status_t SimpleC2Component::drain_nb(drain_mode_t drainMode) {
+    if (drainMode == DRAIN_CHAIN) {
+        return C2_OMITTED;
+    }
+    {
+        Mutexed<ExecState>::Locked state(mExecState);
+        if (state->mState != RUNNING) {
+            return C2_BAD_STATE;
+        }
+    }
+    bool queueWasEmpty = false;
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        queueWasEmpty = queue->empty();
+        queue->markDrain(drainMode);
+    }
+    if (queueWasEmpty) {
+        (new AMessage(WorkHandler::kWhatProcess, mHandler))->post();
+    }
+
+    return C2_OK;
+}
+
+c2_status_t SimpleC2Component::start() {
+    Mutexed<ExecState>::Locked state(mExecState);
+    if (state->mState == RUNNING) {
+        return C2_BAD_STATE;
+    }
+    bool needsInit = (state->mState == UNINITIALIZED);
+    state.unlock();
+    if (needsInit) {
+        sp<AMessage> reply;
+        (new AMessage(WorkHandler::kWhatInit, mHandler))
+            ->postAndAwaitResponse(&reply);
+        int32_t err;
+        CHECK(reply->findInt32("err", &err));
+        if (err != C2_OK) {
+            return (c2_status_t)err;
+        }
+    } else {
+        (new AMessage(WorkHandler::kWhatStart, mHandler))->post();
+    }
+    state.lock();
+    state->mState = RUNNING;
+    return C2_OK;
+}
+
+c2_status_t SimpleC2Component::stop() {
+    DDD("stop");
+    {
+        Mutexed<ExecState>::Locked state(mExecState);
+        if (state->mState != RUNNING) {
+            return C2_BAD_STATE;
+        }
+        state->mState = STOPPED;
+    }
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        queue->clear();
+        queue->pending().clear();
+    }
+    sp<AMessage> reply;
+    (new AMessage(WorkHandler::kWhatStop, mHandler))
+        ->postAndAwaitResponse(&reply);
+    int32_t err;
+    CHECK(reply->findInt32("err", &err));
+    if (err != C2_OK) {
+        return (c2_status_t)err;
+    }
+    return C2_OK;
+}
+
+c2_status_t SimpleC2Component::reset() {
+    DDD("reset");
+    {
+        Mutexed<ExecState>::Locked state(mExecState);
+        state->mState = UNINITIALIZED;
+    }
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        queue->clear();
+        queue->pending().clear();
+    }
+    sp<AMessage> reply;
+    (new AMessage(WorkHandler::kWhatReset, mHandler))
+        ->postAndAwaitResponse(&reply);
+    return C2_OK;
+}
+
+c2_status_t SimpleC2Component::release() {
+    DDD("release");
+    sp<AMessage> reply;
+    (new AMessage(WorkHandler::kWhatRelease, mHandler))
+        ->postAndAwaitResponse(&reply);
+    return C2_OK;
+}
+
+std::shared_ptr<C2ComponentInterface> SimpleC2Component::intf() {
+    return mIntf;
+}
+
+namespace {
+
+std::list<std::unique_ptr<C2Work>> vec(std::unique_ptr<C2Work> &work) {
+    std::list<std::unique_ptr<C2Work>> ret;
+    ret.push_back(std::move(work));
+    return ret;
+}
+
+} // namespace
+
+void SimpleC2Component::finish(
+    uint64_t frameIndex,
+    std::function<void(const std::unique_ptr<C2Work> &)> fillWork) {
+    std::unique_ptr<C2Work> work;
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        if (queue->pending().count(frameIndex) == 0) {
+            ALOGW("unknown frame index: %" PRIu64, frameIndex);
+            return;
+        }
+        work = std::move(queue->pending().at(frameIndex));
+        queue->pending().erase(frameIndex);
+    }
+    if (work) {
+        fillWork(work);
+        std::shared_ptr<C2Component::Listener> listener =
+            mExecState.lock()->mListener;
+        listener->onWorkDone_nb(shared_from_this(), vec(work));
+        DDD("returning pending work");
+    }
+}
+
+void SimpleC2Component::cloneAndSend(
+    uint64_t frameIndex, const std::unique_ptr<C2Work> &currentWork,
+    std::function<void(const std::unique_ptr<C2Work> &)> fillWork) {
+    std::unique_ptr<C2Work> work(new C2Work);
+    if (currentWork->input.ordinal.frameIndex == frameIndex) {
+        work->input.flags = currentWork->input.flags;
+        work->input.ordinal = currentWork->input.ordinal;
+    } else {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        if (queue->pending().count(frameIndex) == 0) {
+            ALOGW("unknown frame index: %" PRIu64, frameIndex);
+            return;
+        }
+        work->input.flags = queue->pending().at(frameIndex)->input.flags;
+        work->input.ordinal = queue->pending().at(frameIndex)->input.ordinal;
+    }
+    work->worklets.emplace_back(new C2Worklet);
+    if (work) {
+        fillWork(work);
+        std::shared_ptr<C2Component::Listener> listener =
+            mExecState.lock()->mListener;
+        listener->onWorkDone_nb(shared_from_this(), vec(work));
+        DDD("cloned and sending work");
+    }
+}
+
+bool SimpleC2Component::processQueue() {
+    std::unique_ptr<C2Work> work;
+    uint64_t generation;
+    int32_t drainMode;
+    bool isFlushPending = false;
+    bool hasQueuedWork = false;
+    {
+        Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+        if (queue->empty()) {
+            return false;
+        }
+
+        generation = queue->generation();
+        drainMode = queue->drainMode();
+        isFlushPending = queue->popPendingFlush();
+        work = queue->pop_front();
+        hasQueuedWork = !queue->empty();
+    }
+    if (isFlushPending) {
+        DDD("processing pending flush");
+        c2_status_t err = onFlush_sm();
+        if (err != C2_OK) {
+            ALOGD("flush err: %d", err);
+            // TODO: error
+        }
+    }
+
+    if (!mOutputBlockPool) {
+        c2_status_t err = [this] {
+            // TODO: don't use query_vb
+            C2StreamBufferTypeSetting::output outputFormat(0u);
+            std::vector<std::unique_ptr<C2Param>> params;
+            c2_status_t err = intf()->query_vb(
+                {&outputFormat}, {C2PortBlockPoolsTuning::output::PARAM_TYPE},
+                C2_DONT_BLOCK, &params);
+            if (err != C2_OK && err != C2_BAD_INDEX) {
+                ALOGD("query err = %d", err);
+                return err;
+            }
+            C2BlockPool::local_id_t poolId =
+                outputFormat.value == C2BufferData::GRAPHIC
+                    ? C2BlockPool::BASIC_GRAPHIC
+                    : C2BlockPool::BASIC_LINEAR;
+            if (params.size()) {
+                C2PortBlockPoolsTuning::output *outputPools =
+                    C2PortBlockPoolsTuning::output::From(params[0].get());
+                if (outputPools && outputPools->flexCount() >= 1) {
+                    poolId = outputPools->m.values[0];
+                }
+            }
+
+            std::shared_ptr<C2BlockPool> blockPool;
+            err = GetCodec2BlockPool(poolId, shared_from_this(), &blockPool);
+            ALOGD("Using output block pool with poolID %llu => got %llu - %d",
+                  (unsigned long long)poolId,
+                  (unsigned long long)(blockPool ? blockPool->getLocalId()
+                                                 : 111000111),
+                  err);
+            if (err == C2_OK) {
+                mOutputBlockPool =
+                    std::make_shared<BlockingBlockPool>(blockPool);
+            }
+            return err;
+        }();
+        if (err != C2_OK) {
+            Mutexed<ExecState>::Locked state(mExecState);
+            std::shared_ptr<C2Component::Listener> listener = state->mListener;
+            state.unlock();
+            listener->onError_nb(shared_from_this(), err);
+            return hasQueuedWork;
+        }
+    }
+
+    if (!work) {
+        c2_status_t err = drain(drainMode, mOutputBlockPool);
+        if (err != C2_OK) {
+            Mutexed<ExecState>::Locked state(mExecState);
+            std::shared_ptr<C2Component::Listener> listener = state->mListener;
+            state.unlock();
+            listener->onError_nb(shared_from_this(), err);
+        }
+        return hasQueuedWork;
+    }
+
+    {
+        std::vector<C2Param *> updates;
+        for (const std::unique_ptr<C2Param> &param : work->input.configUpdate) {
+            if (param) {
+                updates.emplace_back(param.get());
+            }
+        }
+        if (!updates.empty()) {
+            std::vector<std::unique_ptr<C2SettingResult>> failures;
+            c2_status_t err =
+                intf()->config_vb(updates, C2_MAY_BLOCK, &failures);
+            ALOGD("applied %zu configUpdates => %s (%d)", updates.size(),
+                  asString(err), err);
+        }
+    }
+
+    DDD("start processing frame #%" PRIu64,
+        work->input.ordinal.frameIndex.peeku());
+    // If input buffer list is not empty, it means we have some input to process
+    // on. However, input could be a null buffer. In such case, clear the buffer
+    // list before making call to process().
+    if (!work->input.buffers.empty() && !work->input.buffers[0]) {
+        ALOGD("Encountered null input buffer. Clearing the input buffer");
+        work->input.buffers.clear();
+    }
+    process(work, mOutputBlockPool);
+    DDD("processed frame #%" PRIu64, work->input.ordinal.frameIndex.peeku());
+    Mutexed<WorkQueue>::Locked queue(mWorkQueue);
+    if (queue->generation() != generation) {
+        ALOGD("work form old generation: was %" PRIu64 " now %" PRIu64,
+              queue->generation(), generation);
+        work->result = C2_NOT_FOUND;
+        queue.unlock();
+
+        Mutexed<ExecState>::Locked state(mExecState);
+        std::shared_ptr<C2Component::Listener> listener = state->mListener;
+        state.unlock();
+        listener->onWorkDone_nb(shared_from_this(), vec(work));
+        return hasQueuedWork;
+    }
+    if (work->workletsProcessed != 0u) {
+        queue.unlock();
+        Mutexed<ExecState>::Locked state(mExecState);
+        DDD("returning this work");
+        std::shared_ptr<C2Component::Listener> listener = state->mListener;
+        state.unlock();
+        listener->onWorkDone_nb(shared_from_this(), vec(work));
+    } else {
+        work->input.buffers.clear();
+        std::unique_ptr<C2Work> unexpected;
+
+        uint64_t frameIndex = work->input.ordinal.frameIndex.peeku();
+        DDD("queue pending work %" PRIu64, frameIndex);
+        if (queue->pending().count(frameIndex) != 0) {
+            unexpected = std::move(queue->pending().at(frameIndex));
+            queue->pending().erase(frameIndex);
+        }
+        (void)queue->pending().insert({frameIndex, std::move(work)});
+
+        queue.unlock();
+        if (unexpected) {
+            ALOGD("unexpected pending work");
+            unexpected->result = C2_CORRUPTED;
+            Mutexed<ExecState>::Locked state(mExecState);
+            std::shared_ptr<C2Component::Listener> listener = state->mListener;
+            state.unlock();
+            listener->onWorkDone_nb(shared_from_this(), vec(unexpected));
+        }
+    }
+    return hasQueuedWork;
+}
+
+std::shared_ptr<C2Buffer> SimpleC2Component::createLinearBuffer(
+    const std::shared_ptr<C2LinearBlock> &block) {
+    return createLinearBuffer(block, block->offset(), block->size());
+}
+
+std::shared_ptr<C2Buffer> SimpleC2Component::createLinearBuffer(
+    const std::shared_ptr<C2LinearBlock> &block, size_t offset, size_t size) {
+    return C2Buffer::CreateLinearBuffer(
+        block->share(offset, size, ::C2Fence()));
+}
+
+std::shared_ptr<C2Buffer> SimpleC2Component::createGraphicBuffer(
+    const std::shared_ptr<C2GraphicBlock> &block) {
+    return createGraphicBuffer(block, C2Rect(block->width(), block->height()));
+}
+
+std::shared_ptr<C2Buffer> SimpleC2Component::createGraphicBuffer(
+    const std::shared_ptr<C2GraphicBlock> &block, const C2Rect &crop) {
+    return C2Buffer::CreateGraphicBuffer(block->share(crop, ::C2Fence()));
+}
+
+} // namespace android
diff --git a/codecs/c2/decoders/base/SimpleC2Interface.cpp b/codecs/c2/decoders/base/SimpleC2Interface.cpp
new file mode 100644
index 00000000..5e18da95
--- /dev/null
+++ b/codecs/c2/decoders/base/SimpleC2Interface.cpp
@@ -0,0 +1,349 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+//#define LOG_NDEBUG 0
+#define LOG_TAG "SimpleC2Interface"
+#include <utils/Log.h>
+
+// use MediaDefs here vs. MediaCodecConstants as this is not MediaCodec
+// specific/dependent
+#include <media/stagefright/foundation/MediaDefs.h>
+
+#include <C2PlatformSupport.h>
+#include <SimpleC2Interface.h>
+
+namespace android {
+
+/* SimpleInterface */
+
+static C2R SubscribedParamIndicesSetter(
+        bool mayBlock, C2InterfaceHelper::C2P<C2SubscribedParamIndicesTuning> &me) {
+    (void)mayBlock;
+    (void)me;
+
+    return C2R::Ok();
+}
+
+SimpleInterface<void>::BaseParams::BaseParams(
+    const std::shared_ptr<C2ReflectorHelper> &reflector, C2String name,
+    C2Component::kind_t kind, C2Component::domain_t domain, C2String mediaType,
+    std::vector<C2String> aliases)
+    : C2InterfaceHelper(reflector) {
+    setDerivedInstance(this);
+
+    /*
+    addParameter(
+        DefineParam(mApiFeatures, C2_PARAMKEY_API_FEATURES)
+            .withConstValue(new C2ApiFeaturesSetting(C2Config::api_feature_t(
+                API_REFLECTION | API_VALUES | API_CURRENT_VALUES |
+                API_DEPENDENCY | API_SAME_INPUT_BUFFER)))
+            .build());
+*/
+
+    addParameter(DefineParam(mName, C2_PARAMKEY_COMPONENT_NAME)
+                     .withConstValue(AllocSharedString<C2ComponentNameSetting>(
+                         name.c_str()))
+                     .build());
+
+    if (aliases.size()) {
+        C2String joined;
+        for (const C2String &alias : aliases) {
+            if (joined.length()) {
+                joined += ",";
+            }
+            joined += alias;
+        }
+        addParameter(
+            DefineParam(mAliases, C2_PARAMKEY_COMPONENT_ALIASES)
+                .withConstValue(AllocSharedString<C2ComponentAliasesSetting>(
+                    joined.c_str()))
+                .build());
+    }
+
+    addParameter(DefineParam(mKind, C2_PARAMKEY_COMPONENT_KIND)
+                     .withConstValue(new C2ComponentKindSetting(kind))
+                     .build());
+
+    addParameter(DefineParam(mDomain, C2_PARAMKEY_COMPONENT_DOMAIN)
+                     .withConstValue(new C2ComponentDomainSetting(domain))
+                     .build());
+
+    // simple interfaces have single streams
+    addParameter(DefineParam(mInputStreamCount, C2_PARAMKEY_INPUT_STREAM_COUNT)
+                     .withConstValue(new C2PortStreamCountTuning::input(1))
+                     .build());
+
+    addParameter(
+        DefineParam(mOutputStreamCount, C2_PARAMKEY_OUTPUT_STREAM_COUNT)
+            .withConstValue(new C2PortStreamCountTuning::output(1))
+            .build());
+
+    // set up buffer formats and allocators
+
+    // default to linear buffers and no media type
+    C2BufferData::type_t rawBufferType = C2BufferData::LINEAR;
+    C2String rawMediaType;
+    C2Allocator::id_t rawAllocator = C2AllocatorStore::DEFAULT_LINEAR;
+    C2BlockPool::local_id_t rawPoolId = C2BlockPool::BASIC_LINEAR;
+    C2BufferData::type_t codedBufferType = C2BufferData::LINEAR;
+    int poolMask = GetCodec2PoolMask();
+    C2Allocator::id_t preferredLinearId =
+        GetPreferredLinearAllocatorId(poolMask);
+    C2Allocator::id_t codedAllocator = preferredLinearId;
+    C2BlockPool::local_id_t codedPoolId = C2BlockPool::BASIC_LINEAR;
+
+    switch (domain) {
+    case C2Component::DOMAIN_IMAGE:
+        [[fallthrough]];
+    case C2Component::DOMAIN_VIDEO:
+        // TODO: should we define raw image? The only difference is timestamp
+        // handling
+        rawBufferType = C2BufferData::GRAPHIC;
+        rawMediaType = MEDIA_MIMETYPE_VIDEO_RAW;
+        rawAllocator = C2PlatformAllocatorStore::GRALLOC;
+        rawPoolId = C2BlockPool::BASIC_GRAPHIC;
+        break;
+    case C2Component::DOMAIN_AUDIO:
+        rawBufferType = C2BufferData::LINEAR;
+        rawMediaType = MEDIA_MIMETYPE_AUDIO_RAW;
+        rawAllocator = preferredLinearId;
+        rawPoolId = C2BlockPool::BASIC_LINEAR;
+        break;
+    default:
+        break;
+    }
+    bool isEncoder = kind == C2Component::KIND_ENCODER;
+
+    // handle raw decoders
+    if (mediaType == rawMediaType) {
+        codedBufferType = rawBufferType;
+        codedAllocator = rawAllocator;
+        codedPoolId = rawPoolId;
+    }
+
+    addParameter(DefineParam(mInputFormat, C2_PARAMKEY_INPUT_STREAM_BUFFER_TYPE)
+                     .withConstValue(new C2StreamBufferTypeSetting::input(
+                         0u, isEncoder ? rawBufferType : codedBufferType))
+                     .build());
+
+    addParameter(
+        DefineParam(mInputMediaType, C2_PARAMKEY_INPUT_MEDIA_TYPE)
+            .withConstValue(AllocSharedString<C2PortMediaTypeSetting::input>(
+                isEncoder ? rawMediaType : mediaType))
+            .build());
+
+    addParameter(
+        DefineParam(mOutputFormat, C2_PARAMKEY_OUTPUT_STREAM_BUFFER_TYPE)
+            .withConstValue(new C2StreamBufferTypeSetting::output(
+                0u, isEncoder ? codedBufferType : rawBufferType))
+            .build());
+
+    addParameter(
+        DefineParam(mOutputMediaType, C2_PARAMKEY_OUTPUT_MEDIA_TYPE)
+            .withConstValue(AllocSharedString<C2PortMediaTypeSetting::output>(
+                isEncoder ? mediaType : rawMediaType))
+            .build());
+
+    C2Allocator::id_t inputAllocators[1] = {isEncoder ? rawAllocator
+                                                      : codedAllocator};
+    C2Allocator::id_t outputAllocators[1] = {isEncoder ? codedAllocator
+                                                       : rawAllocator};
+    C2BlockPool::local_id_t outputPoolIds[1] = {isEncoder ? codedPoolId
+                                                          : rawPoolId};
+
+    addParameter(
+        DefineParam(mInputAllocators, C2_PARAMKEY_INPUT_ALLOCATORS)
+            .withDefault(
+                C2PortAllocatorsTuning::input::AllocShared(inputAllocators))
+            .withFields({C2F(mInputAllocators, m.values[0]).any(),
+                         C2F(mInputAllocators, m.values).inRange(0, 1)})
+            .withSetter(
+                Setter<
+                    C2PortAllocatorsTuning::input>::NonStrictValuesWithNoDeps)
+            .build());
+
+    addParameter(
+        DefineParam(mOutputAllocators, C2_PARAMKEY_OUTPUT_ALLOCATORS)
+            .withDefault(
+                C2PortAllocatorsTuning::output::AllocShared(outputAllocators))
+            .withFields({C2F(mOutputAllocators, m.values[0]).any(),
+                         C2F(mOutputAllocators, m.values).inRange(0, 1)})
+            .withSetter(
+                Setter<
+                    C2PortAllocatorsTuning::output>::NonStrictValuesWithNoDeps)
+            .build());
+
+    addParameter(
+        DefineParam(mOutputPoolIds, C2_PARAMKEY_OUTPUT_BLOCK_POOLS)
+            .withDefault(
+                C2PortBlockPoolsTuning::output::AllocShared(outputPoolIds))
+            .withFields({C2F(mOutputPoolIds, m.values[0]).any(),
+                         C2F(mOutputPoolIds, m.values).inRange(0, 1)})
+            .withSetter(
+                Setter<
+                    C2PortBlockPoolsTuning::output>::NonStrictValuesWithNoDeps)
+            .build());
+
+    // add stateless params
+    addParameter(
+        DefineParam(mSubscribedParamIndices,
+                    C2_PARAMKEY_SUBSCRIBED_PARAM_INDICES)
+            .withDefault(C2SubscribedParamIndicesTuning::AllocShared(0u))
+            .withFields({C2F(mSubscribedParamIndices, m.values[0]).any(),
+                         C2F(mSubscribedParamIndices, m.values).any()})
+            .withSetter(SubscribedParamIndicesSetter)
+            .build());
+
+    /* TODO
+
+    addParameter(
+            DefineParam(mCurrentWorkOrdinal, C2_PARAMKEY_CURRENT_WORK)
+            .withDefault(new C2CurrentWorkTuning())
+            .withFields({ C2F(mCurrentWorkOrdinal, m.timeStamp).any(),
+                          C2F(mCurrentWorkOrdinal, m.frameIndex).any(),
+                          C2F(mCurrentWorkOrdinal, m.customOrdinal).any() })
+            .withSetter(Setter<C2CurrentWorkTuning>::NonStrictValuesWithNoDeps)
+            .build());
+
+    addParameter(
+            DefineParam(mLastInputQueuedWorkOrdinal,
+    C2_PARAMKEY_LAST_INPUT_QUEUED) .withDefault(new
+    C2LastWorkQueuedTuning::input()) .withFields({
+    C2F(mLastInputQueuedWorkOrdinal, m.timeStamp).any(),
+                          C2F(mLastInputQueuedWorkOrdinal, m.frameIndex).any(),
+                          C2F(mLastInputQueuedWorkOrdinal,
+    m.customOrdinal).any() })
+            .withSetter(Setter<C2LastWorkQueuedTuning::input>::NonStrictValuesWithNoDeps)
+            .build());
+
+    addParameter(
+            DefineParam(mLastOutputQueuedWorkOrdinal,
+    C2_PARAMKEY_LAST_OUTPUT_QUEUED) .withDefault(new
+    C2LastWorkQueuedTuning::output()) .withFields({
+    C2F(mLastOutputQueuedWorkOrdinal, m.timeStamp).any(),
+                          C2F(mLastOutputQueuedWorkOrdinal, m.frameIndex).any(),
+                          C2F(mLastOutputQueuedWorkOrdinal,
+    m.customOrdinal).any() })
+            .withSetter(Setter<C2LastWorkQueuedTuning::output>::NonStrictValuesWithNoDeps)
+            .build());
+
+    std::shared_ptr<C2OutOfMemoryTuning> mOutOfMemory;
+
+    std::shared_ptr<C2PortConfigCounterTuning::input> mInputConfigCounter;
+    std::shared_ptr<C2PortConfigCounterTuning::output> mOutputConfigCounter;
+    std::shared_ptr<C2ConfigCounterTuning> mDirectConfigCounter;
+
+    */
+}
+
+void SimpleInterface<void>::BaseParams::noInputLatency() {
+    addParameter(
+        DefineParam(mRequestedInputDelay, C2_PARAMKEY_INPUT_DELAY_REQUEST)
+            .withConstValue(new C2PortRequestedDelayTuning::input(0u))
+            .build());
+
+    addParameter(DefineParam(mActualInputDelay, C2_PARAMKEY_INPUT_DELAY)
+                     .withConstValue(new C2PortActualDelayTuning::input(0u))
+                     .build());
+}
+
+void SimpleInterface<void>::BaseParams::noOutputLatency() {
+    addParameter(
+        DefineParam(mRequestedOutputDelay, C2_PARAMKEY_OUTPUT_DELAY_REQUEST)
+            .withConstValue(new C2PortRequestedDelayTuning::output(0u))
+            .build());
+
+    addParameter(DefineParam(mActualOutputDelay, C2_PARAMKEY_OUTPUT_DELAY)
+                     .withConstValue(new C2PortActualDelayTuning::output(0u))
+                     .build());
+}
+
+void SimpleInterface<void>::BaseParams::noPipelineLatency() {
+    addParameter(
+        DefineParam(mRequestedPipelineDelay, C2_PARAMKEY_PIPELINE_DELAY_REQUEST)
+            .withConstValue(new C2RequestedPipelineDelayTuning(0u))
+            .build());
+
+    addParameter(DefineParam(mActualPipelineDelay, C2_PARAMKEY_PIPELINE_DELAY)
+                     .withConstValue(new C2ActualPipelineDelayTuning(0u))
+                     .build());
+}
+
+void SimpleInterface<void>::BaseParams::noPrivateBuffers() {
+    addParameter(DefineParam(mPrivateAllocators, C2_PARAMKEY_PRIVATE_ALLOCATORS)
+                     .withConstValue(C2PrivateAllocatorsTuning::AllocShared(0u))
+                     .build());
+
+    addParameter(
+        DefineParam(mMaxPrivateBufferCount,
+                    C2_PARAMKEY_MAX_PRIVATE_BUFFER_COUNT)
+            .withConstValue(C2MaxPrivateBufferCountTuning::AllocShared(0u))
+            .build());
+
+    addParameter(DefineParam(mPrivatePoolIds, C2_PARAMKEY_PRIVATE_BLOCK_POOLS)
+                     .withConstValue(C2PrivateBlockPoolsTuning::AllocShared(0u))
+                     .build());
+}
+
+void SimpleInterface<void>::BaseParams::noInputReferences() {
+    addParameter(
+        DefineParam(mMaxInputReferenceAge, C2_PARAMKEY_INPUT_MAX_REFERENCE_AGE)
+            .withConstValue(new C2StreamMaxReferenceAgeTuning::input(0u))
+            .build());
+
+    addParameter(
+        DefineParam(mMaxInputReferenceCount,
+                    C2_PARAMKEY_INPUT_MAX_REFERENCE_COUNT)
+            .withConstValue(new C2StreamMaxReferenceCountTuning::input(0u))
+            .build());
+}
+
+void SimpleInterface<void>::BaseParams::noOutputReferences() {
+    addParameter(
+        DefineParam(mMaxOutputReferenceAge,
+                    C2_PARAMKEY_OUTPUT_MAX_REFERENCE_AGE)
+            .withConstValue(new C2StreamMaxReferenceAgeTuning::output(0u))
+            .build());
+
+    addParameter(
+        DefineParam(mMaxOutputReferenceCount,
+                    C2_PARAMKEY_OUTPUT_MAX_REFERENCE_COUNT)
+            .withConstValue(new C2StreamMaxReferenceCountTuning::output(0u))
+            .build());
+}
+
+void SimpleInterface<void>::BaseParams::noTimeStretch() {
+    addParameter(DefineParam(mTimeStretch, C2_PARAMKEY_TIME_STRETCH)
+                     .withConstValue(new C2ComponentTimeStretchTuning(1.f))
+                     .build());
+}
+
+/*
+    Clients need to handle the following base params due to custom dependency.
+
+    std::shared_ptr<C2ApiLevelSetting> mApiLevel;
+    std::shared_ptr<C2ComponentAttributesSetting> mAttrib;
+
+    std::shared_ptr<C2PortSuggestedBufferCountTuning::input>
+   mSuggestedInputBufferCount;
+    std::shared_ptr<C2PortSuggestedBufferCountTuning::output>
+   mSuggestedOutputBufferCount;
+
+    std::shared_ptr<C2TrippedTuning> mTripped;
+
+*/
+
+} // namespace android
diff --git a/codecs/c2/decoders/base/color_buffer_utils.cpp b/codecs/c2/decoders/base/color_buffer_utils.cpp
new file mode 100644
index 00000000..86c6eff5
--- /dev/null
+++ b/codecs/c2/decoders/base/color_buffer_utils.cpp
@@ -0,0 +1,141 @@
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
+#include <inttypes.h>
+#include <android-base/parseint.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+#include <log/log.h>
+#include <gralloc_cb_bp.h>
+#include <xf86drm.h>
+
+#include <C2AllocatorGralloc.h>
+
+#include "cros_gralloc_handle.h"
+#include "virtgpu_drm.h"
+
+static bool isMinigbmFromProperty() {
+  static constexpr const auto kGrallocProp = "ro.hardware.gralloc";
+
+  const auto grallocProp = android::base::GetProperty(kGrallocProp, "");
+  ALOGD("%s:codecs: minigbm query prop value is: %s", __FUNCTION__, grallocProp.c_str());
+
+  if (grallocProp == "minigbm") {
+    ALOGD("%s:codecs: Using minigbm, in minigbm mode.\n", __FUNCTION__);
+    return true;
+  } else {
+    ALOGD("%s:codecs: Is not using minigbm, in goldfish mode.\n", __FUNCTION__);
+    return false;
+  }
+}
+
+class ColorBufferUtilsGlobalState {
+public:
+    ColorBufferUtilsGlobalState() {
+        m_isMinigbm = isMinigbmFromProperty();
+
+        if (m_isMinigbm) {
+            static constexpr int kRendernodeMinor = 128;
+            m_rendernodeFd = drmOpenRender(kRendernodeMinor);
+        }
+    }
+
+    uint32_t getColorBufferHandle(native_handle_t const* handle) {
+        if (m_isMinigbm) {
+            struct drm_virtgpu_resource_info info;
+            if (!getResInfo(handle, &info)) {
+                ALOGE("%s: Error gtting color buffer handle (minigbm case)", __func__);
+                return -1;
+            }
+            return info.res_handle;
+        } else {
+            return cb_handle_t::from(handle)->hostHandle;
+        }
+    }
+
+    uint64_t getClientUsage(const std::shared_ptr<C2BlockPool> &pool) {
+        std::shared_ptr<C2GraphicBlock> myOutBlock;
+        const C2MemoryUsage usage = {0, 0};
+        const uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
+        pool->fetchGraphicBlock(2, 2, format, usage, &myOutBlock);
+        auto myc2Handle = myOutBlock->handle();
+        native_handle_t *mygrallocHandle =
+        android::UnwrapNativeCodec2GrallocHandle(myc2Handle);
+        if (m_isMinigbm) {
+            cros_gralloc_handle const* cros_handle =
+                reinterpret_cast<cros_gralloc_handle const*>(mygrallocHandle);
+            return cros_handle->usage;
+        } else {
+            cb_handle_t* mycb = (cb_handle_t*)(mygrallocHandle);
+            return mycb->usage;
+        }
+    }
+
+private:
+
+    bool getResInfo(native_handle_t const* handle,
+                    struct drm_virtgpu_resource_info* info) {
+        memset(info, 0x0, sizeof(*info));
+        if (m_rendernodeFd < 0) {
+            ALOGE("%s: Error, rendernode fd missing\n", __func__);
+            return false;
+        }
+
+        struct drm_gem_close gem_close;
+        memset(&gem_close, 0x0, sizeof(gem_close));
+
+        cros_gralloc_handle const* cros_handle =
+            reinterpret_cast<cros_gralloc_handle const*>(handle);
+
+        uint32_t prime_handle;
+        int ret = drmPrimeFDToHandle(m_rendernodeFd, cros_handle->fds[0], &prime_handle);
+        if (ret) {
+            ALOGE("%s: DRM_IOCTL_PRIME_FD_TO_HANDLE failed: %s (errno %d)\n",
+                  __func__, strerror(errno), errno);
+            return false;
+        }
+
+        info->bo_handle = prime_handle;
+        gem_close.handle = prime_handle;
+
+        ret = drmIoctl(m_rendernodeFd, DRM_IOCTL_VIRTGPU_RESOURCE_INFO, info);
+        if (ret) {
+            ALOGE("%s: DRM_IOCTL_VIRTGPU_RESOURCE_INFO failed: %s (errno %d)\n",
+                  __func__, strerror(errno), errno);
+            drmIoctl(m_rendernodeFd, DRM_IOCTL_GEM_CLOSE, &gem_close);
+            return false;
+        }
+
+        drmIoctl(m_rendernodeFd, DRM_IOCTL_GEM_CLOSE, &gem_close);
+        return true;
+    }
+
+    bool m_isMinigbm;
+    int m_rendernodeFd = -1; // to be closed when this process dies
+};
+
+static ColorBufferUtilsGlobalState* getGlobals() {
+    static ColorBufferUtilsGlobalState* globals = new ColorBufferUtilsGlobalState;
+    return globals;
+}
+
+uint32_t getColorBufferHandle(native_handle_t const* handle) {
+    return getGlobals()->getColorBufferHandle(handle);
+}
+
+uint64_t getClientUsage(const std::shared_ptr<C2BlockPool> &pool) {
+    return getGlobals()->getClientUsage(pool);
+}
+
diff --git a/codecs/c2/decoders/base/cros_gralloc_handle.h b/codecs/c2/decoders/base/cros_gralloc_handle.h
new file mode 100644
index 00000000..2b70d4ba
--- /dev/null
+++ b/codecs/c2/decoders/base/cros_gralloc_handle.h
@@ -0,0 +1,51 @@
+/*
+ * Copyright 2016 The Chromium OS Authors. All rights reserved.
+ * Use of this source code is governed by a BSD-style license that can be
+ * found in the LICENSE file.
+ */
+
+#ifndef CROS_GRALLOC_HANDLE_H
+#define CROS_GRALLOC_HANDLE_H
+
+#include <cstdint>
+#include <cutils/native_handle.h>
+
+#define DRV_MAX_PLANES 4
+#define DRV_MAX_FDS (DRV_MAX_PLANES + 1)
+
+struct cros_gralloc_handle : public native_handle_t {
+	/*
+	 * File descriptors must immediately follow the native_handle_t base and used file
+	 * descriptors must be packed at the beginning of this array to work with
+	 * native_handle_clone().
+	 *
+	 * This field contains 'num_planes' plane file descriptors followed by an optional metadata
+	 * reserved region file descriptor if 'reserved_region_size' is greater than zero.
+	 */
+	int32_t fds[DRV_MAX_FDS];
+	uint32_t strides[DRV_MAX_PLANES];
+	uint32_t offsets[DRV_MAX_PLANES];
+	uint32_t sizes[DRV_MAX_PLANES];
+	uint32_t id;
+	uint32_t width;
+	uint32_t height;
+	uint32_t format; /* DRM format */
+	uint32_t tiling;
+	uint64_t format_modifier;
+	uint64_t use_flags; /* Buffer creation flags */
+	uint32_t magic;
+	uint32_t pixel_stride;
+	int32_t droid_format;
+	int32_t usage; /* Android usage. */
+	uint32_t num_planes;
+	uint64_t reserved_region_size;
+	uint64_t total_size; /* Total allocation size */
+	/*
+	 * Name is a null terminated char array located at handle->base.data[handle->name_offset].
+	 */
+	uint32_t name_offset;
+} __attribute__((packed));
+
+typedef const struct cros_gralloc_handle *cros_gralloc_handle_t;
+
+#endif
diff --git a/codecs/c2/decoders/base/exports.lds b/codecs/c2/decoders/base/exports.lds
new file mode 100644
index 00000000..641bae88
--- /dev/null
+++ b/codecs/c2/decoders/base/exports.lds
@@ -0,0 +1,7 @@
+{
+    global:
+        CreateCodec2Factory;
+        DestroyCodec2Factory;
+    local: *;
+};
+
diff --git a/codecs/c2/decoders/base/goldfish_media_utils.cpp b/codecs/c2/decoders/base/goldfish_media_utils.cpp
new file mode 100644
index 00000000..8013fe03
--- /dev/null
+++ b/codecs/c2/decoders/base/goldfish_media_utils.cpp
@@ -0,0 +1,227 @@
+// Copyright 2018 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+// http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "goldfish_media_utils.h"
+
+#include "goldfish_address_space.h"
+
+#include <log/log.h>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+#include <memory>
+#include <mutex>
+#include <vector>
+
+std::mutex sSingletonMutex;
+std::unique_ptr<GoldfishMediaTransport> sTransport;
+
+class GoldfishMediaTransportImpl : public GoldfishMediaTransport {
+  public:
+    GoldfishMediaTransportImpl();
+    ~GoldfishMediaTransportImpl();
+
+    virtual void writeParam(__u64 val, unsigned int num,
+                            unsigned int offSetToStartAddr = 0) override;
+    virtual bool sendOperation(MediaCodecType type, MediaOperation op,
+                               unsigned int offSetToStartAddr = 0) override;
+    virtual uint8_t *getBaseAddr() const override;
+    virtual uint8_t *getInputAddr(unsigned int offSet = 0) const override;
+    virtual uint8_t *getOutputAddr() const override;
+    virtual uint8_t *getReturnAddr(unsigned int offSet = 0) const override;
+    virtual __u64 offsetOf(uint64_t addr) const override;
+
+  public:
+    // each lot has 2 M
+    virtual int getMemorySlot() override {
+        std::lock_guard<std::mutex> g{mMemoryMutex};
+        // when there are just 1 decoder, it can pretty
+        // much use all the memory starting from 0;
+        // when there are two, each can use at least half
+        // the total memory, etc.
+        constexpr size_t search_order[] = {
+            0,                              // use 32M
+            16,                             // use 16M
+            8,  24,                         // use 8M
+            4,  12, 20, 28,                 // use 4M
+            2,  6,  10, 12, 18, 22, 26, 30, // use 2M
+            1,  3,  5,  7,  9,  11, 13, 15,
+            17, 19, 21, 23, 25, 27, 29, 31 // use 1M
+        };
+        for (size_t i = 0; i < sizeof(search_order) / sizeof(search_order[0]);
+             ++i) {
+            int slot = search_order[i];
+            if (mMemoryLotsAvailable[slot]) {
+                mMemoryLotsAvailable[slot] = false;
+                return slot;
+            }
+        }
+        return -1;
+    }
+    virtual void returnMemorySlot(int lot) override {
+        if (lot < 0 || lot >= mMemoryLotsAvailable.size()) {
+            return;
+        }
+        std::lock_guard<std::mutex> g{mMemoryMutex};
+        if (mMemoryLotsAvailable[lot] == false) {
+            mMemoryLotsAvailable[lot] = true;
+        } else {
+            ALOGE("Error, cannot twice");
+        }
+    }
+
+  private:
+    std::mutex mMemoryMutex;
+    std::vector<bool> mMemoryLotsAvailable = std::vector<bool>(32, true);
+
+    address_space_handle_t mHandle;
+    uint64_t mOffset;
+    uint64_t mPhysAddr;
+    uint64_t mSize;
+    void *mStartPtr = nullptr;
+
+    // MediaCodecType will be or'd together with the metadata, so the highest
+    // 8-bits will have the type.
+    static __u64 makeMetadata(MediaCodecType type, MediaOperation op,
+                              uint64_t offset);
+
+    // Chunk size for parameters/return data
+    static constexpr size_t kParamSizeBytes = 4096; // 4K
+    // Chunk size for input
+    static constexpr size_t kInputSizeBytes = 4096 * 4096; // 16M
+    // Chunk size for output
+    static constexpr size_t kOutputSizeBytes = 4096 * 4096; // 16M
+    // Maximum number of parameters that can be passed
+    static constexpr size_t kMaxParams = 32;
+    // Offset from the memory region for return data (8 is size of
+    // a parameter in bytes)
+    static constexpr size_t kReturnOffset = 8 * kMaxParams;
+};
+
+GoldfishMediaTransportImpl::~GoldfishMediaTransportImpl() {
+    if (mHandle >= 0) {
+        goldfish_address_space_close(mHandle);
+        mHandle = -1;
+    }
+}
+
+GoldfishMediaTransportImpl::GoldfishMediaTransportImpl() {
+    // Allocate host memory; the contiguous memory region will be laid out as
+    // follows:
+    // ========================================================
+    // | kParamSizeBytes | kInputSizeBytes | kOutputSizeBytes |
+    // ========================================================
+    mHandle = goldfish_address_space_open();
+    if (mHandle < 0) {
+        ALOGE("Failed to ping host to allocate memory");
+        abort();
+    }
+    mSize = kParamSizeBytes + kInputSizeBytes + kOutputSizeBytes;
+    bool success =
+        goldfish_address_space_allocate(mHandle, mSize, &mPhysAddr, &mOffset);
+    if (success) {
+        ALOGI("successfully allocated %d bytes in goldfish_address_block",
+              (int)mSize);
+        mStartPtr = goldfish_address_space_map(mHandle, mOffset, mSize);
+        ALOGI("guest address is %p", mStartPtr);
+
+        struct address_space_ping pingInfo;
+        pingInfo.metadata = GoldfishAddressSpaceSubdeviceType::Media;
+        pingInfo.offset = mOffset;
+        if (goldfish_address_space_ping(mHandle, &pingInfo) == false) {
+            ALOGE("Failed to ping host to allocate memory");
+            abort();
+            return;
+        } else {
+            ALOGI("successfully pinged host to allocate memory");
+        }
+    } else {
+        ALOGE("failed to allocate %d bytes in goldfish_address_block",
+              (int)mSize);
+        abort();
+    }
+}
+
+// static
+GoldfishMediaTransport *GoldfishMediaTransport::getInstance() {
+    std::lock_guard<std::mutex> g{sSingletonMutex};
+    if (sTransport == nullptr) {
+        sTransport.reset(new GoldfishMediaTransportImpl());
+    }
+    return sTransport.get();
+}
+
+// static
+__u64 GoldfishMediaTransportImpl::makeMetadata(MediaCodecType type,
+                                               MediaOperation op,
+                                               uint64_t offset) {
+    // Shift |type| into the highest 8-bits, leaving the lower bits for other
+    // metadata.
+    offset = offset >> 20;
+    if (offset < 0 || offset >= 32) {
+        ALOGE("offset %d is wrong", (int)offset);
+        abort();
+    }
+    return ((__u64)type << (64 - 8)) | (offset << 8) | static_cast<uint8_t>(op);
+}
+
+uint8_t *GoldfishMediaTransportImpl::getInputAddr(unsigned int offSet) const {
+    return (uint8_t *)mStartPtr + kParamSizeBytes + offSet;
+}
+
+uint8_t *GoldfishMediaTransportImpl::getOutputAddr() const {
+    return getInputAddr() + kInputSizeBytes;
+}
+
+uint8_t *GoldfishMediaTransportImpl::getBaseAddr() const {
+    return (uint8_t *)mStartPtr;
+}
+
+uint8_t *GoldfishMediaTransportImpl::getReturnAddr(unsigned int offSet) const {
+    return (uint8_t *)mStartPtr + kReturnOffset + offSet;
+}
+
+__u64 GoldfishMediaTransportImpl::offsetOf(uint64_t addr) const {
+    return addr - (uint64_t)mStartPtr;
+}
+
+void GoldfishMediaTransportImpl::writeParam(__u64 val, unsigned int num,
+                                            unsigned int offSetToStartAddr) {
+    uint8_t *p = (uint8_t *)mStartPtr + (offSetToStartAddr);
+    uint64_t *pint = (uint64_t *)(p + 8 * num);
+    *pint = val;
+}
+
+bool GoldfishMediaTransportImpl::sendOperation(MediaCodecType type,
+                                               MediaOperation op,
+                                               unsigned int offSetToStartAddr) {
+    struct address_space_ping pingInfo;
+    pingInfo.metadata = makeMetadata(type, op, offSetToStartAddr);
+    pingInfo.offset = mOffset; // + (offSetToStartAddr);
+    if (goldfish_address_space_ping(mHandle, &pingInfo) == false) {
+        ALOGE("failed to ping host");
+        abort();
+        return false;
+    } else {
+        DDD("successfully pinged host for operation type=%d, op=%d", (int)type,
+            (int)op);
+    }
+
+    return true;
+}
diff --git a/codecs/c2/decoders/base/include/SimpleC2Component.h b/codecs/c2/decoders/base/include/SimpleC2Component.h
new file mode 100644
index 00000000..2c960a7e
--- /dev/null
+++ b/codecs/c2/decoders/base/include/SimpleC2Component.h
@@ -0,0 +1,254 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+#ifndef SIMPLE_C2_COMPONENT_H_
+#define SIMPLE_C2_COMPONENT_H_
+
+#include <list>
+#include <unordered_map>
+
+#include <C2Component.h>
+
+#include <media/stagefright/foundation/AHandler.h>
+#include <media/stagefright/foundation/ALooper.h>
+#include <media/stagefright/foundation/Mutexed.h>
+
+namespace android {
+
+class SimpleC2Component
+    : public C2Component,
+      public std::enable_shared_from_this<SimpleC2Component> {
+  public:
+    explicit SimpleC2Component(
+        const std::shared_ptr<C2ComponentInterface> &intf);
+    virtual ~SimpleC2Component();
+
+    // C2Component
+    // From C2Component
+    virtual c2_status_t
+    setListener_vb(const std::shared_ptr<Listener> &listener,
+                   c2_blocking_t mayBlock) override;
+    virtual c2_status_t
+    queue_nb(std::list<std::unique_ptr<C2Work>> *const items) override;
+    virtual c2_status_t
+    announce_nb(const std::vector<C2WorkOutline> &items) override;
+    virtual c2_status_t
+    flush_sm(flush_mode_t mode,
+             std::list<std::unique_ptr<C2Work>> *const flushedWork) override;
+    virtual c2_status_t drain_nb(drain_mode_t mode) override;
+    virtual c2_status_t start() override;
+    virtual c2_status_t stop() override;
+    virtual c2_status_t reset() override;
+    virtual c2_status_t release() override;
+    virtual std::shared_ptr<C2ComponentInterface> intf() override;
+
+    // for handler
+    bool processQueue();
+
+  protected:
+    /**
+     * Initialize internal states of the component according to the config set
+     * in the interface.
+     *
+     * This method is called during start(), but only at the first invocation or
+     * after reset().
+     */
+    virtual c2_status_t onInit() = 0;
+
+    /**
+     * Stop the component.
+     */
+    virtual c2_status_t onStop() = 0;
+
+    /**
+     * Reset the component.
+     */
+    virtual void onReset() = 0;
+
+    /**
+     * Release the component.
+     */
+    virtual void onRelease() = 0;
+
+    /**
+     * Flush the component.
+     */
+    virtual c2_status_t onFlush_sm() = 0;
+
+    /**
+     * Process the given work and finish pending work using finish().
+     *
+     * \param[in,out]   work    the work to process
+     * \param[in]       pool    the pool to use for allocating output blocks.
+     */
+    virtual void process(const std::unique_ptr<C2Work> &work,
+                         const std::shared_ptr<C2BlockPool> &pool) = 0;
+
+    /**
+     * Drain the component and finish pending work using finish().
+     *
+     * \param[in]   drainMode   mode of drain.
+     * \param[in]   pool        the pool to use for allocating output blocks.
+     *
+     * \retval C2_OK            The component has drained all pending output
+     *                          work.
+     * \retval C2_OMITTED       Unsupported mode (e.g. DRAIN_CHAIN)
+     */
+    virtual c2_status_t drain(uint32_t drainMode,
+                              const std::shared_ptr<C2BlockPool> &pool) = 0;
+
+    // for derived classes
+    /**
+     * Finish pending work.
+     *
+     * This method will retrieve the pending work according to |frameIndex| and
+     * feed the work into |fillWork| function. |fillWork| must be
+     * "non-blocking". Once |fillWork| returns the filled work will be returned
+     * to the client.
+     *
+     * \param[in]   frameIndex    the index of the pending work
+     * \param[in]   fillWork      the function to fill the retrieved work.
+     */
+    void finish(uint64_t frameIndex,
+                std::function<void(const std::unique_ptr<C2Work> &)> fillWork);
+
+    /**
+     * Clone pending or current work and send the work back to client.
+     *
+     * This method will retrieve and clone the pending or current work according
+     * to |frameIndex| and feed the work into |fillWork| function. |fillWork|
+     * must be "non-blocking". Once |fillWork| returns the filled work will be
+     * returned to the client.
+     *
+     * \param[in]   frameIndex    the index of the work
+     * \param[in]   currentWork   the current work under processing
+     * \param[in]   fillWork      the function to fill the retrieved work.
+     */
+    void
+    cloneAndSend(uint64_t frameIndex,
+                 const std::unique_ptr<C2Work> &currentWork,
+                 std::function<void(const std::unique_ptr<C2Work> &)> fillWork);
+
+    std::shared_ptr<C2Buffer>
+    createLinearBuffer(const std::shared_ptr<C2LinearBlock> &block);
+
+    std::shared_ptr<C2Buffer>
+    createLinearBuffer(const std::shared_ptr<C2LinearBlock> &block,
+                       size_t offset, size_t size);
+
+    std::shared_ptr<C2Buffer>
+    createGraphicBuffer(const std::shared_ptr<C2GraphicBlock> &block);
+
+    std::shared_ptr<C2Buffer>
+    createGraphicBuffer(const std::shared_ptr<C2GraphicBlock> &block,
+                        const C2Rect &crop);
+
+    static constexpr uint32_t NO_DRAIN = ~0u;
+
+    C2ReadView mDummyReadView;
+
+  private:
+    const std::shared_ptr<C2ComponentInterface> mIntf;
+
+    class WorkHandler : public AHandler {
+      public:
+        enum {
+            kWhatProcess,
+            kWhatInit,
+            kWhatStart,
+            kWhatStop,
+            kWhatReset,
+            kWhatRelease,
+        };
+
+        WorkHandler();
+        ~WorkHandler() override = default;
+
+        void setComponent(const std::shared_ptr<SimpleC2Component> &thiz);
+
+      protected:
+        void onMessageReceived(const sp<AMessage> &msg) override;
+
+      private:
+        std::weak_ptr<SimpleC2Component> mThiz;
+        bool mRunning;
+    };
+
+    enum {
+        UNINITIALIZED,
+        STOPPED,
+        RUNNING,
+    };
+
+    struct ExecState {
+        ExecState() : mState(UNINITIALIZED) {}
+
+        int mState;
+        std::shared_ptr<C2Component::Listener> mListener;
+    };
+    Mutexed<ExecState> mExecState;
+
+    sp<ALooper> mLooper;
+    sp<WorkHandler> mHandler;
+
+    class WorkQueue {
+      public:
+        typedef std::unordered_map<uint64_t, std::unique_ptr<C2Work>>
+            PendingWork;
+
+        inline WorkQueue() : mFlush(false), mGeneration(0ul) {}
+
+        inline uint64_t generation() const { return mGeneration; }
+        inline void incGeneration() {
+            ++mGeneration;
+            mFlush = true;
+        }
+
+        std::unique_ptr<C2Work> pop_front();
+        void push_back(std::unique_ptr<C2Work> work);
+        bool empty() const;
+        uint32_t drainMode() const;
+        void markDrain(uint32_t drainMode);
+        inline bool popPendingFlush() {
+            bool flush = mFlush;
+            mFlush = false;
+            return flush;
+        }
+        void clear();
+        PendingWork &pending() { return mPendingWork; }
+
+      private:
+        struct Entry {
+            std::unique_ptr<C2Work> work;
+            uint32_t drainMode;
+        };
+
+        bool mFlush;
+        uint64_t mGeneration;
+        std::list<Entry> mQueue;
+        PendingWork mPendingWork;
+    };
+    Mutexed<WorkQueue> mWorkQueue;
+
+    class BlockingBlockPool;
+    std::shared_ptr<BlockingBlockPool> mOutputBlockPool;
+
+    SimpleC2Component() = delete;
+};
+
+} // namespace android
+
+#endif // SIMPLE_C2_COMPONENT_H_
diff --git a/codecs/c2/decoders/base/include/SimpleC2Interface.h b/codecs/c2/decoders/base/include/SimpleC2Interface.h
new file mode 100644
index 00000000..5fbfa3f8
--- /dev/null
+++ b/codecs/c2/decoders/base/include/SimpleC2Interface.h
@@ -0,0 +1,246 @@
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
+
+#ifndef ANDROID_SIMPLE_C2_INTERFACE_H_
+#define ANDROID_SIMPLE_C2_INTERFACE_H_
+
+#include <C2Component.h>
+#include <C2Config.h>
+#include <util/C2InterfaceHelper.h>
+
+namespace android {
+
+/**
+ * Wrap a common interface object (such as Codec2Client::Interface, or
+ * C2InterfaceHelper into a C2ComponentInterface.
+ *
+ * \param T common interface type
+ */
+template <typename T> class SimpleC2Interface : public C2ComponentInterface {
+  public:
+    SimpleC2Interface(const char *name, c2_node_id_t id,
+                      const std::shared_ptr<T> &impl)
+        : mName(name), mId(id), mImpl(impl) {}
+
+    ~SimpleC2Interface() override = default;
+
+    // From C2ComponentInterface
+    C2String getName() const override { return mName; }
+    c2_node_id_t getId() const override { return mId; }
+    c2_status_t query_vb(const std::vector<C2Param *> &stackParams,
+                         const std::vector<C2Param::Index> &heapParamIndices,
+                         c2_blocking_t mayBlock,
+                         std::vector<std::unique_ptr<C2Param>>
+                             *const heapParams) const override {
+        return mImpl->query(stackParams, heapParamIndices, mayBlock,
+                            heapParams);
+    }
+    c2_status_t
+    config_vb(const std::vector<C2Param *> &params, c2_blocking_t mayBlock,
+              std::vector<std::unique_ptr<C2SettingResult>> *const failures)
+        override {
+        return mImpl->config(params, mayBlock, failures);
+    }
+    c2_status_t createTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
+    c2_status_t releaseTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
+    c2_status_t querySupportedParams_nb(
+        std::vector<std::shared_ptr<C2ParamDescriptor>> *const params)
+        const override {
+        return mImpl->querySupportedParams(params);
+    }
+    c2_status_t
+    querySupportedValues_vb(std::vector<C2FieldSupportedValuesQuery> &fields,
+                            c2_blocking_t mayBlock) const override {
+        return mImpl->querySupportedValues(fields, mayBlock);
+    }
+
+  private:
+    C2String mName;
+    const c2_node_id_t mId;
+    const std::shared_ptr<T> mImpl;
+};
+
+/**
+ * Utility classes for common interfaces.
+ */
+template <> class SimpleC2Interface<void> {
+  public:
+    /**
+     * Base Codec 2.0 parameters required for all components.
+     */
+    struct BaseParams : C2InterfaceHelper {
+        explicit BaseParams(
+            const std::shared_ptr<C2ReflectorHelper> &helper, C2String name,
+            C2Component::kind_t kind, C2Component::domain_t domain,
+            C2String mediaType,
+            std::vector<C2String> aliases = std::vector<C2String>());
+
+        /// Marks that this component has no input latency. Otherwise, component
+        /// must add support for C2PortRequestedDelayTuning::input and
+        /// C2PortActualDelayTuning::input.
+        void noInputLatency();
+
+        /// Marks that this component has no output latency. Otherwise,
+        /// component must add support for C2PortRequestedDelayTuning::output
+        /// and C2PortActualDelayTuning::output.
+        void noOutputLatency();
+
+        /// Marks that this component has no pipeline latency. Otherwise,
+        /// component must add support for C2RequestedPipelineDelayTuning and
+        /// C2ActualPipelineDelayTuning.
+        void noPipelineLatency();
+
+        /// Marks that this component has no need for private buffers.
+        /// Otherwise, component must add support for
+        /// C2MaxPrivateBufferCountTuning, C2PrivateAllocatorsTuning and
+        /// C2PrivateBlockPoolsTuning.
+        void noPrivateBuffers();
+
+        /// Marks that this component holds no references to input buffers.
+        /// Otherwise, component must add support for
+        /// C2StreamMaxReferenceAgeTuning::input and
+        /// C2StreamMaxReferenceCountTuning::input.
+        void noInputReferences();
+
+        /// Marks that this component holds no references to output buffers.
+        /// Otherwise, component must add support for
+        /// C2StreamMaxReferenceAgeTuning::output and
+        /// C2StreamMaxReferenceCountTuning::output.
+        void noOutputReferences();
+
+        /// Marks that this component does not stretch time. Otherwise,
+        /// component must add support for C2ComponentTimeStretchTuning.
+        void noTimeStretch();
+
+        std::shared_ptr<C2ApiLevelSetting> mApiLevel;
+        std::shared_ptr<C2ApiFeaturesSetting> mApiFeatures;
+
+        std::shared_ptr<C2PlatformLevelSetting> mPlatformLevel;
+        std::shared_ptr<C2PlatformFeaturesSetting> mPlatformFeatures;
+
+        std::shared_ptr<C2ComponentNameSetting> mName;
+        std::shared_ptr<C2ComponentAliasesSetting> mAliases;
+        std::shared_ptr<C2ComponentKindSetting> mKind;
+        std::shared_ptr<C2ComponentDomainSetting> mDomain;
+        std::shared_ptr<C2ComponentAttributesSetting> mAttrib;
+        std::shared_ptr<C2ComponentTimeStretchTuning> mTimeStretch;
+
+        std::shared_ptr<C2PortMediaTypeSetting::input> mInputMediaType;
+        std::shared_ptr<C2PortMediaTypeSetting::output> mOutputMediaType;
+        std::shared_ptr<C2StreamBufferTypeSetting::input> mInputFormat;
+        std::shared_ptr<C2StreamBufferTypeSetting::output> mOutputFormat;
+
+        std::shared_ptr<C2PortRequestedDelayTuning::input> mRequestedInputDelay;
+        std::shared_ptr<C2PortRequestedDelayTuning::output>
+            mRequestedOutputDelay;
+        std::shared_ptr<C2RequestedPipelineDelayTuning> mRequestedPipelineDelay;
+
+        std::shared_ptr<C2PortActualDelayTuning::input> mActualInputDelay;
+        std::shared_ptr<C2PortActualDelayTuning::output> mActualOutputDelay;
+        std::shared_ptr<C2ActualPipelineDelayTuning> mActualPipelineDelay;
+
+        std::shared_ptr<C2StreamMaxReferenceAgeTuning::input>
+            mMaxInputReferenceAge;
+        std::shared_ptr<C2StreamMaxReferenceCountTuning::input>
+            mMaxInputReferenceCount;
+        std::shared_ptr<C2StreamMaxReferenceAgeTuning::output>
+            mMaxOutputReferenceAge;
+        std::shared_ptr<C2StreamMaxReferenceCountTuning::output>
+            mMaxOutputReferenceCount;
+        std::shared_ptr<C2MaxPrivateBufferCountTuning> mMaxPrivateBufferCount;
+
+        std::shared_ptr<C2PortStreamCountTuning::input> mInputStreamCount;
+        std::shared_ptr<C2PortStreamCountTuning::output> mOutputStreamCount;
+
+        std::shared_ptr<C2SubscribedParamIndicesTuning> mSubscribedParamIndices;
+        std::shared_ptr<C2PortSuggestedBufferCountTuning::input>
+            mSuggestedInputBufferCount;
+        std::shared_ptr<C2PortSuggestedBufferCountTuning::output>
+            mSuggestedOutputBufferCount;
+
+        std::shared_ptr<C2CurrentWorkTuning> mCurrentWorkOrdinal;
+        std::shared_ptr<C2LastWorkQueuedTuning::input>
+            mLastInputQueuedWorkOrdinal;
+        std::shared_ptr<C2LastWorkQueuedTuning::output>
+            mLastOutputQueuedWorkOrdinal;
+
+        std::shared_ptr<C2PortAllocatorsTuning::input> mInputAllocators;
+        std::shared_ptr<C2PortAllocatorsTuning::output> mOutputAllocators;
+        std::shared_ptr<C2PrivateAllocatorsTuning> mPrivateAllocators;
+        std::shared_ptr<C2PortBlockPoolsTuning::output> mOutputPoolIds;
+        std::shared_ptr<C2PrivateBlockPoolsTuning> mPrivatePoolIds;
+
+        std::shared_ptr<C2TrippedTuning> mTripped;
+        std::shared_ptr<C2OutOfMemoryTuning> mOutOfMemory;
+
+        std::shared_ptr<C2PortConfigCounterTuning::input> mInputConfigCounter;
+        std::shared_ptr<C2PortConfigCounterTuning::output> mOutputConfigCounter;
+        std::shared_ptr<C2ConfigCounterTuning> mDirectConfigCounter;
+    };
+};
+
+template <typename T> using SimpleInterface = SimpleC2Interface<T>;
+
+template <typename T, typename... Args>
+std::shared_ptr<T> AllocSharedString(const Args(&...args), const char *str) {
+    size_t len = strlen(str) + 1;
+    std::shared_ptr<T> ret = T::AllocShared(len, args...);
+    strcpy(ret->m.value, str);
+    return ret;
+}
+
+template <typename T, typename... Args>
+std::shared_ptr<T> AllocSharedString(const Args(&...args),
+                                     const std::string &str) {
+    std::shared_ptr<T> ret = T::AllocShared(str.length() + 1, args...);
+    strcpy(ret->m.value, str.c_str());
+    return ret;
+}
+
+template <typename T> struct Setter {
+    typedef typename std::remove_reference<T>::type type;
+
+    static C2R NonStrictValueWithNoDeps(bool mayBlock,
+                                        C2InterfaceHelper::C2P<type> &me) {
+        (void)mayBlock;
+        return me.F(me.v.value).validatePossible(me.v.value);
+    }
+
+    static C2R NonStrictValuesWithNoDeps(bool mayBlock,
+                                         C2InterfaceHelper::C2P<type> &me) {
+        (void)mayBlock;
+        C2R res = C2R::Ok();
+        for (size_t ix = 0; ix < me.v.flexCount(); ++ix) {
+            res.plus(
+                me.F(me.v.m.values[ix]).validatePossible(me.v.m.values[ix]));
+        }
+        return res;
+    }
+
+    static C2R StrictValueWithNoDeps(bool mayBlock,
+                                     const C2InterfaceHelper::C2P<type> &old,
+                                     C2InterfaceHelper::C2P<type> &me) {
+        (void)mayBlock;
+        if (!me.F(me.v.value).supportsNow(me.v.value)) {
+            me.set().value = old.v.value;
+        }
+        return me.F(me.v.value).validatePossible(me.v.value);
+    }
+};
+
+} // namespace android
+
+#endif // ANDROID_SIMPLE_C2_INTERFACE_H_
diff --git a/codecs/c2/decoders/base/include/color_buffer_utils.h b/codecs/c2/decoders/base/include/color_buffer_utils.h
new file mode 100644
index 00000000..ebb8527c
--- /dev/null
+++ b/codecs/c2/decoders/base/include/color_buffer_utils.h
@@ -0,0 +1,20 @@
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
+#include <cutils/native_handle.h>
+#include <SimpleC2Interface.h>
+
+uint32_t getColorBufferHandle(native_handle_t const* handle);
+uint64_t getClientUsage(const std::shared_ptr<C2BlockPool> &pool);
diff --git a/codecs/c2/decoders/base/include/goldfish_media_utils.h b/codecs/c2/decoders/base/include/goldfish_media_utils.h
new file mode 100644
index 00000000..a45cda9f
--- /dev/null
+++ b/codecs/c2/decoders/base/include/goldfish_media_utils.h
@@ -0,0 +1,110 @@
+// Copyright 2018 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+// http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <linux/types.h>
+#include <stdint.h>
+
+#ifndef GOLDFISH_COMMON_GOLDFISH_DEFS_H
+#define GOLDFISH_COMMON_GOLDFISH_DEFS_H
+
+enum class MediaCodecType : __u8 {
+    VP8Codec = 0,
+    VP9Codec = 1,
+    H264Codec = 2,
+    HevcCodec = 3,
+    Max = 4,
+};
+
+struct MetaDataColorAspects {
+    uint64_t type = 1;
+    uint64_t primaries;
+    uint64_t range;
+    uint64_t transfer;
+};
+
+enum class MediaOperation : __u8 {
+    InitContext = 0,
+    DestroyContext = 1,
+    DecodeImage = 2,
+    GetImage = 3,
+    Flush = 4,
+    Reset = 5,
+    SendMetadata = 6,
+    Max = 7,
+};
+
+// This class will abstract away the knowledge required to send media codec data
+// to the host. The implementation should only need the following information to
+// properly send the data:
+//   1) Which codec to use (MediaCodecType)
+//   2) What operation to perform (MediaOperation)
+//
+// Example:
+//   auto transport = GoldfishMediaTransport::getInstance();
+//
+class GoldfishMediaTransport {
+  protected:
+    GoldfishMediaTransport() {}
+
+  public:
+    virtual ~GoldfishMediaTransport() {}
+
+    // Writes a parameter to send to the host. Each parameter will take up
+    // 64-bits. |val| is the value of the parameter, and |num| is the parameter
+    // number, starting from 0. If |val| is an address, wrap it around
+    // offsetOf(), e.g., writeParam(offsetOf((uint64_t)ptr), 2);
+    virtual void writeParam(__u64 val, unsigned int num,
+                            unsigned int offSetToStartAddr = 0) = 0;
+    // Send the operation to perform to the host. At the time of this call, any
+    // parameters that the host needs should have already been passed using
+    // writeParam().
+    virtual bool sendOperation(MediaCodecType codec, MediaOperation op,
+                               unsigned int offSetToStartAddr = 0) = 0;
+    // Get the address for input. This is usually given the codec context to
+    // write data into for the host to process.
+    virtual uint8_t *getInputAddr(unsigned int offSet = 0) const = 0;
+    // Get the address for base pointer
+    virtual uint8_t *getBaseAddr() const = 0;
+    // Get the address for output. This is usually given to the codec context to
+    // read data written there by the host.
+    virtual uint8_t *getOutputAddr() const = 0;
+    // Get the address for return data from the host. The guest codec
+    // implementation will have knowledge of how the return data is laid out.
+    virtual uint8_t *getReturnAddr(unsigned int offSet = 0) const = 0;
+    // Get the offset of an address relative to the starting address of the
+    // allocated memory region. Use this for passing pointers from the guest to
+    // the host, as the guest address will be translated, thus the offset is the
+    // only value of significance.
+    virtual __u64 offsetOf(uint64_t addr) const = 0;
+
+    // Get a slot of memory (8 M per slot) for use by a decoder instance.
+    // returns -1 for failure; or a slot >=0 on success.
+    // as of now, there are only 4 slots for use, each has 8 M, it is up
+    // to client on how to use it.
+    // 0th slot: [base, base+8M)
+    // ...
+    // ith slot: [base+8M*i, base+8M*(i+1))
+    virtual int getMemorySlot() = 0;
+
+    // Return a slot back to pool. the slot should be valid >=0 and less
+    // than the total size of slots. If nobody returns slot timely, the
+    // new client could get -1 from getMemorySlot()
+    virtual void returnMemorySlot(int slot) = 0;
+
+    static GoldfishMediaTransport *getInstance();
+};
+
+__u64 goldfish_create_media_metadata(MediaCodecType codecType, __u64 metadata);
+
+#endif
diff --git a/codecs/c2/decoders/hevcdec/Android.bp b/codecs/c2/decoders/hevcdec/Android.bp
new file mode 100644
index 00000000..43590377
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/Android.bp
@@ -0,0 +1,36 @@
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_library_shared {
+    name: "libcodec2_goldfish_hevcdec",
+    vendor: true,
+    defaults: [
+        "libcodec2_goldfish-defaults",
+    ],
+
+    srcs: ["C2GoldfishHevcDec.cpp",
+        "GoldfishHevcHelper.cpp",
+        "MediaHevcDecoder.cpp",
+    ],
+
+    shared_libs: [
+	    "android.hardware.graphics.allocator@3.0",
+		"android.hardware.graphics.mapper@3.0",
+        "libgoldfish_codec2_store",
+    ],
+
+   header_libs: [
+    "libgralloc_cb.ranchu",
+    ],
+
+   static_libs: ["libhevcdec",
+   ],
+
+}
+
diff --git a/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp b/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
new file mode 100644
index 00000000..3197be05
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.cpp
@@ -0,0 +1,1130 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+//#define LOG_NDEBUG 0
+#define LOG_TAG "C2GoldfishHevcDec"
+#include <inttypes.h>
+#include <log/log.h>
+#include <media/stagefright/foundation/AUtils.h>
+#include <media/stagefright/foundation/MediaDefs.h>
+
+#include <C2AllocatorGralloc.h>
+#include <C2PlatformSupport.h>
+//#include <android/hardware/graphics/common/1.0/types.h>
+
+#include <android/hardware/graphics/allocator/3.0/IAllocator.h>
+#include <android/hardware/graphics/mapper/3.0/IMapper.h>
+#include <hidl/LegacySupport.h>
+
+#include <media/stagefright/foundation/MediaDefs.h>
+
+#include <C2Debug.h>
+#include <C2PlatformSupport.h>
+#include <Codec2Mapper.h>
+#include <SimpleC2Interface.h>
+#include <goldfish_codec2/store/GoldfishComponentStore.h>
+#include <gralloc_cb_bp.h>
+
+#include <color_buffer_utils.h>
+
+#include "C2GoldfishHevcDec.h"
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+using ::android::hardware::graphics::common::V1_0::BufferUsage;
+using ::android::hardware::graphics::common::V1_2::PixelFormat;
+
+namespace android {
+
+namespace {
+constexpr size_t kMinInputBufferSize = 6 * 1024 * 1024;
+constexpr char COMPONENT_NAME[] = "c2.goldfish.hevc.decoder";
+constexpr uint32_t kDefaultOutputDelay = 8;
+constexpr uint32_t kMaxOutputDelay = 16;
+} // namespace
+
+class C2GoldfishHevcDec::IntfImpl : public SimpleInterface<void>::BaseParams {
+  public:
+    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
+        : SimpleInterface<void>::BaseParams(
+              helper, COMPONENT_NAME, C2Component::KIND_DECODER,
+              C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_HEVC) {
+        noPrivateBuffers(); // TODO: account for our buffers here
+        noInputReferences();
+        noOutputReferences();
+        noInputLatency();
+        noTimeStretch();
+
+        // TODO: Proper support for reorder depth.
+        addParameter(
+            DefineParam(mActualOutputDelay, C2_PARAMKEY_OUTPUT_DELAY)
+                .withDefault(
+                    new C2PortActualDelayTuning::output(kDefaultOutputDelay))
+                .withFields({C2F(mActualOutputDelay, value)
+                                 .inRange(0, kMaxOutputDelay)})
+                .withSetter(
+                    Setter<
+                        decltype(*mActualOutputDelay)>::StrictValueWithNoDeps)
+                .build());
+
+        // TODO: output latency and reordering
+
+        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
+                         .withConstValue(new C2ComponentAttributesSetting(
+                             C2Component::ATTRIB_IS_TEMPORAL))
+                         .build());
+
+        // coded and output picture size is the same for this codec
+        addParameter(
+            DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
+                .withDefault(new C2StreamPictureSizeInfo::output(0u, 320, 240))
+                .withFields({
+                    C2F(mSize, width).inRange(2, 4096, 2),
+                    C2F(mSize, height).inRange(2, 4096, 2),
+                })
+                .withSetter(SizeSetter)
+                .build());
+
+        addParameter(DefineParam(mMaxSize, C2_PARAMKEY_MAX_PICTURE_SIZE)
+                         .withDefault(new C2StreamMaxPictureSizeTuning::output(
+                             0u, 320, 240))
+                         .withFields({
+                             C2F(mSize, width).inRange(2, 4096, 2),
+                             C2F(mSize, height).inRange(2, 4096, 2),
+                         })
+                         .withSetter(MaxPictureSizeSetter, mSize)
+                         .build());
+
+        addParameter(
+            DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
+                .withDefault(new C2StreamProfileLevelInfo::input(
+                    0u, C2Config::PROFILE_HEVC_MAIN, C2Config::LEVEL_HEVC_MAIN_5_1))
+                .withFields({
+                    C2F(mProfileLevel, profile).oneOf({
+                            C2Config::PROFILE_HEVC_MAIN,
+                            C2Config::PROFILE_HEVC_MAIN_STILL}),
+                    C2F(mProfileLevel, level).oneOf({
+                            C2Config::LEVEL_HEVC_MAIN_1,
+                            C2Config::LEVEL_HEVC_MAIN_2, C2Config::LEVEL_HEVC_MAIN_2_1,
+                            C2Config::LEVEL_HEVC_MAIN_3, C2Config::LEVEL_HEVC_MAIN_3_1,
+                            C2Config::LEVEL_HEVC_MAIN_4, C2Config::LEVEL_HEVC_MAIN_4_1,
+                            C2Config::LEVEL_HEVC_MAIN_5, C2Config::LEVEL_HEVC_MAIN_5_1,
+                            C2Config::LEVEL_HEVC_MAIN_5_2, C2Config::LEVEL_HEVC_HIGH_4,
+                            C2Config::LEVEL_HEVC_HIGH_4_1, C2Config::LEVEL_HEVC_HIGH_5,
+                            C2Config::LEVEL_HEVC_HIGH_5_1, C2Config::LEVEL_HEVC_HIGH_5_2
+                    })
+                })
+                .withSetter(ProfileLevelSetter, mSize)
+                .build());
+
+        addParameter(
+            DefineParam(mMaxInputSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
+                .withDefault(new C2StreamMaxBufferSizeInfo::input(
+                    0u, kMinInputBufferSize))
+                .withFields({
+                    C2F(mMaxInputSize, value).any(),
+                })
+                .calculatedAs(MaxInputSizeSetter, mMaxSize)
+                .build());
+
+        C2ChromaOffsetStruct locations[1] = {
+            C2ChromaOffsetStruct::ITU_YUV_420_0()};
+        std::shared_ptr<C2StreamColorInfo::output> defaultColorInfo =
+            C2StreamColorInfo::output::AllocShared(1u, 0u, 8u /* bitDepth */,
+                                                   C2Color::YUV_420);
+        memcpy(defaultColorInfo->m.locations, locations, sizeof(locations));
+
+        defaultColorInfo = C2StreamColorInfo::output::AllocShared(
+            {C2ChromaOffsetStruct::ITU_YUV_420_0()}, 0u, 8u /* bitDepth */,
+            C2Color::YUV_420);
+        helper->addStructDescriptors<C2ChromaOffsetStruct>();
+
+        addParameter(DefineParam(mColorInfo, C2_PARAMKEY_CODED_COLOR_INFO)
+                         .withConstValue(defaultColorInfo)
+                         .build());
+
+        addParameter(
+            DefineParam(mDefaultColorAspects, C2_PARAMKEY_DEFAULT_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsTuning::output(
+                    0u, C2Color::RANGE_UNSPECIFIED,
+                    C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mDefaultColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mDefaultColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mDefaultColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mDefaultColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(DefaultColorAspectsSetter)
+                .build());
+
+        addParameter(
+            DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsInfo::input(
+                    0u, C2Color::RANGE_LIMITED, C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mCodedColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mCodedColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mCodedColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mCodedColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(CodedColorAspectsSetter)
+                .build());
+
+        addParameter(
+            DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsInfo::output(
+                    0u, C2Color::RANGE_UNSPECIFIED,
+                    C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(ColorAspectsSetter, mDefaultColorAspects,
+                            mCodedColorAspects)
+                .build());
+
+        // TODO: support more formats?
+        addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
+                         .withConstValue(new C2StreamPixelFormatInfo::output(
+                             0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
+                         .build());
+    }
+    static C2R SizeSetter(bool mayBlock,
+                          const C2P<C2StreamPictureSizeInfo::output> &oldMe,
+                          C2P<C2StreamPictureSizeInfo::output> &me) {
+        (void)mayBlock;
+        DDD("calling sizesetter now %d", oldMe.v.height);
+        DDD("new calling sizesetter now %d", me.v.height);
+
+        C2R res = C2R::Ok();
+        if (!me.F(me.v.width).supportsAtAll(me.v.width)) {
+            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.width)));
+            me.set().width = oldMe.v.width;
+        }
+        if (!me.F(me.v.height).supportsAtAll(me.v.height)) {
+            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.height)));
+            me.set().height = oldMe.v.height;
+        }
+        return res;
+    }
+
+    static C2R
+    MaxPictureSizeSetter(bool mayBlock,
+                         C2P<C2StreamMaxPictureSizeTuning::output> &me,
+                         const C2P<C2StreamPictureSizeInfo::output> &size) {
+        (void)mayBlock;
+        // TODO: get max width/height from the size's field helpers vs.
+        // hardcoding
+        me.set().width = c2_min(c2_max(me.v.width, size.v.width), 4096u);
+        me.set().height = c2_min(c2_max(me.v.height, size.v.height), 4096u);
+        return C2R::Ok();
+    }
+
+    static C2R MaxInputSizeSetter(
+        bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input> &me,
+        const C2P<C2StreamMaxPictureSizeTuning::output> &maxSize) {
+        (void)mayBlock;
+        // assume compression ratio of 2
+        me.set().value = c2_max((((maxSize.v.width + 63) / 64) *
+                                 ((maxSize.v.height + 64) / 64) * 3072),
+                                kMinInputBufferSize);
+        return C2R::Ok();
+    }
+
+    static C2R
+    ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input> &me,
+                       const C2P<C2StreamPictureSizeInfo::output> &size) {
+        (void)mayBlock;
+        (void)size;
+        (void)me; // TODO: validate
+        return C2R::Ok();
+    }
+
+    static C2R
+    DefaultColorAspectsSetter(bool mayBlock,
+                              C2P<C2StreamColorAspectsTuning::output> &me) {
+        (void)mayBlock;
+        if (me.v.range > C2Color::RANGE_OTHER) {
+            me.set().range = C2Color::RANGE_OTHER;
+        }
+        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
+            me.set().primaries = C2Color::PRIMARIES_OTHER;
+        }
+        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
+            me.set().transfer = C2Color::TRANSFER_OTHER;
+        }
+        if (me.v.matrix > C2Color::MATRIX_OTHER) {
+            me.set().matrix = C2Color::MATRIX_OTHER;
+        }
+        return C2R::Ok();
+    }
+
+    static C2R
+    CodedColorAspectsSetter(bool mayBlock,
+                            C2P<C2StreamColorAspectsInfo::input> &me) {
+        (void)mayBlock;
+        if (me.v.range > C2Color::RANGE_OTHER) {
+            me.set().range = C2Color::RANGE_OTHER;
+        }
+        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
+            me.set().primaries = C2Color::PRIMARIES_OTHER;
+        }
+        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
+            me.set().transfer = C2Color::TRANSFER_OTHER;
+        }
+        if (me.v.matrix > C2Color::MATRIX_OTHER) {
+            me.set().matrix = C2Color::MATRIX_OTHER;
+        }
+        return C2R::Ok();
+    }
+
+    static C2R
+    ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output> &me,
+                       const C2P<C2StreamColorAspectsTuning::output> &def,
+                       const C2P<C2StreamColorAspectsInfo::input> &coded) {
+        (void)mayBlock;
+        // take default values for all unspecified fields, and coded values for
+        // specified ones
+        me.set().range =
+            coded.v.range == RANGE_UNSPECIFIED ? def.v.range : coded.v.range;
+        me.set().primaries = coded.v.primaries == PRIMARIES_UNSPECIFIED
+                                 ? def.v.primaries
+                                 : coded.v.primaries;
+        me.set().transfer = coded.v.transfer == TRANSFER_UNSPECIFIED
+                                ? def.v.transfer
+                                : coded.v.transfer;
+        me.set().matrix = coded.v.matrix == MATRIX_UNSPECIFIED ? def.v.matrix
+                                                               : coded.v.matrix;
+        return C2R::Ok();
+    }
+
+    std::shared_ptr<C2StreamColorAspectsInfo::output> getColorAspects_l() {
+        return mColorAspects;
+    }
+
+    int width() const { return mSize->width; }
+
+    int height() const { return mSize->height; }
+
+    int primaries() const { return mColorAspects->primaries; }
+
+    int range() const { return mColorAspects->range; }
+
+    int transfer() const { return mColorAspects->transfer; }
+
+
+  private:
+    std::shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
+    std::shared_ptr<C2StreamPictureSizeInfo::output> mSize;
+    std::shared_ptr<C2StreamMaxPictureSizeTuning::output> mMaxSize;
+    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mMaxInputSize;
+    std::shared_ptr<C2StreamColorInfo::output> mColorInfo;
+    std::shared_ptr<C2StreamColorAspectsInfo::input> mCodedColorAspects;
+    std::shared_ptr<C2StreamColorAspectsTuning::output> mDefaultColorAspects;
+    std::shared_ptr<C2StreamColorAspectsInfo::output> mColorAspects;
+    std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormat;
+};
+
+static void *ivd_aligned_malloc(void *ctxt, uint32_t alignment, uint32_t size) {
+    (void)ctxt;
+    return memalign(alignment, size);
+}
+
+static void ivd_aligned_free(void *ctxt, void *mem) {
+    (void)ctxt;
+    free(mem);
+}
+
+C2GoldfishHevcDec::C2GoldfishHevcDec(const char *name, c2_node_id_t id,
+                                   const std::shared_ptr<IntfImpl> &intfImpl)
+    : SimpleC2Component(
+          std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
+      mIntf(intfImpl), mOutBufferFlush(nullptr), mOutIndex(0u),
+      mWidth(1920), mHeight(1080), mHeaderDecoded(false) {
+    mWidth = mIntf->width();
+    mHeight = mIntf->height();
+    DDD("creating hevc decoder now w %d h %d", mWidth, mHeight);
+}
+
+C2GoldfishHevcDec::~C2GoldfishHevcDec() { onRelease(); }
+
+c2_status_t C2GoldfishHevcDec::onInit() {
+    status_t err = initDecoder();
+    return err == OK ? C2_OK : C2_CORRUPTED;
+}
+
+c2_status_t C2GoldfishHevcDec::onStop() {
+    if (OK != resetDecoder())
+        return C2_CORRUPTED;
+    resetPlugin();
+    return C2_OK;
+}
+
+void C2GoldfishHevcDec::onReset() { (void)onStop(); }
+
+void C2GoldfishHevcDec::onRelease() {
+    deleteContext();
+    if (mOutBlock) {
+        mOutBlock.reset();
+    }
+}
+
+void C2GoldfishHevcDec::decodeHeaderAfterFlush() {
+        DDD("calling %s", __func__);
+    if (mContext && !mCsd0.empty()) {
+        mContext->decodeFrame(&(mCsd0[0]), mCsd0.size(), 0);
+        DDD("resending csd0");
+        DDD("calling %s success", __func__);
+    }
+}
+
+c2_status_t C2GoldfishHevcDec::onFlush_sm() {
+    if (OK != setFlushMode())
+        return C2_CORRUPTED;
+
+    if (!mContext) {
+        // just ignore if context is not even created
+        return C2_OK;
+    }
+
+    uint32_t bufferSize = mStride * mHeight * 3 / 2;
+    mOutBufferFlush = (uint8_t *)ivd_aligned_malloc(nullptr, 128, bufferSize);
+    if (!mOutBufferFlush) {
+        ALOGE("could not allocate tmp output buffer (for flush) of size %u ",
+              bufferSize);
+        return C2_NO_MEMORY;
+    }
+
+    while (true) {
+        mPts = 0;
+        constexpr bool hasPicture = false;
+        setDecodeArgs(nullptr, nullptr, 0, 0, 0, hasPicture);
+        mImg = mContext->getImage();
+        if (mImg.data == nullptr) {
+            resetPlugin();
+            break;
+        }
+    }
+
+    if (mOutBufferFlush) {
+        ivd_aligned_free(nullptr, mOutBufferFlush);
+        mOutBufferFlush = nullptr;
+    }
+
+    deleteContext();
+    return C2_OK;
+}
+
+void C2GoldfishHevcDec::sendMetadata() {
+    // compare and send if changed
+    MetaDataColorAspects currentMetaData = {1, 0, 0, 0};
+    currentMetaData.primaries = mIntf->primaries();
+    currentMetaData.range = mIntf->range();
+    currentMetaData.transfer = mIntf->transfer();
+
+    DDD("metadata primaries %d range %d transfer %d",
+            (int)(currentMetaData.primaries),
+            (int)(currentMetaData.range),
+            (int)(currentMetaData.transfer)
+       );
+
+    if (mSentMetadata.primaries == currentMetaData.primaries &&
+        mSentMetadata.range == currentMetaData.range &&
+        mSentMetadata.transfer == currentMetaData.transfer) {
+        DDD("metadata is the same, no need to update");
+        return;
+    }
+    std::swap(mSentMetadata, currentMetaData);
+
+    mContext->sendMetadata(&(mSentMetadata));
+}
+
+status_t C2GoldfishHevcDec::createDecoder() {
+
+    DDD("creating hevc context now w %d h %d", mWidth, mHeight);
+    if (mEnableAndroidNativeBuffers) {
+        mContext.reset(new MediaHevcDecoder(RenderMode::RENDER_BY_HOST_GPU));
+    } else {
+        mContext.reset(new MediaHevcDecoder(RenderMode::RENDER_BY_GUEST_CPU));
+    }
+    mContext->initHevcContext(mWidth, mHeight, mWidth, mHeight,
+                              MediaHevcDecoder::PixelFormat::YUV420P);
+
+    return OK;
+}
+
+status_t C2GoldfishHevcDec::setParams(size_t stride) {
+    (void)stride;
+    return OK;
+}
+
+status_t C2GoldfishHevcDec::initDecoder() {
+    //    if (OK != createDecoder()) return UNKNOWN_ERROR;
+    mStride = ALIGN2(mWidth);
+    mSignalledError = false;
+    resetPlugin();
+
+    return OK;
+}
+
+bool C2GoldfishHevcDec::setDecodeArgs(C2ReadView *inBuffer,
+                                     C2GraphicView *outBuffer, size_t inOffset,
+                                     size_t inSize, uint32_t tsMarker, bool hasPicture) {
+    uint32_t displayStride = mStride;
+    (void)inBuffer;
+    (void)inOffset;
+    (void)inSize;
+    (void)tsMarker;
+    if (outBuffer) {
+        C2PlanarLayout layout;
+        layout = outBuffer->layout();
+        displayStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
+    }
+
+    if (inBuffer) {
+        //= tsMarker;
+        mInPBuffer = const_cast<uint8_t *>(inBuffer->data() + inOffset);
+        mInPBufferSize = inSize;
+        mInTsMarker = tsMarker;
+        if (hasPicture) {
+            insertPts(tsMarker, mPts);
+        }
+    }
+
+    // uint32_t displayHeight = mHeight;
+    // size_t lumaSize = displayStride * displayHeight;
+    // size_t chromaSize = lumaSize >> 2;
+
+    if (mStride != displayStride) {
+        mStride = displayStride;
+        if (OK != setParams(mStride))
+            return false;
+    }
+
+    return true;
+}
+
+status_t C2GoldfishHevcDec::setFlushMode() {
+    if (mContext) {
+        mContext->flush();
+    }
+    mHeaderDecoded = false;
+    return OK;
+}
+
+status_t C2GoldfishHevcDec::resetDecoder() {
+    mStride = 0;
+    mSignalledError = false;
+    mHeaderDecoded = false;
+    deleteContext();
+
+    return OK;
+}
+
+void C2GoldfishHevcDec::resetPlugin() {
+    mSignalledOutputEos = false;
+    gettimeofday(&mTimeStart, nullptr);
+    gettimeofday(&mTimeEnd, nullptr);
+    if (mOutBlock) {
+        mOutBlock.reset();
+    }
+}
+
+void C2GoldfishHevcDec::deleteContext() {
+    if (mContext) {
+        mContext->destroyHevcContext();
+        mContext.reset(nullptr);
+        mPts2Index.clear();
+        mOldPts2Index.clear();
+        mIndex2Pts.clear();
+    }
+}
+
+static void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
+    uint32_t flags = 0;
+    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
+        flags |= C2FrameData::FLAG_END_OF_STREAM;
+        DDD("signalling eos");
+    }
+    DDD("fill empty work");
+    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
+    work->worklets.front()->output.buffers.clear();
+    work->worklets.front()->output.ordinal = work->input.ordinal;
+    work->workletsProcessed = 1u;
+}
+
+void C2GoldfishHevcDec::finishWork(uint64_t index,
+                                  const std::unique_ptr<C2Work> &work) {
+    std::shared_ptr<C2Buffer> buffer =
+        createGraphicBuffer(std::move(mOutBlock), C2Rect(mWidth, mHeight));
+    mOutBlock = nullptr;
+    {
+        IntfImpl::Lock lock = mIntf->lock();
+        buffer->setInfo(mIntf->getColorAspects_l());
+    }
+
+    class FillWork {
+      public:
+        FillWork(uint32_t flags, C2WorkOrdinalStruct ordinal,
+                 const std::shared_ptr<C2Buffer> &buffer)
+            : mFlags(flags), mOrdinal(ordinal), mBuffer(buffer) {}
+        ~FillWork() = default;
+
+        void operator()(const std::unique_ptr<C2Work> &work) {
+            work->worklets.front()->output.flags = (C2FrameData::flags_t)mFlags;
+            work->worklets.front()->output.buffers.clear();
+            work->worklets.front()->output.ordinal = mOrdinal;
+            work->workletsProcessed = 1u;
+            work->result = C2_OK;
+            if (mBuffer) {
+                work->worklets.front()->output.buffers.push_back(mBuffer);
+            }
+            DDD("timestamp = %lld, index = %lld, w/%s buffer",
+                mOrdinal.timestamp.peekll(), mOrdinal.frameIndex.peekll(),
+                mBuffer ? "" : "o");
+        }
+
+      private:
+        const uint32_t mFlags;
+        const C2WorkOrdinalStruct mOrdinal;
+        const std::shared_ptr<C2Buffer> mBuffer;
+    };
+
+    auto fillWork = [buffer](const std::unique_ptr<C2Work> &work) {
+        work->worklets.front()->output.flags = (C2FrameData::flags_t)0;
+        work->worklets.front()->output.buffers.clear();
+        work->worklets.front()->output.buffers.push_back(buffer);
+        work->worklets.front()->output.ordinal = work->input.ordinal;
+        work->workletsProcessed = 1u;
+    };
+    if (work && c2_cntr64_t(index) == work->input.ordinal.frameIndex) {
+        bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
+        // TODO: Check if cloneAndSend can be avoided by tracking number of
+        // frames remaining
+        if (eos) {
+            if (buffer) {
+                mOutIndex = index;
+                C2WorkOrdinalStruct outOrdinal = work->input.ordinal;
+                DDD("%s %d: cloneAndSend ", __func__, __LINE__);
+                cloneAndSend(
+                    mOutIndex, work,
+                    FillWork(C2FrameData::FLAG_INCOMPLETE, outOrdinal, buffer));
+                buffer.reset();
+            }
+        } else {
+            DDD("%s %d: fill", __func__, __LINE__);
+            fillWork(work);
+        }
+    } else {
+        DDD("%s %d: finish", __func__, __LINE__);
+        finish(index, fillWork);
+    }
+}
+
+c2_status_t
+C2GoldfishHevcDec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
+    if (mOutBlock && (mOutBlock->width() != ALIGN2(mWidth) ||
+                      mOutBlock->height() != mHeight)) {
+        mOutBlock.reset();
+    }
+    if (!mOutBlock) {
+        const uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
+        const C2MemoryUsage usage = {(uint64_t)(BufferUsage::VIDEO_DECODER),
+                                     C2MemoryUsage::CPU_WRITE | C2MemoryUsage::CPU_READ};
+        c2_status_t err = pool->fetchGraphicBlock(ALIGN2(mWidth), mHeight,
+                                                  format, usage, &mOutBlock);
+        if (err != C2_OK) {
+            ALOGE("fetchGraphicBlock for Output failed with status %d", err);
+            return err;
+        }
+        if (mEnableAndroidNativeBuffers) {
+            auto c2Handle = mOutBlock->handle();
+            native_handle_t *grallocHandle =
+                UnwrapNativeCodec2GrallocHandle(c2Handle);
+            mHostColorBufferId = getColorBufferHandle(grallocHandle);
+            DDD("found handle %d", mHostColorBufferId);
+        }
+        DDD("provided (%dx%d) required (%dx%d)", mOutBlock->width(),
+            mOutBlock->height(), ALIGN2(mWidth), mHeight);
+    }
+
+    return C2_OK;
+}
+
+void C2GoldfishHevcDec::checkMode(const std::shared_ptr<C2BlockPool> &pool) {
+    mWidth = mIntf->width();
+    mHeight = mIntf->height();
+    //const bool isGraphic = (pool->getLocalId() == C2PlatformAllocatorStore::GRALLOC);
+    const bool isGraphic = (pool->getAllocatorId() & C2Allocator::GRAPHIC);
+    DDD("buffer pool allocator id %x",  (int)(pool->getAllocatorId()));
+    if (isGraphic) {
+        uint64_t client_usage = getClientUsage(pool);
+        DDD("client has usage as 0x%llx", client_usage);
+        if (client_usage & BufferUsage::CPU_READ_MASK) {
+            DDD("decoding to guest byte buffer as client has read usage");
+            mEnableAndroidNativeBuffers = false;
+        } else {
+            DDD("decoding to host color buffer");
+            mEnableAndroidNativeBuffers = true;
+        }
+    } else {
+        DDD("decoding to guest byte buffer");
+        mEnableAndroidNativeBuffers = false;
+    }
+}
+
+void C2GoldfishHevcDec::getVuiParams(hevc_image_t &img) {
+
+    VuiColorAspects vuiColorAspects;
+    vuiColorAspects.primaries = img.color_primaries;
+    vuiColorAspects.transfer = img.color_trc;
+    vuiColorAspects.coeffs = img.colorspace;
+    vuiColorAspects.fullRange = img.color_range == 2 ? true : false;
+
+    // convert vui aspects to C2 values if changed
+    if (!(vuiColorAspects == mBitstreamColorAspects)) {
+        mBitstreamColorAspects = vuiColorAspects;
+        ColorAspects sfAspects;
+        C2StreamColorAspectsInfo::input codedAspects = {0u};
+        ColorUtils::convertIsoColorAspectsToCodecAspects(
+            vuiColorAspects.primaries, vuiColorAspects.transfer,
+            vuiColorAspects.coeffs, vuiColorAspects.fullRange, sfAspects);
+        if (!C2Mapper::map(sfAspects.mPrimaries, &codedAspects.primaries)) {
+            codedAspects.primaries = C2Color::PRIMARIES_UNSPECIFIED;
+        }
+        if (!C2Mapper::map(sfAspects.mRange, &codedAspects.range)) {
+            codedAspects.range = C2Color::RANGE_UNSPECIFIED;
+        }
+        if (!C2Mapper::map(sfAspects.mMatrixCoeffs, &codedAspects.matrix)) {
+            codedAspects.matrix = C2Color::MATRIX_UNSPECIFIED;
+        }
+        if (!C2Mapper::map(sfAspects.mTransfer, &codedAspects.transfer)) {
+            codedAspects.transfer = C2Color::TRANSFER_UNSPECIFIED;
+        }
+        std::vector<std::unique_ptr<C2SettingResult>> failures;
+        (void)mIntf->config({&codedAspects}, C2_MAY_BLOCK, &failures);
+    }
+}
+
+void C2GoldfishHevcDec::copyImageData(hevc_image_t &img) {
+    getVuiParams(img);
+    if (mEnableAndroidNativeBuffers)
+        return;
+
+    auto writeView = mOutBlock->map().get();
+    if (writeView.error()) {
+        ALOGE("graphic view map failed %d", writeView.error());
+        return;
+    }
+    size_t dstYStride = writeView.layout().planes[C2PlanarLayout::PLANE_Y].rowInc;
+    size_t dstUVStride = writeView.layout().planes[C2PlanarLayout::PLANE_U].rowInc;
+
+    uint8_t *pYBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_Y]);
+    uint8_t *pUBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_U]);
+    uint8_t *pVBuffer = const_cast<uint8_t *>(writeView.data()[C2PlanarLayout::PLANE_V]);
+
+    for (int i = 0; i < mHeight; ++i) {
+        memcpy(pYBuffer + i * dstYStride, img.data + i * mWidth, mWidth);
+    }
+    for (int i = 0; i < mHeight / 2; ++i) {
+        memcpy(pUBuffer + i * dstUVStride,
+               img.data + mWidth * mHeight + i * mWidth / 2, mWidth / 2);
+    }
+    for (int i = 0; i < mHeight / 2; ++i) {
+        memcpy(pVBuffer + i * dstUVStride,
+               img.data + mWidth * mHeight * 5 / 4 + i * mWidth / 2,
+               mWidth / 2);
+    }
+}
+
+uint64_t C2GoldfishHevcDec::getWorkIndex(uint64_t pts) {
+    if (!mOldPts2Index.empty()) {
+        auto iter = mOldPts2Index.find(pts);
+        if (iter != mOldPts2Index.end()) {
+            auto index = iter->second;
+            DDD("found index %d for pts %" PRIu64, (int)index, pts);
+            return index;
+        }
+    }
+    auto iter = mPts2Index.find(pts);
+    if (iter != mPts2Index.end()) {
+        auto index = iter->second;
+        DDD("found index %d for pts %" PRIu64, (int)index, pts);
+        return index;
+    }
+    DDD("not found index for pts %" PRIu64, pts);
+    return 0;
+}
+
+void C2GoldfishHevcDec::insertPts(uint32_t work_index, uint64_t pts) {
+    auto iter = mPts2Index.find(pts);
+    if (iter != mPts2Index.end()) {
+        // we have a collision here:
+        // apparently, older session is not done yet,
+        // lets save them
+        DDD("inserted to old pts %" PRIu64 " with index %d", pts, (int)iter->second);
+        mOldPts2Index[iter->first] = iter->second;
+    }
+    DDD("inserted pts %" PRIu64 " with index %d", pts, (int)work_index);
+    mIndex2Pts[work_index] = pts;
+    mPts2Index[pts] = work_index;
+}
+
+void C2GoldfishHevcDec::removePts(uint64_t pts) {
+    bool found = false;
+    uint64_t index = 0;
+    // note: check old pts first to see
+    // if we have some left over, check them
+    if (!mOldPts2Index.empty()) {
+        auto iter = mOldPts2Index.find(pts);
+        if (iter != mOldPts2Index.end()) {
+            index = iter->second;
+            mOldPts2Index.erase(iter);
+            found = true;
+        }
+    } else {
+        auto iter = mPts2Index.find(pts);
+        if (iter != mPts2Index.end()) {
+            index = iter->second;
+            mPts2Index.erase(iter);
+            found = true;
+        }
+    }
+
+    if (!found) return;
+
+    auto iter2 = mIndex2Pts.find(index);
+    if (iter2 == mIndex2Pts.end()) return;
+    mIndex2Pts.erase(iter2);
+}
+
+// TODO: can overall error checking be improved?
+// TODO: allow configuration of color format and usage for graphic buffers
+// instead
+//       of hard coding them to HAL_PIXEL_FORMAT_YV12
+// TODO: pass coloraspects information to surface
+// TODO: test support for dynamic change in resolution
+// TODO: verify if the decoder sent back all frames
+void C2GoldfishHevcDec::process(const std::unique_ptr<C2Work> &work,
+                               const std::shared_ptr<C2BlockPool> &pool) {
+    // Initialize output work
+    work->result = C2_OK;
+    work->workletsProcessed = 0u;
+    work->worklets.front()->output.flags = work->input.flags;
+    if (mSignalledError || mSignalledOutputEos) {
+        work->result = C2_BAD_VALUE;
+        return;
+    }
+
+    DDD("process work");
+    if (!mContext) {
+        DDD("creating decoder context to host in process work");
+        checkMode(pool);
+        createDecoder();
+        decodeHeaderAfterFlush();
+    }
+
+    size_t inOffset = 0u;
+    size_t inSize = 0u;
+    uint32_t workIndex = work->input.ordinal.frameIndex.peeku() & 0xFFFFFFFF;
+    mPts = work->input.ordinal.timestamp.peeku();
+    C2ReadView rView = mDummyReadView;
+    if (!work->input.buffers.empty()) {
+        rView =
+            work->input.buffers[0]->data().linearBlocks().front().map().get();
+        inSize = rView.capacity();
+        if (inSize && rView.error()) {
+            ALOGE("read view map failed %d", rView.error());
+            work->result = rView.error();
+            return;
+        }
+    }
+    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
+    bool hasPicture = (inSize > 0);
+
+    DDD("in buffer attr. size %zu timestamp %d frameindex %d, flags %x", inSize,
+        (int)work->input.ordinal.timestamp.peeku(),
+        (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);
+    size_t inPos = 0;
+    while (inPos < inSize) {
+        if (C2_OK != ensureDecoderState(pool)) {
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            work->result = C2_CORRUPTED;
+            return;
+        }
+
+        {
+            // C2GraphicView wView;// = mOutBlock->map().get();
+            // if (wView.error()) {
+            //    ALOGE("graphic view map failed %d", wView.error());
+            //    work->result = wView.error();
+            //    return;
+            //}
+            if (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) {
+                hasPicture = false;
+            }
+
+            if (!setDecodeArgs(&rView, nullptr, inOffset + inPos,
+                               inSize - inPos, workIndex, hasPicture)) {
+                mSignalledError = true;
+                work->workletsProcessed = 1u;
+                work->result = C2_CORRUPTED;
+                return;
+            }
+
+            DDD("flag is %x", work->input.flags);
+            if (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) {
+                if (mCsd0.empty()) {
+                    mCsd0.assign(mInPBuffer, mInPBuffer + mInPBufferSize);
+                    DDD("assign to csd0 with %d bytpes", mInPBufferSize);
+                }
+            }
+
+            bool whChanged = false;
+            if (GoldfishHevcHelper::isVpsFrame(mInPBuffer, mInPBufferSize)) {
+                mHevcHelper.reset(new GoldfishHevcHelper(mWidth, mHeight));
+                bool headerStatus = true;
+                whChanged = mHevcHelper->decodeHeader(
+                    mInPBuffer, mInPBufferSize, headerStatus);
+                if (!headerStatus) {
+                    mSignalledError = true;
+                    work->workletsProcessed = 1u;
+                    work->result = C2_CORRUPTED;
+                    return;
+                }
+                if (whChanged) {
+                        DDD("w changed from old %d to new %d\n", mWidth, mHevcHelper->getWidth());
+                        DDD("h changed from old %d to new %d\n", mHeight, mHevcHelper->getHeight());
+                        if (1) {
+                            drainInternal(DRAIN_COMPONENT_NO_EOS, pool, work);
+                            resetDecoder();
+                            resetPlugin();
+                            work->workletsProcessed = 0u;
+                        }
+                        {
+                            mWidth = mHevcHelper->getWidth();
+                            mHeight = mHevcHelper->getHeight();
+                            C2StreamPictureSizeInfo::output size(0u, mWidth, mHeight);
+                            std::vector<std::unique_ptr<C2SettingResult>> failures;
+                            c2_status_t err = mIntf->config({&size}, C2_MAY_BLOCK, &failures);
+                            if (err == OK) {
+                                work->worklets.front()->output.configUpdate.push_back(
+                                        C2Param::Copy(size));
+                                ensureDecoderState(pool);
+                            } else {
+                                ALOGE("Cannot set width and height");
+                                mSignalledError = true;
+                                work->workletsProcessed = 1u;
+                                work->result = C2_CORRUPTED;
+                                return;
+                            }
+                        }
+                        if (!mContext) {
+                            DDD("creating decoder context to host in process work");
+                            checkMode(pool);
+                            createDecoder();
+                        }
+                        continue;//return;
+                } // end of whChanged
+            } // end of isVpsFrame
+
+            sendMetadata();
+
+            uint32_t delay;
+            GETTIME(&mTimeStart, nullptr);
+            TIME_DIFF(mTimeEnd, mTimeStart, delay);
+            (void)delay;
+            //(void) ivdec_api_function(mDecHandle, &s_decode_ip, &s_decode_op);
+            DDD("decoding");
+            hevc_result_t hevcRes =
+                mContext->decodeFrame(mInPBuffer, mInPBufferSize, mPts);
+            mConsumedBytes = hevcRes.bytesProcessed;
+            DDD("decoding consumed %d", (int)mConsumedBytes);
+
+            if (mHostColorBufferId > 0) {
+                mImg = mContext->renderOnHostAndReturnImageMetadata(
+                    mHostColorBufferId);
+            } else {
+                mImg = mContext->getImage();
+            }
+            uint32_t decodeTime;
+            GETTIME(&mTimeEnd, nullptr);
+            TIME_DIFF(mTimeStart, mTimeEnd, decodeTime);
+            (void)decodeTime;
+        }
+        if (mImg.data != nullptr) {
+            DDD("got data %" PRIu64 " with pts %" PRIu64,  getWorkIndex(mImg.pts), mImg.pts);
+            mHeaderDecoded = true;
+            copyImageData(mImg);
+            finishWork(getWorkIndex(mImg.pts), work);
+            removePts(mImg.pts);
+        } else {
+            work->workletsProcessed = 0u;
+        }
+
+        inPos += mConsumedBytes;
+    }
+    if (eos) {
+        DDD("drain because of eos");
+        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
+        mSignalledOutputEos = true;
+    } else if (!hasPicture) {
+        DDD("no picture, fill empty work");
+        fillEmptyWork(work);
+    }
+
+    work->input.buffers.clear();
+}
+
+c2_status_t
+C2GoldfishHevcDec::drainInternal(uint32_t drainMode,
+                                const std::shared_ptr<C2BlockPool> &pool,
+                                const std::unique_ptr<C2Work> &work) {
+    if (drainMode == NO_DRAIN) {
+        ALOGW("drain with NO_DRAIN: no-op");
+        return C2_OK;
+    }
+    if (drainMode == DRAIN_CHAIN) {
+        ALOGW("DRAIN_CHAIN not supported");
+        return C2_OMITTED;
+    }
+
+    if (OK != setFlushMode())
+        return C2_CORRUPTED;
+    while (true) {
+        if (C2_OK != ensureDecoderState(pool)) {
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            work->result = C2_CORRUPTED;
+            return C2_CORRUPTED;
+        }
+        /*
+        C2GraphicView wView = mOutBlock->map().get();
+        if (wView.error()) {
+            ALOGE("graphic view map failed %d", wView.error());
+            return C2_CORRUPTED;
+        }
+        if (!setDecodeArgs(nullptr, &wView, 0, 0, 0)) {
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            return C2_CORRUPTED;
+        }
+        */
+
+        if (mHostColorBufferId > 0) {
+            mImg = mContext->renderOnHostAndReturnImageMetadata(
+                mHostColorBufferId);
+        } else {
+            mImg = mContext->getImage();
+        }
+
+        // TODO: maybe keep rendering to screen
+        //        mImg = mContext->getImage();
+        if (mImg.data != nullptr) {
+            DDD("got data in drain mode %" PRIu64 " with pts %" PRIu64,  getWorkIndex(mImg.pts), mImg.pts);
+            copyImageData(mImg);
+            finishWork(getWorkIndex(mImg.pts), work);
+            removePts(mImg.pts);
+        } else {
+            fillEmptyWork(work);
+            break;
+        }
+    }
+
+    return C2_OK;
+}
+
+c2_status_t C2GoldfishHevcDec::drain(uint32_t drainMode,
+                                    const std::shared_ptr<C2BlockPool> &pool) {
+    DDD("drainInternal because of drain");
+    return drainInternal(drainMode, pool, nullptr);
+}
+
+class C2GoldfishHevcDecFactory : public C2ComponentFactory {
+  public:
+    C2GoldfishHevcDecFactory()
+        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
+              GoldfishComponentStore::Create()->getParamReflector())) {}
+
+    virtual c2_status_t
+    createComponent(c2_node_id_t id,
+                    std::shared_ptr<C2Component> *const component,
+                    std::function<void(C2Component *)> deleter) override {
+        *component = std::shared_ptr<C2Component>(
+            new C2GoldfishHevcDec(
+                COMPONENT_NAME, id,
+                std::make_shared<C2GoldfishHevcDec::IntfImpl>(mHelper)),
+            deleter);
+        return C2_OK;
+    }
+
+    virtual c2_status_t createInterface(
+        c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *const interface,
+        std::function<void(C2ComponentInterface *)> deleter) override {
+        *interface = std::shared_ptr<C2ComponentInterface>(
+            new SimpleInterface<C2GoldfishHevcDec::IntfImpl>(
+                COMPONENT_NAME, id,
+                std::make_shared<C2GoldfishHevcDec::IntfImpl>(mHelper)),
+            deleter);
+        return C2_OK;
+    }
+
+    virtual ~C2GoldfishHevcDecFactory() override = default;
+
+  private:
+    std::shared_ptr<C2ReflectorHelper> mHelper;
+};
+
+} // namespace android
+
+extern "C" ::C2ComponentFactory *CreateCodec2Factory() {
+    DDD("in %s", __func__);
+    return new ::android::C2GoldfishHevcDecFactory();
+}
+
+extern "C" void DestroyCodec2Factory(::C2ComponentFactory *factory) {
+    DDD("in %s", __func__);
+    delete factory;
+}
diff --git a/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h b/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h
new file mode 100644
index 00000000..f1486df3
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/C2GoldfishHevcDec.h
@@ -0,0 +1,173 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_C2_SOFT_HEVC_DEC_H_
+#define ANDROID_C2_SOFT_HEVC_DEC_H_
+
+#include <sys/time.h>
+
+#include <media/stagefright/foundation/ColorUtils.h>
+
+#include "MediaHevcDecoder.h"
+#include "GoldfishHevcHelper.h"
+#include <SimpleC2Component.h>
+#include <atomic>
+#include <map>
+
+namespace android {
+
+#define ALIGN2(x) ((((x) + 1) >> 1) << 1)
+#define ALIGN8(x) ((((x) + 7) >> 3) << 3)
+#define ALIGN16(x) ((((x) + 15) >> 4) << 4)
+#define ALIGN32(x) ((((x) + 31) >> 5) << 5)
+#define MAX_NUM_CORES 4
+#define MIN(a, b) (((a) < (b)) ? (a) : (b))
+#define GETTIME(a, b) gettimeofday(a, b);
+#define TIME_DIFF(start, end, diff)                                            \
+    diff = (((end).tv_sec - (start).tv_sec) * 1000000) +                       \
+           ((end).tv_usec - (start).tv_usec);
+
+class C2GoldfishHevcDec : public SimpleC2Component {
+  public:
+    class IntfImpl;
+    C2GoldfishHevcDec(const char *name, c2_node_id_t id,
+                     const std::shared_ptr<IntfImpl> &intfImpl);
+    virtual ~C2GoldfishHevcDec();
+
+    // From SimpleC2Component
+    c2_status_t onInit() override;
+    c2_status_t onStop() override;
+    void onReset() override;
+    void onRelease() override;
+    c2_status_t onFlush_sm() override;
+    void process(const std::unique_ptr<C2Work> &work,
+                 const std::shared_ptr<C2BlockPool> &pool) override;
+    c2_status_t drain(uint32_t drainMode,
+                      const std::shared_ptr<C2BlockPool> &pool) override;
+
+  private:
+    void checkMode(const std::shared_ptr<C2BlockPool> &pool);
+    //    status_t createDecoder();
+    status_t createDecoder();
+    status_t setParams(size_t stride);
+    status_t initDecoder();
+    bool setDecodeArgs(C2ReadView *inBuffer, C2GraphicView *outBuffer,
+                       size_t inOffset, size_t inSize, uint32_t tsMarker, bool hasPicture);
+    c2_status_t ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool);
+    void finishWork(uint64_t index, const std::unique_ptr<C2Work> &work);
+    status_t setFlushMode();
+    c2_status_t drainInternal(uint32_t drainMode,
+                              const std::shared_ptr<C2BlockPool> &pool,
+                              const std::unique_ptr<C2Work> &work);
+    status_t resetDecoder();
+    void resetPlugin();
+    void deleteContext();
+
+    void removePts(uint64_t pts);
+    void insertPts(uint32_t work_index, uint64_t pts);
+    uint64_t getWorkIndex(uint64_t pts);
+
+    // TODO:This is not the right place for this enum. These should
+    // be part of c2-vndk so that they can be accessed by all video plugins
+    // until then, make them feel at home
+    enum {
+        kNotSupported,
+        kPreferBitstream,
+        kPreferContainer,
+    };
+
+    void getVuiParams(hevc_image_t &img);
+    void copyImageData(hevc_image_t &img);
+
+
+
+
+    // Color aspects. These are ISO values and are meant to detect changes in
+    // aspects to avoid converting them to C2 values for each frame
+    struct VuiColorAspects {
+        uint8_t primaries;
+        uint8_t transfer;
+        uint8_t coeffs;
+        uint8_t fullRange;
+
+        // default color aspects
+        VuiColorAspects()
+            : primaries(2), transfer(2), coeffs(2), fullRange(0) {}
+
+        bool operator==(const VuiColorAspects &o) const {
+            return primaries == o.primaries && transfer == o.transfer &&
+                   coeffs == o.coeffs && fullRange == o.fullRange;
+        }
+    };
+
+    void sendMetadata();
+
+    void decodeHeaderAfterFlush();
+
+    std::unique_ptr<MediaHevcDecoder> mContext;
+    std::unique_ptr<GoldfishHevcHelper> mHevcHelper;
+    std::shared_ptr<IntfImpl> mIntf;
+    std::shared_ptr<C2GraphicBlock> mOutBlock;
+
+    std::vector<uint8_t> mCsd0;
+    std::vector<uint8_t> mCsd1;
+
+    std::map<uint64_t, uint64_t> mOldPts2Index;
+    std::map<uint64_t, uint64_t> mPts2Index;
+    std::map<uint64_t, uint64_t> mIndex2Pts;
+
+    uint8_t *mInPBuffer{nullptr};
+    uint8_t *mOutBufferFlush{nullptr};
+
+    hevc_image_t mImg{};
+    VuiColorAspects mBitstreamColorAspects;
+    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
+
+    std::atomic_uint64_t mOutIndex;
+    // there are same pts matching to different work indices
+    // this happen during csd0/csd1 switching
+    uint64_t  mPts {0};
+
+    uint32_t mConsumedBytes{0};
+    uint32_t mInPBufferSize = 0;
+    uint32_t mInTsMarker = 0;
+
+    // size_t mNumCores;
+    // uint32_t mOutputDelay;
+    uint32_t mWidth = 0;
+    uint32_t mHeight = 0;
+    uint32_t mStride = 0;
+
+    int mHostColorBufferId{-1};
+
+    bool mEnableAndroidNativeBuffers{true};
+    bool mSignalledOutputEos{false};
+    bool mSignalledError{false};
+    bool mHeaderDecoded{false};
+
+    // profile
+    struct timeval mTimeStart;
+    struct timeval mTimeEnd;
+#ifdef FILE_DUMP_ENABLE
+    char mInFile[200];
+#endif /* FILE_DUMP_ENABLE */
+
+    C2_DO_NOT_COPY(C2GoldfishHevcDec);
+};
+
+} // namespace android
+
+#endif // ANDROID_C2_SOFT_HEVC_DEC_H_
diff --git a/codecs/c2/decoders/hevcdec/GoldfishHevcHelper.cpp b/codecs/c2/decoders/hevcdec/GoldfishHevcHelper.cpp
new file mode 100644
index 00000000..d3117a78
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/GoldfishHevcHelper.cpp
@@ -0,0 +1,319 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "GoldfishHevcHelper.h"
+
+#define LOG_TAG "GoldfishHevcHelper"
+#include <log/log.h>
+
+#include "ihevc_typedefs.h"
+#include "ihevcd_cxa.h"
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+
+#include <Codec2Mapper.h>
+
+#define ivdec_api_function ihevcd_cxa_api_function
+#define ivdext_create_ip_t ihevcd_cxa_create_ip_t
+#define ivdext_create_op_t ihevcd_cxa_create_op_t
+#define ivdext_delete_ip_t ihevcd_cxa_delete_ip_t
+#define ivdext_delete_op_t ihevcd_cxa_delete_op_t
+#define ivdext_ctl_set_num_cores_ip_t ihevcd_cxa_ctl_set_num_cores_ip_t
+#define ivdext_ctl_set_num_cores_op_t ihevcd_cxa_ctl_set_num_cores_op_t
+#define ivdext_ctl_get_vui_params_ip_t ihevcd_cxa_ctl_get_vui_params_ip_t
+#define ivdext_ctl_get_vui_params_op_t ihevcd_cxa_ctl_get_vui_params_op_t
+#define ALIGN128(x) ((((x) + 127) >> 7) << 7)
+#define MAX_NUM_CORES 4
+#define IVDEXT_CMD_CTL_SET_NUM_CORES                                           \
+    (IVD_CONTROL_API_COMMAND_TYPE_T) IHEVCD_CXA_CMD_CTL_SET_NUM_CORES
+#define MIN(a, b) (((a) < (b)) ? (a) : (b))
+
+namespace android {
+
+static void *ivd_aligned_malloc(void *ctxt, WORD32 alignment, WORD32 size) {
+    (void) ctxt;
+    return memalign(alignment, size);
+}
+
+static void ivd_aligned_free(void *ctxt, void *mem) {
+    (void) ctxt;
+    free(mem);
+}
+
+
+GoldfishHevcHelper::GoldfishHevcHelper(int w, int h):mWidth(w),mHeight(h) { createDecoder(); }
+
+GoldfishHevcHelper::~GoldfishHevcHelper() {
+    destroyDecoder();
+}
+
+void GoldfishHevcHelper::createDecoder() {
+    ivdext_create_ip_t s_create_ip = {};
+    ivdext_create_op_t s_create_op = {};
+
+    s_create_ip.s_ivd_create_ip_t.u4_size = sizeof(ivdext_create_ip_t);
+    s_create_ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
+    s_create_ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
+    s_create_ip.s_ivd_create_ip_t.e_output_format = mIvColorformat;
+    s_create_ip.s_ivd_create_ip_t.pf_aligned_alloc = ivd_aligned_malloc;
+    s_create_ip.s_ivd_create_ip_t.pf_aligned_free = ivd_aligned_free;
+    s_create_ip.s_ivd_create_ip_t.pv_mem_ctxt = nullptr;
+    s_create_op.s_ivd_create_op_t.u4_size = sizeof(ivdext_create_op_t);
+    IV_API_CALL_STATUS_T status =
+        ivdec_api_function(mDecHandle, &s_create_ip, &s_create_op);
+    if (status != IV_SUCCESS) {
+        ALOGE("error in %s: 0x%x", __func__,
+              s_create_op.s_ivd_create_op_t.u4_error_code);
+        return;
+    }
+    mDecHandle = (iv_obj_t *)s_create_op.s_ivd_create_op_t.pv_handle;
+    mDecHandle->pv_fxns = (void *)ivdec_api_function;
+    mDecHandle->u4_size = sizeof(iv_obj_t);
+
+    mStride = ALIGN128(mWidth);
+
+    setNumCores();
+}
+
+void GoldfishHevcHelper::destroyDecoder() {
+    if (mDecHandle) {
+        ivdext_delete_ip_t s_delete_ip = {};
+        ivdext_delete_op_t s_delete_op = {};
+
+        s_delete_ip.s_ivd_delete_ip_t.u4_size = sizeof(ivdext_delete_ip_t);
+        s_delete_ip.s_ivd_delete_ip_t.e_cmd = IVD_CMD_DELETE;
+        s_delete_op.s_ivd_delete_op_t.u4_size = sizeof(ivdext_delete_op_t);
+        IV_API_CALL_STATUS_T status =
+            ivdec_api_function(mDecHandle, &s_delete_ip, &s_delete_op);
+        if (status != IV_SUCCESS) {
+            ALOGE("error in %s: 0x%x", __func__,
+                  s_delete_op.s_ivd_delete_op_t.u4_error_code);
+        }
+        mDecHandle = nullptr;
+    }
+}
+
+void GoldfishHevcHelper::setNumCores() {
+    ivdext_ctl_set_num_cores_ip_t s_set_num_cores_ip = {};
+    ivdext_ctl_set_num_cores_op_t s_set_num_cores_op = {};
+
+    s_set_num_cores_ip.u4_size = sizeof(ivdext_ctl_set_num_cores_ip_t);
+    s_set_num_cores_ip.e_cmd = IVD_CMD_VIDEO_CTL;
+    s_set_num_cores_ip.e_sub_cmd = IVDEXT_CMD_CTL_SET_NUM_CORES;
+    s_set_num_cores_ip.u4_num_cores = mNumCores;
+    s_set_num_cores_op.u4_size = sizeof(ivdext_ctl_set_num_cores_op_t);
+    IV_API_CALL_STATUS_T status = ivdec_api_function(
+        mDecHandle, &s_set_num_cores_ip, &s_set_num_cores_op);
+    if (IV_SUCCESS != status) {
+        DDD("error in %s: 0x%x", __func__, s_set_num_cores_op.u4_error_code);
+    }
+}
+
+void GoldfishHevcHelper::resetDecoder() {
+    ivd_ctl_reset_ip_t s_reset_ip = {};
+    ivd_ctl_reset_op_t s_reset_op = {};
+
+    s_reset_ip.u4_size = sizeof(ivd_ctl_reset_ip_t);
+    s_reset_ip.e_cmd = IVD_CMD_VIDEO_CTL;
+    s_reset_ip.e_sub_cmd = IVD_CMD_CTL_RESET;
+    s_reset_op.u4_size = sizeof(ivd_ctl_reset_op_t);
+    IV_API_CALL_STATUS_T status =
+        ivdec_api_function(mDecHandle, &s_reset_ip, &s_reset_op);
+    if (IV_SUCCESS != status) {
+        ALOGE("error in %s: 0x%x", __func__, s_reset_op.u4_error_code);
+    }
+    setNumCores();
+}
+
+void GoldfishHevcHelper::setParams(size_t stride,
+                                   IVD_VIDEO_DECODE_MODE_T dec_mode) {
+    ihevcd_cxa_ctl_set_config_ip_t s_hevcd_set_dyn_params_ip = {};
+    ihevcd_cxa_ctl_set_config_op_t s_hevcd_set_dyn_params_op = {};
+    ivd_ctl_set_config_ip_t *ps_set_dyn_params_ip =
+        &s_hevcd_set_dyn_params_ip.s_ivd_ctl_set_config_ip_t;
+    ivd_ctl_set_config_op_t *ps_set_dyn_params_op =
+        &s_hevcd_set_dyn_params_op.s_ivd_ctl_set_config_op_t;
+
+    ps_set_dyn_params_ip->u4_size = sizeof(ihevcd_cxa_ctl_set_config_ip_t);
+    ps_set_dyn_params_ip->e_cmd = IVD_CMD_VIDEO_CTL;
+    ps_set_dyn_params_ip->e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
+    ps_set_dyn_params_ip->u4_disp_wd = (UWORD32)stride;
+    ps_set_dyn_params_ip->e_frm_skip_mode = IVD_SKIP_NONE;
+    ps_set_dyn_params_ip->e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
+    ps_set_dyn_params_ip->e_vid_dec_mode = dec_mode;
+    ps_set_dyn_params_op->u4_size = sizeof(ihevcd_cxa_ctl_set_config_op_t);
+    IV_API_CALL_STATUS_T status = ivdec_api_function(
+        mDecHandle, ps_set_dyn_params_ip, ps_set_dyn_params_op);
+    if (status != IV_SUCCESS) {
+        ALOGE("error in %s: 0x%x", __func__,
+              ps_set_dyn_params_op->u4_error_code);
+    }
+}
+
+bool GoldfishHevcHelper::isVpsFrame(const uint8_t* frame, int inSize) {
+    if (inSize < 5) return false;
+    if (frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == 1) {
+        const bool forbiddenBitIsInvalid = 0x80 & frame[4];
+        if (forbiddenBitIsInvalid) {
+            return false;
+        }
+        // nalu type is the lower 6 bits after shiftting to right 1 bit
+        uint8_t naluType = 0x3f & (frame[4] >> 1);
+        if (naluType == 32
+            || naluType == 33
+            || naluType == 34
+                ) return true;
+        else return false;
+    } else {
+        return false;
+    }
+}
+
+bool GoldfishHevcHelper::decodeHeader(const uint8_t *frame, int inSize,
+                                      bool &helperstatus) {
+    helperstatus = true;
+    // should we check the header for vps/sps/pps frame ? otherwise
+    // there is no point calling decoder
+    if (!isVpsFrame(frame, inSize)) {
+        DDD("could not find valid vps frame");
+        return false;
+    } else {
+        DDD("found valid vps frame");
+    }
+
+    ihevcd_cxa_video_decode_ip_t s_hevcd_decode_ip = {};
+    ihevcd_cxa_video_decode_op_t s_hevcd_decode_op = {};
+    ivd_video_decode_ip_t *ps_decode_ip =
+        &s_hevcd_decode_ip.s_ivd_video_decode_ip_t;
+    ivd_video_decode_op_t *ps_decode_op =
+        &s_hevcd_decode_op.s_ivd_video_decode_op_t;
+
+    // setup input/output arguments to decoder
+    setDecodeArgs(ps_decode_ip, ps_decode_op, frame, mStride,
+            0, // offset
+            inSize, // size
+            0 // time-stamp, does not matter
+            );
+
+    setParams(mStride, IVD_DECODE_HEADER);
+
+    // now kick off the decoding
+    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle, ps_decode_ip, ps_decode_op);
+    if (status != IV_SUCCESS) {
+        ALOGE("failed to call decoder function for header\n");
+        ALOGE("error in %s: 0x%x", __func__,
+              ps_decode_op->u4_error_code);
+        helperstatus = false;
+        return false;
+    }
+
+    if (IVD_RES_CHANGED == (ps_decode_op->u4_error_code & IVD_ERROR_MASK)) {
+        DDD("resolution changed, reset decoder");
+        resetDecoder();
+        setParams(mStride, IVD_DECODE_HEADER);
+        ivdec_api_function(mDecHandle, ps_decode_ip, ps_decode_op);
+    }
+
+    // get the w/h and update
+    if (0 < ps_decode_op->u4_pic_wd && 0 < ps_decode_op->u4_pic_ht) {
+        DDD("success decode w/h %d %d", ps_decode_op->u4_pic_wd , ps_decode_op->u4_pic_ht);
+        DDD("existing w/h %d %d", mWidth, mHeight);
+        if (ps_decode_op->u4_pic_wd != mWidth ||  ps_decode_op->u4_pic_ht != mHeight) {
+            mWidth = ps_decode_op->u4_pic_wd;
+            mHeight = ps_decode_op->u4_pic_ht;
+            return true;
+        } else {
+            DDD("success decode w/h, but they are the same %d %d", ps_decode_op->u4_pic_wd , ps_decode_op->u4_pic_ht);
+        }
+    } else {
+        ALOGE("could not decode w/h");
+    }
+
+    // get output delay
+    if (ps_decode_op->i4_reorder_depth >= 0) {
+        if (mOutputDelay != ps_decode_op->i4_reorder_depth) {
+            mOutputDelay = ps_decode_op->i4_reorder_depth;
+            DDD("New Output delay %d ", mOutputDelay);
+        } else {
+            DDD("same Output delay %d ", mOutputDelay);
+        }
+    }
+
+    return false;
+}
+
+bool GoldfishHevcHelper::setDecodeArgs(ivd_video_decode_ip_t *ps_decode_ip,
+                                       ivd_video_decode_op_t *ps_decode_op,
+                                       const uint8_t *inBuffer,
+                                       uint32_t displayStride, size_t inOffset,
+                                       size_t inSize, uint32_t tsMarker) {
+    uint32_t displayHeight = mHeight;
+    size_t lumaSize = displayStride * displayHeight;
+    size_t chromaSize = lumaSize >> 2;
+
+    if (mStride != displayStride) {
+        mStride = displayStride;
+    }
+
+    // force decoder to always decode header and get dimensions,
+    // hope this will be quick and cheap
+    setParams(mStride, IVD_DECODE_HEADER);
+
+    ps_decode_ip->u4_size = sizeof(ihevcd_cxa_video_decode_ip_t);
+    ps_decode_ip->e_cmd = IVD_CMD_VIDEO_DECODE;
+    if (inBuffer) {
+        ps_decode_ip->u4_ts = tsMarker;
+        ps_decode_ip->pv_stream_buffer = const_cast<uint8_t *>(inBuffer) + inOffset;
+        ps_decode_ip->u4_num_Bytes = inSize;
+    } else {
+        ps_decode_ip->u4_ts = 0;
+        ps_decode_ip->pv_stream_buffer = nullptr;
+        ps_decode_ip->u4_num_Bytes = 0;
+    }
+    DDD("setting pv_stream_buffer 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[0],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[1],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[2],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[3],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[4],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[5],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[6],
+            ((uint8_t*)(ps_decode_ip->pv_stream_buffer))[7]
+            );
+    DDD("input bytes %d", ps_decode_ip->u4_num_Bytes);
+
+    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[0] = lumaSize;
+    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[1] = chromaSize;
+    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[2] = chromaSize;
+    {
+        ps_decode_ip->s_out_buffer.pu1_bufs[0] = nullptr;
+        ps_decode_ip->s_out_buffer.pu1_bufs[1] = nullptr;
+        ps_decode_ip->s_out_buffer.pu1_bufs[2] = nullptr;
+    }
+    ps_decode_ip->s_out_buffer.u4_num_bufs = 3;
+    ps_decode_op->u4_size = sizeof(ihevcd_cxa_video_decode_op_t);
+    ps_decode_op->u4_output_present = 0;
+
+    return true;
+}
+
+} // namespace android
diff --git a/codecs/c2/decoders/hevcdec/GoldfishHevcHelper.h b/codecs/c2/decoders/hevcdec/GoldfishHevcHelper.h
new file mode 100644
index 00000000..36a496b7
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/GoldfishHevcHelper.h
@@ -0,0 +1,66 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef GOLDFISH_HEVC_HELPER_H_
+#define GOLDFISH_HEVC_HELPER_H_
+
+#include <inttypes.h>
+#include "ihevc_typedefs.h"
+#include "ihevcd_cxa.h"
+
+
+namespace android {
+
+// this class is just to provide some functions to decode header
+// so that we know w/h of each sps
+class GoldfishHevcHelper {
+  public:
+    GoldfishHevcHelper(int w, int h);
+    ~GoldfishHevcHelper();
+
+    // check whether the frame is vps; typical hevc will have
+    // a frame that is vps/sps/pps together
+    static bool isVpsFrame(const uint8_t* frame, int inSize);
+  public:
+    // return true if decoding finds out w/h changed;
+    // otherwise false
+   bool decodeHeader(const uint8_t *frame, int inSize, bool &status);
+   int getWidth() const { return mWidth; }
+   int getHeight() const { return mHeight; }
+
+  private:
+    void createDecoder();
+    void destroyDecoder();
+    void resetDecoder();
+    void setNumCores();
+    void setParams(size_t stride, IVD_VIDEO_DECODE_MODE_T dec_mode);
+    bool setDecodeArgs(ivd_video_decode_ip_t *ps_decode_ip,
+                       ivd_video_decode_op_t *ps_decode_op,
+                       const uint8_t *inBuffer, uint32_t displayStride,
+                       size_t inOffset, size_t inSize, uint32_t tsMarker);
+
+  private:
+    iv_obj_t *mDecHandle = nullptr;
+    int mWidth = 320;
+    int mHeight = 240;
+    int mNumCores = 1;
+    int mStride = 16;
+    int mOutputDelay = 8; // default
+    IV_COLOR_FORMAT_T mIvColorformat = IV_YUV_420P;
+};
+
+} // namespace android
+#endif
diff --git a/codecs/c2/decoders/hevcdec/MediaHevcDecoder.cpp b/codecs/c2/decoders/hevcdec/MediaHevcDecoder.cpp
new file mode 100644
index 00000000..f1bc356f
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/MediaHevcDecoder.cpp
@@ -0,0 +1,229 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include <utils/Log.h>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+#include "MediaHevcDecoder.h"
+#include "goldfish_media_utils.h"
+#include <string.h>
+
+MediaHevcDecoder::MediaHevcDecoder(RenderMode renderMode)
+    : mRenderMode(renderMode) {
+    if (renderMode == RenderMode::RENDER_BY_HOST_GPU) {
+        mVersion = 200;
+    } else if (renderMode == RenderMode::RENDER_BY_GUEST_CPU) {
+        mVersion = 100;
+    }
+}
+
+void MediaHevcDecoder::initHevcContext(unsigned int width, unsigned int height,
+                                       unsigned int outWidth,
+                                       unsigned int outHeight,
+                                       PixelFormat pixFmt) {
+    auto transport = GoldfishMediaTransport::getInstance();
+    if (!mHasAddressSpaceMemory) {
+        int slot = transport->getMemorySlot();
+        if (slot < 0) {
+            ALOGE("ERROR: Failed to initHevcContext: cannot get memory slot");
+            return;
+        }
+        mSlot = slot;
+        mAddressOffSet = static_cast<unsigned int>(mSlot) * (1 << 20);
+        DDD("got memory lot %d addrr %x", mSlot, mAddressOffSet);
+        mHasAddressSpaceMemory = true;
+    }
+    transport->writeParam(mVersion, 0, mAddressOffSet);
+    transport->writeParam(width, 1, mAddressOffSet);
+    transport->writeParam(height, 2, mAddressOffSet);
+    transport->writeParam(outWidth, 3, mAddressOffSet);
+    transport->writeParam(outHeight, 4, mAddressOffSet);
+    transport->writeParam(static_cast<uint64_t>(pixFmt), 5, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec,
+                             MediaOperation::InitContext, mAddressOffSet);
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    mHostHandle = *(uint64_t *)(retptr);
+    DDD("initHevcContext: got handle to host %lld", mHostHandle);
+}
+
+void MediaHevcDecoder::resetHevcContext(unsigned int width, unsigned int height,
+                                        unsigned int outWidth,
+                                        unsigned int outHeight,
+                                        PixelFormat pixFmt) {
+    auto transport = GoldfishMediaTransport::getInstance();
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return;
+    }
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(width, 1, mAddressOffSet);
+    transport->writeParam(height, 2, mAddressOffSet);
+    transport->writeParam(outWidth, 3, mAddressOffSet);
+    transport->writeParam(outHeight, 4, mAddressOffSet);
+    transport->writeParam(static_cast<uint64_t>(pixFmt), 5, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec, MediaOperation::Reset,
+                             mAddressOffSet);
+    DDD("resetHevcContext: done");
+}
+
+void MediaHevcDecoder::destroyHevcContext() {
+
+    DDD("return memory lot %d addrr %x", (int)(mAddressOffSet >> 23),
+        mAddressOffSet);
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec,
+                             MediaOperation::DestroyContext, mAddressOffSet);
+    transport->returnMemorySlot(mSlot);
+    mHasAddressSpaceMemory = false;
+}
+
+hevc_result_t MediaHevcDecoder::decodeFrame(uint8_t *img, size_t szBytes,
+                                            uint64_t pts) {
+    DDD("decode frame: use handle to host %lld", mHostHandle);
+    hevc_result_t res = {0, 0};
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return res;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    uint8_t *hostSrc = transport->getInputAddr(mAddressOffSet);
+    if (img != nullptr && szBytes > 0) {
+        memcpy(hostSrc, img, szBytes);
+    }
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(transport->offsetOf((uint64_t)(hostSrc)) -
+                              mAddressOffSet,
+                          1, mAddressOffSet);
+    transport->writeParam((uint64_t)szBytes, 2, mAddressOffSet);
+    transport->writeParam((uint64_t)pts, 3, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec,
+                             MediaOperation::DecodeImage, mAddressOffSet);
+
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    res.bytesProcessed = *(uint64_t *)(retptr);
+    res.ret = *(int *)(retptr + 8);
+
+    return res;
+}
+
+void MediaHevcDecoder::sendMetadata(MetaDataColorAspects *ptr) {
+    DDD("send metadata to host %p", ptr);
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return;
+    }
+    MetaDataColorAspects& meta = *ptr;
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(meta.type, 1, mAddressOffSet);
+    transport->writeParam(meta.primaries, 2, mAddressOffSet);
+    transport->writeParam(meta.range, 3, mAddressOffSet);
+    transport->writeParam(meta.transfer, 4, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec, MediaOperation::SendMetadata, mAddressOffSet);
+}
+
+void MediaHevcDecoder::flush() {
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return;
+    }
+    DDD("flush: use handle to host %lld", mHostHandle);
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec, MediaOperation::Flush,
+                             mAddressOffSet);
+}
+
+hevc_image_t MediaHevcDecoder::getImage() {
+    DDD("getImage: use handle to host %lld", mHostHandle);
+    hevc_image_t res{};
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return res;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    uint8_t *dst = transport->getInputAddr(
+        mAddressOffSet); // Note: reuse the same addr for input and output
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(transport->offsetOf((uint64_t)(dst)) - mAddressOffSet,
+                          1, mAddressOffSet);
+    transport->writeParam(-1, 2, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec,
+                             MediaOperation::GetImage, mAddressOffSet);
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    res.ret = *(int *)(retptr);
+    if (res.ret >= 0) {
+        res.data = dst;
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+        res.pts = *(uint64_t *)(retptr + 24);
+        res.color_primaries = *(uint32_t *)(retptr + 32);
+        res.color_range = *(uint32_t *)(retptr + 40);
+        res.color_trc = *(uint32_t *)(retptr + 48);
+        res.colorspace = *(uint32_t *)(retptr + 56);
+    } else if (res.ret == (int)(Err::DecoderRestarted)) {
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+    }
+    return res;
+}
+
+hevc_image_t
+MediaHevcDecoder::renderOnHostAndReturnImageMetadata(int hostColorBufferId) {
+    DDD("%s: use handle to host %lld", __func__, mHostHandle);
+    hevc_image_t res{};
+    if (hostColorBufferId < 0) {
+        ALOGE("%s negative color buffer id %d", __func__, hostColorBufferId);
+        return res;
+    }
+    DDD("%s send color buffer id %d", __func__, hostColorBufferId);
+    if (!mHasAddressSpaceMemory) {
+        ALOGE("%s no address space memory", __func__);
+        return res;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    uint8_t *dst = transport->getInputAddr(
+        mAddressOffSet); // Note: reuse the same addr for input and output
+    transport->writeParam((uint64_t)mHostHandle, 0, mAddressOffSet);
+    transport->writeParam(transport->offsetOf((uint64_t)(dst)) - mAddressOffSet,
+                          1, mAddressOffSet);
+    transport->writeParam((uint64_t)hostColorBufferId, 2, mAddressOffSet);
+    transport->sendOperation(MediaCodecType::HevcCodec,
+                             MediaOperation::GetImage, mAddressOffSet);
+    auto *retptr = transport->getReturnAddr(mAddressOffSet);
+    res.ret = *(int *)(retptr);
+    if (res.ret >= 0) {
+        res.data = dst; // note: the data could be junk
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+        res.pts = *(uint64_t *)(retptr + 24);
+        res.color_primaries = *(uint32_t *)(retptr + 32);
+        res.color_range = *(uint32_t *)(retptr + 40);
+        res.color_trc = *(uint32_t *)(retptr + 48);
+        res.colorspace = *(uint32_t *)(retptr + 56);
+    } else if (res.ret == (int)(Err::DecoderRestarted)) {
+        res.width = *(uint32_t *)(retptr + 8);
+        res.height = *(uint32_t *)(retptr + 16);
+    }
+    return res;
+}
diff --git a/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h b/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h
new file mode 100644
index 00000000..b071aa15
--- /dev/null
+++ b/codecs/c2/decoders/hevcdec/MediaHevcDecoder.h
@@ -0,0 +1,97 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef GOLDFISH_MEDIA_Hevc_DEC_H_
+#define GOLDFISH_MEDIA_Hevc_DEC_H_
+
+#include "goldfish_media_utils.h"
+
+struct hevc_init_result_t {
+    uint64_t host_handle;
+    int ret;
+};
+
+struct hevc_result_t {
+    int ret;
+    uint64_t bytesProcessed;
+};
+
+struct hevc_image_t {
+    const uint8_t *data;
+    uint32_t width;
+    uint32_t height;
+    uint64_t pts; // presentation time stamp
+    uint64_t color_primaries;
+    uint64_t color_range;
+    uint64_t color_trc;
+    uint64_t colorspace;
+    // on success, |ret| will indicate the size of |data|.
+    // If failed, |ret| will contain some negative error code.
+    int ret;
+};
+
+enum class RenderMode : uint8_t {
+    RENDER_BY_HOST_GPU = 1,
+    RENDER_BY_GUEST_CPU = 2,
+};
+
+class MediaHevcDecoder {
+  public:
+    MediaHevcDecoder(RenderMode renderMode);
+    virtual ~MediaHevcDecoder() = default;
+
+    enum class PixelFormat : uint8_t {
+        YUV420P = 0,
+        UYVY422 = 1,
+        BGRA8888 = 2,
+    };
+
+    enum class Err : int {
+        NoErr = 0,
+        NoDecodedFrame = -1,
+        InitContextFailed = -2,
+        DecoderRestarted = -3,
+        NALUIgnored = -4,
+    };
+
+    bool getAddressSpaceMemory();
+    void initHevcContext(unsigned int width, unsigned int height,
+                         unsigned int outWidth, unsigned int outHeight,
+                         PixelFormat pixFmt);
+    void resetHevcContext(unsigned int width, unsigned int height,
+                          unsigned int outWidth, unsigned int outHeight,
+                          PixelFormat pixFmt);
+    void destroyHevcContext();
+    hevc_result_t decodeFrame(uint8_t *img, size_t szBytes, uint64_t pts);
+    void flush();
+    // ask host to copy image data back to guest, with image metadata
+    // to guest as well
+    hevc_image_t getImage();
+    // ask host to render to hostColorBufferId, return only image metadata back
+    // to guest
+    hevc_image_t renderOnHostAndReturnImageMetadata(int hostColorBufferId);
+
+    void sendMetadata(MetaDataColorAspects *ptr);
+
+  private:
+    uint64_t mHostHandle = 0;
+    uint64_t mAddressOffSet = 0;
+    uint32_t mVersion = 100;
+    int mSlot = -1;
+    RenderMode mRenderMode = RenderMode::RENDER_BY_GUEST_CPU;
+    bool mHasAddressSpaceMemory = false;
+};
+#endif
diff --git a/codecs/c2/decoders/vpxdec/Android.bp b/codecs/c2/decoders/vpxdec/Android.bp
new file mode 100644
index 00000000..3629e9fa
--- /dev/null
+++ b/codecs/c2/decoders/vpxdec/Android.bp
@@ -0,0 +1,61 @@
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_library_static {
+    name: "goldfish_vpx_impl",
+    vendor: true,
+    srcs: [
+        "goldfish_vpx_impl.cpp",
+    ],
+    shared_libs: [
+        "libcodec2_goldfish_common",
+        "libgoldfish_codec2_store",
+        "liblog",
+    ],
+}
+
+cc_defaults {
+    name: "libcodec2_goldfish_vpXdec_defaults",
+    defaults: [
+        "android.hardware.graphics.common-ndk_static",
+        "libcodec2_goldfish-defaults",
+    ],
+
+    vendor: true,
+    srcs: [
+        "C2GoldfishVpxDec.cpp",
+    ],
+    header_libs: [
+        "libgralloc_cb.ranchu",
+    ],
+    static_libs: [
+        "goldfish_vpx_impl",
+    ],
+    shared_libs: [
+        "libgoldfish_codec2_store",
+        "libvpx",
+    ],
+}
+
+cc_library_shared {
+    name: "libcodec2_goldfish_vp8dec",
+    defaults: [
+        "libcodec2_goldfish_vpXdec_defaults",
+    ],
+}
+
+cc_library_shared {
+    name: "libcodec2_goldfish_vp9dec",
+    defaults: [
+        "libcodec2_goldfish_vpXdec_defaults",
+    ],
+    cflags: [
+        "-DVP9",
+    ],
+}
diff --git a/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp b/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
new file mode 100644
index 00000000..f1407af1
--- /dev/null
+++ b/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.cpp
@@ -0,0 +1,1108 @@
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
+
+//#define LOG_NDEBUG 0
+#define LOG_TAG "C2GoldfishVpxDec"
+#include <log/log.h>
+
+#include <algorithm>
+
+#include <aidl/android/hardware/graphics/common/BufferUsage.h>
+
+#include <media/stagefright/foundation/AUtils.h>
+#include <media/stagefright/foundation/MediaDefs.h>
+
+#include <C2AllocatorGralloc.h>
+#include <C2PlatformSupport.h>
+
+#include <C2Debug.h>
+#include <C2PlatformSupport.h>
+#include <SimpleC2Interface.h>
+#include <goldfish_codec2/store/GoldfishComponentStore.h>
+
+#include <gralloc_cb_bp.h>
+
+#include <color_buffer_utils.h>
+
+#include "C2GoldfishVpxDec.h"
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGW(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+using aidl::android::hardware::graphics::common::BufferUsage;
+
+namespace android {
+constexpr size_t kMinInputBufferSize = 6 * 1024 * 1024;
+#ifdef VP9
+constexpr char COMPONENT_NAME[] = "c2.goldfish.vp9.decoder";
+#else
+constexpr char COMPONENT_NAME[] = "c2.goldfish.vp8.decoder";
+#endif
+
+class C2GoldfishVpxDec::IntfImpl : public SimpleInterface<void>::BaseParams {
+  public:
+    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
+        : SimpleInterface<void>::BaseParams(helper, COMPONENT_NAME,
+                                            C2Component::KIND_DECODER,
+                                            C2Component::DOMAIN_VIDEO,
+#ifdef VP9
+                                            MEDIA_MIMETYPE_VIDEO_VP9
+#else
+                                            MEDIA_MIMETYPE_VIDEO_VP8
+#endif
+          ) {
+        DDD("calling IntfImpl now helper %p", helper.get());
+        noPrivateBuffers(); // TODO: account for our buffers here
+        noInputReferences();
+        noOutputReferences();
+        noInputLatency();
+        noTimeStretch();
+
+        // TODO: output latency and reordering
+
+        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
+                         .withConstValue(new C2ComponentAttributesSetting(
+                             C2Component::ATTRIB_IS_TEMPORAL))
+                         .build());
+
+        addParameter(
+            DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
+                .withDefault(new C2StreamPictureSizeInfo::output(0u, 320, 240))
+                .withFields({
+                    C2F(mSize, width).inRange(2, 4096, 2),
+                    C2F(mSize, height).inRange(2, 4096, 2),
+                })
+                .withSetter(SizeSetter)
+                .build());
+
+#ifdef VP9
+        // TODO: Add C2Config::PROFILE_VP9_2HDR ??
+        addParameter(
+            DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
+                .withDefault(new C2StreamProfileLevelInfo::input(
+                    0u, C2Config::PROFILE_VP9_0, C2Config::LEVEL_VP9_5))
+                .withFields({C2F(mProfileLevel, profile)
+                                 .oneOf({C2Config::PROFILE_VP9_0,
+                                         C2Config::PROFILE_VP9_2}),
+                             C2F(mProfileLevel, level)
+                                 .oneOf({
+                                     C2Config::LEVEL_VP9_1,
+                                     C2Config::LEVEL_VP9_1_1,
+                                     C2Config::LEVEL_VP9_2,
+                                     C2Config::LEVEL_VP9_2_1,
+                                     C2Config::LEVEL_VP9_3,
+                                     C2Config::LEVEL_VP9_3_1,
+                                     C2Config::LEVEL_VP9_4,
+                                     C2Config::LEVEL_VP9_4_1,
+                                     C2Config::LEVEL_VP9_5,
+                                 })})
+                .withSetter(ProfileLevelSetter, mSize)
+                .build());
+
+        mHdr10PlusInfoInput = C2StreamHdr10PlusInfo::input::AllocShared(0);
+        addParameter(
+            DefineParam(mHdr10PlusInfoInput, C2_PARAMKEY_INPUT_HDR10_PLUS_INFO)
+                .withDefault(mHdr10PlusInfoInput)
+                .withFields({
+                    C2F(mHdr10PlusInfoInput, m.value).any(),
+                })
+                .withSetter(Hdr10PlusInfoInputSetter)
+                .build());
+
+        mHdr10PlusInfoOutput = C2StreamHdr10PlusInfo::output::AllocShared(0);
+        addParameter(DefineParam(mHdr10PlusInfoOutput,
+                                 C2_PARAMKEY_OUTPUT_HDR10_PLUS_INFO)
+                         .withDefault(mHdr10PlusInfoOutput)
+                         .withFields({
+                             C2F(mHdr10PlusInfoOutput, m.value).any(),
+                         })
+                         .withSetter(Hdr10PlusInfoOutputSetter)
+                         .build());
+
+#if 0
+        // sample BT.2020 static info
+        mHdrStaticInfo = std::make_shared<C2StreamHdrStaticInfo::output>();
+        mHdrStaticInfo->mastering = {
+            .red   = { .x = 0.708,  .y = 0.292 },
+            .green = { .x = 0.170,  .y = 0.797 },
+            .blue  = { .x = 0.131,  .y = 0.046 },
+            .white = { .x = 0.3127, .y = 0.3290 },
+            .maxLuminance = 1000,
+            .minLuminance = 0.1,
+        };
+        mHdrStaticInfo->maxCll = 1000;
+        mHdrStaticInfo->maxFall = 120;
+
+        mHdrStaticInfo->maxLuminance = 0; // disable static info
+
+        helper->addStructDescriptors<C2MasteringDisplayColorVolumeStruct, C2ColorXyStruct>();
+        addParameter(
+                DefineParam(mHdrStaticInfo, C2_PARAMKEY_HDR_STATIC_INFO)
+                .withDefault(mHdrStaticInfo)
+                .withFields({
+                    C2F(mHdrStaticInfo, mastering.red.x).inRange(0, 1),
+                    // TODO
+                })
+                .withSetter(HdrStaticInfoSetter)
+                .build());
+#endif
+#else
+        addParameter(
+            DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
+                .withConstValue(new C2StreamProfileLevelInfo::input(
+                    0u, C2Config::PROFILE_UNUSED, C2Config::LEVEL_UNUSED))
+                .build());
+#endif
+
+        addParameter(DefineParam(mMaxSize, C2_PARAMKEY_MAX_PICTURE_SIZE)
+                         .withDefault(new C2StreamMaxPictureSizeTuning::output(
+                             0u, 320, 240))
+                         .withFields({
+                             C2F(mSize, width).inRange(2, 4096, 2),
+                             C2F(mSize, height).inRange(2, 4096, 2),
+                         })
+                         .withSetter(MaxPictureSizeSetter, mSize)
+                         .build());
+
+        addParameter(
+            DefineParam(mMaxInputSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
+                .withDefault(new C2StreamMaxBufferSizeInfo::input(
+                    0u, kMinInputBufferSize))
+                .withFields({
+                    C2F(mMaxInputSize, value).any(),
+                })
+                .calculatedAs(MaxInputSizeSetter, mMaxSize)
+                .build());
+
+        C2ChromaOffsetStruct locations[1] = {
+            C2ChromaOffsetStruct::ITU_YUV_420_0()};
+        std::shared_ptr<C2StreamColorInfo::output> defaultColorInfo =
+            C2StreamColorInfo::output::AllocShared(1u, 0u, 8u /* bitDepth */,
+                                                   C2Color::YUV_420);
+        memcpy(defaultColorInfo->m.locations, locations, sizeof(locations));
+
+        defaultColorInfo = C2StreamColorInfo::output::AllocShared(
+            {C2ChromaOffsetStruct::ITU_YUV_420_0()}, 0u, 8u /* bitDepth */,
+            C2Color::YUV_420);
+        helper->addStructDescriptors<C2ChromaOffsetStruct>();
+
+        addParameter(DefineParam(mColorInfo, C2_PARAMKEY_CODED_COLOR_INFO)
+                         .withConstValue(defaultColorInfo)
+                         .build());
+
+        addParameter(
+            DefineParam(mDefaultColorAspects, C2_PARAMKEY_DEFAULT_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsTuning::output(
+                    0u, C2Color::RANGE_UNSPECIFIED,
+                    C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mDefaultColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mDefaultColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mDefaultColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mDefaultColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(DefaultColorAspectsSetter)
+                .build());
+
+        addParameter(
+            DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsInfo::input(
+                    0u, C2Color::RANGE_LIMITED, C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mCodedColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mCodedColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mCodedColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mCodedColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(CodedColorAspectsSetter)
+                .build());
+
+        addParameter(
+            DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
+                .withDefault(new C2StreamColorAspectsInfo::output(
+                    0u, C2Color::RANGE_UNSPECIFIED,
+                    C2Color::PRIMARIES_UNSPECIFIED,
+                    C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
+                .withFields({C2F(mColorAspects, range)
+                                 .inRange(C2Color::RANGE_UNSPECIFIED,
+                                          C2Color::RANGE_OTHER),
+                             C2F(mColorAspects, primaries)
+                                 .inRange(C2Color::PRIMARIES_UNSPECIFIED,
+                                          C2Color::PRIMARIES_OTHER),
+                             C2F(mColorAspects, transfer)
+                                 .inRange(C2Color::TRANSFER_UNSPECIFIED,
+                                          C2Color::TRANSFER_OTHER),
+                             C2F(mColorAspects, matrix)
+                                 .inRange(C2Color::MATRIX_UNSPECIFIED,
+                                          C2Color::MATRIX_OTHER)})
+                .withSetter(ColorAspectsSetter, mDefaultColorAspects,
+                            mCodedColorAspects)
+                .build());
+
+        // TODO: support more formats?
+        addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
+                         .withConstValue(new C2StreamPixelFormatInfo::output(
+                             0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
+                         .build());
+    }
+
+    static C2R SizeSetter(bool mayBlock,
+                          const C2P<C2StreamPictureSizeInfo::output> &oldMe,
+                          C2P<C2StreamPictureSizeInfo::output> &me) {
+        (void)mayBlock;
+        DDD("calling sizesetter old w %d", oldMe.v.width);
+        DDD("calling sizesetter old h %d", oldMe.v.height);
+        DDD("calling sizesetter change to w %d", me.v.width);
+        DDD("calling sizesetter change to h %d", me.v.height);
+        C2R res = C2R::Ok();
+        auto mewidth = me.F(me.v.width);
+        auto meheight = me.F(me.v.height);
+
+        if (!mewidth.supportsAtAll(me.v.width)) {
+            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.width)));
+            DDD("override width with oldMe value");
+            me.set().width = oldMe.v.width;
+            DDD("something wrong here %s %d", __func__, __LINE__);
+        }
+        if (!meheight.supportsAtAll(me.v.height)) {
+            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.height)));
+            DDD("override height with oldMe value");
+            me.set().height = oldMe.v.height;
+            DDD("something wrong here %s %d", __func__, __LINE__);
+        }
+        return res;
+    }
+
+    static C2R
+    MaxPictureSizeSetter(bool mayBlock,
+                         C2P<C2StreamMaxPictureSizeTuning::output> &me,
+                         const C2P<C2StreamPictureSizeInfo::output> &size) {
+        (void)mayBlock;
+        // TODO: get max width/height from the size's field helpers vs.
+        // hardcoding
+        me.set().width = c2_min(c2_max(me.v.width, size.v.width), 4096u);
+        me.set().height = c2_min(c2_max(me.v.height, size.v.height), 4096u);
+        return C2R::Ok();
+    }
+
+    static C2R MaxInputSizeSetter(
+        bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input> &me,
+        const C2P<C2StreamMaxPictureSizeTuning::output> &maxSize) {
+        (void)mayBlock;
+        // assume compression ratio of 2
+        me.set().value = c2_max((((maxSize.v.width + 63) / 64) *
+                                 ((maxSize.v.height + 63) / 64) * 3072),
+                                kMinInputBufferSize);
+        return C2R::Ok();
+    }
+
+    static C2R
+    DefaultColorAspectsSetter(bool mayBlock,
+                              C2P<C2StreamColorAspectsTuning::output> &me) {
+        (void)mayBlock;
+        if (me.v.range > C2Color::RANGE_OTHER) {
+            me.set().range = C2Color::RANGE_OTHER;
+        }
+        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
+            me.set().primaries = C2Color::PRIMARIES_OTHER;
+        }
+        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
+            me.set().transfer = C2Color::TRANSFER_OTHER;
+        }
+        if (me.v.matrix > C2Color::MATRIX_OTHER) {
+            me.set().matrix = C2Color::MATRIX_OTHER;
+        }
+        DDD("%s %d update range %d primaries/color %d transfer %d",
+                __func__, __LINE__,
+                (int)(me.v.range),
+                (int)(me.v.primaries),
+                (int)(me.v.transfer)
+                );
+        return C2R::Ok();
+    }
+
+    static C2R
+    CodedColorAspectsSetter(bool mayBlock,
+                            C2P<C2StreamColorAspectsInfo::input> &me) {
+        (void)mayBlock;
+        if (me.v.range > C2Color::RANGE_OTHER) {
+            me.set().range = C2Color::RANGE_OTHER;
+        }
+        if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
+            me.set().primaries = C2Color::PRIMARIES_OTHER;
+        }
+        if (me.v.transfer > C2Color::TRANSFER_OTHER) {
+            me.set().transfer = C2Color::TRANSFER_OTHER;
+        }
+        if (me.v.matrix > C2Color::MATRIX_OTHER) {
+            me.set().matrix = C2Color::MATRIX_OTHER;
+        }
+        DDD("%s %d coded color aspect range %d primaries/color %d transfer %d",
+                __func__, __LINE__,
+                (int)(me.v.range),
+                (int)(me.v.primaries),
+                (int)(me.v.transfer)
+                );
+        return C2R::Ok();
+    }
+
+    static C2R
+    ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output> &me,
+                       const C2P<C2StreamColorAspectsTuning::output> &def,
+                       const C2P<C2StreamColorAspectsInfo::input> &coded) {
+        (void)mayBlock;
+        // take default values for all unspecified fields, and coded values for
+        // specified ones
+        DDD("%s %d before update: color aspect range %d primaries/color %d transfer %d",
+                __func__, __LINE__,
+                (int)(me.v.range),
+                (int)(me.v.primaries),
+                (int)(me.v.transfer)
+                );
+        me.set().range =
+            coded.v.range == RANGE_UNSPECIFIED ? def.v.range : coded.v.range;
+        me.set().primaries = coded.v.primaries == PRIMARIES_UNSPECIFIED
+                                 ? def.v.primaries
+                                 : coded.v.primaries;
+        me.set().transfer = coded.v.transfer == TRANSFER_UNSPECIFIED
+                                ? def.v.transfer
+                                : coded.v.transfer;
+        me.set().matrix = coded.v.matrix == MATRIX_UNSPECIFIED ? def.v.matrix
+                                                               : coded.v.matrix;
+
+        DDD("%s %d after update: color aspect range %d primaries/color %d transfer %d",
+                __func__, __LINE__,
+                (int)(me.v.range),
+                (int)(me.v.primaries),
+                (int)(me.v.transfer)
+                );
+        return C2R::Ok();
+    }
+
+    static C2R
+    ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input> &me,
+                       const C2P<C2StreamPictureSizeInfo::output> &size) {
+        (void)mayBlock;
+        (void)size;
+        (void)me; // TODO: validate
+        return C2R::Ok();
+    }
+    std::shared_ptr<C2StreamColorAspectsTuning::output>
+    getDefaultColorAspects_l() {
+        return mDefaultColorAspects;
+    }
+
+    std::shared_ptr<C2StreamColorAspectsInfo::output> getColorAspects_l() {
+        return mColorAspects;
+    }
+
+    int width() const { return mSize->width; }
+
+    int height() const { return mSize->height; }
+
+    int primaries() const { return mDefaultColorAspects->primaries; }
+
+    int range() const { return mDefaultColorAspects->range; }
+
+    int transfer() const { return mDefaultColorAspects->transfer; }
+
+    static C2R Hdr10PlusInfoInputSetter(bool mayBlock,
+                                        C2P<C2StreamHdr10PlusInfo::input> &me) {
+        (void)mayBlock;
+        (void)me; // TODO: validate
+        return C2R::Ok();
+    }
+
+    static C2R
+    Hdr10PlusInfoOutputSetter(bool mayBlock,
+                              C2P<C2StreamHdr10PlusInfo::output> &me) {
+        (void)mayBlock;
+        (void)me; // TODO: validate
+        return C2R::Ok();
+    }
+
+  private:
+    std::shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
+    std::shared_ptr<C2StreamPictureSizeInfo::output> mSize;
+    std::shared_ptr<C2StreamMaxPictureSizeTuning::output> mMaxSize;
+    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mMaxInputSize;
+    std::shared_ptr<C2StreamColorInfo::output> mColorInfo;
+    std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormat;
+    std::shared_ptr<C2StreamColorAspectsTuning::output> mDefaultColorAspects;
+    std::shared_ptr<C2StreamColorAspectsInfo::input> mCodedColorAspects;
+    std::shared_ptr<C2StreamColorAspectsInfo::output> mColorAspects;
+#ifdef VP9
+#if 0
+    std::shared_ptr<C2StreamHdrStaticInfo::output> mHdrStaticInfo;
+#endif
+    std::shared_ptr<C2StreamHdr10PlusInfo::input> mHdr10PlusInfoInput;
+    std::shared_ptr<C2StreamHdr10PlusInfo::output> mHdr10PlusInfoOutput;
+#endif
+};
+
+C2GoldfishVpxDec::ConverterThread::ConverterThread(
+    const std::shared_ptr<Mutexed<ConversionQueue>> &queue)
+    : Thread(false), mQueue(queue) {}
+
+bool C2GoldfishVpxDec::ConverterThread::threadLoop() {
+    Mutexed<ConversionQueue>::Locked queue(*mQueue);
+    if (queue->entries.empty()) {
+        queue.waitForCondition(queue->cond);
+        if (queue->entries.empty()) {
+            return true;
+        }
+    }
+    std::function<void()> convert = queue->entries.front();
+    queue->entries.pop_front();
+    if (!queue->entries.empty()) {
+        queue->cond.signal();
+    }
+    queue.unlock();
+
+    convert();
+
+    queue.lock();
+    if (--queue->numPending == 0u) {
+        queue->cond.broadcast();
+    }
+    return true;
+}
+
+C2GoldfishVpxDec::C2GoldfishVpxDec(const char *name, c2_node_id_t id,
+                                   const std::shared_ptr<IntfImpl> &intfImpl)
+    : SimpleC2Component(
+          std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
+      mIntf(intfImpl), mQueue(new Mutexed<ConversionQueue>) {}
+
+C2GoldfishVpxDec::~C2GoldfishVpxDec() { onRelease(); }
+
+c2_status_t C2GoldfishVpxDec::onInit() {
+    status_t err = initDecoder();
+    return err == OK ? C2_OK : C2_CORRUPTED;
+}
+
+c2_status_t C2GoldfishVpxDec::onStop() {
+    mSignalledError = false;
+    mSignalledOutputEos = false;
+
+    return C2_OK;
+}
+
+void C2GoldfishVpxDec::onReset() {
+    (void)onStop();
+    c2_status_t err = onFlush_sm();
+    if (err != C2_OK) {
+        ALOGW("Failed to flush decoder. Try to hard reset decoder");
+        destroyDecoder();
+        (void)initDecoder();
+    }
+}
+
+void C2GoldfishVpxDec::onRelease() { destroyDecoder(); }
+
+void C2GoldfishVpxDec::sendMetadata() {
+    // compare and send if changed
+    MetaDataColorAspects currentMetaData = {1, 0, 0, 0};
+    currentMetaData.primaries = mIntf->primaries();
+    currentMetaData.range = mIntf->range();
+    currentMetaData.transfer = mIntf->transfer();
+
+    DDD("metadata primaries %d range %d transfer %d",
+            (int)(currentMetaData.primaries),
+            (int)(currentMetaData.range),
+            (int)(currentMetaData.transfer)
+       );
+
+    if (mSentMetadata.primaries == currentMetaData.primaries &&
+        mSentMetadata.range == currentMetaData.range &&
+        mSentMetadata.transfer == currentMetaData.transfer) {
+        DDD("metadata is the same, no need to update");
+        return;
+    }
+    std::swap(mSentMetadata, currentMetaData);
+
+    vpx_codec_send_metadata(mCtx, &(mSentMetadata));
+}
+
+c2_status_t C2GoldfishVpxDec::onFlush_sm() {
+    if (mFrameParallelMode) {
+        // Flush decoder by passing nullptr data ptr and 0 size.
+        // Ideally, this should never fail.
+        if (vpx_codec_flush(mCtx)) {
+            ALOGE("Failed to flush on2 decoder.");
+            return C2_CORRUPTED;
+        }
+    }
+
+    // Drop all the decoded frames in decoder.
+    if (mCtx) {
+        setup_ctx_parameters(mCtx);
+        while ((mImg = vpx_codec_get_frame(mCtx))) {
+        }
+    }
+
+    mSignalledError = false;
+    mSignalledOutputEos = false;
+    return C2_OK;
+}
+
+status_t C2GoldfishVpxDec::initDecoder() {
+    ALOGI("calling init GoldfishVPX");
+    mWidth = 320;
+    mHeight = 240;
+    mFrameParallelMode = false;
+    mSignalledOutputEos = false;
+    mSignalledError = false;
+
+    return OK;
+}
+
+void C2GoldfishVpxDec::checkContext(const std::shared_ptr<C2BlockPool> &pool) {
+    if (mCtx)
+        return;
+
+    mWidth = mIntf->width();
+    mHeight = mIntf->height();
+    ALOGI("created decoder context w %d h %d", mWidth, mHeight);
+    mCtx = new vpx_codec_ctx_t;
+#ifdef VP9
+    mCtx->vpversion = 9;
+#else
+    mCtx->vpversion = 8;
+#endif
+
+    //const bool isGraphic = (pool->getLocalId() == C2PlatformAllocatorStore::GRALLOC);
+    const bool isGraphic = (pool->getAllocatorId() & C2Allocator::GRAPHIC);
+    DDD("buffer pool allocator id %x",  (int)(pool->getAllocatorId()));
+    if (isGraphic) {
+        uint64_t client_usage = getClientUsage(pool);
+        DDD("client has usage as 0x%llx", client_usage);
+        if (client_usage & static_cast<uint32_t>(BufferUsage::CPU_READ_MASK)) {
+            DDD("decoding to guest byte buffer as client has read usage");
+            mEnableAndroidNativeBuffers = false;
+        } else {
+            DDD("decoding to host color buffer");
+            mEnableAndroidNativeBuffers = true;
+        }
+    } else {
+        DDD("decoding to guest byte buffer");
+        mEnableAndroidNativeBuffers = false;
+    }
+
+    mCtx->version = mEnableAndroidNativeBuffers ? 200 : 100;
+
+    int vpx_err = 0;
+    if ((vpx_err = vpx_codec_dec_init(mCtx))) {
+        ALOGE("vpx decoder failed to initialize. (%d)", vpx_err);
+        delete mCtx;
+        mCtx = NULL;
+    }
+}
+
+status_t C2GoldfishVpxDec::destroyDecoder() {
+    if (mCtx) {
+        ALOGI("calling destroying GoldfishVPX ctx %p", mCtx);
+        vpx_codec_destroy(mCtx);
+        delete mCtx;
+        mCtx = NULL;
+    }
+
+    return OK;
+}
+
+void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
+    uint32_t flags = 0;
+    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
+        flags |= C2FrameData::FLAG_END_OF_STREAM;
+        DDD("signalling eos");
+    }
+    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
+    work->worklets.front()->output.buffers.clear();
+    work->worklets.front()->output.ordinal = work->input.ordinal;
+    work->workletsProcessed = 1u;
+}
+
+void C2GoldfishVpxDec::finishWork(
+    uint64_t index, const std::unique_ptr<C2Work> &work,
+    const std::shared_ptr<C2GraphicBlock> &block) {
+    std::shared_ptr<C2Buffer> buffer =
+        createGraphicBuffer(block, C2Rect(mWidth, mHeight));
+    {
+        IntfImpl::Lock lock = mIntf->lock();
+#ifdef VP9
+        buffer->setInfo(mIntf->getColorAspects_l());
+#else
+        std::shared_ptr<C2StreamColorAspectsInfo::output> tColorAspects =
+            std::make_shared<C2StreamColorAspectsInfo::output>
+            (C2StreamColorAspectsInfo::output(0u, m_range,
+                m_primaries, m_transfer,
+                m_matrix));
+        DDD("%s %d setting to index %d range %d primaries %d transfer %d",
+                __func__, __LINE__, (int)index,
+                (int)tColorAspects->range,
+                (int)tColorAspects->primaries,
+                (int)tColorAspects->transfer);
+        buffer->setInfo(tColorAspects);
+#endif
+    }
+
+    auto fillWork = [buffer, index,
+                     intf = this->mIntf](const std::unique_ptr<C2Work> &work) {
+        uint32_t flags = 0;
+        if ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) &&
+            (c2_cntr64_t(index) == work->input.ordinal.frameIndex)) {
+            flags |= C2FrameData::FLAG_END_OF_STREAM;
+            DDD("signalling eos");
+        }
+        work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
+        work->worklets.front()->output.buffers.clear();
+        work->worklets.front()->output.buffers.push_back(buffer);
+        work->worklets.front()->output.ordinal = work->input.ordinal;
+        work->workletsProcessed = 1u;
+
+        for (const std::unique_ptr<C2Param> &param : work->input.configUpdate) {
+            if (param) {
+                C2StreamHdr10PlusInfo::input *hdr10PlusInfo =
+                    C2StreamHdr10PlusInfo::input::From(param.get());
+
+                if (hdr10PlusInfo != nullptr) {
+                    std::vector<std::unique_ptr<C2SettingResult>> failures;
+                    std::unique_ptr<C2Param> outParam = C2Param::CopyAsStream(
+                        *param.get(), true /*output*/, param->stream());
+                    c2_status_t err =
+                        intf->config({outParam.get()}, C2_MAY_BLOCK, &failures);
+                    if (err == C2_OK) {
+                        work->worklets.front()->output.configUpdate.push_back(
+                            C2Param::Copy(*outParam.get()));
+                    } else {
+                        ALOGE("finishWork: Config update size failed");
+                    }
+                    break;
+                }
+            }
+        }
+    };
+    if (work && c2_cntr64_t(index) == work->input.ordinal.frameIndex) {
+        fillWork(work);
+    } else {
+        finish(index, fillWork);
+    }
+}
+
+void C2GoldfishVpxDec::process(const std::unique_ptr<C2Work> &work,
+                               const std::shared_ptr<C2BlockPool> &pool) {
+    DDD("%s %d doing work now", __func__, __LINE__);
+    // Initialize output work
+    work->result = C2_OK;
+    work->workletsProcessed = 0u;
+    work->worklets.front()->output.configUpdate.clear();
+    work->worklets.front()->output.flags = work->input.flags;
+
+    if (mSignalledError || mSignalledOutputEos) {
+        work->result = C2_BAD_VALUE;
+        return;
+    }
+
+    size_t inOffset = 0u;
+    size_t inSize = 0u;
+    C2ReadView rView = mDummyReadView;
+    if (!work->input.buffers.empty()) {
+        rView =
+            work->input.buffers[0]->data().linearBlocks().front().map().get();
+        inSize = rView.capacity();
+        if (inSize && rView.error()) {
+            ALOGE("read view map failed %d", rView.error());
+            work->result = C2_CORRUPTED;
+            return;
+        }
+    }
+
+    checkContext(pool);
+
+    bool codecConfig =
+        ((work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) != 0);
+    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
+
+    DDD("in buffer attr. size %zu timestamp %d frameindex %d, flags %x", inSize,
+        (int)work->input.ordinal.timestamp.peeku(),
+        (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);
+
+#ifndef VP9
+    {
+        constexpr uint64_t ONE_SECOND_IN_MICRO_SECOND = 1000 * 1000;
+        // bug: 349159609
+        // note, vp8 does not have the FLAG_CODEC_CONFIG and the test
+        // android.mediav2.cts.DecoderDynamicColorAspectTest test still
+        // expects vp8 to pass. so this hack is to check the time stamp
+        // change to update the color aspect: too early or too late is
+        // a problem as it can cause mismatch of frame and coloraspect
+        DDD("%s %d vp8 last pts is %d current pts is %d",
+                __func__, __LINE__, mLastPts, (int) work->input.ordinal.timestamp.peeku());
+        if (mLastPts + ONE_SECOND_IN_MICRO_SECOND <= work->input.ordinal.timestamp.peeku()) {
+            codecConfig = true;
+            DDD("%s %d updated codecConfig to true", __func__, __LINE__);
+        } else {
+            DDD("%s %d keep codecConfig to false", __func__, __LINE__);
+        }
+        mLastPts = work->input.ordinal.timestamp.peeku();
+        if (mLastPts == 0) {
+            codecConfig = true;
+        }
+        if (codecConfig) {
+            IntfImpl::Lock lock = mIntf->lock();
+            std::shared_ptr<C2StreamColorAspectsTuning::output> defaultColorAspects =
+            mIntf->getDefaultColorAspects_l();
+            m_primaries = defaultColorAspects->primaries;
+            m_range = defaultColorAspects->range;
+            m_transfer = defaultColorAspects->transfer;
+            m_matrix = defaultColorAspects->matrix;
+        }
+    }
+#endif  // #ifndef VP9
+
+    if (codecConfig) {
+        {
+            IntfImpl::Lock lock = mIntf->lock();
+            std::shared_ptr<C2StreamColorAspectsTuning::output> defaultColorAspects =
+                mIntf->getDefaultColorAspects_l();
+            lock.unlock();
+            C2StreamColorAspectsInfo::input codedAspects(0u, defaultColorAspects->range,
+                defaultColorAspects->primaries, defaultColorAspects->transfer,
+                defaultColorAspects->matrix);
+            std::vector<std::unique_ptr<C2SettingResult>> failures;
+            (void)mIntf->config({&codedAspects}, C2_MAY_BLOCK, &failures);
+        }
+
+        DDD("%s %d updated coloraspect due to codec config", __func__, __LINE__);
+#ifdef VP9
+        fillEmptyWork(work);
+        return;
+#endif
+    }
+
+    sendMetadata();
+
+    if (inSize) {
+        uint8_t *bitstream = const_cast<uint8_t *>(rView.data() + inOffset);
+        vpx_codec_err_t err = vpx_codec_decode(
+            mCtx, bitstream, inSize, &work->input.ordinal.frameIndex, 0);
+        if (err != 0) {
+            ALOGE("on2 decoder failed to decode frame. err: ");
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            work->result = C2_CORRUPTED;
+            return;
+        }
+    }
+
+    status_t err = outputBuffer(pool, work);
+    if (err == NOT_ENOUGH_DATA) {
+        if (inSize > 0) {
+            DDD("Maybe non-display frame at %lld.",
+                work->input.ordinal.frameIndex.peekll());
+            // send the work back with empty buffer.
+            inSize = 0;
+        }
+    } else if (err != OK) {
+        ALOGD("Error while getting the output frame out");
+        // work->result would be already filled; do fillEmptyWork() below to
+        // send the work back.
+        inSize = 0;
+    }
+
+    if (eos) {
+        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
+        mSignalledOutputEos = true;
+    } else if (!inSize) {
+        fillEmptyWork(work);
+    }
+}
+
+static void copyOutputBufferToYuvPlanarFrame(
+    uint8_t *dst, const uint8_t *srcY, const uint8_t *srcU, const uint8_t *srcV,
+    size_t srcYStride, size_t srcUStride, size_t srcVStride, size_t dstYStride,
+    size_t dstUVStride, uint32_t width, uint32_t height) {
+    uint8_t *dstStart = dst;
+
+    for (size_t i = 0; i < height; ++i) {
+        memcpy(dst, srcY, width);
+        srcY += srcYStride;
+        dst += dstYStride;
+    }
+
+    dst = dstStart + dstYStride * height;
+    for (size_t i = 0; i < height / 2; ++i) {
+        memcpy(dst, srcV, width / 2);
+        srcV += srcVStride;
+        dst += dstUVStride;
+    }
+
+    dst = dstStart + (dstYStride * height) + (dstUVStride * height / 2);
+    for (size_t i = 0; i < height / 2; ++i) {
+        memcpy(dst, srcU, width / 2);
+        srcU += srcUStride;
+        dst += dstUVStride;
+    }
+}
+
+void C2GoldfishVpxDec::setup_ctx_parameters(vpx_codec_ctx_t *ctx,
+                                            int hostColorBufferId) {
+    ctx->width = mWidth;
+    ctx->height = mHeight;
+    ctx->hostColorBufferId = hostColorBufferId;
+    ctx->outputBufferWidth = mWidth;
+    ctx->outputBufferHeight = mHeight;
+    ctx->bpp = 1;
+}
+
+status_t
+C2GoldfishVpxDec::outputBuffer(const std::shared_ptr<C2BlockPool> &pool,
+                               const std::unique_ptr<C2Work> &work) {
+    if (!(work && pool))
+        return BAD_VALUE;
+
+    // now get the block
+    std::shared_ptr<C2GraphicBlock> block;
+    uint32_t format = HAL_PIXEL_FORMAT_YCBCR_420_888;
+    const C2MemoryUsage usage = {(uint64_t)(BufferUsage::VIDEO_DECODER),
+                                 C2MemoryUsage::CPU_WRITE | C2MemoryUsage::CPU_READ};
+
+    c2_status_t err = pool->fetchGraphicBlock(align(mWidth, 2), mHeight, format,
+                                              usage, &block);
+    if (err != C2_OK) {
+        ALOGE("fetchGraphicBlock for Output failed with status %d", err);
+        work->result = err;
+        return UNKNOWN_ERROR;
+    }
+
+    int hostColorBufferId = -1;
+    const bool decodingToHostColorBuffer = mEnableAndroidNativeBuffers;
+    if(decodingToHostColorBuffer){
+        auto c2Handle = block->handle();
+        native_handle_t *grallocHandle =
+            UnwrapNativeCodec2GrallocHandle(c2Handle);
+        hostColorBufferId = getColorBufferHandle(grallocHandle);
+        if (hostColorBufferId > 0) {
+            DDD("found handle %d", hostColorBufferId);
+        } else {
+            DDD("decode to buffer, because handle %d is invalid",
+                hostColorBufferId);
+            // change to -1 so host knows it is definitely invalid
+            // 0 is a bit confusing
+            hostColorBufferId = -1;
+        }
+    }
+    setup_ctx_parameters(mCtx, hostColorBufferId);
+
+    vpx_image_t *img = vpx_codec_get_frame(mCtx);
+
+    if (!img)
+        return NOT_ENOUGH_DATA;
+
+    if (img->d_w != mWidth || img->d_h != mHeight) {
+        DDD("updating w %d h %d to w %d h %d", mWidth, mHeight, img->d_w,
+            img->d_h);
+        mWidth = img->d_w;
+        mHeight = img->d_h;
+
+        // need to re-allocate since size changed, especially for byte buffer
+        // mode
+        if (true) {
+            c2_status_t err = pool->fetchGraphicBlock(align(mWidth, 2), mHeight,
+                                                      format, usage, &block);
+            if (err != C2_OK) {
+                ALOGE("fetchGraphicBlock for Output failed with status %d",
+                      err);
+                work->result = err;
+                return UNKNOWN_ERROR;
+            }
+        }
+
+        C2StreamPictureSizeInfo::output size(0u, mWidth, mHeight);
+        std::vector<std::unique_ptr<C2SettingResult>> failures;
+        c2_status_t err = mIntf->config({&size}, C2_MAY_BLOCK, &failures);
+        if (err == C2_OK) {
+            work->worklets.front()->output.configUpdate.push_back(
+                C2Param::Copy(size));
+        } else {
+            ALOGE("Config update size failed");
+            mSignalledError = true;
+            work->workletsProcessed = 1u;
+            work->result = C2_CORRUPTED;
+            return UNKNOWN_ERROR;
+        }
+    }
+    if (img->fmt != VPX_IMG_FMT_I420 && img->fmt != VPX_IMG_FMT_I42016) {
+        ALOGE("img->fmt %d not supported", img->fmt);
+        mSignalledError = true;
+        work->workletsProcessed = 1u;
+        work->result = C2_CORRUPTED;
+        return false;
+    }
+
+    if (img->fmt == VPX_IMG_FMT_I42016) {
+        IntfImpl::Lock lock = mIntf->lock();
+        std::shared_ptr<C2StreamColorAspectsTuning::output>
+            defaultColorAspects = mIntf->getDefaultColorAspects_l();
+
+        if (defaultColorAspects->primaries == C2Color::PRIMARIES_BT2020 &&
+            defaultColorAspects->matrix == C2Color::MATRIX_BT2020 &&
+            defaultColorAspects->transfer == C2Color::TRANSFER_ST2084) {
+            format = HAL_PIXEL_FORMAT_RGBA_1010102;
+        }
+    }
+
+    if (!decodingToHostColorBuffer) {
+
+        C2GraphicView wView = block->map().get();
+        if (wView.error()) {
+            ALOGE("graphic view map failed %d", wView.error());
+            work->result = C2_CORRUPTED;
+            return UNKNOWN_ERROR;
+        }
+
+        DDD("provided (%dx%d) required (%dx%d), out frameindex %lld",
+            block->width(), block->height(), mWidth, mHeight,
+            ((c2_cntr64_t *)img->user_priv)->peekll());
+
+        uint8_t *dst =
+            const_cast<uint8_t *>(wView.data()[C2PlanarLayout::PLANE_Y]);
+        size_t srcYStride = mWidth;
+        size_t srcUStride = mWidth / 2;
+        size_t srcVStride = mWidth / 2;
+        C2PlanarLayout layout = wView.layout();
+        size_t dstYStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
+        size_t dstUVStride = layout.planes[C2PlanarLayout::PLANE_U].rowInc;
+
+        if (img->fmt == VPX_IMG_FMT_I42016) {
+            ALOGW("WARNING: not I42016 is not supported !!!");
+        } else if (1) {
+            const uint8_t *srcY = (const uint8_t *)mCtx->dst;
+            const uint8_t *srcV = srcY + mWidth * mHeight;
+            const uint8_t *srcU = srcV + mWidth * mHeight / 4;
+            // TODO: the following crashes
+            copyOutputBufferToYuvPlanarFrame(dst, srcY, srcU, srcV, srcYStride,
+                                             srcUStride, srcVStride, dstYStride,
+                                             dstUVStride, mWidth, mHeight);
+            // memcpy(dst, srcY, mWidth * mHeight / 2);
+        }
+    }
+    DDD("provided (%dx%d) required (%dx%d), out frameindex %lld",
+        block->width(), block->height(), mWidth, mHeight,
+        ((c2_cntr64_t *)img->user_priv)->peekll());
+
+    finishWork(((c2_cntr64_t *)img->user_priv)->peekull(), work,
+               std::move(block));
+    return OK;
+}
+
+c2_status_t
+C2GoldfishVpxDec::drainInternal(uint32_t drainMode,
+                                const std::shared_ptr<C2BlockPool> &pool,
+                                const std::unique_ptr<C2Work> &work) {
+    if (drainMode == NO_DRAIN) {
+        ALOGW("drain with NO_DRAIN: no-op");
+        return C2_OK;
+    }
+    if (drainMode == DRAIN_CHAIN) {
+        ALOGW("DRAIN_CHAIN not supported");
+        return C2_OMITTED;
+    }
+
+    while (outputBuffer(pool, work) == OK) {
+    }
+
+    if (drainMode == DRAIN_COMPONENT_WITH_EOS && work &&
+        work->workletsProcessed == 0u) {
+        fillEmptyWork(work);
+    }
+
+    return C2_OK;
+}
+c2_status_t C2GoldfishVpxDec::drain(uint32_t drainMode,
+                                    const std::shared_ptr<C2BlockPool> &pool) {
+    return drainInternal(drainMode, pool, nullptr);
+}
+
+class C2GoldfishVpxFactory : public C2ComponentFactory {
+  public:
+    C2GoldfishVpxFactory()
+        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
+              GoldfishComponentStore::Create()->getParamReflector())) {
+
+        ALOGI("platform store is %p, reflector is %p",
+              GetCodec2PlatformComponentStore().get(),
+              GetCodec2PlatformComponentStore()->getParamReflector().get());
+    }
+
+    virtual c2_status_t
+    createComponent(c2_node_id_t id,
+                    std::shared_ptr<C2Component> *const component,
+                    std::function<void(C2Component *)> deleter) override {
+        *component = std::shared_ptr<C2Component>(
+            new C2GoldfishVpxDec(
+                COMPONENT_NAME, id,
+                std::make_shared<C2GoldfishVpxDec::IntfImpl>(mHelper)),
+            deleter);
+        return C2_OK;
+    }
+
+    virtual c2_status_t createInterface(
+        c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *const interface,
+        std::function<void(C2ComponentInterface *)> deleter) override {
+        *interface = std::shared_ptr<C2ComponentInterface>(
+            new SimpleInterface<C2GoldfishVpxDec::IntfImpl>(
+                COMPONENT_NAME, id,
+                std::make_shared<C2GoldfishVpxDec::IntfImpl>(mHelper)),
+            deleter);
+        return C2_OK;
+    }
+
+    virtual ~C2GoldfishVpxFactory() override = default;
+
+  private:
+    std::shared_ptr<C2ReflectorHelper> mHelper;
+};
+
+} // namespace android
+
+extern "C" ::C2ComponentFactory *CreateCodec2Factory() {
+    DDD("in %s", __func__);
+    return new ::android::C2GoldfishVpxFactory();
+}
+
+extern "C" void DestroyCodec2Factory(::C2ComponentFactory *factory) {
+    DDD("in %s", __func__);
+    delete factory;
+}
diff --git a/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h b/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h
new file mode 100644
index 00000000..25141455
--- /dev/null
+++ b/codecs/c2/decoders/vpxdec/C2GoldfishVpxDec.h
@@ -0,0 +1,110 @@
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
+
+#pragma once
+
+#include "goldfish_media_utils.h"
+#include "goldfish_vpx_defs.h"
+#include <SimpleC2Component.h>
+
+namespace android {
+
+struct C2GoldfishVpxDec : public SimpleC2Component {
+    class IntfImpl;
+
+    C2GoldfishVpxDec(const char *name, c2_node_id_t id,
+                     const std::shared_ptr<IntfImpl> &intfImpl);
+    virtual ~C2GoldfishVpxDec();
+
+    // From SimpleC2Component
+    c2_status_t onInit() override;
+    c2_status_t onStop() override;
+    void onReset() override;
+    void onRelease() override;
+    c2_status_t onFlush_sm() override;
+    void process(const std::unique_ptr<C2Work> &work,
+                 const std::shared_ptr<C2BlockPool> &pool) override;
+    c2_status_t drain(uint32_t drainMode,
+                      const std::shared_ptr<C2BlockPool> &pool) override;
+
+  private:
+    struct ConversionQueue;
+
+    class ConverterThread : public Thread {
+      public:
+        explicit ConverterThread(
+            const std::shared_ptr<Mutexed<ConversionQueue>> &queue);
+        ~ConverterThread() override = default;
+        bool threadLoop() override;
+
+      private:
+        std::shared_ptr<Mutexed<ConversionQueue>> mQueue;
+    };
+
+    struct ConversionQueue {
+        std::list<std::function<void()>> entries;
+        Condition cond;
+        size_t numPending{0u};
+    };
+
+    // create context that talks to host decoder: it needs to use
+    // pool to decide whether decoding to host color buffer ot
+    // decode to guest bytebuffer when pool cannot fetch valid host
+    // color buffer id
+    void checkContext(const std::shared_ptr<C2BlockPool> &pool);
+
+    void setup_ctx_parameters(vpx_codec_ctx_t *ctx, int hostColorBufferId = -1);
+
+    status_t initDecoder();
+    status_t destroyDecoder();
+    void finishWork(uint64_t index, const std::unique_ptr<C2Work> &work,
+                    const std::shared_ptr<C2GraphicBlock> &block);
+    status_t outputBuffer(const std::shared_ptr<C2BlockPool> &pool,
+                          const std::unique_ptr<C2Work> &work);
+    c2_status_t drainInternal(uint32_t drainMode,
+                              const std::shared_ptr<C2BlockPool> &pool,
+                              const std::unique_ptr<C2Work> &work);
+
+    void sendMetadata();
+
+    std::shared_ptr<C2StreamColorAspectsTuning::output> mColorAspects;
+    std::shared_ptr<IntfImpl> mIntf;
+    std::shared_ptr<Mutexed<ConversionQueue>> mQueue;
+    std::vector<sp<ConverterThread>> mConverterThreads;
+    vpx_codec_ctx_t *mCtx{nullptr};
+    vpx_image_t *mImg{nullptr};
+
+#ifndef VP9
+    uint64_t mLastPts { 0 };
+    C2Color::range_t m_range;
+    C2Color::primaries_t m_primaries;
+    C2Color::transfer_t m_transfer;
+    C2Color::matrix_t m_matrix;
+#endif
+
+    MetaDataColorAspects mSentMetadata = {1, 0, 0, 0};
+
+    uint32_t mWidth{0};
+    uint32_t mHeight{0};
+    bool mEnableAndroidNativeBuffers{true};
+    bool mSignalledOutputEos{false};
+    bool mSignalledError{false};
+    bool mFrameParallelMode{false}; // Frame parallel is only supported by VP9 decoder.
+
+    C2_DO_NOT_COPY(C2GoldfishVpxDec);
+};
+
+} // namespace android
diff --git a/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h b/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h
new file mode 100644
index 00000000..cccd1c72
--- /dev/null
+++ b/codecs/c2/decoders/vpxdec/goldfish_vpx_defs.h
@@ -0,0 +1,69 @@
+#ifndef MY_VPX_DEFS_H_
+#define MY_VPX_DEFS_H_
+
+#include <cstdint>
+
+#define VPX_IMG_FMT_PLANAR 0x100       /**< Image is a planar format. */
+#define VPX_IMG_FMT_UV_FLIP 0x200      /**< V plane precedes U in memory. */
+#define VPX_IMG_FMT_HAS_ALPHA 0x400    /**< Image has an alpha channel. */
+#define VPX_IMG_FMT_HIGHBITDEPTH 0x800 /**< Image uses 16bit framebuffer. */
+
+typedef int vpx_codec_err_t;
+
+enum class RenderMode {
+    RENDER_BY_HOST_GPU = 1,
+    RENDER_BY_GUEST_CPU = 2,
+};
+
+enum vpx_img_fmt_t {
+    VPX_IMG_FMT_NONE,
+    VPX_IMG_FMT_YV12 =
+        VPX_IMG_FMT_PLANAR | VPX_IMG_FMT_UV_FLIP | 1, /**< planar YVU */
+    VPX_IMG_FMT_I420 = VPX_IMG_FMT_PLANAR | 2,
+    VPX_IMG_FMT_I422 = VPX_IMG_FMT_PLANAR | 5,
+    VPX_IMG_FMT_I444 = VPX_IMG_FMT_PLANAR | 6,
+    VPX_IMG_FMT_I440 = VPX_IMG_FMT_PLANAR | 7,
+    VPX_IMG_FMT_I42016 = VPX_IMG_FMT_I420 | VPX_IMG_FMT_HIGHBITDEPTH,
+    VPX_IMG_FMT_I42216 = VPX_IMG_FMT_I422 | VPX_IMG_FMT_HIGHBITDEPTH,
+    VPX_IMG_FMT_I44416 = VPX_IMG_FMT_I444 | VPX_IMG_FMT_HIGHBITDEPTH,
+    VPX_IMG_FMT_I44016 = VPX_IMG_FMT_I440 | VPX_IMG_FMT_HIGHBITDEPTH
+};
+
+struct vpx_image_t {
+    void *user_priv;
+    uint32_t d_w;       /**< Displayed image width */
+    uint32_t d_h;       /**< Displayed image height */
+    vpx_img_fmt_t fmt;  /**< Image Format */
+};
+
+#define VPX_CODEC_OK 0
+
+struct vpx_codec_ctx_t {
+    vpx_image_t myImg;
+    uint8_t *data;
+    uint8_t *dst;
+    uint64_t address_offset = 0;
+    uint64_t id; // >= 1, unique
+
+    uint32_t outputBufferWidth;
+    uint32_t outputBufferHeight;
+    uint32_t width;
+    uint32_t height;
+
+    int hostColorBufferId;
+    int memory_slot;
+    int version;        // 100: return decoded frame to guest; 200: render on host
+    uint8_t vpversion;  // 8: vp8 or 9: vp9
+    uint8_t bpp;
+};
+
+int vpx_codec_destroy(vpx_codec_ctx_t *);
+int vpx_codec_dec_init(vpx_codec_ctx_t *);
+vpx_image_t *vpx_codec_get_frame(vpx_codec_ctx_t *, int hostColorBufferId = -1);
+int vpx_codec_flush(vpx_codec_ctx_t *ctx);
+int vpx_codec_decode(vpx_codec_ctx_t *ctx, const uint8_t *data,
+                     unsigned int data_sz, void *user_priv, long deadline);
+
+void vpx_codec_send_metadata(vpx_codec_ctx_t *ctx, void*ptr);
+
+#endif // MY_VPX_DEFS_H_
diff --git a/codecs/c2/decoders/vpxdec/goldfish_vpx_impl.cpp b/codecs/c2/decoders/vpxdec/goldfish_vpx_impl.cpp
new file mode 100644
index 00000000..e1fa879f
--- /dev/null
+++ b/codecs/c2/decoders/vpxdec/goldfish_vpx_impl.cpp
@@ -0,0 +1,188 @@
+#include <log/log.h>
+
+#include "goldfish_media_utils.h"
+#include "goldfish_vpx_defs.h"
+#include <cstdlib>
+#include <errno.h>
+#include <fcntl.h>
+#include <linux/ioctl.h>
+#include <linux/types.h>
+#include <string>
+#include <sys/ioctl.h>
+#include <sys/mman.h>
+#include <sys/stat.h>
+#include <sys/types.h>
+#include <unistd.h>
+
+#include <memory>
+#include <mutex>
+#include <vector>
+
+#define DEBUG 0
+#if DEBUG
+#define DDD(...) ALOGD(__VA_ARGS__)
+#else
+#define DDD(...) ((void)0)
+#endif
+
+// static vpx_image_t myImg;
+static uint64_t s_CtxId = 0;
+static std::mutex sCtxidMutex;
+
+static uint64_t applyForOneId() {
+    DDD("%s %d", __func__, __LINE__);
+    std::lock_guard<std::mutex> g{sCtxidMutex};
+    ++s_CtxId;
+    return s_CtxId;
+}
+
+static void sendVpxOperation(vpx_codec_ctx_t *ctx, MediaOperation op) {
+    DDD("%s %d", __func__, __LINE__);
+    if (ctx->memory_slot < 0) {
+        ALOGE("ERROR: Failed %s %d: there is no memory slot", __func__,
+              __LINE__);
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->sendOperation(ctx->vpversion == 9 ? MediaCodecType::VP9Codec
+                                                 : MediaCodecType::VP8Codec,
+                             op, ctx->address_offset);
+}
+
+int vpx_codec_destroy(vpx_codec_ctx_t *ctx) {
+    DDD("%s %d", __func__, __LINE__);
+    if (!ctx) {
+        ALOGE("ERROR: Failed %s %d: ctx is nullptr", __func__, __LINE__);
+        return -1;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam(ctx->id, 0, ctx->address_offset);
+    sendVpxOperation(ctx, MediaOperation::DestroyContext);
+    transport->returnMemorySlot(ctx->memory_slot);
+    ctx->memory_slot = -1;
+    return 0;
+}
+
+int vpx_codec_dec_init(vpx_codec_ctx_t *ctx) {
+    DDD("%s %d", __func__, __LINE__);
+    auto transport = GoldfishMediaTransport::getInstance();
+    int slot = transport->getMemorySlot();
+    if (slot < 0) {
+        ALOGE("ERROR: Failed %s %d: cannot get memory slot", __func__,
+              __LINE__);
+        return -1;
+    } else {
+        DDD("got slot %d", slot);
+    }
+    ctx->id = applyForOneId();
+    ctx->memory_slot = slot;
+    ctx->address_offset =
+        static_cast<unsigned int>(ctx->memory_slot) * (1 << 20);
+    DDD("got address offset 0x%x version %d", (int)(ctx->address_offset),
+        ctx->version);
+
+    // data and dst are on the host side actually
+    ctx->data = transport->getInputAddr(ctx->address_offset);
+    ctx->dst =
+        transport->getInputAddr(ctx->address_offset); // re-use input address
+    transport->writeParam(ctx->id, 0, ctx->address_offset);
+    transport->writeParam(ctx->version, 1, ctx->address_offset);
+    sendVpxOperation(ctx, MediaOperation::InitContext);
+    return 0;
+}
+
+static int getReturnCode(uint8_t *ptr) {
+    int *pint = (int *)(ptr);
+    return *pint;
+}
+
+// vpx_image_t myImg;
+static void getVpxFrame(uint8_t *ptr, vpx_image_t &myImg) {
+    DDD("%s %d", __func__, __LINE__);
+    uint8_t *imgptr = (ptr + 8);
+    myImg.fmt = *(vpx_img_fmt_t *)imgptr;
+    imgptr += 8;
+    myImg.d_w = *(unsigned int *)imgptr;
+    imgptr += 8;
+    myImg.d_h = *(unsigned int *)imgptr;
+    imgptr += 8;
+    myImg.user_priv = (void *)(*(uint64_t *)imgptr);
+    DDD("fmt %d dw %d dh %d userpriv %p", (int)myImg.fmt, (int)myImg.d_w,
+        (int)myImg.d_h, myImg.user_priv);
+}
+
+// TODO: we might not need to do the putting all the time
+vpx_image_t *vpx_codec_get_frame(vpx_codec_ctx_t *ctx, int hostColorBufferId) {
+    DDD("%s %d %p", __func__, __LINE__);
+    (void)hostColorBufferId;
+    if (!ctx) {
+        ALOGE("ERROR: Failed %s %d: ctx is nullptr", __func__, __LINE__);
+        return nullptr;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+
+    transport->writeParam(ctx->id, 0, ctx->address_offset);
+    transport->writeParam(ctx->outputBufferWidth, 1, ctx->address_offset);
+    transport->writeParam(ctx->outputBufferHeight, 2, ctx->address_offset);
+    transport->writeParam(ctx->width, 3, ctx->address_offset);
+    transport->writeParam(ctx->height, 4, ctx->address_offset);
+    transport->writeParam(ctx->bpp, 5, ctx->address_offset);
+    transport->writeParam(ctx->hostColorBufferId, 6, ctx->address_offset);
+    transport->writeParam(transport->offsetOf((uint64_t)(ctx->dst)) -
+                              ctx->address_offset,
+                          7, ctx->address_offset);
+
+    sendVpxOperation(ctx, MediaOperation::GetImage);
+
+    auto *retptr = transport->getReturnAddr(ctx->address_offset);
+    int ret = getReturnCode(retptr);
+    if (ret) {
+        return nullptr;
+    }
+    getVpxFrame(retptr, ctx->myImg);
+    return &(ctx->myImg);
+}
+
+void vpx_codec_send_metadata(vpx_codec_ctx_t *ctx, void *ptr) {
+    MetaDataColorAspects& meta = *(MetaDataColorAspects*)ptr;
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam(ctx->id, 0, ctx->address_offset);
+    transport->writeParam(meta.type, 1, ctx->address_offset);
+    transport->writeParam(meta.primaries, 2, ctx->address_offset);
+    transport->writeParam(meta.range, 3, ctx->address_offset);
+    transport->writeParam(meta.transfer, 4, ctx->address_offset);
+    sendVpxOperation(ctx, MediaOperation::SendMetadata);
+}
+
+int vpx_codec_flush(vpx_codec_ctx_t *ctx) {
+    DDD("%s %d", __func__, __LINE__);
+    if (!ctx) {
+        ALOGE("ERROR: Failed %s %d: ctx is nullptr", __func__, __LINE__);
+        return -1;
+    }
+    auto transport = GoldfishMediaTransport::getInstance();
+    transport->writeParam(ctx->id, 0, ctx->address_offset);
+    sendVpxOperation(ctx, MediaOperation::Flush);
+    return 0;
+}
+
+int vpx_codec_decode(vpx_codec_ctx_t *ctx, const uint8_t *data,
+                     unsigned int data_sz, void *user_priv, long deadline) {
+    if (!ctx) {
+        ALOGE("ERROR: Failed %s %d: ctx is nullptr", __func__, __LINE__);
+        return -1;
+    }
+    (void)deadline;
+    DDD("%s %d data size %d userpriv %p", __func__, __LINE__, (int)data_sz,
+        user_priv);
+    auto transport = GoldfishMediaTransport::getInstance();
+    memcpy(ctx->data, data, data_sz);
+
+    transport->writeParam(ctx->id, 0, ctx->address_offset);
+    transport->writeParam(transport->offsetOf((uint64_t)(ctx->data)) -
+                              ctx->address_offset,
+                          1, ctx->address_offset);
+    transport->writeParam((__u64)data_sz, 2, ctx->address_offset);
+    transport->writeParam((__u64)user_priv, 3, ctx->address_offset);
+    sendVpxOperation(ctx, MediaOperation::DecodeImage);
+    return 0;
+}
diff --git a/codecs/c2/readme.txt b/codecs/c2/readme.txt
new file mode 100644
index 00000000..a2b0d21e
--- /dev/null
+++ b/codecs/c2/readme.txt
@@ -0,0 +1,11 @@
+This contains the c2 version of emulator's hardware decoders
+
+decoders/ contains avc(a.k.a. h264) and vpx(vp8 and vp9) decoders
+and base. All are based upon c2 sw codecs.
+
+store/ the store that creates decoders
+this is also borrowed from c2.
+
+service/ the hidl service that required by platform;
+to actually get it work, need to set this in file_contexts
+/vendor/bin/hw/android\.hardware\.media\.c2@1\.0-service-goldfish u:object_r:mediacodec_exec:s0
diff --git a/codecs/c2/service/Android.bp b/codecs/c2/service/Android.bp
new file mode 100644
index 00000000..c7c5ddc0
--- /dev/null
+++ b/codecs/c2/service/Android.bp
@@ -0,0 +1,37 @@
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-BSD
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_binary {
+    name: "android.hardware.media.c2@1.0-service-goldfish",
+
+    defaults: [
+        "hidl_defaults",
+        "libcodec2-hidl-defaults",
+    ],
+    vendor: true,
+    relative_install_path: "hw",
+
+    srcs: [
+        "service.cpp",
+    ],
+
+    init_rc: ["android.hardware.media.c2@1.0-service-goldfish.rc"],
+    vintf_fragments: ["android.hardware.media.c2@1.0-service-goldfish.xml"],
+
+    shared_libs: [
+        "libgoldfish_codec2_store",
+        "libavservices_minijail",
+        "libcutils",
+        "libhidlbase",
+        "liblog",
+        "libutils",
+    ],
+
+    required: ["android.hardware.media.c2-default-seccomp_policy"],
+}
diff --git a/codecs/c2/service/android.hardware.media.c2@1.0-service-goldfish.rc b/codecs/c2/service/android.hardware.media.c2@1.0-service-goldfish.rc
new file mode 100644
index 00000000..ada90baf
--- /dev/null
+++ b/codecs/c2/service/android.hardware.media.c2@1.0-service-goldfish.rc
@@ -0,0 +1,6 @@
+service android-hardware-media-c2-goldfish-hal-1-0 /vendor/bin/hw/android.hardware.media.c2@1.0-service-goldfish
+    class hal
+    user media
+    group mediadrm drmrpc
+    ioprio rt 4
+    task_profiles ProcessCapacityHigh
diff --git a/codecs/c2/service/android.hardware.media.c2@1.0-service-goldfish.xml b/codecs/c2/service/android.hardware.media.c2@1.0-service-goldfish.xml
new file mode 100644
index 00000000..3bc347c9
--- /dev/null
+++ b/codecs/c2/service/android.hardware.media.c2@1.0-service-goldfish.xml
@@ -0,0 +1,11 @@
+<manifest version="1.0" type="device">
+    <hal format="hidl">
+        <name>android.hardware.media.c2</name>
+        <transport>hwbinder</transport>
+        <version>1.0</version>
+        <interface>
+            <name>IComponentStore</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</manifest>
diff --git a/codecs/c2/service/service.cpp b/codecs/c2/service/service.cpp
new file mode 100644
index 00000000..1a0f8eb4
--- /dev/null
+++ b/codecs/c2/service/service.cpp
@@ -0,0 +1,52 @@
+// Copyright 2020 The Chromium Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//#define LOG_NDEBUG 0
+#define LOG_TAG "android.hardware.media.c2@1.0-service-goldfish"
+
+#include <C2Component.h>
+#include <codec2/hidl/1.0/ComponentStore.h>
+#include <hidl/HidlTransportSupport.h>
+#include <log/log.h>
+#include <minijail.h>
+
+#include <goldfish_codec2/store/GoldfishComponentStore.h>
+
+// Default policy for codec2.0 service.
+static constexpr char kBaseSeccompPolicyPath[] =
+    "/vendor/etc/seccomp_policy/"
+    "android.hardware.media.c2-default-seccomp_policy";
+
+// Additional device-specific seccomp permissions can be added in this file.
+static constexpr char kExtSeccompPolicyPath[] =
+    "/vendor/etc/seccomp_policy/codec2.vendor.ext.policy";
+
+int main(int /* argc */, char ** /* argv */) {
+    ALOGD("Goldfish C2 Service starting...");
+
+    signal(SIGPIPE, SIG_IGN);
+    android::SetUpMinijail(kBaseSeccompPolicyPath, kExtSeccompPolicyPath);
+
+    android::hardware::configureRpcThreadpool(8, true /* callerWillJoin */);
+
+    // Create IComponentStore service.
+    {
+        using namespace ::android::hardware::media::c2::V1_0;
+
+        ALOGD("Instantiating Codec2's Goldfish IComponentStore service...");
+        android::sp<IComponentStore> store(new utils::ComponentStore(
+            android::GoldfishComponentStore::Create()));
+        if (store == nullptr) {
+            ALOGE("Cannot create Codec2's Goldfish IComponentStore service.");
+        } else if (store->registerAsService("default") != android::OK) {
+            ALOGE("Cannot register Codec2's IComponentStore service.");
+        } else {
+            ALOGI("Codec2's IComponentStore service created.");
+        }
+    }
+
+    android::hardware::joinRpcThreadpool();
+    ALOGD("Service shutdown.");
+    return 0;
+}
diff --git a/codecs/c2/store/Android.bp b/codecs/c2/store/Android.bp
new file mode 100644
index 00000000..39e16826
--- /dev/null
+++ b/codecs/c2/store/Android.bp
@@ -0,0 +1,35 @@
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-GPL-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_library_shared {
+    name: "libgoldfish_codec2_store",
+    vendor: true,
+
+    defaults: [
+        "libcodec2-impl-defaults",
+    ],
+
+    srcs: [
+        "GoldfishComponentStore.cpp",
+    ],
+    export_include_dirs: [
+        "include",
+    ],
+
+    shared_libs: [
+        "libcutils",
+        "liblog",
+    ],
+
+    cflags: [
+      "-Werror",
+      "-Wall",
+      "-Wthread-safety",  // Check thread annotation at build time.
+    ],
+}
diff --git a/codecs/c2/store/GoldfishComponentStore.cpp b/codecs/c2/store/GoldfishComponentStore.cpp
new file mode 100644
index 00000000..2d2ab476
--- /dev/null
+++ b/codecs/c2/store/GoldfishComponentStore.cpp
@@ -0,0 +1,389 @@
+/* Copyright (C) 2020 The Android Open Source Project
+**
+** This software is licensed under the terms of the GNU General Public
+** License version 2, as published by the Free Software Foundation, and
+** may be copied, distributed, and modified under those terms.
+**
+** This program is distributed in the hope that it will be useful,
+** but WITHOUT ANY WARRANTY; without even the implied warranty of
+** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+** GNU General Public License for more details.
+*/
+
+#define LOG_TAG "GoldfishComponentStore"
+
+#include <goldfish_codec2/store/GoldfishComponentStore.h>
+
+#include <dlfcn.h>
+#include <stdint.h>
+
+#include <memory>
+#include <mutex>
+
+#include <C2.h>
+#include <C2Config.h>
+#include <cutils/properties.h>
+#include <log/log.h>
+
+namespace android {
+
+// static
+std::shared_ptr<C2ComponentStore> GoldfishComponentStore::Create() {
+    ALOGI("%s()", __func__);
+
+    static std::mutex mutex;
+    static std::weak_ptr<C2ComponentStore> platformStore;
+
+    std::lock_guard<std::mutex> lock(mutex);
+    std::shared_ptr<C2ComponentStore> store = platformStore.lock();
+    if (store != nullptr)
+        return store;
+
+    store = std::shared_ptr<C2ComponentStore>(new GoldfishComponentStore());
+    platformStore = store;
+    return store;
+}
+
+C2String GoldfishComponentStore::getName() const {
+    return "android.componentStore.goldfish";
+}
+
+c2_status_t GoldfishComponentStore::ComponentModule::init(std::string libPath) {
+    ALOGI("in %s", __func__);
+    ALOGI("loading dll of path %s", libPath.c_str());
+    mLibHandle = dlopen(libPath.c_str(), RTLD_NOW | RTLD_NODELETE);
+    LOG_ALWAYS_FATAL_IF(mLibHandle == nullptr, "could not dlopen %s: %s",
+                        libPath.c_str(), dlerror());
+
+    createFactory = (C2ComponentFactory::CreateCodec2FactoryFunc)dlsym(
+        mLibHandle, "CreateCodec2Factory");
+    LOG_ALWAYS_FATAL_IF(createFactory == nullptr, "createFactory is null in %s",
+                        libPath.c_str());
+
+    destroyFactory = (C2ComponentFactory::DestroyCodec2FactoryFunc)dlsym(
+        mLibHandle, "DestroyCodec2Factory");
+    LOG_ALWAYS_FATAL_IF(destroyFactory == nullptr,
+                        "destroyFactory is null in %s", libPath.c_str());
+
+    mComponentFactory = createFactory();
+    if (mComponentFactory == nullptr) {
+        ALOGD("could not create factory in %s", libPath.c_str());
+        mInit = C2_NO_MEMORY;
+    } else {
+        mInit = C2_OK;
+    }
+
+    if (mInit != C2_OK) {
+        return mInit;
+    }
+
+    std::shared_ptr<C2ComponentInterface> intf;
+    c2_status_t res = createInterface(0, &intf);
+    if (res != C2_OK) {
+        ALOGD("failed to create interface: %d", res);
+        return mInit;
+    }
+
+    std::shared_ptr<C2Component::Traits> traits(new (std::nothrow)
+                                                    C2Component::Traits);
+    if (traits) {
+        traits->name = intf->getName();
+
+        C2ComponentKindSetting kind;
+        C2ComponentDomainSetting domain;
+        res = intf->query_vb({&kind, &domain}, {}, C2_MAY_BLOCK, nullptr);
+        bool fixDomain = res != C2_OK;
+        if (res == C2_OK) {
+            traits->kind = kind.value;
+            traits->domain = domain.value;
+        } else {
+            // TODO: remove this fall-back
+            ALOGD("failed to query interface for kind and domain: %d", res);
+
+            traits->kind = (traits->name.find("encoder") != std::string::npos)
+                               ? C2Component::KIND_ENCODER
+                           : (traits->name.find("decoder") != std::string::npos)
+                               ? C2Component::KIND_DECODER
+                               : C2Component::KIND_OTHER;
+        }
+
+        uint32_t mediaTypeIndex =
+            traits->kind == C2Component::KIND_ENCODER
+                ? C2PortMediaTypeSetting::output::PARAM_TYPE
+                : C2PortMediaTypeSetting::input::PARAM_TYPE;
+        std::vector<std::unique_ptr<C2Param>> params;
+        res = intf->query_vb({}, {mediaTypeIndex}, C2_MAY_BLOCK, &params);
+        if (res != C2_OK) {
+            ALOGD("failed to query interface: %d", res);
+            return mInit;
+        }
+        if (params.size() != 1u) {
+            ALOGD("failed to query interface: unexpected vector size: %zu",
+                  params.size());
+            return mInit;
+        }
+        C2PortMediaTypeSetting *mediaTypeConfig =
+            C2PortMediaTypeSetting::From(params[0].get());
+        if (mediaTypeConfig == nullptr) {
+            ALOGD("failed to query media type");
+            return mInit;
+        }
+        traits->mediaType = std::string(
+            mediaTypeConfig->m.value,
+            strnlen(mediaTypeConfig->m.value, mediaTypeConfig->flexCount()));
+
+        if (fixDomain) {
+            if (strncmp(traits->mediaType.c_str(), "audio/", 6) == 0) {
+                traits->domain = C2Component::DOMAIN_AUDIO;
+            } else if (strncmp(traits->mediaType.c_str(), "video/", 6) == 0) {
+                traits->domain = C2Component::DOMAIN_VIDEO;
+            } else if (strncmp(traits->mediaType.c_str(), "image/", 6) == 0) {
+                traits->domain = C2Component::DOMAIN_IMAGE;
+            } else {
+                traits->domain = C2Component::DOMAIN_OTHER;
+            }
+        }
+
+        // TODO: get this properly from the store during emplace
+        switch (traits->domain) {
+        case C2Component::DOMAIN_AUDIO:
+            traits->rank = 8;
+            break;
+        default:
+            traits->rank = 512;
+        }
+
+        params.clear();
+        res = intf->query_vb({}, {C2ComponentAliasesSetting::PARAM_TYPE},
+                             C2_MAY_BLOCK, &params);
+        if (res == C2_OK && params.size() == 1u) {
+            C2ComponentAliasesSetting *aliasesSetting =
+                C2ComponentAliasesSetting::From(params[0].get());
+            if (aliasesSetting) {
+                // Split aliases on ','
+                // This looks simpler in plain C and even std::string would
+                // still make a copy.
+                char *aliases = ::strndup(aliasesSetting->m.value,
+                                          aliasesSetting->flexCount());
+                ALOGD("'%s' has aliases: '%s'", intf->getName().c_str(),
+                      aliases);
+
+                for (char *tok, *ptr, *str = aliases;
+                     (tok = ::strtok_r(str, ",", &ptr)); str = nullptr) {
+                    traits->aliases.push_back(tok);
+                    ALOGD("adding alias: '%s'", tok);
+                }
+                free(aliases);
+            }
+        }
+    }
+    mTraits = traits;
+
+    return mInit;
+}
+
+GoldfishComponentStore::ComponentModule::~ComponentModule() {
+    ALOGI("in %s", __func__);
+    if (destroyFactory && mComponentFactory) {
+        destroyFactory(mComponentFactory);
+    }
+    if (mLibHandle) {
+        ALOGI("unloading dll");
+        dlclose(mLibHandle);
+    }
+}
+
+c2_status_t GoldfishComponentStore::ComponentModule::createInterface(
+    c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *interface,
+    std::function<void(::C2ComponentInterface *)> deleter) {
+    interface->reset();
+    if (mInit != C2_OK) {
+        return mInit;
+    }
+    std::shared_ptr<ComponentModule> module = shared_from_this();
+    c2_status_t res = mComponentFactory->createInterface(
+        id, interface, [module, deleter](C2ComponentInterface *p) mutable {
+            // capture module so that we ensure we still have it while deleting
+            // interface
+            deleter(p);     // delete interface first
+            module.reset(); // remove module ref (not technically needed)
+        });
+    ALOGI("created interface");
+    return res;
+}
+
+c2_status_t GoldfishComponentStore::ComponentModule::createComponent(
+    c2_node_id_t id, std::shared_ptr<C2Component> *component,
+    std::function<void(::C2Component *)> deleter) {
+    component->reset();
+    if (mInit != C2_OK) {
+        return mInit;
+    }
+    std::shared_ptr<ComponentModule> module = shared_from_this();
+    c2_status_t res = mComponentFactory->createComponent(
+        id, component, [module, deleter](C2Component *p) mutable {
+            // capture module so that we ensure we still have it while deleting
+            // component
+            deleter(p);     // delete component first
+            module.reset(); // remove module ref (not technically needed)
+        });
+    ALOGI("created component");
+    return res;
+}
+
+std::shared_ptr<const C2Component::Traits>
+GoldfishComponentStore::ComponentModule::getTraits() {
+    std::unique_lock<std::recursive_mutex> lock(mLock);
+    return mTraits;
+}
+
+// We have a property set indicating whether to use the host side codec
+// or not (ro.boot.qemu.hwcodec.<mLibNameSuffix>).
+static std::string BuildHWCodecPropName(const char *libname) {
+    using namespace std::literals::string_literals;
+    return "ro.boot.qemu.hwcodec."s + libname;
+}
+
+static bool useAndroidGoldfishComponentInstance(const char *libname) {
+    const std::string propName = BuildHWCodecPropName(libname);
+    char propValue[PROP_VALUE_MAX];
+    bool myret = property_get(propName.c_str(), propValue, "") > 0 &&
+                 strcmp("2", propValue) == 0;
+    if (myret) {
+        ALOGD("%s %d found prop %s val %s", __func__, __LINE__, propName.c_str(),
+              propValue);
+    }
+    return myret;
+}
+
+GoldfishComponentStore::GoldfishComponentStore()
+    : mVisited(false), mReflector(std::make_shared<C2ReflectorHelper>()) {
+
+    ALOGW("created goldfish store %p reflector of param %p", this,
+          mReflector.get());
+    auto emplace = [this](const char *libPath) {
+        mComponents.emplace(libPath, libPath);
+    };
+
+    if (useAndroidGoldfishComponentInstance("vpxdec")) {
+        emplace("libcodec2_goldfish_vp8dec.so");
+        emplace("libcodec2_goldfish_vp9dec.so");
+    }
+    if (useAndroidGoldfishComponentInstance("avcdec")) {
+        emplace("libcodec2_goldfish_avcdec.so");
+    }
+    if (useAndroidGoldfishComponentInstance("hevcdec")) {
+        emplace("libcodec2_goldfish_hevcdec.so");
+    }
+}
+
+c2_status_t
+GoldfishComponentStore::copyBuffer(std::shared_ptr<C2GraphicBuffer> src,
+                                   std::shared_ptr<C2GraphicBuffer> dst) {
+    (void)src;
+    (void)dst;
+    return C2_OMITTED;
+}
+
+c2_status_t GoldfishComponentStore::query_sm(
+    const std::vector<C2Param *> &stackParams,
+    const std::vector<C2Param::Index> &heapParamIndices,
+    std::vector<std::unique_ptr<C2Param>> *const heapParams) const {
+    (void)heapParams;
+    return stackParams.empty() && heapParamIndices.empty() ? C2_OK
+                                                           : C2_BAD_INDEX;
+}
+
+c2_status_t GoldfishComponentStore::config_sm(
+    const std::vector<C2Param *> &params,
+    std::vector<std::unique_ptr<C2SettingResult>> *const failures) {
+    (void)failures;
+    return params.empty() ? C2_OK : C2_BAD_INDEX;
+}
+
+void GoldfishComponentStore::visitComponents() {
+    std::lock_guard<std::mutex> lock(mMutex);
+    if (mVisited) {
+        return;
+    }
+    for (auto &pathAndLoader : mComponents) {
+        const C2String &path = pathAndLoader.first;
+        ComponentLoader &loader = pathAndLoader.second;
+        std::shared_ptr<ComponentModule> module;
+        if (loader.fetchModule(&module) == C2_OK) {
+            std::shared_ptr<const C2Component::Traits> traits =
+                module->getTraits();
+            if (traits) {
+                mComponentList.push_back(traits);
+                mComponentNameToPath.emplace(traits->name, path);
+                for (const C2String &alias : traits->aliases) {
+                    mComponentNameToPath.emplace(alias, path);
+                }
+            }
+        }
+    }
+    mVisited = true;
+}
+
+std::vector<std::shared_ptr<const C2Component::Traits>>
+GoldfishComponentStore::listComponents() {
+    // This method SHALL return within 500ms.
+    visitComponents();
+    return mComponentList;
+}
+
+c2_status_t GoldfishComponentStore::findComponent(
+    C2String name, std::shared_ptr<ComponentModule> *module) {
+    (*module).reset();
+    visitComponents();
+
+    auto pos = mComponentNameToPath.find(name);
+    if (pos != mComponentNameToPath.end()) {
+        return mComponents.at(pos->second).fetchModule(module);
+    }
+    return C2_NOT_FOUND;
+}
+
+c2_status_t GoldfishComponentStore::createComponent(
+    C2String name, std::shared_ptr<C2Component> *const component) {
+    // This method SHALL return within 100ms.
+    component->reset();
+    std::shared_ptr<ComponentModule> module;
+    c2_status_t res = findComponent(name, &module);
+    if (res == C2_OK) {
+        // TODO: get a unique node ID
+        res = module->createComponent(0, component);
+    }
+    return res;
+}
+
+c2_status_t GoldfishComponentStore::createInterface(
+    C2String name, std::shared_ptr<C2ComponentInterface> *const interface) {
+    // This method SHALL return within 100ms.
+    interface->reset();
+    std::shared_ptr<ComponentModule> module;
+    c2_status_t res = findComponent(name, &module);
+    if (res == C2_OK) {
+        // TODO: get a unique node ID
+        res = module->createInterface(0, interface);
+    }
+    return res;
+}
+
+c2_status_t GoldfishComponentStore::querySupportedParams_nb(
+    std::vector<std::shared_ptr<C2ParamDescriptor>> *const params) const {
+    (void)params;
+    return C2_OK;
+}
+
+c2_status_t GoldfishComponentStore::querySupportedValues_sm(
+    std::vector<C2FieldSupportedValuesQuery> &fields) const {
+    return fields.empty() ? C2_OK : C2_BAD_INDEX;
+}
+
+std::shared_ptr<C2ParamReflector>
+GoldfishComponentStore::getParamReflector() const {
+    return mReflector;
+}
+
+} // namespace android
diff --git a/codecs/c2/store/include/goldfish_codec2/store/GoldfishComponentStore.h b/codecs/c2/store/include/goldfish_codec2/store/GoldfishComponentStore.h
new file mode 100644
index 00000000..f484bd4f
--- /dev/null
+++ b/codecs/c2/store/include/goldfish_codec2/store/GoldfishComponentStore.h
@@ -0,0 +1,214 @@
+/* Copyright (C) 2020 The Android Open Source Project
+**
+** This software is licensed under the terms of the GNU General Public
+** License version 2, as published by the Free Software Foundation, and
+** may be copied, distributed, and modified under those terms.
+**
+** This program is distributed in the hope that it will be useful,
+** but WITHOUT ANY WARRANTY; without even the implied warranty of
+** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+** GNU General Public License for more details.
+*/
+
+#pragma once
+
+#include <map>
+#include <mutex>
+
+#include <C2Component.h>
+#include <C2ComponentFactory.h>
+#include <android-base/thread_annotations.h>
+#include <util/C2InterfaceHelper.h>
+
+namespace android {
+
+class GoldfishComponentStore : public C2ComponentStore {
+  public:
+    static std::shared_ptr<C2ComponentStore> Create();
+
+    virtual std::vector<std::shared_ptr<const C2Component::Traits>>
+    listComponents() override;
+    virtual std::shared_ptr<C2ParamReflector>
+    getParamReflector() const override;
+    virtual C2String getName() const override;
+    virtual c2_status_t querySupportedValues_sm(
+        std::vector<C2FieldSupportedValuesQuery> &fields) const override;
+    virtual c2_status_t querySupportedParams_nb(
+        std::vector<std::shared_ptr<C2ParamDescriptor>> *const params)
+        const override;
+    virtual c2_status_t query_sm(
+        const std::vector<C2Param *> &stackParams,
+        const std::vector<C2Param::Index> &heapParamIndices,
+        std::vector<std::unique_ptr<C2Param>> *const heapParams) const override;
+    virtual c2_status_t createInterface(
+        C2String name,
+        std::shared_ptr<C2ComponentInterface> *const interface) override;
+    virtual c2_status_t
+    createComponent(C2String name,
+                    std::shared_ptr<C2Component> *const component) override;
+    virtual c2_status_t
+    copyBuffer(std::shared_ptr<C2GraphicBuffer> src,
+               std::shared_ptr<C2GraphicBuffer> dst) override;
+    virtual c2_status_t config_sm(
+        const std::vector<C2Param *> &params,
+        std::vector<std::unique_ptr<C2SettingResult>> *const failures) override;
+    GoldfishComponentStore();
+
+    virtual ~GoldfishComponentStore() override = default;
+
+  private:
+    /**
+     * An object encapsulating a loaded component module.
+     *
+     * \todo provide a way to add traits to known components here to avoid
+     * loading the .so-s for listComponents
+     */
+    struct ComponentModule
+        : public C2ComponentFactory,
+          public std::enable_shared_from_this<ComponentModule> {
+        virtual c2_status_t
+        createComponent(c2_node_id_t id,
+                        std::shared_ptr<C2Component> *component,
+                        ComponentDeleter deleter =
+                            std::default_delete<C2Component>()) override;
+        virtual c2_status_t createInterface(
+            c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *interface,
+            InterfaceDeleter deleter =
+                std::default_delete<C2ComponentInterface>()) override;
+
+        /**
+         * \returns the traits of the component in this module.
+         */
+        std::shared_ptr<const C2Component::Traits> getTraits();
+
+        /**
+         * Creates an uninitialized component module.
+         *
+         * \param name[in]  component name.
+         *
+         * \note Only used by ComponentLoader.
+         */
+        ComponentModule()
+            : mInit(C2_NO_INIT), mLibHandle(nullptr), createFactory(nullptr),
+              destroyFactory(nullptr), mComponentFactory(nullptr) {}
+
+        /**
+         * Initializes a component module with a given library path. Must be
+         * called exactly once.
+         *
+         * \note Only used by ComponentLoader.
+         *
+         * \param libPath[in] library path
+         *
+         * \retval C2_OK        the component module has been successfully
+         * loaded \retval C2_NO_MEMORY not enough memory to loading the
+         * component module \retval C2_NOT_FOUND could not locate the component
+         * module \retval C2_CORRUPTED the component module could not be loaded
+         * (unexpected) \retval C2_REFUSED   permission denied to load the
+         * component module (unexpected) \retval C2_TIMED_OUT could not load the
+         * module within the time limit (unexpected)
+         */
+        c2_status_t init(std::string libPath);
+
+        virtual ~ComponentModule() override;
+
+      protected:
+        std::recursive_mutex mLock; ///< lock protecting mTraits
+        std::shared_ptr<C2Component::Traits>
+            mTraits; ///< cached component traits
+
+        c2_status_t mInit; ///< initialization result
+
+        void *mLibHandle; ///< loaded library handle
+        C2ComponentFactory::CreateCodec2FactoryFunc
+            createFactory; ///< loaded create function
+        C2ComponentFactory::DestroyCodec2FactoryFunc
+            destroyFactory; ///< loaded destroy function
+        C2ComponentFactory
+            *mComponentFactory; ///< loaded/created component factory
+    };
+
+    /**
+     * An object encapsulating a loadable component module.
+     *
+     * \todo make this also work for enumerations
+     */
+    struct ComponentLoader {
+        /**
+         * Load the component module.
+         *
+         * This method simply returns the component module if it is already
+         * currently loaded, or attempts to load it if it is not.
+         *
+         * \param module[out] pointer to the shared pointer where the loaded
+         * module shall be stored. This will be nullptr on error.
+         *
+         * \retval C2_OK        the component module has been successfully
+         * loaded \retval C2_NO_MEMORY not enough memory to loading the
+         * component module \retval C2_NOT_FOUND could not locate the component
+         * module \retval C2_CORRUPTED the component module could not be loaded
+         * \retval C2_REFUSED   permission denied to load the component module
+         */
+        c2_status_t fetchModule(std::shared_ptr<ComponentModule> *module) {
+            c2_status_t res = C2_OK;
+            std::lock_guard<std::mutex> lock(mMutex);
+            std::shared_ptr<ComponentModule> localModule = mModule.lock();
+            if (localModule == nullptr) {
+                localModule = std::make_shared<ComponentModule>();
+                res = localModule->init(mLibPath);
+                if (res == C2_OK) {
+                    mModule = localModule;
+                }
+            }
+            *module = localModule;
+            return res;
+        }
+
+        /**
+         * Creates a component loader for a specific library path (or name).
+         */
+        ComponentLoader(std::string libPath) : mLibPath(libPath) {}
+
+      private:
+        std::mutex mMutex; ///< mutex guarding the module
+        std::weak_ptr<ComponentModule>
+            mModule;          ///< weak reference to the loaded module
+        std::string mLibPath; ///< library path
+    };
+
+    /**
+     * Retrieves the component module for a component.
+     *
+     * \param module pointer to a shared_pointer where the component module will
+     * be stored on success.
+     *
+     * \retval C2_OK        the component loader has been successfully retrieved
+     * \retval C2_NO_MEMORY not enough memory to locate the component loader
+     * \retval C2_NOT_FOUND could not locate the component to be loaded
+     * \retval C2_CORRUPTED the component loader could not be identified due to
+     * some modules being corrupted (this can happen if the name does not refer
+     * to an already identified component but some components could not be
+     * loaded due to bad library) \retval C2_REFUSED   permission denied to find
+     * the component loader for the named component (this can happen if the name
+     * does not refer to an already identified component but some components
+     * could not be loaded due to lack of permissions)
+     */
+    c2_status_t findComponent(C2String name,
+                              std::shared_ptr<ComponentModule> *module);
+
+    /**
+     * Loads each component module and discover its contents.
+     */
+    void visitComponents();
+
+    std::mutex
+        mMutex;    ///< mutex guarding the component lists during construction
+    bool mVisited; ///< component modules visited
+    std::map<C2String, ComponentLoader>
+        mComponents; ///< path -> component module
+    std::map<C2String, C2String> mComponentNameToPath; ///< name -> path
+    std::vector<std::shared_ptr<const C2Component::Traits>> mComponentList;
+
+    std::shared_ptr<C2ReflectorHelper> mReflector;
+};
+} // namespace android
diff --git a/codecs/media/codecs.xml b/codecs/media/codecs.xml
index 066053e5..f6beadde 100644
--- a/codecs/media/codecs.xml
+++ b/codecs/media/codecs.xml
@@ -82,16 +82,6 @@ Only the three quirks included above are recognized at this point:
         <Setting name="max-video-encoder-input-buffers" value="12" />
     </Settings>
 
-    <MediaCodec name="OMX.android.goldfish.h264.decoder" type="video/avc" >
-        <Limit name="concurrent-instances" max="4" />
-    </MediaCodec>
-    <MediaCodec name="OMX.android.goldfish.vp8.decoder" type="video/x-vnd.on2.vp8" >
-        <Limit name="concurrent-instances" max="4" />
-    </MediaCodec>
-    <MediaCodec name="OMX.android.goldfish.vp9.decoder" type="video/x-vnd.on2.vp9" >
-        <Limit name="concurrent-instances" max="4" />
-    </MediaCodec>
-
     <MediaCodec name="c2.goldfish.h264.decoder" type="video/avc" >
         <Limit name="concurrent-instances" max="4" />
     </MediaCodec>
diff --git a/codecs/media/codecs_google_video_default.xml b/codecs/media/codecs_google_video_default.xml
index 6ead35f1..308c7ea6 100644
--- a/codecs/media/codecs_google_video_default.xml
+++ b/codecs/media/codecs_google_video_default.xml
@@ -16,41 +16,6 @@
 
 <Included>
     <Decoders>
-        <MediaCodec name="OMX.google.mpeg4.decoder" type="video/mp4v-es">
-            <!-- profiles and levels:  ProfileSimple : Level3 -->
-            <Limit name="size" min="2x2" max="352x288" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" range="12-11880" />
-            <Limit name="bitrate" range="1-384000" />
-            <Limit name="performance-point-1920x1080" value="30" />
-            <Feature name="adaptive-playback" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.h263.decoder" type="video/3gpp">
-            <!-- profiles and levels:  ProfileBaseline : Level30, ProfileBaseline : Level45
-                    ProfileISWV2 : Level30, ProfileISWV2 : Level45 -->
-            <Limit name="size" min="2x2" max="352x288" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="bitrate" range="1-384000" />
-            <Limit name="performance-point-1920x1080" value="30" />
-            <Feature name="adaptive-playback" />
-        </MediaCodec>
-        <MediaCodec name="OMX.android.goldfish.h264.decoder" type="video/avc">
-            <Limit name="size" min="96x96" max="3840x2160" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" range="24-2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-3840x2160" value="60" />
-            <Limit name="measured-frame-rate-320x240" range="257-266" />
-            <Limit name="measured-frame-rate-720x480" range="262-264" />
-            <Limit name="measured-frame-rate-1280x720" range="227-251" />
-            <Limit name="measured-frame-rate-1920x1080" range="235-247" />
-            <Limit name="measured-frame-rate-3840x2160" range="90-120" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
         <MediaCodec name="c2.goldfish.h264.decoder" type="video/avc">
             <Limit name="size" min="96x96" max="4096x4096" />
             <Limit name="alignment" value="2x2" />
@@ -84,64 +49,6 @@
             <Feature name="adaptive-playback" />
             <Feature name="dynamic-color-aspects" />
         </MediaCodec>
-        <MediaCodec name="OMX.google.h264.decoder" type="video/avc">
-            <Limit name="size" min="2x2" max="2560x2560" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" range="24-2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="concurrent-instances" max="16" />
-            <Limit name="performance-point-1920x1088" value="30" />
-            <Limit name="measured-frame-rate-320x240" range="183-183" />
-            <Limit name="measured-frame-rate-720x480" range="181-181" />
-            <Limit name="measured-frame-rate-1280x720" range="182-184" />
-            <Limit name="measured-frame-rate-1920x1080" range="30-40" />
-            <Feature name="adaptive-playback" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.hevc.decoder" type="video/hevc">
-            <!-- profiles and levels:  ProfileMain : MainTierLevel51 -->
-            <Limit name="size" min="2x2" max="2048x2048" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="8x8" />
-            <Limit name="block-count" range="1-139264" />
-            <Limit name="blocks-per-second" range="1-2000000" />
-            <Limit name="bitrate" range="1-10000000" />
-            <Limit name="performance-point-1920x1080" value="30" />
-            <Feature name="adaptive-playback" />
-        </MediaCodec>
-        <MediaCodec name="OMX.android.goldfish.vp9.decoder" type="video/x-vnd.on2.vp9">
-            <Limit name="size" min="96x96" max="3840x2160" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" min="24" max="2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-3840x2160" value="60" />
-            <Limit name="measured-frame-rate-320x180" range="237-258" />
-            <Limit name="measured-frame-rate-640x360" range="237-258" />
-            <Limit name="measured-frame-rate-1280x720" range="237-258" />
-            <Limit name="measured-frame-rate-1920x1080" range="293-302" />
-            <Limit name="measured-frame-rate-3840x2160" range="90-120" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
-        <MediaCodec name="OMX.android.goldfish.vp8.decoder" type="video/x-vnd.on2.vp8">
-            <Limit name="size" min="96x96" max="3840x2160" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" min="24" max="2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-3840x2160" value="60" />
-            <Limit name="measured-frame-rate-320x180" range="743-817" />
-            <Limit name="measured-frame-rate-640x360" range="237-258" />
-            <Limit name="measured-frame-rate-1280x720" range="237-258" />
-            <Limit name="measured-frame-rate-1920x1080" range="30-160" />
-            <Limit name="measured-frame-rate-3840x2160" range="30-90" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
         <MediaCodec name="c2.goldfish.vp8.decoder" type="video/x-vnd.on2.vp8">
             <Limit name="size" min="96x96" max="2560x2560" />
             <Limit name="alignment" value="1x1" />
@@ -173,69 +80,5 @@
             <Feature name="adaptive-playback" />
             <Feature name="dynamic-color-aspects" />
         </MediaCodec>
-        <MediaCodec name="OMX.google.vp8.decoder" type="video/x-vnd.on2.vp8">
-            <Limit name="size" min="2x2" max="2560x2560" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" min="24" max="2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-1920x1088" value="60" />
-            <Limit name="measured-frame-rate-320x240" range="183-183" />
-            <Limit name="measured-frame-rate-720x480" range="181-181" />
-            <Limit name="measured-frame-rate-1280x720" range="182-184" />
-            <Limit name="measured-frame-rate-1920x1088" range="30-50" />
-            <Limit name="measured-frame-rate-2560x1440" range="30-40" />
-            <Feature name="adaptive-playback" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.vp9.decoder" type="video/x-vnd.on2.vp9">
-            <Limit name="size" min="2x2" max="2560x2560" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" min="24" max="2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-1920x1088" value="60" />
-            <Limit name="measured-frame-rate-320x240" range="183-183" />
-            <Limit name="measured-frame-rate-720x480" range="181-181" />
-            <Limit name="measured-frame-rate-1280x720" range="121-125" />
-            <Limit name="measured-frame-rate-1920x1088" range="30-50" />
-            <Limit name="measured-frame-rate-2560x1440" range="30-40" />
-            <Feature name="adaptive-playback" />
-        </MediaCodec>
     </Decoders>
-
-    <Encoders>
-        <MediaCodec name="OMX.google.h263.encoder" type="video/3gpp">
-            <!-- profiles and levels:  ProfileBaseline : Level45 -->
-            <Limit name="size" min="176x144" max="176x144" />
-            <Limit name="alignment" value="16x16" />
-            <Limit name="bitrate" range="1-128000" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.h264.encoder" type="video/avc">
-            <!-- profiles and levels:  ProfileBaseline : Level41 -->
-            <Limit name="size" min="16x16" max="1920x1088" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" range="1-244800" />
-            <!-- Changed range from 12000000 to 20000000 for b/31648354 -->
-            <Limit name="bitrate" range="1-20000000" />
-            <Feature name="intra-refresh" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.mpeg4.encoder" type="video/mp4v-es">
-            <!-- profiles and levels:  ProfileCore : Level2 -->
-            <Limit name="size" min="16x16" max="176x144" />
-            <Limit name="alignment" value="16x16" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" range="12-1485" />
-            <Limit name="bitrate" range="1-64000" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.vp8.encoder" type="video/x-vnd.on2.vp8">
-            <!-- profiles and levels:  ProfileMain : Level_Version0-3 -->
-            <Limit name="size" min="2x2" max="2048x2048" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="bitrate" range="1-40000000" />
-            <Feature name="bitrate-modes" value="VBR,CBR" />
-        </MediaCodec>
-    </Encoders>
 </Included>
diff --git a/codecs/media/codecs_performance.xml b/codecs/media/codecs_performance.xml
deleted file mode 100644
index c243a54b..00000000
--- a/codecs/media/codecs_performance.xml
+++ /dev/null
@@ -1,113 +0,0 @@
-<?xml version="1.0" encoding="utf-8" ?>
-<!-- Copyright 2015 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-
-<!--
-     This file was generated from running the following tests:
-        module CtsVideoTestCases test android.video.cts.VideoEncoderDecoderTest
-        module CtsMediaTestCases test android.media.cts.VideoDecoderPerfTest
-     System: z840
-     The results were fed through a script simliar to get_achievable_rates.py:
-     https://source.android.com/devices/media/oem.html
--->
-
-<MediaCodecs>
-    <Encoders>
-        <MediaCodec name="OMX.google.h263.encoder" type="video/3gpp" update="true">
-            <!-- 3 runs, min 849 max 1008 gmean 943 -->
-            <Limit name="measured-frame-rate-176x144" range="849-1008" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.h264.encoder" type="video/avc" update="true">
-            <!-- 3 runs, min 496 max 629 gmean 565 -->
-            <Limit name="measured-frame-rate-320x240" range="496-629" />
-            <!-- 2 runs, min 197 max 203 gmean 201 -->
-            <Limit name="measured-frame-rate-720x480" range="197-203" />
-            <!-- 2 runs, min 93 max 97 gmean 95 -->
-            <Limit name="measured-frame-rate-1280x720" range="93-97" />
-            <!-- 2 runs, min 45 max 47 gmean 46 -->
-            <Limit name="measured-frame-rate-1920x1080" range="45-47" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.mpeg4.encoder" type="video/mp4v-es" update="true">
-            <!-- 3 runs, min 881 max 1142 gmean 994 -->
-            <Limit name="measured-frame-rate-176x144" range="881-1142" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.vp8.encoder" type="video/x-vnd.on2.vp8" update="true">
-            <!-- 3 runs, min 249 max 285 gmean 264 -->
-            <Limit name="measured-frame-rate-320x180" range="249-285" />
-            <!-- 3 runs, min 104 max 115 gmean 109 -->
-            <Limit name="measured-frame-rate-640x360" range="104-115" />
-            <!-- 3 runs, min 34 max 35 gmean 34 -->
-            <Limit name="measured-frame-rate-1280x720" range="34-35" />
-            <!-- 3 runs, min 26 max 29 gmean 27 -->
-            <Limit name="measured-frame-rate-1920x1080" range="26-29" />
-        </MediaCodec>
-    </Encoders>
-    <Decoders>
-        <MediaCodec name="OMX.google.h263.decoder" type="video/3gpp" update="true">
-            <!-- 3 runs, min 1246 max 1390 gmean 1342 -->
-            <Limit name="measured-frame-rate-176x144" range="1246-1390" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.h264.decoder" type="video/avc" update="true">
-            <!-- 5 runs, min 299 max 629 gmean 567 -->
-            <Limit name="measured-frame-rate-320x240" range="299-629" />
-            <!-- 4 runs, min 215 max 250 gmean 232 -->
-            <Limit name="measured-frame-rate-720x480" range="215-250" />
-            <!-- 4 runs, min 75 max 85 gmean 78 -->
-            <Limit name="measured-frame-rate-1280x720" range="75-85" />
-            <!-- 4 runs, min 31 max 34 gmean 33 -->
-            <Limit name="measured-frame-rate-1920x1080" range="31-34" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.hevc.decoder" type="video/hevc" update="true">
-            <!-- 4 runs, min 754 max 817 gmean 775 -->
-            <Limit name="measured-frame-rate-352x288" range="754-817" />
-            <!-- 4 runs, min 323 max 394 gmean 373 -->
-            <Limit name="measured-frame-rate-640x360" range="323-394" />
-            <!-- 4 runs, min 349 max 372 gmean 358 -->
-            <Limit name="measured-frame-rate-720x480" range="349-372" />
-            <!-- 4 runs, min 144 max 157 gmean 151 -->
-            <Limit name="measured-frame-rate-1280x720" range="144-157" />
-            <!-- 4 runs, min 74 max 85 gmean 80 -->
-            <Limit name="measured-frame-rate-1920x1080" range="74-85" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.mpeg4.decoder" type="video/mp4v-es" update="true">
-            <!-- 4 runs, min 1439 max 1625 gmean 1523 -->
-            <Limit name="measured-frame-rate-176x144" range="1439-1625" />
-            <Limit name="measured-frame-rate-480x360" range="200-400" />
-            <Limit name="measured-frame-rate-1280x720" range="100-200" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.vp8.decoder" type="video/x-vnd.on2.vp8" update="true">
-            <!-- 3 runs, min 1129 max 1261 gmean 1190 -->
-            <Limit name="measured-frame-rate-320x180" range="1129-1261" />
-            <!-- 3 runs, min 471 max 525 gmean 504 -->
-            <Limit name="measured-frame-rate-640x360" range="471-525" />
-            <!-- 3 runs, min 126 max 145 gmean 132 -->
-            <Limit name="measured-frame-rate-1280x720" range="126-145" />
-            <!-- 3 runs, min 48 max 51 gmean 49 -->
-            <Limit name="measured-frame-rate-1920x1080" range="48-51" />
-            <Limit name="measured-frame-rate-2160x2160" range="31-34" />
-        </MediaCodec>
-        <MediaCodec name="OMX.google.vp9.decoder" type="video/x-vnd.on2.vp9" update="true">
-            <!-- 2 runs, min 968 max 1101 gmean 1044 -->
-            <Limit name="measured-frame-rate-320x180" range="968-1101" />
-            <!-- 3 runs, min 291 max 338 gmean 319 -->
-            <Limit name="measured-frame-rate-640x360" range="291-338" />
-            <!-- Those values are from buildbots -->
-            <Limit name="measured-frame-rate-1280x720" range="280-400" />
-            <!-- Buildbot gets ~180 if it is in the first run, ~230 if it is the second run -->
-            <Limit name="measured-frame-rate-1920x1080" range="178-240" />
-            <Limit name="measured-frame-rate-2560x1440" range="31-34" />
-        </MediaCodec>
-    </Decoders>
-</MediaCodecs>
diff --git a/fvpbase/BoardConfig.mk b/fvpbase/BoardConfig.mk
deleted file mode 100644
index 0ce04f9f..00000000
--- a/fvpbase/BoardConfig.mk
+++ /dev/null
@@ -1,71 +0,0 @@
-# Copyright (C) 2020 The Android Open Source Project
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
-TARGET_ARCH := arm64
-TARGET_ARCH_VARIANT := armv8-a
-TARGET_CPU_VARIANT := generic
-TARGET_CPU_ABI := arm64-v8a
-
-ifeq ($(FVP_MULTILIB_BUILD),true)
-TARGET_2ND_ARCH := arm
-TARGET_2ND_CPU_ABI := armeabi-v7a
-TARGET_2ND_CPU_ABI2 := armeabi
-TARGET_2ND_ARCH_VARIANT := armv8-a
-TARGET_2ND_CPU_VARIANT := generic
-endif
-
-include build/make/target/board/BoardConfigMainlineCommon.mk
-
-BOARD_USES_SYSTEM_OTHER_ODEX :=
-
-BUILD_QEMU_IMAGES := true
-TARGET_USERIMAGES_SPARSE_EXT_DISABLED := true
-
-BOARD_BUILD_SUPER_IMAGE_BY_DEFAULT := true
-
-BOARD_SUPER_PARTITION_SIZE := 3229614080
-BOARD_SUPER_PARTITION_GROUPS := fvp_dynamic_partitions
-BOARD_FVP_DYNAMIC_PARTITIONS_SIZE := 3221225472
-BOARD_FVP_DYNAMIC_PARTITIONS_PARTITION_LIST := system vendor
-TARGET_COPY_OUT_PRODUCT := system/product
-TARGET_COPY_OUT_SYSTEM_EXT := system/system_ext
-# BOARD_X_FILE_SYSTEM_TYPE must be empty if TARGET_COPY_OUT_X is 'system/xyz'.
-BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE :=
-BOARD_SYSTEM_EXTIMAGE_FILE_SYSTEM_TYPE :=
-
-BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE := ext4
-
-BOARD_USERDATAIMAGE_PARTITION_SIZE := 1153433600
-
-TARGET_KERNEL_USE ?= 5.10
-
-PRODUCT_COPY_FILES += kernel/prebuilts/$(TARGET_KERNEL_USE)/arm64/kernel-$(TARGET_KERNEL_USE):kernel
-
-# This enables the rules defined in
-# device/generic/goldfish/build/tasks/combine_initramfs.mk
-GOLDFISH_COMBINE_INITRAMFS := true
-
-BOARD_MKBOOTIMG_ARGS := --header_version 2 --ramdisk $(OUT_DIR)/target/product/$(PRODUCT_DEVICE)/combined-ramdisk.img
-BOARD_INCLUDE_DTB_IN_BOOTIMG := true
-BOARD_PREBUILT_DTBIMAGE_DIR := kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/arm64
-
-BOARD_KERNEL_CMDLINE := \
-	console=ttyAMA0 \
-	earlycon=pl011,0x1c090000 \
-	androidboot.hardware=fvpbase \
-	androidboot.boot_device=bus@8000000/bus@8000000:motherboard-bus/bus@8000000:motherboard-bus:iofpga-bus@300000000/1c130000.virtio-block \
-	loglevel=9 \
-
-BOARD_SEPOLICY_DIRS += device/generic/goldfish/fvpbase/sepolicy
diff --git a/fvpbase/OWNERS b/fvpbase/OWNERS
deleted file mode 100644
index daa9686e..00000000
--- a/fvpbase/OWNERS
+++ /dev/null
@@ -1 +0,0 @@
-pcc@google.com
diff --git a/fvpbase/README.md b/fvpbase/README.md
deleted file mode 100644
index a0437113..00000000
--- a/fvpbase/README.md
+++ /dev/null
@@ -1,196 +0,0 @@
-This document describes how to build and run an Android system image targeting
-the ARM Fixed Virtual Platform or QEMU.
-
-## New to Android?
-
-If you do not already have the ``repo`` tool, or a copy of the Android
-source tree, please follow the Android instructions for [downloading the
-source](https://source.android.com/setup/build/downloading).
-
-## Building the kernel
-
-It is not normally necessary to build the kernel manually. By
-default, the ``fvp`` target will use the GKI prebuilts for kernel
-version 5.10. If you need to modify the kernel, if you need to use
-a different kernel branch, or if you need graphics in FVP, please
-follow the instructions below.
-
-```
-mkdir android-kernel-mainline
-cd android-kernel-mainline
-repo init -u https://android.googlesource.com/kernel/manifest -b common-android-mainline
-```
-
-Now, update the kernel and setup for building:
-```
-export FVP_KERNEL_PATH=$(pwd)
-# Remove any old fvp-patches cherry-pick branch.
-cd common && git checkout aosp/android-mainline && \
-  git branch -D fvp-patches 2> /dev/null; cd ..
-repo sync -j$(nproc) -q
-# One cherrypick currently required due to a bug with BoundsSan+EHCI.
-repo start fvp-patches common
-repo download -c kernel/common 1634850
-```
-
-To support graphics on FVP, one additional cherry pick is required. This only
-applies to the ``fvp`` target, and not ``fvp_mini``, and it is also not required
-for QEMU.
-
-```
-repo download -c kernel/common 1768866
-```
-
-Then, build the kernel.
-
-```
-BUILD_CONFIG=common/build.config.gki.aarch64 build/build.sh -j$(nproc)
-BUILD_CONFIG=common-modules/virtual-device/build.config.virtual_device.aarch64 build/build.sh -j$(nproc)
-```
-
-## Building the firmware (ARM Trusted Firmware and U-Boot) (FVP only, not required on QEMU)
-
-First, install ``dtc``, the device tree compiler. On Debian, this is in the
-``device-tree-compiler`` package. Return to the top level directory (`cd ..`), and run:
-```
-mkdir platform
-cd platform
-export FVP_FIRMWARE_PATH=$(pwd)
-repo init -u https://git.linaro.org/landing-teams/working/arm/manifest.git -m pinned-uboot.xml -b 20.01
-repo sync
-
-# The included copy of U-Boot is incompatible with this version of AOSP, switch to a recent upstream checkout.
-cd u-boot
-git fetch https://gitlab.denx.de/u-boot/u-boot.git/ master
-git checkout 18b9c98024ec89e00a57707f07ff6ada06089d26
-cd ..
-
-mkdir -p tools/gcc
-cd tools/gcc
-wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/aarch64-linux-gnu/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu.tar.xz
-tar -xJf gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu.tar.xz
-cd ../..
-
-build-scripts/build-test-uboot.sh -p fvp all
-```
-
-## Building userspace
-
-Follow the Android instructions to [download the
-source](https://source.android.com/setup/build/downloading), and run the
-following in the source directory.
-
-```
-. build/envsetup.sh
-lunch fvp-eng # or fvp-userdebug, fvp_mini-eng, fvp_mini-userdebug
-```
-
-The fvp-* lunch targets will build a full Android with UI support, while
-`fvp_mini-*` will build a small subset needed to boot to shell and support
-command line executables.
-
-If you are using FVP, prepopulate the build directory with the
-firmware binaries. Normally, these are copied from the source tree
-as part of the build process, but not for this target yet. This step
-is not required when using QEMU.
-
-```
-mkdir -p $ANDROID_PRODUCT_OUT
-cp $FVP_FIRMWARE_PATH/output/fvp/fvp-uboot/uboot/{bl1,fip}.bin $ANDROID_PRODUCT_OUT/
-```
-
-If you built a custom kernel, copy or symlink the newly built kernel into your
-source tree. For example:
-```
-mkdir -p kernel/prebuilts/mykernel/arm64
-ln -s $FVP_KERNEL_PATH/out/android-mainline/dist/Image kernel/prebuilts/mykernel/arm64/kernel-mykernel
-
-mkdir -p kernel/prebuilts/common-modules/virtual-device/mykernel
-ln -s $FVP_KERNEL_PATH/out/android-mainline/dist kernel/prebuilts/common-modules/virtual-device/mykernel/arm64
-```
-Then set the ``TARGET_KERNEL_USE`` environment variable to the name that you
-gave to your kernel. For example, ``export TARGET_KERNEL_USE=mykernel``.
-
-Set any additional build environment variables.
-* To enable MTE on all platform binaries (by default it is only enabled on a
-  small subset) add `export SANITIZE_TARGET=memtag_heap` for Async mode, or
-  `export SANITIZE_TARGET=memtag_heap SANITIZE_TARGET_DIAG=memtag_heap` for Sync
-  mode.
-* To disable 32 bit support in fvp_mini-* targets use
-  `export FVP_MULTILIB_BUILD=false`.
-
-Finally, build the userspace image with `m`.
-
-## Running
-
-The same image can be used with either ARM Fixed Virtual Platform simulator, or
-with QEMU. Slowdown from QEMU is roughly 10-20x, where ARM's FVP is 100-200x.
-
-### Running the image in FVP
-
-The model may be obtained from [ARM's
-website](https://developer.arm.com/tools-and-software/simulation-models/fixed-virtual-platforms/arm-ecosystem-models)
-(under "Armv-A Base RevC AEM FVP").
-
-From a lunched environment, first set the value of the ``MODEL_BIN`` environment
-variable to the path to the model executable (it should end with something like
-`FVP_Base_RevC-2xAEMv8A/models/Linux64_GCC-6.4/FVP_Base_RevC-2xAEMv8A`). Then
-run the following command to launch the model:
-```
-device/generic/goldfish/fvpbase/run_model
-```
-Additional model parameters may be passed by appending them to the
-``run_model`` command. Add the following to enable MTE support in the model:
-```
--C cluster0.has_arm_v8-5=1 \
--C cluster0.memory_tagging_support_level=2 \
--C bp.dram_metadata.is_enabled=1
-```
-
-To terminate the model, press ``Ctrl-] Ctrl-D`` to terminate the telnet
-connection.
-
-### Running the image in QEMU
-
-As an alternative to using FVP, the image may also be run in QEMU.
-QEMU is generally much faster than FVP, but its support for the
-latest ARM architectural features is relatively new compared to FVP,
-so it may have more bugs.
-
-As of the time of writing, no released version of QEMU can successfully
-boot the system to GUI due to bugs in its MTE support, so a development
-version with bug fixes must be used. The instructions below check out a
-commit that has been successfully tested.
-
-Check [QEMU wiki](https://wiki.qemu.org/Hosts/Linux#Building_QEMU_for_Linux) for
-the list of build dependencies. Common missing packages include `ninja-build`,
-`libpixman-1-dev`, and `libgtk-3-dev` for GUI support.
-
-```
-git clone https://github.com/qemu/qemu
-cd qemu
-git checkout 5c6295a45b4fceac913c11abc62488c49c02b9fd
-mkdir build
-cd build
-../configure --target-list=aarch64-softmmu
-ninja
-export QEMU_BIN=$(pwd)/qemu-system-aarch64
-```
-
-Then run the following command in a lunched environment to start the emulator:
-```
-device/generic/goldfish/fvpbase/run_qemu
-```
-Additional QEMU arguments may be passed by appending them to the ``run_qemu``
-command. One useful argument is ``-nographic``, which disables the GUI, which
-may be useful when working with ``fvp_mini`` or if the GUI is not needed.
-
-To terminate the emulator, press ``Ctrl-A c q <Enter>`` or close the GUI
-window.
-
-### Accessing the model via adb
-
-To connect to the model on the host:
-```
-adb connect localhost:5555
-```
diff --git a/fvpbase/fstab.fvpbase b/fvpbase/fstab.fvpbase
deleted file mode 100644
index 6c62809c..00000000
--- a/fvpbase/fstab.fvpbase
+++ /dev/null
@@ -1,8 +0,0 @@
-# Android fstab file.
-#<src>                                                  <mnt_point>         <type>    <mnt_flags and options>                              <fs_mgr_flags>
-# The filesystem that contains the filesystem checker binary (typically /system) cannot
-# specify MF_CHECK, and must come before any filesystems that do specify MF_CHECK
-system   /system     ext4    ro,barrier=1     wait,logical,first_stage_mount
-vendor   /vendor     ext4    ro,barrier=1     wait,logical,first_stage_mount
-/dev/block/mmcblk0  /data    ext4      noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check,quota
-/devices/*/block/vde  auto  auto      defaults voldmanaged=sdcard:auto,encryptable=userdata
diff --git a/fvpbase/fstab.initrd b/fvpbase/fstab.initrd
deleted file mode 100644
index 56056634..00000000
--- a/fvpbase/fstab.initrd
+++ /dev/null
@@ -1,4 +0,0 @@
-# Android fstab file.
-#<dev>  <mnt_point> <type>  <mnt_flags options> <fs_mgr_flags>
-system   /system     ext4    ro,barrier=1     wait,logical,first_stage_mount
-vendor   /vendor     ext4    ro,barrier=1     wait,logical,first_stage_mount
diff --git a/fvpbase/fstab.qemu b/fvpbase/fstab.qemu
deleted file mode 100644
index a56c8663..00000000
--- a/fvpbase/fstab.qemu
+++ /dev/null
@@ -1,8 +0,0 @@
-# Android fstab file.
-#<src>                                                  <mnt_point>         <type>    <mnt_flags and options>                              <fs_mgr_flags>
-# The filesystem that contains the filesystem checker binary (typically /system) cannot
-# specify MF_CHECK, and must come before any filesystems that do specify MF_CHECK
-system   /system     ext4    ro,barrier=1     wait,logical,first_stage_mount
-vendor   /vendor     ext4    ro,barrier=1     wait,logical,first_stage_mount
-/dev/block/vda  /data    ext4      noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check,quota
-/devices/*/block/vde  auto  auto      defaults voldmanaged=sdcard:auto,encryptable=userdata
diff --git a/fvpbase/fvp.mk b/fvpbase/fvp.mk
deleted file mode 100644
index 0fc25bba..00000000
--- a/fvpbase/fvp.mk
+++ /dev/null
@@ -1,119 +0,0 @@
-#
-# Copyright 2020 The Android Open Source Project
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
-PRODUCT_SHIPPING_API_LEVEL := 29
-PRODUCT_USE_DYNAMIC_PARTITIONS := true
-PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
-
-#
-# All components inherited here go to system image
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
-
-#
-# All components inherited here go to system_ext image
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
-
-#
-# All components inherited here go to product image
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
-
-#
-# All components inherited here go to vendor image
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/media_vendor.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)
-
-PRODUCT_SOONG_NAMESPACES += device/generic/goldfish
-
-PRODUCT_PACKAGES += \
-    android.hardware.audio.service \
-    android.hardware.audio@6.0-impl:32 \
-    android.hardware.audio.effect@6.0-impl:32 \
-    audio.primary.default \
-    audio.r_submix.default \
-    android.hardware.drm@1.0-service \
-    android.hardware.drm@1.0-impl \
-    android.hardware.drm-service.clearkey \
-    android.hardware.gatekeeper@1.0-service.software \
-    android.hardware.graphics.allocator@2.0-service \
-    android.hardware.graphics.allocator@2.0-impl \
-    android.hardware.graphics.composer@2.1-service \
-    android.hardware.graphics.mapper@2.0-impl \
-    android.hardware.health@2.0-service \
-    android.hardware.neuralnetworks@1.3-service-sample-all \
-    android.hardware.neuralnetworks@1.3-service-sample-limited \
-    android.hardware.keymaster@4.0-service \
-    android.hardware.keymaster@4.0-impl \
-    gralloc.minigbm \
-    hwcomposer.drm_minigbm \
-    libEGL_angle \
-    libGLESv1_CM_angle \
-    libGLESv2_angle \
-    vulkan.pastel \
-
-PRODUCT_HOST_PACKAGES += bind_to_localhost
-
-PRODUCT_PACKAGE_OVERLAYS := device/generic/goldfish/fvpbase/overlay
-
-PRODUCT_NAME := fvp
-PRODUCT_DEVICE := fvpbase
-PRODUCT_BRAND := Android
-PRODUCT_MODEL := AOSP on FVP
-
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.hardware.ethernet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.ethernet.xml \
-    frameworks/native/data/etc/android.hardware.wifi.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.xml \
-    frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.host.xml \
-    frameworks/native/data/etc/android.software.app_widgets.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.app_widgets.xml \
-    device/generic/goldfish/fvpbase/fstab.fvpbase:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.fvpbase \
-    device/generic/goldfish/fvpbase/fstab.qemu:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.qemu \
-    device/generic/goldfish/fvpbase/fstab.initrd:$(TARGET_COPY_OUT_RAMDISK)/fstab.fvpbase \
-    device/generic/goldfish/fvpbase/fstab.initrd:$(TARGET_COPY_OUT_RAMDISK)/fstab.qemu \
-    device/generic/goldfish/fvpbase/init.fvpbase.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.fvpbase.rc \
-    device/generic/goldfish/fvpbase/init.qemu.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.qemu.rc \
-    device/generic/goldfish/fvpbase/required_images:required_images \
-    device/generic/goldfish/fvpbase/ueventd.fvp.rc:$(TARGET_COPY_OUT_VENDOR)/ueventd.rc \
-    frameworks/av/services/audiopolicy/config/audio_policy_configuration_generic.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
-    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml \
-    frameworks/av/services/audiopolicy/config/surround_sound_configuration_5_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/surround_sound_configuration_5_0.xml \
-
-PRODUCT_BUILD_BOOT_IMAGE := true
-
-PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
-    qemu.hw.mainkeys=0 \
-    ro.hw_timeout_multiplier=50 \
-    debug.sf.nobootanimation=1 \
-    ro.hardware.egl=angle \
-    ro.hardware.vulkan=pastel \
-
-PRODUCT_REQUIRES_INSECURE_EXECMEM_FOR_SWIFTSHADER := true
-
-# It's almost always faster to dexopt on the host even in eng builds.
-WITH_DEXPREOPT_BOOT_IMG_AND_SYSTEM_SERVER_ONLY := false
-
-DEVICE_MANIFEST_FILE += device/generic/goldfish/fvpbase/manifest.xml
-
-# Use a multilib setup (see fvpbase/BoardConfig.mk).
-FVP_MULTILIB_BUILD := true
-
diff --git a/fvpbase/fvp_mini.mk b/fvpbase/fvp_mini.mk
deleted file mode 100644
index 4293cbb2..00000000
--- a/fvpbase/fvp_mini.mk
+++ /dev/null
@@ -1,59 +0,0 @@
-#
-# Copyright 2020 Arm Ltd. All rights reserved.
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
-$(call inherit-product, $(LOCAL_PATH)/minimal_system.mk)
-
-$(call inherit-product, $(SRC_TARGET_DIR)/product/updatable_apex.mk)
-
-$(call inherit-product, $(SRC_TARGET_DIR)/product/core_no_zygote.mk)
-
-PRODUCT_NAME := fvp_mini
-PRODUCT_DEVICE := fvpbase
-PRODUCT_BRAND := Android
-PRODUCT_MODEL := AOSP on FVP
-PRODUCT_SOONG_NAMESPACES += device/generic/goldfish
-
-PRODUCT_SHIPPING_API_LEVEL := 29
-PRODUCT_USE_DYNAMIC_PARTITIONS := true
-PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
-PRODUCT_BUILD_BOOT_IMAGE := true
-
-# Use a multilib setup (see fvpbase/BoardConfig.mk).
-FVP_MULTILIB_BUILD ?= true
-
-# The check would fail because there are no boot jars.
-SKIP_BOOT_JARS_CHECK ?= true
-
-PRODUCT_PACKAGES += \
-    com.android.runtime \
-    init_vendor \
-    ip \
-    ping \
-    selinux_policy_nonsystem \
-
-PRODUCT_HOST_PACKAGES += \
-    bind_to_localhost
-
-PRODUCT_COPY_FILES += \
-    device/generic/goldfish/fvpbase/fstab.fvpbase:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.fvpbase \
-    device/generic/goldfish/fvpbase/fstab.qemu:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.qemu \
-    device/generic/goldfish/fvpbase/fstab.initrd:$(TARGET_COPY_OUT_RAMDISK)/fstab.fvpbase \
-    device/generic/goldfish/fvpbase/fstab.initrd:$(TARGET_COPY_OUT_RAMDISK)/fstab.qemu \
-    device/generic/goldfish/fvpbase/init.fvpbase.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.fvpbase.rc \
-    device/generic/goldfish/fvpbase/init.qemu.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.qemu.rc \
-    device/generic/goldfish/fvpbase/mini_network.rc:system/etc/init/mini_network.rc \
-    device/generic/goldfish/fvpbase/mini_network.sh:/system/bin/mini_network.sh \
-    device/generic/goldfish/fvpbase/required_images:required_images \
diff --git a/fvpbase/init.fvpbase.rc b/fvpbase/init.fvpbase.rc
deleted file mode 100644
index 4d3db00c..00000000
--- a/fvpbase/init.fvpbase.rc
+++ /dev/null
@@ -1,2 +0,0 @@
-on fs
-    mount_all /vendor/etc/fstab.fvpbase
diff --git a/fvpbase/init.qemu.rc b/fvpbase/init.qemu.rc
deleted file mode 100644
index 621b45c6..00000000
--- a/fvpbase/init.qemu.rc
+++ /dev/null
@@ -1,7 +0,0 @@
-on fs
-    mount_all /vendor/etc/fstab.qemu
-
-on early-init
-    setprop ro.hardware.gralloc minigbm
-    setprop ro.hardware.hwcomposer drm_minigbm
-    setprop ro.sf.lcd_density 150
diff --git a/fvpbase/manifest.xml b/fvpbase/manifest.xml
deleted file mode 100644
index c17b5be0..00000000
--- a/fvpbase/manifest.xml
+++ /dev/null
@@ -1,100 +0,0 @@
-<manifest version="1.0" type="device" target-level="3">
-    <hal format="hidl">
-        <name>android.hardware.audio</name>
-        <transport>hwbinder</transport>
-        <version>6.0</version>
-        <interface>
-            <name>IDevicesFactory</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.audio.effect</name>
-        <transport>hwbinder</transport>
-        <version>6.0</version>
-        <interface>
-            <name>IEffectsFactory</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.configstore</name>
-        <transport>hwbinder</transport>
-        <version>1.1</version>
-        <interface>
-            <name>ISurfaceFlingerConfigs</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.drm</name>
-        <transport>hwbinder</transport>
-        <version>1.0</version>
-        <interface>
-            <name>ICryptoFactory</name>
-            <instance>default</instance>
-        </interface>
-        <interface>
-            <name>IDrmFactory</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.graphics.allocator</name>
-        <transport>hwbinder</transport>
-        <version>2.0</version>
-        <interface>
-            <name>IAllocator</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.graphics.composer</name>
-        <transport>hwbinder</transport>
-        <version>2.1</version>
-        <interface>
-            <name>IComposer</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.graphics.mapper</name>
-        <transport arch="32+64">passthrough</transport>
-        <version>2.0</version>
-        <interface>
-            <name>IMapper</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.health</name>
-        <transport>hwbinder</transport>
-        <version>2.0</version>
-        <interface>
-            <name>IHealth</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.keymaster</name>
-        <transport>hwbinder</transport>
-        <version>4.0</version>
-        <interface>
-            <name>IKeymasterDevice</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-    <hal format="hidl">
-        <name>android.hardware.media.omx</name>
-        <transport>hwbinder</transport>
-        <version>1.0</version>
-        <interface>
-            <name>IOmx</name>
-            <instance>default</instance>
-        </interface>
-        <interface>
-            <name>IOmxStore</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-</manifest>
diff --git a/fvpbase/mini_network.rc b/fvpbase/mini_network.rc
deleted file mode 100644
index 38523b5c..00000000
--- a/fvpbase/mini_network.rc
+++ /dev/null
@@ -1,20 +0,0 @@
-#
-# Copyright 2020 Arm Ltd. All rights reserved.
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
-service mini_network /system/bin/mini_network.sh
-    class core
-    user root
-    oneshot
diff --git a/fvpbase/mini_network.sh b/fvpbase/mini_network.sh
deleted file mode 100755
index f2c90673..00000000
--- a/fvpbase/mini_network.sh
+++ /dev/null
@@ -1,24 +0,0 @@
-#!/system/bin/sh
-#
-# Copyright 2020 Arm Ltd. All rights reserved.
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
-# The Android network stack is not included in Nano, so we need to
-# configure the network manually. The configuration below is the same as
-# would be obtained from the fast model's emulated DHCP.
-
-ip address add 172.20.51.1/24 broadcast 172.20.51.255 dev eth0
-ip link set eth0 up
-ip route add default via 172.20.51.254
diff --git a/fvpbase/minimal_system.mk b/fvpbase/minimal_system.mk
deleted file mode 100644
index a9c360eb..00000000
--- a/fvpbase/minimal_system.mk
+++ /dev/null
@@ -1,64 +0,0 @@
-#
-# Copyright 2020 Arm Ltd. All rights reserved.
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
-# This file contains system partition contents needed for a minimal
-# Android build that boots to shell. The items here should be present in
-# build/make/target/product/base_system.mk.
-
-PRODUCT_PACKAGES += \
-    adbd_system_api \
-    apexd \
-    boringssl_self_test \
-    cgroups.json \
-    com.android.adbd \
-    com.android.conscrypt \
-    debuggerd \
-    gsid \
-    init.environ.rc \
-    init_system \
-    libbinder \
-    libc.bootstrap \
-    libdl.bootstrap \
-    libdl_android.bootstrap \
-    libm.bootstrap \
-    libstdc++ \
-    linker \
-    logcat \
-    logd \
-    odsign \
-    remount \
-    run-as \
-    selinux_policy_system \
-    servicemanager \
-    shell_and_utilities_system \
-    task_profiles.json \
-    tombstoned \
-    vold \
-
-PRODUCT_HOST_PACKAGES += \
-    adb \
-
-PRODUCT_COPY_FILES += \
-    system/core/rootdir/init.usb.rc:system/etc/init/hw/init.usb.rc \
-    system/core/rootdir/init.usb.configfs.rc:system/etc/init/hw/init.usb.configfs.rc \
-    system/core/rootdir/etc/hosts:system/etc/hosts \
-    art/tools/public.libraries.buildbot.txt:system/etc/public.libraries.txt
-
-PRODUCT_SYSTEM_PROPERTIES += debug.atrace.tags.enableflags=0
-
-PRODUCT_PACKAGES_DEBUG := \
-    strace \
-    su \
diff --git a/fvpbase/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml b/fvpbase/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
deleted file mode 100644
index 22aa4b7c..00000000
--- a/fvpbase/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
+++ /dev/null
@@ -1,29 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-/**
- * Copyright (c) 2022, The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *     http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
--->
-
-<resources>
-    <bool name="def_lockscreen_disabled">true</bool>
-
-    <!-- maximize the timeout to INT_MAX about 500+ hours -->
-    <integer name="def_screen_off_timeout">2147483647</integer>
-
-    <!-- Allow users to use both the on-screen keyboard, as well as a real
-         keyboard -->
-    <bool name="def_show_ime_with_hard_keyboard">true</bool>
-</resources>
diff --git a/fvpbase/required_images b/fvpbase/required_images
deleted file mode 100644
index 741ddc54..00000000
--- a/fvpbase/required_images
+++ /dev/null
@@ -1,5 +0,0 @@
-bl1.bin
-boot.img
-fip.bin
-system-qemu.img
-userdata.img
diff --git a/fvpbase/run_model b/fvpbase/run_model
deleted file mode 100755
index d6788371..00000000
--- a/fvpbase/run_model
+++ /dev/null
@@ -1,30 +0,0 @@
-#!/bin/sh -eu
-#
-# Copyright 2020 The Android Open Source Project
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
-tmp="$(mktemp -d)"
-trap "rm -rf $tmp" EXIT
-mkfifo $tmp/port
-
-"$(dirname $0)/run_model_only" \
-  -C bp.terminal_0.start_telnet=1 \
-  -C bp.terminal_0.terminal_command="echo %port > $tmp/port" \
-  "$@" &
-
-read port < $tmp/port
-telnet localhost $port
-kill -INT %%
-wait
diff --git a/fvpbase/run_model_only b/fvpbase/run_model_only
deleted file mode 100755
index c2cfe6f0..00000000
--- a/fvpbase/run_model_only
+++ /dev/null
@@ -1,42 +0,0 @@
-#!/bin/sh -eu
-#
-# Copyright 2020 The Android Open Source Project
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
-export LD_PRELOAD="$ANDROID_HOST_OUT/lib64/bind_to_localhost.so"
-
-exec "$MODEL_BIN" \
-  -C bp.secureflashloader.fname="$ANDROID_PRODUCT_OUT/bl1.bin" \
-  -C bp.flashloader0.fname="$ANDROID_PRODUCT_OUT/fip.bin" \
-  -C cluster0.cpu0.semihosting-cwd="$ANDROID_PRODUCT_OUT" \
-  -C bp.virtioblockdevice.image_path="$ANDROID_PRODUCT_OUT/system-qemu.img" \
-  -C bp.mmc.p_mmc_file="$ANDROID_PRODUCT_OUT/userdata.img" \
-  -C bp.secure_memory=0 \
-  -C cache_state_modelled=0 \
-  -C bp.pl011_uart0.unbuffered_output=1 \
-  -C bp.pl011_uart0.out_file="$ANDROID_PRODUCT_OUT/uart0.log" \
-  -C bp.pl011_uart1.out_file="$ANDROID_PRODUCT_OUT/uart1.log" \
-  -C bp.terminal_0.start_telnet=0 \
-  -C bp.terminal_1.start_telnet=0 \
-  -C bp.ve_sysregs.mmbSiteDefault=0 \
-  -C bp.ve_sysregs.exit_on_shutdown=1 \
-  -C bp.virtio_net.hostbridge.userNetworking=1 \
-  -C bp.virtio_net.hostbridge.userNetPorts=5555=5555 \
-  -C bp.virtio_net.enabled=1 \
-  -C cluster0.NUM_CORES=1 \
-  -C cluster0.cpu0.clock_multiplier=20 \
-  -C cluster0.cpu0.enable_crc32=1 \
-  -C cluster1.NUM_CORES=0 \
-  "$@"
diff --git a/fvpbase/run_qemu b/fvpbase/run_qemu
deleted file mode 100755
index 177e249f..00000000
--- a/fvpbase/run_qemu
+++ /dev/null
@@ -1,38 +0,0 @@
-#!/bin/sh -eu
-#
-# Copyright 2021 The Android Open Source Project
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
-"$QEMU_BIN" \
-  -kernel "$ANDROID_PRODUCT_OUT/kernel" \
-  -initrd "$ANDROID_PRODUCT_OUT/combined-ramdisk.img" \
-  -machine virt,mte=on \
-  -cpu max \
-  -drive "driver=raw,file=$ANDROID_PRODUCT_OUT/system-qemu.img,if=none,id=system" \
-  -device virtio-blk-device,drive=system \
-  -drive "driver=raw,file=$ANDROID_PRODUCT_OUT/userdata.img,if=none,id=userdata" \
-  -device virtio-blk-device,drive=userdata \
-  -append "console=ttyAMA0 earlyprintk=ttyAMA0 androidboot.hardware=qemu androidboot.boot_devices=a003e00.virtio_mmio loglevel=9" \
-  -m 4096 \
-  -no-reboot \
-  -nic user,model=virtio-net-pci-non-transitional,hostfwd=tcp:127.0.0.1:5555-172.20.51.1:5555,host=172.20.51.254,net=172.20.51.0/24,dhcpstart=172.20.51.1 \
-  -device virtio-gpu-pci \
-  -smp 8 \
-  -usb \
-  -device qemu-xhci \
-  -device usb-kbd \
-  -device usb-mouse \
-  -serial mon:stdio \
-  "$@"
diff --git a/fvpbase/sepolicy/file.te b/fvpbase/sepolicy/file.te
deleted file mode 100644
index b3bd582b..00000000
--- a/fvpbase/sepolicy/file.te
+++ /dev/null
@@ -1 +0,0 @@
-type varrun_file, file_type, data_file_type, mlstrustedobject;
diff --git a/fvpbase/sepolicy/file_contexts b/fvpbase/sepolicy/file_contexts
deleted file mode 100644
index b712f44a..00000000
--- a/fvpbase/sepolicy/file_contexts
+++ /dev/null
@@ -1,16 +0,0 @@
-/data/vendor/var/run(/.*)?                       u:object_r:varrun_file:s0
-/dev/block/mmcblk0                               u:object_r:userdata_block_device:s0
-/dev/block/vda                                   u:object_r:userdata_block_device:s0
-/dev/dri/card0                                   u:object_r:gpu_device:s0
-/dev/dri/renderD128                              u:object_r:gpu_device:s0
-/vendor/bin/hw/android\.hardware\.drm-service\.clearkey u:object_r:hal_drm_clearkey_exec:s0
-/vendor/bin/hw/android\.hardware\.gatekeeper@1\.0-service.software     u:object_r:hal_gatekeeper_default_exec:s0
-/vendor/bin/hw/android\.hardware\.neuralnetworks@1\.3-service-sample-.*   u:object_r:hal_neuralnetworks_sample_exec:s0
-/vendor/lib(64)?/hw/gralloc\.minigbm\.so         u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/libdrm\.so                      u:object_r:same_process_hal_file:s0
-/system/bin/mini_network.sh                      u:object_r:mini_network_exec:s0
-/vendor/lib(64)?/hw/vulkan.pastel.so             u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/libEGL_angle\.so                u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/libGLESv1_CM_angle\.so          u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/libGLESv2_angle\.so             u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/libminigbm_gralloc.so           u:object_r:same_process_hal_file:s0
diff --git a/fvpbase/sepolicy/hal_drm_clearkey.te b/fvpbase/sepolicy/hal_drm_clearkey.te
deleted file mode 120000
index ad60c6b9..00000000
--- a/fvpbase/sepolicy/hal_drm_clearkey.te
+++ /dev/null
@@ -1 +0,0 @@
-../../sepolicy/common/hal_drm_clearkey.te
\ No newline at end of file
diff --git a/fvpbase/sepolicy/hal_graphics_allocator_default.te b/fvpbase/sepolicy/hal_graphics_allocator_default.te
deleted file mode 100644
index 6676f578..00000000
--- a/fvpbase/sepolicy/hal_graphics_allocator_default.te
+++ /dev/null
@@ -1,4 +0,0 @@
-allow hal_graphics_allocator_default graphics_device:dir search;
-allow hal_graphics_allocator_default graphics_device:chr_file { ioctl open read write map rw_file_perms };
-allow hal_graphics_allocator_default dumpstate:fd use;
-allow hal_graphics_allocator_default dumpstate:fifo_file write;
diff --git a/fvpbase/sepolicy/hal_graphics_composer_default.te b/fvpbase/sepolicy/hal_graphics_composer_default.te
deleted file mode 100644
index 2cc0bde0..00000000
--- a/fvpbase/sepolicy/hal_graphics_composer_default.te
+++ /dev/null
@@ -1 +0,0 @@
-allow hal_graphics_composer_default self:netlink_kobject_uevent_socket create_socket_perms_no_ioctl;
diff --git a/fvpbase/sepolicy/hal_neuralnetworks_sample.te b/fvpbase/sepolicy/hal_neuralnetworks_sample.te
deleted file mode 120000
index 1477ac3f..00000000
--- a/fvpbase/sepolicy/hal_neuralnetworks_sample.te
+++ /dev/null
@@ -1 +0,0 @@
-../../sepolicy/common/hal_neuralnetworks_sample.te
\ No newline at end of file
diff --git a/fvpbase/sepolicy/mini_network.te b/fvpbase/sepolicy/mini_network.te
deleted file mode 100644
index c330c8c4..00000000
--- a/fvpbase/sepolicy/mini_network.te
+++ /dev/null
@@ -1,10 +0,0 @@
-type mini_network, domain, coredomain;
-type mini_network_exec, exec_type, system_file_type, file_type;
-
-init_daemon_domain(mini_network)
-
-allow mini_network self:capability net_admin;
-allow mini_network self:netlink_route_socket { bind create getattr nlmsg_write read setopt write };
-allow mini_network self:udp_socket { create ioctl };
-allow mini_network shell_exec:file { execute getattr map read };
-allow mini_network system_file:file execute_no_trans;
diff --git a/fvpbase/sepolicy/property.te b/fvpbase/sepolicy/property.te
deleted file mode 100644
index 50f7b343..00000000
--- a/fvpbase/sepolicy/property.te
+++ /dev/null
@@ -1 +0,0 @@
-vendor_internal_prop(vendor_device_prop)
diff --git a/fvpbase/sepolicy/property_contexts b/fvpbase/sepolicy/property_contexts
deleted file mode 100644
index c389bdd3..00000000
--- a/fvpbase/sepolicy/property_contexts
+++ /dev/null
@@ -1 +0,0 @@
-vendor.all.modules.ready u:object_r:vendor_device_prop:s0
diff --git a/fvpbase/sepolicy/surfaceflinger.te b/fvpbase/sepolicy/surfaceflinger.te
deleted file mode 100644
index 95236305..00000000
--- a/fvpbase/sepolicy/surfaceflinger.te
+++ /dev/null
@@ -1 +0,0 @@
-allow surfaceflinger self:process execmem;
diff --git a/fvpbase/tools/Android.bp b/fvpbase/tools/Android.bp
deleted file mode 100644
index 7fcd1f18..00000000
--- a/fvpbase/tools/Android.bp
+++ /dev/null
@@ -1,31 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-// The ARM FVP binds to all network interfaces for telnet and adb. This library
-// is a workaround to that. The corresponding LD_PRELOAD additions in
-// fvpbase/run_model ensure that we only bind to localhost.
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_generic_goldfish_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_generic_goldfish_license"],
-}
-
-cc_library_host_shared {
-  name: "bind_to_localhost",
-  srcs: ["bind_to_localhost.cpp"],
-  stl: "none",
-}
diff --git a/fvpbase/tools/bind_to_localhost.cpp b/fvpbase/tools/bind_to_localhost.cpp
deleted file mode 100644
index 923455b3..00000000
--- a/fvpbase/tools/bind_to_localhost.cpp
+++ /dev/null
@@ -1,30 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <dlfcn.h>
-#include <netinet/in.h>
-#include <sys/socket.h>
-#include <sys/types.h>
-
-static int (*real_bind)(int sockfd, const sockaddr* addr, socklen_t addrlen) =
-    (int (*)(int, const sockaddr*, socklen_t))dlsym(RTLD_NEXT, "bind");
-
-extern "C" int bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
-  if (addr->sa_family != AF_INET) return real_bind(sockfd, addr, addrlen);
-  const sockaddr_in* sin = (const sockaddr_in*)addr;
-  if (sin->sin_addr.s_addr != 0) return real_bind(sockfd, addr, addrlen);
-  sockaddr_in new_sin = *sin;
-  new_sin.sin_addr.s_addr = 0x0100007f;
-  return real_bind(sockfd, (sockaddr*)&new_sin, addrlen);
-}
diff --git a/fvpbase/ueventd.fvp.rc b/fvpbase/ueventd.fvp.rc
deleted file mode 100644
index 921bdf2e..00000000
--- a/fvpbase/ueventd.fvp.rc
+++ /dev/null
@@ -1 +0,0 @@
-/dev/ion        0664   system     system
diff --git a/hals/audio/device_factory.cpp b/hals/audio/device_factory.cpp
index 788893bf..dd2f3cbe 100644
--- a/hals/audio/device_factory.cpp
+++ b/hals/audio/device_factory.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#include <android-base/stringify.h>
 #include <system/audio.h>
 #include <log/log.h>
 #include "device_factory.h"
@@ -34,9 +35,6 @@ using ::android::hardware::Void;
 #define LIB_PATH_PREFIX "vendor/lib/hw/"
 #endif
 
-#define QUOTE(x) #x
-#define STRINGIFY(x) QUOTE(x)
-
 DevicesFactory::DevicesFactory() {
     mLegacyLib.reset(dlopen(
         LIB_PATH_PREFIX "android.hardware.audio.legacy@" STRINGIFY(FILE_VERSION) "-impl.ranchu.so",
diff --git a/hals/camera/Android.bp b/hals/camera/Android.bp
index 1e83bf8b..0c013706 100644
--- a/hals/camera/Android.bp
+++ b/hals/camera/Android.bp
@@ -18,11 +18,10 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_binary {
-    name: "android.hardware.camera.provider.ranchu",
+cc_defaults {
+    name: "android.hardware.camera.provider.ranchu_defaults",
     vendor: true,
     relative_install_path: "hw",
-    init_rc: ["android.hardware.camera.provider.ranchu.rc"],
     vintf_fragments: ["android.hardware.camera.provider.ranchu.xml"],
     srcs: [
         "abc3d.cpp",
@@ -42,7 +41,7 @@ cc_binary {
         "list_qemu_cameras.cpp",
         "main.cpp",
         "metadata_utils.cpp",
-        "QemuCamera.cpp",
+        "BaseQemuCamera.cpp",
         "qemu_channel.cpp",
         "StreamBufferCache.cpp",
         "service_entry.cpp",
@@ -71,8 +70,8 @@ cc_binary {
         "android.hardware.common-V2-ndk",
         "android.hardware.common.fmq-V1-ndk",
         "android.hardware.camera.common-V1-ndk",
-        "android.hardware.camera.device-V1-ndk",
-        "android.hardware.camera.provider-V1-ndk",
+        "android.hardware.camera.device-V3-ndk",
+        "android.hardware.camera.provider-V3-ndk",
         "libaidlcommonsupport",
         "libqemud.ranchu",
         "libqemupipe.ranchu",
@@ -80,9 +79,41 @@ cc_binary {
     ],
     header_libs: [
         "libdebug.ranchu",
-        "libgralloc_cb.ranchu",
     ],
     cflags: [
         "-DLOG_TAG=\"camera.provider.ranchu\"",
     ],
 }
+
+cc_binary {
+    name: "android.hardware.camera.provider.ranchu",
+    defaults: ["android.hardware.camera.provider.ranchu_defaults"],
+    init_rc: ["android.hardware.camera.provider.ranchu.rc"],
+    srcs: [
+        "GasQemuCamera.cpp",
+    ],
+    header_libs: [
+        "libgralloc_cb.ranchu",
+    ],
+}
+
+cc_binary {
+    name: "android.hardware.camera.provider.ranchu_minigbm",
+    defaults: ["android.hardware.camera.provider.ranchu_defaults"],
+    init_rc: ["android.hardware.camera.provider.ranchu_minigbm.rc"],
+    srcs: [
+        "MinigbmQemuCamera.cpp",
+    ],
+    shared_libs: [
+        "libnativewindow",
+    ],
+    static_libs: [
+        "libdrm",
+        "mesa_gfxstream_guest_android",
+        "mesa_platform_virtgpu",
+        "mesa_util",
+    ],
+    cflags: [
+        "-DUSE_MINIGBM_GRALLOC",
+    ],
+}
diff --git a/hals/camera/QemuCamera.cpp b/hals/camera/BaseQemuCamera.cpp
similarity index 50%
rename from hals/camera/QemuCamera.cpp
rename to hals/camera/BaseQemuCamera.cpp
index 746fcad7..7e8eda72 100644
--- a/hals/camera/QemuCamera.cpp
+++ b/hals/camera/BaseQemuCamera.cpp
@@ -21,17 +21,11 @@
 
 #include <log/log.h>
 #include <system/camera_metadata.h>
-#include <linux/videodev2.h>
-#include <ui/GraphicBufferAllocator.h>
-#include <ui/GraphicBufferMapper.h>
 
-#include <gralloc_cb_bp.h>
+#include "BaseQemuCamera.h"
 
 #include "debug.h"
-#include "jpeg.h"
 #include "metadata_utils.h"
-#include "QemuCamera.h"
-#include "qemu_channel.h"
 
 namespace android {
 namespace hardware {
@@ -40,10 +34,8 @@ namespace provider {
 namespace implementation {
 namespace hw {
 
-using base::unique_fd;
-
 namespace {
-constexpr char kClass[] = "QemuCamera";
+constexpr char kClass[] = "BaseQemuCamera";
 
 constexpr int kMinFPS = 2;
 constexpr int kMedFPS = 15;
@@ -66,8 +58,6 @@ constexpr float   kMinAperture = 1.4;
 constexpr float   kMaxAperture = 16.0;
 constexpr float   kDefaultAperture = 4.0;
 
-constexpr int32_t kDefaultJpegQuality = 85;
-
 const float kColorCorrectionGains[4] = {1.0f, 1.0f, 1.0f, 1.0f};
 
 const camera_metadata_rational_t kRationalZero = {
@@ -111,12 +101,13 @@ constexpr bool usageTest(const BufferUsage a, const BufferUsage b) {
 
 }  // namespace
 
-QemuCamera::QemuCamera(const Parameters& params)
+BaseQemuCamera::BaseQemuCamera(const Parameters& params)
         : mParams(params)
-        , mAFStateMachine(200, 1, 2) {}
+        , mAFStateMachine(200, 1, 2)
+{}
 
 std::tuple<PixelFormat, BufferUsage, Dataspace, int32_t>
-QemuCamera::overrideStreamParams(const PixelFormat format,
+BaseQemuCamera::overrideStreamParams(const PixelFormat format,
                                  const BufferUsage usage,
                                  const Dataspace dataspace) const {
     constexpr BufferUsage kExtraUsage = usageOr(BufferUsage::CAMERA_OUTPUT,
@@ -158,302 +149,7 @@ QemuCamera::overrideStreamParams(const PixelFormat format,
     }
 }
 
-bool QemuCamera::configure(const CameraMetadata& sessionParams,
-                           size_t nStreams,
-                           const Stream* streams,
-                           const HalStream* halStreams) {
-    applyMetadata(sessionParams);
-
-    if (!mQemuChannel.ok()) {
-        auto qemuChannel = qemuOpenChannel(std::string("name=") + mParams.name);
-        if (!qemuChannel.ok()) {
-            return false;
-        }
-
-        static const char kConnectQuery[] = "connect";
-        if (qemuRunQuery(qemuChannel.get(), kConnectQuery, sizeof(kConnectQuery)) < 0) {
-            return false;
-        }
-
-        static const char kStartQuery[] = "start";
-        if (qemuRunQuery(qemuChannel.get(), kStartQuery, sizeof(kStartQuery)) < 0) {
-            return false;
-        }
-
-        mQemuChannel = std::move(qemuChannel);
-    }
-
-    mStreamInfoCache.clear();
-    for (; nStreams > 0; --nStreams, ++streams, ++halStreams) {
-        const int32_t id = streams->id;
-        LOG_ALWAYS_FATAL_IF(halStreams->id != id);
-        StreamInfo& si = mStreamInfoCache[id];
-        si.size.width = streams->width;
-        si.size.height = streams->height;
-        si.pixelFormat = halStreams->overrideFormat;
-        si.blobBufferSize = streams->bufferSize;
-    }
-
-    return true;
-}
-
-void QemuCamera::close() {
-    mStreamInfoCache.clear();
-
-    if (mQemuChannel.ok()) {
-        static const char kStopQuery[] = "stop";
-        if (qemuRunQuery(mQemuChannel.get(), kStopQuery, sizeof(kStopQuery)) >= 0) {
-            static const char kDisconnectQuery[] = "disconnect";
-            qemuRunQuery(mQemuChannel.get(), kDisconnectQuery, sizeof(kDisconnectQuery));
-        }
-
-        mQemuChannel.reset();
-    }
-}
-
-std::tuple<int64_t, int64_t, CameraMetadata,
-           std::vector<StreamBuffer>, std::vector<DelayedStreamBuffer>>
-QemuCamera::processCaptureRequest(CameraMetadata metadataUpdate,
-                                  Span<CachedStreamBuffer*> csbs) {
-    CameraMetadata resultMetadata = metadataUpdate.metadata.empty() ?
-        updateCaptureResultMetadata() :
-        applyMetadata(std::move(metadataUpdate));
-
-    const size_t csbsSize = csbs.size();
-    std::vector<StreamBuffer> outputBuffers;
-    std::vector<DelayedStreamBuffer> delayedOutputBuffers;
-    outputBuffers.reserve(csbsSize);
-
-    for (size_t i = 0; i < csbsSize; ++i) {
-        CachedStreamBuffer* csb = csbs[i];
-        LOG_ALWAYS_FATAL_IF(!csb);  // otherwise mNumBuffersInFlight will be hard
-
-        const StreamInfo* si = csb->getStreamInfo<StreamInfo>();
-        if (!si) {
-            const auto sii = mStreamInfoCache.find(csb->getStreamId());
-            if (sii == mStreamInfoCache.end()) {
-                ALOGE("%s:%s:%d could not find stream=%d in the cache",
-                      kClass, __func__, __LINE__, csb->getStreamId());
-            } else {
-                si = &sii->second;
-                csb->setStreamInfo(si);
-            }
-        }
-
-        if (si) {
-            captureFrame(*si, csb, &outputBuffers, &delayedOutputBuffers);
-        } else {
-            outputBuffers.push_back(csb->finish(false));
-        }
-    }
-
-    return make_tuple((mQemuChannel.ok() ? mFrameDurationNs : FAILURE(-1)),
-                      mSensorExposureDurationNs,
-                      std::move(resultMetadata), std::move(outputBuffers),
-                      std::move(delayedOutputBuffers));
-}
-
-void QemuCamera::captureFrame(const StreamInfo& si,
-                              CachedStreamBuffer* csb,
-                              std::vector<StreamBuffer>* outputBuffers,
-                              std::vector<DelayedStreamBuffer>* delayedOutputBuffers) const {
-    switch (si.pixelFormat) {
-    case PixelFormat::YCBCR_420_888:
-        outputBuffers->push_back(csb->finish(captureFrameYUV(si, csb)));
-        break;
-
-    case PixelFormat::RGBA_8888:
-        outputBuffers->push_back(csb->finish(captureFrameRGBA(si, csb)));
-        break;
-
-    case PixelFormat::RAW16:
-        delayedOutputBuffers->push_back(captureFrameRAW16(si, csb));
-        break;
-
-    case PixelFormat::BLOB:
-        delayedOutputBuffers->push_back(captureFrameJpeg(si, csb));
-        break;
-
-    default:
-        ALOGE("%s:%s:%d: unexpected pixelFormat=0x%" PRIx32,
-              kClass, __func__, __LINE__,
-              static_cast<uint32_t>(si.pixelFormat));
-        outputBuffers->push_back(csb->finish(false));
-        break;
-    }
-}
-
-bool QemuCamera::captureFrameYUV(const StreamInfo& si,
-                                 CachedStreamBuffer* csb) const {
-    const cb_handle_t* const cb = cb_handle_t::from(csb->getBuffer());
-    if (!cb) {
-        return FAILURE(false);
-    }
-
-    if (!csb->waitAcquireFence(mFrameDurationNs / 2000000)) {
-        return FAILURE(false);
-    }
-
-    const auto size = si.size;
-    android_ycbcr ycbcr;
-    if (GraphicBufferMapper::get().lockYCbCr(
-            cb, static_cast<uint32_t>(BufferUsage::CPU_WRITE_OFTEN),
-            {size.width, size.height}, &ycbcr) != NO_ERROR) {
-        return FAILURE(false);
-    }
-
-    bool const res = queryFrame(si.size, V4L2_PIX_FMT_YUV420,
-                                mExposureComp, cb->getMmapedOffset());
-
-    LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(cb) != NO_ERROR);
-    return res;
-}
-
-bool QemuCamera::captureFrameRGBA(const StreamInfo& si,
-                                  CachedStreamBuffer* csb) const {
-    const cb_handle_t* const cb = cb_handle_t::from(csb->getBuffer());
-    if (!cb) {
-        return FAILURE(false);
-    }
-
-    if (!csb->waitAcquireFence(mFrameDurationNs / 2000000)) {
-        return FAILURE(false);
-    }
-
-    const auto size = si.size;
-    void* mem = nullptr;
-    if (GraphicBufferMapper::get().lock(
-            cb, static_cast<uint32_t>(BufferUsage::CPU_WRITE_OFTEN),
-            {size.width, size.height}, &mem) != NO_ERROR) {
-        return FAILURE(false);
-    }
-
-    bool const res = queryFrame(si.size, V4L2_PIX_FMT_RGB32,
-                                mExposureComp, cb->getMmapedOffset());
-    LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(cb) != NO_ERROR);
-    return res;
-}
-
-DelayedStreamBuffer QemuCamera::captureFrameRAW16(const StreamInfo& si,
-                                                  CachedStreamBuffer* csb) const {
-    const native_handle_t* const image = captureFrameForCompressing(
-        si.size, PixelFormat::RGBA_8888, V4L2_PIX_FMT_RGB32);
-
-    const Rect<uint16_t> imageSize = si.size;
-    const int64_t frameDurationNs = mFrameDurationNs;
-    CameraMetadata metadata = mCaptureResultMetadata;
-
-    return [csb, image, imageSize, metadata = std::move(metadata),
-            frameDurationNs](const bool ok) -> StreamBuffer {
-        StreamBuffer sb;
-        if (ok && image && csb->waitAcquireFence(frameDurationNs / 1000000)) {
-            void* mem = nullptr;
-            if (GraphicBufferMapper::get().lock(
-                    image, static_cast<uint32_t>(BufferUsage::CPU_READ_OFTEN),
-                    {imageSize.width, imageSize.height}, &mem) == NO_ERROR) {
-                sb = csb->finish(convertRGBAtoRAW16(imageSize, mem, csb->getBuffer()));
-                LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(image) != NO_ERROR);
-            } else {
-                sb = csb->finish(FAILURE(false));
-            }
-        } else {
-            sb = csb->finish(false);
-        }
-
-        if (image) {
-            GraphicBufferAllocator::get().free(image);
-        }
-
-        return sb;
-    };
-}
-
-DelayedStreamBuffer QemuCamera::captureFrameJpeg(const StreamInfo& si,
-                                                 CachedStreamBuffer* csb) const {
-    const native_handle_t* const image = captureFrameForCompressing(
-        si.size, PixelFormat::YCBCR_420_888, V4L2_PIX_FMT_YUV420);
-
-    const Rect<uint16_t> imageSize = si.size;
-    const uint32_t jpegBufferSize = si.blobBufferSize;
-    const int64_t frameDurationNs = mFrameDurationNs;
-    CameraMetadata metadata = mCaptureResultMetadata;
-
-    return [csb, image, imageSize, metadata = std::move(metadata), jpegBufferSize,
-            frameDurationNs](const bool ok) -> StreamBuffer {
-        StreamBuffer sb;
-        if (ok && image && csb->waitAcquireFence(frameDurationNs / 1000000)) {
-            android_ycbcr imageYcbcr;
-            if (GraphicBufferMapper::get().lockYCbCr(
-                    image, static_cast<uint32_t>(BufferUsage::CPU_READ_OFTEN),
-                    {imageSize.width, imageSize.height}, &imageYcbcr) == NO_ERROR) {
-                sb = csb->finish(compressJpeg(imageSize, imageYcbcr, metadata,
-                                              csb->getBuffer(), jpegBufferSize));
-                LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(image) != NO_ERROR);
-            } else {
-                sb = csb->finish(FAILURE(false));
-            }
-        } else {
-            sb = csb->finish(false);
-        }
-
-        if (image) {
-            GraphicBufferAllocator::get().free(image);
-        }
-
-        return sb;
-    };
-}
-
-const native_handle_t* QemuCamera::captureFrameForCompressing(
-        const Rect<uint16_t> dim,
-        const PixelFormat bufferFormat,
-        const uint32_t qemuFormat) const {
-    constexpr BufferUsage kUsage = usageOr(BufferUsage::CAMERA_OUTPUT,
-                                           BufferUsage::CPU_READ_OFTEN);
-
-    GraphicBufferAllocator& gba = GraphicBufferAllocator::get();
-    const native_handle_t* image = nullptr;
-    uint32_t stride;
-
-    if (gba.allocate(dim.width, dim.height, static_cast<int>(bufferFormat), 1,
-                     static_cast<uint64_t>(kUsage), &image, &stride,
-                     "QemuCamera") != NO_ERROR) {
-        return FAILURE(nullptr);
-    }
-
-    const cb_handle_t* const cb = cb_handle_t::from(image);
-    if (!cb) {
-        gba.free(image);
-        return FAILURE(nullptr);
-    }
-
-    if (!queryFrame(dim, qemuFormat, mExposureComp, cb->getMmapedOffset())) {
-        gba.free(image);
-        return FAILURE(nullptr);
-    }
-
-    return image;
-}
-
-bool QemuCamera::queryFrame(const Rect<uint16_t> dim,
-                            const uint32_t pixelFormat,
-                            const float exposureComp,
-                            const uint64_t dataOffset) const {
-    constexpr float scaleR = 1;
-    constexpr float scaleG = 1;
-    constexpr float scaleB = 1;
-
-    char queryStr[128];
-    const int querySize = snprintf(queryStr, sizeof(queryStr),
-        "frame dim=%" PRIu32 "x%" PRIu32 " pix=%" PRIu32 " offset=%" PRIu64
-        " whiteb=%g,%g,%g expcomp=%g time=%d",
-        dim.width, dim.height, static_cast<uint32_t>(pixelFormat), dataOffset,
-        scaleR, scaleG, scaleB, exposureComp, 0);
-
-    return qemuRunQuery(mQemuChannel.get(), queryStr, querySize + 1) >= 0;
-}
-
-float QemuCamera::calculateExposureComp(const int64_t exposureNs,
+float BaseQemuCamera::calculateExposureComp(const int64_t exposureNs,
                                         const int sensorSensitivity,
                                         const float aperture) {
     return (double(exposureNs) * sensorSensitivity
@@ -462,7 +158,7 @@ float QemuCamera::calculateExposureComp(const int64_t exposureNs,
                 * aperture * aperture);
 }
 
-CameraMetadata QemuCamera::applyMetadata(const CameraMetadata& metadata) {
+CameraMetadata BaseQemuCamera::applyMetadata(const CameraMetadata& metadata) {
     const camera_metadata_t* const raw =
         reinterpret_cast<const camera_metadata_t*>(metadata.metadata.data());
     camera_metadata_ro_entry_t entry;
@@ -560,7 +256,7 @@ CameraMetadata QemuCamera::applyMetadata(const CameraMetadata& metadata) {
     }
 }
 
-CameraMetadata QemuCamera::updateCaptureResultMetadata() {
+CameraMetadata BaseQemuCamera::updateCaptureResultMetadata() {
     camera_metadata_t* const raw =
         reinterpret_cast<camera_metadata_t*>(mCaptureResultMetadata.metadata.data());
 
@@ -589,7 +285,7 @@ CameraMetadata QemuCamera::updateCaptureResultMetadata() {
 
 ////////////////////////////////////////////////////////////////////////////////
 
-Span<const std::pair<int32_t, int32_t>> QemuCamera::getTargetFpsRanges() const {
+Span<const std::pair<int32_t, int32_t>> BaseQemuCamera::getTargetFpsRanges() const {
     // ordered to satisfy testPreviewFpsRangeByCamera
     static const std::pair<int32_t, int32_t> targetFpsRanges[] = {
         {kMinFPS, kMedFPS},
@@ -601,16 +297,16 @@ Span<const std::pair<int32_t, int32_t>> QemuCamera::getTargetFpsRanges() const {
     return targetFpsRanges;
 }
 
-Span<const Rect<uint16_t>> QemuCamera::getAvailableThumbnailSizes() const {
+Span<const Rect<uint16_t>> BaseQemuCamera::getAvailableThumbnailSizes() const {
     return {mParams.availableThumbnailResolutions.begin(),
             mParams.availableThumbnailResolutions.end()};
 }
 
-bool QemuCamera::isBackFacing() const {
+bool BaseQemuCamera::isBackFacing() const {
     return mParams.isBackFacing;
 }
 
-Span<const float> QemuCamera::getAvailableApertures() const {
+Span<const float> BaseQemuCamera::getAvailableApertures() const {
     static const float availableApertures[] = {
         1.4, 2.0, 2.8, 4.0, 5.6, 8.0, 11.0, 16.0
     };
@@ -618,7 +314,7 @@ Span<const float> QemuCamera::getAvailableApertures() const {
     return availableApertures;
 }
 
-std::tuple<int32_t, int32_t, int32_t> QemuCamera::getMaxNumOutputStreams() const {
+std::tuple<int32_t, int32_t, int32_t> BaseQemuCamera::getMaxNumOutputStreams() const {
     return {
         1,  // raw
         2,  // processed
@@ -626,14 +322,14 @@ std::tuple<int32_t, int32_t, int32_t> QemuCamera::getMaxNumOutputStreams() const
     };
 }
 
-uint32_t QemuCamera::getAvailableCapabilitiesBitmap() const {
+uint32_t BaseQemuCamera::getAvailableCapabilitiesBitmap() const {
     return
         (1U << ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE) |
         (1U << ANDROID_REQUEST_AVAILABLE_CAPABILITIES_READ_SENSOR_SETTINGS) |
         (1U << ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW);
 }
 
-Span<const PixelFormat> QemuCamera::getSupportedPixelFormats() const {
+Span<const PixelFormat> BaseQemuCamera::getSupportedPixelFormats() const {
     static const PixelFormat supportedPixelFormats[] = {
         PixelFormat::IMPLEMENTATION_DEFINED,
         PixelFormat::YCBCR_420_888,
@@ -645,35 +341,35 @@ Span<const PixelFormat> QemuCamera::getSupportedPixelFormats() const {
     return {supportedPixelFormats};
 }
 
-int64_t QemuCamera::getMinFrameDurationNs() const {
+int64_t BaseQemuCamera::getMinFrameDurationNs() const {
     return kMinFrameDurationNs;
 }
 
-Rect<uint16_t> QemuCamera::getSensorSize() const {
+Rect<uint16_t> BaseQemuCamera::getSensorSize() const {
     return mParams.sensorSize;
 }
 
-uint8_t QemuCamera::getSensorColorFilterArrangement() const {
+uint8_t BaseQemuCamera::getSensorColorFilterArrangement() const {
     return ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT_RGGB;
 }
 
-std::pair<int32_t, int32_t> QemuCamera::getSensorSensitivityRange() const {
+std::pair<int32_t, int32_t> BaseQemuCamera::getSensorSensitivityRange() const {
     return {kMinSensorSensitivity, kMaxSensorSensitivity};
 }
 
-std::pair<int64_t, int64_t> QemuCamera::getSensorExposureTimeRange() const {
+std::pair<int64_t, int64_t> BaseQemuCamera::getSensorExposureTimeRange() const {
     return {kMinSensorExposureTimeNs, kMaxSensorExposureTimeNs};
 }
 
-int64_t QemuCamera::getSensorMaxFrameDuration() const {
+int64_t BaseQemuCamera::getSensorMaxFrameDuration() const {
     return kMaxSensorExposureTimeNs;
 }
 
-Span<const Rect<uint16_t>> QemuCamera::getSupportedResolutions() const {
+Span<const Rect<uint16_t>> BaseQemuCamera::getSupportedResolutions() const {
     return {mParams.supportedResolutions.begin(), mParams.supportedResolutions.end()};
 }
 
-std::pair<int32_t, int32_t> QemuCamera::getDefaultTargetFpsRange(const RequestTemplate tpl) const {
+std::pair<int32_t, int32_t> BaseQemuCamera::getDefaultTargetFpsRange(const RequestTemplate tpl) const {
     switch (tpl) {
     case RequestTemplate::PREVIEW:
     case RequestTemplate::VIDEO_RECORD:
@@ -685,19 +381,19 @@ std::pair<int32_t, int32_t> QemuCamera::getDefaultTargetFpsRange(const RequestTe
     }
 }
 
-float QemuCamera::getDefaultAperture() const {
+float BaseQemuCamera::getDefaultAperture() const {
     return kDefaultAperture;
 }
 
-int64_t QemuCamera::getDefaultSensorExpTime() const {
+int64_t BaseQemuCamera::getDefaultSensorExpTime() const {
     return kDefaultSensorExposureTimeNs;
 }
 
-int64_t QemuCamera::getDefaultSensorFrameDuration() const {
+int64_t BaseQemuCamera::getDefaultSensorFrameDuration() const {
     return kMinFrameDurationNs;
 }
 
-int32_t QemuCamera::getDefaultSensorSensitivity() const {
+int32_t BaseQemuCamera::getDefaultSensorSensitivity() const {
     return kDefaultSensorSensitivity;
 }
 
diff --git a/hals/camera/BaseQemuCamera.h b/hals/camera/BaseQemuCamera.h
new file mode 100644
index 00000000..a2ae0cfa
--- /dev/null
+++ b/hals/camera/BaseQemuCamera.h
@@ -0,0 +1,89 @@
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
+#pragma once
+
+#include <string>
+
+#include "HwCamera.h"
+#include "AFStateMachine.h"
+
+namespace android {
+namespace hardware {
+namespace camera {
+namespace provider {
+namespace implementation {
+namespace hw {
+
+struct BaseQemuCamera : public HwCamera {
+    struct Parameters {
+        std::string name;
+        std::vector<Rect<uint16_t>> supportedResolutions;
+        std::vector<Rect<uint16_t>> availableThumbnailResolutions;
+        Rect<uint16_t> sensorSize;
+        bool isBackFacing;
+    };
+
+    std::tuple<PixelFormat, BufferUsage, Dataspace, int32_t>
+        overrideStreamParams(PixelFormat, BufferUsage, Dataspace) const override;
+
+    // metadata
+    uint32_t getAvailableCapabilitiesBitmap() const override;
+    Span<const std::pair<int32_t, int32_t>> getTargetFpsRanges() const override;
+    Span<const Rect<uint16_t>> getAvailableThumbnailSizes() const override;
+    bool isBackFacing() const override;
+    Span<const float> getAvailableApertures() const override;
+    std::tuple<int32_t, int32_t, int32_t> getMaxNumOutputStreams() const override;
+    Span<const PixelFormat> getSupportedPixelFormats() const override;
+    Span<const Rect<uint16_t>> getSupportedResolutions() const override;
+    int64_t getMinFrameDurationNs() const override;
+    Rect<uint16_t> getSensorSize() const override;
+    uint8_t getSensorColorFilterArrangement() const override;
+    std::pair<int32_t, int32_t> getSensorSensitivityRange() const override;
+    std::pair<int64_t, int64_t> getSensorExposureTimeRange() const override;
+    int64_t getSensorMaxFrameDuration() const override;
+
+    std::pair<int32_t, int32_t> getDefaultTargetFpsRange(RequestTemplate) const override;
+    float getDefaultAperture() const override;
+    int64_t getDefaultSensorExpTime() const override;
+    int64_t getDefaultSensorFrameDuration() const override;
+    int32_t getDefaultSensorSensitivity() const override;
+
+protected:
+    explicit BaseQemuCamera(const Parameters& params);
+
+    static float calculateExposureComp(int64_t exposureNs, int sensorSensitivity,
+                                       float aperture);
+    CameraMetadata applyMetadata(const CameraMetadata& metadata);
+    CameraMetadata updateCaptureResultMetadata();
+
+    const Parameters& mParams;
+    AFStateMachine mAFStateMachine;
+    CameraMetadata mCaptureResultMetadata;
+
+    int64_t mFrameDurationNs = 0;
+    int64_t mSensorExposureDurationNs = 0;
+    int32_t mSensorSensitivity = 0;
+    float mAperture = 0;
+    float mExposureComp = 0;
+};
+
+}  // namespace hw
+}  // namespace implementation
+}  // namespace provider
+}  // namespace camera
+}  // namespace hardware
+}  // namespace android
diff --git a/hals/camera/CameraDevice.cpp b/hals/camera/CameraDevice.cpp
index f3f2c997..727e7ae1 100644
--- a/hals/camera/CameraDevice.cpp
+++ b/hals/camera/CameraDevice.cpp
@@ -397,7 +397,7 @@ ScopedAStatus CameraDevice::getCameraCharacteristics(CameraMetadata* metadata) {
         }
     }
     {
-        CameraMetadataMap r = constructDefaultRequestSettings(RequestTemplate::PREVIEW);
+        CameraMetadataMap r = constructDefaultRequestSettingsImpl(RequestTemplate::PREVIEW);
 
         {
             const std::vector<uint32_t> keys = getSortedKeys(r);
@@ -445,6 +445,11 @@ ScopedAStatus CameraDevice::isStreamCombinationSupported(
     return ScopedAStatus::ok();
 }
 
+ScopedAStatus CameraDevice::isStreamCombinationWithSettingsSupported(
+        const StreamConfiguration& streams, bool* support) {
+    return isStreamCombinationSupported(streams, support);
+}
+
 ScopedAStatus CameraDevice::open(const std::shared_ptr<ICameraDeviceCallback>& callback,
         std::shared_ptr<ICameraDeviceSession>* session) {
     *session = ndk::SharedRefBase::make<CameraDeviceSession>(
@@ -470,7 +475,43 @@ ScopedAStatus CameraDevice::getTorchStrengthLevel(int32_t* /*strength*/) {
     return toScopedAStatus(FAILURE(Status::OPERATION_NOT_SUPPORTED));
 }
 
-CameraMetadataMap CameraDevice::constructDefaultRequestSettings(const RequestTemplate tpl) const {
+ScopedAStatus CameraDevice::constructDefaultRequestSettings(const RequestTemplate tpl,
+                                                            CameraMetadata* metadata) {
+    auto maybeMetadata = serializeCameraMetadataMap(
+        constructDefaultRequestSettingsImpl(tpl));
+    if (maybeMetadata) {
+        *metadata = std::move(maybeMetadata.value());
+        return ScopedAStatus::ok();
+    } else {
+        return toScopedAStatus(Status::INTERNAL_ERROR);
+    }
+}
+
+ScopedAStatus CameraDevice::getSessionCharacteristics(
+          const StreamConfiguration& /*sessionConfig*/,
+          CameraMetadata* metadata) {
+    CameraMetadataMap m;
+
+    {
+        const auto zoomRatioRange = mHwCamera->getZoomRatioRange();
+        m[ANDROID_CONTROL_ZOOM_RATIO_RANGE]
+            .add<float>(zoomRatioRange.first)
+            .add<float>(zoomRatioRange.second);
+    }
+
+    m[ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM] =
+        float(mHwCamera->getMaxDigitalZoom());
+
+    auto maybeMetadata = serializeCameraMetadataMap(m);
+    if (maybeMetadata) {
+        *metadata = std::move(maybeMetadata.value());
+        return ScopedAStatus::ok();
+    } else {
+        return toScopedAStatus(Status::INTERNAL_ERROR);
+    }
+}
+
+CameraMetadataMap CameraDevice::constructDefaultRequestSettingsImpl(const RequestTemplate tpl) const {
     using namespace std::literals;
     const auto sensorSize = mHwCamera->getSensorSize();
     const std::pair<int32_t, int32_t> fpsRange = mHwCamera->getDefaultTargetFpsRange(tpl);
diff --git a/hals/camera/CameraDevice.h b/hals/camera/CameraDevice.h
index f096da37..f44acd60 100644
--- a/hals/camera/CameraDevice.h
+++ b/hals/camera/CameraDevice.h
@@ -50,24 +50,29 @@ struct CameraDevice : public BnCameraDevice {
 
     ScopedAStatus getCameraCharacteristics(CameraMetadata* metadata) override;
     ScopedAStatus getPhysicalCameraCharacteristics(
-            const std::string& in_physicalCameraId, CameraMetadata* metadata) override;
+            const std::string& physicalCameraId, CameraMetadata* metadata) override;
     ScopedAStatus getResourceCost(CameraResourceCost* cost) override;
     ScopedAStatus isStreamCombinationSupported(
-            const StreamConfiguration& in_streams, bool* support) override;
+            const StreamConfiguration& streams, bool* support) override;
+    ScopedAStatus isStreamCombinationWithSettingsSupported(
+            const StreamConfiguration& streams, bool* support) override;
     ScopedAStatus open(const std::shared_ptr<ICameraDeviceCallback>& in_callback,
                        std::shared_ptr<ICameraDeviceSession>* session) override;
     ScopedAStatus openInjectionSession(
-            const std::shared_ptr<ICameraDeviceCallback>& in_callback,
+            const std::shared_ptr<ICameraDeviceCallback>& callback,
             std::shared_ptr<ICameraInjectionSession>* session) override;
     ScopedAStatus setTorchMode(bool on) override;
     ScopedAStatus turnOnTorchWithStrengthLevel(int32_t strength) override;
     ScopedAStatus getTorchStrengthLevel(int32_t* strength) override;
-
-    CameraMetadataMap constructDefaultRequestSettings(RequestTemplate tpl) const;
+    ScopedAStatus constructDefaultRequestSettings(RequestTemplate tpl, CameraMetadata*) override;
+    ScopedAStatus getSessionCharacteristics(
+            const StreamConfiguration& sessionConfig, CameraMetadata* metadata) override;
 
 private:
     friend struct CameraProvider;
 
+    CameraMetadataMap constructDefaultRequestSettingsImpl(RequestTemplate tpl) const;
+
     hw::HwCameraFactoryProduct mHwCamera;
     std::weak_ptr<CameraDevice> mSelf;
 };
diff --git a/hals/camera/CameraDeviceSession.cpp b/hals/camera/CameraDeviceSession.cpp
index 41a22e36..bf87c3ef 100644
--- a/hals/camera/CameraDeviceSession.cpp
+++ b/hals/camera/CameraDeviceSession.cpp
@@ -139,10 +139,10 @@ CaptureResult makeCaptureResult(const int frameNumber,
 }  // namespace
 
 CameraDeviceSession::CameraDeviceSession(
-        std::shared_ptr<CameraDevice> parent,
+        std::shared_ptr<CameraDevice> device,
         std::shared_ptr<ICameraDeviceCallback> cb,
         hw::HwCamera& hwCamera)
-         : mParent(std::move(parent))
+         : mDevice(std::move(device))
          , mCb(std::move(cb))
          , mHwCamera(hwCamera)
          , mRequestQueue(kMsgQueueSize, false)
@@ -225,18 +225,15 @@ ScopedAStatus CameraDeviceSession::configureStreams(
     }
 }
 
+ScopedAStatus CameraDeviceSession::configureStreamsV2(const StreamConfiguration& cfg,
+                                                      ConfigureStreamsRet* ret) {
+    return configureStreams(cfg, &ret->halStreams);
+}
+
 ScopedAStatus CameraDeviceSession::constructDefaultRequestSettings(
         const RequestTemplate tpl,
         CameraMetadata* metadata) {
-    auto maybeMetadata = serializeCameraMetadataMap(
-        mParent->constructDefaultRequestSettings(tpl));
-
-    if (maybeMetadata) {
-        *metadata = std::move(maybeMetadata.value());
-        return ScopedAStatus::ok();
-    } else {
-        return toScopedAStatus(Status::INTERNAL_ERROR);
-    }
+    return mDevice->constructDefaultRequestSettings(tpl, metadata);
 }
 
 ScopedAStatus CameraDeviceSession::flush() {
@@ -315,6 +312,7 @@ bool CameraDeviceSession::isStreamCombinationSupported(const StreamConfiguration
 void CameraDeviceSession::closeImpl() {
     flushImpl(std::chrono::steady_clock::now());
     mHwCamera.close();
+    mStreamBufferCache.clear();
 }
 
 void CameraDeviceSession::flushImpl(const std::chrono::steady_clock::time_point start) {
diff --git a/hals/camera/CameraDeviceSession.h b/hals/camera/CameraDeviceSession.h
index 0b24fcbe..4053abff 100644
--- a/hals/camera/CameraDeviceSession.h
+++ b/hals/camera/CameraDeviceSession.h
@@ -46,6 +46,7 @@ using aidl::android::hardware::camera::device::CameraMetadata;
 using aidl::android::hardware::camera::device::CameraOfflineSessionInfo;
 using aidl::android::hardware::camera::device::CaptureRequest;
 using aidl::android::hardware::camera::device::CaptureResult;
+using aidl::android::hardware::camera::device::ConfigureStreamsRet;
 using aidl::android::hardware::camera::device::HalStream;
 using aidl::android::hardware::camera::device::ICameraDeviceCallback;
 using aidl::android::hardware::camera::device::ICameraOfflineSession;
@@ -64,7 +65,7 @@ using ndk::ScopedAStatus;
 struct CameraDevice;
 
 struct CameraDeviceSession : public BnCameraDeviceSession {
-    CameraDeviceSession(std::shared_ptr<CameraDevice> parent,
+    CameraDeviceSession(std::shared_ptr<CameraDevice> device,
                         std::shared_ptr<ICameraDeviceCallback> cb,
                         hw::HwCamera& hwCamera);
     ~CameraDeviceSession() override;
@@ -72,6 +73,8 @@ struct CameraDeviceSession : public BnCameraDeviceSession {
     ScopedAStatus close() override;
     ScopedAStatus configureStreams(const StreamConfiguration& cfg,
                                    std::vector<HalStream>* halStreamsOut) override;
+    ScopedAStatus configureStreamsV2(const StreamConfiguration& cfg,
+                                     ConfigureStreamsRet* ret) override;
     ScopedAStatus constructDefaultRequestSettings(RequestTemplate tpl,
                                                   CameraMetadata* metadata) override;
     ScopedAStatus flush() override;
@@ -120,7 +123,7 @@ private:
     void consumeCaptureResult(CaptureResult cr);
     void notifyBuffersReturned(size_t n);
 
-    const std::shared_ptr<CameraDevice> mParent;
+    const std::shared_ptr<CameraDevice> mDevice;
     const std::shared_ptr<ICameraDeviceCallback> mCb;
     hw::HwCamera& mHwCamera;
     MetadataQueue mRequestQueue;
diff --git a/hals/camera/GasQemuCamera.cpp b/hals/camera/GasQemuCamera.cpp
new file mode 100644
index 00000000..916b94ae
--- /dev/null
+++ b/hals/camera/GasQemuCamera.cpp
@@ -0,0 +1,334 @@
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
+
+#include <linux/videodev2.h>
+#include <ui/GraphicBufferAllocator.h>
+#include <ui/GraphicBufferMapper.h>
+
+#include <gralloc_cb_bp.h>
+
+#include "GasQemuCamera.h"
+
+#include "debug.h"
+#include "jpeg.h"
+#include "qemu_channel.h"
+
+namespace android {
+namespace hardware {
+namespace camera {
+namespace provider {
+namespace implementation {
+namespace hw {
+namespace {
+constexpr char kClass[] = "GasQemuCamera";
+
+constexpr BufferUsage usageOr(const BufferUsage a, const BufferUsage b) {
+    return static_cast<BufferUsage>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
+}
+}  // namespace
+
+GasQemuCamera::GasQemuCamera(const Parameters& params)
+        : BaseQemuCamera(params)
+{}
+
+bool GasQemuCamera::configure(const CameraMetadata& sessionParams,
+                              const size_t nStreams,
+                              const Stream* streams,
+                              const HalStream* halStreams) {
+    if (!mQemuChannel.ok()) {
+        auto qemuChannel = qemuOpenChannel(std::string("name=") + mParams.name);
+        if (!qemuChannel.ok()) {
+            return false;
+        }
+        static const char kConnectQuery[] = "connect";
+        if (qemuRunQuery(qemuChannel.get(), kConnectQuery, sizeof(kConnectQuery)) < 0) {
+            return false;
+        }
+        static const char kStartQuery[] = "start";
+        if (qemuRunQuery(qemuChannel.get(), kStartQuery, sizeof(kStartQuery)) < 0) {
+            return false;
+        }
+        mQemuChannel = std::move(qemuChannel);
+    }
+
+    mStreams.resize(nStreams);
+    for (size_t i = 0; i < nStreams; ++i, ++streams, ++halStreams) {
+        LOG_ALWAYS_FATAL_IF(streams->id != halStreams->id);
+        StreamInfo& si = mStreams[i];
+        si.id = streams->id;
+        si.size.width = streams->width;
+        si.size.height = streams->height;
+        si.blobBufferSize = streams->bufferSize;
+        si.format = halStreams->overrideFormat;
+    }
+
+    applyMetadata(sessionParams);
+    return true;
+}
+
+void GasQemuCamera::close() {
+    if (mQemuChannel.ok()) {
+        static const char kStopQuery[] = "stop";
+        if (qemuRunQuery(mQemuChannel.get(), kStopQuery, sizeof(kStopQuery)) >= 0) {
+            static const char kDisconnectQuery[] = "disconnect";
+            qemuRunQuery(mQemuChannel.get(), kDisconnectQuery, sizeof(kDisconnectQuery));
+        }
+        mQemuChannel.reset();
+    }
+    mStreams.clear();
+}
+
+std::tuple<int64_t, int64_t, CameraMetadata,
+           std::vector<StreamBuffer>, std::vector<DelayedStreamBuffer>>
+GasQemuCamera::processCaptureRequest(CameraMetadata metadataUpdate,
+                                  Span<CachedStreamBuffer*> csbs) {
+    CameraMetadata resultMetadata = metadataUpdate.metadata.empty() ?
+        updateCaptureResultMetadata() :
+        applyMetadata(std::move(metadataUpdate));
+
+    const size_t csbsSize = csbs.size();
+    std::vector<StreamBuffer> outputBuffers;
+    std::vector<DelayedStreamBuffer> delayedOutputBuffers;
+    outputBuffers.reserve(csbsSize);
+
+    for (size_t i = 0; i < csbsSize; ++i) {
+        CachedStreamBuffer* csb = csbs[i];
+        LOG_ALWAYS_FATAL_IF(!csb);  // otherwise mNumBuffersInFlight will be hard
+
+        const StreamInfo* si = csb->getStreamInfo<StreamInfo>();
+        if (!si) {
+            const int32_t id = csb->getStreamId();
+            const auto sii =
+                std::find_if(mStreams.begin(), mStreams.end(),
+                             [id](const StreamInfo& si){
+                                 return id == si.id;
+                             });
+
+            if (sii == mStreams.end()) {
+                ALOGE("%s:%s:%d could not find stream=%d in the cache",
+                      kClass, __func__, __LINE__, csb->getStreamId());
+            } else {
+                si = &*sii;
+                csb->setStreamInfo(si);
+            }
+        }
+
+        if (si) {
+            captureFrame(*si, csb, &outputBuffers, &delayedOutputBuffers);
+        } else {
+            outputBuffers.push_back(csb->finish(false));
+        }
+    }
+
+    return make_tuple((mQemuChannel.ok() ? mFrameDurationNs : FAILURE(-1)),
+                      mSensorExposureDurationNs,
+                      std::move(resultMetadata), std::move(outputBuffers),
+                      std::move(delayedOutputBuffers));
+}
+
+void GasQemuCamera::captureFrame(const StreamInfo& si,
+                                 CachedStreamBuffer* csb,
+                                 std::vector<StreamBuffer>* outputBuffers,
+                                 std::vector<DelayedStreamBuffer>* delayedOutputBuffers) const {
+    switch (si.format) {
+    case PixelFormat::YCBCR_420_888:
+        outputBuffers->push_back(csb->finish(captureFrameYUV(si, csb)));
+        break;
+    case PixelFormat::RGBA_8888:
+        outputBuffers->push_back(csb->finish(captureFrameRGBA(si, csb)));
+        break;
+    case PixelFormat::RAW16:
+        delayedOutputBuffers->push_back(captureFrameRAW16(si, csb));
+        break;
+    case PixelFormat::BLOB:
+        delayedOutputBuffers->push_back(captureFrameJpeg(si, csb));
+        break;
+    default:
+        ALOGE("%s:%s:%d: unexpected format=%s", kClass,
+              __func__, __LINE__, toString(si.format).c_str());
+        outputBuffers->push_back(csb->finish(false));
+        break;
+    }
+}
+
+bool GasQemuCamera::captureFrameYUV(const StreamInfo& si,
+                                    CachedStreamBuffer* csb) const {
+    if (!csb->waitAcquireFence(mFrameDurationNs / 2000000)) {
+        return FAILURE(false);
+    }
+
+    const cb_handle_t* const cb = cb_handle_t::from(csb->getBuffer());
+    if (!cb) {
+        return FAILURE(false);
+    }
+
+    const auto size = si.size;
+    android_ycbcr ycbcr;
+    if (GraphicBufferMapper::get().lockYCbCr(
+            cb, static_cast<uint32_t>(BufferUsage::CPU_WRITE_OFTEN),
+            {size.width, size.height}, &ycbcr) != NO_ERROR) {
+        return FAILURE(false);
+    }
+
+    bool const res = queryFrame(si.size, V4L2_PIX_FMT_YUV420,
+                                mExposureComp, cb->getMmapedOffset());
+
+    LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(cb) != NO_ERROR);
+    return res;
+}
+
+bool GasQemuCamera::captureFrameRGBA(const StreamInfo& si,
+                                     CachedStreamBuffer* csb) const {
+    if (!csb->waitAcquireFence(mFrameDurationNs / 2000000)) {
+        return FAILURE(false);
+    }
+
+    const cb_handle_t* const cb = cb_handle_t::from(csb->getBuffer());
+    if (!cb) {
+        return FAILURE(false);
+    }
+
+    const auto size = si.size;
+    void* mem = nullptr;
+    if (GraphicBufferMapper::get().lock(
+            cb, static_cast<uint32_t>(BufferUsage::CPU_WRITE_OFTEN),
+            {size.width, size.height}, &mem) != NO_ERROR) {
+        return FAILURE(false);
+    }
+
+    bool const res = queryFrame(si.size, V4L2_PIX_FMT_RGB32,
+                                mExposureComp, cb->getMmapedOffset());
+
+    LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(cb) != NO_ERROR);
+    return res;
+}
+
+DelayedStreamBuffer GasQemuCamera::captureFrameRAW16(const StreamInfo& si,
+                                                     CachedStreamBuffer* csb) const {
+    const native_handle_t* const image = captureFrameForCompressing(
+        si.size, PixelFormat::RGBA_8888, V4L2_PIX_FMT_RGB32);
+
+    const Rect<uint16_t> imageSize = si.size;
+    const int64_t frameDurationNs = mFrameDurationNs;
+    CameraMetadata metadata = mCaptureResultMetadata;
+
+    return [csb, image, imageSize, metadata = std::move(metadata),
+            frameDurationNs](const bool ok) -> StreamBuffer {
+        StreamBuffer sb;
+        if (ok && image && csb->waitAcquireFence(frameDurationNs / 1000000)) {
+            void* mem = nullptr;
+            if (GraphicBufferMapper::get().lock(
+                    image, static_cast<uint32_t>(BufferUsage::CPU_READ_OFTEN),
+                    {imageSize.width, imageSize.height}, &mem) == NO_ERROR) {
+                sb = csb->finish(convertRGBAtoRAW16(imageSize, mem, csb->getBuffer()));
+                LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(image) != NO_ERROR);
+            } else {
+                sb = csb->finish(FAILURE(false));
+            }
+        } else {
+            sb = csb->finish(false);
+        }
+        if (image) {
+            GraphicBufferAllocator::get().free(image);
+        }
+        return sb;
+    };
+}
+DelayedStreamBuffer GasQemuCamera::captureFrameJpeg(const StreamInfo& si,
+                                                    CachedStreamBuffer* csb) const {
+    const native_handle_t* const image = captureFrameForCompressing(
+        si.size, PixelFormat::YCBCR_420_888, V4L2_PIX_FMT_YUV420);
+
+    const Rect<uint16_t> imageSize = si.size;
+    const uint32_t jpegBufferSize = si.blobBufferSize;
+    const int64_t frameDurationNs = mFrameDurationNs;
+    CameraMetadata metadata = mCaptureResultMetadata;
+
+    return [csb, image, imageSize, metadata = std::move(metadata), jpegBufferSize,
+            frameDurationNs](const bool ok) -> StreamBuffer {
+        StreamBuffer sb;
+        if (ok && image && csb->waitAcquireFence(frameDurationNs / 1000000)) {
+            android_ycbcr imageYcbcr;
+            if (GraphicBufferMapper::get().lockYCbCr(
+                    image, static_cast<uint32_t>(BufferUsage::CPU_READ_OFTEN),
+                    {imageSize.width, imageSize.height}, &imageYcbcr) == NO_ERROR) {
+                sb = csb->finish(compressJpeg(imageSize, imageYcbcr, metadata,
+                                              csb->getBuffer(), jpegBufferSize));
+                LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(image) != NO_ERROR);
+            } else {
+                sb = csb->finish(FAILURE(false));
+            }
+        } else {
+            sb = csb->finish(false);
+        }
+
+        if (image) {
+            GraphicBufferAllocator::get().free(image);
+        }
+        return sb;
+    };
+}
+
+const native_handle_t* GasQemuCamera::captureFrameForCompressing(
+        const Rect<uint16_t> dim,
+        const PixelFormat bufferFormat,
+        const uint32_t qemuFormat) const {
+    constexpr BufferUsage kUsage = usageOr(BufferUsage::CAMERA_OUTPUT,
+                                           BufferUsage::CPU_READ_OFTEN);
+
+    GraphicBufferAllocator& gba = GraphicBufferAllocator::get();
+
+    const native_handle_t* image = nullptr;
+    uint32_t stride;
+    if (gba.allocate(dim.width, dim.height, static_cast<int>(bufferFormat), 1,
+                     static_cast<uint64_t>(kUsage), &image, &stride,
+                     "GasQemuCamera") != NO_ERROR) {
+        return FAILURE(nullptr);
+    }
+
+    const cb_handle_t* const cb = cb_handle_t::from(image);
+    if (!cb) {
+        gba.free(image);
+        return FAILURE(nullptr);
+    }
+
+    if (!queryFrame(dim, qemuFormat, mExposureComp, cb->getMmapedOffset())) {
+        gba.free(image);
+        return FAILURE(nullptr);
+    }
+
+    return image;
+}
+
+bool GasQemuCamera::queryFrame(const Rect<uint16_t> dim,
+                               const uint32_t pixelFormat,
+                               const float exposureComp,
+                               const uint64_t dataOffset) const {
+    char queryStr[128];
+    const int querySize = snprintf(queryStr, sizeof(queryStr),
+        "frame dim=%" PRIu32 "x%" PRIu32 " pix=%" PRIu32 " offset=%" PRIu64
+        " expcomp=%g", dim.width, dim.height, static_cast<uint32_t>(pixelFormat),
+        dataOffset, exposureComp);
+
+    return qemuRunQuery(mQemuChannel.get(), queryStr, querySize + 1) >= 0;
+}
+
+}  // namespace hw
+}  // namespace implementation
+}  // namespace provider
+}  // namespace camera
+}  // namespace hardware
+}  // namespace android
diff --git a/hals/camera/GasQemuCamera.h b/hals/camera/GasQemuCamera.h
new file mode 100644
index 00000000..c5a9e411
--- /dev/null
+++ b/hals/camera/GasQemuCamera.h
@@ -0,0 +1,76 @@
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
+
+#pragma once
+
+#include <vector>
+
+#include <android-base/unique_fd.h>
+
+#include "BaseQemuCamera.h"
+
+namespace android {
+namespace hardware {
+namespace camera {
+namespace provider {
+namespace implementation {
+namespace hw {
+
+struct GasQemuCamera : public BaseQemuCamera {
+    explicit GasQemuCamera(const Parameters& params);
+
+    bool configure(const CameraMetadata& sessionParams, size_t nStreams,
+                   const Stream* streams, const HalStream* halStreams) override;
+    void close() override;
+
+    std::tuple<int64_t, int64_t, CameraMetadata, std::vector<StreamBuffer>,
+               std::vector<DelayedStreamBuffer>>
+        processCaptureRequest(CameraMetadata, Span<CachedStreamBuffer*>) override;
+
+private:
+    struct StreamInfo {
+        int32_t id;
+        uint32_t blobBufferSize;
+        PixelFormat format;
+        Rect<uint16_t> size;
+    };
+
+    void captureFrame(const StreamInfo& si,
+                      CachedStreamBuffer* csb,
+                      std::vector<StreamBuffer>* outputBuffers,
+                      std::vector<DelayedStreamBuffer>* delayedOutputBuffers) const;
+    bool captureFrameYUV(const StreamInfo& si, CachedStreamBuffer* dst) const;
+    bool captureFrameRGBA(const StreamInfo& si, CachedStreamBuffer* dst) const;
+    DelayedStreamBuffer captureFrameRAW16(const StreamInfo& si,
+                                          CachedStreamBuffer* csb) const;
+    DelayedStreamBuffer captureFrameJpeg(const StreamInfo& si,
+                                         CachedStreamBuffer* csb) const;
+    const native_handle_t* captureFrameForCompressing(Rect<uint16_t> dim,
+                                                      PixelFormat bufferFormat,
+                                                      uint32_t qemuFormat) const;
+    bool queryFrame(Rect<uint16_t> dim, uint32_t pixelFormat,
+                    float exposureComp, uint64_t dataOffset) const;
+
+    std::vector<StreamInfo> mStreams;
+    base::unique_fd mQemuChannel;
+};
+
+}  // namespace hw
+}  // namespace implementation
+}  // namespace provider
+}  // namespace camera
+}  // namespace hardware
+}  // namespace android
diff --git a/hals/camera/MinigbmQemuCamera.cpp b/hals/camera/MinigbmQemuCamera.cpp
new file mode 100644
index 00000000..d817bf65
--- /dev/null
+++ b/hals/camera/MinigbmQemuCamera.cpp
@@ -0,0 +1,290 @@
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
+
+#include <string>
+#include <string_view>
+
+#include <linux/videodev2.h>
+#include <ui/GraphicBufferAllocator.h>
+#include <ui/GraphicBufferMapper.h>
+
+#include "MinigbmQemuCamera.h"
+
+#include "debug.h"
+#include "jpeg.h"
+#include "qemu_channel.h"
+#include "yuv.h"
+
+namespace android {
+namespace hardware {
+namespace camera {
+namespace provider {
+namespace implementation {
+namespace hw {
+using namespace std::literals;
+
+namespace {
+constexpr char kClass[] = "MinigbmQemuCamera";
+
+constexpr uint64_t kDelayedBufferAllocUsage =
+    static_cast<uint64_t>(BufferUsage::CAMERA_OUTPUT) |
+    static_cast<uint64_t>(BufferUsage::CPU_READ_OFTEN);
+
+}  // namespace
+
+MinigbmQemuCamera::MinigbmQemuCamera(const Parameters& params)
+        : BaseQemuCamera(params)
+        , mGfxGralloc(gfxstream::createPlatformGralloc())
+{}
+
+bool MinigbmQemuCamera::configure(const CameraMetadata& sessionParams,
+                                  size_t nStreams,
+                                  const Stream* streams,
+                                  const HalStream* halStreams) {
+    constexpr std::string_view kConfigureQueryPrefix = "configure streams="sv;
+
+    std::string query;
+    query.reserve(kConfigureQueryPrefix.size() + 30U * nStreams);
+    query.append(kConfigureQueryPrefix);
+
+    std::vector<StreamInfo> newStreams(nStreams);
+    for (size_t i = 0; i < nStreams; ++i, ++streams, ++halStreams) {
+        LOG_ALWAYS_FATAL_IF(streams->id != halStreams->id);
+        StreamInfo& si = newStreams[i];
+        si.id = streams->id;
+        si.size.width = streams->width;
+        si.size.height = streams->height;
+        si.blobBufferSize = streams->bufferSize;
+        si.format = halStreams->overrideFormat;
+
+        PixelFormat hostFormat;
+        switch (si.format) {
+        case PixelFormat::BLOB:
+            hostFormat = PixelFormat::YCBCR_420_888;
+            break;
+
+        case PixelFormat::RAW16:
+            hostFormat = PixelFormat::RGBA_8888;
+            break;
+
+        default:
+            hostFormat = si.format;
+            break;
+        }
+
+        char buf[64];
+        const int len =
+            ::snprintf(buf, sizeof(buf), "%s%d:%ux%u@%X",
+                       ((i > 0) ? "," : ""), si.id,
+                       si.size.width, si.size.height,
+                       static_cast<uint32_t>(hostFormat));
+        query.append(buf, len);
+    }
+
+    if (!mQemuChannel.ok()) {
+        auto qemuChannel = qemuOpenChannel(std::string("name="sv) + mParams.name);
+        if (qemuChannel.ok()) {
+            mQemuChannel = std::move(qemuChannel);
+        } else {
+            return false;
+        }
+    }
+
+    if (qemuRunQuery(mQemuChannel.get(), query.data(), query.size() + 1) < 0) {
+        mQemuChannel.reset();
+        return false;
+    }
+
+    mStreams = std::move(newStreams);
+    applyMetadata(sessionParams);
+    return true;
+}
+
+void MinigbmQemuCamera::close() {
+    mQemuChannel.reset();
+    mStreams.clear();
+}
+
+std::tuple<int64_t, int64_t, CameraMetadata,
+           std::vector<StreamBuffer>, std::vector<DelayedStreamBuffer>>
+MinigbmQemuCamera::processCaptureRequest(CameraMetadata metadataUpdate,
+                                         Span<CachedStreamBuffer*> csbs) {
+    constexpr std::string_view kCaptureQueryPrefix = "capture bufs="sv;
+
+    CameraMetadata resultMetadata = metadataUpdate.metadata.empty() ?
+        updateCaptureResultMetadata() :
+        applyMetadata(std::move(metadataUpdate));
+
+    const size_t csbsSize = csbs.size();
+
+    std::string query;
+    query.reserve(kCaptureQueryPrefix.size() + 10U * csbsSize);
+    query.append(kCaptureQueryPrefix);
+
+    std::vector<CachedStreamBuffer*> immediateBuffers;
+    std::vector<StreamBuffer> outputBuffers;
+    std::vector<DelayedStreamBuffer> delayedOutputBuffers;
+
+    immediateBuffers.reserve(csbsSize);
+    outputBuffers.reserve(csbsSize);
+
+    bool firstEntry = true;
+    for (size_t i = 0; i < csbsSize; ++i) {
+        CachedStreamBuffer* csb = csbs[i];
+        LOG_ALWAYS_FATAL_IF(!csb);  // otherwise mNumBuffersInFlight will be hard
+
+        const native_handle_t* captureBuf;
+        const StreamInfo* si = csb->getStreamInfo<StreamInfo>();
+        if (!si) {
+            const int32_t id = csb->getStreamId();
+            const auto sii =
+                std::find_if(mStreams.begin(), mStreams.end(),
+                             [id](const StreamInfo& si){
+                                 return id == si.id;
+                             });
+
+            if (sii == mStreams.end()) {
+                ALOGE("%s:%s:%d: could not find stream=%d in the cache",
+                      kClass, __func__, __LINE__, id);
+                goto failCsb;
+            } else {
+                si = &*sii;
+                csb->setStreamInfo(si);
+            }
+        }
+
+        switch (si->format) {
+        case PixelFormat::BLOB: {
+                const Rect<uint16_t> imageSize = si->size;
+                GraphicBufferAllocator& gba = GraphicBufferAllocator::get();
+                uint32_t stride;
+                if (gba.allocate(imageSize.width, imageSize.height,
+                                 static_cast<int>(PixelFormat::YCBCR_420_888), 1,
+                                 kDelayedBufferAllocUsage, &captureBuf, &stride,
+                                 "MinigbmQemuCamera") == NO_ERROR) {
+                    CameraMetadata metadata = mCaptureResultMetadata;
+                    const size_t jpegBufferSize = si->blobBufferSize;
+                    delayedOutputBuffers.push_back([captureBuf, csb, imageSize, jpegBufferSize,
+                                                    metadata = std::move(metadata)]
+                                                   (const bool ok) -> StreamBuffer {
+                        StreamBuffer sb;
+                        if (ok && csb->waitAcquireFence(100)) {
+                            android_ycbcr imageYcbcr;
+                            if (GraphicBufferMapper::get().lockYCbCr(
+                                    captureBuf, static_cast<uint32_t>(BufferUsage::CPU_READ_OFTEN),
+                                    {imageSize.width, imageSize.height}, &imageYcbcr) == NO_ERROR) {
+                                sb = csb->finish(compressJpeg(imageSize, imageYcbcr, metadata,
+                                                              csb->getBuffer(), jpegBufferSize));
+                                LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(captureBuf) != NO_ERROR);
+                            } else {
+                                sb = csb->finish(FAILURE(false));
+                            }
+                        } else {
+                            sb = csb->finish(false);
+                        }
+
+                        GraphicBufferAllocator::get().free(captureBuf);
+                        return sb;
+                    });
+                } else {
+                    captureBuf = nullptr;
+                }
+            }
+            break;
+
+        case PixelFormat::RAW16: {
+                const Rect<uint16_t> imageSize = si->size;
+                GraphicBufferAllocator& gba = GraphicBufferAllocator::get();
+                uint32_t stride;
+                if (gba.allocate(imageSize.width, imageSize.height,
+                                 static_cast<int>(PixelFormat::RGBA_8888), 1,
+                                 kDelayedBufferAllocUsage, &captureBuf, &stride,
+                                 "MinigbmQemuCamera") == NO_ERROR) {
+                    CameraMetadata metadata = mCaptureResultMetadata;
+                    delayedOutputBuffers.push_back([captureBuf, csb, imageSize,
+                                                    metadata = std::move(metadata)]
+                                                   (const bool ok) -> StreamBuffer {
+                        StreamBuffer sb;
+                        if (ok && csb->waitAcquireFence(100)) {
+                            void* mem = nullptr;
+                            if (GraphicBufferMapper::get().lock(
+                                    captureBuf, static_cast<uint32_t>(BufferUsage::CPU_READ_OFTEN),
+                                    {imageSize.width, imageSize.height}, &mem) == NO_ERROR) {
+                                sb = csb->finish(convertRGBAtoRAW16(imageSize, mem, csb->getBuffer()));
+                                LOG_ALWAYS_FATAL_IF(GraphicBufferMapper::get().unlock(captureBuf) != NO_ERROR);
+                            } else {
+                                sb = csb->finish(FAILURE(false));
+                            }
+                        } else {
+                            sb = csb->finish(false);
+                        }
+
+                        GraphicBufferAllocator::get().free(captureBuf);
+                        return sb;
+                    });
+                } else {
+                    captureBuf = nullptr;
+                }
+            }
+            break;
+
+        default:
+            immediateBuffers.push_back(csb);
+            captureBuf = csb->getBuffer();
+            break;
+        }
+
+        if (captureBuf) {
+            const uint32_t hostHandle = mGfxGralloc->getHostHandle(captureBuf);
+
+            char buf[32];
+            const int len =
+                ::snprintf(buf, sizeof(buf), "%s%d:%u", (firstEntry ? "" : ","),
+                           si->id, hostHandle);
+            query.append(buf, len);
+            firstEntry = false;
+        } else {
+failCsb:    outputBuffers.push_back(csb->finish(false));
+        }
+    }
+
+    if (qemuRunQuery(mQemuChannel.get(), query.data(), query.size() + 1) >= 0) {
+        for (CachedStreamBuffer* csb : immediateBuffers) {
+            outputBuffers.push_back(csb->finish(true));
+        }
+    } else {
+        for (CachedStreamBuffer* csb : immediateBuffers) {
+            outputBuffers.push_back(csb->finish(false));
+        }
+
+        for (const DelayedStreamBuffer& dsb : delayedOutputBuffers) {
+            outputBuffers.push_back(dsb(false));
+            delayedOutputBuffers.clear();
+        }
+    }
+
+    return make_tuple((mQemuChannel.ok() ? mFrameDurationNs : FAILURE(-1)),
+                      mSensorExposureDurationNs,
+                      std::move(resultMetadata), std::move(outputBuffers),
+                      std::move(delayedOutputBuffers));
+}
+
+}  // namespace hw
+}  // namespace implementation
+}  // namespace provider
+}  // namespace camera
+}  // namespace hardware
+}  // namespace android
diff --git a/hals/camera/MinigbmQemuCamera.h b/hals/camera/MinigbmQemuCamera.h
new file mode 100644
index 00000000..a74c3044
--- /dev/null
+++ b/hals/camera/MinigbmQemuCamera.h
@@ -0,0 +1,61 @@
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
+
+#pragma once
+
+#include <vector>
+
+#include <gfxstream/guest/GfxStreamGralloc.h>
+
+#include "BaseQemuCamera.h"
+
+namespace android {
+namespace hardware {
+namespace camera {
+namespace provider {
+namespace implementation {
+namespace hw {
+
+struct MinigbmQemuCamera : public BaseQemuCamera {
+    explicit MinigbmQemuCamera (const Parameters& params);
+
+    bool configure(const CameraMetadata& sessionParams, size_t nStreams,
+                   const Stream* streams, const HalStream* halStreams) override;
+    void close() override;
+
+    std::tuple<int64_t, int64_t, CameraMetadata, std::vector<StreamBuffer>,
+               std::vector<DelayedStreamBuffer>>
+        processCaptureRequest(CameraMetadata, Span<CachedStreamBuffer*>) override;
+
+private:
+    struct StreamInfo {
+        int32_t id;
+        uint32_t blobBufferSize;
+        PixelFormat format;
+        Rect<uint16_t> size;
+    };
+
+    const std::unique_ptr<gfxstream::Gralloc> mGfxGralloc;
+    std::vector<StreamInfo> mStreams;
+    base::unique_fd mQemuChannel;
+};
+
+}  // namespace hw
+}  // namespace implementation
+}  // namespace provider
+}  // namespace camera
+}  // namespace hardware
+}  // namespace android
diff --git a/hals/camera/QemuCamera.h b/hals/camera/QemuCamera.h
index d6d96385..a76493c2 100644
--- a/hals/camera/QemuCamera.h
+++ b/hals/camera/QemuCamera.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -16,13 +16,11 @@
 
 #pragma once
 
-#include <string>
-#include <unordered_map>
-
-#include <android-base/unique_fd.h>
-
-#include "HwCamera.h"
-#include "AFStateMachine.h"
+#ifdef USE_MINIGBM_GRALLOC
+#include "MinigbmQemuCamera.h"
+#else
+#include "GasQemuCamera.h"
+#endif
 
 namespace android {
 namespace hardware {
@@ -31,89 +29,11 @@ namespace provider {
 namespace implementation {
 namespace hw {
 
-struct QemuCamera : public HwCamera {
-    struct Parameters {
-        std::string name;
-        std::vector<Rect<uint16_t>> supportedResolutions;
-        std::vector<Rect<uint16_t>> availableThumbnailResolutions;
-        Rect<uint16_t> sensorSize;
-        bool isBackFacing;
-    };
-
-    explicit QemuCamera(const Parameters& params);
-
-    std::tuple<PixelFormat, BufferUsage, Dataspace, int32_t>
-        overrideStreamParams(PixelFormat, BufferUsage, Dataspace) const override;
-
-    bool configure(const CameraMetadata& sessionParams, size_t nStreams,
-                   const Stream* streams, const HalStream* halStreams) override;
-    void close() override;
-
-    std::tuple<int64_t, int64_t, CameraMetadata, std::vector<StreamBuffer>,
-               std::vector<DelayedStreamBuffer>>
-        processCaptureRequest(CameraMetadata, Span<CachedStreamBuffer*>) override;
-
-    // metadata
-    uint32_t getAvailableCapabilitiesBitmap() const override;
-    Span<const std::pair<int32_t, int32_t>> getTargetFpsRanges() const override;
-    Span<const Rect<uint16_t>> getAvailableThumbnailSizes() const override;
-    bool isBackFacing() const override;
-    Span<const float> getAvailableApertures() const override;
-    std::tuple<int32_t, int32_t, int32_t> getMaxNumOutputStreams() const override;
-    Span<const PixelFormat> getSupportedPixelFormats() const override;
-    Span<const Rect<uint16_t>> getSupportedResolutions() const override;
-    int64_t getMinFrameDurationNs() const override;
-    Rect<uint16_t> getSensorSize() const override;
-    uint8_t getSensorColorFilterArrangement() const override;
-    std::pair<int32_t, int32_t> getSensorSensitivityRange() const override;
-    std::pair<int64_t, int64_t> getSensorExposureTimeRange() const override;
-    int64_t getSensorMaxFrameDuration() const override;
-
-    std::pair<int32_t, int32_t> getDefaultTargetFpsRange(RequestTemplate) const override;
-    float getDefaultAperture() const override;
-    int64_t getDefaultSensorExpTime() const override;
-    int64_t getDefaultSensorFrameDuration() const override;
-    int32_t getDefaultSensorSensitivity() const override;
-
-private:
-    struct StreamInfo {
-        Rect<uint16_t> size;
-        PixelFormat pixelFormat;
-        uint32_t blobBufferSize;
-    };
-
-    void captureFrame(const StreamInfo& si,
-                      CachedStreamBuffer* csb,
-                      std::vector<StreamBuffer>* outputBuffers,
-                      std::vector<DelayedStreamBuffer>* delayedOutputBuffers) const;
-    bool captureFrameYUV(const StreamInfo& si, CachedStreamBuffer* dst) const;
-    bool captureFrameRGBA(const StreamInfo& si, CachedStreamBuffer* dst) const;
-    DelayedStreamBuffer captureFrameRAW16(const StreamInfo& si,
-                                          CachedStreamBuffer* csb) const;
-    DelayedStreamBuffer captureFrameJpeg(const StreamInfo& si,
-                                         CachedStreamBuffer* csb) const;
-    const native_handle_t* captureFrameForCompressing(Rect<uint16_t> dim,
-                                                      PixelFormat bufferFormat,
-                                                      uint32_t qemuFormat) const;
-    bool queryFrame(Rect<uint16_t> dim, uint32_t pixelFormat,
-                    float exposureComp, uint64_t dataOffset) const;
-    static float calculateExposureComp(int64_t exposureNs, int sensorSensitivity,
-                                       float aperture);
-    CameraMetadata applyMetadata(const CameraMetadata& metadata);
-    CameraMetadata updateCaptureResultMetadata();
-
-    const Parameters& mParams;
-    AFStateMachine mAFStateMachine;
-    std::unordered_map<int32_t, StreamInfo> mStreamInfoCache;
-    base::unique_fd mQemuChannel;
-    CameraMetadata mCaptureResultMetadata;
-
-    int64_t mFrameDurationNs = 0;
-    int64_t mSensorExposureDurationNs = 0;
-    int32_t mSensorSensitivity = 0;
-    float mAperture = 0;
-    float mExposureComp = 0;
-};
+#ifdef USE_MINIGBM_GRALLOC
+using QemuCamera = MinigbmQemuCamera;
+#else
+using QemuCamera = GasQemuCamera;
+#endif
 
 }  // namespace hw
 }  // namespace implementation
diff --git a/hals/camera/StreamBufferCache.cpp b/hals/camera/StreamBufferCache.cpp
index f511b755..ca7d4a8e 100644
--- a/hals/camera/StreamBufferCache.cpp
+++ b/hals/camera/StreamBufferCache.cpp
@@ -27,16 +27,12 @@ namespace implementation {
 
 CachedStreamBuffer*
 StreamBufferCache::update(const StreamBuffer& sb) {
-    const auto bi = mCache.find(sb.bufferId);
-    if (bi == mCache.end()) {
-        const auto r = mCache.insert({sb.bufferId, CachedStreamBuffer(sb)});
-        LOG_ALWAYS_FATAL_IF(!r.second);
-        return &(r.first->second);
-    } else {
-        CachedStreamBuffer* csb = &bi->second;
+    const auto [it, inserted] = mCache.try_emplace(sb.bufferId, sb);
+    CachedStreamBuffer* csb = &it->second;
+    if (!inserted) {
         csb->importAcquireFence(sb.acquireFence);
-        return csb;
     }
+    return csb;
 }
 
 void StreamBufferCache::remove(const int64_t bufferId) {
@@ -49,6 +45,10 @@ void StreamBufferCache::clearStreamInfo() {
     }
 }
 
+void StreamBufferCache::clear() {
+    mCache.clear();
+}
+
 }  // namespace implementation
 }  // namespace provider
 }  // namespace camera
diff --git a/hals/camera/StreamBufferCache.h b/hals/camera/StreamBufferCache.h
index 113fb4da..f856f966 100644
--- a/hals/camera/StreamBufferCache.h
+++ b/hals/camera/StreamBufferCache.h
@@ -36,6 +36,7 @@ struct StreamBufferCache {
     CachedStreamBuffer* update(const StreamBuffer& sb);
     void remove(int64_t bufferId);
     void clearStreamInfo();
+    void clear();
 
 private:
     // std::map is to keep iterators valid after `insert`
diff --git a/hals/camera/android.hardware.camera.provider.ranchu.xml b/hals/camera/android.hardware.camera.provider.ranchu.xml
index c2df3407..eb4cf1ba 100644
--- a/hals/camera/android.hardware.camera.provider.ranchu.xml
+++ b/hals/camera/android.hardware.camera.provider.ranchu.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.camera.provider</name>
-        <version>1</version>
+        <version>3</version>
         <interface>
             <name>ICameraProvider</name>
             <instance>internal/1</instance>
diff --git a/hals/camera/android.hardware.camera.provider.ranchu_minigbm.rc b/hals/camera/android.hardware.camera.provider.ranchu_minigbm.rc
new file mode 100644
index 00000000..69d428f5
--- /dev/null
+++ b/hals/camera/android.hardware.camera.provider.ranchu_minigbm.rc
@@ -0,0 +1,7 @@
+service vendor.camera-provider-ranchu /vendor/bin/hw/android.hardware.camera.provider.ranchu_minigbm
+    class hal
+    user system
+    group system
+    capabilities SYS_NICE
+    rlimit rtprio 10 10
+    task_profiles CameraServiceCapacity CameraServicePerformance
diff --git a/hals/gralloc/allocator.cpp b/hals/gralloc/allocator.cpp
index d9d35ff9..28764722 100644
--- a/hals/gralloc/allocator.cpp
+++ b/hals/gralloc/allocator.cpp
@@ -475,12 +475,9 @@ struct GoldfishAllocator : public BnAllocator {
             req.stride0 = 0;
         }
 
-        if (needGpuBuffer(usage)) {
-            req.rcAllocFormat = (req.format == PixelFormat::RGBX_8888) ? GL_RGB : req.glFormat;
-        } else {
+        if (!needGpuBuffer(usage)) {
             req.glFormat = -1;  // no GPU buffer - no GPU formats
             req.glType = -1;
-            req.rcAllocFormat = -1;
         }
 
         std::vector<std::unique_ptr<cb_handle_t>> cbs(count);
@@ -551,7 +548,6 @@ private:
         PixelFormat format = PixelFormat::UNSPECIFIED;
         int glFormat = -1;
         int glType = -1;
-        int rcAllocFormat = -1;
         EmulatorFrameworkFormat emuFwkFormat = EmulatorFrameworkFormat::GL_COMPATIBLE;
         uint8_t planeSize = 0;
     };
@@ -615,7 +611,7 @@ private:
 
             hostHandle = rcEnc.rcCreateColorBufferDMA(
                 &rcEnc, req.width, req.height,
-                req.rcAllocFormat, static_cast<int>(req.emuFwkFormat));
+                req.glFormat, static_cast<int>(req.emuFwkFormat));
             if (!hostHandle) {
                 return FAILURE(nullptr);
             }
@@ -633,8 +629,8 @@ private:
             if (hostHandle) {
                 snprintf(hostHandleValueStr, sizeof(hostHandleValueStr),
                          "0x%X glFormat=0x%X glType=0x%X "
-                         "rcAllocFormat=0x%X emuFwkFormat=%d",
-                         hostHandle, req.glFormat, req.glType, req.rcAllocFormat,
+                         "glFormat=0x%X emuFwkFormat=%d",
+                         hostHandle, req.glFormat, req.glType, req.glFormat,
                          static_cast<int>(req.emuFwkFormat));
             } else {
                 strcpy(hostHandleValueStr, "null");
diff --git a/hals/hwc3/AlternatingImageStorage.cpp b/hals/hwc3/AlternatingImageStorage.cpp
new file mode 100644
index 00000000..c4a1d85c
--- /dev/null
+++ b/hals/hwc3/AlternatingImageStorage.cpp
@@ -0,0 +1,41 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include "AlternatingImageStorage.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+uint8_t* AlternatingImageStorage::getRotatingScratchBuffer(std::size_t neededSize,
+                                                           std::uint32_t imageIndex) {
+    std::size_t totalNeededSize = neededSize * kNumScratchBufferPieces;
+    if (mScratchBuffer.size() < totalNeededSize) {
+        mScratchBuffer.resize(totalNeededSize);
+    }
+
+    std::size_t bufferIndex = imageIndex % kNumScratchBufferPieces;
+    std::size_t bufferOffset = bufferIndex * neededSize;
+    return &mScratchBuffer[bufferOffset];
+}
+
+uint8_t* AlternatingImageStorage::getSpecialScratchBuffer(size_t neededSize) {
+    if (mSpecialScratchBuffer.size() < neededSize) {
+        mSpecialScratchBuffer.resize(neededSize);
+    }
+
+    return &mSpecialScratchBuffer[0];
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/AlternatingImageStorage.h b/hals/hwc3/AlternatingImageStorage.h
new file mode 100644
index 00000000..aa17bc70
--- /dev/null
+++ b/hals/hwc3/AlternatingImageStorage.h
@@ -0,0 +1,52 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#ifndef ANDROID_HWC_ALTERNATINGIMAGESTORAGE_H
+#define ANDROID_HWC_ALTERNATINGIMAGESTORAGE_H
+
+#include <stdint.h>
+
+#include <vector>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+// Provides storage for images when transforming images with the expectation
+// that image N will no longer be used after producing image N + 1. With this,
+// the storage just needs to be 2x the needed image size and the returned buffers
+// can alternate back and forth.
+class AlternatingImageStorage {
+   public:
+    AlternatingImageStorage() = default;
+
+    uint8_t* getRotatingScratchBuffer(std::size_t neededSize, std::uint32_t imageIndex);
+
+    uint8_t* getSpecialScratchBuffer(std::size_t neededSize);
+
+   private:
+    static constexpr const int kNumScratchBufferPieces = 2;
+
+    // The main alternating storage.
+    std::vector<uint8_t> mScratchBuffer;
+
+    // Extra additional storage for one-off operations (scaling).
+    std::vector<uint8_t> mSpecialScratchBuffer;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/Android.bp b/hals/hwc3/Android.bp
new file mode 100644
index 00000000..f956d5a7
--- /dev/null
+++ b/hals/hwc3/Android.bp
@@ -0,0 +1,143 @@
+//
+// Copyright 2022 The Android Open-Source Project
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "device_generic_goldfish_license",
+    ],
+}
+
+cc_binary {
+    name: "android.hardware.graphics.composer3-service.ranchu",
+
+    defaults: [
+        "android.hardware.graphics.composer3-ndk_shared",
+        "mesa_platform_virtgpu_defaults",
+    ],
+
+    relative_install_path: "hw",
+    vendor: true,
+
+    shared_libs: [
+        "android.hardware.graphics.composer@2.1-resources",
+        "android.hardware.graphics.composer@2.2-resources",
+        "libbase",
+        "libbinder_ndk",
+        "libcutils",
+        "libdrm",
+        "libgralloctypes",
+        "libhidlbase",
+        "libjsoncpp",
+        "liblog",
+        "libsync",
+        "libui",
+        "libutils",
+        "libOpenglSystemCommon",
+        "libui",
+    ],
+
+    static_libs: [
+        "libaidlcommonsupport",
+        "libyuv_static",
+    ],
+
+    header_libs: [
+        "libminigbm_gralloc_headers",
+        "mesa_gfxstream_guest_android_headers",
+    ],
+
+    srcs: [
+        "AlternatingImageStorage.cpp",
+        "ClientFrameComposer.cpp",
+        "Common.cpp",
+        "Composer.cpp",
+        "ComposerClient.cpp",
+        "ComposerResources.cpp",
+        "Device.cpp",
+        "Display.cpp",
+        "DisplayConfig.cpp",
+        "DisplayFinder.cpp",
+        "Drm.cpp",
+        "DrmSwapchain.cpp",
+        "DrmAtomicRequest.cpp",
+        "DrmBuffer.cpp",
+        "DrmClient.cpp",
+        "DrmConnector.cpp",
+        "DrmCrtc.cpp",
+        "DrmDisplay.cpp",
+        "DrmEventListener.cpp",
+        "DrmMode.cpp",
+        "DrmPlane.cpp",
+        "EdidInfo.cpp",
+        "Gralloc.cpp",
+        "GuestFrameComposer.cpp",
+        "HostFrameComposer.cpp",
+        "HostUtils.cpp",
+        "Layer.cpp",
+        "Main.cpp",
+        "NoOpFrameComposer.cpp",
+        "VsyncThread.cpp",
+    ],
+
+    cflags: [
+        "-Wall",
+        "-Werror=conversion",
+        "-Wthread-safety",
+    ],
+
+    vintf_fragments: ["hwc3.xml"],
+    init_rc: ["hwc3.rc"],
+
+}
+
+apex {
+    name: "com.android.hardware.graphics.composer.ranchu",
+    key: "com.android.hardware.key",
+    certificate: ":com.android.hardware.certificate",
+    file_contexts: "apex_file_contexts",
+    manifest: "apex_manifest.json",
+    vendor: true,
+    updatable: false,
+
+    binaries: [
+        "android.hardware.graphics.composer3-service.ranchu",
+    ],
+    prebuilts: [
+        "hwc3.xml",
+        "hwc3-apex.rc",
+    ],
+}
+
+prebuilt_etc {
+    name: "hwc3.xml",
+    src: "hwc3.xml",
+    sub_dir: "vintf",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "hwc3-apex.rc",
+    src: ":gen-hwc3-apex.rc",
+    installable: false,
+}
+
+genrule {
+    name: "gen-hwc3-apex.rc",
+    srcs: ["hwc3.rc"],
+    out: ["hwc3-apex.rc"],
+    cmd: "sed -e 's@/vendor/bin/@/apex/com.android.hardware.graphics.composer/bin/@' $(in) > $(out)",
+}
diff --git a/hals/hwc3/ClientFrameComposer.cpp b/hals/hwc3/ClientFrameComposer.cpp
new file mode 100644
index 00000000..10c6ce89
--- /dev/null
+++ b/hals/hwc3/ClientFrameComposer.cpp
@@ -0,0 +1,160 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "ClientFrameComposer.h"
+
+#include <android-base/parseint.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+#include <android/hardware/graphics/common/1.0/types.h>
+#include <drm_fourcc.h>
+#include <libyuv.h>
+#include <sync/sync.h>
+#include <ui/GraphicBuffer.h>
+#include <ui/GraphicBufferAllocator.h>
+#include <ui/GraphicBufferMapper.h>
+
+#include "Display.h"
+#include "Drm.h"
+#include "Layer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+HWC3::Error ClientFrameComposer::init() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    HWC3::Error error = mDrmClient.init();
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to initialize DrmClient", __FUNCTION__);
+        return error;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ClientFrameComposer::registerOnHotplugCallback(const HotplugCallback& cb) {
+    return mDrmClient.registerOnHotplugCallback(cb);
+    return HWC3::Error::None;
+}
+
+HWC3::Error ClientFrameComposer::unregisterOnHotplugCallback() {
+    return mDrmClient.unregisterOnHotplugCallback();
+}
+
+HWC3::Error ClientFrameComposer::onDisplayCreate(Display* display) {
+    const auto displayId = display->getId();
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    // Ensure created.
+    mDisplayInfos.emplace(displayId, DisplayInfo{});
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ClientFrameComposer::onDisplayDestroy(Display* display) {
+    const auto displayId = display->getId();
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it == mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    mDisplayInfos.erase(it);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ClientFrameComposer::onDisplayClientTargetSet(Display* display) {
+    const auto displayId = display->getId();
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it == mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    DisplayInfo& displayInfo = it->second;
+
+    auto [drmBufferCreateError, drmBuffer] =
+        mDrmClient.create(display->getClientTarget().getBuffer());
+    if (drmBufferCreateError != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " failed to create client target drm buffer", __FUNCTION__,
+              displayId);
+        return HWC3::Error::NoResources;
+    }
+    displayInfo.clientTargetDrmBuffer = std::move(drmBuffer);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ClientFrameComposer::onActiveConfigChange(Display* /*display*/) {
+    return HWC3::Error::None;
+};
+
+HWC3::Error ClientFrameComposer::validateDisplay(Display* display, DisplayChanges* outChanges) {
+    const auto displayId = display->getId();
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    const std::vector<Layer*>& layers = display->getOrderedLayers();
+
+    for (Layer* layer : layers) {
+        const auto layerId = layer->getId();
+        const auto layerCompositionType = layer->getCompositionType();
+
+        if (layerCompositionType != Composition::CLIENT) {
+            outChanges->addLayerCompositionChange(displayId, layerId, Composition::CLIENT);
+            continue;
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ClientFrameComposer::presentDisplay(
+    Display* display, ::android::base::unique_fd* outDisplayFence,
+    std::unordered_map<int64_t, ::android::base::unique_fd>* /*outLayerFences*/) {
+    const auto displayId = display->getId();
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    auto displayInfoIt = mDisplayInfos.find(displayId);
+    if (displayInfoIt == mDisplayInfos.end()) {
+        ALOGE("%s: failed to find display buffers for display:%" PRIu64, __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    DisplayInfo& displayInfo = displayInfoIt->second;
+    if (!displayInfo.clientTargetDrmBuffer) {
+        ALOGW("%s: display:%" PRIu64 " no client target set, nothing to present.", __FUNCTION__,
+              displayId);
+        return HWC3::Error::None;
+    }
+
+    ::android::base::unique_fd fence = display->getClientTarget().getFence();
+
+    auto [flushError, flushCompleteFence] = mDrmClient.flushToDisplay(
+        static_cast<uint32_t>(displayId), displayInfo.clientTargetDrmBuffer, fence);
+    if (flushError != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " failed to flush drm buffer" PRIu64, __FUNCTION__, displayId);
+    }
+
+    *outDisplayFence = std::move(flushCompleteFence);
+    return flushError;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/ClientFrameComposer.h b/hals/hwc3/ClientFrameComposer.h
new file mode 100644
index 00000000..18603505
--- /dev/null
+++ b/hals/hwc3/ClientFrameComposer.h
@@ -0,0 +1,79 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_CLIENTFRAMECOMPOSER_H
+#define ANDROID_HWC_CLIENTFRAMECOMPOSER_H
+
+#include "Common.h"
+#include "Display.h"
+#include "DrmClient.h"
+#include "FrameComposer.h"
+#include "Gralloc.h"
+#include "Layer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+// A frame composer which always fallsback to client composition
+// (a.k.a make SurfaceFlinger do the composition).
+class ClientFrameComposer : public FrameComposer {
+   public:
+    ClientFrameComposer() = default;
+
+    ClientFrameComposer(const ClientFrameComposer&) = delete;
+    ClientFrameComposer& operator=(const ClientFrameComposer&) = delete;
+
+    ClientFrameComposer(ClientFrameComposer&&) = delete;
+    ClientFrameComposer& operator=(ClientFrameComposer&&) = delete;
+
+    HWC3::Error init() override;
+
+    HWC3::Error registerOnHotplugCallback(const HotplugCallback& cb) override;
+
+    HWC3::Error unregisterOnHotplugCallback() override;
+
+    HWC3::Error onDisplayCreate(Display* display) override;
+
+    HWC3::Error onDisplayDestroy(Display* display) override;
+
+    HWC3::Error onDisplayClientTargetSet(Display* display) override;
+
+    HWC3::Error onActiveConfigChange(Display* display) override;
+
+    // Determines if this composer can compose the given layers on the given
+    // display and requests changes for layers that can't not be composed.
+    HWC3::Error validateDisplay(Display* display, DisplayChanges* outChanges) override;
+
+    // Performs the actual composition of layers and presents the composed result
+    // to the display.
+    HWC3::Error presentDisplay(
+        Display* display, ::android::base::unique_fd* outDisplayFence,
+        std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) override;
+
+    const DrmClient* getDrmPresenter() const override { return &mDrmClient; }
+
+   private:
+    struct DisplayInfo {
+        std::shared_ptr<DrmBuffer> clientTargetDrmBuffer;
+    };
+
+    std::unordered_map<int64_t, DisplayInfo> mDisplayInfos;
+
+    DrmClient mDrmClient;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/Common.cpp b/hals/hwc3/Common.cpp
new file mode 100644
index 00000000..4e0a1180
--- /dev/null
+++ b/hals/hwc3/Common.cpp
@@ -0,0 +1,96 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "Common.h"
+
+#include <android-base/properties.h>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+bool IsAutoDevice() {
+    // gcar_emu_x86_64, sdk_car_md_x86_64, cf_x86_64_auto, cf_x86_64_only_auto_md
+    const std::string product_name = ::android::base::GetProperty("ro.product.name", "");
+    return product_name.find("car_") != std::string::npos ||
+        product_name.find("_auto") != std::string::npos;
+}
+
+bool IsCuttlefish() { return ::android::base::GetProperty("ro.product.board", "") == "cutf"; }
+
+bool IsCuttlefishFoldable() {
+    return IsCuttlefish() && ::android::base::GetProperty("ro.product.name", "").find("foldable") !=
+                                 std::string::npos;
+}
+
+bool IsInNoOpCompositionMode() {
+    const std::string mode = ::android::base::GetProperty("ro.vendor.hwcomposer.mode", "");
+    DEBUG_LOG("%s: sysprop ro.vendor.hwcomposer.mode is %s", __FUNCTION__, mode.c_str());
+    return mode == "noop";
+}
+
+bool IsInClientCompositionMode() {
+    const std::string mode = ::android::base::GetProperty("ro.vendor.hwcomposer.mode", "");
+    DEBUG_LOG("%s: sysprop ro.vendor.hwcomposer.mode is %s", __FUNCTION__, mode.c_str());
+    return mode == "client";
+}
+
+bool IsInGem5DisplayFinderMode() {
+    const std::string mode =
+        ::android::base::GetProperty("ro.vendor.hwcomposer.display_finder_mode", "");
+    DEBUG_LOG("%s: sysprop ro.vendor.hwcomposer.display_finder_mode is %s", __FUNCTION__,
+              mode.c_str());
+    return mode == "gem5";
+}
+
+bool IsInNoOpDisplayFinderMode() {
+    const std::string mode =
+        ::android::base::GetProperty("ro.vendor.hwcomposer.display_finder_mode", "");
+    DEBUG_LOG("%s: sysprop ro.vendor.hwcomposer.display_finder_mode is %s", __FUNCTION__,
+              mode.c_str());
+    return mode == "noop";
+}
+
+bool IsInDrmDisplayFinderMode() {
+    const std::string mode =
+        ::android::base::GetProperty("ro.vendor.hwcomposer.display_finder_mode", "");
+    DEBUG_LOG("%s: sysprop ro.vendor.hwcomposer.display_finder_mode is %s", __FUNCTION__,
+              mode.c_str());
+    return mode == "drm";
+}
+
+std::string toString(HWC3::Error error) {
+    switch (error) {
+        case HWC3::Error::None:
+            return "None";
+        case HWC3::Error::BadConfig:
+            return "BadConfig";
+        case HWC3::Error::BadDisplay:
+            return "BadDisplay";
+        case HWC3::Error::BadLayer:
+            return "BadLayer";
+        case HWC3::Error::BadParameter:
+            return "BadParameter";
+        case HWC3::Error::NoResources:
+            return "NoResources";
+        case HWC3::Error::NotValidated:
+            return "NotValidated";
+        case HWC3::Error::Unsupported:
+            return "Unsupported";
+        case HWC3::Error::SeamlessNotAllowed:
+            return "SeamlessNotAllowed";
+    }
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/Common.h b/hals/hwc3/Common.h
new file mode 100644
index 00000000..b4109e6e
--- /dev/null
+++ b/hals/hwc3/Common.h
@@ -0,0 +1,82 @@
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
+#ifndef ANDROID_HWC_COMMON_H
+#define ANDROID_HWC_COMMON_H
+
+#include <inttypes.h>
+
+#include <string>
+
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
+#undef LOG_TAG
+#define LOG_TAG "RanchuHwc"
+
+#include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
+#include <android-base/logging.h>
+#include <log/log.h>
+#include <utils/Trace.h>
+
+// Uncomment to enable additional debug logging.
+// #define DEBUG_RANCHU_HWC
+
+#if defined(DEBUG_RANCHU_HWC)
+#define DEBUG_LOG ALOGE
+#else
+#define DEBUG_LOG(...) ((void)0)
+#endif
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+bool IsAutoDevice();
+bool IsCuttlefish();
+bool IsCuttlefishFoldable();
+
+bool IsInNoOpCompositionMode();
+bool IsInClientCompositionMode();
+
+bool IsInGem5DisplayFinderMode();
+bool IsInNoOpDisplayFinderMode();
+bool IsInDrmDisplayFinderMode();
+
+namespace HWC3 {
+enum class Error : int32_t {
+    None = 0,
+    BadConfig = aidl::android::hardware::graphics::composer3::IComposerClient::EX_BAD_CONFIG,
+    BadDisplay = aidl::android::hardware::graphics::composer3::IComposerClient::EX_BAD_DISPLAY,
+    BadLayer = aidl::android::hardware::graphics::composer3::IComposerClient::EX_BAD_LAYER,
+    BadParameter = aidl::android::hardware::graphics::composer3::IComposerClient::EX_BAD_PARAMETER,
+    NoResources = aidl::android::hardware::graphics::composer3::IComposerClient::EX_NO_RESOURCES,
+    NotValidated = aidl::android::hardware::graphics::composer3::IComposerClient::EX_NOT_VALIDATED,
+    Unsupported = aidl::android::hardware::graphics::composer3::IComposerClient::EX_UNSUPPORTED,
+    SeamlessNotAllowed =
+        aidl::android::hardware::graphics::composer3::IComposerClient::EX_SEAMLESS_NOT_ALLOWED,
+};
+}  // namespace HWC3
+
+std::string toString(HWC3::Error error);
+
+inline ndk::ScopedAStatus ToBinderStatus(HWC3::Error error) {
+    if (error != HWC3::Error::None) {
+        return ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(error));
+    }
+    return ndk::ScopedAStatus::ok();
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/Composer.cpp b/hals/hwc3/Composer.cpp
new file mode 100644
index 00000000..aa70b3b1
--- /dev/null
+++ b/hals/hwc3/Composer.cpp
@@ -0,0 +1,112 @@
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
+#include "Composer.h"
+
+#include <android-base/logging.h>
+#include <android/binder_ibinder_platform.h>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+ndk::ScopedAStatus Composer::createClient(std::shared_ptr<IComposerClient>* outClient) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::unique_lock<std::mutex> lock(mClientMutex);
+
+    const bool previousClientDestroyed = waitForClientDestroyedLocked(lock);
+    if (!previousClientDestroyed) {
+        ALOGE("%s: failed as composer client already exists", __FUNCTION__);
+        *outClient = nullptr;
+        return ToBinderStatus(HWC3::Error::NoResources);
+    }
+
+    auto client = ndk::SharedRefBase::make<ComposerClient>();
+    if (!client) {
+        ALOGE("%s: failed to init composer client", __FUNCTION__);
+        *outClient = nullptr;
+        return ToBinderStatus(HWC3::Error::NoResources);
+    }
+
+    auto error = client->init();
+    if (error != HWC3::Error::None) {
+        *outClient = nullptr;
+        return ToBinderStatus(error);
+    }
+
+    auto clientDestroyed = [this]() { onClientDestroyed(); };
+    client->setOnClientDestroyed(clientDestroyed);
+
+    mClient = client;
+    *outClient = client;
+
+    return ndk::ScopedAStatus::ok();
+}
+
+bool Composer::waitForClientDestroyedLocked(std::unique_lock<std::mutex>& lock) {
+    if (!mClient.expired()) {
+        // In surface flinger we delete a composer client on one thread and
+        // then create a new client on another thread. Although surface
+        // flinger ensures the calls are made in that sequence (destroy and
+        // then create), sometimes the calls land in the composer service
+        // inverted (create and then destroy). Wait for a brief period to
+        // see if the existing client is destroyed.
+        constexpr const auto kTimeout = std::chrono::seconds(5);
+        mClientDestroyedCondition.wait_for(lock, kTimeout,
+                                           [this]() -> bool { return mClient.expired(); });
+        if (!mClient.expired()) {
+            ALOGW("%s: previous client was not destroyed", __FUNCTION__);
+        }
+    }
+
+    return mClient.expired();
+}
+
+void Composer::onClientDestroyed() {
+    std::lock_guard<std::mutex> lock(mClientMutex);
+
+    mClientDestroyedCondition.notify_all();
+}
+
+binder_status_t Composer::dump(int fd, const char** /*args*/, uint32_t /*numArgs*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::string output("TODO");
+
+    write(fd, output.c_str(), output.size());
+    return STATUS_OK;
+}
+
+ndk::ScopedAStatus Composer::getCapabilities(std::vector<Capability>* caps) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    caps->clear();
+    caps->emplace_back(Capability::PRESENT_FENCE_IS_NOT_RELIABLE);
+    caps->emplace_back(Capability::BOOT_DISPLAY_CONFIG);
+
+    return ndk::ScopedAStatus::ok();
+}
+
+::ndk::SpAIBinder Composer::createBinder() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto binder = BnComposer::createBinder();
+    AIBinder_setInheritRt(binder.get(), true);
+    return binder;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hals/hwc3/Composer.h b/hals/hwc3/Composer.h
new file mode 100644
index 00000000..a6286438
--- /dev/null
+++ b/hals/hwc3/Composer.h
@@ -0,0 +1,54 @@
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
+#ifndef ANDROID_HWC_COMPOSER_H
+#define ANDROID_HWC_COMPOSER_H
+
+#include <aidl/android/hardware/graphics/composer3/BnComposer.h>
+#include <android-base/thread_annotations.h>
+
+#include <memory>
+
+#include "ComposerClient.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+// This class is basically just the interface to create a client.
+class Composer : public BnComposer {
+   public:
+    Composer() = default;
+
+    binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;
+
+    // compser3 api
+    ndk::ScopedAStatus createClient(std::shared_ptr<IComposerClient>* client) override;
+    ndk::ScopedAStatus getCapabilities(std::vector<Capability>* caps) override;
+
+   protected:
+    ndk::SpAIBinder createBinder() override;
+
+   private:
+    bool waitForClientDestroyedLocked(std::unique_lock<std::mutex>& lock);
+    void onClientDestroyed();
+
+    std::mutex mClientMutex;
+    std::weak_ptr<ComposerClient> mClient;
+    std::condition_variable mClientDestroyedCondition;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/ComposerClient.cpp b/hals/hwc3/ComposerClient.cpp
new file mode 100644
index 00000000..5dd0dddb
--- /dev/null
+++ b/hals/hwc3/ComposerClient.cpp
@@ -0,0 +1,1397 @@
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
+#include "ComposerClient.h"
+
+#include <aidlcommonsupport/NativeHandle.h>
+#include <android/binder_ibinder_platform.h>
+
+#include "Common.h"
+#include "Device.h"
+#include "GuestFrameComposer.h"
+#include "HostFrameComposer.h"
+#include "Time.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+#define GET_DISPLAY_OR_RETURN_ERROR()                                        \
+    std::shared_ptr<Display> display = getDisplay(displayId);                \
+    if (display == nullptr) {                                                \
+        ALOGE("%s failed to get display:%" PRIu64, __FUNCTION__, displayId); \
+        return ToBinderStatus(HWC3::Error::BadDisplay);                      \
+    }
+
+}  // namespace
+
+using ::aidl::android::hardware::graphics::common::PixelFormat;
+
+class ComposerClient::CommandResultWriter {
+   public:
+    CommandResultWriter(std::vector<CommandResultPayload>* results)
+        : mIndex(0), mResults(results) {}
+
+    void nextCommand() { ++mIndex; }
+
+    void addError(HWC3::Error error) {
+        CommandError commandErrorResult;
+        commandErrorResult.commandIndex = mIndex;
+        commandErrorResult.errorCode = static_cast<int32_t>(error);
+        mResults->emplace_back(std::move(commandErrorResult));
+    }
+
+    void addPresentFence(int64_t displayId, ::android::base::unique_fd fence) {
+        if (fence >= 0) {
+            PresentFence presentFenceResult;
+            presentFenceResult.display = displayId;
+            presentFenceResult.fence = ndk::ScopedFileDescriptor(fence.release());
+            mResults->emplace_back(std::move(presentFenceResult));
+        }
+    }
+
+    void addReleaseFences(int64_t displayId,
+                          std::unordered_map<int64_t, ::android::base::unique_fd> layerFences) {
+        ReleaseFences releaseFencesResult;
+        releaseFencesResult.display = displayId;
+        for (auto& [layer, layerFence] : layerFences) {
+            if (layerFence >= 0) {
+                ReleaseFences::Layer releaseFencesLayerResult;
+                releaseFencesLayerResult.layer = layer;
+                releaseFencesLayerResult.fence = ndk::ScopedFileDescriptor(layerFence.release());
+                releaseFencesResult.layers.emplace_back(std::move(releaseFencesLayerResult));
+            }
+        }
+        mResults->emplace_back(std::move(releaseFencesResult));
+    }
+
+    void addChanges(const DisplayChanges& changes) {
+        if (changes.compositionChanges) {
+            mResults->emplace_back(*changes.compositionChanges);
+        }
+        if (changes.displayRequestChanges) {
+            mResults->emplace_back(*changes.displayRequestChanges);
+        }
+    }
+
+    void addPresentOrValidateResult(int64_t displayId, PresentOrValidate::Result pov) {
+        PresentOrValidate result;
+        result.display = displayId;
+        result.result = pov;
+        mResults->emplace_back(std::move(result));
+    }
+
+   private:
+    int32_t mIndex = 0;
+    std::vector<CommandResultPayload>* mResults = nullptr;
+};
+
+ComposerClient::ComposerClient() { DEBUG_LOG("%s", __FUNCTION__); }
+
+ComposerClient::~ComposerClient() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::lock_guard<std::mutex> lock(mDisplaysMutex);
+
+    destroyDisplaysLocked();
+
+    if (mOnClientDestroyed) {
+        mOnClientDestroyed();
+    }
+}
+
+HWC3::Error ComposerClient::init() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    HWC3::Error error = HWC3::Error::None;
+
+    std::lock_guard<std::mutex> lock(mDisplaysMutex);
+
+    mResources = std::make_unique<ComposerResources>();
+    if (!mResources) {
+        ALOGE("%s failed to allocate ComposerResources", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    error = mResources->init();
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to initialize ComposerResources", __FUNCTION__);
+        return error;
+    }
+
+    error = Device::getInstance().getComposer(&mComposer);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to get FrameComposer", __FUNCTION__);
+        return error;
+    }
+
+    const auto HotplugCallback = [this](bool connected,   //
+                                        uint32_t id,      //
+                                        uint32_t width,   //
+                                        uint32_t height,  //
+                                        uint32_t dpiX,    //
+                                        uint32_t dpiY,    //
+                                        uint32_t refreshRate) {
+        handleHotplug(connected, id, width, height, dpiX, dpiY, refreshRate);
+    };
+    error = mComposer->registerOnHotplugCallback(HotplugCallback);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to register hotplug callback", __FUNCTION__);
+        return error;
+    }
+
+    error = createDisplaysLocked();
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to create displays.", __FUNCTION__);
+        return error;
+    }
+
+    DEBUG_LOG("%s initialized!", __FUNCTION__);
+    return HWC3::Error::None;
+}
+
+ndk::ScopedAStatus ComposerClient::createLayer(int64_t displayId, int32_t bufferSlotCount,
+                                               int64_t* layerId) {
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    HWC3::Error error = display->createLayer(layerId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " failed to create layer", __FUNCTION__, displayId);
+        return ToBinderStatus(error);
+    }
+
+    error = mResources->addLayer(displayId, *layerId, static_cast<uint32_t>(bufferSlotCount));
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " resources failed to create layer", __FUNCTION__, displayId);
+        return ToBinderStatus(error);
+    }
+
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::createVirtualDisplay(int32_t /*width*/, int32_t /*height*/,
+                                                        PixelFormat /*formatHint*/,
+                                                        int32_t /*outputBufferSlotCount*/,
+                                                        VirtualDisplay* /*display*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t displayId, int64_t layerId) {
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    HWC3::Error error = display->destroyLayer(layerId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " failed to destroy layer:%" PRIu64, __FUNCTION__, displayId,
+              layerId);
+        return ToBinderStatus(error);
+    }
+
+    error = mResources->removeLayer(displayId, layerId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " resources failed to destroy layer:%" PRIu64, __FUNCTION__,
+              displayId, layerId);
+        return ToBinderStatus(error);
+    }
+
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::destroyVirtualDisplay(int64_t /*displayId*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::executeCommands(
+    const std::vector<DisplayCommand>& commands,
+    std::vector<CommandResultPayload>* commandResultPayloads) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    CommandResultWriter commandResults(commandResultPayloads);
+    for (const DisplayCommand& command : commands) {
+        executeDisplayCommand(commandResults, command);
+        commandResults.nextCommand();
+    }
+
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t displayId, int32_t* config) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getActiveConfig(config));
+}
+
+ndk::ScopedAStatus ComposerClient::getColorModes(int64_t displayId,
+                                                 std::vector<ColorMode>* colorModes) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getColorModes(colorModes));
+}
+
+ndk::ScopedAStatus ComposerClient::getDataspaceSaturationMatrix(common::Dataspace dataspace,
+                                                                std::vector<float>* matrix) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    if (dataspace != common::Dataspace::SRGB_LINEAR) {
+        return ToBinderStatus(HWC3::Error::BadParameter);
+    }
+
+    // clang-format off
+  constexpr std::array<float, 16> kUnit {
+    1.0f, 0.0f, 0.0f, 0.0f,
+    0.0f, 1.0f, 0.0f, 0.0f,
+    0.0f, 0.0f, 1.0f, 0.0f,
+    0.0f, 0.0f, 0.0f, 1.0f,
+  };
+    // clang-format on
+    matrix->clear();
+    matrix->insert(matrix->begin(), kUnit.begin(), kUnit.end());
+
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayAttribute(int64_t displayId, int32_t config,
+                                                       DisplayAttribute attribute, int32_t* value) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayAttribute(config, attribute, value));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayCapabilities(int64_t displayId,
+                                                          std::vector<DisplayCapability>* outCaps) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayCapabilities(outCaps));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayConfigs(int64_t displayId,
+                                                     std::vector<int32_t>* outConfigs) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayConfigs(outConfigs));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayConnectionType(int64_t displayId,
+                                                            DisplayConnectionType* outType) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayConnectionType(outType));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayIdentificationData(
+    int64_t displayId, DisplayIdentification* outIdentification) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayIdentificationData(outIdentification));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayName(int64_t displayId, std::string* outName) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayName(outName));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayVsyncPeriod(int64_t displayId,
+                                                         int32_t* outVsyncPeriod) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayVsyncPeriod(outVsyncPeriod));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayedContentSample(int64_t displayId, int64_t maxFrames,
+                                                             int64_t timestamp,
+                                                             DisplayContentSample* outSamples) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayedContentSample(maxFrames, timestamp, outSamples));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayedContentSamplingAttributes(
+    int64_t displayId, DisplayContentSamplingAttributes* outAttributes) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayedContentSamplingAttributes(outAttributes));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayPhysicalOrientation(
+    int64_t displayId, common::Transform* outOrientation) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayPhysicalOrientation(outOrientation));
+}
+
+ndk::ScopedAStatus ComposerClient::getHdrCapabilities(int64_t displayId,
+                                                      HdrCapabilities* outCapabilities) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getHdrCapabilities(outCapabilities));
+}
+
+ndk::ScopedAStatus ComposerClient::getOverlaySupport(OverlayProperties* /*properties*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getMaxVirtualDisplayCount(int32_t* outCount) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    // Not supported.
+    *outCount = 0;
+
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::getPerFrameMetadataKeys(
+    int64_t displayId, std::vector<PerFrameMetadataKey>* outKeys) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getPerFrameMetadataKeys(outKeys));
+}
+
+ndk::ScopedAStatus ComposerClient::getReadbackBufferAttributes(
+    int64_t displayId, ReadbackBufferAttributes* outAttributes) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getReadbackBufferAttributes(outAttributes));
+}
+
+ndk::ScopedAStatus ComposerClient::getReadbackBufferFence(
+    int64_t displayId, ndk::ScopedFileDescriptor* outAcquireFence) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getReadbackBufferFence(outAcquireFence));
+}
+
+ndk::ScopedAStatus ComposerClient::getRenderIntents(int64_t displayId, ColorMode mode,
+                                                    std::vector<RenderIntent>* outIntents) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getRenderIntents(mode, outIntents));
+}
+
+ndk::ScopedAStatus ComposerClient::getSupportedContentTypes(int64_t displayId,
+                                                            std::vector<ContentType>* outTypes) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getSupportedContentTypes(outTypes));
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayDecorationSupport(
+    int64_t displayId, std::optional<common::DisplayDecorationSupport>* outSupport) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDecorationSupport(outSupport));
+}
+
+ndk::ScopedAStatus ComposerClient::registerCallback(
+    const std::shared_ptr<IComposerCallback>& callback) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    const bool isFirstRegisterCallback = mCallbacks == nullptr;
+
+    mCallbacks = callback;
+
+    {
+        std::lock_guard<std::mutex> lock(mDisplaysMutex);
+        for (auto& [_, display] : mDisplays) {
+            display->registerCallback(callback);
+        }
+    }
+
+    if (isFirstRegisterCallback) {
+        std::vector<int64_t> displayIds;
+        {
+            std::lock_guard<std::mutex> lock(mDisplaysMutex);
+            for (auto& [displayId, _] : mDisplays) {
+                displayIds.push_back(displayId);
+            }
+        }
+
+        for (auto displayId : displayIds) {
+            DEBUG_LOG("%s initial registration, hotplug connecting display:%" PRIu64, __FUNCTION__,
+                      displayId);
+            mCallbacks->onHotplug(displayId, /*connected=*/true);
+        }
+    }
+
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::setActiveConfig(int64_t displayId, int32_t configId) {
+    DEBUG_LOG("%s display:%" PRIu64 " config:%" PRIu32, __FUNCTION__, displayId, configId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setActiveConfig(configId));
+}
+
+ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
+    int64_t displayId, int32_t configId, const VsyncPeriodChangeConstraints& constraints,
+    VsyncPeriodChangeTimeline* outTimeline) {
+    DEBUG_LOG("%s display:%" PRIu64 " config:%" PRIu32, __FUNCTION__, displayId, configId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(
+        display->setActiveConfigWithConstraints(configId, constraints, outTimeline));
+}
+
+ndk::ScopedAStatus ComposerClient::setBootDisplayConfig(int64_t displayId, int32_t configId) {
+    DEBUG_LOG("%s display:%" PRIu64 " config:%" PRIu32, __FUNCTION__, displayId, configId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setBootConfig(configId));
+}
+
+ndk::ScopedAStatus ComposerClient::clearBootDisplayConfig(int64_t displayId) {
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->clearBootConfig());
+}
+
+ndk::ScopedAStatus ComposerClient::getPreferredBootDisplayConfig(int64_t displayId,
+                                                                 int32_t* outConfigId) {
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getPreferredBootConfig(outConfigId));
+}
+
+ndk::ScopedAStatus ComposerClient::getHdrConversionCapabilities(
+    std::vector<aidl::android::hardware::graphics::common::HdrConversionCapability>* capabilities) {
+    DEBUG_LOG("%s", __FUNCTION__);
+    capabilities->clear();
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::setHdrConversionStrategy(
+    const aidl::android::hardware::graphics::common::HdrConversionStrategy& conversionStrategy,
+    aidl::android::hardware::graphics::common::Hdr* preferredHdrOutputType) {
+    DEBUG_LOG("%s", __FUNCTION__);
+    using HdrConversionStrategyTag =
+        aidl::android::hardware::graphics::common::HdrConversionStrategy::Tag;
+    switch (conversionStrategy.getTag()) {
+        case HdrConversionStrategyTag::autoAllowedHdrTypes: {
+            auto autoHdrTypes =
+                conversionStrategy.get<HdrConversionStrategyTag::autoAllowedHdrTypes>();
+            if (autoHdrTypes.size() != 0) {
+                return ToBinderStatus(HWC3::Error::Unsupported);
+            }
+            break;
+        }
+        case HdrConversionStrategyTag::passthrough:
+        case HdrConversionStrategyTag::forceHdrConversion: {
+            break;
+        }
+    }
+    *preferredHdrOutputType = aidl::android::hardware::graphics::common::Hdr::INVALID;
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t displayId, bool on) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setAutoLowLatencyMode(on));
+}
+
+ndk::ScopedAStatus ComposerClient::setClientTargetSlotCount(int64_t displayId, int32_t count) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(
+        mResources->setDisplayClientTargetCacheSize(displayId, static_cast<uint32_t>(count)));
+}
+
+ndk::ScopedAStatus ComposerClient::setColorMode(int64_t displayId, ColorMode mode,
+                                                RenderIntent intent) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setColorMode(mode, intent));
+}
+
+ndk::ScopedAStatus ComposerClient::setContentType(int64_t displayId, ContentType type) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setContentType(type));
+}
+
+ndk::ScopedAStatus ComposerClient::setDisplayedContentSamplingEnabled(
+    int64_t displayId, bool enable, FormatColorComponent componentMask, int64_t maxFrames) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(
+        display->setDisplayedContentSamplingEnabled(enable, componentMask, maxFrames));
+}
+
+ndk::ScopedAStatus ComposerClient::setPowerMode(int64_t displayId, PowerMode mode) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setPowerMode(mode));
+}
+
+ndk::ScopedAStatus ComposerClient::setReadbackBuffer(
+    int64_t displayId, const aidl::android::hardware::common::NativeHandle& buffer,
+    const ndk::ScopedFileDescriptor& releaseFence) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    // Owned by mResources.
+    buffer_handle_t importedBuffer = nullptr;
+
+    auto releaser = mResources->createReleaser(true /* isBuffer */);
+    auto error =
+        mResources->getDisplayReadbackBuffer(displayId, buffer, &importedBuffer, releaser.get());
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to get readback buffer from resources.", __FUNCTION__);
+        return ToBinderStatus(error);
+    }
+
+    error = display->setReadbackBuffer(importedBuffer, releaseFence);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to set readback buffer to display.", __FUNCTION__);
+        return ToBinderStatus(error);
+    }
+
+    return ToBinderStatus(HWC3::Error::None);
+}
+
+ndk::ScopedAStatus ComposerClient::setVsyncEnabled(int64_t displayId, bool enabled) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setVsyncEnabled(enabled));
+}
+
+ndk::ScopedAStatus ComposerClient::setIdleTimerEnabled(int64_t displayId, int32_t timeoutMs) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->setIdleTimerEnabled(timeoutMs));
+}
+
+ndk::ScopedAStatus ComposerClient::setRefreshRateChangedCallbackDebugEnabled(int64_t displayId,
+                                                                             bool) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayConfigurations(
+    int64_t displayId, int32_t /*maxFrameIntervalNs*/,
+    std::vector<DisplayConfiguration>* outDisplayConfig) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(display->getDisplayConfigurations(outDisplayConfig));
+}
+
+ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
+    int64_t displayId, const ClockMonotonicTimestamp& /*expectedPresentTime*/,
+    int32_t /*frameIntervalNs*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getMaxLayerPictureProfiles(int64_t displayId, int32_t*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::startHdcpNegotiation(int64_t displayId,
+    const aidl::android::hardware::drm::HdcpLevels& /*levels*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getLuts(int64_t displayId,
+        const std::vector<Buffer>&,
+        std::vector<Luts>*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    GET_DISPLAY_OR_RETURN_ERROR();
+
+    return ToBinderStatus(HWC3::Error::Unsupported);
+}
+
+ndk::SpAIBinder ComposerClient::createBinder() {
+    auto binder = BnComposerClient::createBinder();
+    AIBinder_setInheritRt(binder.get(), true);
+    return binder;
+}
+
+namespace {
+
+#define DISPATCH_LAYER_COMMAND(layerCmd, commandResults, display, layer, field, funcName)         \
+    do {                                                                                          \
+        if (layerCmd.field) {                                                                     \
+            ComposerClient::executeLayerCommandSetLayer##funcName(commandResults, display, layer, \
+                                                                  *layerCmd.field);               \
+        }                                                                                         \
+    } while (0)
+
+#define DISPATCH_DISPLAY_COMMAND(displayCmd, commandResults, display, field, funcName)   \
+    do {                                                                                 \
+        if (displayCmd.field) {                                                          \
+            executeDisplayCommand##funcName(commandResults, display, *displayCmd.field); \
+        }                                                                                \
+    } while (0)
+
+#define DISPATCH_DISPLAY_BOOL_COMMAND(displayCmd, commandResults, display, field, funcName) \
+    do {                                                                                    \
+        if (displayCmd.field) {                                                             \
+            executeDisplayCommand##funcName(commandResults, display);                       \
+        }                                                                                   \
+    } while (0)
+
+#define DISPATCH_DISPLAY_BOOL_COMMAND_AND_DATA(displayCmd, commandResults, display, field, data, \
+                                               funcName)                                         \
+    do {                                                                                         \
+        if (displayCmd.field) {                                                                  \
+            executeDisplayCommand##funcName(commandResults, display, displayCmd.data);           \
+        }                                                                                        \
+    } while (0)
+
+#define LOG_DISPLAY_COMMAND_ERROR(display, error)                                      \
+    do {                                                                               \
+        const std::string errorString = toString(error);                               \
+        ALOGE("%s: display:%" PRId64 " failed with:%s", __FUNCTION__, display.getId(), \
+              errorString.c_str());                                                    \
+    } while (0)
+
+#define LOG_LAYER_COMMAND_ERROR(display, layer, error)                                  \
+    do {                                                                                \
+        const std::string errorString = toString(error);                                \
+        ALOGE("%s: display:%" PRId64 " layer:%" PRId64 " failed with:%s", __FUNCTION__, \
+              display.getId(), layer->getId(), errorString.c_str());                    \
+    } while (0)
+
+}  // namespace
+
+void ComposerClient::executeDisplayCommand(CommandResultWriter& commandResults,
+                                           const DisplayCommand& displayCommand) {
+    std::shared_ptr<Display> display = getDisplay(displayCommand.display);
+    if (display == nullptr) {
+        commandResults.addError(HWC3::Error::BadDisplay);
+        return;
+    }
+
+    for (const LayerCommand& layerCmd : displayCommand.layers) {
+        executeLayerCommand(commandResults, *display, layerCmd);
+    }
+
+    DISPATCH_DISPLAY_COMMAND(displayCommand, commandResults, *display, colorTransformMatrix,
+                             SetColorTransform);
+    DISPATCH_DISPLAY_COMMAND(displayCommand, commandResults, *display, brightness, SetBrightness);
+    DISPATCH_DISPLAY_COMMAND(displayCommand, commandResults, *display, clientTarget,
+                             SetClientTarget);
+    DISPATCH_DISPLAY_COMMAND(displayCommand, commandResults, *display, virtualDisplayOutputBuffer,
+                             SetOutputBuffer);
+    DISPATCH_DISPLAY_BOOL_COMMAND_AND_DATA(displayCommand, commandResults, *display,
+                                           validateDisplay, expectedPresentTime, ValidateDisplay);
+    DISPATCH_DISPLAY_BOOL_COMMAND(displayCommand, commandResults, *display, acceptDisplayChanges,
+                                  AcceptDisplayChanges);
+    DISPATCH_DISPLAY_BOOL_COMMAND(displayCommand, commandResults, *display, presentDisplay,
+                                  PresentDisplay);
+    DISPATCH_DISPLAY_BOOL_COMMAND_AND_DATA(displayCommand, commandResults, *display,
+                                           presentOrValidateDisplay, expectedPresentTime,
+                                           PresentOrValidateDisplay);
+}
+
+void ComposerClient::executeLayerCommand(CommandResultWriter& commandResults, Display& display,
+                                         const LayerCommand& layerCommand) {
+    Layer* layer = display.getLayer(layerCommand.layer);
+    if (layer == nullptr) {
+        commandResults.addError(HWC3::Error::BadLayer);
+        return;
+    }
+
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, cursorPosition,
+                           CursorPosition);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, buffer, Buffer);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, damage, SurfaceDamage);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, blendMode, BlendMode);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, color, Color);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, composition, Composition);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, dataspace, Dataspace);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, displayFrame,
+                           DisplayFrame);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, planeAlpha, PlaneAlpha);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, sidebandStream,
+                           SidebandStream);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, sourceCrop, SourceCrop);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, transform, Transform);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, visibleRegion,
+                           VisibleRegion);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, z, ZOrder);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, colorTransform,
+                           ColorTransform);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, brightness, Brightness);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, perFrameMetadata,
+                           PerFrameMetadata);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, perFrameMetadataBlob,
+                           PerFrameMetadataBlobs);
+    DISPATCH_LAYER_COMMAND(layerCommand, commandResults, display, layer, luts,
+                           Luts);
+}
+
+void ComposerClient::executeDisplayCommandSetColorTransform(CommandResultWriter& commandResults,
+                                                            Display& display,
+                                                            const std::vector<float>& matrix) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = display.setColorTransform(matrix);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeDisplayCommandSetBrightness(CommandResultWriter& commandResults,
+                                                        Display& display,
+                                                        const DisplayBrightness& brightness) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = display.setBrightness(brightness.brightness);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeDisplayCommandSetClientTarget(CommandResultWriter& commandResults,
+                                                          Display& display,
+                                                          const ClientTarget& clientTarget) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    // Owned by mResources.
+    buffer_handle_t importedBuffer = nullptr;
+
+    auto releaser = mResources->createReleaser(/*isBuffer=*/true);
+    auto error = mResources->getDisplayClientTarget(display.getId(), clientTarget.buffer,
+                                                    &importedBuffer, releaser.get());
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+        return;
+    }
+
+    error = display.setClientTarget(importedBuffer, clientTarget.buffer.fence,
+                                    clientTarget.dataspace, clientTarget.damage);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+        return;
+    }
+}
+
+void ComposerClient::executeDisplayCommandSetOutputBuffer(CommandResultWriter& commandResults,
+                                                          Display& display, const Buffer& buffer) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    // Owned by mResources.
+    buffer_handle_t importedBuffer = nullptr;
+
+    auto releaser = mResources->createReleaser(/*isBuffer=*/true);
+    auto error = mResources->getDisplayOutputBuffer(display.getId(), buffer, &importedBuffer,
+                                                    releaser.get());
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+        return;
+    }
+
+    error = display.setOutputBuffer(importedBuffer, buffer.fence);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+        return;
+    }
+}
+
+void ComposerClient::executeDisplayCommandValidateDisplay(
+    CommandResultWriter& commandResults, Display& display,
+    const std::optional<ClockMonotonicTimestamp> expectedPresentTime) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = display.setExpectedPresentTime(expectedPresentTime);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    }
+
+    DisplayChanges changes;
+
+    error = display.validate(&changes);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    } else {
+        commandResults.addChanges(changes);
+    }
+
+    mResources->setDisplayMustValidateState(display.getId(), false);
+}
+
+void ComposerClient::executeDisplayCommandAcceptDisplayChanges(CommandResultWriter& commandResults,
+                                                               Display& display) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = display.acceptChanges();
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeDisplayCommandPresentOrValidateDisplay(
+    CommandResultWriter& commandResults, Display& display,
+    const std::optional<ClockMonotonicTimestamp> expectedPresentTime) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    // TODO: Support SKIP_VALIDATE.
+
+    auto error = display.setExpectedPresentTime(expectedPresentTime);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    }
+
+    DisplayChanges changes;
+
+    error = display.validate(&changes);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    } else {
+        const int64_t displayId = display.getId();
+        commandResults.addChanges(changes);
+        commandResults.addPresentOrValidateResult(displayId, PresentOrValidate::Result::Validated);
+    }
+
+    mResources->setDisplayMustValidateState(display.getId(), false);
+}
+
+void ComposerClient::executeDisplayCommandPresentDisplay(CommandResultWriter& commandResults,
+                                                         Display& display) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    if (mResources->mustValidateDisplay(display.getId())) {
+        ALOGE("%s: display:%" PRIu64 " not validated", __FUNCTION__, display.getId());
+        commandResults.addError(HWC3::Error::NotValidated);
+        return;
+    }
+
+    ::android::base::unique_fd displayFence;
+    std::unordered_map<int64_t, ::android::base::unique_fd> layerFences;
+
+    auto error = display.present(&displayFence, &layerFences);
+    if (error != HWC3::Error::None) {
+        LOG_DISPLAY_COMMAND_ERROR(display, error);
+        commandResults.addError(error);
+    } else {
+        const int64_t displayId = display.getId();
+        commandResults.addPresentFence(displayId, std::move(displayFence));
+        commandResults.addReleaseFences(displayId, std::move(layerFences));
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerCursorPosition(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const common::Point& cursorPosition) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setCursorPosition(cursorPosition);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerBuffer(CommandResultWriter& commandResults,
+                                                       Display& display, Layer* layer,
+                                                       const Buffer& buffer) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    // Owned by mResources.
+    buffer_handle_t importedBuffer = nullptr;
+
+    auto releaser = mResources->createReleaser(/*isBuffer=*/true);
+    auto error = mResources->getLayerBuffer(display.getId(), layer->getId(), buffer,
+                                            &importedBuffer, releaser.get());
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+        return;
+    }
+
+    error = layer->setBuffer(importedBuffer, buffer.fence);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerSurfaceDamage(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const std::vector<std::optional<common::Rect>>& damage) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setSurfaceDamage(damage);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerBlendMode(CommandResultWriter& commandResults,
+                                                          Display& display, Layer* layer,
+                                                          const ParcelableBlendMode& blendMode) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setBlendMode(blendMode.blendMode);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerColor(CommandResultWriter& commandResults,
+                                                      Display& display, Layer* layer,
+                                                      const Color& color) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setColor(color);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerComposition(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const ParcelableComposition& composition) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setCompositionType(composition.composition);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerDataspace(CommandResultWriter& commandResults,
+                                                          Display& display, Layer* layer,
+                                                          const ParcelableDataspace& dataspace) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setDataspace(dataspace.dataspace);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerDisplayFrame(CommandResultWriter& commandResults,
+                                                             Display& display, Layer* layer,
+                                                             const common::Rect& rect) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setDisplayFrame(rect);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerPlaneAlpha(CommandResultWriter& commandResults,
+                                                           Display& display, Layer* layer,
+                                                           const PlaneAlpha& planeAlpha) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setPlaneAlpha(planeAlpha.alpha);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerSidebandStream(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const aidl::android::hardware::common::NativeHandle& handle) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    // Owned by mResources.
+    buffer_handle_t importedStream = nullptr;
+
+    auto releaser = mResources->createReleaser(/*isBuffer=*/false);
+    auto error = mResources->getLayerSidebandStream(display.getId(), layer->getId(), handle,
+                                                    &importedStream, releaser.get());
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+        return;
+    }
+
+    error = layer->setSidebandStream(importedStream);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerSourceCrop(CommandResultWriter& commandResults,
+                                                           Display& display, Layer* layer,
+                                                           const common::FRect& sourceCrop) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setSourceCrop(sourceCrop);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerTransform(CommandResultWriter& commandResults,
+                                                          Display& display, Layer* layer,
+                                                          const ParcelableTransform& transform) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setTransform(transform.transform);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerVisibleRegion(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const std::vector<std::optional<common::Rect>>& visibleRegion) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setVisibleRegion(visibleRegion);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerZOrder(CommandResultWriter& commandResults,
+                                                       Display& display, Layer* layer,
+                                                       const ZOrder& zOrder) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setZOrder(zOrder.z);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerPerFrameMetadata(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const std::vector<std::optional<PerFrameMetadata>>& perFrameMetadata) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setPerFrameMetadata(perFrameMetadata);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerColorTransform(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const std::vector<float>& colorTransform) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setColorTransform(colorTransform);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerBrightness(CommandResultWriter& commandResults,
+                                                           Display& display, Layer* layer,
+                                                           const LayerBrightness& brightness) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setBrightness(brightness.brightness);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerPerFrameMetadataBlobs(
+    CommandResultWriter& commandResults, Display& display, Layer* layer,
+    const std::vector<std::optional<PerFrameMetadataBlob>>& perFrameMetadataBlob) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setPerFrameMetadataBlobs(perFrameMetadataBlob);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+void ComposerClient::executeLayerCommandSetLayerLuts(CommandResultWriter& commandResults,
+                                                     Display& display, Layer* layer,
+                                                     const Luts& luts) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    auto error = layer->setLuts(luts);
+    if (error != HWC3::Error::None) {
+        LOG_LAYER_COMMAND_ERROR(display, layer, error);
+        commandResults.addError(error);
+    }
+}
+
+std::shared_ptr<Display> ComposerClient::getDisplay(int64_t displayId) {
+    std::lock_guard<std::mutex> lock(mDisplaysMutex);
+
+    auto it = mDisplays.find(displayId);
+    if (it == mDisplays.end()) {
+        ALOGE("%s: no display:%" PRIu64, __FUNCTION__, displayId);
+        return nullptr;
+    }
+    return it->second;
+}
+
+HWC3::Error ComposerClient::createDisplaysLocked() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    if (!mComposer) {
+        ALOGE("%s composer not initialized!", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    std::vector<DisplayMultiConfigs> displays;
+
+    HWC3::Error error = findDisplays(mComposer->getDrmPresenter(), &displays);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to find display configs", __FUNCTION__);
+        return error;
+    }
+
+    for (const auto& iter : displays) {
+        error = createDisplayLocked(iter.displayId, iter.activeConfigId, iter.configs);
+        if (error != HWC3::Error::None) {
+            ALOGE("%s failed to create display from config", __FUNCTION__);
+            return error;
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ComposerClient::createDisplayLocked(int64_t displayId, int32_t activeConfigId,
+                                                const std::vector<DisplayConfig>& configs) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    if (!mComposer) {
+        ALOGE("%s composer not initialized!", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    auto display = std::make_shared<Display>(mComposer, displayId);
+    if (display == nullptr) {
+        ALOGE("%s failed to allocate display", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    HWC3::Error error = display->init(configs, activeConfigId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to initialize display:%" PRIu64, __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = mComposer->onDisplayCreate(display.get());
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to register display:%" PRIu64 " with composer", __FUNCTION__, displayId);
+        return error;
+    }
+
+    display->setPowerMode(PowerMode::ON);
+
+    DEBUG_LOG("%s: adding display:%" PRIu64, __FUNCTION__, displayId);
+    mDisplays.emplace(displayId, std::move(display));
+
+    error = mResources->addPhysicalDisplay(displayId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to initialize display:%" PRIu64 " resources", __FUNCTION__, displayId);
+        return error;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ComposerClient::destroyDisplaysLocked() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::vector<int64_t> displayIds;
+    for (const auto& [displayId, _] : mDisplays) {
+        displayIds.push_back(displayId);
+    }
+    for (const int64_t displayId : displayIds) {
+        destroyDisplayLocked(displayId);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ComposerClient::destroyDisplayLocked(int64_t displayId) {
+    DEBUG_LOG("%s display:%" PRId64, __FUNCTION__, displayId);
+
+    auto it = mDisplays.find(displayId);
+    if (it == mDisplays.end()) {
+        ALOGE("%s: display:%" PRId64 " no such display?", __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    Display* display = it->second.get();
+
+    display->setPowerMode(PowerMode::OFF);
+
+    HWC3::Error error = mComposer->onDisplayDestroy(it->second.get());
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " failed to destroy with frame composer", __FUNCTION__,
+              displayId);
+    }
+
+    error = mResources->removeDisplay(displayId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " failed to destroy with resources", __FUNCTION__, displayId);
+    }
+
+    mDisplays.erase(it);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error ComposerClient::handleHotplug(bool connected, uint32_t id, uint32_t width,
+                                          uint32_t height, uint32_t dpiX, uint32_t dpiY,
+                                          uint32_t refreshRateHz) {
+    if (!mCallbacks) {
+        return HWC3::Error::None;
+    }
+
+    const int64_t displayId = static_cast<int64_t>(id);
+
+    if (connected) {
+        const int32_t configId = static_cast<int32_t>(id);
+        int32_t vsyncPeriodNanos = HertzToPeriodNanos(refreshRateHz);
+        const std::vector<DisplayConfig> configs = {
+            DisplayConfig(configId, static_cast<int>(width), static_cast<int>(height),
+                          static_cast<int>(dpiX), static_cast<int>(dpiY), vsyncPeriodNanos)};
+        {
+            std::lock_guard<std::mutex> lock(mDisplaysMutex);
+            createDisplayLocked(displayId, configId, configs);
+        }
+
+        ALOGI("Hotplug connecting display:%" PRIu32 " w:%" PRIu32 " h:%" PRIu32 " dpiX:%" PRIu32
+              " dpiY %" PRIu32 "fps %" PRIu32,
+              id, width, height, dpiX, dpiY, refreshRateHz);
+        mCallbacks->onHotplug(displayId, /*connected=*/true);
+    } else {
+        ALOGI("Hotplug disconnecting display:%" PRIu64, displayId);
+        mCallbacks->onHotplug(displayId, /*connected=*/false);
+
+        {
+            std::lock_guard<std::mutex> lock(mDisplaysMutex);
+            destroyDisplayLocked(displayId);
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/ComposerClient.h b/hals/hwc3/ComposerClient.h
new file mode 100644
index 00000000..87a4eb01
--- /dev/null
+++ b/hals/hwc3/ComposerClient.h
@@ -0,0 +1,259 @@
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
+#ifndef ANDROID_HWC_COMPOSERCLIENT_H
+#define ANDROID_HWC_COMPOSERCLIENT_H
+
+#include <aidl/android/hardware/graphics/composer3/BnComposerClient.h>
+#include <aidl/android/hardware/graphics/composer3/Luts.h>
+#include <android-base/thread_annotations.h>
+
+#include <memory>
+
+#include "ComposerResources.h"
+#include "Display.h"
+#include "FrameComposer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class ComposerClient : public BnComposerClient {
+   public:
+    ComposerClient();
+    virtual ~ComposerClient();
+
+    HWC3::Error init();
+
+    void setOnClientDestroyed(std::function<void()> onClientDestroyed) {
+        mOnClientDestroyed = onClientDestroyed;
+    }
+
+    // HWC3 interface:
+    ndk::ScopedAStatus createLayer(int64_t displayId, int32_t bufferSlotCount,
+                                   int64_t* layer) override;
+    ndk::ScopedAStatus createVirtualDisplay(int32_t width, int32_t height,
+                                            common::PixelFormat formatHint,
+                                            int32_t outputBufferSlotCount,
+                                            VirtualDisplay* display) override;
+    ndk::ScopedAStatus destroyLayer(int64_t displayId, int64_t layer) override;
+    ndk::ScopedAStatus destroyVirtualDisplay(int64_t displayId) override;
+    ndk::ScopedAStatus executeCommands(const std::vector<DisplayCommand>& commands,
+                                       std::vector<CommandResultPayload>* results) override;
+    ndk::ScopedAStatus getActiveConfig(int64_t displayId, int32_t* config) override;
+    ndk::ScopedAStatus getColorModes(int64_t displayId,
+                                     std::vector<ColorMode>* colorModes) override;
+    ndk::ScopedAStatus getDataspaceSaturationMatrix(common::Dataspace dataspace,
+                                                    std::vector<float>* matrix) override;
+    ndk::ScopedAStatus getDisplayAttribute(int64_t displayId, int32_t config,
+                                           DisplayAttribute attribute, int32_t* value) override;
+    ndk::ScopedAStatus getDisplayCapabilities(int64_t displayId,
+                                              std::vector<DisplayCapability>* caps) override;
+    ndk::ScopedAStatus getDisplayConfigs(int64_t displayId, std::vector<int32_t>* configs) override;
+    ndk::ScopedAStatus getDisplayConnectionType(int64_t displayId,
+                                                DisplayConnectionType* type) override;
+    ndk::ScopedAStatus getDisplayIdentificationData(int64_t displayId,
+                                                    DisplayIdentification* id) override;
+    ndk::ScopedAStatus getDisplayName(int64_t displayId, std::string* name) override;
+    ndk::ScopedAStatus getDisplayVsyncPeriod(int64_t displayId, int32_t* vsyncPeriod) override;
+    ndk::ScopedAStatus getDisplayedContentSample(int64_t displayId, int64_t maxFrames,
+                                                 int64_t timestamp,
+                                                 DisplayContentSample* samples) override;
+    ndk::ScopedAStatus getDisplayedContentSamplingAttributes(
+        int64_t displayId, DisplayContentSamplingAttributes* attrs) override;
+    ndk::ScopedAStatus getDisplayPhysicalOrientation(int64_t displayId,
+                                                     common::Transform* orientation) override;
+    ndk::ScopedAStatus getHdrCapabilities(int64_t displayId, HdrCapabilities* caps) override;
+    ndk::ScopedAStatus getOverlaySupport(OverlayProperties* properties) override;
+    ndk::ScopedAStatus getMaxVirtualDisplayCount(int32_t* count) override;
+    ndk::ScopedAStatus getPerFrameMetadataKeys(int64_t displayId,
+                                               std::vector<PerFrameMetadataKey>* keys) override;
+    ndk::ScopedAStatus getReadbackBufferAttributes(int64_t displayId,
+                                                   ReadbackBufferAttributes* attrs) override;
+    ndk::ScopedAStatus getReadbackBufferFence(int64_t displayId,
+                                              ndk::ScopedFileDescriptor* acquireFence) override;
+    ndk::ScopedAStatus getRenderIntents(int64_t displayId, ColorMode mode,
+                                        std::vector<RenderIntent>* intents) override;
+    ndk::ScopedAStatus getSupportedContentTypes(int64_t displayId,
+                                                std::vector<ContentType>* types) override;
+    ndk::ScopedAStatus getDisplayDecorationSupport(
+        int64_t displayId, std::optional<common::DisplayDecorationSupport>* support) override;
+    ndk::ScopedAStatus registerCallback(
+        const std::shared_ptr<IComposerCallback>& callback) override;
+    ndk::ScopedAStatus setActiveConfig(int64_t displayId, int32_t config) override;
+    ndk::ScopedAStatus setActiveConfigWithConstraints(
+        int64_t displayId, int32_t config, const VsyncPeriodChangeConstraints& constraints,
+        VsyncPeriodChangeTimeline* timeline) override;
+    ndk::ScopedAStatus setBootDisplayConfig(int64_t displayId, int32_t config) override;
+    ndk::ScopedAStatus clearBootDisplayConfig(int64_t displayId) override;
+    ndk::ScopedAStatus getPreferredBootDisplayConfig(int64_t displayId, int32_t* config) override;
+    ndk::ScopedAStatus getHdrConversionCapabilities(
+        std::vector<aidl::android::hardware::graphics::common::HdrConversionCapability>*) override;
+    ndk::ScopedAStatus setHdrConversionStrategy(
+        const aidl::android::hardware::graphics::common::HdrConversionStrategy& conversionStrategy,
+        aidl::android::hardware::graphics::common::Hdr* preferredHdrOutputType) override;
+    ndk::ScopedAStatus setAutoLowLatencyMode(int64_t displayId, bool on) override;
+    ndk::ScopedAStatus setClientTargetSlotCount(int64_t displayId, int32_t count) override;
+    ndk::ScopedAStatus setColorMode(int64_t displayId, ColorMode mode,
+                                    RenderIntent intent) override;
+    ndk::ScopedAStatus setContentType(int64_t displayId, ContentType type) override;
+    ndk::ScopedAStatus setDisplayedContentSamplingEnabled(int64_t displayId, bool enable,
+                                                          FormatColorComponent componentMask,
+                                                          int64_t maxFrames) override;
+    ndk::ScopedAStatus setPowerMode(int64_t displayId, PowerMode mode) override;
+    ndk::ScopedAStatus setReadbackBuffer(
+        int64_t displayId, const aidl::android::hardware::common::NativeHandle& buffer,
+        const ndk::ScopedFileDescriptor& releaseFence) override;
+    ndk::ScopedAStatus setVsyncEnabled(int64_t displayId, bool enabled) override;
+    ndk::ScopedAStatus setIdleTimerEnabled(int64_t displayId, int32_t timeoutMs) override;
+    ndk::ScopedAStatus setRefreshRateChangedCallbackDebugEnabled(int64_t displayId,
+                                                                 bool enabled) override;
+    ndk::ScopedAStatus getDisplayConfigurations(int64_t displayId, int32_t maxFrameIntervalNs,
+                                                std::vector<DisplayConfiguration>*) override;
+    ndk::ScopedAStatus notifyExpectedPresent(int64_t displayId,
+                                             const ClockMonotonicTimestamp& expectedPresentTime,
+                                             int32_t maxFrameIntervalNs) override;
+    ndk::ScopedAStatus getMaxLayerPictureProfiles(int64_t displayId, int32_t* outMaxProfiles)
+                                                  override;
+    ndk::ScopedAStatus startHdcpNegotiation(
+        int64_t displayId, const aidl::android::hardware::drm::HdcpLevels& levels) override;
+    ndk::ScopedAStatus getLuts(int64_t displayId,
+            const std::vector<Buffer>&,
+            std::vector<Luts>*) override;
+
+   protected:
+    ndk::SpAIBinder createBinder() override;
+
+   private:
+    class CommandResultWriter;
+
+    void executeDisplayCommand(CommandResultWriter& commandResults,
+                               const DisplayCommand& displayCommand);
+
+    void executeLayerCommand(CommandResultWriter& commandResults, Display& display,
+                             const LayerCommand& layerCommand);
+
+    void executeDisplayCommandSetColorTransform(CommandResultWriter& commandResults,
+                                                Display& display, const std::vector<float>& matrix);
+    void executeDisplayCommandSetBrightness(CommandResultWriter& commandResults, Display& display,
+                                            const DisplayBrightness& brightness);
+    void executeDisplayCommandSetClientTarget(CommandResultWriter& commandResults, Display& display,
+                                              const ClientTarget& command);
+    void executeDisplayCommandSetOutputBuffer(CommandResultWriter& commandResults, Display& display,
+                                              const Buffer& buffer);
+    void executeDisplayCommandValidateDisplay(
+        CommandResultWriter& commandResults, Display& display,
+        const std::optional<ClockMonotonicTimestamp> expectedPresentTime);
+    void executeDisplayCommandAcceptDisplayChanges(CommandResultWriter& commandResults,
+                                                   Display& display);
+    void executeDisplayCommandPresentOrValidateDisplay(
+        CommandResultWriter& commandResults, Display& display,
+        const std::optional<ClockMonotonicTimestamp> expectedPresentTime);
+    void executeDisplayCommandPresentDisplay(CommandResultWriter& commandResults, Display& display);
+
+    void executeLayerCommandSetLayerCursorPosition(CommandResultWriter& commandResults,
+                                                   Display& display, Layer* layer,
+                                                   const common::Point& cursorPosition);
+    void executeLayerCommandSetLayerBuffer(CommandResultWriter& commandResults, Display& display,
+                                           Layer* layer, const Buffer& buffer);
+    void executeLayerCommandSetLayerSurfaceDamage(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const std::vector<std::optional<common::Rect>>& damage);
+    void executeLayerCommandSetLayerBlendMode(CommandResultWriter& commandResults, Display& display,
+                                              Layer* layer, const ParcelableBlendMode& blendMode);
+    void executeLayerCommandSetLayerColor(CommandResultWriter& commandResults, Display& display,
+                                          Layer* layer, const Color& color);
+    void executeLayerCommandSetLayerComposition(CommandResultWriter& commandResults,
+                                                Display& display, Layer* layer,
+                                                const ParcelableComposition& composition);
+    void executeLayerCommandSetLayerDataspace(CommandResultWriter& commandResults, Display& display,
+                                              Layer* layer, const ParcelableDataspace& dataspace);
+    void executeLayerCommandSetLayerDisplayFrame(CommandResultWriter& commandResults,
+                                                 Display& display, Layer* layer,
+                                                 const common::Rect& rect);
+    void executeLayerCommandSetLayerPlaneAlpha(CommandResultWriter& commandResults,
+                                               Display& display, Layer* layer,
+                                               const PlaneAlpha& planeAlpha);
+    void executeLayerCommandSetLayerSidebandStream(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const aidl::android::hardware::common::NativeHandle& sidebandStream);
+    void executeLayerCommandSetLayerSourceCrop(CommandResultWriter& commandResults,
+                                               Display& display, Layer* layer,
+                                               const common::FRect& sourceCrop);
+    void executeLayerCommandSetLayerTransform(CommandResultWriter& commandResults, Display& display,
+                                              Layer* layer, const ParcelableTransform& transform);
+    void executeLayerCommandSetLayerVisibleRegion(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const std::vector<std::optional<common::Rect>>& visibleRegion);
+    void executeLayerCommandSetLayerZOrder(CommandResultWriter& commandResults, Display& display,
+                                           Layer* layer, const ZOrder& zOrder);
+    void executeLayerCommandSetLayerPerFrameMetadata(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const std::vector<std::optional<PerFrameMetadata>>& perFrameMetadata);
+    void executeLayerCommandSetLayerColorTransform(CommandResultWriter& commandResults,
+                                                   Display& display, Layer* layer,
+                                                   const std::vector<float>& colorTransform);
+    void executeLayerCommandSetLayerBrightness(CommandResultWriter& commandResults,
+                                               Display& display, Layer* layer,
+                                               const LayerBrightness& brightness);
+    void executeLayerCommandSetLayerPerFrameMetadataBlobs(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const std::vector<std::optional<PerFrameMetadataBlob>>& perFrameMetadataBlob);
+    void executeLayerCommandSetLayerLuts(
+        CommandResultWriter& commandResults, Display& display, Layer* layer,
+        const Luts& luts);
+
+    // Returns the display with the given id or nullptr if not found.
+    std::shared_ptr<Display> getDisplay(int64_t displayId);
+
+    // Finds the Cuttlefish/Goldfish specific configuration and initializes the
+    // displays.
+    HWC3::Error createDisplaysLocked() EXCLUSIVE_LOCKS_REQUIRED(mDisplaysMutex);
+
+    // Creates a display with the given properties.
+    HWC3::Error createDisplayLocked(int64_t displayId, int32_t activeConfigId,
+                                    const std::vector<DisplayConfig>& configs)
+        EXCLUSIVE_LOCKS_REQUIRED(mDisplaysMutex);
+
+    HWC3::Error destroyDisplaysLocked() EXCLUSIVE_LOCKS_REQUIRED(mDisplaysMutex);
+
+    HWC3::Error destroyDisplayLocked(int64_t displayId) EXCLUSIVE_LOCKS_REQUIRED(mDisplaysMutex);
+
+    HWC3::Error handleHotplug(bool connected,   //
+                              uint32_t id,      //
+                              uint32_t width,   //
+                              uint32_t height,  //
+                              uint32_t dpiX,    //
+                              uint32_t dpiY,    //
+                              uint32_t refreshRate);
+
+    std::mutex mDisplaysMutex;
+    std::map<int64_t, std::shared_ptr<Display>> mDisplays GUARDED_BY(mDisplaysMutex);
+
+    // The onHotplug(), onVsync(), etc callbacks registered by SurfaceFlinger.
+    std::shared_ptr<IComposerCallback> mCallbacks;
+
+    std::function<void()> mOnClientDestroyed;
+
+    // Underlying interface for composing layers in the guest using libyuv or in
+    // the host using opengl. Owned by Device.
+    FrameComposer* mComposer = nullptr;
+
+    // Manages importing and caching gralloc buffers for displays and layers.
+    std::unique_ptr<ComposerResources> mResources;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/ComposerResources.cpp b/hals/hwc3/ComposerResources.cpp
new file mode 100644
index 00000000..8083b45d
--- /dev/null
+++ b/hals/hwc3/ComposerResources.cpp
@@ -0,0 +1,216 @@
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
+#include "ComposerResources.h"
+
+#include <aidlcommonsupport/NativeHandle.h>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+HWC3::Error toHwc3Error(::android::hardware::graphics::composer::V2_1::Error error) {
+    switch (error) {
+        case ::android::hardware::graphics::composer::V2_1::Error::NONE:
+            return HWC3::Error::None;
+        case ::android::hardware::graphics::composer::V2_1::Error::BAD_CONFIG:
+            return HWC3::Error::BadConfig;
+        case ::android::hardware::graphics::composer::V2_1::Error::BAD_DISPLAY:
+            return HWC3::Error::BadDisplay;
+        case ::android::hardware::graphics::composer::V2_1::Error::BAD_LAYER:
+            return HWC3::Error::BadLayer;
+        case ::android::hardware::graphics::composer::V2_1::Error::BAD_PARAMETER:
+            return HWC3::Error::BadParameter;
+        case ::android::hardware::graphics::composer::V2_1::Error::NO_RESOURCES:
+            return HWC3::Error::NoResources;
+        case ::android::hardware::graphics::composer::V2_1::Error::NOT_VALIDATED:
+            return HWC3::Error::NotValidated;
+        case ::android::hardware::graphics::composer::V2_1::Error::UNSUPPORTED:
+            return HWC3::Error::Unsupported;
+    }
+}
+
+::android::hardware::graphics::composer::V2_1::Display toHwc2Display(int64_t displayId) {
+    return static_cast<::android::hardware::graphics::composer::V2_1::Display>(displayId);
+}
+
+::android::hardware::graphics::composer::V2_1::Layer toHwc2Layer(int64_t layerId) {
+    return static_cast<::android::hardware::graphics::composer::V2_1::Layer>(layerId);
+}
+
+}  // namespace
+
+std::unique_ptr<ComposerResourceReleaser> ComposerResources::createReleaser(bool isBuffer) {
+    return std::make_unique<ComposerResourceReleaser>(isBuffer);
+}
+
+HWC3::Error ComposerResources::init() {
+    mImpl = ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::create();
+    if (!mImpl) {
+        ALOGE("%s: failed to create underlying ComposerResources.", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+    return HWC3::Error::None;
+}
+
+void ComposerResources::clear(
+    ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::RemoveDisplay
+        removeDisplay) {
+    mImpl->clear(removeDisplay);
+}
+
+bool ComposerResources::hasDisplay(int64_t displayId) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return mImpl->hasDisplay(display);
+}
+
+HWC3::Error ComposerResources::addPhysicalDisplay(int64_t displayId) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, displayId);
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->addPhysicalDisplay(display));
+}
+
+HWC3::Error ComposerResources::addVirtualDisplay(int64_t displayId,
+                                                 uint32_t outputBufferCacheSize) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->addVirtualDisplay(display, outputBufferCacheSize));
+}
+
+HWC3::Error ComposerResources::removeDisplay(int64_t displayId) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->removeDisplay(display));
+}
+
+HWC3::Error ComposerResources::setDisplayClientTargetCacheSize(int64_t displayId,
+                                                               uint32_t clientTargetCacheSize) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->setDisplayClientTargetCacheSize(display, clientTargetCacheSize));
+}
+
+HWC3::Error ComposerResources::getDisplayClientTargetCacheSize(int64_t displayId,
+                                                               size_t* outCacheSize) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->getDisplayClientTargetCacheSize(display, outCacheSize));
+}
+
+HWC3::Error ComposerResources::getDisplayOutputBufferCacheSize(int64_t displayId,
+                                                               size_t* outCacheSize) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->getDisplayOutputBufferCacheSize(display, outCacheSize));
+}
+
+HWC3::Error ComposerResources::addLayer(int64_t displayId, int64_t layerId,
+                                        uint32_t bufferCacheSize) {
+    DEBUG_LOG("%s: display:%" PRId64 " layer:%" PRId64, __FUNCTION__, displayId, layerId);
+
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    ::android::hardware::graphics::composer::V2_1::Layer layer = toHwc2Layer(layerId);
+    return toHwc3Error(mImpl->addLayer(display, layer, bufferCacheSize));
+}
+
+HWC3::Error ComposerResources::removeLayer(int64_t displayId, int64_t layerId) {
+    DEBUG_LOG("%s: display:%" PRId64 " layer:%" PRId64, __FUNCTION__, displayId, layerId);
+
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    ::android::hardware::graphics::composer::V2_1::Layer layer = toHwc2Layer(layerId);
+
+    return toHwc3Error(mImpl->removeLayer(display, layer));
+}
+
+void ComposerResources::setDisplayMustValidateState(int64_t displayId, bool mustValidate) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    mImpl->setDisplayMustValidateState(display, mustValidate);
+}
+
+bool ComposerResources::mustValidateDisplay(int64_t displayId) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return mImpl->mustValidateDisplay(display);
+}
+
+HWC3::Error ComposerResources::getDisplayReadbackBuffer(
+    int64_t displayId, const aidl::android::hardware::common::NativeHandle& handle,
+    buffer_handle_t* outHandle, ComposerResourceReleaser* releaser) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    return toHwc3Error(mImpl->getDisplayReadbackBuffer(display, ::android::makeFromAidl(handle),
+                                                       outHandle, releaser->getReplacedHandle()));
+}
+
+HWC3::Error ComposerResources::getDisplayClientTarget(int64_t displayId, const Buffer& buffer,
+                                                      buffer_handle_t* outHandle,
+                                                      ComposerResourceReleaser* releaser) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+
+    const bool useCache = !buffer.handle.has_value();
+
+    buffer_handle_t bufferHandle = nullptr;
+    if (buffer.handle.has_value()) {
+        bufferHandle = ::android::makeFromAidl(*buffer.handle);
+    }
+
+    return toHwc3Error(mImpl->getDisplayClientTarget(display, static_cast<uint32_t>(buffer.slot),
+                                                     useCache, bufferHandle, outHandle,
+                                                     releaser->getReplacedHandle()));
+}
+
+HWC3::Error ComposerResources::getDisplayOutputBuffer(int64_t displayId, const Buffer& buffer,
+                                                      buffer_handle_t* outHandle,
+                                                      ComposerResourceReleaser* releaser) {
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+
+    const bool useCache = !buffer.handle.has_value();
+
+    buffer_handle_t bufferHandle = nullptr;
+    if (buffer.handle.has_value()) {
+        bufferHandle = ::android::makeFromAidl(*buffer.handle);
+    }
+
+    return toHwc3Error(mImpl->getDisplayOutputBuffer(display, static_cast<uint32_t>(buffer.slot),
+                                                     useCache, bufferHandle, outHandle,
+                                                     releaser->getReplacedHandle()));
+}
+
+HWC3::Error ComposerResources::getLayerBuffer(int64_t displayId, int64_t layerId,
+                                              const Buffer& buffer, buffer_handle_t* outHandle,
+                                              ComposerResourceReleaser* releaser) {
+    DEBUG_LOG("%s: display:%" PRId64 " layer:%" PRId64, __FUNCTION__, displayId, layerId);
+
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    ::android::hardware::graphics::composer::V2_1::Layer layer = toHwc2Layer(layerId);
+
+    const bool useCache = !buffer.handle.has_value();
+
+    buffer_handle_t bufferHandle = nullptr;
+    if (buffer.handle.has_value()) {
+        bufferHandle = ::android::makeFromAidl(*buffer.handle);
+    }
+
+    DEBUG_LOG("%s fromCache:%s", __FUNCTION__, (useCache ? "yes" : "no"));
+    return toHwc3Error(mImpl->getLayerBuffer(display, layer, static_cast<uint32_t>(buffer.slot),
+                                             useCache, bufferHandle, outHandle,
+                                             releaser->getReplacedHandle()));
+}
+
+HWC3::Error ComposerResources::getLayerSidebandStream(
+    int64_t displayId, int64_t layerId, const aidl::android::hardware::common::NativeHandle& handle,
+    buffer_handle_t* outHandle, ComposerResourceReleaser* releaser) {
+    DEBUG_LOG("%s: display:%" PRId64 " layer:%" PRId64, __FUNCTION__, displayId, layerId);
+
+    ::android::hardware::graphics::composer::V2_1::Display display = toHwc2Display(displayId);
+    ::android::hardware::graphics::composer::V2_1::Layer layer = toHwc2Layer(layerId);
+    return toHwc3Error(mImpl->getLayerSidebandStream(
+        display, layer, ::android::makeFromAidl(handle), outHandle, releaser->getReplacedHandle()));
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hals/hwc3/ComposerResources.h b/hals/hwc3/ComposerResources.h
new file mode 100644
index 00000000..2f79dc88
--- /dev/null
+++ b/hals/hwc3/ComposerResources.h
@@ -0,0 +1,109 @@
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
+// Thin wrappers around V2_2::hal::ComposerResources related classes that
+// return HWC3 error codes and accept HWC3 argument types.
+
+#ifndef ANDROID_HWC_COMPOSERRESOURCES_H
+#define ANDROID_HWC_COMPOSERRESOURCES_H
+
+// Must include our LOG_TAG first:
+// clang-format off
+#include "Common.h"
+#include <composer-resources/2.2/ComposerResources.h>
+// clang-format on
+
+#include <memory>
+#include <optional>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class ComposerResourceReleaser {
+   public:
+    ComposerResourceReleaser(bool isBuffer) : mReplacedHandle(isBuffer) {}
+    virtual ~ComposerResourceReleaser() = default;
+
+    ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::ReplacedHandle*
+    getReplacedHandle() {
+        return &mReplacedHandle;
+    }
+
+   private:
+    ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::ReplacedHandle
+        mReplacedHandle;
+};
+
+class ComposerResources {
+   public:
+    ComposerResources() = default;
+
+    HWC3::Error init();
+
+    std::unique_ptr<ComposerResourceReleaser> createReleaser(bool isBuffer);
+
+    void clear(::android::hardware::graphics::composer::V2_2::hal::ComposerResources::RemoveDisplay
+                   removeDisplay);
+
+    bool hasDisplay(int64_t display);
+
+    HWC3::Error addPhysicalDisplay(int64_t display);
+
+    HWC3::Error addVirtualDisplay(int64_t displayId, uint32_t outputBufferCacheSize);
+
+    HWC3::Error removeDisplay(int64_t display);
+
+    HWC3::Error setDisplayClientTargetCacheSize(int64_t displayId, uint32_t clientTargetCacheSize);
+
+    HWC3::Error getDisplayClientTargetCacheSize(int64_t displayId, size_t* outCacheSize);
+
+    HWC3::Error getDisplayOutputBufferCacheSize(int64_t displayId, size_t* outCacheSize);
+
+    HWC3::Error addLayer(int64_t displayId, int64_t layerId, uint32_t bufferCacheSize);
+
+    HWC3::Error removeLayer(int64_t displayId, int64_t layer);
+
+    void setDisplayMustValidateState(int64_t displayId, bool mustValidate);
+
+    bool mustValidateDisplay(int64_t displayId);
+
+    HWC3::Error getDisplayReadbackBuffer(
+        int64_t displayId, const aidl::android::hardware::common::NativeHandle& handle,
+        buffer_handle_t* outHandle, ComposerResourceReleaser* bufReleaser);
+
+    HWC3::Error getDisplayClientTarget(int64_t displayId, const Buffer& buffer,
+                                       buffer_handle_t* outHandle,
+                                       ComposerResourceReleaser* bufReleaser);
+
+    HWC3::Error getDisplayOutputBuffer(int64_t displayId, const Buffer& buffer,
+                                       buffer_handle_t* outHandle,
+                                       ComposerResourceReleaser* bufReleaser);
+
+    HWC3::Error getLayerBuffer(int64_t displayId, int64_t layerId, const Buffer& buffer,
+                               buffer_handle_t* outBufferHandle,
+                               ComposerResourceReleaser* bufReleaser);
+
+    HWC3::Error getLayerSidebandStream(
+        int64_t displayId, int64_t layerId,
+        const aidl::android::hardware::common::NativeHandle& rawHandle,
+        buffer_handle_t* outStreamHandle, ComposerResourceReleaser* bufReleaser);
+
+   private:
+    std::unique_ptr< ::android::hardware::graphics::composer::V2_2::hal::ComposerResources> mImpl;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/Device.cpp b/hals/hwc3/Device.cpp
new file mode 100644
index 00000000..2f03f6ab
--- /dev/null
+++ b/hals/hwc3/Device.cpp
@@ -0,0 +1,166 @@
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
+#include "Device.h"
+
+#include <android-base/file.h>
+#include <android-base/properties.h>
+#include <json/json.h>
+
+#include "ClientFrameComposer.h"
+#include "FrameComposer.h"
+#include "GuestFrameComposer.h"
+#include "HostFrameComposer.h"
+#include "NoOpFrameComposer.h"
+
+ANDROID_SINGLETON_STATIC_INSTANCE(aidl::android::hardware::graphics::composer3::impl::Device);
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+bool shouldUseGuestComposer() {
+    return ::android::base::GetProperty("ro.hardware.vulkan", "") == "pastel";
+}
+
+std::string getPmemPath() { return ::android::base::GetProperty("ro.vendor.hwcomposer.pmem", ""); }
+
+HWC3::Error loadPersistentKeyValues(Json::Value* dictionary) {
+    *dictionary = Json::Value(Json::ValueType::objectValue);
+
+    const std::string path = getPmemPath();
+    if (path.empty()) {
+        ALOGE("%s: persistent key-value store path not available.", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    std::string content;
+    if (!::android::base::ReadFileToString(path, &content)) {
+        ALOGE("%s: failed to read key-value store from %s", __FUNCTION__, path.c_str());
+        return HWC3::Error::NoResources;
+    }
+
+    if (content.empty() || content[0] == '\0') {
+        return HWC3::Error::None;
+    }
+
+    Json::Reader reader;
+    if (!reader.parse(content, *dictionary)) {
+        const std::string error = reader.getFormattedErrorMessages();
+        ALOGE("%s: failed to parse key-value store from %s:%s", __FUNCTION__, path.c_str(),
+              error.c_str());
+        return HWC3::Error::NoResources;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error savePersistentKeyValues(const Json::Value& dictionary) {
+    const std::string path = getPmemPath();
+    if (path.empty()) {
+        ALOGE("%s: persistent key-value store path not available.", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    const std::string contents = dictionary.toStyledString();
+    if (!::android::base::WriteStringToFile(contents, path)) {
+        ALOGE("%s: failed to write key-value store to %s", __FUNCTION__, path.c_str());
+        return HWC3::Error::NoResources;
+    }
+
+    return HWC3::Error::None;
+}
+
+}  // namespace
+
+HWC3::Error Device::getComposer(FrameComposer** outComposer) {
+    std::unique_lock<std::mutex> lock(mMutex);
+
+    if (mComposer == nullptr) {
+        if (IsInNoOpCompositionMode()) {
+            DEBUG_LOG("%s: using NoOpFrameComposer", __FUNCTION__);
+            mComposer = std::make_unique<NoOpFrameComposer>();
+        } else if (IsInClientCompositionMode()) {
+            DEBUG_LOG("%s: using ClientFrameComposer", __FUNCTION__);
+            mComposer = std::make_unique<ClientFrameComposer>();
+        } else if (shouldUseGuestComposer()) {
+            DEBUG_LOG("%s: using GuestFrameComposer", __FUNCTION__);
+            mComposer = std::make_unique<GuestFrameComposer>();
+        } else {
+            DEBUG_LOG("%s: using HostFrameComposer", __FUNCTION__);
+            mComposer = std::make_unique<HostFrameComposer>();
+        }
+        if (!mComposer) {
+            ALOGE("%s failed to allocate FrameComposer", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+
+        HWC3::Error error = mComposer->init();
+        if (error != HWC3::Error::None) {
+            ALOGE("%s failed to init FrameComposer", __FUNCTION__);
+            return error;
+        }
+    }
+
+    *outComposer = mComposer.get();
+    return HWC3::Error::None;
+}
+
+HWC3::Error Device::getPersistentKeyValue(const std::string& key, const std::string& defaultValue,
+                                          std::string* outValue) {
+    std::unique_lock<std::mutex> lock(mMutex);
+
+    Json::Value dictionary;
+
+    HWC3::Error error = loadPersistentKeyValues(&dictionary);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to load pmem json", __FUNCTION__);
+        return error;
+    }
+
+    if (!dictionary.isMember(key)) {
+        *outValue = defaultValue;
+        return HWC3::Error::None;
+    }
+
+    *outValue = defaultValue;
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Device::setPersistentKeyValue(const std::string& key, const std::string& value) {
+    std::unique_lock<std::mutex> lock(mMutex);
+
+    Json::Value dictionary;
+
+    HWC3::Error error = loadPersistentKeyValues(&dictionary);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to load pmem json", __FUNCTION__);
+        return error;
+    }
+
+    dictionary[key] = value;
+
+    error = savePersistentKeyValues(dictionary);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to save pmem json", __FUNCTION__);
+        return error;
+    }
+
+    return HWC3::Error::None;
+}
+
+bool Device::persistentKeyValueEnabled() const { return !getPmemPath().empty(); }
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/Device.h b/hals/hwc3/Device.h
new file mode 100644
index 00000000..196f51b7
--- /dev/null
+++ b/hals/hwc3/Device.h
@@ -0,0 +1,56 @@
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
+#ifndef ANDROID_HWC_DEVICE_H
+#define ANDROID_HWC_DEVICE_H
+
+#include <utils/Singleton.h>
+
+#include <memory>
+#include <thread>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class FrameComposer;
+
+// Provides resources that are stable for the duration of the virtual
+// device.
+class Device : public ::android::Singleton<Device> {
+   public:
+    virtual ~Device() = default;
+
+    HWC3::Error getComposer(FrameComposer** outComposer);
+
+    bool persistentKeyValueEnabled() const;
+
+    HWC3::Error getPersistentKeyValue(const std::string& key, const std::string& defaultVal,
+                                      std::string* outValue);
+
+    HWC3::Error setPersistentKeyValue(const std::string& key, const std::string& outValue);
+
+   private:
+    friend class Singleton<Device>;
+    Device() = default;
+
+    std::mutex mMutex;
+    std::unique_ptr<FrameComposer> mComposer;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/Display.cpp b/hals/hwc3/Display.cpp
new file mode 100644
index 00000000..08b7a46a
--- /dev/null
+++ b/hals/hwc3/Display.cpp
@@ -0,0 +1,1035 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "Display.h"
+
+#include <android-base/parseint.h>
+#include <android-base/unique_fd.h>
+#include <pthread.h>
+#include <sched.h>
+#include <sync/sync.h>
+#include <sys/types.h>
+
+#include <algorithm>
+#include <atomic>
+#include <numeric>
+#include <sstream>
+#include <thread>
+
+#include "Common.h"
+#include "Device.h"
+#include "Time.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+bool isValidColorMode(ColorMode mode) {
+    switch (mode) {
+        case ColorMode::NATIVE:
+        case ColorMode::STANDARD_BT601_625:
+        case ColorMode::STANDARD_BT601_625_UNADJUSTED:
+        case ColorMode::STANDARD_BT601_525:
+        case ColorMode::STANDARD_BT601_525_UNADJUSTED:
+        case ColorMode::STANDARD_BT709:
+        case ColorMode::DCI_P3:
+        case ColorMode::SRGB:
+        case ColorMode::ADOBE_RGB:
+        case ColorMode::DISPLAY_P3:
+        case ColorMode::BT2020:
+        case ColorMode::BT2100_PQ:
+        case ColorMode::BT2100_HLG:
+        case ColorMode::DISPLAY_BT2020:
+            return true;
+        default:
+            return false;
+    }
+}
+
+bool isValidRenderIntent(RenderIntent intent) {
+    switch (intent) {
+        case RenderIntent::COLORIMETRIC:
+        case RenderIntent::ENHANCE:
+        case RenderIntent::TONE_MAP_COLORIMETRIC:
+        case RenderIntent::TONE_MAP_ENHANCE:
+            return true;
+        default:
+            return false;
+    }
+}
+
+bool isValidPowerMode(PowerMode mode) {
+    switch (mode) {
+        case PowerMode::OFF:
+        case PowerMode::DOZE:
+        case PowerMode::DOZE_SUSPEND:
+        case PowerMode::ON:
+        case PowerMode::ON_SUSPEND:
+            return true;
+        default:
+            return false;
+    }
+}
+
+}  // namespace
+
+Display::Display(FrameComposer* composer, int64_t id)
+    : mComposer(composer), mId(id), mVsyncThread(id) {
+    setLegacyEdid();
+}
+
+Display::~Display() {}
+
+HWC3::Error Display::init(const std::vector<DisplayConfig>& configs, int32_t activeConfigId,
+                          const std::optional<std::vector<uint8_t>>& edid) {
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    for (const DisplayConfig& config : configs) {
+        mConfigs.emplace(config.getId(), config);
+    }
+
+    mActiveConfigId = activeConfigId;
+
+    auto bootConfigIdOpt = getBootConfigId();
+    if (bootConfigIdOpt) {
+        mActiveConfigId = *bootConfigIdOpt;
+    }
+
+    if (edid.has_value()) {
+        mEdid = *edid;
+    }
+
+    auto it = mConfigs.find(activeConfigId);
+    if (it == mConfigs.end()) {
+        ALOGE("%s: display:%" PRId64 "missing config:%" PRId32, __FUNCTION__, mId, activeConfigId);
+        return HWC3::Error::NoResources;
+    }
+
+    const auto& activeConfig = it->second;
+    const auto activeConfigString = activeConfig.toString();
+    ALOGD("%s display:%" PRId64 " with config:%s", __FUNCTION__, mId, activeConfigString.c_str());
+
+    mVsyncThread.start(activeConfig.getVsyncPeriod());
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::updateParameters(uint32_t width, uint32_t height, uint32_t dpiX, uint32_t dpiY,
+                                      uint32_t refreshRateHz,
+                                      const std::optional<std::vector<uint8_t>>& edid) {
+    DEBUG_LOG("%s: updating display:%" PRId64
+              " width:%d height:%d dpiX:%d dpiY:%d refreshRateHz:%d",
+              __FUNCTION__, mId, width, height, dpiX, dpiY, refreshRateHz);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    auto it = mConfigs.find(*mActiveConfigId);
+    if (it == mConfigs.end()) {
+        ALOGE("%s: failed to find config %" PRId32, __func__, *mActiveConfigId);
+        return HWC3::Error::NoResources;
+    }
+    DisplayConfig& config = it->second;
+    int32_t oldVsyncPeriod = config.getAttribute(DisplayAttribute::VSYNC_PERIOD);
+    int32_t newVsyncPeriod = HertzToPeriodNanos(refreshRateHz);
+    if (oldVsyncPeriod != newVsyncPeriod) {
+        config.setAttribute(DisplayAttribute::VSYNC_PERIOD, newVsyncPeriod);
+
+        // Schedule a vsync update to propagate across system.
+        VsyncPeriodChangeConstraints constraints;
+        constraints.desiredTimeNanos = 0;
+
+        VsyncPeriodChangeTimeline timeline;
+
+        HWC3::Error error =
+            mVsyncThread.scheduleVsyncUpdate(newVsyncPeriod, constraints, &timeline);
+        if (error != HWC3::Error::None) {
+            ALOGE("%s: display:%" PRId64 " composer failed to schedule vsync update", __FUNCTION__,
+                  mId);
+            return error;
+        }
+    }
+    config.setAttribute(DisplayAttribute::WIDTH, static_cast<int32_t>(width));
+    config.setAttribute(DisplayAttribute::HEIGHT, static_cast<int32_t>(height));
+    config.setAttribute(DisplayAttribute::DPI_X, static_cast<int32_t>(dpiX));
+    config.setAttribute(DisplayAttribute::DPI_Y, static_cast<int32_t>(dpiY));
+
+    if (edid.has_value()) {
+        mEdid = *edid;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::createLayer(int64_t* outLayerId) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    auto layer = std::make_unique<Layer>();
+
+    const int64_t layerId = layer->getId();
+    DEBUG_LOG("%s: created layer:%" PRId64, __FUNCTION__, layerId);
+
+    mLayers.emplace(layerId, std::move(layer));
+
+    *outLayerId = layerId;
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::destroyLayer(int64_t layerId) {
+    DEBUG_LOG("%s: destroy layer:%" PRId64, __FUNCTION__, layerId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    auto it = mLayers.find(layerId);
+    if (it == mLayers.end()) {
+        ALOGE("%s display:%" PRId64 " has no such layer:%." PRId64, __FUNCTION__, mId, layerId);
+        return HWC3::Error::BadLayer;
+    }
+
+    mOrderedLayers.erase(
+        std::remove_if(mOrderedLayers.begin(),  //
+                       mOrderedLayers.end(),    //
+                       [layerId](Layer* layer) { return layer->getId() == layerId; }),
+        mOrderedLayers.end());
+
+    mLayers.erase(it);
+
+    DEBUG_LOG("%s: destroyed layer:%" PRId64, __FUNCTION__, layerId);
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getActiveConfig(int32_t* outConfig) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    if (!mActiveConfigId) {
+        ALOGW("%s: display:%" PRId64 " has no active config.", __FUNCTION__, mId);
+        return HWC3::Error::BadConfig;
+    }
+
+    *outConfig = *mActiveConfigId;
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayAttribute(int32_t configId, DisplayAttribute attribute,
+                                         int32_t* outValue) {
+    auto attributeString = toString(attribute);
+    DEBUG_LOG("%s: display:%" PRId64 " attribute:%s", __FUNCTION__, mId, attributeString.c_str());
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    auto it = mConfigs.find(configId);
+    if (it == mConfigs.end()) {
+        ALOGW("%s: display:%" PRId64 " bad config:%" PRId32, __FUNCTION__, mId, configId);
+        return HWC3::Error::BadConfig;
+    }
+
+    const DisplayConfig& config = it->second;
+    *outValue = config.getAttribute(attribute);
+    DEBUG_LOG("%s: display:%" PRId64 " attribute:%s value is %" PRIi32, __FUNCTION__, mId,
+              attributeString.c_str(), *outValue);
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getColorModes(std::vector<ColorMode>* outModes) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    outModes->clear();
+    outModes->insert(outModes->end(), mColorModes.begin(), mColorModes.end());
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayCapabilities(std::vector<DisplayCapability>* outCapabilities) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    outCapabilities->clear();
+    outCapabilities->push_back(DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM);
+    outCapabilities->push_back(DisplayCapability::MULTI_THREADED_PRESENT);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayConfigs(std::vector<int32_t>* outConfigIds) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    outConfigIds->clear();
+    outConfigIds->reserve(mConfigs.size());
+    for (const auto& [configId, _] : mConfigs) {
+        outConfigIds->push_back(configId);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayConfigurations(std::vector<DisplayConfiguration>* outConfigs) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    outConfigs->clear();
+    outConfigs->reserve(mConfigs.size());
+
+    for (const auto& [configId, displayConfig] : mConfigs) {
+        DisplayConfiguration displayConfiguration;
+        displayConfiguration.configId = configId;
+        displayConfiguration.width = displayConfig.getWidth();
+        displayConfiguration.height = displayConfig.getHeight();
+        displayConfiguration.dpi = {static_cast<float>(displayConfig.getDpiX()),
+                                    static_cast<float>(displayConfig.getDpiY())};
+        displayConfiguration.vsyncPeriod = displayConfig.getVsyncPeriod();
+        displayConfiguration.configGroup = displayConfig.getConfigGroup();
+        displayConfiguration.hdrOutputType = OutputType::SYSTEM;
+
+        outConfigs->emplace_back(displayConfiguration);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayConnectionType(DisplayConnectionType* outType) {
+    *outType = DisplayConnectionType::INTERNAL;
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayIdentificationData(DisplayIdentification* outIdentification) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    if (outIdentification == nullptr) {
+        return HWC3::Error::BadParameter;
+    }
+
+    outIdentification->port = static_cast<int8_t>(mId);
+    outIdentification->data = mEdid;
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayName(std::string* outName) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    *outName = mName;
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayVsyncPeriod(int32_t* outVsyncPeriod) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    if (!mActiveConfigId) {
+        ALOGE("%s : display:%" PRId64 " no active config", __FUNCTION__, mId);
+        return HWC3::Error::BadConfig;
+    }
+
+    const auto it = mConfigs.find(*mActiveConfigId);
+    if (it == mConfigs.end()) {
+        ALOGE("%s : display:%" PRId64 " failed to find active config:%" PRId32, __FUNCTION__, mId,
+              *mActiveConfigId);
+        return HWC3::Error::BadConfig;
+    }
+    const DisplayConfig& activeConfig = it->second;
+
+    *outVsyncPeriod = activeConfig.getAttribute(DisplayAttribute::VSYNC_PERIOD);
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDisplayedContentSample(int64_t /*maxFrames*/, int64_t /*timestamp*/,
+                                               DisplayContentSample* /*samples*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::getDisplayedContentSamplingAttributes(
+    DisplayContentSamplingAttributes* /*outAttributes*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::getDisplayPhysicalOrientation(common::Transform* outOrientation) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    *outOrientation = common::Transform::NONE;
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getHdrCapabilities(HdrCapabilities* outCapabilities) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    // No supported types.
+    outCapabilities->types.clear();
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getPerFrameMetadataKeys(std::vector<PerFrameMetadataKey>* outKeys) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    outKeys->clear();
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::getReadbackBufferAttributes(ReadbackBufferAttributes* outAttributes) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    outAttributes->format = common::PixelFormat::RGBA_8888;
+    outAttributes->dataspace = common::Dataspace::UNKNOWN;
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::getReadbackBufferFence(ndk::ScopedFileDescriptor* /*outAcquireFence*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::getRenderIntents(ColorMode mode, std::vector<RenderIntent>* outIntents) {
+    const auto modeString = toString(mode);
+    DEBUG_LOG("%s: display:%" PRId64 "for mode:%s", __FUNCTION__, mId, modeString.c_str());
+
+    outIntents->clear();
+
+    if (!isValidColorMode(mode)) {
+        DEBUG_LOG("%s: display:%" PRId64 "invalid mode:%s", __FUNCTION__, mId, modeString.c_str());
+        return HWC3::Error::BadParameter;
+    }
+
+    outIntents->push_back(RenderIntent::COLORIMETRIC);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getSupportedContentTypes(std::vector<ContentType>* outTypes) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    outTypes->clear();
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getDecorationSupport(
+    std::optional<common::DisplayDecorationSupport>* outSupport) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    outSupport->reset();
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::registerCallback(const std::shared_ptr<IComposerCallback>& callback) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    mVsyncThread.setCallbacks(callback);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::setActiveConfig(int32_t configId) {
+    DEBUG_LOG("%s: display:%" PRId64 " setting active config to %" PRId32, __FUNCTION__, mId,
+              configId);
+
+    VsyncPeriodChangeConstraints constraints;
+    constraints.desiredTimeNanos = 0;
+    constraints.seamlessRequired = false;
+
+    VsyncPeriodChangeTimeline timeline;
+
+    return setActiveConfigWithConstraints(configId, constraints, &timeline);
+}
+
+HWC3::Error Display::setActiveConfigWithConstraints(int32_t configId,
+                                                    const VsyncPeriodChangeConstraints& constraints,
+                                                    VsyncPeriodChangeTimeline* outTimeline) {
+    DEBUG_LOG("%s: display:%" PRId64 " config:%" PRId32, __FUNCTION__, mId, configId);
+
+    if (outTimeline == nullptr) {
+        return HWC3::Error::BadParameter;
+    }
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    if (mActiveConfigId == configId) {
+        return HWC3::Error::None;
+    }
+
+    DisplayConfig* newConfig = getConfig(configId);
+    if (newConfig == nullptr) {
+        ALOGE("%s: display:%" PRId64 " bad config:%" PRId32, __FUNCTION__, mId, configId);
+        return HWC3::Error::BadConfig;
+    }
+
+    if (constraints.seamlessRequired) {
+        if (mActiveConfigId) {
+            DisplayConfig* oldConfig = getConfig(*mActiveConfigId);
+            if (oldConfig == nullptr) {
+                ALOGE("%s: display:%" PRId64 " missing config:%" PRId32, __FUNCTION__, mId,
+                      *mActiveConfigId);
+                return HWC3::Error::NoResources;
+            }
+
+            const int32_t newConfigGroup = newConfig->getConfigGroup();
+            const int32_t oldConfigGroup = oldConfig->getConfigGroup();
+            if (newConfigGroup != oldConfigGroup) {
+                DEBUG_LOG("%s: display:%" PRId64 " config:%" PRId32
+                          " seamless not supported between different config groups "
+                          "old:%d vs new:%d",
+                          __FUNCTION__, mId, configId, oldConfigGroup, newConfigGroup);
+                return HWC3::Error::SeamlessNotAllowed;
+            }
+        }
+    }
+
+    mActiveConfigId = configId;
+
+    if (mComposer == nullptr) {
+        ALOGE("%s: display:%" PRId64 " missing composer", __FUNCTION__, mId);
+        return HWC3::Error::NoResources;
+    }
+
+    HWC3::Error error = mComposer->onActiveConfigChange(this);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " composer failed to handle config change", __FUNCTION__, mId);
+        return error;
+    }
+
+    int32_t vsyncPeriod;
+    error = getDisplayVsyncPeriod(&vsyncPeriod);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " composer failed to handle config change", __FUNCTION__, mId);
+        return error;
+    }
+
+    return mVsyncThread.scheduleVsyncUpdate(vsyncPeriod, constraints, outTimeline);
+}
+
+std::optional<int32_t> Display::getBootConfigId() {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    if (!Device::getInstance().persistentKeyValueEnabled()) {
+        ALOGD("%s: persistent boot config is not enabled.", __FUNCTION__);
+        return std::nullopt;
+    }
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    std::string val;
+    HWC3::Error error = Device::getInstance().getPersistentKeyValue(std::to_string(mId), "", &val);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " failed to get persistent boot config", __FUNCTION__, mId);
+        return std::nullopt;
+    }
+
+    if (val.empty()) {
+        return std::nullopt;
+    }
+
+    int32_t configId = 0;
+    if (!::android::base::ParseInt(val, &configId)) {
+        ALOGE("%s: display:%" PRId64 " failed to parse persistent boot config from: %s",
+              __FUNCTION__, mId, val.c_str());
+        return std::nullopt;
+    }
+
+    if (!hasConfig(configId)) {
+        ALOGE("%s: display:%" PRId64 " invalid persistent boot config:%" PRId32, __FUNCTION__, mId,
+              configId);
+        return std::nullopt;
+    }
+
+    return configId;
+}
+
+HWC3::Error Display::setBootConfig(int32_t configId) {
+    DEBUG_LOG("%s: display:%" PRId64 " config:%" PRId32, __FUNCTION__, mId, configId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    DisplayConfig* newConfig = getConfig(configId);
+    if (newConfig == nullptr) {
+        ALOGE("%s: display:%" PRId64 " bad config:%" PRId32, __FUNCTION__, mId, configId);
+        return HWC3::Error::BadConfig;
+    }
+
+    const std::string key = std::to_string(mId);
+    const std::string val = std::to_string(configId);
+    HWC3::Error error = Device::getInstance().setPersistentKeyValue(key, val);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " failed to save persistent boot config", __FUNCTION__, mId);
+        return error;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::clearBootConfig() {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    const std::string key = std::to_string(mId);
+    const std::string val = "";
+    HWC3::Error error = Device::getInstance().setPersistentKeyValue(key, val);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " failed to save persistent boot config", __FUNCTION__, mId);
+        return error;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::getPreferredBootConfig(int32_t* outConfigId) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    std::vector<int32_t> configIds;
+    for (const auto [configId, _] : mConfigs) {
+        configIds.push_back(configId);
+    }
+    *outConfigId = *std::min_element(configIds.begin(), configIds.end());
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setAutoLowLatencyMode(bool /*on*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::setColorMode(ColorMode mode, RenderIntent intent) {
+    const std::string modeString = toString(mode);
+    const std::string intentString = toString(intent);
+    DEBUG_LOG("%s: display:%" PRId64 " setting color mode:%s intent:%s", __FUNCTION__, mId,
+              modeString.c_str(), intentString.c_str());
+
+    if (!isValidColorMode(mode)) {
+        ALOGE("%s: display:%" PRId64 " invalid color mode:%s", __FUNCTION__, mId,
+              modeString.c_str());
+        return HWC3::Error::BadParameter;
+    }
+
+    if (!isValidRenderIntent(intent)) {
+        ALOGE("%s: display:%" PRId64 " invalid intent:%s", __FUNCTION__, mId, intentString.c_str());
+        return HWC3::Error::BadParameter;
+    }
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    if (mColorModes.count(mode) == 0) {
+        ALOGE("%s: display %" PRId64 " mode %s not supported", __FUNCTION__, mId,
+              modeString.c_str());
+        return HWC3::Error::Unsupported;
+    }
+
+    mActiveColorMode = mode;
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setContentType(ContentType contentType) {
+    auto contentTypeString = toString(contentType);
+    DEBUG_LOG("%s: display:%" PRId64 " content type:%s", __FUNCTION__, mId,
+              contentTypeString.c_str());
+
+    if (contentType != ContentType::NONE) {
+        return HWC3::Error::Unsupported;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setDisplayedContentSamplingEnabled(bool /*enable*/,
+                                                        FormatColorComponent /*componentMask*/,
+                                                        int64_t /*maxFrames*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::setPowerMode(PowerMode mode) {
+    auto modeString = toString(mode);
+    DEBUG_LOG("%s: display:%" PRId64 " to mode:%s", __FUNCTION__, mId, modeString.c_str());
+
+    if (!isValidPowerMode(mode)) {
+        ALOGE("%s: display:%" PRId64 " invalid mode:%s", __FUNCTION__, mId, modeString.c_str());
+        return HWC3::Error::BadParameter;
+    }
+
+    if (mode == PowerMode::DOZE || mode == PowerMode::DOZE_SUSPEND ||
+        mode == PowerMode::ON_SUSPEND) {
+        ALOGE("%s display %" PRId64 " mode:%s not supported", __FUNCTION__, mId,
+              modeString.c_str());
+        return HWC3::Error::Unsupported;
+    }
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    if (IsCuttlefish()) {
+        if (int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC); fd != -1) {
+            std::ostringstream stream;
+            stream << "VIRTUAL_DEVICE_DISPLAY_POWER_MODE_CHANGED display=" << mId
+                   << " mode=" << modeString << std::endl;
+            std::string message = stream.str();
+            write(fd, message.c_str(), message.length());
+            close(fd);
+        }
+    }
+
+    mPowerMode = mode;
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setReadbackBuffer(const buffer_handle_t buffer,
+                                       const ndk::ScopedFileDescriptor& fence) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    mReadbackBuffer.set(buffer, fence);
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::setVsyncEnabled(bool enabled) {
+    DEBUG_LOG("%s: display:%" PRId64 " setting vsync %s", __FUNCTION__, mId,
+              (enabled ? "on" : "off"));
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    return mVsyncThread.setVsyncEnabled(enabled);
+}
+
+HWC3::Error Display::setIdleTimerEnabled(int32_t timeoutMs) {
+    DEBUG_LOG("%s: display:%" PRId64 " timeout:%" PRId32, __FUNCTION__, mId, timeoutMs);
+
+    (void)timeoutMs;
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::setColorTransform(const std::vector<float>& transformMatrix) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    if (transformMatrix.size() < 16) {
+        ALOGE("%s: display:%" PRId64 " has non 4x4 matrix, size:%zu", __FUNCTION__, mId,
+              transformMatrix.size());
+        return HWC3::Error::BadParameter;
+    }
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    auto& colorTransform = mColorTransform.emplace();
+    std::copy_n(transformMatrix.data(), colorTransform.size(), colorTransform.begin());
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setBrightness(float brightness) {
+    DEBUG_LOG("%s: display:%" PRId64 " brightness:%f", __FUNCTION__, mId, brightness);
+
+    if (brightness < 0.0f) {
+        ALOGE("%s: display:%" PRId64 " invalid brightness:%f", __FUNCTION__, mId, brightness);
+        return HWC3::Error::BadParameter;
+    }
+
+    return HWC3::Error::Unsupported;
+}
+
+HWC3::Error Display::setClientTarget(buffer_handle_t buffer, const ndk::ScopedFileDescriptor& fence,
+                                     common::Dataspace /*dataspace*/,
+                                     const std::vector<common::Rect>& /*damage*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    mClientTarget.set(buffer, fence);
+
+    mComposer->onDisplayClientTargetSet(this);
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setOutputBuffer(buffer_handle_t /*buffer*/,
+                                     const ndk::ScopedFileDescriptor& /*fence*/) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    // TODO: for virtual display
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::setExpectedPresentTime(
+    const std::optional<ClockMonotonicTimestamp>& expectedPresentTime) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    if (!expectedPresentTime.has_value()) {
+        return HWC3::Error::None;
+    }
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    mExpectedPresentTime.emplace(asTimePoint(expectedPresentTime->timestampNanos));
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::validate(DisplayChanges* outChanges) {
+    ATRACE_CALL();
+
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    mPendingChanges.reset();
+
+    mOrderedLayers.clear();
+    mOrderedLayers.reserve(mLayers.size());
+    for (auto& [_, layerPtr] : mLayers) {
+        mOrderedLayers.push_back(layerPtr.get());
+    }
+    std::sort(mOrderedLayers.begin(), mOrderedLayers.end(),
+              [](const Layer* layerA, const Layer* layerB) {
+                  const auto zA = layerA->getZOrder();
+                  const auto zB = layerB->getZOrder();
+                  if (zA != zB) {
+                      return zA < zB;
+                  }
+                  return layerA->getId() < layerB->getId();
+              });
+
+    if (mComposer == nullptr) {
+        ALOGE("%s: display:%" PRId64 " missing composer", __FUNCTION__, mId);
+        return HWC3::Error::NoResources;
+    }
+
+    HWC3::Error error = mComposer->validateDisplay(this, &mPendingChanges);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRId64 " failed to validate", __FUNCTION__, mId);
+        return error;
+    }
+
+    if (mPendingChanges.hasAnyChanges()) {
+        mPresentFlowState = PresentFlowState::WAITING_FOR_ACCEPT;
+        DEBUG_LOG("%s: display:%" PRId64 " now WAITING_FOR_ACCEPT", __FUNCTION__, mId);
+    } else {
+        mPresentFlowState = PresentFlowState::WAITING_FOR_PRESENT;
+        DEBUG_LOG("%s: display:%" PRId64 " now WAITING_FOR_PRESENT", __FUNCTION__, mId);
+    }
+
+    *outChanges = mPendingChanges;
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::acceptChanges() {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    switch (mPresentFlowState) {
+        case PresentFlowState::WAITING_FOR_VALIDATE: {
+            ALOGE("%s: display %" PRId64 " failed, not validated", __FUNCTION__, mId);
+            return HWC3::Error::NotValidated;
+        }
+        case PresentFlowState::WAITING_FOR_ACCEPT:
+        case PresentFlowState::WAITING_FOR_PRESENT: {
+            break;
+        }
+    }
+
+    if (mPendingChanges.compositionChanges) {
+        const ChangedCompositionTypes& compositionChanges = *mPendingChanges.compositionChanges;
+        for (const ChangedCompositionLayer& compositionChange : compositionChanges.layers) {
+            const auto layerId = compositionChange.layer;
+            const auto layerComposition = compositionChange.composition;
+            auto* layer = getLayer(layerId);
+            if (layer == nullptr) {
+                ALOGE("%s: display:%" PRId64 " layer:%" PRId64 " dropped before acceptChanges()?",
+                      __FUNCTION__, mId, layerId);
+                continue;
+            }
+
+            layer->setCompositionType(layerComposition);
+        }
+    }
+    mPendingChanges.reset();
+
+    mPresentFlowState = PresentFlowState::WAITING_FOR_PRESENT;
+    DEBUG_LOG("%s: display:%" PRId64 " now WAITING_FOR_PRESENT", __FUNCTION__, mId);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Display::present(
+    ::android::base::unique_fd* outDisplayFence,
+    std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) {
+    ATRACE_CALL();
+
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    outDisplayFence->reset();
+    outLayerFences->clear();
+
+    std::unique_lock<std::recursive_mutex> lock(mStateMutex);
+
+    switch (mPresentFlowState) {
+        case PresentFlowState::WAITING_FOR_VALIDATE: {
+            ALOGE("%s: display %" PRId64 " failed, not validated", __FUNCTION__, mId);
+            return HWC3::Error::NotValidated;
+        }
+        case PresentFlowState::WAITING_FOR_ACCEPT: {
+            ALOGE("%s: display %" PRId64 " failed, changes not accepted", __FUNCTION__, mId);
+            return HWC3::Error::NotValidated;
+        }
+        case PresentFlowState::WAITING_FOR_PRESENT: {
+            break;
+        }
+    }
+    mPresentFlowState = PresentFlowState::WAITING_FOR_VALIDATE;
+    DEBUG_LOG("%s: display:%" PRId64 " now WAITING_FOR_VALIDATE", __FUNCTION__, mId);
+
+    if (mComposer == nullptr) {
+        ALOGE("%s: display:%" PRId64 " missing composer", __FUNCTION__, mId);
+        return HWC3::Error::NoResources;
+    }
+
+    return mComposer->presentDisplay(this, outDisplayFence, outLayerFences);
+}
+
+bool Display::hasConfig(int32_t configId) const {
+    return mConfigs.find(configId) != mConfigs.end();
+}
+
+DisplayConfig* Display::getConfig(int32_t configId) {
+    auto it = mConfigs.find(configId);
+    if (it != mConfigs.end()) {
+        return &it->second;
+    }
+    return nullptr;
+}
+
+HWC3::Error Display::setEdid(std::vector<uint8_t> edid) {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    mEdid = edid;
+    return HWC3::Error::None;
+}
+
+void Display::setLegacyEdid() {
+    // thess EDIDs are carefully generated according to the EDID spec version 1.3,
+    // more info can be found from the following file:
+    //   frameworks/native/services/surfaceflinger/DisplayHardware/DisplayIdentification.cpp
+    // approved pnp ids can be found here: https://uefi.org/pnp_id_list
+    // pnp id: GGL, name: EMU_display_0, last byte is checksum
+    // display id is local:8141603649153536
+    static constexpr const std::array<uint8_t, 128> kEdid0 = {
+        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1c, 0xec, 0x01, 0x00, 0x01, 0x00, 0x00,
+        0x00, 0x1b, 0x10, 0x01, 0x03, 0x80, 0x50, 0x2d, 0x78, 0x0a, 0x0d, 0xc9, 0xa0, 0x57, 0x47,
+        0x98, 0x27, 0x12, 0x48, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
+        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x3a, 0x80, 0x18, 0x71, 0x38,
+        0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x45, 0x4d, 0x55, 0x5f, 0x64, 0x69, 0x73,
+        0x70, 0x6c, 0x61, 0x79, 0x5f, 0x30, 0x00, 0x4b};
+
+    // pnp id: GGL, name: EMU_display_1
+    // display id is local:8140900251843329
+    static constexpr const std::array<uint8_t, 128> kEdid1 = {
+        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1c, 0xec, 0x01, 0x00, 0x01, 0x00, 0x00,
+        0x00, 0x1b, 0x10, 0x01, 0x03, 0x80, 0x50, 0x2d, 0x78, 0x0a, 0x0d, 0xc9, 0xa0, 0x57, 0x47,
+        0x98, 0x27, 0x12, 0x48, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
+        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x3a, 0x80, 0x18, 0x71, 0x38,
+        0x2d, 0x40, 0x58, 0x2c, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x45, 0x4d, 0x55, 0x5f, 0x64, 0x69, 0x73,
+        0x70, 0x6c, 0x61, 0x79, 0x5f, 0x31, 0x00, 0x3b};
+
+    // pnp id: GGL, name: EMU_display_2
+    // display id is local:8140940453066754
+    static constexpr const std::array<uint8_t, 128> kEdid2 = {
+        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1c, 0xec, 0x01, 0x00, 0x01, 0x00, 0x00,
+        0x00, 0x1b, 0x10, 0x01, 0x03, 0x80, 0x50, 0x2d, 0x78, 0x0a, 0x0d, 0xc9, 0xa0, 0x57, 0x47,
+        0x98, 0x27, 0x12, 0x48, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
+        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x3a, 0x80, 0x18, 0x71, 0x38,
+        0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x45, 0x4d, 0x55, 0x5f, 0x64, 0x69, 0x73,
+        0x70, 0x6c, 0x61, 0x79, 0x5f, 0x32, 0x00, 0x49};
+
+    mEdid.clear();
+    switch (mId) {
+        case 0: {
+            mEdid.insert(mEdid.end(), kEdid0.begin(), kEdid0.end());
+            break;
+        }
+        case 1: {
+            mEdid.insert(mEdid.end(), kEdid1.begin(), kEdid1.end());
+            break;
+        }
+        case 2: {
+            mEdid.insert(mEdid.end(), kEdid2.begin(), kEdid2.end());
+            break;
+        }
+        default: {
+            mEdid.insert(mEdid.end(), kEdid2.begin(), kEdid2.end());
+            const size_t size = mEdid.size();
+            // Update the name to EMU_display_<mID>
+            mEdid[size - 3] = '0' + (uint8_t)mId;
+            // Update the checksum byte
+            uint8_t checksum = -(uint8_t)std::accumulate(mEdid.data(), mEdid.data() + size - 1,
+                                                         static_cast<uint8_t>(0));
+            mEdid[size - 1] = checksum;
+            break;
+        }
+    }
+}
+
+Layer* Display::getLayer(int64_t layerId) {
+    auto it = mLayers.find(layerId);
+    if (it == mLayers.end()) {
+        ALOGE("%s Unknown layer:%" PRId64, __FUNCTION__, layerId);
+        return nullptr;
+    }
+
+    return it->second.get();
+}
+
+buffer_handle_t Display::waitAndGetClientTargetBuffer() {
+    DEBUG_LOG("%s: display:%" PRId64, __FUNCTION__, mId);
+
+    ::android::base::unique_fd fence = mClientTarget.getFence();
+    if (fence.ok()) {
+        int err = sync_wait(fence.get(), 3000);
+        if (err < 0 && errno == ETIME) {
+            ALOGE("%s waited on fence %" PRId32 " for 3000 ms", __FUNCTION__, fence.get());
+        }
+    }
+
+    return mClientTarget.getBuffer();
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/Display.h b/hals/hwc3/Display.h
new file mode 100644
index 00000000..9f89b221
--- /dev/null
+++ b/hals/hwc3/Display.h
@@ -0,0 +1,194 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_DISPLAY_H
+#define ANDROID_HWC_DISPLAY_H
+
+#include <aidl/android/hardware/graphics/common/DisplayDecorationSupport.h>
+#include <aidl/android/hardware/graphics/composer3/ColorMode.h>
+#include <aidl/android/hardware/graphics/composer3/ContentType.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayAttribute.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayCapability.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayConnectionType.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayContentSample.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayIdentification.h>
+#include <aidl/android/hardware/graphics/composer3/HdrCapabilities.h>
+#include <aidl/android/hardware/graphics/composer3/OutputType.h>
+#include <aidl/android/hardware/graphics/composer3/PerFrameMetadataKey.h>
+#include <aidl/android/hardware/graphics/composer3/PowerMode.h>
+#include <aidl/android/hardware/graphics/composer3/ReadbackBufferAttributes.h>
+#include <aidl/android/hardware/graphics/composer3/RenderIntent.h>
+#include <aidl/android/hardware/graphics/composer3/VsyncPeriodChangeConstraints.h>
+#include <aidl/android/hardware/graphics/composer3/VsyncPeriodChangeTimeline.h>
+#include <android-base/unique_fd.h>
+
+#include <array>
+#include <mutex>
+#include <optional>
+#include <thread>
+#include <unordered_map>
+#include <unordered_set>
+#include <vector>
+
+#include "Common.h"
+#include "DisplayChanges.h"
+#include "DisplayConfig.h"
+#include "DisplayFinder.h"
+#include "FencedBuffer.h"
+#include "FrameComposer.h"
+#include "Layer.h"
+#include "Time.h"
+#include "VsyncThread.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class FrameComposer;
+
+class Display {
+   public:
+    Display(FrameComposer* composer, int64_t id);
+    ~Display();
+
+    Display(const Display& display) = delete;
+    Display& operator=(const Display& display) = delete;
+
+    Display(Display&& display) = delete;
+    Display& operator=(Display&& display) = delete;
+
+    HWC3::Error init(const std::vector<DisplayConfig>& configs, int32_t activeConfigId,
+                     const std::optional<std::vector<uint8_t>>& edid = std::nullopt);
+
+    HWC3::Error updateParameters(uint32_t width, uint32_t height, uint32_t dpiX, uint32_t dpiY,
+                                 uint32_t refreshRateHz,
+                                 const std::optional<std::vector<uint8_t>>& edid = std::nullopt);
+
+    // HWComposer3 interface.
+    HWC3::Error createLayer(int64_t* outLayerId);
+    HWC3::Error destroyLayer(int64_t layerId);
+    HWC3::Error getActiveConfig(int32_t* outConfigId);
+    HWC3::Error getDisplayAttribute(int32_t configId, DisplayAttribute attribute,
+                                    int32_t* outValue);
+    HWC3::Error getColorModes(std::vector<ColorMode>* outColorModes);
+    HWC3::Error getDisplayCapabilities(std::vector<DisplayCapability>* caps);
+    HWC3::Error getDisplayConfigs(std::vector<int32_t>* configs);
+    HWC3::Error getDisplayConfigurations(std::vector<DisplayConfiguration>* outConfigs);
+    HWC3::Error getDisplayConnectionType(DisplayConnectionType* outType);
+    HWC3::Error getDisplayIdentificationData(DisplayIdentification* outIdentification);
+    HWC3::Error getDisplayName(std::string* outName);
+    HWC3::Error getDisplayVsyncPeriod(int32_t* outVsyncPeriod);
+    HWC3::Error getDisplayedContentSample(int64_t maxFrames, int64_t timestamp,
+                                          DisplayContentSample* samples);
+    HWC3::Error getDisplayedContentSamplingAttributes(
+        DisplayContentSamplingAttributes* outAttributes);
+    HWC3::Error getDisplayPhysicalOrientation(common::Transform* outOrientation);
+    HWC3::Error getHdrCapabilities(HdrCapabilities* outCapabilities);
+    HWC3::Error getPerFrameMetadataKeys(std::vector<PerFrameMetadataKey>* outKeys);
+    HWC3::Error getReadbackBufferAttributes(ReadbackBufferAttributes* attrs);
+    HWC3::Error getReadbackBufferFence(ndk::ScopedFileDescriptor* acquireFence);
+    HWC3::Error getRenderIntents(ColorMode mode, std::vector<RenderIntent>* intents);
+    HWC3::Error getSupportedContentTypes(std::vector<ContentType>* types);
+    HWC3::Error getDecorationSupport(std::optional<common::DisplayDecorationSupport>* support);
+    HWC3::Error registerCallback(const std::shared_ptr<IComposerCallback>& callback);
+    HWC3::Error setActiveConfig(int32_t configId);
+    HWC3::Error setActiveConfigWithConstraints(int32_t config,
+                                               const VsyncPeriodChangeConstraints& constraints,
+                                               VsyncPeriodChangeTimeline* outTimeline);
+    HWC3::Error setBootConfig(int32_t configId);
+    HWC3::Error clearBootConfig();
+    HWC3::Error getPreferredBootConfig(int32_t* outConfigId);
+    HWC3::Error setAutoLowLatencyMode(bool on);
+    HWC3::Error setColorMode(ColorMode mode, RenderIntent intent);
+    HWC3::Error setContentType(ContentType contentType);
+    HWC3::Error setDisplayedContentSamplingEnabled(bool enable, FormatColorComponent componentMask,
+                                                   int64_t maxFrames);
+    HWC3::Error setPowerMode(PowerMode mode);
+    HWC3::Error setReadbackBuffer(const buffer_handle_t buffer,
+                                  const ndk::ScopedFileDescriptor& releaseFence);
+    HWC3::Error setVsyncEnabled(bool enabled);
+    HWC3::Error setIdleTimerEnabled(int32_t timeoutMs);
+    HWC3::Error setColorTransform(const std::vector<float>& transform);
+    HWC3::Error setBrightness(float brightness);
+    HWC3::Error setClientTarget(buffer_handle_t buffer, const ndk::ScopedFileDescriptor& fence,
+                                common::Dataspace dataspace,
+                                const std::vector<common::Rect>& damage);
+    HWC3::Error setOutputBuffer(buffer_handle_t buffer, const ndk::ScopedFileDescriptor& fence);
+    HWC3::Error setExpectedPresentTime(
+        const std::optional<ClockMonotonicTimestamp>& expectedPresentTime);
+    HWC3::Error validate(DisplayChanges* outChanges);
+    HWC3::Error acceptChanges();
+    HWC3::Error present(::android::base::unique_fd* outDisplayFence,
+                        std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences);
+
+    // Non HWCComposer3 interface.
+    int64_t getId() const { return mId; }
+
+    Layer* getLayer(int64_t layerHandle);
+
+    HWC3::Error setEdid(std::vector<uint8_t> edid);
+
+    bool hasColorTransform() const { return mColorTransform.has_value(); }
+    std::array<float, 16> getColorTransform() const { return *mColorTransform; }
+
+    FencedBuffer& getClientTarget() { return mClientTarget; }
+    buffer_handle_t waitAndGetClientTargetBuffer();
+
+    const std::vector<Layer*>& getOrderedLayers() { return mOrderedLayers; }
+
+   private:
+    bool hasConfig(int32_t configId) const;
+    DisplayConfig* getConfig(int32_t configId);
+
+    std::optional<int32_t> getBootConfigId();
+
+    void setLegacyEdid();
+
+    // The state of this display should only be modified from
+    // SurfaceFlinger's main loop, with the exception of when dump is
+    // called. To prevent a bad state from crashing us during a dump
+    // call, all public calls into Display must acquire this mutex.
+    mutable std::recursive_mutex mStateMutex;
+
+    FrameComposer* mComposer = nullptr;
+    const int64_t mId;
+    std::string mName;
+    PowerMode mPowerMode = PowerMode::OFF;
+    VsyncThread mVsyncThread;
+    FencedBuffer mClientTarget;
+    FencedBuffer mReadbackBuffer;
+    // Will only be non-null after the Display has been validated and
+    // before it has been accepted.
+    enum class PresentFlowState {
+        WAITING_FOR_VALIDATE,
+        WAITING_FOR_ACCEPT,
+        WAITING_FOR_PRESENT,
+    };
+    PresentFlowState mPresentFlowState = PresentFlowState::WAITING_FOR_VALIDATE;
+    DisplayChanges mPendingChanges;
+    std::optional<TimePoint> mExpectedPresentTime;
+    std::unordered_map<int64_t, std::unique_ptr<Layer>> mLayers;
+    // Ordered layers available after validate().
+    std::vector<Layer*> mOrderedLayers;
+    std::optional<int32_t> mActiveConfigId;
+    std::unordered_map<int32_t, DisplayConfig> mConfigs;
+    std::unordered_set<ColorMode> mColorModes = {ColorMode::NATIVE};
+    ColorMode mActiveColorMode = ColorMode::NATIVE;
+    std::optional<std::array<float, 16>> mColorTransform;
+    std::vector<uint8_t> mEdid;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/DisplayChanges.h b/hals/hwc3/DisplayChanges.h
new file mode 100644
index 00000000..7c4b5d18
--- /dev/null
+++ b/hals/hwc3/DisplayChanges.h
@@ -0,0 +1,59 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_DISPLAYCHANGES_H
+#define ANDROID_HWC_DISPLAYCHANGES_H
+
+#include <aidl/android/hardware/graphics/composer3/ChangedCompositionLayer.h>
+#include <aidl/android/hardware/graphics/composer3/ChangedCompositionTypes.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayRequest.h>
+
+#include <optional>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+struct DisplayChanges {
+    std::optional<ChangedCompositionTypes> compositionChanges;
+    std::optional<DisplayRequest> displayRequestChanges;
+
+    void addLayerCompositionChange(int64_t displayId, int64_t layerId,
+                                   Composition layerComposition) {
+        if (!compositionChanges) {
+            compositionChanges.emplace();
+            compositionChanges->display = displayId;
+        }
+
+        ChangedCompositionLayer compositionChange;
+        compositionChange.layer = layerId;
+        compositionChange.composition = layerComposition;
+        compositionChanges->layers.emplace_back(std::move(compositionChange));
+    }
+
+    void clearLayerCompositionChanges() { compositionChanges.reset(); }
+
+    bool hasAnyChanges() const {
+        return compositionChanges.has_value() || displayRequestChanges.has_value();
+    }
+
+    void reset() {
+        compositionChanges.reset();
+        displayRequestChanges.reset();
+    }
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/DisplayConfig.cpp b/hals/hwc3/DisplayConfig.cpp
new file mode 100644
index 00000000..c17fa952
--- /dev/null
+++ b/hals/hwc3/DisplayConfig.cpp
@@ -0,0 +1,130 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DisplayConfig.h"
+
+#include <unordered_map>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+template <class T>
+inline void hashCombine(size_t& hash, const T& value) {
+    std::hash<T> hasher;
+    hash ^= hasher(value) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
+}
+
+}  // namespace
+
+void DisplayConfig::setAttribute(DisplayAttribute attribute, int32_t value) {
+    if (attribute == DisplayAttribute::WIDTH) {
+        mWidth = value;
+    }
+    if (attribute == DisplayAttribute::HEIGHT) {
+        mHeight = value;
+    }
+    if (attribute == DisplayAttribute::DPI_X) {
+        mDpiX = value;
+    }
+    if (attribute == DisplayAttribute::DPI_Y) {
+        mDpiY = value;
+    }
+    if (attribute == DisplayAttribute::VSYNC_PERIOD) {
+        mVsyncPeriodNanos = value;
+    }
+    if (attribute == DisplayAttribute::CONFIG_GROUP) {
+        mConfigGroup = value;
+    }
+}
+
+int32_t DisplayConfig::getAttribute(DisplayAttribute attribute) const {
+    if (attribute == DisplayAttribute::WIDTH) {
+        return mWidth;
+    }
+    if (attribute == DisplayAttribute::HEIGHT) {
+        return mHeight;
+    }
+    if (attribute == DisplayAttribute::DPI_X) {
+        // From hwcomposer2.h, HWC2_ATTRIBUTE_DPI_X returns "Dots per thousand
+        // inches (DPI * 1000)".
+        return getDotsPerThousandInchesX();
+    }
+    if (attribute == DisplayAttribute::DPI_Y) {
+        // From hwcomposer2.h, HWC2_ATTRIBUTE_DPI_Y returns "Dots per thousand
+        // inches (DPI * 1000)"
+        return getDotsPerThousandInchesY();
+    }
+    if (attribute == DisplayAttribute::VSYNC_PERIOD) {
+        return mVsyncPeriodNanos;
+    }
+    if (attribute == DisplayAttribute::CONFIG_GROUP) {
+        return mConfigGroup;
+    }
+    return -1;
+}
+
+std::string DisplayConfig::toString() const {
+    std::string output;
+    output += " id: " + std::to_string(mId);
+    output += " w:" + std::to_string(mWidth);
+    output += " h:" + std::to_string(mHeight);
+    output += " dpi-x:" + std::to_string(mDpiX);
+    output += " dpi-y:" + std::to_string(mDpiY);
+    output += " vsync:" + std::to_string(1e9 / mVsyncPeriodNanos);
+    output += " config-group:" + std::to_string(mConfigGroup);
+    return output;
+}
+
+/*static*/
+void DisplayConfig::addConfigGroups(std::vector<DisplayConfig>* configs) {
+    // From /hardware/interfaces/graphics/composer/2.4/IComposerClient.hal:
+    // "Configurations which share the same config group are similar in all
+    // attributes except for the vsync period."
+    struct ConfigForGroupHash {
+        size_t operator()(const DisplayConfig& config) const {
+            size_t hash = 0;
+            hashCombine(hash, config.mWidth);
+            hashCombine(hash, config.mHeight);
+            hashCombine(hash, config.mDpiX);
+            hashCombine(hash, config.mDpiY);
+            return hash;
+        }
+    };
+    struct ConfigForGroupEq {
+        size_t operator()(const DisplayConfig& a, const DisplayConfig& b) const {
+            if (a.mWidth != b.mWidth) {
+                return a.mWidth < b.mWidth;
+            }
+            if (a.mHeight != b.mHeight) {
+                return a.mHeight < b.mHeight;
+            }
+            if (a.mDpiX != b.mDpiX) {
+                return a.mDpiX < b.mDpiX;
+            }
+            return a.mDpiY < b.mDpiY;
+        }
+    };
+
+    std::unordered_map<DisplayConfig, int32_t, ConfigForGroupHash, ConfigForGroupEq>
+        configToConfigGroup;
+
+    for (auto& config : *configs) {
+        auto [it, inserted] = configToConfigGroup.try_emplace(config, configToConfigGroup.size());
+        config.setConfigGroup(it->second);
+    }
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DisplayConfig.h b/hals/hwc3/DisplayConfig.h
new file mode 100644
index 00000000..1abd992c
--- /dev/null
+++ b/hals/hwc3/DisplayConfig.h
@@ -0,0 +1,90 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_DISPLAYCONFIG_H
+#define ANDROID_HWC_DISPLAYCONFIG_H
+
+#include <aidl/android/hardware/graphics/composer3/DisplayAttribute.h>
+
+#include <vector>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DisplayConfig {
+   public:
+    DisplayConfig(int32_t configId) : mId(configId) {}
+
+    DisplayConfig(int32_t configId, int32_t width, int32_t height, int32_t dpiX, int32_t dpiY,
+                  int32_t vsyncPeriodNanos)
+        : mId(configId),
+          mWidth(width),
+          mHeight(height),
+          mDpiX(dpiX),
+          mDpiY(dpiY),
+          mVsyncPeriodNanos(vsyncPeriodNanos) {}
+
+    DisplayConfig(const DisplayConfig& other) = default;
+    DisplayConfig& operator=(DisplayConfig& other) = default;
+
+    DisplayConfig(DisplayConfig&& other) = default;
+    DisplayConfig& operator=(DisplayConfig&& other) = default;
+
+    int32_t getId() const { return mId; }
+    void setId(int32_t id) { mId = id; }
+
+    int32_t getAttribute(DisplayAttribute attribute) const;
+    void setAttribute(DisplayAttribute attribute, int32_t value);
+
+    int32_t getWidth() const { return mWidth; }
+    void setWidth(int32_t width) { mWidth = width; }
+
+    int32_t getHeight() const { return mHeight; }
+    void getHeight(int32_t height) { mHeight = height; }
+
+    int32_t getDpiX() const { return mDpiX; }
+    void setDpiX(int32_t dpi) { mDpiX = dpi; }
+
+    int32_t getDpiY() const { return mDpiY; }
+    void setDpiY(int32_t dpi) { mDpiY = dpi; }
+
+    int32_t getDotsPerThousandInchesX() const { return mDpiX * 1000; }
+    int32_t getDotsPerThousandInchesY() const { return mDpiY * 1000; }
+
+    int32_t getVsyncPeriod() const { return mVsyncPeriodNanos; }
+    void setVsyncPeriod(int32_t vsync) { mVsyncPeriodNanos = vsync; }
+
+    int32_t getConfigGroup() const { return mConfigGroup; }
+    void setConfigGroup(int32_t group) { mConfigGroup = group; }
+
+    std::string toString() const;
+
+    static void addConfigGroups(std::vector<DisplayConfig>* configs);
+
+   private:
+    int32_t mId;
+    int32_t mWidth;
+    int32_t mHeight;
+    int32_t mDpiX;
+    int32_t mDpiY;
+    int32_t mVsyncPeriodNanos;
+    int32_t mConfigGroup;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/DisplayFinder.cpp b/hals/hwc3/DisplayFinder.cpp
new file mode 100644
index 00000000..0dd59224
--- /dev/null
+++ b/hals/hwc3/DisplayFinder.cpp
@@ -0,0 +1,245 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DisplayFinder.h"
+
+#include <android-base/parseint.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+
+#include "Common.h"
+#include "HostUtils.h"
+#include "Time.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+static uint32_t getVsyncHzFromProperty() {
+    static constexpr const auto kVsyncProp = "ro.boot.qemu.vsync";
+
+    const auto vsyncProp = ::android::base::GetProperty(kVsyncProp, "");
+    DEBUG_LOG("%s: prop value is: %s", __FUNCTION__, vsyncProp.c_str());
+
+    uint64_t vsyncPeriod;
+    if (!::android::base::ParseUint(vsyncProp, &vsyncPeriod)) {
+        ALOGE("%s: failed to parse vsync period '%s', returning default 60", __FUNCTION__,
+              vsyncProp.c_str());
+        return 60;
+    }
+
+    return static_cast<uint32_t>(vsyncPeriod);
+}
+
+HWC3::Error findGoldfishPrimaryDisplay(std::vector<DisplayMultiConfigs>* outDisplays) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    DEFINE_AND_VALIDATE_HOST_CONNECTION
+    hostCon->lock();
+    const int32_t vsyncPeriodNanos = HertzToPeriodNanos(getVsyncHzFromProperty());
+    DisplayMultiConfigs display;
+    display.displayId = 0;
+    if (rcEnc->hasHWCMultiConfigs()) {
+        int count = rcEnc->rcGetFBDisplayConfigsCount(rcEnc);
+        if (count <= 0) {
+            ALOGE("%s failed to allocate primary display, config count %d", __func__, count);
+            return HWC3::Error::NoResources;
+        }
+        display.activeConfigId = rcEnc->rcGetFBDisplayActiveConfig(rcEnc);
+        for (int configId = 0; configId < count; configId++) {
+            display.configs.push_back(DisplayConfig(
+                configId,                                                       //
+                rcEnc->rcGetFBDisplayConfigsParam(rcEnc, configId, FB_WIDTH),   //
+                rcEnc->rcGetFBDisplayConfigsParam(rcEnc, configId, FB_HEIGHT),  //
+                rcEnc->rcGetFBDisplayConfigsParam(rcEnc, configId, FB_XDPI),    //
+                rcEnc->rcGetFBDisplayConfigsParam(rcEnc, configId, FB_YDPI),    //
+                vsyncPeriodNanos                                                //
+                ));
+        }
+    } else {
+        display.activeConfigId = 0;
+        display.configs.push_back(DisplayConfig(0,                                      //
+                                                rcEnc->rcGetFBParam(rcEnc, FB_WIDTH),   //
+                                                rcEnc->rcGetFBParam(rcEnc, FB_HEIGHT),  //
+                                                rcEnc->rcGetFBParam(rcEnc, FB_XDPI),    //
+                                                rcEnc->rcGetFBParam(rcEnc, FB_YDPI),    //
+                                                vsyncPeriodNanos                        //
+                                                ));
+    }
+    hostCon->unlock();
+
+    outDisplays->push_back(display);
+
+    return HWC3::Error::None;
+}
+
+void parseExternalDisplaysFromProperties(std::vector<int>& outPropIntParts) {
+    static constexpr const char* kExternalDisplayProp[] = {
+        "hwservicemanager.external.displays",
+        "ro.boot.qemu.external.displays",
+    };
+
+    for (auto propName : kExternalDisplayProp) {
+        const std::string propVal = ::android::base::GetProperty(propName, "");
+        if (propVal.empty()) {
+            DEBUG_LOG("%s: prop name is: %s, prop value is: empty", __FUNCTION__, propName);
+            continue;
+        }
+        DEBUG_LOG("%s: prop name is: %s, prop value is: %s", __FUNCTION__, propName,
+                  propVal.c_str());
+
+        const std::vector<std::string> propStringParts = ::android::base::Split(propVal, ",");
+        if (propStringParts.size() % 5 != 0) {
+            ALOGE("%s: Invalid syntax for system prop %s which is %s", __FUNCTION__, propName,
+                  propVal.c_str());
+            continue;
+        }
+        std::vector<int> propIntParts;
+        for (const std::string& propStringPart : propStringParts) {
+            int propIntPart;
+            if (!::android::base::ParseInt(propStringPart, &propIntPart)) {
+                ALOGE("%s: Invalid syntax for system prop %s which is %s", __FUNCTION__, propName,
+                      propVal.c_str());
+                break;
+            }
+            propIntParts.push_back(propIntPart);
+        }
+        if (propIntParts.empty() || propIntParts.size() % 5 != 0) {
+            continue;
+        }
+        outPropIntParts.insert(outPropIntParts.end(), propIntParts.begin(), propIntParts.end());
+    }
+}
+
+HWC3::Error findGoldfishSecondaryDisplays(std::vector<DisplayMultiConfigs>* outDisplays) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::vector<int> propIntParts;
+    parseExternalDisplaysFromProperties(propIntParts);
+
+    int64_t secondaryDisplayId = 1;
+    while (!propIntParts.empty()) {
+        DisplayMultiConfigs display;
+        display.displayId = secondaryDisplayId;
+        display.activeConfigId = 0;
+        display.configs.push_back(DisplayConfig(0,                                       //
+                                                /*width=*/propIntParts[1],               //
+                                                /*heighth=*/propIntParts[2],             //
+                                                /*dpiXh=*/propIntParts[3],               //
+                                                /*dpiYh=*/propIntParts[3],               //
+                                                /*vsyncPeriod=*/HertzToPeriodNanos(160)  //
+                                                ));
+        outDisplays->push_back(display);
+
+        ++secondaryDisplayId;
+
+        propIntParts.erase(propIntParts.begin(), propIntParts.begin() + 5);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error findGoldfishDisplays(std::vector<DisplayMultiConfigs>* outDisplays) {
+    HWC3::Error error = findGoldfishPrimaryDisplay(outDisplays);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to find Goldfish primary display", __FUNCTION__);
+        return error;
+    }
+
+    error = findGoldfishSecondaryDisplays(outDisplays);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to find Goldfish secondary displays", __FUNCTION__);
+    }
+
+    return error;
+}
+
+// This is currently only used for Gem5 bring-up where virtio-gpu and drm
+// are not currently available. For now, just return a placeholder display.
+HWC3::Error findNoOpDisplays(std::vector<DisplayMultiConfigs>* outDisplays) {
+    outDisplays->push_back(DisplayMultiConfigs{
+        .displayId = 0,
+        .activeConfigId = 0,
+        .configs = {DisplayConfig(0,
+                                  /*width=*/720,                          //
+                                  /*heighth=*/1280,                       //
+                                  /*dpiXh=*/320,                          //
+                                  /*dpiYh=*/320,                          //
+                                  /*vsyncPeriod=*/HertzToPeriodNanos(30)  //
+                                  )},
+    });
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error findDrmDisplays(const DrmClient& drm, std::vector<DisplayMultiConfigs>* outDisplays) {
+    outDisplays->clear();
+
+    std::vector<DrmClient::DisplayConfig> drmDisplayConfigs;
+
+    HWC3::Error error = drm.getDisplayConfigs(&drmDisplayConfigs);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to find displays from DRM.", __FUNCTION__);
+        return error;
+    }
+
+    for (const DrmClient::DisplayConfig drmDisplayConfig : drmDisplayConfigs) {
+        outDisplays->push_back(DisplayMultiConfigs{
+            .displayId = drmDisplayConfig.id,
+            .activeConfigId = static_cast<int32_t>(drmDisplayConfig.id),
+            .configs =
+                {
+                    DisplayConfig(static_cast<int32_t>(drmDisplayConfig.id),
+                                  static_cast<int32_t>(drmDisplayConfig.width),
+                                  static_cast<int32_t>(drmDisplayConfig.height),
+                                  static_cast<int32_t>(drmDisplayConfig.dpiX),
+                                  static_cast<int32_t>(drmDisplayConfig.dpiY),
+                                  HertzToPeriodNanos(drmDisplayConfig.refreshRateHz)),
+                },
+        });
+    }
+
+    return HWC3::Error::None;
+}
+
+}  // namespace
+
+HWC3::Error findDisplays(const DrmClient* drm, std::vector<DisplayMultiConfigs>* outDisplays) {
+    HWC3::Error error = HWC3::Error::None;
+    if (IsInGem5DisplayFinderMode() || IsInNoOpDisplayFinderMode()) {
+        error = findNoOpDisplays(outDisplays);
+    } else if (IsInDrmDisplayFinderMode()) {
+        if (drm == nullptr) {
+            ALOGE("%s asked to find displays from DRM, but DRM not available.", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+        error = findDrmDisplays(*drm, outDisplays);
+    } else {
+        error = findGoldfishDisplays(outDisplays);
+    }
+
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to find displays", __FUNCTION__);
+        return error;
+    }
+
+    for (auto& display : *outDisplays) {
+        DisplayConfig::addConfigGroups(&display.configs);
+    }
+
+    return HWC3::Error::None;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DisplayFinder.h b/hals/hwc3/DisplayFinder.h
new file mode 100644
index 00000000..c124c805
--- /dev/null
+++ b/hals/hwc3/DisplayFinder.h
@@ -0,0 +1,42 @@
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
+#ifndef ANDROID_HWC_DISPLAYFINDER_H
+#define ANDROID_HWC_DISPLAYFINDER_H
+
+#include <optional>
+#include <vector>
+
+#include "Common.h"
+#include "DisplayConfig.h"
+#include "DrmClient.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+struct DisplayMultiConfigs {
+    int64_t displayId;
+    int32_t activeConfigId;
+    // Modes that this display can be configured to use.
+    std::vector<DisplayConfig> configs;
+};
+
+void parseExternalDisplaysFromProperties(std::vector<int>& outPropIntParts);
+
+HWC3::Error findDisplays(const DrmClient* drm, std::vector<DisplayMultiConfigs>* outDisplays);
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/Drm.cpp b/hals/hwc3/Drm.cpp
new file mode 100644
index 00000000..1ac9051a
--- /dev/null
+++ b/hals/hwc3/Drm.cpp
@@ -0,0 +1,180 @@
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
+#include "Drm.h"
+
+#include <drm_fourcc.h>
+#include <log/log.h>
+#include <system/graphics.h>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+const char* GetDrmFormatString(uint32_t drm_format) {
+    switch (drm_format) {
+        case DRM_FORMAT_ABGR1555:
+            return "DRM_FORMAT_ABGR1555";
+        case DRM_FORMAT_ABGR2101010:
+            return "DRM_FORMAT_ABGR2101010";
+        case DRM_FORMAT_ABGR4444:
+            return "DRM_FORMAT_ABGR4444";
+        case DRM_FORMAT_ABGR8888:
+            return "DRM_FORMAT_ABGR8888";
+        case DRM_FORMAT_ARGB1555:
+            return "DRM_FORMAT_ARGB1555";
+        case DRM_FORMAT_ARGB2101010:
+            return "DRM_FORMAT_ARGB2101010";
+        case DRM_FORMAT_ARGB4444:
+            return "DRM_FORMAT_ARGB4444";
+        case DRM_FORMAT_ARGB8888:
+            return "DRM_FORMAT_ARGB8888";
+        case DRM_FORMAT_AYUV:
+            return "DRM_FORMAT_AYUV";
+        case DRM_FORMAT_BGR233:
+            return "DRM_FORMAT_BGR233";
+        case DRM_FORMAT_BGR565:
+            return "DRM_FORMAT_BGR565";
+        case DRM_FORMAT_BGR888:
+            return "DRM_FORMAT_BGR888";
+        case DRM_FORMAT_BGRA1010102:
+            return "DRM_FORMAT_BGRA1010102";
+        case DRM_FORMAT_BGRA4444:
+            return "DRM_FORMAT_BGRA4444";
+        case DRM_FORMAT_BGRA5551:
+            return "DRM_FORMAT_BGRA5551";
+        case DRM_FORMAT_BGRA8888:
+            return "DRM_FORMAT_BGRA8888";
+        case DRM_FORMAT_BGRX1010102:
+            return "DRM_FORMAT_BGRX1010102";
+        case DRM_FORMAT_BGRX4444:
+            return "DRM_FORMAT_BGRX4444";
+        case DRM_FORMAT_BGRX5551:
+            return "DRM_FORMAT_BGRX5551";
+        case DRM_FORMAT_BGRX8888:
+            return "DRM_FORMAT_BGRX8888";
+        case DRM_FORMAT_C8:
+            return "DRM_FORMAT_C8";
+        case DRM_FORMAT_GR88:
+            return "DRM_FORMAT_GR88";
+        case DRM_FORMAT_NV12:
+            return "DRM_FORMAT_NV12";
+        case DRM_FORMAT_NV21:
+            return "DRM_FORMAT_NV21";
+        case DRM_FORMAT_R8:
+            return "DRM_FORMAT_R8";
+        case DRM_FORMAT_RG88:
+            return "DRM_FORMAT_RG88";
+        case DRM_FORMAT_RGB332:
+            return "DRM_FORMAT_RGB332";
+        case DRM_FORMAT_RGB565:
+            return "DRM_FORMAT_RGB565";
+        case DRM_FORMAT_RGB888:
+            return "DRM_FORMAT_RGB888";
+        case DRM_FORMAT_RGBA1010102:
+            return "DRM_FORMAT_RGBA1010102";
+        case DRM_FORMAT_RGBA4444:
+            return "DRM_FORMAT_RGBA4444";
+        case DRM_FORMAT_RGBA5551:
+            return "DRM_FORMAT_RGBA5551";
+        case DRM_FORMAT_RGBA8888:
+            return "DRM_FORMAT_RGBA8888";
+        case DRM_FORMAT_RGBX1010102:
+            return "DRM_FORMAT_RGBX1010102";
+        case DRM_FORMAT_RGBX4444:
+            return "DRM_FORMAT_RGBX4444";
+        case DRM_FORMAT_RGBX5551:
+            return "DRM_FORMAT_RGBX5551";
+        case DRM_FORMAT_RGBX8888:
+            return "DRM_FORMAT_RGBX8888";
+        case DRM_FORMAT_UYVY:
+            return "DRM_FORMAT_UYVY";
+        case DRM_FORMAT_VYUY:
+            return "DRM_FORMAT_VYUY";
+        case DRM_FORMAT_XBGR1555:
+            return "DRM_FORMAT_XBGR1555";
+        case DRM_FORMAT_XBGR2101010:
+            return "DRM_FORMAT_XBGR2101010";
+        case DRM_FORMAT_XBGR4444:
+            return "DRM_FORMAT_XBGR4444";
+        case DRM_FORMAT_XBGR8888:
+            return "DRM_FORMAT_XBGR8888";
+        case DRM_FORMAT_XRGB1555:
+            return "DRM_FORMAT_XRGB1555";
+        case DRM_FORMAT_XRGB2101010:
+            return "DRM_FORMAT_XRGB2101010";
+        case DRM_FORMAT_XRGB4444:
+            return "DRM_FORMAT_XRGB4444";
+        case DRM_FORMAT_XRGB8888:
+            return "DRM_FORMAT_XRGB8888";
+        case DRM_FORMAT_YUYV:
+            return "DRM_FORMAT_YUYV";
+        case DRM_FORMAT_YVU420:
+            return "DRM_FORMAT_YVU420";
+        case DRM_FORMAT_YVYU:
+            return "DRM_FORMAT_YVYU";
+    }
+    return "Unknown";
+}
+
+uint32_t GetDrmFormatBytesPerPixel(uint32_t drm_format) {
+    switch (drm_format) {
+        case DRM_FORMAT_ABGR8888:
+        case DRM_FORMAT_ARGB8888:
+        case DRM_FORMAT_XBGR8888:
+            return 4;
+        case DRM_FORMAT_BGR888:
+            return 3;
+        case DRM_FORMAT_RGB565:
+        case DRM_FORMAT_YVU420:
+#ifdef GRALLOC_MODULE_API_VERSION_0_2
+        case DRM_FORMAT_FLEX_YCbCr_420_888:
+#endif
+            return 2;
+        case DRM_FORMAT_R8:
+            return 1;
+    }
+    ALOGE("%s: format size unknown %d(%s)", __FUNCTION__, drm_format,
+          GetDrmFormatString(drm_format));
+    return 8;
+}
+
+uint32_t GetDrmFormatFromHalFormat(int hal_format) {
+    switch (hal_format) {
+        case HAL_PIXEL_FORMAT_RGBA_FP16:
+            return DRM_FORMAT_ABGR16161616F;
+        case HAL_PIXEL_FORMAT_RGBA_8888:
+            return DRM_FORMAT_ABGR8888;
+        case HAL_PIXEL_FORMAT_RGBX_8888:
+            return DRM_FORMAT_XBGR8888;
+        case HAL_PIXEL_FORMAT_BGRA_8888:
+            return DRM_FORMAT_ARGB8888;
+        case HAL_PIXEL_FORMAT_RGB_888:
+            return DRM_FORMAT_BGR888;
+        case HAL_PIXEL_FORMAT_RGB_565:
+            return DRM_FORMAT_BGR565;
+        case HAL_PIXEL_FORMAT_YV12:
+            return DRM_FORMAT_YVU420;
+        case HAL_PIXEL_FORMAT_YCbCr_420_888:
+            return DRM_FORMAT_YVU420;
+        case HAL_PIXEL_FORMAT_BLOB:
+            return DRM_FORMAT_R8;
+        default:
+            break;
+    }
+    ALOGE("%s unhandled hal format: %d", __FUNCTION__, hal_format);
+    return 0;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hals/hwc3/Drm.h b/hals/hwc3/Drm.h
new file mode 100644
index 00000000..7b822552
--- /dev/null
+++ b/hals/hwc3/Drm.h
@@ -0,0 +1,31 @@
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
+#ifndef ANDROID_HWC_DRM_H
+#define ANDROID_HWC_DRM_H
+
+#include <cstdlib>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+const char* GetDrmFormatString(uint32_t drm_format);
+
+uint32_t GetDrmFormatBytesPerPixel(uint32_t drm_format);
+
+uint32_t GetDrmFormatFromHalFormat(int hal_format);
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/DrmAtomicRequest.cpp b/hals/hwc3/DrmAtomicRequest.cpp
new file mode 100644
index 00000000..63e5c10a
--- /dev/null
+++ b/hals/hwc3/DrmAtomicRequest.cpp
@@ -0,0 +1,58 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmAtomicRequest.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+std::unique_ptr<DrmAtomicRequest> DrmAtomicRequest::create() {
+    drmModeAtomicReqPtr request = drmModeAtomicAlloc();
+    if (!request) {
+        return nullptr;
+    }
+
+    return std::unique_ptr<DrmAtomicRequest>(new DrmAtomicRequest(request));
+}
+
+DrmAtomicRequest::~DrmAtomicRequest() {
+    if (mRequest) {
+        drmModeAtomicFree(mRequest);
+    }
+}
+
+bool DrmAtomicRequest::Set(uint32_t objectId, const DrmProperty& prop, uint64_t value) {
+    int ret = drmModeAtomicAddProperty(mRequest, objectId, prop.getId(), value);
+    if (ret < 0) {
+        ALOGE("%s: failed to set atomic request property %s to %" PRIu64 ": %s", __FUNCTION__,
+              prop.getName().c_str(), value, strerror(errno));
+        return false;
+    }
+    return true;
+}
+
+bool DrmAtomicRequest::Commit(::android::base::borrowed_fd drmFd) {
+    constexpr const uint32_t kCommitFlags = DRM_MODE_ATOMIC_ALLOW_MODESET;
+
+    int ret = drmModeAtomicCommit(drmFd.get(), mRequest, kCommitFlags, 0);
+    if (ret) {
+        ALOGE("%s:%d: atomic commit failed: %s\n", __FUNCTION__, __LINE__, strerror(errno));
+        return false;
+    }
+
+    return true;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmAtomicRequest.h b/hals/hwc3/DrmAtomicRequest.h
new file mode 100644
index 00000000..862ea2f2
--- /dev/null
+++ b/hals/hwc3/DrmAtomicRequest.h
@@ -0,0 +1,50 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <memory>
+#include <string>
+#include <unordered_map>
+
+#include "Common.h"
+#include "DrmMode.h"
+#include "DrmProperty.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmAtomicRequest {
+   public:
+    static std::unique_ptr<DrmAtomicRequest> create();
+    ~DrmAtomicRequest();
+
+    bool Set(uint32_t objectId, const DrmProperty& prop, uint64_t value);
+
+    bool Commit(::android::base::borrowed_fd drmFd);
+
+   private:
+    DrmAtomicRequest(drmModeAtomicReqPtr request) : mRequest(request) {}
+
+    drmModeAtomicReqPtr mRequest;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmBuffer.cpp b/hals/hwc3/DrmBuffer.cpp
new file mode 100644
index 00000000..68b5457a
--- /dev/null
+++ b/hals/hwc3/DrmBuffer.cpp
@@ -0,0 +1,27 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmBuffer.h"
+
+#include "DrmClient.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+DrmBuffer::DrmBuffer(DrmClient& DrmClient) : mDrmClient(DrmClient) {}
+
+DrmBuffer::~DrmBuffer() { mDrmClient.destroyDrmFramebuffer(this); }
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmBuffer.h b/hals/hwc3/DrmBuffer.h
new file mode 100644
index 00000000..5107250e
--- /dev/null
+++ b/hals/hwc3/DrmBuffer.h
@@ -0,0 +1,62 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <optional>
+#include <unordered_map>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmClient;
+
+// A RAII object that will clear a drm framebuffer upon destruction.
+class DrmBuffer {
+   public:
+    ~DrmBuffer();
+
+    DrmBuffer(const DrmBuffer&) = delete;
+    DrmBuffer& operator=(const DrmBuffer&) = delete;
+
+    DrmBuffer(DrmBuffer&&) = delete;
+    DrmBuffer& operator=(DrmBuffer&&) = delete;
+
+   private:
+    friend class DrmClient;
+    friend class DrmDisplay;
+    DrmBuffer(DrmClient& drmClient);
+
+    DrmClient& mDrmClient;
+
+    uint32_t mWidth = 0;
+    uint32_t mHeight = 0;
+    uint32_t mDrmFormat = 0;
+    int32_t mPlaneFds[4] = {0, 0, 0, 0};
+    uint32_t mPlaneHandles[4] = {0, 0, 0, 0};
+    uint32_t mPlanePitches[4] = {0, 0, 0, 0};
+    uint32_t mPlaneOffsets[4] = {0, 0, 0, 0};
+    std::optional<uint32_t> mDrmFramebuffer;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmClient.cpp b/hals/hwc3/DrmClient.cpp
new file mode 100644
index 00000000..a55e94bd
--- /dev/null
+++ b/hals/hwc3/DrmClient.cpp
@@ -0,0 +1,369 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmClient.h"
+
+#include <cros_gralloc_handle.h>
+
+using ::gfxstream::guest::AutoReadLock;
+using ::gfxstream::guest::AutoWriteLock;
+using ::gfxstream::guest::ReadWriteLock;
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+DrmClient::~DrmClient() {
+    if (mFd > 0) {
+        drmDropMaster(mFd.get());
+    }
+}
+
+::android::base::unique_fd DrmClient::OpenVirtioGpuDrmFd() {
+    for (int i = 0; i < 10; i++) {
+        const std::string path = "/dev/dri/card" + std::to_string(i);
+        DEBUG_LOG("%s: trying to open DRM device at %s", __FUNCTION__, path.c_str());
+
+        ::android::base::unique_fd fd(open(path.c_str(), O_RDWR | O_CLOEXEC));
+
+        if (fd < 0) {
+            ALOGE("%s: failed to open drm device %s: %s", __FUNCTION__, path.c_str(),
+                  strerror(errno));
+            continue;
+        }
+
+        auto version = drmGetVersion(fd.get());
+        const std::string name = version->name;
+        drmFreeVersion(version);
+
+        DEBUG_LOG("%s: The DRM device at %s is \"%s\"", __FUNCTION__, path.c_str(), name.c_str());
+        if (name.find("virtio") != std::string::npos) {
+            return fd;
+        }
+    }
+
+    ALOGE(
+        "Failed to find virtio-gpu DRM node. Ranchu HWComposer "
+        "is only expected to be used with \"virtio_gpu\"");
+
+    return ::android::base::unique_fd(-1);
+}
+
+HWC3::Error DrmClient::init() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    mFd = OpenVirtioGpuDrmFd();
+    if (mFd < 0) {
+        ALOGE("%s: failed to open drm device: %s", __FUNCTION__, strerror(errno));
+        return HWC3::Error::NoResources;
+    }
+
+    int ret = drmSetClientCap(mFd.get(), DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);
+    if (ret) {
+        ALOGE("%s: failed to set cap universal plane %s\n", __FUNCTION__, strerror(errno));
+        return HWC3::Error::NoResources;
+    }
+
+    ret = drmSetClientCap(mFd.get(), DRM_CLIENT_CAP_ATOMIC, 1);
+    if (ret) {
+        ALOGE("%s: failed to set cap atomic %s\n", __FUNCTION__, strerror(errno));
+        return HWC3::Error::NoResources;
+    }
+
+    drmSetMaster(mFd.get());
+
+    if (!drmIsMaster(mFd.get())) {
+        ALOGE("%s: failed to get master drm device", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    {
+        AutoWriteLock lock(mDisplaysMutex);
+        bool success = loadDrmDisplays();
+        if (success) {
+            DEBUG_LOG("%s: Successfully initialized DRM backend", __FUNCTION__);
+        } else {
+            ALOGE("%s: Failed to initialize DRM backend", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+    }
+
+    mDrmEventListener = DrmEventListener::create(mFd, [this]() { handleHotplug(); });
+    if (!mDrmEventListener) {
+        ALOGE("%s: Failed to initialize DRM event listener", __FUNCTION__);
+    } else {
+        DEBUG_LOG("%s: Successfully initialized DRM event listener", __FUNCTION__);
+    }
+
+    DEBUG_LOG("%s: Successfully initialized.", __FUNCTION__);
+    return HWC3::Error::None;
+}
+
+HWC3::Error DrmClient::getDisplayConfigs(std::vector<DisplayConfig>* configs) const {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    AutoReadLock lock(mDisplaysMutex);
+
+    configs->clear();
+
+    for (const auto& display : mDisplays) {
+        if (!display->isConnected()) {
+            continue;
+        }
+
+        configs->emplace_back(DisplayConfig{
+            .id = display->getId(),
+            .width = display->getWidth(),
+            .height = display->getHeight(),
+            .dpiX = display->getDpiX(),
+            .dpiY = display->getDpiY(),
+            .refreshRateHz = display->getRefreshRateUint(),
+        });
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error DrmClient::registerOnHotplugCallback(const HotplugCallback& cb) {
+    mHotplugCallback = cb;
+    return HWC3::Error::None;
+}
+
+HWC3::Error DrmClient::unregisterOnHotplugCallback() {
+    mHotplugCallback.reset();
+    return HWC3::Error::None;
+}
+
+bool DrmClient::loadDrmDisplays() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::vector<std::unique_ptr<DrmCrtc>> crtcs;
+    std::vector<std::unique_ptr<DrmConnector>> connectors;
+    std::vector<std::unique_ptr<DrmPlane>> planes;
+
+    drmModePlaneResPtr drmPlaneResources = drmModeGetPlaneResources(mFd.get());
+    for (uint32_t i = 0; i < drmPlaneResources->count_planes; ++i) {
+        const uint32_t planeId = drmPlaneResources->planes[i];
+
+        auto crtc = DrmPlane::create(mFd, planeId);
+        if (!crtc) {
+            ALOGE("%s: Failed to create DRM CRTC.", __FUNCTION__);
+            return false;
+        }
+
+        planes.emplace_back(std::move(crtc));
+    }
+    drmModeFreePlaneResources(drmPlaneResources);
+
+    drmModeRes* drmResources = drmModeGetResources(mFd.get());
+    for (uint32_t crtcIndex = 0; crtcIndex < drmResources->count_crtcs; crtcIndex++) {
+        const uint32_t crtcId = drmResources->crtcs[crtcIndex];
+
+        auto crtc = DrmCrtc::create(mFd, crtcId, crtcIndex);
+        if (!crtc) {
+            ALOGE("%s: Failed to create DRM CRTC.", __FUNCTION__);
+            return false;
+        }
+
+        crtcs.emplace_back(std::move(crtc));
+    }
+
+    for (uint32_t i = 0; i < drmResources->count_connectors; ++i) {
+        const uint32_t connectorId = drmResources->connectors[i];
+
+        auto connector = DrmConnector::create(mFd, connectorId);
+        if (!connector) {
+            ALOGE("%s: Failed to create DRM CRTC.", __FUNCTION__);
+            return false;
+        }
+
+        connectors.emplace_back(std::move(connector));
+    }
+
+    drmModeFreeResources(drmResources);
+
+    if (crtcs.size() != connectors.size()) {
+        ALOGE("%s: Failed assumption mCrtcs.size():%zu equals mConnectors.size():%zu", __FUNCTION__,
+              crtcs.size(), connectors.size());
+        return false;
+    }
+
+    for (uint32_t i = 0; i < crtcs.size(); i++) {
+        std::unique_ptr<DrmCrtc> crtc = std::move(crtcs[i]);
+        std::unique_ptr<DrmConnector> connector = std::move(connectors[i]);
+
+        auto planeIt =
+            std::find_if(planes.begin(), planes.end(), [&](const std::unique_ptr<DrmPlane>& plane) {
+                if (!plane->isOverlay() && !plane->isPrimary()) {
+                    return false;
+                }
+                return plane->isCompatibleWith(*crtc);
+            });
+        if (planeIt == planes.end()) {
+            ALOGE("%s: Failed to find plane for display:%" PRIu32, __FUNCTION__, i);
+            return false;
+        }
+
+        std::unique_ptr<DrmPlane> plane = std::move(*planeIt);
+        planes.erase(planeIt);
+
+        auto display =
+            DrmDisplay::create(i, std::move(connector), std::move(crtc), std::move(plane), mFd);
+        if (!display) {
+            return false;
+        }
+        mDisplays.push_back(std::move(display));
+    }
+
+    return true;
+}
+
+std::tuple<HWC3::Error, std::shared_ptr<DrmBuffer>> DrmClient::create(
+    const native_handle_t* handle) {
+    cros_gralloc_handle* crosHandle = (cros_gralloc_handle*)handle;
+    if (crosHandle == nullptr) {
+        ALOGE("%s: invalid cros_gralloc_handle", __FUNCTION__);
+        return std::make_tuple(HWC3::Error::NoResources, nullptr);
+    }
+
+    DrmPrimeBufferHandle primeHandle = 0;
+    int ret = drmPrimeFDToHandle(mFd.get(), crosHandle->fds[0], &primeHandle);
+    if (ret) {
+        ALOGE("%s: drmPrimeFDToHandle failed: %s (errno %d)", __FUNCTION__, strerror(errno), errno);
+        return std::make_tuple(HWC3::Error::NoResources, nullptr);
+    }
+
+    auto buffer = std::shared_ptr<DrmBuffer>(new DrmBuffer(*this));
+    buffer->mWidth = crosHandle->width;
+    buffer->mHeight = crosHandle->height;
+    buffer->mDrmFormat = crosHandle->format;
+    buffer->mPlaneFds[0] = crosHandle->fds[0];
+    buffer->mPlaneHandles[0] = primeHandle;
+    buffer->mPlanePitches[0] = crosHandle->strides[0];
+    buffer->mPlaneOffsets[0] = crosHandle->offsets[0];
+
+    uint32_t framebuffer = 0;
+    ret = drmModeAddFB2(mFd.get(), buffer->mWidth, buffer->mHeight, buffer->mDrmFormat,
+                        buffer->mPlaneHandles, buffer->mPlanePitches, buffer->mPlaneOffsets,
+                        &framebuffer, 0);
+    if (ret) {
+        ALOGE("%s: drmModeAddFB2 failed: %s (errno %d)", __FUNCTION__, strerror(errno), errno);
+        return std::make_tuple(HWC3::Error::NoResources, nullptr);
+    }
+    DEBUG_LOG("%s: created framebuffer:%" PRIu32, __FUNCTION__, framebuffer);
+    buffer->mDrmFramebuffer = framebuffer;
+
+    return std::make_tuple(HWC3::Error::None, std::shared_ptr<DrmBuffer>(buffer));
+}
+
+HWC3::Error DrmClient::destroyDrmFramebuffer(DrmBuffer* buffer) {
+    if (buffer->mDrmFramebuffer) {
+        uint32_t framebuffer = *buffer->mDrmFramebuffer;
+        if (drmModeRmFB(mFd.get(), framebuffer)) {
+            ALOGE("%s: drmModeRmFB failed: %s (errno %d)", __FUNCTION__, strerror(errno), errno);
+            return HWC3::Error::NoResources;
+        }
+        DEBUG_LOG("%s: destroyed framebuffer:%" PRIu32, __FUNCTION__, framebuffer);
+        buffer->mDrmFramebuffer.reset();
+    }
+    if (buffer->mPlaneHandles[0]) {
+        struct drm_gem_close gem_close = {};
+        gem_close.handle = buffer->mPlaneHandles[0];
+        if (drmIoctl(mFd.get(), DRM_IOCTL_GEM_CLOSE, &gem_close)) {
+            ALOGE("%s: DRM_IOCTL_GEM_CLOSE failed: %s (errno %d)", __FUNCTION__, strerror(errno),
+                  errno);
+            return HWC3::Error::NoResources;
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+bool DrmClient::handleHotplug() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    struct HotplugToReport {
+        uint32_t id;
+        uint32_t width;
+        uint32_t height;
+        uint32_t dpiX;
+        uint32_t dpiY;
+        uint32_t rr;
+        bool connected;
+    };
+
+    std::vector<HotplugToReport> hotplugs;
+
+    {
+        AutoWriteLock lock(mDisplaysMutex);
+
+        for (auto& display : mDisplays) {
+            auto change = display->checkAndHandleHotplug(mFd);
+            if (change == DrmHotplugChange::kNoChange) {
+                continue;
+            }
+
+            hotplugs.push_back(HotplugToReport{
+                .id = display->getId(),
+                .width = display->getWidth(),
+                .height = display->getHeight(),
+                .dpiX = display->getDpiX(),
+                .dpiY = display->getDpiY(),
+                .rr = display->getRefreshRateUint(),
+                .connected = change == DrmHotplugChange::kConnected,
+            });
+        }
+    }
+
+    for (const auto& hotplug : hotplugs) {
+        if (mHotplugCallback) {
+            (*mHotplugCallback)(hotplug.connected,  //
+                                hotplug.id,         //
+                                hotplug.width,      //
+                                hotplug.height,     //
+                                hotplug.dpiX,       //
+                                hotplug.dpiY,       //
+                                hotplug.rr);
+        }
+    }
+
+    return true;
+}
+
+std::tuple<HWC3::Error, ::android::base::unique_fd> DrmClient::flushToDisplay(
+    uint32_t displayId, const std::shared_ptr<DrmBuffer>& buffer,
+    ::android::base::borrowed_fd inSyncFd) {
+    ATRACE_CALL();
+
+    if (!buffer->mDrmFramebuffer) {
+        ALOGE("%s: failed, no framebuffer created.", __FUNCTION__);
+        return std::make_tuple(HWC3::Error::NoResources, ::android::base::unique_fd());
+    }
+
+    AutoReadLock lock(mDisplaysMutex);
+    return mDisplays[displayId]->flush(mFd, inSyncFd, buffer);
+}
+
+std::optional<std::vector<uint8_t>> DrmClient::getEdid(uint32_t displayId) {
+    AutoReadLock lock(mDisplaysMutex);
+
+    if (displayId >= mDisplays.size()) {
+        DEBUG_LOG("%s: invalid display:%" PRIu32, __FUNCTION__, displayId);
+        return std::nullopt;
+    }
+
+    return mDisplays[displayId]->getEdid();
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmClient.h b/hals/hwc3/DrmClient.h
new file mode 100644
index 00000000..3c8fd41b
--- /dev/null
+++ b/hals/hwc3/DrmClient.h
@@ -0,0 +1,111 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/unique_fd.h>
+#include <cutils/native_handle.h>
+
+#include <memory>
+#include <tuple>
+#include <vector>
+
+#include "Common.h"
+#include "DrmAtomicRequest.h"
+#include "DrmBuffer.h"
+#include "DrmConnector.h"
+#include "DrmCrtc.h"
+#include "DrmDisplay.h"
+#include "DrmEventListener.h"
+#include "DrmMode.h"
+#include "DrmPlane.h"
+#include "DrmProperty.h"
+#include "LruCache.h"
+#include "aemu/base/synchronization/AndroidLock.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmClient {
+   public:
+    DrmClient() = default;
+    ~DrmClient();
+
+    DrmClient(const DrmClient&) = delete;
+    DrmClient& operator=(const DrmClient&) = delete;
+
+    DrmClient(DrmClient&&) = delete;
+    DrmClient& operator=(DrmClient&&) = delete;
+
+    ::android::base::unique_fd OpenVirtioGpuDrmFd();
+
+    HWC3::Error init();
+
+    struct DisplayConfig {
+        uint32_t id;
+        uint32_t width;
+        uint32_t height;
+        uint32_t dpiX;
+        uint32_t dpiY;
+        uint32_t refreshRateHz;
+    };
+
+    HWC3::Error getDisplayConfigs(std::vector<DisplayConfig>* configs) const;
+
+    using HotplugCallback = std::function<void(bool /*connected*/,   //
+                                               uint32_t /*id*/,      //
+                                               uint32_t /*width*/,   //
+                                               uint32_t /*height*/,  //
+                                               uint32_t /*dpiX*/,    //
+                                               uint32_t /*dpiY*/,    //
+                                               uint32_t /*refreshRate*/)>;
+
+    HWC3::Error registerOnHotplugCallback(const HotplugCallback& cb);
+    HWC3::Error unregisterOnHotplugCallback();
+
+    uint32_t refreshRate() const { return mDisplays[0]->getRefreshRateUint(); }
+
+    std::tuple<HWC3::Error, std::shared_ptr<DrmBuffer>> create(const native_handle_t* handle);
+
+    std::tuple<HWC3::Error, ::android::base::unique_fd> flushToDisplay(
+        uint32_t displayId, const std::shared_ptr<DrmBuffer>& buffer,
+        ::android::base::borrowed_fd inWaitSyncFd);
+
+    std::optional<std::vector<uint8_t>> getEdid(uint32_t displayId);
+
+   private:
+    using DrmPrimeBufferHandle = uint32_t;
+
+    // Grant visibility to destroyDrmFramebuffer to DrmBuffer.
+    friend class DrmBuffer;
+    HWC3::Error destroyDrmFramebuffer(DrmBuffer* buffer);
+
+    // Grant visibility for handleHotplug to DrmEventListener.
+    bool handleHotplug();
+
+    bool loadDrmDisplays();
+
+    // Drm device.
+    ::android::base::unique_fd mFd;
+
+    mutable ::gfxstream::guest::ReadWriteLock mDisplaysMutex;
+    std::vector<std::unique_ptr<DrmDisplay>> mDisplays;
+
+    std::optional<HotplugCallback> mHotplugCallback;
+
+    std::unique_ptr<DrmEventListener> mDrmEventListener;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmConnector.cpp b/hals/hwc3/DrmConnector.cpp
new file mode 100644
index 00000000..a7b67299
--- /dev/null
+++ b/hals/hwc3/DrmConnector.cpp
@@ -0,0 +1,187 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmConnector.h"
+
+#include <span>
+
+#include "EdidInfo.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+static constexpr const float kMillimetersPerInch = 25.4f;
+
+}  // namespace
+
+std::unique_ptr<DrmConnector> DrmConnector::create(::android::base::borrowed_fd drmFd,
+                                                   uint32_t connectorId) {
+    std::unique_ptr<DrmConnector> connector(new DrmConnector(connectorId));
+
+    if (!connector->update(drmFd)) {
+        return nullptr;
+    }
+
+    return connector;
+}
+
+bool DrmConnector::update(::android::base::borrowed_fd drmFd) {
+    DEBUG_LOG("%s: Loading properties for connector:%" PRIu32, __FUNCTION__, mId);
+
+    if (!LoadDrmProperties(drmFd, mId, DRM_MODE_OBJECT_CONNECTOR, GetPropertiesMap(),
+                           this)) {
+        ALOGE("%s: Failed to load connector properties.", __FUNCTION__);
+        return false;
+    }
+
+
+    drmModeConnector* drmConnector = drmModeGetConnector(drmFd.get(), mId);
+    if (!drmConnector) {
+        ALOGE("%s: Failed to load connector.", __FUNCTION__);
+        return false;
+    }
+
+    mStatus = drmConnector->connection;
+
+    mModes.clear();
+    for (uint32_t i = 0; i < drmConnector->count_modes; i++) {
+        auto mode = DrmMode::create(drmFd, drmConnector->modes[i]);
+        if (!mode) {
+            ALOGE("%s: Failed to create mode for connector.", __FUNCTION__);
+            return false;
+        }
+
+        mModes.push_back(std::move(mode));
+    }
+
+
+    if (mStatus == DRM_MODE_CONNECTED) {
+        std::optional<EdidInfo> maybeEdidInfo = loadEdid(drmFd);
+        if (maybeEdidInfo) {
+            const EdidInfo& edidInfo = maybeEdidInfo.value();
+            mWidthMillimeters = edidInfo.mWidthMillimeters;
+            mHeightMillimeters = edidInfo.mHeightMillimeters;
+        } else {
+            ALOGW("%s: Use fallback size from drmModeConnector. This can result inaccurate DPIs.",
+                  __FUNCTION__);
+            mWidthMillimeters = drmConnector->mmWidth;
+            mHeightMillimeters = drmConnector->mmHeight;
+        }
+    }
+
+    DEBUG_LOG("%s: connector:%" PRIu32 " widthMillimeters:%" PRIu32 " heightMillimeters:%" PRIu32,
+              __FUNCTION__, mId, (mWidthMillimeters ? *mWidthMillimeters : 0),
+              (mHeightMillimeters ? *mHeightMillimeters : 0));
+
+    drmModeFreeConnector(drmConnector);
+    return true;
+}
+
+std::optional<EdidInfo> DrmConnector::loadEdid(::android::base::borrowed_fd drmFd) {
+    DEBUG_LOG("%s: display:%" PRIu32, __FUNCTION__, mId);
+
+    const uint64_t edidBlobId = mEdidProp.getValue();
+    if (edidBlobId == -1) {
+        ALOGW("%s: display:%" PRIu32 " does not have EDID.", __FUNCTION__, mId);
+        return std::nullopt;
+    }
+
+    auto blob = drmModeGetPropertyBlob(drmFd.get(), static_cast<uint32_t>(edidBlobId));
+    if (!blob) {
+        ALOGE("%s: display:%" PRIu32 " failed to read EDID blob (%" PRIu64 "): %s", __FUNCTION__,
+              mId, edidBlobId, strerror(errno));
+        return std::nullopt;
+    }
+
+    const uint8_t* blobStart = static_cast<uint8_t*>(blob->data);
+    mEdid = std::vector<uint8_t>(blobStart, blobStart + blob->length);
+
+    drmModeFreePropertyBlob(blob);
+
+    using byte_view = std::span<const uint8_t>;
+    byte_view edid(*mEdid);
+
+    return EdidInfo::parse(edid);
+}
+
+uint32_t DrmConnector::getWidth() const {
+    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);
+
+    if (mModes.empty()) {
+        return 0;
+    }
+    return mModes[0]->hdisplay;
+}
+
+uint32_t DrmConnector::getHeight() const {
+    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);
+
+    if (mModes.empty()) {
+        return 0;
+    }
+    return mModes[0]->vdisplay;
+}
+
+uint32_t DrmConnector::getDpiX() const {
+    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);
+
+    if (mModes.empty()) {
+        return 0;
+    }
+
+    const auto& mode = mModes[0];
+    if (mWidthMillimeters) {
+        const uint32_t dpi = static_cast<uint32_t>(
+            (static_cast<float>(mode->hdisplay) / static_cast<float>(*mWidthMillimeters)) *
+            kMillimetersPerInch);
+        DEBUG_LOG("%s: connector:%" PRIu32 " has dpi-x:%" PRIu32, __FUNCTION__, mId, dpi);
+        return dpi;
+    }
+
+    return 0;
+}
+
+uint32_t DrmConnector::getDpiY() const {
+    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);
+
+    if (mModes.empty()) {
+        return 0;
+    }
+
+    const auto& mode = mModes[0];
+    if (mHeightMillimeters) {
+        const uint32_t dpi = static_cast<uint32_t>(
+            (static_cast<float>(mode->vdisplay) / static_cast<float>(*mHeightMillimeters)) *
+            kMillimetersPerInch);
+        DEBUG_LOG("%s: connector:%" PRIu32 " has dpi-x:%" PRIu32, __FUNCTION__, mId, dpi);
+        return dpi;
+    }
+
+    return 0;
+}
+
+float DrmConnector::getRefreshRate() const {
+    DEBUG_LOG("%s: connector:%" PRIu32, __FUNCTION__, mId);
+
+    if (!mModes.empty()) {
+        const auto& mode = mModes[0];
+        return 1000.0f * mode->clock / ((float)mode->vtotal * (float)mode->htotal);
+    }
+
+    return -1.0f;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmConnector.h b/hals/hwc3/DrmConnector.h
new file mode 100644
index 00000000..f908631d
--- /dev/null
+++ b/hals/hwc3/DrmConnector.h
@@ -0,0 +1,91 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <memory>
+#include <optional>
+#include <string>
+#include <unordered_map>
+
+#include "Common.h"
+#include "DrmMode.h"
+#include "DrmProperty.h"
+#include "EdidInfo.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+// A "cable" to the display (HDMI, DisplayPort, etc).
+class DrmConnector {
+   public:
+    static std::unique_ptr<DrmConnector> create(::android::base::borrowed_fd drmFd,
+                                                uint32_t connectorId);
+    ~DrmConnector(){};
+
+    uint32_t getId() const { return mId; }
+
+    uint32_t getWidth() const;
+    uint32_t getHeight() const;
+
+    uint32_t getDpiX() const;
+    uint32_t getDpiY() const;
+
+    float getRefreshRate() const;
+    uint32_t getRefreshRateUint() const { return (uint32_t)(getRefreshRate() + 0.5f); }
+
+    bool isConnected() const { return mStatus == DRM_MODE_CONNECTED; }
+
+    std::optional<std::vector<uint8_t>> getEdid() const { return mEdid; }
+
+    const DrmProperty& getCrtcProperty() const { return mCrtc; }
+    const DrmMode* getDefaultMode() const { return mModes[0].get(); }
+
+    bool update(::android::base::borrowed_fd drmFd);
+
+   private:
+    DrmConnector(uint32_t id) : mId(id) {}
+
+    std::optional<EdidInfo> loadEdid(::android::base::borrowed_fd drmFd);
+
+    const uint32_t mId;
+
+    drmModeConnection mStatus = DRM_MODE_UNKNOWNCONNECTION;
+    std::optional<uint32_t> mWidthMillimeters;
+    std::optional<uint32_t> mHeightMillimeters;
+    std::vector<std::unique_ptr<DrmMode>> mModes;
+
+    DrmProperty mCrtc;
+    DrmProperty mEdidProp;
+    std::optional<std::vector<uint8_t>> mEdid;
+
+    static const auto& GetPropertiesMap() {
+        static const auto* sMap = []() {
+            return new DrmPropertyMemberMap<DrmConnector>{
+                {"CRTC_ID", &DrmConnector::mCrtc},
+                {"EDID", &DrmConnector::mEdidProp},
+            };
+        }();
+        return *sMap;
+    }
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmCrtc.cpp b/hals/hwc3/DrmCrtc.cpp
new file mode 100644
index 00000000..4648a9fb
--- /dev/null
+++ b/hals/hwc3/DrmCrtc.cpp
@@ -0,0 +1,34 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmCrtc.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+std::unique_ptr<DrmCrtc> DrmCrtc::create(::android::base::borrowed_fd drmFd, uint32_t crtcId,
+                                         uint32_t crtcIndexInResourcesArray) {
+    std::unique_ptr<DrmCrtc> crtc(new DrmCrtc(crtcId, crtcIndexInResourcesArray));
+
+    DEBUG_LOG("%s: Loading properties for crtc:%" PRIu32, __FUNCTION__, crtcId);
+    if (!LoadDrmProperties(drmFd, crtcId, DRM_MODE_OBJECT_CRTC, GetPropertiesMap(), crtc.get())) {
+        ALOGE("%s: Failed to load crtc properties.", __FUNCTION__);
+        return nullptr;
+    }
+
+    return crtc;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmCrtc.h b/hals/hwc3/DrmCrtc.h
new file mode 100644
index 00000000..6dcd93bd
--- /dev/null
+++ b/hals/hwc3/DrmCrtc.h
@@ -0,0 +1,70 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <memory>
+#include <string>
+#include <unordered_map>
+
+#include "Common.h"
+#include "DrmProperty.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmCrtc {
+   public:
+    static std::unique_ptr<DrmCrtc> create(::android::base::borrowed_fd drmFd, uint32_t crtcId,
+                                           uint32_t crtcIndexInResourcesArray);
+    ~DrmCrtc() {}
+
+    uint32_t getId() const { return mId; }
+
+    const DrmProperty& getActiveProperty() const { return mActive; }
+    const DrmProperty& getModeProperty() const { return mMode; }
+    const DrmProperty& getOutFenceProperty() const { return mOutFence; }
+
+   private:
+    DrmCrtc(uint32_t id, uint32_t index) : mId(id), mIndexInResourcesArray(index) {}
+
+    friend class DrmPlane;
+
+    const uint32_t mId;
+    const uint32_t mIndexInResourcesArray;
+
+    DrmProperty mActive;
+    DrmProperty mMode;
+    DrmProperty mOutFence;
+
+    static const auto& GetPropertiesMap() {
+        static const auto* sMap = []() {
+            return new DrmPropertyMemberMap<DrmCrtc>{
+                {"ACTIVE", &DrmCrtc::mActive},
+                {"MODE_ID", &DrmCrtc::mMode},
+                {"OUT_FENCE_PTR", &DrmCrtc::mOutFence},
+            };
+        }();
+        return *sMap;
+    }
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmDisplay.cpp b/hals/hwc3/DrmDisplay.cpp
new file mode 100644
index 00000000..182fce5e
--- /dev/null
+++ b/hals/hwc3/DrmDisplay.cpp
@@ -0,0 +1,185 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmDisplay.h"
+
+#include "DrmAtomicRequest.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+template <typename T>
+uint64_t addressAsUint(T* pointer) {
+    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(pointer));
+}
+
+}  // namespace
+
+std::unique_ptr<DrmDisplay> DrmDisplay::create(uint32_t id, std::unique_ptr<DrmConnector> connector,
+                                               std::unique_ptr<DrmCrtc> crtc,
+                                               std::unique_ptr<DrmPlane> plane,
+                                               ::android::base::borrowed_fd drmFd) {
+    if (!crtc) {
+        ALOGE("%s: invalid crtc.", __FUNCTION__);
+        return nullptr;
+    }
+    if (!connector) {
+        ALOGE("%s: invalid connector.", __FUNCTION__);
+        return nullptr;
+    }
+    if (!plane) {
+        ALOGE("%s: invalid plane.", __FUNCTION__);
+        return nullptr;
+    }
+
+    if (connector->isConnected()) {
+        auto request = DrmAtomicRequest::create();
+        if (!request) {
+            ALOGE("%s: failed to create atomic request.", __FUNCTION__);
+            return nullptr;
+        }
+
+        bool okay = true;
+        okay &= request->Set(connector->getId(), connector->getCrtcProperty(), crtc->getId());
+        okay &= request->Set(crtc->getId(), crtc->getActiveProperty(), 1);
+        okay &= request->Set(crtc->getId(), crtc->getModeProperty(),
+                             connector->getDefaultMode()->getBlobId());
+        okay &= request->Commit(drmFd);
+        if (!okay) {
+            ALOGE("%s: failed to set display mode.", __FUNCTION__);
+            return nullptr;
+        }
+    }
+
+    return std::unique_ptr<DrmDisplay>(
+        new DrmDisplay(id, std::move(connector), std::move(crtc), std::move(plane)));
+}
+
+std::tuple<HWC3::Error, ::android::base::unique_fd> DrmDisplay::flush(
+    ::android::base::borrowed_fd drmFd, ::android::base::borrowed_fd inSyncFd,
+    const std::shared_ptr<DrmBuffer>& buffer) {
+    std::unique_ptr<DrmAtomicRequest> request = DrmAtomicRequest::create();
+    if (!request) {
+        ALOGE("%s: failed to create atomic request.", __FUNCTION__);
+        return std::make_tuple(HWC3::Error::NoResources, ::android::base::unique_fd());
+    }
+
+    int flushFenceFd = -1;
+
+    bool okay = true;
+    okay &=
+        request->Set(mCrtc->getId(), mCrtc->getOutFenceProperty(), addressAsUint(&flushFenceFd));
+    okay &= request->Set(mPlane->getId(), mPlane->getCrtcProperty(), mCrtc->getId());
+    if (inSyncFd != -1) {
+        okay &= request->Set(mPlane->getId(), mPlane->getInFenceProperty(),
+                             static_cast<uint64_t>(inSyncFd.get()));
+    }
+    okay &= request->Set(mPlane->getId(), mPlane->getFbProperty(), *buffer->mDrmFramebuffer);
+    okay &= request->Set(mPlane->getId(), mPlane->getCrtcXProperty(), 0);
+    okay &= request->Set(mPlane->getId(), mPlane->getCrtcYProperty(), 0);
+    okay &= request->Set(mPlane->getId(), mPlane->getCrtcWProperty(), buffer->mWidth);
+    okay &= request->Set(mPlane->getId(), mPlane->getCrtcHProperty(), buffer->mHeight);
+    okay &= request->Set(mPlane->getId(), mPlane->getSrcXProperty(), 0);
+    okay &= request->Set(mPlane->getId(), mPlane->getSrcYProperty(), 0);
+    okay &= request->Set(mPlane->getId(), mPlane->getSrcWProperty(), buffer->mWidth << 16);
+    okay &= request->Set(mPlane->getId(), mPlane->getSrcHProperty(), buffer->mHeight << 16);
+
+    okay &= request->Commit(drmFd);
+    if (!okay) {
+        ALOGE("%s: failed to flush to display.", __FUNCTION__);
+        return std::make_tuple(HWC3::Error::NoResources, ::android::base::unique_fd());
+    }
+
+    mPreviousBuffer = buffer;
+
+    DEBUG_LOG("%s: submitted atomic update, flush fence:%d\n", __FUNCTION__, flushFenceFd);
+    return std::make_tuple(HWC3::Error::None, ::android::base::unique_fd(flushFenceFd));
+}
+
+bool DrmDisplay::onConnect(::android::base::borrowed_fd drmFd) {
+    DEBUG_LOG("%s: display:%" PRIu32, __FUNCTION__, mId);
+
+    auto request = DrmAtomicRequest::create();
+    if (!request) {
+        ALOGE("%s: display:%" PRIu32 " failed to create atomic request.", __FUNCTION__, mId);
+        return false;
+    }
+
+    bool okay = true;
+    okay &= request->Set(mConnector->getId(), mConnector->getCrtcProperty(), mCrtc->getId());
+    okay &= request->Set(mCrtc->getId(), mCrtc->getActiveProperty(), 1);
+    okay &= request->Set(mCrtc->getId(), mCrtc->getModeProperty(),
+                         mConnector->getDefaultMode()->getBlobId());
+
+    okay &= request->Commit(drmFd);
+    if (!okay) {
+        ALOGE("%s: display:%" PRIu32 " failed to set mode.", __FUNCTION__, mId);
+        return false;
+    }
+
+    return true;
+}
+
+bool DrmDisplay::onDisconnect(::android::base::borrowed_fd drmFd) {
+    DEBUG_LOG("%s: display:%" PRIu32, __FUNCTION__, mId);
+
+    auto request = DrmAtomicRequest::create();
+    if (!request) {
+        ALOGE("%s: display:%" PRIu32 " failed to create atomic request.", __FUNCTION__, mId);
+        return false;
+    }
+
+    bool okay = true;
+    okay &= request->Set(mPlane->getId(), mPlane->getCrtcProperty(), 0);
+    okay &= request->Set(mPlane->getId(), mPlane->getFbProperty(), 0);
+
+    okay &= request->Commit(drmFd);
+    if (!okay) {
+        ALOGE("%s: display:%" PRIu32 " failed to set mode", __FUNCTION__, mId);
+    }
+
+    mPreviousBuffer.reset();
+
+    return okay;
+}
+
+DrmHotplugChange DrmDisplay::checkAndHandleHotplug(::android::base::borrowed_fd drmFd) {
+    DEBUG_LOG("%s: display:%" PRIu32, __FUNCTION__, mId);
+
+    const bool oldConnected = mConnector->isConnected();
+    mConnector->update(drmFd);
+    const bool newConnected = mConnector->isConnected();
+
+    if (oldConnected == newConnected) {
+        return DrmHotplugChange::kNoChange;
+    }
+
+    if (newConnected) {
+        ALOGI("%s: display:%" PRIu32 " was connected.", __FUNCTION__, mId);
+        if (!onConnect(drmFd)) {
+            ALOGE("%s: display:%" PRIu32 " failed to connect.", __FUNCTION__, mId);
+        }
+        return DrmHotplugChange::kConnected;
+    } else {
+        ALOGI("%s: display:%" PRIu32 " was disconnected.", __FUNCTION__, mId);
+        if (!onDisconnect(drmFd)) {
+            ALOGE("%s: display:%" PRIu32 " failed to disconnect.", __FUNCTION__, mId);
+        }
+        return DrmHotplugChange::kDisconnected;
+    }
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmDisplay.h b/hals/hwc3/DrmDisplay.h
new file mode 100644
index 00000000..0a349c7b
--- /dev/null
+++ b/hals/hwc3/DrmDisplay.h
@@ -0,0 +1,92 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <memory>
+#include <string>
+#include <unordered_map>
+
+#include "Common.h"
+#include "DrmBuffer.h"
+#include "DrmConnector.h"
+#include "DrmCrtc.h"
+#include "DrmPlane.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+enum class DrmHotplugChange {
+    kNoChange,
+    kConnected,
+    kDisconnected,
+};
+
+class DrmDisplay {
+   public:
+    static std::unique_ptr<DrmDisplay> create(uint32_t id, std::unique_ptr<DrmConnector> connector,
+                                              std::unique_ptr<DrmCrtc> crtc,
+                                              std::unique_ptr<DrmPlane> plane,
+                                              ::android::base::borrowed_fd drmFd);
+
+    uint32_t getId() const { return mId; }
+
+    uint32_t getWidth() const { return mConnector->getWidth(); }
+    uint32_t getHeight() const { return mConnector->getHeight(); }
+
+    uint32_t getDpiX() const { return mConnector->getDpiX(); }
+    uint32_t getDpiY() const { return mConnector->getDpiY(); }
+
+    uint32_t getRefreshRateUint() const { return mConnector->getRefreshRateUint(); }
+
+    bool isConnected() const { return mConnector->isConnected(); }
+
+    std::optional<std::vector<uint8_t>> getEdid() const { return mConnector->getEdid(); }
+
+    std::tuple<HWC3::Error, ::android::base::unique_fd> flush(
+        ::android::base::borrowed_fd drmFd, ::android::base::borrowed_fd inWaitSyncFd,
+        const std::shared_ptr<DrmBuffer>& buffer);
+
+    DrmHotplugChange checkAndHandleHotplug(::android::base::borrowed_fd drmFd);
+
+   private:
+    DrmDisplay(uint32_t id, std::unique_ptr<DrmConnector> connector, std::unique_ptr<DrmCrtc> crtc,
+               std::unique_ptr<DrmPlane> plane)
+        : mId(id),
+          mConnector(std::move(connector)),
+          mCrtc(std::move(crtc)),
+          mPlane(std::move(plane)) {}
+
+    bool onConnect(::android::base::borrowed_fd drmFd);
+
+    bool onDisconnect(::android::base::borrowed_fd drmFd);
+
+    const uint32_t mId;
+    std::unique_ptr<DrmConnector> mConnector;
+    std::unique_ptr<DrmCrtc> mCrtc;
+    std::unique_ptr<DrmPlane> mPlane;
+
+    // The last presented buffer / DRM framebuffer is cached until
+    // the next present to avoid toggling the display on and off.
+    std::shared_ptr<DrmBuffer> mPreviousBuffer;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmEventListener.cpp b/hals/hwc3/DrmEventListener.cpp
new file mode 100644
index 00000000..e56f50c3
--- /dev/null
+++ b/hals/hwc3/DrmEventListener.cpp
@@ -0,0 +1,101 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmEventListener.h"
+
+#include <linux/netlink.h>
+#include <sys/socket.h>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+std::unique_ptr<DrmEventListener> DrmEventListener::create(::android::base::borrowed_fd drmFd,
+                                                           std::function<void()> callback) {
+    std::unique_ptr<DrmEventListener> listener(new DrmEventListener(std::move(callback)));
+
+    if (!listener->init(drmFd)) {
+        return nullptr;
+    }
+
+    return listener;
+}
+
+bool DrmEventListener::init(::android::base::borrowed_fd drmFd) {
+    mEventFd = ::android::base::unique_fd(socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT));
+    if (!mEventFd.ok()) {
+        ALOGE("Failed to open uevent socket: %s", strerror(errno));
+        return false;
+    }
+    struct sockaddr_nl addr;
+    memset(&addr, 0, sizeof(addr));
+    addr.nl_family = AF_NETLINK;
+    addr.nl_pid = 0;
+    addr.nl_groups = 0xFFFFFFFF;
+
+    int ret = bind(mEventFd, (struct sockaddr*)&addr, sizeof(addr));
+    if (ret) {
+        ALOGE("Failed to bind uevent socket: %s", strerror(errno));
+        return false;
+    }
+
+    FD_ZERO(&mMonitoredFds);
+    FD_SET(drmFd.get(), &mMonitoredFds);
+    FD_SET(mEventFd.get(), &mMonitoredFds);
+    mMaxMonitoredFd = std::max(drmFd.get(), mEventFd.get());
+
+    mThread = std::thread([this]() { threadLoop(); });
+
+    return true;
+}
+
+void DrmEventListener::threadLoop() {
+    int ret;
+    do {
+        ret = select(mMaxMonitoredFd + 1, &mMonitoredFds, NULL, NULL, NULL);
+    } while (ret == -1 && errno == EINTR);
+
+    if (!FD_ISSET(mEventFd.get(), &mMonitoredFds)) {
+        ALOGE("%s: DrmEventListevener event fd unset?", __FUNCTION__);
+        return;
+    }
+
+    char buffer[1024];
+    while (true) {
+        ssize_t ret = read(mEventFd.get(), &buffer, sizeof(buffer));
+        if (ret == 0) {
+            return;
+        } else if (ret < 0) {
+            ALOGE("Got error reading uevent %zd", ret);
+            return;
+        }
+        // Replace all but the last `\0` to potentially not affect string
+        // operations which look for `\0`.
+        for (ssize_t i = 0; i < ret - 1; i++) {
+            if (buffer[i] == '\0') {
+                buffer[i] = '\n';
+            }
+        }
+        const std::string events = std::string(buffer, static_cast<size_t>(ret));
+
+        const bool hasEventDrm = events.find("DEVTYPE=drm_minor") != std::string::npos;
+        const bool hasEventHotplug = events.find("HOTPLUG=1") != std::string::npos;
+        if (hasEventDrm && hasEventHotplug) {
+            DEBUG_LOG("DrmEventListener detected hotplug event .");
+            mOnEventCallback();
+        }
+    }
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmEventListener.h b/hals/hwc3/DrmEventListener.h
new file mode 100644
index 00000000..4ab29b61
--- /dev/null
+++ b/hals/hwc3/DrmEventListener.h
@@ -0,0 +1,55 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <functional>
+#include <optional>
+#include <thread>
+#include <unordered_map>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmEventListener {
+   public:
+    static std::unique_ptr<DrmEventListener> create(::android::base::borrowed_fd drmFd,
+                                                    std::function<void()> callback);
+
+    ~DrmEventListener() {}
+
+   private:
+    DrmEventListener(std::function<void()> callback) : mOnEventCallback(std::move(callback)) {}
+
+    bool init(::android::base::borrowed_fd drmFd);
+
+    void threadLoop();
+
+    std::thread mThread;
+    std::function<void()> mOnEventCallback;
+    ::android::base::unique_fd mEventFd;
+    fd_set mMonitoredFds;
+    int mMaxMonitoredFd = 0;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmMode.cpp b/hals/hwc3/DrmMode.cpp
new file mode 100644
index 00000000..d65f0cc9
--- /dev/null
+++ b/hals/hwc3/DrmMode.cpp
@@ -0,0 +1,38 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmMode.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+std::unique_ptr<DrmMode> DrmMode::create(::android::base::borrowed_fd drmFd,
+                                         const drmModeModeInfo& info) {
+    uint32_t blobId = 0;
+
+    int ret = drmModeCreatePropertyBlob(drmFd.get(), &info, sizeof(info), &blobId);
+    if (ret != 0) {
+        ALOGE("%s: Failed to create mode blob: %s.", __FUNCTION__, strerror(errno));
+        return nullptr;
+    }
+
+    return std::unique_ptr<DrmMode>(new DrmMode(info, blobId));
+}
+
+DrmMode::~DrmMode() {
+    // TODO: don't leak the blob.
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmMode.h b/hals/hwc3/DrmMode.h
new file mode 100644
index 00000000..23b170de
--- /dev/null
+++ b/hals/hwc3/DrmMode.h
@@ -0,0 +1,78 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <memory>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmMode {
+   public:
+    static std::unique_ptr<DrmMode> create(::android::base::borrowed_fd drmFd,
+                                           const drmModeModeInfo& info);
+
+    ~DrmMode();
+
+    const uint32_t clock;
+    const uint16_t hdisplay;
+    const uint16_t hsync_start;
+    const uint16_t hsync_end;
+    const uint16_t htotal;
+    const uint16_t hskew;
+    const uint16_t vdisplay;
+    const uint16_t vsync_start;
+    const uint16_t vsync_end;
+    const uint16_t vtotal;
+    const uint16_t vscan;
+    const uint32_t vrefresh;
+    const uint32_t flags;
+    const uint32_t type;
+    const std::string name;
+
+    uint32_t getBlobId() const { return mBlobId; }
+
+   private:
+    DrmMode(const drmModeModeInfo& info, uint32_t blobId)
+        : clock(info.clock),
+          hdisplay(info.hdisplay),
+          hsync_start(info.hsync_start),
+          hsync_end(info.hsync_end),
+          htotal(info.htotal),
+          hskew(info.hskew),
+          vdisplay(info.vdisplay),
+          vsync_start(info.vsync_start),
+          vsync_end(info.vsync_end),
+          vtotal(info.vtotal),
+          vscan(info.vscan),
+          vrefresh(info.vrefresh),
+          flags(info.flags),
+          type(info.type),
+          name(info.name),
+          mBlobId(blobId) {}
+
+    const uint32_t mBlobId;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmPlane.cpp b/hals/hwc3/DrmPlane.cpp
new file mode 100644
index 00000000..f2027ee2
--- /dev/null
+++ b/hals/hwc3/DrmPlane.cpp
@@ -0,0 +1,46 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "DrmPlane.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+std::unique_ptr<DrmPlane> DrmPlane::create(::android::base::borrowed_fd drmFd, uint32_t planeId) {
+    std::unique_ptr<DrmPlane> plane(new DrmPlane(planeId));
+
+    DEBUG_LOG("%s: Loading properties for DRM plane:%" PRIu32, __FUNCTION__, planeId);
+    if (!LoadDrmProperties(drmFd, planeId, DRM_MODE_OBJECT_PLANE, GetPropertiesMap(),
+                           plane.get())) {
+        ALOGE("%s: Failed to load plane properties.", __FUNCTION__);
+        return nullptr;
+    }
+
+    drmModePlanePtr drmPlane = drmModeGetPlane(drmFd.get(), planeId);
+    plane->mPossibleCrtcsMask = drmPlane->possible_crtcs;
+    drmModeFreePlane(drmPlane);
+
+    return plane;
+}
+
+bool DrmPlane::isPrimary() const { return mType.getValue() == DRM_PLANE_TYPE_PRIMARY; }
+
+bool DrmPlane::isOverlay() const { return mType.getValue() == DRM_PLANE_TYPE_OVERLAY; }
+
+bool DrmPlane::isCompatibleWith(const DrmCrtc& crtc) {
+    return ((0x1 << crtc.mIndexInResourcesArray) & mPossibleCrtcsMask);
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmPlane.h b/hals/hwc3/DrmPlane.h
new file mode 100644
index 00000000..b2447566
--- /dev/null
+++ b/hals/hwc3/DrmPlane.h
@@ -0,0 +1,100 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <memory>
+#include <string>
+#include <unordered_map>
+
+#include "Common.h"
+#include "DrmCrtc.h"
+#include "DrmProperty.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmPlane {
+   public:
+    static std::unique_ptr<DrmPlane> create(::android::base::borrowed_fd drmFd, uint32_t planeId);
+    ~DrmPlane(){};
+
+    uint32_t getId() const { return mId; }
+
+    bool isPrimary() const;
+    bool isOverlay() const;
+
+    bool isCompatibleWith(const DrmCrtc& crtc);
+
+    const DrmProperty& getCrtcProperty() const { return mCrtc; }
+    const DrmProperty& getInFenceProperty() const { return mInFenceFd; }
+    const DrmProperty& getFbProperty() const { return mFb; }
+    const DrmProperty& getCrtcXProperty() const { return mCrtcX; }
+    const DrmProperty& getCrtcYProperty() const { return mCrtcY; }
+    const DrmProperty& getCrtcWProperty() const { return mCrtcW; }
+    const DrmProperty& getCrtcHProperty() const { return mCrtcH; }
+    const DrmProperty& getSrcXProperty() const { return mSrcX; }
+    const DrmProperty& getSrcYProperty() const { return mSrcY; }
+    const DrmProperty& getSrcWProperty() const { return mSrcW; }
+    const DrmProperty& getSrcHProperty() const { return mSrcH; }
+
+   private:
+    DrmPlane(uint32_t id) : mId(id){};
+
+    const uint32_t mId;
+
+    uint32_t mPossibleCrtcsMask = 0;
+
+    DrmProperty mCrtc;
+    DrmProperty mInFenceFd;
+    DrmProperty mFb;
+    DrmProperty mCrtcX;
+    DrmProperty mCrtcY;
+    DrmProperty mCrtcW;
+    DrmProperty mCrtcH;
+    DrmProperty mSrcX;
+    DrmProperty mSrcY;
+    DrmProperty mSrcW;
+    DrmProperty mSrcH;
+    DrmProperty mType;
+
+    static const auto& GetPropertiesMap() {
+        static const auto* sMap = []() {
+            return new DrmPropertyMemberMap<DrmPlane>{
+                {"CRTC_ID", &DrmPlane::mCrtc},
+                {"CRTC_X", &DrmPlane::mCrtcX},
+                {"CRTC_Y", &DrmPlane::mCrtcY},
+                {"CRTC_W", &DrmPlane::mCrtcW},
+                {"CRTC_H", &DrmPlane::mCrtcH},
+                {"FB_ID", &DrmPlane::mFb},
+                {"IN_FENCE_FD", &DrmPlane::mInFenceFd},
+                {"SRC_X", &DrmPlane::mSrcX},
+                {"SRC_Y", &DrmPlane::mSrcY},
+                {"SRC_W", &DrmPlane::mSrcW},
+                {"SRC_H", &DrmPlane::mSrcH},
+                {"type", &DrmPlane::mType},
+            };
+        }();
+        return *sMap;
+    }
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmProperty.h b/hals/hwc3/DrmProperty.h
new file mode 100644
index 00000000..d52cd9de
--- /dev/null
+++ b/hals/hwc3/DrmProperty.h
@@ -0,0 +1,98 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#pragma once
+
+#include <android-base/logging.h>
+#include <android-base/unique_fd.h>
+#include <xf86drm.h>
+#include <xf86drmMode.h>
+
+#include <cstdint>
+#include <limits>
+#include <string>
+#include <unordered_map>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmProperty {
+   public:
+    DrmProperty() {}
+    DrmProperty(uint32_t id, uint64_t value, std::string name)
+        : mId(id), mValue(value), mName(name) {}
+
+    ~DrmProperty() {}
+
+    uint32_t getId() const { return mId; }
+
+    uint64_t getValue() const { return mValue; }
+
+    const std::string& getName() const { return mName; }
+
+   private:
+    uint32_t mId = std::numeric_limits<uint32_t>::max();
+    uint64_t mValue = std::numeric_limits<uint64_t>::max();
+    std::string mName;
+};
+
+template <typename T>
+using DrmPropertyMember = DrmProperty T::*;
+
+template <typename T>
+using DrmPropertyMemberMap = std::unordered_map<std::string, DrmPropertyMember<T>>;
+
+// Helper to many DrmProperty members for DrmCrtc, DrmConnector, and DrmPlane.
+template <typename T>
+bool LoadDrmProperties(::android::base::borrowed_fd drmFd, uint32_t objectId, uint32_t objectType,
+                       const DrmPropertyMemberMap<T>& objectPropertyMap, T* object) {
+    auto drmProperties = drmModeObjectGetProperties(drmFd.get(), objectId, objectType);
+    if (!drmProperties) {
+        ALOGE("%s: Failed to get properties: %s", __FUNCTION__, strerror(errno));
+        return false;
+    }
+
+    for (uint32_t i = 0; i < drmProperties->count_props; ++i) {
+        const auto propertyId = drmProperties->props[i];
+
+        auto drmProperty = drmModeGetProperty(drmFd.get(), propertyId);
+        if (!drmProperty) {
+            ALOGE("%s: Failed to get property: %s", __FUNCTION__, strerror(errno));
+            continue;
+        }
+
+        const auto propertyName = drmProperty->name;
+        const auto propertyValue = drmProperties->prop_values[i];
+
+        auto it = objectPropertyMap.find(propertyName);
+        if (it != objectPropertyMap.end()) {
+            DEBUG_LOG("%s: Loaded property:%" PRIu32 " (%s) val:%" PRIu64, __FUNCTION__, propertyId,
+                      propertyName, propertyValue);
+
+            auto& objectPointerToMember = it->second;
+            object->*objectPointerToMember = DrmProperty(propertyId, propertyValue, propertyName);
+        }
+
+        drmModeFreeProperty(drmProperty);
+    }
+
+    drmModeFreeObjectProperties(drmProperties);
+
+    return true;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/DrmSwapchain.cpp b/hals/hwc3/DrmSwapchain.cpp
new file mode 100644
index 00000000..ae891255
--- /dev/null
+++ b/hals/hwc3/DrmSwapchain.cpp
@@ -0,0 +1,104 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include "DrmSwapchain.h"
+
+#include <log/log.h>
+#include <sync/sync.h>
+#include <ui/GraphicBufferAllocator.h>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+DrmSwapchain::Image::Image(const native_handle_t* buffer, std::shared_ptr<DrmBuffer> drmBuffer)
+    : mBuffer(buffer), mDrmBuffer(drmBuffer) {}
+
+DrmSwapchain::Image::Image(Image&& other)
+    : mBuffer(std::move(other.mBuffer)),
+      mDrmBuffer(std::move(other.mDrmBuffer)),
+      mLastUseFenceFd(std::move(other.mLastUseFenceFd)) {
+    other.mBuffer = nullptr;
+}
+
+DrmSwapchain::Image::~Image() {
+    if (mBuffer) {
+        ::android::GraphicBufferAllocator::get().free(mBuffer);
+    }
+}
+
+int DrmSwapchain::Image::wait() {
+    if (!mLastUseFenceFd.ok()) {
+        return 0;
+    }
+    int err = sync_wait(mLastUseFenceFd.get(), 3000);
+    mLastUseFenceFd = ::android::base::unique_fd();
+    if (err < 0 && errno == ETIME) {
+        ALOGE("%s waited on fence %d for 3000 ms", __FUNCTION__, mLastUseFenceFd.get());
+    }
+    if (err < 0) {
+        return err;
+    }
+    return 0;
+}
+
+void DrmSwapchain::Image::markAsInUse(::android::base::unique_fd useCompleteFenceFd) {
+    mLastUseFenceFd = std::move(useCompleteFenceFd);
+}
+
+const native_handle_t* DrmSwapchain::Image::getBuffer() { return mBuffer; }
+
+const std::shared_ptr<DrmBuffer> DrmSwapchain::Image::getDrmBuffer() { return mDrmBuffer; }
+
+std::unique_ptr<DrmSwapchain> DrmSwapchain::create(uint32_t width, uint32_t height, uint32_t usage,
+                                                   DrmClient* client, uint32_t numImages) {
+    DEBUG_LOG("%s: creating swapchain w:%" PRIu32 " h:%" PRIu32 " usage:%" PRIu32 " count:%" PRIu32,
+              __FUNCTION__, width, height, usage, numImages);
+    std::vector<Image> images;
+    for (uint32_t i = 0; i < numImages; i++) {
+        const uint32_t layerCount = 1;
+        buffer_handle_t handle;
+        uint32_t stride;
+        if (::android::GraphicBufferAllocator::get().allocate(
+                width, height, ::android::PIXEL_FORMAT_RGBA_8888, layerCount, usage, &handle,
+                &stride, "RanchuHwc") != ::android::OK) {
+            ALOGE("%s: Failed to allocate drm ahb", __FUNCTION__);
+            return nullptr;
+        }
+        auto ahb = static_cast<const native_handle_t*>(handle);
+
+        HWC3::Error drmBufferCreateError;
+        std::shared_ptr<DrmBuffer> drmBuffer;
+        if (client) {
+            std::tie(drmBufferCreateError, drmBuffer) = client->create(ahb);
+            if (drmBufferCreateError != HWC3::Error::None) {
+                ALOGE("%s: failed to create target drm ahb", __FUNCTION__);
+                return nullptr;
+            }
+        }
+
+        images.emplace_back(Image(ahb, std::move(drmBuffer)));
+    }
+    return std::unique_ptr<DrmSwapchain>(new DrmSwapchain(std::move(images)));
+}
+
+DrmSwapchain::DrmSwapchain(std::vector<Image> images) : mImages(std::move(images)) {}
+
+DrmSwapchain::Image* DrmSwapchain::getNextImage() {
+    auto index = (mLastUsedIndex + 1) % mImages.size();
+    mLastUsedIndex = index;
+    return &mImages[index];
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hals/hwc3/DrmSwapchain.h b/hals/hwc3/DrmSwapchain.h
new file mode 100644
index 00000000..a26031c2
--- /dev/null
+++ b/hals/hwc3/DrmSwapchain.h
@@ -0,0 +1,59 @@
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
+#ifndef ANDROID_HWC_DRMSWAPCHAIN_H
+#define ANDROID_HWC_DRMSWAPCHAIN_H
+
+#include <android-base/unique_fd.h>
+
+#include "Common.h"
+#include "DrmClient.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmSwapchain {
+   public:
+    class Image {
+       public:
+        Image() = delete;
+        ~Image();
+        int wait();
+        void markAsInUse(::android::base::unique_fd useCompleteFenceFd);
+        const native_handle_t* getBuffer();
+        const std::shared_ptr<DrmBuffer> getDrmBuffer();
+        Image(Image&& other);
+
+       private:
+        Image(const native_handle_t*, std::shared_ptr<DrmBuffer>);
+        const native_handle_t* mBuffer = nullptr;
+        std::shared_ptr<DrmBuffer> mDrmBuffer;
+        ::android::base::unique_fd mLastUseFenceFd;
+
+        friend class DrmSwapchain;
+    };
+
+    static std::unique_ptr<DrmSwapchain> create(uint32_t width, uint32_t height, uint32_t usage,
+                                                DrmClient* client, uint32_t numImages = 3);
+    Image* getNextImage();
+
+   private:
+    DrmSwapchain(std::vector<Image> images);
+    std::vector<Image> mImages;
+    std::size_t mLastUsedIndex = 0;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
\ No newline at end of file
diff --git a/hals/hwc3/EdidInfo.cpp b/hals/hwc3/EdidInfo.cpp
new file mode 100644
index 00000000..e4b63fa6
--- /dev/null
+++ b/hals/hwc3/EdidInfo.cpp
@@ -0,0 +1,30 @@
+#include "EdidInfo.h"
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+std::optional<EdidInfo> EdidInfo::parse(std::span<const uint8_t> blob) {
+    constexpr size_t kEdidDescriptorOffset = 54;
+    constexpr size_t kEdidDescriptorLength = 18;
+
+    blob = blob.subspan(kEdidDescriptorOffset);
+
+    using byte_view = std::span<const uint8_t>;
+    byte_view descriptor(blob.data(), kEdidDescriptorLength);
+    if (descriptor[0] == 0 && descriptor[1] == 0) {
+        ALOGE("%s: missing preferred detailed timing descriptor", __FUNCTION__);
+        return std::nullopt;
+    }
+
+    const uint8_t w_mm_lsb = descriptor[12];
+    const uint8_t h_mm_lsb = descriptor[13];
+    const uint8_t w_and_h_mm_msb = descriptor[14];
+
+    return EdidInfo{
+        .mWidthMillimeters =
+            static_cast<uint32_t>(w_mm_lsb) | ((static_cast<uint32_t>(w_and_h_mm_msb) & 0xf0) << 4),
+        .mHeightMillimeters =
+            static_cast<uint32_t>(h_mm_lsb) | ((static_cast<uint32_t>(w_and_h_mm_msb) & 0xf) << 8),
+    };
+}
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/EdidInfo.h b/hals/hwc3/EdidInfo.h
new file mode 100644
index 00000000..bcccebfd
--- /dev/null
+++ b/hals/hwc3/EdidInfo.h
@@ -0,0 +1,16 @@
+#pragma once
+
+#include <cinttypes>
+#include <optional>
+#include <span>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+struct EdidInfo {
+    uint32_t mWidthMillimeters = 0;
+    uint32_t mHeightMillimeters = 0;
+
+    static std::optional<EdidInfo> parse(std::span<const uint8_t> blob);
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/FencedBuffer.h b/hals/hwc3/FencedBuffer.h
new file mode 100644
index 00000000..03f71f42
--- /dev/null
+++ b/hals/hwc3/FencedBuffer.h
@@ -0,0 +1,59 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_FENCEDBUFFER_H
+#define ANDROID_HWC_FENCEDBUFFER_H
+
+#include <aidlcommonsupport/NativeHandle.h>
+#include <android-base/unique_fd.h>
+#include <cutils/native_handle.h>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class FencedBuffer {
+   public:
+    FencedBuffer() : mBuffer(nullptr) {}
+
+    void set(buffer_handle_t buffer, const ndk::ScopedFileDescriptor& fence) {
+        mBuffer = buffer;
+        mFence = GetUniqueFd(fence);
+    }
+
+    buffer_handle_t getBuffer() const { return mBuffer; }
+
+    ::android::base::unique_fd getFence() const {
+        if (mFence.ok()) {
+            return ::android::base::unique_fd(dup(mFence.get()));
+        } else {
+            return ::android::base::unique_fd();
+        }
+    }
+
+   private:
+    static ::android::base::unique_fd GetUniqueFd(const ndk::ScopedFileDescriptor& in) {
+        auto& sfd = const_cast<ndk::ScopedFileDescriptor&>(in);
+        ::android::base::unique_fd ret(sfd.get());
+        *sfd.getR() = -1;
+        return ret;
+    }
+
+    buffer_handle_t mBuffer;
+    ::android::base::unique_fd mFence;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/FrameComposer.h b/hals/hwc3/FrameComposer.h
new file mode 100644
index 00000000..5e54561b
--- /dev/null
+++ b/hals/hwc3/FrameComposer.h
@@ -0,0 +1,76 @@
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
+#ifndef ANDROID_HWC_COMPOSER_H
+#define ANDROID_HWC_COMPOSER_H
+
+#include <android-base/unique_fd.h>
+
+#include <functional>
+#include <tuple>
+#include <unordered_map>
+#include <vector>
+
+#include "Common.h"
+#include "DisplayChanges.h"
+#include "DrmClient.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class Display;
+
+class FrameComposer {
+   public:
+    virtual ~FrameComposer() {}
+
+    virtual HWC3::Error init() = 0;
+
+    using HotplugCallback = std::function<void(bool /*connected*/,   //
+                                               uint32_t /*id*/,      //
+                                               uint32_t /*width*/,   //
+                                               uint32_t /*height*/,  //
+                                               uint32_t /*dpiX*/,    //
+                                               uint32_t /*dpiY*/,    //
+                                               uint32_t /*refreshRate*/)>;
+
+    virtual HWC3::Error registerOnHotplugCallback(const HotplugCallback& cb) = 0;
+
+    virtual HWC3::Error unregisterOnHotplugCallback() = 0;
+
+    virtual HWC3::Error onDisplayCreate(Display* display) = 0;
+
+    virtual HWC3::Error onDisplayDestroy(Display* display) = 0;
+
+    virtual HWC3::Error onDisplayClientTargetSet(Display* display) = 0;
+
+    // Determines if this composer can compose the given layers and requests
+    // changes for layers that can't not be composed.
+    virtual HWC3::Error validateDisplay(Display* display, DisplayChanges* outChanges) = 0;
+
+    // Performs the actual composition of layers and presents the composed result
+    // to the display.
+    virtual HWC3::Error presentDisplay(
+        Display* display, ::android::base::unique_fd* outDisplayFence,
+        std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) = 0;
+
+    virtual HWC3::Error onActiveConfigChange(Display* display) = 0;
+
+    virtual const DrmClient* getDrmPresenter() const { return nullptr; }
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/Gralloc.cpp b/hals/hwc3/Gralloc.cpp
new file mode 100644
index 00000000..1b364cd5
--- /dev/null
+++ b/hals/hwc3/Gralloc.cpp
@@ -0,0 +1,357 @@
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
+#include "Gralloc.h"
+
+#include <aidl/android/hardware/graphics/common/BufferUsage.h>
+#include <aidl/android/hardware/graphics/common/PlaneLayoutComponent.h>
+#include <aidl/android/hardware/graphics/common/PlaneLayoutComponentType.h>
+#include <drm_fourcc.h>
+#include <gralloctypes/Gralloc4.h>
+#include <log/log.h>
+#include <ui/GraphicBufferMapper.h>
+
+#include <algorithm>
+
+#include "Drm.h"
+
+using aidl::android::hardware::graphics::common::BufferUsage;
+using aidl::android::hardware::graphics::common::PlaneLayout;
+using aidl::android::hardware::graphics::common::PlaneLayoutComponent;
+using aidl::android::hardware::graphics::common::PlaneLayoutComponentType;
+using android::GraphicBufferMapper;
+using android::OK;
+using android::Rect;
+using android::status_t;
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+std::optional<uint32_t> Gralloc::GetWidth(buffer_handle_t buffer) {
+    uint64_t width = 0;
+    status_t status = GraphicBufferMapper::get().getWidth(buffer, &width);
+    if (status != OK) {
+        return std::nullopt;
+    }
+
+    if (width > std::numeric_limits<uint32_t>::max()) {
+        ALOGE("%s Width too large to cast to uint32_t: %ld", __FUNCTION__, width);
+        return std::nullopt;
+    }
+    return static_cast<uint32_t>(width);
+}
+
+std::optional<uint32_t> Gralloc::GetHeight(buffer_handle_t buffer) {
+    uint64_t height = 0;
+    status_t status = GraphicBufferMapper::get().getHeight(buffer, &height);
+    if (status != OK) {
+        return std::nullopt;
+    }
+
+    if (height > std::numeric_limits<uint32_t>::max()) {
+        ALOGE("%s Height too large to cast to uint32_t: %ld", __FUNCTION__, height);
+        return std::nullopt;
+    }
+    return static_cast<uint32_t>(height);
+}
+
+std::optional<uint32_t> Gralloc::GetDrmFormat(buffer_handle_t buffer) {
+    uint32_t format = 0;
+    status_t status = GraphicBufferMapper::get().getPixelFormatFourCC(buffer, &format);
+    if (status != OK) {
+        return std::nullopt;
+    }
+
+    return format;
+}
+
+std::optional<std::vector<PlaneLayout>> Gralloc::GetPlaneLayouts(buffer_handle_t buffer) {
+    std::vector<PlaneLayout> layouts;
+    status_t status = GraphicBufferMapper::get().getPlaneLayouts(buffer, &layouts);
+    if (status != OK) {
+        return std::nullopt;
+    }
+
+    return layouts;
+}
+
+std::optional<uint32_t> Gralloc::GetMonoPlanarStrideBytes(buffer_handle_t buffer) {
+    auto plane_layouts_opt = GetPlaneLayouts(buffer);
+    if (!plane_layouts_opt) {
+        return std::nullopt;
+    }
+
+    std::vector<PlaneLayout>& plane_layouts = *plane_layouts_opt;
+    if (plane_layouts.size() != 1) {
+        return std::nullopt;
+    }
+
+    if (plane_layouts[0].strideInBytes > std::numeric_limits<uint32_t>::max()) {
+        ALOGE("%s strideInBytes too large to cast to uint32_t: %ld", __FUNCTION__,
+              plane_layouts[0].strideInBytes);
+        return std::nullopt;
+    }
+    return static_cast<uint32_t>(plane_layouts[0].strideInBytes);
+}
+
+std::optional<GrallocBuffer> Gralloc::Import(buffer_handle_t buffer) {
+    buffer_handle_t imported_buffer;
+
+    status_t status = GraphicBufferMapper::get().importBufferNoValidate(buffer, &imported_buffer);
+
+    if (status != OK) {
+        ALOGE("%s failed to import buffer: %d", __FUNCTION__, status);
+        return std::nullopt;
+    }
+    return GrallocBuffer(this, imported_buffer);
+}
+
+void Gralloc::Release(buffer_handle_t buffer) {
+    status_t status = GraphicBufferMapper::get().freeBuffer(buffer);
+
+    if (status != OK) {
+        ALOGE("%s failed to release buffer: %d", __FUNCTION__, status);
+    }
+}
+
+std::optional<void*> Gralloc::Lock(buffer_handle_t buffer) {
+    const auto buffer_usage = static_cast<uint64_t>(BufferUsage::CPU_READ_OFTEN) |
+                              static_cast<uint64_t>(BufferUsage::CPU_WRITE_OFTEN);
+
+    auto width_opt = GetWidth(buffer);
+    if (!width_opt) {
+        return std::nullopt;
+    }
+
+    auto height_opt = GetHeight(buffer);
+    if (!height_opt) {
+        return std::nullopt;
+    }
+
+    Rect buffer_region;
+    buffer_region.left = 0;
+    buffer_region.top = 0;
+    // width = right - left
+    buffer_region.right = static_cast<int32_t>(*width_opt);
+    // height = bottom - top
+    buffer_region.bottom = static_cast<int32_t>(*height_opt);
+
+    void* data = nullptr;
+
+    status_t status = GraphicBufferMapper::get().lock(buffer, buffer_usage, buffer_region, &data);
+
+    if (status != OK) {
+        ALOGE("%s failed to lock buffer: %d", __FUNCTION__, status);
+        return std::nullopt;
+    }
+
+    return data;
+}
+
+std::optional<android_ycbcr> Gralloc::LockYCbCr(buffer_handle_t buffer) {
+    auto format_opt = GetDrmFormat(buffer);
+    if (!format_opt) {
+        ALOGE("%s failed to check format of buffer", __FUNCTION__);
+        return std::nullopt;
+    }
+
+    if (*format_opt != DRM_FORMAT_NV12 && *format_opt != DRM_FORMAT_NV21 &&
+        *format_opt != DRM_FORMAT_YVU420) {
+        ALOGE("%s called on non-ycbcr buffer", __FUNCTION__);
+        return std::nullopt;
+    }
+
+    auto lock_opt = Lock(buffer);
+    if (!lock_opt) {
+        ALOGE("%s failed to lock buffer", __FUNCTION__);
+        return std::nullopt;
+    }
+
+    auto plane_layouts_opt = GetPlaneLayouts(buffer);
+    if (!plane_layouts_opt) {
+        ALOGE("%s failed to get plane layouts", __FUNCTION__);
+        return std::nullopt;
+    }
+
+    android_ycbcr buffer_ycbcr;
+    buffer_ycbcr.y = nullptr;
+    buffer_ycbcr.cb = nullptr;
+    buffer_ycbcr.cr = nullptr;
+    buffer_ycbcr.ystride = 0;
+    buffer_ycbcr.cstride = 0;
+    buffer_ycbcr.chroma_step = 0;
+
+    for (const auto& plane_layout : *plane_layouts_opt) {
+        for (const auto& plane_layout_component : plane_layout.components) {
+            const auto& type = plane_layout_component.type;
+
+            if (!::android::gralloc4::isStandardPlaneLayoutComponentType(type)) {
+                continue;
+            }
+
+            auto* component_data = reinterpret_cast<uint8_t*>(*lock_opt) +
+                                   plane_layout.offsetInBytes +
+                                   plane_layout_component.offsetInBits / 8;
+
+            switch (static_cast<PlaneLayoutComponentType>(type.value)) {
+                case PlaneLayoutComponentType::Y:
+                    buffer_ycbcr.y = component_data;
+                    buffer_ycbcr.ystride = static_cast<size_t>(plane_layout.strideInBytes);
+                    break;
+                case PlaneLayoutComponentType::CB:
+                    buffer_ycbcr.cb = component_data;
+                    buffer_ycbcr.cstride = static_cast<size_t>(plane_layout.strideInBytes);
+                    buffer_ycbcr.chroma_step =
+                        static_cast<size_t>(plane_layout.sampleIncrementInBits / 8);
+                    break;
+                case PlaneLayoutComponentType::CR:
+                    buffer_ycbcr.cr = component_data;
+                    buffer_ycbcr.cstride = static_cast<size_t>(plane_layout.strideInBytes);
+                    buffer_ycbcr.chroma_step =
+                        static_cast<size_t>(plane_layout.sampleIncrementInBits / 8);
+                    break;
+                default:
+                    break;
+            }
+        }
+    }
+
+    return buffer_ycbcr;
+}
+
+void Gralloc::Unlock(buffer_handle_t buffer) {
+    status_t status = GraphicBufferMapper::get().unlock(buffer);
+
+    if (status != OK) {
+        ALOGE("%s failed to unlock buffer %d", __FUNCTION__, status);
+    }
+}
+
+GrallocBuffer::GrallocBuffer(Gralloc* gralloc, buffer_handle_t buffer)
+    : gralloc_(gralloc), buffer_(buffer) {}
+
+GrallocBuffer::~GrallocBuffer() { Release(); }
+
+GrallocBuffer::GrallocBuffer(GrallocBuffer&& rhs) { *this = std::move(rhs); }
+
+GrallocBuffer& GrallocBuffer::operator=(GrallocBuffer&& rhs) {
+    gralloc_ = rhs.gralloc_;
+    buffer_ = rhs.buffer_;
+    rhs.gralloc_ = nullptr;
+    rhs.buffer_ = nullptr;
+    return *this;
+}
+
+void GrallocBuffer::Release() {
+    if (gralloc_ && buffer_) {
+        gralloc_->Release(buffer_);
+        gralloc_ = nullptr;
+        buffer_ = nullptr;
+    }
+}
+
+std::optional<GrallocBufferView> GrallocBuffer::Lock() {
+    if (gralloc_ && buffer_) {
+        auto format_opt = GetDrmFormat();
+        if (!format_opt) {
+            ALOGE("%s failed to check format of buffer", __FUNCTION__);
+            return std::nullopt;
+        }
+        if (*format_opt != DRM_FORMAT_NV12 && *format_opt != DRM_FORMAT_NV21 &&
+            *format_opt != DRM_FORMAT_YVU420) {
+            auto locked_opt = gralloc_->Lock(buffer_);
+            if (!locked_opt) {
+                return std::nullopt;
+            }
+            return GrallocBufferView(this, *locked_opt);
+        } else {
+            auto locked_ycbcr_opt = gralloc_->LockYCbCr(buffer_);
+            if (!locked_ycbcr_opt) {
+                ALOGE("%s failed to lock ycbcr buffer", __FUNCTION__);
+                return std::nullopt;
+            }
+            return GrallocBufferView(this, *locked_ycbcr_opt);
+        }
+    }
+    return std::nullopt;
+}
+
+void GrallocBuffer::Unlock() {
+    if (gralloc_ && buffer_) {
+        gralloc_->Unlock(buffer_);
+    }
+}
+
+std::optional<uint32_t> GrallocBuffer::GetWidth() {
+    if (gralloc_ && buffer_) {
+        return gralloc_->GetWidth(buffer_);
+    }
+    return std::nullopt;
+}
+
+std::optional<uint32_t> GrallocBuffer::GetHeight() {
+    if (gralloc_ && buffer_) {
+        return gralloc_->GetHeight(buffer_);
+    }
+    return std::nullopt;
+}
+
+std::optional<uint32_t> GrallocBuffer::GetDrmFormat() {
+    if (gralloc_ && buffer_) {
+        return gralloc_->GetDrmFormat(buffer_);
+    }
+    return std::nullopt;
+}
+
+std::optional<std::vector<PlaneLayout>> GrallocBuffer::GetPlaneLayouts() {
+    if (gralloc_ && buffer_) {
+        return gralloc_->GetPlaneLayouts(buffer_);
+    }
+    return std::nullopt;
+}
+
+std::optional<uint32_t> GrallocBuffer::GetMonoPlanarStrideBytes() {
+    if (gralloc_ && buffer_) {
+        return gralloc_->GetMonoPlanarStrideBytes(buffer_);
+    }
+    return std::nullopt;
+}
+
+GrallocBufferView::GrallocBufferView(GrallocBuffer* buffer, void* raw)
+    : gralloc_buffer_(buffer), locked_(raw) {}
+
+GrallocBufferView::GrallocBufferView(GrallocBuffer* buffer, android_ycbcr raw)
+    : gralloc_buffer_(buffer), locked_ycbcr_(raw) {}
+
+GrallocBufferView::~GrallocBufferView() {
+    if (gralloc_buffer_) {
+        gralloc_buffer_->Unlock();
+    }
+}
+
+GrallocBufferView::GrallocBufferView(GrallocBufferView&& rhs) { *this = std::move(rhs); }
+
+GrallocBufferView& GrallocBufferView::operator=(GrallocBufferView&& rhs) {
+    std::swap(gralloc_buffer_, rhs.gralloc_buffer_);
+    std::swap(locked_, rhs.locked_);
+    std::swap(locked_ycbcr_, rhs.locked_ycbcr_);
+    return *this;
+}
+
+const std::optional<void*> GrallocBufferView::Get() const { return locked_; }
+
+const std::optional<android_ycbcr>& GrallocBufferView::GetYCbCr() const { return locked_ycbcr_; }
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/Gralloc.h b/hals/hwc3/Gralloc.h
new file mode 100644
index 00000000..a759089c
--- /dev/null
+++ b/hals/hwc3/Gralloc.h
@@ -0,0 +1,148 @@
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
+#ifndef ANDROID_HWC_GRALLOC_H
+#define ANDROID_HWC_GRALLOC_H
+
+#include <aidl/android/hardware/graphics/common/PlaneLayout.h>
+#include <hardware/gralloc.h>
+#include <system/graphics.h>
+#include <utils/StrongPointer.h>
+
+#include <memory>
+#include <optional>
+#include <vector>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class Gralloc;
+class GrallocBuffer;
+
+// An RAII object that will Unlock() a GrallocBuffer upon destruction.
+class GrallocBufferView {
+   public:
+    virtual ~GrallocBufferView();
+
+    GrallocBufferView(const GrallocBufferView& rhs) = delete;
+    GrallocBufferView& operator=(const GrallocBufferView& rhs) = delete;
+
+    GrallocBufferView(GrallocBufferView&& rhs);
+    GrallocBufferView& operator=(GrallocBufferView&& rhs);
+
+    const std::optional<void*> Get() const;
+
+    const std::optional<android_ycbcr>& GetYCbCr() const;
+
+   private:
+    friend class GrallocBuffer;
+    GrallocBufferView(GrallocBuffer* buffer, void* raw);
+    GrallocBufferView(GrallocBuffer* buffer, android_ycbcr raw);
+
+    // The GrallocBuffer that should be unlocked upon destruction of this object.
+    GrallocBuffer* gralloc_buffer_ = nullptr;
+
+    std::optional<void*> locked_;
+    std::optional<android_ycbcr> locked_ycbcr_;
+};
+
+// A gralloc 4.0 buffer that has been imported in the current process and
+// that will be released upon destruction. Users must ensure that the Gralloc
+// instance that this buffer is created with out lives this buffer.
+class GrallocBuffer {
+   public:
+    GrallocBuffer(Gralloc* gralloc, buffer_handle_t buffer);
+    virtual ~GrallocBuffer();
+
+    GrallocBuffer(const GrallocBuffer& rhs) = delete;
+    GrallocBuffer& operator=(const GrallocBuffer& rhs) = delete;
+
+    GrallocBuffer(GrallocBuffer&& rhs);
+    GrallocBuffer& operator=(GrallocBuffer&& rhs);
+
+    // Locks the buffer for reading and returns a view if successful.
+    std::optional<GrallocBufferView> Lock();
+
+    std::optional<uint32_t> GetWidth();
+    std::optional<uint32_t> GetHeight();
+    std::optional<uint32_t> GetDrmFormat();
+
+    // Returns the stride of the buffer if it is a single plane buffer or fails
+    // and returns nullopt if the buffer is for a multi plane buffer.
+    std::optional<uint32_t> GetMonoPlanarStrideBytes();
+
+    std::optional<std::vector<aidl::android::hardware::graphics::common::PlaneLayout>>
+    GetPlaneLayouts();
+
+   private:
+    // Internal visibility for Unlock().
+    friend class GrallocBufferView;
+
+    // Unlocks the buffer from reading.
+    void Unlock();
+
+    void Release();
+
+    Gralloc* gralloc_ = nullptr;
+    buffer_handle_t buffer_ = nullptr;
+};
+
+class Gralloc {
+   public:
+    virtual ~Gralloc() = default;
+
+    // Imports the given buffer handle into the current process and returns an
+    // imported buffer which can be used for reading. Users must ensure that the
+    // Gralloc instance outlives any GrallocBuffers.
+    std::optional<GrallocBuffer> Import(buffer_handle_t buffer);
+
+   private:
+    // The below functions are made available only to GrallocBuffer so that
+    // users only call gralloc functions on *imported* buffers.
+    friend class GrallocBuffer;
+
+    // See GrallocBuffer::Release.
+    void Release(buffer_handle_t buffer);
+
+    // See GrallocBuffer::Lock.
+    std::optional<void*> Lock(buffer_handle_t buffer);
+
+    // See GrallocBuffer::LockYCbCr.
+    std::optional<android_ycbcr> LockYCbCr(buffer_handle_t buffer);
+
+    // See GrallocBuffer::Unlock.
+    void Unlock(buffer_handle_t buffer);
+
+    // See GrallocBuffer::GetWidth.
+    std::optional<uint32_t> GetWidth(buffer_handle_t buffer);
+
+    // See GrallocBuffer::GetHeight.
+    std::optional<uint32_t> GetHeight(buffer_handle_t buffer);
+
+    // See GrallocBuffer::GetDrmFormat.
+    std::optional<uint32_t> GetDrmFormat(buffer_handle_t buffer);
+
+    // See GrallocBuffer::GetPlaneLayouts.
+    std::optional<std::vector<aidl::android::hardware::graphics::common::PlaneLayout>>
+    GetPlaneLayouts(buffer_handle_t buffer);
+
+    // Returns the stride of the buffer if it is a single plane buffer or fails
+    // and returns nullopt if the buffer is for a multi plane buffer.
+    std::optional<uint32_t> GetMonoPlanarStrideBytes(buffer_handle_t);
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/GuestFrameComposer.cpp b/hals/hwc3/GuestFrameComposer.cpp
new file mode 100644
index 00000000..9fc0b3c8
--- /dev/null
+++ b/hals/hwc3/GuestFrameComposer.cpp
@@ -0,0 +1,1207 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "GuestFrameComposer.h"
+
+#include <android-base/parseint.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+#include <android/hardware/graphics/common/1.0/types.h>
+#include <drm_fourcc.h>
+#include <libyuv.h>
+#include <sync/sync.h>
+#include <ui/GraphicBuffer.h>
+#include <ui/GraphicBufferAllocator.h>
+#include <ui/GraphicBufferMapper.h>
+
+#include "Display.h"
+#include "DisplayFinder.h"
+#include "Drm.h"
+#include "Layer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+// Returns a color matrix that can be used with libyuv by converting values
+// in -1 to 1 into -64 to 64 and converting row-major to column-major by transposing.
+std::array<std::int8_t, 16> ToLibyuvColorMatrix(const std::array<float, 16>& in) {
+    std::array<std::int8_t, 16> out;
+
+    for (int r = 0; r < 4; r++) {
+        for (int c = 0; c < 4; c++) {
+            int indexIn = (4 * r) + c;
+            int indexOut = (4 * c) + r;
+
+            float clampedValue = std::max(
+                -128.0f, std::min(127.0f, in[static_cast<size_t>(indexIn)] * 64.0f + 0.5f));
+            out[(size_t)indexOut] = static_cast<std::int8_t>(clampedValue);
+        }
+    }
+
+    return out;
+}
+
+std::uint8_t ToLibyuvColorChannel(float v) {
+    return static_cast<std::uint8_t>(std::min(255, static_cast<int>(v * 255.0f + 0.5f)));
+}
+
+std::uint32_t ToLibyuvColor(float r, float g, float b, float a) {
+    std::uint32_t out;
+    std::uint8_t* outChannels = reinterpret_cast<std::uint8_t*>(&out);
+    outChannels[0] = ToLibyuvColorChannel(r);
+    outChannels[1] = ToLibyuvColorChannel(g);
+    outChannels[2] = ToLibyuvColorChannel(b);
+    outChannels[3] = ToLibyuvColorChannel(a);
+    return out;
+}
+
+using ::android::hardware::graphics::common::V1_0::ColorTransform;
+
+uint32_t AlignToPower2(uint32_t val, uint8_t align_log) {
+    uint32_t align = 1 << align_log;
+    return ((val + (align - 1)) / align) * align;
+}
+
+bool LayerNeedsScaling(const Layer& layer) {
+    if (layer.getCompositionType() == Composition::SOLID_COLOR) {
+        return false;
+    }
+
+    common::Rect crop = layer.getSourceCropInt();
+    common::Rect frame = layer.getDisplayFrame();
+
+    int fromW = crop.right - crop.left;
+    int fromH = crop.bottom - crop.top;
+    int toW = frame.right - frame.left;
+    int toH = frame.bottom - frame.top;
+
+    bool not_rot_scale = fromW != toW || fromH != toH;
+    bool rot_scale = fromW != toH || fromH != toW;
+
+    bool needs_rot = static_cast<int32_t>(layer.getTransform()) &
+                     static_cast<int32_t>(common::Transform::ROT_90);
+
+    return needs_rot ? rot_scale : not_rot_scale;
+}
+
+bool LayerNeedsBlending(const Layer& layer) {
+    return layer.getBlendMode() != common::BlendMode::NONE;
+}
+
+bool LayerNeedsAttenuation(const Layer& layer) {
+    return layer.getBlendMode() == common::BlendMode::COVERAGE;
+}
+
+struct BufferSpec;
+typedef int (*ConverterFunction)(const BufferSpec& src, const BufferSpec& dst, bool v_flip);
+int DoCopy(const BufferSpec& src, const BufferSpec& dst, bool vFlip);
+int ConvertFromRGB565(const BufferSpec& src, const BufferSpec& dst, bool vFlip);
+int ConvertFromYV12(const BufferSpec& src, const BufferSpec& dst, bool vFlip);
+
+ConverterFunction GetConverterForDrmFormat(uint32_t drmFormat) {
+    switch (drmFormat) {
+        case DRM_FORMAT_ABGR8888:
+        case DRM_FORMAT_XBGR8888:
+            return &DoCopy;
+        case DRM_FORMAT_RGB565:
+            return &ConvertFromRGB565;
+        case DRM_FORMAT_YVU420:
+            return &ConvertFromYV12;
+    }
+    DEBUG_LOG("Unsupported drm format: %d(%s), returning null converter", drmFormat,
+              GetDrmFormatString(drmFormat));
+    return nullptr;
+}
+
+bool IsDrmFormatSupported(uint32_t drmFormat) {
+    return GetConverterForDrmFormat(drmFormat) != nullptr;
+}
+
+// Libyuv's convert functions only allow the combination of any rotation
+// (multiple of 90 degrees) and a vertical flip, but not horizontal flips.
+// Surfaceflinger's transformations are expressed in terms of a vertical flip,
+// a horizontal flip and/or a single 90 degrees clockwise rotation (see
+// NATIVE_WINDOW_TRANSFORM_HINT documentation on system/window.h for more
+// insight). The following code allows to turn a horizontal flip into a 180
+// degrees rotation and a vertical flip.
+libyuv::RotationMode GetRotationFromTransform(common::Transform transform) {
+    uint32_t rotation = 0;
+    rotation += (static_cast<int32_t>(transform) & static_cast<int32_t>(common::Transform::ROT_90))
+                    ? 1
+                    : 0;  // 1 * ROT90 bit
+    rotation += (static_cast<int32_t>(transform) & static_cast<int32_t>(common::Transform::FLIP_H))
+                    ? 2
+                    : 0;  // 2 * VFLIP bit
+    return static_cast<libyuv::RotationMode>(90 * rotation);
+}
+
+bool GetVFlipFromTransform(common::Transform transform) {
+    // vertical flip xor horizontal flip
+    bool hasVFlip =
+        static_cast<int32_t>(transform) & static_cast<int32_t>(common::Transform::FLIP_V);
+    bool hasHFlip =
+        static_cast<int32_t>(transform) & static_cast<int32_t>(common::Transform::FLIP_H);
+    return hasVFlip ^ hasHFlip;
+}
+
+struct BufferSpec {
+    uint8_t* buffer;
+    std::optional<android_ycbcr> buffer_ycbcr;
+    uint32_t width;
+    uint32_t height;
+    uint32_t cropX;
+    uint32_t cropY;
+    uint32_t cropWidth;
+    uint32_t cropHeight;
+    uint32_t drmFormat;
+    uint32_t strideBytes;
+    uint32_t sampleBytes;
+
+    BufferSpec() = default;
+
+    BufferSpec(uint8_t* buffer, std::optional<android_ycbcr> buffer_ycbcr, uint32_t width,
+               uint32_t height, uint32_t cropX, uint32_t cropY, uint32_t cropWidth,
+               uint32_t cropHeight, uint32_t drmFormat, uint32_t strideBytes, uint32_t sampleBytes)
+        : buffer(buffer),
+          buffer_ycbcr(buffer_ycbcr),
+          width(width),
+          height(height),
+          cropX(cropX),
+          cropY(cropY),
+          cropWidth(cropWidth),
+          cropHeight(cropHeight),
+          drmFormat(drmFormat),
+          strideBytes(strideBytes),
+          sampleBytes(sampleBytes) {}
+
+    BufferSpec(uint8_t* buffer, uint32_t width, uint32_t height, uint32_t strideBytes)
+        : BufferSpec(buffer,
+                     /*buffer_ycbcr=*/std::nullopt, width, height,
+                     /*cropX=*/0,
+                     /*cropY=*/0,
+                     /*cropWidth=*/width,
+                     /*cropHeight=*/height,
+                     /*drmFormat=*/DRM_FORMAT_ABGR8888, strideBytes,
+                     /*sampleBytes=*/4) {}
+};
+
+int DoFill(const BufferSpec& dst, const Color& color) {
+    ATRACE_CALL();
+    DEBUG_LOG(
+        "%s with r:%f g:%f b:%f a:%f in dst.buffer:%p dst.width:%" PRIu32 " dst.height:%" PRIu32
+        " dst.cropX:%" PRIu32 " dst.cropY:%" PRIu32 " dst.cropWidth:%" PRIu32
+        " dst.cropHeight:%" PRIu32 " dst.strideBytes:%" PRIu32 " dst.sampleBytes:%" PRIu32,
+        __FUNCTION__, color.r, color.g, color.b, color.a, dst.buffer, dst.width, dst.height,
+        dst.cropX, dst.cropY, dst.cropWidth, dst.cropHeight, dst.strideBytes, dst.sampleBytes);
+
+    const uint8_t r = static_cast<uint8_t>(color.r * 255.0f);
+    const uint8_t g = static_cast<uint8_t>(color.g * 255.0f);
+    const uint8_t b = static_cast<uint8_t>(color.b * 255.0f);
+    const uint8_t a = static_cast<uint8_t>(color.a * 255.0f);
+
+    const uint32_t rgba = static_cast<uint32_t>(r) | static_cast<uint32_t>(g) << 8 |
+                          static_cast<uint32_t>(b) << 16 | static_cast<uint32_t>(a) << 24;
+
+    if (dst.drmFormat != DRM_FORMAT_ABGR8888 && dst.drmFormat != DRM_FORMAT_XBGR8888) {
+        ALOGE("Failed to DoFill: unhandled drm format:%" PRIu32, dst.drmFormat);
+        return -1;
+    }
+
+    return libyuv::ARGBRect(dst.buffer,                         //
+                            static_cast<int>(dst.strideBytes),  //
+                            static_cast<int>(dst.cropX),        //
+                            static_cast<int>(dst.cropY),        //
+                            static_cast<int>(dst.cropWidth),    //
+                            static_cast<int>(dst.cropHeight),   //
+                            rgba);
+}
+
+int ConvertFromRGB565(const BufferSpec& src, const BufferSpec& dst, bool vFlip) {
+    ATRACE_CALL();
+
+    // Point to the upper left corner of the crop rectangle
+    uint8_t* srcBuffer = src.buffer + src.cropY * src.strideBytes + src.cropX * src.sampleBytes;
+    const int srcStrideBytes = static_cast<int>(src.strideBytes);
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+
+    int width = static_cast<int>(src.cropWidth);
+    int height = static_cast<int>(src.cropHeight);
+    if (vFlip) {
+        height = -height;
+    }
+
+    return libyuv::RGB565ToARGB(srcBuffer, srcStrideBytes,  //
+                                dstBuffer, dstStrideBytes,  //
+                                width, height);
+}
+
+int ConvertFromYV12(const BufferSpec& src, const BufferSpec& dst, bool vFlip) {
+    ATRACE_CALL();
+
+    // The following calculation of plane offsets and alignments are based on
+    // swiftshader's Sampler::setTextureLevel() implementation
+    // (Renderer/Sampler.cpp:225)
+
+    auto& srcBufferYCbCrOpt = src.buffer_ycbcr;
+    if (!srcBufferYCbCrOpt) {
+        ALOGE("%s called on non ycbcr buffer", __FUNCTION__);
+        return -1;
+    }
+    auto& srcBufferYCbCr = *srcBufferYCbCrOpt;
+
+    // The libyuv::I420ToARGB() function is for tri-planar.
+    if (srcBufferYCbCr.chroma_step != 1) {
+        ALOGE("%s called with bad chroma step", __FUNCTION__);
+        return -1;
+    }
+
+    uint8_t* srcY = reinterpret_cast<uint8_t*>(srcBufferYCbCr.y);
+    const int strideYBytes = static_cast<int>(srcBufferYCbCr.ystride);
+    uint8_t* srcU = reinterpret_cast<uint8_t*>(srcBufferYCbCr.cb);
+    const int strideUBytes = static_cast<int>(srcBufferYCbCr.cstride);
+    uint8_t* srcV = reinterpret_cast<uint8_t*>(srcBufferYCbCr.cr);
+    const int strideVBytes = static_cast<int>(srcBufferYCbCr.cstride);
+
+    // Adjust for crop
+    srcY += src.cropY * srcBufferYCbCr.ystride + src.cropX;
+    srcV += (src.cropY / 2) * srcBufferYCbCr.cstride + (src.cropX / 2);
+    srcU += (src.cropY / 2) * srcBufferYCbCr.cstride + (src.cropX / 2);
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+
+    int width = static_cast<int>(dst.cropWidth);
+    int height = static_cast<int>(dst.cropHeight);
+
+    if (vFlip) {
+        height = -height;
+    }
+
+    // YV12 is the same as I420, with the U and V planes swapped
+    return libyuv::I420ToARGB(srcY, strideYBytes,  //
+                              srcV, strideVBytes,  //
+                              srcU, strideUBytes,  //
+                              dstBuffer, dstStrideBytes, width, height);
+}
+
+int DoConversion(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
+    ConverterFunction func = GetConverterForDrmFormat(src.drmFormat);
+    if (!func) {
+        // GetConverterForDrmFormat should've logged the issue for us.
+        return -1;
+    }
+    return func(src, dst, v_flip);
+}
+
+int DoCopy(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
+    ATRACE_CALL();
+
+    // Point to the upper left corner of the crop rectangle
+    uint8_t* srcBuffer = src.buffer + src.cropY * src.strideBytes + src.cropX * src.sampleBytes;
+    const int srcStrideBytes = static_cast<int>(src.strideBytes);
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+    int width = static_cast<int>(src.cropWidth);
+    int height = static_cast<int>(src.cropHeight);
+
+    if (v_flip) {
+        height = -height;
+    }
+
+    // HAL formats are named based on the order of the pixel components on the
+    // byte stream, while libyuv formats are named based on the order of those
+    // pixel components in an integer written from left to right. So
+    // libyuv::FOURCC_ARGB is equivalent to HAL_PIXEL_FORMAT_BGRA_8888.
+    auto ret = libyuv::ARGBCopy(srcBuffer, srcStrideBytes,  //
+                                dstBuffer, dstStrideBytes,  //
+                                width, height);
+    return ret;
+}
+
+int DoRotation(const BufferSpec& src, const BufferSpec& dst, libyuv::RotationMode rotation,
+               bool v_flip) {
+    ATRACE_CALL();
+
+    // Point to the upper left corner of the crop rectangles
+    uint8_t* srcBuffer = src.buffer + src.cropY * src.strideBytes + src.cropX * src.sampleBytes;
+    const int srcStrideBytes = static_cast<int>(src.strideBytes);
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+    int width = static_cast<int>(src.cropWidth);
+    int height = static_cast<int>(src.cropHeight);
+
+    if (v_flip) {
+        height = -height;
+    }
+
+    return libyuv::ARGBRotate(srcBuffer, srcStrideBytes,  //
+                              dstBuffer, dstStrideBytes,  //
+                              width, height, rotation);
+}
+
+int DoScaling(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
+    ATRACE_CALL();
+
+    // Point to the upper left corner of the crop rectangles
+    uint8_t* srcBuffer = src.buffer + src.cropY * src.strideBytes + src.cropX * src.sampleBytes;
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int srcStrideBytes = static_cast<int>(src.strideBytes);
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+    const int srcWidth = static_cast<int>(src.cropWidth);
+    int srcHeight = static_cast<int>(src.cropHeight);
+    const int dstWidth = static_cast<int>(dst.cropWidth);
+    const int dstHeight = static_cast<int>(dst.cropHeight);
+
+    if (v_flip) {
+        srcHeight = -srcHeight;
+    }
+
+    return libyuv::ARGBScale(srcBuffer, srcStrideBytes, srcWidth, srcHeight, dstBuffer,
+                             dstStrideBytes, dstWidth, dstHeight, libyuv::kFilterBilinear);
+}
+
+int DoAttenuation(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
+    ATRACE_CALL();
+
+    // Point to the upper left corner of the crop rectangles
+    uint8_t* srcBuffer = src.buffer + src.cropY * src.strideBytes + src.cropX * src.sampleBytes;
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int srcStrideBytes = static_cast<int>(src.strideBytes);
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+    const int width = static_cast<int>(dst.cropWidth);
+    int height = static_cast<int>(dst.cropHeight);
+    if (v_flip) {
+        height = -height;
+    }
+
+    return libyuv::ARGBAttenuate(srcBuffer, srcStrideBytes,  //
+                                 dstBuffer, dstStrideBytes,  //
+                                 width, height);
+}
+
+int DoBrightnessShading(const BufferSpec& src, const BufferSpec& dst, float layerBrightness) {
+    ATRACE_CALL();
+
+    const float layerBrightnessGammaCorrected = std::pow(layerBrightness, 1.0f / 2.2f);
+
+    const std::uint32_t shade =
+        ToLibyuvColor(layerBrightnessGammaCorrected, layerBrightnessGammaCorrected,
+                      layerBrightnessGammaCorrected, 1.0f);
+
+    auto ret = libyuv::ARGBShade(src.buffer, static_cast<int>(src.strideBytes), dst.buffer,
+                                 static_cast<int>(dst.strideBytes), static_cast<int>(dst.width),
+                                 static_cast<int>(dst.height), shade);
+
+    return ret;
+}
+
+int DoBlending(const BufferSpec& src, const BufferSpec& dst, bool v_flip) {
+    ATRACE_CALL();
+
+    // Point to the upper left corner of the crop rectangles
+    uint8_t* srcBuffer = src.buffer + src.cropY * src.strideBytes + src.cropX * src.sampleBytes;
+    uint8_t* dstBuffer = dst.buffer + dst.cropY * dst.strideBytes + dst.cropX * dst.sampleBytes;
+    const int srcStrideBytes = static_cast<int>(src.strideBytes);
+    const int dstStrideBytes = static_cast<int>(dst.strideBytes);
+    const int width = static_cast<int>(dst.cropWidth);
+    int height = static_cast<int>(dst.cropHeight);
+    if (v_flip) {
+        height = -height;
+    }
+
+    // libyuv's ARGB format is hwcomposer's BGRA format, since blending only cares
+    // for the position of alpha in the pixel and not the position of the colors
+    // this function is perfectly usable.
+    return libyuv::ARGBBlend(srcBuffer, srcStrideBytes,  //
+                             dstBuffer, dstStrideBytes,  //
+                             dstBuffer, dstStrideBytes,  //
+                             width, height);
+}
+
+std::optional<BufferSpec> GetBufferSpec(GrallocBuffer& buffer, GrallocBufferView& bufferView,
+                                        const common::Rect& bufferCrop) {
+    auto bufferFormatOpt = buffer.GetDrmFormat();
+    if (!bufferFormatOpt) {
+        ALOGE("Failed to get gralloc buffer format.");
+        return std::nullopt;
+    }
+    uint32_t bufferFormat = *bufferFormatOpt;
+
+    auto bufferWidthOpt = buffer.GetWidth();
+    if (!bufferWidthOpt) {
+        ALOGE("Failed to get gralloc buffer width.");
+        return std::nullopt;
+    }
+    uint32_t bufferWidth = *bufferWidthOpt;
+
+    auto bufferHeightOpt = buffer.GetHeight();
+    if (!bufferHeightOpt) {
+        ALOGE("Failed to get gralloc buffer height.");
+        return std::nullopt;
+    }
+    uint32_t bufferHeight = *bufferHeightOpt;
+
+    uint8_t* bufferData = nullptr;
+    uint32_t bufferStrideBytes = 0;
+    std::optional<android_ycbcr> bufferYCbCrData;
+
+    if (bufferFormat == DRM_FORMAT_NV12 || bufferFormat == DRM_FORMAT_NV21 ||
+        bufferFormat == DRM_FORMAT_YVU420) {
+        bufferYCbCrData = bufferView.GetYCbCr();
+        if (!bufferYCbCrData) {
+            ALOGE("%s failed to get raw ycbcr from view.", __FUNCTION__);
+            return std::nullopt;
+        }
+    } else {
+        auto bufferDataOpt = bufferView.Get();
+        if (!bufferDataOpt) {
+            ALOGE("%s failed to lock gralloc buffer.", __FUNCTION__);
+            return std::nullopt;
+        }
+        bufferData = reinterpret_cast<uint8_t*>(*bufferDataOpt);
+
+        auto bufferStrideBytesOpt = buffer.GetMonoPlanarStrideBytes();
+        if (!bufferStrideBytesOpt) {
+            ALOGE("%s failed to get plane stride.", __FUNCTION__);
+            return std::nullopt;
+        }
+        bufferStrideBytes = *bufferStrideBytesOpt;
+    }
+
+    uint32_t bufferCropX = static_cast<uint32_t>(bufferCrop.left);
+    uint32_t bufferCropY = static_cast<uint32_t>(bufferCrop.top);
+    uint32_t bufferCropWidth = static_cast<uint32_t>(bufferCrop.right - bufferCrop.left);
+    uint32_t bufferCropHeight = static_cast<uint32_t>(bufferCrop.bottom - bufferCrop.top);
+
+    return BufferSpec(bufferData, bufferYCbCrData, bufferWidth, bufferHeight, bufferCropX,
+                      bufferCropY, bufferCropWidth, bufferCropHeight, bufferFormat,
+                      bufferStrideBytes, GetDrmFormatBytesPerPixel(bufferFormat));
+}
+
+}  // namespace
+
+HWC3::Error GuestFrameComposer::init() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    HWC3::Error error = mDrmClient.init();
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: failed to initialize DrmClient", __FUNCTION__);
+        return error;
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::registerOnHotplugCallback(const HotplugCallback& cb) {
+    return mDrmClient.registerOnHotplugCallback(cb);
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::unregisterOnHotplugCallback() {
+    return mDrmClient.unregisterOnHotplugCallback();
+}
+
+HWC3::Error GuestFrameComposer::onDisplayCreate(Display* display) {
+    const uint32_t displayId = static_cast<uint32_t>(display->getId());
+    int32_t displayConfigId;
+    int32_t displayWidth;
+    int32_t displayHeight;
+
+    HWC3::Error error = display->getActiveConfig(&displayConfigId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " has no active config", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::WIDTH, &displayWidth);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " failed to get width", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::HEIGHT, &displayHeight);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " failed to get height", __FUNCTION__, displayId);
+        return error;
+    }
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it != mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu32 " already created?", __FUNCTION__, displayId);
+    }
+
+    DisplayInfo& displayInfo = mDisplayInfos[displayId];
+
+    displayInfo.swapchain = DrmSwapchain::create(static_cast<uint32_t>(displayWidth),
+                                                 static_cast<uint32_t>(displayHeight),
+                                                 ::android::GraphicBuffer::USAGE_HW_COMPOSER |
+                                                     ::android::GraphicBuffer::USAGE_SW_READ_OFTEN |
+                                                     ::android::GraphicBuffer::USAGE_SW_WRITE_OFTEN,
+                                                 &mDrmClient);
+
+    if (displayId == 0) {
+        auto compositionResult = displayInfo.swapchain->getNextImage();
+        auto [flushError, flushSyncFd] =
+            mDrmClient.flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
+        if (flushError != HWC3::Error::None) {
+            ALOGW(
+                "%s: Initial display flush failed. HWComposer assuming that we are "
+                "running in QEMU without a display and disabling presenting.",
+                __FUNCTION__);
+            mPresentDisabled = true;
+        } else {
+            compositionResult->markAsInUse(std::move(flushSyncFd));
+        }
+    }
+
+    std::optional<std::vector<uint8_t>> edid = mDrmClient.getEdid(displayId);
+    if (edid) {
+        display->setEdid(*edid);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::onDisplayDestroy(Display* display) {
+    auto displayId = display->getId();
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it == mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+    mDisplayInfos.erase(it);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::onDisplayClientTargetSet(Display*) { return HWC3::Error::None; }
+
+HWC3::Error GuestFrameComposer::onActiveConfigChange(Display* /*display*/) {
+    return HWC3::Error::None;
+};
+
+HWC3::Error GuestFrameComposer::getDisplayConfigsFromSystemProp(
+    std::vector<GuestFrameComposer::DisplayConfig>* configs) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    std::vector<int> propIntParts;
+    parseExternalDisplaysFromProperties(propIntParts);
+
+    while (!propIntParts.empty()) {
+        DisplayConfig display_config = {
+            .width = propIntParts[1],
+            .height = propIntParts[2],
+            .dpiX = propIntParts[3],
+            .dpiY = propIntParts[3],
+            .refreshRateHz = 160,
+        };
+
+        configs->push_back(display_config);
+
+        propIntParts.erase(propIntParts.begin(), propIntParts.begin() + 5);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::validateDisplay(Display* display, DisplayChanges* outChanges) {
+    const auto displayId = display->getId();
+    DEBUG_LOG("%s display:%" PRIu64, __FUNCTION__, displayId);
+
+    const std::vector<Layer*>& layers = display->getOrderedLayers();
+
+    bool fallbackToClientComposition = false;
+    for (Layer* layer : layers) {
+        const auto layerId = layer->getId();
+        const auto layerCompositionType = layer->getCompositionType();
+        const auto layerCompositionTypeString = toString(layerCompositionType);
+
+        if (layerCompositionType == Composition::INVALID) {
+            ALOGE("%s display:%" PRIu64 " layer:%" PRIu64 " has Invalid composition", __FUNCTION__,
+                  displayId, layerId);
+            continue;
+        }
+
+        if (layerCompositionType == Composition::CLIENT ||
+            layerCompositionType == Composition::CURSOR ||
+            layerCompositionType == Composition::SIDEBAND) {
+            DEBUG_LOG("%s: display:%" PRIu64 " layer:%" PRIu64
+                      " has composition type %s, falling back to client composition",
+                      __FUNCTION__, displayId, layerId, layerCompositionTypeString.c_str());
+            fallbackToClientComposition = true;
+            break;
+        }
+
+        if (layerCompositionType == Composition::DISPLAY_DECORATION) {
+            return HWC3::Error::Unsupported;
+        }
+
+        if (!canComposeLayer(layer)) {
+            DEBUG_LOG("%s: display:%" PRIu64 " layer:%" PRIu64
+                      " composition not supported, falling back to client composition",
+                      __FUNCTION__, displayId, layerId);
+            fallbackToClientComposition = true;
+            break;
+        }
+    }
+
+    if (fallbackToClientComposition) {
+        for (Layer* layer : layers) {
+            const auto layerId = layer->getId();
+            const auto layerCompositionType = layer->getCompositionType();
+
+            if (layerCompositionType == Composition::INVALID) {
+                continue;
+            }
+
+            if (layerCompositionType != Composition::CLIENT) {
+                DEBUG_LOG("%s display:%" PRIu64 " layer:%" PRIu64 "composition updated to Client",
+                          __FUNCTION__, displayId, layerId);
+
+                outChanges->addLayerCompositionChange(displayId, layerId, Composition::CLIENT);
+            }
+        }
+    }
+
+    // We can not draw below a Client (SurfaceFlinger) composed layer. Change all
+    // layers below a Client composed layer to also be Client composed.
+    if (layers.size() > 1) {
+        for (std::size_t layerIndex = layers.size() - 1; layerIndex > 0; layerIndex--) {
+            auto layer = layers[layerIndex];
+            auto layerCompositionType = layer->getCompositionType();
+
+            if (layerCompositionType == Composition::CLIENT) {
+                for (std::size_t lowerLayerIndex = 0; lowerLayerIndex < layerIndex;
+                     lowerLayerIndex++) {
+                    auto lowerLayer = layers[lowerLayerIndex];
+                    auto lowerLayerId = lowerLayer->getId();
+                    auto lowerLayerCompositionType = lowerLayer->getCompositionType();
+
+                    if (lowerLayerCompositionType != Composition::CLIENT) {
+                        DEBUG_LOG("%s: display:%" PRIu64 " changing layer:%" PRIu64
+                                  " to Client because"
+                                  "hwcomposer can not draw below the Client composed "
+                                  "layer:%" PRIu64,
+                                  __FUNCTION__, displayId, lowerLayerId, layer->getId());
+
+                        outChanges->addLayerCompositionChange(displayId, lowerLayerId,
+                                                              Composition::CLIENT);
+                    }
+                }
+            }
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::presentDisplay(
+    Display* display, ::android::base::unique_fd* outDisplayFence,
+    std::unordered_map<int64_t, ::android::base::unique_fd>* /*outLayerFences*/) {
+    const uint32_t displayId = static_cast<uint32_t>(display->getId());
+    DEBUG_LOG("%s display:%" PRIu32, __FUNCTION__, displayId);
+
+    if (mPresentDisabled) {
+        return HWC3::Error::None;
+    }
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it == mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu32 " not found", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    DisplayInfo& displayInfo = it->second;
+
+    auto compositionResult = displayInfo.swapchain->getNextImage();
+    compositionResult->wait();
+
+    if (compositionResult->getBuffer() == nullptr) {
+        ALOGE("%s: display:%" PRIu32 " missing composition result buffer", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    if (compositionResult->getDrmBuffer() == nullptr) {
+        ALOGE("%s: display:%" PRIu32 " missing composition result drm buffer", __FUNCTION__,
+              displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    std::optional<GrallocBuffer> compositionResultBufferOpt =
+        mGralloc.Import(compositionResult->getBuffer());
+    if (!compositionResultBufferOpt) {
+        ALOGE("%s: display:%" PRIu32 " failed to import buffer", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    std::optional<uint32_t> compositionResultBufferWidthOpt =
+        compositionResultBufferOpt->GetWidth();
+    if (!compositionResultBufferWidthOpt) {
+        ALOGE("%s: display:%" PRIu32 " failed to query buffer width", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    std::optional<uint32_t> compositionResultBufferHeightOpt =
+        compositionResultBufferOpt->GetHeight();
+    if (!compositionResultBufferHeightOpt) {
+        ALOGE("%s: display:%" PRIu32 " failed to query buffer height", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    std::optional<uint32_t> compositionResultBufferStrideOpt =
+        compositionResultBufferOpt->GetMonoPlanarStrideBytes();
+    if (!compositionResultBufferStrideOpt) {
+        ALOGE("%s: display:%" PRIu32 " failed to query buffer stride", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    std::optional<GrallocBufferView> compositionResultBufferViewOpt =
+        compositionResultBufferOpt->Lock();
+    if (!compositionResultBufferViewOpt) {
+        ALOGE("%s: display:%" PRIu32 " failed to get buffer view", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    const std::optional<void*> compositionResultBufferDataOpt =
+        compositionResultBufferViewOpt->Get();
+    if (!compositionResultBufferDataOpt) {
+        ALOGE("%s: display:%" PRIu32 " failed to get buffer data", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+
+    uint32_t compositionResultBufferWidth = *compositionResultBufferWidthOpt;
+    uint32_t compositionResultBufferHeight = *compositionResultBufferHeightOpt;
+    uint32_t compositionResultBufferStride = *compositionResultBufferStrideOpt;
+    uint8_t* compositionResultBufferData =
+        reinterpret_cast<uint8_t*>(*compositionResultBufferDataOpt);
+
+    const std::vector<Layer*>& layers = display->getOrderedLayers();
+
+    const bool noOpComposition = layers.empty();
+    const bool allLayersClientComposed = std::all_of(
+        layers.begin(),  //
+        layers.end(),    //
+        [](const Layer* layer) { return layer->getCompositionType() == Composition::CLIENT; });
+
+    if (noOpComposition) {
+        DEBUG_LOG("%s: display:%" PRIu32 " empty composition", __FUNCTION__, displayId);
+    } else if (allLayersClientComposed) {
+        auto clientTargetBufferOpt = mGralloc.Import(display->waitAndGetClientTargetBuffer());
+        if (!clientTargetBufferOpt) {
+            ALOGE("%s: failed to import client target buffer.", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+        GrallocBuffer& clientTargetBuffer = *clientTargetBufferOpt;
+
+        auto clientTargetBufferViewOpt = clientTargetBuffer.Lock();
+        if (!clientTargetBufferViewOpt) {
+            ALOGE("%s: failed to lock client target buffer.", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+        GrallocBufferView& clientTargetBufferView = *clientTargetBufferViewOpt;
+
+        auto clientTargetPlaneLayoutsOpt = clientTargetBuffer.GetPlaneLayouts();
+        if (!clientTargetPlaneLayoutsOpt) {
+            ALOGE("Failed to get client target buffer plane layouts.");
+            return HWC3::Error::NoResources;
+        }
+        auto& clientTargetPlaneLayouts = *clientTargetPlaneLayoutsOpt;
+
+        if (clientTargetPlaneLayouts.size() != 1) {
+            ALOGE("Unexpected number of plane layouts for client target buffer.");
+            return HWC3::Error::NoResources;
+        }
+
+        std::size_t clientTargetPlaneSize =
+            static_cast<std::size_t>(clientTargetPlaneLayouts[0].totalSizeInBytes);
+
+        auto clientTargetDataOpt = clientTargetBufferView.Get();
+        if (!clientTargetDataOpt) {
+            ALOGE("%s failed to lock gralloc buffer.", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+        auto* clientTargetData = reinterpret_cast<uint8_t*>(*clientTargetDataOpt);
+
+        std::memcpy(compositionResultBufferData, clientTargetData, clientTargetPlaneSize);
+    } else {
+        for (Layer* layer : layers) {
+            const auto layerId = layer->getId();
+            const auto layerCompositionType = layer->getCompositionType();
+
+            if (layerCompositionType != Composition::DEVICE &&
+                layerCompositionType != Composition::SOLID_COLOR) {
+                continue;
+            }
+
+            HWC3::Error error = composeLayerInto(displayInfo.compositionIntermediateStorage,  //
+                                                 layer,                                       //
+                                                 compositionResultBufferData,                 //
+                                                 compositionResultBufferWidth,                //
+                                                 compositionResultBufferHeight,               //
+                                                 compositionResultBufferStride,               //
+                                                 4);
+            if (error != HWC3::Error::None) {
+                ALOGE("%s: display:%" PRIu32 " failed to compose layer:%" PRIu64, __FUNCTION__,
+                      displayId, layerId);
+                return error;
+            }
+        }
+    }
+
+    if (display->hasColorTransform()) {
+        HWC3::Error error = applyColorTransformToRGBA(display->getColorTransform(),   //
+                                                      compositionResultBufferData,    //
+                                                      compositionResultBufferWidth,   //
+                                                      compositionResultBufferHeight,  //
+                                                      compositionResultBufferStride);
+        if (error != HWC3::Error::None) {
+            ALOGE("%s: display:%" PRIu32 " failed to apply color transform", __FUNCTION__,
+                  displayId);
+            return error;
+        }
+    }
+
+    DEBUG_LOG("%s display:%" PRIu32 " flushing drm buffer", __FUNCTION__, displayId);
+
+    auto [error, fence] =
+        mDrmClient.flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " failed to flush drm buffer" PRIu64, __FUNCTION__, displayId);
+    }
+
+    *outDisplayFence = std::move(fence);
+    compositionResult->markAsInUse(outDisplayFence->ok()
+                                       ? ::android::base::unique_fd(dup(*outDisplayFence))
+                                       : ::android::base::unique_fd());
+    return error;
+}
+
+bool GuestFrameComposer::canComposeLayer(Layer* layer) {
+    const auto layerCompositionType = layer->getCompositionType();
+    if (layerCompositionType == Composition::SOLID_COLOR) {
+        return true;
+    }
+
+    if (layerCompositionType != Composition::DEVICE) {
+        return false;
+    }
+
+    buffer_handle_t bufferHandle = layer->getBuffer().getBuffer();
+    if (bufferHandle == nullptr) {
+        ALOGW("%s received a layer with a null handle", __FUNCTION__);
+        return false;
+    }
+
+    auto bufferOpt = mGralloc.Import(bufferHandle);
+    if (!bufferOpt) {
+        ALOGE("Failed to import layer buffer.");
+        return false;
+    }
+    GrallocBuffer& buffer = *bufferOpt;
+
+    auto bufferFormatOpt = buffer.GetDrmFormat();
+    if (!bufferFormatOpt) {
+        ALOGE("Failed to get layer buffer format.");
+        return false;
+    }
+    uint32_t bufferFormat = *bufferFormatOpt;
+
+    if (!IsDrmFormatSupported(bufferFormat)) {
+        return false;
+    }
+
+    if (layer->hasLuts()) {
+        return false;
+    }
+
+    return true;
+}
+
+HWC3::Error GuestFrameComposer::composeLayerInto(
+    AlternatingImageStorage& compositionIntermediateStorage,
+    Layer* srcLayer,                     //
+    std::uint8_t* dstBuffer,             //
+    std::uint32_t dstBufferWidth,        //
+    std::uint32_t dstBufferHeight,       //
+    std::uint32_t dstBufferStrideBytes,  //
+    std::uint32_t dstBufferBytesPerPixel) {
+    ATRACE_CALL();
+
+    DEBUG_LOG("%s dstBuffer:%p dstBufferWidth:%" PRIu32 " dstBufferHeight:%" PRIu32
+              " dstBufferStrideBytes:%" PRIu32 " dstBufferBytesPerPixel:%" PRIu32,
+              __FUNCTION__, dstBuffer, dstBufferWidth, dstBufferHeight, dstBufferStrideBytes,
+              dstBufferBytesPerPixel);
+
+    libyuv::RotationMode rotation = GetRotationFromTransform(srcLayer->getTransform());
+
+    common::Rect srcLayerCrop = srcLayer->getSourceCropInt();
+    common::Rect srcLayerDisplayFrame = srcLayer->getDisplayFrame();
+
+    BufferSpec srcLayerSpec;
+
+    std::optional<GrallocBuffer> srcBufferOpt;
+    std::optional<GrallocBufferView> srcBufferViewOpt;
+
+    const auto srcLayerCompositionType = srcLayer->getCompositionType();
+    if (srcLayerCompositionType == Composition::DEVICE) {
+        srcBufferOpt = mGralloc.Import(srcLayer->waitAndGetBuffer());
+        if (!srcBufferOpt) {
+            ALOGE("%s: failed to import layer buffer.", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+        GrallocBuffer& srcBuffer = *srcBufferOpt;
+
+        srcBufferViewOpt = srcBuffer.Lock();
+        if (!srcBufferViewOpt) {
+            ALOGE("%s: failed to lock import layer buffer.", __FUNCTION__);
+            return HWC3::Error::NoResources;
+        }
+        GrallocBufferView& srcBufferView = *srcBufferViewOpt;
+
+        auto srcLayerSpecOpt = GetBufferSpec(srcBuffer, srcBufferView, srcLayerCrop);
+        if (!srcLayerSpecOpt) {
+            return HWC3::Error::NoResources;
+        }
+
+        srcLayerSpec = *srcLayerSpecOpt;
+    } else if (srcLayerCompositionType == Composition::SOLID_COLOR) {
+        // srcLayerSpec not used by `needsFill` below.
+    }
+
+    // TODO(jemoreira): Remove the hardcoded fomat.
+    bool needsFill = srcLayerCompositionType == Composition::SOLID_COLOR;
+    bool needsConversion = srcLayerCompositionType == Composition::DEVICE &&
+                           srcLayerSpec.drmFormat != DRM_FORMAT_XBGR8888 &&
+                           srcLayerSpec.drmFormat != DRM_FORMAT_ABGR8888;
+    bool needsScaling = LayerNeedsScaling(*srcLayer);
+    bool needsRotation = rotation != libyuv::kRotate0;
+    bool needsTranspose = needsRotation && rotation != libyuv::kRotate180;
+    bool needsVFlip = GetVFlipFromTransform(srcLayer->getTransform());
+    bool needsAttenuation = LayerNeedsAttenuation(*srcLayer);
+    bool needsBlending = LayerNeedsBlending(*srcLayer);
+    bool needsBrightness = srcLayer->getBrightness() != 1.0f;
+    bool needsCopy = !(needsFill || needsConversion || needsScaling || needsRotation ||
+                       needsVFlip || needsAttenuation || needsBlending);
+
+    BufferSpec dstLayerSpec(
+        dstBuffer,
+        /*buffer_ycbcr=*/std::nullopt, dstBufferWidth, dstBufferHeight,
+        static_cast<uint32_t>(srcLayerDisplayFrame.left),
+        static_cast<uint32_t>(srcLayerDisplayFrame.top),
+        static_cast<uint32_t>(srcLayerDisplayFrame.right - srcLayerDisplayFrame.left),
+        static_cast<uint32_t>(srcLayerDisplayFrame.bottom - srcLayerDisplayFrame.top),
+        DRM_FORMAT_XBGR8888, dstBufferStrideBytes, dstBufferBytesPerPixel);
+
+    // Add the destination layer to the bottom of the buffer stack
+    std::vector<BufferSpec> dstBufferStack(1, dstLayerSpec);
+
+    // If more than operation is to be performed, a temporary buffer is needed for
+    // each additional operation
+
+    // N operations need N destination buffers, the destination layer (the
+    // framebuffer) is one of them, so only N-1 temporary buffers are needed.
+    // Vertical flip is not taken into account because it can be done together
+    // with any other operation.
+    int neededIntermediateImages = (needsFill ? 1 : 0) + (needsConversion ? 1 : 0) +
+                                   (needsScaling ? 1 : 0) + (needsRotation ? 1 : 0) +
+                                   (needsAttenuation ? 1 : 0) + (needsBlending ? 1 : 0) +
+                                   (needsCopy ? 1 : 0) + (needsBrightness ? 1 : 0) - 1;
+
+    uint32_t mScratchBufferWidth =
+        static_cast<uint32_t>(srcLayerDisplayFrame.right - srcLayerDisplayFrame.left);
+    uint32_t mScratchBufferHeight =
+        static_cast<uint32_t>(srcLayerDisplayFrame.bottom - srcLayerDisplayFrame.top);
+    uint32_t mScratchBufferStrideBytes =
+        AlignToPower2(mScratchBufferWidth * dstBufferBytesPerPixel, 4);
+    uint32_t mScratchBufferSizeBytes = mScratchBufferHeight * mScratchBufferStrideBytes;
+
+    DEBUG_LOG("%s neededIntermediateImages:%d", __FUNCTION__, neededIntermediateImages);
+    for (uint32_t i = 0; i < neededIntermediateImages; i++) {
+        BufferSpec mScratchBufferspec(
+            compositionIntermediateStorage.getRotatingScratchBuffer(mScratchBufferSizeBytes, i),
+            mScratchBufferWidth, mScratchBufferHeight, mScratchBufferStrideBytes);
+        dstBufferStack.push_back(mScratchBufferspec);
+    }
+
+    // Filling, conversion, and scaling should always be the first operations, so
+    // that every other operation works on equally sized frames (guaranteed to fit
+    // in the scratch buffers) in a common format.
+
+    if (needsFill) {
+        DEBUG_LOG("%s needs fill", __FUNCTION__);
+
+        BufferSpec& dstBufferSpec = dstBufferStack.back();
+
+        int retval = DoFill(dstBufferSpec, srcLayer->getColor());
+        if (retval) {
+            ALOGE("Got error code %d from DoFill function", retval);
+        }
+
+        srcLayerSpec = dstBufferSpec;
+        dstBufferStack.pop_back();
+    }
+
+    // TODO(jemoreira): We are converting to ARGB as the first step under the
+    // assumption that scaling ARGB is faster than scaling I420 (the most common).
+    // This should be confirmed with testing.
+    if (needsConversion) {
+        DEBUG_LOG("%s needs conversion", __FUNCTION__);
+
+        BufferSpec& dstBufferSpec = dstBufferStack.back();
+        if (needsScaling || needsTranspose) {
+            // If a rotation or a scaling operation are needed the dimensions at the
+            // top of the buffer stack are wrong (wrong sizes for scaling, swapped
+            // width and height for 90 and 270 rotations).
+            // Make width and height match the crop sizes on the source
+            uint32_t srcWidth = srcLayerSpec.cropWidth;
+            uint32_t srcHeight = srcLayerSpec.cropHeight;
+            uint32_t dst_stride_bytes = AlignToPower2(srcWidth * dstBufferBytesPerPixel, 4);
+            uint32_t neededSize = dst_stride_bytes * srcHeight;
+            dstBufferSpec.width = srcWidth;
+            dstBufferSpec.height = srcHeight;
+            // Adjust the stride accordingly
+            dstBufferSpec.strideBytes = dst_stride_bytes;
+            // Crop sizes also need to be adjusted
+            dstBufferSpec.cropWidth = srcWidth;
+            dstBufferSpec.cropHeight = srcHeight;
+            // cropX and y are fine at 0, format is already set to match destination
+
+            // In case of a scale, the source frame may be bigger than the default tmp
+            // buffer size
+            dstBufferSpec.buffer =
+                compositionIntermediateStorage.getSpecialScratchBuffer(neededSize);
+        }
+
+        int retval = DoConversion(srcLayerSpec, dstBufferSpec, needsVFlip);
+        if (retval) {
+            ALOGE("Got error code %d from DoConversion function", retval);
+        }
+        needsVFlip = false;
+        srcLayerSpec = dstBufferSpec;
+        dstBufferStack.pop_back();
+    }
+
+    if (needsScaling) {
+        DEBUG_LOG("%s needs scaling", __FUNCTION__);
+
+        BufferSpec& dstBufferSpec = dstBufferStack.back();
+        if (needsTranspose) {
+            // If a rotation is needed, the temporary buffer has the correct size but
+            // needs to be transposed and have its stride updated accordingly. The
+            // crop sizes also needs to be transposed, but not the x and y since they
+            // are both zero in a temporary buffer (and it is a temporary buffer
+            // because a rotation will be performed next).
+            std::swap(dstBufferSpec.width, dstBufferSpec.height);
+            std::swap(dstBufferSpec.cropWidth, dstBufferSpec.cropHeight);
+            // TODO (jemoreira): Aligment (To align here may cause the needed size to
+            // be bigger than the buffer, so care should be taken)
+            dstBufferSpec.strideBytes = dstBufferSpec.width * dstBufferBytesPerPixel;
+        }
+        int retval = DoScaling(srcLayerSpec, dstBufferSpec, needsVFlip);
+        needsVFlip = false;
+        if (retval) {
+            ALOGE("Got error code %d from DoScaling function", retval);
+        }
+        srcLayerSpec = dstBufferSpec;
+        dstBufferStack.pop_back();
+    }
+
+    if (needsRotation) {
+        DEBUG_LOG("%s needs rotation", __FUNCTION__);
+
+        int retval = DoRotation(srcLayerSpec, dstBufferStack.back(), rotation, needsVFlip);
+        needsVFlip = false;
+        if (retval) {
+            ALOGE("Got error code %d from DoTransform function", retval);
+        }
+        srcLayerSpec = dstBufferStack.back();
+        dstBufferStack.pop_back();
+    }
+
+    if (needsAttenuation) {
+        DEBUG_LOG("%s needs attenuation", __FUNCTION__);
+
+        int retval = DoAttenuation(srcLayerSpec, dstBufferStack.back(), needsVFlip);
+        needsVFlip = false;
+        if (retval) {
+            ALOGE("Got error code %d from DoBlending function", retval);
+        }
+        srcLayerSpec = dstBufferStack.back();
+        dstBufferStack.pop_back();
+    }
+
+    if (needsBrightness) {
+        DEBUG_LOG("%s needs brightness", __FUNCTION__);
+
+        int retval =
+            DoBrightnessShading(srcLayerSpec, dstBufferStack.back(), srcLayer->getBrightness());
+        if (retval) {
+            ALOGE("Got error code %d from DoBrightnessShading function", retval);
+        }
+        srcLayerSpec = dstBufferStack.back();
+        dstBufferStack.pop_back();
+    }
+
+    if (needsCopy) {
+        DEBUG_LOG("%s needs copy", __FUNCTION__);
+
+        int retval = DoCopy(srcLayerSpec, dstBufferStack.back(), needsVFlip);
+        needsVFlip = false;
+        if (retval) {
+            ALOGE("Got error code %d from DoBlending function", retval);
+        }
+        srcLayerSpec = dstBufferStack.back();
+        dstBufferStack.pop_back();
+    }
+
+    // Blending (if needed) should always be the last operation, so that it reads
+    // and writes in the destination layer and not some temporary buffer.
+    if (needsBlending) {
+        DEBUG_LOG("%s needs blending", __FUNCTION__);
+
+        int retval = DoBlending(srcLayerSpec, dstBufferStack.back(), needsVFlip);
+        needsVFlip = false;
+        if (retval) {
+            ALOGE("Got error code %d from DoBlending function", retval);
+        }
+        // Don't need to assign destination to source in the last one
+        dstBufferStack.pop_back();
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error GuestFrameComposer::applyColorTransformToRGBA(
+    const std::array<float, 16>& transfromMatrix,  //
+    std::uint8_t* buffer,                          //
+    std::uint32_t bufferWidth,                     //
+    std::uint32_t bufferHeight,                    //
+    std::uint32_t bufferStrideBytes) {
+    ATRACE_CALL();
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    const auto transformMatrixLibyuv = ToLibyuvColorMatrix(transfromMatrix);
+    libyuv::ARGBColorMatrix(buffer, static_cast<int>(bufferStrideBytes),  //
+                            buffer, static_cast<int>(bufferStrideBytes),  //
+                            transformMatrixLibyuv.data(),                 //
+                            static_cast<int>(bufferWidth),                //
+                            static_cast<int>(bufferHeight));
+
+    return HWC3::Error::None;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/GuestFrameComposer.h b/hals/hwc3/GuestFrameComposer.h
new file mode 100644
index 00000000..9a054f10
--- /dev/null
+++ b/hals/hwc3/GuestFrameComposer.h
@@ -0,0 +1,115 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_GUESTFRAMECOMPOSER_H
+#define ANDROID_HWC_GUESTFRAMECOMPOSER_H
+
+#include "AlternatingImageStorage.h"
+#include "Common.h"
+#include "Display.h"
+#include "DrmClient.h"
+#include "DrmSwapchain.h"
+#include "FrameComposer.h"
+#include "Gralloc.h"
+#include "Layer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class GuestFrameComposer : public FrameComposer {
+   public:
+    GuestFrameComposer() = default;
+
+    GuestFrameComposer(const GuestFrameComposer&) = delete;
+    GuestFrameComposer& operator=(const GuestFrameComposer&) = delete;
+
+    GuestFrameComposer(GuestFrameComposer&&) = delete;
+    GuestFrameComposer& operator=(GuestFrameComposer&&) = delete;
+
+    HWC3::Error init() override;
+
+    HWC3::Error registerOnHotplugCallback(const HotplugCallback& cb) override;
+
+    HWC3::Error unregisterOnHotplugCallback() override;
+
+    HWC3::Error onDisplayCreate(Display*) override;
+
+    HWC3::Error onDisplayDestroy(Display*) override;
+
+    HWC3::Error onDisplayClientTargetSet(Display*) override;
+
+    // Determines if this composer can compose the given layers on the given
+    // display and requests changes for layers that can't not be composed.
+    HWC3::Error validateDisplay(Display* display, DisplayChanges* outChanges) override;
+
+    // Performs the actual composition of layers and presents the composed result
+    // to the display.
+    HWC3::Error presentDisplay(
+        Display* display, ::android::base::unique_fd* outDisplayFence,
+        std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) override;
+
+    HWC3::Error onActiveConfigChange(Display* /*display*/) override;
+
+    const DrmClient* getDrmPresenter() const override { return &mDrmClient; }
+
+   private:
+    struct DisplayConfig {
+        int width;
+        int height;
+        int dpiX;
+        int dpiY;
+        int refreshRateHz;
+    };
+
+    HWC3::Error getDisplayConfigsFromSystemProp(std::vector<DisplayConfig>* configs);
+
+    // Returns true if the given layer's buffer has supported format.
+    bool canComposeLayer(Layer* layer);
+
+    // Composes the given layer into the given destination buffer.
+    HWC3::Error composeLayerInto(AlternatingImageStorage& storage, Layer* layer,
+                                 std::uint8_t* dstBuffer, std::uint32_t dstBufferWidth,
+                                 std::uint32_t dstBufferHeight, std::uint32_t dstBufferStrideBytes,
+                                 std::uint32_t dstBufferBytesPerPixel);
+
+    struct DisplayInfo {
+        // Additional per display buffers for the composition result.
+        std::unique_ptr<DrmSwapchain> swapchain = {};
+
+        // Scratch storage space for intermediate images during composition.
+        AlternatingImageStorage compositionIntermediateStorage;
+    };
+
+
+    std::unordered_map<int64_t, DisplayInfo> mDisplayInfos;
+
+    Gralloc mGralloc;
+
+    DrmClient mDrmClient;
+
+    // Cuttlefish on QEMU does not have a display. Disable presenting to avoid
+    // spamming logcat with DRM commit failures.
+    bool mPresentDisabled = false;
+
+    HWC3::Error applyColorTransformToRGBA(const std::array<float, 16>& colorTransform,  //
+                                          std::uint8_t* buffer,                         //
+                                          std::uint32_t bufferWidth,                    //
+                                          std::uint32_t bufferHeight,                   //
+                                          std::uint32_t bufferStrideBytes);
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/HostFrameComposer.cpp b/hals/hwc3/HostFrameComposer.cpp
new file mode 100644
index 00000000..15ce8be6
--- /dev/null
+++ b/hals/hwc3/HostFrameComposer.cpp
@@ -0,0 +1,758 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "HostFrameComposer.h"
+
+#include <EGL/egl.h>
+#include <EGL/eglext.h>
+#include <android-base/parseint.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+#include <android-base/unique_fd.h>
+#include <hardware/hwcomposer2.h>
+#include <poll.h>
+#include <sync/sync.h>
+#include <ui/GraphicBuffer.h>
+
+#include <optional>
+#include <tuple>
+
+#include "Display.h"
+#include "HostUtils.h"
+#include "Sync.h"
+#include "gfxstream/guest/goldfish_sync.h"
+#include "virtgpu_drm.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+hwc_rect AsHwcRect(const common::Rect& rect) {
+    hwc_rect out;
+    out.left = rect.left;
+    out.top = rect.top;
+    out.right = rect.right;
+    out.bottom = rect.bottom;
+    return out;
+}
+
+hwc_frect AsHwcFrect(const common::FRect& rect) {
+    hwc_frect out;
+    out.left = rect.left;
+    out.top = rect.top;
+    out.right = rect.right;
+    out.bottom = rect.bottom;
+    return out;
+}
+
+hwc_color AsHwcColor(const Color& color) {
+    hwc_color out;
+    out.r = static_cast<uint8_t>(color.r * 255.0f);
+    out.g = static_cast<uint8_t>(color.g * 255.0f);
+    out.b = static_cast<uint8_t>(color.b * 255.0f);
+    out.a = static_cast<uint8_t>(color.a * 255.0f);
+    return out;
+}
+
+hwc_transform_t AsHwcTransform(const common::Transform& transform) {
+    switch (transform) {
+        case common::Transform::NONE:
+            return static_cast<hwc_transform_t>(0);
+        case common::Transform::FLIP_H:
+            return HWC_TRANSFORM_FLIP_H;
+        case common::Transform::FLIP_V:
+            return HWC_TRANSFORM_FLIP_V;
+        case common::Transform::ROT_90:
+            return HWC_TRANSFORM_ROT_90;
+        case common::Transform::ROT_180:
+            return HWC_TRANSFORM_ROT_180;
+        case common::Transform::ROT_270:
+            return HWC_TRANSFORM_ROT_270;
+    }
+}
+
+static bool isMinigbmFromProperty() {
+    static constexpr const auto kGrallocProp = "ro.hardware.gralloc";
+
+    const auto grallocProp = ::android::base::GetProperty(kGrallocProp, "");
+    DEBUG_LOG("%s: prop value is: %s", __FUNCTION__, grallocProp.c_str());
+
+    if (grallocProp == "minigbm") {
+        DEBUG_LOG("%s: Using minigbm, in minigbm mode.\n", __FUNCTION__);
+        return true;
+    } else {
+        DEBUG_LOG("%s: Is not using minigbm, in goldfish mode.\n", __FUNCTION__);
+        return false;
+    }
+}
+
+typedef struct compose_layer {
+    uint32_t cbHandle;
+    hwc2_composition_t composeMode;
+    hwc_rect_t displayFrame;
+    hwc_frect_t crop;
+    int32_t blendMode;
+    float alpha;
+    hwc_color_t color;
+    hwc_transform_t transform;
+} ComposeLayer;
+
+typedef struct compose_device {
+    uint32_t version;
+    uint32_t targetHandle;
+    uint32_t numLayers;
+    struct compose_layer layer[0];
+} ComposeDevice;
+
+typedef struct compose_device_v2 {
+    uint32_t version;
+    uint32_t displayId;
+    uint32_t targetHandle;
+    uint32_t numLayers;
+    struct compose_layer layer[0];
+} ComposeDevice_v2;
+
+class ComposeMsg {
+   public:
+    ComposeMsg(uint32_t layerCnt = 0)
+        : mData(sizeof(ComposeDevice) + layerCnt * sizeof(ComposeLayer)) {
+        mComposeDevice = reinterpret_cast<ComposeDevice*>(mData.data());
+        mLayerCnt = layerCnt;
+    }
+
+    ComposeDevice* get() { return mComposeDevice; }
+
+    uint32_t getLayerCnt() { return mLayerCnt; }
+
+   private:
+    std::vector<uint8_t> mData;
+    uint32_t mLayerCnt;
+    ComposeDevice* mComposeDevice;
+};
+
+class ComposeMsg_v2 {
+   public:
+    ComposeMsg_v2(uint32_t layerCnt = 0)
+        : mData(sizeof(ComposeDevice_v2) + layerCnt * sizeof(ComposeLayer)) {
+        mComposeDevice = reinterpret_cast<ComposeDevice_v2*>(mData.data());
+        mLayerCnt = layerCnt;
+    }
+
+    ComposeDevice_v2* get() { return mComposeDevice; }
+
+    uint32_t getLayerCnt() { return mLayerCnt; }
+
+   private:
+    std::vector<uint8_t> mData;
+    uint32_t mLayerCnt;
+    ComposeDevice_v2* mComposeDevice;
+};
+
+}  // namespace
+
+HWC3::Error HostFrameComposer::init() {
+    mIsMinigbm = isMinigbmFromProperty();
+
+    if (mIsMinigbm) {
+        mDrmClient.emplace();
+
+        HWC3::Error error = mDrmClient->init();
+        if (error != HWC3::Error::None) {
+            ALOGE("%s: failed to initialize DrmClient", __FUNCTION__);
+            return error;
+        }
+
+        mSyncHelper.reset(gfxstream::createPlatformSyncHelper());
+    } else {
+        mSyncDeviceFd = goldfish_sync_open();
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::registerOnHotplugCallback(const HotplugCallback& cb) {
+    if (mDrmClient) {
+        mDrmClient->registerOnHotplugCallback(cb);
+    }
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::unregisterOnHotplugCallback() {
+    if (mDrmClient) {
+        mDrmClient->unregisterOnHotplugCallback();
+    }
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::createHostComposerDisplayInfo(Display* display,
+                                                             uint32_t hostDisplayId) {
+    HWC3::Error error = HWC3::Error::None;
+
+    int64_t displayId = display->getId();
+    int32_t displayConfigId;
+    int32_t displayWidth;
+    int32_t displayHeight;
+
+    error = display->getActiveConfig(&displayConfigId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " has no active config", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::WIDTH, &displayWidth);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " failed to get width", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::HEIGHT, &displayHeight);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu64 " failed to get height", __FUNCTION__, displayId);
+        return error;
+    }
+
+    HostComposerDisplayInfo& displayInfo = mDisplayInfos[displayId];
+
+    displayInfo.hostDisplayId = hostDisplayId;
+    displayInfo.swapchain = DrmSwapchain::create(
+        static_cast<uint32_t>(displayWidth), static_cast<uint32_t>(displayHeight),
+        ::android::GraphicBuffer::USAGE_HW_COMPOSER | ::android::GraphicBuffer::USAGE_HW_RENDER,
+        mDrmClient ? &mDrmClient.value() : nullptr);
+    if (!displayInfo.swapchain) {
+        ALOGE("%s: display:%" PRIu64 " failed to allocate swapchain", __FUNCTION__, displayId);
+        return HWC3::Error::NoResources;
+    }
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::onDisplayCreate(Display* display) {
+    HWC3::Error error = HWC3::Error::None;
+
+    const uint32_t displayId = static_cast<uint32_t>(display->getId());
+    int32_t displayConfigId;
+    int32_t displayWidth;
+    int32_t displayHeight;
+    int32_t displayDpiX;
+
+    error = display->getActiveConfig(&displayConfigId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " has no active config", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::WIDTH, &displayWidth);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " failed to get width", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::HEIGHT, &displayHeight);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " failed to get height", __FUNCTION__, displayId);
+        return error;
+    }
+
+    error = display->getDisplayAttribute(displayConfigId, DisplayAttribute::DPI_X, &displayDpiX);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s: display:%" PRIu32 " failed to get height", __FUNCTION__, displayId);
+        return error;
+    }
+
+    uint32_t hostDisplayId = 0;
+
+    DEFINE_AND_VALIDATE_HOST_CONNECTION
+    if (displayId == 0) {
+        // Primary display:
+        hostCon->lock();
+        if (rcEnc->rcCreateDisplayById(rcEnc, displayId)) {
+            ALOGE("%s host failed to create display %" PRIu32, __func__, displayId);
+            hostCon->unlock();
+            return HWC3::Error::NoResources;
+        }
+        if (rcEnc->rcSetDisplayPoseDpi(
+                rcEnc, displayId, -1, -1, static_cast<uint32_t>(displayWidth),
+                static_cast<uint32_t>(displayHeight), static_cast<uint32_t>(displayDpiX / 1000))) {
+            ALOGE("%s host failed to set display %" PRIu32, __func__, displayId);
+            hostCon->unlock();
+            return HWC3::Error::NoResources;
+        }
+        hostCon->unlock();
+    } else {
+        // Secondary display:
+        static constexpr const uint32_t kHostDisplayIdStart = 6;
+
+        uint32_t expectedHostDisplayId = kHostDisplayIdStart + displayId - 1;
+        uint32_t actualHostDisplayId = 0;
+
+        hostCon->lock();
+        rcEnc->rcDestroyDisplay(rcEnc, expectedHostDisplayId);
+        rcEnc->rcCreateDisplay(rcEnc, &actualHostDisplayId);
+        rcEnc->rcSetDisplayPose(rcEnc, actualHostDisplayId, -1, -1,
+                                static_cast<uint32_t>(displayWidth),
+                                static_cast<uint32_t>(displayHeight));
+        hostCon->unlock();
+
+        if (actualHostDisplayId != expectedHostDisplayId) {
+            ALOGE(
+                "Something wrong with host displayId allocation, expected %d "
+                "but received %d",
+                expectedHostDisplayId, actualHostDisplayId);
+        }
+
+        hostDisplayId = actualHostDisplayId;
+    }
+
+    error = createHostComposerDisplayInfo(display, hostDisplayId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to initialize host info for display:%" PRIu32, __FUNCTION__, displayId);
+        return error;
+    }
+
+    std::optional<std::vector<uint8_t>> edid;
+    if (mDrmClient) {
+        edid = mDrmClient->getEdid(displayId);
+        if (edid) {
+            display->setEdid(*edid);
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::onDisplayDestroy(Display* display) {
+    int64_t displayId = display->getId();
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it == mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    HostComposerDisplayInfo& displayInfo = mDisplayInfos[displayId];
+
+    if (displayId != 0) {
+        DEFINE_AND_VALIDATE_HOST_CONNECTION
+        hostCon->lock();
+        rcEnc->rcDestroyDisplay(rcEnc, displayInfo.hostDisplayId);
+        hostCon->unlock();
+    }
+
+    mDisplayInfos.erase(it);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::onDisplayClientTargetSet(Display* display) {
+    int64_t displayId = display->getId();
+
+    auto it = mDisplayInfos.find(displayId);
+    if (it == mDisplayInfos.end()) {
+        ALOGE("%s: display:%" PRIu64 " missing display buffers?", __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    HostComposerDisplayInfo& displayInfo = mDisplayInfos[displayId];
+
+    if (mIsMinigbm) {
+        FencedBuffer& clientTargetFencedBuffer = display->getClientTarget();
+
+        auto [drmBufferCreateError, drmBuffer] =
+            mDrmClient->create(clientTargetFencedBuffer.getBuffer());
+        if (drmBufferCreateError != HWC3::Error::None) {
+            ALOGE("%s: display:%" PRIu64 " failed to create client target drm buffer", __FUNCTION__,
+                  displayId);
+            return HWC3::Error::NoResources;
+        }
+        displayInfo.clientTargetDrmBuffer = std::move(drmBuffer);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::validateDisplay(Display* display, DisplayChanges* outChanges) {
+    const auto& displayId = display->getId();
+
+    DEFINE_AND_VALIDATE_HOST_CONNECTION
+    hostCon->lock();
+    bool hostCompositionV1 = rcEnc->hasHostCompositionV1();
+    bool hostCompositionV2 = rcEnc->hasHostCompositionV2();
+    hostCon->unlock();
+
+    const std::vector<Layer*> layers = display->getOrderedLayers();
+    for (const auto& layer : layers) {
+        switch (layer->getCompositionType()) {
+            case Composition::INVALID:
+                // Log error for unused layers, layer leak?
+                ALOGE("%s layer:%" PRIu64 " CompositionType not set", __FUNCTION__, layer->getId());
+                break;
+            case Composition::DISPLAY_DECORATION:
+                return HWC3::Error::Unsupported;
+            default:
+                break;
+        }
+    }
+
+    // If one layer requires a fall back to the client composition type, all
+    // layers will fall back to the client composition type.
+    bool fallBackToClient = (!hostCompositionV1 && !hostCompositionV2);
+    std::unordered_map<Layer*, Composition> changes;
+
+    if (!fallBackToClient) {
+        for (const auto& layer : layers) {
+            const auto& layerCompositionType = layer->getCompositionType();
+            const auto layerCompositionTypeString = toString(layerCompositionType);
+
+            std::optional<Composition> layerFallBackTo = std::nullopt;
+            switch (layerCompositionType) {
+                case Composition::CLIENT:
+                case Composition::SIDEBAND:
+                    ALOGV("%s: layer %" PRIu32 " CompositionType %s, fallback to client",
+                          __FUNCTION__, static_cast<uint32_t>(layer->getId()),
+                          layerCompositionTypeString.c_str());
+                    layerFallBackTo = Composition::CLIENT;
+                    break;
+                case Composition::CURSOR:
+                    ALOGV("%s: layer %" PRIu32 " CompositionType %s, fallback to device",
+                          __FUNCTION__, static_cast<uint32_t>(layer->getId()),
+                          layerCompositionTypeString.c_str());
+                    layerFallBackTo = Composition::DEVICE;
+                    break;
+                case Composition::INVALID:
+                case Composition::DEVICE:
+                case Composition::SOLID_COLOR:
+                    layerFallBackTo = std::nullopt;
+                    break;
+                default:
+                    ALOGE("%s: layer %" PRIu32 " has an unknown composition type: %s", __FUNCTION__,
+                          static_cast<uint32_t>(layer->getId()),
+                          layerCompositionTypeString.c_str());
+            }
+            if (layer->hasLuts()) {
+                layerFallBackTo = Composition::CLIENT;
+            }
+            if (layerFallBackTo == Composition::CLIENT) {
+                fallBackToClient = true;
+            }
+            if (layerFallBackTo.has_value()) {
+                changes.emplace(layer, layerFallBackTo.value());
+            }
+        }
+    }
+
+    if (fallBackToClient) {
+        changes.clear();
+        for (auto& layer : layers) {
+            if (layer->getCompositionType() == Composition::INVALID) {
+                continue;
+            }
+            if (layer->getCompositionType() != Composition::CLIENT) {
+                changes.emplace(layer, Composition::CLIENT);
+            }
+        }
+    }
+
+    outChanges->clearLayerCompositionChanges();
+    for (auto& [layer, newCompositionType] : changes) {
+        layer->logCompositionFallbackIfChanged(newCompositionType);
+        outChanges->addLayerCompositionChange(displayId, layer->getId(), newCompositionType);
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error HostFrameComposer::presentDisplay(
+    Display* display, ::android::base::unique_fd* outDisplayFence,
+    std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) {
+    const uint32_t displayId = static_cast<uint32_t>(display->getId());
+    auto displayInfoIt = mDisplayInfos.find(displayId);
+    if (displayInfoIt == mDisplayInfos.end()) {
+        ALOGE("%s: failed to find display buffers for display:%" PRIu32, __FUNCTION__, displayId);
+        return HWC3::Error::BadDisplay;
+    }
+
+    HostComposerDisplayInfo& displayInfo = displayInfoIt->second;
+
+    HostConnection* hostCon;
+    ExtendedRCEncoderContext* rcEnc;
+    HWC3::Error error = getAndValidateHostConnection(&hostCon, &rcEnc);
+    if (error != HWC3::Error::None) {
+        return error;
+    }
+    *outDisplayFence = ::android::base::unique_fd();
+    hostCon->lock();
+    bool hostCompositionV1 = rcEnc->hasHostCompositionV1();
+    bool hostCompositionV2 = rcEnc->hasHostCompositionV2();
+    hostCon->unlock();
+
+    // Ff we supports v2, then discard v1
+    if (hostCompositionV2) {
+        hostCompositionV1 = false;
+    }
+
+    auto compositionResult = displayInfo.swapchain->getNextImage();
+    compositionResult->wait();
+
+    const std::vector<Layer*> layers = display->getOrderedLayers();
+    if (hostCompositionV2 || hostCompositionV1) {
+        uint32_t numLayer = 0;
+        for (auto layer : layers) {
+            if (layer->getCompositionType() == Composition::DEVICE ||
+                layer->getCompositionType() == Composition::SOLID_COLOR) {
+                numLayer++;
+            }
+        }
+
+        DEBUG_LOG("%s: presenting display:%" PRIu32 " with %d layers", __FUNCTION__, displayId,
+                  static_cast<int>(layers.size()));
+
+        if (numLayer == 0) {
+            ALOGV("%s display has no layers to compose, flushing client target buffer.",
+                  __FUNCTION__);
+
+            FencedBuffer& displayClientTarget = display->getClientTarget();
+            if (displayClientTarget.getBuffer() != nullptr) {
+                ::android::base::unique_fd fence = displayClientTarget.getFence();
+                if (mIsMinigbm) {
+                    auto [_, flushCompleteFence] = mDrmClient->flushToDisplay(
+                        displayId, displayInfo.clientTargetDrmBuffer, fence);
+
+                    *outDisplayFence = std::move(flushCompleteFence);
+                } else {
+                    post(hostCon, rcEnc, displayInfo.hostDisplayId,
+                         displayClientTarget.getBuffer());
+                    *outDisplayFence = std::move(fence);
+                }
+            }
+            return HWC3::Error::None;
+        }
+
+        std::unique_ptr<ComposeMsg> composeMsg;
+        std::unique_ptr<ComposeMsg_v2> composeMsgV2;
+
+        if (hostCompositionV1) {
+            composeMsg.reset(new ComposeMsg(numLayer));
+        } else {
+            composeMsgV2.reset(new ComposeMsg_v2(numLayer));
+        }
+
+        // Handle the composition
+        ComposeDevice* p;
+        ComposeDevice_v2* p2;
+        ComposeLayer* l;
+
+        if (hostCompositionV1) {
+            p = composeMsg->get();
+            l = p->layer;
+        } else {
+            p2 = composeMsgV2->get();
+            l = p2->layer;
+        }
+
+        std::vector<int64_t> releaseLayerIds;
+        for (auto layer : layers) {
+            const auto& layerCompositionType = layer->getCompositionType();
+            const auto layerCompositionTypeString = toString(layerCompositionType);
+
+            // TODO: use local var composisitonType to store getCompositionType()
+            if (layerCompositionType != Composition::DEVICE &&
+                layerCompositionType != Composition::SOLID_COLOR) {
+                ALOGE("%s: Unsupported composition type %s layer %u", __FUNCTION__,
+                      layerCompositionTypeString.c_str(), (uint32_t)layer->getId());
+                continue;
+            }
+            // send layer composition command to host
+            if (layerCompositionType == Composition::DEVICE) {
+                releaseLayerIds.emplace_back(layer->getId());
+
+                ::android::base::unique_fd fence = layer->getBuffer().getFence();
+                if (fence.ok()) {
+                    int err = sync_wait(fence.get(), 3000);
+                    if (err < 0 && errno == ETIME) {
+                        ALOGE("%s waited on fence %d for 3000 ms", __FUNCTION__, fence.get());
+                    }
+
+#if GOLDFISH_OPENGL_SYNC_DEBUG
+                    mSyncHelper->debugPrint(fence.get());
+#endif
+                } else {
+                    ALOGV("%s: acquire fence not set for layer %u", __FUNCTION__,
+                          (uint32_t)layer->getId());
+                }
+                const native_handle_t* cb = layer->getBuffer().getBuffer();
+                if (cb != nullptr) {
+                    l->cbHandle = hostCon->grallocHelper()->getHostHandle(cb);
+                } else {
+                    ALOGE("%s null buffer for layer %d", __FUNCTION__, (uint32_t)layer->getId());
+                }
+            } else {
+                // solidcolor has no buffer
+                l->cbHandle = 0;
+            }
+            l->composeMode = (hwc2_composition_t)layerCompositionType;
+            l->displayFrame = AsHwcRect(layer->getDisplayFrame());
+            l->crop = AsHwcFrect(layer->getSourceCrop());
+            l->blendMode = static_cast<int32_t>(layer->getBlendMode());
+            float alpha = layer->getPlaneAlpha();
+            float brightness = layer->getBrightness();
+            // Apply brightness by modulating the layer's alpha.
+            //
+            // Due to limitations in the current implementation, per-layer brightness control
+            // is not supported. To simulate the desired visual effect, brightness is approximated
+            // by adjusting the alpha value of the layer.
+            //
+            // This approach, while not ideal, is sufficient enough for a virtual device (TV
+            // Cuttlefish) because virtual displays based on Virtio GPU do not have per-layer
+            // brightness control.
+
+            float mixFactor = 0.5f;
+            l->alpha = (alpha * (1.0f - mixFactor)) + (brightness * mixFactor);
+            l->color = AsHwcColor(layer->getColor());
+            l->transform = AsHwcTransform(layer->getTransform());
+            ALOGV(
+                "   cb %d blendmode %d alpha %f %d %d %d %d z %d"
+                " composeMode %d, transform %d",
+                l->cbHandle, l->blendMode, l->alpha, l->displayFrame.left, l->displayFrame.top,
+                l->displayFrame.right, l->displayFrame.bottom, layer->getZOrder(), l->composeMode,
+                l->transform);
+            l++;
+        }
+
+        if (hostCompositionV1) {
+            p->version = 1;
+            p->targetHandle =
+                hostCon->grallocHelper()->getHostHandle(compositionResult->getBuffer());
+            p->numLayers = numLayer;
+        } else {
+            p2->version = 2;
+            p2->displayId = displayInfo.hostDisplayId;
+            p2->targetHandle =
+                hostCon->grallocHelper()->getHostHandle(compositionResult->getBuffer());
+            p2->numLayers = numLayer;
+        }
+
+        void* buffer;
+        uint32_t bufferSize;
+        if (hostCompositionV1) {
+            buffer = (void*)p;
+            bufferSize = sizeof(ComposeDevice) + numLayer * sizeof(ComposeLayer);
+        } else {
+            bufferSize = sizeof(ComposeDevice_v2) + numLayer * sizeof(ComposeLayer);
+            buffer = (void*)p2;
+        }
+
+        ::android::base::unique_fd retire_fd;
+        hostCon->lock();
+        if (rcEnc->hasAsyncFrameCommands()) {
+            if (mIsMinigbm) {
+                rcEnc->rcComposeAsyncWithoutPost(rcEnc, bufferSize, buffer);
+            } else {
+                rcEnc->rcComposeAsync(rcEnc, bufferSize, buffer);
+            }
+        } else {
+            if (mIsMinigbm) {
+                rcEnc->rcComposeWithoutPost(rcEnc, bufferSize, buffer);
+            } else {
+                rcEnc->rcCompose(rcEnc, bufferSize, buffer);
+            }
+        }
+        hostCon->unlock();
+
+        // Send a retire fence and use it as the release fence for all layers,
+        // since media expects it
+        EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_ANDROID, EGL_NO_NATIVE_FENCE_FD_ANDROID};
+
+        uint64_t sync_handle, thread_handle;
+
+        // We don't use rc command to sync if we are using virtio-gpu, which is
+        // proxied by minigbm.
+        bool useRcCommandToSync = !mIsMinigbm;
+
+        if (useRcCommandToSync) {
+            hostCon->lock();
+            rcEnc->rcCreateSyncKHR(rcEnc, EGL_SYNC_NATIVE_FENCE_ANDROID, attribs,
+                                   2 * sizeof(EGLint), true /* destroy when signaled */,
+                                   &sync_handle, &thread_handle);
+            hostCon->unlock();
+        }
+
+        if (mIsMinigbm) {
+            auto [_, fence] =
+                mDrmClient->flushToDisplay(displayId, compositionResult->getDrmBuffer(), -1);
+            retire_fd = std::move(fence);
+        } else {
+            int fd;
+            goldfish_sync_queue_work(mSyncDeviceFd, sync_handle, thread_handle, &fd);
+            retire_fd = ::android::base::unique_fd(fd);
+        }
+
+        for (int64_t layerId : releaseLayerIds) {
+            (*outLayerFences)[layerId] = ::android::base::unique_fd(dup(retire_fd.get()));
+        }
+        *outDisplayFence = ::android::base::unique_fd(dup(retire_fd.get()));
+
+        if (useRcCommandToSync) {
+            hostCon->lock();
+            if (rcEnc->hasAsyncFrameCommands()) {
+                rcEnc->rcDestroySyncKHRAsync(rcEnc, sync_handle);
+            } else {
+                rcEnc->rcDestroySyncKHR(rcEnc, sync_handle);
+            }
+            hostCon->unlock();
+        }
+    } else {
+        // we set all layers Composition::CLIENT, so do nothing.
+        FencedBuffer& displayClientTarget = display->getClientTarget();
+        ::android::base::unique_fd displayClientTargetFence = displayClientTarget.getFence();
+        if (mIsMinigbm) {
+            auto [_, flushFence] = mDrmClient->flushToDisplay(
+                displayId, compositionResult->getDrmBuffer(), displayClientTargetFence);
+            *outDisplayFence = std::move(flushFence);
+        } else {
+            post(hostCon, rcEnc, displayInfo.hostDisplayId, displayClientTarget.getBuffer());
+            *outDisplayFence = std::move(displayClientTargetFence);
+        }
+        ALOGV("%s fallback to post, returns outRetireFence %d", __FUNCTION__,
+              outDisplayFence->get());
+    }
+    compositionResult->markAsInUse(outDisplayFence->ok()
+                                       ? ::android::base::unique_fd(dup(*outDisplayFence))
+                                       : ::android::base::unique_fd());
+    return HWC3::Error::None;
+}
+
+void HostFrameComposer::post(HostConnection* hostCon, ExtendedRCEncoderContext* rcEnc,
+                             uint32_t hostDisplayId, buffer_handle_t h) {
+    assert(cb && "native_handle_t::from(h) failed");
+
+    hostCon->lock();
+    rcEnc->rcSetDisplayColorBuffer(rcEnc, hostDisplayId,
+                                   hostCon->grallocHelper()->getHostHandle(h));
+    rcEnc->rcFBPost(rcEnc, hostCon->grallocHelper()->getHostHandle(h));
+    hostCon->flush();
+    hostCon->unlock();
+}
+
+HWC3::Error HostFrameComposer::onActiveConfigChange(Display* display) {
+    const uint32_t displayId = static_cast<uint32_t>(display->getId());
+    DEBUG_LOG("%s: display:%" PRIu32, __FUNCTION__, displayId);
+    HWC3::Error error = createHostComposerDisplayInfo(display, displayId);
+    if (error != HWC3::Error::None) {
+        ALOGE("%s failed to update host info for display:%" PRIu32, __FUNCTION__, displayId);
+        return error;
+    }
+    return HWC3::Error::None;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/HostFrameComposer.h b/hals/hwc3/HostFrameComposer.h
new file mode 100644
index 00000000..79d98783
--- /dev/null
+++ b/hals/hwc3/HostFrameComposer.h
@@ -0,0 +1,99 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_HOSTFRAMECOMPOSER_H
+#define ANDROID_HWC_HOSTFRAMECOMPOSER_H
+
+#include <android-base/unique_fd.h>
+
+#include <optional>
+#include <tuple>
+
+#include "Common.h"
+#include "DrmClient.h"
+#include "DrmSwapchain.h"
+#include "FrameComposer.h"
+#include "HostConnection.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class HostFrameComposer : public FrameComposer {
+   public:
+    HostFrameComposer() = default;
+
+    HostFrameComposer(const HostFrameComposer&) = delete;
+    HostFrameComposer& operator=(const HostFrameComposer&) = delete;
+
+    HostFrameComposer(HostFrameComposer&&) = delete;
+    HostFrameComposer& operator=(HostFrameComposer&&) = delete;
+
+    HWC3::Error init() override;
+
+    HWC3::Error registerOnHotplugCallback(const HotplugCallback& cb) override;
+
+    HWC3::Error unregisterOnHotplugCallback() override;
+
+    HWC3::Error onDisplayCreate(Display* display) override;
+
+    HWC3::Error onDisplayDestroy(Display* display) override;
+
+    HWC3::Error onDisplayClientTargetSet(Display* display) override;
+
+    // Determines if this composer can compose the given layers on the given
+    // display and requests changes for layers that can't not be composed.
+    HWC3::Error validateDisplay(Display* display, DisplayChanges* outChanges) override;
+
+    // Performs the actual composition of layers and presents the composed result
+    // to the display.
+    HWC3::Error presentDisplay(
+        Display* display, ::android::base::unique_fd* outDisplayFence,
+        std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) override;
+
+    HWC3::Error onActiveConfigChange(Display* display) override;
+
+    const DrmClient* getDrmPresenter() const override {
+        if (mDrmClient) {
+            return &*mDrmClient;
+        }
+        return nullptr;
+    }
+
+   private:
+    HWC3::Error createHostComposerDisplayInfo(Display* display, uint32_t hostDisplayId);
+
+    void post(HostConnection* hostCon, ExtendedRCEncoderContext* rcEnc, uint32_t hostDisplayId,
+              buffer_handle_t h);
+
+    bool mIsMinigbm = false;
+
+    int mSyncDeviceFd = -1;
+
+    struct HostComposerDisplayInfo {
+        uint32_t hostDisplayId = 0;
+        std::unique_ptr<DrmSwapchain> swapchain = {};
+        // Drm info for the displays client target buffer.
+        std::shared_ptr<DrmBuffer> clientTargetDrmBuffer;
+    };
+
+    std::unique_ptr<gfxstream::SyncHelper> mSyncHelper = nullptr;
+    std::unordered_map<int64_t, HostComposerDisplayInfo> mDisplayInfos;
+
+    std::optional<DrmClient> mDrmClient;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/HostUtils.cpp b/hals/hwc3/HostUtils.cpp
new file mode 100644
index 00000000..0ed178fb
--- /dev/null
+++ b/hals/hwc3/HostUtils.cpp
@@ -0,0 +1,32 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "HostUtils.h"
+
+#include <memory>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+HostConnection* createOrGetHostConnection() {
+    static std::unique_ptr<HostConnection> sHostCon;
+
+    if (!sHostCon) {
+        sHostCon = HostConnection::createUnique(kCapsetNone);
+    }
+    return sHostCon.get();
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hals/hwc3/HostUtils.h b/hals/hwc3/HostUtils.h
new file mode 100644
index 00000000..95d8b1d4
--- /dev/null
+++ b/hals/hwc3/HostUtils.h
@@ -0,0 +1,59 @@
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
+#ifndef ANDROID_HWC_HOSTUTILS_H
+#define ANDROID_HWC_HOSTUTILS_H
+
+#include "Common.h"
+#include "HostConnection.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+HostConnection* createOrGetHostConnection();
+
+inline HWC3::Error getAndValidateHostConnection(HostConnection** ppHostCon,
+                                                ExtendedRCEncoderContext** ppRcEnc) {
+    *ppHostCon = nullptr;
+    *ppRcEnc = nullptr;
+
+    HostConnection* hostCon = createOrGetHostConnection();
+    if (!hostCon) {
+        ALOGE("%s: Failed to get host connection\n", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+    ExtendedRCEncoderContext* rcEnc = hostCon->rcEncoder();
+    if (!rcEnc) {
+        ALOGE("%s: Failed to get renderControl encoder context\n", __FUNCTION__);
+        return HWC3::Error::NoResources;
+    }
+
+    *ppHostCon = hostCon;
+    *ppRcEnc = rcEnc;
+    return HWC3::Error::None;
+}
+
+#define DEFINE_AND_VALIDATE_HOST_CONNECTION                               \
+    HostConnection* hostCon;                                              \
+    ExtendedRCEncoderContext* rcEnc;                                      \
+    {                                                                     \
+        HWC3::Error res = getAndValidateHostConnection(&hostCon, &rcEnc); \
+        if (res != HWC3::Error::None) {                                   \
+            return res;                                                   \
+        }                                                                 \
+    }
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/Layer.cpp b/hals/hwc3/Layer.cpp
new file mode 100644
index 00000000..d391f2b5
--- /dev/null
+++ b/hals/hwc3/Layer.cpp
@@ -0,0 +1,346 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "Layer.h"
+
+#include <android-base/unique_fd.h>
+#include <sync/sync.h>
+
+#include <atomic>
+#include <cmath>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+std::atomic<int64_t> sNextId{1};
+
+}  // namespace
+
+Layer::Layer() : mId(sNextId++) {}
+
+HWC3::Error Layer::setCursorPosition(const common::Point& position) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    if (mCompositionType != Composition::CURSOR) {
+        ALOGE("%s: CompositionType not Cursor type", __FUNCTION__);
+        return HWC3::Error::BadLayer;
+    }
+
+    mCursorPosition = position;
+    return HWC3::Error::None;
+}
+
+common::Point Layer::getCursorPosition() const {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return mCursorPosition;
+}
+
+HWC3::Error Layer::setBuffer(buffer_handle_t buffer, const ndk::ScopedFileDescriptor& fence) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    if (buffer == nullptr) {
+        ALOGE("%s: missing handle", __FUNCTION__);
+        return HWC3::Error::BadParameter;
+    }
+
+    mBuffer.set(buffer, fence);
+    return HWC3::Error::None;
+}
+
+FencedBuffer& Layer::getBuffer() {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return mBuffer;
+}
+
+buffer_handle_t Layer::waitAndGetBuffer() {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    ::android::base::unique_fd fence = mBuffer.getFence();
+    if (fence.ok()) {
+        int err = sync_wait(fence.get(), 3000);
+        if (err < 0 && errno == ETIME) {
+            ALOGE("%s waited on fence %" PRId32 " for 3000 ms", __FUNCTION__, fence.get());
+        }
+    }
+
+    return mBuffer.getBuffer();
+}
+
+HWC3::Error Layer::setSurfaceDamage(const std::vector<std::optional<common::Rect>>& /*damage*/) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Layer::setBlendMode(common::BlendMode blendMode) {
+    const auto blendModeString = toString(blendMode);
+    DEBUG_LOG("%s: layer:%" PRId64 " blend mode:%s", __FUNCTION__, mId, blendModeString.c_str());
+
+    mBlendMode = blendMode;
+    return HWC3::Error::None;
+}
+
+common::BlendMode Layer::getBlendMode() const {
+    const auto blendMode = mBlendMode;
+    const auto blendModeString = toString(blendMode);
+    DEBUG_LOG("%s: layer:%" PRId64 " blend mode:%s", __FUNCTION__, mId, blendModeString.c_str());
+
+    return blendMode;
+}
+
+HWC3::Error Layer::setColor(Color color) {
+    DEBUG_LOG("%s: layer:%" PRId64 " color-r:%f color-g:%f color-b:%f color-a:%f)", __FUNCTION__,
+              mId, color.r, color.g, color.b, color.a);
+
+    mColor = color;
+    return HWC3::Error::None;
+}
+
+Color Layer::getColor() const {
+    auto color = mColor;
+    DEBUG_LOG("%s: layer:%" PRId64 " color-r:%f color-g:%f color-b:%f color-a:%f)", __FUNCTION__,
+              mId, color.r, color.g, color.b, color.a);
+
+    return color;
+}
+
+HWC3::Error Layer::setCompositionType(Composition compositionType) {
+    const auto compositionTypeString = toString(compositionType);
+    DEBUG_LOG("%s: layer:%" PRId64 " composition type:%s", __FUNCTION__, mId,
+              compositionTypeString.c_str());
+
+    mCompositionType = compositionType;
+    return HWC3::Error::None;
+}
+
+Composition Layer::getCompositionType() const {
+    const auto compositionTypeString = toString(mCompositionType);
+    DEBUG_LOG("%s: layer:%" PRId64 " composition type:%s", __FUNCTION__, mId,
+              compositionTypeString.c_str());
+
+    return mCompositionType;
+}
+
+HWC3::Error Layer::setDataspace(common::Dataspace dataspace) {
+    const auto dataspaceString = toString(dataspace);
+    DEBUG_LOG("%s: layer:%" PRId64 " dataspace:%s", __FUNCTION__, mId, dataspaceString.c_str());
+
+    mDataspace = dataspace;
+    return HWC3::Error::None;
+}
+
+common::Dataspace Layer::getDataspace() const {
+    const auto dataspaceString = toString(mDataspace);
+    DEBUG_LOG("%s: layer:%" PRId64 " dataspace:%s", __FUNCTION__, mId, dataspaceString.c_str());
+
+    return mDataspace;
+}
+
+HWC3::Error Layer::setDisplayFrame(common::Rect frame) {
+    DEBUG_LOG("%s: layer:%" PRId64
+              " display frame rect-left:%d rect-top:%d rect-right:%d rect-bot:%d",
+              __FUNCTION__, mId, frame.left, frame.top, frame.right, frame.bottom);
+
+    mDisplayFrame = frame;
+    return HWC3::Error::None;
+}
+
+common::Rect Layer::getDisplayFrame() const {
+    auto frame = mDisplayFrame;
+    DEBUG_LOG("%s: layer:%" PRId64
+              " display frame rect-left:%d rect-top:%d rect-right:%d rect-bot:%d",
+              __FUNCTION__, mId, frame.left, frame.top, frame.right, frame.bottom);
+
+    return frame;
+}
+
+HWC3::Error Layer::setPlaneAlpha(float alpha) {
+    DEBUG_LOG("%s: layer:%" PRId64 "alpha:%f", __FUNCTION__, mId, alpha);
+
+    mPlaneAlpha = alpha;
+    return HWC3::Error::None;
+}
+
+float Layer::getPlaneAlpha() const {
+    auto alpha = mPlaneAlpha;
+    DEBUG_LOG("%s: layer:%" PRId64 "alpha:%f", __FUNCTION__, mId, alpha);
+
+    return alpha;
+}
+
+HWC3::Error Layer::setSidebandStream(buffer_handle_t /*stream*/) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Layer::setSourceCrop(common::FRect crop) {
+    DEBUG_LOG("%s: layer:%" PRId64 "crop rect-left:%f rect-top:%f rect-right:%f rect-bot:%f",
+              __FUNCTION__, mId, crop.left, crop.top, crop.right, crop.bottom);
+
+    mSourceCrop = crop;
+    return HWC3::Error::None;
+}
+
+common::FRect Layer::getSourceCrop() const {
+    common::FRect crop = mSourceCrop;
+    DEBUG_LOG("%s: layer:%" PRId64 "crop rect-left:%f rect-top:%f rect-right:%f rect-bot:%f",
+              __FUNCTION__, mId, crop.left, crop.top, crop.right, crop.bottom);
+
+    return crop;
+}
+
+common::Rect Layer::getSourceCropInt() const {
+    common::Rect crop = {};
+    crop.left = static_cast<int>(mSourceCrop.left);
+    crop.top = static_cast<int>(mSourceCrop.top);
+    crop.right = static_cast<int>(mSourceCrop.right);
+    crop.bottom = static_cast<int>(mSourceCrop.bottom);
+    DEBUG_LOG("%s: layer:%" PRId64 "crop rect-left:%d rect-top:%d rect-right:%d rect-bot:%d",
+              __FUNCTION__, mId, crop.left, crop.top, crop.right, crop.bottom);
+
+    return crop;
+}
+
+HWC3::Error Layer::setTransform(common::Transform transform) {
+    const auto transformString = toString(transform);
+    DEBUG_LOG("%s: layer:%" PRId64 " transform:%s", __FUNCTION__, mId, transformString.c_str());
+
+    mTransform = transform;
+    return HWC3::Error::None;
+}
+
+common::Transform Layer::getTransform() const {
+    const auto transformString = toString(mTransform);
+    DEBUG_LOG("%s: layer:%" PRId64 " transform:%s", __FUNCTION__, mId, transformString.c_str());
+
+    return mTransform;
+}
+
+HWC3::Error Layer::setVisibleRegion(const std::vector<std::optional<common::Rect>>& visible) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    mVisibleRegion.clear();
+    mVisibleRegion.reserve(visible.size());
+    for (const auto& rectOption : visible) {
+        if (rectOption) {
+            mVisibleRegion.push_back(*rectOption);
+        }
+    }
+
+    return HWC3::Error::None;
+}
+
+std::size_t Layer::getNumVisibleRegions() const {
+    const std::size_t num = mVisibleRegion.size();
+    DEBUG_LOG("%s: layer:%" PRId64 " number of visible regions: %zu", __FUNCTION__, mId, num);
+
+    return num;
+}
+
+HWC3::Error Layer::setZOrder(int32_t z) {
+    DEBUG_LOG("%s: layer:%" PRId64 " z:%d", __FUNCTION__, mId, z);
+
+    mZOrder = z;
+    return HWC3::Error::None;
+}
+
+int32_t Layer::getZOrder() const {
+    DEBUG_LOG("%s: layer:%" PRId64 " z:%d", __FUNCTION__, mId, mZOrder);
+
+    return mZOrder;
+}
+
+HWC3::Error Layer::setPerFrameMetadata(
+    const std::vector<std::optional<PerFrameMetadata>>& /*perFrameMetadata*/) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Layer::setColorTransform(const std::vector<float>& colorTransform) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    if (colorTransform.size() < 16) {
+        return HWC3::Error::BadParameter;
+    }
+
+    mColorTransform.emplace();
+    std::copy_n(colorTransform.data(), 16, mColorTransform->data());
+    return HWC3::Error::None;
+}
+
+const std::optional<std::array<float, 16>>& Layer::getColorTransform() const {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return mColorTransform;
+}
+
+HWC3::Error Layer::setBrightness(float brightness) {
+    DEBUG_LOG("%s: layer:%" PRId64 " brightness:%f", __FUNCTION__, mId, brightness);
+
+    if (std::isnan(brightness) || brightness < 0.0f || brightness > 1.0f) {
+        ALOGE("%s: layer:%" PRId64 " brightness:%f", __FUNCTION__, mId, brightness);
+        return HWC3::Error::BadParameter;
+    }
+
+    mBrightness = brightness;
+    return HWC3::Error::None;
+}
+
+float Layer::getBrightness() const {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return mBrightness;
+}
+
+HWC3::Error Layer::setPerFrameMetadataBlobs(
+    const std::vector<std::optional<PerFrameMetadataBlob>>& /*perFrameMetadata*/) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error Layer::setLuts(const Luts& luts) {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    mHasLuts = luts.pfd.get() >= 0;
+    return HWC3::Error::None;
+}
+
+bool Layer::hasLuts() const {
+    DEBUG_LOG("%s: layer:%" PRId64, __FUNCTION__, mId);
+
+    return mHasLuts;
+}
+
+void Layer::logCompositionFallbackIfChanged(Composition to) {
+    Composition from = getCompositionType();
+    if (mLastCompositionFallback && mLastCompositionFallback->from == from &&
+        mLastCompositionFallback->to == to) {
+        return;
+    }
+    ALOGI("%s: layer %" PRIu32 " CompositionType fallback from %d to %d", __FUNCTION__,
+          static_cast<uint32_t>(getId()), static_cast<int>(from), static_cast<int>(to));
+    mLastCompositionFallback = {
+        .from = from,
+        .to = to,
+    };
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/Layer.h b/hals/hwc3/Layer.h
new file mode 100644
index 00000000..22ac4e96
--- /dev/null
+++ b/hals/hwc3/Layer.h
@@ -0,0 +1,127 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_LAYER_H
+#define ANDROID_HWC_LAYER_H
+
+#include <optional>
+#include <vector>
+
+#include "Common.h"
+#include "FencedBuffer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class Layer {
+   public:
+    explicit Layer();
+
+    Layer(const Layer&) = delete;
+    Layer& operator=(const Layer&) = delete;
+
+    Layer(Layer&&) = delete;
+    Layer& operator=(Layer&&) = delete;
+
+    int64_t getId() const { return mId; }
+
+    HWC3::Error setCursorPosition(const common::Point& cursorPosition);
+    common::Point getCursorPosition() const;
+
+    HWC3::Error setBuffer(buffer_handle_t buffer, const ndk::ScopedFileDescriptor& fence);
+    FencedBuffer& getBuffer();
+    buffer_handle_t waitAndGetBuffer();
+
+    HWC3::Error setSurfaceDamage(const std::vector<std::optional<common::Rect>>& damage);
+
+    HWC3::Error setBlendMode(common::BlendMode mode);
+    common::BlendMode getBlendMode() const;
+
+    HWC3::Error setColor(Color color);
+    Color getColor() const;
+
+    HWC3::Error setCompositionType(Composition composition);
+    Composition getCompositionType() const;
+
+    HWC3::Error setDataspace(common::Dataspace dataspace);
+    common::Dataspace getDataspace() const;
+
+    HWC3::Error setDisplayFrame(common::Rect frame);
+    common::Rect getDisplayFrame() const;
+
+    HWC3::Error setPlaneAlpha(float alpha);
+    float getPlaneAlpha() const;
+
+    HWC3::Error setSidebandStream(buffer_handle_t stream);
+
+    HWC3::Error setSourceCrop(common::FRect crop);
+    common::FRect getSourceCrop() const;
+    common::Rect getSourceCropInt() const;
+
+    HWC3::Error setTransform(common::Transform transform);
+    common::Transform getTransform() const;
+
+    HWC3::Error setVisibleRegion(const std::vector<std::optional<common::Rect>>& visible);
+    std::size_t getNumVisibleRegions() const;
+
+    HWC3::Error setZOrder(int32_t z);
+    int32_t getZOrder() const;
+
+    HWC3::Error setPerFrameMetadata(
+        const std::vector<std::optional<PerFrameMetadata>>& perFrameMetadata);
+
+    HWC3::Error setColorTransform(const std::vector<float>& colorTransform);
+    const std::optional<std::array<float, 16>>& getColorTransform() const;
+
+    HWC3::Error setBrightness(float brightness);
+    float getBrightness() const;
+
+    HWC3::Error setPerFrameMetadataBlobs(
+        const std::vector<std::optional<PerFrameMetadataBlob>>& perFrameMetadata);
+
+    HWC3::Error setLuts(const Luts& luts);
+    bool hasLuts() const;
+
+    // For log use only.
+    void logCompositionFallbackIfChanged(Composition to);
+
+   private:
+    const int64_t mId;
+    common::Point mCursorPosition;
+    FencedBuffer mBuffer;
+    common::BlendMode mBlendMode = common::BlendMode::NONE;
+    Color mColor = {0, 0, 0, 0};
+    Composition mCompositionType = Composition::INVALID;
+    common::Dataspace mDataspace = common::Dataspace::UNKNOWN;
+    struct CompositionTypeFallback {
+        Composition from;
+        Composition to;
+    };
+    // For log use only.
+    std::optional<CompositionTypeFallback> mLastCompositionFallback = std::nullopt;
+    common::Rect mDisplayFrame = {0, 0, -1, -1};
+    float mPlaneAlpha = 0.0f;
+    common::FRect mSourceCrop = {0.0f, 0.0f, -1.0f, -1.0f};
+    common::Transform mTransform = common::Transform{0};
+    std::vector<common::Rect> mVisibleRegion;
+    int32_t mZOrder = 0;
+    std::optional<std::array<float, 16>> mColorTransform;
+    float mBrightness = 1.0f;
+    bool mHasLuts = false;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/LruCache.h b/hals/hwc3/LruCache.h
new file mode 100644
index 00000000..f5b8f986
--- /dev/null
+++ b/hals/hwc3/LruCache.h
@@ -0,0 +1,81 @@
+// Copyright 2022 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+// http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#pragma once
+
+#include <list>
+#include <unordered_map>
+
+template <typename Key, typename Value>
+class LruCache {
+   public:
+    LruCache(std::size_t maxSize) : m_maxSize(maxSize) { m_table.reserve(maxSize); }
+
+    Value* get(const Key& key) {
+        auto tableIt = m_table.find(key);
+        if (tableIt == m_table.end()) {
+            return nullptr;
+        }
+
+        // Move to front.
+        auto elementsIt = tableIt->second;
+        m_elements.splice(elementsIt, m_elements, m_elements.begin());
+        return &elementsIt->value;
+    }
+
+    void set(const Key& key, Value&& value) {
+        auto tableIt = m_table.find(key);
+        if (tableIt == m_table.end()) {
+            if (m_table.size() >= m_maxSize) {
+                auto& kv = m_elements.back();
+                m_table.erase(kv.key);
+                m_elements.pop_back();
+            }
+        } else {
+            auto elementsIt = tableIt->second;
+            m_elements.erase(elementsIt);
+        }
+        m_elements.emplace_front(KeyValue{
+            key,
+            std::forward<Value>(value),
+        });
+        m_table[key] = m_elements.begin();
+    }
+
+    void remove(const Key& key) {
+        auto tableIt = m_table.find(key);
+        if (tableIt == m_table.end()) {
+            return;
+        }
+        auto elementsIt = tableIt->second;
+        m_elements.erase(elementsIt);
+        m_table.erase(tableIt);
+    }
+
+    void clear() {
+        m_elements.clear();
+        m_table.clear();
+    }
+
+   private:
+    struct KeyValue {
+        Key key;
+        Value value;
+    };
+
+    const std::size_t m_maxSize;
+    // Front is the most recently used and back is the least recently used.
+    std::list<KeyValue> m_elements;
+    std::unordered_map<Key, typename std::list<KeyValue>::iterator> m_table;
+};
diff --git a/hals/hwc3/Main.cpp b/hals/hwc3/Main.cpp
new file mode 100644
index 00000000..811d5f8a
--- /dev/null
+++ b/hals/hwc3/Main.cpp
@@ -0,0 +1,51 @@
+/*
+ * Copyright 2022, The Android Open Source Project
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
+
+#include <android-base/logging.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+#include <sched.h>
+
+#include "Composer.h"
+
+using aidl::android::hardware::graphics::composer3::impl::Composer;
+
+int main(int /*argc*/, char** /*argv*/) {
+    ALOGI("RanchuHWC (HWComposer3/HWC3) starting up...");
+
+    // same as SF main thread
+    struct sched_param param = {0};
+    param.sched_priority = 2;
+    if (sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &param) != 0) {
+        ALOGE("%s: failed to set priority: %s", __FUNCTION__, strerror(errno));
+    }
+
+    auto composer = ndk::SharedRefBase::make<Composer>();
+    CHECK(composer != nullptr);
+
+    const std::string instance = std::string() + Composer::descriptor + "/default";
+    binder_status_t status =
+        AServiceManager_addService(composer->asBinder().get(), instance.c_str());
+    CHECK(status == STATUS_OK);
+
+    // Thread pool for system libbinder (via libbinder_ndk) for aidl services
+    // IComposer and IDisplay
+    ABinderProcess_setThreadPoolMaxThreadCount(5);
+    ABinderProcess_startThreadPool();
+    ABinderProcess_joinThreadPool();
+
+    return EXIT_FAILURE;
+}
diff --git a/hals/hwc3/NoOpFrameComposer.cpp b/hals/hwc3/NoOpFrameComposer.cpp
new file mode 100644
index 00000000..b665d99b
--- /dev/null
+++ b/hals/hwc3/NoOpFrameComposer.cpp
@@ -0,0 +1,81 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "NoOpFrameComposer.h"
+
+#include "Display.h"
+#include "Drm.h"
+#include "Layer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+HWC3::Error NoOpFrameComposer::init() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::registerOnHotplugCallback(const HotplugCallback&) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::unregisterOnHotplugCallback() {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::onDisplayCreate(Display*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::onDisplayDestroy(Display*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::onDisplayClientTargetSet(Display*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::onActiveConfigChange(Display*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+};
+
+HWC3::Error NoOpFrameComposer::validateDisplay(Display*, DisplayChanges*) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error NoOpFrameComposer::presentDisplay(
+    Display*, ::android::base::unique_fd*,
+    std::unordered_map<int64_t, ::android::base::unique_fd>* /*outLayerFences*/) {
+    DEBUG_LOG("%s", __FUNCTION__);
+
+    return HWC3::Error::None;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/NoOpFrameComposer.h b/hals/hwc3/NoOpFrameComposer.h
new file mode 100644
index 00000000..a8b2acb5
--- /dev/null
+++ b/hals/hwc3/NoOpFrameComposer.h
@@ -0,0 +1,66 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_NOOPFRAMECOMPOSER_H
+#define ANDROID_HWC_NOOPFRAMECOMPOSER_H
+
+#include "Common.h"
+#include "Display.h"
+#include "DrmClient.h"
+#include "FrameComposer.h"
+#include "Gralloc.h"
+#include "Layer.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class NoOpFrameComposer : public FrameComposer {
+   public:
+    NoOpFrameComposer() = default;
+
+    NoOpFrameComposer(const NoOpFrameComposer&) = delete;
+    NoOpFrameComposer& operator=(const NoOpFrameComposer&) = delete;
+
+    NoOpFrameComposer(NoOpFrameComposer&&) = delete;
+    NoOpFrameComposer& operator=(NoOpFrameComposer&&) = delete;
+
+    HWC3::Error init() override;
+
+    HWC3::Error registerOnHotplugCallback(const HotplugCallback& cb) override;
+
+    HWC3::Error unregisterOnHotplugCallback() override;
+
+    HWC3::Error onDisplayCreate(Display*) override;
+
+    HWC3::Error onDisplayDestroy(Display*) override;
+
+    HWC3::Error onDisplayClientTargetSet(Display*) override;
+
+    // Determines if this composer can compose the given layers on the given
+    // display and requests changes for layers that can't not be composed.
+    HWC3::Error validateDisplay(Display* display, DisplayChanges* outChanges) override;
+
+    // Performs the actual composition of layers and presents the composed result
+    // to the display.
+    HWC3::Error presentDisplay(
+        Display* display, ::android::base::unique_fd* outDisplayFence,
+        std::unordered_map<int64_t, ::android::base::unique_fd>* outLayerFences) override;
+
+    HWC3::Error onActiveConfigChange(Display* /*display*/) override;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/OWNERS b/hals/hwc3/OWNERS
new file mode 100644
index 00000000..a6930b99
--- /dev/null
+++ b/hals/hwc3/OWNERS
@@ -0,0 +1,7 @@
+cstout@google.com
+doughorn@google.com
+kaiyili@google.com
+liyl@google.com
+msandy@google.com
+natsu@google.com
+tutankhamen@google.com
diff --git a/hals/hwc3/Time.h b/hals/hwc3/Time.h
new file mode 100644
index 00000000..f05e965a
--- /dev/null
+++ b/hals/hwc3/Time.h
@@ -0,0 +1,47 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_TIME_H
+#define ANDROID_HWC_TIME_H
+
+#include <utils/Timers.h>
+
+#include <chrono>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+using Nanoseconds = std::chrono::nanoseconds;
+
+using TimePoint = std::chrono::time_point<std::chrono::steady_clock>;
+
+inline TimePoint asTimePoint(int64_t nanos) { return TimePoint(Nanoseconds(nanos)); }
+
+inline TimePoint now() { return asTimePoint(systemTime(SYSTEM_TIME_MONOTONIC)); }
+
+inline int64_t asNanosDuration(Nanoseconds duration) { return duration.count(); }
+
+inline int64_t asNanosTimePoint(TimePoint time) {
+    TimePoint zero(Nanoseconds(0));
+    return static_cast<int64_t>(std::chrono::duration_cast<Nanoseconds>(time - zero).count());
+}
+
+constexpr int32_t HertzToPeriodNanos(uint32_t hertz) { return 1000 * 1000 * 1000 / hertz; }
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/VsyncThread.cpp b/hals/hwc3/VsyncThread.cpp
new file mode 100644
index 00000000..0ec1b23e
--- /dev/null
+++ b/hals/hwc3/VsyncThread.cpp
@@ -0,0 +1,179 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#include "VsyncThread.h"
+
+#include <utils/ThreadDefs.h>
+
+#include <thread>
+
+#include "Time.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+// Returns the timepoint of the next vsync after the 'now' timepoint that is
+// a multiple of 'vsyncPeriod' in-phase/offset-from 'previousSync'.
+//
+// Some examples:
+//  * vsyncPeriod=50ns previousVsync=500ns now=510ns => 550ns
+//  * vsyncPeriod=50ns previousVsync=300ns now=510ns => 550ns
+//  * vsyncPeriod=50ns previousVsync=500ns now=550ns => 550ns
+TimePoint GetNextVsyncInPhase(Nanoseconds vsyncPeriod, TimePoint previousVsync, TimePoint now) {
+    const auto elapsed = Nanoseconds(now - previousVsync);
+    const auto nextMultiple = (elapsed / vsyncPeriod) + 1;
+    return previousVsync + (nextMultiple * vsyncPeriod);
+}
+
+}  // namespace
+
+VsyncThread::VsyncThread(int64_t displayId) : mDisplayId(displayId) {
+    mPreviousVsync = std::chrono::steady_clock::now() - mVsyncPeriod;
+}
+
+VsyncThread::~VsyncThread() { stop(); }
+
+HWC3::Error VsyncThread::start(int32_t vsyncPeriodNanos) {
+    DEBUG_LOG("%s for display:%" PRIu64, __FUNCTION__, mDisplayId);
+
+    mVsyncPeriod = Nanoseconds(vsyncPeriodNanos);
+
+    mThread = std::thread([this]() { threadLoop(); });
+
+    // Truncate to 16 chars (15 + null byte) to satisfy pthread_setname_np max name length
+    // requirement.
+    const std::string name =
+            std::string("display_" + std::to_string(mDisplayId) + "_vsync_thread").substr(15);
+
+    int ret = pthread_setname_np(mThread.native_handle(), name.c_str());
+    if (ret != 0) {
+        ALOGE("%s: failed to set Vsync thread name: %s", __FUNCTION__, strerror(ret));
+    }
+
+    struct sched_param param = {
+        .sched_priority = ANDROID_PRIORITY_DISPLAY,
+    };
+    ret = pthread_setschedparam(mThread.native_handle(), SCHED_FIFO, &param);
+    if (ret != 0) {
+        ALOGE("%s: failed to set Vsync thread priority: %s", __FUNCTION__, strerror(ret));
+    }
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error VsyncThread::stop() {
+    mShuttingDown.store(true);
+    mThread.join();
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error VsyncThread::setCallbacks(const std::shared_ptr<IComposerCallback>& callback) {
+    DEBUG_LOG("%s for display:%" PRIu64, __FUNCTION__, mDisplayId);
+
+    std::unique_lock<std::mutex> lock(mStateMutex);
+
+    mCallbacks = callback;
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error VsyncThread::setVsyncEnabled(bool enabled) {
+    DEBUG_LOG("%s for display:%" PRIu64 " enabled:%d", __FUNCTION__, mDisplayId, enabled);
+
+    std::unique_lock<std::mutex> lock(mStateMutex);
+
+    mVsyncEnabled = enabled;
+
+    return HWC3::Error::None;
+}
+
+HWC3::Error VsyncThread::scheduleVsyncUpdate(int32_t newVsyncPeriod,
+                                             const VsyncPeriodChangeConstraints& constraints,
+                                             VsyncPeriodChangeTimeline* outTimeline) {
+    DEBUG_LOG("%s for display:%" PRIu64, __FUNCTION__, mDisplayId);
+
+    PendingUpdate update;
+    update.period = Nanoseconds(newVsyncPeriod);
+    update.updateAfter = asTimePoint(constraints.desiredTimeNanos);
+
+    std::unique_lock<std::mutex> lock(mStateMutex);
+    mPendingUpdate.emplace(std::move(update));
+
+    TimePoint nextVsync = GetNextVsyncInPhase(mVsyncPeriod, mPreviousVsync, update.updateAfter);
+
+    outTimeline->newVsyncAppliedTimeNanos = asNanosTimePoint(nextVsync);
+    outTimeline->refreshRequired = false;
+    outTimeline->refreshTimeNanos = 0;
+
+    return HWC3::Error::None;
+}
+
+Nanoseconds VsyncThread::updateVsyncPeriodLocked(TimePoint now) {
+    if (mPendingUpdate && now > mPendingUpdate->updateAfter) {
+        mVsyncPeriod = mPendingUpdate->period;
+        mPendingUpdate.reset();
+    }
+
+    return mVsyncPeriod;
+}
+
+void VsyncThread::threadLoop() {
+    ALOGI("Vsync thread for display:%" PRId64 " starting", mDisplayId);
+
+    Nanoseconds vsyncPeriod = mVsyncPeriod;
+
+    int vsyncs = 0;
+    TimePoint previousLog = std::chrono::steady_clock::now();
+
+    while (!mShuttingDown.load()) {
+        TimePoint now = std::chrono::steady_clock::now();
+        TimePoint nextVsync = GetNextVsyncInPhase(vsyncPeriod, mPreviousVsync, now);
+
+        std::this_thread::sleep_until(nextVsync);
+        {
+            std::unique_lock<std::mutex> lock(mStateMutex);
+
+            mPreviousVsync = nextVsync;
+
+            // Display has finished refreshing at previous vsync period. Update the
+            // vsync period if there was a pending update.
+            vsyncPeriod = updateVsyncPeriodLocked(mPreviousVsync);
+        }
+
+        if (mVsyncEnabled) {
+            if (mCallbacks) {
+                DEBUG_LOG("%s: for display:%" PRIu64 " calling vsync", __FUNCTION__, mDisplayId);
+                mCallbacks->onVsync(mDisplayId, asNanosTimePoint(nextVsync),
+                                    static_cast<int32_t>(asNanosDuration(vsyncPeriod)));
+            }
+        }
+
+        static constexpr const int kLogIntervalSeconds = 60;
+        if (now > (previousLog + std::chrono::seconds(kLogIntervalSeconds))) {
+            DEBUG_LOG("%s: for display:%" PRIu64 " send %" PRIu32 " in last %d seconds",
+                      __FUNCTION__, mDisplayId, vsyncs, kLogIntervalSeconds);
+            (void)vsyncs;
+            previousLog = now;
+            vsyncs = 0;
+        }
+        ++vsyncs;
+    }
+
+    ALOGI("Vsync thread for display:%" PRId64 " finished", mDisplayId);
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hals/hwc3/VsyncThread.h b/hals/hwc3/VsyncThread.h
new file mode 100644
index 00000000..0c477632
--- /dev/null
+++ b/hals/hwc3/VsyncThread.h
@@ -0,0 +1,86 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+#ifndef ANDROID_HWC_VSYNCTHREAD_H
+#define ANDROID_HWC_VSYNCTHREAD_H
+
+#include <aidl/android/hardware/graphics/composer3/VsyncPeriodChangeConstraints.h>
+#include <aidl/android/hardware/graphics/composer3/VsyncPeriodChangeTimeline.h>
+#include <android/hardware/graphics/common/1.0/types.h>
+
+#include <chrono>
+#include <mutex>
+#include <optional>
+#include <thread>
+
+#include "Common.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+// Generates Vsync signals in software.
+class VsyncThread {
+   public:
+    VsyncThread(int64_t id);
+    virtual ~VsyncThread();
+
+    VsyncThread(const VsyncThread&) = delete;
+    VsyncThread& operator=(const VsyncThread&) = delete;
+
+    VsyncThread(VsyncThread&&) = delete;
+    VsyncThread& operator=(VsyncThread&&) = delete;
+
+    HWC3::Error start(int32_t periodNanos);
+
+    HWC3::Error setCallbacks(const std::shared_ptr<IComposerCallback>& callback);
+
+    HWC3::Error setVsyncEnabled(bool enabled);
+
+    HWC3::Error scheduleVsyncUpdate(
+        int32_t newVsyncPeriod, const VsyncPeriodChangeConstraints& newVsyncPeriodChangeConstraints,
+        VsyncPeriodChangeTimeline* timeline);
+
+   private:
+    HWC3::Error stop();
+
+    void threadLoop();
+
+    std::chrono::nanoseconds updateVsyncPeriodLocked(
+        std::chrono::time_point<std::chrono::steady_clock> now);
+
+    const int64_t mDisplayId;
+
+    std::thread mThread;
+
+    std::mutex mStateMutex;
+
+    std::atomic<bool> mShuttingDown{false};
+
+    std::shared_ptr<IComposerCallback> mCallbacks;
+
+    bool mVsyncEnabled = false;
+    std::chrono::nanoseconds mVsyncPeriod;
+    std::chrono::time_point<std::chrono::steady_clock> mPreviousVsync;
+
+    struct PendingUpdate {
+        std::chrono::nanoseconds period;
+        std::chrono::time_point<std::chrono::steady_clock> updateAfter;
+    };
+    std::optional<PendingUpdate> mPendingUpdate;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
+
+#endif
diff --git a/hals/hwc3/apex_file_contexts b/hals/hwc3/apex_file_contexts
new file mode 100644
index 00000000..1af970fc
--- /dev/null
+++ b/hals/hwc3/apex_file_contexts
@@ -0,0 +1,3 @@
+(/.*)?                                                          u:object_r:vendor_file:s0
+/etc(/.*)?                                                      u:object_r:vendor_configs_file:s0
+/bin/hw/android\.hardware\.graphics\.composer3-service\.ranchu  u:object_r:hal_graphics_composer_default_exec:s0
diff --git a/hals/hwc3/apex_manifest.json b/hals/hwc3/apex_manifest.json
new file mode 100644
index 00000000..fa9e626b
--- /dev/null
+++ b/hals/hwc3/apex_manifest.json
@@ -0,0 +1,5 @@
+{
+    "name": "com.android.hardware.graphics.composer",
+    "version": 1,
+    "vendorBootstrap": true
+}
\ No newline at end of file
diff --git a/hals/hwc3/hwc3.rc b/hals/hwc3/hwc3.rc
new file mode 100644
index 00000000..ebb29483
--- /dev/null
+++ b/hals/hwc3/hwc3.rc
@@ -0,0 +1,7 @@
+service vendor.hwcomposer-3 /vendor/bin/hw/android.hardware.graphics.composer3-service.ranchu
+    class hal animation
+    user system
+    group graphics drmrpc
+    capabilities SYS_NICE
+    onrestart restart surfaceflinger
+    task_profiles ServiceCapacityLow
\ No newline at end of file
diff --git a/hals/hwc3/hwc3.xml b/hals/hwc3/hwc3.xml
new file mode 100644
index 00000000..4c4fb95e
--- /dev/null
+++ b/hals/hwc3/hwc3.xml
@@ -0,0 +1,10 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl">
+        <name>android.hardware.graphics.composer3</name>
+        <version>4</version>
+        <interface>
+            <name>IComposer</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</manifest>
\ No newline at end of file
diff --git a/libdebug/Android.bp b/hals/lib/debug/Android.bp
similarity index 100%
rename from libdebug/Android.bp
rename to hals/lib/debug/Android.bp
diff --git a/libdebug/include/debug.h b/hals/lib/debug/include/debug.h
similarity index 100%
rename from libdebug/include/debug.h
rename to hals/lib/debug/include/debug.h
diff --git a/qemud/Android.bp b/hals/lib/qemud/Android.bp
similarity index 100%
rename from qemud/Android.bp
rename to hals/lib/qemud/Android.bp
diff --git a/qemud/include/qemud.h b/hals/lib/qemud/include/qemud.h
similarity index 100%
rename from qemud/include/qemud.h
rename to hals/lib/qemud/include/qemud.h
diff --git a/qemud/qemud.cpp b/hals/lib/qemud/qemud.cpp
similarity index 100%
rename from qemud/qemud.cpp
rename to hals/lib/qemud/qemud.cpp
diff --git a/hals/sensors/multihal_sensors_qemu.cpp b/hals/sensors/multihal_sensors_qemu.cpp
index 985612e0..3c7b560c 100644
--- a/hals/sensors/multihal_sensors_qemu.cpp
+++ b/hals/sensors/multihal_sensors_qemu.cpp
@@ -335,8 +335,15 @@ void MultihalSensors::parseQemuSensorEventLocked(QemuSensorsProtocolState* state
             // Skip if the measurement id is not included.
             parsed = true;
         }
-
-     } else if (const char* values = testPrefix(buf, end, "guest-sync", ':')) {
+    } else if (const char* values = testPrefix(buf, end, "heading", ':')) {
+        float azimuthRad;
+        if (sscanf(values, "%f", &azimuthRad) == 1) {
+            const int azimuthDeg = int(azimuthRad / M_PI * 180.0 + 0.5f);
+            payload->data[0] = float((azimuthDeg + 360) % 360);
+            payload->data[1] = 10.0f; // precision
+            parsed = true;
+        }
+    } else if (const char* values = testPrefix(buf, end, "guest-sync", ':')) {
         long long value;
         if ((sscanf(values, "%lld", &value) == 1) && (value >= 0)) {
             const int64_t guestTimeNs = static_cast<int64_t>(value * 1000LL);
diff --git a/hals/sensors/sensor_list.cpp b/hals/sensors/sensor_list.cpp
index 44278e72..f895f1d2 100644
--- a/hals/sensors/sensor_list.cpp
+++ b/hals/sensors/sensor_list.cpp
@@ -41,6 +41,7 @@ const char* const kQemuSensorName[] = {
     "rgbc-light",
     "wrist-tilt",
     "acceleration-uncalibrated",
+    "heading",
 };
 
 const SensorInfo kAllSensors[] = {
@@ -358,7 +359,26 @@ const SensorInfo kAllSensors[] = {
         .flags = SensorFlagBits::DATA_INJECTION |
                  SensorFlagBits::ADDITIONAL_INFO |
                  SensorFlagBits::CONTINUOUS_MODE
-    }};
+    },
+    {
+        .sensorHandle = kSensorHandleHeading,
+        .name = "Goldfish heading sensor",
+        .vendor = kAospVendor,
+        .version = 1,
+        .type = static_cast<SensorType>(42),  // sensors/aidl/android/hardware/sensors/SensorType.aidl#HEADING
+        .typeAsString = "android.sensor.heading",
+        .maxRange = 359.9,
+        .resolution = 1.0,
+        .power = 3.0,
+        .minDelay = 10000,
+        .fifoReservedEventCount = 0,
+        .fifoMaxEventCount = 0,
+        .requiredPermission = "",
+        .maxDelay = 500000,
+        .flags = SensorFlagBits::DATA_INJECTION |
+                 SensorFlagBits::CONTINUOUS_MODE
+    },
+};
 
 constexpr int kSensorNumber = sizeof(kAllSensors) / sizeof(kAllSensors[0]);
 
diff --git a/hals/sensors/sensor_list.h b/hals/sensors/sensor_list.h
index 86e4d98f..2e4a7a83 100644
--- a/hals/sensors/sensor_list.h
+++ b/hals/sensors/sensor_list.h
@@ -39,6 +39,7 @@ constexpr int kSensorHandleHingeAngle2 = 13;
 constexpr int kSensorHandleHeartRate = 14;
 constexpr int kSensorHandleWristTilt = 16;
 constexpr int kSensorHandleAccelerometerUncalibrated = 17;
+constexpr int kSensorHandleHeading = 18;
 
 int getSensorNumber();
 bool isSensorHandleValid(int h);
diff --git a/init.ranchu.adb.setup.sh b/init/init.adb-setup.ranchu.sh
similarity index 100%
rename from init.ranchu.adb.setup.sh
rename to init/init.adb-setup.ranchu.sh
diff --git a/init_ranchu_device_state.sh b/init/init.device-state.ranchu.sh
similarity index 100%
rename from init_ranchu_device_state.sh
rename to init/init.device-state.ranchu.sh
diff --git a/init.ranchu-net.sh b/init/init.net.ranchu.sh
similarity index 100%
rename from init.ranchu-net.sh
rename to init/init.net.ranchu.sh
diff --git a/init.ranchu.rc b/init/init.ranchu.rc
similarity index 95%
rename from init.ranchu.rc
rename to init/init.ranchu.rc
index 8596973e..519aa7dd 100644
--- a/init.ranchu.rc
+++ b/init/init.ranchu.rc
@@ -70,7 +70,7 @@ on post-fs-data
     mkdir /data/vendor/var 0755 root root
     mkdir /data/vendor/var/run 0755 root root
 
-    start qemu-device-state
+    start ranchu-device-state
     start ranchu-adb-setup
 
 on zygote-start
@@ -93,18 +93,32 @@ service vendor.dlkm_loader /vendor/bin/dlkm_loader
     disabled
     oneshot
 
-service ranchu-setup /vendor/bin/init.ranchu-core.sh
+service ranchu-adb-setup /system_ext/bin/init.adb-setup.ranchu.sh
+    user system
+    group shell
+    stdio_to_kmsg
+    disabled
+    oneshot
+
+service ranchu-device-state /vendor/bin/init.device-state.ranchu.sh
     user root
     group root
     oneshot
     disabled
-
-service ranchu-adb-setup /system_ext/bin/init.ranchu.adb.setup.sh
-    user system
-    group shell
     stdio_to_kmsg
-    disabled
+
+service ranchu-net /vendor/bin/init.net.ranchu.sh
+    class late_start
+    user root
+    group root wakelock wifi
     oneshot
+    disabled    # Started on post-fs-data
+
+service ranchu-setup /vendor/bin/init.setup.ranchu.sh
+    user root
+    group root
+    oneshot
+    disabled
 
 on property:vendor.qemu.vport.gnss=*
     symlink ${vendor.qemu.vport.gnss} /dev/gnss0
@@ -121,13 +135,6 @@ on property:dev.bootcomplete=1 && property:vendor.qemu.dev.bootcomplete=0
 on post-fs-data && property:ro.boot.qemu.virtiowifi=1
     start ranchu-net
 
-service ranchu-net /vendor/bin/init.ranchu-net.sh
-    class late_start
-    user root
-    group root wakelock wifi
-    oneshot
-    disabled    # Started on post-fs-data
-
 # The qemu-props program is used to set various system
 # properties on boot. It must be run early during the boot
 # process to avoid race conditions with other daemons that
@@ -146,13 +153,6 @@ service qemu-props-bootcomplete /vendor/bin/qemu-props "bootcomplete"
     oneshot
     disabled
 
-service qemu-device-state /vendor/bin/init_ranchu_device_state.sh
-    user root
-    group root
-    oneshot
-    disabled
-    stdio_to_kmsg
-
 service goldfish-logcat /system/bin/logcat -f /dev/hvc1 ${ro.boot.logcat}
     class main
     user logd
@@ -160,6 +160,7 @@ service goldfish-logcat /system/bin/logcat -f /dev/hvc1 ${ro.boot.logcat}
 
 service bugreport /system/bin/dumpstate -d -p -z
     class main
+    user root
     disabled
     oneshot
     keycodes 114 115 116
@@ -198,7 +199,6 @@ service vendor.uwb_hal /vendor/bin/hw/android.hardware.uwb-service /dev/hvc2
 
 on property:sys.boot_completed=1
     trigger sys-boot-completed-set
-    start vendor.ril-daemon
 
 on sys-boot-completed-set && property:persist.sys.zram_enabled=1
     swapon_all /vendor/etc/fstab.${ro.hardware}
diff --git a/init.ranchu-core.sh b/init/init.setup.ranchu.sh
similarity index 100%
rename from init.ranchu-core.sh
rename to init/init.setup.ranchu.sh
diff --git a/init.system_ext.rc b/init/init.system_ext.rc
similarity index 80%
rename from init.system_ext.rc
rename to init/init.system_ext.rc
index 07711d16..f3736b63 100644
--- a/init.system_ext.rc
+++ b/init/init.system_ext.rc
@@ -1,7 +1,7 @@
 on property:init.svc.ranchu-adb-setup=stopped
     start adbd
 
-on property:init.svc.qemu-device-state=stopped && property:ro.boot.qemu.device_state=*
+on property:init.svc.ranchu-device-state=stopped && property:ro.boot.qemu.device_state=*
     mkdir /data/system/devicestate/ 0755 system system
     copy /data/vendor/device_state_configuration.xml /data/system/devicestate/device_state_configuration.xml
     rm /data/vendor/device_state_configuration.xml
diff --git a/ueventd.ranchu.rc b/init/ueventd.rc
similarity index 100%
rename from ueventd.ranchu.rc
rename to init/ueventd.rc
diff --git a/phone/overlay/frameworks/base/core/res/res/values/config.xml b/phone/overlay/frameworks/base/core/res/res/values/config.xml
index 841bc694..5a2f42b0 100644
--- a/phone/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/phone/overlay/frameworks/base/core/res/res/values/config.xml
@@ -92,12 +92,6 @@
         <item>network</item>
     </string-array>
 
-    <string-array name="config_perDeviceStateRotationLockDefaults" translatable="false">
-        <item>0:1</item> <!-- CLOSED -> LOCKED -->
-        <item>2:0:1</item> <!-- HALF_OPENED -> IGNORED and fallback to device state OPENED -->
-        <item>1:2</item> <!-- OPENED -> UNLOCKED -->
-    </string-array>
-
     <bool name="config_supportMicNearUltrasound">true</bool>
     <bool name="config_supportSpeakerNearUltrasound">true</bool>
 
diff --git a/pixel_fold/device_state_configuration.xml b/pixel_fold/device_state_configuration.xml
index 8a181431..5b8c5a5c 100644
--- a/pixel_fold/device_state_configuration.xml
+++ b/pixel_fold/device_state_configuration.xml
@@ -2,6 +2,12 @@
     <device-state>
         <identifier>0</identifier>
         <name>CLOSED</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_POLICY_CANCEL_OVERRIDE_REQUESTS</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_SLEEP</property>
+        </properties>
         <conditions>
             <sensor>
                 <type>android.sensor.hinge_angle</type>
@@ -16,6 +22,11 @@
     <device-state>
         <identifier>1</identifier>
         <name>HALF_OPENED</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
+        </properties>
         <conditions>
             <sensor>
                 <type>android.sensor.hinge_angle</type>
@@ -30,6 +41,11 @@
     <device-state>
         <identifier>2</identifier>
         <name>OPENED</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
+       </properties>
             <conditions>
                 <sensor>
                     <type>android.sensor.hinge_angle</type>
@@ -44,6 +60,13 @@
     <device-state>
         <identifier>3</identifier>
         <name>REAR_DISPLAY_MODE</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_EMULATED_ONLY</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POLICY_AVAILABLE_FOR_APP_REQUEST</property>
+            <property>com.android.server.policy.PROPERTY_FEATURE_REAR_DISPLAY</property>
+        </properties>
+
         <flags>
             <flag>FLAG_EMULATED_ONLY</flag>
         </flags>
diff --git a/pixel_fold2/device_state_configuration.xml b/pixel_fold2/device_state_configuration.xml
index 8a181431..5b8c5a5c 100644
--- a/pixel_fold2/device_state_configuration.xml
+++ b/pixel_fold2/device_state_configuration.xml
@@ -2,6 +2,12 @@
     <device-state>
         <identifier>0</identifier>
         <name>CLOSED</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_POLICY_CANCEL_OVERRIDE_REQUESTS</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_SLEEP</property>
+        </properties>
         <conditions>
             <sensor>
                 <type>android.sensor.hinge_angle</type>
@@ -16,6 +22,11 @@
     <device-state>
         <identifier>1</identifier>
         <name>HALF_OPENED</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
+        </properties>
         <conditions>
             <sensor>
                 <type>android.sensor.hinge_angle</type>
@@ -30,6 +41,11 @@
     <device-state>
         <identifier>2</identifier>
         <name>OPENED</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
+       </properties>
             <conditions>
                 <sensor>
                     <type>android.sensor.hinge_angle</type>
@@ -44,6 +60,13 @@
     <device-state>
         <identifier>3</identifier>
         <name>REAR_DISPLAY_MODE</name>
+        <properties>
+            <property>com.android.server.policy.PROPERTY_EMULATED_ONLY</property>
+            <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+            <property>com.android.server.policy.PROPERTY_POLICY_AVAILABLE_FOR_APP_REQUEST</property>
+            <property>com.android.server.policy.PROPERTY_FEATURE_REAR_DISPLAY</property>
+        </properties>
+
         <flags>
             <flag>FLAG_EMULATED_ONLY</flag>
         </flags>
diff --git a/product/generic.mk b/product/generic.mk
index 74504a66..f1870181 100644
--- a/product/generic.mk
+++ b/product/generic.mk
@@ -27,9 +27,7 @@ ifneq ($(EMULATOR_VENDOR_NO_MANIFEST_FILE),true)
 DEVICE_MANIFEST_FILE += device/generic/goldfish/manifest.xml
 endif
 
-PRODUCT_SOONG_NAMESPACES += \
-    device/generic/goldfish \
-    device/generic/goldfish-opengl
+PRODUCT_SOONG_NAMESPACES += device/generic/goldfish
 
 TARGET_USES_MKE2FS := true
 
@@ -200,11 +198,15 @@ endif
 
 ifneq ($(EMULATOR_VENDOR_NO_CAMERA),true)
 PRODUCT_SOONG_NAMESPACES += \
-    hardware/google/camera \
     hardware/google/camera/devices/EmulatedCamera \
 
+ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
+PRODUCT_PACKAGES += android.hardware.camera.provider.ranchu_minigbm
+else
+PRODUCT_PACKAGES += android.hardware.camera.provider.ranchu
+endif
+
 PRODUCT_PACKAGES += \
-    android.hardware.camera.provider.ranchu \
     android.hardware.camera.provider@2.7-service-google \
     libgooglecamerahwl_impl \
     android.hardware.camera.flash-autofocus.prebuilt.xml \
@@ -213,11 +215,10 @@ PRODUCT_PACKAGES += \
     android.hardware.camera.full.prebuilt.xml \
     android.hardware.camera.raw.prebuilt.xml \
 
-PRODUCT_COPY_FILES += \
-    hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_back.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_back.json \
-    hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_front.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_front.json \
-    hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_depth.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_depth.json \
-
+PRODUCT_PACKAGES += \
+    emu_camera_back.json \
+    emu_camera_front.json \
+    emu_camera_depth.json
 endif
 
 ifneq ($(EMULATOR_VENDOR_NO_SOUND),true)
@@ -288,7 +289,6 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/codecs/media/profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml \
     device/generic/goldfish/codecs/media/codecs_google_video_default.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_video.xml \
     device/generic/goldfish/codecs/media/codecs.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs.xml \
-    device/generic/goldfish/codecs/media/codecs_performance.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance.xml \
     device/generic/goldfish/codecs/media/$(CODECS_PERFORMANCE_C2_PROFILE):$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance_c2.xml \
 
 
@@ -299,13 +299,13 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/etc/atrace_categories.txt:$(TARGET_COPY_OUT_VENDOR)/etc/atrace/atrace_categories.txt \
     device/generic/goldfish/emulator-info.txt:data/misc/emulator/version.txt \
     device/generic/goldfish/data/etc/local.prop:data/local.prop \
-    device/generic/goldfish/init.ranchu.adb.setup.sh:$(TARGET_COPY_OUT_SYSTEM_EXT)/bin/init.ranchu.adb.setup.sh \
-    device/generic/goldfish/init_ranchu_device_state.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init_ranchu_device_state.sh \
-    device/generic/goldfish/init.ranchu-core.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.ranchu-core.sh \
-    device/generic/goldfish/init.ranchu-net.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.ranchu-net.sh \
-    device/generic/goldfish/init.ranchu.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.ranchu.rc \
-    device/generic/goldfish/init.system_ext.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.system_ext.rc \
-    device/generic/goldfish/ueventd.ranchu.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc \
+    device/generic/goldfish/init/init.adb-setup.ranchu.sh:$(TARGET_COPY_OUT_SYSTEM_EXT)/bin/init.adb-setup.ranchu.sh \
+    device/generic/goldfish/init/init.device-state.ranchu.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.device-state.ranchu.sh \
+    device/generic/goldfish/init/init.net.ranchu.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.net.ranchu.sh \
+    device/generic/goldfish/init/init.setup.ranchu.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.setup.ranchu.sh \
+    device/generic/goldfish/init/init.ranchu.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.ranchu.rc \
+    device/generic/goldfish/init/init.system_ext.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.system_ext.rc \
+    device/generic/goldfish/init/ueventd.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc \
     device/generic/goldfish/input/virtio_input_rotary.idc:$(TARGET_COPY_OUT_VENDOR)/usr/idc/virtio_input_rotary.idc \
     device/generic/goldfish/input/qwerty2.idc:$(TARGET_COPY_OUT_VENDOR)/usr/idc/qwerty2.idc \
     device/generic/goldfish/input/qwerty2.kcm:$(TARGET_COPY_OUT_VENDOR)/usr/keychars/qwerty2.kcm \
@@ -341,3 +341,5 @@ PRODUCT_COPY_FILES += \
 
 # Goldfish uses 6.X kernels.
 PRODUCT_ENABLE_UFFD_GC := true
+
+PRODUCT_ENFORCE_SELINUX_TREBLE_LABELING := true
diff --git a/product/versions.mk b/product/versions.mk
index 221d8a99..ae86bcec 100644
--- a/product/versions.mk
+++ b/product/versions.mk
@@ -13,5 +13,5 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-PRODUCT_SHIPPING_API_LEVEL := 35
-EMULATOR_MINIMAL_VERSION := 35.2.10
+PRODUCT_SHIPPING_API_LEVEL := 36
+EMULATOR_MINIMAL_VERSION := 35.4.9
diff --git a/rro_overlays/UwbOverlay/res/values/config.xml b/rro_overlays/UwbOverlay/res/values/config.xml
index 93401b41..838ed03f 100644
--- a/rro_overlays/UwbOverlay/res/values/config.xml
+++ b/rro_overlays/UwbOverlay/res/values/config.xml
@@ -15,4 +15,5 @@
 -->
 <resources>
   <bool name="is_multicast_list_update_ntf_v2_supported">true</bool>
-</resources>
\ No newline at end of file
+  <bool name="is_multicast_list_update_rsp_v2_supported">true</bool>
+</resources>
diff --git a/sepolicy/system_ext/private/file_contexts b/sepolicy/system_ext/private/file_contexts
new file mode 100644
index 00000000..0bda2973
--- /dev/null
+++ b/sepolicy/system_ext/private/file_contexts
@@ -0,0 +1 @@
+/system_ext/bin/init\.adb-setup\.ranchu\.sh u:object_r:goldfish_adb_setup_exec:s0
diff --git a/sepolicy/system_ext/private/goldfish_adb_setup.te b/sepolicy/system_ext/private/goldfish_adb_setup.te
new file mode 100644
index 00000000..719cc404
--- /dev/null
+++ b/sepolicy/system_ext/private/goldfish_adb_setup.te
@@ -0,0 +1,15 @@
+type goldfish_adb_setup, domain, coredomain;
+type goldfish_adb_setup_exec, system_file_type, exec_type, file_type;
+
+init_daemon_domain(goldfish_adb_setup)
+
+allow goldfish_adb_setup shell_exec:file { rx_file_perms };
+
+# Allow write to /dev/kmsg
+allow goldfish_adb_setup kmsg_debug_device:chr_file { w_file_perms getattr ioctl };
+
+# Allow read/write /data/misc/adb/adb_keys
+allow goldfish_adb_setup adb_keys_file:file { create setattr rw_file_perms };
+allow goldfish_adb_setup adb_keys_file:dir { search add_name write };
+
+allow goldfish_adb_setup toolbox_exec:file { getattr execute read open execute_no_trans map };
diff --git a/sepolicy/vendor/file_contexts b/sepolicy/vendor/file_contexts
index a2bc01c9..91a73cef 100644
--- a/sepolicy/vendor/file_contexts
+++ b/sepolicy/vendor/file_contexts
@@ -31,11 +31,10 @@
 # UWB
 /dev/hvc2                    u:object_r:uwb_device:s0
 
+/vendor/bin/init\.device-state\.ranchu\.sh u:object_r:init_ranchu_device_state_exec:s0
+/vendor/bin/init\.net\.ranchu\.sh u:object_r:goldfish_setup_exec:s0
+/vendor/bin/init\.setup\.ranchu\.sh u:object_r:goldfish_setup_exec:s0
 
-/system_ext/bin/init\.ranchu\.adb\.setup\.sh u:object_r:goldfish_system_setup_exec:s0
-/vendor/bin/init_ranchu_device_state\.sh u:object_r:init_ranchu_device_state_exec:s0
-/vendor/bin/init\.ranchu-core\.sh u:object_r:goldfish_setup_exec:s0
-/vendor/bin/init\.ranchu-net\.sh u:object_r:goldfish_setup_exec:s0
 /vendor/bin/dlkm_loader  u:object_r:dlkm_loader_exec:s0
 /vendor/bin/qemu-props       u:object_r:qemu_props_exec:s0
 /vendor/bin/mac80211_create_radios u:object_r:mac80211_create_radios_exec:s0
@@ -82,6 +81,7 @@
 
 # not yet AOSP HALs
 /vendor/bin/hw/android\.hardware\.camera\.provider\.ranchu u:object_r:hal_camera_default_exec:s0
+/vendor/bin/hw/android\.hardware\.camera\.provider\.ranchu_minigbm u:object_r:hal_camera_default_exec:s0
 /vendor/bin/hw/android\.hardware\.camera\.provider@2\.7-service-google u:object_r:hal_camera_default_exec:s0
 /vendor/bin/hw/android\.hardware\.rebootescrow-service\.default        u:object_r:hal_rebootescrow_default_exec:s0
 /vendor/bin/hw/android\.hardware\.contexthub-service\.example        u:object_r:hal_contexthub_default_exec:s0
diff --git a/sepolicy/vendor/goldfish_system_setup.te b/sepolicy/vendor/goldfish_system_setup.te
deleted file mode 100644
index 3152230d..00000000
--- a/sepolicy/vendor/goldfish_system_setup.te
+++ /dev/null
@@ -1,16 +0,0 @@
-# goldfish-system-setup service: runs init.qemu-adb-keys.sh script
-type goldfish_system_setup, domain, coredomain;
-type goldfish_system_setup_exec, system_file_type, exec_type, file_type;
-
-init_daemon_domain(goldfish_system_setup)
-
-allow goldfish_system_setup shell_exec:file { rx_file_perms };
-
-# Allow write to /dev/kmsg
-allow goldfish_system_setup kmsg_debug_device:chr_file { w_file_perms getattr ioctl };
-
-# Allow read/write /data/misc/adb/adb_keys
-allow goldfish_system_setup adb_keys_file:file { create setattr rw_file_perms };
-allow goldfish_system_setup adb_keys_file:dir { search add_name write };
-
-allow goldfish_system_setup toolbox_exec:file { getattr execute read open execute_no_trans map };
```

