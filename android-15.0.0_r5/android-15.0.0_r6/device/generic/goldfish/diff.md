```diff
diff --git a/64bitonly/product/sdk_phone64_arm64_uwb.mk b/64bitonly/product/sdk_phone64_arm64_minigbm.mk
similarity index 75%
rename from 64bitonly/product/sdk_phone64_arm64_uwb.mk
rename to 64bitonly/product/sdk_phone64_arm64_minigbm.mk
index ff62c0fa..9f8f53bf 100644
--- a/64bitonly/product/sdk_phone64_arm64_uwb.mk
+++ b/64bitonly/product/sdk_phone64_arm64_minigbm.mk
@@ -15,12 +15,12 @@
 #
 
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/data/etc/advancedFeatures.ini.uwb:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/advancedFeatures.ini.minigbm:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/config.ini.nexus5:config.ini
 
 $(call inherit-product, device/generic/goldfish/64bitonly/product/sdk_phone64_arm64.mk)
-$(call inherit-product, device/generic/goldfish/product/uwb.mk)
 
 PRODUCT_BRAND := Android
-PRODUCT_NAME := sdk_phone64_arm64_uwb
+PRODUCT_NAME := sdk_phone64_arm64_minigbm
 PRODUCT_DEVICE := emu64a
-PRODUCT_MODEL := Android SDK built for arm64_uwb
+PRODUCT_MODEL := Android SDK built for arm64_minigbm
diff --git a/64bitonly/product/sdk_phone64_arm64_riscv64.mk b/64bitonly/product/sdk_phone64_arm64_riscv64.mk
new file mode 100644
index 00000000..00862c5c
--- /dev/null
+++ b/64bitonly/product/sdk_phone64_arm64_riscv64.mk
@@ -0,0 +1,27 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+# sdk_phone64_arm64 with riscv64 translated
+
+$(call inherit-product, device/generic/goldfish/64bitonly/product/sdk_phone64_arm64.mk)
+
+# TODO(b/303700901): Add riscv64 translation support.
+
+# Overrides
+PRODUCT_BRAND := Android
+PRODUCT_NAME := sdk_phone64_arm64_riscv64
+PRODUCT_DEVICE := emu64ar
+PRODUCT_MODEL := Android SDK built for arm64 with riscv64 translated
diff --git a/64bitonly/product/sdk_phone64_x86_64_uwb.mk b/64bitonly/product/sdk_phone64_x86_64_minigbm.mk
similarity index 75%
rename from 64bitonly/product/sdk_phone64_x86_64_uwb.mk
rename to 64bitonly/product/sdk_phone64_x86_64_minigbm.mk
index 622ca0af..e485e249 100644
--- a/64bitonly/product/sdk_phone64_x86_64_uwb.mk
+++ b/64bitonly/product/sdk_phone64_x86_64_minigbm.mk
@@ -15,12 +15,12 @@
 #
 
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/data/etc/advancedFeatures.ini.uwb:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/advancedFeatures.ini.minigbm:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/config.ini.nexus5:config.ini
 
 $(call inherit-product, device/generic/goldfish/64bitonly/product/sdk_phone64_x86_64.mk)
-$(call inherit-product, device/generic/goldfish/product/uwb.mk)
 
 PRODUCT_BRAND := Android
-PRODUCT_NAME := sdk_phone64_x86_64_uwb
+PRODUCT_NAME := sdk_phone64_x86_64_minigbm
 PRODUCT_DEVICE := emu64x
-PRODUCT_MODEL := Android SDK built for x86_64_uwb
+PRODUCT_MODEL := Android SDK built for x86_64_minigbm
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index e277963d..e29be79b 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -1,13 +1,14 @@
 PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/64bitonly/product/sdk_phone64_x86_64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_phone16k_x86_64.mk \
+    $(LOCAL_DIR)/64bitonly/product/sdk_phone64_x86_64_minigbm.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_phone64_x86_64_riscv64.mk \
-    $(LOCAL_DIR)/64bitonly/product/sdk_phone64_x86_64_uwb.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_tablet_arm64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_tablet_x86_64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_phone64_arm64.mk \
-    $(LOCAL_DIR)/64bitonly/product/sdk_phone64_arm64_uwb.mk \
+    $(LOCAL_DIR)/64bitonly/product/sdk_phone64_arm64_minigbm.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_phone16k_arm64.mk \
+    $(LOCAL_DIR)/64bitonly/product/sdk_phone64_arm64_riscv64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_slim_x86_64.mk \
     $(LOCAL_DIR)/64bitonly/product/sdk_slim_arm64.mk \
     $(LOCAL_DIR)/fvpbase/fvp.mk \
diff --git a/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp b/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp
index 26c7a439..f60b54ef 100644
--- a/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp
+++ b/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp
@@ -16,23 +16,23 @@
 */
 
 #define LOG_TAG "android_emulator_multidisplay_JNI"
-#include <gui/BufferQueue.h>
+
+#include <com_android_graphics_libgui_flags.h>
+#include <gralloc_cb_bp.h>
 #include <gui/BufferItemConsumer.h>
-#include <gui/Surface.h>
+#include <gui/BufferQueue.h>
 #include <gui/ISurfaceComposer.h>
+#include <gui/Surface.h>
 #include <gui/SurfaceComposerClient.h>
-
-#include <sys/epoll.h>
-
-#include <gralloc_cb_bp.h>
+#include <nativehelper/ScopedLocalRef.h>
 #include <qemu_pipe_bp.h>
+#include <sys/epoll.h>
 
-#include "utils/Log.h"
-#include "nativehelper/JNIHelp.h"
-#include <nativehelper/ScopedLocalRef.h>
-#include "jni.h"
 #include "android_runtime/AndroidRuntime.h"
 #include "android_runtime/android_view_Surface.h"
+#include "jni.h"
+#include "nativehelper/JNIHelp.h"
+#include "utils/Log.h"
 
 #define MAX_DISPLAYS 10
 
@@ -94,15 +94,25 @@ static jobject nativeCreateSurface(JNIEnv *env, jobject obj, jint id, jint width
 {
     ALOGI("create surface for %d", id);
     // Create surface for this new display
+#if COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
+    sp<BufferItemConsumer> bufferItemConsumer =
+        new BufferItemConsumer(GRALLOC_USAGE_HW_RENDER);
+#else
     sp<IGraphicBufferProducer> producer;
     sp<IGraphicBufferConsumer> consumer;
     sp<BufferItemConsumer> bufferItemConsumer;
     BufferQueue::createBufferQueue(&producer, &consumer);
     bufferItemConsumer = new BufferItemConsumer(consumer, GRALLOC_USAGE_HW_RENDER);
+#endif  // COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
     gFrameListener[id] = new FrameListener(bufferItemConsumer, id);
     gFrameListener[id]->setDefaultBufferSize(width, height);
     bufferItemConsumer->setFrameAvailableListener(gFrameListener[id]);
+#if COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
+    return android_view_Surface_createFromSurface(
+        env, bufferItemConsumer->getSurface());
+#else
     return android_view_Surface_createFromIGraphicBufferProducer(env, producer);
+#endif  // COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
 }
 
 static jint nativeOpen(JNIEnv* env, jobject obj) {
diff --git a/board/emu64a16k/BoardConfig.mk b/board/emu64a16k/BoardConfig.mk
index 9b549a67..aca13088 100644
--- a/board/emu64a16k/BoardConfig.mk
+++ b/board/emu64a16k/BoardConfig.mk
@@ -22,6 +22,8 @@ TARGET_CPU_ABI := arm64-v8a
 TARGET_2ND_ARCH_VARIANT := armv8-a
 TARGET_2ND_CPU_VARIANT := generic
 
+TARGET_BOOTS_16K := true
+
 include device/generic/goldfish/board/BoardConfigCommon.mk
 
 BOARD_BOOTIMAGE_PARTITION_SIZE := 0x02000000
diff --git a/board/emu64ar/BoardConfig.mk b/board/emu64ar/BoardConfig.mk
new file mode 100644
index 00000000..fdcedb51
--- /dev/null
+++ b/board/emu64ar/BoardConfig.mk
@@ -0,0 +1,34 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+# arm64 emulator specific definitions
+TARGET_ARCH := arm64
+TARGET_ARCH_VARIANT := armv8-a
+TARGET_CPU_VARIANT := generic
+TARGET_CPU_ABI := arm64-v8a
+
+TARGET_2ND_ARCH_VARIANT := armv8-a
+TARGET_2ND_CPU_VARIANT := generic
+
+TARGET_NATIVE_BRIDGE_ARCH := riscv64
+TARGET_NATIVE_BRIDGE_ARCH_VARIANT :=
+TARGET_NATIVE_BRIDGE_CPU_VARIANT := generic
+TARGET_NATIVE_BRIDGE_ABI := riscv64
+
+include device/generic/goldfish/board/BoardConfigCommon.mk
+
+BOARD_BOOTIMAGE_PARTITION_SIZE := 0x02000000
+BOARD_USERDATAIMAGE_PARTITION_SIZE := 576716800
diff --git a/board/emu64ar/README.txt b/board/emu64ar/README.txt
new file mode 100644
index 00000000..49ff7d15
--- /dev/null
+++ b/board/emu64ar/README.txt
@@ -0,0 +1,10 @@
+The "emu64ar" product defines a non-hardware-specific IA target without a
+kernel or bootloader.
+
+This only supports 64-bit ABI and translated riscv64 ABI.
+
+It can be used to build the entire user-level system, and will work with the
+IA version of the emulator,
+
+It is not a product "base class"; no other products inherit from it or use it
+in any way.
diff --git a/board/emu64x16k/BoardConfig.mk b/board/emu64x16k/BoardConfig.mk
index 7ac58287..8cf44bdd 100644
--- a/board/emu64x16k/BoardConfig.mk
+++ b/board/emu64x16k/BoardConfig.mk
@@ -19,6 +19,8 @@ TARGET_ARCH := x86_64
 TARGET_ARCH_VARIANT := x86_64
 TARGET_2ND_ARCH_VARIANT := x86_64
 
+TARGET_BOOTS_16K := true
+
 include device/generic/goldfish/board/BoardConfigCommon.mk
 
 BOARD_USERDATAIMAGE_PARTITION_SIZE := 576716800
diff --git a/board/emu64xa16k/BoardConfig.mk b/board/emu64xa16k/BoardConfig.mk
index 1ba32259..86963230 100644
--- a/board/emu64xa16k/BoardConfig.mk
+++ b/board/emu64xa16k/BoardConfig.mk
@@ -24,6 +24,8 @@ TARGET_NATIVE_BRIDGE_ARCH_VARIANT := armv8-a
 TARGET_NATIVE_BRIDGE_CPU_VARIANT := generic
 TARGET_NATIVE_BRIDGE_ABI := arm64-v8a
 
+TARGET_BOOTS_16K := true
+
 include device/generic/goldfish/board/BoardConfigCommon.mk
 
 BOARD_USERDATAIMAGE_PARTITION_SIZE := 576716800
diff --git a/board/kernel/arm64.mk b/board/kernel/arm64.mk
index 48697292..6ab08763 100644
--- a/board/kernel/arm64.mk
+++ b/board/kernel/arm64.mk
@@ -48,3 +48,7 @@ BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/generic/goldfish/board/kernel/kernel_modules.blocklist
 
 EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)-gz
+
+# BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/board/kernel/arm64_cmdline.txt:kernel_cmdline.txt
diff --git a/board/kernel/arm64_16k.mk b/board/kernel/arm64_16k.mk
index 85c780ad..f1a3a066 100644
--- a/board/kernel/arm64_16k.mk
+++ b/board/kernel/arm64_16k.mk
@@ -50,3 +50,7 @@ BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/generic/goldfish/board/kernel/kernel_modules.blocklist
 
 EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)-gz
+
+# BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/board/kernel/arm64_16k_cmdline.txt:kernel_cmdline.txt
diff --git a/board/kernel/arm64_16k_cmdline.txt b/board/kernel/arm64_16k_cmdline.txt
new file mode 100644
index 00000000..074d768a
--- /dev/null
+++ b/board/kernel/arm64_16k_cmdline.txt
@@ -0,0 +1 @@
+8250.nr_uarts=1
diff --git a/board/kernel/arm64_cmdline.txt b/board/kernel/arm64_cmdline.txt
new file mode 100644
index 00000000..074d768a
--- /dev/null
+++ b/board/kernel/arm64_cmdline.txt
@@ -0,0 +1 @@
+8250.nr_uarts=1
diff --git a/board/kernel/x86_64.mk b/board/kernel/x86_64.mk
index 2622da6e..645be598 100644
--- a/board/kernel/x86_64.mk
+++ b/board/kernel/x86_64.mk
@@ -47,3 +47,7 @@ BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/generic/goldfish/board/kernel/kernel_modules.blocklist
 
 EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)
+
+# BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/board/kernel/x86_64_cmdline.txt:kernel_cmdline.txt
diff --git a/board/kernel/x86_64_16k.mk b/board/kernel/x86_64_16k.mk
index b2740db8..18e71f8f 100644
--- a/board/kernel/x86_64_16k.mk
+++ b/board/kernel/x86_64_16k.mk
@@ -48,7 +48,8 @@ BOARD_VENDOR_KERNEL_MODULES := \
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/generic/goldfish/board/kernel/kernel_modules.blocklist
 
-# Emulate 16KB page size
-BOARD_KERNEL_CMDLINE += androidboot.page_shift=14
-
 EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)
+
+# BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/board/kernel/x86_64_16k_cmdline.txt:kernel_cmdline.txt
diff --git a/board/kernel/x86_64_16k_cmdline.txt b/board/kernel/x86_64_16k_cmdline.txt
new file mode 100644
index 00000000..9d2b51f3
--- /dev/null
+++ b/board/kernel/x86_64_16k_cmdline.txt
@@ -0,0 +1 @@
+8250.nr_uarts=1 clocksource=pit page_shift=14
diff --git a/board/kernel/x86_64_cmdline.txt b/board/kernel/x86_64_cmdline.txt
new file mode 100644
index 00000000..76198b55
--- /dev/null
+++ b/board/kernel/x86_64_cmdline.txt
@@ -0,0 +1 @@
+8250.nr_uarts=1 clocksource=pit
diff --git a/camera/FakeRotatingCamera.cpp b/camera/FakeRotatingCamera.cpp
index 17966ee3..31ab6c36 100644
--- a/camera/FakeRotatingCamera.cpp
+++ b/camera/FakeRotatingCamera.cpp
@@ -23,7 +23,6 @@
 #include <ui/GraphicBufferAllocator.h>
 #include <ui/GraphicBufferMapper.h>
 
-#include <gralloc_cb_bp.h>
 #include <qemu_pipe_bp.h>
 
 #define GL_GLEXT_PROTOTYPES
@@ -316,14 +315,13 @@ bool FakeRotatingCamera::configure(const CameraMetadata& sessionParams,
         if (si.pixelFormat != PixelFormat::RGBA_8888) {
             const native_handle_t* buffer;
             GraphicBufferAllocator& gba = GraphicBufferAllocator::get();
-            uint32_t stride;
 
             if (gba.allocate(si.size.width, si.size.height,
                     static_cast<int>(PixelFormat::RGBA_8888), 1,
                     static_cast<uint64_t>(usageOr(BufferUsage::GPU_RENDER_TARGET,
                                                   usageOr(BufferUsage::CPU_READ_OFTEN,
                                                           BufferUsage::CAMERA_OUTPUT))),
-                    &buffer, &stride, kClass) == NO_ERROR) {
+                    &buffer, &si.stride, kClass) == NO_ERROR) {
                 si.rgbaBuffer.reset(buffer);
             } else {
                 mStreamInfoCache.clear();
@@ -731,15 +729,10 @@ bool FakeRotatingCamera::drawSceneImpl(const float pvMatrix44[]) const {
 bool FakeRotatingCamera::renderIntoRGBA(const StreamInfo& si,
                                         const RenderParams& renderParams,
                                         const native_handle_t* rgbaBuffer) const {
-    const cb_handle_t* const cb = cb_handle_t::from(rgbaBuffer);
-    if (!cb) {
-        return FAILURE(false);
-    }
-
     const auto gb = sp<GraphicBuffer>::make(
         rgbaBuffer, GraphicBuffer::WRAP_HANDLE, si.size.width,
         si.size.height, static_cast<int>(si.pixelFormat), 1,
-        static_cast<uint64_t>(si.usage), cb->stride);
+        static_cast<uint64_t>(si.usage), si.stride);
 
     const EGLClientBuffer clientBuf =
         eglGetNativeClientBufferANDROID(gb->toAHardwareBuffer());
diff --git a/camera/FakeRotatingCamera.h b/camera/FakeRotatingCamera.h
index 48bec3f6..9a53c355 100644
--- a/camera/FakeRotatingCamera.h
+++ b/camera/FakeRotatingCamera.h
@@ -74,6 +74,7 @@ private:
         Rect<uint16_t> size;
         PixelFormat pixelFormat;
         uint32_t blobBufferSize;
+        uint32_t stride;
     };
 
     struct SensorValues {
diff --git a/camera/arm64/media_codecs_google_video_default.xml b/camera/arm64/media_codecs_google_video_default.xml
deleted file mode 100644
index 2a42e10e..00000000
--- a/camera/arm64/media_codecs_google_video_default.xml
+++ /dev/null
@@ -1,225 +0,0 @@
-<?xml version="1.0" encoding="utf-8" ?>
-<!-- Copyright (C) 2014 The Android Open Source Project
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
-<Included>
-    <Decoders>
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
-            <Limit name="measured-frame-rate-3840x2160" range="235-247" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
-        <MediaCodec name="c2.goldfish.h264.decoder" type="video/avc">
-            <Limit name="size" min="96x96" max="4096x4096" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" range="24-2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-3840x2160" value="30" />
-            <Limit name="measured-frame-rate-320x240" range="1000-1500" />
-            <Limit name="measured-frame-rate-720x480" range="400-800" />
-            <Limit name="measured-frame-rate-1280x720" range="227-251" />
-            <Limit name="measured-frame-rate-1920x1080" range="235-247" />
-            <Limit name="measured-frame-rate-3840x2160" range="235-247" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
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
-            <Limit name="measured-frame-rate-3840x2160" range="150-150" />
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
-            <Limit name="measured-frame-rate-640x360" range="290-1100" />
-            <Limit name="measured-frame-rate-1280x720" range="237-258" />
-            <Limit name="measured-frame-rate-1920x1080" range="30-160" />
-            <Limit name="measured-frame-rate-3840x2160" range="30-90" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
-        <MediaCodec name="c2.goldfish.vp8.decoder" type="video/x-vnd.on2.vp8">
-            <Limit name="size" min="96x96" max="3840x2160" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" min="24" max="2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-3840x2160" value="30" />
-            <Limit name="measured-frame-rate-320x180" range="743-817" />
-            <Limit name="measured-frame-rate-640x360" range="290-1100" />
-            <Limit name="measured-frame-rate-1280x720" range="60-160" />
-            <Limit name="measured-frame-rate-1920x1080" range="30-160" />
-            <Limit name="measured-frame-rate-3840x2160" range="30-90" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
-        <MediaCodec name="c2.goldfish.vp9.decoder" type="video/x-vnd.on2.vp9">
-            <Limit name="size" min="96x96" max="3840x2160" />
-            <Limit name="alignment" value="2x2" />
-            <Limit name="block-size" value="16x16" />
-            <Limit name="blocks-per-second" min="24" max="2073600" />
-            <Limit name="bitrate" range="1-120000000" />
-            <Limit name="frame-rate" range="1-480" />
-            <Limit name="performance-point-3840x2160" value="30" />
-            <Limit name="measured-frame-rate-320x180" range="500-2000" />
-            <Limit name="measured-frame-rate-640x360" range="340-1300" />
-            <Limit name="measured-frame-rate-1280x720" range="120-500" />
-            <Limit name="measured-frame-rate-1920x1080" range="75-280" />
-            <Limit name="measured-frame-rate-3840x2160" range="30-90" />
-            <Feature name="adaptive-playback" />
-            <Feature name="dynamic-color-aspects" />
-        </MediaCodec>
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
-    </Decoders>
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
-</Included>
diff --git a/camera/arm64/media_codecs_performance_c2.xml b/camera/arm64/media_codecs_performance_c2.xml
deleted file mode 100644
index 51ca5424..00000000
--- a/camera/arm64/media_codecs_performance_c2.xml
+++ /dev/null
@@ -1,93 +0,0 @@
-<?xml version="1.0" encoding="utf-8" ?>
-<!-- Copyright 2020 The Android Open Source Project
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
-<MediaCodecs>
-    <Decoders>
-
-        <MediaCodec name="c2.android.avc.decoder" type="video/avc" update="true">
-            <Limit name="measured-frame-rate-320x240" range="486-504" /> <!-- N=50 v96%=1.3 -->
-            <Limit name="measured-frame-rate-720x480" range="230-920" /> <!-- v90%=1.0 -->
-            <Limit name="measured-frame-rate-1280x720" range="90-360" /> <!-- v90%=1.0 -->
-            <Limit name="measured-frame-rate-1920x1080" range="40-160" /> <!-- v90%=1.0 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.hevc.decoder" type="video/hevc" update="true">
-            <Limit name="measured-frame-rate-352x288" range="469-485" /> <!-- v90%=1.1 -->
-            <Limit name="measured-frame-rate-640x360" range="267-275" /> <!-- v90%=1.1 -->
-            <Limit name="measured-frame-rate-720x480" range="248-248" /> <!-- v90%=1.1 -->
-            <Limit name="measured-frame-rate-1280x720" range="120-460" /> <!-- v90%=1.0 -->
-            <Limit name="measured-frame-rate-1920x1080" range="75-290" /> <!-- v90%=1.0 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.vp8.decoder" type="video/x-vnd.on2.vp8" update="true">
-            <!-- measured 90%:799-924 med:815 N=12 -->
-            <Limit name="measured-frame-rate-320x180" range="814-859" /> <!-- v90%=1.1 -->
-            <!-- measured 90%:338-379 med:345 N=12 -->
-            <Limit name="measured-frame-rate-640x360" range="344-358" /> <!-- v90%=1.1 -->
-            <Limit name="measured-frame-rate-1280x720" range="88-92" /> <!-- N=50 v90%=1.1 -->
-            <!-- measured 90%:35-40 med:36 N=12 -->
-            <Limit name="measured-frame-rate-1920x1080" range="35-37" /> <!-- v90%=1.1 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.vp9.decoder" type="video/x-vnd.on2.vp9" update="true">
-            <!-- measured 90%:621-650 med:634 N=12 -->
-            <Limit name="measured-frame-rate-320x180" range="633-635" /> <!-- v90%=1.0 -->
-            <!-- measured 90%:225-231 med:228 N=12 -->
-            <Limit name="measured-frame-rate-640x360" range="290-1100" /> <!-- v90%=1.0 -->
-            <!-- measured 90%:91-94 med:93 N=12 -->
-            <Limit name="measured-frame-rate-1280x720" range="120-500" /> <!-- v90%=1.0 -->
-            <!-- measured 90%:56-58 med:57 N=12 -->
-            <Limit name="measured-frame-rate-1920x1080" range="75-300" /> <!-- v90%=1.0 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.h263.decoder" type="video/3gpp" update="true">
-            <!-- measured 90%:1219-1704 med:1479 N=12 -->
-            <Limit name="measured-frame-rate-176x144" range="1441-1441" /> <!-- v90%=1.2 -->
-            <!-- measured 96%:889-1227 med:922 SLOW -->
-            <Limit name="measured-frame-rate-352x288" range="921-1045" /> <!-- N=50 v96%=1.2 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.mpeg4.decoder" type="video/mp4v-es" update="true">
-            <!-- measured 90%:1298-1653 med:1316 SLOW N=12 -->
-            <Limit name="measured-frame-rate-176x144" range="1315-1465" /> <!-- v90%=1.1 -->
-        </MediaCodec>
-    </Decoders>
-
-    <Encoders>
-
-        <MediaCodec name="c2.android.h263.encoder" type="video/3gpp" update="true">
-            <Limit name="measured-frame-rate-176x144" range="1200-4500" /> <!-- TWEAKED N=224 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.avc.encoder" type="video/avc" update="true">
-            <Limit name="measured-frame-rate-320x240" range="750-3000" /> <!-- Manual N=20 -->
-            <Limit name="measured-frame-rate-720x480" range="350-1300" /> <!-- Manual N=20 -->
-            <Limit name="measured-frame-rate-1280x720" range="240-920" /> <!-- Manual N=20 -->
-            <Limit name="measured-frame-rate-1920x1080" range="140-500" /> <!-- Manual N=20 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.hevc.encoder" type="video/hevc" update="true">
-            <Limit name="measured-frame-rate-320x240" range="100-400" /> <!-- Manual N=20 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.mpeg4.encoder" type="video/mp4v-es" update="true">
-            <Limit name="measured-frame-rate-176x144" range="1200-4500" /> <!-- SHOULDN'T HAVE TWEAKED N=220 v90%=4.0 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.vp8.encoder" type="video/x-vnd.on2.vp8" update="true">
-            <Limit name="measured-frame-rate-320x180" range="320-1280" /> <!-- Manual N=20 -->
-            <Limit name="measured-frame-rate-640x360" range="230-900" /> <!-- Manual N=20 -->
-            <Limit name="measured-frame-rate-1280x720" range="50-220" /> <!-- Manual N=20 -->
-            <Limit name="measured-frame-rate-1920x1080" range="24-31" /> <!-- Manual N=20 -->
-        </MediaCodec>
-        <MediaCodec name="c2.android.vp9.encoder" type="video/x-vnd.on2.vp9" update="true">
-            <Limit name="measured-frame-rate-320x180" range="109-109" /> <!-- v93%=1.3 -->
-            <Limit name="measured-frame-rate-640x360" range="61-61" /> <!-- v95%=1.1 -->
-            <Limit name="measured-frame-rate-1280x720" range="20-20" /> <!-- v95%=1.3 -->
-        </MediaCodec>
-    </Encoders>
-</MediaCodecs>
diff --git a/data/etc/advancedFeatures.ini b/data/etc/advancedFeatures.ini
index 80e508f7..919f64de 100644
--- a/data/etc/advancedFeatures.ini
+++ b/data/etc/advancedFeatures.ini
@@ -29,3 +29,4 @@ DeviceStateOnBoot = on
 HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
+Uwb = on
\ No newline at end of file
diff --git a/data/etc/advancedFeatures.ini.uwb b/data/etc/advancedFeatures.ini.uwb
deleted file mode 100644
index 919f64de..00000000
--- a/data/etc/advancedFeatures.ini.uwb
+++ /dev/null
@@ -1,32 +0,0 @@
-BluetoothEmulation = on
-GrallocSync = on
-GLDMA = on
-LogcatPipe = on
-GLAsyncSwap = on
-GLESDynamicVersion = on
-EncryptUserData = on
-IntelPerformanceMonitoringUnit = on
-VirtioWifi = on
-HostComposition = on
-RefCountPipe = on
-VirtioInput = on
-HardwareDecoder = on
-DynamicPartition = on
-ModemSimulator = on
-MultiDisplay = on
-YUVCache = on
-GLDirectMem = on
-VulkanNullOptionalStrings = on
-VulkanIgnoredHandles = on
-Mac80211hwsimUserspaceManaged = on
-VirtconsoleLogcat = on
-VirtioVsockPipe = on
-AndroidbootProps2 = on
-DeviceSkinOverlay = on
-VulkanQueueSubmitWithCommands = on
-VulkanBatchedDescriptorSetUpdate = on
-DeviceStateOnBoot = on
-HWCMultiConfigs = on
-VirtioSndCard = on
-DeviceKeyboardHasAssistKey = on
-Uwb = on
\ No newline at end of file
diff --git a/fvpbase/fvp.mk b/fvpbase/fvp.mk
index 1fe7e95b..0fc25bba 100644
--- a/fvpbase/fvp.mk
+++ b/fvpbase/fvp.mk
@@ -16,7 +16,6 @@
 
 PRODUCT_SHIPPING_API_LEVEL := 29
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
-PRODUCT_FULL_TREBLE_OVERRIDE := true
 PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
 
 #
diff --git a/fvpbase/fvp_mini.mk b/fvpbase/fvp_mini.mk
index e543f312..4293cbb2 100644
--- a/fvpbase/fvp_mini.mk
+++ b/fvpbase/fvp_mini.mk
@@ -28,7 +28,6 @@ PRODUCT_SOONG_NAMESPACES += device/generic/goldfish
 
 PRODUCT_SHIPPING_API_LEVEL := 29
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
-PRODUCT_FULL_TREBLE_OVERRIDE := true
 PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
 PRODUCT_BUILD_BOOT_IMAGE := true
 
diff --git a/gnss/GnssBatching.cpp b/gnss/GnssBatching.cpp
index 3226bfe8..c4032260 100644
--- a/gnss/GnssBatching.cpp
+++ b/gnss/GnssBatching.cpp
@@ -67,12 +67,15 @@ ndk::ScopedAStatus GnssBatching::start(const Options& options) {
     std::lock_guard<std::mutex> lock(mMtx);
     mRunning = true;
     mThread = std::thread([this, interval, wakeUpOnFifoFull](){
-        Clock::time_point wakeupT = Clock::now() + interval;
+        std::unique_lock<std::mutex> lock(mMtx);
+        if (!mRunning) {
+            return;
+        }
 
+        Clock::time_point wakeupT = Clock::now() + interval;
         for (;; wakeupT += interval) {
-            std::unique_lock<std::mutex> lock(mMtx);
-            if ((mThreadNotification.wait_until(lock, wakeupT) == std::cv_status::no_timeout) &&
-                    !mRunning) {
+            mThreadNotification.wait_until(lock, wakeupT);
+            if (!mRunning) {
                 return;
             }
 
diff --git a/gnss/GnssMeasurementInterface.cpp b/gnss/GnssMeasurementInterface.cpp
index dcb91e95..9f93df21 100644
--- a/gnss/GnssMeasurementInterface.cpp
+++ b/gnss/GnssMeasurementInterface.cpp
@@ -169,15 +169,17 @@ ndk::ScopedAStatus GnssMeasurementInterface::setCallbackImpl(
 
     std::lock_guard<std::mutex> lock(mMtx);
     mRunning = true;
-
     mThread = std::thread([this, callback, interval](){
-        Clock::time_point wakeupT = Clock::now() + interval;
+        std::unique_lock<std::mutex> lock(mMtx);
+        if (!mRunning) {
+            return;
+        }
 
+        Clock::time_point wakeupT = Clock::now() + interval;
         for (unsigned gnssDataIndex = 0;; gnssDataIndex = (gnssDataIndex + 1) % mGnssData.size(),
                                           wakeupT += interval) {
-            std::unique_lock<std::mutex> lock(mMtx);
-            if ((mThreadNotification.wait_until(lock, wakeupT) == std::cv_status::no_timeout) &&
-                    !mRunning) {
+            mThreadNotification.wait_until(lock, wakeupT);
+            if (!mRunning) {
                 return;
             }
 
diff --git a/gralloc/Android.bp b/gralloc/Android.bp
new file mode 100644
index 00000000..33c8aa21
--- /dev/null
+++ b/gralloc/Android.bp
@@ -0,0 +1,90 @@
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
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish-opengl_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_defaults {
+    name: "gralloc_defaults",
+    relative_install_path: "hw",
+    vendor: true,
+    static_libs: [
+        "mesa_goldfish_address_space",
+        "mesa_util",
+    ],
+    shared_libs: [
+        "android.hardware.graphics.allocator-V2-ndk",
+        "libbase",
+        "libcutils",
+        "libdrm",
+        "liblog",
+        "libutils",
+        "libOpenglCodecCommon",
+        "libOpenglSystemCommon",
+    ],
+    header_libs: [
+        "libdebug.ranchu",
+        "libgralloc_cb.ranchu",
+    ],
+    cflags: [
+        "-DANDROID_BASE_UNIQUE_FD_DISABLE_IMPLICIT_CONVERSION",
+    ],
+}
+
+cc_library_shared {
+    name: "mapper.ranchu",
+    defaults: ["gralloc_defaults"],
+    srcs: ["mapper.cpp"],
+    shared_libs: [
+        "libsync",
+        "libandroidemu",
+    ],
+    header_libs: [
+        "libbase_headers",
+        "libimapper_stablec",
+        "libimapper_providerutils",
+    ],
+    cflags: [
+        "-DLOG_TAG=\"mapper.ranchu\"",
+    ],
+}
+
+cc_binary {
+    name: "android.hardware.graphics.allocator-service.ranchu",
+    defaults: ["gralloc_defaults"],
+    srcs: ["allocator.cpp"],
+    init_rc: ["android.hardware.graphics.allocator-service.ranchu.rc"],
+    vintf_fragments: ["android.hardware.graphics.gralloc.ranchu.xml"],
+    shared_libs: [
+        "libbinder_ndk",
+        "libqemupipe.ranchu",
+    ],
+    static_libs: [
+        "libaidlcommonsupport",
+    ],
+    required: [
+        "mapper.ranchu",
+    ],
+    cflags: [
+        "-DLOG_TAG=\"allocator-service.ranchu\"",
+    ],
+}
diff --git a/gralloc/CbExternalMetadata.h b/gralloc/CbExternalMetadata.h
new file mode 100644
index 00000000..c62512c2
--- /dev/null
+++ b/gralloc/CbExternalMetadata.h
@@ -0,0 +1,65 @@
+/*
+* Copyright 2024 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+* http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+#pragma once
+#include "PlaneLayout.h"
+
+struct CbExternalMetadata {
+    static constexpr uint64_t kMagicValue = 0x247439A87E42E932LLU;
+
+    struct Smpte2086 {
+        struct XyColor {
+            float x;
+            float y;
+        };
+
+        XyColor primaryRed;
+        XyColor primaryGreen;
+        XyColor primaryBlue;
+        XyColor whitePoint;
+        float maxLuminance;
+        float minLuminance;
+    };
+
+    struct Cta861_3 {
+        float maxContentLightLevel;
+        float maxFrameAverageLightLevel;
+    };
+
+    uint64_t    magic;
+    uint64_t    bufferID;
+    PlaneLayout planeLayout[3];
+    PlaneLayoutComponent planeLayoutComponent[4];
+    Smpte2086   smpte2086;
+    Cta861_3    cta861_3;
+    uint32_t    width;              // buffer width
+    uint32_t    height;             // buffer height
+    int32_t     glFormat;           // OpenGL format enum used for host h/w color buffer
+    int32_t     glType;             // OpenGL type enum used when uploading to host
+    uint32_t    reservedRegionSize;
+    int32_t     dataspace;
+    int32_t     blendMode;
+
+    uint8_t     planeLayoutSize;
+    uint8_t     nameSize;
+    bool        has_smpte2086;
+    bool        has_cta861_3;
+
+    char        name[127];
+    char        unused[1];
+};
+
+static_assert((sizeof(CbExternalMetadata) % 16) == 0);
diff --git a/gralloc/DebugLevel.h b/gralloc/DebugLevel.h
new file mode 100644
index 00000000..ca649e4f
--- /dev/null
+++ b/gralloc/DebugLevel.h
@@ -0,0 +1,33 @@
+/*
+* Copyright 2024 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+* http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+#pragma once
+#include <android-base/properties.h>
+
+enum class DebugLevel {
+    ERROR = 0,
+    ALLOC = 1,
+    IMPORT = 2,
+    LOCK = 3,
+    FLUSH = 4,
+    METADATA = 5,
+};
+
+inline DebugLevel getDebugLevel() {
+    return static_cast<DebugLevel>(
+        ::android::base::GetIntProperty("ro.boot.qemu.gralloc.debug_level",
+                                        static_cast<int>(DebugLevel::ERROR)));
+}
diff --git a/gralloc/HostConnectionSession.h b/gralloc/HostConnectionSession.h
new file mode 100644
index 00000000..6d60a764
--- /dev/null
+++ b/gralloc/HostConnectionSession.h
@@ -0,0 +1,56 @@
+/*
+* Copyright (C) 2024 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+* http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+#ifndef GOLDFISH_OPENGL_SYSTEM_HALS_HOST_CONNECTION_SESSION_H_INCLUDED
+#define GOLDFISH_OPENGL_SYSTEM_HALS_HOST_CONNECTION_SESSION_H_INCLUDED
+
+#include "HostConnection.h"
+
+class HostConnectionSession {
+public:
+    explicit HostConnectionSession(HostConnection* hc) : conn(hc) {
+        hc->lock();
+    }
+
+    ~HostConnectionSession() {
+        if (conn) {
+            conn->unlock();
+        }
+     }
+
+    HostConnectionSession(HostConnectionSession&& rhs) : conn(rhs.conn) {
+        rhs.conn = nullptr;
+    }
+
+    HostConnectionSession& operator=(HostConnectionSession&& rhs) {
+        if (this != &rhs) {
+            std::swap(conn, rhs.conn);
+        }
+        return *this;
+    }
+
+    HostConnectionSession(const HostConnectionSession&) = delete;
+    HostConnectionSession& operator=(const HostConnectionSession&) = delete;
+
+    ExtendedRCEncoderContext* getRcEncoder() const {
+        return conn->rcEncoder();
+    }
+
+private:
+    HostConnection* conn;
+};
+
+#endif  // GOLDFISH_OPENGL_SYSTEM_HALS_HOST_CONNECTION_SESSION_H_INCLUDED
diff --git a/gralloc/PlaneLayout.h b/gralloc/PlaneLayout.h
new file mode 100644
index 00000000..f1f7ac31
--- /dev/null
+++ b/gralloc/PlaneLayout.h
@@ -0,0 +1,35 @@
+/*
+* Copyright 2024 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+* http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+#pragma once
+#include <cstdint>
+
+struct PlaneLayoutComponent {
+    uint32_t type; // see PlaneLayoutComponentType
+    uint16_t offsetInBits;
+    uint16_t sizeInBits;
+};
+
+struct PlaneLayout {
+    uint32_t offsetInBytes;
+    uint32_t strideInBytes;
+    uint32_t totalSizeInBytes;
+    uint8_t sampleIncrementInBytes;
+    uint8_t horizontalSubsamplingShift : 4;
+    uint8_t verticalSubsamplingShift : 4;
+    uint8_t componentsBase; // in the PlaneLayoutComponent array
+    uint8_t componentsSize;
+};
diff --git a/gralloc/allocator.cpp b/gralloc/allocator.cpp
new file mode 100644
index 00000000..d9d35ff9
--- /dev/null
+++ b/gralloc/allocator.cpp
@@ -0,0 +1,754 @@
+/*
+* Copyright (C) 2024 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+* http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+#include <cstring>
+#include <string_view>
+
+#include <sched.h>
+
+#include <android-base/unique_fd.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+
+#include <aidl/android/hardware/graphics/allocator/AllocationError.h>
+#include <aidl/android/hardware/graphics/allocator/AllocationResult.h>
+#include <aidl/android/hardware/graphics/allocator/BnAllocator.h>
+#include <aidl/android/hardware/graphics/common/BufferUsage.h>
+#include <aidl/android/hardware/graphics/common/PixelFormat.h>
+#include <aidl/android/hardware/graphics/common/PlaneLayoutComponentType.h>
+
+#include <aidlcommonsupport/NativeHandle.h>
+
+#include <debug.h>
+#include <drm_fourcc.h>
+#include <glUtils.h>
+#include <goldfish_address_space.h>
+#include <gralloc_cb_bp.h>
+#include <qemu_pipe_bp.h>
+
+#include "CbExternalMetadata.h"
+#include "DebugLevel.h"
+#include "HostConnectionSession.h"
+
+using ::aidl::android::hardware::graphics::allocator::AllocationError;
+using ::aidl::android::hardware::graphics::allocator::AllocationResult;
+using ::aidl::android::hardware::graphics::allocator::BnAllocator;
+using ::aidl::android::hardware::graphics::allocator::BufferDescriptorInfo;
+using ::aidl::android::hardware::graphics::common::BufferUsage;
+using ::aidl::android::hardware::graphics::common::PixelFormat;
+using ::aidl::android::hardware::graphics::common::PlaneLayoutComponentType;
+
+#ifndef GL_RGBA16F
+#define GL_RGBA16F                        0x881A
+#endif // GL_RGBA16F
+
+#ifndef GL_HALF_FLOAT
+#define GL_HALF_FLOAT                     0x140B
+#endif // GL_HALF_FLOAT
+
+#ifndef GL_RGB10_A2
+#define GL_RGB10_A2                       0x8059
+#endif // GL_RGB10_A2
+
+#ifndef GL_UNSIGNED_INT_2_10_10_10_REV
+#define GL_UNSIGNED_INT_2_10_10_10_REV    0x8368
+#endif // GL_UNSIGNED_INT_2_10_10_10_REV
+
+namespace {
+enum class EmulatorFrameworkFormat : uint8_t {
+    GL_COMPATIBLE = 0,
+    YV12 = 1,
+    YUV_420_888 = 2, // (Y+)(U+)(V+)
+};
+
+size_t align(const size_t value, const size_t alignmentP2) {
+    return (value + alignmentP2 - 1) & ~(alignmentP2 - 1);
+}
+
+size_t strnlen(const char* str, const size_t maxSize) {
+    const char* const begin = str;
+    const char* const end = begin + maxSize;
+    for (; *str && (str != end); ++str) {}
+    return str - begin;
+}
+
+ndk::ScopedAStatus toBinderStatus(const AllocationError error) {
+    return ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(error));
+}
+
+uint64_t toUsage64(const BufferUsage usage) {
+    return static_cast<uint64_t>(usage);
+}
+
+bool needGpuBuffer(const uint64_t usage) {
+    return usage & (toUsage64(BufferUsage::GPU_TEXTURE)
+                    | toUsage64(BufferUsage::GPU_RENDER_TARGET)
+                    | toUsage64(BufferUsage::COMPOSER_OVERLAY)
+                    | toUsage64(BufferUsage::COMPOSER_CLIENT_TARGET)
+                    | toUsage64(BufferUsage::GPU_DATA_BUFFER));
+}
+
+bool needCpuBuffer(const uint64_t usage) {
+    return usage & (toUsage64(BufferUsage::CPU_READ_MASK)
+                    | toUsage64(BufferUsage::CPU_WRITE_MASK));
+}
+
+PlaneLayoutComponent makePlaneLayoutComponent(const PlaneLayoutComponentType type,
+                                              const unsigned offsetInBits,
+                                              const unsigned sizeInBits) {
+    return {
+        .type = static_cast<uint32_t>(type),
+        .offsetInBits = static_cast<uint16_t>(offsetInBits),
+        .sizeInBits = static_cast<uint16_t>(sizeInBits),
+    };
+}
+
+size_t initPlaneLayout(PlaneLayout& plane,
+                       const uint32_t width,
+                       const uint32_t height,
+                       const size_t offsetInBytes,
+                       const uint32_t alignment,
+                       const unsigned sampleSizeInBytes,
+                       const unsigned subsamplingShift,
+                       const unsigned componentsBase,
+                       const unsigned componentsSize) {
+    const uint32_t strideInBytes = align(width * sampleSizeInBytes, alignment);
+
+    plane.offsetInBytes = offsetInBytes;
+    plane.strideInBytes = strideInBytes;
+    plane.totalSizeInBytes = strideInBytes * height;
+    plane.sampleIncrementInBytes = sampleSizeInBytes;
+    plane.horizontalSubsamplingShift = subsamplingShift;
+    plane.verticalSubsamplingShift = subsamplingShift;
+    plane.componentsBase = componentsBase;
+    plane.componentsSize = componentsSize;
+
+    return offsetInBytes + plane.totalSizeInBytes;
+}
+
+struct GoldfishAllocator : public BnAllocator {
+    GoldfishAllocator()
+        : mHostConn(HostConnection::createUnique(kCapsetNone))
+        , mDebugLevel(getDebugLevel()) {}
+
+    ndk::ScopedAStatus allocate2(const BufferDescriptorInfo& desc,
+                                 const int32_t count,
+                                 AllocationResult* const outResult) override {
+        if (count <= 0) {
+            return toBinderStatus(FAILURE_V(AllocationError::BAD_DESCRIPTOR,
+                                            "%s: count=%d", "BAD_DESCRIPTOR",
+                                            count));
+        }
+        if (desc.width <= 0) {
+            return toBinderStatus(FAILURE_V(AllocationError::BAD_DESCRIPTOR,
+                                            "%s: width=%d", "BAD_DESCRIPTOR",
+                                            desc.width));
+        }
+        if (desc.height <= 0) {
+            return toBinderStatus(FAILURE_V(AllocationError::BAD_DESCRIPTOR,
+                                            "%s: height=%d", "BAD_DESCRIPTOR",
+                                            desc.height));
+        }
+        if (!validateUsage(desc.usage)) {
+            return toBinderStatus(FAILURE_V(AllocationError::BAD_DESCRIPTOR,
+                                            "%s: usage=0x%" PRIX64, "BAD_DESCRIPTOR",
+                                            toUsage64(desc.usage)));
+        }
+        if (desc.layerCount != 1) {
+            return toBinderStatus(FAILURE_V(AllocationError::BAD_DESCRIPTOR,
+                                            "%s: layerCount=%d", "BAD_DESCRIPTOR",
+                                            desc.layerCount));
+        }
+        if (desc.reservedSize < 0) {
+            return toBinderStatus(FAILURE_V(AllocationError::BAD_DESCRIPTOR,
+                                            "%s: reservedSize=%" PRId64, "BAD_DESCRIPTOR",
+                                            desc.reservedSize));
+        }
+        if (!desc.additionalOptions.empty()) {
+            return toBinderStatus(FAILURE_V(
+                AllocationError::BAD_DESCRIPTOR, "%s: %s", "BAD_DESCRIPTOR",
+                "'BufferDescriptorInfo::additionalOptions' are not supported"));
+        }
+
+        const uint64_t usage = toUsage64(desc.usage);
+        const uint32_t width = desc.width;
+        const uint32_t height = desc.height;
+        size_t offsetInBytes = 0;
+
+        AllocationRequest req;
+        switch (desc.format) {
+        case PixelFormat::RGBA_8888:
+            req.glFormat = GL_RGBA;
+            req.glType = GL_UNSIGNED_BYTE;
+
+            req.drmFormat = DRM_FORMAT_ABGR8888;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 4, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 4);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 8, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 16, 8);
+            req.planeComponent[3] = makePlaneLayoutComponent(PlaneLayoutComponentType::A, 24, 8);
+            break;
+
+        case PixelFormat::RGBX_8888:
+            req.glFormat = GL_RGBA;
+            req.glType = GL_UNSIGNED_BYTE;
+
+            req.drmFormat = DRM_FORMAT_XBGR8888;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 4, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 3);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 8, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 16, 8);
+            break;
+
+        case PixelFormat::BGRA_8888:
+            req.glFormat = GL_RGBA;
+            req.glType = GL_UNSIGNED_BYTE;
+
+            req.drmFormat = DRM_FORMAT_ARGB8888;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 4, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 4);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 8, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 16, 8);
+            req.planeComponent[3] = makePlaneLayoutComponent(PlaneLayoutComponentType::A, 24, 8);
+            break;
+
+        case PixelFormat::RGB_888:
+            if (needGpuBuffer(usage)) {
+                return toBinderStatus(FAILURE(AllocationError::UNSUPPORTED));
+            }
+
+            req.drmFormat = DRM_FORMAT_BGR888;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 3, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 3);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 8, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 16, 8);
+            break;
+
+        case PixelFormat::RGB_565:
+            req.glFormat = GL_RGB565;
+            req.glType = GL_UNSIGNED_SHORT_5_6_5;
+
+            req.drmFormat = DRM_FORMAT_BGR565;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 2, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 3);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 0, 5);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 5, 6);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 11, 5);
+            break;
+
+        case PixelFormat::RGBA_FP16:
+            req.glFormat = GL_RGBA16F;
+            req.glType = GL_HALF_FLOAT;
+
+            req.drmFormat = DRM_FORMAT_ABGR16161616F;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 8, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 4);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 0, 16);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 16, 16);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 32, 16);
+            req.planeComponent[3] = makePlaneLayoutComponent(PlaneLayoutComponentType::A, 48, 16);
+            break;
+
+        case PixelFormat::RGBA_1010102:
+            req.glFormat = GL_RGB10_A2;
+            req.glType = GL_UNSIGNED_INT_2_10_10_10_REV;
+
+            req.drmFormat = DRM_FORMAT_ABGR2101010;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 4, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 4);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::R, 0, 10);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::G, 10, 10);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::B, 20, 10);
+            req.planeComponent[3] = makePlaneLayoutComponent(PlaneLayoutComponentType::A, 30, 2);
+            break;
+
+        case PixelFormat::RAW16:
+            if (needGpuBuffer(usage)) {
+                return toBinderStatus(FAILURE(AllocationError::UNSUPPORTED));
+            }
+
+            req.drmFormat = DRM_FORMAT_R16;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 16,
+                /*sampleSizeInBytes=*/ 2, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::RAW, 0, 16);
+            break;
+
+        case PixelFormat::Y16:
+            if (needGpuBuffer(usage)) {
+                return toBinderStatus(FAILURE(AllocationError::UNSUPPORTED));
+            }
+
+            req.drmFormat = DRM_FORMAT_R16;
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 16,
+                /*sampleSizeInBytes=*/ 2, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::Y, 0, 16);
+            break;
+
+        case PixelFormat::BLOB:
+            if (needGpuBuffer(usage)) {
+                return toBinderStatus(FAILURE(AllocationError::UNSUPPORTED));
+            }
+
+            req.planeSize = 1;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::RAW, 0, 8);
+            break;
+
+        case PixelFormat::YCRCB_420_SP:  // Y + CrCb interleaved
+            if (needGpuBuffer(usage)) {
+                return toBinderStatus(FAILURE(AllocationError::UNSUPPORTED));
+            }
+
+            req.drmFormat = DRM_FORMAT_YVU420;
+
+            req.planeSize = 2;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            offsetInBytes = initPlaneLayout(
+                req.plane[1], width / 2, height / 2, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 2, /*subsamplingShift=*/ 1,
+                /*componentsBase=*/ 1, /*componentsSize*/ 2);
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::Y, 0, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::CR, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::CB, 8, 8);
+            break;
+
+        case PixelFormat::YV12:  // 3 planes (Y, Cr, Cb), 16bytes aligned
+            req.glFormat = GL_RGBA;
+            req.glType = GL_UNSIGNED_BYTE;
+            req.emuFwkFormat = EmulatorFrameworkFormat::YV12;
+
+            req.drmFormat = DRM_FORMAT_YVU420;
+
+            req.planeSize = 3;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 16,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            offsetInBytes = initPlaneLayout(
+                req.plane[1], width / 2, height / 2, offsetInBytes, /*alignment=*/ 16,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 1,
+                /*componentsBase=*/ 1, /*componentsSize*/ 1);
+            offsetInBytes = initPlaneLayout(
+                req.plane[2], width / 2, height / 2, offsetInBytes, /*alignment=*/ 16,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 1,
+                /*componentsBase=*/ 2, /*componentsSize*/ 1);
+
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::Y, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::CR, 0, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::CB, 0, 8);
+            break;
+
+        case PixelFormat::YCBCR_420_888:  // 3 planes (Y, Cb, Cr)
+            req.glFormat = GL_RGBA;
+            req.glType = GL_UNSIGNED_BYTE;
+            req.emuFwkFormat = EmulatorFrameworkFormat::YUV_420_888;
+
+            req.drmFormat = DRM_FORMAT_YUV420;
+
+            req.planeSize = 3;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            offsetInBytes = initPlaneLayout(
+                req.plane[1], width / 2, height / 2, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 1,
+                /*componentsBase=*/ 1, /*componentsSize*/ 1);
+            offsetInBytes = initPlaneLayout(
+                req.plane[2], width / 2, height / 2, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 1, /*subsamplingShift=*/ 1,
+                /*componentsBase=*/ 2, /*componentsSize*/ 1);
+
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::Y, 0, 8);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::CB, 0, 8);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::CR, 0, 8);
+            break;
+
+        case PixelFormat::YCBCR_P010:  // Y + CbCr interleaved, 2bytes per component
+            req.glFormat = GL_RGBA;
+            req.glType = GL_UNSIGNED_BYTE;
+
+            req.drmFormat = DRM_FORMAT_YUV420_10BIT;
+
+            req.planeSize = 2;
+            offsetInBytes = initPlaneLayout(
+                req.plane[0], width, height, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 2, /*subsamplingShift=*/ 0,
+                /*componentsBase=*/ 0, /*componentsSize*/ 1);
+            offsetInBytes = initPlaneLayout(
+                req.plane[1], width / 2, height / 2, offsetInBytes, /*alignment=*/ 1,
+                /*sampleSizeInBytes=*/ 4, /*subsamplingShift=*/ 1,
+                /*componentsBase=*/ 1, /*componentsSize*/ 2);
+
+            req.planeComponent[0] = makePlaneLayoutComponent(PlaneLayoutComponentType::Y, 6, 10);
+            req.planeComponent[1] = makePlaneLayoutComponent(PlaneLayoutComponentType::CB, 6, 10);
+            req.planeComponent[2] = makePlaneLayoutComponent(PlaneLayoutComponentType::CR, 6 + 10 + 6, 10);
+            break;
+
+        default:
+            return toBinderStatus(FAILURE_V(AllocationError::UNSUPPORTED,
+                                            "Unsupported format: format=0x%X, usage=%" PRIX64,
+                                            static_cast<uint32_t>(desc.format), desc.usage));
+        }
+
+        req.name = std::string_view(reinterpret_cast<const char*>(desc.name.data()),
+                                    strnlen(reinterpret_cast<const char*>(desc.name.data()),
+                                    desc.name.size()));
+        req.usage = usage;
+        req.width = width;
+        req.height = height;
+        req.format = desc.format;
+        req.reservedRegionSize = desc.reservedSize;
+
+        if (needCpuBuffer(usage)) {
+            req.imageSizeInBytes = offsetInBytes;
+            req.stride0 = (req.planeSize == 1) ?
+                              (req.plane[0].strideInBytes /
+                               req.plane[0].sampleIncrementInBytes) : 0;
+        } else {
+            req.imageSizeInBytes = 0;   // the image is not allocated
+            /*
+             * b/359874912: the spec does not say how to handle PLANE_LAYOUTS
+             * if the CPU buffer is not allocated. Let's not populate them
+             * without the CPU buffer (sizes and offsets don't make sense anyway).
+             */
+            req.planeSize = 0;
+            req.stride0 = 0;
+        }
+
+        if (needGpuBuffer(usage)) {
+            req.rcAllocFormat = (req.format == PixelFormat::RGBX_8888) ? GL_RGB : req.glFormat;
+        } else {
+            req.glFormat = -1;  // no GPU buffer - no GPU formats
+            req.glType = -1;
+            req.rcAllocFormat = -1;
+        }
+
+        std::vector<std::unique_ptr<cb_handle_t>> cbs(count);
+
+        {
+            HostConnectionSession connSession(mHostConn.get());
+            ExtendedRCEncoderContext* const rcEnc = connSession.getRcEncoder();
+            LOG_ALWAYS_FATAL_IF(!rcEnc);
+            const bool hasSharedSlots =
+                rcEnc->featureInfo_const()->hasSharedSlotsHostMemoryAllocator;
+
+            for (int i = 0; i < count; ++i) {
+                std::unique_ptr<cb_handle_t> cb = allocateImpl(
+                    req, *rcEnc, ++mBufferIdGenerator, hasSharedSlots);
+                if (cb) {
+                    cbs[i] = std::move(cb);
+                } else {
+                    for (--i; i > 0; --i) {
+                        unallocate(std::move(cbs[i]));
+                    }
+                    return toBinderStatus(FAILURE(AllocationError::NO_RESOURCES));
+                }
+            }
+        }
+
+        outResult->stride = req.stride0;
+        outResult->buffers.reserve(count);
+        for (auto& cb : cbs) {
+            outResult->buffers.push_back(android::dupToAidl(cb.get()));
+            unallocate(std::move(cb));
+        }
+
+        return ndk::ScopedAStatus::ok();
+    }
+
+    ndk::ScopedAStatus isSupported(const BufferDescriptorInfo& descriptor,
+                                   bool* outResult) override {
+        *outResult = isSupportedImpl(descriptor);
+        return ndk::ScopedAStatus::ok();
+    }
+
+    ndk::ScopedAStatus getIMapperLibrarySuffix(std::string* outResult) override {
+        *outResult = "ranchu";
+        return ndk::ScopedAStatus::ok();
+    }
+
+    ndk::ScopedAStatus allocate(const std::vector<uint8_t>& encodedDescriptor,
+                                const int32_t count,
+                                AllocationResult* const outResult) override {
+        (void)encodedDescriptor;
+        (void)count;
+        (void)outResult;
+        return toBinderStatus(FAILURE(AllocationError::UNSUPPORTED));
+    }
+
+private:
+    struct AllocationRequest {
+        std::string_view name;
+        PlaneLayout plane[3];
+        PlaneLayoutComponent planeComponent[4];
+        size_t imageSizeInBytes = 0;
+        size_t reservedRegionSize = 0;
+        uint64_t usage = 0;
+        uint32_t width = 0;
+        uint32_t height = 0;
+        uint32_t stride0 = 0;
+        uint32_t drmFormat = DRM_FORMAT_INVALID;
+        PixelFormat format = PixelFormat::UNSPECIFIED;
+        int glFormat = -1;
+        int glType = -1;
+        int rcAllocFormat = -1;
+        EmulatorFrameworkFormat emuFwkFormat = EmulatorFrameworkFormat::GL_COMPATIBLE;
+        uint8_t planeSize = 0;
+    };
+
+    std::unique_ptr<cb_handle_t>
+    allocateImpl(const AllocationRequest& req,
+                 ExtendedRCEncoderContext& rcEnc,
+                 const uint64_t bufferID,
+                 const bool hasSharedSlots) const {
+        android::base::unique_fd cpuAlocatorFd;
+        GoldfishAddressSpaceBlock bufferBits;
+        const size_t imageSizeInBytesAligned = align(req.imageSizeInBytes, 16);
+        const size_t totalAllocationSize =
+            imageSizeInBytesAligned + sizeof(CbExternalMetadata) + req.reservedRegionSize;
+
+        {
+            GoldfishAddressSpaceHostMemoryAllocator hostMemoryAllocator(hasSharedSlots);
+            LOG_ALWAYS_FATAL_IF(!hostMemoryAllocator.is_opened());
+
+            if (hostMemoryAllocator.hostMalloc(&bufferBits, totalAllocationSize)) {
+                return FAILURE(nullptr);
+            }
+
+            cpuAlocatorFd.reset(hostMemoryAllocator.release());
+
+            CbExternalMetadata& metadata =
+                *reinterpret_cast<CbExternalMetadata*>(
+                    static_cast<char*>(bufferBits.guestPtr()) + imageSizeInBytesAligned);
+
+            memset(&metadata, 0, sizeof(metadata));
+            metadata.magic = CbExternalMetadata::kMagicValue;
+            metadata.bufferID = bufferID;
+            metadata.nameSize = std::min(req.name.size(), sizeof(CbExternalMetadata::name));
+            memcpy(metadata.name, req.name.data(), metadata.nameSize);
+
+            metadata.planeLayoutSize = req.planeSize;
+            if (req.planeSize) {
+                static_assert(sizeof(metadata.planeLayout) == sizeof(req.plane));
+                memcpy(metadata.planeLayout, req.plane, sizeof(req.plane));
+
+                static_assert(sizeof(metadata.planeLayoutComponent) ==
+                              sizeof(req.planeComponent));
+                memcpy(metadata.planeLayoutComponent, req.planeComponent,
+                       sizeof(req.planeComponent));
+            }
+
+            metadata.reservedRegionSize = req.reservedRegionSize;
+            metadata.width = req.width;
+            metadata.height = req.height;
+            metadata.glFormat = req.glFormat;
+            metadata.glType = req.glType;
+        }
+
+        uint32_t hostHandle = 0;
+        android::base::unique_fd hostHandleRefCountFd;
+        if (needGpuBuffer(req.usage)) {
+            hostHandleRefCountFd.reset(qemu_pipe_open("refcount"));
+            if (!hostHandleRefCountFd.ok()) {
+                return FAILURE(nullptr);
+            }
+
+            hostHandle = rcEnc.rcCreateColorBufferDMA(
+                &rcEnc, req.width, req.height,
+                req.rcAllocFormat, static_cast<int>(req.emuFwkFormat));
+            if (!hostHandle) {
+                return FAILURE(nullptr);
+            }
+
+            if (qemu_pipe_write(hostHandleRefCountFd.get(),
+                                &hostHandle,
+                                sizeof(hostHandle)) != sizeof(hostHandle)) {
+                rcEnc.rcCloseColorBuffer(&rcEnc, hostHandle);
+                return FAILURE(nullptr);
+            }
+        }
+
+        if (mDebugLevel >= DebugLevel::ALLOC) {
+            char hostHandleValueStr[128];
+            if (hostHandle) {
+                snprintf(hostHandleValueStr, sizeof(hostHandleValueStr),
+                         "0x%X glFormat=0x%X glType=0x%X "
+                         "rcAllocFormat=0x%X emuFwkFormat=%d",
+                         hostHandle, req.glFormat, req.glType, req.rcAllocFormat,
+                         static_cast<int>(req.emuFwkFormat));
+            } else {
+                strcpy(hostHandleValueStr, "null");
+            }
+
+            char bufferValueStr[96];
+            if (req.imageSizeInBytes) {
+                snprintf(bufferValueStr, sizeof(bufferValueStr),
+                         "{ ptr=%p mappedSize=%zu offset=0x%" PRIX64 " } imageSizeInBytes=%zu",
+                         bufferBits.guestPtr(), size_t(bufferBits.size()),
+                         bufferBits.offset(), size_t(req.imageSizeInBytes));
+            } else {
+                strcpy(bufferValueStr, "null");
+            }
+
+            ALOGD("%s:%d name='%.*s' id=%" PRIu64 " width=%u height=%u format=0x%X "
+                  "usage=0x%" PRIX64 " hostHandle=%s buffer=%s reservedSize=%zu",
+                  __func__, __LINE__, int(req.name.size()), req.name.data(), bufferID,
+                  req.width, req.height, static_cast<uint32_t>(req.format),
+                  req.usage, hostHandleValueStr, bufferValueStr,
+                  req.reservedRegionSize);
+        }
+
+        auto cb = std::make_unique<cb_handle_t>(
+            cpuAlocatorFd.release(), hostHandleRefCountFd.release(), hostHandle,
+            req.usage, static_cast<uint32_t>(req.format), req.drmFormat,
+            req.stride0, req.imageSizeInBytes, bufferBits.guestPtr(),
+            bufferBits.size(), bufferBits.offset(),
+            imageSizeInBytesAligned);
+
+        bufferBits.release();  // now cb owns it
+        return cb;
+    }
+
+    static void unallocate(const std::unique_ptr<cb_handle_t> cb) {
+        if (cb->hostHandleRefcountFd >= 0) {
+            ::close(cb->hostHandleRefcountFd);
+        }
+
+        if (cb->bufferFd >= 0) {
+            if (cb->mmapedSize > 0) {
+                GoldfishAddressSpaceBlock::memoryUnmap(cb->getBufferPtr(), cb->mmapedSize);
+            }
+
+            GoldfishAddressSpaceHostMemoryAllocator::closeHandle(cb->bufferFd);
+        }
+    }
+
+    static bool validateUsage(const BufferUsage usage) {
+        static constexpr uint64_t kReservedUsage =
+            (1U << 10) | (1U << 13) | (1U << 19) | (1U << 21);
+
+        return 0 == (toUsage64(usage) & kReservedUsage);
+    }
+
+    static bool isSupportedImpl(const BufferDescriptorInfo& desc) {
+        if (desc.width <= 0) { return false; }
+        if (desc.height <= 0) { return false; }
+        if (desc.layerCount != 1) { return false; }
+        if (desc.reservedSize < 0) { return false; }
+        if (!desc.additionalOptions.empty()) { return false; }
+
+        switch (desc.format) {
+        case PixelFormat::RGBA_8888:
+        case PixelFormat::RGBX_8888:
+        case PixelFormat::BGRA_8888:
+        case PixelFormat::RGB_565:
+        case PixelFormat::RGBA_FP16:
+        case PixelFormat::RGBA_1010102:
+        case PixelFormat::YV12:
+        case PixelFormat::YCBCR_420_888:
+        case PixelFormat::YCBCR_P010:
+            return validateUsage(desc.usage);
+
+        case PixelFormat::RGB_888:
+        case PixelFormat::YCRCB_420_SP:
+        case PixelFormat::RAW16:
+        case PixelFormat::Y16:
+        case PixelFormat::BLOB:
+            return validateUsage(desc.usage) &&
+                   !needGpuBuffer(toUsage64(desc.usage));
+
+        case PixelFormat::IMPLEMENTATION_DEFINED:  // we don't support it
+        default:
+            return false;
+        }
+    }
+
+    const std::unique_ptr<HostConnection> mHostConn;
+    uint64_t mBufferIdGenerator = 0;
+    const DebugLevel mDebugLevel;
+};
+}  // namespace
+
+int main(int /*argc*/, char** /*argv*/) {
+    struct sched_param param = {0};
+    param.sched_priority = 2;
+    if (sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &param) != 0) {
+        ALOGW("Failed to set priority: %s", strerror(errno));
+    }
+
+    auto allocator = ndk::SharedRefBase::make<GoldfishAllocator>();
+
+    {
+        const std::string instance = std::string(GoldfishAllocator::descriptor) + "/default";
+        if (AServiceManager_addService(allocator->asBinder().get(),
+                                       instance.c_str()) != STATUS_OK) {
+            ALOGE("Failed to register: '%s'", instance.c_str());
+            return EXIT_FAILURE;
+        }
+    }
+
+    ABinderProcess_setThreadPoolMaxThreadCount(4);
+    ABinderProcess_startThreadPool();
+    ABinderProcess_joinThreadPool();
+    return EXIT_FAILURE;    // joinThreadPool is not expected to return
+}
diff --git a/gralloc/android.hardware.graphics.allocator-service.ranchu.rc b/gralloc/android.hardware.graphics.allocator-service.ranchu.rc
new file mode 100644
index 00000000..a0ab246c
--- /dev/null
+++ b/gralloc/android.hardware.graphics.allocator-service.ranchu.rc
@@ -0,0 +1,7 @@
+service vendor.graphics.allocator /vendor/bin/hw/android.hardware.graphics.allocator-service.ranchu
+    class hal animation
+    user system
+    group graphics drmrpc
+    capabilities SYS_NICE
+    onrestart restart surfaceflinger
+    task_profiles ServiceCapacityLow
diff --git a/gralloc/android.hardware.graphics.gralloc.ranchu.xml b/gralloc/android.hardware.graphics.gralloc.ranchu.xml
new file mode 100644
index 00000000..51a6c2bf
--- /dev/null
+++ b/gralloc/android.hardware.graphics.gralloc.ranchu.xml
@@ -0,0 +1,17 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl">
+        <name>android.hardware.graphics.allocator</name>
+        <version>2</version>
+        <interface>
+            <name>IAllocator</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+    <hal format="native">
+        <name>mapper</name>
+        <version>5.0</version>
+        <interface>
+            <instance>ranchu</instance>
+        </interface>
+    </hal>
+</manifest>
diff --git a/gralloc/mapper.cpp b/gralloc/mapper.cpp
new file mode 100644
index 00000000..8d1353a3
--- /dev/null
+++ b/gralloc/mapper.cpp
@@ -0,0 +1,1103 @@
+/*
+* Copyright (C) 2024 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+* http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+#include <array>
+#include <mutex>
+#include <string_view>
+#include <unordered_set>
+#include <vector>
+
+#include <cutils/native_handle.h>
+#include <log/log.h>
+#include <sync/sync.h>
+
+#include <aidl/android/hardware/graphics/common/BufferUsage.h>
+#include <aidl/android/hardware/graphics/common/ChromaSiting.h>
+#include <aidl/android/hardware/graphics/common/Compression.h>
+#include <aidl/android/hardware/graphics/common/Interlaced.h>
+#include <aidl/android/hardware/graphics/common/PixelFormat.h>
+#include <aidl/android/hardware/graphics/common/StandardMetadataType.h>
+
+#include <android/hardware/graphics/mapper/IMapper.h>
+#include <android/hardware/graphics/mapper/utils/IMapperMetadataTypes.h>
+
+#include <debug.h>
+#include <FormatConversions.h>
+#include <goldfish_address_space.h>
+#include <gralloc_cb_bp.h>
+
+#include "CbExternalMetadata.h"
+#include "DebugLevel.h"
+#include "HostConnectionSession.h"
+
+#ifndef DRM_FORMAT_MOD_LINEAR
+#define DRM_FORMAT_MOD_LINEAR 0
+#endif
+
+namespace aahgc = ::aidl::android::hardware::graphics::common;
+using aahgc::BufferUsage;
+using aahgc::ChromaSiting;
+using aahgc::Interlaced;
+using aahgc::PixelFormat;
+using aahgc::StandardMetadataType;
+
+using ::android::hardware::graphics::mapper::MetadataReader;
+using ::android::hardware::graphics::mapper::MetadataWriter;
+
+namespace {
+constexpr size_t kMetadataBufferInitialSize = 1024;
+constexpr uint32_t kCPU_READ_MASK = static_cast<uint32_t>(BufferUsage::CPU_READ_MASK);
+constexpr uint32_t kCPU_WRITE_MASK = static_cast<uint32_t>(BufferUsage::CPU_WRITE_MASK);
+
+using namespace std::literals;
+
+const char kStandardMetadataTypeStr[] = "android.hardware.graphics.common.StandardMetadataType";
+const std::string_view kStandardMetadataTypeTag(kStandardMetadataTypeStr, sizeof(kStandardMetadataTypeStr) - 1);
+const std::string_view kChromaSitingTag = "android.hardware.graphics.common.ChromaSiting"sv;
+const std::string_view kCompressionTag = "android.hardware.graphics.common.Compression"sv;
+const std::string_view kInterlacedTag = "android.hardware.graphics.common.Interlaced"sv;
+const std::string_view kPlaneLayoutComponentTypeTag = "android.hardware.graphics.common.PlaneLayoutComponentType"sv;
+
+template<class T, size_t SIZE> constexpr size_t arraySize(T (&)[SIZE]) { return SIZE; }
+
+PixelFormat getPixelFormat(const cb_handle_t& cb) {
+    return static_cast<PixelFormat>(cb.format);
+}
+
+bool isYuvFormat(const PixelFormat format) {
+    switch (format) {
+    case PixelFormat::YCRCB_420_SP:
+    case PixelFormat::YV12:
+    case PixelFormat::YCBCR_420_888:
+    case PixelFormat::YCBCR_P010:
+        return true;
+
+    default:
+        return false;
+    }
+}
+
+ChromaSiting getFormatChromaSiting(const PixelFormat format) {
+    return isYuvFormat(format) ? ChromaSiting::SITED_INTERSTITIAL : ChromaSiting::NONE;
+}
+
+CbExternalMetadata& getExternalMetadata(const cb_handle_t& cb) {
+    CbExternalMetadata& m = *reinterpret_cast<CbExternalMetadata*>(
+        cb.getBufferPtr() + cb.externalMetadataOffset);
+    LOG_ALWAYS_FATAL_IF(m.magic != CbExternalMetadata::kMagicValue);
+    return m;
+}
+
+uint64_t getID(const cb_handle_t& cb) {
+    return getExternalMetadata(cb).bufferID;
+}
+
+int waitFenceFd(const int fd, const char* logname) {
+    const int warningTimeout = 5000;
+    if (sync_wait(fd, warningTimeout) < 0) {
+        if (errno == ETIME) {
+            ALOGW("%s: fence %d didn't signal in %d ms", logname, fd, warningTimeout);
+            if (sync_wait(fd, -1) < 0) {
+                return errno;
+            } else {
+                return 0;
+            }
+        } else {
+            return errno;
+        }
+    } else {
+        return 0;
+    }
+}
+
+const AIMapper_MetadataTypeDescription kMetadataTypeDescriptionList[] = {
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::BUFFER_ID),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::NAME),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::WIDTH),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::HEIGHT),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::LAYER_COUNT),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::PIXEL_FORMAT_REQUESTED),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::PIXEL_FORMAT_FOURCC),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::PIXEL_FORMAT_MODIFIER),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::USAGE),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::ALLOCATION_SIZE),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::PROTECTED_CONTENT),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::COMPRESSION),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::INTERLACED),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::CHROMA_SITING),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::PLANE_LAYOUTS),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::CROP),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::DATASPACE),
+        },
+        .isGettable = true,
+        .isSettable = true,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::BLEND_MODE),
+        },
+        .isGettable = true,
+        .isSettable = true,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::SMPTE2086),
+        },
+        .isGettable = true,
+        .isSettable = true,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::CTA861_3),
+        },
+        .isGettable = true,
+        .isSettable = true,
+    },
+    {
+        .metadataType = {
+            .name = kStandardMetadataTypeStr,
+            .value = static_cast<int64_t>(StandardMetadataType::STRIDE),
+        },
+        .isGettable = true,
+        .isSettable = false,
+    },
+};
+
+struct GoldfishMapper {
+    GoldfishMapper()
+            : mHostConn(HostConnection::createUnique(kCapsetNone))
+            , mDebugLevel(getDebugLevel()) {
+        GoldfishAddressSpaceHostMemoryAllocator hostMemoryAllocator(false);
+        LOG_ALWAYS_FATAL_IF(!hostMemoryAllocator.is_opened(),
+            "GoldfishAddressSpaceHostMemoryAllocator failed to open");
+
+        GoldfishAddressSpaceBlock bufferBits;
+        LOG_ALWAYS_FATAL_IF(hostMemoryAllocator.hostMalloc(&bufferBits, 256),
+                            "hostMalloc failed");
+
+        mPhysAddrToOffset = bufferBits.physAddr() - bufferBits.offset();
+        hostMemoryAllocator.hostFree(&bufferBits);
+
+        static GoldfishMapper* s_instance;
+
+        mMapper.version = AIMAPPER_VERSION_5;
+        mMapper.v5.importBuffer = [](const native_handle_t* handle,
+                                     buffer_handle_t* outBufferHandle) {
+            return s_instance->importBuffer(handle, outBufferHandle);
+        };
+        mMapper.v5.freeBuffer = [](buffer_handle_t buffer) {
+            return s_instance->freeBuffer(buffer);
+        };
+        mMapper.v5.getTransportSize = &getTransportSize;
+        mMapper.v5.lock = [](buffer_handle_t buffer, uint64_t cpuUsage,
+                             ARect accessRegion, int acquireFence,
+                             void** outData){
+            return s_instance->lock(buffer, cpuUsage, accessRegion,
+                                    acquireFence, outData);
+        };
+        mMapper.v5.unlock = [](buffer_handle_t buffer, int* releaseFence) {
+            return s_instance->unlock(buffer, releaseFence);
+        };
+        mMapper.v5.flushLockedBuffer = [](buffer_handle_t buffer) {
+            return s_instance->flushLockedBuffer(buffer);
+        };
+        mMapper.v5.rereadLockedBuffer = [](buffer_handle_t buffer) {
+            return s_instance->rereadLockedBuffer(buffer);
+        };
+        mMapper.v5.getMetadata = [](const buffer_handle_t buffer,
+                                    const AIMapper_MetadataType metadataType,
+                                    void* const destBuffer, const size_t destBufferSize) {
+            return s_instance->getMetadata(buffer, metadataType,
+                                           destBuffer, destBufferSize);
+        };
+        mMapper.v5.getStandardMetadata = [](const buffer_handle_t buffer,
+                                            const int64_t standardMetadataType,
+                                            void* const destBuffer,
+                                            const size_t destBufferSize) {
+            return s_instance->getStandardMetadata(buffer, standardMetadataType,
+                                                   destBuffer, destBufferSize);
+        };
+        mMapper.v5.setMetadata = [](const buffer_handle_t buffer,
+                                    const AIMapper_MetadataType metadataType,
+                                    const void* const metadata, const size_t metadataSize) {
+            return s_instance->setMetadata(buffer, metadataType,
+                                           metadata, metadataSize);
+        };
+        mMapper.v5.setStandardMetadata = [](const buffer_handle_t buffer,
+                                            const int64_t standardMetadataType,
+                                            const void* const metadata,
+                                            const size_t metadataSize) {
+            return s_instance->setStandardMetadata(buffer, standardMetadataType,
+                                                   metadata, metadataSize);
+        };
+        mMapper.v5.listSupportedMetadataTypes = &listSupportedMetadataTypes;
+        mMapper.v5.dumpBuffer = [](const buffer_handle_t buffer,
+                                   const AIMapper_DumpBufferCallback dumpBufferCallback,
+                                   void* const context) {
+            return s_instance->dumpBuffer(buffer, dumpBufferCallback, context);
+        };
+        mMapper.v5.dumpAllBuffers = [](AIMapper_BeginDumpBufferCallback beginDumpCallback,
+                                       AIMapper_DumpBufferCallback dumpBufferCallback,
+                                       void* context){
+            return s_instance->dumpAllBuffers(beginDumpCallback, dumpBufferCallback,
+                                              context);
+        };
+        mMapper.v5.getReservedRegion = [](const buffer_handle_t buffer,
+                                          void** const outReservedRegion,
+                                          uint64_t* const outReservedSize) {
+            return s_instance->getReservedRegion(buffer, outReservedRegion,
+                                                 outReservedSize);
+        };
+
+        s_instance = this;
+    }
+
+    AIMapper& getAIMapper() {
+        return mMapper;
+    }
+
+private:
+    AIMapper_Error importBuffer(const native_handle_t* const handle,
+                                buffer_handle_t* const outBufferHandle) {
+        if (!handle) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+        native_handle_t* const imported = native_handle_clone(handle);
+        if (!imported) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+        cb_handle_t* const cb = cb_handle_t::from(imported);
+        if (!cb) {
+            native_handle_close(imported);
+            native_handle_delete(imported);
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        if (cb->mmapedSize) {
+            const int bufferFd = cb->bufferFd;
+            LOG_ALWAYS_FATAL_IF(bufferFd < 0);
+
+            void* newPtr;
+            const int err = GoldfishAddressSpaceBlock::memoryMap(
+                cb->getBufferPtr(), cb->mmapedSize,
+                bufferFd, cb->getMmapedOffset(), &newPtr);
+            if (err) {
+                native_handle_close(imported);
+                native_handle_delete(imported);
+                return FAILURE_V(AIMAPPER_ERROR_NO_RESOURCES, "%s: %s",
+                                 "NO_RESOURCES", strerror(err));
+            }
+            cb->setBufferPtr(newPtr);
+        }
+
+        if (mDebugLevel >= DebugLevel::IMPORT) {
+            ALOGD("%s:%d: id=%" PRIu64, __func__, __LINE__, getID(*cb));
+        }
+
+        std::lock_guard<std::mutex> lock(mImportedBuffersMtx);
+        LOG_ALWAYS_FATAL_IF(!mImportedBuffers.insert(cb).second);
+        *outBufferHandle = cb;
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error freeBuffer(buffer_handle_t buffer) {
+        cb_handle_t* const cb = const_cast<cb_handle_t*>(static_cast<const cb_handle_t*>(buffer));
+
+        {
+            std::lock_guard<std::mutex> lock(mImportedBuffersMtx);
+            if (mImportedBuffers.erase(cb) == 0) {
+                return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+            }
+        }
+
+        if (mDebugLevel >= DebugLevel::IMPORT) {
+            ALOGD("%s:%d: id=%" PRIu64, __func__, __LINE__, getID(*cb));
+        }
+
+        if (cb->hostHandle && (cb->lockedUsage & kCPU_WRITE_MASK)) {
+            flushToHost(*cb);
+        }
+        GoldfishAddressSpaceBlock::memoryUnmap(cb->getBufferPtr(),
+                                               cb->mmapedSize);
+        native_handle_close(cb);
+        native_handle_delete(cb);
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    static AIMapper_Error getTransportSize(const buffer_handle_t buffer,
+                                           uint32_t* const outNumFds,
+                                           uint32_t* const outNumInts) {
+        const cb_handle_t* const cb = cb_handle_t::from(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        *outNumFds = cb->numFds;
+        *outNumInts = cb->numInts;
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error lock(const buffer_handle_t buffer, const uint64_t uncheckedUsage,
+                        const ARect& accessRegion, const int acquireFence,
+                        void** const outData) const {
+        cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        const CbExternalMetadata& metadata = getExternalMetadata(*cb);
+        if (cb->lockedUsage) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_BUFFER, "%s: id=%" PRIu64,
+                             "BAD_BUFFER(lockedUsage)", metadata.bufferID);
+        }
+
+        if ((accessRegion.left < 0) ||
+                (accessRegion.top < 0) ||
+                (accessRegion.bottom < accessRegion.top) ||
+                (accessRegion.right < accessRegion.left) ||
+                (accessRegion.right > metadata.width) ||
+                (accessRegion.bottom > metadata.height)) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64,
+                             "BAD_VALUE(accessRegion)", metadata.bufferID);
+        }
+        if (accessRegion.right && (accessRegion.left == accessRegion.right)) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64,
+                             "BAD_VALUE(accessRegion)", metadata.bufferID);
+        }
+        if (accessRegion.bottom && (accessRegion.top == accessRegion.bottom)) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64,
+                             "BAD_VALUE(accessRegion)", metadata.bufferID);
+        }
+
+        const uint8_t cpuUsage = uncheckedUsage & cb->usage & (kCPU_READ_MASK | kCPU_WRITE_MASK);
+        if (cpuUsage == 0) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64,
+                             "BAD_VALUE(uncheckedUsage)", metadata.bufferID);
+        }
+        if ((acquireFence >= 0) && waitFenceFd(acquireFence, __func__)) {
+            return FAILURE_V(AIMAPPER_ERROR_NO_RESOURCES, "%s: id=%" PRIu64,
+                             "NO_RESOURCES(acquireFence)", metadata.bufferID);
+        }
+
+        if (mDebugLevel >= DebugLevel::LOCK) {
+            ALOGD("%s:%d: id=%" PRIu64 " usage=0x%X accessRegion="
+                  "{ .left=%d, .top=%d, .right=%d, .bottom=%d }",
+                  __func__, __LINE__, metadata.bufferID, cpuUsage, accessRegion.left,
+                  accessRegion.top, accessRegion.right, accessRegion.bottom);
+        }
+
+        if (cb->hostHandle) {
+            const AIMapper_Error e = readFromHost(*cb);
+            if (e != AIMAPPER_ERROR_NONE) {
+                return e;
+            }
+        }
+
+        cb->lockedUsage = cpuUsage;
+        *outData = cb->getBufferPtr();
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error unlock(const buffer_handle_t buffer, int* const releaseFence) const {
+        cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+        if (cb->lockedUsage == 0) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_BUFFER, "%s: id=%" PRIu64,
+                             "BAD_BUFFER(lockedUsage)", getID(*cb));
+        }
+
+        if (mDebugLevel >= DebugLevel::LOCK) {
+            ALOGD("%s:%d: id=%" PRIu64, __func__, __LINE__, getID(*cb));
+        }
+
+        if (cb->hostHandle && (cb->lockedUsage & kCPU_WRITE_MASK)) {
+            flushToHost(*cb);
+        }
+
+        cb->lockedUsage = 0;
+        *releaseFence = -1;
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error flushLockedBuffer(const buffer_handle_t buffer) const {
+        const cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+        if (mDebugLevel >= DebugLevel::FLUSH) {
+            ALOGD("%s:%d: id=%" PRIu64, __func__, __LINE__, getID(*cb));
+        }
+        if ((cb->lockedUsage & kCPU_WRITE_MASK) == 0) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_BUFFER, "%s: id=%" PRIu64 ,
+                             "BAD_BUFFER(lockedUsage)", getID(*cb));
+        }
+        if (cb->hostHandle) {
+            flushToHost(*cb);
+        }
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error rereadLockedBuffer(const buffer_handle_t buffer) const {
+        const cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+        if (mDebugLevel >= DebugLevel::FLUSH) {
+            ALOGD("%s:%d: id=%" PRIu64, __func__, __LINE__, getID(*cb));
+        }
+        if ((cb->lockedUsage & kCPU_READ_MASK) == 0) {
+            return FAILURE_V(AIMAPPER_ERROR_BAD_BUFFER, "%s: id=%" PRIu64 ,
+                             "BAD_BUFFER(lockedUsage)", getID(*cb));
+        }
+
+        if (cb->hostHandle) {
+            return readFromHost(*cb);
+        } else {
+            return AIMAPPER_ERROR_NONE;
+        }
+    }
+
+    AIMapper_Error readFromHost(const cb_handle_t& cb) const {
+        const CbExternalMetadata& metadata = getExternalMetadata(cb);
+        const HostConnectionSession conn = getHostConnectionSession();
+        ExtendedRCEncoderContext *const rcEnc = conn.getRcEncoder();
+
+        const int res = rcEnc->rcColorBufferCacheFlush(
+            rcEnc, cb.hostHandle, 0, true);
+        if (res < 0) {
+            return FAILURE_V(AIMAPPER_ERROR_NO_RESOURCES, "%s: id=%" PRIu64 " res=%d",
+                             "NO_RESOURCES", metadata.bufferID, res);
+        }
+
+        if (isYuvFormat(getPixelFormat(cb))) {
+            LOG_ALWAYS_FATAL_IF(!rcEnc->hasYUVCache());
+            rcEnc->rcReadColorBufferYUV(rcEnc, cb.hostHandle,
+                                        0, 0, metadata.width, metadata.height,
+                                        cb.getBufferPtr(), cb.bufferSize);
+        } else {
+            LOG_ALWAYS_FATAL_IF(!rcEnc->featureInfo()->hasReadColorBufferDma);
+            rcEnc->bindDmaDirectly(cb.getBufferPtr(),
+                                   getMmapedPhysAddr(cb.getMmapedOffset()));
+            rcEnc->rcReadColorBufferDMA(rcEnc, cb.hostHandle,
+                                        0, 0, metadata.width, metadata.height,
+                                        metadata.glFormat, metadata.glType,
+                                        cb.getBufferPtr(), cb.bufferSize);
+        }
+
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    void flushToHost(const cb_handle_t& cb) const {
+        const CbExternalMetadata& metadata = getExternalMetadata(cb);
+        const HostConnectionSession conn = getHostConnectionSession();
+        ExtendedRCEncoderContext *const rcEnc = conn.getRcEncoder();
+
+        rcEnc->bindDmaDirectly(cb.getBufferPtr(),
+                               getMmapedPhysAddr(cb.getMmapedOffset()));
+        rcEnc->rcUpdateColorBufferDMA(rcEnc, cb.hostHandle,
+                                      0, 0, metadata.width, metadata.height,
+                                      metadata.glFormat, metadata.glType,
+                                      cb.getBufferPtr(), cb.bufferSize);
+    }
+
+    int32_t getMetadata(const buffer_handle_t buffer,
+                        const AIMapper_MetadataType metadataType,
+                        void* const destBuffer, const size_t destBufferSize) const {
+        if (strcmp(metadataType.name, kStandardMetadataTypeStr)) {
+            return -FAILURE_V(AIMAPPER_ERROR_UNSUPPORTED, "%s: name=%s",
+                              "UNSUPPORTED", metadataType.name);
+        } else {
+            return getStandardMetadata(buffer, metadataType.value,
+                                       destBuffer, destBufferSize);
+        }
+    }
+
+    int32_t getStandardMetadata(const buffer_handle_t buffer,
+                                const int64_t standardMetadataType,
+                                void* const destBuffer,
+                                const size_t destBufferSize) const {
+        const cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return -FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        // don't log dry runs
+        if (destBufferSize && (mDebugLevel >= DebugLevel::METADATA)) {
+            ALOGD("%s:%d: id=%" PRIu64 " standardMetadataType=%" PRId64,
+                  __func__, __LINE__, getID(*cb), standardMetadataType);
+        }
+
+        return getStandardMetadataImpl(*cb, MetadataWriter(destBuffer, destBufferSize),
+                                       static_cast<StandardMetadataType>(standardMetadataType));
+    }
+
+    AIMapper_Error setMetadata(const buffer_handle_t buffer,
+                               const AIMapper_MetadataType metadataType,
+                               const void* const metadata, const size_t metadataSize) const {
+        if (strcmp(metadataType.name, kStandardMetadataTypeStr)) {
+            return FAILURE_V(AIMAPPER_ERROR_UNSUPPORTED, "%s: name=%s",
+                             "UNSUPPORTED", metadataType.name);
+        } else {
+            return setStandardMetadata(buffer, metadataType.value,
+                                       metadata, metadataSize);
+        }
+    }
+
+    AIMapper_Error setStandardMetadata(const buffer_handle_t buffer,
+                                       const int64_t standardMetadataType,
+                                       const void* const metadata,
+                                       const size_t metadataSize) const {
+        const cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        if (mDebugLevel >= DebugLevel::METADATA) {
+            ALOGD("%s:%d: id=%" PRIu64 " standardMetadataType=%" PRId64,
+                  __func__, __LINE__, getID(*cb), standardMetadataType);
+        }
+
+        return setStandardMetadataImpl(*cb, MetadataReader(metadata, metadataSize),
+                                       static_cast<StandardMetadataType>(standardMetadataType));
+    }
+
+    int32_t getStandardMetadataImpl(const cb_handle_t& cb, MetadataWriter writer,
+                                    const StandardMetadataType standardMetadataType) const {
+        const auto putMetadataHeader = [](MetadataWriter& writer,
+                                          const StandardMetadataType standardMetadataType) -> MetadataWriter& {
+            return writer.write(kStandardMetadataTypeTag)
+                         .write(static_cast<int64_t>(standardMetadataType));
+        };
+
+        const CbExternalMetadata& metadata = getExternalMetadata(cb);
+        switch (standardMetadataType) {
+        case StandardMetadataType::BUFFER_ID:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(metadata.bufferID);
+            break;
+
+        case StandardMetadataType::NAME:
+            putMetadataHeader(writer, standardMetadataType)
+                .write(std::string_view(metadata.name, metadata.nameSize));
+            break;
+
+        case StandardMetadataType::WIDTH:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(metadata.width);
+            break;
+
+        case StandardMetadataType::HEIGHT:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(metadata.height);
+            break;
+
+        case StandardMetadataType::LAYER_COUNT:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(1);
+            break;
+
+        case StandardMetadataType::PIXEL_FORMAT_REQUESTED:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint32_t>(cb.format);
+            break;
+
+        case StandardMetadataType::PIXEL_FORMAT_FOURCC:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint32_t>(cb.drmformat);
+            break;
+
+        case StandardMetadataType::PIXEL_FORMAT_MODIFIER:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(DRM_FORMAT_MOD_LINEAR);
+            break;
+
+        case StandardMetadataType::USAGE:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(cb.usage);
+            break;
+
+        case StandardMetadataType::ALLOCATION_SIZE:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>(cb.mmapedSize);
+            break;
+
+        case StandardMetadataType::PROTECTED_CONTENT:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<uint64_t>((cb.usage & static_cast<uint64_t>(BufferUsage::PROTECTED))
+                                 ? 1 : 0);
+            break;
+
+        case StandardMetadataType::COMPRESSION:
+            putMetadataHeader(writer, standardMetadataType)
+                .write(kCompressionTag)
+                .write(static_cast<int64_t>(aahgc::Compression::NONE));
+            break;
+
+        case StandardMetadataType::INTERLACED:
+            putMetadataHeader(writer, standardMetadataType)
+                .write(kInterlacedTag)
+                .write(static_cast<int64_t>(aahgc::Interlaced::NONE));
+            break;
+
+        case StandardMetadataType::CHROMA_SITING:
+            putMetadataHeader(writer, standardMetadataType)
+                .write(kChromaSitingTag)
+                .write(static_cast<int64_t>(getFormatChromaSiting(getPixelFormat(cb))));
+            break;
+
+        case StandardMetadataType::PLANE_LAYOUTS: {
+                const unsigned planeLayoutSize = metadata.planeLayoutSize;
+                if (!planeLayoutSize) {
+                    return -AIMAPPER_ERROR_UNSUPPORTED;
+                }
+                const PlaneLayoutComponent* const layoutComponents =
+                    metadata.planeLayoutComponent;
+
+                putMetadataHeader(writer, standardMetadataType)
+                    .write<int64_t>(planeLayoutSize);
+                for (unsigned plane = 0; plane < planeLayoutSize; ++plane) {
+                    const auto& planeLayout = metadata.planeLayout[plane];
+                    unsigned n = planeLayout.componentsSize;
+                    const PlaneLayoutComponent* component =
+                        layoutComponents + planeLayout.componentsBase;
+
+                    writer.write<int64_t>(n);
+                    for (; n > 0; --n, ++component) {
+                        writer.write(kPlaneLayoutComponentTypeTag)
+                              .write<int64_t>(component->type)
+                              .write<int64_t>(component->offsetInBits)
+                              .write<int64_t>(component->sizeInBits);
+                    }
+
+                    const unsigned horizontalSubsampling =
+                        (1U << planeLayout.horizontalSubsamplingShift);
+                    const unsigned verticalSubsampling =
+                        (1U << planeLayout.verticalSubsamplingShift);
+
+                    writer.write<int64_t>(planeLayout.offsetInBytes)
+                          .write<int64_t>(planeLayout.sampleIncrementInBytes * CHAR_BIT)
+                          .write<int64_t>(planeLayout.strideInBytes)
+                          .write<int64_t>(metadata.width / horizontalSubsampling)
+                          .write<int64_t>(metadata.height / verticalSubsampling)
+                          .write<int64_t>(planeLayout.totalSizeInBytes)
+                          .write<int64_t>(horizontalSubsampling)
+                          .write<int64_t>(verticalSubsampling);
+                }
+            }
+            break;
+
+        case StandardMetadataType::CROP: {
+                unsigned planeLayoutSize = metadata.planeLayoutSize;
+                if (!planeLayoutSize) {
+                    return -AIMAPPER_ERROR_UNSUPPORTED;
+                }
+
+                putMetadataHeader(writer, standardMetadataType)
+                    .write<uint64_t>(planeLayoutSize);
+                for (; planeLayoutSize > 0; --planeLayoutSize) {
+                    /*
+                     * b/359690632: `width`,`height` and `CROP` are uint64_t
+                     * in the spec. But the metadata parser in Android uses
+                     * int32_t for `CROP`.
+                     */
+                    writer.write<int32_t>(0).write<int32_t>(0)
+                          .write<int32_t>(metadata.width)
+                          .write<int32_t>(metadata.height);
+                }
+            }
+            break;
+
+        case StandardMetadataType::DATASPACE:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<int32_t>(metadata.dataspace);
+            break;
+
+        case StandardMetadataType::BLEND_MODE:
+            putMetadataHeader(writer, standardMetadataType)
+                .write<int32_t>(metadata.blendMode);
+            break;
+
+        case StandardMetadataType::SMPTE2086:
+            if (metadata.has_smpte2086) {
+                const auto& smpte2086 = metadata.smpte2086;
+                putMetadataHeader(writer, standardMetadataType)
+                      .write(smpte2086.primaryRed.x).write(smpte2086.primaryRed.y)
+                      .write(smpte2086.primaryGreen.x).write(smpte2086.primaryGreen.y)
+                      .write(smpte2086.primaryBlue.x).write(smpte2086.primaryBlue.y)
+                      .write(smpte2086.whitePoint.x).write(smpte2086.whitePoint.y)
+                      .write(smpte2086.maxLuminance).write(smpte2086.minLuminance);
+            }
+            break;
+
+        case StandardMetadataType::CTA861_3:
+            if (metadata.has_cta861_3) {
+                const auto& cta861_3 = metadata.cta861_3;
+                putMetadataHeader(writer, standardMetadataType)
+                      .write(cta861_3.maxContentLightLevel)
+                      .write(cta861_3.maxFrameAverageLightLevel);
+            }
+            break;
+
+        case StandardMetadataType::STRIDE: {
+                const uint32_t value = (metadata.planeLayoutSize == 1) ?
+                    (metadata.planeLayout[0].strideInBytes /
+                     metadata.planeLayout[0].sampleIncrementInBytes) : 0;
+
+                putMetadataHeader(writer, standardMetadataType).write(value);
+            }
+            break;
+
+        default:
+            return -FAILURE_V(AIMAPPER_ERROR_UNSUPPORTED,
+                              "%s: id=%" PRIu64 ": unexpected standardMetadataType=%" PRId64,
+                              "UNSUPPORTED", metadata.bufferID, static_cast<int64_t>(standardMetadataType));
+        }
+
+        return writer.desiredSize();
+    }
+
+    AIMapper_Error setStandardMetadataImpl(const cb_handle_t& cb, MetadataReader reader,
+                                           const StandardMetadataType standardMetadataType) const {
+        const auto checkMetadataHeader = [](MetadataReader& reader,
+                                            const StandardMetadataType standardMetadataType) {
+            if (reader.readString().compare(kStandardMetadataTypeTag)) {
+                return false;
+            }
+
+            const std::optional<int64_t> type = reader.readInt<int64_t>();
+            return type.has_value() &&
+                   (type == static_cast<int64_t>(standardMetadataType)) &&
+                   reader.ok();
+        };
+
+        CbExternalMetadata& metadata = getExternalMetadata(cb);
+        switch (standardMetadataType) {
+        case StandardMetadataType::DATASPACE:
+            if (!checkMetadataHeader(reader, standardMetadataType)) {
+                return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                 "BAD_VALUE", metadata.bufferID, "DATASPACE");
+            }
+
+            reader.read(metadata.dataspace);
+            if (!reader.ok()) {
+                return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                 "BAD_VALUE", metadata.bufferID, "DATASPACE");
+            }
+            break;
+
+        case StandardMetadataType::BLEND_MODE:
+            if (!checkMetadataHeader(reader, standardMetadataType)) {
+                return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                 "BAD_VALUE", metadata.bufferID, "BLEND_MODE");
+            }
+            reader.read(metadata.blendMode);
+            if (!reader.ok()) {
+                return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                 "BAD_VALUE", metadata.bufferID, "BLEND_MODE");
+            }
+            break;
+
+        case StandardMetadataType::SMPTE2086:
+            if (reader.remaining() > 0) {
+                if (!checkMetadataHeader(reader, standardMetadataType)) {
+                    return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                     "BAD_VALUE", metadata.bufferID, "SMPTE2086");
+                }
+
+                CbExternalMetadata::Smpte2086 smpte2086;
+                reader.read(smpte2086.primaryRed.x).read(smpte2086.primaryRed.y)
+                      .read(smpte2086.primaryGreen.x).read(smpte2086.primaryGreen.y)
+                      .read(smpte2086.primaryBlue.x).read(smpte2086.primaryBlue.y)
+                      .read(smpte2086.whitePoint.x).read(smpte2086.whitePoint.y)
+                      .read(smpte2086.maxLuminance).read(smpte2086.minLuminance);
+                if (reader.ok()) {
+                    metadata.smpte2086 = smpte2086;
+                    metadata.has_smpte2086 = true;
+                } else {
+                    return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                     "BAD_VALUE", metadata.bufferID, "SMPTE2086");
+                }
+            } else {
+                metadata.has_smpte2086 = false;
+            }
+            break;
+
+        case StandardMetadataType::CTA861_3:
+            if (reader.remaining() > 0) {
+                if (!checkMetadataHeader(reader, standardMetadataType)) {
+                    return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                     "BAD_VALUE", metadata.bufferID, "CTA861_3");
+                }
+
+                CbExternalMetadata::Cta861_3 cta861_3;
+                reader.read(cta861_3.maxContentLightLevel)
+                      .read(cta861_3.maxFrameAverageLightLevel);
+                if (reader.ok()) {
+                    metadata.cta861_3 = cta861_3;
+                    metadata.has_cta861_3 = true;
+                } else {
+                    return FAILURE_V(AIMAPPER_ERROR_BAD_VALUE, "%s: id=%" PRIu64 ": %s",
+                                     "BAD_VALUE", metadata.bufferID, "CTA861_3");
+                }
+            } else {
+                metadata.has_cta861_3 = false;
+            }
+            break;
+
+        default:
+            return FAILURE_V(AIMAPPER_ERROR_UNSUPPORTED,
+                             "%s: id=%" PRIu64 ": standardMetadataType=%" PRId64,
+                             "UNSUPPORTED", metadata.bufferID, static_cast<int64_t>(standardMetadataType));
+        }
+
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    static AIMapper_Error listSupportedMetadataTypes(
+            const AIMapper_MetadataTypeDescription** outDescriptionList,
+            size_t* outNumberOfDescriptions) {
+        *outDescriptionList = kMetadataTypeDescriptionList;
+        *outNumberOfDescriptions = arraySize(kMetadataTypeDescriptionList);
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error dumpBuffer(const buffer_handle_t buffer,
+                              const AIMapper_DumpBufferCallback dumpBufferCallback,
+                              void* const context) const {
+        const cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        if (mDebugLevel >= DebugLevel::METADATA) {
+            ALOGD("%s:%d: id=%" PRIu64, __func__, __LINE__, getID(*cb));
+        }
+
+        std::vector<uint8_t> metadataBuffer(kMetadataBufferInitialSize);
+        dumpBufferImpl(*cb, dumpBufferCallback, context, metadataBuffer);
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    void dumpBufferImpl(const cb_handle_t& cb,
+                        const AIMapper_DumpBufferCallback dumpBufferCallback,
+                        void* const context,
+                        std::vector<uint8_t>& metadataBuffer) const {
+        for (const auto& m : kMetadataTypeDescriptionList) {
+            if (m.isGettable) {
+                bool firstTry = true;
+retryWithLargerBuffer:
+                MetadataWriter writer(metadataBuffer.data(), metadataBuffer.size());
+                const int32_t desiredSize = getStandardMetadataImpl(cb, writer,
+                    static_cast<StandardMetadataType>(m.metadataType.value));
+                if (desiredSize < 0) {
+                    // should not happen, update `getStandardMetadata`
+                    continue;
+                } else if (desiredSize <= metadataBuffer.size()) {
+                    (*dumpBufferCallback)(context, m.metadataType,
+                                          metadataBuffer.data(), desiredSize);
+                } else {
+                    LOG_ALWAYS_FATAL_IF(!firstTry);
+                    metadataBuffer.resize(desiredSize);
+                    firstTry = false;
+                    goto retryWithLargerBuffer;
+                }
+            }
+        }
+    }
+
+    AIMapper_Error dumpAllBuffers(const AIMapper_BeginDumpBufferCallback beginDumpCallback,
+                                  const AIMapper_DumpBufferCallback dumpBufferCallback,
+                                  void* const context) const {
+        std::vector<uint8_t> metadataBuffer(kMetadataBufferInitialSize);
+
+        std::lock_guard<std::mutex> lock(mImportedBuffersMtx);
+        for (const cb_handle_t* const cb : mImportedBuffers) {
+            (*beginDumpCallback)(context);
+            dumpBufferImpl(*cb, dumpBufferCallback, context, metadataBuffer);
+        }
+
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    AIMapper_Error getReservedRegion(const buffer_handle_t buffer,
+                                     void** const outReservedRegion,
+                                     uint64_t* const outReservedSize) const {
+        const cb_handle_t* const cb = validateCb(buffer);
+        if (!cb) {
+            return FAILURE(AIMAPPER_ERROR_BAD_BUFFER);
+        }
+
+        CbExternalMetadata& metadata = getExternalMetadata(*cb);
+        const size_t reservedRegionSize = metadata.reservedRegionSize;
+        if (reservedRegionSize) {
+            *outReservedRegion = &metadata + 1;  // right after `CbExternalMetadata`
+        } else {
+            *outReservedRegion = nullptr;
+        }
+        *outReservedSize = reservedRegionSize;
+        return AIMAPPER_ERROR_NONE;
+    }
+
+    cb_handle_t* validateCb(const buffer_handle_t buffer) const {
+        cb_handle_t* cb = const_cast<cb_handle_t*>(static_cast<const cb_handle_t*>(buffer));
+        std::lock_guard<std::mutex> lock(mImportedBuffersMtx);
+        return mImportedBuffers.count(cb) ? cb : nullptr;
+    }
+
+    HostConnectionSession getHostConnectionSession() const {
+        return HostConnectionSession(mHostConn.get());
+    }
+
+    uint64_t getMmapedPhysAddr(const uint64_t offset) const {
+        return mPhysAddrToOffset + offset;
+    }
+
+    AIMapper mMapper;
+    const std::unique_ptr<HostConnection> mHostConn;
+    std::unordered_set<const cb_handle_t*> mImportedBuffers;
+    uint64_t mPhysAddrToOffset;
+    mutable std::mutex mImportedBuffersMtx;
+    const DebugLevel mDebugLevel;
+};
+}  // namespace
+
+extern "C" uint32_t ANDROID_HAL_MAPPER_VERSION = AIMAPPER_VERSION_5;
+
+extern "C" AIMapper_Error AIMapper_loadIMapper(AIMapper* _Nullable* _Nonnull outImplementation) {
+    static GoldfishMapper instance;
+    *outImplementation = &instance.getAIMapper();
+    return AIMAPPER_ERROR_NONE;
+}
diff --git a/init.ranchu.rc b/init.ranchu.rc
index 001fd46f..ba7618dd 100644
--- a/init.ranchu.rc
+++ b/init.ranchu.rc
@@ -106,6 +106,7 @@ on property:dev.bootcomplete=1 && property:vendor.qemu.dev.bootcomplete=0
     setprop vendor.qemu.dev.bootcomplete 1
     start qemu-props-bootcomplete
     start ranchu-setup
+    start ranchu-adb-setup
 
 on post-fs-data && property:ro.boot.qemu.virtiowifi=1
     start ranchu-net
@@ -197,6 +198,7 @@ service vendor.uwb_hal /vendor/bin/hw/android.hardware.uwb-service /dev/hvc2
 
 on property:sys.boot_completed=1
     trigger sys-boot-completed-set
+    start vendor.ril-daemon
 
 on sys-boot-completed-set && property:persist.sys.zram_enabled=1
     swapon_all /vendor/etc/fstab.${ro.hardware}
diff --git a/overlay/frameworks/base/packages/overlays/pixel_fold2/AndroidOverlay/res/values/config.xml b/overlay/frameworks/base/packages/overlays/pixel_fold2/AndroidOverlay/res/values/config.xml
index c5845945..7001da60 100644
--- a/overlay/frameworks/base/packages/overlays/pixel_fold2/AndroidOverlay/res/values/config.xml
+++ b/overlay/frameworks/base/packages/overlays/pixel_fold2/AndroidOverlay/res/values/config.xml
@@ -34,6 +34,14 @@
         @left
     </string>
 
+
+    <integer-array name="config_mainBuiltInDisplayCutoutSideOverride" translatable="false">
+        <item>1</item> <!-- Top -->
+        <item>1</item> <!-- Top -->
+        <item>3</item> <!-- Bottom -->
+        <item>3</item> <!-- Bottom -->
+    </integer-array>
+
     <string translatable="false" name="config_mainBuiltInDisplayCutoutRectApproximation">
         m 0,0
         V 136
diff --git a/pc/overlay/frameworks/base/core/res/res/values/config.xml b/pc/overlay/frameworks/base/core/res/res/values/config.xml
index 0b4b423b..f38ace51 100644
--- a/pc/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/pc/overlay/frameworks/base/core/res/res/values/config.xml
@@ -23,4 +23,6 @@
     <bool name="config_supportsSplitScreenMultiWindow">false</bool>
     <!-- Disable quick settings b/240884945 -->
     <bool name="config_quickSettingsSupported">false</bool>
+    <!-- Enable close button on notifications -->
+    <bool name="config_notificationCloseButtonSupported">true</bool>
 </resources>
diff --git a/phone/overlay/frameworks/base/packages/overlays/DisplayCutoutEmulationEmu01/Android.bp b/phone/overlay/frameworks/base/packages/overlays/DisplayCutoutEmulationEmu01/Android.bp
new file mode 100644
index 00000000..f53f8248
--- /dev/null
+++ b/phone/overlay/frameworks/base/packages/overlays/DisplayCutoutEmulationEmu01/Android.bp
@@ -0,0 +1,28 @@
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+    ],
+}
+
+runtime_resource_overlay {
+    name: "DisplayCutoutEmulationEmu01Overlay",
+    theme: "DisplayCutoutEmulationEmu01",
+    certificate: "platform",
+    sdk_version: "current",
+    product_specific: true,
+}
diff --git a/phone/overlay/frameworks/base/packages/overlays/DisplayCutoutEmulationEmu01/Android.mk b/phone/overlay/frameworks/base/packages/overlays/DisplayCutoutEmulationEmu01/Android.mk
deleted file mode 100644
index 4b70089f..00000000
--- a/phone/overlay/frameworks/base/packages/overlays/DisplayCutoutEmulationEmu01/Android.mk
+++ /dev/null
@@ -1,16 +0,0 @@
-LOCAL_PATH:= $(call my-dir)
-include $(CLEAR_VARS)
-
-LOCAL_RRO_THEME := DisplayCutoutEmulationEmu01
-LOCAL_CERTIFICATE := platform
-
-LOCAL_SRC_FILES := $(call all-subdir-java-files)
-
-LOCAL_RESOURCE_DIR := $(LOCAL_PATH)/res
-
-LOCAL_PACKAGE_NAME := DisplayCutoutEmulationEmu01Overlay
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_SDK_VERSION := current
-
-include $(BUILD_RRO_PACKAGE)
diff --git a/phone/overlay/frameworks/base/packages/overlays/pixel_8_pro/AndroidOverlay/res/values/config.xml b/phone/overlay/frameworks/base/packages/overlays/pixel_8_pro/AndroidOverlay/res/values/config.xml
index 7eb20d74..40efdf8f 100644
--- a/phone/overlay/frameworks/base/packages/overlays/pixel_8_pro/AndroidOverlay/res/values/config.xml
+++ b/phone/overlay/frameworks/base/packages/overlays/pixel_8_pro/AndroidOverlay/res/values/config.xml
@@ -50,19 +50,4 @@
         Z
         @left
     </string>
-
-    <!-- A string config in svg path format for the main display shape.
-         (@see https://www.w3.org/TR/SVG/paths.html#PathData).
-
-         This config must be set unless:
-         1. {@link Configuration#isScreenRound} is true which means the display shape is circular
-            and the system will auto-generate a circular shape.
-         2. The display has no rounded corner and the system will auto-generate a rectangular shape.
-         (@see DisplayShape#createDefaultDisplayShape)
-
-         Note: If the display supports multiple resolutions, please define the path config based on
-         the highest resolution so that it can be scaled correctly in each resolution.
-    -->
-    <string name="config_mainDisplayShape" translatable="false">M 119.9999 -3.7795276e-05 C 113.32402 0.34316186 102.8311 1.9200038 98.695215 2.8066029 C 73.98156 8.0987976 62.561448 13.566009 49.605371 22.5859 C 34.411306 33.163789 20.551075 49.59161 12.962793 65.706994 C 7.8660073 76.530983 2.8411097 93.439401 1.4120111 104.32809 C 0.066002501 114.58638 0.28550144 114.76397 -9.8267718e-05 119.99996 L -9.8267718e-05 2877 L 1.9803705 2891.3164 C 8.0676544 2919.9453 16.781085 2937.4625 33.785058 2955.2598 C 51.142521 2973.4268 70.876659 2983.6798 100.6835 2990.0176 L 114.9999 2992 L 1228.9999 2992 L 1243.3163 2990.0176 C 1273.1232 2983.6798 1292.8573 2973.4268 1310.2148 2955.2598 C 1327.2186 2937.4625 1335.9323 2919.9453 1342.0194 2891.3164 L 1343.9999 2877 L 1343.9999 119.99996 C 1343.7143 114.76397 1343.9338 114.58638 1342.5878 104.32809 C 1341.1587 93.439401 1336.1338 76.530983 1331.037 65.706994 C 1323.4487 49.59161 1309.5885 33.163789 1294.3944 22.5859 C 1281.4385 13.566009 1270.0183 8.0987976 1245.3046 2.8066029 C 1241.1687 1.9200038 1230.6758 0.34316186 1223.9999 -3.7795276e-05 L 119.9999 -3.7795276e-05 z</string>
-
 </resources>
diff --git a/phone/overlay/frameworks/base/packages/overlays/pixel_8a/AndroidOverlay/res/values/config.xml b/phone/overlay/frameworks/base/packages/overlays/pixel_8a/AndroidOverlay/res/values/config.xml
index 7f578925..143433a4 100644
--- a/phone/overlay/frameworks/base/packages/overlays/pixel_8a/AndroidOverlay/res/values/config.xml
+++ b/phone/overlay/frameworks/base/packages/overlays/pixel_8a/AndroidOverlay/res/values/config.xml
@@ -47,18 +47,4 @@
         @left
     </string>
 
-    <!-- A string config in svg path format for the main display shape.
-         (@see https://www.w3.org/TR/SVG/paths.html#PathData).
-
-         This config must be set unless:
-         1. {@link Configuration#isScreenRound} is true which means the display shape is circular
-            and the system will auto-generate a circular shape.
-         2. The display has no rounded corner and the system will auto-generate a rectangular shape.
-         (@see DisplayShape#createDefaultDisplayShape)
-
-         Note: If the display supports multiple resolutions, please define the path config based on
-         the highest resolution so that it can be scaled correctly in each resolution.
-    -->
-    <string name="config_mainDisplayShape" translatable="false">M 96.5,0.09 C 91.13,0.36 82.7,1.63 79.38,2.34 59.53,6.58 50.35,10.97 39.94,18.2 27.73,26.69 16.6,39.86 10.5,52.79 6.41,61.47 2.37,75.03 1.22,83.76 0.14,91.99 0.31,92.14 0.09,96.34 V 2307.68 l 1.59,11.48 c 4.89,22.96 11.89,37.01 25.55,51.29 13.95,14.57 29.8,22.8 53.75,27.88 l 11.5,1.59 H 987.52 l 11.5,-1.59 c 23.95,-5.08 39.8,-13.31 53.75,-27.88 13.66,-14.27 20.66,-28.33 25.55,-51.29 l 1.59,-11.48 V 96.34 c -0.23,-4.2 -0.05,-4.34 -1.13,-12.57 -1.15,-8.73 -5.19,-22.3 -9.28,-30.98 C 1063.4,39.86 1052.27,26.69 1040.06,18.2 1029.65,10.97 1020.47,6.58 1000.62,2.34 997.3,1.63 988.87,0.36 983.5,0.09 Z</string>
-
 </resources>
diff --git a/64bitonly/product/emulator64_vendor.mk b/product/base_phone.mk
similarity index 55%
rename from 64bitonly/product/emulator64_vendor.mk
rename to product/base_phone.mk
index c6fc83e0..0deb9fea 100644
--- a/64bitonly/product/emulator64_vendor.mk
+++ b/product/base_phone.mk
@@ -1,5 +1,5 @@
 #
-# Copyright (C) 2012 The Android Open Source Project
+# Copyright (C) 2024 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,22 +13,19 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-#
-# This file is included by other product makefiles to add all the
-# emulator-related modules to PRODUCT_PACKAGES.
-#
-
-$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
-ifneq ($(EMULATOR_DISABLE_RADIO),true)
+# the common file for phone.mk (AOSP) and gphone.mk (internal)
+$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
-endif
-
-ifeq ($(EMULATOR_DISABLE_RADIO),true)
-DEVICE_PACKAGE_OVERLAYS += device/generic/goldfish/tablet/overlay
-else
-DEVICE_PACKAGE_OVERLAYS := device/generic/goldfish/phone/overlay
-endif
 
+DEVICE_PACKAGE_OVERLAYS += device/generic/goldfish/phone/overlay
 PRODUCT_CHARACTERISTICS := emulator
 
 $(call inherit-product, device/generic/goldfish/product/generic.mk)
+
+PRODUCT_PACKAGES += GoldfishSkinConfig \
+                    GoldfishExtraFeature
+
+$(call inherit-product, device/generic/goldfish/product/phone_overlays.mk)
+
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/phone/overlay/frameworks/base/packages/overlays/GoldfishSkinConfig/readme.txt:$(TARGET_COPY_OUT_DATA)/misc/GoldfishSkinConfig \
diff --git a/product/generic.mk b/product/generic.mk
index 2c08e157..ad8507e4 100644
--- a/product/generic.mk
+++ b/product/generic.mk
@@ -22,7 +22,6 @@ $(call inherit-product-if-exists, frameworks/native/build/phone-xhdpi-2048-dalvi
 $(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)
 
 PRODUCT_SHIPPING_API_LEVEL := 35
-PRODUCT_FULL_TREBLE_OVERRIDE := true
 DEVICE_MANIFEST_FILE += device/generic/goldfish/manifest.xml
 
 PRODUCT_SOONG_NAMESPACES += \
@@ -67,7 +66,7 @@ PRODUCT_VENDOR_PROPERTIES += \
     debug.sf.vsync_reactor_ignore_present_fences=true \
     debug.stagefright.c2inputsurface=-1 \
     debug.stagefright.ccodec=4 \
-    graphics.gpu.profiler.support=true \
+    graphics.gpu.profiler.support=false \
     persist.sys.usb.config="" \
     persist.sys.zram_enabled=1 \
     wifi.direct.interface=p2p-dev-wlan0 \
@@ -104,13 +103,10 @@ ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
 PRODUCT_VENDOR_PROPERTIES += ro.hardware.gralloc=minigbm
 PRODUCT_PACKAGES += \
     android.hardware.graphics.allocator-service.minigbm \
-    android.hardware.graphics.mapper@4.0-impl.minigbm \
     mapper.minigbm
 else
 PRODUCT_VENDOR_PROPERTIES += ro.hardware.gralloc=ranchu
-PRODUCT_PACKAGES += \
-    android.hardware.graphics.allocator@3.0-service.ranchu \
-    android.hardware.graphics.mapper@3.0-impl-ranchu
+PRODUCT_PACKAGES += android.hardware.graphics.allocator-service.ranchu
 endif
 
 ifneq ($(EMULATOR_DISABLE_RADIO),true)
@@ -122,17 +118,16 @@ PRODUCT_PACKAGES += \
 
 DEVICE_MANIFEST_FILE += device/generic/goldfish/radio/manifest.radio.xml
 DISABLE_RILD_OEM_HOOK := true
+# For customize cflags for libril share library building by soong.
+$(call soong_config_set,ril,disable_rild_oem_hook,true)
 endif
 
 ifneq ($(EMULATOR_VENDOR_NO_BIOMETRICS), true)
 PRODUCT_PACKAGES += \
     android.hardware.biometrics.fingerprint-service.ranchu \
     android.hardware.biometrics.face-service.example \
-
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.hardware.fingerprint.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.fingerprint.xml \
-    frameworks/native/data/etc/android.hardware.biometrics.face.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.biometrics.face.xml \
-
+    android.hardware.fingerprint.prebuilt.xml \
+    android.hardware.biometrics.face.prebuilt.xml
 endif
 
 ifneq ($(BUILD_EMULATOR_OPENGL),false)
@@ -149,6 +144,10 @@ PRODUCT_PACKAGES += \
     libGLESv2_angle
 endif
 
+# Enable Thread Network HAL with simulation RCP
+PRODUCT_PACKAGES += \
+    com.android.hardware.threadnetwork-simulation-rcp
+
 # Enable bluetooth
 PRODUCT_PACKAGES += \
     android.hardware.bluetooth-service.default \
@@ -165,46 +164,14 @@ PRODUCT_PACKAGES += \
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.keystore.app_attest_key.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.keystore.app_attest_key.xml
 
+# Enable Uwb
 PRODUCT_PACKAGES += \
-    DisplayCutoutEmulationEmu01Overlay \
-    EmulationPixelFoldOverlay \
-    SystemUIEmulationPixelFoldOverlay \
-    EmulationPixel8ProOverlay \
-    SystemUIEmulationPixel8ProOverlay \
-    EmulationPixel8aOverlay \
-    SystemUIEmulationPixel8aOverlay \
-    EmulationPixel8Overlay \
-    SystemUIEmulationPixel8Overlay \
-    EmulationPixel7ProOverlay \
-    SystemUIEmulationPixel7ProOverlay \
-    EmulationPixel7Overlay \
-    SystemUIEmulationPixel7Overlay \
-    EmulationPixel7aOverlay \
-    SystemUIEmulationPixel7aOverlay \
-    EmulationPixel6ProOverlay \
-    SystemUIEmulationPixel6ProOverlay \
-    EmulationPixel6Overlay \
-    SystemUIEmulationPixel6Overlay \
-    EmulationPixel6aOverlay \
-    SystemUIEmulationPixel6aOverlay \
-    EmulationPixel5Overlay \
-    SystemUIEmulationPixel5Overlay \
-    EmulationPixel4XLOverlay \
-    SystemUIEmulationPixel4XLOverlay \
-    EmulationPixel4Overlay \
-    SystemUIEmulationPixel4Overlay \
-    EmulationPixel4aOverlay \
-    SystemUIEmulationPixel4aOverlay \
-    EmulationPixel3XLOverlay \
-    SystemUIEmulationPixel3XLOverlay \
-    EmulationPixel3Overlay \
-    SystemUIEmulationPixel3Overlay \
-    EmulationPixel3aOverlay \
-    SystemUIEmulationPixel3aOverlay \
-    EmulationPixel3aXLOverlay \
-    SystemUIEmulationPixel3aXLOverlay \
-    EmulationPixel2XLOverlay \
-    NavigationBarMode2ButtonOverlay \
+    com.android.hardware.uwb \
+    android.hardware.uwb-service \
+    UwbOverlay
+PRODUCT_VENDOR_PROPERTIES += ro.vendor.uwb.dev=/dev/hvc2
+PRODUCT_COPY_FILES += \
+    frameworks/native/data/etc/android.hardware.uwb.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.uwb.xml
 
 ifneq ($(EMULATOR_VENDOR_NO_GNSS),true)
 PRODUCT_PACKAGES += android.hardware.gnss-service.ranchu
@@ -231,18 +198,24 @@ PRODUCT_PACKAGES += \
     android.hardware.camera.provider.ranchu \
     android.hardware.camera.provider@2.7-service-google \
     libgooglecamerahwl_impl \
+    android.hardware.camera.flash-autofocus.prebuilt.xml \
+    android.hardware.camera.concurrent.prebuilt.xml \
+    android.hardware.camera.front.prebuilt.xml \
+    android.hardware.camera.full.prebuilt.xml \
+    android.hardware.camera.raw.prebuilt.xml \
+
+ifeq (,$(filter %_arm64,$(TARGET_PRODUCT)))  # TARGET_ARCH is not available here
+CODECS_PERFORMANCE_C2_PROFILE := codecs_performance_c2.xml
+else
+CODECS_PERFORMANCE_C2_PROFILE := codecs_performance_c2_arm64.xml
+endif
 
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/camera/media/profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml \
     device/generic/goldfish/camera/media/codecs_google_video_default.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_video.xml \
     device/generic/goldfish/camera/media/codecs.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs.xml \
     device/generic/goldfish/camera/media/codecs_performance.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance.xml \
-    device/generic/goldfish/camera/media/codecs_performance_c2.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance_c2.xml \
-    frameworks/native/data/etc/android.hardware.camera.flash-autofocus.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.flash-autofocus.xml \
-    frameworks/native/data/etc/android.hardware.camera.concurrent.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.concurrent.xml \
-    frameworks/native/data/etc/android.hardware.camera.front.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.front.xml \
-    frameworks/native/data/etc/android.hardware.camera.full.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.full.xml \
-    frameworks/native/data/etc/android.hardware.camera.raw.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.raw.xml \
+    device/generic/goldfish/camera/media/$(CODECS_PERFORMANCE_C2_PROFILE):$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance_c2.xml \
     hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_back.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_back.json \
     hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_front.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_front.json \
     hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_depth.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_depth.json \
@@ -308,6 +281,7 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/etc/apns-conf.xml:data/misc/apns/apns-conf.xml \
     device/generic/goldfish/radio/RadioConfig/radioconfig.xml:data/misc/emulator/config/radioconfig.xml \
     device/generic/goldfish/data/etc/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim0.xml \
+    device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim_tel_alaska.xml \
     device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0_for_CtsCarrierApiTestCases.xml:data/misc/modem_simulator/iccprofile_for_carrierapitests.xml \
     device/generic/goldfish/data/etc/numeric_operator.xml:data/misc/modem_simulator/etc/modem_simulator/files/numeric_operator.xml \
     device/generic/goldfish/data/etc/local.prop:data/local.prop \
diff --git a/product/phone.mk b/product/phone.mk
index 9ed092c5..c6009b63 100644
--- a/product/phone.mk
+++ b/product/phone.mk
@@ -14,15 +14,4 @@
 # limitations under the License.
 
 $(call inherit-product, device/generic/goldfish/product/handheld.mk)
-
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
-
-DEVICE_PACKAGE_OVERLAYS += device/generic/goldfish/phone/overlay
-PRODUCT_CHARACTERISTICS := emulator
-
-$(call inherit-product, device/generic/goldfish/product/generic.mk)
-
-PRODUCT_PACKAGES += GoldfishSkinConfig \
-                    GoldfishExtraFeature
-
+$(call inherit-product, device/generic/goldfish/product/base_phone.mk)
diff --git a/product/phone_overlays.mk b/product/phone_overlays.mk
new file mode 100644
index 00000000..5f2e5064
--- /dev/null
+++ b/product/phone_overlays.mk
@@ -0,0 +1,55 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+PRODUCT_PACKAGES += \
+    DisplayCutoutEmulationEmu01Overlay \
+    EmulationPixelFoldOverlay \
+    SystemUIEmulationPixelFoldOverlay \
+    EmulationPixel8ProOverlay \
+    SystemUIEmulationPixel8ProOverlay \
+    EmulationPixel8aOverlay \
+    SystemUIEmulationPixel8aOverlay \
+    EmulationPixel8Overlay \
+    SystemUIEmulationPixel8Overlay \
+    EmulationPixel7ProOverlay \
+    SystemUIEmulationPixel7ProOverlay \
+    EmulationPixel7Overlay \
+    SystemUIEmulationPixel7Overlay \
+    EmulationPixel7aOverlay \
+    SystemUIEmulationPixel7aOverlay \
+    EmulationPixel6ProOverlay \
+    SystemUIEmulationPixel6ProOverlay \
+    EmulationPixel6Overlay \
+    SystemUIEmulationPixel6Overlay \
+    EmulationPixel6aOverlay \
+    SystemUIEmulationPixel6aOverlay \
+    EmulationPixel5Overlay \
+    SystemUIEmulationPixel5Overlay \
+    EmulationPixel4XLOverlay \
+    SystemUIEmulationPixel4XLOverlay \
+    EmulationPixel4Overlay \
+    SystemUIEmulationPixel4Overlay \
+    EmulationPixel4aOverlay \
+    SystemUIEmulationPixel4aOverlay \
+    EmulationPixel3XLOverlay \
+    SystemUIEmulationPixel3XLOverlay \
+    EmulationPixel3Overlay \
+    SystemUIEmulationPixel3Overlay \
+    EmulationPixel3aOverlay \
+    SystemUIEmulationPixel3aOverlay \
+    EmulationPixel3aXLOverlay \
+    SystemUIEmulationPixel3aXLOverlay \
+    EmulationPixel2XLOverlay \
+    NavigationBarMode2ButtonOverlay \
diff --git a/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java b/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
index 8ce1fff5..23d87d63 100644
--- a/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
+++ b/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
@@ -17,6 +17,7 @@
 package com.android.emulatorprovisionlib;
 
 import android.app.Activity;
+import android.app.ActivityManager;
 import android.app.StatusBarManager;
 import android.content.ComponentName;
 import android.content.Context;
@@ -32,6 +33,8 @@ import android.os.Process;
 import android.os.RemoteException;
 import android.os.ServiceManager;
 import android.os.SystemProperties;
+import android.os.UserHandle;
+import android.os.UserManager;
 import android.telephony.TelephonyManager;
 import android.util.Log;
 import android.view.InputDevice;
@@ -40,7 +43,7 @@ import com.android.internal.widget.LockPatternUtils;
 
 public abstract class ProvisionActivity extends Activity {
     protected abstract String TAG();
-    private StatusBarManager mStatusBarManager;
+    protected StatusBarManager mStatusBarManager;
 
     @Override
     protected void onCreate(Bundle icicle) {
@@ -60,19 +63,32 @@ public abstract class ProvisionActivity extends Activity {
 
     protected void preProvivion() {
         final Context appContext = getApplicationContext();
-        mStatusBarManager = appContext.getSystemService(StatusBarManager.class);
+        if (!isVisibleBackgroundUser(appContext)) {
+            mStatusBarManager = appContext.getSystemService(StatusBarManager.class);
+        }
 
-        mStatusBarManager.setDisabledForSetup(true);
+        if (mStatusBarManager != null) {
+            mStatusBarManager.setDisabledForSetup(true);
+        }
     }
 
     protected void postProvision() {
-        mStatusBarManager.setDisabledForSetup(false);
+        if (mStatusBarManager != null) {
+            mStatusBarManager.setDisabledForSetup(false);
+        }
 
-        removeSelf();
 
         // Add a persistent setting to allow other apps to know the device has been provisioned.
         Settings.Secure.putInt(getContentResolver(), Settings.Secure.USER_SETUP_COMPLETE, 1);
         Settings.Global.putInt(getContentResolver(), Settings.Global.DEVICE_PROVISIONED, 1);
+        final boolean isDeviceProvisioned = (Settings.Global.getInt(getContentResolver(),
+                Settings.Global.DEVICE_PROVISIONED, 0) == 1);
+        if (isDeviceProvisioned) {
+            Log.i(TAG(), "Successfully set device_provisioned to 1");
+        } else {
+            Log.e(TAG(), "Unable to set device_provisioned to 1");
+        }
+        removeSelf();
     }
 
     // remove this activity from the package manager.
@@ -234,11 +250,17 @@ public abstract class ProvisionActivity extends Activity {
     }
 
     protected boolean provisionRequired() {
-        return (Settings.Global.getInt(getContentResolver(),
-                Settings.Global.DEVICE_PROVISIONED, 0) != 1) || forceProvision();
+        return true;
     }
 
-    protected boolean forceProvision() {
-        return SystemProperties.get("ro.automotive_emulator.provisioning", "").equals("SdkSetup");
+    protected boolean isVisibleBackgroundUser(Context context) {
+        if (!UserManager.isVisibleBackgroundUsersEnabled()) {
+            return false;
+        }
+        UserHandle user = context.getUser();
+        if (user.isSystem() || user.getIdentifier() == ActivityManager.getCurrentUser()) {
+            return false;
+        }
+        return true;
     }
 }
diff --git a/provision/SdkSetup/AndroidManifest.xml b/provision/SdkSetup/AndroidManifest.xml
index 5458baa3..c047c358 100644
--- a/provision/SdkSetup/AndroidManifest.xml
+++ b/provision/SdkSetup/AndroidManifest.xml
@@ -35,6 +35,7 @@
         <activity android:name="DefaultActivity"
                 android:excludeFromRecents="true"
                 android:exported="True"
+                android:directBootAware="true"
                 android:launchMode="singleTask">
             <intent-filter android:priority="3">
                 <action android:name="android.intent.action.MAIN" />
diff --git a/qemu-props/qemu-props.cpp b/qemu-props/qemu-props.cpp
index c79a2284..c375b3a1 100644
--- a/qemu-props/qemu-props.cpp
+++ b/qemu-props/qemu-props.cpp
@@ -22,15 +22,17 @@
  * /system/etc/init.ranchu.rc exclusively.
  */
 
-#include <string_view>
+#include <android-base/properties.h>
 #include <android-base/unique_fd.h>
 #include <cutils/properties.h>
-#include <unistd.h>
+#include <debug.h>
 #include <qemu_pipe_bp.h>
 #include <qemud.h>
-#include <string.h>
 #include <stdio.h>
-#include <debug.h>
+#include <string.h>
+#include <unistd.h>
+
+#include <string_view>
 
 namespace {
 constexpr char kBootPropertiesService[] = "boot-properties";
@@ -157,13 +159,12 @@ int main(const int argc, const char* argv[])
 
     sendHeartBeat();
     while (s_QemuMiscPipe >= 0) {
-        usleep(5000000); /* 5 seconds */
-        sendHeartBeat();
-        char temp[PROPERTY_VALUE_MAX];
-        property_get("vendor.qemu.dev.bootcomplete", temp, "");
-        if (strcmp(temp, "1") == 0) {
+        if (android::base::WaitForProperty(
+                    "vendor.qemu.dev.bootcomplete", "1",
+                    /*relative_timeout=*/std::chrono::seconds(5))) {
             break;
         }
+        sendHeartBeat();
     }
 
     while (s_QemuMiscPipe >= 0) {
diff --git a/radio/rild/Android.bp b/radio/rild/Android.bp
new file mode 100644
index 00000000..07348fdb
--- /dev/null
+++ b/radio/rild/Android.bp
@@ -0,0 +1,44 @@
+// Copyright (C) 2006 The Android Open Source Project
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
+        "Android-Apache-2.0",
+    ],
+}
+
+cc_binary {
+    name: "libgoldfish-rild",
+    cflags: [
+        "-DPRODUCT_COMPATIBLE_PROPERTY",
+        "-DRIL_SHLIB",
+        "-Wall",
+        "-Wextra",
+        "-Werror",
+    ],
+    srcs: ["rild_goldfish.c"],
+    shared_libs: [
+        "libcutils",
+        "libdl",
+        "liblog",
+        "libril-modem-lib",
+    ],
+    // Temporary hack for broken vendor RILs.
+    whole_static_libs: ["librilutils-goldfish-fork"],
+    relative_install_path: "hw",
+    proprietary: true,
+    overrides: ["rild"],
+    init_rc: ["rild_goldfish.rc"],
+}
diff --git a/radio/rild/Android.mk b/radio/rild/Android.mk
deleted file mode 100644
index efad10f8..00000000
--- a/radio/rild/Android.mk
+++ /dev/null
@@ -1,50 +0,0 @@
-# Copyright 2006 The Android Open Source Project
-
-ifndef EMULATOR_DISABLE_RADIO
-
-ifndef ENABLE_VENDOR_RIL_SERVICE
-
-LOCAL_PATH:= $(call my-dir)
-include $(CLEAR_VARS)
-
-LOCAL_SRC_FILES:= \
-	rild_goldfish.c
-
-LOCAL_SHARED_LIBRARIES := \
-	libcutils \
-	libdl \
-	liblog \
-	libril-modem-lib
-
-# Temporary hack for broken vendor RILs.
-LOCAL_WHOLE_STATIC_LIBRARIES := \
-	librilutils-goldfish-fork
-
-LOCAL_CFLAGS := -DRIL_SHLIB
-LOCAL_CFLAGS += -Wall -Wextra -Werror
-
-ifeq ($(SIM_COUNT), 2)
-    LOCAL_CFLAGS += -DANDROID_MULTI_SIM
-    LOCAL_CFLAGS += -DANDROID_SIM_COUNT_2
-endif
-
-LOCAL_MODULE_RELATIVE_PATH := hw
-LOCAL_PROPRIETARY_MODULE := true
-#LOCAL_MODULE:= rild
-LOCAL_MODULE:= libgoldfish-rild
-LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS:= notice
-LOCAL_NOTICE_FILE:= $(LOCAL_PATH)/NOTICE
-LOCAL_OVERRIDES_PACKAGES := rild
-PACKAGES.$(LOCAL_MODULE).OVERRIDES := rild
-ifeq ($(PRODUCT_COMPATIBLE_PROPERTY),true)
-LOCAL_INIT_RC := rild_goldfish.rc
-LOCAL_CFLAGS += -DPRODUCT_COMPATIBLE_PROPERTY
-else
-LOCAL_INIT_RC := rild_goldfish.legacy.rc
-endif
-
-include $(BUILD_EXECUTABLE)
-
-endif
-endif
diff --git a/radio/rild/rild_goldfish.rc b/radio/rild/rild_goldfish.rc
index 3203b413..c88e7f84 100644
--- a/radio/rild/rild_goldfish.rc
+++ b/radio/rild/rild_goldfish.rc
@@ -3,3 +3,4 @@ service vendor.ril-daemon /vendor/bin/hw/libgoldfish-rild
     user radio
     group radio cache inet misc audio log readproc wakelock
     capabilities BLOCK_SUSPEND NET_ADMIN NET_RAW
+    disabled
diff --git a/sensors/multihal_sensors.cpp b/sensors/multihal_sensors.cpp
index 829c501c..1a9828ad 100644
--- a/sensors/multihal_sensors.cpp
+++ b/sensors/multihal_sensors.cpp
@@ -42,12 +42,12 @@ struct SensorsTransportStub : public SensorsTransport {
 // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/sensors/aidl/android/hardware/sensors/SensorInfo.aidl#146
 // 3 bits starting from the 1st: MMMx
 uint32_t getSensorReportingMode(const uint32_t sensorFlagBits) {
-    return sensorFlagBits & (7U << 1);
+    return sensorFlagBits & (3U << 1);
 }
 
-bool isOnChangeSensor(const uint32_t sensorFlagBits) {
+bool isContiniousReportingSensor(const uint32_t sensorFlagBits) {
     return getSensorReportingMode(sensorFlagBits) ==
-        static_cast<uint32_t>(SensorFlagBits::ON_CHANGE_MODE);
+        static_cast<uint32_t>(SensorFlagBits::CONTINUOUS_MODE);
 }
 
 const SensorsTransportStub g_sensorsTransportStub;
@@ -151,10 +151,7 @@ Return<Result> MultihalSensors::activate(const int32_t sensorHandle,
     if (enabled) {
         const SensorInfo* sensor = getSensorInfoByHandle(sensorHandle);
         LOG_ALWAYS_FATAL_IF(!sensor);
-        if (isOnChangeSensor(sensor->flags)) {
-            doPostSensorEventLocked(*sensor,
-                                    activationOnChangeSensorEvent(sensorHandle, *sensor));
-        } else {
+        if (isContiniousReportingSensor(sensor->flags)) {
             if (batchInfo.samplingPeriodNs <= 0) {
                 return Result::BAD_VALUE;
             }
@@ -167,6 +164,9 @@ Return<Result> MultihalSensors::activate(const int32_t sensorHandle,
 
             m_batchQueue.push(batchEventRef);
             m_batchUpdated.notify_one();
+        } else {
+            doPostSensorEventLocked(*sensor,
+                                    activationOnChangeSensorEvent(sensorHandle, *sensor));
         }
         sendAdditionalInfoReport(sensorHandle);
         m_activeSensorsMask = m_activeSensorsMask | (1u << sensorHandle);
diff --git a/sepolicy/vendor/dumpstate.te b/sepolicy/vendor/dumpstate.te
index e7ef3d98..e7c1b5ff 100644
--- a/sepolicy/vendor/dumpstate.te
+++ b/sepolicy/vendor/dumpstate.te
@@ -6,7 +6,6 @@ allow dumpstate mnt_media_rw_file:dir { getattr open read };
 dontaudit dumpstate kernel:system module_request;
 
 dontaudit dumpstate device:file { open write };
-allow dumpstate nsfs:file getattr;
 dontaudit dumpstate varrun_file:dir search;
 allow dumpstate vold:binder call;
 dontaudit dumpstate apexd:binder call;
diff --git a/sepolicy/vendor/file.te b/sepolicy/vendor/file.te
index 6df2ef48..8c505a87 100644
--- a/sepolicy/vendor/file.te
+++ b/sepolicy/vendor/file.te
@@ -3,4 +3,3 @@ type sysfs_writable, fs_type, sysfs_type, mlstrustedobject;
 type sysfs_virtio_block, sysfs_type, fs_type;
 type varrun_file, file_type, data_file_type, mlstrustedobject;
 type mediadrm_vendor_data_file, file_type, data_file_type;
-type nsfs, fs_type;
diff --git a/sepolicy/vendor/file_contexts b/sepolicy/vendor/file_contexts
index de32b8f9..c3860980 100644
--- a/sepolicy/vendor/file_contexts
+++ b/sepolicy/vendor/file_contexts
@@ -42,7 +42,7 @@
 /vendor/bin/hw/libgoldfish-rild               u:object_r:rild_exec:s0
 /vendor/bin/dhcpclient       u:object_r:dhcpclient_exec:s0
 /vendor/bin/bt_vhci_forwarder  u:object_r:bt_vhci_forwarder_exec:s0
-/vendor/bin/hw/android\.hardware\.graphics\.allocator@3\.0-service\.ranchu u:object_r:hal_graphics_allocator_default_exec:s0
+/vendor/bin/hw/android\.hardware\.graphics\.allocator-service\.ranchu u:object_r:hal_graphics_allocator_default_exec:s0
 /vendor/bin/hw/android\.hardware\.drm-service\.widevine    u:object_r:hal_drm_widevine_exec:s0
 /vendor/bin/hw/android\.hardware\.drm-service-lazy\.widevine    u:object_r:hal_drm_widevine_exec:s0
 /vendor/bin/hw/android\.hardware\.drm-service\.clearkey          u:object_r:hal_drm_clearkey_exec:s0
@@ -69,11 +69,10 @@
 /vendor/lib(64)?/libvulkan_enc\.so       u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/libandroidemu\.so       u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/libdrm.so  u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/hw/android\.hardware\.graphics\.mapper@3\.0-impl-ranchu\.so   u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/libGoldfishProfiler\.so       u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/dri/.* u:object_r:same_process_hal_file:s0
-/vendor/lib(64)?/hw/android\.hardware\.graphics\.mapper@4\.0-impl\.minigbm\.so u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/hw/mapper\.minigbm\.so u:object_r:same_process_hal_file:s0
+/vendor/lib(64)?/hw/mapper\.ranchu\.so  u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/libminigbm_gralloc.so  u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/libminigbm_gralloc4_utils.so  u:object_r:same_process_hal_file:s0
 /vendor/bin/hw/android\.hardware\.graphics\.allocator-service\.minigbm   u:object_r:hal_graphics_allocator_default_exec:s0
diff --git a/sepolicy/vendor/genfs_contexts b/sepolicy/vendor/genfs_contexts
index 2c7885cd..ceece555 100644
--- a/sepolicy/vendor/genfs_contexts
+++ b/sepolicy/vendor/genfs_contexts
@@ -146,6 +146,3 @@ genfscon sysfs /devices/platform/rtc-test.2/wakeup/wakeup40
 genfscon sysfs /devices/platform/rtc-test.2/wakeup/wakeup40/event_count            u:object_r:sysfs_wakeup:s0
 
 genfscon sysfs /bus/iio/devices                                                    u:object_r:sysfs_iio_devices:s0
-
-# /proc/<pid>/ns
-genfscon nsfs / u:object_r:nsfs:s0
diff --git a/sepolicy/vendor/goldfish_setup.te b/sepolicy/vendor/goldfish_setup.te
index 5ae62ba3..8c071753 100644
--- a/sepolicy/vendor/goldfish_setup.te
+++ b/sepolicy/vendor/goldfish_setup.te
@@ -25,7 +25,6 @@ allow goldfish_setup self:netlink_generic_socket create_socket_perms_no_ioctl;
 allow goldfish_setup self:capability { sys_module sys_admin };
 allow goldfish_setup proc_net:file rw_file_perms;
 allow goldfish_setup proc:file r_file_perms;
-allow goldfish_setup nsfs:file r_file_perms;
 allow goldfish_setup system_data_file:dir getattr;
 set_prop(goldfish_setup, vendor_qemu_prop);
 get_prop(goldfish_setup, vendor_net_share_prop);
diff --git a/sepolicy/vendor/service_contexts b/sepolicy/vendor/service_contexts
index 3f0d3632..d15d9f9b 100644
--- a/sepolicy/vendor/service_contexts
+++ b/sepolicy/vendor/service_contexts
@@ -3,3 +3,6 @@ android.hardware.camera.provider.ICameraProvider/internal/1 u:object_r:hal_camer
 android.hardware.neuralnetworks.IDevice/nnapi-sample_all u:object_r:hal_neuralnetworks_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_quant    u:object_r:hal_neuralnetworks_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_sl_shim  u:object_r:hal_neuralnetworks_service:s0
+# see https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/mapper/stable-c
+mapper/minigbm u:object_r:hal_graphics_mapper_service:s0
+mapper/ranchu u:object_r:hal_graphics_mapper_service:s0
diff --git a/sepolicy/vendor/vold.te b/sepolicy/vendor/vold.te
index 3ab24e68..590338d4 100644
--- a/sepolicy/vendor/vold.te
+++ b/sepolicy/vendor/vold.te
@@ -1,3 +1,2 @@
 allow vold sysfs_devices_block:file w_file_perms;
 allow vold sysfs_virtio_block:file w_file_perms;
-allow vold nsfs:file r_file_perms;
diff --git a/tasks/emu_img_zip.mk b/tasks/emu_img_zip.mk
index ddf1b43c..99eadd6b 100644
--- a/tasks/emu_img_zip.mk
+++ b/tasks/emu_img_zip.mk
@@ -1,116 +1,109 @@
 # Rules to generate a zip file that contains google emulator images
 # and other files for distribution
 
-ifeq ($(filter $(TARGET_PRODUCT), qemu_trusty_arm64),)
-ifeq ($(filter $(MAKECMDGOALS), sdk win_sdk sdk_repo goog_emu_imgs),)
-emulator_img_source_prop := $(TARGET_OUT_INTERMEDIATES)/source.properties
+ifneq ($(filter sdk_% gcar_%, $(TARGET_PRODUCT)),)
 target_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE.txt
+
+emulator_img_source_prop := $(TARGET_OUT_INTERMEDIATES)/source.properties
 $(emulator_img_source_prop): $(PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP)
 	$(process_prop_template)
 
+ifeq ($(TARGET_ARCH), x86)
+# a 32bit guest on a 64bit kernel
+EMULATOR_KERNEL_DIST_NAME := kernel-ranchu-64
+else
+EMULATOR_KERNEL_DIST_NAME := kernel-ranchu
+endif # x86
+
 INTERNAL_EMULATOR_PACKAGE_FILES := \
-        $(target_notice_file_txt) \
-        $(emulator_img_source_prop) \
-        $(PRODUCT_OUT)/system/build.prop \
+	$(target_notice_file_txt) \
+	$(emulator_img_source_prop) \
+	$(PRODUCT_OUT)/system/build.prop \
+	$(PRODUCT_OUT)/VerifiedBootParams.textproto \
+	$(PRODUCT_OUT)/advancedFeatures.ini \
+	$(PRODUCT_OUT)/$(EMULATOR_KERNEL_DIST_NAME) \
+	$(PRODUCT_OUT)/kernel_cmdline.txt \
+	$(PRODUCT_OUT)/encryptionkey.img \
 
 ifneq ($(filter $(TARGET_PRODUCT), sdk_goog3_x86 sdk_goog3_x86_64 sdk_goog3_x86_arm),)
-    INTERNAL_EMULATOR_PACKAGE_FILES += \
-        $(HOST_OUT_EXECUTABLES)/dex2oat \
-        $(HOST_OUT_EXECUTABLES)/dex2oatd
+INTERNAL_EMULATOR_PACKAGE_FILES += \
+	$(HOST_OUT_EXECUTABLES)/dex2oat \
+	$(HOST_OUT_EXECUTABLES)/dex2oatd
 endif
 
-ifeq ($(BUILD_QEMU_IMAGES),true)
-ifeq ($(BOARD_AVB_ENABLE),true)
+ifneq ($(filter $(PRODUCT_DEVICE), emulator_car64_arm64 emulator_car64_x86_64),)
 INTERNAL_EMULATOR_PACKAGE_FILES += \
-        $(PRODUCT_OUT)/VerifiedBootParams.textproto
-endif
+	hardware/interfaces/automotive/vehicle/aidl/emu_metadata/android.hardware.automotive.vehicle-types-meta.json
 endif
 
 INTERNAL_EMULATOR_PACKAGE_SOURCE := $(PRODUCT_OUT)/emulator
+INTERNAL_EMULATOR_PACKAGE_SOURCE_DST := $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)
+INTERNAL_EMULATOR_PACKAGE_TARGET := $(PRODUCT_OUT)/sdk-repo-linux-system-images.zip
 
 INSTALLED_QEMU_SYSTEMIMAGE := $(PRODUCT_OUT)/system-qemu.img
-FINAL_INSTALLED_QEMU_SYSTEMIMAGE := $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)/system.img
-$(eval $(call copy-one-file,$(INSTALLED_QEMU_SYSTEMIMAGE),$(FINAL_INSTALLED_QEMU_SYSTEMIMAGE)))
-
 INSTALLED_QEMU_RAMDISKIMAGE := $(PRODUCT_OUT)/ramdisk-qemu.img
-FINAL_INSTALLED_QEMU_RAMDISKIMAGE := $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)/ramdisk.img
-$(eval $(call copy-one-file,$(INSTALLED_QEMU_RAMDISKIMAGE),$(FINAL_INSTALLED_QEMU_RAMDISKIMAGE)))
-
 INSTALLED_QEMU_VENDORIMAGE := $(PRODUCT_OUT)/vendor-qemu.img
-FINAL_INSTALLED_QEMU_VENDORIMAGE := $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)/vendor.img
-$(eval $(call copy-one-file,$(INSTALLED_QEMU_VENDORIMAGE),$(FINAL_INSTALLED_QEMU_VENDORIMAGE)))
-
 
-INTERNAL_EMULATOR_PACKAGE_FILES += device/generic/goldfish/data/etc/encryptionkey.img
+PRODUCT_OUT_DATA_FILES := $(PRODUCT_OUT)/userdata.img # also builds $(PRODUCT_OUT)/data
 
-ADVANCED_FEATURES_FILENAME := advancedFeatures.ini
-ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
-ADVANCED_FEATURES_FILENAME := advancedFeatures.ini.minigbm
-endif
-
-# Experimental Feature (Uwb | b/237088064)
-ifneq ($(filter %_uwb, $(TARGET_PRODUCT)),)
-ADVANCED_FEATURES_FILENAME := advancedFeatures.ini.uwb
-endif
-
-ifneq ($(filter sdk_tablet% sdk_gtablet%, $(TARGET_PRODUCT)),)
-ADVANCED_FEATURES_FILENAME := advancedFeatures.ini.tablet
-endif
+INTERNAL_EMULATOR_PACKAGE_TARGET_DEPENDENCIES := \
+	$(INTERNAL_EMULATOR_PACKAGE_FILES) \
+	$(INSTALLED_QEMU_SYSTEMIMAGE) \
+	$(INSTALLED_QEMU_RAMDISKIMAGE) \
+	$(INSTALLED_QEMU_VENDORIMAGE) \
+	$(PRODUCT_OUT_DATA_FILES) \
+	$(ACP) $(SOONG_ZIP) \
 
-ADVANCED_FEATURES_FILES :=
-ifeq ($(TARGET_BUILD_VARIANT),user)
-ADVANCED_FEATURES_FILES += device/generic/goldfish/data/etc/google/user/$(ADVANCED_FEATURES_FILENAME)
-else
-ADVANCED_FEATURES_FILES += device/generic/goldfish/data/etc/google/userdebug/$(ADVANCED_FEATURES_FILENAME)
-endif
+$(INTERNAL_EMULATOR_PACKAGE_TARGET): $(INTERNAL_EMULATOR_PACKAGE_TARGET_DEPENDENCIES)
+	@echo "Package: $@"
+	$(hide) rm -rf $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)
+	$(hide) mkdir -p $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)
+	$(hide) $(foreach f,$(INTERNAL_EMULATOR_PACKAGE_FILES), $(ACP) $(f) $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)/$(notdir $(f));)
+	$(hide) $(ACP) -r $(INSTALLED_QEMU_SYSTEMIMAGE) $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)/system.img
+	$(hide) $(ACP) -r $(INSTALLED_QEMU_RAMDISKIMAGE) $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)/ramdisk.img
+	$(hide) $(ACP) -r $(INSTALLED_QEMU_VENDORIMAGE) $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)/vendor.img
+	$(hide) $(ACP) -r $(PRODUCT_OUT)/data $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)
+	$(hide) $(SOONG_ZIP) -o $@ -C $(INTERNAL_EMULATOR_PACKAGE_SOURCE) -D $(INTERNAL_EMULATOR_PACKAGE_SOURCE_DST)
 
-ifneq ($(filter $(PRODUCT_DEVICE), emulator_car64_arm64 emulator_car64_x86_64),)
-INTERNAL_EMULATOR_PACKAGE_FILES += hardware/interfaces/automotive/vehicle/aidl/emu_metadata/android.hardware.automotive.vehicle-types-meta.json
-endif
+.PHONY: emu_img_zip
+emu_img_zip: $(INTERNAL_EMULATOR_PACKAGE_TARGET)
 
-name := sdk-repo-linux-system-images
+# TODO(b/361152997): replace goog_emu_imgs with emu_img_zip and retire this target
+.PHONY: goog_emu_imgs
+goog_emu_imgs: emu_img_zip
 
+# The following rules generate emu_extra_imgs package. It is similar to
+# emu_img_zip, but it does not contain system-qemu.img and vendor-qemu.img. It
+# conatins the necessary data to build the qemu images. The package can be
+# mixed with generic system, kernel, and system_dlkm images.
+EMU_EXTRA_FILES := \
+	$(INTERNAL_EMULATOR_PACKAGE_FILES) \
+	$(INSTALLED_QEMU_RAMDISKIMAGE) \
+	$(PRODUCT_OUT)/system-qemu-config.txt \
+	$(PRODUCT_OUT)/misc_info.txt \
+	$(PRODUCT_OUT)/vbmeta.img \
+	$(foreach p,$(BOARD_SUPER_PARTITION_PARTITION_LIST),$(PRODUCT_OUT)/$(p).img)
 
-INTERNAL_EMULATOR_PACKAGE_TARGET := $(PRODUCT_OUT)/$(name).zip
+EMU_EXTRA_TARGET_DEPENDENCIES := \
+	$(EMU_EXTRA_FILES) \
+	$(PRODUCT_OUT_DATA_FILES)
 
-ifeq ($(TARGET_ARCH), arm)
-# This is wrong and should be retired.
-EMULATOR_KERNEL_FILE := prebuilts/qemu-kernel/arm/3.18/kernel-qemu2
-EMULATOR_KERNEL_DIST_NAME := kernel-ranchu
-else
-ifeq ($(TARGET_ARCH), x86)
-# Use 64-bit kernel even for 32-bit Android
-EMULATOR_KERNEL_DIST_NAME := kernel-ranchu-64
-else
-# All other arches are 64-bit
-EMULATOR_KERNEL_DIST_NAME := kernel-ranchu
-endif # x86
-endif # arm
+EMU_EXTRA_TARGET := $(PRODUCT_OUT)/emu-extra-linux-system-images.zip
 
-$(INTERNAL_EMULATOR_PACKAGE_TARGET): $(INTERNAL_EMULATOR_PACKAGE_FILES) $(FINAL_INSTALLED_QEMU_SYSTEMIMAGE) $(FINAL_INSTALLED_QEMU_RAMDISKIMAGE) $(FINAL_INSTALLED_QEMU_VENDORIMAGE) $(EMULATOR_KERNEL_FILE) $(ADVANCED_FEATURES_FILES)
-	@echo "Package: $@"
-	$(hide) mkdir -p $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)
-	$(hide) $(foreach f,$(INTERNAL_EMULATOR_PACKAGE_FILES), $(ACP) $(f) $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)/$(notdir $(f));)
-	$(hide) $(foreach f,$(ADVANCED_FEATURES_FILES), $(ACP) $(f) $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)/advancedFeatures.ini;)
-	$(hide) ($(ACP) $(EMULATOR_KERNEL_FILE) $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)/${EMULATOR_KERNEL_DIST_NAME})
-	$(hide) $(ACP) -r $(PRODUCT_OUT)/data $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)
-	$(hide) $(SOONG_ZIP) -o $@ -C $(INTERNAL_EMULATOR_PACKAGE_SOURCE) -D $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/$(TARGET_CPU_ABI)
+$(EMU_EXTRA_TARGET): PRIVATE_PACKAGE_SRC := \
+	$(call intermediates-dir-for, PACKAGING, emu_extra_target)
 
-.PHONY: emu_img_zip
-emu_img_zip: $(INTERNAL_EMULATOR_PACKAGE_TARGET)
-
-INTERNAL_EMULATOR_KERNEL_TARGET := $(PRODUCT_OUT)/emu-gki-$(TARGET_KERNEL_USE).zip
-INTERNAL_GKI_SOURCE := $(INTERNAL_EMULATOR_PACKAGE_SOURCE)/GKI-$(TARGET_KERNEL_USE)
-$(INTERNAL_EMULATOR_KERNEL_TARGET): $(INSTALLED_QEMU_RAMDISKIMAGE) $(EMULATOR_KERNEL_FILE)
+$(EMU_EXTRA_TARGET): $(EMU_EXTRA_TARGET_DEPENDENCIES) $(SOONG_ZIP)
 	@echo "Package: $@"
-	$(hide) mkdir -p $(INTERNAL_GKI_SOURCE)
-	$(hide) ($(ACP) $(EMULATOR_KERNEL_FILE) $(INTERNAL_GKI_SOURCE)/${EMULATOR_KERNEL_DIST_NAME})
-	$(hide) ($(ACP) $(INSTALLED_QEMU_RAMDISKIMAGE) $(INTERNAL_GKI_SOURCE)/ramdisk.img)
-	$(hide) $(SOONG_ZIP) -o $@ -C $(INTERNAL_GKI_SOURCE) -D $(INTERNAL_GKI_SOURCE)
+	$(hide) rm -rf $@ $(PRIVATE_PACKAGE_SRC)
+	$(hide) mkdir -p $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/system
+	$(hide) $(ACP) $(PRODUCT_OUT)/system/build.prop $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/system
+	$(hide) $(foreach f,$(EMU_EXTRA_FILES), $(ACP) $(f) $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/$(notdir $(f)) &&) true
+	$(hide) $(ACP) -r $(PRODUCT_OUT)/data $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)
+	$(SOONG_ZIP) -o $@ -C $(PRIVATE_PACKAGE_SRC) -D $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)
 
-.PHONY: emu_kernel_zip
-emu_kernel_zip: $(INTERNAL_EMULATOR_KERNEL_TARGET)
+.PHONY: emu_extra_imgs
+emu_extra_imgs: $(EMU_EXTRA_TARGET)
 
-$(call dist-for-goals-with-filenametag, emu_kernel_zip, $(INTERNAL_EMULATOR_KERNEL_TARGET))
-endif
+$(call dist-for-goals-with-filenametag, emu_extra_imgs, $(EMU_EXTRA_TARGET))
 endif
diff --git a/tools/Android.mk b/tools/Android.mk
deleted file mode 100644
index dddf7a5c..00000000
--- a/tools/Android.mk
+++ /dev/null
@@ -1,90 +0,0 @@
-#
-# Copyright 2019 The Android Open-Source Project
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
-ifneq ($(filter emulator_% emulator64_% emu64%, $(TARGET_DEVICE)),)
-LOCAL_PATH:= $(call my-dir)
-
-include $(CLEAR_VARS)
-EMU_EXTRA_FILES := \
-        $(PRODUCT_OUT)/system-qemu-config.txt \
-        $(PRODUCT_OUT)/ramdisk-qemu.img \
-        $(PRODUCT_OUT)/misc_info.txt \
-        $(PRODUCT_OUT)/vbmeta.img \
-        $(PRODUCT_OUT)/VerifiedBootParams.textproto \
-        $(foreach p,$(BOARD_SUPER_PARTITION_PARTITION_LIST),$(PRODUCT_OUT)/$(p).img)
-
-ADVANCED_FEATURES_FILENAME := advancedFeatures.ini
-ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
-ADVANCED_FEATURES_FILENAME := advancedFeatures.ini.minigbm
-ADVANCED_FEATURES_FILES :=
-
-endif
-ifeq ($(filter sdk_gphone_%, $(TARGET_PRODUCT)),)
-ifeq ($(TARGET_BUILD_VARIANT),user)
-ADVANCED_FEATURES_FILES += device/generic/goldfish/data/etc/user/$(ADVANCED_FEATURES_FILENAME)
-else
-ADVANCED_FEATURES_FILES += device/generic/goldfish/data/etc/$(ADVANCED_FEATURES_FILENAME)
-endif
-else
-ifeq ($(TARGET_BUILD_VARIANT),user)
-ADVANCED_FEATURES_FILES += device/generic/goldfish/data/etc/google/user/$(ADVANCED_FEATURES_FILENAME)
-else
-ADVANCED_FEATURES_FILES += device/generic/goldfish/data/etc/google/userdebug/$(ADVANCED_FEATURES_FILENAME)
-endif
-endif
-
-EMU_EXTRA_FILES += device/generic/goldfish/data/etc/config.ini
-EMU_EXTRA_FILES += device/generic/goldfish/data/etc/encryptionkey.img
-
-name := emu-extra-linux-system-images
-
-EMU_EXTRA_TARGET := $(PRODUCT_OUT)/$(name).zip
-
-ifeq ($(TARGET_ARCH), arm)
-# This is wrong and should be retired.
-EMULATOR_KERNEL_FILE := prebuilts/qemu-kernel/arm/3.18/kernel-qemu2
-EMULATOR_KERNEL_DIST_NAME := kernel-ranchu
-else
-ifeq ($(TARGET_ARCH), x86)
-# Use 64-bit kernel even for 32-bit Android
-EMULATOR_KERNEL_DIST_NAME := kernel-ranchu-64
-else
-# All other arches are 64-bit
-EMULATOR_KERNEL_DIST_NAME := kernel-ranchu
-endif # x86
-endif # arm
-
-$(EMU_EXTRA_TARGET): PRIVATE_PACKAGE_SRC := \
-        $(call intermediates-dir-for, PACKAGING, emu_extra_target)
-
-$(EMU_EXTRA_TARGET): $(EMU_EXTRA_FILES) $(ADVANCED_FEATURES_FILES) $(EMULATOR_KERNEL_FILE) $(SOONG_ZIP)
-	@echo "Package: $@"
-	rm -rf $@ $(PRIVATE_PACKAGE_SRC)
-	mkdir -p $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/system
-	$(foreach f,$(EMU_EXTRA_FILES), cp $(f) $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/$(notdir $(f)) &&) true
-	$(foreach f,$(ADVANCED_FEATURES_FILES), cp $(f) $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/advancedFeatures.ini &&) true
-	cp $(EMULATOR_KERNEL_FILE) $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/${EMULATOR_KERNEL_DIST_NAME}
-	cp -r $(PRODUCT_OUT)/data $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)
-	cp $(PRODUCT_OUT)/system/build.prop $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)/system
-	$(SOONG_ZIP) -o $@ -C $(PRIVATE_PACKAGE_SRC) -D $(PRIVATE_PACKAGE_SRC)/$(TARGET_ARCH)
-
-.PHONY: emu_extra_imgs
-emu_extra_imgs: $(EMU_EXTRA_TARGET)
-
-$(call dist-for-goals-with-filenametag, emu_extra_imgs, $(EMU_EXTRA_TARGET))
-
-include $(call all-makefiles-under,$(LOCAL_PATH))
-endif
```

