```diff
diff --git a/64bitonly/product/tablet_images_x86_64_source.prop_template b/64bitonly/product/phone_source.prop_template
similarity index 54%
rename from 64bitonly/product/tablet_images_x86_64_source.prop_template
rename to 64bitonly/product/phone_source.prop_template
index 722d0855..87aaf603 100644
--- a/64bitonly/product/tablet_images_x86_64_source.prop_template
+++ b/64bitonly/product/phone_source.prop_template
@@ -1,12 +1,12 @@
-Pkg.Desc=Tablet Android SDK System Image
+Pkg.Desc=Android SDK System Image
 Pkg.UserSrc=false
-Pkg.Revision=1
-Pkg.Dependencies=emulator#29.1.11
+Pkg.Revision=2
+Pkg.Dependencies=emulator#${EMULATOR_MINIMAL_VERSION}
 AndroidVersion.ApiLevel=${PLATFORM_SDK_VERSION}
 AndroidVersion.CodeName=${PLATFORM_VERSION_CODENAME}
 AndroidVersion.ExtensionLevel=${PLATFORM_SDK_EXTENSION_VERSION}
 AndroidVersion.IsBaseSdk=${PLATFORM_IS_BASE_SDK}
-SystemImage.Abi=x86_64
+SystemImage.Abi=${TARGET_CPU_ABI}
 SystemImage.GpuSupport=true
-SystemImage.TagId=aosp_tablet
-SystemImage.TagDisplay=Tablet Default Android System Image
+SystemImage.TagId=default
+SystemImage.TagDisplay=Default Android System Image
diff --git a/64bitonly/product/sdk_phone16k_arm64.mk b/64bitonly/product/sdk_phone16k_arm64.mk
index ee7a4933..aaeeed86 100644
--- a/64bitonly/product/sdk_phone16k_arm64.mk
+++ b/64bitonly/product/sdk_phone16k_arm64.mk
@@ -28,7 +28,7 @@ BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_S
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    development/sys-img/images_arm64-v8a_source.prop_template
+    device/generic/goldfish/64bitonly/product/phone_source.prop_template
 
 $(call inherit-product, device/generic/goldfish/board/emu64a16k/details.mk)
 $(call inherit-product, device/generic/goldfish/product/phone.mk)
diff --git a/64bitonly/product/sdk_phone16k_x86_64.mk b/64bitonly/product/sdk_phone16k_x86_64.mk
index 7d061136..0721f054 100644
--- a/64bitonly/product/sdk_phone16k_x86_64.mk
+++ b/64bitonly/product/sdk_phone16k_x86_64.mk
@@ -29,7 +29,7 @@ PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 endif
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    development/sys-img/images_x86_64_source.prop_template
+    device/generic/goldfish/64bitonly/product/phone_source.prop_template
 
 $(call inherit-product, device/generic/goldfish/board/emu64x16k/details.mk)
 $(call inherit-product, device/generic/goldfish/product/phone.mk)
diff --git a/64bitonly/product/sdk_phone64_arm64.mk b/64bitonly/product/sdk_phone64_arm64.mk
index 085a8779..9e68651e 100644
--- a/64bitonly/product/sdk_phone64_arm64.mk
+++ b/64bitonly/product/sdk_phone64_arm64.mk
@@ -28,7 +28,7 @@ BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_S
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    development/sys-img/images_arm64-v8a_source.prop_template
+    device/generic/goldfish/64bitonly/product/phone_source.prop_template
 
 $(call inherit-product, device/generic/goldfish/board/emu64a/details.mk)
 $(call inherit-product, device/generic/goldfish/product/phone.mk)
diff --git a/64bitonly/product/sdk_phone64_x86_64.mk b/64bitonly/product/sdk_phone64_x86_64.mk
index 6d831b19..6cdb685f 100644
--- a/64bitonly/product/sdk_phone64_x86_64.mk
+++ b/64bitonly/product/sdk_phone64_x86_64.mk
@@ -26,7 +26,7 @@ PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 endif
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    development/sys-img/images_x86_64_source.prop_template
+    device/generic/goldfish/64bitonly/product/phone_source.prop_template
 
 $(call inherit-product, device/generic/goldfish/board/emu64x/details.mk)
 $(call inherit-product, device/generic/goldfish/product/phone.mk)
diff --git a/64bitonly/product/sdk_slim_arm64.mk b/64bitonly/product/sdk_slim_arm64.mk
index 467cf46b..a09d1496 100644
--- a/64bitonly/product/sdk_slim_arm64.mk
+++ b/64bitonly/product/sdk_slim_arm64.mk
@@ -30,7 +30,7 @@ BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_S
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    development/sys-img/images_atd_source.prop_template
+    device/generic/goldfish/64bitonly/product/slim_source.prop_template
 
 # this must go first - overwrites the goldfish handheld_core_hardware.xml
 $(call inherit-product, device/generic/goldfish/slim/vendor.mk)
diff --git a/64bitonly/product/sdk_slim_x86_64.mk b/64bitonly/product/sdk_slim_x86_64.mk
index 1907e3a0..9509b3f6 100644
--- a/64bitonly/product/sdk_slim_x86_64.mk
+++ b/64bitonly/product/sdk_slim_x86_64.mk
@@ -33,6 +33,9 @@ $(call inherit-product, device/generic/goldfish/product/slim_handheld.mk)
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
     development/sys-img/images_atd_source.prop_template
 
+PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
+    device/generic/goldfish/64bitonly/product/slim_source.prop_template
+
 PRODUCT_BRAND := Android
 PRODUCT_NAME := sdk_slim_x86_64
 PRODUCT_DEVICE := emu64x
diff --git a/64bitonly/product/sdk_tablet_arm64.mk b/64bitonly/product/sdk_tablet_arm64.mk
index a52942cd..b9e76cc3 100644
--- a/64bitonly/product/sdk_tablet_arm64.mk
+++ b/64bitonly/product/sdk_tablet_arm64.mk
@@ -24,7 +24,7 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    device/generic/goldfish/64bitonly/product/tablet_images_arm64-v8a_source.prop_template
+    device/generic/goldfish/64bitonly/product/tablet_source.prop_template
 
 $(call inherit-product, device/generic/goldfish/board/emu64a/details.mk)
 $(call inherit-product, device/generic/goldfish/product/tablet.mk)
diff --git a/64bitonly/product/sdk_tablet_x86_64.mk b/64bitonly/product/sdk_tablet_x86_64.mk
index d8f9c7c0..9398639a 100644
--- a/64bitonly/product/sdk_tablet_x86_64.mk
+++ b/64bitonly/product/sdk_tablet_x86_64.mk
@@ -24,7 +24,7 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 
 PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
-    device/generic/goldfish/64bitonly/product/tablet_images_x86_64_source.prop_template
+    device/generic/goldfish/64bitonly/product/tablet_source.prop_template
 
 $(call inherit-product, device/generic/goldfish/board/emu64x/details.mk)
 $(call inherit-product, device/generic/goldfish/product/tablet.mk)
diff --git a/64bitonly/product/slim_source.prop_template b/64bitonly/product/slim_source.prop_template
new file mode 100644
index 00000000..522a34bd
--- /dev/null
+++ b/64bitonly/product/slim_source.prop_template
@@ -0,0 +1,12 @@
+Pkg.Desc=AOSP Automated Test Device System Image ${TARGET_CPU_ABI}
+Pkg.Revision=1
+Pkg.Dependencies=emulator#${EMULATOR_MINIMAL_VERSION}
+AndroidVersion.ApiLevel=${PLATFORM_SDK_VERSION}
+AndroidVersion.CodeName=${PLATFORM_VERSION_CODENAME}
+SystemImage.Abi=${TARGET_CPU_ABI}
+SystemImage.TagId=aosp_atd
+SystemImage.TagDisplay=AOSP ATD
+SystemImage.GpuSupport=true
+Addon.VendorId=google
+Addon.VendorDisplay=Google Inc.
+
diff --git a/64bitonly/product/tablet_images_arm64-v8a_source.prop_template b/64bitonly/product/tablet_source.prop_template
similarity index 82%
rename from 64bitonly/product/tablet_images_arm64-v8a_source.prop_template
rename to 64bitonly/product/tablet_source.prop_template
index 5463d6aa..a473a3b7 100644
--- a/64bitonly/product/tablet_images_arm64-v8a_source.prop_template
+++ b/64bitonly/product/tablet_source.prop_template
@@ -1,12 +1,12 @@
 Pkg.Desc=Tablet Android SDK System Image
 Pkg.UserSrc=false
 Pkg.Revision=1
-Pkg.Dependencies=emulator#29.1.11
+Pkg.Dependencies=emulator#${EMULATOR_MINIMAL_VERSION}
 AndroidVersion.ApiLevel=${PLATFORM_SDK_VERSION}
 AndroidVersion.CodeName=${PLATFORM_VERSION_CODENAME}
 AndroidVersion.ExtensionLevel=${PLATFORM_SDK_EXTENSION_VERSION}
 AndroidVersion.IsBaseSdk=${PLATFORM_IS_BASE_SDK}
-SystemImage.Abi=arm64-v8a
+SystemImage.Abi=${TARGET_CPU_ABI}
 SystemImage.GpuSupport=true
 SystemImage.TagId=aosp_tablet
 SystemImage.TagDisplay=Tablet Default Android System Image
diff --git a/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp b/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp
index f60b54ef..07ce8ca6 100644
--- a/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp
+++ b/MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp
@@ -94,25 +94,13 @@ static jobject nativeCreateSurface(JNIEnv *env, jobject obj, jint id, jint width
 {
     ALOGI("create surface for %d", id);
     // Create surface for this new display
-#if COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
-    sp<BufferItemConsumer> bufferItemConsumer =
-        new BufferItemConsumer(GRALLOC_USAGE_HW_RENDER);
-#else
-    sp<IGraphicBufferProducer> producer;
-    sp<IGraphicBufferConsumer> consumer;
-    sp<BufferItemConsumer> bufferItemConsumer;
-    BufferQueue::createBufferQueue(&producer, &consumer);
-    bufferItemConsumer = new BufferItemConsumer(consumer, GRALLOC_USAGE_HW_RENDER);
-#endif  // COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
+    auto [bufferItemConsumer, surface] =
+        BufferItemConsumer::create(GRALLOC_USAGE_HW_RENDER);
     gFrameListener[id] = new FrameListener(bufferItemConsumer, id);
     gFrameListener[id]->setDefaultBufferSize(width, height);
     bufferItemConsumer->setFrameAvailableListener(gFrameListener[id]);
-#if COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
-    return android_view_Surface_createFromSurface(
-        env, bufferItemConsumer->getSurface());
-#else
-    return android_view_Surface_createFromIGraphicBufferProducer(env, producer);
-#endif  // COM_ANDROID_GRAPHICS_LIBGUI_FLAGS(WB_CONSUMER_BASE_OWNS_BQ)
+
+    return android_view_Surface_createFromSurface(env, surface);
 }
 
 static jint nativeOpen(JNIEnv* env, jobject obj) {
diff --git a/OWNERS b/OWNERS
index 6e2be2df..573a31f5 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,8 @@
 bohu@google.com
+jansene@google.com
+joshuaduong@google.com
+jpcottin@google.com
+hshan@google.com
+kocdemir@google.com
 rkir@google.com
-lfy@google.com
-huans@google.com
-pcc@google.com
+sergiuferentz@google.com
diff --git a/board/emu64a/details.mk b/board/emu64a/details.mk
index e371c587..1344881e 100644
--- a/board/emu64a/details.mk
+++ b/board/emu64a/details.mk
@@ -16,9 +16,6 @@
 
 include device/generic/goldfish/board/kernel/arm64.mk
 
-PRODUCT_PROPERTY_OVERRIDES += \
-       vendor.rild.libpath=/vendor/lib64/libgoldfish-ril.so
-
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu \
diff --git a/board/emu64a16k/details.mk b/board/emu64a16k/details.mk
index fc53261b..93b333ee 100644
--- a/board/emu64a16k/details.mk
+++ b/board/emu64a16k/details.mk
@@ -16,9 +16,6 @@
 
 include device/generic/goldfish/board/kernel/arm64_16k.mk
 
-PRODUCT_PROPERTY_OVERRIDES += \
-       vendor.rild.libpath=/vendor/lib64/libgoldfish-ril.so
-
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu \
diff --git a/board/emu64x/details.mk b/board/emu64x/details.mk
index 75299f0a..480e333b 100644
--- a/board/emu64x/details.mk
+++ b/board/emu64x/details.mk
@@ -16,8 +16,6 @@
 
 include device/generic/goldfish/board/kernel/x86_64.mk
 
-PRODUCT_PROPERTY_OVERRIDES += \
-       vendor.rild.libpath=/vendor/lib64/libgoldfish-ril.so
 
 PRODUCT_COPY_FILES += \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu \
diff --git a/board/emu64x16k/details.mk b/board/emu64x16k/details.mk
index 7d450c00..8c274ce9 100644
--- a/board/emu64x16k/details.mk
+++ b/board/emu64x16k/details.mk
@@ -16,8 +16,6 @@
 
 include device/generic/goldfish/board/kernel/x86_64_16k.mk
 
-PRODUCT_PROPERTY_OVERRIDES += \
-       vendor.rild.libpath=/vendor/lib64/libgoldfish-ril.so
 
 PRODUCT_COPY_FILES += \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu \
diff --git a/board/kernel/arm64.mk b/board/kernel/arm64.mk
index 640f3c0f..2ff17bf9 100644
--- a/board/kernel/arm64.mk
+++ b/board/kernel/arm64.mk
@@ -18,9 +18,9 @@
 PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
 
 TARGET_KERNEL_USE ?= 6.6
-KERNEL_ARTIFACTS_PATH := kernel/prebuilts/$(TARGET_KERNEL_USE)/arm64
-VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
-    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/arm64
+KERNEL_ARTIFACTS_PATH := prebuilts/qemu-kernel/arm64/$(TARGET_KERNEL_USE)
+KERNEL_MODULES_ARTIFACTS_PATH := $(KERNEL_ARTIFACTS_PATH)/gki_modules
+VIRTUAL_DEVICE_KERNEL_MODULES_PATH := $(KERNEL_ARTIFACTS_PATH)/goldfish_modules
 
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
@@ -29,7 +29,7 @@ RAMDISK_KERNEL_MODULES := \
     virtio_mmio.ko \
     virtio-rng.ko \
 
-RAMDISK_SYSTEM_KERNEL_MODULES += \
+RAMDISK_SYSTEM_KERNEL_MODULES := \
     virtio_blk.ko \
     virtio_console.ko \
     virtio_pci.ko \
@@ -37,11 +37,12 @@ RAMDISK_SYSTEM_KERNEL_MODULES += \
     virtio_pci_modern_dev.ko \
     vmw_vsock_virtio_transport.ko \
 
-BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
+BOARD_SYSTEM_KERNEL_MODULES := \
+    $(wildcard $(KERNEL_MODULES_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
-    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
+    $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
diff --git a/board/kernel/arm64_16k.mk b/board/kernel/arm64_16k.mk
index 34d9d446..9e91b892 100644
--- a/board/kernel/arm64_16k.mk
+++ b/board/kernel/arm64_16k.mk
@@ -19,10 +19,9 @@ PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
 
 # Use 16K page size kernel
 TARGET_KERNEL_USE := 6.6
-TARGET_KERNEL_ARCH := arm64
-KERNEL_ARTIFACTS_PATH := kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)/16k
-VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
-    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))/16k
+KERNEL_ARTIFACTS_PATH := prebuilts/qemu-kernel/arm64_16k/$(TARGET_KERNEL_USE)
+KERNEL_MODULES_ARTIFACTS_PATH := $(KERNEL_ARTIFACTS_PATH)/gki_modules
+VIRTUAL_DEVICE_KERNEL_MODULES_PATH := $(KERNEL_ARTIFACTS_PATH)/goldfish_modules
 
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
@@ -31,7 +30,7 @@ RAMDISK_KERNEL_MODULES := \
     virtio_mmio.ko \
     virtio-rng.ko \
 
-RAMDISK_SYSTEM_KERNEL_MODULES += \
+RAMDISK_SYSTEM_KERNEL_MODULES := \
     virtio_blk.ko \
     virtio_console.ko \
     virtio_pci.ko \
@@ -39,11 +38,12 @@ RAMDISK_SYSTEM_KERNEL_MODULES += \
     virtio_pci_modern_dev.ko \
     vmw_vsock_virtio_transport.ko \
 
-BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
+BOARD_SYSTEM_KERNEL_MODULES := \
+    $(wildcard $(KERNEL_MODULES_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
-    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
+    $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
diff --git a/board/kernel/kernel_modules.blocklist b/board/kernel/kernel_modules.blocklist
index 8dc5e712..3b963105 100644
--- a/board/kernel/kernel_modules.blocklist
+++ b/board/kernel/kernel_modules.blocklist
@@ -1 +1,4 @@
 blocklist vkms.ko
+# When enabled, hijacks the first audio device that's expected to be backed by
+# virtio-snd. See also: aosp/3391025
+blocklist snd-aloop.ko
diff --git a/board/kernel/x86_64.mk b/board/kernel/x86_64.mk
index 1088216b..30ee4a54 100644
--- a/board/kernel/x86_64.mk
+++ b/board/kernel/x86_64.mk
@@ -18,9 +18,9 @@
 PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
 
 TARGET_KERNEL_USE ?= 6.6
-KERNEL_ARTIFACTS_PATH := kernel/prebuilts/$(TARGET_KERNEL_USE)/x86_64
-VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
-    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/x86-64
+KERNEL_ARTIFACTS_PATH := prebuilts/qemu-kernel/x86_64/$(TARGET_KERNEL_USE)
+KERNEL_MODULES_ARTIFACTS_PATH := $(KERNEL_ARTIFACTS_PATH)/gki_modules
+VIRTUAL_DEVICE_KERNEL_MODULES_PATH := $(KERNEL_ARTIFACTS_PATH)/goldfish_modules
 
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
@@ -28,7 +28,7 @@ RAMDISK_KERNEL_MODULES := \
     virtio_dma_buf.ko \
     virtio-rng.ko \
 
-RAMDISK_SYSTEM_KERNEL_MODULES += \
+RAMDISK_SYSTEM_KERNEL_MODULES := \
     virtio_blk.ko \
     virtio_console.ko \
     virtio_pci.ko \
@@ -36,11 +36,11 @@ RAMDISK_SYSTEM_KERNEL_MODULES += \
     virtio_pci_modern_dev.ko \
     vmw_vsock_virtio_transport.ko \
 
-BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
+BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_MODULES_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
-    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
+    $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
diff --git a/board/kernel/x86_64_16k.mk b/board/kernel/x86_64_16k.mk
index 20ec3f14..2a67e938 100644
--- a/board/kernel/x86_64_16k.mk
+++ b/board/kernel/x86_64_16k.mk
@@ -19,10 +19,9 @@ PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
 
 # Use 6.6 kernel
 TARGET_KERNEL_USE := 6.6
-TARGET_KERNEL_ARCH := x86_64
-KERNEL_ARTIFACTS_PATH := kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
-VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
-    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
+KERNEL_ARTIFACTS_PATH := prebuilts/qemu-kernel/x86_64/$(TARGET_KERNEL_USE)
+KERNEL_MODULES_ARTIFACTS_PATH := $(KERNEL_ARTIFACTS_PATH)/gki_modules
+VIRTUAL_DEVICE_KERNEL_MODULES_PATH := $(KERNEL_ARTIFACTS_PATH)/goldfish_modules
 
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
@@ -30,7 +29,7 @@ RAMDISK_KERNEL_MODULES := \
     virtio_dma_buf.ko \
     virtio-rng.ko \
 
-RAMDISK_SYSTEM_KERNEL_MODULES += \
+RAMDISK_SYSTEM_KERNEL_MODULES := \
     virtio_blk.ko \
     virtio_console.ko \
     virtio_pci.ko \
@@ -38,11 +37,12 @@ RAMDISK_SYSTEM_KERNEL_MODULES += \
     virtio_pci_modern_dev.ko \
     vmw_vsock_virtio_transport.ko \
 
-BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
+BOARD_SYSTEM_KERNEL_MODULES := \
+    $(wildcard $(KERNEL_MODULES_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
-    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
+    $(wildcard $(patsubst %,$(KERNEL_MODULES_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
diff --git a/camera/media/codecs.xml b/codecs/media/codecs.xml
similarity index 100%
rename from camera/media/codecs.xml
rename to codecs/media/codecs.xml
diff --git a/camera/media/codecs_google_video_default.xml b/codecs/media/codecs_google_video_default.xml
similarity index 100%
rename from camera/media/codecs_google_video_default.xml
rename to codecs/media/codecs_google_video_default.xml
diff --git a/camera/media/codecs_performance.xml b/codecs/media/codecs_performance.xml
similarity index 100%
rename from camera/media/codecs_performance.xml
rename to codecs/media/codecs_performance.xml
diff --git a/camera/media/codecs_performance_c2.xml b/codecs/media/codecs_performance_c2.xml
similarity index 100%
rename from camera/media/codecs_performance_c2.xml
rename to codecs/media/codecs_performance_c2.xml
diff --git a/camera/media/codecs_performance_c2_arm64.xml b/codecs/media/codecs_performance_c2_arm64.xml
similarity index 100%
rename from camera/media/codecs_performance_c2_arm64.xml
rename to codecs/media/codecs_performance_c2_arm64.xml
diff --git a/camera/media/media_codecs_google_tv.xml b/codecs/media/media_codecs_google_tv.xml
similarity index 100%
rename from camera/media/media_codecs_google_tv.xml
rename to codecs/media/media_codecs_google_tv.xml
diff --git a/camera/media/profiles.xml b/codecs/media/profiles.xml
similarity index 100%
rename from camera/media/profiles.xml
rename to codecs/media/profiles.xml
diff --git a/data/etc/advancedFeatures.ini b/data/etc/advancedFeatures.ini
index 919f64de..e671fec6 100644
--- a/data/etc/advancedFeatures.ini
+++ b/data/etc/advancedFeatures.ini
@@ -29,4 +29,5 @@ DeviceStateOnBoot = on
 HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
-Uwb = on
\ No newline at end of file
+Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/advancedFeatures.ini.desktop b/data/etc/advancedFeatures.ini.desktop
index f1aad493..fe798ad2 100644
--- a/data/etc/advancedFeatures.ini.desktop
+++ b/data/etc/advancedFeatures.ini.desktop
@@ -31,3 +31,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 VirtioTablet = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/advancedFeatures.ini.minigbm b/data/etc/advancedFeatures.ini.minigbm
index ac613c8e..89e23804 100644
--- a/data/etc/advancedFeatures.ini.minigbm
+++ b/data/etc/advancedFeatures.ini.minigbm
@@ -30,3 +30,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 Uwb = on
 Minigbm = on
+VulkanVirtualQueue = on
diff --git a/data/etc/advancedFeatures.ini.tablet b/data/etc/advancedFeatures.ini.tablet
index 659aaab0..c17c943a 100644
--- a/data/etc/advancedFeatures.ini.tablet
+++ b/data/etc/advancedFeatures.ini.tablet
@@ -29,3 +29,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/config.ini.tv b/data/etc/config.ini.tv
index 535bcfc6..8abafa68 100644
--- a/data/etc/config.ini.tv
+++ b/data/etc/config.ini.tv
@@ -6,7 +6,7 @@ hw.audioInput=yes
 hw.battery=no
 hw.camera.back=none
 hw.camera.front=emulated
-hw.dPad=no
+hw.dPad=yes
 hw.gps=yes
 hw.gpu.enabled=yes
 hw.keyboard=yes
diff --git a/data/etc/google/user/advancedFeatures.ini b/data/etc/google/user/advancedFeatures.ini
index eb0286eb..c262cc32 100644
--- a/data/etc/google/user/advancedFeatures.ini
+++ b/data/etc/google/user/advancedFeatures.ini
@@ -33,3 +33,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/user/advancedFeatures.ini.desktop b/data/etc/google/user/advancedFeatures.ini.desktop
index 86e9d3d4..cde8591f 100644
--- a/data/etc/google/user/advancedFeatures.ini.desktop
+++ b/data/etc/google/user/advancedFeatures.ini.desktop
@@ -32,3 +32,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 VirtioTablet = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/user/advancedFeatures.ini.minigbm b/data/etc/google/user/advancedFeatures.ini.minigbm
index 666145b4..6538f18f 100644
--- a/data/etc/google/user/advancedFeatures.ini.minigbm
+++ b/data/etc/google/user/advancedFeatures.ini.minigbm
@@ -33,3 +33,4 @@ DeviceKeyboardHasAssistKey = on
 Uwb = on
 Minigbm = on
 AndroidVirtualizationFramework = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/user/advancedFeatures.ini.tablet b/data/etc/google/user/advancedFeatures.ini.tablet
index f7dbbc5e..0a9564e9 100644
--- a/data/etc/google/user/advancedFeatures.ini.tablet
+++ b/data/etc/google/user/advancedFeatures.ini.tablet
@@ -31,3 +31,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini b/data/etc/google/userdebug/advancedFeatures.ini
index e907c6ca..73263eaf 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini
+++ b/data/etc/google/userdebug/advancedFeatures.ini
@@ -32,3 +32,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini.desktop b/data/etc/google/userdebug/advancedFeatures.ini.desktop
index 12979bbf..9e4cc225 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini.desktop
+++ b/data/etc/google/userdebug/advancedFeatures.ini.desktop
@@ -31,3 +31,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 VirtioTablet = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini.minigbm b/data/etc/google/userdebug/advancedFeatures.ini.minigbm
index 337f253e..334bfefb 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini.minigbm
+++ b/data/etc/google/userdebug/advancedFeatures.ini.minigbm
@@ -32,3 +32,4 @@ DeviceKeyboardHasAssistKey = on
 Uwb = on
 Minigbm = on
 AndroidVirtualizationFramework = on
+VulkanVirtualQueue = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini.tablet b/data/etc/google/userdebug/advancedFeatures.ini.tablet
index a7098313..a5cc49e1 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini.tablet
+++ b/data/etc/google/userdebug/advancedFeatures.ini.tablet
@@ -30,3 +30,4 @@ VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
 Uwb = on
+VulkanVirtualQueue = on
diff --git a/dhcp/client/Android.bp b/dhcp/client/Android.bp
deleted file mode 100644
index 5937a21e..00000000
--- a/dhcp/client/Android.bp
+++ /dev/null
@@ -1,41 +0,0 @@
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
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_generic_goldfish_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_generic_goldfish_license"],
-}
-
-cc_binary {
-    name: "dhcpclient",
-    srcs: [
-        "dhcpclient.cpp",
-        "interface.cpp",
-        "main.cpp",
-        "router.cpp",
-        "timer.cpp",
-    ],
-    shared_libs: [
-        "libcutils",
-        "liblog",
-    ],
-    static_libs: [
-        "libdhcpclient",
-    ],
-    proprietary: true,
-}
diff --git a/dhcp/client/dhcpclient.cpp b/dhcp/client/dhcpclient.cpp
deleted file mode 100644
index 7404fad4..00000000
--- a/dhcp/client/dhcpclient.cpp
+++ /dev/null
@@ -1,546 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "dhcpclient.h"
-#include "dhcp.h"
-#include "interface.h"
-#include "log.h"
-
-#include <arpa/inet.h>
-#include <errno.h>
-#include <linux/if_ether.h>
-#include <poll.h>
-#include <unistd.h>
-
-#include <cutils/properties.h>
-
-#include <inttypes.h>
-
-// The initial retry timeout for DHCP is 4000 milliseconds
-static const uint32_t kInitialTimeout = 4000;
-// The maximum retry timeout for DHCP is 64000 milliseconds
-static const uint32_t kMaxTimeout = 64000;
-// A specific value that indicates that no timeout should happen and that
-// the state machine should immediately transition to the next state
-static const uint32_t kNoTimeout = 0;
-
-// Enable debug messages
-static const bool kDebug = false;
-
-// The number of milliseconds that the timeout should vary (up or down) from the
-// base timeout. DHCP requires a -1 to +1 second variation in timeouts.
-static const int kTimeoutSpan = 1000;
-
-static std::string addrToStr(in_addr_t address) {
-    struct in_addr addr = { address };
-    char buffer[64];
-    return inet_ntop(AF_INET, &addr, buffer, sizeof(buffer));
-}
-
-DhcpClient::DhcpClient(uint32_t options)
-    : mOptions(options),
-      mRandomEngine(std::random_device()()),
-      mRandomDistribution(-kTimeoutSpan, kTimeoutSpan),
-      mState(State::Init),
-      mNextTimeout(kInitialTimeout),
-      mFuzzNextTimeout(true) {
-}
-
-Result DhcpClient::init(const char* interfaceName) {
-    Result res = mInterface.init(interfaceName);
-    if (!res) {
-        return res;
-    }
-
-    res = mRouter.init();
-    if (!res) {
-        return res;
-    }
-
-    res = mSocket.open(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
-    if (!res) {
-        return res;
-    }
-
-    res = mSocket.bindRaw(mInterface.getIndex());
-    if (!res) {
-        return res;
-    }
-    return Result::success();
-}
-
-Result DhcpClient::run() {
-    // Block all signals while we're running. This way we don't have to deal
-    // with things like EINTR. waitAndReceive then uses ppoll to set the
-    // original mask while polling. This way polling can be interrupted but
-    // socket writing, reading and ioctl remain interrupt free. If a signal
-    // arrives while we're blocking it it will be placed in the signal queue
-    // and handled once ppoll sets the original mask. This way no signals are
-    // lost.
-    sigset_t blockMask, originalMask;
-    int status = ::sigfillset(&blockMask);
-    if (status != 0) {
-        return Result::error("Unable to fill signal set: %s", strerror(errno));
-    }
-    status = ::sigprocmask(SIG_SETMASK, &blockMask, &originalMask);
-    if (status != 0) {
-        return Result::error("Unable to set signal mask: %s", strerror(errno));
-    }
-
-    for (;;) {
-        // Before waiting, polling or receiving we check the current state and
-        // see what we should do next. This may result in polling but could
-        // also lead to instant state changes without any polling. The new state
-        // will then be evaluated instead, most likely leading to polling.
-        switch (mState) {
-            case State::Init:
-                // The starting state. This is the state the client is in when
-                // it first starts. It's also the state that the client returns
-                // to when things go wrong in other states.
-                setNextState(State::Selecting);
-                break;
-            case State::Selecting:
-                // In the selecting state the client attempts to find DHCP
-                // servers on the network. The client remains in this state
-                // until a suitable server responds.
-                sendDhcpDiscover();
-                increaseTimeout();
-                break;
-            case State::Requesting:
-                // In the requesting state the client has found a suitable
-                // server. The next step is to send a request directly to that
-                // server.
-                if (mNextTimeout >= kMaxTimeout) {
-                    // We've tried to request a bunch of times, start over
-                    setNextState(State::Init);
-                } else {
-                    sendDhcpRequest(mServerAddress);
-                    increaseTimeout();
-                }
-                break;
-            case State::Bound:
-                // The client enters the bound state when the server has
-                // accepted and acknowledged a request and given us a lease. At
-                // this point the client will wait until the lease is close to
-                // expiring and then it will try to renew the lease.
-                if (mT1.expired()) {
-                    // Lease expired, renew lease
-                    setNextState(State::Renewing);
-                } else {
-                    // Spurious wake-up, continue waiting. Do not fuzz the
-                    // timeout with a random offset. Doing so can cause wakeups
-                    // before the timer has expired causing unnecessary
-                    // processing. Even worse it can cause the timer to expire
-                    // after the lease has ended.
-                    mNextTimeout = mT1.remainingMillis();
-                    mFuzzNextTimeout = false;
-                }
-                break;
-            case State::Renewing:
-                // In the renewing state the client is sending a request for the
-                // same address it had was previously bound to. If the second
-                // timer expires when in this state the client will attempt to
-                // do a full rebind.
-                if (mT2.expired()) {
-                    // Timeout while renewing, move to rebinding
-                    setNextState(State::Rebinding);
-                } else {
-                    sendDhcpRequest(mServerAddress);
-                    increaseTimeout();
-                }
-                break;
-            case State::Rebinding:
-                // The client was unable to renew the lease and moved to the
-                // rebinding state. In this state the client sends a request for
-                // the same address it had before to the broadcast address. This
-                // means that any DHCP server on the network is free to respond.
-                // After attempting this a few times the client will give up and
-                // move to the Init state to try to find a new DHCP server.
-                if (mNextTimeout >= kMaxTimeout) {
-                    // We've tried to rebind a bunch of times, start over
-                    setNextState(State::Init);
-                } else {
-                    // Broadcast a request
-                    sendDhcpRequest(INADDR_BROADCAST);
-                    increaseTimeout();
-                }
-                break;
-            default:
-                break;
-        }
-        // The proper action for the current state has been taken, perform any
-        // polling and/or waiting needed.
-        waitAndReceive(originalMask);
-    }
-
-    return Result::error("Client terminated unexpectedly");
-}
-
-const char* DhcpClient::stateToStr(State state) {
-    switch (state) {
-        case State::Init:
-            return "Init";
-        case State::Selecting:
-            return "Selecting";
-        case State::Requesting:
-            return "Requesting";
-        case State::Bound:
-            return "Bound";
-        case State::Renewing:
-            return "Renewing";
-        case State::Rebinding:
-            return "Rebinding";
-    }
-    return "<unknown>";
-}
-
-void DhcpClient::waitAndReceive(const sigset_t& pollSignalMask) {
-    if (mNextTimeout == kNoTimeout) {
-        // If there is no timeout the state machine has indicated that it wants
-        // an immediate transition to another state. Do nothing.
-        return;
-    }
-
-    struct pollfd fds;
-    fds.fd = mSocket.get();
-    fds.events = POLLIN;
-
-    uint32_t timeout = calculateTimeoutMillis();
-    for (;;) {
-        uint64_t startedAt = now();
-
-        struct timespec ts;
-        ts.tv_sec = timeout / 1000;
-        ts.tv_nsec = (timeout - ts.tv_sec * 1000) * 1000000;
-
-        // Poll for any incoming traffic with the calculated timeout. While
-        // polling the original signal mask is set so that the polling can be
-        // interrupted.
-        int res = ::ppoll(&fds, 1, &ts, &pollSignalMask);
-        if (res == 0) {
-            // Timeout, return to let the caller evaluate
-            return;
-        } else if (res > 0) {
-            // Something to read
-            Message msg;
-            if (receiveDhcpMessage(&msg)) {
-                // We received a DHCP message, check if it's of interest
-                uint8_t msgType = msg.type();
-                switch (mState) {
-                    case State::Selecting:
-                        if (msgType == DHCPOFFER) {
-                            // Received an offer, move to the Requesting state
-                            // to request it.
-                            mServerAddress = msg.serverId();
-                            mRequestAddress = msg.dhcpData.yiaddr;
-                            setNextState(State::Requesting);
-                            return;
-                        }
-                        break;
-                    case State::Requesting:
-                    case State::Renewing:
-                    case State::Rebinding:
-                        // All of these states have sent a DHCP request and are
-                        // now waiting for an ACK so the behavior is the same.
-                        if (msgType == DHCPACK) {
-                            // Request approved
-                            if (configureDhcp(msg)) {
-                                // Successfully configured DHCP, move to Bound
-                                setNextState(State::Bound);
-                                return;
-                            }
-                            // Unable to configure DHCP, keep sending requests.
-                            // This may not fix the issue but eventually it will
-                            // allow for a full timeout which will lead to a
-                            // move to the Init state. This might still not fix
-                            // the issue but at least the client keeps trying.
-                        } else if (msgType == DHCPNAK) {
-                            // Request denied, halt network and start over
-                            haltNetwork();
-                            setNextState(State::Init);
-                            return;
-                        } 
-                        break;
-                    default:
-                        // For the other states the client is not expecting any
-                        // network messages so we ignore those messages.
-                        break;
-                }
-            }
-        } else {
-            // An error occurred in polling, don't do anything here. The client
-            // should keep going anyway to try to acquire a lease in the future
-            // if things start working again.
-        }
-        // If we reach this point we received something that's not a DHCP,
-        // message, we timed out, or an error occurred. Go again with whatever
-        // time remains.
-        uint64_t currentTime = now();
-        uint64_t end = startedAt + timeout;
-        if (currentTime >= end) {
-            // We're done anyway, return and let caller evaluate
-            return;
-        }
-        // Wait whatever the remaining time is
-        timeout = end - currentTime;
-    }
-}
-
-bool DhcpClient::configureDhcp(const Message& msg) {
-    size_t optsSize = msg.optionsSize();
-    if (optsSize < 4) {
-        // Message is too small
-        if (kDebug) ALOGD("Opts size too small %d", static_cast<int>(optsSize));
-        return false;
-    }
-
-    const uint8_t* options = msg.dhcpData.options;
-
-    memset(&mDhcpInfo, 0, sizeof(mDhcpInfo));
-
-    // Inspect all options in the message to try to find the ones we want
-    for (size_t i = 4; i + 1 < optsSize; ) {
-        uint8_t optCode = options[i];
-        uint8_t optLength = options[i + 1];
-        if (optCode == OPT_END) {
-            break;
-        }
-
-        if (options + optLength + i >= msg.end()) {
-            // Invalid option length, drop it
-            if (kDebug) ALOGD("Invalid opt length %d for opt %d",
-                              static_cast<int>(optLength),
-                              static_cast<int>(optCode));
-            return false;
-        }
-        const uint8_t* opt = options + i + 2;
-        switch (optCode) {
-            case OPT_LEASE_TIME:
-                if (optLength == 4) {
-                    mDhcpInfo.leaseTime =
-                        ntohl(*reinterpret_cast<const uint32_t*>(opt));
-                }
-                break;
-            case OPT_T1:
-                if (optLength == 4) {
-                    mDhcpInfo.t1 =
-                        ntohl(*reinterpret_cast<const uint32_t*>(opt));
-                }
-                break;
-            case OPT_T2:
-                if (optLength == 4) {
-                    mDhcpInfo.t2 =
-                        ntohl(*reinterpret_cast<const uint32_t*>(opt));
-                }
-                break;
-            case OPT_SUBNET_MASK:
-                if (optLength == 4) {
-                    mDhcpInfo.subnetMask =
-                        *reinterpret_cast<const in_addr_t*>(opt);
-                }
-                break;
-            case OPT_GATEWAY:
-                if (optLength >= 4) {
-                    mDhcpInfo.gateway =
-                        *reinterpret_cast<const in_addr_t*>(opt);
-                }
-                break;
-            case OPT_MTU:
-                if (optLength == 2) {
-                    mDhcpInfo.mtu =
-                        ntohs(*reinterpret_cast<const uint16_t*>(opt));
-                }
-                break;
-            case OPT_DNS:
-                if (optLength >= 4) {
-                    mDhcpInfo.dns[0] =
-                        *reinterpret_cast<const in_addr_t*>(opt);
-                }
-                if (optLength >= 8) {
-                    mDhcpInfo.dns[1] =
-                        *reinterpret_cast<const in_addr_t*>(opt + 4);
-                }
-                if (optLength >= 12) {
-                    mDhcpInfo.dns[2] =
-                        *reinterpret_cast<const in_addr_t*>(opt + 8);
-                }
-                if (optLength >= 16) {
-                    mDhcpInfo.dns[3] =
-                        *reinterpret_cast<const in_addr_t*>(opt + 12);
-                }
-                break;
-            case OPT_SERVER_ID:
-                if (optLength == 4) {
-                    mDhcpInfo.serverId =
-                        *reinterpret_cast<const in_addr_t*>(opt);
-                }
-                break;
-            default:
-                break;
-        }
-        i += 2 + optLength;
-    }
-    mDhcpInfo.offeredAddress = msg.dhcpData.yiaddr;
-
-    if (mDhcpInfo.leaseTime == 0) {
-        // We didn't get a lease time, ignore this offer
-        return false;
-    }
-    // If there is no T1 or T2 timer given then we create an estimate as
-    // suggested for servers in RFC 2131.
-    uint32_t t1 = mDhcpInfo.t1, t2 = mDhcpInfo.t2;
-    mT1.expireSeconds(t1 > 0 ? t1 : (mDhcpInfo.leaseTime / 2));
-    mT2.expireSeconds(t2 > 0 ? t2 : ((mDhcpInfo.leaseTime * 7) / 8));
-
-    Result res = mInterface.bringUp();
-    if (!res) {
-        ALOGE("Could not configure DHCP: %s", res.c_str());
-        return false;
-    }
-
-    if (mDhcpInfo.mtu != 0) {
-        res = mInterface.setMtu(mDhcpInfo.mtu);
-        if (!res) {
-            // Consider this non-fatal, the system will not perform at its best
-            // but should still work.
-            ALOGE("Could not configure DHCP: %s", res.c_str());
-        }
-    }
-
-    char propName[64];
-    snprintf(propName, sizeof(propName), "vendor.net.%s.gw",
-             mInterface.getName().c_str());
-    if (property_set(propName, addrToStr(mDhcpInfo.gateway).c_str()) != 0) {
-        ALOGE("Failed to set %s: %s", propName, strerror(errno));
-    }
-
-    int numDnsEntries = sizeof(mDhcpInfo.dns) / sizeof(mDhcpInfo.dns[0]);
-    for (int i = 0; i < numDnsEntries; ++i) {
-        snprintf(propName, sizeof(propName), "vendor.net.%s.dns%d",
-                 mInterface.getName().c_str(), i + 1);
-        if (mDhcpInfo.dns[i] != 0) {
-            if (property_set(propName,
-                             addrToStr(mDhcpInfo.dns[i]).c_str()) != 0) {
-                ALOGE("Failed to set %s: %s", propName, strerror(errno));
-            }
-        } else {
-            // Clear out any previous value here in case it was set
-            if (property_set(propName, "") != 0) {
-                ALOGE("Failed to clear %s: %s", propName, strerror(errno));
-            }
-        }
-    }
-
-    res = mInterface.setAddress(mDhcpInfo.offeredAddress,
-                                mDhcpInfo.subnetMask);
-    if (!res) {
-        ALOGE("Could not configure DHCP: %s", res.c_str());
-        return false;
-    }
-
-    if ((mOptions & static_cast<uint32_t>(ClientOption::NoGateway)) == 0) {
-        res = mRouter.setDefaultGateway(mDhcpInfo.gateway,
-                                        mInterface.getIndex());
-        if (!res) {
-            ALOGE("Could not configure DHCP: %s", res.c_str());
-            return false;
-        }
-    }
-    return true;
-}
-
-void DhcpClient::haltNetwork() {
-    Result res = mInterface.setAddress(0, 0);
-    if (!res) {
-        ALOGE("Could not halt network: %s", res.c_str());
-    }
-    res = mInterface.bringDown();
-    if (!res) {
-        ALOGE("Could not halt network: %s", res.c_str());
-    }
-}
-
-bool DhcpClient::receiveDhcpMessage(Message* msg) {
-    bool isValid = false;
-    Result res = mSocket.receiveRawUdp(PORT_BOOTP_CLIENT, msg, &isValid);
-    if (!res) {
-        if (kDebug) ALOGD("Discarding message: %s", res.c_str());
-        return false;
-    }
-
-    return isValid &&
-           msg->isValidDhcpMessage(OP_BOOTREPLY, mLastMsg.dhcpData.xid);
-}
-
-uint32_t DhcpClient::calculateTimeoutMillis() {
-    if (!mFuzzNextTimeout) {
-        return mNextTimeout;
-    }
-    int adjustment = mRandomDistribution(mRandomEngine);
-    if (adjustment < 0 && static_cast<uint32_t>(-adjustment) > mNextTimeout) {
-        // Underflow, return a timeout of zero milliseconds
-        return 0;
-    }
-    return mNextTimeout + adjustment;
-}
-
-void DhcpClient::increaseTimeout() {
-    if (mNextTimeout == kNoTimeout) {
-        mNextTimeout = kInitialTimeout;
-    } else {
-        if (mNextTimeout < kMaxTimeout) {
-            mNextTimeout *= 2;
-        }
-        if (mNextTimeout > kMaxTimeout) {
-            mNextTimeout = kMaxTimeout;
-        }
-    }
-}
-
-void DhcpClient::setNextState(State state) {
-    if (kDebug) ALOGD("Moving from state %s to %s",
-                      stateToStr(mState), stateToStr(state));
-    mState = state;
-    mNextTimeout = kNoTimeout;
-    mFuzzNextTimeout = true;
-}
-
-void DhcpClient::sendDhcpRequest(in_addr_t destination) {
-    if (kDebug) ALOGD("Sending DHCPREQUEST");
-    mLastMsg = Message::request(mInterface.getMacAddress(),
-                                mRequestAddress,
-                                destination);
-    sendMessage(mLastMsg);
-}
-
-void DhcpClient::sendDhcpDiscover() {
-    if (kDebug) ALOGD("Sending DHCPDISCOVER");
-    mLastMsg = Message::discover(mInterface.getMacAddress());
-    sendMessage(mLastMsg);
-}
-
-void DhcpClient::sendMessage(const Message& message) {
-    Result res = mSocket.sendRawUdp(INADDR_ANY,
-                                    PORT_BOOTP_CLIENT,
-                                    INADDR_BROADCAST,
-                                    PORT_BOOTP_SERVER,
-                                    mInterface.getIndex(),
-                                    message);
-    if (!res) {
-        ALOGE("Unable to send message: %s", res.c_str());
-    }
-}
-
diff --git a/dhcp/client/dhcpclient.h b/dhcp/client/dhcpclient.h
deleted file mode 100644
index 128d416f..00000000
--- a/dhcp/client/dhcpclient.h
+++ /dev/null
@@ -1,109 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-#pragma once
-
-#include "interface.h"
-#include "message.h"
-#include "result.h"
-#include "router.h"
-#include "socket.h"
-#include "timer.h"
-
-#include <netinet/in.h>
-#include <stdint.h>
-
-#include <random>
-
-// Options to configure the behavior of the DHCP client.
-enum class ClientOption : uint32_t {
-    NoGateway = (1 << 0),   // Do not configure the system's default gateway
-};
-
-class DhcpClient {
-public:
-    // Create a DHCP client with the given |options|. These options are values
-    // from the ClientOption enum.
-    explicit DhcpClient(uint32_t options);
-
-    // Initialize the DHCP client to listen on |interfaceName|.
-    Result init(const char* interfaceName);
-    Result run();
-private:
-    enum class State {
-        Init,
-        Selecting,
-        Requesting,
-        Bound,
-        Renewing,
-        Rebinding
-    };
-    const char* stateToStr(State state);
-
-    // Wait for any pending timeouts
-    void waitAndReceive(const sigset_t& pollSignalMask);
-    // Create a varying timeout (+- 1 second) based on the next timeout.
-    uint32_t calculateTimeoutMillis();
-    // Increase the next timeout in a manner that's compliant with the DHCP RFC.
-    void increaseTimeout();
-    // Move to |state|, the next poll timeout will be zero and the new
-    // state will be immediately evaluated.
-    void setNextState(State state);
-    // Configure network interface based on the DHCP configuration in |msg|.
-    bool configureDhcp(const Message& msg);
-    // Halt network operations on the network interface for when configuration
-    // is not possible and the protocol demands it.
-    void haltNetwork();
-    // Receive a message on the socket and populate |msg| with the received
-    // data. If the message is a valid DHCP message the method returns true. If
-    // it's not valid false is returned.
-    bool receiveDhcpMessage(Message* msg);
-
-    void sendDhcpDiscover();
-    void sendDhcpRequest(in_addr_t destination);
-    void sendMessage(const Message& message);
-    Result send(in_addr_t source, in_addr_t destination,
-                uint16_t sourcePort, uint16_t destinationPort,
-                const uint8_t* data, size_t size);
-
-    uint32_t mOptions;
-    std::mt19937 mRandomEngine; // Mersenne Twister RNG
-    std::uniform_int_distribution<int> mRandomDistribution;
-
-    struct DhcpInfo {
-        uint32_t t1;
-        uint32_t t2;
-        uint32_t leaseTime;
-        uint16_t mtu;
-        in_addr_t dns[4];
-        in_addr_t gateway;
-        in_addr_t subnetMask;
-        in_addr_t serverId;
-        in_addr_t offeredAddress;
-    } mDhcpInfo;
-
-    Router mRouter;
-    Interface mInterface;
-    Message mLastMsg;
-    Timer mT1, mT2;
-    Socket mSocket;
-    State mState;
-    uint32_t mNextTimeout;
-    bool mFuzzNextTimeout;
-
-    in_addr_t mRequestAddress; // Address we'd like to use in requests
-    in_addr_t mServerAddress;  // Server to send request to
-};
-
diff --git a/dhcp/client/interface.cpp b/dhcp/client/interface.cpp
deleted file mode 100644
index a13af084..00000000
--- a/dhcp/client/interface.cpp
+++ /dev/null
@@ -1,230 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "interface.h"
-
-#include "netlink.h"
-
-#include <errno.h>
-#include <linux/if.h>
-#include <linux/if_ether.h>
-#include <linux/route.h>
-#include <linux/rtnetlink.h>
-#include <string.h>
-#include <unistd.h>
-
-in_addr_t broadcastFromNetmask(in_addr_t address, in_addr_t netmask) {
-    // The broadcast address is the address with the bits excluded in the
-    // netmask set to 1. For example if address = 10.0.2.15 and netmask is
-    // 255.255.255.0 then the broadcast is 10.0.2.255. If instead netmask was
-    // 255.0.0.0.0 then the broadcast would be 10.255.255.255
-    //
-    // Simply set all the lower bits to 1 and that should do it.
-    return address | (~netmask);
-}
-
-Interface::Interface() : mSocketFd(-1) {
-}
-
-Interface::~Interface() {
-    if (mSocketFd != -1) {
-        close(mSocketFd);
-        mSocketFd = -1;
-    }
-}
-
-Result Interface::init(const char* interfaceName) {
-    mInterfaceName = interfaceName;
-
-    if (mSocketFd != -1) {
-        return Result::error("Interface initialized more than once");
-    }
-
-    mSocketFd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
-    if (mSocketFd == -1) {
-        return Result::error("Failed to create interface socket for '%s': %s",
-                             interfaceName, strerror(errno));
-    }
-
-    Result res = populateIndex();
-    if (!res) {
-        return res;
-    }
-
-    res = populateMacAddress();
-    if (!res) {
-        return res;
-    }
-
-    res = bringUp();
-    if (!res) {
-        return res;
-    }
-
-    res = setAddress(0, 0);
-    if (!res) {
-        return res;
-    }
-
-    return Result::success();
-}
-
-Result Interface::bringUp() {
-    return setInterfaceUp(true);
-}
-
-Result Interface::bringDown() {
-    return setInterfaceUp(false);
-}
-
-Result Interface::setMtu(uint16_t mtu) {
-    struct ifreq request = createRequest();
-
-    strncpy(request.ifr_name, mInterfaceName.c_str(), sizeof(request.ifr_name));
-    request.ifr_mtu = mtu;
-    int status = ::ioctl(mSocketFd, SIOCSIFMTU, &request);
-    if (status != 0) {
-        return Result::error("Failed to set interface MTU %u for '%s': %s",
-                             static_cast<unsigned int>(mtu),
-                             mInterfaceName.c_str(),
-                             strerror(errno));
-    }
-
-    return Result::success();
-}
-
-Result Interface::setAddress(in_addr_t address, in_addr_t subnetMask) {
-    struct Request {
-        struct nlmsghdr hdr;
-        struct ifaddrmsg msg;
-        char buf[256];
-    } request;
-
-    memset(&request, 0, sizeof(request));
-
-    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.msg));
-    request.hdr.nlmsg_type = RTM_NEWADDR;
-    request.hdr.nlmsg_flags = NLM_F_REQUEST |
-                              NLM_F_ACK |
-                              NLM_F_CREATE |
-                              NLM_F_REPLACE;
-
-    request.msg.ifa_family = AF_INET;
-    // Count the number of bits in the subnet mask, this is the length.
-    request.msg.ifa_prefixlen = __builtin_popcount(subnetMask);
-    request.msg.ifa_index = mIndex;
-
-    addRouterAttribute(request, IFA_ADDRESS, &address, sizeof(address));
-    addRouterAttribute(request, IFA_LOCAL, &address, sizeof(address));
-    in_addr_t broadcast = broadcastFromNetmask(address, subnetMask);
-    addRouterAttribute(request, IFA_BROADCAST, &broadcast, sizeof(broadcast));
-
-    struct sockaddr_nl nlAddr;
-    memset(&nlAddr, 0, sizeof(nlAddr));
-    nlAddr.nl_family = AF_NETLINK;
-
-    int status = ::sendto(mSocketFd, &request, request.hdr.nlmsg_len, 0,
-                          reinterpret_cast<sockaddr*>(&nlAddr),
-                          sizeof(nlAddr));
-    if (status == -1) {
-        return Result::error("Unable to set interface address: %s",
-                             strerror(errno));
-    }
-    char buffer[8192];
-    status = ::recv(mSocketFd, buffer, sizeof(buffer), 0);
-    if (status < 0) {
-        return Result::error("Unable to read netlink response: %s",
-                             strerror(errno));
-    }
-    size_t responseSize = static_cast<size_t>(status);
-    if (responseSize < sizeof(nlmsghdr)) {
-        return Result::error("Received incomplete response from netlink");
-    }
-    auto response = reinterpret_cast<const nlmsghdr*>(buffer);
-    if (response->nlmsg_type == NLMSG_ERROR) {
-        if (responseSize < NLMSG_HDRLEN + sizeof(nlmsgerr)) {
-            return Result::error("Recieved an error from netlink but the "
-                                 "response was incomplete");
-        }
-        auto err = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(response));
-        if (err->error) {
-            return Result::error("Could not set interface address: %s",
-                                 strerror(-err->error));
-        }
-    }
-    return Result::success();
-}
-
-struct ifreq Interface::createRequest() const {
-    struct ifreq request;
-    memset(&request, 0, sizeof(request));
-    strncpy(request.ifr_name, mInterfaceName.c_str(), sizeof(request.ifr_name));
-    request.ifr_name[sizeof(request.ifr_name) - 1] = '\0';
-
-    return request;
-}
-
-Result Interface::populateIndex() {
-    struct ifreq request = createRequest();
-
-    int status = ::ioctl(mSocketFd, SIOCGIFINDEX, &request);
-    if (status != 0) {
-        return Result::error("Failed to get interface index for '%s': %s",
-                             mInterfaceName.c_str(), strerror(errno));
-    }
-    mIndex = request.ifr_ifindex;
-    return Result::success();
-}
-
-Result Interface::populateMacAddress() {
-    struct ifreq request = createRequest();
-
-    int status = ::ioctl(mSocketFd, SIOCGIFHWADDR, &request);
-    if (status != 0) {
-        return Result::error("Failed to get MAC address for '%s': %s",
-                             mInterfaceName.c_str(), strerror(errno));
-    }
-    memcpy(mMacAddress, &request.ifr_hwaddr.sa_data, ETH_ALEN);
-    return Result::success();
-}
-
-Result Interface::setInterfaceUp(bool shouldBeUp) {
-    struct ifreq request = createRequest();
-
-    int status = ::ioctl(mSocketFd, SIOCGIFFLAGS, &request);
-    if (status != 0) {
-        return Result::error("Failed to get interface flags for '%s': %s",
-                             mInterfaceName.c_str(), strerror(errno));
-    }
-
-    bool isUp = (request.ifr_flags & IFF_UP) != 0;
-    if (isUp != shouldBeUp) {
-        // Toggle the up flag
-        request.ifr_flags ^= IFF_UP;
-    } else {
-        // Interface is already in desired state, do nothing
-        return Result::success();
-    }
-
-    status = ::ioctl(mSocketFd, SIOCSIFFLAGS, &request);
-    if (status != 0) {
-        return Result::error("Failed to set interface flags for '%s': %s",
-                             mInterfaceName.c_str(), strerror(errno));
-    }
-
-    return Result::success();
-}
-
diff --git a/dhcp/client/interface.h b/dhcp/client/interface.h
deleted file mode 100644
index ca9e9e5a..00000000
--- a/dhcp/client/interface.h
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-#pragma once
-
-#include "result.h"
-
-#include <linux/if_ether.h>
-#include <netinet/in.h>
-
-#include <string>
-
-// A class representing a network interface. The class provides useful
-// functionality to configure and query the network interface.
-class Interface {
-public:
-    Interface();
-    ~Interface();
-    Result init(const char* interfaceName);
-
-    // Returns the interface index indicated by the system
-    unsigned int getIndex() const { return mIndex; }
-    // Get the MAC address of the interface
-    const uint8_t (&getMacAddress() const)[ETH_ALEN] { return mMacAddress; }
-    // Get the name of the interface
-    const std::string& getName() const { return mInterfaceName; }
-
-    Result bringUp();
-    Result bringDown();
-    Result setMtu(uint16_t mtu);
-    Result setAddress(in_addr_t address, in_addr_t subnetMask);
-
-private:
-    struct ifreq createRequest() const;
-    Result populateIndex();
-    Result populateMacAddress();
-    Result setInterfaceUp(bool shouldBeUp);
-
-    std::string mInterfaceName;
-    int mSocketFd;
-    unsigned int mIndex;
-    uint8_t mMacAddress[ETH_ALEN];
-};
-
diff --git a/dhcp/client/main.cpp b/dhcp/client/main.cpp
deleted file mode 100644
index 70b854f4..00000000
--- a/dhcp/client/main.cpp
+++ /dev/null
@@ -1,72 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "dhcpclient.h"
-#include "log.h"
-
-static void usage(const char* program) {
-    ALOGE("Usage: %s [--no-gateway] -i <interface>", program);
-    ALOGE("  If the optional parameter --no-gateway is specified the client");
-    ALOGE("  will not configure the default gateway of the system.");
-}
-
-int main(int argc, char* argv[]) {
-    if (argc < 3) {
-        usage(argv[0]);
-        return 1;
-    }
-    const char* interfaceName = nullptr;
-    uint32_t options = 0;
-
-    for (int i = 1; i < argc; ++i) {
-        if (strcmp(argv[i], "-i") == 0) {
-            if (i + 1 < argc) {
-                interfaceName = argv[++i];
-            } else {
-                ALOGE("ERROR: -i parameter needs an argument");
-                usage(argv[0]);
-                return 1;
-            }
-        } else if (strcmp(argv[i], "--no-gateway") == 0) {
-            options |= static_cast<uint32_t>(ClientOption::NoGateway);
-        } else {
-            ALOGE("ERROR: unknown parameters %s", argv[i]);
-            usage(argv[0]);
-            return 1;
-        }
-    }
-    if (interfaceName == nullptr) {
-        ALOGE("ERROR: No interface specified");
-        usage(argv[0]);
-        return 1;
-    }
-
-    DhcpClient client(options);
-    Result res = client.init(interfaceName);
-    if (!res) {
-        ALOGE("Failed to initialize DHCP client: %s\n", res.c_str());
-        return 1;
-    }
-
-    res = client.run();
-    if (!res) {
-        ALOGE("DHCP client failed: %s\n", res.c_str());
-        return 1;
-    }
-    // This is weird and shouldn't happen, the client should run forever.
-    return 0;
-}
-
diff --git a/dhcp/client/netlink.h b/dhcp/client/netlink.h
deleted file mode 100644
index e0c916f3..00000000
--- a/dhcp/client/netlink.h
+++ /dev/null
@@ -1,22 +0,0 @@
-#pragma once
-
-#include <linux/rtnetlink.h>
-
-template<class Request>
-inline void addRouterAttribute(Request& r,
-                               int type,
-                               const void* data,
-                               size_t size) {
-    // Calculate the offset into the character buffer where the RTA data lives
-    // We use offsetof on the buffer to get it. This avoids undefined behavior
-    // by casting the buffer (which is safe because it's char) instead of the
-    // Request struct.(which is undefined because of aliasing)
-    size_t offset = NLMSG_ALIGN(r.hdr.nlmsg_len) - offsetof(Request, buf);
-    auto attr = reinterpret_cast<struct rtattr*>(r.buf + offset);
-    attr->rta_type = type;
-    attr->rta_len = RTA_LENGTH(size);
-    memcpy(RTA_DATA(attr), data, size);
-
-    // Update the message length to include the router attribute.
-    r.hdr.nlmsg_len = NLMSG_ALIGN(r.hdr.nlmsg_len) + RTA_ALIGN(attr->rta_len);
-}
diff --git a/dhcp/client/router.cpp b/dhcp/client/router.cpp
deleted file mode 100644
index 7c87e2d9..00000000
--- a/dhcp/client/router.cpp
+++ /dev/null
@@ -1,87 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#include "router.h"
-
-#include "netlink.h"
-
-#include <linux/rtnetlink.h>
-
-#include <errno.h>
-#include <string.h>
-#include <unistd.h>
-
-Router::Router() : mSocketFd(-1) {
-}
-
-Router::~Router() {
-    if (mSocketFd != -1) {
-        ::close(mSocketFd);
-        mSocketFd = -1;
-    }
-}
-
-Result Router::init() {
-    // Create a netlink socket to the router
-    mSocketFd = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
-    if (mSocketFd == -1) {
-        return Result::error(strerror(errno));
-    }
-    return Result::success();
-}
-
-Result Router::setDefaultGateway(in_addr_t gateway, unsigned int ifaceIndex) {
-    struct Request {
-        struct nlmsghdr hdr;
-        struct rtmsg msg;
-        char buf[256];
-    } request;
-
-    memset(&request, 0, sizeof(request));
-
-    // Set up a request to create a new route
-    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.msg));
-    request.hdr.nlmsg_type = RTM_NEWROUTE;
-    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
-
-    request.msg.rtm_family = AF_INET;
-    request.msg.rtm_dst_len = 0;
-    request.msg.rtm_table = RT_TABLE_MAIN;
-    request.msg.rtm_protocol = RTPROT_BOOT;
-    request.msg.rtm_scope = RT_SCOPE_UNIVERSE;
-    request.msg.rtm_type = RTN_UNICAST;
-
-    addRouterAttribute(request, RTA_GATEWAY, &gateway, sizeof(gateway));
-    addRouterAttribute(request, RTA_OIF, &ifaceIndex, sizeof(ifaceIndex));
-
-    return sendNetlinkMessage(&request, request.hdr.nlmsg_len);
-}
-
-Result Router::sendNetlinkMessage(const void* data, size_t size) {
-    struct sockaddr_nl nlAddress;
-    memset(&nlAddress, 0, sizeof(nlAddress));
-    nlAddress.nl_family = AF_NETLINK;
-
-    int res = ::sendto(mSocketFd, data, size, 0,
-                       reinterpret_cast<sockaddr*>(&nlAddress),
-                       sizeof(nlAddress));
-    if (res == -1) {
-        return Result::error("Unable to send on netlink socket: %s",
-                             strerror(errno));
-    }
-    return Result::success();
-}
-
diff --git a/dhcp/client/router.h b/dhcp/client/router.h
deleted file mode 100644
index 1ab66540..00000000
--- a/dhcp/client/router.h
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#pragma once
-
-#include <stdint.h>
-
-#include <netinet/in.h>
-
-#include "result.h"
-
-class Router {
-public:
-    Router();
-    ~Router();
-    // Initialize the router, this has to be called before any other methods can
-    // be called. It only needs to be called once.
-    Result init();
-
-    // Set the default route to |gateway| on the interface specified by
-    // |interfaceIndex|. If the default route is already set up with the same
-    // configuration then nothing is done. If another default route exists it
-    // will be removed and replaced by the new one. If no default route exists
-    // a route will be created with the given parameters.
-    Result setDefaultGateway(in_addr_t gateway, unsigned int interfaceIndex);
-private:
-    Result sendNetlinkMessage(const void* data, size_t size);
-
-    // Netlink socket for setting up neighbors and routes
-    int mSocketFd;
-};
-
diff --git a/dhcp/client/timer.cpp b/dhcp/client/timer.cpp
deleted file mode 100644
index 5f813224..00000000
--- a/dhcp/client/timer.cpp
+++ /dev/null
@@ -1,46 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "timer.h"
-
-#include <time.h>
-
-uint64_t now() {
-    struct timespec time = { 0, 0 };
-    clock_gettime(CLOCK_MONOTONIC, &time);
-    return static_cast<uint64_t>(time.tv_sec) * 1000u +
-           static_cast<uint64_t>(time.tv_nsec / 1000000u);
-}
-
-Timer::Timer() : mExpires(0) {
-}
-
-void Timer::expireSeconds(uint64_t seconds) {
-    mExpires = now() + seconds * 1000u;
-}
-
-bool Timer::expired() const {
-    return now() >= mExpires;
-}
-
-uint64_t Timer::remainingMillis() const {
-    uint64_t current = now();
-    if (current > mExpires) {
-        return 0;
-    }
-    return mExpires - current;
-}
-
diff --git a/dhcp/client/timer.h b/dhcp/client/timer.h
deleted file mode 100644
index 7ae01f9d..00000000
--- a/dhcp/client/timer.h
+++ /dev/null
@@ -1,40 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#pragma once
-
-#include <stdint.h>
-
-// Return the current timestamp from a monotonic clock in milliseconds.
-uint64_t now();
-
-class Timer {
-public:
-    // Create a timer, initially the timer is already expired.
-    Timer();
-
-    // Set the timer to expire in |seconds| seconds.
-    void expireSeconds(uint64_t seconds);
-
-    // Return true if the timer has expired.
-    bool expired() const;
-    // Get the remaining time on the timer in milliseconds.
-    uint64_t remainingMillis() const;
-
-private:
-    uint64_t mExpires;
-};
-
diff --git a/dhcp/common/Android.bp b/dhcp/common/Android.bp
deleted file mode 100644
index 9dd0aaa2..00000000
--- a/dhcp/common/Android.bp
+++ /dev/null
@@ -1,38 +0,0 @@
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
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_generic_goldfish_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_generic_goldfish_license"],
-}
-
-cc_library_static {
-    name: "libdhcpclient",
-    srcs: [
-        "message.cpp",
-        "socket.cpp",
-        "utils.cpp",
-    ],
-    export_include_dirs: ["include"],
-    cflags: [
-        "-Wall",
-        "-Wextra",
-        "-Werror",
-    ],
-    proprietary: true,
-}
diff --git a/dhcp/common/include/dhcp.h b/dhcp/common/include/dhcp.h
deleted file mode 100644
index beb388fd..00000000
--- a/dhcp/common/include/dhcp.h
+++ /dev/null
@@ -1,72 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-#pragma once
-
-// Ports
-#define PORT_BOOTP_SERVER 67
-#define PORT_BOOTP_CLIENT 68
-
-// Operations
-#define OP_BOOTREQUEST 1
-#define OP_BOOTREPLY   2
-
-// Flags
-#define FLAGS_BROADCAST 0x8000
-
-// Hardware address types
-#define HTYPE_ETHER    1
-
-// The first four bytes of options are a cookie to indicate that the payload are
-// DHCP options as opposed to some other BOOTP extension.
-#define OPT_COOKIE1          0x63
-#define OPT_COOKIE2          0x82
-#define OPT_COOKIE3          0x53
-#define OPT_COOKIE4          0x63
-
-// BOOTP/DHCP options - see RFC 2132
-#define OPT_PAD              0
-
-#define OPT_SUBNET_MASK      1     // 4 <ipaddr>
-#define OPT_TIME_OFFSET      2     // 4 <seconds>
-#define OPT_GATEWAY          3     // 4*n <ipaddr> * n
-#define OPT_DNS              6     // 4*n <ipaddr> * n
-#define OPT_DOMAIN_NAME      15    // n <domainnamestring>
-#define OPT_MTU              26    // 2 <mtu>
-#define OPT_BROADCAST_ADDR   28    // 4 <ipaddr>
-
-#define OPT_REQUESTED_IP     50    // 4 <ipaddr>
-#define OPT_LEASE_TIME       51    // 4 <seconds>
-#define OPT_MESSAGE_TYPE     53    // 1 <msgtype>
-#define OPT_SERVER_ID        54    // 4 <ipaddr>
-#define OPT_PARAMETER_LIST   55    // n <optcode> * n
-#define OPT_MESSAGE          56    // n <errorstring>
-#define OPT_T1               58    // 4 <renewal time value>
-#define OPT_T2               59    // 4 <rebinding time value>
-#define OPT_CLASS_ID         60    // n <opaque>
-#define OPT_CLIENT_ID        61    // n <opaque>
-#define OPT_END              255
-
-// DHCP message types
-#define DHCPDISCOVER         1
-#define DHCPOFFER            2
-#define DHCPREQUEST          3
-#define DHCPDECLINE          4
-#define DHCPACK              5
-#define DHCPNAK              6
-#define DHCPRELEASE          7
-#define DHCPINFORM           8
-
-
diff --git a/dhcp/common/include/message.h b/dhcp/common/include/message.h
deleted file mode 100644
index 84029cc0..00000000
--- a/dhcp/common/include/message.h
+++ /dev/null
@@ -1,131 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-#pragma once
-
-#include <linux/if_ether.h>
-#include <netinet/in.h>
-#include <stddef.h>
-#include <string.h>
-
-#include <initializer_list>
-
-class Message {
-public:
-    Message();
-    Message(const uint8_t* data, size_t size);
-    static Message discover(const uint8_t (&sourceMac)[ETH_ALEN]);
-    static Message request(const uint8_t (&sourceMac)[ETH_ALEN],
-                           in_addr_t requestAddress,
-                           in_addr_t serverAddress);
-    static Message offer(const Message& sourceMessage,
-                         in_addr_t serverAddress,
-                         in_addr_t offeredAddress,
-                         in_addr_t offeredNetmask,
-                         in_addr_t offeredGateway,
-                         const in_addr_t* offeredDnsServers,
-                         size_t numOfferedDnsServers);
-    static Message ack(const Message& sourceMessage,
-                       in_addr_t serverAddress,
-                       in_addr_t offeredAddress,
-                       in_addr_t offeredNetmask,
-                       in_addr_t offeredGateway,
-                       const in_addr_t* offeredDnsServers,
-                       size_t numOfferedDnsServers);
-    static Message nack(const Message& sourceMessage, in_addr_t serverAddress);
-
-    // Ensure that the data in the message represent a valid DHCP message
-    bool isValidDhcpMessage(uint8_t expectedOp) const;
-    // Ensure that the data in the message represent a valid DHCP message and
-    // has a xid (transaction ID) that matches |expectedXid|.
-    bool isValidDhcpMessage(uint8_t expectedOp, uint32_t expectedXid) const;
-
-    const uint8_t* data() const {
-        return reinterpret_cast<const uint8_t*>(&dhcpData);
-    }
-    uint8_t* data() {
-        return reinterpret_cast<uint8_t*>(&dhcpData);
-    }
-    const uint8_t* end() const { return data() + mSize; }
-
-    size_t optionsSize() const;
-    size_t size() const { return mSize; }
-    void setSize(size_t size) { mSize = size; }
-    size_t capacity() const { return sizeof(dhcpData); }
-
-    // Get the DHCP message type
-    uint8_t type() const;
-    // Get the DHCP server ID
-    in_addr_t serverId() const;
-    // Get the requested IP
-    in_addr_t requestedIp() const;
-
-    struct Dhcp {
-        uint8_t op;           /* BOOTREQUEST / BOOTREPLY    */
-        uint8_t htype;        /* hw addr type               */
-        uint8_t hlen;         /* hw addr len                */
-        uint8_t hops;         /* client set to 0            */
-
-        uint32_t xid;         /* transaction id             */
-
-        uint16_t secs;        /* seconds since start of acq */
-        uint16_t flags;
-
-        uint32_t ciaddr;      /* client IP addr             */
-        uint32_t yiaddr;      /* your (client) IP addr      */
-        uint32_t siaddr;      /* ip addr of next server     */
-                              /* (DHCPOFFER and DHCPACK)    */
-        uint32_t giaddr;      /* relay agent IP addr        */
-
-        uint8_t chaddr[16];  /* client hw addr             */
-        char sname[64];      /* asciiz server hostname     */
-        char file[128];      /* asciiz boot file name      */
-
-        uint8_t options[1024];  /* optional parameters        */
-    }  dhcpData;
-private:
-    Message(uint8_t operation,
-            const uint8_t (&macAddress)[ETH_ALEN],
-            uint8_t type);
-
-    void addOption(uint8_t type, const void* data, uint8_t size);
-    template<typename T>
-    void addOption(uint8_t type, T data) {
-        static_assert(sizeof(T) <= 255, "The size of data is too large");
-        addOption(type, &data, sizeof(data));
-    }
-    template<typename T, size_t N>
-    void addOption(uint8_t type, T (&items)[N]) {
-        static_assert(sizeof(T) * N <= 255,
-                      "The size of data is too large");
-        uint8_t* opts = nextOption();
-        *opts++ = type;
-        *opts++ = sizeof(T) * N;
-        for (const T& item : items) {
-            memcpy(opts, &item, sizeof(item));
-            opts += sizeof(item);
-        }
-        updateSize(opts);
-    }
-    void endOptions();
-
-    const uint8_t* getOption(uint8_t optCode, uint8_t* length) const;
-    uint8_t* nextOption();
-    void updateSize(uint8_t* optionsEnd);
-    size_t mSize;
-};
-
-static_assert(offsetof(Message::Dhcp, htype) == sizeof(Message::Dhcp::op),
-              "Invalid packing for DHCP message struct");
diff --git a/dhcp/common/include/result.h b/dhcp/common/include/result.h
deleted file mode 100644
index 5087e146..00000000
--- a/dhcp/common/include/result.h
+++ /dev/null
@@ -1,54 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
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
-#pragma once
-
-#include <stdio.h>
-#include <stdarg.h>
-
-#include <string>
-
-class Result {
-public:
-    static Result success() {
-        return Result(true);
-    }
-    // Construct a result indicating an error.
-    static Result error(std::string message) {
-        return Result(message);
-    }
-    static Result error(const char* format, ...) {
-        char buffer[1024];
-        va_list args;
-        va_start(args, format);
-        vsnprintf(buffer, sizeof(buffer), format, args);
-        va_end(args);
-        buffer[sizeof(buffer) - 1] = '\0';
-        return Result(std::string(buffer));
-    }
-
-    bool isSuccess() const { return mSuccess; }
-    bool operator!() const { return !mSuccess; }
-
-    const char* c_str() const { return mMessage.c_str(); }
-private:
-    explicit Result(bool success) : mSuccess(success) { }
-    explicit Result(std::string message)
-        : mMessage(message), mSuccess(false) {
-    }
-    std::string mMessage;
-    bool mSuccess;
-};
-
diff --git a/dhcp/common/include/socket.h b/dhcp/common/include/socket.h
deleted file mode 100644
index 0c9483c2..00000000
--- a/dhcp/common/include/socket.h
+++ /dev/null
@@ -1,78 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#pragma once
-
-#include "result.h"
-
-#include <arpa/inet.h>
-
-class Message;
-
-class Socket {
-public:
-    Socket();
-    Socket(const Socket&) = delete;
-    ~Socket();
-
-    Socket& operator=(const Socket&) = delete;
-
-    int get() const { return mSocketFd; }
-    // Open a socket, |domain|, |type| and |protocol| are as described in the
-    // man pages for socket.
-    Result open(int domain, int type, int protocol);
-    // Bind to a generic |sockaddr| of size |sockaddrLength|
-    Result bind(const void* sockaddr, size_t sockaddrLength);
-    // Bind to an IP |address| and |port|
-    Result bindIp(in_addr_t address, uint16_t port);
-    // Bind a raw socket to the interface with index |interfaceIndex|.
-    Result bindRaw(unsigned int interfaceIndex);
-    // Send data in |message| on an IP socket to
-    // |destinationAddress|:|destinationPort|, the message will egress on the
-    // interface specified by |interfaceIndex|
-    Result sendOnInterface(unsigned int interfaceIndex,
-                           in_addr_t destinationAddress,
-                           uint16_t destinationPort,
-                           const Message& message);
-    // Send |message| as a UDP datagram on a raw socket. The source address of
-    // the message will be |source|:|sourcePort| and the destination will be
-    // |destination|:|destinationPort|. The message will be sent on the
-    // interface indicated by |interfaceIndex|.
-    Result sendRawUdp(in_addr_t source,
-                      uint16_t sourcePort,
-                      in_addr_t destination,
-                      uint16_t destinationPort,
-                      unsigned int interfaceIndex,
-                      const Message& message);
-    // Receive data on the socket and indicate which interface the data was
-    // received on in |interfaceIndex|. The received data is placed in |message|
-    Result receiveFromInterface(Message* message, unsigned int* interfaceIndex);
-    // Receive UDP data on a raw socket. Expect that the protocol in the IP
-    // header is UDP and that the port in the UDP header is |expectedPort|. If
-    // the received data is valid then |isValid| will be set to true, otherwise
-    // false. The validity check includes the expected values as well as basic
-    // size requirements to fit the expected protocol headers.  The method will
-    // only return an error result if the actual receiving fails.
-    Result receiveRawUdp(uint16_t expectedPort,
-                         Message* message,
-                         bool* isValid);
-    // Enable |optionName| on option |level|. These values are the same as used
-    // in setsockopt calls.
-    Result enableOption(int level, int optionName);
-private:
-    int mSocketFd;
-};
-
diff --git a/dhcp/common/include/utils.h b/dhcp/common/include/utils.h
deleted file mode 100644
index 5f4b971f..00000000
--- a/dhcp/common/include/utils.h
+++ /dev/null
@@ -1,24 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#pragma once
-
-#include <arpa/inet.h>
-
-#include <string>
-
-std::string addrToStr(in_addr_t address);
-
diff --git a/dhcp/common/message.cpp b/dhcp/common/message.cpp
deleted file mode 100644
index 64a29384..00000000
--- a/dhcp/common/message.cpp
+++ /dev/null
@@ -1,312 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "message.h"
-#include "dhcp.h"
-
-#include <string.h>
-
-#include <vector>
-
-static uint32_t sNextTransactionId = 1;
-
-// The default lease time in seconds
-static const uint32_t kDefaultLeaseTime = 10 * 60;
-
-// The parameters that the client would like to receive from the server
-static const uint8_t kRequestParameters[] = { OPT_SUBNET_MASK,
-                                              OPT_GATEWAY,
-                                              OPT_DNS,
-                                              OPT_BROADCAST_ADDR,
-                                              OPT_LEASE_TIME,
-                                              OPT_T1,
-                                              OPT_T2,
-                                              OPT_MTU };
-
-Message::Message() {
-    memset(&dhcpData, 0, sizeof(dhcpData));
-    mSize = 0;
-}
-
-Message::Message(const uint8_t* data, size_t size) {
-    if (size <= sizeof(dhcpData)) {
-        memcpy(&dhcpData, data, size);
-        mSize = size;
-    } else {
-        memset(&dhcpData, 0, sizeof(dhcpData));
-        mSize = 0;
-    }
-}
-
-Message Message::discover(const uint8_t (&sourceMac)[ETH_ALEN]) {
-    Message message(OP_BOOTREQUEST,
-                    sourceMac,
-                    static_cast<uint8_t>(DHCPDISCOVER));
-
-    message.addOption(OPT_PARAMETER_LIST, kRequestParameters);
-    message.endOptions();
-
-    return message;
-}
-
-Message Message::request(const uint8_t (&sourceMac)[ETH_ALEN],
-                         in_addr_t requestAddress,
-                         in_addr_t serverAddress) {
-
-    Message message(OP_BOOTREQUEST,
-                    sourceMac,
-                    static_cast<uint8_t>(DHCPREQUEST));
-
-    message.addOption(OPT_PARAMETER_LIST, kRequestParameters);
-    message.addOption(OPT_REQUESTED_IP, requestAddress);
-    message.addOption(OPT_SERVER_ID, serverAddress);
-    message.endOptions();
-
-    return message;
-}
-
-Message Message::offer(const Message& sourceMessage,
-                       in_addr_t serverAddress,
-                       in_addr_t offeredAddress,
-                       in_addr_t offeredNetmask,
-                       in_addr_t offeredGateway,
-                       const in_addr_t* offeredDnsServers,
-                       size_t numOfferedDnsServers) {
-
-    uint8_t macAddress[ETH_ALEN];
-    memcpy(macAddress, sourceMessage.dhcpData.chaddr, sizeof(macAddress));
-    Message message(OP_BOOTREPLY, macAddress, static_cast<uint8_t>(DHCPOFFER));
-
-    message.dhcpData.xid = sourceMessage.dhcpData.xid;
-    message.dhcpData.flags = sourceMessage.dhcpData.flags;
-    message.dhcpData.yiaddr = offeredAddress;
-    message.dhcpData.giaddr = sourceMessage.dhcpData.giaddr;
-
-    message.addOption(OPT_SERVER_ID, serverAddress);
-    message.addOption(OPT_LEASE_TIME, kDefaultLeaseTime);
-    message.addOption(OPT_SUBNET_MASK, offeredNetmask);
-    message.addOption(OPT_GATEWAY, offeredGateway);
-    message.addOption(OPT_DNS,
-                      offeredDnsServers,
-                      numOfferedDnsServers * sizeof(in_addr_t));
-
-    message.endOptions();
-
-    return message;
-}
-
-Message Message::ack(const Message& sourceMessage,
-                     in_addr_t serverAddress,
-                     in_addr_t offeredAddress,
-                     in_addr_t offeredNetmask,
-                     in_addr_t offeredGateway,
-                     const in_addr_t* offeredDnsServers,
-                     size_t numOfferedDnsServers) {
-    uint8_t macAddress[ETH_ALEN];
-    memcpy(macAddress, sourceMessage.dhcpData.chaddr, sizeof(macAddress));
-    Message message(OP_BOOTREPLY, macAddress, static_cast<uint8_t>(DHCPACK));
-
-    message.dhcpData.xid = sourceMessage.dhcpData.xid;
-    message.dhcpData.flags = sourceMessage.dhcpData.flags;
-    message.dhcpData.yiaddr = offeredAddress;
-    message.dhcpData.giaddr = sourceMessage.dhcpData.giaddr;
-
-    message.addOption(OPT_SERVER_ID, serverAddress);
-    message.addOption(OPT_LEASE_TIME, kDefaultLeaseTime);
-    message.addOption(OPT_SUBNET_MASK, offeredNetmask);
-    message.addOption(OPT_GATEWAY, offeredGateway);
-    message.addOption(OPT_DNS,
-                      offeredDnsServers,
-                      numOfferedDnsServers * sizeof(in_addr_t));
-
-    message.endOptions();
-
-    return message;
-}
-
-Message Message::nack(const Message& sourceMessage, in_addr_t serverAddress) {
-    uint8_t macAddress[ETH_ALEN];
-    memcpy(macAddress, sourceMessage.dhcpData.chaddr, sizeof(macAddress));
-    Message message(OP_BOOTREPLY, macAddress, static_cast<uint8_t>(DHCPNAK));
-
-    message.dhcpData.xid = sourceMessage.dhcpData.xid;
-    message.dhcpData.flags = sourceMessage.dhcpData.flags;
-    message.dhcpData.giaddr = sourceMessage.dhcpData.giaddr;
-
-    message.addOption(OPT_SERVER_ID, serverAddress);
-    message.endOptions();
-
-    return message;
-}
-
-bool Message::isValidDhcpMessage(uint8_t expectedOp,
-                                 uint32_t expectedXid) const {
-    if (!isValidDhcpMessage(expectedOp)) {
-        return false;
-    }
-    // Only look for message with a matching transaction ID
-    if (dhcpData.xid != expectedXid) {
-        return false;
-    }
-    return true;
-}
-
-bool Message::isValidDhcpMessage(uint8_t expectedOp) const {
-    // Require that there is at least enough options for the DHCP cookie
-    if (dhcpData.options + 4 > end()) {
-        return false;
-    }
-
-    if (dhcpData.op != expectedOp) {
-        return false;
-    }
-    if (dhcpData.htype != HTYPE_ETHER) {
-        return false;
-    }
-    if (dhcpData.hlen != ETH_ALEN) {
-        return false;
-    }
-
-    // Need to have the correct cookie in the options
-    if (dhcpData.options[0] != OPT_COOKIE1) {
-        return false;
-    }
-    if (dhcpData.options[1] != OPT_COOKIE2) {
-        return false;
-    }
-    if (dhcpData.options[2] != OPT_COOKIE3) {
-        return false;
-    }
-    if (dhcpData.options[3] != OPT_COOKIE4) {
-        return false;
-    }
-
-    return true;
-}
-
-size_t Message::optionsSize() const {
-    auto options = reinterpret_cast<const uint8_t*>(&dhcpData.options);
-    const uint8_t* msgEnd = end();
-    if (msgEnd <= options) {
-        return 0;
-    }
-    return msgEnd - options;
-}
-
-uint8_t Message::type() const {
-    uint8_t length = 0;
-    const uint8_t* opt = getOption(OPT_MESSAGE_TYPE, &length);
-    if (opt && length == 1) {
-        return *opt;
-    }
-    return 0;
-}
-
-in_addr_t Message::serverId() const {
-    uint8_t length = 0;
-    const uint8_t* opt = getOption(OPT_SERVER_ID, &length);
-    if (opt && length == 4) {
-        return *reinterpret_cast<const in_addr_t*>(opt);
-    }
-    return 0;
-}
-
-in_addr_t Message::requestedIp() const {
-    uint8_t length = 0;
-    const uint8_t* opt = getOption(OPT_REQUESTED_IP, &length);
-    if (opt && length == 4) {
-        return *reinterpret_cast<const in_addr_t*>(opt);
-    }
-    return 0;
-}
-
-Message::Message(uint8_t operation,
-                 const uint8_t (&macAddress)[ETH_ALEN],
-                 uint8_t type) {
-    memset(&dhcpData, 0, sizeof(dhcpData));
-
-    dhcpData.op = operation;
-    dhcpData.htype = HTYPE_ETHER;
-    dhcpData.hlen = ETH_ALEN;
-    dhcpData.hops = 0;
-
-    dhcpData.flags = htons(FLAGS_BROADCAST);
-
-    dhcpData.xid = htonl(sNextTransactionId++);
-
-    memcpy(dhcpData.chaddr, macAddress, ETH_ALEN);
-
-    uint8_t* opts = dhcpData.options;
-
-    *opts++ = OPT_COOKIE1;
-    *opts++ = OPT_COOKIE2;
-    *opts++ = OPT_COOKIE3;
-    *opts++ = OPT_COOKIE4;
-
-    *opts++ = OPT_MESSAGE_TYPE;
-    *opts++ = 1;
-    *opts++ = type;
-
-    updateSize(opts);
-}
-
-void Message::addOption(uint8_t type, const void* data, uint8_t size) {
-    uint8_t* opts = nextOption();
-
-    *opts++ = type;
-    *opts++ = size;
-    memcpy(opts, data, size);
-    opts += size;
-
-    updateSize(opts);
-}
-
-void Message::endOptions() {
-    uint8_t* opts = nextOption();
-
-    *opts++ = OPT_END;
-
-    updateSize(opts);
-}
-
-const uint8_t* Message::getOption(uint8_t expectedOptCode,
-                                  uint8_t* length) const {
-    size_t optsSize = optionsSize();
-    for (size_t i = 4; i + 2 < optsSize; ) {
-        uint8_t optCode = dhcpData.options[i];
-        uint8_t optLen = dhcpData.options[i + 1];
-        const uint8_t* opt = dhcpData.options + i + 2;
-
-        if (optCode == OPT_END) {
-            return nullptr;
-        }
-        if (optCode == expectedOptCode) {
-            *length = optLen;
-            return opt;
-        }
-        i += 2 + optLen;
-    }
-    return nullptr;
-}
-
-uint8_t* Message::nextOption() {
-    return reinterpret_cast<uint8_t*>(&dhcpData) + size();
-}
-
-void Message::updateSize(uint8_t* optionsEnd) {
-    mSize = optionsEnd - reinterpret_cast<uint8_t*>(&dhcpData);
-}
-
diff --git a/dhcp/common/socket.cpp b/dhcp/common/socket.cpp
deleted file mode 100644
index 8fd7b9f3..00000000
--- a/dhcp/common/socket.cpp
+++ /dev/null
@@ -1,315 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "socket.h"
-
-#include "message.h"
-#include "utils.h"
-
-#include <errno.h>
-#include <linux/if_packet.h>
-#include <netinet/ip.h>
-#include <netinet/udp.h>
-#include <string.h>
-#include <sys/socket.h>
-#include <sys/types.h>
-#include <sys/uio.h>
-#include <unistd.h>
-
-// Combine the checksum of |buffer| with |size| bytes with |checksum|. This is
-// used for checksum calculations for IP and UDP.
-static uint32_t addChecksum(const uint8_t* buffer,
-                            size_t size,
-                            uint32_t checksum) {
-    const uint16_t* data = reinterpret_cast<const uint16_t*>(buffer);
-    while (size > 1) {
-        checksum += *data++;
-        size -= 2;
-    }
-    if (size > 0) {
-        // Odd size, add the last byte
-        checksum += *reinterpret_cast<const uint8_t*>(data);
-    }
-    // msw is the most significant word, the upper 16 bits of the checksum
-    for (uint32_t msw = checksum >> 16; msw != 0; msw = checksum >> 16) {
-        checksum = (checksum & 0xFFFF) + msw;
-    }
-    return checksum;
-}
-
-// Convenienct template function for checksum calculation
-template<typename T>
-static uint32_t addChecksum(const T& data, uint32_t checksum) {
-    return addChecksum(reinterpret_cast<const uint8_t*>(&data), sizeof(T), checksum);
-}
-
-// Finalize the IP or UDP |checksum| by inverting and truncating it.
-static uint32_t finishChecksum(uint32_t checksum) {
-    return ~checksum & 0xFFFF;
-}
-
-Socket::Socket() : mSocketFd(-1) {
-}
-
-Socket::~Socket() {
-    if (mSocketFd != -1) {
-        ::close(mSocketFd);
-        mSocketFd = -1;
-    }
-}
-
-
-Result Socket::open(int domain, int type, int protocol) {
-    if (mSocketFd != -1) {
-        return Result::error("Socket already open");
-    }
-    mSocketFd = ::socket(domain, type, protocol);
-    if (mSocketFd == -1) {
-        return Result::error("Failed to open socket: %s", strerror(errno));
-    }
-    return Result::success();
-}
-
-Result Socket::bind(const void* sockaddr, size_t sockaddrLength) {
-    if (mSocketFd == -1) {
-        return Result::error("Socket not open");
-    }
-
-    int status = ::bind(mSocketFd,
-                        reinterpret_cast<const struct sockaddr*>(sockaddr),
-                        sockaddrLength);
-    if (status != 0) {
-        return Result::error("Unable to bind raw socket: %s", strerror(errno));
-    }
-
-    return Result::success();
-}
-
-Result Socket::bindIp(in_addr_t address, uint16_t port) {
-    struct sockaddr_in sockaddr;
-    memset(&sockaddr, 0, sizeof(sockaddr));
-    sockaddr.sin_family = AF_INET;
-    sockaddr.sin_port = htons(port);
-    sockaddr.sin_addr.s_addr = address;
-
-    return bind(&sockaddr, sizeof(sockaddr));
-}
-
-Result Socket::bindRaw(unsigned int interfaceIndex) {
-    struct sockaddr_ll sockaddr;
-    memset(&sockaddr, 0, sizeof(sockaddr));
-    sockaddr.sll_family = AF_PACKET;
-    sockaddr.sll_protocol = htons(ETH_P_IP);
-    sockaddr.sll_ifindex = interfaceIndex;
-
-    return bind(&sockaddr, sizeof(sockaddr));
-}
-
-Result Socket::sendOnInterface(unsigned int interfaceIndex,
-                               in_addr_t destinationAddress,
-                               uint16_t destinationPort,
-                               const Message& message) {
-    if (mSocketFd == -1) {
-        return Result::error("Socket not open");
-    }
-
-    char controlData[CMSG_SPACE(sizeof(struct in_pktinfo))] = { 0 };
-    struct sockaddr_in addr;
-    memset(&addr, 0, sizeof(addr));
-    addr.sin_family = AF_INET;
-    addr.sin_port = htons(destinationPort);
-    addr.sin_addr.s_addr = destinationAddress;
-
-    struct msghdr header;
-    memset(&header, 0, sizeof(header));
-    struct iovec iov;
-    // The struct member is non-const since it's used for receiving but it's
-    // safe to cast away const for sending.
-    iov.iov_base = const_cast<uint8_t*>(message.data());
-    iov.iov_len = message.size();
-    header.msg_name = &addr;
-    header.msg_namelen = sizeof(addr);
-    header.msg_iov = &iov;
-    header.msg_iovlen = 1;
-    header.msg_control = &controlData;
-    header.msg_controllen = sizeof(controlData);
-
-    struct cmsghdr* controlHeader = CMSG_FIRSTHDR(&header);
-    controlHeader->cmsg_level = IPPROTO_IP;
-    controlHeader->cmsg_type = IP_PKTINFO;
-    controlHeader->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
-    auto packetInfo =
-        reinterpret_cast<struct in_pktinfo*>(CMSG_DATA(controlHeader));
-    memset(packetInfo, 0, sizeof(*packetInfo));
-    packetInfo->ipi_ifindex = interfaceIndex;
-
-    ssize_t status = ::sendmsg(mSocketFd, &header, 0);
-    if (status <= 0) {
-        return Result::error("Failed to send packet: %s", strerror(errno));
-    }
-    return Result::success();
-}
-
-Result Socket::sendRawUdp(in_addr_t source,
-                          uint16_t sourcePort,
-                          in_addr_t destination,
-                          uint16_t destinationPort,
-                          unsigned int interfaceIndex,
-                          const Message& message) {
-    struct iphdr ip;
-    struct udphdr udp;
-
-    ip.version = IPVERSION;
-    ip.ihl = sizeof(ip) >> 2;
-    ip.tos = 0;
-    ip.tot_len = htons(sizeof(ip) + sizeof(udp) + message.size());
-    ip.id = 0;
-    ip.frag_off = 0;
-    ip.ttl = IPDEFTTL;
-    ip.protocol = IPPROTO_UDP;
-    ip.check = 0;
-    ip.saddr = source;
-    ip.daddr = destination;
-    ip.check = finishChecksum(addChecksum(ip, 0));
-
-    udp.source = htons(sourcePort);
-    udp.dest = htons(destinationPort);
-    udp.len = htons(sizeof(udp) + message.size());
-    udp.check = 0;
-
-    uint32_t udpChecksum = 0;
-    udpChecksum = addChecksum(ip.saddr, udpChecksum);
-    udpChecksum = addChecksum(ip.daddr, udpChecksum);
-    udpChecksum = addChecksum(htons(IPPROTO_UDP), udpChecksum);
-    udpChecksum = addChecksum(udp.len, udpChecksum);
-    udpChecksum = addChecksum(udp, udpChecksum);
-    udpChecksum = addChecksum(message.data(), message.size(), udpChecksum);
-    udp.check = finishChecksum(udpChecksum);
-
-    struct iovec iov[3];
-
-    iov[0].iov_base = static_cast<void*>(&ip);
-    iov[0].iov_len = sizeof(ip);
-    iov[1].iov_base = static_cast<void*>(&udp);
-    iov[1].iov_len = sizeof(udp);
-    // sendmsg requires these to be non-const but for sending won't modify them
-    iov[2].iov_base = static_cast<void*>(const_cast<uint8_t*>(message.data()));
-    iov[2].iov_len = message.size();
-
-    struct sockaddr_ll dest;
-    memset(&dest, 0, sizeof(dest));
-    dest.sll_family = AF_PACKET;
-    dest.sll_protocol = htons(ETH_P_IP);
-    dest.sll_ifindex = interfaceIndex;
-    dest.sll_halen = ETH_ALEN;
-    memset(dest.sll_addr, 0xFF, ETH_ALEN);
-
-    struct msghdr header;
-    memset(&header, 0, sizeof(header));
-    header.msg_name = &dest;
-    header.msg_namelen = sizeof(dest);
-    header.msg_iov = iov;
-    header.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
-
-    ssize_t res = ::sendmsg(mSocketFd, &header, 0);
-    if (res == -1) {
-        return Result::error("Failed to send message: %s", strerror(errno));
-    }
-    return Result::success();
-}
-
-Result Socket::receiveFromInterface(Message* message,
-                                    unsigned int* interfaceIndex) {
-    char controlData[CMSG_SPACE(sizeof(struct in_pktinfo))];
-    struct msghdr header;
-    memset(&header, 0, sizeof(header));
-    struct iovec iov;
-    iov.iov_base = message->data();
-    iov.iov_len = message->capacity();
-    header.msg_iov = &iov;
-    header.msg_iovlen = 1;
-    header.msg_control = &controlData;
-    header.msg_controllen = sizeof(controlData);
-
-    ssize_t bytesRead = ::recvmsg(mSocketFd, &header, 0);
-    if (bytesRead < 0) {
-        return Result::error("Error receiving on socket: %s", strerror(errno));
-    }
-    message->setSize(static_cast<size_t>(bytesRead));
-    if (header.msg_controllen >= sizeof(struct cmsghdr)) {
-        for (struct cmsghdr* ctrl = CMSG_FIRSTHDR(&header);
-             ctrl;
-             ctrl = CMSG_NXTHDR(&header, ctrl)) {
-            if (ctrl->cmsg_level == SOL_IP &&
-                ctrl->cmsg_type == IP_PKTINFO) {
-                auto packetInfo =
-                    reinterpret_cast<struct in_pktinfo*>(CMSG_DATA(ctrl));
-                *interfaceIndex = packetInfo->ipi_ifindex;
-            }
-        }
-    }
-    return Result::success();
-}
-
-Result Socket::receiveRawUdp(uint16_t expectedPort,
-                             Message* message,
-                             bool* isValid) {
-    struct iphdr ip;
-    struct udphdr udp;
-
-    struct iovec iov[3];
-    iov[0].iov_base = &ip;
-    iov[0].iov_len = sizeof(ip);
-    iov[1].iov_base = &udp;
-    iov[1].iov_len = sizeof(udp);
-    iov[2].iov_base = message->data();
-    iov[2].iov_len = message->capacity();
-
-    ssize_t bytesRead = ::readv(mSocketFd, iov, 3);
-    if (bytesRead < 0) {
-        return Result::error("Unable to read from socket: %s", strerror(errno));
-    }
-    if (static_cast<size_t>(bytesRead) < sizeof(ip) + sizeof(udp)) {
-        // Not enough bytes to even cover IP and UDP headers
-        *isValid = false;
-        return Result::success();
-    }
-    *isValid = ip.version == IPVERSION &&
-               ip.ihl == (sizeof(ip) >> 2) &&
-               ip.protocol == IPPROTO_UDP &&
-               udp.dest == htons(expectedPort);
-
-    message->setSize(bytesRead - sizeof(ip) - sizeof(udp));
-    return Result::success();
-}
-
-Result Socket::enableOption(int level, int optionName) {
-    if (mSocketFd == -1) {
-        return Result::error("Socket not open");
-    }
-
-    int enabled = 1;
-    int status = ::setsockopt(mSocketFd,
-                              level,
-                              optionName,
-                              &enabled,
-                              sizeof(enabled));
-    if (status == -1) {
-        return Result::error("Failed to set socket option: %s",
-                             strerror(errno));
-    }
-    return Result::success();
-}
diff --git a/dhcp/common/utils.cpp b/dhcp/common/utils.cpp
deleted file mode 100644
index e4a37f32..00000000
--- a/dhcp/common/utils.cpp
+++ /dev/null
@@ -1,26 +0,0 @@
-/*
- * Copyright 2017, The Android Open Source Project
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
-
-#include "utils.h"
-
-std::string addrToStr(in_addr_t address) {
-    char buffer[INET_ADDRSTRLEN];
-    if (::inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
-        return "[unknown]";
-    }
-    return buffer;
-}
-
diff --git a/fvpbase/OWNERS b/fvpbase/OWNERS
new file mode 100644
index 00000000..daa9686e
--- /dev/null
+++ b/fvpbase/OWNERS
@@ -0,0 +1 @@
+pcc@google.com
diff --git a/audio/Android.bp b/hals/audio/Android.bp
similarity index 93%
rename from audio/Android.bp
rename to hals/audio/Android.bp
index 1145c6ee..4d3d869d 100644
--- a/audio/Android.bp
+++ b/hals/audio/Android.bp
@@ -82,10 +82,16 @@ cc_library_shared {
     vendor: true,
 }
 
+vintf_fragment {
+    name: "android.hardware.audio@7.1-impl.ranchu.xml",
+    src: "android.hardware.audio@7.1-impl.ranchu.xml",
+    vendor: true,
+}
+
 cc_library_shared {
     name: "android.hardware.audio@7.1-impl.ranchu",
     defaults: ["android.hardware.audio@7.x-impl.ranchu_default"],
-    vintf_fragments: ["android.hardware.audio@7.1-impl.ranchu.xml"],
+    vintf_fragment_modules: ["android.hardware.audio@7.1-impl.ranchu.xml"],
     shared_libs: [
         "android.hardware.audio@7.1",
         "android.hardware.audio.common@7.1-enums",
diff --git a/audio/MODULE_LICENSE_APACHE2 b/hals/audio/MODULE_LICENSE_APACHE2
similarity index 100%
rename from audio/MODULE_LICENSE_APACHE2
rename to hals/audio/MODULE_LICENSE_APACHE2
diff --git a/audio/NOTICE b/hals/audio/NOTICE
similarity index 100%
rename from audio/NOTICE
rename to hals/audio/NOTICE
diff --git a/audio/android.hardware.audio.effects@7.0.xml b/hals/audio/android.hardware.audio.effects@7.0.xml
similarity index 100%
rename from audio/android.hardware.audio.effects@7.0.xml
rename to hals/audio/android.hardware.audio.effects@7.0.xml
diff --git a/audio/android.hardware.audio@7.0-impl.ranchu.xml b/hals/audio/android.hardware.audio@7.0-impl.ranchu.xml
similarity index 100%
rename from audio/android.hardware.audio@7.0-impl.ranchu.xml
rename to hals/audio/android.hardware.audio@7.0-impl.ranchu.xml
diff --git a/audio/android.hardware.audio@7.1-impl.ranchu.xml b/hals/audio/android.hardware.audio@7.1-impl.ranchu.xml
similarity index 100%
rename from audio/android.hardware.audio@7.1-impl.ranchu.xml
rename to hals/audio/android.hardware.audio@7.1-impl.ranchu.xml
diff --git a/audio/audio_ops.cpp b/hals/audio/audio_ops.cpp
similarity index 100%
rename from audio/audio_ops.cpp
rename to hals/audio/audio_ops.cpp
diff --git a/audio/audio_ops.h b/hals/audio/audio_ops.h
similarity index 100%
rename from audio/audio_ops.h
rename to hals/audio/audio_ops.h
diff --git a/audio/deleters.h b/hals/audio/deleters.h
similarity index 100%
rename from audio/deleters.h
rename to hals/audio/deleters.h
diff --git a/audio/device_factory.cpp b/hals/audio/device_factory.cpp
similarity index 100%
rename from audio/device_factory.cpp
rename to hals/audio/device_factory.cpp
diff --git a/audio/device_factory.h b/hals/audio/device_factory.h
similarity index 100%
rename from audio/device_factory.h
rename to hals/audio/device_factory.h
diff --git a/audio/device_port_sink.cpp b/hals/audio/device_port_sink.cpp
similarity index 98%
rename from audio/device_port_sink.cpp
rename to hals/audio/device_port_sink.cpp
index c4295c29..2f022d7a 100644
--- a/audio/device_port_sink.cpp
+++ b/hals/audio/device_port_sink.cpp
@@ -71,7 +71,12 @@ struct TinyalsaSink : public DevicePortSink {
 
     ~TinyalsaSink() {
         mConsumeThreadRunning = false;
+        ALOGD("%s: joining consumeThread", __func__);
         mConsumeThread.join();
+        if (mPcm) {
+            ALOGD("%s: stopping PCM stream", __func__);
+            LOG_ALWAYS_FATAL_IF(pcm_stop(mPcm.get()) != 0);
+        }
     }
 
     static int getLatencyMs(const AudioConfig &cfg) {
@@ -223,6 +228,7 @@ struct TinyalsaSink : public DevicePortSink {
                 }
             }
         }
+        ALOGD("%s: exiting", __func__);
     }
 
     static std::unique_ptr<TinyalsaSink> create(unsigned pcmCard,
diff --git a/audio/device_port_sink.h b/hals/audio/device_port_sink.h
similarity index 100%
rename from audio/device_port_sink.h
rename to hals/audio/device_port_sink.h
diff --git a/audio/device_port_source.cpp b/hals/audio/device_port_source.cpp
similarity index 98%
rename from audio/device_port_source.cpp
rename to hals/audio/device_port_source.cpp
index 79582dc1..1a98a0fb 100644
--- a/audio/device_port_source.cpp
+++ b/hals/audio/device_port_source.cpp
@@ -73,7 +73,12 @@ struct TinyalsaSource : public DevicePortSource {
 
     ~TinyalsaSource() {
         mProduceThreadRunning = false;
+        ALOGD("%s: joining producerThread", __func__);
         mProduceThread.join();
+        if (mPcm) {
+            ALOGD("%s: stopping PCM stream", __func__);
+            LOG_ALWAYS_FATAL_IF(pcm_stop(mPcm.get()) != 0);
+        }
     }
 
     Result getCapturePosition(uint64_t &frames, uint64_t &time) override {
@@ -182,6 +187,7 @@ struct TinyalsaSource : public DevicePortSource {
                 }
             }
         }
+        ALOGD("%s: exiting", __func__);
     }
 
     size_t doRead(void *dst, size_t sz) {
diff --git a/audio/device_port_source.h b/hals/audio/device_port_source.h
similarity index 100%
rename from audio/device_port_source.h
rename to hals/audio/device_port_source.h
diff --git a/audio/entry.cpp b/hals/audio/entry.cpp
similarity index 100%
rename from audio/entry.cpp
rename to hals/audio/entry.cpp
diff --git a/audio/io_thread.cpp b/hals/audio/io_thread.cpp
similarity index 100%
rename from audio/io_thread.cpp
rename to hals/audio/io_thread.cpp
diff --git a/audio/io_thread.h b/hals/audio/io_thread.h
similarity index 100%
rename from audio/io_thread.h
rename to hals/audio/io_thread.h
diff --git a/audio/ireader.h b/hals/audio/ireader.h
similarity index 100%
rename from audio/ireader.h
rename to hals/audio/ireader.h
diff --git a/audio/iwriter.h b/hals/audio/iwriter.h
similarity index 100%
rename from audio/iwriter.h
rename to hals/audio/iwriter.h
diff --git a/audio/policy/audio_policy_configuration.xml b/hals/audio/policy/audio_policy_configuration.xml
similarity index 100%
rename from audio/policy/audio_policy_configuration.xml
rename to hals/audio/policy/audio_policy_configuration.xml
diff --git a/audio/policy/primary_audio_policy_configuration.xml b/hals/audio/policy/primary_audio_policy_configuration.xml
similarity index 100%
rename from audio/policy/primary_audio_policy_configuration.xml
rename to hals/audio/policy/primary_audio_policy_configuration.xml
diff --git a/audio/primary_device.cpp b/hals/audio/primary_device.cpp
similarity index 100%
rename from audio/primary_device.cpp
rename to hals/audio/primary_device.cpp
diff --git a/audio/primary_device.h b/hals/audio/primary_device.h
similarity index 100%
rename from audio/primary_device.h
rename to hals/audio/primary_device.h
diff --git a/audio/ring_buffer.cpp b/hals/audio/ring_buffer.cpp
similarity index 100%
rename from audio/ring_buffer.cpp
rename to hals/audio/ring_buffer.cpp
diff --git a/audio/ring_buffer.h b/hals/audio/ring_buffer.h
similarity index 100%
rename from audio/ring_buffer.h
rename to hals/audio/ring_buffer.h
diff --git a/audio/stream_common.cpp b/hals/audio/stream_common.cpp
similarity index 100%
rename from audio/stream_common.cpp
rename to hals/audio/stream_common.cpp
diff --git a/audio/stream_common.h b/hals/audio/stream_common.h
similarity index 100%
rename from audio/stream_common.h
rename to hals/audio/stream_common.h
diff --git a/audio/stream_in.cpp b/hals/audio/stream_in.cpp
similarity index 90%
rename from audio/stream_in.cpp
rename to hals/audio/stream_in.cpp
index 251e1f2b..0524ee21 100644
--- a/audio/stream_in.cpp
+++ b/hals/audio/stream_in.cpp
@@ -100,6 +100,24 @@ struct ReadThread : public IOThread {
         return mTid.get_future();
     }
 
+    Result getCapturePosition(uint64_t &frames, uint64_t &ts) const {
+        std::lock_guard l(mExternalSourceReadLock);
+        if (mSource == nullptr) {
+            // this could return a slightly stale position under data race.
+            frames = 0;
+            ts = systemTime(SYSTEM_TIME_MONOTONIC);
+            return Result::OK;
+        } else {
+            return mSource->getCapturePosition(frames, ts);
+        }
+    }
+
+    auto getDescriptors() const {
+        return std::make_tuple(
+                mCommandMQ.getDesc(), mDataMQ.getDesc(), mStatusMQ.getDesc());
+    }
+
+  private:
     void threadLoop() {
         util::setThreadPriority(SP_AUDIO_SYS, PRIORITY_AUDIO);
         mTid.set_value(pthread_self());
@@ -113,17 +131,21 @@ struct ReadThread : public IOThread {
             }
 
             if (efState & STAND_BY_REQUEST) {
+                ALOGD("%s: entering standby", __func__);
+                std::lock_guard l(mExternalSourceReadLock);
                 mSource.reset();
             }
 
             if (efState & (MessageQueueFlagBits::NOT_FULL | 0)) {
                 if (!mSource) {
-                    mSource = DevicePortSource::create(mDataMQ.getQuantumCount(),
+                    auto source = DevicePortSource::create(mDataMQ.getQuantumCount(),
                                                        mStream->getDeviceAddress(),
                                                        mStream->getAudioConfig(),
                                                        mStream->getAudioOutputFlags(),
                                                        mStream->getFrameCounter());
-                    LOG_ALWAYS_FATAL_IF(!mSource);
+                    LOG_ALWAYS_FATAL_IF(!source);
+                    std::lock_guard l(mExternalSourceReadLock);
+                    mSource = std::move(source);
                 }
 
                 processCommand();
@@ -214,9 +236,10 @@ struct ReadThread : public IOThread {
     StatusMQ mStatusMQ;
     DataMQ mDataMQ;
     std::unique_ptr<EventFlag, deleters::forEventFlag> mEfGroup;
-    std::unique_ptr<DevicePortSource> mSource;
     std::thread mThread;
     std::promise<pthread_t> mTid;
+    mutable std::mutex mExternalSourceReadLock; // used for external access to mSource.
+    std::unique_ptr<DevicePortSource> mSource;
 };
 
 } // namespace
@@ -380,10 +403,11 @@ Return<void> StreamIn::prepareForReading(uint32_t frameSize,
     auto t = std::make_unique<ReadThread>(this, frameSize * framesCount);
 
     if (t->isRunning()) {
+        const auto [commandDesc, dataDesc, statusDesc ] = t->getDescriptors();
         _hidl_cb(Result::OK,
-                 *(t->mCommandMQ.getDesc()),
-                 *(t->mDataMQ.getDesc()),
-                 *(t->mStatusMQ.getDesc()),
+                 *commandDesc,
+                 *dataDesc,
+                 *statusDesc,
                  t->getTid().get());
 
         mReadThread = std::move(t);
@@ -399,22 +423,16 @@ Return<uint32_t> StreamIn::getInputFramesLost() {
 }
 
 Return<void> StreamIn::getCapturePosition(getCapturePosition_cb _hidl_cb) {
-    const auto r = static_cast<ReadThread*>(mReadThread.get());
-    if (!r) {
+    const auto rt = static_cast<ReadThread*>(mReadThread.get());
+    if (!rt) {
         _hidl_cb(FAILURE(Result::INVALID_STATE), {}, {});
         return Void();
     }
 
-    const auto s = r->mSource.get();
-    if (!s) {
-        _hidl_cb(Result::OK, mFrames, systemTime(SYSTEM_TIME_MONOTONIC));
-    } else {
-        uint64_t frames;
-        uint64_t time;
-        const Result r = s->getCapturePosition(frames, time);
-        _hidl_cb(r, frames, time);
-    }
-
+    uint64_t frames{};
+    uint64_t time{};
+    const Result r = rt->getCapturePosition(frames, time);
+    _hidl_cb(r, frames, time);
     return Void();
 }
 
diff --git a/audio/stream_in.h b/hals/audio/stream_in.h
similarity index 100%
rename from audio/stream_in.h
rename to hals/audio/stream_in.h
diff --git a/audio/stream_out.cpp b/hals/audio/stream_out.cpp
similarity index 100%
rename from audio/stream_out.cpp
rename to hals/audio/stream_out.cpp
diff --git a/audio/stream_out.h b/hals/audio/stream_out.h
similarity index 100%
rename from audio/stream_out.h
rename to hals/audio/stream_out.h
diff --git a/audio/talsa.cpp b/hals/audio/talsa.cpp
similarity index 100%
rename from audio/talsa.cpp
rename to hals/audio/talsa.cpp
diff --git a/audio/talsa.h b/hals/audio/talsa.h
similarity index 100%
rename from audio/talsa.h
rename to hals/audio/talsa.h
diff --git a/audio/util.cpp b/hals/audio/util.cpp
similarity index 99%
rename from audio/util.cpp
rename to hals/audio/util.cpp
index dff075b5..7a595dd9 100644
--- a/audio/util.cpp
+++ b/hals/audio/util.cpp
@@ -16,7 +16,7 @@
 
 #include <log/log.h>
 //#include <cutils/bitops.h>
-#include <cutils/sched_policy.h>
+#include <processgroup/sched_policy.h>
 #include <system/audio.h>
 #include <sys/resource.h>
 #include <pthread.h>
diff --git a/audio/util.h b/hals/audio/util.h
similarity index 100%
rename from audio/util.h
rename to hals/audio/util.h
diff --git a/camera/AFStateMachine.cpp b/hals/camera/AFStateMachine.cpp
similarity index 100%
rename from camera/AFStateMachine.cpp
rename to hals/camera/AFStateMachine.cpp
diff --git a/camera/AFStateMachine.h b/hals/camera/AFStateMachine.h
similarity index 100%
rename from camera/AFStateMachine.h
rename to hals/camera/AFStateMachine.h
diff --git a/camera/Android.bp b/hals/camera/Android.bp
similarity index 100%
rename from camera/Android.bp
rename to hals/camera/Android.bp
diff --git a/camera/AutoNativeHandle.cpp b/hals/camera/AutoNativeHandle.cpp
similarity index 100%
rename from camera/AutoNativeHandle.cpp
rename to hals/camera/AutoNativeHandle.cpp
diff --git a/camera/AutoNativeHandle.h b/hals/camera/AutoNativeHandle.h
similarity index 100%
rename from camera/AutoNativeHandle.h
rename to hals/camera/AutoNativeHandle.h
diff --git a/camera/BlockingQueue.h b/hals/camera/BlockingQueue.h
similarity index 100%
rename from camera/BlockingQueue.h
rename to hals/camera/BlockingQueue.h
diff --git a/camera/CachedStreamBuffer.cpp b/hals/camera/CachedStreamBuffer.cpp
similarity index 100%
rename from camera/CachedStreamBuffer.cpp
rename to hals/camera/CachedStreamBuffer.cpp
diff --git a/camera/CachedStreamBuffer.h b/hals/camera/CachedStreamBuffer.h
similarity index 100%
rename from camera/CachedStreamBuffer.h
rename to hals/camera/CachedStreamBuffer.h
diff --git a/camera/CameraDevice.cpp b/hals/camera/CameraDevice.cpp
similarity index 100%
rename from camera/CameraDevice.cpp
rename to hals/camera/CameraDevice.cpp
diff --git a/camera/CameraDevice.h b/hals/camera/CameraDevice.h
similarity index 100%
rename from camera/CameraDevice.h
rename to hals/camera/CameraDevice.h
diff --git a/camera/CameraDeviceSession.cpp b/hals/camera/CameraDeviceSession.cpp
similarity index 100%
rename from camera/CameraDeviceSession.cpp
rename to hals/camera/CameraDeviceSession.cpp
diff --git a/camera/CameraDeviceSession.h b/hals/camera/CameraDeviceSession.h
similarity index 100%
rename from camera/CameraDeviceSession.h
rename to hals/camera/CameraDeviceSession.h
diff --git a/camera/CameraProvider.cpp b/hals/camera/CameraProvider.cpp
similarity index 100%
rename from camera/CameraProvider.cpp
rename to hals/camera/CameraProvider.cpp
diff --git a/camera/CameraProvider.h b/hals/camera/CameraProvider.h
similarity index 100%
rename from camera/CameraProvider.h
rename to hals/camera/CameraProvider.h
diff --git a/camera/FakeRotatingCamera.cpp b/hals/camera/FakeRotatingCamera.cpp
similarity index 100%
rename from camera/FakeRotatingCamera.cpp
rename to hals/camera/FakeRotatingCamera.cpp
diff --git a/camera/FakeRotatingCamera.h b/hals/camera/FakeRotatingCamera.h
similarity index 100%
rename from camera/FakeRotatingCamera.h
rename to hals/camera/FakeRotatingCamera.h
diff --git a/camera/HwCamera.cpp b/hals/camera/HwCamera.cpp
similarity index 100%
rename from camera/HwCamera.cpp
rename to hals/camera/HwCamera.cpp
diff --git a/camera/HwCamera.h b/hals/camera/HwCamera.h
similarity index 100%
rename from camera/HwCamera.h
rename to hals/camera/HwCamera.h
diff --git a/camera/QemuCamera.cpp b/hals/camera/QemuCamera.cpp
similarity index 100%
rename from camera/QemuCamera.cpp
rename to hals/camera/QemuCamera.cpp
diff --git a/camera/QemuCamera.h b/hals/camera/QemuCamera.h
similarity index 100%
rename from camera/QemuCamera.h
rename to hals/camera/QemuCamera.h
diff --git a/camera/Rect.h b/hals/camera/Rect.h
similarity index 100%
rename from camera/Rect.h
rename to hals/camera/Rect.h
diff --git a/camera/Span.h b/hals/camera/Span.h
similarity index 100%
rename from camera/Span.h
rename to hals/camera/Span.h
diff --git a/camera/StreamBufferCache.cpp b/hals/camera/StreamBufferCache.cpp
similarity index 100%
rename from camera/StreamBufferCache.cpp
rename to hals/camera/StreamBufferCache.cpp
diff --git a/camera/StreamBufferCache.h b/hals/camera/StreamBufferCache.h
similarity index 100%
rename from camera/StreamBufferCache.h
rename to hals/camera/StreamBufferCache.h
diff --git a/camera/abc3d.cpp b/hals/camera/abc3d.cpp
similarity index 100%
rename from camera/abc3d.cpp
rename to hals/camera/abc3d.cpp
diff --git a/camera/abc3d.h b/hals/camera/abc3d.h
similarity index 100%
rename from camera/abc3d.h
rename to hals/camera/abc3d.h
diff --git a/camera/acircles_pattern_512_512.cpp b/hals/camera/acircles_pattern_512_512.cpp
similarity index 100%
rename from camera/acircles_pattern_512_512.cpp
rename to hals/camera/acircles_pattern_512_512.cpp
diff --git a/camera/acircles_pattern_512_512.h b/hals/camera/acircles_pattern_512_512.h
similarity index 100%
rename from camera/acircles_pattern_512_512.h
rename to hals/camera/acircles_pattern_512_512.h
diff --git a/camera/android.hardware.camera.provider.ranchu.rc b/hals/camera/android.hardware.camera.provider.ranchu.rc
similarity index 100%
rename from camera/android.hardware.camera.provider.ranchu.rc
rename to hals/camera/android.hardware.camera.provider.ranchu.rc
diff --git a/camera/android.hardware.camera.provider.ranchu.xml b/hals/camera/android.hardware.camera.provider.ranchu.xml
similarity index 100%
rename from camera/android.hardware.camera.provider.ranchu.xml
rename to hals/camera/android.hardware.camera.provider.ranchu.xml
diff --git a/camera/converters.cpp b/hals/camera/converters.cpp
similarity index 100%
rename from camera/converters.cpp
rename to hals/camera/converters.cpp
diff --git a/camera/converters.h b/hals/camera/converters.h
similarity index 100%
rename from camera/converters.h
rename to hals/camera/converters.h
diff --git a/camera/exif.cpp b/hals/camera/exif.cpp
similarity index 100%
rename from camera/exif.cpp
rename to hals/camera/exif.cpp
diff --git a/camera/exif.h b/hals/camera/exif.h
similarity index 100%
rename from camera/exif.h
rename to hals/camera/exif.h
diff --git a/camera/jpeg.cpp b/hals/camera/jpeg.cpp
similarity index 100%
rename from camera/jpeg.cpp
rename to hals/camera/jpeg.cpp
diff --git a/camera/jpeg.h b/hals/camera/jpeg.h
similarity index 100%
rename from camera/jpeg.h
rename to hals/camera/jpeg.h
diff --git a/camera/list_fake_rotating_cameras.cpp b/hals/camera/list_fake_rotating_cameras.cpp
similarity index 100%
rename from camera/list_fake_rotating_cameras.cpp
rename to hals/camera/list_fake_rotating_cameras.cpp
diff --git a/camera/list_fake_rotating_cameras.h b/hals/camera/list_fake_rotating_cameras.h
similarity index 100%
rename from camera/list_fake_rotating_cameras.h
rename to hals/camera/list_fake_rotating_cameras.h
diff --git a/camera/list_qemu_cameras.cpp b/hals/camera/list_qemu_cameras.cpp
similarity index 100%
rename from camera/list_qemu_cameras.cpp
rename to hals/camera/list_qemu_cameras.cpp
diff --git a/camera/list_qemu_cameras.h b/hals/camera/list_qemu_cameras.h
similarity index 100%
rename from camera/list_qemu_cameras.h
rename to hals/camera/list_qemu_cameras.h
diff --git a/camera/main.cpp b/hals/camera/main.cpp
similarity index 100%
rename from camera/main.cpp
rename to hals/camera/main.cpp
diff --git a/camera/metadata_utils.cpp b/hals/camera/metadata_utils.cpp
similarity index 100%
rename from camera/metadata_utils.cpp
rename to hals/camera/metadata_utils.cpp
diff --git a/camera/metadata_utils.h b/hals/camera/metadata_utils.h
similarity index 100%
rename from camera/metadata_utils.h
rename to hals/camera/metadata_utils.h
diff --git a/camera/qemu_channel.cpp b/hals/camera/qemu_channel.cpp
similarity index 100%
rename from camera/qemu_channel.cpp
rename to hals/camera/qemu_channel.cpp
diff --git a/camera/qemu_channel.h b/hals/camera/qemu_channel.h
similarity index 100%
rename from camera/qemu_channel.h
rename to hals/camera/qemu_channel.h
diff --git a/camera/service_entry.cpp b/hals/camera/service_entry.cpp
similarity index 100%
rename from camera/service_entry.cpp
rename to hals/camera/service_entry.cpp
diff --git a/camera/service_entry.h b/hals/camera/service_entry.h
similarity index 100%
rename from camera/service_entry.h
rename to hals/camera/service_entry.h
diff --git a/camera/utils.cpp b/hals/camera/utils.cpp
similarity index 97%
rename from camera/utils.cpp
rename to hals/camera/utils.cpp
index eb738017..174f20d0 100644
--- a/camera/utils.cpp
+++ b/hals/camera/utils.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#include <processgroup/sched_policy.h>
 #include <sys/resource.h>
 
 #include "utils.h"
diff --git a/camera/utils.h b/hals/camera/utils.h
similarity index 100%
rename from camera/utils.h
rename to hals/camera/utils.h
diff --git a/camera/yuv.cpp b/hals/camera/yuv.cpp
similarity index 100%
rename from camera/yuv.cpp
rename to hals/camera/yuv.cpp
diff --git a/camera/yuv.h b/hals/camera/yuv.h
similarity index 100%
rename from camera/yuv.h
rename to hals/camera/yuv.h
diff --git a/fingerprint/Android.bp b/hals/fingerprint/Android.bp
similarity index 100%
rename from fingerprint/Android.bp
rename to hals/fingerprint/Android.bp
diff --git a/fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.rc b/hals/fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.rc
similarity index 100%
rename from fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.rc
rename to hals/fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.rc
diff --git a/fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.xml b/hals/fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.xml
similarity index 100%
rename from fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.xml
rename to hals/fingerprint/android.hardware.biometrics.fingerprint-service.ranchu.xml
diff --git a/fingerprint/hal.cpp b/hals/fingerprint/hal.cpp
similarity index 100%
rename from fingerprint/hal.cpp
rename to hals/fingerprint/hal.cpp
diff --git a/fingerprint/hal.h b/hals/fingerprint/hal.h
similarity index 100%
rename from fingerprint/hal.h
rename to hals/fingerprint/hal.h
diff --git a/fingerprint/main.cpp b/hals/fingerprint/main.cpp
similarity index 100%
rename from fingerprint/main.cpp
rename to hals/fingerprint/main.cpp
diff --git a/fingerprint/session.cpp b/hals/fingerprint/session.cpp
similarity index 100%
rename from fingerprint/session.cpp
rename to hals/fingerprint/session.cpp
diff --git a/fingerprint/session.h b/hals/fingerprint/session.h
similarity index 100%
rename from fingerprint/session.h
rename to hals/fingerprint/session.h
diff --git a/fingerprint/storage.cpp b/hals/fingerprint/storage.cpp
similarity index 100%
rename from fingerprint/storage.cpp
rename to hals/fingerprint/storage.cpp
diff --git a/fingerprint/storage.h b/hals/fingerprint/storage.h
similarity index 100%
rename from fingerprint/storage.h
rename to hals/fingerprint/storage.h
diff --git a/gnss/Agnss.cpp b/hals/gnss/Agnss.cpp
similarity index 100%
rename from gnss/Agnss.cpp
rename to hals/gnss/Agnss.cpp
diff --git a/gnss/Agnss.h b/hals/gnss/Agnss.h
similarity index 100%
rename from gnss/Agnss.h
rename to hals/gnss/Agnss.h
diff --git a/gnss/AgnssRil.cpp b/hals/gnss/AgnssRil.cpp
similarity index 100%
rename from gnss/AgnssRil.cpp
rename to hals/gnss/AgnssRil.cpp
diff --git a/gnss/AgnssRil.h b/hals/gnss/AgnssRil.h
similarity index 100%
rename from gnss/AgnssRil.h
rename to hals/gnss/AgnssRil.h
diff --git a/gnss/Android.bp b/hals/gnss/Android.bp
similarity index 100%
rename from gnss/Android.bp
rename to hals/gnss/Android.bp
diff --git a/gnss/Gnss.cpp b/hals/gnss/Gnss.cpp
similarity index 100%
rename from gnss/Gnss.cpp
rename to hals/gnss/Gnss.cpp
diff --git a/gnss/Gnss.h b/hals/gnss/Gnss.h
similarity index 100%
rename from gnss/Gnss.h
rename to hals/gnss/Gnss.h
diff --git a/gnss/GnssAntennaInfo.cpp b/hals/gnss/GnssAntennaInfo.cpp
similarity index 100%
rename from gnss/GnssAntennaInfo.cpp
rename to hals/gnss/GnssAntennaInfo.cpp
diff --git a/gnss/GnssAntennaInfo.h b/hals/gnss/GnssAntennaInfo.h
similarity index 100%
rename from gnss/GnssAntennaInfo.h
rename to hals/gnss/GnssAntennaInfo.h
diff --git a/gnss/GnssBatching.cpp b/hals/gnss/GnssBatching.cpp
similarity index 100%
rename from gnss/GnssBatching.cpp
rename to hals/gnss/GnssBatching.cpp
diff --git a/gnss/GnssBatching.h b/hals/gnss/GnssBatching.h
similarity index 100%
rename from gnss/GnssBatching.h
rename to hals/gnss/GnssBatching.h
diff --git a/gnss/GnssConfiguration.cpp b/hals/gnss/GnssConfiguration.cpp
similarity index 100%
rename from gnss/GnssConfiguration.cpp
rename to hals/gnss/GnssConfiguration.cpp
diff --git a/gnss/GnssConfiguration.h b/hals/gnss/GnssConfiguration.h
similarity index 100%
rename from gnss/GnssConfiguration.h
rename to hals/gnss/GnssConfiguration.h
diff --git a/gnss/GnssDebug.cpp b/hals/gnss/GnssDebug.cpp
similarity index 100%
rename from gnss/GnssDebug.cpp
rename to hals/gnss/GnssDebug.cpp
diff --git a/gnss/GnssDebug.h b/hals/gnss/GnssDebug.h
similarity index 100%
rename from gnss/GnssDebug.h
rename to hals/gnss/GnssDebug.h
diff --git a/gnss/GnssGeofence.cpp b/hals/gnss/GnssGeofence.cpp
similarity index 100%
rename from gnss/GnssGeofence.cpp
rename to hals/gnss/GnssGeofence.cpp
diff --git a/gnss/GnssGeofence.h b/hals/gnss/GnssGeofence.h
similarity index 100%
rename from gnss/GnssGeofence.h
rename to hals/gnss/GnssGeofence.h
diff --git a/gnss/GnssHwConn.cpp b/hals/gnss/GnssHwConn.cpp
similarity index 100%
rename from gnss/GnssHwConn.cpp
rename to hals/gnss/GnssHwConn.cpp
diff --git a/gnss/GnssHwConn.h b/hals/gnss/GnssHwConn.h
similarity index 100%
rename from gnss/GnssHwConn.h
rename to hals/gnss/GnssHwConn.h
diff --git a/gnss/GnssHwListener.cpp b/hals/gnss/GnssHwListener.cpp
similarity index 100%
rename from gnss/GnssHwListener.cpp
rename to hals/gnss/GnssHwListener.cpp
diff --git a/gnss/GnssHwListener.h b/hals/gnss/GnssHwListener.h
similarity index 100%
rename from gnss/GnssHwListener.h
rename to hals/gnss/GnssHwListener.h
diff --git a/gnss/GnssMeasurementInterface.cpp b/hals/gnss/GnssMeasurementInterface.cpp
similarity index 100%
rename from gnss/GnssMeasurementInterface.cpp
rename to hals/gnss/GnssMeasurementInterface.cpp
diff --git a/gnss/GnssMeasurementInterface.h b/hals/gnss/GnssMeasurementInterface.h
similarity index 100%
rename from gnss/GnssMeasurementInterface.h
rename to hals/gnss/GnssMeasurementInterface.h
diff --git a/gnss/GnssNavigationMessageInterface.cpp b/hals/gnss/GnssNavigationMessageInterface.cpp
similarity index 100%
rename from gnss/GnssNavigationMessageInterface.cpp
rename to hals/gnss/GnssNavigationMessageInterface.cpp
diff --git a/gnss/GnssNavigationMessageInterface.h b/hals/gnss/GnssNavigationMessageInterface.h
similarity index 100%
rename from gnss/GnssNavigationMessageInterface.h
rename to hals/gnss/GnssNavigationMessageInterface.h
diff --git a/gnss/GnssPowerIndication.cpp b/hals/gnss/GnssPowerIndication.cpp
similarity index 100%
rename from gnss/GnssPowerIndication.cpp
rename to hals/gnss/GnssPowerIndication.cpp
diff --git a/gnss/GnssPowerIndication.h b/hals/gnss/GnssPowerIndication.h
similarity index 100%
rename from gnss/GnssPowerIndication.h
rename to hals/gnss/GnssPowerIndication.h
diff --git a/gnss/GnssPsds.cpp b/hals/gnss/GnssPsds.cpp
similarity index 100%
rename from gnss/GnssPsds.cpp
rename to hals/gnss/GnssPsds.cpp
diff --git a/gnss/GnssPsds.h b/hals/gnss/GnssPsds.h
similarity index 100%
rename from gnss/GnssPsds.h
rename to hals/gnss/GnssPsds.h
diff --git a/gnss/GnssVisibilityControl.cpp b/hals/gnss/GnssVisibilityControl.cpp
similarity index 100%
rename from gnss/GnssVisibilityControl.cpp
rename to hals/gnss/GnssVisibilityControl.cpp
diff --git a/gnss/GnssVisibilityControl.h b/hals/gnss/GnssVisibilityControl.h
similarity index 100%
rename from gnss/GnssVisibilityControl.h
rename to hals/gnss/GnssVisibilityControl.h
diff --git a/gnss/IDataSink.h b/hals/gnss/IDataSink.h
similarity index 100%
rename from gnss/IDataSink.h
rename to hals/gnss/IDataSink.h
diff --git a/gnss/MeasurementCorrectionsInterface.cpp b/hals/gnss/MeasurementCorrectionsInterface.cpp
similarity index 100%
rename from gnss/MeasurementCorrectionsInterface.cpp
rename to hals/gnss/MeasurementCorrectionsInterface.cpp
diff --git a/gnss/MeasurementCorrectionsInterface.h b/hals/gnss/MeasurementCorrectionsInterface.h
similarity index 100%
rename from gnss/MeasurementCorrectionsInterface.h
rename to hals/gnss/MeasurementCorrectionsInterface.h
diff --git a/gnss/android.hardware.gnss-service.ranchu.rc b/hals/gnss/android.hardware.gnss-service.ranchu.rc
similarity index 100%
rename from gnss/android.hardware.gnss-service.ranchu.rc
rename to hals/gnss/android.hardware.gnss-service.ranchu.rc
diff --git a/gnss/android.hardware.gnss-service.ranchu.xml b/hals/gnss/android.hardware.gnss-service.ranchu.xml
similarity index 100%
rename from gnss/android.hardware.gnss-service.ranchu.xml
rename to hals/gnss/android.hardware.gnss-service.ranchu.xml
diff --git a/gnss/main.cpp b/hals/gnss/main.cpp
similarity index 100%
rename from gnss/main.cpp
rename to hals/gnss/main.cpp
diff --git a/gralloc/Android.bp b/hals/gralloc/Android.bp
similarity index 100%
rename from gralloc/Android.bp
rename to hals/gralloc/Android.bp
diff --git a/gralloc/CbExternalMetadata.h b/hals/gralloc/CbExternalMetadata.h
similarity index 100%
rename from gralloc/CbExternalMetadata.h
rename to hals/gralloc/CbExternalMetadata.h
diff --git a/gralloc/DebugLevel.h b/hals/gralloc/DebugLevel.h
similarity index 100%
rename from gralloc/DebugLevel.h
rename to hals/gralloc/DebugLevel.h
diff --git a/gralloc/HostConnectionSession.h b/hals/gralloc/HostConnectionSession.h
similarity index 100%
rename from gralloc/HostConnectionSession.h
rename to hals/gralloc/HostConnectionSession.h
diff --git a/gralloc/PlaneLayout.h b/hals/gralloc/PlaneLayout.h
similarity index 100%
rename from gralloc/PlaneLayout.h
rename to hals/gralloc/PlaneLayout.h
diff --git a/gralloc/allocator.cpp b/hals/gralloc/allocator.cpp
similarity index 100%
rename from gralloc/allocator.cpp
rename to hals/gralloc/allocator.cpp
diff --git a/gralloc/android.hardware.graphics.allocator-service.ranchu.rc b/hals/gralloc/android.hardware.graphics.allocator-service.ranchu.rc
similarity index 100%
rename from gralloc/android.hardware.graphics.allocator-service.ranchu.rc
rename to hals/gralloc/android.hardware.graphics.allocator-service.ranchu.rc
diff --git a/gralloc/android.hardware.graphics.gralloc.ranchu.xml b/hals/gralloc/android.hardware.graphics.gralloc.ranchu.xml
similarity index 100%
rename from gralloc/android.hardware.graphics.gralloc.ranchu.xml
rename to hals/gralloc/android.hardware.graphics.gralloc.ranchu.xml
diff --git a/gralloc/mapper.cpp b/hals/gralloc/mapper.cpp
similarity index 100%
rename from gralloc/mapper.cpp
rename to hals/gralloc/mapper.cpp
diff --git a/hals/radio/Android.bp b/hals/radio/Android.bp
new file mode 100644
index 00000000..04feae21
--- /dev/null
+++ b/hals/radio/Android.bp
@@ -0,0 +1,78 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
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
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_goldfish_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_goldfish_license"],
+}
+
+cc_binary {
+    name: "android.hardware.radio-service.ranchu",
+    relative_install_path: "hw",
+    vendor: true,
+    cpp_std: "c++20",
+    srcs: [
+        "AtChannel.cpp",
+        "AtResponse.cpp",
+        "hexbin.cpp",
+        "IdAllocator.cpp",
+        "ImsMedia.cpp",
+        "main.cpp",
+        "makeRadioResponseInfo.cpp",
+        "Parser.cpp",
+        "ratUtils.cpp",
+        "RadioConfig.cpp",
+        "RadioData.cpp",
+        "RadioIms.cpp",
+        "RadioMessaging.cpp",
+        "RadioModem.cpp",
+        "RadioNetwork.cpp",
+        "RadioSim.cpp",
+        "RadioVoice.cpp",
+        "Sap.cpp",
+    ],
+    init_rc: ["android.hardware.radio.ranchu.rc"],
+    vintf_fragments: ["android.hardware.radio.ranchu.xml"],
+    shared_libs: [
+        "android.hardware.radio.config-V3-ndk",
+        "android.hardware.radio.data-V3-ndk",
+        "android.hardware.radio.ims-V2-ndk",
+        "android.hardware.radio.ims.media-V2-ndk",
+        "android.hardware.radio.messaging-V3-ndk",
+        "android.hardware.radio.modem-V3-ndk",
+        "android.hardware.radio.network-V3-ndk",
+        "android.hardware.radio.sap-V1-ndk",
+        "android.hardware.radio.sim-V3-ndk",
+        "android.hardware.radio.voice-V3-ndk",
+        "libbase",
+        "libbinder_ndk",
+        "libcrypto",
+        "libcutils",
+        "liblog",
+        "libutils",
+    ],
+    cflags: [
+        "-DLOG_TAG=\"radio-service.ranchu\"",
+        "-DANDROID_BASE_UNIQUE_FD_DISABLE_IMPLICIT_CONVERSION",
+    ],
+    required: [
+        "EmulatorRadioConfig",
+        "EmulatorTetheringConfigOverlay",
+    ],
+}
diff --git a/hals/radio/AtChannel.cpp b/hals/radio/AtChannel.cpp
new file mode 100644
index 00000000..cbb52f69
--- /dev/null
+++ b/hals/radio/AtChannel.cpp
@@ -0,0 +1,288 @@
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
+#define FAILURE_DEBUG_PREFIX "AtChannel"
+
+#include <cstring>
+#include <unistd.h>
+
+#include "AtChannel.h"
+#include "debug.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace {
+int sendRequestImpl(const int fd, const char* data, size_t size) {
+    while (size > 0) {
+        const ssize_t written = ::write(fd, data, size);
+        if (written >= 0) {
+            data += written;
+            size -= written;
+        } else if (errno == EINTR) {
+            continue;
+        } else {
+            return FAILURE(errno);
+        }
+    }
+
+    return 0;
+}
+}  // namespace
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "AtChannel::RequestPipe"
+
+bool AtChannel::RequestPipe::operator()(const std::string_view request) const {
+    int err = sendRequestImpl(mFd, request.data(), request.size());
+    if (err == 0) {
+        const char kCR = 0x0D;
+        err = sendRequestImpl(mFd, &kCR, 1);
+    }
+
+    return err == 0;
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "AtChannel"
+
+AtChannel::AtChannel(HostChannelFactory hostChannelFactory,
+                     InitSequence initSequence)
+        : mHostChannelFactory(std::move(hostChannelFactory))
+        , mInitSequence(std::move(initSequence)) {
+    mRequestThread = std::thread(&AtChannel::requestLoop, this);
+}
+
+AtChannel::~AtChannel() {
+    queueRequester({});
+    mRequestThread.join();
+    mReaderThread.join();
+}
+
+void AtChannel::queueRequester(Requester requester) {
+    std::lock_guard<std::mutex> lock(mRequestQueueMtx);
+    mRequesterQueue.push_back(std::move(requester));
+    mRequesterAvailable.notify_one();
+}
+
+void AtChannel::addResponseSink(ResponseSink responseSink) {
+    std::lock_guard<std::mutex> lock(mResponseSinksMtx);
+    mResponseSinks.push_back(std::move(responseSink));
+}
+
+void AtChannel::requestLoop() {
+    while (true) {
+        const Requester requester = getRequester();
+        if (requester) {
+            if (!requester(getHostChannelPipe())) {
+                mHostChannel.reset();
+            }
+        } else {
+            break;
+        }
+    }
+
+    mHostChannel.reset();
+}
+
+void AtChannel::readingLoop(const int hostChannelFd) {
+    std::vector<char> unconsumed;
+    while (receiveResponses(hostChannelFd, &unconsumed)) {}
+    LOG_ALWAYS_FATAL("We could not parse the modem response");
+}
+
+AtChannel::Requester AtChannel::getRequester() {
+    std::unique_lock<std::mutex> lock(mRequestQueueMtx);
+    while (true) {
+        if (!mRequesterQueue.empty()) {
+            Requester requester(std::move(mRequesterQueue.front()));
+            mRequesterQueue.pop_front();
+            return requester;
+        } else {
+            mRequesterAvailable.wait(lock);
+        }
+    }
+}
+
+void AtChannel::broadcastResponse(const AtResponsePtr& response) {
+    mConversation.send(response);
+
+    std::lock_guard<std::mutex> lock(mResponseSinksMtx);
+
+    const auto newEnd = std::remove_if(mResponseSinks.begin(), mResponseSinks.end(),
+        [&response](const ResponseSink& responseSink) -> bool {
+            return !responseSink(response);
+        });
+
+    mResponseSinks.erase(newEnd, mResponseSinks.end());
+}
+
+AtChannel::RequestPipe AtChannel::getHostChannelPipe() {
+    if (!mHostChannel.ok()) {
+        if (mReaderThread.joinable()) {
+            mReaderThread.join();
+        }
+
+        mHostChannel = mHostChannelFactory();
+        LOG_ALWAYS_FATAL_IF(!mHostChannel.ok(),
+                            "%s:%d: Can't open the host channel", __func__, __LINE__);
+
+        const int hostChannelFd = mHostChannel.get();
+        mReaderThread = std::thread([this, hostChannelFd](){
+            readingLoop(hostChannelFd);
+        });
+
+        LOG_ALWAYS_FATAL_IF(!mInitSequence(RequestPipe(hostChannelFd), mConversation),
+                            "%s:%d: Can't init the host channel", __func__, __LINE__);
+    }
+
+    return RequestPipe(mHostChannel.get());
+}
+
+bool AtChannel::receiveResponses(const int hostChannelFd,
+                                 std::vector<char>* unconsumed) {
+    const size_t unconsumedSize = unconsumed->size();
+    if (unconsumedSize == 0) {
+        char buf[128];
+        const int len = ::read(hostChannelFd, buf, sizeof(buf));
+        if (len > 0) {
+            return receiveResponsesImpl(buf, buf + len, unconsumed);
+        } else if (len < 0) {
+            const int err = errno;
+            if (err == EINTR) {
+                return true;
+            } else {
+                return FAILURE_V(false, "fd=%d, err=%s (%d)",
+                                 hostChannelFd, ::strerror(err), err);
+            }
+        }
+    } else {
+        const size_t newSize = std::max(unconsumedSize + 1024, unconsumed->capacity());
+        unconsumed->resize(newSize);
+        const int len = ::read(hostChannelFd, &(*unconsumed)[unconsumedSize],
+                               newSize - unconsumedSize);
+        if (len > 0) {
+            unconsumed->resize(unconsumedSize + len);
+            char* begin = unconsumed->data();
+            char* end = begin + unconsumedSize + len;
+            return receiveResponsesImpl(begin, end, unconsumed);
+        } else if (len < 0) {
+            const int err = errno;
+            if (err == EINTR) {
+                return true;
+            } else {
+                return FAILURE_V(false, "fd=%d, err=%s (%d)",
+                                 hostChannelFd, ::strerror(err), err);
+            }
+        }
+    }
+
+    return true;
+}
+
+// NOTE: [begin, end) could contain one or more requests,
+// the last one might be incomplete
+bool AtChannel::receiveResponsesImpl(const char* begin, const char* const end,
+                                     std::vector<char>* unconsumed) {
+    while (begin < end) {
+        const char* next = receiveOneResponse(begin, end);
+        if (next == begin) {
+            unconsumed->assign(begin, end);
+            return true;
+        } else if (next == nullptr) {
+            return false;
+        } else {
+            begin = next;
+        }
+    }
+
+    unconsumed->clear();
+    return true;
+}
+
+const char* AtChannel::receiveOneResponse(const char* const begin, const char* const end) {
+    switch (*begin) {
+    case '\r':
+    case '\n':
+        return begin + 1;
+    }
+
+    auto [consumed, response] = AtResponse::parse(std::string_view(begin, end - begin));
+    if (response) {
+        broadcastResponse(response);
+    }
+
+    return (consumed >= 0) ? (begin + consumed) : nullptr;
+}
+
+AtResponsePtr AtChannel::Conversation::operator()(
+        const RequestPipe requestPipe,
+        const std::string_view request,
+        const AtChannel::Conversation::FilterFunc& filter,
+        const AtChannel::Conversation::Duration timeout) {
+    std::future<AtResponsePtr> futureResponse;
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mFilter = &filter;
+        mSink = decltype(mSink)();
+        futureResponse = mSink.get_future();
+    }
+
+    if (!requestPipe(request)) {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mFilter = nullptr;
+        return nullptr;
+    } else if (futureResponse.wait_for(timeout) == std::future_status::ready) {
+        return futureResponse.get();
+    } else {
+        {
+            std::lock_guard<std::mutex> lock(mMtx);
+            mFilter = nullptr;
+        }
+
+        const int requestLen = request.size();
+        return FAILURE_V(nullptr, "Timeout for '%*.*s'",
+                         requestLen, requestLen, request.data());
+    }
+}
+
+AtResponsePtr AtChannel::Conversation::operator()(
+        const RequestPipe requestPipe,
+        const std::string_view request,
+        const FilterFunc& filter) {
+    using namespace std::chrono_literals;
+    return (*this)(requestPipe, request, filter, 3s);
+}
+
+bool AtChannel::Conversation::send(const AtResponsePtr& response) {
+    std::lock_guard<std::mutex> lock(mMtx);
+    if (mFilter && (*mFilter)(*response)) {
+        mFilter = nullptr;
+        mSink.set_value(response);
+        return true;
+    } else {
+        return false;
+    }
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/AtChannel.h b/hals/radio/AtChannel.h
new file mode 100644
index 00000000..3bd43a36
--- /dev/null
+++ b/hals/radio/AtChannel.h
@@ -0,0 +1,114 @@
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
+#include <condition_variable>
+#include <deque>
+#include <functional>
+#include <future>
+#include <mutex>
+#include <optional>
+#include <string_view>
+#include <thread>
+#include <variant>
+#include <vector>
+
+#include <android-base/unique_fd.h>
+
+#include "AtResponse.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::android::base::unique_fd;
+
+struct AtChannel {
+    using HostChannelFactory = std::function<unique_fd()>;
+
+    struct RequestPipe {
+        explicit RequestPipe(int fd) : mFd(fd) {}
+
+        bool operator()(std::string_view request) const;
+
+        RequestPipe(const RequestPipe&) = default;
+        RequestPipe& operator=(const RequestPipe&) = default;
+
+    private:
+        int mFd;
+    };
+
+    struct Conversation {
+        using FilterFunc = std::function<bool(const AtResponse&)>;
+        using Duration = std::chrono::steady_clock::duration;
+
+        AtResponsePtr operator()(RequestPipe, std::string_view request,
+                                 const FilterFunc& filter, Duration timeout);
+        AtResponsePtr operator()(RequestPipe, std::string_view request,
+                                 const FilterFunc& filter);
+
+        bool send(const AtResponsePtr& response);
+
+    private:
+        const FilterFunc* mFilter = nullptr;
+        std::promise<AtResponsePtr> mSink;
+        mutable std::mutex mMtx;
+    };
+
+    using InitSequence = std::function<bool(RequestPipe, Conversation&)>;
+    using Requester = std::function<bool(RequestPipe)>;
+    using ResponseSink = std::function<bool(const AtResponsePtr&)>;
+
+    AtChannel(HostChannelFactory hostChannelFactory,
+              InitSequence initSequence);
+    ~AtChannel();
+
+    void queueRequester(Requester);
+    void addResponseSink(ResponseSink);
+
+private:
+    void requestLoop();
+    void readingLoop(int fd);
+    Requester getRequester();
+    void broadcastResponse(const AtResponsePtr&);
+
+    RequestPipe getHostChannelPipe();
+    bool receiveResponses(int hostChannel, std::vector<char>* unconsumed);
+    bool receiveResponsesImpl(const char* begin, const char* end,
+                              std::vector<char>* unconsumed);
+    const char* receiveOneResponse(const char* begin, const char* end);
+
+    const HostChannelFactory mHostChannelFactory;
+    const InitSequence mInitSequence;
+    Conversation mConversation;
+    unique_fd mHostChannel;
+    std::deque<Requester> mRequesterQueue;
+    std::condition_variable mRequesterAvailable;
+    std::vector<ResponseSink> mResponseSinks;
+    std::vector<char> mResponseBuf;
+    std::thread mRequestThread;
+    std::thread mReaderThread;
+    mutable std::mutex mRequestQueueMtx;
+    mutable std::mutex mResponseSinksMtx;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/AtResponse.cpp b/hals/radio/AtResponse.cpp
new file mode 100644
index 00000000..e70a82fd
--- /dev/null
+++ b/hals/radio/AtResponse.cpp
@@ -0,0 +1,1538 @@
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
+#define FAILURE_DEBUG_PREFIX "AtResponse"
+
+#include <algorithm>
+#include <charconv>
+#include <numeric>
+#include <string>
+#include <string_view>
+
+#include "atCmds.h"
+#include "AtResponse.h"
+#include "Parser.h"
+#include "debug.h"
+#include "hexbin.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using namespace std::literals;
+
+namespace {
+constexpr char kCR = '\r';
+constexpr std::string_view krOKr = "\rOK\r"sv;
+
+struct ValueParser {
+    std::string_view cmd;
+    AtResponsePtr (*parse)(std::string_view str);
+    bool multiline;
+};
+
+struct CmdIdVisitor {
+    std::string_view operator()(const AtResponse::OK&) const {
+        return "OK"sv;
+    }
+
+    std::string_view operator()(const AtResponse::ERROR&) const {
+        return "ERROR"sv;
+    }
+
+    std::string_view operator()(const AtResponse::RING&) const {
+        return "RING"sv;
+    }
+
+    std::string_view operator()(const AtResponse::SmsPrompt&) const {
+        return "SmsPrompt"sv;
+    }
+
+    std::string_view operator()(const AtResponse::ParseError&) const {
+        return "ParseError"sv;
+    }
+
+    std::string_view operator()(const std::string&) const {
+        return "string"sv;
+    }
+
+    template <class T> std::string_view operator()(const T&) const {
+        return T::id();
+    }
+};
+
+std::string_view ltrim(std::string_view s) {
+    while (!s.empty()) {
+        if (s.front() <= 0x20) {
+            s.remove_prefix(1);
+        } else {
+            break;
+        }
+    }
+    return s;
+}
+
+std::string toString(std::string_view s) {
+    return std::string(s.data(), s.size());
+}
+
+AtResponse::ParseResult parseCmds(const std::string_view str,
+                                  const ValueParser* vp,
+                                  const ValueParser* const vpEnd) {
+    const std::string_view str1 = str.substr(1);  // skip + or %
+    if (str1.empty()) {
+        return { 0, nullptr };
+    }
+
+    bool maybeIncomplete = false;
+    for (; vp != vpEnd; ++vp) {
+        const std::string_view& cmd = vp->cmd;
+
+        if (str1.starts_with(cmd.substr(0, str1.size()))) {
+            size_t skipSize;
+            std::string_view payload;
+
+            if (str1.size() <= cmd.size()) {
+                maybeIncomplete = true;
+                continue;
+            } else if (str1[cmd.size()] == ':') {
+                skipSize = 1 + cmd.size() + 1; // `+CMD:`
+            } else if (str1[cmd.size()] == '\r') {
+                skipSize = 1 + cmd.size(); // `+CMD`
+            } else {
+                continue;
+            }
+
+            int consumed;
+
+            if (vp->multiline) {
+                const size_t payloadEnd = str.find(krOKr, skipSize);
+                if (payloadEnd != str.npos) {
+                    // keep '+CMD:' and add extra '\r' to keep lines consistent
+                    payload = str.substr(0, payloadEnd + 1);
+                    consumed = payloadEnd + krOKr.size();
+                } else {
+                    return { 0, nullptr };
+                }
+            } else {
+                const size_t payloadEnd = str.find(kCR, skipSize);
+                if (payloadEnd != str.npos) {
+                    payload = ltrim(str.substr(skipSize, payloadEnd - skipSize));
+                    consumed = payloadEnd + 1;
+                } else {
+                    return { 0, nullptr };
+                }
+            }
+
+            return { consumed, (*vp->parse)(payload) };
+        }
+    }
+
+    if (maybeIncomplete) {
+        return { 0, nullptr };
+    } else {
+        return { -1, FAILURE(nullptr) };
+    }
+}
+}  // namespace
+
+AtResponse::ParseResult AtResponse::parse(const std::string_view str) {
+#define CMD(C) AtResponse::C::id(), &AtResponse::C::parse
+    static const ValueParser plusValueParsers[] = {
+        { CMD(CPIN),        false },
+        { CMD(CPINR),       false },
+        { CMD(CRSM),        false },
+        { CMD(CFUN),        false },
+        { CMD(CREG),        false },
+        { CMD(CEREG),       false },
+        { CMD(CGREG),       false },
+        { CMD(CTEC),        false },
+        { CMD(COPS),        true },
+        { CMD(WRMP),        false },
+        { CMD(CCSS),        false },
+        { CMD(CSQ),         false },
+        { CMD(CLCC),        true },
+        { CMD(CCFCU),       true },
+        { CMD(CCWA),        false },
+        { CMD(CUSATD),      false },
+        { CMD(CUSATP),      false },
+        { CMD(CUSATE),      false },
+        { CMD(CUSATT),      false },
+        { CMD(CUSATEND),    false },
+        { CMD(CGDCONT),     true },
+        { CMD(CGCONTRDP),   false },
+        { CMD(CLCK),        false },
+        { CMD(CSIM),        false },
+        { CMD(CGLA),        false },
+        { CMD(CCHC),        false },
+        { CMD(CLIP),        false },
+        { CMD(CLIR),        false },
+        { CMD(CMUT),        false },
+        { CMD(WSOS),        false },
+        { CMD(CSCA),        false },
+        { CMD(CSCB),        false },
+        { CMD(CMGS),        false },
+        { CMD(CMGW),        false },
+        { CMD(CmeError),    false },
+        { CMD(CmsError),    false },
+    };
+
+    static const ValueParser percentValueParsers[] = {
+        { CMD(CTZV),     false },
+        { CMD(CGFPCCFG), false },
+    };
+
+    static const ValueParser caretValueParsers[] = {
+        { CMD(MBAU),     false },
+    };
+#undef CMD
+
+    static constexpr std::string_view kRING = "RING\r"sv;
+    if (str.starts_with(kRING)) {
+        return { int(kRING.size()), AtResponse::make(RING()) };
+    }
+
+    static constexpr std::string_view kCMT = "+CMT:"sv;
+    if (str.starts_with(kCMT)) {
+        const std::string_view trimmed = ltrim(str.substr(kCMT.size()));
+        const auto [consumed, response] = AtResponse::CMT::parse(trimmed);
+        if (consumed > 0) {
+            return { int(consumed + str.size() - trimmed.size()), std::move(response) };
+        } else {
+            return { consumed, nullptr };
+        }
+    }
+
+    static constexpr std::string_view kCDS = "+CDS:"sv;
+    if (str.starts_with(kCDS)) {
+        const std::string_view trimmed = ltrim(str.substr(kCDS.size()));
+        const auto [consumed, response] = AtResponse::CDS::parse(trimmed);
+        if (consumed > 0) {
+            return { int(consumed + str.size() - trimmed.size()), std::move(response) };
+        } else {
+            return { consumed, nullptr };
+        }
+    }
+
+    switch (str.front()) {
+    case '+': return parseCmds(str,
+                               std::begin(plusValueParsers),
+                               std::end(plusValueParsers));
+
+    case '%': return parseCmds(str,
+                               std::begin(percentValueParsers),
+                               std::end(percentValueParsers));
+    case '^': return parseCmds(str,
+                               std::begin(caretValueParsers),
+                               std::end(caretValueParsers));
+    }
+
+    static constexpr std::string_view kSmsPrompt = "> \r"sv;
+    if (str.starts_with(kSmsPrompt)) {
+        return { int(kSmsPrompt.size()), AtResponse::make(SmsPrompt()) };
+    }
+
+    static constexpr std::string_view kOKr = "OK\r"sv;
+    if (str.starts_with(kOKr)) {
+        return { int(kOKr.size()), AtResponse::make(OK()) };
+    }
+
+    static constexpr std::string_view kERRORr = "ERROR\r"sv;
+    if (str.starts_with(kERRORr)) {
+        return { int(kERRORr.size()), AtResponse::make(ERROR()) };
+    }
+
+    const size_t pos = str.find(krOKr);
+    if (pos != str.npos) {
+        std::string value(str.begin(), str.begin() + pos);
+        return { int(pos + krOKr.size()), make(std::move(value)) };
+    }
+
+    return { 0, nullptr };
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CmeError"
+AtResponsePtr AtResponse::CmeError::parse(const std::string_view str) {
+    RadioError err;
+
+    if (str.compare(atCmds::kCmeErrorOperationNotAllowed) == 0) {
+        err = RadioError::OPERATION_NOT_ALLOWED;
+    } else if (str.compare(atCmds::kCmeErrorOperationNotSupported) == 0) {
+        err = RadioError::REQUEST_NOT_SUPPORTED;
+    } else if (str.compare(atCmds::kCmeErrorSimNotInserted) == 0) {
+        err = RadioError::SIM_ABSENT;
+    } else if (str.compare(atCmds::kCmeErrorSimPinRequired) == 0) {
+        err = RadioError::SIM_PIN2;
+    } else if (str.compare(atCmds::kCmeErrorSimPukRequired) == 0) {
+        err = RadioError::SIM_PUK2;
+    } else if (str.compare(atCmds::kCmeErrorSimBusy) == 0) {
+        err = RadioError::SIM_BUSY;
+    } else if (str.compare(atCmds::kCmeErrorIncorrectPassword) == 0) {
+        err = RadioError::PASSWORD_INCORRECT;
+    } else if (str.compare(atCmds::kCmeErrorMemoryFull) == 0) {
+        err = RadioError::SIM_FULL;
+    } else if (str.compare(atCmds::kCmeErrorInvalidIndex) == 0) {
+        err = RadioError::INVALID_ARGUMENTS;
+    } else if (str.compare(atCmds::kCmeErrorNotFound) == 0) {
+        err = RadioError::NO_SUCH_ELEMENT;
+    } else if (str.compare(atCmds::kCmeErrorInvalidCharactersInTextString) == 0) {
+        err = RadioError::GENERIC_FAILURE;
+    } else if (str.compare(atCmds::kCmeErrorNoNetworkService) == 0) {
+        err = RadioError::NO_NETWORK_FOUND;
+    } else if (str.compare(atCmds::kCmeErrorNetworkNotAllowedEmergencyCallsOnly) == 0) {
+        err = RadioError::NETWORK_REJECT;
+    } else if (str.compare(atCmds::kCmeErrorInCorrectParameters) == 0) {
+        err = RadioError::INVALID_ARGUMENTS;
+    } else if (str.compare(atCmds::kCmeErrorNetworkNotAttachedDueToMTFunctionalRestrictions) == 0) {
+        err = RadioError::NETWORK_REJECT;
+    } else if (str.compare(atCmds::kCmeErrorFixedDialNumberOnlyAllowed) == 0) {
+        err = RadioError::GENERIC_FAILURE;
+    } else {
+        err = RadioError::GENERIC_FAILURE;
+    }
+
+    CmeError cmeErr = {
+        .error = err,
+    };
+
+    return make(std::move(cmeErr));
+}
+
+RadioError AtResponse::CmeError::getErrorAndLog(
+        const char* klass, const char* func, int line) const {
+    RLOGE("%s:%s:%d failure: %s", klass, func, line,
+          toString(error).c_str());
+    return error;
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CmsError"
+AtResponsePtr AtResponse::CmsError::parse(const std::string_view str) {
+    CmsError cmsErr = {
+        .message = toString(str),
+    };
+
+    return make(std::move(cmsErr));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CPIN"
+AtResponsePtr AtResponse::CPIN::parse(const std::string_view str) {
+    CPIN cpin;
+    if (str == "READY"sv) {
+        cpin.state = CPIN::State::READY;
+    } else if (str == "SIM PIN"sv) {
+        cpin.state = CPIN::State::PIN;
+    } else if (str == "SIM PUK"sv) {
+        cpin.state = CPIN::State::PUK;
+    } else {
+        return FAILURE_V(makeParseErrorFor<CPIN>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(cpin));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CPINR"
+AtResponsePtr AtResponse::CPINR::parse(const std::string_view str) {
+    CPINR cpinr;
+
+    Parser parser(str);
+    std::string_view unused;
+    if (!parser(&unused, ',')
+               (&cpinr.remainingRetryTimes).skip(',')
+               (&cpinr.maxRetryTimes).fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CPINR>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(cpinr));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CRSM"
+AtResponsePtr AtResponse::CRSM::parse(const std::string_view str) {
+    CRSM crsm;
+
+    Parser parser(str);
+    if (parser(&crsm.sw1).skip(',')(&crsm.sw2).hasMore()) {
+        if (parser.skip(',').matchSoFar()) {
+            crsm.response = toString(parser.remaining());
+        } else {
+            return FAILURE_V(makeParseErrorFor<CRSM>(),
+                             "Can't parse: '%*.*s'",
+                             int(str.size()), int(str.size()), str.data());
+        }
+    } else if (!parser.fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CRSM>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(crsm));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CFUN"
+AtResponsePtr AtResponse::CFUN::parse(const std::string_view str) {
+    using modem::RadioState;
+
+    int state;
+    Parser parser(str);
+    if (parser(&state).fullMatch()) {
+        CFUN cfun = {
+            .state = state ? RadioState::ON : RadioState::OFF,
+        };
+        return make(std::move(cfun));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CFUN>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CREG"
+AtResponsePtr AtResponse::CREG::parse(const std::string_view str) {
+    CREG creg;
+    Parser parser(str);
+    std::string_view areaCodeHex;
+    std::string_view cellIdHex;
+    int unsolMode;
+    int state;
+
+    switch (std::count(str.begin(), str.end(), ',')) {
+    case 0:  // state
+        if (parser(&state).fullMatch()) {
+            creg.state = static_cast<network::RegState>(state);
+            return make(std::move(creg));
+        }
+        break;
+
+    case 1:  // unsolMode,state
+        if (parser(&unsolMode).skip(',')(&state).fullMatch()) {
+            creg.state = static_cast<network::RegState>(state);
+            return make(std::move(creg));
+        }
+        break;
+
+    case 3:  // state,areaCode,cellId,networkType
+        if (parser(&state).skip(',').skip('"')(&areaCodeHex, '"')
+                  .skip(',').skip('"')(&cellIdHex, '"').skip(',')
+                  (&creg.networkType).fullMatch()) {
+            std::from_chars(areaCodeHex.begin(), areaCodeHex.end(), creg.areaCode, 16);
+            std::from_chars(cellIdHex.begin(), cellIdHex.end(), creg.cellId, 16);
+            creg.state = static_cast<network::RegState>(state);
+            return make(std::move(creg));
+        }
+        break;
+
+    case 4:  // unsolMode,state,areaCode,cellId,networkType
+        if (parser(&unsolMode).skip(',')
+                  (&state).skip(',')
+                  .skip('"')(&areaCodeHex, '"').skip(',')
+                  .skip('"')(&cellIdHex, '"').skip(',')
+                  (&creg.networkType).fullMatch()) {
+            std::from_chars(areaCodeHex.begin(), areaCodeHex.end(), creg.areaCode, 16);
+            std::from_chars(cellIdHex.begin(), cellIdHex.end(), creg.cellId, 16);
+            creg.state = static_cast<network::RegState>(state);
+            return make(std::move(creg));
+        }
+        break;
+    }
+
+    return FAILURE_V(makeParseErrorFor<CREG>(),
+                     "Can't parse: '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CGREG"
+AtResponsePtr AtResponse::CGREG::parse(const std::string_view str) {
+    CGREG cgreg;
+    Parser parser(str);
+    std::string_view areaCodeHex;
+    std::string_view cellIdHex;
+    int unsolMode;
+    int state;
+
+    switch (std::count(str.begin(), str.end(), ',')) {
+    case 0:  // state
+        if (parser(&state).fullMatch()) {
+            cgreg.state = static_cast<network::RegState>(state);
+            return make(std::move(cgreg));
+        }
+        break;
+
+    case 1:  // unsolMode,state
+        if (parser(&unsolMode).skip(',')(&state).fullMatch()) {
+            cgreg.state = static_cast<network::RegState>(state);
+            return make(std::move(cgreg));
+        }
+        break;
+
+    case 3:  // state,areaCode,cellId,networkType
+        if (parser(&state).skip(',').skip('"')(&areaCodeHex, '"')
+                  .skip(',').skip('"')(&cellIdHex, '"').skip(',')
+                  (&cgreg.networkType).fullMatch()) {
+            std::from_chars(areaCodeHex.begin(), areaCodeHex.end(), cgreg.areaCode, 16);
+            std::from_chars(cellIdHex.begin(), cellIdHex.end(), cgreg.cellId, 16);
+            cgreg.state = static_cast<network::RegState>(state);
+            return make(std::move(cgreg));
+        }
+        break;
+
+    case 4:  // unsolMode,state,areaCode,cellId,networkType
+        if (parser(&unsolMode).skip(',')
+                  (&state).skip(',')
+                  .skip('"')(&areaCodeHex, '"').skip(',')
+                  .skip('"')(&cellIdHex, '"').skip(',')
+                  (&cgreg.networkType).fullMatch()) {
+            std::from_chars(areaCodeHex.begin(), areaCodeHex.end(), cgreg.areaCode, 16);
+            std::from_chars(cellIdHex.begin(), cellIdHex.end(), cgreg.cellId, 16);
+            cgreg.state = static_cast<network::RegState>(state);
+            return make(std::move(cgreg));
+        }
+        break;
+    }
+
+    return FAILURE_V(makeParseErrorFor<CGREG>(),
+                     "Can't parse: '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CEREG"
+AtResponsePtr AtResponse::CEREG::parse(const std::string_view str) {
+    CEREG cereg;
+    Parser parser(str);
+    std::string_view areaCodeHex;
+    std::string_view cellIdHex;
+    int unsolMode;
+    int state;
+
+    switch (std::count(str.begin(), str.end(), ',')) {
+    case 0:  // state
+        if (parser(&state).fullMatch()) {
+            cereg.state = static_cast<network::RegState>(state);
+            return make(std::move(cereg));
+        }
+        break;
+
+    case 1:  // unsolMode,state
+        if (parser(&unsolMode).skip(',')(&state).fullMatch()) {
+            cereg.state = static_cast<network::RegState>(state);
+            return make(std::move(cereg));
+        }
+        break;
+
+    case 3:  // state,areaCode,cellId,networkType
+        if (parser(&state).skip(',').skip('"')(&areaCodeHex, '"')
+                  .skip(',').skip('"')(&cellIdHex, '"').skip(',')
+                  (&cereg.networkType).fullMatch()) {
+            std::from_chars(areaCodeHex.begin(), areaCodeHex.end(), cereg.areaCode, 16);
+            std::from_chars(cellIdHex.begin(), cellIdHex.end(), cereg.cellId, 16);
+            cereg.state = static_cast<network::RegState>(state);
+            return make(std::move(cereg));
+        }
+        break;
+
+    case 4:  // unsolMode,state,areaCode,cellId,networkType
+        if (parser(&unsolMode).skip(',')
+                  (&state).skip(',')
+                  .skip('"')(&areaCodeHex, '"').skip(',')
+                  .skip('"')(&cellIdHex, '"').skip(',')
+                  (&cereg.networkType).fullMatch()) {
+            std::from_chars(areaCodeHex.begin(), areaCodeHex.end(), cereg.areaCode, 16);
+            std::from_chars(cellIdHex.begin(), cellIdHex.end(), cereg.cellId, 16);
+            cereg.state = static_cast<network::RegState>(state);
+            return make(std::move(cereg));
+        }
+        break;
+    }
+
+    return FAILURE_V(makeParseErrorFor<CEREG>(),
+                     "Can't parse: '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CTEC"
+/*      +CTEC: current (decimal),preferred_bitmask (hex)
+ *  OR
+ *      +CTEC: comma_separated_list_of_supported (decimal)
+ *  OR
+ *      +CTEC: current (decimal)
+ *  OR
+ *      +CTEC: DONE
+*/
+AtResponsePtr AtResponse::CTEC::parse(const std::string_view str) {
+    CTEC ctec;
+
+    size_t i = 0;
+    while (true) {
+        const size_t comma = str.find(',', i);
+        if (comma != std::string_view::npos) {
+            ctec.values.push_back(std::string(str.substr(i, comma - i)));
+            i = comma + 1;
+        } else {
+            ctec.values.push_back(std::string(str.substr(i)));
+            break;
+        }
+    }
+
+    return make(std::move(ctec));
+}
+
+std::optional<ratUtils::ModemTechnology> AtResponse::CTEC::getCurrentModemTechnology() const {
+    using ratUtils::ModemTechnology;
+
+    if ((values.size() == 0) || (values.size() > 2) ||
+            ((values.size() == 1) && (values[0] == "DONE"))) {
+        return std::nullopt;
+    }
+
+    int mtech;
+    std::from_chars_result r =
+        std::from_chars(&*values[0].begin(), &*values[0].end(), mtech, 10);
+
+    if ((r.ec != std::errc()) || (r.ptr != &*values[0].end())) {
+        return FAILURE(std::nullopt);
+    }
+
+    for (unsigned i = static_cast<unsigned>(ModemTechnology::GSM);
+                  i <= static_cast<unsigned>(ModemTechnology::NR); ++i) {
+        if (mtech & (1U << i)) {
+            return static_cast<ratUtils::ModemTechnology>(i);
+        }
+    }
+
+    return FAILURE(std::nullopt);
+}
+
+bool AtResponse::CTEC::isDONE() const {
+    return (values.size() == 1) && (values[0] == "DONE");
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "COPS"
+/*      "+COPS: 0,0,longName\r+COPS: 0,1,shortName\r+COPS: 0,2,numeric\r"
+ *  OR
+ *      "+COPS: (state,longName,shortName,numeric),(...),...\r"
+ *  OR
+ *      "+COPS: selectionMode,2,numeric\r"
+ *  OR
+ *      "+COPS: selectionMode,0,0\r"
+ *  OR
+ *      "+COPS: 0,0,0\r"
+ */
+AtResponsePtr AtResponse::COPS::parse(const std::string_view str) {
+    COPS cops;
+
+    Parser parser(str);
+    if (!parser.skip("+COPS:").skip(' ').hasMore()) { goto err; }
+
+    if (parser.front() == '(') {
+        while (parser.matchSoFar()) {
+            COPS::OperatorInfo operatorInfo;
+            int state;
+
+            if (parser.skip('(')(&state).skip(',')
+                                (&operatorInfo.longName, ',')
+                                (&operatorInfo.shortName, ',')
+                                (&operatorInfo.numeric, ')').matchSoFar()) {
+                operatorInfo.state = static_cast<COPS::OperatorInfo::State>(state);
+                cops.operators.push_back(std::move(operatorInfo));
+
+                if (parser.front() == ',') {
+                    parser.skip(',');
+                } else {
+                    break;
+                }
+            } else {
+                goto err;
+            }
+        }
+
+        return make(std::move(cops));
+    } else {
+        std::string str;
+        int networkSelectionMode, n;
+
+        if (!parser(&networkSelectionMode).skip(',')(&n).skip(',')(&str, kCR).matchSoFar()) {
+            goto err;
+        }
+
+        if ((n == 2) && parser.fullMatch()) {
+            cops.networkSelectionMode = static_cast<COPS::NetworkSelectionMode>(networkSelectionMode);
+            cops.numeric = std::move(str);
+            return make(std::move(cops));
+        } else if (n != 0) {
+            goto err;
+        } else if ((str == "0") && parser.fullMatch()) {
+            cops.networkSelectionMode = static_cast<COPS::NetworkSelectionMode>(networkSelectionMode);
+            return make(std::move(cops));
+        }
+
+        COPS::OperatorInfo operatorInfo;
+        operatorInfo.state = COPS::OperatorInfo::State::CURRENT;
+        operatorInfo.longName = std::move(str);
+
+        if (!parser.skip("+COPS:").skip(' ').skip("0,1,")(&operatorInfo.shortName, kCR)
+                   .skip("+COPS:").skip(' ').skip("0,2,")(&operatorInfo.numeric, kCR)
+                   .fullMatch()) {
+            goto err;
+        }
+
+        cops.operators.push_back(std::move(operatorInfo));
+        return make(std::move(cops));
+    }
+
+err:
+    return FAILURE_V(makeParseErrorFor<COPS>(),
+                     "Can't parse: '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "WRMP"
+AtResponsePtr AtResponse::WRMP::parse(const std::string_view str) {
+    int cdmaRoamingPreference;
+
+    Parser parser(str);
+    if (!parser(&cdmaRoamingPreference).fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<WRMP>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    WRMP wrmp = {
+        .cdmaRoamingPreference =
+            static_cast<network::CdmaRoamingType>(cdmaRoamingPreference),
+    };
+
+    return make(std::move(wrmp));
+}
+
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CCSS"
+AtResponsePtr AtResponse::CCSS::parse(const std::string_view str) {
+    CCSS ccss;
+    int source;
+
+    Parser parser(str);
+    if (parser(&source).fullMatch()) {
+        ccss.source = static_cast<sim::CdmaSubscriptionSource>(source);
+        return make(std::move(ccss));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CCSS>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CSQ"
+AtResponsePtr AtResponse::CSQ::parse(const std::string_view str) {
+    constexpr size_t kMaxSize = 22;
+    int values[kMaxSize];
+
+    Parser parser(str);
+    if (!parser(&values[0]).matchSoFar()) {
+        return FAILURE_V(makeParseErrorFor<CSQ>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    size_t n;
+    for (n = 1; parser.hasMore() && (n < kMaxSize); ++n) {
+        if (!parser.skip(',')(&values[n]).matchSoFar()) {
+            return FAILURE_V(makeParseErrorFor<CSQ>(),
+                             "Can't parse: '%*.*s'",
+                             int(str.size()), int(str.size()), str.data());
+        }
+    }
+
+    if (!parser.fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CSQ>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    CSQ csq;
+    switch (n) {
+    case 22:
+        csq.wcdma_signalStrength = values[14];
+        if (csq.wcdma_signalStrength != kUnknown) {
+            csq.wcdma_rscp = 42;
+            csq.wcdma_ecno = 19;
+        }
+        csq.wcdma_bitErrorRate = values[15];
+        csq.nr_ssRsrp = values[16];
+        csq.nr_ssRsrq = values[17];
+        csq.nr_ssSinr = values[18];
+        csq.nr_csiRsrp = values[19];
+        csq.nr_csiRsrq = values[20];
+        csq.nr_csiSinr = values[21];
+        [[fallthrough]];
+
+    case 14:
+        csq.tdscdma_rscp = values[13];
+        [[fallthrough]];
+
+    case 13:
+        csq.lte_timingAdvance = values[12];
+        [[fallthrough]];
+
+    case 12:
+        csq.gsm_signalStrength = values[0];
+        csq.gsm_bitErrorRate = values[1];
+        csq.cdma_dbm = values[2];
+        csq.cdma_ecio = values[3];
+        csq.evdo_dbm = values[4];
+        csq.evdo_ecio = values[5];
+        csq.evdo_signalNoiseRatio = values[6];
+        csq.lte_signalStrength = values[7];
+        csq.lte_rsrp = values[8];
+        csq.lte_rsrq = values[9];
+        csq.lte_rssnr = values[10];
+        csq.lte_cqi = values[11];
+        break;
+
+    default:
+        return FAILURE_V(makeParseErrorFor<CSQ>(),
+                         "Unexpected size: %zu", n);
+    }
+
+    return make(std::move(csq));
+}
+
+network::SignalStrength AtResponse::CSQ::toSignalStrength() const {
+    return {
+        .gsm = {
+            .signalStrength = gsm_signalStrength,
+            .bitErrorRate = gsm_bitErrorRate,
+            .timingAdvance = gsm_timingAdvance,
+        },
+        .cdma = {
+            .dbm = cdma_dbm,
+            .ecio = cdma_ecio,
+        },
+        .evdo = {
+            .dbm = evdo_dbm,
+            .ecio = evdo_ecio,
+            .signalNoiseRatio = evdo_signalNoiseRatio,
+        },
+        .lte = {
+            .signalStrength = lte_signalStrength,
+            .rsrp = lte_rsrp,
+            .rsrq = lte_rsrq,
+            .rssnr = lte_rssnr,
+            .cqi = lte_cqi,
+            .timingAdvance = lte_timingAdvance,
+            .cqiTableIndex = lte_cqiTableIndex,
+        },
+        .tdscdma = {
+            .signalStrength = tdscdma_signalStrength,
+            .bitErrorRate = tdscdma_bitErrorRate,
+            .rscp = tdscdma_rscp,
+        },
+        .wcdma = {
+            .signalStrength = wcdma_signalStrength,
+            .bitErrorRate = wcdma_bitErrorRate,
+            .rscp = wcdma_rscp,
+            .ecno = wcdma_ecno,
+        },
+        .nr = {
+            .ssRsrp = nr_ssRsrp,
+            .ssRsrq = nr_ssRsrq,
+            .ssSinr = nr_ssSinr,
+            .csiRsrp = nr_csiRsrp,
+            .csiRsrq = nr_csiRsrq,
+            .csiSinr = nr_csiSinr,
+            .csiCqiTableIndex = nr_csiCqiTableIndex,
+            .timingAdvance = nr_timingAdvance,
+        },
+    };
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CLCC"
+AtResponsePtr AtResponse::CLCC::parse(const std::string_view str) {
+    CLCC clcc;
+
+    Parser parser(str);
+    while (parser.hasMore()) {
+        int index;
+        int dir;
+        int state;
+        int mode;
+        int mpty;
+        int type;
+        std::string number;
+
+        // +CLCC: <index>,<dir>,<state>,<mode>,<mpty>,<number>,<type>\r
+        if (parser.skip("+CLCC:").skip(' ')(&index).skip(',')
+                  (&dir).skip(',')(&state).skip(',')
+                  (&mode).skip(',')(&mpty).skip(',')
+                  (&number, ',')(&type).skip(kCR).matchSoFar()) {
+
+            voice::Call call = {
+                .state = state,
+                .index = index,
+                .toa = type,
+                .isMpty = (mpty != 0),
+                .isMT = (dir != 0),
+                .isVoice = (mode == 0),
+                .number = std::move(number),
+            };
+
+            clcc.calls.push_back(std::move(call));
+        } else {
+            return FAILURE_V(makeParseErrorFor<CLCC>(),
+                             "Can't parse '%*.*s'",
+                             int(str.size()), int(str.size()), str.data());
+        }
+    }
+
+    return make(std::move(clcc));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CCFCU"
+AtResponsePtr AtResponse::CCFCU::parse(const std::string_view str) {
+    CCFCU ccfcu;
+
+    Parser parser(str);
+    while (parser.hasMore()) {
+        voice::CallForwardInfo cfi;
+        int numberType;
+        std::string_view ignore;
+        if (parser.skip("+CCFCU:").skip(' ')(&cfi.status).skip(',')
+                (&cfi.serviceClass).skip(',')(&numberType).skip(',')
+                (&cfi.toa).skip(',').skip('"')(&cfi.number, '"').matchSoFar()) {
+            switch (parser.front()) {
+            case ',':
+                if (!parser.skip(',')(&ignore, ',')(&ignore, ',')
+                          (&cfi.timeSeconds).skip(kCR).matchSoFar()) {
+                    return FAILURE_V(makeParseErrorFor<CCFCU>(),
+                                     "Can't parse '%*.*s'",
+                                     int(str.size()), int(str.size()), str.data());
+                }
+                break;
+
+            case kCR:
+                parser.skip(kCR);
+                break;
+
+            default:
+                return FAILURE_V(makeParseErrorFor<CCFCU>(),
+                                 "Can't parse '%*.*s'",
+                                 int(str.size()), int(str.size()), str.data());
+            }
+
+            ccfcu.callForwardInfos.push_back(std::move(cfi));
+        } else {
+            return FAILURE_V(makeParseErrorFor<CCFCU>(),
+                             "Can't parse '%*.*s'",
+                             int(str.size()), int(str.size()), str.data());
+        }
+    }
+
+    return make(std::move(ccfcu));
+}
+
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CCWA"
+AtResponsePtr AtResponse::CCWA::parse(const std::string_view str) {
+    CCWA ccwa;
+    int mode;
+
+    Parser parser(str);
+    if (parser(&mode).skip(',')(&ccwa.serviceClass).fullMatch()) {
+        ccwa.enable = (mode == 1);
+        return make(std::move(ccwa));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CCWA>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CUSATD"
+AtResponsePtr AtResponse::CUSATD::parse(const std::string_view str) {
+    CUSATD cusatd;
+
+    Parser parser(str);
+    if (parser(&cusatd.a).skip(',').skip(' ')(&cusatd.a).fullMatch()) {
+        return make(std::move(cusatd));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CUSATD>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CUSATP"
+AtResponsePtr AtResponse::CUSATP::parse(const std::string_view str) {
+    CUSATP cusatp = {
+        .cmd = toString(str),
+    };
+
+    return make(std::move(cusatp));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CUSATE"
+AtResponsePtr AtResponse::CUSATE::parse(const std::string_view str) {
+    CUSATE cusate = {
+        .response = toString(str),
+    };
+
+    return make(std::move(cusate));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CUSATT"
+AtResponsePtr AtResponse::CUSATT::parse(const std::string_view str) {
+    CUSATT cusatt;
+
+    Parser parser(str);
+    if (parser(&cusatt.value).fullMatch()) {
+        return make(std::move(cusatt));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CUSATT>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CUSATEND"
+AtResponsePtr AtResponse::CUSATEND::parse(const std::string_view) {
+    return make(CUSATEND());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CLCK"
+AtResponsePtr AtResponse::CLCK::parse(const std::string_view str) {
+    CLCK clck;
+
+    switch (str.front()) {
+    case '0': clck.locked = false; break;
+    case '1': clck.locked = true; break;
+    default:
+        return FAILURE_V(makeParseErrorFor<CLCK>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(clck));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CSIM"
+AtResponsePtr AtResponse::CSIM::parse(const std::string_view str) {
+    Parser parser(str);
+    int len;
+
+    if (parser(&len).skip(',').matchSoFar()) {
+        const std::string_view response = parser.remaining();
+
+        if (len == response.size()) {
+            CSIM csim = {
+                .response = toString(response),
+            };
+
+            return make(std::move(csim));
+        }
+    }
+
+    return FAILURE_V(makeParseErrorFor<CSIM>(),
+                     "Can't parse '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CGLA"
+AtResponsePtr AtResponse::CGLA::parse(const std::string_view str) {
+    Parser parser(str);
+    int len;
+
+    if (parser(&len).skip(',').matchSoFar()) {
+        const std::string_view response = parser.remaining();
+
+        if (len == response.size()) {
+            CGLA cgla = {
+                .response = toString(response),
+            };
+
+            return make(std::move(cgla));
+        }
+    }
+
+    return FAILURE_V(makeParseErrorFor<CGLA>(),
+                     "Can't parse '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CCHC"
+AtResponsePtr AtResponse::CCHC::parse(const std::string_view) {
+    return make(CCHC());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CLIP"
+AtResponsePtr AtResponse::CLIP::parse(const std::string_view str) {
+    int enable;
+    int status;
+
+    Parser parser(str);
+    if (parser(&enable).skip(',')(&status).fullMatch()) {
+        CLIP clip;
+        clip.enable = enable != 0;
+        clip.status = static_cast<voice::ClipStatus>(status);
+
+        return make(std::move(clip));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CLIP>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CLIR"
+AtResponsePtr AtResponse::CLIR::parse(const std::string_view str) {
+    CLIR clir;
+    Parser parser(str);
+    if (parser(&clir.n).skip(',')(&clir.m).fullMatch()) {
+        return make(std::move(clir));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CLIR>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CMUT"
+AtResponsePtr AtResponse::CMUT::parse(const std::string_view str) {
+    int on;
+    Parser parser(str);
+    if (parser(&on).fullMatch()) {
+        CMUT cmut;
+        cmut.on = (on != 0);
+        return make(std::move(cmut));
+    } else {
+        return FAILURE_V(makeParseErrorFor<CMUT>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "WSOS"
+AtResponsePtr AtResponse::WSOS::parse(const std::string_view str) {
+    int isEmergencyMode;
+    Parser parser(str);
+    if (parser(&isEmergencyMode).fullMatch()) {
+        WSOS wsos;
+        wsos.isEmergencyMode = (isEmergencyMode != 0);
+        return make(std::move(wsos));
+    } else {
+        return FAILURE_V(makeParseErrorFor<WSOS>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CSCA"
+AtResponsePtr AtResponse::CSCA::parse(const std::string_view str) {
+    CSCA csca;
+
+    Parser parser(str);
+    if (!parser(&csca.sca, ',')(&csca.tosca).fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CSCA>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(csca));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CSCB"
+AtResponsePtr AtResponse::CSCB::parse(const std::string_view str) {
+    CSCB cscb;
+    std::string_view serviceId;
+    std::string_view codeScheme;
+
+    Parser parser(str);
+    if (!parser(&cscb.mode).skip(',')
+               .skip('"')(&serviceId, '"').skip(',')
+               .skip('"')(&codeScheme, '"').fullMatch()) {
+fail:   return FAILURE_V(makeParseErrorFor<CSCB>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    auto maybeIds = parseIds(serviceId);
+    if (!maybeIds) {
+        goto fail;
+    }
+    cscb.serviceId = std::move(maybeIds.value());
+
+    maybeIds = parseIds(codeScheme);
+    if (!maybeIds) {
+        goto fail;
+    }
+    cscb.codeScheme = std::move(maybeIds.value());
+
+    return make(std::move(cscb));
+}
+
+std::optional<std::vector<AtResponse::CSCB::Association>>
+AtResponse::CSCB::parseIds(const std::string_view str) {
+    std::vector<Association> ids;
+    Parser parser(str);
+    while (parser.hasMore()) {
+        Association a;
+        if (!parser(&a.from).matchSoFar()) {
+            return std::nullopt;
+        }
+
+        if (parser.fullMatch()) {
+            a.to = a.from;
+            ids.push_back(a);
+            break;
+        }
+
+        switch (parser.front()) {
+        case '-':
+            if (!parser.skip('-')(&a.to).matchSoFar()) {
+                return std::nullopt;
+            }
+            ids.push_back(a);
+            if (parser.fullMatch()) {
+                break;
+            } else if (parser.front() == ',') {
+                parser.skip(',');
+            } else {
+                return std::nullopt;
+            }
+            break;
+
+        case ',':
+            parser.skip(',');
+            break;
+
+        default:
+            return std::nullopt;
+        }
+    }
+
+    return ids;
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CMGS"
+AtResponsePtr AtResponse::CMGS::parse(const std::string_view str) {
+    CMGS cmgs;
+
+    Parser parser(str);
+    if (!parser(&cmgs.messageRef).fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CMGS>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(cmgs));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CMGW"
+AtResponsePtr AtResponse::CMGW::parse(const std::string_view str) {
+    CMGW cmgw;
+
+    Parser parser(str);
+    if (!parser(&cmgw.messageRef).fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CMGS>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    return make(std::move(cmgw));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CMT"
+std::pair<int, AtResponsePtr> AtResponse::CMT::parse(const std::string_view str) {
+    CMT cmt;
+    std::string strPdu;
+
+    Parser parser(str);
+    if (parser(&cmt.something).skip(kCR).matchSoFar()) {
+        if (parser(&strPdu, kCR).matchSoFar()) {
+            if (hex2bin(strPdu, &cmt.pdu)) {
+                return { parser.consumed(), make(std::move(cmt)) };
+            }
+        } else {
+            return { 0, nullptr };
+        }
+    }
+
+    auto err = std::make_pair(-1, makeParseErrorFor<CMT>());
+    return FAILURE_V(err, "Can't parse '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CDS"
+std::pair<int, AtResponsePtr> AtResponse::CDS::parse(const std::string_view str) {
+    CDS cds;
+    std::string strPdu;
+
+    Parser parser(str);
+    if (parser(&cds.pduSize).skip(kCR).matchSoFar()) {
+        if (parser(&strPdu, kCR).matchSoFar()) {
+            if (hex2bin(strPdu, &cds.pdu)) {
+                return { parser.consumed(), make(std::move(cds)) };
+            }
+        } else {
+            return { 0, nullptr };
+        }
+    }
+
+    auto err = std::make_pair(-1, makeParseErrorFor<CDS>());
+    return FAILURE_V(err, "Can't parse '%*.*s'",
+                     int(str.size()), int(str.size()), str.data());
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CGDCONT"
+// +CGDCONT: <cid>,<pdp_type>,<APN>,<pdp_addr>,<d_comp>,<h_comp>\r
+// 1,"IPV6","fast.t-mobile.com",,0,0
+AtResponsePtr AtResponse::CGDCONT::parse(const std::string_view str) {
+    CGDCONT cgdcont;
+
+    Parser parser(str);
+    while (parser.hasMore()) {
+        CGDCONT::PdpContext pdpContext;
+
+        if (parser.skip("+CGDCONT:").skip(' ')(&pdpContext.index).skip(',')
+                  .skip('"')(&pdpContext.type, '"').skip(',')
+                  .skip('"')(&pdpContext.apn, '"').skip(',')
+                  (&pdpContext.addr, ',')(&pdpContext.dComp)
+                  .skip(',')(&pdpContext.hComp).skip(' ').matchSoFar()) {
+            cgdcont.contexts.push_back(std::move(pdpContext));
+        } else {
+            return FAILURE_V(makeParseErrorFor<CGDCONT>(),
+                             "Can't parse '%*.*s'",
+                             int(str.size()), int(str.size()), str.data());
+        }
+    }
+
+    return make(std::move(cgdcont));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CGCONTRDP"
+// 1,5,"epc.tmobile.com",10.0.2.15/24,10.0.2.2,10.0.2.3
+// 1,5,"epc.tmobile.com",10.0.2.15,10.0.2.2,10.0.2.3
+AtResponsePtr AtResponse::CGCONTRDP::parse(const std::string_view str) {
+    CGCONTRDP cgcontrdp;
+    std::string_view unused;
+    std::string_view localAddr;
+
+    Parser parser(str);
+    if (parser(&cgcontrdp.cid).skip(',')(&cgcontrdp.bearer).skip(',')
+               .skip('"')(&cgcontrdp.apn, '"').skip(',')
+               (&localAddr, ',')
+               (&cgcontrdp.gwAddr, ',').matchSoFar()) {
+        cgcontrdp.dns1 = parser.remainingAsString();
+    } else {
+        return FAILURE_V(makeParseErrorFor<CGCONTRDP>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    Parser localAddrParser(localAddr);
+    if (!localAddrParser(&cgcontrdp.localAddr, '/')
+                        (&cgcontrdp.localAddrSize).fullMatch()) {
+        cgcontrdp.localAddr = std::string(localAddr.data(), localAddr.size());
+        cgcontrdp.localAddrSize = 0;
+    }
+
+    return make(std::move(cgcontrdp));
+}
+
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CGFPCCFG"
+// 1,5000,32,0,1
+AtResponsePtr AtResponse::CGFPCCFG::parse(const std::string_view str) {
+    CGFPCCFG cgfpccfg;
+    int status;
+    int mtech;
+
+    Parser parser(str);
+    if (!parser(&status).skip(',')
+               (&cgfpccfg.bandwidth).skip(',')
+               (&mtech).skip(',')
+               (&cgfpccfg.freq).skip(',')
+               (&cgfpccfg.contextId).fullMatch()) {
+        return FAILURE_V(makeParseErrorFor<CGFPCCFG>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    cgfpccfg.status = static_cast<network::CellConnectionStatus>(status);
+    cgfpccfg.mtech = static_cast<ratUtils::ModemTechnology>(mtech);
+
+    return make(std::move(cgfpccfg));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "MBAU"
+// <STATUS>,<KC>,<SRES>
+// <STATUS>,<CK>,<IK>,<RES/AUTS>
+AtResponsePtr AtResponse::MBAU::parse(const std::string_view str) {
+    MBAU mbau;
+
+    std::string_view kc;
+    std::string_view sres;
+    std::string_view ck;
+    std::string_view ik;
+    std::string_view resAuts;
+
+    Parser parser(str);
+    switch (std::count(str.begin(), str.end(), ',')) {
+    default:
+failed:
+        return FAILURE_V(makeParseErrorFor<MBAU>(),
+                         "Can't parse '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+
+    case 0:
+        if (!parser(&mbau.status).fullMatch()) {
+            goto failed;
+        }
+        break;
+
+    case 2:
+        if (parser(&mbau.status).skip(',')(&kc, ',').matchSoFar()) {
+            sres = parser.remaining();
+        } else {
+            goto failed;
+        }
+        break;
+
+    case 3:
+        if (parser(&mbau.status).skip(',')(&ck, ',')(&ik, ',').matchSoFar()) {
+            resAuts = parser.remaining();
+        } else {
+            goto failed;
+        }
+        break;
+    }
+
+    if (!hex2bin(kc, &mbau.kc) || !hex2bin(sres, &mbau.sres) || !hex2bin(ck, &mbau.ck) ||
+            !hex2bin(ik, &mbau.ik) || !hex2bin(resAuts, &mbau.resAuts)) {
+        goto failed;
+    }
+
+    return make(std::move(mbau));
+}
+
+#undef FAILURE_DEBUG_PREFIX
+#define FAILURE_DEBUG_PREFIX "CTZV"
+// 24/11/05:17:01:32-32:0:America!Los_Angeles
+AtResponsePtr AtResponse::CTZV::parse(const std::string_view str) {
+    int yy, month, day, hh, mm, ss, tzOffset15m;
+    char tzSign, daylight;
+
+    Parser parser(str);
+    parser.skip(' ')(&yy).skip('/')(&month).skip('/')(&day).skip(':')
+          (&hh).skip(':')(&mm).skip(':')(&ss)
+          (&tzSign)(&tzOffset15m).skip(':')(&daylight).skip(':');
+
+    if (!parser.matchSoFar()) {
+        return FAILURE_V(makeParseErrorFor<CTZV>(),
+                         "Can't parse: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    switch (tzSign) {
+    case '+': break;
+    case '-': tzOffset15m = -tzOffset15m; break;
+    default:
+        return FAILURE_V(makeParseErrorFor<CTZV>(),
+                         "Unexpected timezone offset sign: '%*.*s'",
+                         int(str.size()), int(str.size()), str.data());
+    }
+
+    CTZV ctzv = {
+        .tzName = toString(parser.remaining()),
+        .year = uint16_t(yy + 2000),
+        .month = uint8_t(month),
+        .day = uint8_t(day),
+        .hour = uint8_t(hh),
+        .isDaylightSaving = uint8_t(daylight != '0'),
+        .minute = uint8_t(mm),
+        .second = uint8_t(ss),
+        .tzOffset15m = int8_t(tzOffset15m),
+    };
+
+    return make(std::move(ctzv));
+}
+
+std::string AtResponse::CTZV::nitzString() const {
+    return std::format("{:02d}/{:02d}/{:02d}:{:02d}:{:02d}:{:02d}{:+d}:{:d}:{:s}",
+                       year % 100, month, day, hour, minute, second,
+                       tzOffset15m, isDaylightSaving, tzName.c_str());
+}
+
+std::string_view AtResponse::what() const {
+    return visitR<std::string_view>(CmdIdVisitor());
+}
+
+void AtResponse::unexpected(const char* klass, const char* request,
+                            const std::source_location location) const {
+    const std::string_view r = what();
+    const int rl = r.size();
+
+    LOG_ALWAYS_FATAL("Unexpected response: '%*.*s' in %s:%s at %s:%d in %s", rl, rl, r.data(),
+                     klass, request, location.function_name(), location.line(),
+                     location.file_name());
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/AtResponse.h b/hals/radio/AtResponse.h
new file mode 100644
index 00000000..d479e99a
--- /dev/null
+++ b/hals/radio/AtResponse.h
@@ -0,0 +1,701 @@
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
+#include <memory>
+#include <string>
+#include <source_location>
+#include <string_view>
+#include <variant>
+
+#include <aidl/android/hardware/radio/RadioError.h>
+#include <aidl/android/hardware/radio/modem/RadioState.h>
+#include <aidl/android/hardware/radio/network/CellConnectionStatus.h>
+#include <aidl/android/hardware/radio/network/CdmaRoamingType.h>
+#include <aidl/android/hardware/radio/network/RegState.h>
+#include <aidl/android/hardware/radio/network/SignalStrength.h>
+#include <aidl/android/hardware/radio/RadioTechnology.h>
+#include <aidl/android/hardware/radio/sim/CdmaSubscriptionSource.h>
+#include <aidl/android/hardware/radio/voice/Call.h>
+#include <aidl/android/hardware/radio/voice/CallForwardInfo.h>
+#include <aidl/android/hardware/radio/voice/ClipStatus.h>
+
+#include "ratUtils.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+struct AtResponse;
+using AtResponsePtr = std::shared_ptr<const AtResponse>;
+
+struct AtResponse {
+    using ParseResult = std::pair<int, AtResponsePtr>;
+
+    struct OK {};
+    struct ERROR {};
+    struct RING {};
+    struct SmsPrompt {};
+
+    struct CmeError {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CME ERROR"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        RadioError getErrorAndLog(const char* klass,
+                                  const char* func, int line) const;
+
+        RadioError error;
+    };
+
+    struct CmsError {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CMS ERROR"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string message;
+    };
+
+    struct ParseError {
+        std::string_view cmd;
+    };
+
+    struct CPIN {
+        enum class State {
+            ABSENT, NOT_READY, READY, PIN, PUK
+        };
+
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CPIN"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        State state;
+    };
+
+    struct CPINR {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CPINR"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int remainingRetryTimes = -1;
+        int maxRetryTimes = -1;
+    };
+
+    struct CRSM {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CRSM"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string response;
+        int sw1 = -1;
+        int sw2 = -1;
+    };
+
+    struct CFUN {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CFUN"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        modem::RadioState state;
+    };
+
+    struct CIMI {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CIMI"sv;
+        }
+    };
+
+    struct CREG {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CREG"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int areaCode = -1;
+        int cellId = -1;
+        int networkType = -1;
+        network::RegState state = network::RegState::NOT_REG_MT_NOT_SEARCHING_OP;
+    };
+
+    struct CGREG {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CGREG"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int areaCode = -1;
+        int cellId = -1;
+        int networkType = -1;
+        network::RegState state = network::RegState::NOT_REG_MT_NOT_SEARCHING_OP;
+    };
+
+    struct CEREG {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CEREG"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int areaCode = -1;
+        int cellId = -1;
+        int networkType = -1;
+        network::RegState state = network::RegState::NOT_REG_MT_NOT_SEARCHING_OP;
+    };
+
+    struct CTEC {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CTEC"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::optional<ratUtils::ModemTechnology> getCurrentModemTechnology() const;
+        bool isDONE() const;
+
+        std::vector<std::string> values;
+    };
+
+    struct COPS {
+        enum class NetworkSelectionMode {
+            AUTOMATIC, MANUAL, DEREGISTER, SET_FORMAT, MANUAL_AUTOMATIC
+        };
+
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "COPS"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        struct OperatorInfo {
+            enum class State {
+                UNKNOWN, AVAILABLE, CURRENT, FORBIDDEN
+            };
+
+            bool isCurrent() const {
+                return state == State::CURRENT;
+            }
+
+            std::string mcc() const {
+                return numeric.substr(0, 3);
+            }
+
+            std::string mnc() const {
+                return numeric.substr(3);
+            }
+
+            State state = State::UNKNOWN;
+            std::string longName;
+            std::string shortName;
+            std::string numeric;
+        };
+
+        std::vector<OperatorInfo> operators;
+        std::string numeric;
+        NetworkSelectionMode networkSelectionMode = NetworkSelectionMode::AUTOMATIC;
+    };
+
+    struct WRMP {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "WRMP"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        network::CdmaRoamingType cdmaRoamingPreference;
+    };
+
+    struct CCSS {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CCSS"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        sim::CdmaSubscriptionSource source;
+    };
+
+    struct CSQ {
+        static constexpr int32_t kUnknown = INT32_MAX;
+
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CSQ"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        network::SignalStrength toSignalStrength() const;
+
+        int32_t gsm_signalStrength = kUnknown;
+        int32_t gsm_bitErrorRate = kUnknown;
+        int32_t gsm_timingAdvance = kUnknown;
+        int32_t cdma_dbm = kUnknown;
+        int32_t cdma_ecio = kUnknown;
+        int32_t evdo_dbm = kUnknown;
+        int32_t evdo_ecio = kUnknown;
+        int32_t evdo_signalNoiseRatio = kUnknown;
+        int32_t lte_signalStrength = kUnknown;
+        int32_t lte_rsrp = kUnknown;
+        int32_t lte_rsrq = kUnknown;
+        int32_t lte_rssnr = kUnknown;
+        int32_t lte_cqi = kUnknown;
+        int32_t lte_timingAdvance = kUnknown;
+        int32_t lte_cqiTableIndex = kUnknown;
+        int32_t tdscdma_signalStrength = kUnknown;
+        int32_t tdscdma_bitErrorRate = kUnknown;
+        int32_t tdscdma_rscp = kUnknown;
+        int32_t wcdma_signalStrength = kUnknown;
+        int32_t wcdma_bitErrorRate = kUnknown;
+        int32_t wcdma_rscp = kUnknown;
+        int32_t wcdma_ecno = kUnknown;
+        int32_t nr_ssRsrp = kUnknown;
+        int32_t nr_ssRsrq = kUnknown;
+        int32_t nr_ssSinr = kUnknown;
+        int32_t nr_csiRsrp = kUnknown;
+        int32_t nr_csiRsrq = kUnknown;
+        int32_t nr_csiSinr = kUnknown;
+        int32_t nr_csiCqiTableIndex = kUnknown;
+        int32_t nr_timingAdvance = kUnknown;
+    };
+
+    struct CLCC {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CLCC"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::vector<voice::Call> calls;
+    };
+
+    struct CCFCU {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CCFCU"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::vector<voice::CallForwardInfo> callForwardInfos;
+    };
+
+    struct CCWA {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CCWA"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int serviceClass = -1;
+        bool enable = false;
+    };
+
+    struct CGDCONT {
+        struct PdpContext {
+            std::string type;
+            std::string apn;
+            std::string addr;
+            int index = -1;
+            int dComp = 0;
+            int hComp = 0;
+        };
+
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CGDCONT"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::vector<PdpContext> contexts;
+    };
+
+    struct CGCONTRDP {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CGCONTRDP"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string apn;
+        std::string localAddr;
+        std::string gwAddr;
+        std::string dns1;
+        std::string dns2;
+        int cid = -1;
+        int bearer = -1;
+        int localAddrSize = 0;
+    };
+
+    struct CGFPCCFG {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CGFPCCFG"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        network::CellConnectionStatus status;
+        ratUtils::ModemTechnology mtech;
+        int contextId = -1;
+        int bandwidth = -1;
+        int freq = -1;
+    };
+
+    struct CUSATD {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CUSATD"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int a = 0;
+        int b = 0;
+    };
+
+    struct CUSATP {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CUSATP"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string cmd;
+    };
+
+    struct CUSATE {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CUSATE"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string response;
+    };
+
+    struct CUSATT {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CUSATT"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int value = 0;
+    };
+
+    struct CUSATEND {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CUSATEND"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+    };
+
+    struct CLCK {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CLCK"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        bool locked = false;
+    };
+
+    struct CSIM {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CSIM"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string response;
+    };
+
+    struct CGLA {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CGLA"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string response;
+    };
+
+    struct CCHC {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CCHC"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+    };
+
+    struct CLIP {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CLIP"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        bool enable = false;
+        voice::ClipStatus status = voice::ClipStatus::UNKNOWN;
+    };
+
+    struct CLIR {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CLIR"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int n = -1;
+        int m = -1;
+    };
+
+    struct CMUT {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CMUT"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        bool on = false;
+    };
+
+    struct WSOS {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "WSOS"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        bool isEmergencyMode = false;
+    };
+
+    struct CSCA {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CSCA"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string sca;
+        int tosca = -1;
+    };
+
+    struct CSCB {
+        struct Association {
+            int from;
+            int to;
+        };
+
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CSCB"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        static std::optional<std::vector<Association>> parseIds(std::string_view str);
+
+        std::vector<Association> serviceId;
+        std::vector<Association> codeScheme;
+        int mode = -1;
+    };
+
+    struct CMGS {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CMGS"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int messageRef = -1;
+    };
+
+    struct CMGW {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CMGW"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        int messageRef = -1;
+    };
+
+    struct CMT {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CMT"sv;
+        }
+        static std::pair<int, AtResponsePtr> parse(std::string_view str);
+
+        std::vector<uint8_t> pdu;
+        int something = -1;
+    };
+
+    struct CDS {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CDS"sv;
+        }
+        static std::pair<int, AtResponsePtr> parse(std::string_view str);
+
+        std::vector<uint8_t> pdu;
+        int pduSize = -1;
+    };
+
+    struct MBAU {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "MBAU"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::vector<uint8_t> kc;
+        std::vector<uint8_t> sres;
+        std::vector<uint8_t> ck;
+        std::vector<uint8_t> ik;
+        std::vector<uint8_t> resAuts;
+        int status;
+    };
+
+    struct CTZV {
+        static constexpr std::string_view id() {
+            using namespace std::literals;
+            return "CTZV"sv;
+        }
+        static AtResponsePtr parse(std::string_view str);
+
+        std::string nitzString() const;
+
+        std::string tzName;
+        uint16_t year = 0;
+        uint8_t month = 0;
+        uint8_t day = 0;
+        uint8_t hour : 7 = 0;
+        uint8_t isDaylightSaving : 1 = 0;
+        uint8_t minute = 0;
+        uint8_t second = 0;
+        int8_t tzOffset15m = 0;
+    };
+
+    static ParseResult parse(std::string_view str);
+
+    template <class T> static AtResponsePtr make(T v) {
+        const auto r = std::make_shared<AtResponse>(std::move(v));
+        const auto w = r->what();
+        return r;
+    }
+
+    template <class T> static AtResponsePtr makeParseErrorFor() {
+        ParseError parseError = {
+            .cmd = T::id(),
+        };
+
+        return make(std::move(parseError));
+    }
+
+    bool isOK() const {
+        return std::holds_alternative<OK>(value);
+    }
+
+    bool isERROR() const {
+        return std::holds_alternative<ERROR>(value);
+    }
+
+    bool isParseError() const {
+        return std::holds_alternative<ParseError>(value);
+    }
+
+    template <class T> bool holds() const {
+        if (std::holds_alternative<T>(value)) {
+            return true;
+        } else if (const ParseError* e = std::get_if<ParseError>(&value)) {
+            return e->cmd.compare(T::id()) == 0;
+        } else {
+            return false;
+        }
+    }
+
+    template <> bool holds<OK>() const {
+        return std::holds_alternative<OK>(value);
+    }
+
+    template <> bool holds<SmsPrompt>() const {
+        return std::holds_alternative<SmsPrompt>(value);
+    }
+
+    template <> bool holds<std::string>() const {
+        return std::holds_alternative<std::string>(value);
+    }
+
+    template <class T> const T* get_if() const {
+        return std::get_if<T>(&value);
+    }
+
+    std::string_view what() const;
+
+    template <class F> void visit(const F& f) const {
+        std::visit(f, value);
+    }
+
+    template <class R, class F> R visitR(const F& f) const {
+        return std::visit(f, value);
+    }
+
+    [[noreturn]] void unexpected(
+            const char* klass, const char* request,
+            std::source_location location = std::source_location::current()) const;
+
+    template <class T> AtResponse(T v) : value(std::move(v)) {}
+
+private:
+    using Value = std::variant<OK, ParseError,
+                               ERROR, RING, SmsPrompt, CmeError, CmsError,
+                               CPIN, CPINR, CRSM, CFUN,
+                               CREG, CEREG, CGREG,
+                               CTEC, COPS, WRMP, CCSS, CSQ,
+                               CLCC, CCFCU, CCWA,
+                               CGDCONT, CGCONTRDP, CGFPCCFG,
+                               CUSATD, CUSATP, CUSATE, CUSATT, CUSATEND,
+                               CLCK, CSIM, CGLA, CCHC,
+                               CLIP, CLIR, CMUT, WSOS,
+                               CSCA, CSCB, CMGS, CMGW, CMT, CDS,
+                               MBAU,
+                               CTZV,
+                               std::string
+                  >;
+    Value value;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/radio/EmulatorRadioConfig/Android.bp b/hals/radio/EmulatorRadioConfig/Android.bp
similarity index 100%
rename from radio/EmulatorRadioConfig/Android.bp
rename to hals/radio/EmulatorRadioConfig/Android.bp
diff --git a/radio/EmulatorRadioConfig/AndroidManifest.xml b/hals/radio/EmulatorRadioConfig/AndroidManifest.xml
similarity index 100%
rename from radio/EmulatorRadioConfig/AndroidManifest.xml
rename to hals/radio/EmulatorRadioConfig/AndroidManifest.xml
diff --git a/radio/EmulatorRadioConfig/NOTICE b/hals/radio/EmulatorRadioConfig/NOTICE
similarity index 100%
rename from radio/EmulatorRadioConfig/NOTICE
rename to hals/radio/EmulatorRadioConfig/NOTICE
diff --git a/radio/EmulatorRadioConfig/com.android.emulator.radio.config.xml b/hals/radio/EmulatorRadioConfig/com.android.emulator.radio.config.xml
similarity index 100%
rename from radio/EmulatorRadioConfig/com.android.emulator.radio.config.xml
rename to hals/radio/EmulatorRadioConfig/com.android.emulator.radio.config.xml
diff --git a/radio/EmulatorRadioConfig/radioconfig.xml b/hals/radio/EmulatorRadioConfig/radioconfig.xml
similarity index 100%
rename from radio/EmulatorRadioConfig/radioconfig.xml
rename to hals/radio/EmulatorRadioConfig/radioconfig.xml
diff --git a/radio/EmulatorRadioConfig/src/com/android/emulator/radio/config/MeterService.java b/hals/radio/EmulatorRadioConfig/src/com/android/emulator/radio/config/MeterService.java
similarity index 100%
rename from radio/EmulatorRadioConfig/src/com/android/emulator/radio/config/MeterService.java
rename to hals/radio/EmulatorRadioConfig/src/com/android/emulator/radio/config/MeterService.java
diff --git a/hals/radio/IdAllocator.cpp b/hals/radio/IdAllocator.cpp
new file mode 100644
index 00000000..8470b0d8
--- /dev/null
+++ b/hals/radio/IdAllocator.cpp
@@ -0,0 +1,59 @@
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
+#include "IdAllocator.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+int32_t IdAllocator::get() {
+    const auto i = mReturnedIds.rbegin();
+
+    if (i == mReturnedIds.rend()) {
+        return ++mIdGenerator;
+    } else {
+        const int32_t id = *i;
+        mReturnedIds.erase(std::next(i).base());
+        return id;
+    }
+}
+
+void IdAllocator::put(const int32_t id) {
+    if (id == mIdGenerator) {
+        --mIdGenerator;
+
+        auto i = mReturnedIds.begin();
+        while (i != mReturnedIds.end()) {
+            if (*i == mIdGenerator) {
+                --mIdGenerator;
+                i = mReturnedIds.erase(i);
+            } else {
+                break;
+            }
+        }
+    } else {
+        mReturnedIds.insert(id);
+    }
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/dhcp/client/log.h b/hals/radio/IdAllocator.h
similarity index 55%
rename from dhcp/client/log.h
rename to hals/radio/IdAllocator.h
index bf141df7..b0028e78 100644
--- a/dhcp/client/log.h
+++ b/hals/radio/IdAllocator.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2017 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,8 +13,28 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+
 #pragma once
 
-#define LOG_TAG "dhcpclient"
-#include <log/log.h>
+#include <set>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+struct IdAllocator {
+    int32_t get();
+    void put(int32_t);
+
+private:
+    std::set<int32_t, std::greater<int32_t>> mReturnedIds;
+    int32_t mIdGenerator = 0;
+};
 
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/ImsMedia.cpp b/hals/radio/ImsMedia.cpp
new file mode 100644
index 00000000..27f79087
--- /dev/null
+++ b/hals/radio/ImsMedia.cpp
@@ -0,0 +1,56 @@
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
+#define FAILURE_DEBUG_PREFIX "ImsMedia"
+
+#include "ImsMedia.h"
+#include "debug.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+ImsMedia::ImsMedia(std::shared_ptr<AtChannel> /*atChannel*/) {
+}
+
+ScopedAStatus ImsMedia::openSession(
+        const int32_t sessionId, const ims::media::LocalEndPoint& /*localEndPoint*/,
+        const ims::media::RtpConfig& /*config*/) {
+    NOT_NULL(mMediaListener)->onOpenSessionFailure(
+        sessionId, FAILURE(ims::media::RtpError::NOT_SUPPORTED));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus ImsMedia::closeSession(const int32_t sessionId) {
+    NOT_NULL(mMediaListener)->onSessionClosed(sessionId);
+    return ScopedAStatus::ok();
+}
+
+void ImsMedia::atResponseSink(const AtResponsePtr& /*response*/) {}
+
+ScopedAStatus ImsMedia::setListener(
+        const std::shared_ptr<ims::media::IImsMediaListener>& mediaListener) {
+    mMediaListener = NOT_NULL(mediaListener);
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/ImsMedia.h b/hals/radio/ImsMedia.h
new file mode 100644
index 00000000..cfabc5dc
--- /dev/null
+++ b/hals/radio/ImsMedia.h
@@ -0,0 +1,50 @@
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
+#include <memory>
+
+#include <aidl/android/hardware/radio/ims/media/BnImsMedia.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct ImsMedia : public ims::media::BnImsMedia {
+    ImsMedia(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus openSession(
+            int32_t sessionId, const ims::media::LocalEndPoint& localEndPoint,
+            const ims::media::RtpConfig& config) override;
+    ScopedAStatus closeSession(int32_t in_sessionId) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+
+    ScopedAStatus setListener(
+            const std::shared_ptr<ims::media::IImsMediaListener>& mediaListener) override;
+
+    std::shared_ptr<ims::media::IImsMediaListener> mMediaListener;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/Parser.cpp b/hals/radio/Parser.cpp
new file mode 100644
index 00000000..d5bdc8f4
--- /dev/null
+++ b/hals/radio/Parser.cpp
@@ -0,0 +1,133 @@
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
+#include <charconv>
+
+#include "debug.h"
+#include "Parser.h"
+
+Parser& Parser::skip(const char c) {
+    if (mBegin) {
+        if (c == ' ') {
+            while ((mBegin != mEnd) && (*mBegin <= ' ')) {
+                ++mBegin;
+            }
+        } else if ((mBegin != mEnd) && (*mBegin == c)) {
+            ++mBegin;
+        } else {
+            mBegin = FAILURE(nullptr);
+        }
+    }
+
+    return *this;
+}
+
+Parser& Parser::skip(const char* s) {
+    if (mBegin) {
+        while (mBegin != mEnd) {
+            const char c = *s;
+            if (!c) {
+                return *this;
+            } else if (c == *mBegin) {
+                ++mBegin;
+                ++s;
+            } else {
+                mBegin = FAILURE(nullptr);
+                return *this;
+            }
+        }
+
+        if (*s) {
+            mBegin = FAILURE(nullptr);
+        }
+    }
+
+    return *this;
+}
+
+Parser& Parser::operator()(char* result) {
+    if (mBegin) {
+        if (mBegin != mEnd) {
+            *result = *mBegin;
+            ++mBegin;
+        } else {
+            mBegin = FAILURE(nullptr);
+        }
+    }
+
+    return *this;
+}
+
+Parser& Parser::operator()(int* result, const int base) {
+    if (mBegin) {
+        if (mBegin != mEnd) {
+            const auto [unconsumed, ec] =
+                std::from_chars(mBegin, mEnd, *result, base);
+            if (ec == std::errc()) {
+                mBegin = unconsumed;
+            } else {
+                mBegin = FAILURE(nullptr);
+            }
+        } else {
+            mBegin = FAILURE(nullptr);
+        }
+    }
+
+    return *this;
+}
+
+Parser& Parser::operator()(std::string_view* result, const char end) {
+    if (mBegin) {
+        for (const char* i = mBegin; i != mEnd; ++i) {
+            if (*i == end) {
+                *result = std::string_view(mBegin, i - mBegin);
+                mBegin = i + 1;
+                return *this;
+            }
+        }
+
+        mBegin = FAILURE(nullptr);
+    }
+
+    return *this;
+}
+
+Parser& Parser::operator()(std::string* result, const char end) {
+    std::string_view view;
+    if ((*this)(&view, end).matchSoFar()) {
+        *result = std::string(view.data(), view.size());
+    }
+    return *this;
+}
+
+std::string_view Parser::remaining() {
+    const char* begin = mBegin;
+    if (begin) {
+        mBegin = mEnd;
+        return std::string_view(begin, mEnd - begin);
+    } else {
+        return {};
+    }
+}
+
+std::string Parser::remainingAsString() {
+    std::string_view rem = remaining();
+    return std::string(rem.data(), rem.size());
+}
+
+int Parser::consumed() const {
+    return mBegin ? int(mBegin - mImmutableBegin) : -1;
+}
diff --git a/hals/radio/Parser.h b/hals/radio/Parser.h
new file mode 100644
index 00000000..707b45ae
--- /dev/null
+++ b/hals/radio/Parser.h
@@ -0,0 +1,47 @@
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
+#include <string>
+#include <string_view>
+
+struct Parser {
+    Parser(std::string_view str)
+        : mImmutableBegin(str.data())
+        , mBegin(str.data())
+        , mEnd(str.data() + str.size()) {}
+
+    bool matchSoFar() const { return mBegin != nullptr; }
+    bool fullMatch() const { return matchSoFar() && (mBegin == mEnd); }
+    bool hasMore() const { return matchSoFar() && (mBegin != mEnd); }
+    char front() const { return hasMore() ? *mBegin : char(-1); }
+
+    Parser& skip(char c);
+    Parser& skip(const char* s);
+    Parser& operator()(char* result);
+    Parser& operator()(int* result, int base = 10);
+    Parser& operator()(std::string_view* result, char end);
+    Parser& operator()(std::string* result, char end);
+
+    std::string_view remaining();
+    std::string remainingAsString();
+    int consumed() const;
+
+private:
+    const char* const mImmutableBegin;
+    const char* mBegin;
+    const char* mEnd;
+};
diff --git a/hals/radio/RadioConfig.cpp b/hals/radio/RadioConfig.cpp
new file mode 100644
index 00000000..9ee83a4e
--- /dev/null
+++ b/hals/radio/RadioConfig.cpp
@@ -0,0 +1,200 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioConfig"
+
+#include <aidl/android/hardware/radio/sim/CardStatus.h>
+
+#include "RadioConfig.h"
+
+#include "atCmds.h"
+#include "debug.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+constexpr int8_t kLogicalModemId = 0;
+
+RadioConfig::RadioConfig(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioConfig::getHalDeviceCapabilities(const int32_t serial) {
+    NOT_NULL(mRadioConfigResponse)->getHalDeviceCapabilitiesResponse(
+            makeRadioResponseInfo(serial), false);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::getNumOfLiveModems(const int32_t serial) {
+    NOT_NULL(mRadioConfigResponse)->getNumOfLiveModemsResponse(
+            makeRadioResponseInfo(serial), 1);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::getPhoneCapability(const int32_t serial) {
+    config::PhoneCapability capability = {
+        .maxActiveData = 1,
+        .maxActiveInternetData = 1,
+        .isInternetLingeringSupported = false,
+        .logicalModemIds = { kLogicalModemId },
+        .maxActiveVoice = 1,
+    };
+    NOT_NULL(mRadioConfigResponse)->getPhoneCapabilityResponse(
+            makeRadioResponseInfo(serial), std::move(capability));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::getSimultaneousCallingSupport(const int32_t serial) {
+    NOT_NULL(mRadioConfigResponse)->getSimultaneousCallingSupportResponse(
+            makeRadioResponseInfoNOP(serial), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::getSimSlotsStatus(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using config::SimSlotStatus;
+        using config::SimPortInfo;
+        using CmeError = AtResponse::CmeError;
+        using CPIN = AtResponse::CPIN;
+
+        SimSlotStatus simSlotStatus;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getSimCardStatus,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CPIN>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+failed:     NOT_NULL(mRadioConfigResponse)->getSimSlotsStatusResponse(
+                makeRadioResponseInfo(serial, FAILURE(RadioError::INTERNAL_ERR)), {});
+            return false;
+        } else if (const CPIN* cpin = response->get_if<CPIN>()) {
+            switch (cpin->state) {
+            case CPIN::State::READY:
+                simSlotStatus.cardState = sim::CardStatus::STATE_PRESENT;
+                simSlotStatus.atr = "";  // TODO 3BF000818000
+                simSlotStatus.eid = "";  // TODO
+                break;
+
+            case CPIN::State::PIN:
+            case CPIN::State::PUK:
+                simSlotStatus.cardState = sim::CardStatus::STATE_RESTRICTED;
+                break;
+
+            default:
+                goto failed;
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            switch (cmeError->error) {
+            case RadioError::SIM_ABSENT:
+                simSlotStatus.cardState = sim::CardStatus::STATE_ABSENT;
+                break;
+            case RadioError::SIM_BUSY:
+            case RadioError::SIM_ERR:
+                simSlotStatus.cardState = sim::CardStatus::STATE_ERROR;
+                break;
+
+            default:
+                RLOGE("%s:%s:%s:%d unexpected error: '%s'",
+                      FAILURE_DEBUG_PREFIX, kFunc, "CPIN", __LINE__,
+                      toString(cmeError->error).c_str());
+                goto failed;
+            }
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (simSlotStatus.cardState != sim::CardStatus::STATE_ABSENT) {
+            SimPortInfo simPortInfo = {
+                .logicalSlotId = 0,
+                .portActive = true,
+            };
+
+            response =
+                mAtConversation(requestPipe, atCmds::getICCID,
+                                [](const AtResponse& response) -> bool {
+                                   return response.holds<std::string>();
+                                });
+            if (!response || response->isParseError()) {
+                goto failed;
+            } else if (const std::string* iccid = response->get_if<std::string>()) {
+                simPortInfo.iccId = *iccid;
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+
+            simSlotStatus.portInfo.push_back(std::move(simPortInfo));
+        }
+
+        NOT_NULL(mRadioConfigResponse)->getSimSlotsStatusResponse(
+                makeRadioResponseInfo(serial), { std::move(simSlotStatus) });
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::setNumOfLiveModems(const int32_t serial,
+                                              const int8_t numOfLiveModems) {
+    const RadioError result = (numOfLiveModems == 1) ?
+        RadioError::NONE : FAILURE_V(RadioError::INVALID_ARGUMENTS,
+                                     "numOfLiveModems=%d", numOfLiveModems);
+
+    NOT_NULL(mRadioConfigResponse)->setNumOfLiveModemsResponse(
+            makeRadioResponseInfo(serial, result));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::setPreferredDataModem(const int32_t serial,
+                                                 const int8_t modemId) {
+    const RadioError result = (modemId == kLogicalModemId) ?
+        RadioError::NONE : FAILURE_V(RadioError::INVALID_ARGUMENTS,
+                                     "modemId=%d", modemId);
+
+    NOT_NULL(mRadioConfigResponse)->setPreferredDataModemResponse(
+        makeRadioResponseInfo(serial, result));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioConfig::setSimSlotsMapping(
+        const int32_t serial, const std::vector<config::SlotPortMapping>& /*slotMap*/) {
+    NOT_NULL(mRadioConfigResponse)->setSimSlotsMappingResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+void RadioConfig::atResponseSink(const AtResponsePtr& response) {
+    if (!mAtConversation.send(response)) {
+        response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    }
+}
+
+ScopedAStatus RadioConfig::setResponseFunctions(
+        const std::shared_ptr<config::IRadioConfigResponse>& radioConfigResponse,
+        const std::shared_ptr<config::IRadioConfigIndication>& radioConfigIndication) {
+    mRadioConfigResponse = NOT_NULL(radioConfigResponse);
+    mRadioConfigIndication = NOT_NULL(radioConfigIndication);
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioConfig.h b/hals/radio/RadioConfig.h
new file mode 100644
index 00000000..7c06ede3
--- /dev/null
+++ b/hals/radio/RadioConfig.h
@@ -0,0 +1,65 @@
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
+#include <functional>
+#include <future>
+#include <memory>
+#include <mutex>
+
+#include <aidl/android/hardware/radio/config/BnRadioConfig.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioConfig : public config::BnRadioConfig {
+    RadioConfig(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus getHalDeviceCapabilities(int32_t serial) override;
+    ScopedAStatus getNumOfLiveModems(int32_t serial) override;
+    ScopedAStatus getPhoneCapability(int32_t serial) override;
+    ScopedAStatus getSimultaneousCallingSupport(int32_t serial) override;
+    ScopedAStatus getSimSlotsStatus(int32_t serial) override;
+    ScopedAStatus setNumOfLiveModems(int32_t serial, int8_t numOfLiveModems) override;
+    ScopedAStatus setPreferredDataModem(int32_t serial, int8_t modemId) override;
+    ScopedAStatus setSimSlotsMapping(
+            int32_t serial, const std::vector<config::SlotPortMapping>& slotMap) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<config::IRadioConfigResponse>& radioConfigResponse,
+            const std::shared_ptr<config::IRadioConfigIndication>& radioConfigIndication) override;
+
+private:
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+    std::shared_ptr<config::IRadioConfigResponse> mRadioConfigResponse;
+    std::shared_ptr<config::IRadioConfigIndication> mRadioConfigIndication;
+
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioData.cpp b/hals/radio/RadioData.cpp
new file mode 100644
index 00000000..0f07a9a5
--- /dev/null
+++ b/hals/radio/RadioData.cpp
@@ -0,0 +1,489 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioData"
+
+#include <format>
+#include <string_view>
+
+#include <arpa/inet.h>
+#include <net/if.h>
+#include <netinet/in.h>
+#include <sys/socket.h>
+
+#include "RadioData.h"
+
+#include "debug.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using data::DataProfileInfo;
+using data::PdpProtocolType;
+using data::SetupDataCallResult;
+
+namespace {
+constexpr char kInterfaceName[] = "eth0";
+
+std::string_view getProtocolStr(const PdpProtocolType p) {
+    using namespace std::literals;
+
+    switch (p) {
+    case PdpProtocolType::IP: return "IP"sv;
+    case PdpProtocolType::IPV6: return "IPV6"sv;
+    case PdpProtocolType::IPV4V6: return "IPV4V6"sv;
+    case PdpProtocolType::PPP: return "PPP"sv;
+    case PdpProtocolType::NON_IP: return "NON_IP"sv;
+    case PdpProtocolType::UNSTRUCTURED: return "UNSTRUCTURED"sv;
+    default: return {};
+    }
+}
+
+std::string formatCGDCONT(const int cid,
+                          const PdpProtocolType protocol,
+                          const std::string_view apn) {
+    const std::string_view protocolStr = getProtocolStr(protocol);
+    if (protocolStr.empty()) {
+        return FAILURE_V("", "Unexpected protocol: %s", toString(protocol).c_str());
+    }
+
+    if (apn.empty()) {
+        return FAILURE_V("", "%s", "APN is empty");
+    }
+
+    return std::format("AT+CGDCONT={0:d},\"{1:s}\",\"{2:s}\",,0,0",
+                       cid, protocolStr, apn);
+}
+
+bool setInterfaceState(const char* interfaceName, const bool on) {
+    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
+    if (sock < 0) {
+        return FAILURE_V(false, "Failed to open interface socket: %s (%d)",
+                         strerror(errno), errno);
+    }
+
+    struct ifreq request;
+    memset(&request, 0, sizeof(request));
+    strncpy(request.ifr_name, interfaceName, sizeof(request.ifr_name));
+    request.ifr_name[sizeof(request.ifr_name) - 1] = '\0';
+
+    if (ioctl(sock, SIOCGIFFLAGS, &request)) {
+        ::close(sock);
+        return FAILURE_V(false, "Failed to get interface flags for %s: %s (%d)",
+                         interfaceName, strerror(errno), errno);
+    }
+
+    if (((request.ifr_flags & IFF_UP) != 0) == on) {
+        ::close(sock);
+        return true;  // Interface already in desired state
+    }
+
+    request.ifr_flags ^= IFF_UP;
+    if (ioctl(sock, SIOCSIFFLAGS, &request)) {
+        ::close(sock);
+        return FAILURE_V(false, "Failed to set interface flags for %s: %s (%d)",
+                         interfaceName, strerror(errno), errno);
+    }
+
+    ::close(sock);
+    return true;
+}
+
+bool setIpAddr(const char *addr, const int addrSize,
+               const char* radioInterfaceName) {
+    const int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
+    const int sock = socket(family, SOCK_DGRAM, 0);
+    if (sock == -1) {
+        return FAILURE_V(false, "Failed to open a %s socket: %s (%d)",
+                         ((family == AF_INET) ? "INET" : "INET6"),
+                         strerror(errno), errno);
+    }
+
+    struct ifreq req4;
+    memset(&req4, 0, sizeof(req4));
+
+    strncpy(req4.ifr_name, radioInterfaceName, sizeof(req4.ifr_name));
+    req4.ifr_name[sizeof(req4.ifr_name) - 1] = '\0';
+
+    if (family == AF_INET) {
+        struct sockaddr_in *sin = (struct sockaddr_in *)&req4.ifr_addr;
+        sin->sin_family = AF_INET;
+        sin->sin_addr.s_addr = inet_addr(addr);
+        if (ioctl(sock, SIOCSIFADDR, &req4) < 0) {
+            ::close(sock);
+            return FAILURE_V(false, "SIOCSIFADDR IPv4 failed: %s (%d)",
+                             strerror(errno), errno);
+        }
+
+        sin->sin_addr.s_addr = htonl(0xFFFFFFFFu << (32 - (addrSize ? addrSize : 32)));
+        if (ioctl(sock, SIOCSIFNETMASK, &req4) < 0) {
+            ::close(sock);
+            return FAILURE_V(false, "SIOCSIFNETMASK IPv4 failed: %s (%d)",
+                             strerror(errno), errno);
+        }
+    } else {
+        if (ioctl(sock, SIOCGIFINDEX, &req4) < 0) {
+            ::close(sock);
+            return FAILURE_V(false, "SIOCGIFINDEX IPv6 failed: %s (%d)",
+                             strerror(errno), errno);
+        }
+
+        struct in6_ifreq req6 = {
+            .ifr6_prefixlen = static_cast<__u32>(addrSize ? addrSize : 128),
+            .ifr6_ifindex = req4.ifr_ifindex,
+        };
+
+        if (inet_pton(AF_INET6, addr, &req6.ifr6_addr) != 1) {
+            ::close(sock);
+            return FAILURE_V(false, "inet_pton(AF_INET6, '%s') failed: %s (%d)",
+                             addr, strerror(errno), errno);
+        }
+
+        if (ioctl(sock, SIOCSIFADDR, &req6) < 0) {
+            ::close(sock);
+            return FAILURE_V(false, "SIOCSIFADDR failed: %s (%d)",
+                             strerror(errno), errno);
+        }
+    }
+
+    ::close(sock);
+    return true;
+}
+
+} // namespace
+
+RadioData::RadioData(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioData::getSlicingConfig(const int32_t serial) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioDataResponse)->getSlicingConfigResponse(
+        makeRadioResponseInfo(serial), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::setDataAllowed(const int32_t serial,
+                                        const bool /*allow*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioDataResponse)->setDataAllowedResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::setDataProfile(const int32_t serial,
+                                        const std::vector<DataProfileInfo>& /*profiles*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioDataResponse)->setDataProfileResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::setDataThrottling(const int32_t serial,
+                                           const data::DataThrottlingAction /*dataThrottlingAction*/,
+                                           const int64_t /*completionDurationMillis*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioDataResponse)->setDataThrottlingResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::setInitialAttachApn(const int32_t serial,
+                                             const std::optional<DataProfileInfo>& /*maybeDpInfo*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioDataResponse)->setInitialAttachApnResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::allocatePduSessionId(const int32_t serial) {
+    NOT_NULL(mRadioDataResponse)->allocatePduSessionIdResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), 0);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::releasePduSessionId(const int32_t serial,
+                                             const int32_t /*id*/) {
+    NOT_NULL(mRadioDataResponse)->releasePduSessionIdResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::setupDataCall(const int32_t serial,
+                                       const AccessNetwork /*accessNetwork*/,
+                                       const DataProfileInfo& dataProfileInfo,
+                                       const bool /*roamingAllowed*/,
+                                       const data::DataRequestReason /*reason*/,
+                                       const std::vector<data::LinkAddress>& /*addresses*/,
+                                       const std::vector<std::string>& /*dnses*/,
+                                       const int32_t pduSessionId,
+                                       const std::optional<data::SliceInfo>& /*sliceInfo*/,
+                                       const bool /*matchAllRuleAllowed*/) {
+    if (!setInterfaceState(kInterfaceName, true)) {
+        NOT_NULL(mRadioDataResponse)->setupDataCallResponse(
+                makeRadioResponseInfo(serial, FAILURE(RadioError::GENERIC_FAILURE)), {});
+        return ScopedAStatus::ok();
+    }
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, dataProfileInfo, pduSessionId]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        using CGCONTRDP = AtResponse::CGCONTRDP;
+
+        RadioError status;
+        const int32_t cid = allocateId();
+
+        std::string request = formatCGDCONT(cid, dataProfileInfo.protocol,
+                                            dataProfileInfo.apn);
+        if (request.empty()) {
+            status = RadioError::INVALID_ARGUMENTS;
+
+failed:     releaseId(cid);
+            NOT_NULL(mRadioDataResponse)->setupDataCallResponse(
+                    makeRadioResponseInfo(serial, FAILURE(status)), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<AtResponse::OK>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+            goto failed;
+        } else if (const CmeError* err = response->get_if<CmeError>()) {
+            status = FAILURE_V(err->error, "%s",  toString(err->error).c_str());
+            goto failed;
+        } else if (!response->holds<AtResponse::OK>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        SetupDataCallResult setupDataCallResult = {
+            .suggestedRetryTime = -1,
+            .cid = cid,
+            .active = SetupDataCallResult::DATA_CONNECTION_STATUS_ACTIVE,
+            .type = dataProfileInfo.protocol,
+            .ifname = kInterfaceName,
+            .mtuV4 = 1500,
+            .mtuV6 = 1500,
+            .handoverFailureMode = SetupDataCallResult::HANDOVER_FAILURE_MODE_LEGACY,
+            .pduSessionId = pduSessionId,
+        };
+
+        request = std::format("AT+CGCONTRDP={0:d}", cid);
+        response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CGCONTRDP>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+            goto failed;
+        } else if (const CGCONTRDP* cgcontrdp = response->get_if<CGCONTRDP>()) {
+            if (!setIpAddr(cgcontrdp->localAddr.c_str(),
+                           cgcontrdp->localAddrSize,
+                           setupDataCallResult.ifname.c_str())) {
+                status = FAILURE(RadioError::GENERIC_FAILURE);
+                goto failed;
+            }
+
+            const auto makeLinkAddress = [](const std::string_view address,
+                                            const size_t addrSize) -> data::LinkAddress {
+                return {
+                    .address = std::format("{0:s}/{1:d}", address, addrSize),
+                    .addressProperties = 0,
+                    .deprecationTime = -1,
+                    .expirationTime = -1,
+                };
+            };
+
+            setupDataCallResult.addresses.push_back(
+                makeLinkAddress(cgcontrdp->localAddr, cgcontrdp->localAddrSize));
+            setupDataCallResult.gateways.push_back(cgcontrdp->gwAddr);
+            setupDataCallResult.dnses.push_back(cgcontrdp->dns1);
+            if (!cgcontrdp->dns2.empty()) {
+                setupDataCallResult.dnses.push_back(cgcontrdp->dns2);
+            }
+
+            std::lock_guard<std::mutex> lock(mMtx);
+            mDataCalls.insert({ cid, setupDataCallResult });
+            status = RadioError::NONE;
+        } else if (const CmeError* err = response->get_if<CmeError>()) {
+            status = FAILURE_V(err->error, "%s",  toString(err->error).c_str());
+            goto failed;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioDataResponse)->setupDataCallResponse(
+            makeRadioResponseInfo(serial), std::move(setupDataCallResult));
+
+        NOT_NULL(mRadioDataIndication)->dataCallListChanged(
+            RadioIndicationType::UNSOLICITED, getDataCalls());
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::deactivateDataCall(
+        const int32_t serial, const int32_t cid,
+        const data::DataRequestReason /*reason*/) {
+    bool removed;
+    bool empty;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        const auto i = mDataCalls.find(cid);
+        if (i != mDataCalls.end()) {
+            mDataCalls.erase(i);
+            mIdAllocator.put(cid);
+            removed = true;
+        } else {
+            removed = false;
+        }
+        empty = mDataCalls.empty();
+    }
+
+    if (empty) {
+        setInterfaceState(kInterfaceName, false);
+    }
+
+    if (removed) {
+        NOT_NULL(mRadioDataResponse)->deactivateDataCallResponse(
+            makeRadioResponseInfo(serial));
+
+        NOT_NULL(mRadioDataIndication)->dataCallListChanged(
+            RadioIndicationType::UNSOLICITED, getDataCalls());
+    } else {
+        NOT_NULL(mRadioDataResponse)->deactivateDataCallResponse(
+            makeRadioResponseInfo(serial, FAILURE(RadioError::INVALID_ARGUMENTS)));
+    }
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::getDataCallList(const int32_t serial) {
+    NOT_NULL(mRadioDataResponse)->getDataCallListResponse(
+        makeRadioResponseInfo(serial), getDataCalls());
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::startHandover(const int32_t serial,
+                                       const int32_t /*callId*/) {
+    NOT_NULL(mRadioDataResponse)->startHandoverResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::cancelHandover(const int32_t serial,
+                                        const int32_t /*callId*/) {
+    NOT_NULL(mRadioDataResponse)->cancelHandoverResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::startKeepalive(const int32_t serial,
+                                        const data::KeepaliveRequest& /*keepalive*/) {
+    const int32_t sessionHandle = allocateId();
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mKeepAliveSessions.insert(sessionHandle);
+    }
+
+    using data::KeepaliveStatus;
+
+    KeepaliveStatus keepaliveStatus = {
+        .sessionHandle = sessionHandle,
+        .code = KeepaliveStatus::CODE_ACTIVE,
+    };
+
+    NOT_NULL(mRadioDataResponse)->startKeepaliveResponse(
+        makeRadioResponseInfo(serial), std::move(keepaliveStatus));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::stopKeepalive(const int32_t serial,
+                                       const int32_t sessionHandle) {
+    bool removed;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        removed = mKeepAliveSessions.erase(sessionHandle) > 0;
+    }
+
+    if (removed) {
+        releaseId(sessionHandle);
+    }
+
+    NOT_NULL(mRadioDataResponse)->stopKeepaliveResponse(
+        makeRadioResponseInfo(serial, removed ?
+            RadioError::NONE : FAILURE(RadioError::INVALID_ARGUMENTS)));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioData::responseAcknowledgement() {
+    return ScopedAStatus::ok();
+}
+
+void RadioData::atResponseSink(const AtResponsePtr& response) {
+    if (!mAtConversation.send(response)) {
+        response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    }
+}
+
+ScopedAStatus RadioData::setResponseFunctions(
+        const std::shared_ptr<data::IRadioDataResponse>& radioDataResponse,
+        const std::shared_ptr<data::IRadioDataIndication>& radioDataIndication) {
+    mRadioDataResponse = NOT_NULL(radioDataResponse);
+    mRadioDataIndication = NOT_NULL(radioDataIndication);
+    return ScopedAStatus::ok();
+}
+
+int32_t RadioData::allocateId() {
+    std::lock_guard<std::mutex> lock(mMtx);
+    return mIdAllocator.get();
+}
+
+void RadioData::releaseId(const int32_t cid) {
+    std::lock_guard<std::mutex> lock(mMtx);
+    mIdAllocator.put(cid);
+}
+
+std::vector<SetupDataCallResult> RadioData::getDataCalls() const {
+    std::vector<SetupDataCallResult> dataCalls;
+
+    std::lock_guard<std::mutex> lock(mMtx);
+    for (const auto& kv : mDataCalls) {
+        dataCalls.push_back(kv.second);
+    }
+
+    return dataCalls;
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioData.h b/hals/radio/RadioData.h
new file mode 100644
index 00000000..f13fe567
--- /dev/null
+++ b/hals/radio/RadioData.h
@@ -0,0 +1,105 @@
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
+#include <memory>
+#include <mutex>
+#include <unordered_map>
+#include <unordered_set>
+
+#include <aidl/android/hardware/radio/data/BnRadioData.h>
+#include "AtChannel.h"
+#include "IdAllocator.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioData : public data::BnRadioData {
+    RadioData(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus getSlicingConfig(int32_t serial) override;
+
+    ScopedAStatus setDataAllowed(int32_t serial, bool allow) override;
+    ScopedAStatus setDataProfile(
+            int32_t serial,
+            const std::vector<data::DataProfileInfo>& profiles)
+            override;
+    ScopedAStatus setDataThrottling(
+            int32_t serial,
+            data::DataThrottlingAction dataThrottlingAction,
+            int64_t completionDurationMillis) override;
+    ScopedAStatus setInitialAttachApn(
+            int32_t serial,
+            const std::optional<data::DataProfileInfo>& dpInfo)
+            override;
+
+    ScopedAStatus allocatePduSessionId(int32_t serial) override;
+    ScopedAStatus releasePduSessionId(int32_t serial, int32_t id) override;
+
+    ScopedAStatus setupDataCall(
+            int32_t serial, AccessNetwork accessNetwork,
+            const data::DataProfileInfo& dataProfileInfo,
+            bool roamingAllowed, data::DataRequestReason reason,
+            const std::vector<data::LinkAddress>& addresses,
+            const std::vector<std::string>& dnses, int32_t pduSessionId,
+            const std::optional<data::SliceInfo>& sliceInfo,
+            bool matchAllRuleAllowed) override;
+    ScopedAStatus deactivateDataCall(
+            int32_t serial, int32_t cid,
+            data::DataRequestReason reason) override;
+    ScopedAStatus getDataCallList(int32_t serial) override;
+
+    ScopedAStatus startHandover(int32_t serial, int32_t callId) override;
+    ScopedAStatus cancelHandover(int32_t serial, int32_t callId) override;
+
+    ScopedAStatus startKeepalive(
+            int32_t serial,
+            const data::KeepaliveRequest& keepalive) override;
+    ScopedAStatus stopKeepalive(int32_t serial, int32_t sessionHandle) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus responseAcknowledgement() override;
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<data::IRadioDataResponse>& radioDataResponse,
+            const std::shared_ptr<data::IRadioDataIndication>& radioDataIndication) override;
+
+private:
+    int32_t allocateId();
+    void releaseId(int32_t cid);
+
+    std::vector<data::SetupDataCallResult> getDataCalls() const;
+
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+    std::shared_ptr<data::IRadioDataResponse> mRadioDataResponse;
+    std::shared_ptr<data::IRadioDataIndication> mRadioDataIndication;
+    std::unordered_map<int32_t, data::SetupDataCallResult> mDataCalls;
+    std::unordered_set<int32_t> mKeepAliveSessions;
+    IdAllocator mIdAllocator;
+    mutable std::mutex mMtx;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioIms.cpp b/hals/radio/RadioIms.cpp
new file mode 100644
index 00000000..5b5843db
--- /dev/null
+++ b/hals/radio/RadioIms.cpp
@@ -0,0 +1,96 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioIms"
+
+#include "RadioIms.h"
+#include "debug.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+RadioIms::RadioIms(std::shared_ptr<AtChannel> atChannel) {
+}
+
+ScopedAStatus RadioIms::setSrvccCallInfo(
+        const int32_t serial, const std::vector<ims::SrvccCall>& /*srvccCalls*/) {
+    NOT_NULL(mRadioImsResponse)->setSrvccCallInfoResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioIms::updateImsRegistrationInfo(
+        const int32_t serial, const ims::ImsRegistration& /*imsRegistration*/) {
+    NOT_NULL(mRadioImsResponse)->updateImsRegistrationInfoResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioIms::startImsTraffic(
+        const int32_t serial, int32_t /*token*/, ims::ImsTrafficType /*imsTrafficType*/,
+        AccessNetwork /*accessNetworkType*/, ims::ImsCall::Direction /*trafficDirection*/) {
+    NOT_NULL(mRadioImsResponse)->startImsTrafficResponse(
+        makeRadioResponseInfoNOP(serial), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioIms::stopImsTraffic(const int32_t serial, int32_t /*token*/) {
+    NOT_NULL(mRadioImsResponse)->stopImsTrafficResponse(
+            makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioIms::triggerEpsFallback(
+        const int32_t serial, ims::EpsFallbackReason /*reason*/) {
+    NOT_NULL(mRadioImsResponse)->triggerEpsFallbackResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioIms::sendAnbrQuery(
+        const int32_t serial, ims::ImsStreamType /*mediaType*/,
+        ims::ImsStreamDirection /*direction*/, int32_t /*bitsPerSecond*/) {
+    NOT_NULL(mRadioImsResponse)->sendAnbrQueryResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioIms::updateImsCallStatus(
+        const int32_t serial, const std::vector<ims::ImsCall>& /*imsCalls*/) {
+    NOT_NULL(mRadioImsResponse)->updateImsCallStatusResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+void RadioIms::atResponseSink(const AtResponsePtr& response) {}
+
+ScopedAStatus RadioIms::setResponseFunctions(
+        const std::shared_ptr<ims::IRadioImsResponse>& radioImsResponse,
+        const std::shared_ptr<ims::IRadioImsIndication>& radioImsIndication) {
+    mRadioImsResponse = NOT_NULL(radioImsResponse);
+    mRadioImsIndication = NOT_NULL(radioImsIndication);
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioIms.h b/hals/radio/RadioIms.h
new file mode 100644
index 00000000..7b2336a7
--- /dev/null
+++ b/hals/radio/RadioIms.h
@@ -0,0 +1,63 @@
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
+#include <memory>
+
+#include <aidl/android/hardware/radio/ims/BnRadioIms.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioIms : public ims::BnRadioIms {
+    RadioIms(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus setSrvccCallInfo(
+            int32_t serial, const std::vector<ims::SrvccCall>& srvccCalls) override;
+    ScopedAStatus updateImsRegistrationInfo(
+            int32_t serial, const ims::ImsRegistration& imsRegistration) override;
+    ScopedAStatus startImsTraffic(
+            int32_t serial, int32_t token, ims::ImsTrafficType imsTrafficType,
+            AccessNetwork accessNetworkType, ims::ImsCall::Direction trafficDirection) override;
+    ScopedAStatus stopImsTraffic(int32_t serial, int32_t token) override;
+    ScopedAStatus triggerEpsFallback(
+            int32_t serial, ims::EpsFallbackReason reason) override;
+    ScopedAStatus sendAnbrQuery(
+            int32_t serial, ims::ImsStreamType mediaType,
+            ims::ImsStreamDirection direction, int32_t bitsPerSecond) override;
+    ScopedAStatus updateImsCallStatus(
+            int32_t serial, const std::vector<ims::ImsCall>& imsCalls) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<ims::IRadioImsResponse>& radioImsResponse,
+            const std::shared_ptr<ims::IRadioImsIndication>& radioImsIndication) override;
+
+    std::shared_ptr<ims::IRadioImsResponse> mRadioImsResponse;
+    std::shared_ptr<ims::IRadioImsIndication> mRadioImsIndication;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioMessaging.cpp b/hals/radio/RadioMessaging.cpp
new file mode 100644
index 00000000..f99ee9f3
--- /dev/null
+++ b/hals/radio/RadioMessaging.cpp
@@ -0,0 +1,513 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioMessaging"
+
+#include "RadioMessaging.h"
+
+#include "atCmds.h"
+#include "debug.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace {
+using messaging::GsmBroadcastSmsConfigInfo;
+
+using namespace std::literals;
+constexpr std::string_view kCtrlZ = "\032"sv;
+}  // namespace
+
+RadioMessaging::RadioMessaging(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioMessaging::acknowledgeIncomingGsmSmsWithPdu(const int32_t serial,
+                                                               const bool /*success*/,
+                                                               const std::string& /*ackPdu*/) {
+    // unsupported in reference-ril.c
+    NOT_NULL(mRadioMessagingResponse)->acknowledgeIncomingGsmSmsWithPduResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::acknowledgeLastIncomingCdmaSms(const int32_t serial,
+                                                             const messaging::CdmaSmsAck& /*smsAck*/) {
+    // unsupported in reference-ril.c
+    NOT_NULL(mRadioMessagingResponse)->acknowledgeLastIncomingCdmaSmsResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::acknowledgeLastIncomingGsmSms(const int32_t serial,
+                                                            const bool success,
+                                                            const messaging::SmsAcknowledgeFailCause /*cause*/) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, success]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        RadioError status = RadioError::NONE;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, std::format("AT+CNMA={0:d}", (success ? 1 : 2)),
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        }
+
+        NOT_NULL(mRadioMessagingResponse)->acknowledgeLastIncomingGsmSmsResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::deleteSmsOnRuim(const int32_t serial,
+                                              const int32_t /*index*/) {
+    NOT_NULL(mRadioMessagingResponse)->deleteSmsOnRuimResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::deleteSmsOnSim(const int32_t serial,
+                                             const int32_t index) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, index]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, std::format("AT+CMGD={0:d}", index),
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (response->get_if<CmeError>()) {
+            status = FAILURE(RadioError::INVALID_ARGUMENTS);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioMessagingResponse)->deleteSmsOnSimResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::getCdmaBroadcastConfig(const int32_t serial) {
+    NOT_NULL(mRadioMessagingResponse)->getCdmaBroadcastConfigResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::getGsmBroadcastConfig(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CSCB = AtResponse::CSCB;
+        using messaging::GsmBroadcastSmsConfigInfo;
+
+        RadioError status = RadioError::NONE;
+        std::vector<GsmBroadcastSmsConfigInfo> gbsci;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getBroadcastConfig,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CSCB>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CSCB* cscb = response->get_if<CSCB>()) {
+            const size_t size = std::min(cscb->serviceId.size(),
+                                         cscb->codeScheme.size());
+            gbsci.resize(size);
+
+            const bool selected = (cscb->mode != 0);
+
+            for (size_t i = 0; i < size; ++i) {
+                gbsci[i].selected = selected;
+                gbsci[i].fromServiceId = cscb->serviceId[i].from;
+                gbsci[i].toServiceId = cscb->serviceId[i].to;
+                gbsci[i].fromCodeScheme = cscb->codeScheme[i].from;
+                gbsci[i].toCodeScheme = cscb->codeScheme[i].to;
+            }
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioMessagingResponse)->getGsmBroadcastConfigResponse(
+            makeRadioResponseInfo(serial, status), std::move(gbsci));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::getSmscAddress(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CSCA = AtResponse::CSCA;
+        RadioError status = RadioError::NONE;
+        std::string smscAddress;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getSmscAddress,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CSCA>();
+                            });
+        if (!response || response->isParseError()) {
+            NOT_NULL(mRadioMessagingResponse)->getSmscAddressResponse(
+                makeRadioResponseInfo(serial, FAILURE(RadioError::INTERNAL_ERR)),
+                "");
+            return false;
+        } else if (const CSCA* csca = response->get_if<CSCA>()) {
+            smscAddress = csca->sca;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioMessagingResponse)->getSmscAddressResponse(
+            makeRadioResponseInfo(serial), std::move(smscAddress));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::reportSmsMemoryStatus(const int32_t serial,
+                                                    const bool /*available*/) {
+    NOT_NULL(mRadioMessagingResponse)->reportSmsMemoryStatusResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::sendCdmaSms(const int32_t serial,
+                                          const messaging::CdmaSmsMessage& /*sms*/) {
+    NOT_NULL(mRadioMessagingResponse)->sendCdmaSmsResponse(
+        makeRadioResponseInfoUnsupported(  // reference-ril.c returns OK but does nothing
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::sendCdmaSmsExpectMore(const int32_t serial,
+                                                    const messaging::CdmaSmsMessage& /*sms*/) {
+    NOT_NULL(mRadioMessagingResponse)->sendCdmaSmsExpectMoreResponse(
+        makeRadioResponseInfoUnsupported(  // reference-ril.c returns OK but does nothing
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::sendImsSms(const int32_t serial,
+                                         const messaging::ImsSmsMessage& /*message*/) {
+    NOT_NULL(mRadioMessagingResponse)->sendImsSmsResponse(
+        makeRadioResponseInfoUnsupported(  // <TODO>
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+std::pair<RadioResponseInfo, messaging::SendSmsResult>
+RadioMessaging::sendSmsImpl(const AtChannel::RequestPipe requestPipe,
+                            const int serial,
+                            const messaging::GsmSmsMessage &message) {
+    using messaging::SendSmsResult;
+    using SmsPrompt = AtResponse::SmsPrompt;
+    using CMGS = AtResponse::CMGS;
+
+    RadioError status = RadioError::NONE;
+    std::string request = std::format("AT+CMGS={0:d}", message.pdu.size() / 2);
+
+    AtResponsePtr response =
+        mAtConversation(requestPipe, request,
+                        [](const AtResponse& response) -> bool {
+                           return response.holds<SmsPrompt>();
+                        });
+    if (!response || response->isParseError()) {
+        status = FAILURE(RadioError::INTERNAL_ERR);
+done:   return {makeRadioResponseInfo(serial, status), {}};
+    } else if (!response->holds<SmsPrompt>()) {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+
+    SendSmsResult sendSmsResult;
+
+    const std::string_view smsc =
+        message.smscPdu.empty() ? "00"sv : std::string_view(message.smscPdu);
+
+    request = std::format("{0:s}{1:s}{2:s}", smsc, message.pdu, kCtrlZ);
+    response =
+        mAtConversation(requestPipe, request,
+                        [](const AtResponse& response) -> bool {
+                           return response.holds<CMGS>();
+                        });
+    if (!response || response->isParseError()) {
+        status = FAILURE(RadioError::INTERNAL_ERR);
+        goto done;
+    } else if (const CMGS* cmgs = response->get_if<CMGS>()) {
+        sendSmsResult.messageRef = cmgs->messageRef;
+    } else {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+
+    return {makeRadioResponseInfo(serial), std::move(sendSmsResult)};
+}
+
+
+ScopedAStatus RadioMessaging::sendSms(
+        const int32_t serial, const messaging::GsmSmsMessage& message) {
+    mAtChannel->queueRequester([this, serial, message]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        auto [response, sendSmsResult] = sendSmsImpl(requestPipe, serial, message);
+
+        NOT_NULL(mRadioMessagingResponse)->sendSmsResponse(
+            response, std::move(sendSmsResult));
+
+        return response.error != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::sendSmsExpectMore(
+        const int32_t serial, const messaging::GsmSmsMessage& message) {
+    mAtChannel->queueRequester([this, serial, message]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        auto [response, sendSmsResult] = sendSmsImpl(requestPipe, serial, message);
+
+        NOT_NULL(mRadioMessagingResponse)->sendSmsExpectMoreResponse(
+            response, std::move(sendSmsResult));
+
+        return response.error != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::setCdmaBroadcastConfig(const int32_t serial,
+                                                     const std::vector<messaging::CdmaBroadcastSmsConfigInfo>& /*configInfo*/) {
+    NOT_NULL(mRadioMessagingResponse)->setCdmaBroadcastConfigResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::setCdmaBroadcastActivation(const int32_t serial,
+                                                         const bool /*activate*/) {
+    NOT_NULL(mRadioMessagingResponse)->setCdmaBroadcastActivationResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::setGsmBroadcastConfig(
+        int32_t serial, const std::vector<GsmBroadcastSmsConfigInfo>& configInfo) {
+    if (configInfo.empty()) {
+        NOT_NULL(mRadioMessagingResponse)->setGsmBroadcastConfigResponse(
+            makeRadioResponseInfo(serial, FAILURE(RadioError::INVALID_ARGUMENTS)));
+        return ScopedAStatus::ok();
+    }
+
+    const int mode = configInfo.front().selected ? 0 : 1;
+    std::string channel;
+    std::string language;
+
+    for (const GsmBroadcastSmsConfigInfo& ci : configInfo) {
+        if (!channel.empty()) {
+            channel += ",";
+            language += ",";
+        }
+
+        if (ci.fromServiceId == ci.toServiceId) {
+            channel += std::to_string(ci.fromServiceId);
+        } else {
+            channel += std::format("{0:d}-{1:d}", ci.fromServiceId,
+                                   ci.toServiceId);
+        }
+
+        if (ci.fromCodeScheme == ci.toCodeScheme) {
+            language += std::to_string(ci.fromCodeScheme);
+        } else {
+            language += std::format("{0:d}-{1:d}", ci.fromCodeScheme,
+                                    ci.toCodeScheme);
+        }
+    }
+
+    std::string request = std::format("AT+CSCB={0:d},\"{1:s}\",\"{2:s}\"",
+                                      mode, channel, language);
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, request = std::move(request)]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using OK = AtResponse::OK;
+        RadioError status = RadioError::NONE;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<OK>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->holds<OK>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioMessagingResponse)->setSmscAddressResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::setGsmBroadcastActivation(const int32_t serial,
+                                                        const bool /*activate*/) {
+    NOT_NULL(mRadioMessagingResponse)->setGsmBroadcastActivationResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::setSmscAddress(const int32_t serial, const std::string& smsc) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, smsc]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using OK = AtResponse::OK;
+        RadioError status = RadioError::NONE;
+
+        const std::string request = std::format("AT+CSCA={0:s},{1:d}", smsc, 0);
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<OK>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->holds<OK>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioMessagingResponse)->setSmscAddressResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::writeSmsToRuim(const int32_t serial,
+                                             const messaging::CdmaSmsWriteArgs& /*cdmaSms*/) {
+    NOT_NULL(mRadioMessagingResponse)->writeSmsToRuimResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), 0);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::writeSmsToSim(const int32_t serial,
+                                            const messaging::SmsWriteArgs& smsWriteArgs) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, smsWriteArgs]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using SmsPrompt = AtResponse::SmsPrompt;
+        using CMGW = AtResponse::CMGW;
+
+        RadioError status = RadioError::NONE;
+        int messageRef = -1;
+
+        std::string request = std::format("AT+CMGW=%d,%d",
+            smsWriteArgs.pdu.size() / 2, smsWriteArgs.status);
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<SmsPrompt>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+            goto done;
+        } else if (!response->holds<SmsPrompt>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+        }
+
+        request = std::format("{0:s}{1:s}", smsWriteArgs.pdu, kCtrlZ);
+        response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CMGW>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+            goto done;
+        } else if (const CMGW* cmgw = response->get_if<CMGW>()) {
+            messageRef = cmgw->messageRef;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+        }
+
+done:   NOT_NULL(mRadioMessagingResponse)->writeSmsToSimResponse(
+            makeRadioResponseInfo(serial, status), messageRef);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+void RadioMessaging::atResponseSink(const AtResponsePtr& response) {
+    if (!mAtConversation.send(response)) {
+        response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    }
+}
+
+void RadioMessaging::handleUnsolicited(const AtResponse::CMT& cmt) {
+    if (mRadioMessagingIndication) {
+        mRadioMessagingIndication->newSms(
+            RadioIndicationType::UNSOLICITED, cmt.pdu);
+    }
+}
+
+void RadioMessaging::handleUnsolicited(const AtResponse::CDS& cds) {
+    if (mRadioMessagingIndication) {
+        mRadioMessagingIndication->newSmsStatusReport(
+            RadioIndicationType::UNSOLICITED, cds.pdu);
+    }
+}
+
+ScopedAStatus RadioMessaging::responseAcknowledgement() {
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioMessaging::setResponseFunctions(
+        const std::shared_ptr<messaging::IRadioMessagingResponse>& radioMessagingResponse,
+        const std::shared_ptr<messaging::IRadioMessagingIndication>& radioMessagingIndication) {
+    mRadioMessagingResponse = NOT_NULL(radioMessagingResponse);
+    mRadioMessagingIndication = NOT_NULL(radioMessagingIndication);
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioMessaging.h b/hals/radio/RadioMessaging.h
new file mode 100644
index 00000000..5638ae93
--- /dev/null
+++ b/hals/radio/RadioMessaging.h
@@ -0,0 +1,95 @@
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
+#include <memory>
+
+#include <aidl/android/hardware/radio/messaging/BnRadioMessaging.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioMessaging : public messaging::BnRadioMessaging {
+    RadioMessaging(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus acknowledgeIncomingGsmSmsWithPdu(int32_t serial, bool success,
+                                                   const std::string& ackPdu) override;
+    ScopedAStatus acknowledgeLastIncomingCdmaSms(
+            int32_t serial, const messaging::CdmaSmsAck& smsAck) override;
+    ScopedAStatus acknowledgeLastIncomingGsmSms(
+            int32_t serial, bool success,
+            messaging::SmsAcknowledgeFailCause cause) override;
+    ScopedAStatus deleteSmsOnRuim(int32_t serial, int32_t index) override;
+    ScopedAStatus deleteSmsOnSim(int32_t serial, int32_t index) override;
+    ScopedAStatus getCdmaBroadcastConfig(int32_t serial) override;
+    ScopedAStatus getGsmBroadcastConfig(int32_t serial) override;
+    ScopedAStatus getSmscAddress(int32_t serial) override;
+    ScopedAStatus reportSmsMemoryStatus(int32_t serial, bool available) override;
+    ScopedAStatus sendCdmaSms(
+            int32_t serial, const messaging::CdmaSmsMessage& sms) override;
+    ScopedAStatus sendCdmaSmsExpectMore(
+            int32_t serial, const messaging::CdmaSmsMessage& sms) override;
+    ScopedAStatus sendImsSms(
+            int32_t serial, const messaging::ImsSmsMessage& message) override;
+    ScopedAStatus sendSms(
+            int32_t serial, const messaging::GsmSmsMessage& message) override;
+    ScopedAStatus sendSmsExpectMore(
+            int32_t serial, const messaging::GsmSmsMessage& message) override;
+    ScopedAStatus setCdmaBroadcastConfig(
+            int32_t serial, const std::vector<messaging::CdmaBroadcastSmsConfigInfo>&
+                    configInfo) override;
+    ScopedAStatus setCdmaBroadcastActivation(int32_t serial, bool activate) override;
+    ScopedAStatus setGsmBroadcastConfig(
+            int32_t serial, const std::vector<messaging::GsmBroadcastSmsConfigInfo>&
+                    configInfo) override;
+    ScopedAStatus setGsmBroadcastActivation(int32_t serial, bool activate) override;
+    ScopedAStatus setSmscAddress(int32_t serial, const std::string& smsc) override;
+    ScopedAStatus writeSmsToRuim(
+            int32_t serial, const messaging::CdmaSmsWriteArgs& cdmaSms) override;
+    ScopedAStatus writeSmsToSim(
+            int32_t serial, const messaging::SmsWriteArgs& smsWriteArgs) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    void handleUnsolicited(const AtResponse::CMT&);
+    void handleUnsolicited(const AtResponse::CDS&);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus responseAcknowledgement() override;
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<messaging::IRadioMessagingResponse>& radioMessagingResponse,
+            const std::shared_ptr<messaging::IRadioMessagingIndication>& radioMessagingIndication) override;
+
+private:
+    std::pair<RadioResponseInfo, messaging::SendSmsResult>
+        sendSmsImpl(AtChannel::RequestPipe, int serial,
+                    const messaging::GsmSmsMessage &);
+
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+    std::shared_ptr<messaging::IRadioMessagingResponse> mRadioMessagingResponse;
+    std::shared_ptr<messaging::IRadioMessagingIndication> mRadioMessagingIndication;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioModem.cpp b/hals/radio/RadioModem.cpp
new file mode 100644
index 00000000..53d7db09
--- /dev/null
+++ b/hals/radio/RadioModem.cpp
@@ -0,0 +1,387 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioModem"
+
+#include <charconv>
+#include <format>
+
+#include "RadioModem.h"
+
+#include "atCmds.h"
+#include "debug.h"
+#include "makeRadioResponseInfo.h"
+#include "ratUtils.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace {
+constexpr char kBasebandversion[] = "1.0.0.0";
+constexpr char kModemUuid[] = "com.android.modem.simulator";
+constexpr char kSimUuid[] = "com.android.modem.simcard";
+}  // namespace
+
+RadioModem::RadioModem(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioModem::enableModem(const int32_t serial, const bool /*on*/) {
+    NOT_NULL(mRadioModemResponse)->enableModemResponse(
+        makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::getBasebandVersion(const int32_t serial) {
+    NOT_NULL(mRadioModemResponse)->getBasebandVersionResponse(
+            makeRadioResponseInfo(serial), kBasebandversion);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::getImei(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using namespace std::literals;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getIMEI,
+                            [](const AtResponse& response) -> bool {
+                                return response.holds<std::string>();
+                            });
+        if (!response) {
+            NOT_NULL(mRadioModemResponse)->getImeiResponse(
+                    makeRadioResponseInfo(serial, FAILURE(RadioError::INTERNAL_ERR)), {});
+            return false;
+        } else if (const std::string* imeiSvn = response->get_if<std::string>()) {
+            using modem::ImeiInfo;
+
+            ImeiInfo imeiInfo = {
+                .type = ImeiInfo::ImeiType::PRIMARY,
+                .imei = imeiSvn->substr(0, 15),
+                .svn = imeiSvn->substr(15, 2),
+            };
+
+            NOT_NULL(mRadioModemResponse)->getImeiResponse(
+                makeRadioResponseInfo(serial), std::move(imeiInfo));
+           return true;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::getHardwareConfig(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using modem::HardwareConfig;
+        using modem::HardwareConfigModem;
+        using modem::HardwareConfigSim;
+
+        std::vector<HardwareConfig> config;
+
+        const auto [status, rafBitmask] =
+            getSupportedRadioTechs(requestPipe, mAtConversation);
+        if (status == RadioError::NONE) {
+            const HardwareConfigModem modemHwConfig = {
+                .rilModel = 0,  // 0 - single: one-to-one relationship between a modem hardware and a ril daemon.
+                .rat = static_cast<RadioTechnology>(rafBitmask),
+                .maxVoiceCalls = 1,
+                .maxDataCalls = 1,
+                .maxStandby = 1,
+            };
+
+            HardwareConfig modemConfig = {
+                .type = HardwareConfig::TYPE_MODEM,
+                .uuid = kModemUuid,
+                .state = HardwareConfig::STATE_ENABLED,
+            };
+
+            modemConfig.modem.push_back(modemHwConfig);
+
+            HardwareConfig simConfig = {
+                .type = HardwareConfig::TYPE_SIM,
+                .uuid = kSimUuid,
+                .state = HardwareConfig::STATE_ENABLED,
+            };
+
+            HardwareConfigSim simHwConfig = {
+                .modemUuid = modemConfig.uuid,
+            };
+            simConfig.sim.push_back(simHwConfig);
+
+            config.push_back(std::move(modemConfig));
+            config.push_back(std::move(simConfig));
+        }
+
+        NOT_NULL(mRadioModemResponse)->getHardwareConfigResponse(
+                makeRadioResponseInfo(serial, status), std::move(config));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::getModemActivityInfo(const int32_t serial) {
+    using modem::ActivityStatsInfo;
+    using modem::ActivityStatsTechSpecificInfo;
+
+    ActivityStatsInfo activityStatsInfo = {
+        .sleepModeTimeMs = 42,
+        .idleModeTimeMs = 14,
+        .techSpecificInfo = {
+            {
+                .frequencyRange = ActivityStatsTechSpecificInfo::FREQUENCY_RANGE_UNKNOWN,
+                .txmModetimeMs = { 1, 3, 6, 8, 9 },
+                .rxModeTimeMs = 9,
+            },
+        },
+    };
+
+    NOT_NULL(mRadioModemResponse)->getModemActivityInfoResponse(
+            makeRadioResponseInfo(serial), std::move(activityStatsInfo));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::getModemStackStatus(const int32_t serial) {
+    NOT_NULL(mRadioModemResponse)->getModemStackStatusResponse(
+            makeRadioResponseInfo(serial), true);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::getRadioCapability(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using modem::RadioCapability;
+        RadioCapability cap;
+
+        const auto [status, rafBitmask] =
+            getSupportedRadioTechs(requestPipe, mAtConversation);
+        if (status == RadioError::NONE) {
+            cap.session = serial;
+            cap.phase = RadioCapability::PHASE_CONFIGURED;
+            cap.raf = rafBitmask;
+            cap.logicalModemUuid = kModemUuid;
+            cap.status = RadioCapability::STATUS_SUCCESS;
+        }
+
+        NOT_NULL(mRadioModemResponse)->getRadioCapabilityResponse(
+                makeRadioResponseInfo(serial, status), std::move(cap));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::requestShutdown(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        if (setRadioPowerImpl(requestPipe, false)) {
+            NOT_NULL(mRadioModemResponse)->requestShutdownResponse(
+                makeRadioResponseInfo(serial));
+            return true;
+        } else {
+            return false;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::sendDeviceState(const int32_t serial,
+                                          const modem::DeviceStateType /*stateType*/,
+                                          const bool /*state*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioModemResponse)->sendDeviceStateResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::setRadioCapability(const int32_t serial,
+                                             const modem::RadioCapability& /*rc*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioModemResponse)->setRadioCapabilityResponse(
+        makeRadioResponseInfoNOP(serial), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::setRadioPower(const int32_t serial, const bool powerOn,
+                                        const bool forEmergencyCall,
+                                        const bool preferredForEmergencyCall) {
+    mAtChannel->queueRequester([this, serial, powerOn]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        if (setRadioPowerImpl(requestPipe, powerOn)) {
+            NOT_NULL(mRadioModemResponse)->setRadioPowerResponse(
+                    makeRadioResponseInfo(serial));
+            return true;
+        } else {
+            return false;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::responseAcknowledgement() {
+    return ScopedAStatus::ok();
+}
+
+void RadioModem::atResponseSink(const AtResponsePtr& response) {
+    if (!mAtConversation.send(response)) {
+        response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    }
+}
+
+void RadioModem::handleUnsolicited(const AtResponse::CFUN& cfun) {
+    bool changed;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        changed = (mRadioState != cfun.state);
+        mRadioState = cfun.state;
+    }
+
+    if (changed && mRadioModemIndication) {
+        mRadioModemIndication->radioStateChanged(
+            RadioIndicationType::UNSOLICITED, cfun.state);
+    }
+}
+
+ScopedAStatus RadioModem::setResponseFunctions(
+        const std::shared_ptr<modem::IRadioModemResponse>& radioModemResponse,
+        const std::shared_ptr<modem::IRadioModemIndication>& radioModemIndication) {
+    mRadioModemResponse = NOT_NULL(radioModemResponse);
+    mRadioModemIndication = NOT_NULL(radioModemIndication);
+
+    modem::RadioState radioState;
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        radioState = mRadioState;
+    }
+
+    radioModemIndication->rilConnected(RadioIndicationType::UNSOLICITED);
+
+    radioModemIndication->radioStateChanged(
+            RadioIndicationType::UNSOLICITED, radioState);
+
+    return ScopedAStatus::ok();
+}
+
+std::pair<RadioError, uint32_t> RadioModem::getSupportedRadioTechs(
+            const AtChannel::RequestPipe requestPipe,
+            AtChannel::Conversation& atConversation) {
+    using ParseError = AtResponse::ParseError;
+    using CTEC = AtResponse::CTEC;
+    using ratUtils::ModemTechnology;
+
+    AtResponsePtr response =
+        atConversation(requestPipe, atCmds::getSupportedRadioTechs,
+                        [](const AtResponse& response) -> bool {
+                            return response.holds<CTEC>();
+                        });
+    if (!response || response->isParseError()) {
+        return {FAILURE(RadioError::INTERNAL_ERR), 0};
+    } else if (const CTEC* ctec = response->get_if<CTEC>()) {
+        uint32_t rafBitmask = 0;
+
+        for (const std::string& mtechStr : ctec->values) {
+            int mtech;
+            std::from_chars(&*mtechStr.begin(), &*mtechStr.end(), mtech, 10);
+
+            rafBitmask |= ratUtils::supportedRadioTechBitmask(
+                static_cast<ModemTechnology>(mtech));
+        }
+
+        return {RadioError::NONE, rafBitmask};
+    } else {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+}
+
+bool RadioModem::setRadioPowerImpl(const AtChannel::RequestPipe requestPipe,
+                                   const bool powerOn) {
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        if (powerOn == (mRadioState == modem::RadioState::ON)) {
+            return true;
+        }
+    }
+
+    const std::string request = std::format("AT+CFUN={0:d}", powerOn ? 1 : 0);
+    if (!requestPipe(request)) {
+        return FAILURE(false);
+    }
+
+    // to broadcast CFUN from the listening thread
+    if (!requestPipe(atCmds::getModemPowerState)) {
+        return FAILURE(false);
+    }
+
+    using modem::RadioState;
+
+    const modem::RadioState newState =
+        powerOn ? RadioState::ON : RadioState::OFF;
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mRadioState = newState;
+    }
+
+    NOT_NULL(mRadioModemIndication)->radioStateChanged(
+            RadioIndicationType::UNSOLICITED, newState);
+
+    return true;
+}
+
+/************************* deprecated *************************/
+ScopedAStatus RadioModem::getDeviceIdentity(const int32_t serial) {
+    NOT_NULL(mRadioModemResponse)->getDeviceIdentityResponse(
+        makeRadioResponseInfoDeprecated(serial),
+        "", "", "", "");
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::nvReadItem(const int32_t serial, modem::NvItem) {
+    NOT_NULL(mRadioModemResponse)->nvReadItemResponse(
+        makeRadioResponseInfoDeprecated(serial), "");
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::nvResetConfig(const int32_t serial, modem::ResetNvType) {
+    NOT_NULL(mRadioModemResponse)->nvResetConfigResponse(
+        makeRadioResponseInfoDeprecated(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::nvWriteCdmaPrl(const int32_t serial, const std::vector<uint8_t>&) {
+    NOT_NULL(mRadioModemResponse)->nvWriteCdmaPrlResponse(
+        makeRadioResponseInfoDeprecated(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioModem::nvWriteItem(const int32_t serial, const modem::NvWriteItem&) {
+    NOT_NULL(mRadioModemResponse)->nvWriteItemResponse(
+        makeRadioResponseInfoDeprecated(serial));
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioModem.h b/hals/radio/RadioModem.h
new file mode 100644
index 00000000..eacca2a4
--- /dev/null
+++ b/hals/radio/RadioModem.h
@@ -0,0 +1,89 @@
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
+#include <memory>
+#include <mutex>
+
+#include <aidl/android/hardware/radio/modem/BnRadioModem.h>
+#include "AtChannel.h"
+#include "AtResponse.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioModem : public modem::BnRadioModem {
+    RadioModem(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus enableModem(int32_t serial, bool on) override;
+    ScopedAStatus getBasebandVersion(int32_t serial) override;
+    ScopedAStatus getDeviceIdentity(int32_t serial) override;
+    ScopedAStatus getImei(int32_t serial) override;
+    ScopedAStatus getHardwareConfig(int32_t serial) override;
+    ScopedAStatus getModemActivityInfo(int32_t serial) override;
+    ScopedAStatus getModemStackStatus(int32_t serial) override;
+    ScopedAStatus getRadioCapability(int32_t serial) override;
+    ScopedAStatus nvReadItem(
+            int32_t serial, modem::NvItem itemId) override;
+    ScopedAStatus nvResetConfig(
+            int32_t serial, modem::ResetNvType type) override;
+    ScopedAStatus nvWriteCdmaPrl(int32_t serial, const std::vector<uint8_t>& prl) override;
+    ScopedAStatus nvWriteItem(
+            int32_t serial, const modem::NvWriteItem& i) override;
+    ScopedAStatus requestShutdown(int32_t serial) override;
+    ScopedAStatus sendDeviceState(
+            int32_t serial, modem::DeviceStateType stateType,
+            bool state) override;
+    ScopedAStatus setRadioCapability(
+            int32_t s, const modem::RadioCapability& rc) override;
+    ScopedAStatus setRadioPower(int32_t serial, bool powerOn, bool forEmergencyCall,
+                                bool preferredForEmergencyCall) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    void handleUnsolicited(const AtResponse::CFUN& cfun);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus responseAcknowledgement() override;
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<modem::IRadioModemResponse>& radioModemResponse,
+            const std::shared_ptr<modem::IRadioModemIndication>& radioModemIndication) override;
+
+private:
+    std::pair<RadioError, uint32_t> getSupportedRadioTechs(
+            const AtChannel::RequestPipe requestPipe,
+            AtChannel::Conversation& atConversation);
+
+    bool setRadioPowerImpl(const AtChannel::RequestPipe requestPipe,
+                           bool powerOn);
+
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+    std::shared_ptr<modem::IRadioModemResponse> mRadioModemResponse;
+    std::shared_ptr<modem::IRadioModemIndication> mRadioModemIndication;
+
+    modem::RadioState   mRadioState = modem::RadioState::OFF;
+    std::mutex          mMtx;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioNetwork.cpp b/hals/radio/RadioNetwork.cpp
new file mode 100644
index 00000000..69dddfc7
--- /dev/null
+++ b/hals/radio/RadioNetwork.cpp
@@ -0,0 +1,1534 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioNetwork"
+
+#include <chrono>
+#include <thread>
+
+#include <utils/SystemClock.h>
+
+#include <aidl/android/hardware/radio/RadioConst.h>
+
+#include "RadioNetwork.h"
+#include "atCmds.h"
+#include "debug.h"
+#include "ratUtils.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using network::AccessTechnologySpecificInfo;
+using network::EutranBands;
+using network::EutranRegistrationInfo;
+using network::Cdma2000RegistrationInfo;
+using network::CellConnectionStatus;
+using network::CellIdentity;
+using network::CellIdentityCdma;
+using network::CellIdentityGsm;
+using network::CellIdentityLte;
+using network::CellIdentityNr;
+using network::CellIdentityTdscdma;
+using network::CellIdentityWcdma;
+using network::CellInfo;
+using network::CellInfoCdma;
+using network::CellInfoGsm;
+using network::CellInfoLte;
+using network::CellInfoNr;
+using network::CellInfoTdscdma;
+using network::CellInfoWcdma;
+using network::CellInfoRatSpecificInfo;
+using network::NgranBands;
+using network::OperatorInfo;
+using network::RegStateResult;
+using network::SignalStrength;
+
+namespace {
+// somehow RadioConst.h does not contain these values
+constexpr int32_t kRadioConst_VALUE_UNAVAILABLE = 0x7FFFFFFF;  // b/382554555
+constexpr uint8_t kRadioConst_VALUE_UNAVAILABLE_BYTE = 0xFFU;
+
+CellIdentityCdma makeCellIdentityCdma(OperatorInfo operatorInfo) {
+    CellIdentityCdma result = {
+        .networkId = kRadioConst_VALUE_UNAVAILABLE,
+        .systemId = kRadioConst_VALUE_UNAVAILABLE,
+        .baseStationId = kRadioConst_VALUE_UNAVAILABLE,
+        .longitude = kRadioConst_VALUE_UNAVAILABLE,
+        .latitude = kRadioConst_VALUE_UNAVAILABLE,
+    };
+
+    result.operatorNames = std::move(operatorInfo);
+
+    return result;
+}
+
+std::string getMcc(const OperatorInfo& operatorInfo) {
+    return operatorInfo.operatorNumeric.substr(0, 3);
+}
+
+std::string getMnc(const OperatorInfo& operatorInfo) {
+    return operatorInfo.operatorNumeric.substr(3);
+}
+
+CellIdentityGsm makeCellIdentityGsm(OperatorInfo operatorInfo,
+                                    const int areaCode, const int cellId) {
+    CellIdentityGsm result = {
+        .mcc = getMcc(operatorInfo),
+        .mnc = getMnc(operatorInfo),
+        .lac = areaCode,
+        .cid = cellId,
+        .arfcn = 42,
+        .bsic = 127, // kRadioConst_VALUE_UNAVAILABLE_BYTE, b/382555063
+    };
+
+    result.additionalPlmns.push_back(operatorInfo.operatorNumeric);
+    result.operatorNames = std::move(operatorInfo);
+
+    return result;
+}
+
+CellIdentityLte makeCellIdentityLte(OperatorInfo operatorInfo,
+                                    const int areaCode, const int cellId) {
+    CellIdentityLte result = {
+        .mcc = getMcc(operatorInfo),
+        .mnc = getMnc(operatorInfo),
+        .ci = cellId,
+        .pci = 0,
+        .tac = areaCode,
+        .earfcn = 103,
+        .bandwidth = 10000,
+    };
+
+    result.additionalPlmns.push_back(operatorInfo.operatorNumeric);
+    result.operatorNames = std::move(operatorInfo);
+    result.bands.push_back(EutranBands::BAND_42);
+
+    return result;
+}
+
+CellIdentityNr makeCellIdentityNr(OperatorInfo operatorInfo, const int areaCode) {
+    std::string plmn = operatorInfo.operatorNumeric;
+
+    CellIdentityNr result = {
+        .mcc = getMcc(operatorInfo),
+        .mnc = getMnc(operatorInfo),
+        .nci = 100500,
+        .pci = 555,
+        .tac = areaCode,
+        .nrarfcn = 9000,
+    };
+
+    result.additionalPlmns.push_back(operatorInfo.operatorNumeric);
+    result.operatorNames = std::move(operatorInfo);
+    result.bands.push_back(NgranBands::BAND_41);
+
+    return result;
+}
+
+CellIdentityTdscdma makeCellIdentityTdscdma(OperatorInfo operatorInfo,
+                                            const int areaCode, const int cellId) {
+    CellIdentityTdscdma result = {
+        .mcc = getMcc(operatorInfo),
+        .mnc = getMnc(operatorInfo),
+        .lac = areaCode,
+        .cid = cellId,
+        .cpid = kRadioConst_VALUE_UNAVAILABLE,
+        .uarfcn = 777,
+    };
+
+    result.additionalPlmns.push_back(operatorInfo.operatorNumeric);
+    result.operatorNames = std::move(operatorInfo);
+
+    return result;
+}
+
+CellIdentityWcdma makeCellIdentityWcdma(OperatorInfo operatorInfo,
+                                        const int areaCode, const int cellId) {
+    CellIdentityWcdma result = {
+        .mcc = getMcc(operatorInfo),
+        .mnc = getMnc(operatorInfo),
+        .lac = areaCode,
+        .cid = cellId,
+        .psc = 222,
+        .uarfcn = 777,
+    };
+
+    result.additionalPlmns.push_back(operatorInfo.operatorNumeric);
+    result.operatorNames = std::move(operatorInfo);
+
+    return result;
+}
+
+OperatorInfo toOperatorInfo(AtResponse::COPS::OperatorInfo cops) {
+    return {
+        .alphaLong = std::move(cops.longName),
+        .alphaShort = std::move(cops.shortName),
+        .operatorNumeric = std::move(cops.numeric),
+        .status = OperatorInfo::STATUS_CURRENT,
+    };
+}
+
+using CellIdentityResult = std::pair<RadioError, CellIdentity>;
+
+CellIdentityResult getCellIdentityImpl(OperatorInfo operatorInfo,
+                                       const ratUtils::ModemTechnology mtech,
+                                       const int areaCode, const int cellId,
+                                       std::string* plmn) {
+    using ratUtils::ModemTechnology;
+
+    if (plmn) {
+        *plmn = operatorInfo.operatorNumeric;
+    }
+
+    CellIdentity cellIdentity;
+
+    switch (mtech) {
+    case ModemTechnology::GSM:
+        cellIdentity.set<CellIdentity::gsm>(makeCellIdentityGsm(std::move(operatorInfo),
+                                                                areaCode, cellId));
+        break;
+    case ModemTechnology::WCDMA:
+    case ModemTechnology::EVDO:
+        cellIdentity.set<CellIdentity::wcdma>(makeCellIdentityWcdma(std::move(operatorInfo),
+                                                                    areaCode, cellId));
+        break;
+    case ModemTechnology::CDMA:
+        cellIdentity.set<CellIdentity::cdma>(makeCellIdentityCdma(std::move(operatorInfo)));
+        break;
+    case ModemTechnology::TDSCDMA:
+        cellIdentity.set<CellIdentity::tdscdma>(makeCellIdentityTdscdma(std::move(operatorInfo),
+                                                                        areaCode, cellId));
+        break;
+    case ModemTechnology::LTE:
+        cellIdentity.set<CellIdentity::lte>(makeCellIdentityLte(std::move(operatorInfo),
+                                                                areaCode, cellId));
+        break;
+    case ModemTechnology::NR:
+        cellIdentity.set<CellIdentity::nr>(makeCellIdentityNr(std::move(operatorInfo), areaCode));
+        break;
+    default:
+        return {FAILURE_V(RadioError::INTERNAL_ERR, "Unexpected radio technology: %u",
+                          static_cast<unsigned>(mtech)), {}};
+    };
+
+    return {RadioError::NONE, std::move(cellIdentity)};
+}
+
+CellIdentityResult getCellIdentityImpl(const int areaCode, const int cellId, std::string* plmn,
+                                       AtChannel::Conversation& atConversation,
+                                       const AtChannel::RequestPipe requestPipe) {
+    static const auto fail = [](RadioError e) -> CellIdentityResult { return {e, {}}; };
+
+    using CmeError = AtResponse::CmeError;
+    using COPS = AtResponse::COPS;
+    using CTEC = AtResponse::CTEC;
+    using ratUtils::ModemTechnology;
+
+    OperatorInfo operatorInfo;
+    AtResponsePtr response =
+        atConversation(requestPipe, atCmds::getOperator,
+                       [](const AtResponse& response) -> bool {
+                           return response.holds<COPS>() || response.holds<CmeError>();
+                       });
+    if (!response || response->isParseError()) {
+        return FAILURE(fail(RadioError::INTERNAL_ERR));
+    } else if (const COPS* cops = response->get_if<COPS>()) {
+        if ((cops->operators.size() == 1) && (cops->operators[0].isCurrent())) {
+            operatorInfo = toOperatorInfo(cops->operators[0]);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+        }
+    } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+        const RadioError status =
+            (cmeError->error == RadioError::OPERATION_NOT_ALLOWED) ?
+                RadioError::RADIO_NOT_AVAILABLE : cmeError->error;
+
+        return fail(FAILURE_V(status, "%s", toString(status).c_str()));
+    } else {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+
+    ModemTechnology mtech;
+    response =
+        atConversation(requestPipe, atCmds::getCurrentPreferredRadioTechs,
+                       [](const AtResponse& response) -> bool {
+                           return response.holds<CTEC>();
+                       });
+    if (!response || response->isParseError()) {
+        return FAILURE(fail(RadioError::INTERNAL_ERR));
+    } else if (const CTEC* ctec = response->get_if<CTEC>()) {
+        mtech = ctec->getCurrentModemTechnology().value();
+    } else {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+
+    return getCellIdentityImpl(std::move(operatorInfo), mtech,
+                               areaCode, cellId, plmn);
+}
+
+std::pair<RadioError, CellInfo> buildCellInfo(const bool registered,
+                                              CellIdentity cellIdentity,
+                                              SignalStrength signalStrength) {
+    CellInfo cellInfo = {
+        .registered = registered,
+        .connectionStatus = registered ?
+            CellConnectionStatus::PRIMARY_SERVING : CellConnectionStatus::NONE,
+    };
+
+    switch (cellIdentity.getTag()) {
+    default:
+        return {FAILURE_V(RadioError::INTERNAL_ERR, "%s",
+                          "unexpected getTag"), {}};
+
+    case CellIdentity::gsm: {
+            CellInfoGsm cellInfoGsm = {
+                .cellIdentityGsm = std::move(cellIdentity.get<CellIdentity::gsm>()),
+                .signalStrengthGsm = std::move(signalStrength.gsm),
+            };
+            cellInfo.ratSpecificInfo.set<CellInfoRatSpecificInfo::gsm>(std::move(cellInfoGsm));
+        }
+        break;
+
+    case CellIdentity::wcdma: {
+            CellInfoWcdma cellInfoWcdma = {
+                .cellIdentityWcdma = std::move(cellIdentity.get<CellIdentity::wcdma>()),
+                .signalStrengthWcdma = std::move(signalStrength.wcdma),
+            };
+            cellInfo.ratSpecificInfo.set<CellInfoRatSpecificInfo::wcdma>(std::move(cellInfoWcdma));
+        }
+        break;
+
+    case CellIdentity::tdscdma: {
+            CellInfoTdscdma cellInfoTdscdma = {
+                .cellIdentityTdscdma = std::move(cellIdentity.get<CellIdentity::tdscdma>()),
+                .signalStrengthTdscdma = std::move(signalStrength.tdscdma),
+            };
+            cellInfo.ratSpecificInfo.set<CellInfoRatSpecificInfo::tdscdma>(std::move(cellInfoTdscdma));
+        }
+        break;
+
+    case CellIdentity::cdma: {
+            CellInfoCdma cellInfoCdma = {
+                .cellIdentityCdma = std::move(cellIdentity.get<CellIdentity::cdma>()),
+                .signalStrengthCdma = std::move(signalStrength.cdma),
+            };
+            cellInfo.ratSpecificInfo.set<CellInfoRatSpecificInfo::cdma>(std::move(cellInfoCdma));
+        }
+        break;
+
+
+    case CellIdentity::lte: {
+            CellInfoLte cellInfoLte = {
+                .cellIdentityLte = std::move(cellIdentity.get<CellIdentity::lte>()),
+                .signalStrengthLte = std::move(signalStrength.lte),
+            };
+            cellInfo.ratSpecificInfo.set<CellInfoRatSpecificInfo::lte>(std::move(cellInfoLte));
+        }
+        break;
+
+    case CellIdentity::nr: {
+            CellInfoNr cellInfoNr = {
+                .cellIdentityNr = std::move(cellIdentity.get<CellIdentity::nr>()),
+                .signalStrengthNr = std::move(signalStrength.nr),
+            };
+            cellInfo.ratSpecificInfo.set<CellInfoRatSpecificInfo::nr>(std::move(cellInfoNr));
+        }
+        break;
+    }
+
+    return {RadioError::NONE, std::move(cellInfo)};
+}
+
+void setAccessTechnologySpecificInfo(
+        AccessTechnologySpecificInfo* accessTechnologySpecificInfo,
+        const RadioTechnology rat) {
+    switch (rat) {
+    case RadioTechnology::LTE:
+    case RadioTechnology::LTE_CA: {
+            EutranRegistrationInfo eri = {
+                .lteVopsInfo = {
+                    .isVopsSupported = false,
+                    .isEmcBearerSupported = false,
+                },
+            };
+
+            accessTechnologySpecificInfo->set<
+                AccessTechnologySpecificInfo::eutranInfo>(std::move(eri));
+        }
+        break;
+
+    case RadioTechnology::NR: {
+            EutranRegistrationInfo eri = {
+                .nrIndicators = {
+                    .isNrAvailable = true,
+                    .isDcNrRestricted = false,
+                    .isEndcAvailable = false,
+                },
+            };
+
+            accessTechnologySpecificInfo->set<
+                AccessTechnologySpecificInfo::eutranInfo>(std::move(eri));
+        }
+        break;
+
+    case RadioTechnology::HSUPA:
+    case RadioTechnology::HSDPA:
+    case RadioTechnology::HSPA:
+    case RadioTechnology::HSPAP:
+    case RadioTechnology::UMTS:
+    case RadioTechnology::IS95A:
+    case RadioTechnology::IS95B:
+    case RadioTechnology::ONE_X_RTT:
+    case RadioTechnology::EVDO_0:
+    case RadioTechnology::EVDO_A:
+    case RadioTechnology::EVDO_B:
+    case RadioTechnology::EHRPD:
+    case RadioTechnology::TD_SCDMA: {
+            Cdma2000RegistrationInfo cri = {
+                .systemIsInPrl = Cdma2000RegistrationInfo::PRL_INDICATOR_IN_PRL,
+            };
+
+            accessTechnologySpecificInfo->set<
+                AccessTechnologySpecificInfo::cdmaInfo>(std::move(cri));
+        }
+        break;
+
+    default:
+        break;
+    }
+}
+
+}  // namespace
+
+RadioNetwork::RadioNetwork(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioNetwork::getAllowedNetworkTypesBitmap(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CTEC = AtResponse::CTEC;
+
+        RadioError status = RadioError::NONE;
+        uint32_t networkTypeBitmap = 0;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getCurrentPreferredRadioTechs,
+                            [](const AtResponse& response) -> bool {
+                                return response.holds<CTEC>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CTEC* ctec = response->get_if<CTEC>()) {
+            networkTypeBitmap =
+                ratUtils::supportedRadioTechBitmask(
+                    ctec->getCurrentModemTechnology().value());
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->getAllowedNetworkTypesBitmapResponse(
+                makeRadioResponseInfo(serial, status), networkTypeBitmap);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getAvailableBandModes(const int32_t serial) {
+    using network::RadioBandMode;
+
+    NOT_NULL(mRadioNetworkResponse)->getAvailableBandModesResponse(
+        makeRadioResponseInfo(serial), {
+            RadioBandMode::BAND_MODE_UNSPECIFIED,
+            RadioBandMode::BAND_MODE_EURO,
+            RadioBandMode::BAND_MODE_USA,
+            RadioBandMode::BAND_MODE_JPN,
+            RadioBandMode::BAND_MODE_AUS,
+            RadioBandMode::BAND_MODE_USA_2500M,
+        });
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getAvailableNetworks(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->getAvailableNetworksResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getBarringInfo(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        int areaCode;
+        int cellId;
+        {
+            std::lock_guard<std::mutex> lock(mMtx);
+            areaCode = mCreg.areaCode;
+            cellId = mCreg.cellId;
+        }
+
+        CellIdentityResult cellIdentityResult =
+            getCellIdentityImpl(areaCode, cellId, nullptr, mAtConversation, requestPipe);
+        if (cellIdentityResult.first == RadioError::NONE) {
+            using network::BarringInfo;
+
+            BarringInfo barringInfoCs = {
+                .serviceType = BarringInfo::SERVICE_TYPE_CS_SERVICE,
+                .barringType = BarringInfo::BARRING_TYPE_NONE,
+            };
+
+            BarringInfo barringInfoPs = {
+                .serviceType = BarringInfo::SERVICE_TYPE_PS_SERVICE,
+                .barringType = BarringInfo::BARRING_TYPE_NONE,
+            };
+
+            BarringInfo barringInfoCsVoice = {
+                .serviceType = BarringInfo::SERVICE_TYPE_CS_VOICE,
+                .barringType = BarringInfo::BARRING_TYPE_NONE,
+            };
+
+            BarringInfo barringInfoEmergency = {
+                .serviceType = BarringInfo::SERVICE_TYPE_EMERGENCY,
+                .barringType = BarringInfo::BARRING_TYPE_NONE,
+            };
+
+            NOT_NULL(mRadioNetworkResponse)->getBarringInfoResponse(
+                    makeRadioResponseInfo(serial),
+                    std::move(cellIdentityResult.second),
+                    {
+                        std::move(barringInfoCs),
+                        std::move(barringInfoPs),
+                        std::move(barringInfoCsVoice),
+                        std::move(barringInfoEmergency),
+                    });
+            return true;
+        } else {
+            NOT_NULL(mRadioNetworkResponse)->getBarringInfoResponse(
+                    makeRadioResponseInfo(serial,
+                                          FAILURE_V(cellIdentityResult.first, "%s",
+                                                    toString(cellIdentityResult.first).c_str())),
+                    {}, {});
+            return cellIdentityResult.first != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getCdmaRoamingPreference(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using WRMP = AtResponse::WRMP;
+        using network::CdmaRoamingType;
+
+        RadioError status = RadioError::NONE;
+        CdmaRoamingType cdmaRoamingPreference = CdmaRoamingType::HOME_NETWORK;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getCdmaRoamingPreference,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<WRMP>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const WRMP* wrmp = response->get_if<WRMP>()) {
+            cdmaRoamingPreference = wrmp->cdmaRoamingPreference;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->getCdmaRoamingPreferenceResponse(
+            makeRadioResponseInfo(serial, status), cdmaRoamingPreference);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getCellInfoList(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        SignalStrength signalStrength;
+        int areaCode;
+        int cellId;
+        bool registered;
+        {
+            std::lock_guard<std::mutex> lock(mMtx);
+            signalStrength = mCsq.toSignalStrength();
+            areaCode = mCreg.areaCode;
+            cellId = mCreg.cellId;
+            registered = (mCreg.state == network::RegState::REG_HOME);
+        }
+
+        RadioError status;
+        CellIdentity cellIdentity;
+        CellInfo cellInfo;
+
+        std::tie(status, cellIdentity) =
+            getCellIdentityImpl(areaCode, cellId, nullptr, mAtConversation, requestPipe);
+        if (status == RadioError::NONE) {
+            std::tie(status, cellInfo) = buildCellInfo(registered,
+                                                       std::move(cellIdentity),
+                                                       std::move(signalStrength));
+
+            if (status == RadioError::NONE) {
+                NOT_NULL(mRadioNetworkResponse)->getCellInfoListResponse(
+                    makeRadioResponseInfo(serial), { std::move(cellInfo) });
+                return true;
+            }
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->getCellInfoListResponse(
+            makeRadioResponseInfo(serial, status), {});
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getDataRegistrationState(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CTEC = AtResponse::CTEC;
+
+        RadioError status = RadioError::NONE;
+        RegStateResult regStateResult;
+        int areaCode;
+        int cellId;
+
+        {
+            std::lock_guard<std::mutex> lock(mMtx);
+            regStateResult.regState = mCreg.state;
+            areaCode = mCreg.areaCode;
+            cellId = mCreg.cellId;
+        }
+
+        std::tie(status, regStateResult.cellIdentity) =
+            getCellIdentityImpl(areaCode, cellId, &regStateResult.registeredPlmn,
+                                mAtConversation, requestPipe);
+        if (status != RadioError::NONE) {
+            goto failed;
+        }
+
+        {
+            AtResponsePtr response =
+                mAtConversation(requestPipe, atCmds::getCurrentPreferredRadioTechs,
+                                [](const AtResponse& response) -> bool {
+                                   return response.holds<CTEC>();
+                                });
+            if (!response || response->isParseError()) {
+                status = FAILURE(RadioError::INTERNAL_ERR);
+                goto failed;
+            } else if (const CTEC* ctec = response->get_if<CTEC>()) {
+                regStateResult.rat =
+                    ratUtils::currentRadioTechnology(
+                        ctec->getCurrentModemTechnology().value());
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+        }
+
+        setAccessTechnologySpecificInfo(
+            &regStateResult.accessTechnologySpecificInfo,
+            regStateResult.rat);
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioNetworkResponse)->getDataRegistrationStateResponse(
+                makeRadioResponseInfo(serial), std::move(regStateResult));
+            return true;
+        } else {
+failed:     NOT_NULL(mRadioNetworkResponse)->getDataRegistrationStateResponse(
+                makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getNetworkSelectionMode(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        using COPS = AtResponse::COPS;
+
+        RadioError status = RadioError::NONE;
+        bool manual = true;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getNetworkSelectionMode,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<COPS>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const COPS* cops = response->get_if<COPS>()) {
+            manual = (cops->networkSelectionMode == COPS::NetworkSelectionMode::MANUAL);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->getNetworkSelectionModeResponse(
+                makeRadioResponseInfo(serial, status), manual);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getOperator(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        using COPS = AtResponse::COPS;
+
+        RadioError status = RadioError::NONE;
+        std::string longName;
+        std::string shortName;
+        std::string numeric;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getOperator,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<COPS>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const COPS* cops = response->get_if<COPS>()) {
+            if ((cops->operators.size() == 1) && (cops->operators[0].isCurrent())) {
+                const COPS::OperatorInfo& current = cops->operators[0];
+
+                longName = current.longName;
+                shortName = current.shortName;
+                numeric = current.numeric;
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = (cmeError->error == RadioError::OPERATION_NOT_ALLOWED) ?
+                    RadioError::RADIO_NOT_AVAILABLE : cmeError->error;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->getOperatorResponse(
+                makeRadioResponseInfo(serial, status),
+                std::move(longName), std::move(shortName), std::move(numeric));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getSignalStrength(const int32_t serial) {
+    network::SignalStrength signalStrength;
+
+    RadioError status;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        signalStrength = mCsq.toSignalStrength();
+        status = (mRadioState == modem::RadioState::ON) ?
+            RadioError::NONE : FAILURE(RadioError::RADIO_NOT_AVAILABLE);
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->getSignalStrengthResponse(
+            makeRadioResponseInfo(serial, status), std::move(signalStrength));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getSystemSelectionChannels(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->getSystemSelectionChannelsResponse(
+            makeRadioResponseInfoNOP(serial), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getVoiceRadioTechnology(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CTEC = AtResponse::CTEC;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getCurrentPreferredRadioTechs,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CTEC>();
+                            });
+        if (!response || response->isParseError()) {
+            NOT_NULL(mRadioNetworkResponse)->getVoiceRadioTechnologyResponse(
+                makeRadioResponseInfo(serial, FAILURE(RadioError::INTERNAL_ERR)), {});
+            return false;
+        } else if (const CTEC* ctec = response->get_if<CTEC>()) {
+            NOT_NULL(mRadioNetworkResponse)->getVoiceRadioTechnologyResponse(
+                makeRadioResponseInfo(serial),
+                ratUtils::currentRadioTechnology(
+                    ctec->getCurrentModemTechnology().value()));
+            return true;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getVoiceRegistrationState(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CTEC = AtResponse::CTEC;
+
+        RadioError status = RadioError::NONE;
+        RegStateResult regStateResult;
+        int areaCode;
+        int cellId;
+
+        {
+            std::lock_guard<std::mutex> lock(mMtx);
+            regStateResult.regState = mCreg.state;
+            areaCode = mCreg.areaCode;
+            cellId = mCreg.cellId;
+        }
+
+        CellIdentityResult cellIdentityResult =
+            getCellIdentityImpl(areaCode, cellId, &regStateResult.registeredPlmn,
+                                mAtConversation, requestPipe);
+        if (cellIdentityResult.first == RadioError::NONE) {
+            regStateResult.cellIdentity = std::move(cellIdentityResult.second);
+        } else {
+            status = cellIdentityResult.first;
+            goto failed;
+        }
+
+        {
+            AtResponsePtr response =
+                mAtConversation(requestPipe, atCmds::getCurrentPreferredRadioTechs,
+                                [](const AtResponse& response) -> bool {
+                                   return response.holds<CTEC>();
+                                });
+            if (!response || response->isParseError()) {
+                status = FAILURE(RadioError::INTERNAL_ERR);
+                goto failed;
+            } else if (const CTEC* ctec = response->get_if<CTEC>()) {
+                regStateResult.rat =
+                    ratUtils::currentRadioTechnology(
+                        ctec->getCurrentModemTechnology().value());
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+        }
+
+        setAccessTechnologySpecificInfo(
+            &regStateResult.accessTechnologySpecificInfo,
+            regStateResult.rat);
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioNetworkResponse)->getVoiceRegistrationStateResponse(
+                makeRadioResponseInfo(serial), std::move(regStateResult));
+            return true;
+        } else {
+failed:     NOT_NULL(mRadioNetworkResponse)->getVoiceRegistrationStateResponse(
+                makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::isNrDualConnectivityEnabled(const int32_t serial) {
+    bool enabled;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        enabled = mIsNrDualConnectivityEnabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->isNrDualConnectivityEnabledResponse(
+            makeRadioResponseInfo(serial), enabled);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setAllowedNetworkTypesBitmap(const int32_t serial,
+                                                         const int32_t networkTypeBitmap) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, networkTypeBitmap]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CTEC = AtResponse::CTEC;
+
+        RadioError status = RadioError::NONE;
+
+        const ratUtils::ModemTechnology currentTech =
+            ratUtils::modemTechnologyFromRadioTechnologyBitmask(networkTypeBitmap);
+        const uint32_t techBitmask =
+            ratUtils::modemTechnologyBitmaskFromRadioTechnologyBitmask(networkTypeBitmap);
+
+        const std::string request = std::format("AT+CTEC={0:d},\"{1:X}\"",
+            (1 << static_cast<int>(currentTech)), techBitmask);
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CTEC>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->get_if<CTEC>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->setAllowedNetworkTypesBitmapResponse(
+            makeRadioResponseInfo(serial, status));
+
+        if (mRadioNetworkIndication) {
+            mRadioNetworkIndication->voiceRadioTechChanged(
+                RadioIndicationType::UNSOLICITED,
+                ratUtils::currentRadioTechnology(currentTech));
+        }
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setBandMode(const int32_t serial,
+                                        const network::RadioBandMode /*mode*/) {
+    NOT_NULL(mRadioNetworkResponse)->setBandModeResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setBarringPassword(const int32_t serial,
+                                               const std::string& facility,
+                                               const std::string& oldPassword,
+                                               const std::string& newPassword) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, facility, oldPassword, newPassword]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        RadioError status = RadioError::NONE;
+
+        const std::string request =
+            std::format("AT+CPWD=\"{0:s}\",\"{1:s}\",\"{2:s}\"",
+                        facility, oldPassword, newPassword);
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->setBarringPasswordResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setCdmaRoamingPreference(const int32_t serial,
+                                                     const network::CdmaRoamingType type) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, type]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        RadioError status = RadioError::NONE;
+
+        const std::string request =
+            std::format("AT+WRMP={0:d}", static_cast<unsigned>(type));
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->setCdmaRoamingPreferenceResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setCellInfoListRate(const int32_t serial,
+                                                const int32_t /*rate*/) {
+    NOT_NULL(mRadioNetworkResponse)->setCellInfoListRateResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setIndicationFilter(const int32_t serial,
+                                                const int32_t /*indicationFilter*/) {
+    NOT_NULL(mRadioNetworkResponse)->setIndicationFilterResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setLinkCapacityReportingCriteria(const int32_t serial,
+                                                             const int32_t /*hysteresisMs*/,
+                                                             const int32_t /*hysteresisDlKbps*/,
+                                                             const int32_t /*hysteresisUlKbps*/,
+                                                             const std::vector<int32_t>& /*thresholdsDownlinkKbps*/,
+                                                             const std::vector<int32_t>& /*thresholdsUplinkKbps*/,
+                                                             const AccessNetwork /*accessNetwork*/) {
+    NOT_NULL(mRadioNetworkResponse)->setLinkCapacityReportingCriteriaResponse(
+            makeRadioResponseInfoNOP(serial));
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setLocationUpdates(const int32_t serial,
+                                               const bool /*enable*/) {
+    NOT_NULL(mRadioNetworkResponse)->setLocationUpdatesResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setNetworkSelectionModeAutomatic(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        RadioError status = RadioError::NONE;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::setNetworkSelectionModeAutomatic,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->setNetworkSelectionModeAutomaticResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setNetworkSelectionModeManual(const int32_t serial,
+                                                          const std::string& operatorNumeric,
+                                                          const radio::AccessNetwork ran) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, operatorNumeric, ran]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        std::string request;
+        if (ran != radio::AccessNetwork::UNKNOWN) {
+            request = std::format("AT+COPS={0:d},{1:d},\"{2:s}\",{3:d}",
+                                  1, 2, operatorNumeric, static_cast<unsigned>(ran));
+        } else {
+            request = std::format("AT+COPS={0:d},{1:d},\"{2:s}\"",
+                                  1, 2, operatorNumeric);
+        }
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (response->isOK()) {
+            // good
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->setNetworkSelectionModeManualResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setNrDualConnectivityState(const int32_t serial,
+                                                       const network::NrDualConnectivityState nrSt) {
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mIsNrDualConnectivityEnabled =
+            (nrSt == network::NrDualConnectivityState::ENABLE);
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->setNrDualConnectivityStateResponse(
+            makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setSignalStrengthReportingCriteria(const int32_t serial,
+                                                               const std::vector<network::SignalThresholdInfo>& /*signalThresholdInfos*/) {
+    NOT_NULL(mRadioNetworkResponse)->setSignalStrengthReportingCriteriaResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setSuppServiceNotifications(const int32_t serial,
+                                                        const bool enable) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, enable]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        RadioError status = RadioError::NONE;
+
+        const int enableInt = enable ? 1 : 0;
+        const std::string request = std::format("AT+CSSN={0:d},{1:d}",
+            enableInt, enableInt);
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioNetworkResponse)->setSuppServiceNotificationsResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setSystemSelectionChannels(const int32_t serial,
+                                                       const bool /*specifyChannels*/,
+                                                       const std::vector<network::RadioAccessSpecifier>& /*specifiers*/) {
+    NOT_NULL(mRadioNetworkResponse)->setSystemSelectionChannelsResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::startNetworkScan(const int32_t serial,
+                                             const network::NetworkScanRequest& /*request*/) {
+    using network::NetworkScanResult;
+
+    NOT_NULL(mRadioNetworkResponse)->startNetworkScanResponse(
+        makeRadioResponseInfoNOP(serial));
+    if (mRadioNetworkIndication) {
+        using namespace std::chrono_literals;
+        std::this_thread::sleep_for(2000ms);
+
+        mRadioNetworkIndication->networkScanResult(
+            RadioIndicationType::UNSOLICITED,
+            { .status = NetworkScanResult::SCAN_STATUS_COMPLETE });
+    }
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::stopNetworkScan(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->stopNetworkScanResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::supplyNetworkDepersonalization(const int32_t serial,
+                                                           const std::string& /*netPin*/) {
+    NOT_NULL(mRadioNetworkResponse)->supplyNetworkDepersonalizationResponse(
+        makeRadioResponseInfoNOP(serial), -1);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setUsageSetting(const int32_t serial,
+                                            const network::UsageSetting /*usageSetting*/) {
+    NOT_NULL(mRadioNetworkResponse)->setUsageSettingResponse(
+            makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::getUsageSetting(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->getUsageSettingResponse(
+            makeRadioResponseInfo(serial),
+            network::UsageSetting::VOICE_CENTRIC);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setEmergencyMode(const int32_t serial,
+                                             const network::EmergencyMode /*emergencyMode*/) {
+    using network::Domain;
+    using network::EmergencyRegResult;
+    using network::RegState;
+
+    EmergencyRegResult emergencyRegResult = {
+        .accessNetwork = AccessNetwork::EUTRAN,
+        .regState = RegState::REG_HOME,
+        .emcDomain = static_cast<Domain>(
+            static_cast<uint32_t>(Domain::CS) |
+            static_cast<uint32_t>(Domain::PS)),
+    };
+
+    NOT_NULL(mRadioNetworkResponse)->setEmergencyModeResponse(
+        makeRadioResponseInfo(serial), std::move(emergencyRegResult));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::triggerEmergencyNetworkScan(const int32_t serial,
+                                                        const network::EmergencyNetworkScanTrigger& /*scanTrigger*/) {
+    NOT_NULL(mRadioNetworkResponse)->triggerEmergencyNetworkScanResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::cancelEmergencyNetworkScan(const int32_t serial,
+                                                       const bool /*resetScan*/) {
+    NOT_NULL(mRadioNetworkResponse)->cancelEmergencyNetworkScanResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::exitEmergencyMode(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->exitEmergencyModeResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::isN1ModeEnabled(const int32_t serial) {
+    bool enabled;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        enabled = mIsN1ModeEnabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->isN1ModeEnabledResponse(
+            makeRadioResponseInfo(serial), enabled);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setN1ModeEnabled(const int32_t serial,
+                                             const bool enable) {
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mIsN1ModeEnabled = enable;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->setN1ModeEnabledResponse(
+            makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setNullCipherAndIntegrityEnabled(const int32_t serial,
+                                                             const bool enabled) {
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mNullCipherAndIntegrityEnabled = enabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->setNullCipherAndIntegrityEnabledResponse(
+            makeRadioResponseInfo(serial, RadioError::NONE));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::isNullCipherAndIntegrityEnabled(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->isNullCipherAndIntegrityEnabledResponse(
+            makeRadioResponseInfo(serial), mNullCipherAndIntegrityEnabled);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::isCellularIdentifierTransparencyEnabled(const int32_t serial) {
+    bool enabled;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        enabled = mIsCellularIdentifierTransparencyEnabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->isCellularIdentifierTransparencyEnabledResponse(
+            makeRadioResponseInfo(serial), enabled);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setCellularIdentifierTransparencyEnabled(const int32_t serial,
+                                                                     const bool enabled) {
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mIsCellularIdentifierTransparencyEnabled = enabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->setCellularIdentifierTransparencyEnabledResponse(
+            makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::setSecurityAlgorithmsUpdatedEnabled(const int32_t serial,
+                                                                const bool enabled) {
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mSecurityAlgorithmsUpdatedEnabled = enabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->setSecurityAlgorithmsUpdatedEnabledResponse(
+            makeRadioResponseInfo(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::isSecurityAlgorithmsUpdatedEnabled(const int32_t serial) {
+    bool enabled;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        enabled = mSecurityAlgorithmsUpdatedEnabled;
+    }
+
+    NOT_NULL(mRadioNetworkResponse)->isSecurityAlgorithmsUpdatedEnabledResponse(
+            makeRadioResponseInfo(serial), enabled);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioNetwork::responseAcknowledgement() {
+    return ScopedAStatus::ok();
+}
+
+void RadioNetwork::atResponseSink(const AtResponsePtr& response) {
+    response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    mAtConversation.send(response);
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CFUN& cfun) {
+    bool changed;
+
+    std::lock_guard<std::mutex> lock(mMtx);
+    mRadioState = cfun.state;
+    if (cfun.state == modem::RadioState::OFF) {
+        changed = mCreg.state != network::RegState::NOT_REG_MT_NOT_SEARCHING_OP;
+        mCreg.state = network::RegState::NOT_REG_MT_NOT_SEARCHING_OP;
+        mCgreg.state = network::RegState::NOT_REG_MT_NOT_SEARCHING_OP;
+    }
+
+    if (changed && mRadioNetworkIndication) {
+        mRadioNetworkIndication->networkStateChanged(RadioIndicationType::UNSOLICITED);
+        mRadioNetworkIndication->imsNetworkStateChanged(RadioIndicationType::UNSOLICITED);
+    }
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CREG& creg) {
+    bool changed;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        changed = mCreg.state != creg.state;
+        mCreg = creg;
+    }
+
+    if (changed && mRadioNetworkIndication) {
+        mRadioNetworkIndication->networkStateChanged(RadioIndicationType::UNSOLICITED);
+        mRadioNetworkIndication->imsNetworkStateChanged(RadioIndicationType::UNSOLICITED);
+    }
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CGREG& cgreg) {
+    std::lock_guard<std::mutex> lock(mMtx);
+    mCgreg = cgreg;
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CSQ& csq) {
+    SignalStrength signalStrength;
+    std::vector<CellInfo> cellInfos;
+
+    bool poweredOn;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mCsq = csq;
+        poweredOn = (mRadioState == modem::RadioState::ON);
+
+        if (poweredOn) {
+            signalStrength = csq.toSignalStrength();
+
+            if (mCurrentOperator && mCurrentModemTech) {
+                RadioError status;
+                CellIdentity cellIdentity;
+                std::tie(status, cellIdentity) =
+                    getCellIdentityImpl(toOperatorInfo(mCurrentOperator.value()),
+                                        mCurrentModemTech.value(),
+                                        mCreg.areaCode, mCreg.cellId,
+                                        nullptr);
+                if (status == RadioError::NONE) {
+                    const bool registered =
+                        (mCreg.state == network::RegState::REG_HOME);
+
+                    CellInfo cellinfo;
+                    std::tie(status, cellinfo) =
+                        buildCellInfo(registered, std::move(cellIdentity),
+                                      signalStrength);
+                    if (status == RadioError::NONE) {
+                        cellInfos.push_back(std::move(cellinfo));
+                    }
+                }
+            }
+        }
+    }
+
+    if (poweredOn && mRadioNetworkIndication) {
+        mRadioNetworkIndication->currentSignalStrength(
+            RadioIndicationType::UNSOLICITED, std::move(signalStrength));
+
+        if (!cellInfos.empty()) {
+            mRadioNetworkIndication->cellInfoList(
+                RadioIndicationType::UNSOLICITED, std::move(cellInfos));
+        }
+    }
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::COPS& cops) {
+    using COPS = AtResponse::COPS;
+
+    if ((cops.operators.size() == 1) && (cops.operators[0].isCurrent())) {
+        const COPS::OperatorInfo& current = cops.operators[0];
+
+        std::lock_guard<std::mutex> lock(mMtx);
+        mCurrentOperator = current;
+    }
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CTEC& ctec) {
+    auto currentModemTech = ctec.getCurrentModemTechnology();
+    if (currentModemTech) {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mCurrentModemTech = std::move(currentModemTech.value());
+    }
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CGFPCCFG& cgfpccfg) {
+    using network::CellConnectionStatus;
+    using network::LinkCapacityEstimate;
+    using network::PhysicalChannelConfig;
+
+    bool registered;
+    int cellId;
+    int primaryBandwidth = 0;
+    int secondaryBandwidth = 0;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        registered = (mRadioState == modem::RadioState::ON) &&
+            (mCreg.state == network::RegState::REG_HOME);
+        cellId = mCreg.cellId;
+        if (cgfpccfg.status == CellConnectionStatus::PRIMARY_SERVING) {
+            mPrimaryBandwidth = cgfpccfg.bandwidth;
+        } else {
+            primaryBandwidth = mPrimaryBandwidth;
+            secondaryBandwidth = cgfpccfg.bandwidth;
+            mSecondaryBandwidth = cgfpccfg.bandwidth;
+        }
+    }
+
+    if (registered && mRadioNetworkIndication) {
+        {
+            PhysicalChannelConfig physicalChannelConfig = {
+                .status = cgfpccfg.status,
+                .rat = ratUtils::currentRadioTechnology(cgfpccfg.mtech),
+                .downlinkChannelNumber = 1,
+                .uplinkChannelNumber = 2,
+                .cellBandwidthDownlinkKhz = cgfpccfg.bandwidth,
+                .cellBandwidthUplinkKhz = cgfpccfg.bandwidth / 2,
+                .physicalCellId = cellId,
+                // .band - TODO
+            };
+
+            physicalChannelConfig.contextIds.push_back(cgfpccfg.contextId);
+
+            mRadioNetworkIndication->currentPhysicalChannelConfigs(
+                RadioIndicationType::UNSOLICITED,
+                { std::move(physicalChannelConfig) });
+        }
+
+        if (cgfpccfg.status == CellConnectionStatus::SECONDARY_SERVING) {
+            LinkCapacityEstimate lce = {
+                .downlinkCapacityKbps = primaryBandwidth * 3,
+                .uplinkCapacityKbps = primaryBandwidth,
+                .secondaryDownlinkCapacityKbps = secondaryBandwidth * 3,
+                .secondaryUplinkCapacityKbps = secondaryBandwidth,
+            };
+
+            mRadioNetworkIndication->currentLinkCapacityEstimate(
+                RadioIndicationType::UNSOLICITED, std::move(lce));
+        }
+    }
+}
+
+void RadioNetwork::handleUnsolicited(const AtResponse::CTZV& ctzv) {
+    const int64_t now = ::android::elapsedRealtime();
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mCtzv = ctzv;
+        mCtzvTimestamp = now;
+    }
+
+    if (mRadioNetworkIndication) {
+        mRadioNetworkIndication->nitzTimeReceived(
+            RadioIndicationType::UNSOLICITED, ctzv.nitzString(), now, 0);
+    }
+}
+
+ScopedAStatus RadioNetwork::setResponseFunctions(
+        const std::shared_ptr<network::IRadioNetworkResponse>& radioNetworkResponse,
+        const std::shared_ptr<network::IRadioNetworkIndication>& radioNetworkIndication) {
+    mRadioNetworkResponse = NOT_NULL(radioNetworkResponse);
+    mRadioNetworkIndication = NOT_NULL(radioNetworkIndication);
+
+    AtResponse::CSQ csq;
+    std::string nitz;
+    int64_t nitzTs;
+    bool poweredOn;
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        csq = mCsq;
+        nitz = mCtzv.nitzString();
+        nitzTs = mCtzvTimestamp;
+        poweredOn = (mRadioState == modem::RadioState::ON);
+    }
+
+    if (poweredOn) {
+        radioNetworkIndication->networkStateChanged(RadioIndicationType::UNSOLICITED);
+
+        radioNetworkIndication->currentSignalStrength(
+            RadioIndicationType::UNSOLICITED, csq.toSignalStrength());
+
+        radioNetworkIndication->nitzTimeReceived(
+            RadioIndicationType::UNSOLICITED, std::move(nitz), nitzTs, 0);
+    }
+
+    return ScopedAStatus::ok();
+}
+
+/************************* deprecated *************************/
+ScopedAStatus RadioNetwork::getImsRegistrationState(const int32_t serial) {
+    NOT_NULL(mRadioNetworkResponse)->getImsRegistrationStateResponse(
+        makeRadioResponseInfoDeprecated(serial), {}, {});
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioNetwork.h b/hals/radio/RadioNetwork.h
new file mode 100644
index 00000000..2623b192
--- /dev/null
+++ b/hals/radio/RadioNetwork.h
@@ -0,0 +1,144 @@
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
+#include <memory>
+#include <mutex>
+
+#include <aidl/android/hardware/radio/network/BnRadioNetwork.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioNetwork : public network::BnRadioNetwork {
+    RadioNetwork(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus getAllowedNetworkTypesBitmap(int32_t serial) override;
+    ScopedAStatus getAvailableBandModes(int32_t serial) override;
+    ScopedAStatus getAvailableNetworks(int32_t serial) override;
+    ScopedAStatus getBarringInfo(int32_t serial) override;
+    ScopedAStatus getCdmaRoamingPreference(int32_t serial) override;
+    ScopedAStatus getCellInfoList(int32_t serial) override;
+    ScopedAStatus getDataRegistrationState(int32_t serial) override;
+    ScopedAStatus getImsRegistrationState(int32_t serial) override;
+    ScopedAStatus getNetworkSelectionMode(int32_t serial) override;
+    ScopedAStatus getOperator(int32_t serial) override;
+    ScopedAStatus getSignalStrength(int32_t serial) override;
+    ScopedAStatus getSystemSelectionChannels(int32_t serial) override;
+    ScopedAStatus getVoiceRadioTechnology(int32_t serial) override;
+    ScopedAStatus getVoiceRegistrationState(int32_t serial) override;
+    ScopedAStatus isNrDualConnectivityEnabled(int32_t serial) override;
+    ScopedAStatus setAllowedNetworkTypesBitmap(int32_t serial,
+                                               int32_t networkTypeBitmap) override;
+    ScopedAStatus setBandMode(
+            int32_t serial, network::RadioBandMode mode) override;
+    ScopedAStatus setBarringPassword(int32_t serial, const std::string& facility,
+                                     const std::string& oldPassword,
+                                     const std::string& newPassword) override;
+    ScopedAStatus setCdmaRoamingPreference(
+            int32_t serial, network::CdmaRoamingType type) override;
+    ScopedAStatus setCellInfoListRate(int32_t serial, int32_t rate) override;
+    ScopedAStatus setIndicationFilter(int32_t serial, int32_t indicationFilter) override;
+    ScopedAStatus setLinkCapacityReportingCriteria(
+            int32_t serial, int32_t hysteresisMs, int32_t hysteresisDlKbps,
+            int32_t hysteresisUlKbps, const std::vector<int32_t>& thresholdsDownlinkKbps,
+            const std::vector<int32_t>& thresholdsUplinkKbps, AccessNetwork accessNetwork) override;
+    ScopedAStatus setLocationUpdates(int32_t serial, bool enable) override;
+    ScopedAStatus setNetworkSelectionModeAutomatic(int32_t serial) override;
+    ScopedAStatus setNetworkSelectionModeManual(
+            int32_t serial, const std::string& operatorNumeric, AccessNetwork ran) override;
+    ScopedAStatus setNrDualConnectivityState(
+            int32_t serial, network::NrDualConnectivityState nrSt) override;
+    ScopedAStatus setSignalStrengthReportingCriteria(
+            int32_t serial, const std::vector<network::SignalThresholdInfo>&
+                    signalThresholdInfos) override;
+    ScopedAStatus setSuppServiceNotifications(int32_t serial, bool enable) override;
+    ScopedAStatus setSystemSelectionChannels(
+            int32_t serial, bool specifyChannels,
+            const std::vector<network::RadioAccessSpecifier>& specifiers) override;
+    ScopedAStatus startNetworkScan(
+            int32_t serial, const network::NetworkScanRequest& request) override;
+    ScopedAStatus stopNetworkScan(int32_t serial) override;
+    ScopedAStatus supplyNetworkDepersonalization(int32_t serial, const std::string& netPin) override;
+    ScopedAStatus setUsageSetting(
+            int32_t serial, network::UsageSetting usageSetting) override;
+    ScopedAStatus getUsageSetting(int32_t serial) override;
+    ScopedAStatus setEmergencyMode(
+            int32_t serial, network::EmergencyMode emergencyMode) override;
+    ScopedAStatus triggerEmergencyNetworkScan(
+            int32_t serial, const network::EmergencyNetworkScanTrigger& scanTrigger) override;
+    ScopedAStatus cancelEmergencyNetworkScan(int32_t serial, bool resetScan) override;
+    ScopedAStatus exitEmergencyMode(int32_t serial) override;
+    ScopedAStatus isN1ModeEnabled(int32_t serial) override;
+    ScopedAStatus setN1ModeEnabled(int32_t serial, bool enable) override;
+    ScopedAStatus setNullCipherAndIntegrityEnabled(int32_t serial, bool enabled) override;
+    ScopedAStatus isNullCipherAndIntegrityEnabled(int32_t serial) override;
+    ScopedAStatus isCellularIdentifierTransparencyEnabled(int32_t serial) override;
+    ScopedAStatus setCellularIdentifierTransparencyEnabled(int32_t serial,
+                                                           bool enabled) override;
+    ScopedAStatus setSecurityAlgorithmsUpdatedEnabled(int32_t serial, bool enabled) override;
+    ScopedAStatus isSecurityAlgorithmsUpdatedEnabled(int32_t serial) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    void handleUnsolicited(const AtResponse::CFUN&);
+    void handleUnsolicited(const AtResponse::CREG&);
+    void handleUnsolicited(const AtResponse::CGREG&);
+    void handleUnsolicited(const AtResponse::CSQ&);
+    void handleUnsolicited(const AtResponse::COPS&);
+    void handleUnsolicited(const AtResponse::CTEC&);
+    void handleUnsolicited(const AtResponse::CGFPCCFG&);
+    void handleUnsolicited(const AtResponse::CTZV&);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus responseAcknowledgement() override;
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<network::IRadioNetworkResponse>& radioNetworkResponse,
+            const std::shared_ptr<network::IRadioNetworkIndication>& radioNetworkIndication) override;
+
+private:
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+    std::shared_ptr<network::IRadioNetworkResponse> mRadioNetworkResponse;
+    std::shared_ptr<network::IRadioNetworkIndication> mRadioNetworkIndication;
+
+    std::mutex          mMtx;
+    AtResponse::CREG    mCreg;
+    AtResponse::CGREG   mCgreg;
+    AtResponse::CSQ     mCsq;
+    std::optional<AtResponse::COPS::OperatorInfo> mCurrentOperator;
+    std::optional<ratUtils::ModemTechnology> mCurrentModemTech;
+    AtResponse::CTZV    mCtzv;
+    int64_t             mCtzvTimestamp;
+    modem::RadioState   mRadioState = modem::RadioState::OFF;
+    int                 mPrimaryBandwidth = 0;
+    int                 mSecondaryBandwidth = 0;
+    bool                mNullCipherAndIntegrityEnabled = false;
+    bool                mIsCellularIdentifierTransparencyEnabled = false;
+    bool                mSecurityAlgorithmsUpdatedEnabled = false;
+    bool                mIsNrDualConnectivityEnabled = true;
+    bool                mIsN1ModeEnabled = false;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioSim.cpp b/hals/radio/RadioSim.cpp
new file mode 100644
index 00000000..af0b6d67
--- /dev/null
+++ b/hals/radio/RadioSim.cpp
@@ -0,0 +1,1609 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioSim"
+
+#include <charconv>
+#include <format>
+#include <tuple>
+#include <vector>
+
+#include "RadioSim.h"
+
+#include "atCmds.h"
+#include "debug.h"
+#include "hexbin.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace {
+using namespace std::literals;
+
+enum class AuthContext {
+    SIM = 128,
+    AKA = 129,
+};
+
+enum class StkCmdType {
+    RUN_AT        = 0x34,
+    SEND_DTMF     = 0x14,
+    SEND_SMS      = 0x13,
+    SEND_SS       = 0x11,
+    SEND_USSD     = 0x12,
+    PLAY_TONE     = 0x20,
+    OPEN_CHANNEL  = 0x40,
+    CLOSE_CHANNEL = 0x41,
+    RECEIVE_DATA  = 0x42,
+    SEND_DATA     = 0x43,
+    GET_CHANNEL_STATUS = 0x44,
+    REFRESH       = 0x01,
+};
+
+#define USIM_DATA_OFFSET_2                      2
+#define USIM_DATA_OFFSET_3                      3
+#define USIM_RESPONSE_DATA_FILE_RECORD_LEN_1         6
+#define USIM_RESPONSE_DATA_FILE_RECORD_LEN_2         7
+#define USIM_TYPE_FILE_DES_LEN                       5
+
+#define USIM_RESPONSE_DATA_FILE_DES_FLAG             2
+#define USIM_RESPONSE_DATA_FILE_DES_LEN_FLAG         3
+
+#define USIM_FILE_DES_TAG                       0x82
+#define USIM_FILE_SIZE_TAG                      0x80
+
+
+#define SIM_RESPONSE_EF_SIZE                        15
+#define SIM_RESPONSE_DATA_FILE_SIZE_1               2
+#define SIM_RESPONSE_DATA_FILE_SIZE_2               3
+#define SIM_RESPONSE_DATA_FILE_TYPE                 6
+#define SIM_RESPONSE_DATA_STRUCTURE                 13
+#define SIM_RESPONSE_DATA_RECORD_LENGTH             14
+#define SIM_TYPE_EF                                 4
+
+enum class UsimEfType {
+    TRANSPARENT = 1,
+    LINEAR_FIXED = 2,
+    CYCLIC = 6,
+};
+
+// 62 17 82 02 41 2183022FE28A01058B032F06038002000A880110
+bool convertUsimToSim(const std::vector<uint8_t>& bytesUSIM, std::string* hexSIM) {
+    const size_t sz = bytesUSIM.size();
+    size_t i = 0;
+
+    size_t desIndex;
+    while (true) {
+        if (bytesUSIM[i] == USIM_FILE_DES_TAG) {
+            desIndex = i;
+            break;
+        } else {
+            ++i;
+            if (i >= sz) {
+                return false;
+            }
+        }
+    }
+
+    size_t sizeIndex;
+    while (true) {
+        if (bytesUSIM[i] == USIM_FILE_SIZE_TAG) {
+            sizeIndex = i;
+            break;
+        } else {
+            i += bytesUSIM[i + 1] + 2;
+            if (i >= sz) {
+                return FAILURE(false);
+            }
+        }
+    }
+
+    uint8_t bytesSIM[SIM_RESPONSE_EF_SIZE] = {0};
+    switch (static_cast<UsimEfType>(bytesUSIM[desIndex + USIM_RESPONSE_DATA_FILE_DES_FLAG] & 0x07)) {
+    case UsimEfType::TRANSPARENT:
+        bytesSIM[SIM_RESPONSE_DATA_STRUCTURE] = 0;
+        break;
+
+    case UsimEfType::LINEAR_FIXED:
+        if (USIM_FILE_DES_TAG != bytesUSIM[USIM_RESPONSE_DATA_FILE_DES_FLAG]) {
+            return FAILURE(false);
+        }
+        if (USIM_TYPE_FILE_DES_LEN != bytesUSIM[USIM_RESPONSE_DATA_FILE_DES_LEN_FLAG]) {
+            return FAILURE(false);
+        }
+
+        bytesSIM[SIM_RESPONSE_DATA_STRUCTURE] = 1;
+        bytesSIM[SIM_RESPONSE_DATA_RECORD_LENGTH] =
+                //(byteUSIM[USIM_RESPONSE_DATA_FILE_RECORD_LEN_1] << 8) +
+                bytesUSIM[USIM_RESPONSE_DATA_FILE_RECORD_LEN_2];
+        break;
+
+    case UsimEfType::CYCLIC:
+        bytesSIM[SIM_RESPONSE_DATA_STRUCTURE] = 3;
+        bytesSIM[SIM_RESPONSE_DATA_RECORD_LENGTH] =
+                //(byteUSIM[USIM_RESPONSE_DATA_FILE_RECORD_LEN_1] << 8) +
+                bytesUSIM[USIM_RESPONSE_DATA_FILE_RECORD_LEN_2];
+        break;
+
+    default:
+        return false;
+    }
+
+    bytesSIM[SIM_RESPONSE_DATA_FILE_TYPE] = SIM_TYPE_EF;
+    bytesSIM[SIM_RESPONSE_DATA_FILE_SIZE_1] =
+            bytesUSIM[sizeIndex + USIM_DATA_OFFSET_2];
+    bytesSIM[SIM_RESPONSE_DATA_FILE_SIZE_2] =
+            bytesUSIM[sizeIndex + USIM_DATA_OFFSET_3];
+
+    *hexSIM = bin2hex(bytesSIM, sizeof(bytesSIM));
+    return true;
+}
+
+std::optional<int> getRemainingRetries(const std::string_view pinType,
+                                       const AtChannel::RequestPipe requestPipe,
+                                       AtChannel::Conversation& atConversation) {
+    using CPINR = AtResponse::CPINR;
+
+    AtResponsePtr response =
+        atConversation(requestPipe, std::format("AT+CPINR=\"{0:s}\"", pinType),
+                       [](const AtResponse& response) -> bool {
+                          return response.holds<CPINR>();
+                       });
+    if (!response || response->isParseError()) {
+        return FAILURE(std::nullopt);
+    } else if (const CPINR* cpinr = response->get_if<CPINR>()) {
+        return cpinr->remainingRetryTimes;
+    } else {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+}
+
+std::pair<RadioError, int> enterOrChangeSimPinPuk(const bool change,
+                                                  const std::string_view oldPin,
+                                                  const std::string_view newPin,
+                                                  const std::string_view pinType,
+                                                  const AtChannel::RequestPipe requestPipe,
+                                                  AtChannel::Conversation& atConversation) {
+    using CmeError = AtResponse::CmeError;
+
+    std::string request;
+    if (change) {
+        if (pinType.compare("SIM PIN2"sv) == 0) {
+            request = std::format("AT+CPWD=\"{0:s}\",\"{1:s}\",\"{2:s}\"",
+                                  "P2"sv, oldPin, newPin);
+        } else {
+            request = std::format("AT+CPIN={0:s},{1:s}", oldPin, newPin);
+        }
+    } else {
+        request = std::format("AT+CPIN={0:s}", oldPin);
+    }
+
+    AtResponsePtr response =
+        atConversation(requestPipe, request,
+                       [](const AtResponse& response) -> bool {
+                          return response.holds<CmeError>() || response.isOK();
+                       });
+    if (!response || response->isParseError()) {
+        return {FAILURE(RadioError::INTERNAL_ERR), 0};
+    } else if (response->isOK()) {
+        return {RadioError::NONE, 0};
+    } else if (!response->get_if<CmeError>()) {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+
+    const std::optional<int> maybeRetries =
+        getRemainingRetries(pinType, requestPipe, atConversation);
+    if (maybeRetries) {
+        return {RadioError::PASSWORD_INCORRECT, maybeRetries.value()};
+    } else {
+        return {FAILURE(RadioError::INTERNAL_ERR), 0};
+    }
+}
+
+// authData64 = base64([randLen][...rand...][authLen][...auth...])
+std::tuple<RadioError, std::vector<uint8_t>, std::vector<uint8_t>>
+parseAuthData(const AuthContext authContext, const std::string_view authData64) {
+    auto maybeAuthData = base64decode(authData64.data(), authData64.size());
+    if (!maybeAuthData) {
+        return {FAILURE(RadioError::INVALID_ARGUMENTS), {}, {}};
+    }
+
+    const std::vector<uint8_t> authData = std::move(maybeAuthData.value());
+    const size_t authDataSize = authData.size();
+    if (authDataSize == 0) {
+        return {FAILURE(RadioError::INVALID_ARGUMENTS), {}, {}};
+    }
+
+    const size_t randLen = authData[0];
+    if (authDataSize < (1U + randLen)) {
+        return {FAILURE(RadioError::INVALID_ARGUMENTS), {}, {}};
+    }
+
+    std::vector rand(&authData[1], &authData[1U + randLen]);
+    if (authContext == AuthContext::SIM) {
+        return {RadioError::NONE, std::move(rand), {}};
+    }
+
+    const size_t authLen = authData[1U + randLen];
+    if (authDataSize < (1U + randLen + 1U + authLen)) {
+        return {FAILURE(RadioError::INVALID_ARGUMENTS), {}, {}};
+    }
+
+    std::vector auth(&authData[1U + randLen + 1U],
+                     &authData[1U + randLen + 1U + authLen]);
+    if (authContext == AuthContext::AKA) {
+        return {RadioError::NONE, std::move(rand), std::move(auth)};
+    }
+
+    return {FAILURE(RadioError::REQUEST_NOT_SUPPORTED), {}, {}};
+}
+
+std::optional<std::vector<uint8_t>> getSelectResponse(const AtChannel::RequestPipe requestPipe,
+                                                      AtChannel::Conversation& atConversation,
+                                                      const int channel, const int p2) {
+    using CGLA = AtResponse::CGLA;
+    using CmeError = AtResponse::CmeError;
+
+    const std::string request =
+        std::format("AT+CGLA={0:d},14,00A400{1:02X}023F00", channel, p2);
+    AtResponsePtr response =
+        atConversation(requestPipe, request,
+                       [](const AtResponse& response) -> bool {
+                          return response.holds<CGLA>() || response.holds<CmeError>();
+                       });
+    if (!response || response->isParseError()) {
+        return FAILURE(std::nullopt);
+    } else if (const CGLA* cgla = response->get_if<CGLA>()) {
+        if (cgla->response.size() < 4) {
+            return FAILURE(std::nullopt);
+        }
+
+        int sw12;
+        const size_t size4 = cgla->response.size() - 4;
+        if (1 != ::sscanf(&cgla->response[size4], "%04x", &sw12)) {
+            return FAILURE(std::nullopt);
+        }
+
+        if (sw12 != 0x9000) {
+            return FAILURE(std::nullopt);
+        }
+
+        std::vector<uint8_t> selectResponse;
+        if (!hex2bin(cgla->response, &selectResponse)) {
+            return FAILURE(std::nullopt);
+        }
+
+        return selectResponse;
+    } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+        cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, __func__, __LINE__);
+        return FAILURE(std::nullopt);
+    } else {
+        response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+    }
+}
+
+}  // namespace
+
+RadioSim::RadioSim(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioSim::areUiccApplicationsEnabled(const int32_t serial) {
+    using modem::RadioState;
+
+    RadioState radioState;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        radioState = mRadioState;
+    }
+
+    const RadioError status = (radioState == RadioState::ON) ?
+        RadioError::NONE : RadioError::RADIO_NOT_AVAILABLE;
+
+    NOT_NULL(mRadioSimResponse)->areUiccApplicationsEnabledResponse(
+            makeRadioResponseInfo(serial, status), mUiccApplicationsEnabled);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::changeIccPin2ForApp(int32_t serial,
+                                            const std::string& oldPin2,
+                                            const std::string& newPin2,
+                                            const std::string& /*aid*/) {
+    mAtChannel->queueRequester([this, serial, oldPin2, newPin2]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        const auto [status, remainingRetries] =
+            enterOrChangeSimPinPuk(true, oldPin2, newPin2, "SIM PIN2"sv,
+                                   requestPipe, mAtConversation);
+
+        NOT_NULL(mRadioSimResponse)->supplyIccPin2ForAppResponse(
+                makeRadioResponseInfo(serial, status), remainingRetries);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::changeIccPinForApp(const int32_t serial,
+                                           const std::string& oldPin,
+                                           const std::string& newPin,
+                                           const std::string& /*aid*/) {
+    mAtChannel->queueRequester([this, serial, oldPin, newPin]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        const auto [status, remainingRetries] =
+            enterOrChangeSimPinPuk(true, oldPin, newPin, "SIM PIN"sv,
+                                   requestPipe, mAtConversation);
+
+        NOT_NULL(mRadioSimResponse)->changeIccPinForAppResponse(
+                makeRadioResponseInfo(serial, status), remainingRetries);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::enableUiccApplications(const int32_t serial, const bool enable) {
+    bool changed;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        changed = mUiccApplicationsEnabled != enable;
+        mUiccApplicationsEnabled = enable;
+    }
+
+    NOT_NULL(mRadioSimResponse)->enableUiccApplicationsResponse(
+            makeRadioResponseInfo(serial));
+
+    if (changed && mRadioSimIndication) {
+        mRadioSimIndication->uiccApplicationsEnablementChanged(
+                RadioIndicationType::UNSOLICITED, enable);
+    }
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getAllowedCarriers(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using sim::CarrierInfo;
+        using sim::CarrierRestrictions;
+        using sim::SimLockMultiSimPolicy;
+        using CmeError = AtResponse::CmeError;
+        using COPS = AtResponse::COPS;
+
+        RadioError status = RadioError::NONE;
+        CarrierRestrictions carrierRestrictions = {
+            .allowedCarriersPrioritized = true,
+        };
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getOperator,
+                            [](const AtResponse& response) -> bool {
+                                return response.holds<COPS>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const COPS* cops = response->get_if<COPS>()) {
+            if ((cops->operators.size() == 1) && (cops->operators[0].isCurrent())) {
+                const COPS::OperatorInfo& current = cops->operators[0];
+                CarrierInfo ci = {
+                    .mcc = current.mcc(),
+                    .mnc = current.mnc(),
+                };
+
+                carrierRestrictions.allowedCarrierInfoList.push_back(std::move(ci));
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, __func__);
+        }
+
+        NOT_NULL(mRadioSimResponse)->getAllowedCarriersResponse(
+            makeRadioResponseInfo(serial, status),
+            std::move(carrierRestrictions),
+            SimLockMultiSimPolicy::NO_MULTISIM_POLICY);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getCdmaSubscription(const int32_t serial) {
+    NOT_NULL(mRadioSimResponse)->getCdmaSubscriptionResponse(
+        makeRadioResponseInfo(serial),
+        "8587777777",   // mdn
+        "1",            // sid
+        "1",            // nid
+        "8587777777",   // min
+        "1");           // prl
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getCdmaSubscriptionSource(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CCSS = AtResponse::CCSS;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getCdmaSubscriptionSource,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CCSS>();
+                            });
+        if (!response || response->isParseError()) {
+            NOT_NULL(mRadioSimResponse)->getCdmaSubscriptionSourceResponse(
+                    makeRadioResponseInfo(serial, RadioError::INTERNAL_ERR), {});
+            return false;
+        } else if (const CCSS* csss = response->get_if<CCSS>()) {
+            NOT_NULL(mRadioSimResponse)->getCdmaSubscriptionSourceResponse(
+                    makeRadioResponseInfo(serial), csss->source);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getFacilityLockForApp(const int32_t serial, const std::string& facility,
+                                              const std::string& password, const int32_t serviceClass,
+                                              const std::string& /*appId*/) {
+    std::string request = std::format("AT+CLCK=\"{0:s}\",{1:d},\"{2:s}\",{3:d}",
+                                      facility, atCmds::kClckQuery, password, serviceClass);
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, request = std::move(request)]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        using CLCK = AtResponse::CLCK;
+
+        RadioError status = RadioError::NONE;
+        int lockBitmask = 0;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CLCK>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CLCK* clck = response->get_if<CLCK>()) {
+            lockBitmask = clck->locked ? 7 : 0;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->getFacilityLockForAppResponse(
+                makeRadioResponseInfo(serial, status), lockBitmask);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getIccCardStatus(const int32_t serial) {
+    using sim::AppStatus;
+    using sim::PersoSubstate;
+    using sim::PinState;
+
+    struct AppStatus3 {
+        AppStatus usim;
+        AppStatus ruim;
+        AppStatus isim;
+    };
+
+    static const std::string kAidPtr = ""; //"A0000000871002FF86FF0389FFFFFFFF";
+    static const std::string kAppLabelPtr = "";
+
+    static const std::string kATR = ""; //"3BF000818000";
+    // This data is mandatory and applicable only when cardState is
+    // STATE_PRESENT and SIM card supports eUICC.
+    static const std::string kEID = "";
+
+    static const AppStatus3 kIccStatusReady = {
+        .usim = {
+            AppStatus::APP_TYPE_USIM, AppStatus::APP_STATE_READY, PersoSubstate::READY,
+            kAidPtr, kAppLabelPtr, false, PinState::UNKNOWN, PinState::UNKNOWN
+        },
+        .ruim = {
+            AppStatus::APP_TYPE_RUIM, AppStatus::APP_STATE_READY, PersoSubstate::READY,
+            kAidPtr, kAppLabelPtr, false, PinState::UNKNOWN, PinState::UNKNOWN
+        },
+        .isim = {
+            AppStatus::APP_TYPE_ISIM, AppStatus::APP_STATE_READY, PersoSubstate::READY,
+            kAidPtr, kAppLabelPtr, false, PinState::UNKNOWN, PinState::UNKNOWN
+        }
+    };
+
+    static const AppStatus3 kIccStatusPIN = {
+        .usim = {
+            AppStatus::APP_TYPE_USIM, AppStatus::APP_STATE_PIN, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::ENABLED_NOT_VERIFIED, PinState::ENABLED_NOT_VERIFIED
+        },
+        .ruim = {
+            AppStatus::APP_TYPE_RUIM, AppStatus::APP_STATE_PIN, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::ENABLED_NOT_VERIFIED, PinState::ENABLED_NOT_VERIFIED
+        },
+        .isim = {
+            AppStatus::APP_TYPE_ISIM, AppStatus::APP_STATE_PIN, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::ENABLED_NOT_VERIFIED, PinState::ENABLED_NOT_VERIFIED
+        }
+    };
+
+    static const AppStatus3 kIccStatusPUK = {
+        .usim = {
+            AppStatus::APP_TYPE_USIM, AppStatus::APP_STATE_PUK, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::ENABLED_NOT_VERIFIED, PinState::ENABLED_NOT_VERIFIED
+        },
+        .ruim = {
+            AppStatus::APP_TYPE_RUIM, AppStatus::APP_STATE_PUK, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::ENABLED_NOT_VERIFIED, PinState::ENABLED_NOT_VERIFIED
+        },
+        .isim = {
+            AppStatus::APP_TYPE_ISIM, AppStatus::APP_STATE_PUK, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::ENABLED_NOT_VERIFIED, PinState::ENABLED_NOT_VERIFIED
+        }
+    };
+
+    static const AppStatus3 kIccStatusBUSY = {
+        .usim = {
+            AppStatus::APP_TYPE_USIM, AppStatus::APP_STATE_DETECTED, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::UNKNOWN, PinState::UNKNOWN
+        },
+        .ruim = {
+            AppStatus::APP_TYPE_RUIM, AppStatus::APP_STATE_DETECTED, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::UNKNOWN, PinState::UNKNOWN
+        },
+        .isim = {
+            AppStatus::APP_TYPE_ISIM, AppStatus::APP_STATE_DETECTED, PersoSubstate::UNKNOWN,
+            kAidPtr, kAppLabelPtr, false, PinState::UNKNOWN, PinState::UNKNOWN
+        }
+    };
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using sim::CardStatus;
+        using CmeError = AtResponse::CmeError;
+        using CPIN = AtResponse::CPIN;
+
+        RadioError status = RadioError::NONE;
+        CardStatus cardStatus = {
+            .slotMap = {
+                .physicalSlotId = -1,  // see ril_service.cpp in CF
+                .portId = 0,
+            }
+        };
+
+        const AppStatus3* appStatus = nullptr;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getSimCardStatus,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CPIN>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+            goto failed;
+        } else if (const CPIN* cpin = response->get_if<CPIN>()) {
+            switch (cpin->state) {
+            case CPIN::State::READY:
+                cardStatus.cardState = sim::CardStatus::STATE_PRESENT;
+                cardStatus.universalPinState = sim::PinState::UNKNOWN;
+                appStatus = &kIccStatusReady;
+                break;
+
+            case CPIN::State::PIN:
+                cardStatus.cardState = sim::CardStatus::STATE_RESTRICTED;
+                cardStatus.universalPinState = sim::PinState::ENABLED_NOT_VERIFIED;
+                appStatus = &kIccStatusPIN;
+                break;
+
+            case CPIN::State::PUK:
+                cardStatus.cardState = sim::CardStatus::STATE_RESTRICTED;
+                cardStatus.universalPinState = sim::PinState::ENABLED_NOT_VERIFIED;
+                appStatus = &kIccStatusPUK;
+                break;
+
+            default:
+                status = FAILURE(RadioError::INTERNAL_ERR);
+                goto failed;
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            switch (cmeError->error) {
+            case RadioError::SIM_ABSENT:
+                cardStatus.cardState = sim::CardStatus::STATE_ABSENT;
+                cardStatus.universalPinState = sim::PinState::UNKNOWN;
+                break;
+
+            case RadioError::SIM_BUSY:
+            case RadioError::SIM_ERR:
+                cardStatus.cardState = sim::CardStatus::STATE_ERROR;
+                cardStatus.universalPinState = sim::PinState::UNKNOWN;
+                appStatus = &kIccStatusBUSY;
+                break;
+
+            default:
+                status = cmeError->getErrorAndLog(
+                    FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+                goto failed;
+            }
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (cardStatus.cardState != sim::CardStatus::STATE_ABSENT) {
+            response =
+                mAtConversation(requestPipe, atCmds::getICCID,
+                                [](const AtResponse& response) -> bool {
+                                   return response.holds<std::string>();
+                                });
+            if (!response || response->isParseError()) {
+                status = FAILURE(RadioError::INTERNAL_ERR);
+                goto failed;
+            } else if (const std::string* iccid = response->get_if<std::string>()) {
+                cardStatus.iccid = *iccid;
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+
+            cardStatus.applications.push_back(appStatus->usim);
+            cardStatus.applications.push_back(appStatus->ruim);
+            cardStatus.applications.push_back(appStatus->isim);
+            cardStatus.gsmUmtsSubscriptionAppIndex = 0; // usim
+            cardStatus.cdmaSubscriptionAppIndex = 1;    // ruim
+            cardStatus.imsSubscriptionAppIndex = 2;     // isim
+
+            cardStatus.atr = kATR;
+            cardStatus.eid = kEID;
+        }
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioSimResponse)->getIccCardStatusResponse(
+                    makeRadioResponseInfo(serial), std::move(cardStatus));
+            return true;
+        } else {
+failed:     NOT_NULL(mRadioSimResponse)->getIccCardStatusResponse(
+                    makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getImsiForApp(const int32_t serial, const std::string& /*aid*/) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        std::string imsi;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getIMSI,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<std::string>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const std::string* pImsi = response->get_if<std::string>()) {
+            imsi = *pImsi;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioSimResponse)->getImsiForAppResponse(
+                    makeRadioResponseInfo(serial), std::move(imsi));
+            return true;
+        } else {
+            NOT_NULL(mRadioSimResponse)->getImsiForAppResponse(
+                    makeRadioResponseInfo(serial, FAILURE(status)), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getSimPhonebookCapacity(const int32_t serial) {
+    NOT_NULL(mRadioSimResponse)->getSimPhonebookCapacityResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::getSimPhonebookRecords(const int32_t serial) {
+    NOT_NULL(mRadioSimResponse)->getSimPhonebookRecordsResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::iccCloseLogicalChannelWithSessionInfo(const int32_t serial,
+                                                              const sim::SessionInfo& recordInfo) {
+    const int32_t sessionId = recordInfo.sessionId;
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, sessionId](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CCHC = AtResponse::CCHC;
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        const std::string request = std::format("AT+CCHC={0:d}", sessionId);
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CCHC>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+            if (status == RadioError::NO_SUCH_ELEMENT) {
+                status = RadioError::INVALID_ARGUMENTS;
+            }
+        } else if (!response->get_if<CCHC>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->iccCloseLogicalChannelWithSessionInfoResponse(
+                makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::iccIoForApp(const int32_t serial, const sim::IccIo& iccIo) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, iccIo]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CRSM = AtResponse::CRSM;
+        using CmeError = AtResponse::CmeError;
+        using sim::IccIoResult;
+
+        RadioError status = RadioError::NONE;
+        IccIoResult iccIoResult;
+
+        std::string request;
+        if (iccIo.data.empty()) {
+            request = std::format("AT+CRSM={0:d},{1:d},{2:d},{3:d},{4:d}",
+                    iccIo.command, iccIo.fileId, iccIo.p1, iccIo.p2, iccIo.p3);
+        } else {
+            request = std::format("AT+CRSM={0:d},{1:d},{2:d},{3:d},{4:d},{5:s},{6:s}",
+                    iccIo.command, iccIo.fileId, iccIo.p1, iccIo.p2, iccIo.p3,
+                    iccIo.data, iccIo.aid);
+        }
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CRSM>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CRSM* crsm = response->get_if<CRSM>()) {
+            iccIoResult.sw1 = crsm->sw1;
+            iccIoResult.sw2 = crsm->sw2;
+
+            if (iccIo.command == 192) {  // get
+                std::vector<uint8_t> bytes;
+                if (hex2bin(crsm->response, &bytes) && !bytes.empty() && (bytes.front() == 0x62)) {
+                    if (!convertUsimToSim(bytes, &iccIoResult.simResponse)) {
+                        status = FAILURE(RadioError::GENERIC_FAILURE);
+                    }
+                } else {
+                    iccIoResult.simResponse = crsm->response;
+                }
+            } else {
+                iccIoResult.simResponse = crsm->response;
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioSimResponse)->iccIoForAppResponse(
+                    makeRadioResponseInfo(serial), std::move(iccIoResult));
+            return true;
+        } else {
+            NOT_NULL(mRadioSimResponse)->iccIoForAppResponse(
+                    makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::iccOpenLogicalChannel(const int32_t serial,
+                                              const std::string& aid,
+                                              const int32_t p2) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, aid, p2](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CSIM = AtResponse::CSIM;
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        int channelId = 0;
+        std::vector<uint8_t> selectResponse;
+
+        if (aid.empty()) {
+            AtResponsePtr response =
+                mAtConversation(requestPipe, "AT+CSIM=10,\"0070000001\""sv,
+                                [](const AtResponse& response) -> bool {
+                                   return response.holds<CSIM>() || response.holds<CmeError>();
+                                });
+            if (!response || response->isParseError()) {
+                status = FAILURE(RadioError::INTERNAL_ERR);
+            } else if (const CSIM* csim = response->get_if<CSIM>()) {
+                if (1 == ::sscanf(csim->response.c_str(), "%02x", &channelId)) {
+                    if (p2 >= 0) {
+                        auto maybeSelectResponse =
+                            getSelectResponse(requestPipe, mAtConversation,
+                                              channelId, p2);
+                        if (maybeSelectResponse) {
+                            selectResponse = std::move(maybeSelectResponse.value());
+                        } else {
+                            requestPipe(std::format("AT+CCHC={0:d}", channelId));
+                            status = FAILURE(RadioError::GENERIC_FAILURE);
+                        }
+                    } else {
+                        if (!hex2bin(std::string_view(csim->response).substr(2),
+                                     &selectResponse)) {
+                            status = FAILURE(RadioError::GENERIC_FAILURE);
+                        }
+                    }
+                } else {
+                    status = FAILURE(RadioError::GENERIC_FAILURE);
+                }
+            } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+                status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+        } else {
+            const std::string request = std::format("AT+CCHO={0:s}", aid);
+            AtResponsePtr response =
+                mAtConversation(requestPipe, request,
+                                [](const AtResponse& response) -> bool {
+                                   return response.holds<std::string>() || response.holds<CmeError>();
+                                });
+            if (!response || response->isParseError()) {
+                status = FAILURE(RadioError::INTERNAL_ERR);
+            } else if (const std::string* idStr = response->get_if<std::string>()) {
+                const char* end = idStr->data() + idStr->size();
+
+                if (std::from_chars(idStr->data(), end, channelId, 10).ptr != end) {
+                    status = FAILURE(RadioError::INTERNAL_ERR);
+                }
+            } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+                status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+            } else {
+                response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+            }
+        }
+
+        NOT_NULL(mRadioSimResponse)->iccOpenLogicalChannelResponse(
+                makeRadioResponseInfo(serial, status), channelId, std::move(selectResponse));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::iccTransmitApduBasicChannel(const int32_t serial,
+                                                    const sim::SimApdu& message) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, message]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CSIM = AtResponse::CSIM;
+        using CmeError = AtResponse::CmeError;
+        using sim::IccIoResult;
+
+        RadioError status = RadioError::NONE;
+        IccIoResult iccIoResult;
+
+        std::string request;
+        if (message.data.empty()) {
+            if (message.p3 < 0) {
+                request = std::format(
+                        "AT+CSIM={0:d},\"{1:02x}{2:02x}{3:02x}{4:02x}\"", 8,
+                        message.cla, message.instruction, message.p1, message.p2);
+            } else {
+                request = std::format(
+                        "AT+CSIM={0:d},\"{1:02x}{2:02x}{3:02x}{4:02x}{5:02x}\"", 10,
+                        message.cla, message.instruction, message.p1, message.p2, message.p3);
+            }
+        } else {
+            const size_t dataSize = 10 + message.data.size();
+            request = std::format(
+                    "AT+CSIM={0:d},\"{1:02x}{2:02x}{3:02x}{4:02x}{5:02x}{6:s}\"",
+                    dataSize, message.cla, message.instruction, message.p1,
+                    message.p2, message.p3, message.data);
+        }
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CSIM>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CSIM* csim = response->get_if<CSIM>()) {
+            const std::string& simResponse = csim->response;
+            if (simResponse.size() >= 4) {
+                if (2 == ::sscanf(&simResponse[simResponse.size() - 4], "%02X%02X",
+                                  &iccIoResult.sw1, &iccIoResult.sw2)) {
+                    iccIoResult.simResponse = simResponse.substr(0, simResponse.size() - 4);
+                } else {
+                    status = FAILURE(RadioError::GENERIC_FAILURE);
+                }
+            } else {
+                status = FAILURE(RadioError::GENERIC_FAILURE);
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioSimResponse)->iccTransmitApduBasicChannelResponse(
+                makeRadioResponseInfo(serial), std::move(iccIoResult));
+            return true;
+        } else {
+            NOT_NULL(mRadioSimResponse)->iccTransmitApduBasicChannelResponse(
+                makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::iccTransmitApduLogicalChannel(
+        const int32_t serial, const sim::SimApdu& message) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, message]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CGLA = AtResponse::CGLA;
+        using CmeError = AtResponse::CmeError;
+        using sim::IccIoResult;
+
+        RadioError status = RadioError::NONE;
+        IccIoResult iccIoResult;
+
+        const size_t dataSize = 10 + message.data.size();
+        const std::string request = std::format(
+                "AT+CGLA={0:d},{1:d},{2:02x}{3:02x}{4:02x}{5:02x}{6:02x}{7:s}",
+                message.sessionId, dataSize,
+                message.cla, message.instruction, message.p1,
+                message.p2, message.p3, message.data);
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CGLA>() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CGLA* cgla = response->get_if<CGLA>()) {
+            if (cgla->response.size() >= 4) {
+                const size_t size4 = cgla->response.size() - 4;
+                if (2 == ::sscanf(&cgla->response[size4], "%02x%02x",
+                                  &iccIoResult.sw1, &iccIoResult.sw2)) {
+                    iccIoResult.simResponse = cgla->response.substr(0, size4);
+                } else {
+                    status = FAILURE(RadioError::GENERIC_FAILURE);
+                }
+            } else {
+                status = FAILURE(RadioError::GENERIC_FAILURE);
+            }
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioSimResponse)->iccTransmitApduLogicalChannelResponse(
+                makeRadioResponseInfo(serial), std::move(iccIoResult));
+            return true;
+        } else {
+            NOT_NULL(mRadioSimResponse)->iccTransmitApduLogicalChannelResponse(
+                makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::reportStkServiceIsRunning(const int32_t serial) {
+    decltype(mStkUnsolResponse) stkUnsolResponse;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        mStkServiceRunning = true;
+        stkUnsolResponse = std::move(mStkUnsolResponse);
+    }
+
+    if (stkUnsolResponse) {
+        NOT_NULL(mRadioSimIndication)->stkProactiveCommand(
+            RadioIndicationType::UNSOLICITED, std::move(stkUnsolResponse.value().cmd));
+    }
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CUSATD = AtResponse::CUSATD;
+
+        RadioError status = RadioError::NONE;
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::reportStkServiceRunning,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CUSATD>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->get_if<CUSATD>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->reportStkServiceIsRunningResponse(
+                makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::requestIccSimAuthentication(const int32_t serial,
+                                                    const int32_t authContextInt,
+                                                    const std::string& authData64,
+                                                    const std::string& /*aid*/) {
+    const AuthContext authContext = static_cast<AuthContext>(authContextInt);
+
+    auto [status, randBin, authBin] = parseAuthData(authContext, authData64);
+    if (status != RadioError::NONE) {
+        NOT_NULL(mRadioSimResponse)->requestIccSimAuthenticationResponse(
+                makeRadioResponseInfo(serial, status), {});
+        return ScopedAStatus::ok();
+    }
+
+    std::string randHex = bin2hex(randBin.data(), randBin.size());
+    std::string authHex = bin2hex(authBin.data(), authBin.size());
+
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, authContext,
+                                randHex = std::move(randHex),
+                                authHex = std::move(authHex)]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        using MBAU = AtResponse::MBAU;
+        using sim::IccIoResult;
+
+        RadioError status = RadioError::NONE;
+        IccIoResult iccIoResult;
+
+        std::string request;
+        switch (authContext) {
+        case AuthContext::SIM:
+            request = std::format("AT^MBAU=\"{0:s}\"", randHex);
+            break;
+
+        case AuthContext::AKA:
+            request = std::format("AT^MBAU=\"{0:s},{1:s}\"", randHex, authHex);  // the quotes are interesting here
+            break;
+
+        default:
+            return FAILURE(false);
+        }
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<MBAU>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const MBAU* mbau = response->get_if<MBAU>()) {
+            const auto putByte = [](uint8_t* dst, uint8_t b) -> uint8_t* {
+                *dst = b;
+                return dst + 1;
+            };
+
+            const auto putRange = [](uint8_t* dst, const uint8_t* src, size_t size) -> uint8_t* {
+                memcpy(dst, src, size);
+                return dst + size;
+            };
+
+            const auto putSizedRange = [putByte, putRange](uint8_t* dst, const uint8_t* src, size_t size) -> uint8_t* {
+                return putRange(putByte(dst, size), src, size);
+            };
+
+            std::vector<uint8_t> responseBin;
+            uint8_t* p;
+
+            switch (authContext) {
+            case AuthContext::SIM:  // sresLen + sres + kcLen + kc
+                responseBin.resize(2 + mbau->sres.size() + mbau->kc.size());
+                p = responseBin.data();
+                p = putSizedRange(p, mbau->sres.data(), mbau->sres.size());
+                p = putSizedRange(p, mbau->kc.data(), mbau->kc.size());
+                break;
+
+            case AuthContext::AKA:  // 0xDB + ckLen + ck + ikLen + ik + resAutsLen + resAuts
+                responseBin.resize(4 + mbau->ck.size() + mbau->ik.size() + mbau->resAuts.size());
+                p = responseBin.data();
+                p = putByte(p, 0xDB);
+                p = putSizedRange(p, mbau->ck.data(), mbau->ck.size());
+                p = putSizedRange(p, mbau->ik.data(), mbau->ik.size());
+                p = putSizedRange(p, mbau->resAuts.data(), mbau->resAuts.size());
+                break;
+            }
+
+            iccIoResult.sw1 = 0x90;
+            iccIoResult.sw2 = 0;
+            iccIoResult.simResponse = base64encode(responseBin.data(), responseBin.size());
+        } else if (response->isOK()) {
+            status = FAILURE(RadioError::GENERIC_FAILURE);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        if (status == RadioError::NONE) {
+            NOT_NULL(mRadioSimResponse)->requestIccSimAuthenticationResponse(
+                    makeRadioResponseInfo(serial), std::move(iccIoResult));
+            return true;
+        } else {
+            NOT_NULL(mRadioSimResponse)->requestIccSimAuthenticationResponse(
+                    makeRadioResponseInfo(serial, status), {});
+            return status != RadioError::INTERNAL_ERR;
+        }
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::sendEnvelope(const int32_t serial,
+                                     const std::string& contents) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, contents]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CUSATE = AtResponse::CUSATE;
+        RadioError status = RadioError::NONE;
+        std::string commandResponse;
+
+        const std::string request = std::format("AT+CUSATE=\"{0:s}\"", contents);
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CUSATE>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CUSATE* cusate = response->get_if<CUSATE>()) {
+            commandResponse = cusate->response;
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->sendEnvelopeResponse(
+            makeRadioResponseInfo(serial, status), std::move(commandResponse));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::sendEnvelopeWithStatus(const int32_t serial,
+                                               const std::string& /*contents*/) {
+    NOT_NULL(mRadioSimResponse)->sendEnvelopeWithStatusResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::sendTerminalResponseToSim(const int32_t serial,
+                                                  const std::string& commandResponse) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, commandResponse]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CUSATT = AtResponse::CUSATT;
+        RadioError status = RadioError::NONE;
+
+        const std::string request = std::format("AT+CUSATT=\"{0:s}\"", commandResponse);
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CUSATT>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->get_if<CUSATT>()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->sendTerminalResponseToSimResponse(
+                makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setAllowedCarriers(const int32_t serial,
+                                           const sim::CarrierRestrictions& /*carriers*/,
+                                           const sim::SimLockMultiSimPolicy /*multiSimPolicy*/) {
+    NOT_NULL(mRadioSimResponse)->setAllowedCarriersResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setCarrierInfoForImsiEncryption(const int32_t serial,
+                                                        const sim::ImsiEncryptionInfo& /*imsiEncryptionInfo*/) {
+    NOT_NULL(mRadioSimResponse)->setCarrierInfoForImsiEncryptionResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setCdmaSubscriptionSource(const int32_t serial,
+                                                  const sim::CdmaSubscriptionSource cdmaSub) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, cdmaSub]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        RadioError status = RadioError::NONE;
+
+        const std::string request =
+            std::format("AT+CCSS={0:d}", static_cast<unsigned>(cdmaSub));
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->setCdmaSubscriptionSourceResponse(
+            makeRadioResponseInfo(serial, status));
+        if ((status == RadioError::NONE) && mRadioSimIndication) {
+            mRadioSimIndication->cdmaSubscriptionSourceChanged(
+                RadioIndicationType::UNSOLICITED, cdmaSub);
+        }
+
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setFacilityLockForApp(const int32_t serial,
+                                              const std::string& facility,
+                                              const bool lockState,
+                                              const std::string& passwd,
+                                              const int32_t serviceClass,
+                                              const std::string& /*appId*/) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, facility, lockState,
+                                passwd, serviceClass]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        int retry = 1;
+        const int lockStateInt = lockState ? 1 : 0;
+
+        std::string request;
+        if (serviceClass == 0) {
+            request = std::format("AT+CLCK=\"{0:s}\",{1:d},\"{2:s}\"",
+                                  facility, lockStateInt, passwd);
+        } else {
+            request = std::format("AT+CLCK=\"{0:s}\",{1:d},\"{2:s}\",{3:d}",
+                                  facility, lockStateInt, passwd, serviceClass);
+        }
+
+        AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (response->get_if<CmeError>()) {
+            if (facility.compare("SC"sv) == 0) {
+                const std::optional<int> maybeRetries =
+                    getRemainingRetries("SIM PIN"sv, requestPipe, mAtConversation);
+                if (maybeRetries) {
+                    status = FAILURE(RadioError::PASSWORD_INCORRECT);
+                    retry = maybeRetries.value();
+                } else {
+                    status = FAILURE(RadioError::INTERNAL_ERR);
+                }
+            } else if (facility.compare("FD"sv) == 0) {
+                const std::optional<int> maybeRetries =
+                    getRemainingRetries("SIM PIN2"sv, requestPipe, mAtConversation);
+                if (maybeRetries) {
+                    status = FAILURE(RadioError::PASSWORD_INCORRECT);
+                    retry = maybeRetries.value();
+                } else {
+                    status = FAILURE(RadioError::INTERNAL_ERR);
+                }
+            } else {
+                status = FAILURE(RadioError::INVALID_ARGUMENTS);
+                retry = -1;
+            }
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioSimResponse)->setFacilityLockForAppResponse(
+            makeRadioResponseInfo(serial, status), retry);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setSimCardPower(const int32_t serial,
+                                        sim::CardPowerState /*powerUp*/) {
+    NOT_NULL(mRadioSimResponse)->setSimCardPowerResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setUiccSubscription(const int32_t serial,
+                                            const sim::SelectUiccSub& /*uiccSub*/) {
+    NOT_NULL(mRadioSimResponse)->setUiccSubscriptionResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::supplyIccPin2ForApp(int32_t serial,
+                                            const std::string& pin2,
+                                            const std::string& /*aid*/) {
+    mAtChannel->queueRequester([this, serial, pin2]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        const auto [status, remainingRetries] =
+            enterOrChangeSimPinPuk(false, pin2, "", "SIM PIN2"sv,
+                                   requestPipe, mAtConversation);
+
+        NOT_NULL(mRadioSimResponse)->supplyIccPin2ForAppResponse(
+                makeRadioResponseInfo(serial, status), remainingRetries);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::supplyIccPinForApp(int32_t serial,
+                                           const std::string& pin,
+                                           const std::string& /*aid*/) {
+    mAtChannel->queueRequester([this, serial, pin]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        const auto [status, remainingRetries] =
+            enterOrChangeSimPinPuk(false, pin, "", "SIM PIN"sv,
+                                   requestPipe, mAtConversation);
+
+        NOT_NULL(mRadioSimResponse)->supplyIccPinForAppResponse(
+                makeRadioResponseInfo(serial, status), remainingRetries);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::supplyIccPuk2ForApp(int32_t serial,
+                                            const std::string& puk2,
+                                            const std::string& pin2,
+                                            const std::string& /*aid*/) {
+    mAtChannel->queueRequester([this, serial, puk2, pin2]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        const auto [status, remainingRetries] =
+            enterOrChangeSimPinPuk(true, puk2, pin2, "SIM PUK2"sv,
+                                   requestPipe, mAtConversation);
+
+        NOT_NULL(mRadioSimResponse)->supplyIccPuk2ForAppResponse(
+                makeRadioResponseInfo(serial, status), remainingRetries);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::supplyIccPukForApp(const int32_t serial,
+                                           const std::string& puk,
+                                           const std::string& pin,
+                                           const std::string& /*aid*/) {
+    mAtChannel->queueRequester([this, serial, puk, pin]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        const auto [status, remainingRetries] =
+            enterOrChangeSimPinPuk(true, puk, pin, "SIM PUK"sv,
+                                   requestPipe, mAtConversation);
+
+        NOT_NULL(mRadioSimResponse)->supplyIccPukForAppResponse(
+                makeRadioResponseInfo(serial, status), remainingRetries);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::supplySimDepersonalization(const int32_t serial,
+                                                   sim::PersoSubstate /*persoType*/,
+                                                   const std::string& /*controlKey*/) {
+    NOT_NULL(mRadioSimResponse)->supplySimDepersonalizationResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__),
+        {}, 0);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::updateSimPhonebookRecords(const int32_t serial,
+                                                  const sim::PhonebookRecordInfo& /*recordInfo*/) {
+    NOT_NULL(mRadioSimResponse)->updateSimPhonebookRecordsResponse(
+        makeRadioResponseInfoUnsupported(  // matches reference-ril.c
+            serial, FAILURE_DEBUG_PREFIX, __func__), 0);
+    return ScopedAStatus::ok();
+}
+
+void RadioSim::handleUnsolicited(const AtResponse::CFUN& cfun) {
+    bool changed;
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+        changed = mRadioState != cfun.state;
+        mRadioState = cfun.state;
+    }
+
+    if (changed && mRadioSimIndication) {
+        mRadioSimIndication->simStatusChanged(
+            RadioIndicationType::UNSOLICITED);
+
+        mRadioSimIndication->subscriptionStatusChanged(
+            RadioIndicationType::UNSOLICITED, mRadioState == modem::RadioState::ON);
+    }
+}
+
+void RadioSim::handleUnsolicited(const AtResponse::CUSATP& cusatp) {
+    const std::string& cmd = cusatp.cmd;
+    if (cmd.size() < 3) {
+        return;
+    }
+    const unsigned typeOffset = (cmd[2] <= '7') ? 10 : 12;
+    if (cmd.size() < (typeOffset + 2)) {
+        return;
+    }
+
+    unsigned cmdType = 0;
+    if (!(std::from_chars(&cmd[typeOffset], &cmd[typeOffset + 2], cmdType, 16).ec == std::errc{})) {
+        return;
+    }
+
+    const StkCmdType stkCmdType = static_cast<StkCmdType>(cmdType);
+
+    enum class Action {
+        NOTHING, NOTIFY, PROACTIVE_CMD
+    };
+
+    Action action;
+
+    {
+        std::lock_guard<std::mutex> lock(mMtx);
+
+        switch (stkCmdType) {
+        case StkCmdType::RUN_AT:
+        case StkCmdType::SEND_DTMF:
+        case StkCmdType::SEND_SMS:
+        case StkCmdType::SEND_SS:
+        case StkCmdType::SEND_USSD:
+        case StkCmdType::PLAY_TONE:
+        case StkCmdType::CLOSE_CHANNEL:
+            action = Action::NOTIFY;
+            break;
+
+        case StkCmdType::REFRESH:
+            if (cmd.size() >= (typeOffset + 4) && !strncmp(&cmd[typeOffset + 2], "04", 2)) {
+                // SIM_RESET
+                mStkServiceRunning = false;
+                action = Action::NOTHING;
+            } else {
+                action = Action::NOTIFY;
+            }
+            break;
+
+        default:
+            action = Action::PROACTIVE_CMD;
+            break;
+        }
+
+        if (!mStkServiceRunning) {
+            mStkUnsolResponse = cusatp;
+            action = Action::NOTHING;
+        }
+    }
+
+    if (mRadioSimIndication) {
+        switch (action) {
+        case Action::NOTIFY:
+            mRadioSimIndication->stkEventNotify(RadioIndicationType::UNSOLICITED, cmd);
+            break;
+
+        case Action::PROACTIVE_CMD:
+            mRadioSimIndication->stkProactiveCommand(RadioIndicationType::UNSOLICITED, cmd);
+            break;
+
+        case Action::NOTHING:
+            break;
+        }
+    }
+}
+
+void RadioSim::handleUnsolicited(const AtResponse::CUSATEND&) {
+    if (mRadioSimIndication) {
+        mRadioSimIndication->stkSessionEnd(RadioIndicationType::UNSOLICITED);
+    }
+}
+
+void RadioSim::atResponseSink(const AtResponsePtr& response) {
+    if (!mAtConversation.send(response)) {
+        response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    }
+}
+
+ScopedAStatus RadioSim::responseAcknowledgement() {
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioSim::setResponseFunctions(
+        const std::shared_ptr<sim::IRadioSimResponse>& radioSimResponse,
+        const std::shared_ptr<sim::IRadioSimIndication>& radioSimIndication) {
+    mRadioSimResponse = NOT_NULL(radioSimResponse);
+    mRadioSimIndication = NOT_NULL(radioSimIndication);
+    return ScopedAStatus::ok();
+}
+
+/************************* deprecated *************************/
+ScopedAStatus RadioSim::iccCloseLogicalChannel(const int32_t serial,
+                                               const int32_t /*channelId*/) {
+    NOT_NULL(mRadioSimResponse)->iccCloseLogicalChannelResponse(
+        makeRadioResponseInfoDeprecated(serial));
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioSim.h b/hals/radio/RadioSim.h
new file mode 100644
index 00000000..d009540e
--- /dev/null
+++ b/hals/radio/RadioSim.h
@@ -0,0 +1,130 @@
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
+#include <memory>
+#include <mutex>
+
+#include <aidl/android/hardware/radio/sim/BnRadioSim.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioSim : public sim::BnRadioSim {
+    RadioSim(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus areUiccApplicationsEnabled(int32_t serial) override;
+    ScopedAStatus changeIccPin2ForApp(int32_t serial, const std::string& oldPin2,
+                                      const std::string& newPin2,
+                                      const std::string& aid) override;
+    ScopedAStatus changeIccPinForApp(int32_t serial, const std::string& oldPin,
+                                     const std::string& newPin,
+                                     const std::string& aid) override;
+    ScopedAStatus enableUiccApplications(int32_t serial, bool enable) override;
+    ScopedAStatus getAllowedCarriers(int32_t serial) override;
+    ScopedAStatus getCdmaSubscription(int32_t serial) override;
+    ScopedAStatus getCdmaSubscriptionSource(int32_t serial) override;
+    ScopedAStatus getFacilityLockForApp(int32_t serial, const std::string& facility,
+                                        const std::string& password, int32_t serviceClass,
+                                        const std::string& appId) override;
+    ScopedAStatus getIccCardStatus(int32_t serial) override;
+    ScopedAStatus getImsiForApp(int32_t serial, const std::string& aid) override;
+    ScopedAStatus getSimPhonebookCapacity(int32_t serial) override;
+    ScopedAStatus getSimPhonebookRecords(int32_t serial) override;
+    ScopedAStatus iccCloseLogicalChannel(int32_t serial, int32_t channelId) override;
+    ScopedAStatus iccCloseLogicalChannelWithSessionInfo(int32_t serial,
+            const sim::SessionInfo& recordInfo) override;
+    ScopedAStatus iccIoForApp(int32_t serial, const sim::IccIo& iccIo) override;
+    ScopedAStatus iccOpenLogicalChannel(int32_t serial, const std::string& aid,
+                                        int32_t p2) override;
+    ScopedAStatus iccTransmitApduBasicChannel(
+            int32_t serial, const sim::SimApdu& message) override;
+    ScopedAStatus iccTransmitApduLogicalChannel(
+            int32_t serial, const sim::SimApdu& message) override;
+    ScopedAStatus reportStkServiceIsRunning(int32_t serial) override;
+    ScopedAStatus requestIccSimAuthentication(int32_t serial, int32_t authContext,
+                                              const std::string& authData,
+                                              const std::string& aid) override;
+    ScopedAStatus sendEnvelope(int32_t serial, const std::string& command) override;
+    ScopedAStatus sendEnvelopeWithStatus(int32_t serial,
+                                         const std::string& contents) override;
+    ScopedAStatus sendTerminalResponseToSim(int32_t serial,
+                                            const std::string& commandResponse) override;
+    ScopedAStatus setAllowedCarriers(
+            int32_t serial, const sim::CarrierRestrictions& carriers,
+            sim::SimLockMultiSimPolicy multiSimPolicy) override;
+    ScopedAStatus setCarrierInfoForImsiEncryption(
+            int32_t serial, const sim::ImsiEncryptionInfo& imsiEncryptionInfo)
+            override;
+    ScopedAStatus setCdmaSubscriptionSource(
+            int32_t serial, sim::CdmaSubscriptionSource cdmaSub) override;
+    ScopedAStatus setFacilityLockForApp(
+            int32_t serial, const std::string& facility,
+            bool lockState, const std::string& passwd,
+            int32_t serviceClass, const std::string& appId) override;
+    ScopedAStatus setSimCardPower(int32_t serial, sim::CardPowerState powerUp) override;
+    ScopedAStatus setUiccSubscription(
+            int32_t serial, const sim::SelectUiccSub& uiccSub) override;
+    ScopedAStatus supplyIccPin2ForApp(int32_t serial, const std::string& pin2,
+                                      const std::string& aid) override;
+    ScopedAStatus supplyIccPinForApp(int32_t serial, const std::string& pin,
+                                     const std::string& aid) override;
+    ScopedAStatus supplyIccPuk2ForApp(int32_t serial, const std::string& puk2,
+                                      const std::string& pin2,
+                                      const std::string& aid) override;
+    ScopedAStatus supplyIccPukForApp(int32_t serial, const std::string& puk,
+                                     const std::string& pin,
+                                     const std::string& aid) override;
+    ScopedAStatus supplySimDepersonalization(
+            int32_t serial, sim::PersoSubstate persoType, const std::string& controlKey) override;
+    ScopedAStatus updateSimPhonebookRecords(
+            int32_t serial, const sim::PhonebookRecordInfo& recordInfo) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    void handleUnsolicited(const AtResponse::CFUN&);
+    void handleUnsolicited(const AtResponse::CUSATP&);
+    void handleUnsolicited(const AtResponse::CUSATEND&);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus responseAcknowledgement() override;
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<sim::IRadioSimResponse>& radioSimResponse,
+            const std::shared_ptr<sim::IRadioSimIndication>& radioSimIndication) override;
+
+private:
+    std::shared_ptr<sim::IRadioSimResponse> mRadioSimResponse;
+    std::shared_ptr<sim::IRadioSimIndication> mRadioSimIndication;
+
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+
+    std::mutex mMtx;
+    std::optional<AtResponse::CUSATP> mStkUnsolResponse;
+    modem::RadioState mRadioState = modem::RadioState::OFF;
+    bool mUiccApplicationsEnabled = true;
+    bool mStkServiceRunning = false;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioVoice.cpp b/hals/radio/RadioVoice.cpp
new file mode 100644
index 00000000..8eb1fabb
--- /dev/null
+++ b/hals/radio/RadioVoice.cpp
@@ -0,0 +1,835 @@
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
+#define FAILURE_DEBUG_PREFIX "RadioVoice"
+
+#include "RadioVoice.h"
+
+#include "atCmds.h"
+#include "debug.h"
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+RadioVoice::RadioVoice(std::shared_ptr<AtChannel> atChannel) : mAtChannel(std::move(atChannel)) {
+}
+
+ScopedAStatus RadioVoice::acceptCall(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::acceptCall);
+        NOT_NULL(mRadioVoiceResponse)->acceptCallResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::cancelPendingUssd(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::cancelUssd);
+        NOT_NULL(mRadioVoiceResponse)->cancelPendingUssdResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::conference(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::conference);
+        NOT_NULL(mRadioVoiceResponse)->conferenceResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::dial(const int32_t serial,
+                               const voice::Dial& dialInfo) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, dialInfo]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using namespace std::literals;
+        using CmeError = AtResponse::CmeError;
+        using voice::Dial;
+
+        RadioError status = RadioError::NONE;
+
+        std::string_view clir;
+        switch (dialInfo.clir) {
+        case Dial::CLIR_INVOCATION:
+            clir = "I"sv;
+            break;
+        case Dial::CLIR_SUPPRESSION:
+            clir = "i"sv;
+            break;
+        default:
+        case Dial::CLIR_DEFAULT:
+            // clir is the empty string
+            break;
+        }
+
+        const std::string request = std::format("ATD{0:s}{1:s};",
+            dialInfo.address, clir);
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->dialResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::emergencyDial(const int32_t serial,
+                                        const voice::Dial& dialInfo,
+                                        const int32_t categories,
+                                        const std::vector<std::string>& /*urns*/,
+                                        const voice::EmergencyCallRouting routing,
+                                        const bool /*hasKnownUserIntentEmergency*/,
+                                        const bool /*isTesting*/) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, dialInfo, categories, routing]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using namespace std::literals;
+        using CmeError = AtResponse::CmeError;
+        using voice::Dial;
+        using voice::EmergencyCallRouting;
+
+        RadioError status = RadioError::NONE;
+
+        std::string_view clir;
+        switch (dialInfo.clir) {
+        case Dial::CLIR_INVOCATION:
+            clir = "I"sv;
+            break;
+        case Dial::CLIR_SUPPRESSION:
+            clir = "i"sv;
+            break;
+        default:
+        case Dial::CLIR_DEFAULT:
+            // clir is the empty string
+            break;
+        }
+
+        std::string request;
+        switch (routing) {
+        case EmergencyCallRouting::EMERGENCY:
+        case EmergencyCallRouting::UNKNOWN:
+            if (categories) {
+                request = std::format("ATD{0:s}@{1:d},#{2:s};",
+                                      dialInfo.address, categories, clir);
+            } else {
+                request = std::format("ATD{0:s}@,#{1:s};", dialInfo.address, clir);
+            }
+            break;
+
+        default:
+        case EmergencyCallRouting::NORMAL:
+            request = std::format("ATD{0:s}{1:s};", dialInfo.address, clir);
+            break;
+        }
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->emergencyDialResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::exitEmergencyCallbackMode(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::exitEmergencyMode,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() || response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->exitEmergencyCallbackModeResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::explicitCallTransfer(const int32_t serial) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->explicitCallTransferResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getCallForwardStatus(const int32_t serial,
+                                               const voice::CallForwardInfo& callInfo) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, callInfo](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CCFCU = AtResponse::CCFCU;
+        using CmeError = AtResponse::CmeError;
+        using voice::CallForwardInfo;
+
+        RadioError status = RadioError::NONE;
+        std::vector<CallForwardInfo> callForwardInfos;
+
+        const std::string request = std::format(
+                "AT+CCFCU={0:d},{1:d},{2:d},{3:d},\"{4:s}\",{5:d}",
+                callInfo.reason, 2, 2, callInfo.toa,
+                callInfo.number, callInfo.serviceClass);
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CCFCU>() ||
+                                      response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CCFCU* ccfcu = response->get_if<CCFCU>()) {
+            callForwardInfos = ccfcu->callForwardInfos;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->getCallForwardStatusResponse(
+                makeRadioResponseInfo(serial, status),
+                std::move(callForwardInfos));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getCallWaiting(const int32_t serial,
+                                         const int32_t serviceClass) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, serviceClass]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CCWA = AtResponse::CCWA;
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        bool enable = false;
+        int serviceClassOut = -1;
+
+        const std::string request =
+            std::format("AT+CCWA={0:d},{1:d},{2:d}",
+                        1, 2, serviceClass);
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CCWA>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CCWA* ccwa = response->get_if<CCWA>()) {
+            enable = ccwa->enable;
+            serviceClassOut = ccwa->serviceClass;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->getCallWaitingResponse(
+            makeRadioResponseInfo(serial, status), enable, serviceClassOut);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getClip(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CLIP = AtResponse::CLIP;
+        using CmeError = AtResponse::CmeError;
+        using ClipStatus = voice::ClipStatus;
+
+        RadioError status = RadioError::NONE;
+        ClipStatus clipStatus = ClipStatus::UNKNOWN;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getClip,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CLIP>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CLIP* clip = response->get_if<CLIP>()) {
+            clipStatus = clip->status;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->getClipResponse(
+            makeRadioResponseInfo(serial, status), clipStatus);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getClir(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CLIR = AtResponse::CLIR;
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        int n = -1;
+        int m = -1;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getClir,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CLIR>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CLIR* clir = response->get_if<CLIR>()) {
+            n = clir->n;
+            m = clir->m;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->getClirResponse(
+            makeRadioResponseInfo(serial, status), n, m);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getCurrentCalls(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CLCC = AtResponse::CLCC;
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        std::vector<voice::Call> calls;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getCurrentCalls,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CLCC>() ||
+                                      response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CLCC* clcc = response->get_if<CLCC>()) {
+            calls = clcc->calls;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->getCurrentCallsResponse(
+            makeRadioResponseInfo(serial, status), std::move(calls));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getLastCallFailCause(const int32_t serial) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->getLastCallFailCauseResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getMute(const int32_t serial) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CMUT = AtResponse::CMUT;
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+        bool isMuted = false;
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, atCmds::getCurrentCalls,
+                            [](const AtResponse& response) -> bool {
+                               return response.holds<CMUT>() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+             NOT_NULL(mRadioVoiceResponse)->getCurrentCallsResponse(
+                    makeRadioResponseInfo(serial, FAILURE(RadioError::INTERNAL_ERR)), {});
+            return false;
+        } else if (const CMUT* cmut = response->get_if<CMUT>()) {
+            isMuted = cmut->on;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+
+        NOT_NULL(mRadioVoiceResponse)->getMuteResponse(
+            makeRadioResponseInfo(serial, status), isMuted);
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getPreferredVoicePrivacy(const int32_t serial) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->getPreferredVoicePrivacyResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__), false);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::getTtyMode(const int32_t serial) {
+    NOT_NULL(mRadioVoiceResponse)->getTtyModeResponse(
+        makeRadioResponseInfo(serial), voice::TtyMode::FULL);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::handleStkCallSetupRequestFromSim(const int32_t serial,
+                                                           const bool /*accept*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->handleStkCallSetupRequestFromSimResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::hangup(const int32_t serial,
+                                 const int32_t gsmIndex) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, gsmIndex]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(std::format("AT+CHLD=1{0:d}", gsmIndex));
+        NOT_NULL(mRadioVoiceResponse)->hangupConnectionResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::hangupForegroundResumeBackground(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::hangupForeground);
+        NOT_NULL(mRadioVoiceResponse)->hangupForegroundResumeBackgroundResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::hangupWaitingOrBackground(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::hangupWaiting);
+        NOT_NULL(mRadioVoiceResponse)->hangupWaitingOrBackgroundResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::isVoNrEnabled(const int32_t serial) {
+    NOT_NULL(mRadioVoiceResponse)->isVoNrEnabledResponse(
+            makeRadioResponseInfoNOP(serial), false);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::rejectCall(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::rejectCall);
+        NOT_NULL(mRadioVoiceResponse)->rejectCallResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::sendBurstDtmf(const int32_t serial,
+                                        const std::string& /*dtmf*/,
+                                        const int32_t /*on*/,
+                                        const int32_t /*off*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->sendBurstDtmfResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::sendCdmaFeatureCode(const int32_t serial,
+                                              const std::string& /*fcode*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->sendCdmaFeatureCodeResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::sendDtmf(const int32_t serial,
+                                   const std::string& s) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, s]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(std::format("AT+VTS={0:s}", s));
+        NOT_NULL(mRadioVoiceResponse)->sendDtmfResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::sendUssd(const int32_t serial,
+                                   const std::string& ussd) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, ussd]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(std::format("AT+CUSD=1,\"%s\"", ussd));
+        NOT_NULL(mRadioVoiceResponse)->sendUssdResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::separateConnection(const int32_t serial,
+                                             const int32_t gsmIndex) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, gsmIndex]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        if ((gsmIndex > 0) && (gsmIndex < 10)) {
+            requestPipe(std::format("AT+CHLD=2{0:d}", gsmIndex));
+            NOT_NULL(mRadioVoiceResponse)->separateConnectionResponse(
+                makeRadioResponseInfo(serial));
+        } else {
+            NOT_NULL(mRadioVoiceResponse)->separateConnectionResponse(
+                makeRadioResponseInfo(serial, FAILURE(RadioError::GENERIC_FAILURE)));
+        }
+
+        return true;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setCallForward(const int32_t serial,
+                                         const voice::CallForwardInfo& callInfo) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, callInfo](const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        std::string request = std::format(
+                "AT+CCFCU={0:d},{1:d},{2:d},{3:d},\"{4:s}\",{5:d}",
+                callInfo.reason, callInfo.status, 2, callInfo.toa,
+                callInfo.number, callInfo.serviceClass);
+        if ((callInfo.timeSeconds > 0) && (callInfo.status == 3)) {
+            request += std::format(",\"\",\"\",,{0:d}", callInfo.timeSeconds);
+        } else if (callInfo.serviceClass) {
+            request += ",\"\"";
+        }
+
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->setCallForwardResponse(
+                makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setCallWaiting(const int32_t serial,
+                                         const bool enable,
+                                         const int32_t serviceClass) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, enable, serviceClass]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        const std::string request =
+            std::format("AT+CCWA={0:d},{1:d},{2:d}", 1, (enable ? 1 : 0),
+                        serviceClass);
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->setCallWaitingResponse(
+                makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setClir(const int32_t serial, const int32_t clirStatus) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, clirStatus]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+
+        RadioError status = RadioError::NONE;
+
+        const std::string request = std::format("AT+CLIR: {0:d}", clirStatus);
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+            status = FAILURE(RadioError::INTERNAL_ERR);
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->setClirResponse(
+                makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setMute(const int32_t serial,
+                                  const bool enable) {
+    static const char* const kFunc = __func__;
+    mAtChannel->queueRequester([this, serial, enable]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        using CmeError = AtResponse::CmeError;
+        RadioError status = RadioError::NONE;
+
+        const std::string request =
+            std::format("AT+CMUT={0:d}", (enable ? 1 : 0));
+        const AtResponsePtr response =
+            mAtConversation(requestPipe, request,
+                            [](const AtResponse& response) -> bool {
+                               return response.isOK() ||
+                                      response.holds<CmeError>();
+                            });
+        if (!response || response->isParseError()) {
+             NOT_NULL(mRadioVoiceResponse)->getCurrentCallsResponse(
+                    makeRadioResponseInfo(serial, FAILURE(RadioError::INTERNAL_ERR)), {});
+            return false;
+        } else if (const CmeError* cmeError = response->get_if<CmeError>()) {
+            status = cmeError->getErrorAndLog(FAILURE_DEBUG_PREFIX, kFunc, __LINE__);
+        } else if (!response->isOK()) {
+            response->unexpected(FAILURE_DEBUG_PREFIX, kFunc);
+        }
+
+        NOT_NULL(mRadioVoiceResponse)->setMuteResponse(
+            makeRadioResponseInfo(serial, status));
+        return status != RadioError::INTERNAL_ERR;
+    });
+
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setPreferredVoicePrivacy(const int32_t serial,
+                                                   const bool /*enable*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->setPreferredVoicePrivacyResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setTtyMode(const int32_t serial, voice::TtyMode /*mode*/) {
+    NOT_NULL(mRadioVoiceResponse)->setTtyModeResponse(
+        makeRadioResponseInfoNOP(serial));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setVoNrEnabled(const int32_t serial, const bool enable) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->setVoNrEnabledResponse(
+        makeRadioResponseInfo(serial, enable ?
+            FAILURE(RadioError::REQUEST_NOT_SUPPORTED) : RadioError::NONE));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::startDtmf(const int32_t serial, const std::string& /*s*/) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->startDtmfResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::stopDtmf(const int32_t serial) {
+    // matches reference-ril.c
+    NOT_NULL(mRadioVoiceResponse)->stopDtmfResponse(
+        makeRadioResponseInfoUnsupported(
+            serial, FAILURE_DEBUG_PREFIX, __func__));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::switchWaitingOrHoldingAndActive(const int32_t serial) {
+    mAtChannel->queueRequester([this, serial]
+                               (const AtChannel::RequestPipe requestPipe) -> bool {
+        requestPipe(atCmds::switchWaiting);
+        NOT_NULL(mRadioVoiceResponse)->switchWaitingOrHoldingAndActiveResponse(
+            makeRadioResponseInfo(serial));
+        return true;
+    });
+    return ScopedAStatus::ok();
+}
+
+void RadioVoice::atResponseSink(const AtResponsePtr& response) {
+    if (!mAtConversation.send(response)) {
+        response->visit([this](const auto& msg){ handleUnsolicited(msg); });
+    }
+}
+
+void RadioVoice::handleUnsolicited(const AtResponse::RING&) {
+    if (mRadioVoiceIndication) {
+        mRadioVoiceIndication->callRing(RadioIndicationType::UNSOLICITED, true, {});
+        mRadioVoiceIndication->callStateChanged(RadioIndicationType::UNSOLICITED);
+    }
+}
+
+void RadioVoice::handleUnsolicited(const AtResponse::WSOS& wsos) {
+    if (mRadioVoiceIndication) {
+        if (wsos.isEmergencyMode) {
+            mRadioVoiceIndication->enterEmergencyCallbackMode(
+                RadioIndicationType::UNSOLICITED);
+        } else {
+            mRadioVoiceIndication->exitEmergencyCallbackMode(
+                RadioIndicationType::UNSOLICITED);
+        }
+    }
+}
+
+ScopedAStatus RadioVoice::responseAcknowledgement() {
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus RadioVoice::setResponseFunctions(
+        const std::shared_ptr<voice::IRadioVoiceResponse>& radioVoiceResponse,
+        const std::shared_ptr<voice::IRadioVoiceIndication>& radioVoiceIndication) {
+    mRadioVoiceResponse = NOT_NULL(radioVoiceResponse);
+    mRadioVoiceIndication = NOT_NULL(radioVoiceIndication);
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/RadioVoice.h b/hals/radio/RadioVoice.h
new file mode 100644
index 00000000..facee954
--- /dev/null
+++ b/hals/radio/RadioVoice.h
@@ -0,0 +1,100 @@
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
+#include <memory>
+
+#include <aidl/android/hardware/radio/voice/BnRadioVoice.h>
+#include "AtChannel.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct RadioVoice : public voice::BnRadioVoice {
+    RadioVoice(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus acceptCall(int32_t serial) override;
+    ScopedAStatus cancelPendingUssd(int32_t serial) override;
+    ScopedAStatus conference(int32_t serial) override;
+    ScopedAStatus dial(
+            int32_t serial, const voice::Dial& dialInfo) override;
+    ScopedAStatus emergencyDial(
+            int32_t serial, const voice::Dial& dialInfo,
+            int32_t categories, const std::vector<std::string>& urns,
+            voice::EmergencyCallRouting routing,
+            bool hasKnownUserIntentEmergency, bool isTesting) override;
+    ScopedAStatus exitEmergencyCallbackMode(int32_t serial) override;
+    ScopedAStatus explicitCallTransfer(int32_t serial) override;
+    ScopedAStatus getCallForwardStatus(
+            int32_t serial,
+            const voice::CallForwardInfo& callInfo) override;
+    ScopedAStatus getCallWaiting(int32_t serial, int32_t serviceClass) override;
+    ScopedAStatus getClip(int32_t serial) override;
+    ScopedAStatus getClir(int32_t serial) override;
+    ScopedAStatus getCurrentCalls(int32_t serial) override;
+    ScopedAStatus getLastCallFailCause(int32_t serial) override;
+    ScopedAStatus getMute(int32_t serial) override;
+    ScopedAStatus getPreferredVoicePrivacy(int32_t serial) override;
+    ScopedAStatus getTtyMode(int32_t serial) override;
+    ScopedAStatus handleStkCallSetupRequestFromSim(int32_t serial, bool accept) override;
+    ScopedAStatus hangup(int32_t serial, int32_t gsmIndex) override;
+    ScopedAStatus hangupForegroundResumeBackground(int32_t serial) override;
+    ScopedAStatus hangupWaitingOrBackground(int32_t serial) override;
+    ScopedAStatus isVoNrEnabled(int32_t serial) override;
+    ScopedAStatus rejectCall(int32_t serial) override;
+    ScopedAStatus sendBurstDtmf(int32_t serial, const std::string& dtmf,
+                                int32_t on, int32_t off) override;
+    ScopedAStatus sendCdmaFeatureCode(int32_t serial, const std::string& fcode) override;
+    ScopedAStatus sendDtmf(int32_t serial, const std::string& s) override;
+    ScopedAStatus sendUssd(int32_t serial, const std::string& ussd) override;
+    ScopedAStatus separateConnection(int32_t serial, int32_t gsmIndex) override;
+    ScopedAStatus setCallForward(
+            int32_t serial, const voice::CallForwardInfo& callInfo) override;
+    ScopedAStatus setCallWaiting(int32_t serial, bool enable, int32_t serviceClass) override;
+    ScopedAStatus setClir(int32_t serial, int32_t status) override;
+    ScopedAStatus setMute(int32_t serial, bool enable) override;
+    ScopedAStatus setPreferredVoicePrivacy(int32_t serial, bool enable) override;
+    ScopedAStatus setTtyMode(int32_t serial, voice::TtyMode mode) override;
+    ScopedAStatus setVoNrEnabled(int32_t serial, bool enable) override;
+    ScopedAStatus startDtmf(int32_t serial, const std::string& s) override;
+    ScopedAStatus stopDtmf(int32_t serial) override;
+    ScopedAStatus switchWaitingOrHoldingAndActive(int32_t serial) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+    void handleUnsolicited(const AtResponse::RING&);
+    void handleUnsolicited(const AtResponse::WSOS&);
+    template <class IGNORE> void handleUnsolicited(const IGNORE&) {}
+
+    ScopedAStatus responseAcknowledgement() override;
+    ScopedAStatus setResponseFunctions(
+            const std::shared_ptr<voice::IRadioVoiceResponse>& radioVoiceResponse,
+            const std::shared_ptr<voice::IRadioVoiceIndication>& radioVoiceIndication) override;
+
+    const std::shared_ptr<AtChannel> mAtChannel;
+    AtChannel::Conversation mAtConversation;
+    std::shared_ptr<voice::IRadioVoiceResponse> mRadioVoiceResponse;
+    std::shared_ptr<voice::IRadioVoiceIndication> mRadioVoiceIndication;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/Sap.cpp b/hals/radio/Sap.cpp
new file mode 100644
index 00000000..50b3b49a
--- /dev/null
+++ b/hals/radio/Sap.cpp
@@ -0,0 +1,92 @@
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
+#define FAILURE_DEBUG_PREFIX "Sap"
+
+#include "Sap.h"
+#include "debug.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+Sap::Sap(std::shared_ptr<AtChannel> atChannel) {}
+
+ScopedAStatus Sap::apduReq(const int32_t serial, sap::SapApduType /*type*/,
+                           const std::vector<uint8_t>& /*command*/) {
+    NOT_NULL(mSapCallback)->apduResponse(
+        serial, FAILURE(sap::SapResultCode::NOT_SUPPORTED), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::connectReq(const int32_t serial, const int32_t /*maxMsgSize*/) {
+    NOT_NULL(mSapCallback)->connectResponse(
+        serial, FAILURE_V(sap::SapConnectRsp::CONNECT_FAILURE,
+                          "%s", "NOT_SUPPORTED"),
+        {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::disconnectReq(const int32_t serial) {
+    NOT_NULL(mSapCallback)->disconnectResponse(serial);
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::powerReq(const int32_t serial, bool /*state*/) {
+    NOT_NULL(mSapCallback)->powerResponse(
+        serial, FAILURE(sap::SapResultCode::NOT_SUPPORTED));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::resetSimReq(const int32_t serial) {
+    NOT_NULL(mSapCallback)->resetSimResponse(
+        serial, FAILURE(sap::SapResultCode::NOT_SUPPORTED));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::setTransferProtocolReq(
+        const int32_t serial, const sap::SapTransferProtocol /*transferProtocol*/) {
+    NOT_NULL(mSapCallback)->transferProtocolResponse(
+        serial, FAILURE(sap::SapResultCode::NOT_SUPPORTED));
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::transferAtrReq(const int32_t serial) {
+    NOT_NULL(mSapCallback)->transferAtrResponse(
+        serial, FAILURE(sap::SapResultCode::NOT_SUPPORTED), {});
+    return ScopedAStatus::ok();
+}
+
+ScopedAStatus Sap::transferCardReaderStatusReq(const int32_t serial) {
+    NOT_NULL(mSapCallback)->transferCardReaderStatusResponse(
+        serial, FAILURE(sap::SapResultCode::NOT_SUPPORTED), 0);
+    return ScopedAStatus::ok();
+}
+
+void Sap::atResponseSink(const AtResponsePtr& /*response*/) {}
+
+ScopedAStatus Sap::setCallback(const std::shared_ptr<sap::ISapCallback>& sapCallback) {
+    mSapCallback = NOT_NULL(sapCallback);
+    return ScopedAStatus::ok();
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/Sap.h b/hals/radio/Sap.h
new file mode 100644
index 00000000..38a5390c
--- /dev/null
+++ b/hals/radio/Sap.h
@@ -0,0 +1,57 @@
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
+#include <memory>
+
+#include <aidl/android/hardware/radio/sap/BnSap.h>
+#include "AtChannel.h"
+#include "AtResponse.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+using ::ndk::ScopedAStatus;
+
+struct Sap : public sap::BnSap {
+    Sap(std::shared_ptr<AtChannel> atChannel);
+
+    ScopedAStatus apduReq(int32_t serial, sap::SapApduType type,
+                          const std::vector<uint8_t>& command) override;
+    ScopedAStatus connectReq(int32_t serial, int32_t maxMsgSize) override;
+    ScopedAStatus disconnectReq(int32_t serial) override;
+    ScopedAStatus powerReq(int32_t serial, bool state) override;
+    ScopedAStatus resetSimReq(int32_t serial) override;
+    ScopedAStatus setTransferProtocolReq(
+            int32_t serial, sap::SapTransferProtocol transferProtocol) override;
+    ScopedAStatus transferAtrReq(int32_t serial) override;
+    ScopedAStatus transferCardReaderStatusReq(int32_t serial) override;
+
+    void atResponseSink(const AtResponsePtr& response);
+
+    ScopedAStatus setCallback(const std::shared_ptr<sap::ISapCallback>& sapCallback) override;
+
+private:
+    std::shared_ptr<sap::ISapCallback> mSapCallback;
+};
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/android.hardware.radio.ranchu.rc b/hals/radio/android.hardware.radio.ranchu.rc
new file mode 100644
index 00000000..65bd1ad4
--- /dev/null
+++ b/hals/radio/android.hardware.radio.ranchu.rc
@@ -0,0 +1,5 @@
+service vendor.radio-ranchu /vendor/bin/hw/android.hardware.radio-service.ranchu
+    class hal
+    user radio
+    group radio inet misc log readproc wakelock
+    capabilities BLOCK_SUSPEND NET_ADMIN NET_RAW
diff --git a/hals/radio/android.hardware.radio.ranchu.xml b/hals/radio/android.hardware.radio.ranchu.xml
new file mode 100644
index 00000000..763dac4c
--- /dev/null
+++ b/hals/radio/android.hardware.radio.ranchu.xml
@@ -0,0 +1,51 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl">
+        <name>android.hardware.radio.config</name>
+        <version>3</version>
+        <fqname>IRadioConfig/default</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.data</name>
+        <version>3</version>
+        <fqname>IRadioData/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.ims</name>
+        <version>2</version>
+        <fqname>IRadioIms/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.messaging</name>
+        <version>3</version>
+        <fqname>IRadioMessaging/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.modem</name>
+        <version>3</version>
+        <fqname>IRadioModem/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.network</name>
+        <version>3</version>
+        <fqname>IRadioNetwork/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.sim</name>
+        <version>3</version>
+        <fqname>IRadioSim/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.voice</name>
+        <version>3</version>
+        <fqname>IRadioVoice/slot1</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.ims.media</name>
+        <version>2</version>
+        <fqname>IImsMedia/default</fqname>
+    </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.sap</name>
+        <fqname>ISap/slot1</fqname>
+    </hal>
+</manifest>
diff --git a/hals/radio/atCmds.h b/hals/radio/atCmds.h
new file mode 100644
index 00000000..cfa07061
--- /dev/null
+++ b/hals/radio/atCmds.h
@@ -0,0 +1,130 @@
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
+#include <string_view>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace atCmds {
+using namespace std::literals;
+
+static constexpr std::string_view kCmeErrorOperationNotAllowed = "3"sv;
+static constexpr std::string_view kCmeErrorOperationNotSupported = "4"sv;
+static constexpr std::string_view kCmeErrorSimNotInserted = "10"sv;
+static constexpr std::string_view kCmeErrorSimPinRequired = "11"sv;
+static constexpr std::string_view kCmeErrorSimPukRequired = "12"sv;
+static constexpr std::string_view kCmeErrorSimBusy = "14"sv;
+static constexpr std::string_view kCmeErrorIncorrectPassword = "16"sv;
+static constexpr std::string_view kCmeErrorMemoryFull = "20"sv;
+static constexpr std::string_view kCmeErrorInvalidIndex = "21"sv;
+static constexpr std::string_view kCmeErrorNotFound = "22"sv;
+static constexpr std::string_view kCmeErrorInvalidCharactersInTextString = "27"sv;
+static constexpr std::string_view kCmeErrorNoNetworkService = "30"sv;
+static constexpr std::string_view kCmeErrorNetworkNotAllowedEmergencyCallsOnly = "32"sv;
+static constexpr std::string_view kCmeErrorInCorrectParameters = "50"sv;
+static constexpr std::string_view kCmeErrorNetworkNotAttachedDueToMTFunctionalRestrictions = "53"sv;
+static constexpr std::string_view kCmeErrorFixedDialNumberOnlyAllowed = "56"sv;
+
+static constexpr std::string_view kCmsErrorOperationNotAllowed = "302";
+static constexpr std::string_view kCmsErrorOperationNotSupported = "303";
+static constexpr std::string_view kCmsErrorInvalidPDUModeParam = "304";
+static constexpr std::string_view kCmsErrorSCAddressUnknown = "304";
+
+constexpr int kClckUnlock = 0;
+constexpr int kClckLock = 1;
+constexpr int kClckQuery = 2;
+
+static constexpr std::string_view getModemPowerState =
+    "AT+CFUN?"sv;
+
+static constexpr std::string_view getSupportedRadioTechs =
+    "AT+CTEC=?"sv;
+
+static constexpr std::string_view getCurrentPreferredRadioTechs =
+    "AT+CTEC?"sv;
+
+static constexpr std::string_view getSimCardStatus =
+    "AT+CPIN?"sv;
+
+static constexpr std::string_view reportStkServiceRunning =
+    "AT+CUSATD?"sv;
+
+static constexpr std::string_view getICCID = "AT+CICCID"sv;
+
+static constexpr std::string_view getIMEI = "AT+CGSN=2"sv;
+
+static constexpr std::string_view getIMSI = "AT+CIMI"sv;
+
+static constexpr std::string_view getSignalStrength =
+    "AT+CSQ"sv;
+
+static constexpr std::string_view getNetworkSelectionMode =
+    "AT+COPS?"sv;
+
+static constexpr std::string_view getAvailableNetworks =
+    "AT+COPS=?"sv;
+
+static constexpr std::string_view getOperator =
+    "AT+COPS=3,0;+COPS?;+COPS=3,1;+COPS?;+COPS=3,2;+COPS?"sv;
+
+static constexpr std::string_view setNetworkSelectionModeAutomatic =
+    "AT+COPS=0"sv;
+
+static constexpr std::string_view getCdmaRoamingPreference =
+    "AT+WRMP?"sv;
+
+static constexpr std::string_view getVoiceRegistrationState =
+    "AT+CREG?"sv;
+
+static constexpr std::string_view getDataRegistrationState =
+    "AT+CEREG?"sv;
+
+static constexpr std::string_view getCdmaSubscriptionSource =
+    "AT+CCSS?"sv;
+
+static constexpr std::string_view getCurrentCalls = "AT+CLCC"sv;
+
+static constexpr std::string_view acceptCall = "ATA"sv;
+static constexpr std::string_view rejectCall = "ATH"sv;
+static constexpr std::string_view hangupWaiting = "AT+CHLD=0"sv;
+static constexpr std::string_view hangupForeground = "AT+CHLD=1"sv;
+static constexpr std::string_view switchWaiting = "AT+CHLD=2"sv;
+static constexpr std::string_view conference = "AT+CHLD=3"sv;
+
+static constexpr std::string_view cancelUssd = "AT+CUSD=2"sv;
+
+static constexpr std::string_view getClip = "AT+CLIP?"sv;
+static constexpr std::string_view getClir = "AT+CLIR?"sv;
+static constexpr std::string_view getMute = "AT+CMUT?"sv;
+
+static constexpr std::string_view exitEmergencyMode = "AT+WSOS=0"sv;
+
+static constexpr std::string_view getSmscAddress = "AT+CSCA?"sv;
+
+static constexpr std::string_view getBroadcastConfig = "AT+CSCB?"sv;
+
+}  // namespace atCmds
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
+
diff --git a/radio/data/apns-conf.xml b/hals/radio/data/apns-conf.xml
similarity index 100%
rename from radio/data/apns-conf.xml
rename to hals/radio/data/apns-conf.xml
diff --git a/radio/data/iccprofile_for_sim0.xml b/hals/radio/data/iccprofile_for_sim0.xml
similarity index 100%
rename from radio/data/iccprofile_for_sim0.xml
rename to hals/radio/data/iccprofile_for_sim0.xml
diff --git a/radio/data/numeric_operator.xml b/hals/radio/data/numeric_operator.xml
similarity index 100%
rename from radio/data/numeric_operator.xml
rename to hals/radio/data/numeric_operator.xml
diff --git a/hals/radio/debug.h b/hals/radio/debug.h
new file mode 100644
index 00000000..0fd4b4a6
--- /dev/null
+++ b/hals/radio/debug.h
@@ -0,0 +1,43 @@
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
+#include <log/log_main.h>
+#include <log/log_radio.h>
+
+#ifdef FAILURE_DEBUG_PREFIX
+
+#define FAILURE(X) \
+    (RLOGE("%s:%s:%d failure: %s", FAILURE_DEBUG_PREFIX, __func__, __LINE__, #X), X)
+
+#define FAILURE_V(X, FMT, ...) \
+    (RLOGE("%s:%s:%d failure: " FMT, FAILURE_DEBUG_PREFIX, __func__, __LINE__, __VA_ARGS__), X)
+
+#define NOT_NULL(P) (LOG_ALWAYS_FATAL_IF(!(P), "%s:%d %s is nullptr", __func__, __LINE__, #P), P)
+
+#else
+
+#define FAILURE(X) \
+    (RLOGE("%s:%d failure: %s", __func__, __LINE__, #X), X)
+
+#define FAILURE_V(X, FMT, ...) \
+    (RLOGE("%s:%d failure: " FMT, __func__, __LINE__, __VA_ARGS__), X)
+
+#define NOT_NULL(P) (LOG_ALWAYS_FATAL_IF(!(P), "%s:%s:%d %s is nullptr", \
+                                         FAILURE_DEBUG_PREFIX, __func__, __LINE__, #P), \
+                     P)
+
+#endif  // ifdef FAILURE_DEBUG_PREFIX
diff --git a/hals/radio/hexbin.cpp b/hals/radio/hexbin.cpp
new file mode 100644
index 00000000..eac2f4b8
--- /dev/null
+++ b/hals/radio/hexbin.cpp
@@ -0,0 +1,108 @@
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
+#include "debug.h"
+#include "hexbin.h"
+
+#include <openssl/base64.h>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+uint8_t hex2bin1(const char c) {
+    if ((c >= '0') && (c <= '9')) {
+        return c - '0';
+    } else if ((c >= 'a') && (c <= 'f')) {
+        return c - 'a' + 10;
+    } else if ((c >= 'A') && (c <= 'F')) {
+        return c - 'A' + 10;
+    } else {
+        return 0;
+    }
+}
+
+void hex2binImpl(const char* s, uint8_t* b, size_t sz) {
+    for (; sz > 0; s += 2, ++b, --sz) {
+        *b = (hex2bin1(s[0]) << 4) | hex2bin1(s[1]);
+    }
+}
+
+bool hex2bin(const std::string_view hex, std::vector<uint8_t>* bin) {
+    if (hex.size() & 1) {
+        return FAILURE_V(false, "%s", "odd length");
+    }
+
+    const size_t sz = hex.size() / 2;
+    bin->resize(sz);
+    hex2binImpl(hex.data(), bin->data(), sz);
+    return true;
+}
+
+char bin2hex1(const unsigned x) {
+    return (x < 10) ? char(x + '0') : char(x - 10 + 'A');
+}
+
+void bin2hexImpl(const uint8_t* b, char* s, size_t sz) {
+    for (; sz > 0; s += 2, ++b, --sz) {
+        const unsigned bb = *b;
+        s[0] = bin2hex1(bb >> 4);
+        s[1] = bin2hex1(bb & 0xF);
+    }
+}
+
+std::string bin2hex(const uint8_t* b, const size_t sz) {
+    std::string str(sz + sz, '?');
+    bin2hexImpl(b, str.data(), sz);
+    return str;
+}
+
+std::string base64encode(const void* const binaryData, const size_t binarySize) {
+    int size = ((binarySize + 2) / 3 * 4) + 1;  // `+1` is for the "trailing NUL"
+    std::string encoded(size, '?');
+    size = EVP_EncodeBlock(reinterpret_cast<uint8_t *>(encoded.data()),
+                           static_cast<const uint8_t*>(binaryData),
+                           binarySize);
+    encoded.resize(size);  // without "trailing NUL"
+    LOG_ALWAYS_FATAL_IF(size < 0);
+    return encoded;
+}
+
+std::optional<std::vector<uint8_t>> base64decode(const char* const encodedData, const size_t encodedSize) {
+    if (encodedSize % 4) {
+        return std::nullopt;
+    }
+
+    int size = encodedSize / 4 * 3;
+    std::vector<uint8_t> decoded(size);
+    size = EVP_DecodeBlock(decoded.data(),
+                           reinterpret_cast<const uint8_t*>(encodedData),
+                           encodedSize);
+    if (size < 0) {
+        return std::nullopt;
+    } else {
+        decoded.resize(size);
+        return decoded;
+    }
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/hexbin.h b/hals/radio/hexbin.h
new file mode 100644
index 00000000..72cc6c69
--- /dev/null
+++ b/hals/radio/hexbin.h
@@ -0,0 +1,44 @@
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
+#include <optional>
+#include <string>
+#include <vector>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+uint8_t hex2bin1(const char c);
+void hex2binImpl(const char* s, uint8_t* b, size_t sz);
+bool hex2bin(const std::string_view hex, std::vector<uint8_t>* bin);
+
+char bin2hex1(const unsigned x);
+void bin2hexImpl(const uint8_t* b, char* s, size_t sz);
+std::string bin2hex(const uint8_t* b, size_t sz);
+
+std::string base64encode(const void* binaryData, size_t binarySize);
+std::optional<std::vector<uint8_t>> base64decode(const char* encodedData, size_t encodedSize);
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/radio/init.system_ext.radio.rc b/hals/radio/init.system_ext.radio.rc
similarity index 100%
rename from radio/init.system_ext.radio.rc
rename to hals/radio/init.system_ext.radio.rc
diff --git a/hals/radio/main.cpp b/hals/radio/main.cpp
new file mode 100644
index 00000000..ef7e6e39
--- /dev/null
+++ b/hals/radio/main.cpp
@@ -0,0 +1,234 @@
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
+#include <string_view>
+#include <memory>
+
+#include <cutils/properties.h>
+#include <fcntl.h>
+
+#include <android/binder_interface_utils.h>
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+
+#include "AtChannel.h"
+#include "ImsMedia.h"
+#include "RadioConfig.h"
+#include "RadioData.h"
+#include "RadioIms.h"
+#include "RadioMessaging.h"
+#include "RadioModem.h"
+#include "RadioNetwork.h"
+#include "RadioSim.h"
+#include "RadioVoice.h"
+#include "Sap.h"
+
+#include "debug.h"
+
+namespace {
+using ::android::base::unique_fd;
+namespace impl = ::aidl::android::hardware::radio::implementation;
+
+unique_fd openHostChannel(const char propertyName[]) {
+    char channelName[PROPERTY_VALUE_MAX];
+    if (::property_get(propertyName, channelName, nullptr) <= 0) {
+        return FAILURE_V(unique_fd(), "The '%s' property is not defined", propertyName);
+    }
+
+    const int fd = ::open(channelName, O_RDWR);
+    if (fd >= 0) {
+        return unique_fd(fd);
+    } else {
+        return FAILURE_V(unique_fd(), "Could not open '%s'", channelName);
+    }
+}
+
+std::string getInstanceName(const std::string_view descriptor,
+                            const std::string_view slot) {
+    std::string result(descriptor.data(), descriptor.size());
+    result.append(1, '/');
+    result.append(slot.data(), slot.size());
+    return result;
+}
+
+template <class S> std::shared_ptr<S> registerService(
+        const std::string_view instanceSuffix,
+        std::shared_ptr<impl::AtChannel> atChannel) {
+    auto serice = ndk::SharedRefBase::make<S>(std::move(atChannel));
+    const std::string instanceName = getInstanceName(S::descriptor, instanceSuffix);
+
+    if (AServiceManager_addService(serice->asBinder().get(),
+                                   instanceName.c_str()) != STATUS_OK) {
+        return FAILURE_V(nullptr, "Failed to register: '%s'",
+                         instanceName.c_str());
+    }
+
+    return serice;
+}
+
+template <class T> void addResponseSink(impl::AtChannel& atChannel,
+                                        const std::shared_ptr<T>& strongObject,
+                                        void(T::*method)(const impl::AtResponsePtr&)) {
+    std::weak_ptr<T> weakObject(strongObject);
+
+    atChannel.addResponseSink([weakObject = std::move(weakObject), method]
+                              (const impl::AtResponsePtr& response) -> bool {
+        if (const auto strongObject = weakObject.lock()) {
+            (*strongObject.*method)(response);
+            return true;
+        } else {
+            return false;
+        }
+    });
+}
+
+int mainImpl(impl::AtChannel::HostChannelFactory hostChannelFactory) {
+    using impl::AtChannel;
+    using impl::ImsMedia;
+    using impl::RadioConfig;
+    using impl::RadioData;
+    using impl::RadioIms;
+    using impl::RadioMessaging;
+    using impl::RadioModem;
+    using impl::RadioNetwork;
+    using impl::RadioSim;
+    using impl::RadioVoice;
+    using impl::Sap;
+
+    using namespace std::literals;
+
+    auto initSequence = [](const AtChannel::RequestPipe pipe,
+                           AtChannel::Conversation& conversation) -> bool {
+        static const std::string_view initCmds[] = {
+            "ATE0Q0V1"sv,
+            "AT+CMEE=1"sv,
+            "AT+CREG=2"sv,
+            "AT+CGREG=2"sv,
+            "AT+CEREG=2"sv,
+            "AT+CCWA=1"sv,
+            "AT+CMOD=0"sv,
+            "AT+CMUT=0"sv,
+            "AT+CSSN=0,1"sv,
+            "AT+COLP=0"sv,
+            "AT+CSCS=\"HEX\""sv,
+            "AT+CUSD=1"sv,
+            "AT+CGEREP=1,0"sv,
+            "AT+CMGF=0"sv,
+            "AT+CFUN?"sv,
+        };
+
+        for (const std::string_view& cmd : initCmds) {
+            using impl::AtResponse;
+            using impl::AtResponsePtr;
+            using OK = AtResponse::OK;
+
+            const AtResponsePtr response =
+                conversation(pipe, cmd,
+                             [](const AtResponse& response) -> bool {
+                                 return response.holds<OK>();
+                             });
+
+            if (!response) {
+                return false;
+            } else if (!response->isOK()) {
+                response->unexpected(__func__, "initSequence");
+                return false;
+            }
+        }
+
+        return true;
+    };
+
+    const auto atChannel = std::make_shared<AtChannel>(std::move(hostChannelFactory),
+                                                       std::move(initSequence));
+
+    static constexpr std::string_view kDefaultInstance = "default"sv;
+    static constexpr std::string_view kSlot1Instance = "slot1"sv;
+
+    ABinderProcess_setThreadPoolMaxThreadCount(2);
+    ABinderProcess_startThreadPool();
+
+    const auto imsMedia = registerService<ImsMedia>(kDefaultInstance, atChannel);
+    if (!imsMedia) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioConfig = registerService<RadioConfig>(kDefaultInstance, atChannel);
+    if (!radioConfig) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioData = registerService<RadioData>(kSlot1Instance, atChannel);
+    if (!radioData) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioIms = registerService<RadioIms>(kSlot1Instance, atChannel);
+    if (!radioIms) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioMessaging = registerService<RadioMessaging>(kSlot1Instance, atChannel);
+    if (!radioMessaging) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioModem = registerService<RadioModem>(kSlot1Instance, atChannel);
+    if (!radioModem) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioNetwork = registerService<RadioNetwork>(kSlot1Instance, atChannel);
+    if (!radioNetwork) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioSim = registerService<RadioSim>(kSlot1Instance, atChannel);
+    if (!radioNetwork) {
+        return EXIT_FAILURE;
+    }
+
+    const auto radioVoice = registerService<RadioVoice>(kSlot1Instance, atChannel);
+    if (!radioVoice) {
+        return EXIT_FAILURE;
+    }
+
+    const auto sap = registerService<Sap>(kSlot1Instance, atChannel);
+    if (!sap) {
+        return EXIT_FAILURE;
+    }
+
+    addResponseSink(*atChannel, imsMedia, &ImsMedia::atResponseSink);
+    addResponseSink(*atChannel, radioConfig, &RadioConfig::atResponseSink);
+    addResponseSink(*atChannel, radioData, &RadioData::atResponseSink);
+    addResponseSink(*atChannel, radioIms, &RadioIms::atResponseSink);
+    addResponseSink(*atChannel, radioMessaging, &RadioMessaging::atResponseSink);
+    addResponseSink(*atChannel, radioModem, &RadioModem::atResponseSink);
+    addResponseSink(*atChannel, radioNetwork, &RadioNetwork::atResponseSink);
+    addResponseSink(*atChannel, radioSim, &RadioSim::atResponseSink);
+    addResponseSink(*atChannel, radioVoice, &RadioVoice::atResponseSink);
+    addResponseSink(*atChannel, sap, &Sap::atResponseSink);
+
+    ABinderProcess_joinThreadPool();
+    return EXIT_FAILURE;    // joinThreadPool is not expected to return
+}
+}  // namespace
+
+int main(int /*argc*/, char** /*argv*/) {
+    return mainImpl([](){
+        return openHostChannel("vendor.qemu.vport.modem");
+    });
+}
diff --git a/hals/radio/makeRadioResponseInfo.cpp b/hals/radio/makeRadioResponseInfo.cpp
new file mode 100644
index 00000000..92f7a01f
--- /dev/null
+++ b/hals/radio/makeRadioResponseInfo.cpp
@@ -0,0 +1,51 @@
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
+#include <log/log_radio.h>
+
+#include "makeRadioResponseInfo.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+RadioResponseInfo makeRadioResponseInfo(const int32_t serial,
+                                        const RadioError e) {
+    return {
+        .type = RadioResponseType::SOLICITED,
+        .serial = serial,
+        .error = e,
+    };
+}
+
+RadioResponseInfo makeRadioResponseInfo(const int32_t serial) {
+    return makeRadioResponseInfo(serial, RadioError::NONE);
+}
+
+RadioResponseInfo makeRadioResponseInfoUnsupported(const int32_t serial,
+                                                   const char* const klass,
+                                                   const char* const method) {
+    RLOGE("%s::%s is not supported", klass, method);
+    return makeRadioResponseInfo(serial, RadioError::REQUEST_NOT_SUPPORTED);
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/makeRadioResponseInfo.h b/hals/radio/makeRadioResponseInfo.h
new file mode 100644
index 00000000..06edaab6
--- /dev/null
+++ b/hals/radio/makeRadioResponseInfo.h
@@ -0,0 +1,46 @@
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
+#include <aidl/android/hardware/radio/RadioResponseInfo.h>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+
+RadioResponseInfo makeRadioResponseInfo(int32_t serial);
+RadioResponseInfo makeRadioResponseInfo(int32_t serial, RadioError);
+RadioResponseInfo makeRadioResponseInfoUnsupported(int32_t serial,
+                                                   const char* klass,
+                                                   const char* method);
+
+static RadioResponseInfo makeRadioResponseInfoDeprecated(int32_t serial) {
+    return makeRadioResponseInfo(serial, RadioError::REQUEST_NOT_SUPPORTED);
+}
+
+// the same as makeRadioResponseInfo, but allows grepping
+static RadioResponseInfo makeRadioResponseInfoNOP(int32_t serial) {
+    return makeRadioResponseInfo(serial);
+}
+
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/radio/manifest.radio.xml b/hals/radio/manifest.radio.xml
similarity index 76%
rename from radio/manifest.radio.xml
rename to hals/radio/manifest.radio.xml
index d0a6cb61..763dac4c 100644
--- a/radio/manifest.radio.xml
+++ b/hals/radio/manifest.radio.xml
@@ -1,38 +1,51 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.radio.config</name>
+        <version>3</version>
         <fqname>IRadioConfig/default</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.data</name>
+        <version>3</version>
         <fqname>IRadioData/slot1</fqname>
     </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.ims</name>
+        <version>2</version>
+        <fqname>IRadioIms/slot1</fqname>
+    </hal>
     <hal format="aidl">
         <name>android.hardware.radio.messaging</name>
+        <version>3</version>
         <fqname>IRadioMessaging/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.modem</name>
+        <version>3</version>
         <fqname>IRadioModem/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.network</name>
+        <version>3</version>
         <fqname>IRadioNetwork/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.sim</name>
+        <version>3</version>
         <fqname>IRadioSim/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.voice</name>
+        <version>3</version>
         <fqname>IRadioVoice/slot1</fqname>
     </hal>
-    <hal format="aidl">
-        <name>android.hardware.radio.ims</name>
-        <fqname>IRadioIms/slot1</fqname>
-    </hal>
     <hal format="aidl">
         <name>android.hardware.radio.ims.media</name>
+        <version>2</version>
         <fqname>IImsMedia/default</fqname>
     </hal>
+    <hal format="aidl">
+        <name>android.hardware.radio.sap</name>
+        <fqname>ISap/slot1</fqname>
+    </hal>
 </manifest>
diff --git a/hals/radio/ratUtils.cpp b/hals/radio/ratUtils.cpp
new file mode 100644
index 00000000..94da856f
--- /dev/null
+++ b/hals/radio/ratUtils.cpp
@@ -0,0 +1,128 @@
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
+#include "ratUtils.h"
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace ratUtils {
+
+uint32_t supportedRadioTechBitmask(const ModemTechnology mtech) {
+    static constexpr uint32_t kTechsBitmask[] = {
+        kGSM, kWCDMA, kCDMA, kEVDO, kTDSCDMA, kLTE, kNR,
+    };
+
+    const size_t i = static_cast<size_t>(mtech);
+    if (i < (sizeof(kTechsBitmask) / sizeof(kTechsBitmask[0]))) {
+        return kTechsBitmask[i];
+    } else {
+        return 0;
+    }
+}
+
+RadioTechnology currentRadioTechnology(const ModemTechnology mtech) {
+    static constexpr RadioTechnology kCurrentTech[] = {
+        RadioTechnology::EDGE,
+        RadioTechnology::HSPA,
+        RadioTechnology::IS95B,
+        RadioTechnology::EVDO_B,
+        RadioTechnology::TD_SCDMA,
+        RadioTechnology::LTE,
+        RadioTechnology::NR,
+    };
+
+    const size_t i = static_cast<size_t>(mtech);
+    if (i < (sizeof(kCurrentTech) / sizeof(kCurrentTech[0]))) {
+        return kCurrentTech[i];
+    } else {
+        return RadioTechnology::EDGE;
+    }
+}
+
+ModemTechnology modemTechnologyFromRadioTechnologyBitmask(
+        const uint32_t radioTechnologyBitmask) {
+    if (radioTechnologyBitmask & kNR) {
+        return ModemTechnology::NR;
+    }
+    if (radioTechnologyBitmask & kLTE) {
+        return ModemTechnology::LTE;
+    }
+    if (radioTechnologyBitmask & kTDSCDMA) {
+        return ModemTechnology::TDSCDMA;
+    }
+    if (radioTechnologyBitmask & kEVDO) {
+        return ModemTechnology::EVDO;
+    }
+    if (radioTechnologyBitmask & kCDMA) {
+        return ModemTechnology::CDMA;
+    }
+    if (radioTechnologyBitmask & kWCDMA) {
+        return ModemTechnology::WCDMA;
+    }
+    return ModemTechnology::GSM;
+}
+
+uint32_t modemTechnologyBitmaskFromRadioTechnologyBitmask(
+    const uint32_t radioTechnologyBitmask) {
+    uint32_t modemTechnologyBitmask = 0;
+
+    const auto mtechBit = [](const ModemTechnology mtech){
+        return 1U << static_cast<unsigned>(mtech);
+    };
+
+    if (radioTechnologyBitmask & kNR) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::NR);
+    }
+    if (radioTechnologyBitmask & kLTE) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::LTE);
+    }
+    if (radioTechnologyBitmask & kTDSCDMA) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::TDSCDMA);
+    }
+    if (radioTechnologyBitmask & kEVDO) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::EVDO);
+    }
+    if (radioTechnologyBitmask & kCDMA) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::CDMA);
+    }
+    if (radioTechnologyBitmask & kWCDMA) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::WCDMA);
+    }
+
+    if (radioTechnologyBitmask & kGSM) {
+        modemTechnologyBitmask |=
+            mtechBit(ModemTechnology::GSM);
+    }
+
+    return modemTechnologyBitmask;
+}
+
+
+}  // namespace ratUtils
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/hals/radio/ratUtils.h b/hals/radio/ratUtils.h
new file mode 100644
index 00000000..4ec6e6ea
--- /dev/null
+++ b/hals/radio/ratUtils.h
@@ -0,0 +1,71 @@
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
+#include <cstdint>
+#include <aidl/android/hardware/radio/RadioTechnology.h>
+
+namespace aidl {
+namespace android {
+namespace hardware {
+namespace radio {
+namespace implementation {
+namespace ratUtils {
+
+constexpr uint32_t ratbit(const RadioTechnology r) {
+    return 1U << static_cast<unsigned>(r);
+}
+
+enum class ModemTechnology {
+    GSM, WCDMA, CDMA, EVDO, TDSCDMA, LTE, NR
+};
+
+constexpr uint32_t kGSM =   ratbit(RadioTechnology::GSM) |
+                            ratbit(RadioTechnology::GPRS) |
+                            ratbit(RadioTechnology::EDGE);
+constexpr uint32_t kWCDMA = ratbit(RadioTechnology::HSUPA) |
+                            ratbit(RadioTechnology::HSDPA) |
+                            ratbit(RadioTechnology::HSPA) |
+                            ratbit(RadioTechnology::HSPAP) |
+                            ratbit(RadioTechnology::UMTS);
+constexpr uint32_t kCDMA =  ratbit(RadioTechnology::IS95A) |
+                            ratbit(RadioTechnology::IS95B) |
+                            ratbit(RadioTechnology::ONE_X_RTT);
+constexpr uint32_t kEVDO =  ratbit(RadioTechnology::EVDO_0) |
+                            ratbit(RadioTechnology::EVDO_A) |
+                            ratbit(RadioTechnology::EVDO_B) |
+                            ratbit(RadioTechnology::EHRPD);
+constexpr uint32_t kTDSCDMA =
+                            ratbit(RadioTechnology::TD_SCDMA);
+constexpr uint32_t kLTE =   ratbit(RadioTechnology::LTE);
+constexpr uint32_t kNR =    ratbit(RadioTechnology::NR);
+
+uint32_t supportedRadioTechBitmask(const ModemTechnology mtech);
+RadioTechnology currentRadioTechnology(const ModemTechnology mtech);
+
+ModemTechnology modemTechnologyFromRadioTechnologyBitmask(
+    uint32_t radioTechnologyBitmask);
+
+uint32_t modemTechnologyBitmaskFromRadioTechnologyBitmask(
+    uint32_t radioTechnologyBitmask);
+
+}  // namespace ratUtils
+}  // namespace implementation
+}  // namespace radio
+}  // namespace hardware
+}  // namespace android
+}  // namespace aidl
diff --git a/sensors/Android.bp b/hals/sensors/Android.bp
similarity index 100%
rename from sensors/Android.bp
rename to hals/sensors/Android.bp
diff --git a/sensors/entry.cpp b/hals/sensors/entry.cpp
similarity index 100%
rename from sensors/entry.cpp
rename to hals/sensors/entry.cpp
diff --git a/sensors/hals.conf b/hals/sensors/hals.conf
similarity index 100%
rename from sensors/hals.conf
rename to hals/sensors/hals.conf
diff --git a/sensors/include/multihal_sensors.h b/hals/sensors/include/multihal_sensors.h
similarity index 100%
rename from sensors/include/multihal_sensors.h
rename to hals/sensors/include/multihal_sensors.h
diff --git a/sensors/include/multihal_sensors_transport.h b/hals/sensors/include/multihal_sensors_transport.h
similarity index 100%
rename from sensors/include/multihal_sensors_transport.h
rename to hals/sensors/include/multihal_sensors_transport.h
diff --git a/sensors/multihal_sensors.cpp b/hals/sensors/multihal_sensors.cpp
similarity index 100%
rename from sensors/multihal_sensors.cpp
rename to hals/sensors/multihal_sensors.cpp
diff --git a/sensors/multihal_sensors_epoll.cpp b/hals/sensors/multihal_sensors_epoll.cpp
similarity index 100%
rename from sensors/multihal_sensors_epoll.cpp
rename to hals/sensors/multihal_sensors_epoll.cpp
diff --git a/sensors/multihal_sensors_qemu.cpp b/hals/sensors/multihal_sensors_qemu.cpp
similarity index 100%
rename from sensors/multihal_sensors_qemu.cpp
rename to hals/sensors/multihal_sensors_qemu.cpp
diff --git a/sensors/sensor_list.cpp b/hals/sensors/sensor_list.cpp
similarity index 100%
rename from sensors/sensor_list.cpp
rename to hals/sensors/sensor_list.cpp
diff --git a/sensors/sensor_list.h b/hals/sensors/sensor_list.h
similarity index 100%
rename from sensors/sensor_list.h
rename to hals/sensors/sensor_list.h
diff --git a/init.ranchu-net.sh b/init.ranchu-net.sh
index 588f2104..8023d7b6 100755
--- a/init.ranchu-net.sh
+++ b/init.ranchu-net.sh
@@ -1,14 +1,12 @@
 #!/vendor/bin/sh
 
 # Check if VirtIO Wi-Fi is enabled. If so, create a mac80211_hwsim radio
-# and run the DHCP client
 wifi_virtio=`getprop ro.boot.qemu.virtiowifi`
 case "$wifi_virtio" in
     1) wifi_mac_prefix=`getprop vendor.net.wifi_mac_prefix`
       if [ -n "$wifi_mac_prefix" ]; then
           /vendor/bin/mac80211_create_radios 1 $wifi_mac_prefix || exit 1
       fi
-      setprop ctl.start dhcpclient_wifi
       ;;
 esac
 
diff --git a/init.ranchu.rc b/init.ranchu.rc
index 1df747f7..8596973e 100644
--- a/init.ranchu.rc
+++ b/init.ranchu.rc
@@ -128,16 +128,6 @@ service ranchu-net /vendor/bin/init.ranchu-net.sh
     oneshot
     disabled    # Started on post-fs-data
 
-service dhcpclient_wifi /vendor/bin/dhcpclient -i wlan0 --no-gateway
-    user root
-    group root
-    disabled
-
-service dhcpclient_def /vendor/bin/dhcpclient -i eth0 --no-gateway
-    user root
-    group root
-    disabled
-
 # The qemu-props program is used to set various system
 # properties on boot. It must be run early during the boot
 # process to avoid race conditions with other daemons that
diff --git a/input-mt/virtio_input_multi_touch_1.idc b/input-mt/virtio_input_multi_touch_1.idc
deleted file mode 100644
index f740c047..00000000
--- a/input-mt/virtio_input_multi_touch_1.idc
+++ /dev/null
@@ -1,7 +0,0 @@
-device.internal = 1
-
-touch.deviceType = touchScreen
-touch.orientationAware = 1
-
-cursor.mode = navigation
-cursor.orientationAware = 1
diff --git a/input-mt/virtio_input_multi_touch_2.idc b/input-mt/virtio_input_multi_touch_2.idc
deleted file mode 100644
index 8e1b02ab..00000000
--- a/input-mt/virtio_input_multi_touch_2.idc
+++ /dev/null
@@ -1,12 +0,0 @@
-device.internal = 1
-
-touch.deviceType = touchScreen
-touch.orientationAware = 1
-
-cursor.mode = navigation
-cursor.orientationAware = 1
-
-# This displayID matches the unique ID of the virtual display created for Emulator.
-# This will indicate to input flinger than it should link this input device
-# with the virtual display.
-touch.displayId = local:8140900251843329
diff --git a/input-mt/virtio_input_multi_touch_3.idc b/input-mt/virtio_input_multi_touch_3.idc
deleted file mode 100644
index 6a112404..00000000
--- a/input-mt/virtio_input_multi_touch_3.idc
+++ /dev/null
@@ -1,12 +0,0 @@
-device.internal = 1
-
-touch.deviceType = touchScreen
-touch.orientationAware = 1
-
-cursor.mode = navigation
-cursor.orientationAware = 1
-
-# This displayID matches the unique ID of the virtual display created for Emulator.
-# This will indicate to input flinger than it should link this input device
-# with the virtual display.
-touch.displayId = local:8140940453066754
diff --git a/input-mt/virtio_input_multi_touch_4.idc b/input-mt/virtio_input_multi_touch_4.idc
deleted file mode 100644
index 33302f5b..00000000
--- a/input-mt/virtio_input_multi_touch_4.idc
+++ /dev/null
@@ -1,12 +0,0 @@
-device.internal = 1
-
-touch.deviceType = touchScreen
-touch.orientationAware = 1
-
-cursor.mode = navigation
-cursor.orientationAware = 1
-
-# This displayID matches the unique ID of the virtual display created for Emulator.
-# This will indicate to input flinger than it should link this input device
-# with the virtual display.
-touch.displayId = local:3
diff --git a/input-mt/virtio_input_multi_touch_5.idc b/input-mt/virtio_input_multi_touch_5.idc
deleted file mode 100644
index e489bb1f..00000000
--- a/input-mt/virtio_input_multi_touch_5.idc
+++ /dev/null
@@ -1,12 +0,0 @@
-device.internal = 1
-
-touch.deviceType = touchScreen
-touch.orientationAware = 1
-
-cursor.mode = navigation
-cursor.orientationAware = 1
-
-# This displayID matches the unique ID of the virtual display created for Emulator.
-# This will indicate to input flinger than it should link this input device
-# with the virtual display.
-touch.displayId = local:4
diff --git a/manifest.xml b/manifest.xml
index b8b0d378..3d1fff70 100644
--- a/manifest.xml
+++ b/manifest.xml
@@ -1,2 +1,2 @@
-<manifest version="1.0" type="device" target-level="7">
+<manifest version="1.0" type="device" target-level="8">
 </manifest>
diff --git a/pc/images_source.prop_template b/pc/images_source.prop_template
index 69a88157..76d1d19e 100644
--- a/pc/images_source.prop_template
+++ b/pc/images_source.prop_template
@@ -1,6 +1,6 @@
 Pkg.Desc=System Image ${TARGET_CPU_ABI}.
 Pkg.Revision=1
-Pkg.Dependencies=emulator#33.1.19
+Pkg.Dependencies=emulator#${EMULATOR_MINIMAL_VERSION}
 AndroidVersion.ApiLevel=${PLATFORM_SDK_VERSION}
 AndroidVersion.CodeName=${PLATFORM_VERSION_CODENAME}
 SystemImage.Abi=${TARGET_CPU_ABI}
diff --git a/product/base_phone.mk b/product/base_phone.mk
index 02eee491..b630dd1e 100644
--- a/product/base_phone.mk
+++ b/product/base_phone.mk
@@ -15,7 +15,6 @@
 
 # the common file for phone.mk (AOSP) and gphone.mk (internal)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
 
 DEVICE_PACKAGE_OVERLAYS += device/generic/goldfish/phone/overlay
 PRODUCT_CHARACTERISTICS := emulator
diff --git a/product/generic.mk b/product/generic.mk
index dacce206..74504a66 100644
--- a/product/generic.mk
+++ b/product/generic.mk
@@ -13,6 +13,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+$(call inherit-product, device/generic/goldfish/product/versions.mk)
+
 #
 # This file is to configure vendor/data partitions of emulator-related products
 #
@@ -21,8 +23,9 @@ $(call inherit-product-if-exists, frameworks/native/build/phone-xhdpi-2048-dalvi
 # Enable Scoped Storage related
 $(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)
 
-PRODUCT_SHIPPING_API_LEVEL := 35
+ifneq ($(EMULATOR_VENDOR_NO_MANIFEST_FILE),true)
 DEVICE_MANIFEST_FILE += device/generic/goldfish/manifest.xml
+endif
 
 PRODUCT_SOONG_NAMESPACES += \
     device/generic/goldfish \
@@ -68,7 +71,6 @@ PRODUCT_VENDOR_PROPERTIES += \
     debug.stagefright.c2inputsurface=-1 \
     debug.stagefright.ccodec=4 \
     graphics.gpu.profiler.support=false \
-    persist.sys.usb.config="" \
     persist.sys.zram_enabled=1 \
     wifi.direct.interface=p2p-dev-wlan0 \
     wifi.interface=wlan0 \
@@ -112,23 +114,17 @@ PRODUCT_PACKAGES += android.hardware.graphics.allocator-service.ranchu
 endif
 
 ifneq ($(EMULATOR_DISABLE_RADIO),true)
-PRODUCT_PACKAGES += \
-    libcuttlefish-ril-2 \
-    libgoldfish-rild \
-    EmulatorRadioConfig \
-    EmulatorTetheringConfigOverlay
+PRODUCT_PACKAGES += android.hardware.radio-service.ranchu
 
-DEVICE_MANIFEST_FILE += device/generic/goldfish/radio/manifest.radio.xml
-DISABLE_RILD_OEM_HOOK := true
-# For customize cflags for libril share library building by soong.
-$(call soong_config_set,ril,disable_rild_oem_hook,true)
+# NR 5G, LTE, TD-SCDMA, CDMA, EVDO, GSM and WCDMA
+PRODUCT_VENDOR_PROPERTIES += ro.telephony.default_network=33
 
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/radio/init.system_ext.radio.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.system_ext.radio.rc \
-    device/generic/goldfish/radio/data/apns-conf.xml:$(TARGET_COPY_OUT_VENDOR)/etc/apns/apns-conf.xml \
-    device/generic/goldfish/radio/data/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim0.xml \
-    device/generic/goldfish/radio/data/numeric_operator.xml:data/misc/modem_simulator/etc/modem_simulator/files/numeric_operator.xml \
-    device/generic/goldfish/radio/EmulatorRadioConfig/radioconfig.xml:data/misc/emulator/config/radioconfig.xml \
+    device/generic/goldfish/hals/radio/init.system_ext.radio.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.system_ext.radio.rc \
+    device/generic/goldfish/hals/radio/data/apns-conf.xml:$(TARGET_COPY_OUT_VENDOR)/etc/apns/apns-conf.xml \
+    device/generic/goldfish/hals/radio/data/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim0.xml \
+    device/generic/goldfish/hals/radio/data/numeric_operator.xml:data/misc/modem_simulator/etc/modem_simulator/files/numeric_operator.xml \
+    device/generic/goldfish/hals/radio/EmulatorRadioConfig/radioconfig.xml:data/misc/emulator/config/radioconfig.xml \
     device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim_tel_alaska.xml \
     device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0_for_CtsCarrierApiTestCases.xml:data/misc/modem_simulator/iccprofile_for_carrierapitests.xml \
 
@@ -154,14 +150,15 @@ PRODUCT_PACKAGES += \
     libGLESv2_angle
 endif
 
+ifneq ($(EMULATOR_VENDOR_NO_THREADNETWORK), true)
 # Enable Thread Network HAL with simulation RCP
 PRODUCT_PACKAGES += \
     com.android.hardware.threadnetwork-simulation-rcp
+endif
 
 # Enable bluetooth
 PRODUCT_PACKAGES += \
     android.hardware.bluetooth-service.default \
-    android.hardware.bluetooth.audio-impl \
     bt_vhci_forwarder \
 
 # Bluetooth hardware properties.
@@ -174,6 +171,7 @@ PRODUCT_PACKAGES += \
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.keystore.app_attest_key.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.keystore.app_attest_key.xml
 
+ifneq ($(EMULATOR_VENDOR_NO_UWB),true)
 # Enable Uwb
 PRODUCT_PACKAGES += \
     com.android.hardware.uwb \
@@ -182,6 +180,7 @@ PRODUCT_PACKAGES += \
 PRODUCT_VENDOR_PROPERTIES += ro.vendor.uwb.dev=/dev/hvc2
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.uwb.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.uwb.xml
+endif
 
 ifneq ($(EMULATOR_VENDOR_NO_GNSS),true)
 PRODUCT_PACKAGES += android.hardware.gnss-service.ranchu
@@ -196,7 +195,7 @@ PRODUCT_PACKAGES += \
 # as prebuilt_etc. For now soong_namespace causes a build break because the fw
 # refers to our wifi HAL in random places.
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/sensors/hals.conf:$(TARGET_COPY_OUT_VENDOR)/etc/sensors/hals.conf
+    device/generic/goldfish/hals/sensors/hals.conf:$(TARGET_COPY_OUT_VENDOR)/etc/sensors/hals.conf
 endif
 
 ifneq ($(EMULATOR_VENDOR_NO_CAMERA),true)
@@ -214,18 +213,7 @@ PRODUCT_PACKAGES += \
     android.hardware.camera.full.prebuilt.xml \
     android.hardware.camera.raw.prebuilt.xml \
 
-ifeq (,$(filter %_arm64,$(TARGET_PRODUCT)))  # TARGET_ARCH is not available here
-CODECS_PERFORMANCE_C2_PROFILE := codecs_performance_c2.xml
-else
-CODECS_PERFORMANCE_C2_PROFILE := codecs_performance_c2_arm64.xml
-endif
-
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/camera/media/profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml \
-    device/generic/goldfish/camera/media/codecs_google_video_default.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_video.xml \
-    device/generic/goldfish/camera/media/codecs.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs.xml \
-    device/generic/goldfish/camera/media/codecs_performance.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance.xml \
-    device/generic/goldfish/camera/media/$(CODECS_PERFORMANCE_C2_PROFILE):$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance_c2.xml \
     hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_back.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_back.json \
     hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_front.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_front.json \
     hardware/google/camera/devices/EmulatedCamera/hwl/configs/emu_camera_depth.json:$(TARGET_COPY_OUT_VENDOR)/etc/config/emu_camera_depth.json \
@@ -238,11 +226,15 @@ PRODUCT_PACKAGES += \
     android.hardware.audio@7.1-impl.ranchu \
     android.hardware.audio.effect@7.0-impl \
 
-DEVICE_MANIFEST_FILE += device/generic/goldfish/audio/android.hardware.audio.effects@7.0.xml
+# Bluetooth Audio HAL
+PRODUCT_PACKAGES += \
+    android.hardware.bluetooth.audio-impl \
+
+DEVICE_MANIFEST_FILE += device/generic/goldfish/hals/audio/android.hardware.audio.effects@7.0.xml
 
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/audio/policy/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
-    device/generic/goldfish/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml \
+    device/generic/goldfish/hals/audio/policy/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
+    device/generic/goldfish/hals/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml \
     frameworks/av/services/audiopolicy/config/bluetooth_audio_policy_configuration_7_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_audio_policy_configuration_7_0.xml \
     frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
     frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
@@ -254,7 +246,6 @@ endif
 # WiFi: vendor side
 PRODUCT_PACKAGES += \
     mac80211_create_radios \
-    dhcpclient \
     hostapd \
     wpa_supplicant \
 
@@ -271,7 +262,6 @@ PRODUCT_PACKAGES += \
     android.hardware.lights-service.example \
     com.android.hardware.neuralnetworks \
     com.android.hardware.power \
-    com.android.hardware.rebootescrow \
     com.android.hardware.thermal \
     com.android.hardware.vibrator
 
@@ -281,6 +271,27 @@ ifneq ($(PRODUCT_IS_ATV_SDK),true)
         android.hardware.identity-service.example
 endif
 
+ifneq ($(EMULATOR_VENDOR_NO_REBOOT_ESCROW),true)
+PRODUCT_PACKAGES += \
+    com.android.hardware.rebootescrow
+endif
+
+ifeq (,$(filter %_arm64,$(TARGET_PRODUCT)))  # TARGET_ARCH is not available here
+CODECS_PERFORMANCE_C2_PROFILE := codecs_performance_c2.xml
+else
+CODECS_PERFORMANCE_C2_PROFILE := codecs_performance_c2_arm64.xml
+endif
+
+PRODUCT_COPY_FILES += \
+    frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_audio.xml \
+    frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_telephony.xml \
+    device/generic/goldfish/codecs/media/profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml \
+    device/generic/goldfish/codecs/media/codecs_google_video_default.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_video.xml \
+    device/generic/goldfish/codecs/media/codecs.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs.xml \
+    device/generic/goldfish/codecs/media/codecs_performance.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance.xml \
+    device/generic/goldfish/codecs/media/$(CODECS_PERFORMANCE_C2_PROFILE):$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance_c2.xml \
+
+
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/empty_data_disk:data/empty_data_disk \
     device/generic/goldfish/data/etc/dtb.img:dtb.img \
@@ -318,8 +329,6 @@ PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.wifi.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.xml \
     frameworks/native/data/etc/android.hardware.wifi.passpoint.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.passpoint.xml \
     frameworks/native/data/etc/android.hardware.wifi.direct.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.direct.xml \
-    frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_audio.xml \
-    frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_telephony.xml \
     frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml \
     frameworks/native/data/etc/android.hardware.vulkan.level-1.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.vulkan.level.xml \
     frameworks/native/data/etc/android.hardware.vulkan.compute-0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.vulkan.compute.xml \
diff --git a/Android.mk b/product/versions.mk
similarity index 81%
rename from Android.mk
rename to product/versions.mk
index efe0a3cb..221d8a99 100644
--- a/Android.mk
+++ b/product/versions.mk
@@ -1,5 +1,5 @@
 #
-# Copyright 2017 The Android Open Source Project
+# Copyright (C) 2024 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -12,8 +12,6 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
-#
-
-
-include device/generic/goldfish/tasks/emu_img_zip.mk
 
+PRODUCT_SHIPPING_API_LEVEL := 35
+EMULATOR_MINIMAL_VERSION := 35.2.10
diff --git a/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java b/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
index fb10e5c3..5aca7bce 100644
--- a/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
+++ b/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
@@ -22,6 +22,7 @@ import android.app.StatusBarManager;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.hardware.input.InputManager;
 import android.hardware.input.InputManagerGlobal;
 import android.hardware.input.KeyboardLayout;
 import android.location.LocationManager;
@@ -101,7 +102,7 @@ public abstract class ProvisionActivity extends Activity {
 
     protected void doProvision() {
         provisionWifi("AndroidWifi");
-        provisionKeyboard("qwerty2");
+        provisionKeyboard("qwerty2", SystemProperties.get("vendor.qemu.keyboard_layout"));
         provisionDisplay();
         provisionTelephony();
         provisionLocation();
@@ -139,16 +140,41 @@ public abstract class ProvisionActivity extends Activity {
     }
 
     // Set physical keyboard layout based on the system property set by emulator host.
-    protected void provisionKeyboard(final String deviceName) {
-        Settings.Secure.putInt(getContentResolver(), Settings.Secure.SHOW_IME_WITH_HARD_KEYBOARD, 1);
-
-        final String layoutName = SystemProperties.get("vendor.qemu.keyboard_layout");
+    protected void provisionKeyboard(final String deviceName, final String layoutName) {
         final InputDevice device = getKeyboardDevice(deviceName);
         if (device != null && !layoutName.isEmpty()) {
             setKeyboardLayout(device, layoutName);
         }
     }
 
+    protected InputDevice getKeyboardDevice(final String keyboardDeviceName) {
+        final int[] deviceIds = InputDevice.getDeviceIds();
+
+        for (int deviceId : deviceIds) {
+            InputDevice inputDevice = InputDevice.getDevice(deviceId);
+            if (inputDevice != null
+                    && inputDevice.supportsSource(InputDevice.SOURCE_KEYBOARD)
+                    && inputDevice.getName().equals(keyboardDeviceName)) {
+                return inputDevice;
+            }
+        }
+
+        return null;
+    }
+
+    protected void setKeyboardLayout(final InputDevice keyboardDevice, final String layoutName) {
+        final InputManager im = getApplicationContext().getSystemService(InputManager.class);
+        final KeyboardLayout[] keyboardLayouts = im.getKeyboardLayouts();
+
+        for (KeyboardLayout keyboardLayout : keyboardLayouts) {
+            if (keyboardLayout.getDescriptor().endsWith(layoutName)) {
+                InputManagerGlobal.getInstance().setKeyboardLayoutOverrideForInputDevice(
+                        keyboardDevice.getIdentifier(), keyboardLayout.getDescriptor());
+                return;
+            }
+        }
+    }
+
     protected void provisionDisplay() {
         Settings.Global.putInt(getContentResolver(), Settings.Global.STAY_ON_WHILE_PLUGGED_IN, 1);
 
@@ -201,11 +227,6 @@ public abstract class ProvisionActivity extends Activity {
     }
 
     protected void provisionTelephony() {
-        // b/193418404
-        // the following blocks, TODO: find out why and fix it. disable this for now.
-        // TelephonyManager mTelephony = getApplicationContext().getSystemService(TelephonyManager.class);
-        // mTelephony.setPreferredNetworkTypeBitmask(TelephonyManager.NETWORK_TYPE_BITMASK_NR);
-
         provisionMockModem();
     }
 
@@ -224,36 +245,6 @@ public abstract class ProvisionActivity extends Activity {
         Settings.Global.putInt(getContentResolver(), Settings.Global.PACKAGE_VERIFIER_INCLUDE_ADB, 0);
     }
 
-    protected InputDevice getKeyboardDevice(final String keyboardDeviceName) {
-        final int[] deviceIds = InputDevice.getDeviceIds();
-
-        for (int deviceId : deviceIds) {
-            InputDevice inputDevice = InputDevice.getDevice(deviceId);
-            if (inputDevice != null
-                    && inputDevice.supportsSource(InputDevice.SOURCE_KEYBOARD)
-                    && inputDevice.getName().equals(keyboardDeviceName)) {
-                return inputDevice;
-            }
-        }
-
-        return null;
-    }
-
-    protected void setKeyboardLayout(final InputDevice keyboardDevice, final String layoutName) {
-        final InputManagerGlobal im = InputManagerGlobal.getInstance();
-
-        final KeyboardLayout[] keyboardLayouts =
-                im.getKeyboardLayoutsForInputDevice(keyboardDevice.getIdentifier());
-
-        for (KeyboardLayout keyboardLayout : keyboardLayouts) {
-            if (keyboardLayout.getDescriptor().endsWith(layoutName)) {
-                im.setCurrentKeyboardLayoutForInputDevice(
-                        keyboardDevice.getIdentifier(), keyboardLayout.getDescriptor());
-                return;
-            }
-        }
-    }
-
     protected boolean provisionRequired() {
         return Settings.Global.getInt(getContentResolver(), Settings.Global.DEVICE_PROVISIONED, 0) != 1;
     }
diff --git a/radio/Android.bp b/radio/Android.bp
deleted file mode 100644
index d1cc13be..00000000
--- a/radio/Android.bp
+++ /dev/null
@@ -1,14 +0,0 @@
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_generic_goldfish_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    default_applicable_licenses: ["device_generic_goldfish_license"],
-}
-
-cc_library_headers {
-    name: "goldfish_ril_headers",
-    vendor: true,
-    export_include_dirs: ["include"],
-}
diff --git a/radio/include/telephony/ril.h b/radio/include/telephony/ril.h
deleted file mode 100644
index 7895a60e..00000000
--- a/radio/include/telephony/ril.h
+++ /dev/null
@@ -1,7377 +0,0 @@
-/*
- * Copyright (C) 2006 The Android Open Source Project
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
-#ifndef ANDROID_RIL_H
-#define ANDROID_RIL_H 1
-
-#include <stdlib.h>
-#include <stdint.h>
-#include <telephony/ril_cdma_sms.h>
-#include <telephony/ril_nv_items.h>
-
-#ifndef FEATURE_UNIT_TEST
-#include <sys/time.h>
-#endif /* !FEATURE_UNIT_TEST */
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-#ifndef SIM_COUNT
-#if defined(ANDROID_SIM_COUNT_2)
-#define SIM_COUNT 2
-#elif defined(ANDROID_SIM_COUNT_3)
-#define SIM_COUNT 3
-#elif defined(ANDROID_SIM_COUNT_4)
-#define SIM_COUNT 4
-#else
-#define SIM_COUNT 1
-#endif
-
-#ifndef ANDROID_MULTI_SIM
-#define SIM_COUNT 1
-#endif
-#endif
-
-/*
- * RIL version.
- * Value of RIL_VERSION should not be changed in future. Here onwards,
- * when a new change is supposed to be introduced  which could involve new
- * schemes added like Wakelocks, data structures added/updated, etc, we would
- * just document RIL version associated with that change below. When OEM updates its
- * RIL with those changes, they would return that new RIL version during RIL_REGISTER.
- * We should make use of the returned version by vendor to identify appropriate scheme
- * or data structure version to use.
- *
- * Documentation of RIL version and associated changes
- * RIL_VERSION = 12 : This version corresponds to updated data structures namely
- *                    RIL_Data_Call_Response_v11, RIL_SIM_IO_v6, RIL_CardStatus_v6,
- *                    RIL_SimRefreshResponse_v7, RIL_CDMA_CallWaiting_v6,
- *                    RIL_LTE_SignalStrength_v8, RIL_SignalStrength_v10, RIL_CellIdentityGsm_v12
- *                    RIL_CellIdentityWcdma_v12, RIL_CellIdentityLte_v12,RIL_CellInfoGsm_v12,
- *                    RIL_CellInfoWcdma_v12, RIL_CellInfoLte_v12, RIL_CellInfo_v12.
- *
- * RIL_VERSION = 13 : This version includes new wakelock semantics and as the first
- *                    strongly versioned version it enforces structure use.
- *
- * RIL_VERSION = 14 : New data structures are added, namely RIL_CarrierMatchType,
- *                    RIL_Carrier, RIL_CarrierRestrictions and RIL_PCO_Data.
- *                    New commands added: RIL_REQUEST_SET_CARRIER_RESTRICTIONS,
- *                    RIL_REQUEST_SET_CARRIER_RESTRICTIONS and RIL_UNSOL_PCO_DATA.
- *
- * RIL_VERSION = 15 : New commands added:
- *                    RIL_UNSOL_MODEM_RESTART,
- *                    RIL_REQUEST_SEND_DEVICE_STATE,
- *                    RIL_REQUEST_SET_UNSOLICITED_RESPONSE_FILTER,
- *                    RIL_REQUEST_SET_SIM_CARD_POWER,
- *                    RIL_REQUEST_SET_CARRIER_INFO_IMSI_ENCRYPTION,
- *                    RIL_UNSOL_CARRIER_INFO_IMSI_ENCRYPTION
- *                    The new parameters for RIL_REQUEST_SETUP_DATA_CALL,
- *                    Updated data structures: RIL_DataProfileInfo_v15, RIL_InitialAttachApn_v15
- *                    New data structure RIL_DataRegistrationStateResponse,
- *                    RIL_VoiceRegistrationStateResponse same is
- *                    used in RIL_REQUEST_DATA_REGISTRATION_STATE and
- *                    RIL_REQUEST_VOICE_REGISTRATION_STATE respectively.
- *                    New data structure RIL_OpenChannelParams.
- *                    RIL_REQUEST_START_NETWORK_SCAN
- *                    RIL_REQUEST_STOP_NETWORK_SCAN
- *                    RIL_UNSOL_NETWORK_SCAN_RESULT
- */
-#define RIL_VERSION 12
-#define LAST_IMPRECISE_RIL_VERSION 12 // Better self-documented name
-#define RIL_VERSION_MIN 6 /* Minimum RIL_VERSION supported */
-
-#define CDMA_ALPHA_INFO_BUFFER_LENGTH 64
-#define CDMA_NUMBER_INFO_BUFFER_LENGTH 81
-
-#define MAX_RILDS 3
-#define MAX_SERVICE_NAME_LENGTH 6
-#define MAX_CLIENT_ID_LENGTH 2
-#define MAX_DEBUG_SOCKET_NAME_LENGTH 12
-#define MAX_QEMU_PIPE_NAME_LENGTH  11
-#define MAX_UUID_LENGTH 64
-#define MAX_BANDS 8
-#define MAX_CHANNELS 32
-#define MAX_RADIO_ACCESS_NETWORKS 8
-#define MAX_BROADCAST_SMS_CONFIG_INFO 25
-
-
-typedef void * RIL_Token;
-
-typedef enum {
-    RIL_SOCKET_1,
-#if (SIM_COUNT >= 2)
-    RIL_SOCKET_2,
-#if (SIM_COUNT >= 3)
-    RIL_SOCKET_3,
-#endif
-#if (SIM_COUNT >= 4)
-    RIL_SOCKET_4,
-#endif
-#endif
-    RIL_SOCKET_NUM
-} RIL_SOCKET_ID;
-
-
-typedef enum {
-    RIL_E_SUCCESS = 0,
-    RIL_E_RADIO_NOT_AVAILABLE = 1,     /* If radio did not start or is resetting */
-    RIL_E_GENERIC_FAILURE = 2,
-    RIL_E_PASSWORD_INCORRECT = 3,      /* for PIN/PIN2 methods only! */
-    RIL_E_SIM_PIN2 = 4,                /* Operation requires SIM PIN2 to be entered */
-    RIL_E_SIM_PUK2 = 5,                /* Operation requires SIM PIN2 to be entered */
-    RIL_E_REQUEST_NOT_SUPPORTED = 6,
-    RIL_E_CANCELLED = 7,
-    RIL_E_OP_NOT_ALLOWED_DURING_VOICE_CALL = 8, /* data ops are not allowed during voice
-                                                   call on a Class C GPRS device */
-    RIL_E_OP_NOT_ALLOWED_BEFORE_REG_TO_NW = 9,  /* data ops are not allowed before device
-                                                   registers in network */
-    RIL_E_SMS_SEND_FAIL_RETRY = 10,             /* fail to send sms and need retry */
-    RIL_E_SIM_ABSENT = 11,                      /* fail to set the location where CDMA subscription
-                                                   shall be retrieved because of SIM or RUIM
-                                                   card absent */
-    RIL_E_SUBSCRIPTION_NOT_AVAILABLE = 12,      /* fail to find CDMA subscription from specified
-                                                   location */
-    RIL_E_MODE_NOT_SUPPORTED = 13,              /* HW does not support preferred network type */
-    RIL_E_FDN_CHECK_FAILURE = 14,               /* command failed because recipient is not on FDN list */
-    RIL_E_ILLEGAL_SIM_OR_ME = 15,               /* network selection failed due to
-                                                   illegal SIM or ME */
-    RIL_E_MISSING_RESOURCE = 16,                /* no logical channel available */
-    RIL_E_NO_SUCH_ELEMENT = 17,                  /* application not found on SIM */
-    RIL_E_DIAL_MODIFIED_TO_USSD = 18,           /* DIAL request modified to USSD */
-    RIL_E_DIAL_MODIFIED_TO_SS = 19,             /* DIAL request modified to SS */
-    RIL_E_DIAL_MODIFIED_TO_DIAL = 20,           /* DIAL request modified to DIAL with different
-                                                   data */
-    RIL_E_USSD_MODIFIED_TO_DIAL = 21,           /* USSD request modified to DIAL */
-    RIL_E_USSD_MODIFIED_TO_SS = 22,             /* USSD request modified to SS */
-    RIL_E_USSD_MODIFIED_TO_USSD = 23,           /* USSD request modified to different USSD
-                                                   request */
-    RIL_E_SS_MODIFIED_TO_DIAL = 24,             /* SS request modified to DIAL */
-    RIL_E_SS_MODIFIED_TO_USSD = 25,             /* SS request modified to USSD */
-    RIL_E_SUBSCRIPTION_NOT_SUPPORTED = 26,      /* Subscription not supported by RIL */
-    RIL_E_SS_MODIFIED_TO_SS = 27,               /* SS request modified to different SS request */
-    RIL_E_LCE_NOT_SUPPORTED = 36,               /* LCE service not supported(36 in RILConstants.java) */
-    RIL_E_NO_MEMORY = 37,                       /* Not sufficient memory to process the request */
-    RIL_E_INTERNAL_ERR = 38,                    /* Modem hit unexpected error scenario while handling
-                                                   this request */
-    RIL_E_SYSTEM_ERR = 39,                      /* Hit platform or system error */
-    RIL_E_MODEM_ERR = 40,                       /* Vendor RIL got unexpected or incorrect response
-                                                   from modem for this request */
-    RIL_E_INVALID_STATE = 41,                   /* Unexpected request for the current state */
-    RIL_E_NO_RESOURCES = 42,                    /* Not sufficient resource to process the request */
-    RIL_E_SIM_ERR = 43,                         /* Received error from SIM card */
-    RIL_E_INVALID_ARGUMENTS = 44,               /* Received invalid arguments in request */
-    RIL_E_INVALID_SIM_STATE = 45,               /* Can not process the request in current SIM state */
-    RIL_E_INVALID_MODEM_STATE = 46,             /* Can not process the request in current Modem state */
-    RIL_E_INVALID_CALL_ID = 47,                 /* Received invalid call id in request */
-    RIL_E_NO_SMS_TO_ACK = 48,                   /* ACK received when there is no SMS to ack */
-    RIL_E_NETWORK_ERR = 49,                     /* Received error from network */
-    RIL_E_REQUEST_RATE_LIMITED = 50,            /* Operation denied due to overly-frequent requests */
-    RIL_E_SIM_BUSY = 51,                        /* SIM is busy */
-    RIL_E_SIM_FULL = 52,                        /* The target EF is full */
-    RIL_E_NETWORK_REJECT = 53,                  /* Request is rejected by network */
-    RIL_E_OPERATION_NOT_ALLOWED = 54,           /* Not allowed the request now */
-    RIL_E_EMPTY_RECORD = 55,                    /* The request record is empty */
-    RIL_E_INVALID_SMS_FORMAT = 56,              /* Invalid sms format */
-    RIL_E_ENCODING_ERR = 57,                    /* Message not encoded properly */
-    RIL_E_INVALID_SMSC_ADDRESS = 58,            /* SMSC address specified is invalid */
-    RIL_E_NO_SUCH_ENTRY = 59,                   /* No such entry present to perform the request */
-    RIL_E_NETWORK_NOT_READY = 60,               /* Network is not ready to perform the request */
-    RIL_E_NOT_PROVISIONED = 61,                 /* Device doesnot have this value provisioned */
-    RIL_E_NO_SUBSCRIPTION = 62,                 /* Device doesnot have subscription */
-    RIL_E_NO_NETWORK_FOUND = 63,                /* Network cannot be found */
-    RIL_E_DEVICE_IN_USE = 64,                   /* Operation cannot be performed because the device
-                                                   is currently in use */
-    RIL_E_ABORTED = 65,                         /* Operation aborted */
-    RIL_E_INVALID_RESPONSE = 66,                /* Invalid response sent by vendor code */
-    // OEM specific error codes. To be used by OEM when they don't want to reveal
-    // specific error codes which would be replaced by Generic failure.
-    RIL_E_OEM_ERROR_1 = 501,
-    RIL_E_OEM_ERROR_2 = 502,
-    RIL_E_OEM_ERROR_3 = 503,
-    RIL_E_OEM_ERROR_4 = 504,
-    RIL_E_OEM_ERROR_5 = 505,
-    RIL_E_OEM_ERROR_6 = 506,
-    RIL_E_OEM_ERROR_7 = 507,
-    RIL_E_OEM_ERROR_8 = 508,
-    RIL_E_OEM_ERROR_9 = 509,
-    RIL_E_OEM_ERROR_10 = 510,
-    RIL_E_OEM_ERROR_11 = 511,
-    RIL_E_OEM_ERROR_12 = 512,
-    RIL_E_OEM_ERROR_13 = 513,
-    RIL_E_OEM_ERROR_14 = 514,
-    RIL_E_OEM_ERROR_15 = 515,
-    RIL_E_OEM_ERROR_16 = 516,
-    RIL_E_OEM_ERROR_17 = 517,
-    RIL_E_OEM_ERROR_18 = 518,
-    RIL_E_OEM_ERROR_19 = 519,
-    RIL_E_OEM_ERROR_20 = 520,
-    RIL_E_OEM_ERROR_21 = 521,
-    RIL_E_OEM_ERROR_22 = 522,
-    RIL_E_OEM_ERROR_23 = 523,
-    RIL_E_OEM_ERROR_24 = 524,
-    RIL_E_OEM_ERROR_25 = 525
-} RIL_Errno;
-
-typedef enum {
-    RIL_CALL_ACTIVE = 0,
-    RIL_CALL_HOLDING = 1,
-    RIL_CALL_DIALING = 2,    /* MO call only */
-    RIL_CALL_ALERTING = 3,   /* MO call only */
-    RIL_CALL_INCOMING = 4,   /* MT call only */
-    RIL_CALL_WAITING = 5     /* MT call only */
-} RIL_CallState;
-
-typedef enum {
-    RADIO_STATE_OFF = 0,                   /* Radio explictly powered off (eg CFUN=0) */
-    RADIO_STATE_UNAVAILABLE = 1,           /* Radio unavailable (eg, resetting or not booted) */
-    RADIO_STATE_ON = 10                    /* Radio is on */
-} RIL_RadioState;
-
-typedef enum {
-    RADIO_TECH_UNKNOWN = 0,
-    RADIO_TECH_GPRS = 1,
-    RADIO_TECH_EDGE = 2,
-    RADIO_TECH_UMTS = 3,
-    RADIO_TECH_IS95A = 4,
-    RADIO_TECH_IS95B = 5,
-    RADIO_TECH_1xRTT =  6,
-    RADIO_TECH_EVDO_0 = 7,
-    RADIO_TECH_EVDO_A = 8,
-    RADIO_TECH_HSDPA = 9,
-    RADIO_TECH_HSUPA = 10,
-    RADIO_TECH_HSPA = 11,
-    RADIO_TECH_EVDO_B = 12,
-    RADIO_TECH_EHRPD = 13,
-    RADIO_TECH_LTE = 14,
-    RADIO_TECH_HSPAP = 15, // HSPA+
-    RADIO_TECH_GSM = 16, // Only supports voice
-    RADIO_TECH_TD_SCDMA = 17,
-    RADIO_TECH_IWLAN = 18,
-    RADIO_TECH_LTE_CA = 19
-} RIL_RadioTechnology;
-
-typedef enum {
-    RAF_UNKNOWN =  (1 <<  RADIO_TECH_UNKNOWN),
-    RAF_GPRS = (1 << RADIO_TECH_GPRS),
-    RAF_EDGE = (1 << RADIO_TECH_EDGE),
-    RAF_UMTS = (1 << RADIO_TECH_UMTS),
-    RAF_IS95A = (1 << RADIO_TECH_IS95A),
-    RAF_IS95B = (1 << RADIO_TECH_IS95B),
-    RAF_1xRTT = (1 << RADIO_TECH_1xRTT),
-    RAF_EVDO_0 = (1 << RADIO_TECH_EVDO_0),
-    RAF_EVDO_A = (1 << RADIO_TECH_EVDO_A),
-    RAF_HSDPA = (1 << RADIO_TECH_HSDPA),
-    RAF_HSUPA = (1 << RADIO_TECH_HSUPA),
-    RAF_HSPA = (1 << RADIO_TECH_HSPA),
-    RAF_EVDO_B = (1 << RADIO_TECH_EVDO_B),
-    RAF_EHRPD = (1 << RADIO_TECH_EHRPD),
-    RAF_LTE = (1 << RADIO_TECH_LTE),
-    RAF_HSPAP = (1 << RADIO_TECH_HSPAP),
-    RAF_GSM = (1 << RADIO_TECH_GSM),
-    RAF_TD_SCDMA = (1 << RADIO_TECH_TD_SCDMA),
-    RAF_LTE_CA = (1 << RADIO_TECH_LTE_CA)
-} RIL_RadioAccessFamily;
-
-typedef enum {
-    BAND_MODE_UNSPECIFIED = 0,      //"unspecified" (selected by baseband automatically)
-    BAND_MODE_EURO = 1,             //"EURO band" (GSM-900 / DCS-1800 / WCDMA-IMT-2000)
-    BAND_MODE_USA = 2,              //"US band" (GSM-850 / PCS-1900 / WCDMA-850 / WCDMA-PCS-1900)
-    BAND_MODE_JPN = 3,              //"JPN band" (WCDMA-800 / WCDMA-IMT-2000)
-    BAND_MODE_AUS = 4,              //"AUS band" (GSM-900 / DCS-1800 / WCDMA-850 / WCDMA-IMT-2000)
-    BAND_MODE_AUS_2 = 5,            //"AUS band 2" (GSM-900 / DCS-1800 / WCDMA-850)
-    BAND_MODE_CELL_800 = 6,         //"Cellular" (800-MHz Band)
-    BAND_MODE_PCS = 7,              //"PCS" (1900-MHz Band)
-    BAND_MODE_JTACS = 8,            //"Band Class 3" (JTACS Band)
-    BAND_MODE_KOREA_PCS = 9,        //"Band Class 4" (Korean PCS Band)
-    BAND_MODE_5_450M = 10,          //"Band Class 5" (450-MHz Band)
-    BAND_MODE_IMT2000 = 11,         //"Band Class 6" (2-GMHz IMT2000 Band)
-    BAND_MODE_7_700M_2 = 12,        //"Band Class 7" (Upper 700-MHz Band)
-    BAND_MODE_8_1800M = 13,         //"Band Class 8" (1800-MHz Band)
-    BAND_MODE_9_900M = 14,          //"Band Class 9" (900-MHz Band)
-    BAND_MODE_10_800M_2 = 15,       //"Band Class 10" (Secondary 800-MHz Band)
-    BAND_MODE_EURO_PAMR_400M = 16,  //"Band Class 11" (400-MHz European PAMR Band)
-    BAND_MODE_AWS = 17,             //"Band Class 15" (AWS Band)
-    BAND_MODE_USA_2500M = 18        //"Band Class 16" (US 2.5-GHz Band)
-} RIL_RadioBandMode;
-
-typedef enum {
-    RC_PHASE_CONFIGURED = 0,  // LM is configured is initial value and value after FINISH completes
-    RC_PHASE_START      = 1,  // START is sent before Apply and indicates that an APPLY will be
-                              // forthcoming with these same parameters
-    RC_PHASE_APPLY      = 2,  // APPLY is sent after all LM's receive START and returned
-                              // RIL_RadioCapability.status = 0, if any START's fail no
-                              // APPLY will be sent
-    RC_PHASE_UNSOL_RSP  = 3,  // UNSOL_RSP is sent with RIL_UNSOL_RADIO_CAPABILITY
-    RC_PHASE_FINISH     = 4   // FINISH is sent after all commands have completed. If an error
-                              // occurs in any previous command the RIL_RadioAccessesFamily and
-                              // logicalModemUuid fields will be the prior configuration thus
-                              // restoring the configuration to the previous value. An error
-                              // returned by this command will generally be ignored or may
-                              // cause that logical modem to be removed from service.
-} RadioCapabilityPhase;
-
-typedef enum {
-    RC_STATUS_NONE       = 0, // This parameter has no meaning with RC_PHASE_START,
-                              // RC_PHASE_APPLY
-    RC_STATUS_SUCCESS    = 1, // Tell modem the action transaction of set radio
-                              // capability was success with RC_PHASE_FINISH
-    RC_STATUS_FAIL       = 2, // Tell modem the action transaction of set radio
-                              // capability is fail with RC_PHASE_FINISH.
-} RadioCapabilityStatus;
-
-#define RIL_RADIO_CAPABILITY_VERSION 1
-typedef struct {
-    int version;            // Version of structure, RIL_RADIO_CAPABILITY_VERSION
-    int session;            // Unique session value defined by framework returned in all "responses/unsol"
-    int phase;              // CONFIGURED, START, APPLY, FINISH
-    int rat;                // RIL_RadioAccessFamily for the radio
-    char logicalModemUuid[MAX_UUID_LENGTH]; // A UUID typically "com.xxxx.lmX where X is the logical modem.
-    int status;             // Return status and an input parameter for RC_PHASE_FINISH
-} RIL_RadioCapability;
-
-// Do we want to split Data from Voice and the use
-// RIL_RadioTechnology for get/setPreferredVoice/Data ?
-typedef enum {
-    PREF_NET_TYPE_GSM_WCDMA                = 0, /* GSM/WCDMA (WCDMA preferred) */
-    PREF_NET_TYPE_GSM_ONLY                 = 1, /* GSM only */
-    PREF_NET_TYPE_WCDMA                    = 2, /* WCDMA  */
-    PREF_NET_TYPE_GSM_WCDMA_AUTO           = 3, /* GSM/WCDMA (auto mode, according to PRL) */
-    PREF_NET_TYPE_CDMA_EVDO_AUTO           = 4, /* CDMA and EvDo (auto mode, according to PRL) */
-    PREF_NET_TYPE_CDMA_ONLY                = 5, /* CDMA only */
-    PREF_NET_TYPE_EVDO_ONLY                = 6, /* EvDo only */
-    PREF_NET_TYPE_GSM_WCDMA_CDMA_EVDO_AUTO = 7, /* GSM/WCDMA, CDMA, and EvDo (auto mode, according to PRL) */
-    PREF_NET_TYPE_LTE_CDMA_EVDO            = 8, /* LTE, CDMA and EvDo */
-    PREF_NET_TYPE_LTE_GSM_WCDMA            = 9, /* LTE, GSM/WCDMA */
-    PREF_NET_TYPE_LTE_CMDA_EVDO_GSM_WCDMA  = 10, /* LTE, CDMA, EvDo, GSM/WCDMA */
-    PREF_NET_TYPE_LTE_ONLY                 = 11, /* LTE only */
-    PREF_NET_TYPE_LTE_WCDMA                = 12,  /* LTE/WCDMA */
-    PREF_NET_TYPE_TD_SCDMA_ONLY            = 13, /* TD-SCDMA only */
-    PREF_NET_TYPE_TD_SCDMA_WCDMA           = 14, /* TD-SCDMA and WCDMA */
-    PREF_NET_TYPE_TD_SCDMA_LTE             = 15, /* TD-SCDMA and LTE */
-    PREF_NET_TYPE_TD_SCDMA_GSM             = 16, /* TD-SCDMA and GSM */
-    PREF_NET_TYPE_TD_SCDMA_GSM_LTE         = 17, /* TD-SCDMA,GSM and LTE */
-    PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA       = 18, /* TD-SCDMA, GSM/WCDMA */
-    PREF_NET_TYPE_TD_SCDMA_WCDMA_LTE       = 19, /* TD-SCDMA, WCDMA and LTE */
-    PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA_LTE   = 20, /* TD-SCDMA, GSM/WCDMA and LTE */
-    PREF_NET_TYPE_TD_SCDMA_GSM_WCDMA_CDMA_EVDO_AUTO  = 21, /* TD-SCDMA, GSM/WCDMA, CDMA and EvDo */
-    PREF_NET_TYPE_TD_SCDMA_LTE_CDMA_EVDO_GSM_WCDMA   = 22  /* TD-SCDMA, LTE, CDMA, EvDo GSM/WCDMA */
-} RIL_PreferredNetworkType;
-
-/* Source for cdma subscription */
-typedef enum {
-   CDMA_SUBSCRIPTION_SOURCE_RUIM_SIM = 0,
-   CDMA_SUBSCRIPTION_SOURCE_NV = 1
-} RIL_CdmaSubscriptionSource;
-
-/* User-to-User signaling Info activation types derived from 3GPP 23.087 v8.0 */
-typedef enum {
-    RIL_UUS_TYPE1_IMPLICIT = 0,
-    RIL_UUS_TYPE1_REQUIRED = 1,
-    RIL_UUS_TYPE1_NOT_REQUIRED = 2,
-    RIL_UUS_TYPE2_REQUIRED = 3,
-    RIL_UUS_TYPE2_NOT_REQUIRED = 4,
-    RIL_UUS_TYPE3_REQUIRED = 5,
-    RIL_UUS_TYPE3_NOT_REQUIRED = 6
-} RIL_UUS_Type;
-
-/* User-to-User Signaling Information data coding schemes. Possible values for
- * Octet 3 (Protocol Discriminator field) in the UUIE. The values have been
- * specified in section 10.5.4.25 of 3GPP TS 24.008 */
-typedef enum {
-    RIL_UUS_DCS_USP = 0,          /* User specified protocol */
-    RIL_UUS_DCS_OSIHLP = 1,       /* OSI higher layer protocol */
-    RIL_UUS_DCS_X244 = 2,         /* X.244 */
-    RIL_UUS_DCS_RMCF = 3,         /* Reserved for system mangement
-                                     convergence function */
-    RIL_UUS_DCS_IA5c = 4          /* IA5 characters */
-} RIL_UUS_DCS;
-
-/* User-to-User Signaling Information defined in 3GPP 23.087 v8.0
- * This data is passed in RIL_ExtensionRecord and rec contains this
- * structure when type is RIL_UUS_INFO_EXT_REC */
-typedef struct {
-  RIL_UUS_Type    uusType;    /* UUS Type */
-  RIL_UUS_DCS     uusDcs;     /* UUS Data Coding Scheme */
-  int             uusLength;  /* Length of UUS Data */
-  char *          uusData;    /* UUS Data */
-} RIL_UUS_Info;
-
-/* CDMA Signal Information Record as defined in C.S0005 section 3.7.5.5 */
-typedef struct {
-  char isPresent;    /* non-zero if signal information record is present */
-  char signalType;   /* as defined 3.7.5.5-1 */
-  char alertPitch;   /* as defined 3.7.5.5-2 */
-  char signal;       /* as defined 3.7.5.5-3, 3.7.5.5-4 or 3.7.5.5-5 */
-} RIL_CDMA_SignalInfoRecord;
-
-typedef struct {
-    RIL_CallState   state;
-    int             index;      /* Connection Index for use with, eg, AT+CHLD */
-    int             toa;        /* type of address, eg 145 = intl */
-    char            isMpty;     /* nonzero if is mpty call */
-    char            isMT;       /* nonzero if call is mobile terminated */
-    char            als;        /* ALS line indicator if available
-                                   (0 = line 1) */
-    char            isVoice;    /* nonzero if this is is a voice call */
-    char            isVoicePrivacy;     /* nonzero if CDMA voice privacy mode is active */
-    char *          number;     /* Remote party number */
-    int             numberPresentation; /* 0=Allowed, 1=Restricted, 2=Not Specified/Unknown 3=Payphone */
-    char *          name;       /* Remote party name */
-    int             namePresentation; /* 0=Allowed, 1=Restricted, 2=Not Specified/Unknown 3=Payphone */
-    RIL_UUS_Info *  uusInfo;    /* NULL or Pointer to User-User Signaling Information */
-} RIL_Call;
-
-/* Deprecated, use RIL_Data_Call_Response_v6 */
-typedef struct {
-    int             cid;        /* Context ID, uniquely identifies this call */
-    int             active;     /* 0=inactive, 1=active/physical link down, 2=active/physical link up */
-    char *          type;       /* One of the PDP_type values in TS 27.007 section 10.1.1.
-                                   For example, "IP", "IPV6", "IPV4V6", or "PPP". */
-    char *          apn;        /* ignored */
-    char *          address;    /* An address, e.g., "192.0.1.3" or "2001:db8::1". */
-} RIL_Data_Call_Response_v4;
-
-/*
- * Returned by RIL_REQUEST_SETUP_DATA_CALL, RIL_REQUEST_DATA_CALL_LIST
- * and RIL_UNSOL_DATA_CALL_LIST_CHANGED, on error status != 0.
- */
-typedef struct {
-    int             status;     /* A RIL_DataCallFailCause, 0 which is PDP_FAIL_NONE if no error */
-    int             suggestedRetryTime; /* If status != 0, this fields indicates the suggested retry
-                                           back-off timer value RIL wants to override the one
-                                           pre-configured in FW.
-                                           The unit is miliseconds.
-                                           The value < 0 means no value is suggested.
-                                           The value 0 means retry should be done ASAP.
-                                           The value of INT_MAX(0x7fffffff) means no retry. */
-    int             cid;        /* Context ID, uniquely identifies this call */
-    int             active;     /* 0=inactive, 1=active/physical link down, 2=active/physical link up */
-    char *          type;       /* One of the PDP_type values in TS 27.007 section 10.1.1.
-                                   For example, "IP", "IPV6", "IPV4V6", or "PPP". If status is
-                                   PDP_FAIL_ONLY_SINGLE_BEARER_ALLOWED this is the type supported
-                                   such as "IP" or "IPV6" */
-    char *          ifname;     /* The network interface name */
-    char *          addresses;  /* A space-delimited list of addresses with optional "/" prefix length,
-                                   e.g., "192.0.1.3" or "192.0.1.11/16 2001:db8::1/64".
-                                   May not be empty, typically 1 IPv4 or 1 IPv6 or
-                                   one of each. If the prefix length is absent the addresses
-                                   are assumed to be point to point with IPv4 having a prefix
-                                   length of 32 and IPv6 128. */
-    char *          dnses;      /* A space-delimited list of DNS server addresses,
-                                   e.g., "192.0.1.3" or "192.0.1.11 2001:db8::1".
-                                   May be empty. */
-    char *          gateways;   /* A space-delimited list of default gateway addresses,
-                                   e.g., "192.0.1.3" or "192.0.1.11 2001:db8::1".
-                                   May be empty in which case the addresses represent point
-                                   to point connections. */
-} RIL_Data_Call_Response_v6;
-
-typedef struct {
-    int             status;     /* A RIL_DataCallFailCause, 0 which is PDP_FAIL_NONE if no error */
-    int             suggestedRetryTime; /* If status != 0, this fields indicates the suggested retry
-                                           back-off timer value RIL wants to override the one
-                                           pre-configured in FW.
-                                           The unit is miliseconds.
-                                           The value < 0 means no value is suggested.
-                                           The value 0 means retry should be done ASAP.
-                                           The value of INT_MAX(0x7fffffff) means no retry. */
-    int             cid;        /* Context ID, uniquely identifies this call */
-    int             active;     /* 0=inactive, 1=active/physical link down, 2=active/physical link up */
-    char *          type;       /* One of the PDP_type values in TS 27.007 section 10.1.1.
-                                   For example, "IP", "IPV6", "IPV4V6", or "PPP". If status is
-                                   PDP_FAIL_ONLY_SINGLE_BEARER_ALLOWED this is the type supported
-                                   such as "IP" or "IPV6" */
-    char *          ifname;     /* The network interface name */
-    char *          addresses;  /* A space-delimited list of addresses with optional "/" prefix length,
-                                   e.g., "192.0.1.3" or "192.0.1.11/16 2001:db8::1/64".
-                                   May not be empty, typically 1 IPv4 or 1 IPv6 or
-                                   one of each. If the prefix length is absent the addresses
-                                   are assumed to be point to point with IPv4 having a prefix
-                                   length of 32 and IPv6 128. */
-    char *          dnses;      /* A space-delimited list of DNS server addresses,
-                                   e.g., "192.0.1.3" or "192.0.1.11 2001:db8::1".
-                                   May be empty. */
-    char *          gateways;   /* A space-delimited list of default gateway addresses,
-                                   e.g., "192.0.1.3" or "192.0.1.11 2001:db8::1".
-                                   May be empty in which case the addresses represent point
-                                   to point connections. */
-    char *          pcscf;    /* the Proxy Call State Control Function address
-                                 via PCO(Protocol Configuration Option) for IMS client. */
-} RIL_Data_Call_Response_v9;
-
-typedef struct {
-    int             status;     /* A RIL_DataCallFailCause, 0 which is PDP_FAIL_NONE if no error */
-    int             suggestedRetryTime; /* If status != 0, this fields indicates the suggested retry
-                                           back-off timer value RIL wants to override the one
-                                           pre-configured in FW.
-                                           The unit is miliseconds.
-                                           The value < 0 means no value is suggested.
-                                           The value 0 means retry should be done ASAP.
-                                           The value of INT_MAX(0x7fffffff) means no retry. */
-    int             cid;        /* Context ID, uniquely identifies this call */
-    int             active;     /* 0=inactive, 1=active/physical link down, 2=active/physical link up */
-    char *          type;       /* One of the PDP_type values in TS 27.007 section 10.1.1.
-                                   For example, "IP", "IPV6", "IPV4V6", or "PPP". If status is
-                                   PDP_FAIL_ONLY_SINGLE_BEARER_ALLOWED this is the type supported
-                                   such as "IP" or "IPV6" */
-    char *          ifname;     /* The network interface name */
-    char *          addresses;  /* A space-delimited list of addresses with optional "/" prefix length,
-                                   e.g., "192.0.1.3" or "192.0.1.11/16 2001:db8::1/64".
-                                   May not be empty, typically 1 IPv4 or 1 IPv6 or
-                                   one of each. If the prefix length is absent the addresses
-                                   are assumed to be point to point with IPv4 having a prefix
-                                   length of 32 and IPv6 128. */
-    char *          dnses;      /* A space-delimited list of DNS server addresses,
-                                   e.g., "192.0.1.3" or "192.0.1.11 2001:db8::1".
-                                   May be empty. */
-    char *          gateways;   /* A space-delimited list of default gateway addresses,
-                                   e.g., "192.0.1.3" or "192.0.1.11 2001:db8::1".
-                                   May be empty in which case the addresses represent point
-                                   to point connections. */
-    char *          pcscf;    /* the Proxy Call State Control Function address
-                                 via PCO(Protocol Configuration Option) for IMS client. */
-    int             mtu;        /* MTU received from network
-                                   Value <= 0 means network has either not sent a value or
-                                   sent an invalid value */
-} RIL_Data_Call_Response_v11;
-
-typedef enum {
-    RADIO_TECH_3GPP = 1, /* 3GPP Technologies - GSM, WCDMA */
-    RADIO_TECH_3GPP2 = 2 /* 3GPP2 Technologies - CDMA */
-} RIL_RadioTechnologyFamily;
-
-typedef struct {
-    RIL_RadioTechnologyFamily tech;
-    unsigned char             retry;       /* 0 == not retry, nonzero == retry */
-    int                       messageRef;  /* Valid field if retry is set to nonzero.
-                                              Contains messageRef from RIL_SMS_Response
-                                              corresponding to failed MO SMS.
-                                            */
-
-    union {
-        /* Valid field if tech is RADIO_TECH_3GPP2. See RIL_REQUEST_CDMA_SEND_SMS */
-        RIL_CDMA_SMS_Message* cdmaMessage;
-
-        /* Valid field if tech is RADIO_TECH_3GPP. See RIL_REQUEST_SEND_SMS */
-        char**                gsmMessage;   /* This is an array of pointers where pointers
-                                               are contiguous but elements pointed by those pointers
-                                               are not contiguous
-                                            */
-    } message;
-} RIL_IMS_SMS_Message;
-
-typedef struct {
-    int messageRef;   /* TP-Message-Reference for GSM,
-                         and BearerData MessageId for CDMA
-                         (See 3GPP2 C.S0015-B, v2.0, table 4.5-1). */
-    char *ackPDU;     /* or NULL if n/a */
-    int errorCode;    /* See 3GPP 27.005, 3.2.5 for GSM/UMTS,
-                         3GPP2 N.S0005 (IS-41C) Table 171 for CDMA,
-                         -1 if unknown or not applicable*/
-} RIL_SMS_Response;
-
-/** Used by RIL_REQUEST_WRITE_SMS_TO_SIM */
-typedef struct {
-    int status;     /* Status of message.  See TS 27.005 3.1, "<stat>": */
-                    /*      0 = "REC UNREAD"    */
-                    /*      1 = "REC READ"      */
-                    /*      2 = "STO UNSENT"    */
-                    /*      3 = "STO SENT"      */
-    char * pdu;     /* PDU of message to write, as an ASCII hex string less the SMSC address,
-                       the TP-layer length is "strlen(pdu)/2". */
-    char * smsc;    /* SMSC address in GSM BCD format prefixed by a length byte
-                       (as expected by TS 27.005) or NULL for default SMSC */
-} RIL_SMS_WriteArgs;
-
-/** Used by RIL_REQUEST_DIAL */
-typedef struct {
-    char * address;
-    int clir;
-            /* (same as 'n' paremeter in TS 27.007 7.7 "+CLIR"
-             * clir == 0 on "use subscription default value"
-             * clir == 1 on "CLIR invocation" (restrict CLI presentation)
-             * clir == 2 on "CLIR suppression" (allow CLI presentation)
-             */
-    RIL_UUS_Info *  uusInfo;    /* NULL or Pointer to User-User Signaling Information */
-} RIL_Dial;
-
-typedef struct {
-    int command;    /* one of the commands listed for TS 27.007 +CRSM*/
-    int fileid;     /* EF id */
-    char *path;     /* "pathid" from TS 27.007 +CRSM command.
-                       Path is in hex asciii format eg "7f205f70"
-                       Path must always be provided.
-                     */
-    int p1;
-    int p2;
-    int p3;
-    char *data;     /* May be NULL*/
-    char *pin2;     /* May be NULL*/
-} RIL_SIM_IO_v5;
-
-typedef struct {
-    int command;    /* one of the commands listed for TS 27.007 +CRSM*/
-    int fileid;     /* EF id */
-    char *path;     /* "pathid" from TS 27.007 +CRSM command.
-                       Path is in hex asciii format eg "7f205f70"
-                       Path must always be provided.
-                     */
-    int p1;
-    int p2;
-    int p3;
-    char *data;     /* May be NULL*/
-    char *pin2;     /* May be NULL*/
-    char *aidPtr;   /* AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value. */
-} RIL_SIM_IO_v6;
-
-/* Used by RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL and
- * RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC. */
-typedef struct {
-    int sessionid;  /* "sessionid" from TS 27.007 +CGLA command. Should be
-                       ignored for +CSIM command. */
-
-    /* Following fields are used to derive the APDU ("command" and "length"
-       values in TS 27.007 +CSIM and +CGLA commands). */
-    int cla;
-    int instruction;
-    int p1;
-    int p2;
-    int p3;         /* A negative P3 implies a 4 byte APDU. */
-    char *data;     /* May be NULL. In hex string format. */
-} RIL_SIM_APDU;
-
-typedef struct {
-    int sw1;
-    int sw2;
-    char *simResponse;  /* In hex string format ([a-fA-F0-9]*), except for SIM_AUTHENTICATION
-                           response for which it is in Base64 format, see 3GPP TS 31.102 7.1.2 */
-} RIL_SIM_IO_Response;
-
-/* See also com.android.internal.telephony.gsm.CallForwardInfo */
-
-typedef struct {
-    int             status;     /*
-                                 * For RIL_REQUEST_QUERY_CALL_FORWARD_STATUS
-                                 * status 1 = active, 0 = not active
-                                 *
-                                 * For RIL_REQUEST_SET_CALL_FORWARD:
-                                 * status is:
-                                 * 0 = disable
-                                 * 1 = enable
-                                 * 2 = interrogate
-                                 * 3 = registeration
-                                 * 4 = erasure
-                                 */
-
-    int             reason;      /* from TS 27.007 7.11 "reason" */
-    int             serviceClass;/* From 27.007 +CCFC/+CLCK "class"
-                                    See table for Android mapping from
-                                    MMI service code
-                                    0 means user doesn't input class */
-    int             toa;         /* "type" from TS 27.007 7.11 */
-    char *          number;      /* "number" from TS 27.007 7.11. May be NULL */
-    int             timeSeconds; /* for CF no reply only */
-}RIL_CallForwardInfo;
-
-typedef struct {
-   char * cid;         /* Combination of LAC and Cell Id in 32 bits in GSM.
-                        * Upper 16 bits is LAC and lower 16 bits
-                        * is CID (as described in TS 27.005)
-                        * Primary Scrambling Code (as described in TS 25.331)
-                        *         in 9 bits in UMTS
-                        * Valid values are hexadecimal 0x0000 - 0xffffffff.
-                        */
-   int    rssi;        /* Received RSSI in GSM,
-                        * Level index of CPICH Received Signal Code Power in UMTS
-                        */
-} RIL_NeighboringCell;
-
-typedef struct {
-  char lce_status;                 /* LCE service status:
-                                    * -1 = not supported;
-                                    * 0 = stopped;
-                                    * 1 = active.
-                                    */
-  unsigned int actual_interval_ms; /* actual LCE reporting interval,
-                                    * meaningful only if LCEStatus = 1.
-                                    */
-} RIL_LceStatusInfo;
-
-typedef struct {
-  unsigned int last_hop_capacity_kbps; /* last-hop cellular capacity: kilobits/second. */
-  unsigned char confidence_level;      /* capacity estimate confidence: 0-100 */
-  unsigned char lce_suspended;         /* LCE report going to be suspended? (e.g., radio
-                                        * moves to inactive state or network type change)
-                                        * 1 = suspended;
-                                        * 0 = not suspended.
-                                        */
-} RIL_LceDataInfo;
-
-typedef enum {
-    RIL_MATCH_ALL = 0,          /* Apply to all carriers with the same mcc/mnc */
-    RIL_MATCH_SPN = 1,          /* Use SPN and mcc/mnc to identify the carrier */
-    RIL_MATCH_IMSI_PREFIX = 2,  /* Use IMSI prefix and mcc/mnc to identify the carrier */
-    RIL_MATCH_GID1 = 3,         /* Use GID1 and mcc/mnc to identify the carrier */
-    RIL_MATCH_GID2 = 4,         /* Use GID2 and mcc/mnc to identify the carrier */
-} RIL_CarrierMatchType;
-
-typedef struct {
-    const char * mcc;
-    const char * mnc;
-    RIL_CarrierMatchType match_type;   /* Specify match type for the carrier.
-                                        * If it’s RIL_MATCH_ALL, match_data is null;
-                                        * otherwise, match_data is the value for the match type.
-                                        */
-    const char * match_data;
-} RIL_Carrier;
-
-typedef struct {
-  int32_t len_allowed_carriers;         /* length of array allowed_carriers */
-  int32_t len_excluded_carriers;        /* length of array excluded_carriers */
-  RIL_Carrier * allowed_carriers;       /* list of allowed carriers */
-  RIL_Carrier * excluded_carriers;      /* list of explicitly excluded carriers
-                                         * which match allowed_carriers. Eg. allowed_carriers match
-                                         * mcc/mnc, excluded_carriers has same mcc/mnc and gid1
-                                         * is ABCD. It means except the carrier whose gid1 is ABCD,
-                                         * all carriers with the same mcc/mnc are allowed.
-                                         */
-} RIL_CarrierRestrictions;
-
-typedef struct {
-  char * mcc;                         /* MCC of the Carrier. */
-  char * mnc ;                        /* MNC of the Carrier. */
-  uint8_t * carrierKey;               /* Public Key from the Carrier used to encrypt the
-                                       * IMSI/IMPI.
-                                       */
-  int32_t carrierKeyLength;            /* Length of the Public Key. */
-  char * keyIdentifier;               /* The keyIdentifier Attribute value pair that helps
-                                       * a server locate the private key to decrypt the
-                                       * permanent identity.
-                                       */
-  int64_t expirationTime;             /* Date-Time (in UTC) when the key will expire. */
-
-} RIL_CarrierInfoForImsiEncryption;
-
-/* See RIL_REQUEST_LAST_CALL_FAIL_CAUSE */
-typedef enum {
-    CALL_FAIL_UNOBTAINABLE_NUMBER = 1,
-    CALL_FAIL_NO_ROUTE_TO_DESTINATION = 3,
-    CALL_FAIL_CHANNEL_UNACCEPTABLE = 6,
-    CALL_FAIL_OPERATOR_DETERMINED_BARRING = 8,
-    CALL_FAIL_NORMAL = 16,
-    CALL_FAIL_BUSY = 17,
-    CALL_FAIL_NO_USER_RESPONDING = 18,
-    CALL_FAIL_NO_ANSWER_FROM_USER = 19,
-    CALL_FAIL_CALL_REJECTED = 21,
-    CALL_FAIL_NUMBER_CHANGED = 22,
-    CALL_FAIL_PREEMPTION = 25,
-    CALL_FAIL_DESTINATION_OUT_OF_ORDER = 27,
-    CALL_FAIL_INVALID_NUMBER_FORMAT = 28,
-    CALL_FAIL_FACILITY_REJECTED = 29,
-    CALL_FAIL_RESP_TO_STATUS_ENQUIRY = 30,
-    CALL_FAIL_NORMAL_UNSPECIFIED = 31,
-    CALL_FAIL_CONGESTION = 34,
-    CALL_FAIL_NETWORK_OUT_OF_ORDER = 38,
-    CALL_FAIL_TEMPORARY_FAILURE = 41,
-    CALL_FAIL_SWITCHING_EQUIPMENT_CONGESTION = 42,
-    CALL_FAIL_ACCESS_INFORMATION_DISCARDED = 43,
-    CALL_FAIL_REQUESTED_CIRCUIT_OR_CHANNEL_NOT_AVAILABLE = 44,
-    CALL_FAIL_RESOURCES_UNAVAILABLE_OR_UNSPECIFIED = 47,
-    CALL_FAIL_QOS_UNAVAILABLE = 49,
-    CALL_FAIL_REQUESTED_FACILITY_NOT_SUBSCRIBED = 50,
-    CALL_FAIL_INCOMING_CALLS_BARRED_WITHIN_CUG = 55,
-    CALL_FAIL_BEARER_CAPABILITY_NOT_AUTHORIZED = 57,
-    CALL_FAIL_BEARER_CAPABILITY_UNAVAILABLE = 58,
-    CALL_FAIL_SERVICE_OPTION_NOT_AVAILABLE = 63,
-    CALL_FAIL_BEARER_SERVICE_NOT_IMPLEMENTED = 65,
-    CALL_FAIL_ACM_LIMIT_EXCEEDED = 68,
-    CALL_FAIL_REQUESTED_FACILITY_NOT_IMPLEMENTED = 69,
-    CALL_FAIL_ONLY_DIGITAL_INFORMATION_BEARER_AVAILABLE = 70,
-    CALL_FAIL_SERVICE_OR_OPTION_NOT_IMPLEMENTED = 79,
-    CALL_FAIL_INVALID_TRANSACTION_IDENTIFIER = 81,
-    CALL_FAIL_USER_NOT_MEMBER_OF_CUG = 87,
-    CALL_FAIL_INCOMPATIBLE_DESTINATION = 88,
-    CALL_FAIL_INVALID_TRANSIT_NW_SELECTION = 91,
-    CALL_FAIL_SEMANTICALLY_INCORRECT_MESSAGE = 95,
-    CALL_FAIL_INVALID_MANDATORY_INFORMATION = 96,
-    CALL_FAIL_MESSAGE_TYPE_NON_IMPLEMENTED = 97,
-    CALL_FAIL_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE = 98,
-    CALL_FAIL_INFORMATION_ELEMENT_NON_EXISTENT = 99,
-    CALL_FAIL_CONDITIONAL_IE_ERROR = 100,
-    CALL_FAIL_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE = 101,
-    CALL_FAIL_RECOVERY_ON_TIMER_EXPIRED = 102,
-    CALL_FAIL_PROTOCOL_ERROR_UNSPECIFIED = 111,
-    CALL_FAIL_INTERWORKING_UNSPECIFIED = 127,
-    CALL_FAIL_CALL_BARRED = 240,
-    CALL_FAIL_FDN_BLOCKED = 241,
-    CALL_FAIL_IMSI_UNKNOWN_IN_VLR = 242,
-    CALL_FAIL_IMEI_NOT_ACCEPTED = 243,
-    CALL_FAIL_DIAL_MODIFIED_TO_USSD = 244, /* STK Call Control */
-    CALL_FAIL_DIAL_MODIFIED_TO_SS = 245,
-    CALL_FAIL_DIAL_MODIFIED_TO_DIAL = 246,
-    CALL_FAIL_RADIO_OFF = 247, /* Radio is OFF */
-    CALL_FAIL_OUT_OF_SERVICE = 248, /* No cellular coverage */
-    CALL_FAIL_NO_VALID_SIM = 249, /* No valid SIM is present */
-    CALL_FAIL_RADIO_INTERNAL_ERROR = 250, /* Internal error at Modem */
-    CALL_FAIL_NETWORK_RESP_TIMEOUT = 251, /* No response from network */
-    CALL_FAIL_NETWORK_REJECT = 252, /* Explicit network reject */
-    CALL_FAIL_RADIO_ACCESS_FAILURE = 253, /* RRC connection failure. Eg.RACH */
-    CALL_FAIL_RADIO_LINK_FAILURE = 254, /* Radio Link Failure */
-    CALL_FAIL_RADIO_LINK_LOST = 255, /* Radio link lost due to poor coverage */
-    CALL_FAIL_RADIO_UPLINK_FAILURE = 256, /* Radio uplink failure */
-    CALL_FAIL_RADIO_SETUP_FAILURE = 257, /* RRC connection setup failure */
-    CALL_FAIL_RADIO_RELEASE_NORMAL = 258, /* RRC connection release, normal */
-    CALL_FAIL_RADIO_RELEASE_ABNORMAL = 259, /* RRC connection release, abnormal */
-    CALL_FAIL_ACCESS_CLASS_BLOCKED = 260, /* Access class barring */
-    CALL_FAIL_NETWORK_DETACH = 261, /* Explicit network detach */
-    CALL_FAIL_CDMA_LOCKED_UNTIL_POWER_CYCLE = 1000,
-    CALL_FAIL_CDMA_DROP = 1001,
-    CALL_FAIL_CDMA_INTERCEPT = 1002,
-    CALL_FAIL_CDMA_REORDER = 1003,
-    CALL_FAIL_CDMA_SO_REJECT = 1004,
-    CALL_FAIL_CDMA_RETRY_ORDER = 1005,
-    CALL_FAIL_CDMA_ACCESS_FAILURE = 1006,
-    CALL_FAIL_CDMA_PREEMPTED = 1007,
-    CALL_FAIL_CDMA_NOT_EMERGENCY = 1008, /* For non-emergency number dialed
-                                            during emergency callback mode */
-    CALL_FAIL_CDMA_ACCESS_BLOCKED = 1009, /* CDMA network access probes blocked */
-
-    /* OEM specific error codes. Used to distinguish error from
-     * CALL_FAIL_ERROR_UNSPECIFIED and help assist debugging */
-    CALL_FAIL_OEM_CAUSE_1 = 0xf001,
-    CALL_FAIL_OEM_CAUSE_2 = 0xf002,
-    CALL_FAIL_OEM_CAUSE_3 = 0xf003,
-    CALL_FAIL_OEM_CAUSE_4 = 0xf004,
-    CALL_FAIL_OEM_CAUSE_5 = 0xf005,
-    CALL_FAIL_OEM_CAUSE_6 = 0xf006,
-    CALL_FAIL_OEM_CAUSE_7 = 0xf007,
-    CALL_FAIL_OEM_CAUSE_8 = 0xf008,
-    CALL_FAIL_OEM_CAUSE_9 = 0xf009,
-    CALL_FAIL_OEM_CAUSE_10 = 0xf00a,
-    CALL_FAIL_OEM_CAUSE_11 = 0xf00b,
-    CALL_FAIL_OEM_CAUSE_12 = 0xf00c,
-    CALL_FAIL_OEM_CAUSE_13 = 0xf00d,
-    CALL_FAIL_OEM_CAUSE_14 = 0xf00e,
-    CALL_FAIL_OEM_CAUSE_15 = 0xf00f,
-
-    CALL_FAIL_ERROR_UNSPECIFIED = 0xffff /* This error will be deprecated soon,
-                                            vendor code should make sure to map error
-                                            code to specific error */
-} RIL_LastCallFailCause;
-
-typedef struct {
-  RIL_LastCallFailCause cause_code;
-  char *                vendor_cause;
-} RIL_LastCallFailCauseInfo;
-
-/* See RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE */
-typedef enum {
-    PDP_FAIL_NONE = 0, /* No error, connection ok */
-
-    /* an integer cause code defined in TS 24.008
-       section 6.1.3.1.3 or TS 24.301 Release 8+ Annex B.
-       If the implementation does not have access to the exact cause codes,
-       then it should return one of the following values,
-       as the UI layer needs to distinguish these
-       cases for error notification and potential retries. */
-    PDP_FAIL_OPERATOR_BARRED = 0x08,               /* no retry */
-    PDP_FAIL_NAS_SIGNALLING = 0x0E,
-    PDP_FAIL_LLC_SNDCP = 0x19,
-    PDP_FAIL_INSUFFICIENT_RESOURCES = 0x1A,
-    PDP_FAIL_MISSING_UKNOWN_APN = 0x1B,            /* no retry */
-    PDP_FAIL_UNKNOWN_PDP_ADDRESS_TYPE = 0x1C,      /* no retry */
-    PDP_FAIL_USER_AUTHENTICATION = 0x1D,           /* no retry */
-    PDP_FAIL_ACTIVATION_REJECT_GGSN = 0x1E,        /* no retry */
-    PDP_FAIL_ACTIVATION_REJECT_UNSPECIFIED = 0x1F,
-    PDP_FAIL_SERVICE_OPTION_NOT_SUPPORTED = 0x20,  /* no retry */
-    PDP_FAIL_SERVICE_OPTION_NOT_SUBSCRIBED = 0x21, /* no retry */
-    PDP_FAIL_SERVICE_OPTION_OUT_OF_ORDER = 0x22,
-    PDP_FAIL_NSAPI_IN_USE = 0x23,                  /* no retry */
-    PDP_FAIL_REGULAR_DEACTIVATION = 0x24,          /* possibly restart radio,
-                                                      based on framework config */
-    PDP_FAIL_QOS_NOT_ACCEPTED = 0x25,
-    PDP_FAIL_NETWORK_FAILURE = 0x26,
-    PDP_FAIL_UMTS_REACTIVATION_REQ = 0x27,
-    PDP_FAIL_FEATURE_NOT_SUPP = 0x28,
-    PDP_FAIL_TFT_SEMANTIC_ERROR = 0x29,
-    PDP_FAIL_TFT_SYTAX_ERROR = 0x2A,
-    PDP_FAIL_UNKNOWN_PDP_CONTEXT = 0x2B,
-    PDP_FAIL_FILTER_SEMANTIC_ERROR = 0x2C,
-    PDP_FAIL_FILTER_SYTAX_ERROR = 0x2D,
-    PDP_FAIL_PDP_WITHOUT_ACTIVE_TFT = 0x2E,
-    PDP_FAIL_ONLY_IPV4_ALLOWED = 0x32,             /* no retry */
-    PDP_FAIL_ONLY_IPV6_ALLOWED = 0x33,             /* no retry */
-    PDP_FAIL_ONLY_SINGLE_BEARER_ALLOWED = 0x34,
-    PDP_FAIL_ESM_INFO_NOT_RECEIVED = 0x35,
-    PDP_FAIL_PDN_CONN_DOES_NOT_EXIST = 0x36,
-    PDP_FAIL_MULTI_CONN_TO_SAME_PDN_NOT_ALLOWED = 0x37,
-    PDP_FAIL_MAX_ACTIVE_PDP_CONTEXT_REACHED = 0x41,
-    PDP_FAIL_UNSUPPORTED_APN_IN_CURRENT_PLMN = 0x42,
-    PDP_FAIL_INVALID_TRANSACTION_ID = 0x51,
-    PDP_FAIL_MESSAGE_INCORRECT_SEMANTIC = 0x5F,
-    PDP_FAIL_INVALID_MANDATORY_INFO = 0x60,
-    PDP_FAIL_MESSAGE_TYPE_UNSUPPORTED = 0x61,
-    PDP_FAIL_MSG_TYPE_NONCOMPATIBLE_STATE = 0x62,
-    PDP_FAIL_UNKNOWN_INFO_ELEMENT = 0x63,
-    PDP_FAIL_CONDITIONAL_IE_ERROR = 0x64,
-    PDP_FAIL_MSG_AND_PROTOCOL_STATE_UNCOMPATIBLE = 0x65,
-    PDP_FAIL_PROTOCOL_ERRORS = 0x6F,             /* no retry */
-    PDP_FAIL_APN_TYPE_CONFLICT = 0x70,
-    PDP_FAIL_INVALID_PCSCF_ADDR = 0x71,
-    PDP_FAIL_INTERNAL_CALL_PREEMPT_BY_HIGH_PRIO_APN = 0x72,
-    PDP_FAIL_EMM_ACCESS_BARRED = 0x73,
-    PDP_FAIL_EMERGENCY_IFACE_ONLY = 0x74,
-    PDP_FAIL_IFACE_MISMATCH = 0x75,
-    PDP_FAIL_COMPANION_IFACE_IN_USE = 0x76,
-    PDP_FAIL_IP_ADDRESS_MISMATCH = 0x77,
-    PDP_FAIL_IFACE_AND_POL_FAMILY_MISMATCH = 0x78,
-    PDP_FAIL_EMM_ACCESS_BARRED_INFINITE_RETRY = 0x79,
-    PDP_FAIL_AUTH_FAILURE_ON_EMERGENCY_CALL = 0x7A,
-
-    // OEM specific error codes. To be used by OEMs when they don't want to
-    // reveal error code which would be replaced by PDP_FAIL_ERROR_UNSPECIFIED
-    PDP_FAIL_OEM_DCFAILCAUSE_1 = 0x1001,
-    PDP_FAIL_OEM_DCFAILCAUSE_2 = 0x1002,
-    PDP_FAIL_OEM_DCFAILCAUSE_3 = 0x1003,
-    PDP_FAIL_OEM_DCFAILCAUSE_4 = 0x1004,
-    PDP_FAIL_OEM_DCFAILCAUSE_5 = 0x1005,
-    PDP_FAIL_OEM_DCFAILCAUSE_6 = 0x1006,
-    PDP_FAIL_OEM_DCFAILCAUSE_7 = 0x1007,
-    PDP_FAIL_OEM_DCFAILCAUSE_8 = 0x1008,
-    PDP_FAIL_OEM_DCFAILCAUSE_9 = 0x1009,
-    PDP_FAIL_OEM_DCFAILCAUSE_10 = 0x100A,
-    PDP_FAIL_OEM_DCFAILCAUSE_11 = 0x100B,
-    PDP_FAIL_OEM_DCFAILCAUSE_12 = 0x100C,
-    PDP_FAIL_OEM_DCFAILCAUSE_13 = 0x100D,
-    PDP_FAIL_OEM_DCFAILCAUSE_14 = 0x100E,
-    PDP_FAIL_OEM_DCFAILCAUSE_15 = 0x100F,
-
-    /* Not mentioned in the specification */
-    PDP_FAIL_VOICE_REGISTRATION_FAIL = -1,
-    PDP_FAIL_DATA_REGISTRATION_FAIL = -2,
-
-   /* reasons for data call drop - network/modem disconnect */
-    PDP_FAIL_SIGNAL_LOST = -3,
-    PDP_FAIL_PREF_RADIO_TECH_CHANGED = -4,/* preferred technology has changed, should retry
-                                             with parameters appropriate for new technology */
-    PDP_FAIL_RADIO_POWER_OFF = -5,        /* data call was disconnected because radio was resetting,
-                                             powered off - no retry */
-    PDP_FAIL_TETHERED_CALL_ACTIVE = -6,   /* data call was disconnected by modem because tethered
-                                             mode was up on same APN/data profile - no retry until
-                                             tethered call is off */
-
-    PDP_FAIL_ERROR_UNSPECIFIED = 0xffff,  /* retry silently. Will be deprecated soon as
-                                             new error codes are added making this unnecessary */
-} RIL_DataCallFailCause;
-
-/* See RIL_REQUEST_SETUP_DATA_CALL */
-typedef enum {
-    RIL_DATA_PROFILE_DEFAULT    = 0,
-    RIL_DATA_PROFILE_TETHERED   = 1,
-    RIL_DATA_PROFILE_IMS        = 2,
-    RIL_DATA_PROFILE_FOTA       = 3,
-    RIL_DATA_PROFILE_CBS        = 4,
-    RIL_DATA_PROFILE_OEM_BASE   = 1000,    /* Start of OEM-specific profiles */
-    RIL_DATA_PROFILE_INVALID    = 0xFFFFFFFF
-} RIL_DataProfile;
-
-/* Used by RIL_UNSOL_SUPP_SVC_NOTIFICATION */
-typedef struct {
-    int     notificationType;   /*
-                                 * 0 = MO intermediate result code
-                                 * 1 = MT unsolicited result code
-                                 */
-    int     code;               /* See 27.007 7.17
-                                   "code1" for MO
-                                   "code2" for MT. */
-    int     index;              /* CUG index. See 27.007 7.17. */
-    int     type;               /* "type" from 27.007 7.17 (MT only). */
-    char *  number;             /* "number" from 27.007 7.17
-                                   (MT only, may be NULL). */
-} RIL_SuppSvcNotification;
-
-#define RIL_CARD_MAX_APPS     8
-
-typedef enum {
-    RIL_CARDSTATE_ABSENT     = 0,
-    RIL_CARDSTATE_PRESENT    = 1,
-    RIL_CARDSTATE_ERROR      = 2,
-    RIL_CARDSTATE_RESTRICTED = 3  /* card is present but not usable due to carrier restrictions.*/
-} RIL_CardState;
-
-typedef enum {
-    RIL_PERSOSUBSTATE_UNKNOWN                   = 0, /* initial state */
-    RIL_PERSOSUBSTATE_IN_PROGRESS               = 1, /* in between each lock transition */
-    RIL_PERSOSUBSTATE_READY                     = 2, /* when either SIM or RUIM Perso is finished
-                                                        since each app can only have 1 active perso
-                                                        involved */
-    RIL_PERSOSUBSTATE_SIM_NETWORK               = 3,
-    RIL_PERSOSUBSTATE_SIM_NETWORK_SUBSET        = 4,
-    RIL_PERSOSUBSTATE_SIM_CORPORATE             = 5,
-    RIL_PERSOSUBSTATE_SIM_SERVICE_PROVIDER      = 6,
-    RIL_PERSOSUBSTATE_SIM_SIM                   = 7,
-    RIL_PERSOSUBSTATE_SIM_NETWORK_PUK           = 8, /* The corresponding perso lock is blocked */
-    RIL_PERSOSUBSTATE_SIM_NETWORK_SUBSET_PUK    = 9,
-    RIL_PERSOSUBSTATE_SIM_CORPORATE_PUK         = 10,
-    RIL_PERSOSUBSTATE_SIM_SERVICE_PROVIDER_PUK  = 11,
-    RIL_PERSOSUBSTATE_SIM_SIM_PUK               = 12,
-    RIL_PERSOSUBSTATE_RUIM_NETWORK1             = 13,
-    RIL_PERSOSUBSTATE_RUIM_NETWORK2             = 14,
-    RIL_PERSOSUBSTATE_RUIM_HRPD                 = 15,
-    RIL_PERSOSUBSTATE_RUIM_CORPORATE            = 16,
-    RIL_PERSOSUBSTATE_RUIM_SERVICE_PROVIDER     = 17,
-    RIL_PERSOSUBSTATE_RUIM_RUIM                 = 18,
-    RIL_PERSOSUBSTATE_RUIM_NETWORK1_PUK         = 19, /* The corresponding perso lock is blocked */
-    RIL_PERSOSUBSTATE_RUIM_NETWORK2_PUK         = 20,
-    RIL_PERSOSUBSTATE_RUIM_HRPD_PUK             = 21,
-    RIL_PERSOSUBSTATE_RUIM_CORPORATE_PUK        = 22,
-    RIL_PERSOSUBSTATE_RUIM_SERVICE_PROVIDER_PUK = 23,
-    RIL_PERSOSUBSTATE_RUIM_RUIM_PUK             = 24
-} RIL_PersoSubstate;
-
-typedef enum {
-    RIL_APPSTATE_UNKNOWN               = 0,
-    RIL_APPSTATE_DETECTED              = 1,
-    RIL_APPSTATE_PIN                   = 2, /* If PIN1 or UPin is required */
-    RIL_APPSTATE_PUK                   = 3, /* If PUK1 or Puk for UPin is required */
-    RIL_APPSTATE_SUBSCRIPTION_PERSO    = 4, /* perso_substate should be look at
-                                               when app_state is assigned to this value */
-    RIL_APPSTATE_READY                 = 5
-} RIL_AppState;
-
-typedef enum {
-    RIL_PINSTATE_UNKNOWN              = 0,
-    RIL_PINSTATE_ENABLED_NOT_VERIFIED = 1,
-    RIL_PINSTATE_ENABLED_VERIFIED     = 2,
-    RIL_PINSTATE_DISABLED             = 3,
-    RIL_PINSTATE_ENABLED_BLOCKED      = 4,
-    RIL_PINSTATE_ENABLED_PERM_BLOCKED = 5
-} RIL_PinState;
-
-typedef enum {
-  RIL_APPTYPE_UNKNOWN = 0,
-  RIL_APPTYPE_SIM     = 1,
-  RIL_APPTYPE_USIM    = 2,
-  RIL_APPTYPE_RUIM    = 3,
-  RIL_APPTYPE_CSIM    = 4,
-  RIL_APPTYPE_ISIM    = 5
-} RIL_AppType;
-
-/*
- * Please note that registration state UNKNOWN is
- * treated as "out of service" in the Android telephony.
- * Registration state REG_DENIED must be returned if Location Update
- * Reject (with cause 17 - Network Failure) is received
- * repeatedly from the network, to facilitate
- * "managed roaming"
- */
-typedef enum {
-    RIL_NOT_REG_AND_NOT_SEARCHING = 0,           // Not registered, MT is not currently searching
-                                                 // a new operator to register
-    RIL_REG_HOME = 1,                            // Registered, home network
-    RIL_NOT_REG_AND_SEARCHING = 2,               // Not registered, but MT is currently searching
-                                                 // a new operator to register
-    RIL_REG_DENIED = 3,                          // Registration denied
-    RIL_UNKNOWN = 4,                             // Unknown
-    RIL_REG_ROAMING = 5,                         // Registered, roaming
-    RIL_NOT_REG_AND_EMERGENCY_AVAILABLE_AND_NOT_SEARCHING = 10,   // Same as
-                                                 // RIL_NOT_REG_AND_NOT_SEARCHING but indicates that
-                                                 // emergency calls are enabled.
-    RIL_NOT_REG_AND_EMERGENCY_AVAILABLE_AND_SEARCHING = 12,  // Same as RIL_NOT_REG_AND_SEARCHING
-                                                 // but indicates that
-                                                 // emergency calls are enabled.
-    RIL_REG_DENIED_AND_EMERGENCY_AVAILABLE = 13, // Same as REG_DENIED but indicates that
-                                                 // emergency calls are enabled.
-    RIL_UNKNOWN_AND_EMERGENCY_AVAILABLE = 14,    // Same as UNKNOWN but indicates that
-                                                 // emergency calls are enabled.
-} RIL_RegState;
-
-typedef struct
-{
-  RIL_AppType      app_type;
-  RIL_AppState     app_state;
-  RIL_PersoSubstate perso_substate; /* applicable only if app_state ==
-                                       RIL_APPSTATE_SUBSCRIPTION_PERSO */
-  char             *aid_ptr;        /* null terminated string, e.g., from 0xA0, 0x00 -> 0x41,
-                                       0x30, 0x30, 0x30 */
-  char             *app_label_ptr;  /* null terminated string */
-  int              pin1_replaced;   /* applicable to USIM, CSIM & ISIM */
-  RIL_PinState     pin1;
-  RIL_PinState     pin2;
-} RIL_AppStatus;
-
-/* Deprecated, use RIL_CardStatus_v6 */
-typedef struct
-{
-  RIL_CardState card_state;
-  RIL_PinState  universal_pin_state;             /* applicable to USIM and CSIM: RIL_PINSTATE_xxx */
-  int           gsm_umts_subscription_app_index; /* value < RIL_CARD_MAX_APPS, -1 if none */
-  int           cdma_subscription_app_index;     /* value < RIL_CARD_MAX_APPS, -1 if none */
-  int           num_applications;                /* value <= RIL_CARD_MAX_APPS */
-  RIL_AppStatus applications[RIL_CARD_MAX_APPS];
-} RIL_CardStatus_v5;
-
-typedef struct
-{
-  RIL_CardState card_state;
-  RIL_PinState  universal_pin_state;             /* applicable to USIM and CSIM: RIL_PINSTATE_xxx */
-  int           gsm_umts_subscription_app_index; /* value < RIL_CARD_MAX_APPS, -1 if none */
-  int           cdma_subscription_app_index;     /* value < RIL_CARD_MAX_APPS, -1 if none */
-  int           ims_subscription_app_index;      /* value < RIL_CARD_MAX_APPS, -1 if none */
-  int           num_applications;                /* value <= RIL_CARD_MAX_APPS */
-  RIL_AppStatus applications[RIL_CARD_MAX_APPS];
-} RIL_CardStatus_v6;
-
-/** The result of a SIM refresh, returned in data[0] of RIL_UNSOL_SIM_REFRESH
- *      or as part of RIL_SimRefreshResponse_v7
- */
-typedef enum {
-    /* A file on SIM has been updated.  data[1] contains the EFID. */
-    SIM_FILE_UPDATE = 0,
-    /* SIM initialized.  All files should be re-read. */
-    SIM_INIT = 1,
-    /* SIM reset.  SIM power required, SIM may be locked and all files should be re-read. */
-    SIM_RESET = 2
-} RIL_SimRefreshResult;
-
-typedef struct {
-    RIL_SimRefreshResult result;
-    int                  ef_id; /* is the EFID of the updated file if the result is */
-                                /* SIM_FILE_UPDATE or 0 for any other result. */
-    char *               aid;   /* is AID(application ID) of the card application */
-                                /* See ETSI 102.221 8.1 and 101.220 4 */
-                                /*     For SIM_FILE_UPDATE result it can be set to AID of */
-                                /*         application in which updated EF resides or it can be */
-                                /*         NULL if EF is outside of an application. */
-                                /*     For SIM_INIT result this field is set to AID of */
-                                /*         application that caused REFRESH */
-                                /*     For SIM_RESET result it is NULL. */
-} RIL_SimRefreshResponse_v7;
-
-/* Deprecated, use RIL_CDMA_CallWaiting_v6 */
-typedef struct {
-    char *          number;             /* Remote party number */
-    int             numberPresentation; /* 0=Allowed, 1=Restricted, 2=Not Specified/Unknown */
-    char *          name;               /* Remote party name */
-    RIL_CDMA_SignalInfoRecord signalInfoRecord;
-} RIL_CDMA_CallWaiting_v5;
-
-typedef struct {
-    char *          number;             /* Remote party number */
-    int             numberPresentation; /* 0=Allowed, 1=Restricted, 2=Not Specified/Unknown */
-    char *          name;               /* Remote party name */
-    RIL_CDMA_SignalInfoRecord signalInfoRecord;
-    /* Number type/Number plan required to support International Call Waiting */
-    int             number_type;        /* 0=Unknown, 1=International, 2=National,
-                                           3=Network specific, 4=subscriber */
-    int             number_plan;        /* 0=Unknown, 1=ISDN, 3=Data, 4=Telex, 8=Nat'l, 9=Private */
-} RIL_CDMA_CallWaiting_v6;
-
-/**
- * Which types of Cell Broadcast Message (CBM) are to be received by the ME
- *
- * uFromServiceID - uToServiceID defines a range of CBM message identifiers
- * whose value is 0x0000 - 0xFFFF as defined in TS 23.041 9.4.1.2.2 for GMS
- * and 9.4.4.2.2 for UMTS. All other values can be treated as empty
- * CBM message ID.
- *
- * uFromCodeScheme - uToCodeScheme defines a range of CBM data coding schemes
- * whose value is 0x00 - 0xFF as defined in TS 23.041 9.4.1.2.3 for GMS
- * and 9.4.4.2.3 for UMTS.
- * All other values can be treated as empty CBM data coding scheme.
- *
- * selected 0 means message types specified in <fromServiceId, toServiceId>
- * and <fromCodeScheme, toCodeScheme>are not accepted, while 1 means accepted.
- *
- * Used by RIL_REQUEST_GSM_GET_BROADCAST_CONFIG and
- * RIL_REQUEST_GSM_SET_BROADCAST_CONFIG.
- */
-typedef struct {
-    int fromServiceId;
-    int toServiceId;
-    int fromCodeScheme;
-    int toCodeScheme;
-    unsigned char selected;
-} RIL_GSM_BroadcastSmsConfigInfo;
-
-/* No restriction at all including voice/SMS/USSD/SS/AV64 and packet data. */
-#define RIL_RESTRICTED_STATE_NONE           0x00
-/* Block emergency call due to restriction. But allow all normal voice/SMS/USSD/SS/AV64. */
-#define RIL_RESTRICTED_STATE_CS_EMERGENCY   0x01
-/* Block all normal voice/SMS/USSD/SS/AV64 due to restriction. Only Emergency call allowed. */
-#define RIL_RESTRICTED_STATE_CS_NORMAL      0x02
-/* Block all voice/SMS/USSD/SS/AV64 including emergency call due to restriction.*/
-#define RIL_RESTRICTED_STATE_CS_ALL         0x04
-/* Block packet data access due to restriction. */
-#define RIL_RESTRICTED_STATE_PS_ALL         0x10
-
-/* The status for an OTASP/OTAPA session */
-typedef enum {
-    CDMA_OTA_PROVISION_STATUS_SPL_UNLOCKED,
-    CDMA_OTA_PROVISION_STATUS_SPC_RETRIES_EXCEEDED,
-    CDMA_OTA_PROVISION_STATUS_A_KEY_EXCHANGED,
-    CDMA_OTA_PROVISION_STATUS_SSD_UPDATED,
-    CDMA_OTA_PROVISION_STATUS_NAM_DOWNLOADED,
-    CDMA_OTA_PROVISION_STATUS_MDN_DOWNLOADED,
-    CDMA_OTA_PROVISION_STATUS_IMSI_DOWNLOADED,
-    CDMA_OTA_PROVISION_STATUS_PRL_DOWNLOADED,
-    CDMA_OTA_PROVISION_STATUS_COMMITTED,
-    CDMA_OTA_PROVISION_STATUS_OTAPA_STARTED,
-    CDMA_OTA_PROVISION_STATUS_OTAPA_STOPPED,
-    CDMA_OTA_PROVISION_STATUS_OTAPA_ABORTED
-} RIL_CDMA_OTA_ProvisionStatus;
-
-typedef struct {
-    int signalStrength;  /* Valid values are (0-31, 99) as defined in TS 27.007 8.5 */
-    int bitErrorRate;    /* bit error rate (0-7, 99) as defined in TS 27.007 8.5 */
-} RIL_GW_SignalStrength;
-
-typedef struct {
-    int signalStrength;  /* Valid values are (0-31, 99) as defined in TS 27.007 8.5 */
-    int bitErrorRate;    /* bit error rate (0-7, 99) as defined in TS 27.007 8.5 */
-    int timingAdvance;   /* Timing Advance in bit periods. 1 bit period = 48/13 us.
-                          * INT_MAX denotes invalid value */
-} RIL_GSM_SignalStrength_v12;
-
-typedef struct {
-    int signalStrength;  /* Valid values are (0-31, 99) as defined in TS 27.007 8.5 */
-    int bitErrorRate;    /* bit error rate (0-7, 99) as defined in TS 27.007 8.5 */
-} RIL_SignalStrengthWcdma;
-
-typedef struct {
-    int dbm;  /* Valid values are positive integers.  This value is the actual RSSI value
-               * multiplied by -1.  Example: If the actual RSSI is -75, then this response
-               * value will be 75.
-               */
-    int ecio; /* Valid values are positive integers.  This value is the actual Ec/Io multiplied
-               * by -10.  Example: If the actual Ec/Io is -12.5 dB, then this response value
-               * will be 125.
-               */
-} RIL_CDMA_SignalStrength;
-
-
-typedef struct {
-    int dbm;  /* Valid values are positive integers.  This value is the actual RSSI value
-               * multiplied by -1.  Example: If the actual RSSI is -75, then this response
-               * value will be 75.
-               */
-    int ecio; /* Valid values are positive integers.  This value is the actual Ec/Io multiplied
-               * by -10.  Example: If the actual Ec/Io is -12.5 dB, then this response value
-               * will be 125.
-               */
-    int signalNoiseRatio; /* Valid values are 0-8.  8 is the highest signal to noise ratio. */
-} RIL_EVDO_SignalStrength;
-
-typedef struct {
-    int signalStrength;  /* Valid values are (0-31, 99) as defined in TS 27.007 8.5 */
-    int rsrp;            /* The current Reference Signal Receive Power in dBm multipled by -1.
-                          * Range: 44 to 140 dBm
-                          * INT_MAX: 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.133 9.1.4 */
-    int rsrq;            /* The current Reference Signal Receive Quality in dB multiplied by -1.
-                          * Range: 20 to 3 dB.
-                          * INT_MAX: 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.133 9.1.7 */
-    int rssnr;           /* The current reference signal signal-to-noise ratio in 0.1 dB units.
-                          * Range: -200 to +300 (-200 = -20.0 dB, +300 = 30dB).
-                          * INT_MAX : 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.101 8.1.1 */
-    int cqi;             /* The current Channel Quality Indicator.
-                          * Range: 0 to 15.
-                          * INT_MAX : 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.101 9.2, 9.3, A.4 */
-} RIL_LTE_SignalStrength;
-
-typedef struct {
-    int signalStrength;  /* Valid values are (0-31, 99) as defined in TS 27.007 8.5 */
-    int rsrp;            /* The current Reference Signal Receive Power in dBm multipled by -1.
-                          * Range: 44 to 140 dBm
-                          * INT_MAX: 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.133 9.1.4 */
-    int rsrq;            /* The current Reference Signal Receive Quality in dB multiplied by -1.
-                          * Range: 20 to 3 dB.
-                          * INT_MAX: 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.133 9.1.7 */
-    int rssnr;           /* The current reference signal signal-to-noise ratio in 0.1 dB units.
-                          * Range: -200 to +300 (-200 = -20.0 dB, +300 = 30dB).
-                          * INT_MAX : 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.101 8.1.1 */
-    int cqi;             /* The current Channel Quality Indicator.
-                          * Range: 0 to 15.
-                          * INT_MAX : 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP TS 36.101 9.2, 9.3, A.4 */
-    int timingAdvance;   /* timing advance in micro seconds for a one way trip from cell to device.
-                          * Approximate distance can be calculated using 300m/us * timingAdvance.
-                          * Range: 0 to 0x7FFFFFFE
-                          * INT_MAX : 0x7FFFFFFF denotes invalid value.
-                          * Reference: 3GPP 36.321 section 6.1.3.5
-                          * also: http://www.cellular-planningoptimization.com/2010/02/timing-advance-with-calculation.html */
-} RIL_LTE_SignalStrength_v8;
-
-typedef struct {
-    int rscp;    /* The Received Signal Code Power in dBm multipled by -1.
-                  * Range : 25 to 120
-                  * INT_MAX: 0x7FFFFFFF denotes invalid value.
-                  * Reference: 3GPP TS 25.123, section 9.1.1.1 */
-} RIL_TD_SCDMA_SignalStrength;
-
-/* Deprecated, use RIL_SignalStrength_v6 */
-typedef struct {
-    RIL_GW_SignalStrength   GW_SignalStrength;
-    RIL_CDMA_SignalStrength CDMA_SignalStrength;
-    RIL_EVDO_SignalStrength EVDO_SignalStrength;
-} RIL_SignalStrength_v5;
-
-typedef struct {
-    RIL_GW_SignalStrength   GW_SignalStrength;
-    RIL_CDMA_SignalStrength CDMA_SignalStrength;
-    RIL_EVDO_SignalStrength EVDO_SignalStrength;
-    RIL_LTE_SignalStrength  LTE_SignalStrength;
-} RIL_SignalStrength_v6;
-
-typedef struct {
-    RIL_GW_SignalStrength       GW_SignalStrength;
-    RIL_CDMA_SignalStrength     CDMA_SignalStrength;
-    RIL_EVDO_SignalStrength     EVDO_SignalStrength;
-    RIL_LTE_SignalStrength_v8   LTE_SignalStrength;
-} RIL_SignalStrength_v8;
-
-typedef struct {
-    RIL_GW_SignalStrength       GW_SignalStrength;
-    RIL_CDMA_SignalStrength     CDMA_SignalStrength;
-    RIL_EVDO_SignalStrength     EVDO_SignalStrength;
-    RIL_LTE_SignalStrength_v8   LTE_SignalStrength;
-    RIL_TD_SCDMA_SignalStrength TD_SCDMA_SignalStrength;
-} RIL_SignalStrength_v10;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int lac;    /* 16-bit Location Area Code, 0..65535, INT_MAX if unknown  */
-    int cid;    /* 16-bit GSM Cell Identity described in TS 27.007, 0..65535, INT_MAX if unknown  */
-} RIL_CellIdentityGsm;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int lac;    /* 16-bit Location Area Code, 0..65535, INT_MAX if unknown  */
-    int cid;    /* 16-bit GSM Cell Identity described in TS 27.007, 0..65535, INT_MAX if unknown  */
-    int arfcn;  /* 16-bit GSM Absolute RF channel number; this value must be reported */
-    uint8_t bsic; /* 6-bit Base Station Identity Code; 0xFF if unknown */
-} RIL_CellIdentityGsm_v12;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown  */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int lac;    /* 16-bit Location Area Code, 0..65535, INT_MAX if unknown  */
-    int cid;    /* 28-bit UMTS Cell Identity described in TS 25.331, 0..268435455, INT_MAX if unknown  */
-    int psc;    /* 9-bit UMTS Primary Scrambling Code described in TS 25.331, 0..511, INT_MAX if unknown */
-} RIL_CellIdentityWcdma;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown  */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int lac;    /* 16-bit Location Area Code, 0..65535, INT_MAX if unknown  */
-    int cid;    /* 28-bit UMTS Cell Identity described in TS 25.331, 0..268435455, INT_MAX if unknown  */
-    int psc;    /* 9-bit UMTS Primary Scrambling Code described in TS 25.331, 0..511; this value must be reported */
-    int uarfcn; /* 16-bit UMTS Absolute RF Channel Number; this value must be reported */
-} RIL_CellIdentityWcdma_v12;
-
-typedef struct {
-    int networkId;      /* Network Id 0..65535, INT_MAX if unknown */
-    int systemId;       /* CDMA System Id 0..32767, INT_MAX if unknown  */
-    int basestationId;  /* Base Station Id 0..65535, INT_MAX if unknown  */
-    int longitude;      /* Longitude is a decimal number as specified in 3GPP2 C.S0005-A v6.0.
-                         * It is represented in units of 0.25 seconds and ranges from -2592000
-                         * to 2592000, both values inclusive (corresponding to a range of -180
-                         * to +180 degrees). INT_MAX if unknown */
-
-    int latitude;       /* Latitude is a decimal number as specified in 3GPP2 C.S0005-A v6.0.
-                         * It is represented in units of 0.25 seconds and ranges from -1296000
-                         * to 1296000, both values inclusive (corresponding to a range of -90
-                         * to +90 degrees). INT_MAX if unknown */
-} RIL_CellIdentityCdma;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown  */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int ci;     /* 28-bit Cell Identity described in TS ???, INT_MAX if unknown */
-    int pci;    /* physical cell id 0..503, INT_MAX if unknown  */
-    int tac;    /* 16-bit tracking area code, INT_MAX if unknown  */
-} RIL_CellIdentityLte;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown  */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int ci;     /* 28-bit Cell Identity described in TS ???, INT_MAX if unknown */
-    int pci;    /* physical cell id 0..503; this value must be reported */
-    int tac;    /* 16-bit tracking area code, INT_MAX if unknown  */
-    int earfcn; /* 18-bit LTE Absolute RF Channel Number; this value must be reported */
-} RIL_CellIdentityLte_v12;
-
-typedef struct {
-    int mcc;    /* 3-digit Mobile Country Code, 0..999, INT_MAX if unknown  */
-    int mnc;    /* 2 or 3-digit Mobile Network Code, 0..999;
-                   the most significant nibble encodes the number of digits - {2, 3, 0 (unset)};
-                   INT_MAX if unknown */
-    int lac;    /* 16-bit Location Area Code, 0..65535, INT_MAX if unknown  */
-    int cid;    /* 28-bit UMTS Cell Identity described in TS 25.331, 0..268435455, INT_MAX if unknown  */
-    int cpid;    /* 8-bit Cell Parameters ID described in TS 25.331, 0..127, INT_MAX if unknown */
-} RIL_CellIdentityTdscdma;
-
-typedef struct {
-  RIL_CellIdentityGsm   cellIdentityGsm;
-  RIL_GW_SignalStrength signalStrengthGsm;
-} RIL_CellInfoGsm;
-
-typedef struct {
-  RIL_CellIdentityGsm_v12   cellIdentityGsm;
-  RIL_GSM_SignalStrength_v12 signalStrengthGsm;
-} RIL_CellInfoGsm_v12;
-
-typedef struct {
-  RIL_CellIdentityWcdma cellIdentityWcdma;
-  RIL_SignalStrengthWcdma signalStrengthWcdma;
-} RIL_CellInfoWcdma;
-
-typedef struct {
-  RIL_CellIdentityWcdma_v12 cellIdentityWcdma;
-  RIL_SignalStrengthWcdma signalStrengthWcdma;
-} RIL_CellInfoWcdma_v12;
-
-typedef struct {
-  RIL_CellIdentityCdma      cellIdentityCdma;
-  RIL_CDMA_SignalStrength   signalStrengthCdma;
-  RIL_EVDO_SignalStrength   signalStrengthEvdo;
-} RIL_CellInfoCdma;
-
-typedef struct {
-  RIL_CellIdentityLte        cellIdentityLte;
-  RIL_LTE_SignalStrength_v8  signalStrengthLte;
-} RIL_CellInfoLte;
-
-typedef struct {
-  RIL_CellIdentityLte_v12    cellIdentityLte;
-  RIL_LTE_SignalStrength_v8  signalStrengthLte;
-} RIL_CellInfoLte_v12;
-
-typedef struct {
-  RIL_CellIdentityTdscdma cellIdentityTdscdma;
-  RIL_TD_SCDMA_SignalStrength signalStrengthTdscdma;
-} RIL_CellInfoTdscdma;
-
-// Must be the same as CellInfo.TYPE_XXX
-typedef enum {
-  RIL_CELL_INFO_TYPE_NONE   = 0, /* indicates no cell information */
-  RIL_CELL_INFO_TYPE_GSM    = 1,
-  RIL_CELL_INFO_TYPE_CDMA   = 2,
-  RIL_CELL_INFO_TYPE_LTE    = 3,
-  RIL_CELL_INFO_TYPE_WCDMA  = 4,
-  RIL_CELL_INFO_TYPE_TD_SCDMA  = 5
-} RIL_CellInfoType;
-
-// Must be the same as CellInfo.TIMESTAMP_TYPE_XXX
-typedef enum {
-    RIL_TIMESTAMP_TYPE_UNKNOWN = 0,
-    RIL_TIMESTAMP_TYPE_ANTENNA = 1,
-    RIL_TIMESTAMP_TYPE_MODEM = 2,
-    RIL_TIMESTAMP_TYPE_OEM_RIL = 3,
-    RIL_TIMESTAMP_TYPE_JAVA_RIL = 4,
-} RIL_TimeStampType;
-
-typedef struct {
-  RIL_CellInfoType  cellInfoType;   /* cell type for selecting from union CellInfo */
-  int               registered;     /* !0 if this cell is registered 0 if not registered */
-  RIL_TimeStampType timeStampType;  /* type of time stamp represented by timeStamp */
-  uint64_t          timeStamp;      /* Time in nanos as returned by ril_nano_time */
-  union {
-    RIL_CellInfoGsm     gsm;
-    RIL_CellInfoCdma    cdma;
-    RIL_CellInfoLte     lte;
-    RIL_CellInfoWcdma   wcdma;
-    RIL_CellInfoTdscdma tdscdma;
-  } CellInfo;
-} RIL_CellInfo;
-
-typedef struct {
-  RIL_CellInfoType  cellInfoType;   /* cell type for selecting from union CellInfo */
-  int               registered;     /* !0 if this cell is registered 0 if not registered */
-  RIL_TimeStampType timeStampType;  /* type of time stamp represented by timeStamp */
-  uint64_t          timeStamp;      /* Time in nanos as returned by ril_nano_time */
-  union {
-    RIL_CellInfoGsm_v12     gsm;
-    RIL_CellInfoCdma        cdma;
-    RIL_CellInfoLte_v12     lte;
-    RIL_CellInfoWcdma_v12   wcdma;
-    RIL_CellInfoTdscdma     tdscdma;
-  } CellInfo;
-} RIL_CellInfo_v12;
-
-typedef struct {
-  RIL_CellInfoType  cellInfoType;   /* cell type for selecting from union CellInfo */
-  union {
-    RIL_CellIdentityGsm_v12 cellIdentityGsm;
-    RIL_CellIdentityWcdma_v12 cellIdentityWcdma;
-    RIL_CellIdentityLte_v12 cellIdentityLte;
-    RIL_CellIdentityTdscdma cellIdentityTdscdma;
-    RIL_CellIdentityCdma cellIdentityCdma;
-  };
-}RIL_CellIdentity_v16;
-
-typedef struct {
-    RIL_RegState regState;                // Valid reg states are RIL_NOT_REG_AND_NOT_SEARCHING,
-                                          // REG_HOME, RIL_NOT_REG_AND_SEARCHING, REG_DENIED,
-                                          // UNKNOWN, REG_ROAMING defined in RegState
-    RIL_RadioTechnology rat;              // indicates the available voice radio technology,
-                                          // valid values as defined by RadioTechnology.
-    int32_t cssSupported;                 // concurrent services support indicator. if
-                                          // registered on a CDMA system.
-                                          // 0 - Concurrent services not supported,
-                                          // 1 - Concurrent services supported
-    int32_t roamingIndicator;             // TSB-58 Roaming Indicator if registered
-                                          // on a CDMA or EVDO system or -1 if not.
-                                          // Valid values are 0-255.
-    int32_t systemIsInPrl;                // indicates whether the current system is in the
-                                          // PRL if registered on a CDMA or EVDO system or -1 if
-                                          // not. 0=not in the PRL, 1=in the PRL
-    int32_t defaultRoamingIndicator;      // default Roaming Indicator from the PRL,
-                                          // if registered on a CDMA or EVDO system or -1 if not.
-                                          // Valid values are 0-255.
-    int32_t reasonForDenial;              // reasonForDenial if registration state is 3
-                                          // (Registration denied) this is an enumerated reason why
-                                          // registration was denied. See 3GPP TS 24.008,
-                                          // 10.5.3.6 and Annex G.
-                                          // 0 - General
-                                          // 1 - Authentication Failure
-                                          // 2 - IMSI unknown in HLR
-                                          // 3 - Illegal MS
-                                          // 4 - Illegal ME
-                                          // 5 - PLMN not allowed
-                                          // 6 - Location area not allowed
-                                          // 7 - Roaming not allowed
-                                          // 8 - No Suitable Cells in this Location Area
-                                          // 9 - Network failure
-                                          // 10 - Persistent location update reject
-                                          // 11 - PLMN not allowed
-                                          // 12 - Location area not allowed
-                                          // 13 - Roaming not allowed in this Location Area
-                                          // 15 - No Suitable Cells in this Location Area
-                                          // 17 - Network Failure
-                                          // 20 - MAC Failure
-                                          // 21 - Sync Failure
-                                          // 22 - Congestion
-                                          // 23 - GSM Authentication unacceptable
-                                          // 25 - Not Authorized for this CSG
-                                          // 32 - Service option not supported
-                                          // 33 - Requested service option not subscribed
-                                          // 34 - Service option temporarily out of order
-                                          // 38 - Call cannot be identified
-                                          // 48-63 - Retry upon entry into a new cell
-                                          // 95 - Semantically incorrect message
-                                          // 96 - Invalid mandatory information
-                                          // 97 - Message type non-existent or not implemented
-                                          // 98 - Message type not compatible with protocol state
-                                          // 99 - Information element non-existent or
-                                          //      not implemented
-                                          // 100 - Conditional IE error
-                                          // 101 - Message not compatible with protocol state;
-    RIL_CellIdentity_v16 cellIdentity;    // current cell information
-}RIL_VoiceRegistrationStateResponse;
-
-
-typedef struct {
-    RIL_RegState regState;                // Valid reg states are RIL_NOT_REG_AND_NOT_SEARCHING,
-                                          // REG_HOME, RIL_NOT_REG_AND_SEARCHING, REG_DENIED,
-                                          // UNKNOWN, REG_ROAMING defined in RegState
-    RIL_RadioTechnology rat;              // indicates the available data radio technology,
-                                          // valid values as defined by RadioTechnology.
-    int32_t reasonDataDenied;             // if registration state is 3 (Registration
-                                          // denied) this is an enumerated reason why
-                                          // registration was denied. See 3GPP TS 24.008,
-                                          // Annex G.6 "Additional cause codes for GMM".
-                                          // 7 == GPRS services not allowed
-                                          // 8 == GPRS services and non-GPRS services not allowed
-                                          // 9 == MS identity cannot be derived by the network
-                                          // 10 == Implicitly detached
-                                          // 14 == GPRS services not allowed in this PLMN
-                                          // 16 == MSC temporarily not reachable
-                                          // 40 == No PDP context activated
-    int32_t maxDataCalls;                 // The maximum number of simultaneous Data Calls that
-                                          // must be established using setupDataCall().
-    RIL_CellIdentity_v16 cellIdentity;    // Current cell information
-}RIL_DataRegistrationStateResponse;
-
-/* Names of the CDMA info records (C.S0005 section 3.7.5) */
-typedef enum {
-  RIL_CDMA_DISPLAY_INFO_REC,
-  RIL_CDMA_CALLED_PARTY_NUMBER_INFO_REC,
-  RIL_CDMA_CALLING_PARTY_NUMBER_INFO_REC,
-  RIL_CDMA_CONNECTED_NUMBER_INFO_REC,
-  RIL_CDMA_SIGNAL_INFO_REC,
-  RIL_CDMA_REDIRECTING_NUMBER_INFO_REC,
-  RIL_CDMA_LINE_CONTROL_INFO_REC,
-  RIL_CDMA_EXTENDED_DISPLAY_INFO_REC,
-  RIL_CDMA_T53_CLIR_INFO_REC,
-  RIL_CDMA_T53_RELEASE_INFO_REC,
-  RIL_CDMA_T53_AUDIO_CONTROL_INFO_REC
-} RIL_CDMA_InfoRecName;
-
-/* Display Info Rec as defined in C.S0005 section 3.7.5.1
-   Extended Display Info Rec as defined in C.S0005 section 3.7.5.16
-   Note: the Extended Display info rec contains multiple records of the
-   form: display_tag, display_len, and display_len occurrences of the
-   chari field if the display_tag is not 10000000 or 10000001.
-   To save space, the records are stored consecutively in a byte buffer.
-   The display_tag, display_len and chari fields are all 1 byte.
-*/
-
-typedef struct {
-  char alpha_len;
-  char alpha_buf[CDMA_ALPHA_INFO_BUFFER_LENGTH];
-} RIL_CDMA_DisplayInfoRecord;
-
-/* Called Party Number Info Rec as defined in C.S0005 section 3.7.5.2
-   Calling Party Number Info Rec as defined in C.S0005 section 3.7.5.3
-   Connected Number Info Rec as defined in C.S0005 section 3.7.5.4
-*/
-
-typedef struct {
-  char len;
-  char buf[CDMA_NUMBER_INFO_BUFFER_LENGTH];
-  char number_type;
-  char number_plan;
-  char pi;
-  char si;
-} RIL_CDMA_NumberInfoRecord;
-
-/* Redirecting Number Information Record as defined in C.S0005 section 3.7.5.11 */
-typedef enum {
-  RIL_REDIRECTING_REASON_UNKNOWN = 0,
-  RIL_REDIRECTING_REASON_CALL_FORWARDING_BUSY = 1,
-  RIL_REDIRECTING_REASON_CALL_FORWARDING_NO_REPLY = 2,
-  RIL_REDIRECTING_REASON_CALLED_DTE_OUT_OF_ORDER = 9,
-  RIL_REDIRECTING_REASON_CALL_FORWARDING_BY_THE_CALLED_DTE = 10,
-  RIL_REDIRECTING_REASON_CALL_FORWARDING_UNCONDITIONAL = 15,
-  RIL_REDIRECTING_REASON_RESERVED
-} RIL_CDMA_RedirectingReason;
-
-typedef struct {
-  RIL_CDMA_NumberInfoRecord redirectingNumber;
-  /* redirectingReason is set to RIL_REDIRECTING_REASON_UNKNOWN if not included */
-  RIL_CDMA_RedirectingReason redirectingReason;
-} RIL_CDMA_RedirectingNumberInfoRecord;
-
-/* Line Control Information Record as defined in C.S0005 section 3.7.5.15 */
-typedef struct {
-  char lineCtrlPolarityIncluded;
-  char lineCtrlToggle;
-  char lineCtrlReverse;
-  char lineCtrlPowerDenial;
-} RIL_CDMA_LineControlInfoRecord;
-
-/* T53 CLIR Information Record */
-typedef struct {
-  char cause;
-} RIL_CDMA_T53_CLIRInfoRecord;
-
-/* T53 Audio Control Information Record */
-typedef struct {
-  char upLink;
-  char downLink;
-} RIL_CDMA_T53_AudioControlInfoRecord;
-
-typedef struct {
-
-  RIL_CDMA_InfoRecName name;
-
-  union {
-    /* Display and Extended Display Info Rec */
-    RIL_CDMA_DisplayInfoRecord           display;
-
-    /* Called Party Number, Calling Party Number, Connected Number Info Rec */
-    RIL_CDMA_NumberInfoRecord            number;
-
-    /* Signal Info Rec */
-    RIL_CDMA_SignalInfoRecord            signal;
-
-    /* Redirecting Number Info Rec */
-    RIL_CDMA_RedirectingNumberInfoRecord redir;
-
-    /* Line Control Info Rec */
-    RIL_CDMA_LineControlInfoRecord       lineCtrl;
-
-    /* T53 CLIR Info Rec */
-    RIL_CDMA_T53_CLIRInfoRecord          clir;
-
-    /* T53 Audio Control Info Rec */
-    RIL_CDMA_T53_AudioControlInfoRecord  audioCtrl;
-  } rec;
-} RIL_CDMA_InformationRecord;
-
-#define RIL_CDMA_MAX_NUMBER_OF_INFO_RECS 10
-
-typedef struct {
-  char numberOfInfoRecs;
-  RIL_CDMA_InformationRecord infoRec[RIL_CDMA_MAX_NUMBER_OF_INFO_RECS];
-} RIL_CDMA_InformationRecords;
-
-/* See RIL_REQUEST_NV_READ_ITEM */
-typedef struct {
-  RIL_NV_Item itemID;
-} RIL_NV_ReadItem;
-
-/* See RIL_REQUEST_NV_WRITE_ITEM */
-typedef struct {
-  RIL_NV_Item   itemID;
-  char *        value;
-} RIL_NV_WriteItem;
-
-typedef enum {
-    HANDOVER_STARTED = 0,
-    HANDOVER_COMPLETED = 1,
-    HANDOVER_FAILED = 2,
-    HANDOVER_CANCELED = 3
-} RIL_SrvccState;
-
-/* hardware configuration reported to RILJ. */
-typedef enum {
-   RIL_HARDWARE_CONFIG_MODEM = 0,
-   RIL_HARDWARE_CONFIG_SIM = 1,
-} RIL_HardwareConfig_Type;
-
-typedef enum {
-   RIL_HARDWARE_CONFIG_STATE_ENABLED = 0,
-   RIL_HARDWARE_CONFIG_STATE_STANDBY = 1,
-   RIL_HARDWARE_CONFIG_STATE_DISABLED = 2,
-} RIL_HardwareConfig_State;
-
-typedef struct {
-   int rilModel;
-   uint32_t rat; /* bitset - ref. RIL_RadioTechnology. */
-   int maxVoice;
-   int maxData;
-   int maxStandby;
-} RIL_HardwareConfig_Modem;
-
-typedef struct {
-   char modemUuid[MAX_UUID_LENGTH];
-} RIL_HardwareConfig_Sim;
-
-typedef struct {
-  RIL_HardwareConfig_Type type;
-  char uuid[MAX_UUID_LENGTH];
-  RIL_HardwareConfig_State state;
-  union {
-     RIL_HardwareConfig_Modem modem;
-     RIL_HardwareConfig_Sim sim;
-  } cfg;
-} RIL_HardwareConfig;
-
-typedef enum {
-  SS_CFU,
-  SS_CF_BUSY,
-  SS_CF_NO_REPLY,
-  SS_CF_NOT_REACHABLE,
-  SS_CF_ALL,
-  SS_CF_ALL_CONDITIONAL,
-  SS_CLIP,
-  SS_CLIR,
-  SS_COLP,
-  SS_COLR,
-  SS_WAIT,
-  SS_BAOC,
-  SS_BAOIC,
-  SS_BAOIC_EXC_HOME,
-  SS_BAIC,
-  SS_BAIC_ROAMING,
-  SS_ALL_BARRING,
-  SS_OUTGOING_BARRING,
-  SS_INCOMING_BARRING
-} RIL_SsServiceType;
-
-typedef enum {
-  SS_ACTIVATION,
-  SS_DEACTIVATION,
-  SS_INTERROGATION,
-  SS_REGISTRATION,
-  SS_ERASURE
-} RIL_SsRequestType;
-
-typedef enum {
-  SS_ALL_TELE_AND_BEARER_SERVICES,
-  SS_ALL_TELESEVICES,
-  SS_TELEPHONY,
-  SS_ALL_DATA_TELESERVICES,
-  SS_SMS_SERVICES,
-  SS_ALL_TELESERVICES_EXCEPT_SMS
-} RIL_SsTeleserviceType;
-
-#define SS_INFO_MAX 4
-#define NUM_SERVICE_CLASSES 7
-
-typedef struct {
-  int numValidIndexes; /* This gives the number of valid values in cfInfo.
-                       For example if voice is forwarded to one number and data
-                       is forwarded to a different one then numValidIndexes will be
-                       2 indicating total number of valid values in cfInfo.
-                       Similarly if all the services are forwarded to the same
-                       number then the value of numValidIndexes will be 1. */
-
-  RIL_CallForwardInfo cfInfo[NUM_SERVICE_CLASSES]; /* This is the response data
-                                                      for SS request to query call
-                                                      forward status. see
-                                                      RIL_REQUEST_QUERY_CALL_FORWARD_STATUS */
-} RIL_CfData;
-
-typedef struct {
-  RIL_SsServiceType serviceType;
-  RIL_SsRequestType requestType;
-  RIL_SsTeleserviceType teleserviceType;
-  int serviceClass;
-  RIL_Errno result;
-
-  union {
-    int ssInfo[SS_INFO_MAX]; /* This is the response data for most of the SS GET/SET
-                                RIL requests. E.g. RIL_REQUSET_GET_CLIR returns
-                                two ints, so first two values of ssInfo[] will be
-                                used for response if serviceType is SS_CLIR and
-                                requestType is SS_INTERROGATION */
-
-    RIL_CfData cfData;
-  };
-} RIL_StkCcUnsolSsResponse;
-
-/**
- * Data connection power state
- */
-typedef enum {
-    RIL_DC_POWER_STATE_LOW      = 1,        // Low power state
-    RIL_DC_POWER_STATE_MEDIUM   = 2,        // Medium power state
-    RIL_DC_POWER_STATE_HIGH     = 3,        // High power state
-    RIL_DC_POWER_STATE_UNKNOWN  = INT32_MAX // Unknown state
-} RIL_DcPowerStates;
-
-/**
- * Data connection real time info
- */
-typedef struct {
-    uint64_t                    time;       // Time in nanos as returned by ril_nano_time
-    RIL_DcPowerStates           powerState; // Current power state
-} RIL_DcRtInfo;
-
-/**
- * Data profile to modem
- */
-typedef struct {
-    /* id of the data profile */
-    int profileId;
-    /* the APN to connect to */
-    char* apn;
-    /** one of the PDP_type values in TS 27.007 section 10.1.1.
-     * For example, "IP", "IPV6", "IPV4V6", or "PPP".
-     */
-    char* protocol;
-    /** authentication protocol used for this PDP context
-     * (None: 0, PAP: 1, CHAP: 2, PAP&CHAP: 3)
-     */
-    int authType;
-    /* the username for APN, or NULL */
-    char* user;
-    /* the password for APN, or NULL */
-    char* password;
-    /* the profile type, TYPE_COMMON-0, TYPE_3GPP-1, TYPE_3GPP2-2 */
-    int type;
-    /* the period in seconds to limit the maximum connections */
-    int maxConnsTime;
-    /* the maximum connections during maxConnsTime */
-    int maxConns;
-    /** the required wait time in seconds after a successful UE initiated
-     * disconnect of a given PDN connection before the device can send
-     * a new PDN connection request for that given PDN
-     */
-    int waitTime;
-    /* true to enable the profile, 0 to disable, 1 to enable */
-    int enabled;
-} RIL_DataProfileInfo;
-
-typedef struct {
-    /* id of the data profile */
-    int profileId;
-    /* the APN to connect to */
-    char* apn;
-    /** one of the PDP_type values in TS 27.007 section 10.1.1.
-     * For example, "IP", "IPV6", "IPV4V6", or "PPP".
-     */
-    char* protocol;
-    /** one of the PDP_type values in TS 27.007 section 10.1.1 used on roaming network.
-     * For example, "IP", "IPV6", "IPV4V6", or "PPP".
-     */
-    char *roamingProtocol;
-    /** authentication protocol used for this PDP context
-     * (None: 0, PAP: 1, CHAP: 2, PAP&CHAP: 3)
-     */
-    int authType;
-    /* the username for APN, or NULL */
-    char* user;
-    /* the password for APN, or NULL */
-    char* password;
-    /* the profile type, TYPE_COMMON-0, TYPE_3GPP-1, TYPE_3GPP2-2 */
-    int type;
-    /* the period in seconds to limit the maximum connections */
-    int maxConnsTime;
-    /* the maximum connections during maxConnsTime */
-    int maxConns;
-    /** the required wait time in seconds after a successful UE initiated
-     * disconnect of a given PDN connection before the device can send
-     * a new PDN connection request for that given PDN
-     */
-    int waitTime;
-    /* true to enable the profile, 0 to disable, 1 to enable */
-    int enabled;
-    /* supported APN types bitmask. See RIL_ApnTypes for the value of each bit. */
-    int supportedTypesBitmask;
-    /** the bearer bitmask. See RIL_RadioAccessFamily for the value of each bit. */
-    int bearerBitmask;
-    /** maximum transmission unit (MTU) size in bytes */
-    int mtu;
-    /** the MVNO type: possible values are "imsi", "gid", "spn" */
-    char *mvnoType;
-    /** MVNO match data. Can be anything defined by the carrier. For example,
-     *        SPN like: "A MOBILE", "BEN NL", etc...
-     *        IMSI like: "302720x94", "2060188", etc...
-     *        GID like: "4E", "33", etc...
-     */
-    char *mvnoMatchData;
-} RIL_DataProfileInfo_v15;
-
-/* Tx Power Levels */
-#define RIL_NUM_TX_POWER_LEVELS     5
-
-/**
- * Aggregate modem activity information
- */
-typedef struct {
-
-  /* total time (in ms) when modem is in a low power or
-   * sleep state
-   */
-  uint32_t sleep_mode_time_ms;
-
-  /* total time (in ms) when modem is awake but neither
-   * the transmitter nor receiver are active/awake */
-  uint32_t idle_mode_time_ms;
-
-  /* total time (in ms) during which the transmitter is active/awake,
-   * subdivided by manufacturer-defined device-specific
-   * contiguous increasing ranges of transmit power between
-   * 0 and the transmitter's maximum transmit power.
-   */
-  uint32_t tx_mode_time_ms[RIL_NUM_TX_POWER_LEVELS];
-
-  /* total time (in ms) for which receiver is active/awake and
-   * the transmitter is inactive */
-  uint32_t rx_mode_time_ms;
-} RIL_ActivityStatsInfo;
-
-typedef enum {
-    RIL_APN_TYPE_UNKNOWN      = 0x0,          // Unknown
-    RIL_APN_TYPE_DEFAULT      = 0x1,          // APN type for default data traffic
-    RIL_APN_TYPE_MMS          = 0x2,          // APN type for MMS traffic
-    RIL_APN_TYPE_SUPL         = 0x4,          // APN type for SUPL assisted GPS
-    RIL_APN_TYPE_DUN          = 0x8,          // APN type for DUN traffic
-    RIL_APN_TYPE_HIPRI        = 0x10,         // APN type for HiPri traffic
-    RIL_APN_TYPE_FOTA         = 0x20,         // APN type for FOTA
-    RIL_APN_TYPE_IMS          = 0x40,         // APN type for IMS
-    RIL_APN_TYPE_CBS          = 0x80,         // APN type for CBS
-    RIL_APN_TYPE_IA           = 0x100,        // APN type for IA Initial Attach APN
-    RIL_APN_TYPE_EMERGENCY    = 0x200,        // APN type for Emergency PDN. This is not an IA apn,
-                                              // but is used for access to carrier services in an
-                                              // emergency call situation.
-    RIL_APN_TYPE_ALL          = 0xFFFFFFFF    // All APN types
-} RIL_ApnTypes;
-
-typedef enum {
-    RIL_DST_POWER_SAVE_MODE,        // Device power save mode (provided by PowerManager)
-                                    // True indicates the device is in power save mode.
-    RIL_DST_CHARGING_STATE,         // Device charging state (provided by BatteryManager)
-                                    // True indicates the device is charging.
-    RIL_DST_LOW_DATA_EXPECTED       // Low data expected mode. True indicates low data traffic
-                                    // is expected, for example, when the device is idle
-                                    // (e.g. not doing tethering in the background). Note
-                                    // this doesn't mean no data is expected.
-} RIL_DeviceStateType;
-
-typedef enum {
-    RIL_UR_SIGNAL_STRENGTH            = 0x01, // When this bit is set, modem should always send the
-                                              // signal strength update through
-                                              // RIL_UNSOL_SIGNAL_STRENGTH, otherwise suppress it.
-    RIL_UR_FULL_NETWORK_STATE         = 0x02, // When this bit is set, modem should always send
-                                              // RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED
-                                              // when any field in
-                                              // RIL_REQUEST_VOICE_REGISTRATION_STATE or
-                                              // RIL_REQUEST_DATA_REGISTRATION_STATE changes. When
-                                              // this bit is not set, modem should suppress
-                                              // RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED
-                                              // only when insignificant fields change
-                                              // (e.g. cell info).
-                                              // Modem should continue sending
-                                              // RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED
-                                              // when significant fields are updated even when this
-                                              // bit is not set. The following fields are
-                                              // considered significant, registration state and
-                                              // radio technology.
-    RIL_UR_DATA_CALL_DORMANCY_CHANGED = 0x04  // When this bit is set, modem should send the data
-                                              // call list changed unsolicited response
-                                              // RIL_UNSOL_DATA_CALL_LIST_CHANGED whenever any
-                                              // field in RIL_Data_Call_Response changes.
-                                              // Otherwise modem should suppress the unsolicited
-                                              // response when the only changed field is 'active'
-                                              // (for data dormancy). For all other fields change,
-                                              // modem should continue sending
-                                              // RIL_UNSOL_DATA_CALL_LIST_CHANGED regardless this
-                                              // bit is set or not.
-} RIL_UnsolicitedResponseFilter;
-
-typedef struct {
-    char * aidPtr; /* AID value, See ETSI 102.221 and 101.220*/
-    int p2;        /* P2 parameter (described in ISO 7816-4)
-                      P2Constants:NO_P2 if to be ignored */
-} RIL_OpenChannelParams;
-
-typedef enum {
-    RIL_ONE_SHOT = 0x01, // Performs the scan only once
-    RIL_PERIODIC = 0x02  // Performs the scan periodically until cancelled
-} RIL_ScanType;
-
-typedef enum {
-    GERAN = 0x01,   // GSM EDGE Radio Access Network
-    UTRAN = 0x02,   // Universal Terrestrial Radio Access Network
-    EUTRAN = 0x03,  // Evolved Universal Terrestrial Radio Access Network
-} RIL_RadioAccessNetworks;
-
-typedef enum {
-    GERAN_BAND_T380 = 1,
-    GERAN_BAND_T410 = 2,
-    GERAN_BAND_450 = 3,
-    GERAN_BAND_480 = 4,
-    GERAN_BAND_710 = 5,
-    GERAN_BAND_750 = 6,
-    GERAN_BAND_T810 = 7,
-    GERAN_BAND_850 = 8,
-    GERAN_BAND_P900 = 9,
-    GERAN_BAND_E900 = 10,
-    GERAN_BAND_R900 = 11,
-    GERAN_BAND_DCS1800 = 12,
-    GERAN_BAND_PCS1900 = 13,
-    GERAN_BAND_ER900 = 14,
-} RIL_GeranBands;
-
-typedef enum {
-    UTRAN_BAND_1 = 1,
-    UTRAN_BAND_2 = 2,
-    UTRAN_BAND_3 = 3,
-    UTRAN_BAND_4 = 4,
-    UTRAN_BAND_5 = 5,
-    UTRAN_BAND_6 = 6,
-    UTRAN_BAND_7 = 7,
-    UTRAN_BAND_8 = 8,
-    UTRAN_BAND_9 = 9,
-    UTRAN_BAND_10 = 10,
-    UTRAN_BAND_11 = 11,
-    UTRAN_BAND_12 = 12,
-    UTRAN_BAND_13 = 13,
-    UTRAN_BAND_14 = 14,
-    UTRAN_BAND_19 = 19,
-    UTRAN_BAND_20 = 20,
-    UTRAN_BAND_21 = 21,
-    UTRAN_BAND_22 = 22,
-    UTRAN_BAND_25 = 25,
-    UTRAN_BAND_26 = 26,
-} RIL_UtranBands;
-
-typedef enum {
-    EUTRAN_BAND_1 = 1,
-    EUTRAN_BAND_2 = 2,
-    EUTRAN_BAND_3 = 3,
-    EUTRAN_BAND_4 = 4,
-    EUTRAN_BAND_5 = 5,
-    EUTRAN_BAND_6 = 6,
-    EUTRAN_BAND_7 = 7,
-    EUTRAN_BAND_8 = 8,
-    EUTRAN_BAND_9 = 9,
-    EUTRAN_BAND_10 = 10,
-    EUTRAN_BAND_11 = 11,
-    EUTRAN_BAND_12 = 12,
-    EUTRAN_BAND_13 = 13,
-    EUTRAN_BAND_14 = 14,
-    EUTRAN_BAND_17 = 17,
-    EUTRAN_BAND_18 = 18,
-    EUTRAN_BAND_19 = 19,
-    EUTRAN_BAND_20 = 20,
-    EUTRAN_BAND_21 = 21,
-    EUTRAN_BAND_22 = 22,
-    EUTRAN_BAND_23 = 23,
-    EUTRAN_BAND_24 = 24,
-    EUTRAN_BAND_25 = 25,
-    EUTRAN_BAND_26 = 26,
-    EUTRAN_BAND_27 = 27,
-    EUTRAN_BAND_28 = 28,
-    EUTRAN_BAND_30 = 30,
-    EUTRAN_BAND_31 = 31,
-    EUTRAN_BAND_33 = 33,
-    EUTRAN_BAND_34 = 34,
-    EUTRAN_BAND_35 = 35,
-    EUTRAN_BAND_36 = 36,
-    EUTRAN_BAND_37 = 37,
-    EUTRAN_BAND_38 = 38,
-    EUTRAN_BAND_39 = 39,
-    EUTRAN_BAND_40 = 40,
-    EUTRAN_BAND_41 = 41,
-    EUTRAN_BAND_42 = 42,
-    EUTRAN_BAND_43 = 43,
-    EUTRAN_BAND_44 = 44,
-    EUTRAN_BAND_45 = 45,
-    EUTRAN_BAND_46 = 46,
-    EUTRAN_BAND_47 = 47,
-    EUTRAN_BAND_48 = 48,
-    EUTRAN_BAND_65 = 65,
-    EUTRAN_BAND_66 = 66,
-    EUTRAN_BAND_68 = 68,
-    EUTRAN_BAND_70 = 70,
-} RIL_EutranBands;
-
-typedef struct {
-    RIL_RadioAccessNetworks radio_access_network; // The type of network to scan.
-    uint32_t bands_length;                        // Length of bands
-    union {
-        RIL_GeranBands geran_bands[MAX_BANDS];
-        RIL_UtranBands utran_bands[MAX_BANDS];
-        RIL_EutranBands eutran_bands[MAX_BANDS];
-    } bands;
-    uint32_t channels_length;                     // Length of channels
-    uint32_t channels[MAX_CHANNELS];              // Frequency channels to scan
-} RIL_RadioAccessSpecifier;
-
-typedef struct {
-    RIL_ScanType type;                                              // Type of the scan
-    int32_t interval;                                               // Time interval in seconds
-                                                                    // between periodic scans, only
-                                                                    // valid when type=RIL_PERIODIC
-    uint32_t specifiers_length;                                     // Length of specifiers
-    RIL_RadioAccessSpecifier specifiers[MAX_RADIO_ACCESS_NETWORKS]; // Radio access networks
-                                                                    // with bands/channels.
-} RIL_NetworkScanRequest;
-
-typedef enum {
-    PARTIAL = 0x01,   // The result contains a part of the scan results
-    COMPLETE = 0x02,  // The result contains the last part of the scan results
-} RIL_ScanStatus;
-
-typedef struct {
-    RIL_ScanStatus status;              // The status of the scan
-    uint32_t network_infos_length;      // Total length of RIL_CellInfo
-    RIL_CellInfo_v12* network_infos;    // List of network information
-    RIL_Errno error;
-} RIL_NetworkScanResult;
-
-/**
- * RIL_REQUEST_GET_SIM_STATUS
- *
- * Requests status of the SIM interface and the SIM card
- *
- * "data" is NULL
- *
- * "response" is const RIL_CardStatus_v6 *
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_GET_SIM_STATUS 1
-
-/**
- * RIL_REQUEST_ENTER_SIM_PIN
- *
- * Supplies SIM PIN. Only called if RIL_CardStatus has RIL_APPSTATE_PIN state
- *
- * "data" is const char **
- * ((const char **)data)[0] is PIN value
- * ((const char **)data)[1] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- * SUCCESS
- * RADIO_NOT_AVAILABLE (radio resetting)
- * PASSWORD_INCORRECT
- * INTERNAL_ERR
- * NO_MEMORY
- * NO_RESOURCES
- * CANCELLED
- * INVALID_ARGUMENTS
- * INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_ENTER_SIM_PIN 2
-
-/**
- * RIL_REQUEST_ENTER_SIM_PUK
- *
- * Supplies SIM PUK and new PIN.
- *
- * "data" is const char **
- * ((const char **)data)[0] is PUK value
- * ((const char **)data)[1] is new PIN value
- * ((const char **)data)[2] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  PASSWORD_INCORRECT
- *     (PUK is invalid)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_ARGUMENTS
- *  INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_ENTER_SIM_PUK 3
-
-/**
- * RIL_REQUEST_ENTER_SIM_PIN2
- *
- * Supplies SIM PIN2. Only called following operation where SIM_PIN2 was
- * returned as a a failure from a previous operation.
- *
- * "data" is const char **
- * ((const char **)data)[0] is PIN2 value
- * ((const char **)data)[1] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  PASSWORD_INCORRECT
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_ARGUMENTS
- *  INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_ENTER_SIM_PIN2 4
-
-/**
- * RIL_REQUEST_ENTER_SIM_PUK2
- *
- * Supplies SIM PUK2 and new PIN2.
- *
- * "data" is const char **
- * ((const char **)data)[0] is PUK2 value
- * ((const char **)data)[1] is new PIN2 value
- * ((const char **)data)[2] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  PASSWORD_INCORRECT
- *     (PUK2 is invalid)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_ARGUMENTS
- *  INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_ENTER_SIM_PUK2 5
-
-/**
- * RIL_REQUEST_CHANGE_SIM_PIN
- *
- * Supplies old SIM PIN and new PIN.
- *
- * "data" is const char **
- * ((const char **)data)[0] is old PIN value
- * ((const char **)data)[1] is new PIN value
- * ((const char **)data)[2] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  PASSWORD_INCORRECT
- *     (old PIN is invalid)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_ARGUMENTS
- *  INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_CHANGE_SIM_PIN 6
-
-
-/**
- * RIL_REQUEST_CHANGE_SIM_PIN2
- *
- * Supplies old SIM PIN2 and new PIN2.
- *
- * "data" is const char **
- * ((const char **)data)[0] is old PIN2 value
- * ((const char **)data)[1] is new PIN2 value
- * ((const char **)data)[2] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  PASSWORD_INCORRECT
- *     (old PIN2 is invalid)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_ARGUMENTS
- *  INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-
-#define RIL_REQUEST_CHANGE_SIM_PIN2 7
-
-/**
- * RIL_REQUEST_ENTER_NETWORK_DEPERSONALIZATION
- *
- * Requests that network personlization be deactivated
- *
- * "data" is const char **
- * ((const char **)(data))[0]] is network depersonlization code
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  PASSWORD_INCORRECT
- *  SIM_ABSENT
- *     (code is invalid)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_ENTER_NETWORK_DEPERSONALIZATION 8
-
-/**
- * RIL_REQUEST_GET_CURRENT_CALLS
- *
- * Requests current call list
- *
- * "data" is NULL
- *
- * "response" must be a "const RIL_Call **"
- *
- * Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *      (request will be made again in a few hundred msec)
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_GET_CURRENT_CALLS 9
-
-
-/**
- * RIL_REQUEST_DIAL
- *
- * Initiate voice call
- *
- * "data" is const RIL_Dial *
- * "response" is NULL
- *
- * This method is never used for supplementary service codes
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  DIAL_MODIFIED_TO_USSD
- *  DIAL_MODIFIED_TO_SS
- *  DIAL_MODIFIED_TO_DIAL
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  INVALID_STATE
- *  NO_RESOURCES
- *  INTERNAL_ERR
- *  FDN_CHECK_FAILURE
- *  MODEM_ERR
- *  NO_SUBSCRIPTION
- *  NO_NETWORK_FOUND
- *  INVALID_CALL_ID
- *  DEVICE_IN_USE
- *  OPERATION_NOT_ALLOWED
- *  ABORTED
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_DIAL 10
-
-/**
- * RIL_REQUEST_GET_IMSI
- *
- * Get the SIM IMSI
- *
- * Only valid when radio state is "RADIO_STATE_ON"
- *
- * "data" is const char **
- * ((const char **)data)[0] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- * "response" is a const char * containing the IMSI
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_SIM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_GET_IMSI 11
-
-/**
- * RIL_REQUEST_HANGUP
- *
- * Hang up a specific line (like AT+CHLD=1x)
- *
- * After this HANGUP request returns, RIL should show the connection is NOT
- * active anymore in next RIL_REQUEST_GET_CURRENT_CALLS query.
- *
- * "data" is an int *
- * (int *)data)[0] contains Connection index (value of 'x' in CHLD above)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  INVALID_STATE
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_CALL_ID
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_HANGUP 12
-
-/**
- * RIL_REQUEST_HANGUP_WAITING_OR_BACKGROUND
- *
- * Hang up waiting or held (like AT+CHLD=0)
- *
- * After this HANGUP request returns, RIL should show the connection is NOT
- * active anymore in next RIL_REQUEST_GET_CURRENT_CALLS query.
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_STATE
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_CALL_ID
- *  NO_RESOURCES
- *  OPERATION_NOT_ALLOWED
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_HANGUP_WAITING_OR_BACKGROUND 13
-
-/**
- * RIL_REQUEST_HANGUP_FOREGROUND_RESUME_BACKGROUND
- *
- * Hang up waiting or held (like AT+CHLD=1)
- *
- * After this HANGUP request returns, RIL should show the connection is NOT
- * active anymore in next RIL_REQUEST_GET_CURRENT_CALLS query.
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_STATE
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  OPERATION_NOT_ALLOWED
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_HANGUP_FOREGROUND_RESUME_BACKGROUND 14
-
-/**
- * RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE
- *
- * Switch waiting or holding call and active call (like AT+CHLD=2)
- *
- * State transitions should be is follows:
- *
- * If call 1 is waiting and call 2 is active, then if this re
- *
- *   BEFORE                               AFTER
- * Call 1   Call 2                 Call 1       Call 2
- * ACTIVE   HOLDING                HOLDING     ACTIVE
- * ACTIVE   WAITING                HOLDING     ACTIVE
- * HOLDING  WAITING                HOLDING     ACTIVE
- * ACTIVE   IDLE                   HOLDING     IDLE
- * IDLE     IDLE                   IDLE        IDLE
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_STATE
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  INVALID_CALL_ID
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE 15
-#define RIL_REQUEST_SWITCH_HOLDING_AND_ACTIVE 15
-
-/**
- * RIL_REQUEST_CONFERENCE
- *
- * Conference holding and active (like AT+CHLD=3)
-
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_STATE
- *  INVALID_CALL_ID
- *  INVALID_ARGUMENTS
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_CONFERENCE 16
-
-/**
- * RIL_REQUEST_UDUB
- *
- * Send UDUB (user determined used busy) to ringing or
- * waiting call answer)(RIL_BasicRequest r);
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_STATE
- *  NO_RESOURCES
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  OPERATION_NOT_ALLOWED
- *  INVALID_ARGUMENTS
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_UDUB 17
-
-/**
- * RIL_REQUEST_LAST_CALL_FAIL_CAUSE
- *
- * Requests the failure cause code for the most recently terminated call
- *
- * "data" is NULL
- * "response" is a const RIL_LastCallFailCauseInfo *
- * RIL_LastCallFailCauseInfo contains LastCallFailCause and vendor cause.
- * The vendor cause code must be used for debugging purpose only.
- * The implementation must return one of the values of LastCallFailCause
- * as mentioned below.
- *
- * GSM failure reasons codes for the cause codes defined in TS 24.008 Annex H
- * where possible.
- * CDMA failure reasons codes for the possible call failure scenarios
- * described in the "CDMA IS-2000 Release A (C.S0005-A v6.0)" standard.
- * Any of the following reason codes if the call is failed or dropped due to reason
- * mentioned with in the braces.
- *
- *      CALL_FAIL_RADIO_OFF (Radio is OFF)
- *      CALL_FAIL_OUT_OF_SERVICE (No cell coverage)
- *      CALL_FAIL_NO_VALID_SIM (No valid SIM)
- *      CALL_FAIL_RADIO_INTERNAL_ERROR (Modem hit unexpected error scenario)
- *      CALL_FAIL_NETWORK_RESP_TIMEOUT (No response from network)
- *      CALL_FAIL_NETWORK_REJECT (Explicit network reject)
- *      CALL_FAIL_RADIO_ACCESS_FAILURE (RRC connection failure. Eg.RACH)
- *      CALL_FAIL_RADIO_LINK_FAILURE (Radio Link Failure)
- *      CALL_FAIL_RADIO_LINK_LOST (Radio link lost due to poor coverage)
- *      CALL_FAIL_RADIO_UPLINK_FAILURE (Radio uplink failure)
- *      CALL_FAIL_RADIO_SETUP_FAILURE (RRC connection setup failure)
- *      CALL_FAIL_RADIO_RELEASE_NORMAL (RRC connection release, normal)
- *      CALL_FAIL_RADIO_RELEASE_ABNORMAL (RRC connection release, abnormal)
- *      CALL_FAIL_ACCESS_CLASS_BLOCKED (Access class barring)
- *      CALL_FAIL_NETWORK_DETACH (Explicit network detach)
- *
- * OEM causes (CALL_FAIL_OEM_CAUSE_XX) must be used for debug purpose only
- *
- * If the implementation does not have access to the exact cause codes,
- * then it should return one of the values listed in RIL_LastCallFailCause,
- * as the UI layer needs to distinguish these cases for tone generation or
- * error notification.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE
- */
-#define RIL_REQUEST_LAST_CALL_FAIL_CAUSE 18
-
-/**
- * RIL_REQUEST_SIGNAL_STRENGTH
- *
- * Requests current signal strength and associated information
- *
- * Must succeed if radio is on.
- *
- * "data" is NULL
- *
- * "response" is a const RIL_SignalStrength *
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SIGNAL_STRENGTH 19
-
-/**
- * RIL_REQUEST_VOICE_REGISTRATION_STATE
- *
- * Request current registration state
- *
- * "data" is NULL
- * "response" is a const RIL_VoiceRegistrationStateResponse *
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_VOICE_REGISTRATION_STATE 20
-
-/**
- * RIL_REQUEST_DATA_REGISTRATION_STATE
- *
- * Request current DATA registration state
- *
- * "data" is NULL
- * "response" is a const RIL_DataRegistrationStateResponse *
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_DATA_REGISTRATION_STATE 21
-
-/**
- * RIL_REQUEST_OPERATOR
- *
- * Request current operator ONS or EONS
- *
- * "data" is NULL
- * "response" is a "const char **"
- * ((const char **)response)[0] is long alpha ONS or EONS
- *                                  or NULL if unregistered
- *
- * ((const char **)response)[1] is short alpha ONS or EONS
- *                                  or NULL if unregistered
- * ((const char **)response)[2] is 5 or 6 digit numeric code (MCC + MNC)
- *                                  or NULL if unregistered
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_OPERATOR 22
-
-/**
- * RIL_REQUEST_RADIO_POWER
- *
- * Toggle radio on and off (for "airplane" mode)
- * If the radio is is turned off/on the radio modem subsystem
- * is expected return to an initialized state. For instance,
- * any voice and data calls will be terminated and all associated
- * lists emptied.
- *
- * "data" is int *
- * ((int *)data)[0] is > 0 for "Radio On"
- * ((int *)data)[0] is == 0 for "Radio Off"
- *
- * "response" is NULL
- *
- * Turn radio on if "on" > 0
- * Turn radio off if "on" == 0
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  INVALID_STATE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  DEVICE_IN_USE
- *  OPERATION_NOT_ALLOWED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_RADIO_POWER 23
-
-/**
- * RIL_REQUEST_DTMF
- *
- * Send a DTMF tone
- *
- * If the implementation is currently playing a tone requested via
- * RIL_REQUEST_DTMF_START, that tone should be cancelled and the new tone
- * should be played instead
- *
- * "data" is a char * containing a single character with one of 12 values: 0-9,*,#
- * "response" is NULL
- *
- * FIXME should this block/mute microphone?
- * How does this interact with local DTMF feedback?
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_DTMF_STOP, RIL_REQUEST_DTMF_START
- *
- */
-#define RIL_REQUEST_DTMF 24
-
-/**
- * RIL_REQUEST_SEND_SMS
- *
- * Send an SMS message
- *
- * "data" is const char **
- * ((const char **)data)[0] is SMSC address in GSM BCD format prefixed
- *      by a length byte (as expected by TS 27.005) or NULL for default SMSC
- * ((const char **)data)[1] is SMS in PDU format as an ASCII hex string
- *      less the SMSC address
- *      TP-Layer-Length is be "strlen(((const char **)data)[1])/2"
- *
- * "response" is a const RIL_SMS_Response *
- *
- * Based on the return error, caller decides to resend if sending sms
- * fails. SMS_SEND_FAIL_RETRY means retry (i.e. error cause is 332)
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SMS_SEND_FAIL_RETRY
- *  FDN_CHECK_FAILURE
- *  NETWORK_REJECT
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  INVALID_SMS_FORMAT
- *  SYSTEM_ERR
- *  ENCODING_ERR
- *  INVALID_SMSC_ADDRESS
- *  MODEM_ERR
- *  NETWORK_ERR
- *  OPERATION_NOT_ALLOWED
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  MODE_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- * FIXME how do we specify TP-Message-Reference if we need to resend?
- */
-#define RIL_REQUEST_SEND_SMS 25
-
-
-/**
- * RIL_REQUEST_SEND_SMS_EXPECT_MORE
- *
- * Send an SMS message. Identical to RIL_REQUEST_SEND_SMS,
- * except that more messages are expected to be sent soon. If possible,
- * keep SMS relay protocol link open (eg TS 27.005 AT+CMMS command)
- *
- * "data" is const char **
- * ((const char **)data)[0] is SMSC address in GSM BCD format prefixed
- *      by a length byte (as expected by TS 27.005) or NULL for default SMSC
- * ((const char **)data)[1] is SMS in PDU format as an ASCII hex string
- *      less the SMSC address
- *      TP-Layer-Length is be "strlen(((const char **)data)[1])/2"
- *
- * "response" is a const RIL_SMS_Response *
- *
- * Based on the return error, caller decides to resend if sending sms
- * fails. SMS_SEND_FAIL_RETRY means retry (i.e. error cause is 332)
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SMS_SEND_FAIL_RETRY
- *  NETWORK_REJECT
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  INVALID_SMS_FORMAT
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  FDN_CHECK_FAILURE
- *  MODEM_ERR
- *  NETWORK_ERR
- *  ENCODING_ERR
- *  INVALID_SMSC_ADDRESS
- *  OPERATION_NOT_ALLOWED
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  MODE_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- */
-#define RIL_REQUEST_SEND_SMS_EXPECT_MORE 26
-
-
-/**
- * RIL_REQUEST_SETUP_DATA_CALL
- *
- * Setup a packet data connection. If RIL_Data_Call_Response_v6.status
- * return success it is added to the list of data calls and a
- * RIL_UNSOL_DATA_CALL_LIST_CHANGED is sent. The call remains in the
- * list until RIL_REQUEST_DEACTIVATE_DATA_CALL is issued or the
- * radio is powered off/on. This list is returned by RIL_REQUEST_DATA_CALL_LIST
- * and RIL_UNSOL_DATA_CALL_LIST_CHANGED.
- *
- * The RIL is expected to:
- *  - Create one data call context.
- *  - Create and configure a dedicated interface for the context
- *  - The interface must be point to point.
- *  - The interface is configured with one or more addresses and
- *    is capable of sending and receiving packets. The prefix length
- *    of the addresses must be /32 for IPv4 and /128 for IPv6.
- *  - Must NOT change the linux routing table.
- *  - Support up to RIL_REQUEST_DATA_REGISTRATION_STATE response[5]
- *    number of simultaneous data call contexts.
- *
- * "data" is a const char **
- * ((const char **)data)[0] Radio technology to use: 0-CDMA, 1-GSM/UMTS, 2...
- *                          for values above 2 this is RIL_RadioTechnology + 2.
- * ((const char **)data)[1] is a RIL_DataProfile (support is optional)
- * ((const char **)data)[2] is the APN to connect to if radio technology is GSM/UMTS. This APN will
- *                          override the one in the profile. NULL indicates no APN overrride.
- * ((const char **)data)[3] is the username for APN, or NULL
- * ((const char **)data)[4] is the password for APN, or NULL
- * ((const char **)data)[5] is the PAP / CHAP auth type. Values:
- *                          0 => PAP and CHAP is never performed.
- *                          1 => PAP may be performed; CHAP is never performed.
- *                          2 => CHAP may be performed; PAP is never performed.
- *                          3 => PAP / CHAP may be performed - baseband dependent.
- * ((const char **)data)[6] is the non-roaming/home connection type to request. Must be one of the
- *                          PDP_type values in TS 27.007 section 10.1.1.
- *                          For example, "IP", "IPV6", "IPV4V6", or "PPP".
- * ((const char **)data)[7] is the roaming connection type to request. Must be one of the
- *                          PDP_type values in TS 27.007 section 10.1.1.
- *                          For example, "IP", "IPV6", "IPV4V6", or "PPP".
- * ((const char **)data)[8] is the bitmask of APN type in decimal string format. The
- *                          bitmask will encapsulate the following values:
- *                          ia,mms,agps,supl,hipri,fota,dun,ims,default.
- * ((const char **)data)[9] is the bearer bitmask in decimal string format. Each bit is a
- *                          RIL_RadioAccessFamily. "0" or NULL indicates all RATs.
- * ((const char **)data)[10] is the boolean in string format indicating the APN setting was
- *                           sent to the modem through RIL_REQUEST_SET_DATA_PROFILE earlier.
- * ((const char **)data)[11] is the mtu size in bytes of the mobile interface to which
- *                           the apn is connected.
- * ((const char **)data)[12] is the MVNO type:
- *                           possible values are "imsi", "gid", "spn".
- * ((const char **)data)[13] is MVNO match data in string. Can be anything defined by the carrier.
- *                           For example,
- *                           SPN like: "A MOBILE", "BEN NL", etc...
- *                           IMSI like: "302720x94", "2060188", etc...
- *                           GID like: "4E", "33", etc...
- * ((const char **)data)[14] is the boolean string indicating data roaming is allowed or not. "1"
- *                           indicates data roaming is enabled by the user, "0" indicates disabled.
- *
- * "response" is a RIL_Data_Call_Response_v11
- *
- * FIXME may need way to configure QoS settings
- *
- * Valid errors:
- *  SUCCESS should be returned on both success and failure of setup with
- *  the RIL_Data_Call_Response_v6.status containing the actual status.
- *  For all other errors the RIL_Data_Call_Resonse_v6 is ignored.
- *
- *  Other errors could include:
- *    RADIO_NOT_AVAILABLE, OP_NOT_ALLOWED_BEFORE_REG_TO_NW,
- *    OP_NOT_ALLOWED_DURING_VOICE_CALL, REQUEST_NOT_SUPPORTED,
- *    INVALID_ARGUMENTS, INTERNAL_ERR, NO_MEMORY, NO_RESOURCES,
- *    CANCELLED and SIM_ABSENT
- *
- * See also: RIL_REQUEST_DEACTIVATE_DATA_CALL
- */
-#define RIL_REQUEST_SETUP_DATA_CALL 27
-
-
-/**
- * RIL_REQUEST_SIM_IO
- *
- * Request SIM I/O operation.
- * This is similar to the TS 27.007 "restricted SIM" operation
- * where it assumes all of the EF selection will be done by the
- * callee.
- *
- * "data" is a const RIL_SIM_IO_v6 *
- * Please note that RIL_SIM_IO has a "PIN2" field which may be NULL,
- * or may specify a PIN2 for operations that require a PIN2 (eg
- * updating FDN records)
- *
- * "response" is a const RIL_SIM_IO_Response *
- *
- * Arguments and responses that are unused for certain
- * values of "command" should be ignored or set to NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SIM_PIN2
- *  SIM_PUK2
- *  INVALID_SIM_STATE
- *  SIM_ERR
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SIM_IO 28
-
-/**
- * RIL_REQUEST_SEND_USSD
- *
- * Send a USSD message
- *
- * If a USSD session already exists, the message should be sent in the
- * context of that session. Otherwise, a new session should be created.
- *
- * The network reply should be reported via RIL_UNSOL_ON_USSD
- *
- * Only one USSD session may exist at a time, and the session is assumed
- * to exist until:
- *   a) The android system invokes RIL_REQUEST_CANCEL_USSD
- *   b) The implementation sends a RIL_UNSOL_ON_USSD with a type code
- *      of "0" (USSD-Notify/no further action) or "2" (session terminated)
- *
- * "data" is a const char * containing the USSD request in UTF-8 format
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  FDN_CHECK_FAILURE
- *  USSD_MODIFIED_TO_DIAL
- *  USSD_MODIFIED_TO_SS
- *  USSD_MODIFIED_TO_USSD
- *  SIM_BUSY
- *  OPERATION_NOT_ALLOWED
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  ABORTED
- *  SYSTEM_ERR
- *  INVALID_STATE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_CANCEL_USSD, RIL_UNSOL_ON_USSD
- */
-
-#define RIL_REQUEST_SEND_USSD 29
-
-/**
- * RIL_REQUEST_CANCEL_USSD
- *
- * Cancel the current USSD session if one exists
- *
- * "data" is null
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SIM_BUSY
- *  OPERATION_NOT_ALLOWED
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_STATE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_CANCEL_USSD 30
-
-/**
- * RIL_REQUEST_GET_CLIR
- *
- * Gets current CLIR status
- * "data" is NULL
- * "response" is int *
- * ((int *)data)[0] is "n" parameter from TS 27.007 7.7
- * ((int *)data)[1] is "m" parameter from TS 27.007 7.7
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  FDN_CHECK_FAILURE
- *  SYSTEM_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_GET_CLIR 31
-
-/**
- * RIL_REQUEST_SET_CLIR
- *
- * "data" is int *
- * ((int *)data)[0] is "n" parameter from TS 27.007 7.7
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  SYSTEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SET_CLIR 32
-
-/**
- * RIL_REQUEST_QUERY_CALL_FORWARD_STATUS
- *
- * "data" is const RIL_CallForwardInfo *
- *
- * "response" is const RIL_CallForwardInfo **
- * "response" points to an array of RIL_CallForwardInfo *'s, one for
- * each distinct registered phone number.
- *
- * For example, if data is forwarded to +18005551212 and voice is forwarded
- * to +18005559999, then two separate RIL_CallForwardInfo's should be returned
- *
- * If, however, both data and voice are forwarded to +18005551212, then
- * a single RIL_CallForwardInfo can be returned with the service class
- * set to "data + voice = 3")
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_QUERY_CALL_FORWARD_STATUS 33
-
-
-/**
- * RIL_REQUEST_SET_CALL_FORWARD
- *
- * Configure call forward rule
- *
- * "data" is const RIL_CallForwardInfo *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_STATE
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SET_CALL_FORWARD 34
-
-
-/**
- * RIL_REQUEST_QUERY_CALL_WAITING
- *
- * Query current call waiting state
- *
- * "data" is const int *
- * ((const int *)data)[0] is the TS 27.007 service class to query.
- * "response" is a const int *
- * ((const int *)response)[0] is 0 for "disabled" and 1 for "enabled"
- *
- * If ((const int *)response)[0] is = 1, then ((const int *)response)[1]
- * must follow, with the TS 27.007 service class bit vector of services
- * for which call waiting is enabled.
- *
- * For example, if ((const int *)response)[0]  is 1 and
- * ((const int *)response)[1] is 3, then call waiting is enabled for data
- * and voice and disabled for everything else
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  FDN_CHECK_FAILURE
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_QUERY_CALL_WAITING 35
-
-
-/**
- * RIL_REQUEST_SET_CALL_WAITING
- *
- * Configure current call waiting state
- *
- * "data" is const int *
- * ((const int *)data)[0] is 0 for "disabled" and 1 for "enabled"
- * ((const int *)data)[1] is the TS 27.007 service class bit vector of
- *                           services to modify
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_STATE
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SET_CALL_WAITING 36
-
-/**
- * RIL_REQUEST_SMS_ACKNOWLEDGE
- *
- * Acknowledge successful or failed receipt of SMS previously indicated
- * via RIL_UNSOL_RESPONSE_NEW_SMS
- *
- * "data" is int *
- * ((int *)data)[0] is 1 on successful receipt
- *                  (basically, AT+CNMA=1 from TS 27.005
- *                  is 0 on failed receipt
- *                  (basically, AT+CNMA=2 from TS 27.005)
- * ((int *)data)[1] if data[0] is 0, this contains the failure cause as defined
- *                  in TS 23.040, 9.2.3.22. Currently only 0xD3 (memory
- *                  capacity exceeded) and 0xFF (unspecified error) are
- *                  reported.
- *
- * "response" is NULL
- *
- * FIXME would like request that specified RP-ACK/RP-ERROR PDU
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SMS_ACKNOWLEDGE  37
-
-/**
- * RIL_REQUEST_GET_IMEI - DEPRECATED
- *
- * Get the device IMEI, including check digit
- *
- * The request is DEPRECATED, use RIL_REQUEST_DEVICE_IDENTITY
- * Valid when RadioState is not RADIO_STATE_UNAVAILABLE
- *
- * "data" is NULL
- * "response" is a const char * containing the IMEI
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-
-#define RIL_REQUEST_GET_IMEI 38
-
-/**
- * RIL_REQUEST_GET_IMEISV - DEPRECATED
- *
- * Get the device IMEISV, which should be two decimal digits
- *
- * The request is DEPRECATED, use RIL_REQUEST_DEVICE_IDENTITY
- * Valid when RadioState is not RADIO_STATE_UNAVAILABLE
- *
- * "data" is NULL
- * "response" is a const char * containing the IMEISV
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-
-#define RIL_REQUEST_GET_IMEISV 39
-
-
-/**
- * RIL_REQUEST_ANSWER
- *
- * Answer incoming call
- *
- * Will not be called for WAITING calls.
- * RIL_REQUEST_SWITCH_WAITING_OR_HOLDING_AND_ACTIVE will be used in this case
- * instead
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_STATE
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_ANSWER 40
-
-/**
- * RIL_REQUEST_DEACTIVATE_DATA_CALL
- *
- * Deactivate packet data connection and remove from the
- * data call list if SUCCESS is returned. Any other return
- * values should also try to remove the call from the list,
- * but that may not be possible. In any event a
- * RIL_REQUEST_RADIO_POWER off/on must clear the list. An
- * RIL_UNSOL_DATA_CALL_LIST_CHANGED is not expected to be
- * issued because of an RIL_REQUEST_DEACTIVATE_DATA_CALL.
- *
- * "data" is const char **
- * ((char**)data)[0] indicating CID
- * ((char**)data)[1] indicating Disconnect Reason
- *                   0 => No specific reason specified
- *                   1 => Radio shutdown requested
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_CALL_ID
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  REQUEST_NOT_SUPPORTED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  SIM_ABSENT
- *
- * See also: RIL_REQUEST_SETUP_DATA_CALL
- */
-#define RIL_REQUEST_DEACTIVATE_DATA_CALL 41
-
-/**
- * RIL_REQUEST_QUERY_FACILITY_LOCK
- *
- * Query the status of a facility lock state
- *
- * "data" is const char **
- * ((const char **)data)[0] is the facility string code from TS 27.007 7.4
- *                      (eg "AO" for BAOC, "SC" for SIM lock)
- * ((const char **)data)[1] is the password, or "" if not required
- * ((const char **)data)[2] is the TS 27.007 service class bit vector of
- *                           services to query
- * ((const char **)data)[3] is AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *                            This is only applicable in the case of Fixed Dialing Numbers
- *                            (FDN) requests.
- *
- * "response" is an int *
- * ((const int *)response) 0 is the TS 27.007 service class bit vector of
- *                           services for which the specified barring facility
- *                           is active. "0" means "disabled for all"
- *
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_QUERY_FACILITY_LOCK 42
-
-/**
- * RIL_REQUEST_SET_FACILITY_LOCK
- *
- * Enable/disable one facility lock
- *
- * "data" is const char **
- *
- * ((const char **)data)[0] = facility string code from TS 27.007 7.4
- * (eg "AO" for BAOC)
- * ((const char **)data)[1] = "0" for "unlock" and "1" for "lock"
- * ((const char **)data)[2] = password
- * ((const char **)data)[3] = string representation of decimal TS 27.007
- *                            service class bit vector. Eg, the string
- *                            "1" means "set this facility for voice services"
- * ((const char **)data)[4] = AID value, See ETSI 102.221 8.1 and 101.220 4, NULL if no value.
- *                            This is only applicable in the case of Fixed Dialing Numbers
- *                            (FDN) requests.
- *
- * "response" is int *
- * ((int *)response)[0] is the number of retries remaining, or -1 if unknown
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  MODEM_ERR
- *  INVALID_STATE
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_SET_FACILITY_LOCK 43
-
-/**
- * RIL_REQUEST_CHANGE_BARRING_PASSWORD
- *
- * Change call barring facility password
- *
- * "data" is const char **
- *
- * ((const char **)data)[0] = facility string code from TS 27.007 7.4
- * (eg "AO" for BAOC)
- * ((const char **)data)[1] = old password
- * ((const char **)data)[2] = new password
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CHANGE_BARRING_PASSWORD 44
-
-/**
- * RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE
- *
- * Query current network selectin mode
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((const int *)response)[0] is
- *     0 for automatic selection
- *     1 for manual selection
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE 45
-
-/**
- * RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC
- *
- * Specify that the network should be selected automatically
- *
- * "data" is NULL
- * "response" is NULL
- *
- * This request must not respond until the new operator is selected
- * and registered
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  ILLEGAL_SIM_OR_ME
- *  OPERATION_NOT_ALLOWED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- * Note: Returns ILLEGAL_SIM_OR_ME when the failure is permanent and
- *       no retries needed, such as illegal SIM or ME.
- *
- */
-#define RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC 46
-
-/**
- * RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL
- *
- * Manually select a specified network.
- *
- * "data" is const char * specifying MCCMNC of network to select (eg "310170")
- * "response" is NULL
- *
- * This request must not respond until the new operator is selected
- * and registered
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  ILLEGAL_SIM_OR_ME
- *  OPERATION_NOT_ALLOWED
- *  INVALID_STATE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- * Note: Returns ILLEGAL_SIM_OR_ME when the failure is permanent and
- *       no retries needed, such as illegal SIM or ME.
- *
- */
-#define RIL_REQUEST_SET_NETWORK_SELECTION_MANUAL 47
-
-/**
- * RIL_REQUEST_QUERY_AVAILABLE_NETWORKS
- *
- * Scans for available networks
- *
- * "data" is NULL
- * "response" is const char ** that should be an array of n*4 strings, where
- *    n is the number of available networks
- * For each available network:
- *
- * ((const char **)response)[n+0] is long alpha ONS or EONS
- * ((const char **)response)[n+1] is short alpha ONS or EONS
- * ((const char **)response)[n+2] is 5 or 6 digit numeric code (MCC + MNC)
- * ((const char **)response)[n+3] is a string value of the status:
- *           "unknown"
- *           "available"
- *           "current"
- *           "forbidden"
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  ABORTED
- *  DEVICE_IN_USE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  CANCELLED
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_QUERY_AVAILABLE_NETWORKS 48
-
-/**
- * RIL_REQUEST_DTMF_START
- *
- * Start playing a DTMF tone. Continue playing DTMF tone until
- * RIL_REQUEST_DTMF_STOP is received
- *
- * If a RIL_REQUEST_DTMF_START is received while a tone is currently playing,
- * it should cancel the previous tone and play the new one.
- *
- * "data" is a char *
- * ((char *)data)[0] is a single character with one of 12 values: 0-9,*,#
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_DTMF, RIL_REQUEST_DTMF_STOP
- */
-#define RIL_REQUEST_DTMF_START 49
-
-/**
- * RIL_REQUEST_DTMF_STOP
- *
- * Stop playing a currently playing DTMF tone.
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  NO_MEMORY
- *  INVALID_ARGUMENTS
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_DTMF, RIL_REQUEST_DTMF_START
- */
-#define RIL_REQUEST_DTMF_STOP 50
-
-/**
- * RIL_REQUEST_BASEBAND_VERSION
- *
- * Return string value indicating baseband version, eg
- * response from AT+CGMR
- *
- * "data" is NULL
- * "response" is const char * containing version string for log reporting
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  EMPTY_RECORD
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_BASEBAND_VERSION 51
-
-/**
- * RIL_REQUEST_SEPARATE_CONNECTION
- *
- * Separate a party from a multiparty call placing the multiparty call
- * (less the specified party) on hold and leaving the specified party
- * as the only other member of the current (active) call
- *
- * Like AT+CHLD=2x
- *
- * See TS 22.084 1.3.8.2 (iii)
- * TS 22.030 6.5.5 "Entering "2X followed by send"
- * TS 27.007 "AT+CHLD=2x"
- *
- * "data" is an int *
- * (int *)data)[0] contains Connection index (value of 'x' in CHLD above) "response" is NULL
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_ARGUMENTS
- *  INVALID_STATE
- *  NO_RESOURCES
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  INVALID_STATE
- *  OPERATION_NOT_ALLOWED
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SEPARATE_CONNECTION 52
-
-
-/**
- * RIL_REQUEST_SET_MUTE
- *
- * Turn on or off uplink (microphone) mute.
- *
- * Will only be sent while voice call is active.
- * Will always be reset to "disable mute" when a new voice call is initiated
- *
- * "data" is an int *
- * (int *)data)[0] is 1 for "enable mute" and 0 for "disable mute"
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_SET_MUTE 53
-
-/**
- * RIL_REQUEST_GET_MUTE
- *
- * Queries the current state of the uplink mute setting
- *
- * "data" is NULL
- * "response" is an int *
- * (int *)response)[0] is 1 for "mute enabled" and 0 for "mute disabled"
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  SS_MODIFIED_TO_DIAL
- *  SS_MODIFIED_TO_USSD
- *  SS_MODIFIED_TO_SS
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_GET_MUTE 54
-
-/**
- * RIL_REQUEST_QUERY_CLIP
- *
- * Queries the status of the CLIP supplementary service
- *
- * (for MMI code "*#30#")
- *
- * "data" is NULL
- * "response" is an int *
- * (int *)response)[0] is 1 for "CLIP provisioned"
- *                           and 0 for "CLIP not provisioned"
- *                           and 2 for "unknown, e.g. no network etc"
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  FDN_CHECK_FAILURE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_QUERY_CLIP 55
-
-/**
- * RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE - Deprecated use the status
- * field in RIL_Data_Call_Response_v6.
- *
- * Requests the failure cause code for the most recently failed PDP
- * context or CDMA data connection active
- * replaces RIL_REQUEST_LAST_PDP_FAIL_CAUSE
- *
- * "data" is NULL
- *
- * "response" is a "int *"
- * ((int *)response)[0] is an integer cause code defined in TS 24.008
- *   section 6.1.3.1.3 or close approximation
- *
- * If the implementation does not have access to the exact cause codes,
- * then it should return one of the values listed in
- * RIL_DataCallFailCause, as the UI layer needs to distinguish these
- * cases for error notification
- * and potential retries.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_LAST_CALL_FAIL_CAUSE
- *
- * Deprecated use the status field in RIL_Data_Call_Response_v6.
- */
-
-#define RIL_REQUEST_LAST_DATA_CALL_FAIL_CAUSE 56
-
-/**
- * RIL_REQUEST_DATA_CALL_LIST
- *
- * Returns the data call list. An entry is added when a
- * RIL_REQUEST_SETUP_DATA_CALL is issued and removed on a
- * RIL_REQUEST_DEACTIVATE_DATA_CALL. The list is emptied
- * when RIL_REQUEST_RADIO_POWER off/on is issued.
- *
- * "data" is NULL
- * "response" is an array of RIL_Data_Call_Response_v6
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- * See also: RIL_UNSOL_DATA_CALL_LIST_CHANGED
- */
-
-#define RIL_REQUEST_DATA_CALL_LIST 57
-
-/**
- * RIL_REQUEST_RESET_RADIO - DEPRECATED
- *
- * Request a radio reset. The RIL implementation may postpone
- * the reset until after this request is responded to if the baseband
- * is presently busy.
- *
- * The request is DEPRECATED, use RIL_REQUEST_RADIO_POWER
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  REQUEST_NOT_SUPPORTED
- */
-
-#define RIL_REQUEST_RESET_RADIO 58
-
-/**
- * RIL_REQUEST_OEM_HOOK_RAW
- *
- * This request reserved for OEM-specific uses. It passes raw byte arrays
- * back and forth.
- *
- * It can be invoked on the Java side from
- * com.android.internal.telephony.Phone.invokeOemRilRequestRaw()
- *
- * "data" is a char * of bytes copied from the byte[] data argument in java
- * "response" is a char * of bytes that will returned via the
- * caller's "response" Message here:
- * (byte[])(((AsyncResult)response.obj).result)
- *
- * An error response here will result in
- * (((AsyncResult)response.obj).result) == null and
- * (((AsyncResult)response.obj).exception) being an instance of
- * com.android.internal.telephony.gsm.CommandException
- *
- * Valid errors:
- *  All
- */
-
-#define RIL_REQUEST_OEM_HOOK_RAW 59
-
-/**
- * RIL_REQUEST_OEM_HOOK_STRINGS
- *
- * This request reserved for OEM-specific uses. It passes strings
- * back and forth.
- *
- * It can be invoked on the Java side from
- * com.android.internal.telephony.Phone.invokeOemRilRequestStrings()
- *
- * "data" is a const char **, representing an array of null-terminated UTF-8
- * strings copied from the "String[] strings" argument to
- * invokeOemRilRequestStrings()
- *
- * "response" is a const char **, representing an array of null-terminated UTF-8
- * stings that will be returned via the caller's response message here:
- *
- * (String[])(((AsyncResult)response.obj).result)
- *
- * An error response here will result in
- * (((AsyncResult)response.obj).result) == null and
- * (((AsyncResult)response.obj).exception) being an instance of
- * com.android.internal.telephony.gsm.CommandException
- *
- * Valid errors:
- *  All
- */
-
-#define RIL_REQUEST_OEM_HOOK_STRINGS 60
-
-/**
- * RIL_REQUEST_SCREEN_STATE - DEPRECATED
- *
- * Indicates the current state of the screen.  When the screen is off, the
- * RIL should notify the baseband to suppress certain notifications (eg,
- * signal strength and changes in LAC/CID or BID/SID/NID/latitude/longitude)
- * in an effort to conserve power.  These notifications should resume when the
- * screen is on.
- *
- * Note this request is deprecated. Use RIL_REQUEST_SEND_DEVICE_STATE to report the device state
- * to the modem and use RIL_REQUEST_SET_UNSOLICITED_RESPONSE_FILTER to turn on/off unsolicited
- * response from the modem in different scenarios.
- *
- * "data" is int *
- * ((int *)data)[0] is == 1 for "Screen On"
- * ((int *)data)[0] is == 0 for "Screen Off"
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SCREEN_STATE 61
-
-
-/**
- * RIL_REQUEST_SET_SUPP_SVC_NOTIFICATION
- *
- * Enables/disables supplementary service related notifications
- * from the network.
- *
- * Notifications are reported via RIL_UNSOL_SUPP_SVC_NOTIFICATION.
- *
- * "data" is int *
- * ((int *)data)[0] is == 1 for notifications enabled
- * ((int *)data)[0] is == 0 for notifications disabled
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SIM_BUSY
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_UNSOL_SUPP_SVC_NOTIFICATION.
- */
-#define RIL_REQUEST_SET_SUPP_SVC_NOTIFICATION 62
-
-/**
- * RIL_REQUEST_WRITE_SMS_TO_SIM
- *
- * Stores a SMS message to SIM memory.
- *
- * "data" is RIL_SMS_WriteArgs *
- *
- * "response" is int *
- * ((const int *)response)[0] is the record index where the message is stored.
- *
- * Valid errors:
- *  SUCCESS
- *  SIM_FULL
- *  INVALID_ARGUMENTS
- *  INVALID_SMS_FORMAT
- *  INTERNAL_ERR
- *  MODEM_ERR
- *  ENCODING_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  INVALID_MODEM_STATE
- *  OPERATION_NOT_ALLOWED
- *  INVALID_SMSC_ADDRESS
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- */
-#define RIL_REQUEST_WRITE_SMS_TO_SIM 63
-
-/**
- * RIL_REQUEST_DELETE_SMS_ON_SIM
- *
- * Deletes a SMS message from SIM memory.
- *
- * "data" is int  *
- * ((int *)data)[0] is the record index of the message to delete.
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  SIM_FULL
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NO_SUCH_ENTRY
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- */
-#define RIL_REQUEST_DELETE_SMS_ON_SIM 64
-
-/**
- * RIL_REQUEST_SET_BAND_MODE
- *
- * Assign a specified band for RF configuration.
- *
- * "data" is int *
- * ((int *)data)[0] is a RIL_RadioBandMode
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- * See also: RIL_REQUEST_QUERY_AVAILABLE_BAND_MODE
- */
-#define RIL_REQUEST_SET_BAND_MODE 65
-
-/**
- * RIL_REQUEST_QUERY_AVAILABLE_BAND_MODE
- *
- * Query the list of band mode supported by RF.
- *
- * "data" is NULL
- *
- * "response" is int *
- * "response" points to an array of int's, the int[0] is the size of array;
- * subsequent values are a list of RIL_RadioBandMode listing supported modes.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- * See also: RIL_REQUEST_SET_BAND_MODE
- */
-#define RIL_REQUEST_QUERY_AVAILABLE_BAND_MODE 66
-
-/**
- * RIL_REQUEST_STK_GET_PROFILE
- *
- * Requests the profile of SIM tool kit.
- * The profile indicates the SAT/USAT features supported by ME.
- * The SAT/USAT features refer to 3GPP TS 11.14 and 3GPP TS 31.111
- *
- * "data" is NULL
- *
- * "response" is a const char * containing SAT/USAT profile
- * in hexadecimal format string starting with first byte of terminal profile
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE (radio resetting)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_STK_GET_PROFILE 67
-
-/**
- * RIL_REQUEST_STK_SET_PROFILE
- *
- * Download the STK terminal profile as part of SIM initialization
- * procedure
- *
- * "data" is a const char * containing SAT/USAT profile
- * in hexadecimal format string starting with first byte of terminal profile
- *
- * "response" is NULL
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE (radio resetting)
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_STK_SET_PROFILE 68
-
-/**
- * RIL_REQUEST_STK_SEND_ENVELOPE_COMMAND
- *
- * Requests to send a SAT/USAT envelope command to SIM.
- * The SAT/USAT envelope command refers to 3GPP TS 11.14 and 3GPP TS 31.111
- *
- * "data" is a const char * containing SAT/USAT command
- * in hexadecimal format string starting with command tag
- *
- * "response" is a const char * containing SAT/USAT response
- * in hexadecimal format string starting with first byte of response
- * (May be NULL)
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE (radio resetting)
- *  SIM_BUSY
- *  OPERATION_NOT_ALLOWED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_STK_SEND_ENVELOPE_COMMAND 69
-
-/**
- * RIL_REQUEST_STK_SEND_TERMINAL_RESPONSE
- *
- * Requests to send a terminal response to SIM for a received
- * proactive command
- *
- * "data" is a const char * containing SAT/USAT response
- * in hexadecimal format string starting with first byte of response data
- *
- * "response" is NULL
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE (radio resetting)
- *  RIL_E_OPERATION_NOT_ALLOWED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_STK_SEND_TERMINAL_RESPONSE 70
-
-/**
- * RIL_REQUEST_STK_HANDLE_CALL_SETUP_REQUESTED_FROM_SIM
- *
- * When STK application gets RIL_UNSOL_STK_CALL_SETUP, the call actually has
- * been initialized by ME already. (We could see the call has been in the 'call
- * list') So, STK application needs to accept/reject the call according as user
- * operations.
- *
- * "data" is int *
- * ((int *)data)[0] is > 0 for "accept" the call setup
- * ((int *)data)[0] is == 0 for "reject" the call setup
- *
- * "response" is NULL
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE (radio resetting)
- *  RIL_E_OPERATION_NOT_ALLOWED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_STK_HANDLE_CALL_SETUP_REQUESTED_FROM_SIM 71
-
-/**
- * RIL_REQUEST_EXPLICIT_CALL_TRANSFER
- *
- * Connects the two calls and disconnects the subscriber from both calls.
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  INVALID_STATE
- *  NO_RESOURCES
- *  NO_MEMORY
- *  INVALID_ARGUMENTS
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  INVALID_STATE
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_EXPLICIT_CALL_TRANSFER 72
-
-/**
- * RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE
- *
- * Requests to set the preferred network type for searching and registering
- * (CS/PS domain, RAT, and operation mode)
- *
- * "data" is int * which is RIL_PreferredNetworkType
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  OPERATION_NOT_ALLOWED
- *  MODE_NOT_SUPPORTED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE 73
-
-/**
- * RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE
- *
- * Query the preferred network type (CS/PS domain, RAT, and operation mode)
- * for searching and registering
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((int *)reponse)[0] is == RIL_PreferredNetworkType
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- * See also: RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE
- */
-#define RIL_REQUEST_GET_PREFERRED_NETWORK_TYPE 74
-
-/**
- * RIL_REQUEST_NEIGHBORING_CELL_IDS
- *
- * Request neighboring cell id in GSM network
- *
- * "data" is NULL
- * "response" must be a " const RIL_NeighboringCell** "
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NO_NETWORK_FOUND
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_GET_NEIGHBORING_CELL_IDS 75
-
-/**
- * RIL_REQUEST_SET_LOCATION_UPDATES
- *
- * Enables/disables network state change notifications due to changes in
- * LAC and/or CID (for GSM) or BID/SID/NID/latitude/longitude (for CDMA).
- * Basically +CREG=2 vs. +CREG=1 (TS 27.007).
- *
- * Note:  The RIL implementation should default to "updates enabled"
- * when the screen is on and "updates disabled" when the screen is off.
- *
- * "data" is int *
- * ((int *)data)[0] is == 1 for updates enabled (+CREG=2)
- * ((int *)data)[0] is == 0 for updates disabled (+CREG=1)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- * See also: RIL_REQUEST_SCREEN_STATE, RIL_UNSOL_RESPONSE_NETWORK_STATE_CHANGED
- */
-#define RIL_REQUEST_SET_LOCATION_UPDATES 76
-
-/**
- * RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE
- *
- * Request to set the location where the CDMA subscription shall
- * be retrieved
- *
- * "data" is int *
- * ((int *)data)[0] is == RIL_CdmaSubscriptionSource
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SIM_ABSENT
- *  SUBSCRIPTION_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_CDMA_GET_SUBSCRIPTION_SOURCE
- */
-#define RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE 77
-
-/**
- * RIL_REQUEST_CDMA_SET_ROAMING_PREFERENCE
- *
- * Request to set the roaming preferences in CDMA
- *
- * "data" is int *
- * ((int *)data)[0] is == 0 for Home Networks only, as defined in PRL
- * ((int *)data)[0] is == 1 for Roaming on Affiliated networks, as defined in PRL
- * ((int *)data)[0] is == 2 for Roaming on Any Network, as defined in the PRL
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_CDMA_SET_ROAMING_PREFERENCE 78
-
-/**
- * RIL_REQUEST_CDMA_QUERY_ROAMING_PREFERENCE
- *
- * Request the actual setting of the roaming preferences in CDMA in the modem
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((int *)response)[0] is == 0 for Home Networks only, as defined in PRL
- * ((int *)response)[0] is == 1 for Roaming on Affiliated networks, as defined in PRL
- * ((int *)response)[0] is == 2 for Roaming on Any Network, as defined in the PRL
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_CDMA_QUERY_ROAMING_PREFERENCE 79
-
-/**
- * RIL_REQUEST_SET_TTY_MODE
- *
- * Request to set the TTY mode
- *
- * "data" is int *
- * ((int *)data)[0] is == 0 for TTY off
- * ((int *)data)[0] is == 1 for TTY Full
- * ((int *)data)[0] is == 2 for TTY HCO (hearing carryover)
- * ((int *)data)[0] is == 3 for TTY VCO (voice carryover)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SET_TTY_MODE 80
-
-/**
- * RIL_REQUEST_QUERY_TTY_MODE
- *
- * Request the setting of TTY mode
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((int *)response)[0] is == 0 for TTY off
- * ((int *)response)[0] is == 1 for TTY Full
- * ((int *)response)[0] is == 2 for TTY HCO (hearing carryover)
- * ((int *)response)[0] is == 3 for TTY VCO (voice carryover)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_QUERY_TTY_MODE 81
-
-/**
- * RIL_REQUEST_CDMA_SET_PREFERRED_VOICE_PRIVACY_MODE
- *
- * Request to set the preferred voice privacy mode used in voice
- * scrambling
- *
- * "data" is int *
- * ((int *)data)[0] is == 0 for Standard Privacy Mode (Public Long Code Mask)
- * ((int *)data)[0] is == 1 for Enhanced Privacy Mode (Private Long Code Mask)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_CALL_ID
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_CDMA_SET_PREFERRED_VOICE_PRIVACY_MODE 82
-
-/**
- * RIL_REQUEST_CDMA_QUERY_PREFERRED_VOICE_PRIVACY_MODE
- *
- * Request the setting of preferred voice privacy mode
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((int *)response)[0] is == 0 for Standard Privacy Mode (Public Long Code Mask)
- * ((int *)response)[0] is == 1 for Enhanced Privacy Mode (Private Long Code Mask)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  INVALID_ARGUMENTS
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_CDMA_QUERY_PREFERRED_VOICE_PRIVACY_MODE 83
-
-/**
- * RIL_REQUEST_CDMA_FLASH
- *
- * Send FLASH
- *
- * "data" is const char *
- * ((const char *)data)[0] is a FLASH string
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  INVALID_STATE
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CDMA_FLASH 84
-
-/**
- * RIL_REQUEST_CDMA_BURST_DTMF
- *
- * Send DTMF string
- *
- * "data" is const char **
- * ((const char **)data)[0] is a DTMF string
- * ((const char **)data)[1] is the DTMF ON length in milliseconds, or 0 to use
- *                          default
- * ((const char **)data)[2] is the DTMF OFF length in milliseconds, or 0 to use
- *                          default
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  INVALID_CALL_ID
- *  NO_RESOURCES
- *  CANCELLED
- *  OPERATION_NOT_ALLOWED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CDMA_BURST_DTMF 85
-
-/**
- * RIL_REQUEST_CDMA_VALIDATE_AND_WRITE_AKEY
- *
- * Takes a 26 digit string (20 digit AKEY + 6 digit checksum).
- * If the checksum is valid the 20 digit AKEY is written to NV,
- * replacing the existing AKEY no matter what it was before.
- *
- * "data" is const char *
- * ((const char *)data)[0] is a 26 digit string (ASCII digits '0'-'9')
- *                         where the last 6 digits are a checksum of the
- *                         first 20, as specified in TR45.AHAG
- *                         "Common Cryptographic Algorithms, Revision D.1
- *                         Section 2.2"
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_CDMA_VALIDATE_AND_WRITE_AKEY 86
-
-/**
- * RIL_REQUEST_CDMA_SEND_SMS
- *
- * Send a CDMA SMS message
- *
- * "data" is const RIL_CDMA_SMS_Message *
- *
- * "response" is a const RIL_SMS_Response *
- *
- * Based on the return error, caller decides to resend if sending sms
- * fails. The CDMA error class is derived as follows,
- * SUCCESS is error class 0 (no error)
- * SMS_SEND_FAIL_RETRY is error class 2 (temporary failure)
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SMS_SEND_FAIL_RETRY
- *  NETWORK_REJECT
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  INVALID_SMS_FORMAT
- *  SYSTEM_ERR
- *  FDN_CHECK_FAILURE
- *  MODEM_ERR
- *  NETWORK_ERR
- *  ENCODING_ERR
- *  INVALID_SMSC_ADDRESS
- *  OPERATION_NOT_ALLOWED
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  MODE_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- */
-#define RIL_REQUEST_CDMA_SEND_SMS 87
-
-/**
- * RIL_REQUEST_CDMA_SMS_ACKNOWLEDGE
- *
- * Acknowledge the success or failure in the receipt of SMS
- * previously indicated via RIL_UNSOL_RESPONSE_CDMA_NEW_SMS
- *
- * "data" is const RIL_CDMA_SMS_Ack *
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_SMS_TO_ACK
- *  INVALID_STATE
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INVALID_STATE
- *  OPERATION_NOT_ALLOWED
- *  NETWORK_NOT_READY
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CDMA_SMS_ACKNOWLEDGE 88
-
-/**
- * RIL_REQUEST_GSM_GET_BROADCAST_SMS_CONFIG
- *
- * Request the setting of GSM/WCDMA Cell Broadcast SMS config.
- *
- * "data" is NULL
- *
- * "response" is a const RIL_GSM_BroadcastSmsConfigInfo **
- * "responselen" is count * sizeof (RIL_GSM_BroadcastSmsConfigInfo *)
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_STATE
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  SYSTEM_ERR
- *  NO_RESOURCES
- *  MODEM_ERR
- *  SYSTEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_GSM_GET_BROADCAST_SMS_CONFIG 89
-
-/**
- * RIL_REQUEST_GSM_SET_BROADCAST_SMS_CONFIG
- *
- * Set GSM/WCDMA Cell Broadcast SMS config
- *
- * "data" is a const RIL_GSM_BroadcastSmsConfigInfo **
- * "datalen" is count * sizeof(RIL_GSM_BroadcastSmsConfigInfo *)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  MODEM_ERR
- *  SYSTEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_GSM_SET_BROADCAST_SMS_CONFIG 90
-
-/**
- * RIL_REQUEST_GSM_SMS_BROADCAST_ACTIVATION
- *
-* Enable or disable the reception of GSM/WCDMA Cell Broadcast SMS
- *
- * "data" is const int *
- * (const int *)data[0] indicates to activate or turn off the
- * reception of GSM/WCDMA Cell Broadcast SMS, 0-1,
- *                       0 - Activate, 1 - Turn off
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
-*   MODEM_ERR
-*   INTERNAL_ERR
-*   NO_RESOURCES
-*   CANCELLED
-*   INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_GSM_SMS_BROADCAST_ACTIVATION 91
-
-/**
- * RIL_REQUEST_CDMA_GET_BROADCAST_SMS_CONFIG
- *
- * Request the setting of CDMA Broadcast SMS config
- *
- * "data" is NULL
- *
- * "response" is a const RIL_CDMA_BroadcastSmsConfigInfo **
- * "responselen" is count * sizeof (RIL_CDMA_BroadcastSmsConfigInfo *)
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_STATE
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  SYSTEM_ERR
- *  NO_RESOURCES
- *  MODEM_ERR
- *  SYSTEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CDMA_GET_BROADCAST_SMS_CONFIG 92
-
-/**
- * RIL_REQUEST_CDMA_SET_BROADCAST_SMS_CONFIG
- *
- * Set CDMA Broadcast SMS config
- *
- * "data" is a const RIL_CDMA_BroadcastSmsConfigInfo **
- * "datalen" is count * sizeof(const RIL_CDMA_BroadcastSmsConfigInfo *)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  MODEM_ERR
- *  SYSTEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CDMA_SET_BROADCAST_SMS_CONFIG 93
-
-/**
- * RIL_REQUEST_CDMA_SMS_BROADCAST_ACTIVATION
- *
- * Enable or disable the reception of CDMA Broadcast SMS
- *
- * "data" is const int *
- * (const int *)data[0] indicates to activate or turn off the
- * reception of CDMA Broadcast SMS, 0-1,
- *                       0 - Activate, 1 - Turn off
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_STATE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_CDMA_SMS_BROADCAST_ACTIVATION 94
-
-/**
- * RIL_REQUEST_CDMA_SUBSCRIPTION
- *
- * Request the device MDN / H_SID / H_NID.
- *
- * The request is only allowed when CDMA subscription is available.  When CDMA
- * subscription is changed, application layer should re-issue the request to
- * update the subscription information.
- *
- * If a NULL value is returned for any of the device id, it means that error
- * accessing the device.
- *
- * "response" is const char **
- * ((const char **)response)[0] is MDN if CDMA subscription is available
- * ((const char **)response)[1] is a comma separated list of H_SID (Home SID) if
- *                              CDMA subscription is available, in decimal format
- * ((const char **)response)[2] is a comma separated list of H_NID (Home NID) if
- *                              CDMA subscription is available, in decimal format
- * ((const char **)response)[3] is MIN (10 digits, MIN2+MIN1) if CDMA subscription is available
- * ((const char **)response)[4] is PRL version if CDMA subscription is available
- *
- * Valid errors:
- *  SUCCESS
- *  RIL_E_SUBSCRIPTION_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-
-#define RIL_REQUEST_CDMA_SUBSCRIPTION 95
-
-/**
- * RIL_REQUEST_CDMA_WRITE_SMS_TO_RUIM
- *
- * Stores a CDMA SMS message to RUIM memory.
- *
- * "data" is RIL_CDMA_SMS_WriteArgs *
- *
- * "response" is int *
- * ((const int *)response)[0] is the record index where the message is stored.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SIM_FULL
- *  INVALID_ARGUMENTS
- *  INVALID_SMS_FORMAT
- *  INTERNAL_ERR
- *  MODEM_ERR
- *  ENCODING_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  INVALID_MODEM_STATE
- *  OPERATION_NOT_ALLOWED
- *  INVALID_SMSC_ADDRESS
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- */
-#define RIL_REQUEST_CDMA_WRITE_SMS_TO_RUIM 96
-
-/**
- * RIL_REQUEST_CDMA_DELETE_SMS_ON_RUIM
- *
- * Deletes a CDMA SMS message from RUIM memory.
- *
- * "data" is int  *
- * ((int *)data)[0] is the record index of the message to delete.
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NO_SUCH_ENTRY
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- */
-#define RIL_REQUEST_CDMA_DELETE_SMS_ON_RUIM 97
-
-/**
- * RIL_REQUEST_DEVICE_IDENTITY
- *
- * Request the device ESN / MEID / IMEI / IMEISV.
- *
- * The request is always allowed and contains GSM and CDMA device identity;
- * it substitutes the deprecated requests RIL_REQUEST_GET_IMEI and
- * RIL_REQUEST_GET_IMEISV.
- *
- * If a NULL value is returned for any of the device id, it means that error
- * accessing the device.
- *
- * When CDMA subscription is changed the ESN/MEID may change.  The application
- * layer should re-issue the request to update the device identity in this case.
- *
- * "response" is const char **
- * ((const char **)response)[0] is IMEI if GSM subscription is available
- * ((const char **)response)[1] is IMEISV if GSM subscription is available
- * ((const char **)response)[2] is ESN if CDMA subscription is available
- * ((const char **)response)[3] is MEID if CDMA subscription is available
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_DEVICE_IDENTITY 98
-
-/**
- * RIL_REQUEST_EXIT_EMERGENCY_CALLBACK_MODE
- *
- * Request the radio's system selection module to exit emergency
- * callback mode.  RIL will not respond with SUCCESS until the modem has
- * completely exited from Emergency Callback Mode.
- *
- * "data" is NULL
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_EXIT_EMERGENCY_CALLBACK_MODE 99
-
-/**
- * RIL_REQUEST_GET_SMSC_ADDRESS
- *
- * Queries the default Short Message Service Center address on the device.
- *
- * "data" is NULL
- *
- * "response" is const char * containing the SMSC address.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  REQUEST_RATE_LIMITED
- *  SYSTEM_ERR
- *  INTERNAL_ERR
- *  MODEM_ERR
- *  INVALID_ARGUMENTS
- *  INVALID_MODEM_STATE
- *  NOT_PROVISIONED
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- *
- */
-#define RIL_REQUEST_GET_SMSC_ADDRESS 100
-
-/**
- * RIL_REQUEST_SET_SMSC_ADDRESS
- *
- * Sets the default Short Message Service Center address on the device.
- *
- * "data" is const char * containing the SMSC address.
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  INVALID_SMS_FORMAT
- *  NO_MEMORY
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  MODEM_ERR
- *  NO_RESOURCES
- *  INTERNAL_ERR
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- */
-#define RIL_REQUEST_SET_SMSC_ADDRESS 101
-
-/**
- * RIL_REQUEST_REPORT_SMS_MEMORY_STATUS
- *
- * Indicates whether there is storage available for new SMS messages.
- *
- * "data" is int *
- * ((int *)data)[0] is 1 if memory is available for storing new messages
- *                  is 0 if memory capacity is exceeded
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INVALID_ARGUMENTS
- *  NO_MEMORY
- *  INVALID_STATE
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  MODEM_ERR
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_REPORT_SMS_MEMORY_STATUS 102
-
-/**
- * RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING
- *
- * Indicates that the StkSerivce is running and is
- * ready to receive RIL_UNSOL_STK_XXXXX commands.
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_REPORT_STK_SERVICE_IS_RUNNING 103
-
-/**
- * RIL_REQUEST_CDMA_GET_SUBSCRIPTION_SOURCE
- *
- * Request to query the location where the CDMA subscription shall
- * be retrieved
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((int *)data)[0] is == RIL_CdmaSubscriptionSource
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SUBSCRIPTION_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- * See also: RIL_REQUEST_CDMA_SET_SUBSCRIPTION_SOURCE
- */
-#define RIL_REQUEST_CDMA_GET_SUBSCRIPTION_SOURCE 104
-
-/**
- * RIL_REQUEST_ISIM_AUTHENTICATION
- *
- * Request the ISIM application on the UICC to perform AKA
- * challenge/response algorithm for IMS authentication
- *
- * "data" is a const char * containing the challenge string in Base64 format
- * "response" is a const char * containing the response in Base64 format
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_ISIM_AUTHENTICATION 105
-
-/**
- * RIL_REQUEST_ACKNOWLEDGE_INCOMING_GSM_SMS_WITH_PDU
- *
- * Acknowledge successful or failed receipt of SMS previously indicated
- * via RIL_UNSOL_RESPONSE_NEW_SMS, including acknowledgement TPDU to send
- * as the RP-User-Data element of the RP-ACK or RP-ERROR PDU.
- *
- * "data" is const char **
- * ((const char **)data)[0] is "1" on successful receipt (send RP-ACK)
- *                          is "0" on failed receipt (send RP-ERROR)
- * ((const char **)data)[1] is the acknowledgement TPDU in hexadecimal format
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_ACKNOWLEDGE_INCOMING_GSM_SMS_WITH_PDU 106
-
-/**
- * RIL_REQUEST_STK_SEND_ENVELOPE_WITH_STATUS
- *
- * Requests to send a SAT/USAT envelope command to SIM.
- * The SAT/USAT envelope command refers to 3GPP TS 11.14 and 3GPP TS 31.111.
- *
- * This request has one difference from RIL_REQUEST_STK_SEND_ENVELOPE_COMMAND:
- * the SW1 and SW2 status bytes from the UICC response are returned along with
- * the response data, using the same structure as RIL_REQUEST_SIM_IO.
- *
- * The RIL implementation shall perform the normal processing of a '91XX'
- * response in SW1/SW2 to retrieve the pending proactive command and send it
- * as an unsolicited response, as RIL_REQUEST_STK_SEND_ENVELOPE_COMMAND does.
- *
- * "data" is a const char * containing the SAT/USAT command
- * in hexadecimal format starting with command tag
- *
- * "response" is a const RIL_SIM_IO_Response *
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE (radio resetting)
- *  SIM_BUSY
- *  OPERATION_NOT_ALLOWED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- */
-#define RIL_REQUEST_STK_SEND_ENVELOPE_WITH_STATUS 107
-
-/**
- * RIL_REQUEST_VOICE_RADIO_TECH
- *
- * Query the radio technology type (3GPP/3GPP2) used for voice. Query is valid only
- * when radio state is not RADIO_STATE_UNAVAILABLE
- *
- * "data" is NULL
- * "response" is int *
- * ((int *) response)[0] is of type const RIL_RadioTechnology
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_VOICE_RADIO_TECH 108
-
-/**
- * RIL_REQUEST_GET_CELL_INFO_LIST
- *
- * Request all of the current cell information known to the radio. The radio
- * must a list of all current cells, including the neighboring cells. If for a particular
- * cell information isn't known then the appropriate unknown value will be returned.
- * This does not cause or change the rate of RIL_UNSOL_CELL_INFO_LIST.
- *
- * "data" is NULL
- *
- * "response" is an array of  RIL_CellInfo_v12.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  NO_NETWORK_FOUND
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_GET_CELL_INFO_LIST 109
-
-/**
- * RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE
- *
- * Sets the minimum time between when RIL_UNSOL_CELL_INFO_LIST should be invoked.
- * A value of 0, means invoke RIL_UNSOL_CELL_INFO_LIST when any of the reported
- * information changes. Setting the value to INT_MAX(0x7fffffff) means never issue
- * a RIL_UNSOL_CELL_INFO_LIST.
- *
- * "data" is int *
- * ((int *)data)[0] is minimum time in milliseconds
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SET_UNSOL_CELL_INFO_LIST_RATE 110
-
-/**
- * RIL_REQUEST_SET_INITIAL_ATTACH_APN
- *
- * Set an apn to initial attach network
- *
- * "data" is a const char **
- * ((const char **)data)[0] is the APN to connect if radio technology is LTE
- * ((const char **)data)[1] is the connection type to request must be one of the
- *                          PDP_type values in TS 27.007 section 10.1.1.
- *                          For example, "IP", "IPV6", "IPV4V6", or "PPP".
- * ((const char **)data)[2] is the PAP / CHAP auth type. Values:
- *                          0 => PAP and CHAP is never performed.
- *                          1 => PAP may be performed; CHAP is never performed.
- *                          2 => CHAP may be performed; PAP is never performed.
- *                          3 => PAP / CHAP may be performed - baseband dependent.
- * ((const char **)data)[3] is the username for APN, or NULL
- * ((const char **)data)[4] is the password for APN, or NULL
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  SUBSCRIPTION_NOT_AVAILABLE
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  NOT_PROVISIONED
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_SET_INITIAL_ATTACH_APN 111
-
-/**
- * RIL_REQUEST_IMS_REGISTRATION_STATE
- *
- * This message is DEPRECATED and shall be removed in a future release (target: 2018);
- * instead, provide IMS registration status via an IMS Service.
- *
- * Request current IMS registration state
- *
- * "data" is NULL
- *
- * "response" is int *
- * ((int *)response)[0] is registration state:
- *              0 - Not registered
- *              1 - Registered
- *
- * If ((int*)response)[0] is = 1, then ((int *) response)[1]
- * must follow with IMS SMS format:
- *
- * ((int *) response)[1] is of type RIL_RadioTechnologyFamily
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_IMS_REGISTRATION_STATE 112
-
-/**
- * RIL_REQUEST_IMS_SEND_SMS
- *
- * Send a SMS message over IMS
- *
- * "data" is const RIL_IMS_SMS_Message *
- *
- * "response" is a const RIL_SMS_Response *
- *
- * Based on the return error, caller decides to resend if sending sms
- * fails. SMS_SEND_FAIL_RETRY means retry, and other errors means no retry.
- * In case of retry, data is encoded based on Voice Technology available.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  SMS_SEND_FAIL_RETRY
- *  FDN_CHECK_FAILURE
- *  NETWORK_REJECT
- *  INVALID_ARGUMENTS
- *  INVALID_STATE
- *  NO_MEMORY
- *  INVALID_SMS_FORMAT
- *  SYSTEM_ERR
- *  REQUEST_RATE_LIMITED
- *  MODEM_ERR
- *  NETWORK_ERR
- *  ENCODING_ERR
- *  INVALID_SMSC_ADDRESS
- *  OPERATION_NOT_ALLOWED
- *  INTERNAL_ERR
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_IMS_SEND_SMS 113
-
-/**
- * RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC
- *
- * Request APDU exchange on the basic channel. This command reflects TS 27.007
- * "generic SIM access" operation (+CSIM). The modem must ensure proper function
- * of GSM/CDMA, and filter commands appropriately. It should filter
- * channel management and SELECT by DF name commands.
- *
- * "data" is a const RIL_SIM_APDU *
- * "sessionid" field should be ignored.
- *
- * "response" is a const RIL_SIM_IO_Response *
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SIM_TRANSMIT_APDU_BASIC 114
-
-/**
- * RIL_REQUEST_SIM_OPEN_CHANNEL
- *
- * Open a new logical channel and select the given application. This command
- * reflects TS 27.007 "open logical channel" operation (+CCHO). This request
- * also specifies the P2 parameter (described in ISO 7816-4).
- *
- * "data" is a const RIL_OpenChannelParam *
- *
- * "response" is int *
- * ((int *)data)[0] contains the session id of the logical channel.
- * ((int *)data)[1] onwards may optionally contain the select response for the
- *     open channel command with one byte per integer.
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  MISSING_RESOURCE
- *  NO_SUCH_ELEMENT
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  SIM_ERR
- *  INVALID_SIM_STATE
- *  MISSING_RESOURCE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SIM_OPEN_CHANNEL 115
-
-/**
- * RIL_REQUEST_SIM_CLOSE_CHANNEL
- *
- * Close a previously opened logical channel. This command reflects TS 27.007
- * "close logical channel" operation (+CCHC).
- *
- * "data" is int *
- * ((int *)data)[0] is the session id of logical the channel to close.
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SIM_CLOSE_CHANNEL 116
-
-/**
- * RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL
- *
- * Exchange APDUs with a UICC over a previously opened logical channel. This
- * command reflects TS 27.007 "generic logical channel access" operation
- * (+CGLA). The modem should filter channel management and SELECT by DF name
- * commands.
- *
- * "data" is a const RIL_SIM_APDU*
- *
- * "response" is a const RIL_SIM_IO_Response *
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SIM_TRANSMIT_APDU_CHANNEL 117
-
-/**
- * RIL_REQUEST_NV_READ_ITEM
- *
- * Read one of the radio NV items defined in RadioNVItems.java / ril_nv_items.h.
- * This is used for device configuration by some CDMA operators.
- *
- * "data" is a const RIL_NV_ReadItem *
- *
- * "response" is const char * containing the contents of the NV item
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_NV_READ_ITEM 118
-
-/**
- * RIL_REQUEST_NV_WRITE_ITEM
- *
- * Write one of the radio NV items defined in RadioNVItems.java / ril_nv_items.h.
- * This is used for device configuration by some CDMA operators.
- *
- * "data" is a const RIL_NV_WriteItem *
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_NV_WRITE_ITEM 119
-
-/**
- * RIL_REQUEST_NV_WRITE_CDMA_PRL
- *
- * Update the CDMA Preferred Roaming List (PRL) in the radio NV storage.
- * This is used for device configuration by some CDMA operators.
- *
- * "data" is a const char * containing the PRL as a byte array
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_NV_WRITE_CDMA_PRL 120
-
-/**
- * RIL_REQUEST_NV_RESET_CONFIG
- *
- * Reset the radio NV configuration to the factory state.
- * This is used for device configuration by some CDMA operators.
- *
- * "data" is int *
- * ((int *)data)[0] is 1 to reload all NV items
- * ((int *)data)[0] is 2 for erase NV reset (SCRTN)
- * ((int *)data)[0] is 3 for factory reset (RTN)
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_NV_RESET_CONFIG 121
-
- /** RIL_REQUEST_SET_UICC_SUBSCRIPTION
- * FIXME This API needs to have more documentation.
- *
- * Selection/de-selection of a subscription from a SIM card
- * "data" is const  RIL_SelectUiccSub*
-
- *
- * "response" is NULL
- *
- *  Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  SUBSCRIPTION_NOT_SUPPORTED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_SET_UICC_SUBSCRIPTION  122
-
-/**
- *  RIL_REQUEST_ALLOW_DATA
- *
- *  Tells the modem whether data calls are allowed or not
- *
- * "data" is int *
- * FIXME slotId and aid will be added.
- * ((int *)data)[0] is == 0 to allow data calls
- * ((int *)data)[0] is == 1 to disallow data calls
- *
- * "response" is NULL
- *
- *  Valid errors:
- *
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  MODEM_ERR
- *  INVALID_ARGUMENTS
- *  DEVICE_IN_USE
- *  INVALID_MODEM_STATE
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_ALLOW_DATA  123
-
-/**
- * RIL_REQUEST_GET_HARDWARE_CONFIG
- *
- * Request all of the current hardware (modem and sim) associated
- * with the RIL.
- *
- * "data" is NULL
- *
- * "response" is an array of  RIL_HardwareConfig.
- *
- * Valid errors:
- * RADIO_NOT_AVAILABLE
- * REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_GET_HARDWARE_CONFIG 124
-
-/**
- * RIL_REQUEST_SIM_AUTHENTICATION
- *
- * Returns the response of SIM Authentication through RIL to a
- * challenge request.
- *
- * "data" Base64 encoded string containing challenge:
- *      int   authContext;          P2 value of authentication command, see P2 parameter in
- *                                  3GPP TS 31.102 7.1.2
- *      char *authData;             the challenge string in Base64 format, see 3GPP
- *                                  TS 31.102 7.1.2
- *      char *aid;                  AID value, See ETSI 102.221 8.1 and 101.220 4,
- *                                  NULL if no value
- *
- * "response" Base64 encoded strings containing response:
- *      int   sw1;                  Status bytes per 3GPP TS 31.102 section 7.3
- *      int   sw2;
- *      char *simResponse;          Response in Base64 format, see 3GPP TS 31.102 7.1.2
- *
- *  Valid errors:
- *  RADIO_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  INVALID_MODEM_STATE
- *  INVALID_ARGUMENTS
- *  SIM_ERR
- *  REQUEST_NOT_SUPPORTED
- */
-#define RIL_REQUEST_SIM_AUTHENTICATION 125
-
-/**
- * RIL_REQUEST_GET_DC_RT_INFO
- *
- * The request is DEPRECATED, use RIL_REQUEST_GET_ACTIVITY_INFO
- * Requests the Data Connection Real Time Info
- *
- * "data" is NULL
- *
- * "response" is the most recent RIL_DcRtInfo
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  REQUEST_NOT_SUPPORTED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *
- * See also: RIL_UNSOL_DC_RT_INFO_CHANGED
- */
-#define RIL_REQUEST_GET_DC_RT_INFO 126
-
-/**
- * RIL_REQUEST_SET_DC_RT_INFO_RATE
- *
- * The request is DEPRECATED
- * This is the minimum number of milliseconds between successive
- * RIL_UNSOL_DC_RT_INFO_CHANGED messages and defines the highest rate
- * at which RIL_UNSOL_DC_RT_INFO_CHANGED's will be sent. A value of
- * 0 means send as fast as possible.
- *
- * "data" The number of milliseconds as an int
- *
- * "response" is null
- *
- * Valid errors:
- *  SUCCESS must not fail
- */
-#define RIL_REQUEST_SET_DC_RT_INFO_RATE 127
-
-/**
- * RIL_REQUEST_SET_DATA_PROFILE
- *
- * Set data profile in modem
- * Modem should erase existed profiles from framework, and apply new profiles
- * "data" is a const RIL_DataProfileInfo **
- * "datalen" is count * sizeof(const RIL_DataProfileInfo *)
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  SUBSCRIPTION_NOT_AVAILABLE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- */
-#define RIL_REQUEST_SET_DATA_PROFILE 128
-
-/**
- * RIL_REQUEST_SHUTDOWN
- *
- * Device is shutting down. All further commands are ignored
- * and RADIO_NOT_AVAILABLE must be returned.
- *
- * "data" is null
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SHUTDOWN 129
-
-/**
- * RIL_REQUEST_GET_RADIO_CAPABILITY
- *
- * Used to get phone radio capablility.
- *
- * "data" is the RIL_RadioCapability structure
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  INVALID_STATE
- *  REQUEST_NOT_SUPPORTED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_GET_RADIO_CAPABILITY 130
-
-/**
- * RIL_REQUEST_SET_RADIO_CAPABILITY
- *
- * Used to set the phones radio capability. Be VERY careful
- * using this request as it may cause some vendor modems to reset. Because
- * of the possible modem reset any RIL commands after this one may not be
- * processed.
- *
- * "data" is the RIL_RadioCapability structure
- *
- * "response" is the RIL_RadioCapability structure, used to feedback return status
- *
- * Valid errors:
- *  SUCCESS means a RIL_UNSOL_RADIO_CAPABILITY will be sent within 30 seconds.
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  MODEM_ERR
- *  INVALID_STATE
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SET_RADIO_CAPABILITY 131
-
-/**
- * RIL_REQUEST_START_LCE
- *
- * Start Link Capacity Estimate (LCE) service if supported by the radio.
- *
- * "data" is const int *
- * ((const int*)data)[0] specifies the desired reporting interval (ms).
- * ((const int*)data)[1] specifies the LCE service mode. 1: PULL; 0: PUSH.
- *
- * "response" is the RIL_LceStatusInfo.
- *
- * Valid errors:
- * SUCCESS
- * RADIO_NOT_AVAILABLE
- * LCE_NOT_SUPPORTED
- * INTERNAL_ERR
- * REQUEST_NOT_SUPPORTED
- * NO_MEMORY
- * NO_RESOURCES
- * CANCELLED
- * SIM_ABSENT
- */
-#define RIL_REQUEST_START_LCE 132
-
-/**
- * RIL_REQUEST_STOP_LCE
- *
- * Stop Link Capacity Estimate (LCE) service, the STOP operation should be
- * idempotent for the radio modem.
- *
- * "response" is the RIL_LceStatusInfo.
- *
- * Valid errors:
- * SUCCESS
- * RADIO_NOT_AVAILABLE
- * LCE_NOT_SUPPORTED
- * INTERNAL_ERR
- * NO_MEMORY
- * NO_RESOURCES
- * CANCELLED
- * REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- */
-#define RIL_REQUEST_STOP_LCE 133
-
-/**
- * RIL_REQUEST_PULL_LCEDATA
- *
- * Pull LCE service for capacity information.
- *
- * "response" is the RIL_LceDataInfo.
- *
- * Valid errors:
- * SUCCESS
- * RADIO_NOT_AVAILABLE
- * LCE_NOT_SUPPORTED
- * INTERNAL_ERR
- * NO_MEMORY
- * NO_RESOURCES
- * CANCELLED
- * REQUEST_NOT_SUPPORTED
- *  SIM_ABSENT
- */
-#define RIL_REQUEST_PULL_LCEDATA 134
-
-/**
- * RIL_REQUEST_GET_ACTIVITY_INFO
- *
- * Get modem activity information for power consumption estimation.
- *
- * Request clear-on-read statistics information that is used for
- * estimating the per-millisecond power consumption of the cellular
- * modem.
- *
- * "data" is null
- * "response" is const RIL_ActivityStatsInfo *
- *
- * Valid errors:
- *
- * SUCCESS
- * RADIO_NOT_AVAILABLE (radio resetting)
- * NO_MEMORY
- * INTERNAL_ERR
- * SYSTEM_ERR
- * MODEM_ERR
- * NOT_PROVISIONED
- * REQUEST_NOT_SUPPORTED
- * NO_RESOURCES CANCELLED
- */
-#define RIL_REQUEST_GET_ACTIVITY_INFO 135
-
-/**
- * RIL_REQUEST_SET_CARRIER_RESTRICTIONS
- *
- * Set carrier restrictions for this sim slot. Expected modem behavior:
- *  If never receives this command
- *  - Must allow all carriers
- *  Receives this command with data being NULL
- *  - Must allow all carriers. If a previously allowed SIM is present, modem must not reload
- *    the SIM. If a previously disallowed SIM is present, reload the SIM and notify Android.
- *  Receives this command with a list of carriers
- *  - Only allow specified carriers, persist across power cycles and FDR. If a present SIM
- *    is in the allowed list, modem must not reload the SIM. If a present SIM is *not* in
- *    the allowed list, modem must detach from the registered network and only keep emergency
- *    service, and notify Android SIM refresh reset with new SIM state being
- *    RIL_CARDSTATE_RESTRICTED. Emergency service must be enabled.
- *
- * "data" is const RIL_CarrierRestrictions *
- * A list of allowed carriers and possibly a list of excluded carriers.
- * If data is NULL, means to clear previous carrier restrictions and allow all carriers
- *
- * "response" is int *
- * ((int *)data)[0] contains the number of allowed carriers which have been set correctly.
- * On success, it should match the length of list data->allowed_carriers.
- * If data is NULL, the value must be 0.
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_INVALID_ARGUMENTS
- *  RIL_E_RADIO_NOT_AVAILABLE
- *  RIL_E_REQUEST_NOT_SUPPORTED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SET_CARRIER_RESTRICTIONS 136
-
-/**
- * RIL_REQUEST_GET_CARRIER_RESTRICTIONS
- *
- * Get carrier restrictions for this sim slot. Expected modem behavior:
- *  Return list of allowed carriers, or null if all carriers are allowed.
- *
- * "data" is NULL
- *
- * "response" is const RIL_CarrierRestrictions *.
- * If response is NULL, it means all carriers are allowed.
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE
- *  RIL_E_REQUEST_NOT_SUPPORTED
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_GET_CARRIER_RESTRICTIONS 137
-
-/**
- * RIL_REQUEST_SEND_DEVICE_STATE
- *
- * Send the updated device state.
- * Modem can perform power saving based on the provided device state.
- * "data" is const int *
- * ((const int*)data)[0] A RIL_DeviceStateType that specifies the device state type.
- * ((const int*)data)[1] Specifies the state. See RIL_DeviceStateType for the definition of each
- *                       type.
- *
- * "datalen" is count * sizeof(const RIL_DeviceState *)
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  INVALID_ARGUMENTS
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SEND_DEVICE_STATE 138
-
-/**
- * RIL_REQUEST_SET_UNSOLICITED_RESPONSE_FILTER
- *
- * Set the unsolicited response filter
- * This is used to prevent unnecessary application processor
- * wake up for power saving purposes by suppressing the
- * unsolicited responses in certain scenarios.
- *
- * "data" is an int *
- *
- * ((int *)data)[0] is a 32-bit bitmask of RIL_UnsolicitedResponseFilter
- *
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  INVALID_ARGUMENTS (e.g. the requested filter doesn't exist)
- *  RADIO_NOT_AVAILABLE (radio resetting)
- *  NO_MEMORY
- *  INTERNAL_ERR
- *  SYSTEM_ERR
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SET_UNSOLICITED_RESPONSE_FILTER 139
-
- /**
-  * RIL_REQUEST_SET_SIM_CARD_POWER
-  *
-  * Set SIM card power up or down
-  *
-  * Request is equivalent to inserting and removing the card, with
-  * an additional effect where the ability to detect card removal/insertion
-  * is disabled when the SIM card is powered down.
-  *
-  * This will generate RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED
-  * as if the SIM had been inserted or removed.
-  *
-  * "data" is int *
-  * ((int *)data)[0] is 1 for "SIM POWER UP"
-  * ((int *)data)[0] is 0 for "SIM POWER DOWN"
-  *
-  * "response" is NULL
-  *
-  * Valid errors:
-  *  SUCCESS
-  *  RADIO_NOT_AVAILABLE
-  *  REQUEST_NOT_SUPPORTED
-  *  SIM_ABSENT
-  *  INVALID_ARGUMENTS
-  *  INTERNAL_ERR
-  *  NO_MEMORY
-  *  NO_RESOURCES
-  *  CANCELLED
-  */
-#define RIL_REQUEST_SET_SIM_CARD_POWER 140
-
-/**
- * RIL_REQUEST_SET_CARRIER_INFO_IMSI_ENCRYPTION
- *
- * Provide Carrier specific information to the modem that will be used to
- * encrypt the IMSI and IMPI. Sent by the framework during boot, carrier
- * switch and everytime we receive a new certificate.
- *
- * "data" is the RIL_CarrierInfoForImsiEncryption * structure.
- *
- * "response" is NULL
- *
- * Valid errors:
- *  RIL_E_SUCCESS
- *  RIL_E_RADIO_NOT_AVAILABLE
- *  SIM_ABSENT
- *  RIL_E_REQUEST_NOT_SUPPORTED
- *  INVALID_ARGUMENTS
- *  MODEM_INTERNAL_FAILURE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- */
-#define RIL_REQUEST_SET_CARRIER_INFO_IMSI_ENCRYPTION 141
-
-/**
- * RIL_REQUEST_START_NETWORK_SCAN
- *
- * Starts a new network scan
- *
- * Request to start a network scan with specified radio access networks with frequency bands and/or
- * channels.
- *
- * "data" is a const RIL_NetworkScanRequest *.
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  RADIO_NOT_AVAILABLE
- *  OPERATION_NOT_ALLOWED
- *  DEVICE_IN_USE
- *  INTERNAL_ERR
- *  NO_MEMORY
- *  MODEM_ERR
- *  INVALID_ARGUMENTS
- *  REQUEST_NOT_SUPPORTED
- *  NO_RESOURCES
- *  CANCELLED
- *
- */
-#define RIL_REQUEST_START_NETWORK_SCAN 142
-
-/**
- * RIL_REQUEST_STOP_NETWORK_SCAN
- *
- * Stops an ongoing network scan
- *
- * Request to stop the ongoing network scan. Since the modem can only perform one scan at a time,
- * there is no parameter for this request.
- *
- * "data" is NULL
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  INTERNAL_ERR
- *  MODEM_ERR
- *  NO_MEMORY
- *  NO_RESOURCES
- *  CANCELLED
- *  REQUEST_NOT_SUPPORTED
- *
- */
-#define RIL_REQUEST_STOP_NETWORK_SCAN 143
-
-/**
- * RIL_REQUEST_START_KEEPALIVE
- *
- * Start a keepalive session
- *
- * Request that the modem begin sending keepalive packets on a particular
- * data call, with a specified source, destination, and format.
- *
- * "data" is a const RIL_RequestKeepalive
- * "response" is RIL_KeepaliveStatus with a valid "handle"
- *
- * Valid errors:
- *  SUCCESS
- *  NO_RESOURCES
- *  INVALID_ARGUMENTS
- *
- */
-#define RIL_REQUEST_START_KEEPALIVE 144
-
-/**
- * RIL_REQUEST_STOP_KEEPALIVE
- *
- * Stops an ongoing keepalive session
- *
- * Requests that a keepalive session with the given handle be stopped.
- * there is no parameter for this request.
- *
- * "data" is an integer handle
- * "response" is NULL
- *
- * Valid errors:
- *  SUCCESS
- *  INVALID_ARGUMENTS
- *
- */
-#define RIL_REQUEST_STOP_KEEPALIVE 145
-
-/***********************************************************************/
-
-/**
- * RIL_RESPONSE_ACKNOWLEDGEMENT
- *
- * This is used by Asynchronous solicited messages and Unsolicited messages
- * to acknowledge the receipt of those messages in RIL.java so that the ack
- * can be used to let ril.cpp to release wakelock.
- *
- * Valid errors
- * SUCCESS
- * RADIO_NOT_AVAILABLE
- */
-
-#define RIL_RESPONSE_ACKNOWLEDGEMENT 800
-
-/***********************************************************************/
-
-
-#define RIL_UNSOL_RESPONSE_BASE 1000
-
-/**
- * RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED
- *
- * Indicate when value of RIL_RadioState has changed.
- *
- * Callee will invoke RIL_RadioStateRequest method on main thread
- *
- * "data" is NULL
- */
-
-#define RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED 1000
-
-
-/**
- * RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED
- *
- * Indicate when call state has changed
- *
- * Callee will invoke RIL_REQUEST_GET_CURRENT_CALLS on main thread
- *
- * "data" is NULL
- *
- * Response should be invoked on, for example,
- * "RING", "BUSY", "NO CARRIER", and also call state
- * transitions (DIALING->ALERTING ALERTING->ACTIVE)
- *
- * Redundent or extraneous invocations are tolerated
- */
-#define RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED 1001
-
-
-/**
- * RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED
- *
- * Called when the voice network state changed
- *
- * Callee will invoke the following requests on main thread:
- *
- * RIL_REQUEST_VOICE_REGISTRATION_STATE
- * RIL_REQUEST_OPERATOR
- *
- * "data" is NULL
- *
- * FIXME should this happen when SIM records are loaded? (eg, for
- * EONS)
- */
-#define RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED 1002
-
-/**
- * RIL_UNSOL_RESPONSE_NEW_SMS
- *
- * Called when new SMS is received.
- *
- * "data" is const char *
- * This is a pointer to a string containing the PDU of an SMS-DELIVER
- * as an ascii string of hex digits. The PDU starts with the SMSC address
- * per TS 27.005 (+CMT:)
- *
- * Callee will subsequently confirm the receipt of thei SMS with a
- * RIL_REQUEST_SMS_ACKNOWLEDGE
- *
- * No new RIL_UNSOL_RESPONSE_NEW_SMS
- * or RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT messages should be sent until a
- * RIL_REQUEST_SMS_ACKNOWLEDGE has been received
- */
-
-#define RIL_UNSOL_RESPONSE_NEW_SMS 1003
-
-/**
- * RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT
- *
- * Called when new SMS Status Report is received.
- *
- * "data" is const char *
- * This is a pointer to a string containing the PDU of an SMS-STATUS-REPORT
- * as an ascii string of hex digits. The PDU starts with the SMSC address
- * per TS 27.005 (+CDS:).
- *
- * Callee will subsequently confirm the receipt of the SMS with a
- * RIL_REQUEST_SMS_ACKNOWLEDGE
- *
- * No new RIL_UNSOL_RESPONSE_NEW_SMS
- * or RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT messages should be sent until a
- * RIL_REQUEST_SMS_ACKNOWLEDGE has been received
- */
-
-#define RIL_UNSOL_RESPONSE_NEW_SMS_STATUS_REPORT 1004
-
-/**
- * RIL_UNSOL_RESPONSE_NEW_SMS_ON_SIM
- *
- * Called when new SMS has been stored on SIM card
- *
- * "data" is const int *
- * ((const int *)data)[0] contains the slot index on the SIM that contains
- * the new message
- */
-
-#define RIL_UNSOL_RESPONSE_NEW_SMS_ON_SIM 1005
-
-/**
- * RIL_UNSOL_ON_USSD
- *
- * Called when a new USSD message is received.
- *
- * "data" is const char **
- * ((const char **)data)[0] points to a type code, which is
- *  one of these string values:
- *      "0"   USSD-Notify -- text in ((const char **)data)[1]
- *      "1"   USSD-Request -- text in ((const char **)data)[1]
- *      "2"   Session terminated by network
- *      "3"   other local client (eg, SIM Toolkit) has responded
- *      "4"   Operation not supported
- *      "5"   Network timeout
- *
- * The USSD session is assumed to persist if the type code is "1", otherwise
- * the current session (if any) is assumed to have terminated.
- *
- * ((const char **)data)[1] points to a message string if applicable, which
- * should always be in UTF-8.
- */
-#define RIL_UNSOL_ON_USSD 1006
-/* Previously #define RIL_UNSOL_ON_USSD_NOTIFY 1006   */
-
-/**
- * RIL_UNSOL_ON_USSD_REQUEST
- *
- * Obsolete. Send via RIL_UNSOL_ON_USSD
- */
-#define RIL_UNSOL_ON_USSD_REQUEST 1007
-
-/**
- * RIL_UNSOL_NITZ_TIME_RECEIVED
- *
- * Called when radio has received a NITZ time message
- *
- * "data" is const char * pointing to NITZ time string
- * in the form "yy/mm/dd,hh:mm:ss(+/-)tz,dt"
- */
-#define RIL_UNSOL_NITZ_TIME_RECEIVED  1008
-
-/**
- * RIL_UNSOL_SIGNAL_STRENGTH
- *
- * Radio may report signal strength rather han have it polled.
- *
- * "data" is a const RIL_SignalStrength *
- */
-#define RIL_UNSOL_SIGNAL_STRENGTH  1009
-
-
-/**
- * RIL_UNSOL_DATA_CALL_LIST_CHANGED
- *
- * "data" is an array of RIL_Data_Call_Response_v6 identical to that
- * returned by RIL_REQUEST_DATA_CALL_LIST. It is the complete list
- * of current data contexts including new contexts that have been
- * activated. A data call is only removed from this list when the
- * framework sends a RIL_REQUEST_DEACTIVATE_DATA_CALL or the radio
- * is powered off/on.
- *
- * See also: RIL_REQUEST_DATA_CALL_LIST
- */
-
-#define RIL_UNSOL_DATA_CALL_LIST_CHANGED 1010
-
-/**
- * RIL_UNSOL_SUPP_SVC_NOTIFICATION
- *
- * Reports supplementary service related notification from the network.
- *
- * "data" is a const RIL_SuppSvcNotification *
- *
- */
-
-#define RIL_UNSOL_SUPP_SVC_NOTIFICATION 1011
-
-/**
- * RIL_UNSOL_STK_SESSION_END
- *
- * Indicate when STK session is terminated by SIM.
- *
- * "data" is NULL
- */
-#define RIL_UNSOL_STK_SESSION_END 1012
-
-/**
- * RIL_UNSOL_STK_PROACTIVE_COMMAND
- *
- * Indicate when SIM issue a STK proactive command to applications
- *
- * "data" is a const char * containing SAT/USAT proactive command
- * in hexadecimal format string starting with command tag
- *
- */
-#define RIL_UNSOL_STK_PROACTIVE_COMMAND 1013
-
-/**
- * RIL_UNSOL_STK_EVENT_NOTIFY
- *
- * Indicate when SIM notifies applcations some event happens.
- * Generally, application does not need to have any feedback to
- * SIM but shall be able to indicate appropriate messages to users.
- *
- * "data" is a const char * containing SAT/USAT commands or responses
- * sent by ME to SIM or commands handled by ME, in hexadecimal format string
- * starting with first byte of response data or command tag
- *
- */
-#define RIL_UNSOL_STK_EVENT_NOTIFY 1014
-
-/**
- * RIL_UNSOL_STK_CALL_SETUP
- *
- * Indicate when SIM wants application to setup a voice call.
- *
- * "data" is const int *
- * ((const int *)data)[0] contains timeout value (in milliseconds)
- */
-#define RIL_UNSOL_STK_CALL_SETUP 1015
-
-/**
- * RIL_UNSOL_SIM_SMS_STORAGE_FULL
- *
- * Indicates that SMS storage on the SIM is full.  Sent when the network
- * attempts to deliver a new SMS message.  Messages cannot be saved on the
- * SIM until space is freed.  In particular, incoming Class 2 messages
- * cannot be stored.
- *
- * "data" is null
- *
- */
-#define RIL_UNSOL_SIM_SMS_STORAGE_FULL 1016
-
-/**
- * RIL_UNSOL_SIM_REFRESH
- *
- * Indicates that file(s) on the SIM have been updated, or the SIM
- * has been reinitialized.
- *
- * In the case where RIL is version 6 or older:
- * "data" is an int *
- * ((int *)data)[0] is a RIL_SimRefreshResult.
- * ((int *)data)[1] is the EFID of the updated file if the result is
- * SIM_FILE_UPDATE or NULL for any other result.
- *
- * In the case where RIL is version 7:
- * "data" is a RIL_SimRefreshResponse_v7 *
- *
- * Note: If the SIM state changes as a result of the SIM refresh (eg,
- * SIM_READY -> SIM_LOCKED_OR_ABSENT), RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED
- * should be sent.
- */
-#define RIL_UNSOL_SIM_REFRESH 1017
-
-/**
- * RIL_UNSOL_CALL_RING
- *
- * Ring indication for an incoming call (eg, RING or CRING event).
- * There must be at least one RIL_UNSOL_CALL_RING at the beginning
- * of a call and sending multiple is optional. If the system property
- * ro.telephony.call_ring.multiple is false then the upper layers
- * will generate the multiple events internally. Otherwise the vendor
- * ril must generate multiple RIL_UNSOL_CALL_RING if
- * ro.telephony.call_ring.multiple is true or if it is absent.
- *
- * The rate of these events is controlled by ro.telephony.call_ring.delay
- * and has a default value of 3000 (3 seconds) if absent.
- *
- * "data" is null for GSM
- * "data" is const RIL_CDMA_SignalInfoRecord * if CDMA
- */
-#define RIL_UNSOL_CALL_RING 1018
-
-/**
- * RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED
- *
- * Indicates that SIM state changes.
- *
- * Callee will invoke RIL_REQUEST_GET_SIM_STATUS on main thread
-
- * "data" is null
- */
-#define RIL_UNSOL_RESPONSE_SIM_STATUS_CHANGED 1019
-
-/**
- * RIL_UNSOL_RESPONSE_CDMA_NEW_SMS
- *
- * Called when new CDMA SMS is received
- *
- * "data" is const RIL_CDMA_SMS_Message *
- *
- * Callee will subsequently confirm the receipt of the SMS with
- * a RIL_REQUEST_CDMA_SMS_ACKNOWLEDGE
- *
- * No new RIL_UNSOL_RESPONSE_CDMA_NEW_SMS should be sent until
- * RIL_REQUEST_CDMA_SMS_ACKNOWLEDGE has been received
- *
- */
-#define RIL_UNSOL_RESPONSE_CDMA_NEW_SMS 1020
-
-/**
- * RIL_UNSOL_RESPONSE_NEW_BROADCAST_SMS
- *
- * Called when new Broadcast SMS is received
- *
- * "data" can be one of the following:
- * If received from GSM network, "data" is const char of 88 bytes
- * which indicates each page of a CBS Message sent to the MS by the
- * BTS as coded in 3GPP 23.041 Section 9.4.1.2.
- * If received from UMTS network, "data" is const char of 90 up to 1252
- * bytes which contain between 1 and 15 CBS Message pages sent as one
- * packet to the MS by the BTS as coded in 3GPP 23.041 Section 9.4.2.2.
- *
- */
-#define RIL_UNSOL_RESPONSE_NEW_BROADCAST_SMS 1021
-
-/**
- * RIL_UNSOL_CDMA_RUIM_SMS_STORAGE_FULL
- *
- * Indicates that SMS storage on the RUIM is full.  Messages
- * cannot be saved on the RUIM until space is freed.
- *
- * "data" is null
- *
- */
-#define RIL_UNSOL_CDMA_RUIM_SMS_STORAGE_FULL 1022
-
-/**
- * RIL_UNSOL_RESTRICTED_STATE_CHANGED
- *
- * Indicates a restricted state change (eg, for Domain Specific Access Control).
- *
- * Radio need send this msg after radio off/on cycle no matter it is changed or not.
- *
- * "data" is an int *
- * ((int *)data)[0] contains a bitmask of RIL_RESTRICTED_STATE_* values.
- */
-#define RIL_UNSOL_RESTRICTED_STATE_CHANGED 1023
-
-/**
- * RIL_UNSOL_ENTER_EMERGENCY_CALLBACK_MODE
- *
- * Indicates that the radio system selection module has
- * autonomously entered emergency callback mode.
- *
- * "data" is null
- *
- */
-#define RIL_UNSOL_ENTER_EMERGENCY_CALLBACK_MODE 1024
-
-/**
- * RIL_UNSOL_CDMA_CALL_WAITING
- *
- * Called when CDMA radio receives a call waiting indication.
- *
- * "data" is const RIL_CDMA_CallWaiting *
- *
- */
-#define RIL_UNSOL_CDMA_CALL_WAITING 1025
-
-/**
- * RIL_UNSOL_CDMA_OTA_PROVISION_STATUS
- *
- * Called when CDMA radio receives an update of the progress of an
- * OTASP/OTAPA call.
- *
- * "data" is const int *
- *  For CDMA this is an integer OTASP/OTAPA status listed in
- *  RIL_CDMA_OTA_ProvisionStatus.
- *
- */
-#define RIL_UNSOL_CDMA_OTA_PROVISION_STATUS 1026
-
-/**
- * RIL_UNSOL_CDMA_INFO_REC
- *
- * Called when CDMA radio receives one or more info recs.
- *
- * "data" is const RIL_CDMA_InformationRecords *
- *
- */
-#define RIL_UNSOL_CDMA_INFO_REC 1027
-
-/**
- * RIL_UNSOL_OEM_HOOK_RAW
- *
- * This is for OEM specific use.
- *
- * "data" is a byte[]
- */
-#define RIL_UNSOL_OEM_HOOK_RAW 1028
-
-/**
- * RIL_UNSOL_RINGBACK_TONE
- *
- * Indicates that nework doesn't have in-band information,  need to
- * play out-band tone.
- *
- * "data" is an int *
- * ((int *)data)[0] == 0 for stop play ringback tone.
- * ((int *)data)[0] == 1 for start play ringback tone.
- */
-#define RIL_UNSOL_RINGBACK_TONE 1029
-
-/**
- * RIL_UNSOL_RESEND_INCALL_MUTE
- *
- * Indicates that framework/application need reset the uplink mute state.
- *
- * There may be situations where the mute state becomes out of sync
- * between the application and device in some GSM infrastructures.
- *
- * "data" is null
- */
-#define RIL_UNSOL_RESEND_INCALL_MUTE 1030
-
-/**
- * RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED
- *
- * Called when CDMA subscription source changed.
- *
- * "data" is int *
- * ((int *)data)[0] is == RIL_CdmaSubscriptionSource
- */
-#define RIL_UNSOL_CDMA_SUBSCRIPTION_SOURCE_CHANGED 1031
-
-/**
- * RIL_UNSOL_CDMA_PRL_CHANGED
- *
- * Called when PRL (preferred roaming list) changes.
- *
- * "data" is int *
- * ((int *)data)[0] is PRL_VERSION as would be returned by RIL_REQUEST_CDMA_SUBSCRIPTION
- */
-#define RIL_UNSOL_CDMA_PRL_CHANGED 1032
-
-/**
- * RIL_UNSOL_EXIT_EMERGENCY_CALLBACK_MODE
- *
- * Called when Emergency Callback Mode Ends
- *
- * Indicates that the radio system selection module has
- * proactively exited emergency callback mode.
- *
- * "data" is NULL
- *
- */
-#define RIL_UNSOL_EXIT_EMERGENCY_CALLBACK_MODE 1033
-
-/**
- * RIL_UNSOL_RIL_CONNECTED
- *
- * Called the ril connects and returns the version
- *
- * "data" is int *
- * ((int *)data)[0] is RIL_VERSION
- */
-#define RIL_UNSOL_RIL_CONNECTED 1034
-
-/**
- * RIL_UNSOL_VOICE_RADIO_TECH_CHANGED
- *
- * Indicates that voice technology has changed. Contains new radio technology
- * as a data in the message.
- *
- * "data" is int *
- * ((int *)data)[0] is of type const RIL_RadioTechnology
- *
- */
-#define RIL_UNSOL_VOICE_RADIO_TECH_CHANGED 1035
-
-/**
- * RIL_UNSOL_CELL_INFO_LIST
- *
- * Same information as returned by RIL_REQUEST_GET_CELL_INFO_LIST, but returned
- * at the rate no greater than specified by RIL_REQUEST_SET_UNSOL_CELL_INFO_RATE.
- *
- * "data" is NULL
- *
- * "response" is an array of RIL_CellInfo_v12.
- */
-#define RIL_UNSOL_CELL_INFO_LIST 1036
-
-/**
- * RIL_UNSOL_RESPONSE_IMS_NETWORK_STATE_CHANGED
- *
- * This message is DEPRECATED and shall be removed in a future release (target: 2018);
- * instead, provide IMS registration status via an IMS Service.
- *
- * Called when IMS registration state has changed
- *
- * To get IMS registration state and IMS SMS format, callee needs to invoke the
- * following request on main thread:
- *
- * RIL_REQUEST_IMS_REGISTRATION_STATE
- *
- * "data" is NULL
- *
- */
-#define RIL_UNSOL_RESPONSE_IMS_NETWORK_STATE_CHANGED 1037
-
-/**
- * RIL_UNSOL_UICC_SUBSCRIPTION_STATUS_CHANGED
- *
- * Indicated when there is a change in subscription status.
- * This event will be sent in the following scenarios
- *  - subscription readiness at modem, which was selected by telephony layer
- *  - when subscription is deactivated by modem due to UICC card removal
- *  - When network invalidates the subscription i.e. attach reject due to authentication reject
- *
- * "data" is const int *
- * ((const int *)data)[0] == 0 for Subscription Deactivated
- * ((const int *)data)[0] == 1 for Subscription Activated
- *
- */
-#define RIL_UNSOL_UICC_SUBSCRIPTION_STATUS_CHANGED 1038
-
-/**
- * RIL_UNSOL_SRVCC_STATE_NOTIFY
- *
- * Called when Single Radio Voice Call Continuity(SRVCC)
- * progress state has changed
- *
- * "data" is int *
- * ((int *)data)[0] is of type const RIL_SrvccState
- *
- */
-
-#define RIL_UNSOL_SRVCC_STATE_NOTIFY 1039
-
-/**
- * RIL_UNSOL_HARDWARE_CONFIG_CHANGED
- *
- * Called when the hardware configuration associated with the RILd changes
- *
- * "data" is an array of RIL_HardwareConfig
- *
- */
-#define RIL_UNSOL_HARDWARE_CONFIG_CHANGED 1040
-
-/**
- * RIL_UNSOL_DC_RT_INFO_CHANGED
- *
- * The message is DEPRECATED, use RIL_REQUEST_GET_ACTIVITY_INFO
- * Sent when the DC_RT_STATE changes but the time
- * between these messages must not be less than the
- * value set by RIL_REQUEST_SET_DC_RT_RATE.
- *
- * "data" is the most recent RIL_DcRtInfo
- *
- */
-#define RIL_UNSOL_DC_RT_INFO_CHANGED 1041
-
-/**
- * RIL_UNSOL_RADIO_CAPABILITY
- *
- * Sent when RIL_REQUEST_SET_RADIO_CAPABILITY completes.
- * Returns the phone radio capability exactly as
- * RIL_REQUEST_GET_RADIO_CAPABILITY and should be the
- * same set as sent by RIL_REQUEST_SET_RADIO_CAPABILITY.
- *
- * "data" is the RIL_RadioCapability structure
- */
-#define RIL_UNSOL_RADIO_CAPABILITY 1042
-
-/*
- * RIL_UNSOL_ON_SS
- *
- * Called when SS response is received when DIAL/USSD/SS is changed to SS by
- * call control.
- *
- * "data" is const RIL_StkCcUnsolSsResponse *
- *
- */
-#define RIL_UNSOL_ON_SS 1043
-
-/**
- * RIL_UNSOL_STK_CC_ALPHA_NOTIFY
- *
- * Called when there is an ALPHA from UICC during Call Control.
- *
- * "data" is const char * containing ALPHA string from UICC in UTF-8 format.
- *
- */
-#define RIL_UNSOL_STK_CC_ALPHA_NOTIFY 1044
-
-/**
- * RIL_UNSOL_LCEDATA_RECV
- *
- * Called when there is an incoming Link Capacity Estimate (LCE) info report.
- *
- * "data" is the RIL_LceDataInfo structure.
- *
- */
-#define RIL_UNSOL_LCEDATA_RECV 1045
-
- /**
-  * RIL_UNSOL_PCO_DATA
-  *
-  * Called when there is new Carrier PCO data received for a data call.  Ideally
-  * only new data will be forwarded, though this is not required.  Multiple
-  * boxes of carrier PCO data for a given call should result in a series of
-  * RIL_UNSOL_PCO_DATA calls.
-  *
-  * "data" is the RIL_PCO_Data structure.
-  *
-  */
-#define RIL_UNSOL_PCO_DATA 1046
-
- /**
-  * RIL_UNSOL_MODEM_RESTART
-  *
-  * Called when there is a modem reset.
-  *
-  * "reason" is "const char *" containing the reason for the reset. It
-  * could be a crash signature if the restart was due to a crash or some
-  * string such as "user-initiated restart" or "AT command initiated
-  * restart" that explains the cause of the modem restart.
-  *
-  * When modem restarts, one of the following radio state transitions will happen
-  * 1) RADIO_STATE_ON->RADIO_STATE_UNAVAILABLE->RADIO_STATE_ON or
-  * 2) RADIO_STATE_OFF->RADIO_STATE_UNAVAILABLE->RADIO_STATE_OFF
-  * This message can be sent either just before the RADIO_STATE changes to RADIO_STATE_UNAVAILABLE
-  * or just after but should never be sent after the RADIO_STATE changes from UNAVAILABLE to
-  * AVAILABLE(RADIO_STATE_ON/RADIO_STATE_OFF) again.
-  *
-  * It should NOT be sent after the RADIO_STATE changes to AVAILABLE after the
-  * modem restart as that could be interpreted as a second modem reset by the
-  * framework.
-  */
-#define RIL_UNSOL_MODEM_RESTART 1047
-
-/**
- * RIL_UNSOL_CARRIER_INFO_IMSI_ENCRYPTION
- *
- * Called when the modem needs Carrier specific information that will
- * be used to encrypt IMSI and IMPI.
- *
- * "data" is NULL
- *
- */
-#define RIL_UNSOL_CARRIER_INFO_IMSI_ENCRYPTION 1048
-
-/**
- * RIL_UNSOL_NETWORK_SCAN_RESULT
- *
- * Returns incremental result for the network scan which is started by
- * RIL_REQUEST_START_NETWORK_SCAN, sent to report results, status, or errors.
- *
- * "data" is NULL
- * "response" is a const RIL_NetworkScanResult *
- */
-#define RIL_UNSOL_NETWORK_SCAN_RESULT 1049
-
-/**
- * RIL_UNSOL_KEEPALIVE_STATUS
- *
- * "data" is NULL
- * "response" is a const RIL_KeepaliveStatus *
- */
-#define RIL_UNSOL_KEEPALIVE_STATUS 1050
-
-/***********************************************************************/
-
-
-#if defined(ANDROID_MULTI_SIM)
-/**
- * RIL_Request Function pointer
- *
- * @param request is one of RIL_REQUEST_*
- * @param data is pointer to data defined for that RIL_REQUEST_*
- *        data is owned by caller, and should not be modified or freed by callee
- *        structures passed as data may contain pointers to non-contiguous memory
- * @param t should be used in subsequent call to RIL_onResponse
- * @param datalen is the length of "data" which is defined as other argument. It may or may
- *        not be equal to sizeof(data). Refer to the documentation of individual structures
- *        to find if pointers listed in the structure are contiguous and counted in the datalen
- *        length or not.
- *        (Eg: RIL_IMS_SMS_Message where we don't have datalen equal to sizeof(data))
- *
- */
-typedef void (*RIL_RequestFunc) (int request, void *data,
-                                    size_t datalen, RIL_Token t, RIL_SOCKET_ID socket_id);
-
-/**
- * This function should return the current radio state synchronously
- */
-typedef RIL_RadioState (*RIL_RadioStateRequest)(RIL_SOCKET_ID socket_id);
-
-#else
-/* Backward compatible */
-
-/**
- * RIL_Request Function pointer
- *
- * @param request is one of RIL_REQUEST_*
- * @param data is pointer to data defined for that RIL_REQUEST_*
- *        data is owned by caller, and should not be modified or freed by callee
- *        structures passed as data may contain pointers to non-contiguous memory
- * @param t should be used in subsequent call to RIL_onResponse
- * @param datalen is the length of "data" which is defined as other argument. It may or may
- *        not be equal to sizeof(data). Refer to the documentation of individual structures
- *        to find if pointers listed in the structure are contiguous and counted in the datalen
- *        length or not.
- *        (Eg: RIL_IMS_SMS_Message where we don't have datalen equal to sizeof(data))
- *
- */
-typedef void (*RIL_RequestFunc) (int request, void *data,
-                                    size_t datalen, RIL_Token t);
-
-/**
- * This function should return the current radio state synchronously
- */
-typedef RIL_RadioState (*RIL_RadioStateRequest)();
-
-#endif
-
-
-/**
- * This function returns "1" if the specified RIL_REQUEST code is
- * supported and 0 if it is not
- *
- * @param requestCode is one of RIL_REQUEST codes
- */
-
-typedef int (*RIL_Supports)(int requestCode);
-
-/**
- * This function is called from a separate thread--not the
- * thread that calls RIL_RequestFunc--and indicates that a pending
- * request should be cancelled.
- *
- * On cancel, the callee should do its best to abandon the request and
- * call RIL_onRequestComplete with RIL_Errno CANCELLED at some later point.
- *
- * Subsequent calls to  RIL_onRequestComplete for this request with
- * other results will be tolerated but ignored. (That is, it is valid
- * to ignore the cancellation request)
- *
- * RIL_Cancel calls should return immediately, and not wait for cancellation
- *
- * Please see ITU v.250 5.6.1 for how one might implement this on a TS 27.007
- * interface
- *
- * @param t token wants to be canceled
- */
-
-typedef void (*RIL_Cancel)(RIL_Token t);
-
-typedef void (*RIL_TimedCallback) (void *param);
-
-/**
- * Return a version string for your RIL implementation
- */
-typedef const char * (*RIL_GetVersion) (void);
-
-typedef struct {
-    int version;        /* set to RIL_VERSION */
-    RIL_RequestFunc onRequest;
-    RIL_RadioStateRequest onStateRequest;
-    RIL_Supports supports;
-    RIL_Cancel onCancel;
-    RIL_GetVersion getVersion;
-} RIL_RadioFunctions;
-
-typedef struct {
-    char *apn;                  /* the APN to connect to */
-    char *protocol;             /* one of the PDP_type values in TS 27.007 section 10.1.1 used on
-                                   roaming network. For example, "IP", "IPV6", "IPV4V6", or "PPP".*/
-    int authtype;               /* authentication protocol used for this PDP context
-                                   (None: 0, PAP: 1, CHAP: 2, PAP&CHAP: 3) */
-    char *username;             /* the username for APN, or NULL */
-    char *password;             /* the password for APN, or NULL */
-} RIL_InitialAttachApn;
-
-typedef struct {
-    char *apn;                  /* the APN to connect to */
-    char *protocol;             /* one of the PDP_type values in TS 27.007 section 10.1.1 used on
-                                   home network. For example, "IP", "IPV6", "IPV4V6", or "PPP". */
-    char *roamingProtocol;      /* one of the PDP_type values in TS 27.007 section 10.1.1 used on
-                                   roaming network. For example, "IP", "IPV6", "IPV4V6", or "PPP".*/
-    int authtype;               /* authentication protocol used for this PDP context
-                                   (None: 0, PAP: 1, CHAP: 2, PAP&CHAP: 3) */
-    char *username;             /* the username for APN, or NULL */
-    char *password;             /* the password for APN, or NULL */
-    int supportedTypesBitmask;  /* supported APN types bitmask. See RIL_ApnTypes for the value of
-                                   each bit. */
-    int bearerBitmask;          /* the bearer bitmask. See RIL_RadioAccessFamily for the value of
-                                   each bit. */
-    int modemCognitive;         /* indicating the APN setting was sent to the modem through
-                                   setDataProfile earlier. */
-    int mtu;                    /* maximum transmission unit (MTU) size in bytes */
-    char *mvnoType;             /* the MVNO type: possible values are "imsi", "gid", "spn" */
-    char *mvnoMatchData;        /* MVNO match data. Can be anything defined by the carrier.
-                                   For example,
-                                     SPN like: "A MOBILE", "BEN NL", etc...
-                                     IMSI like: "302720x94", "2060188", etc...
-                                     GID like: "4E", "33", etc... */
-} RIL_InitialAttachApn_v15;
-
-typedef struct {
-    int authContext;            /* P2 value of authentication command, see P2 parameter in
-                                   3GPP TS 31.102 7.1.2 */
-    char *authData;             /* the challenge string in Base64 format, see 3GPP
-                                   TS 31.102 7.1.2 */
-    char *aid;                  /* AID value, See ETSI 102.221 8.1 and 101.220 4,
-                                   NULL if no value. */
-} RIL_SimAuthentication;
-
-typedef struct {
-    int cid;                    /* Context ID, uniquely identifies this call */
-    char *bearer_proto;         /* One of the PDP_type values in TS 27.007 section 10.1.1.
-                                   For example, "IP", "IPV6", "IPV4V6". */
-    int pco_id;                 /* The protocol ID for this box.  Note that only IDs from
-                                   FF00H - FFFFH are accepted.  If more than one is included
-                                   from the network, multiple calls should be made to send all
-                                   of them. */
-    int contents_length;        /* The number of octets in the contents. */
-    char *contents;             /* Carrier-defined content.  It is binary, opaque and
-                                   loosely defined in LTE Layer 3 spec 24.008 */
-} RIL_PCO_Data;
-
-typedef enum {
-    NATT_IPV4 = 0,              /* Keepalive specified by RFC 3948 Sec. 2.3 using IPv4 */
-    NATT_IPV6 = 1               /* Keepalive specified by RFC 3948 Sec. 2.3 using IPv6 */
-} RIL_KeepaliveType;
-
-#define MAX_INADDR_LEN 16
-typedef struct {
-    RIL_KeepaliveType type;                  /* Type of keepalive packet */
-    char sourceAddress[MAX_INADDR_LEN];      /* Source address in network-byte order */
-    int sourcePort;                          /* Source port if applicable, or 0x7FFFFFFF;
-                                                the maximum value is 65535 */
-    char destinationAddress[MAX_INADDR_LEN]; /* Destination address in network-byte order */
-    int destinationPort;                     /* Destination port if applicable or 0x7FFFFFFF;
-                                                the maximum value is 65535 */
-    int maxKeepaliveIntervalMillis;          /* Maximum milliseconds between two packets */
-    int cid;                                 /* Context ID, uniquely identifies this call */
-} RIL_KeepaliveRequest;
-
-typedef enum {
-    KEEPALIVE_ACTIVE,                       /* Keepalive session is active */
-    KEEPALIVE_INACTIVE,                     /* Keepalive session is inactive */
-    KEEPALIVE_PENDING                       /* Keepalive session status not available */
-} RIL_KeepaliveStatusCode;
-
-typedef struct {
-    uint32_t sessionHandle;
-    RIL_KeepaliveStatusCode code;
-} RIL_KeepaliveStatus;
-
-#ifdef RIL_SHLIB
-struct RIL_Env {
-    /**
-     * "t" is parameter passed in on previous call to RIL_Notification
-     * routine.
-     *
-     * If "e" != SUCCESS, then response can be null/is ignored
-     *
-     * "response" is owned by caller, and should not be modified or
-     * freed by callee
-     *
-     * RIL_onRequestComplete will return as soon as possible
-     */
-    void (*OnRequestComplete)(RIL_Token t, RIL_Errno e,
-                           void *response, size_t responselen);
-
-#if defined(ANDROID_MULTI_SIM)
-    /**
-     * "unsolResponse" is one of RIL_UNSOL_RESPONSE_*
-     * "data" is pointer to data defined for that RIL_UNSOL_RESPONSE_*
-     *
-     * "data" is owned by caller, and should not be modified or freed by callee
-     */
-    void (*OnUnsolicitedResponse)(int unsolResponse, const void *data, size_t datalen, RIL_SOCKET_ID socket_id);
-#else
-    /**
-     * "unsolResponse" is one of RIL_UNSOL_RESPONSE_*
-     * "data" is pointer to data defined for that RIL_UNSOL_RESPONSE_*
-     *
-     * "data" is owned by caller, and should not be modified or freed by callee
-     */
-    void (*OnUnsolicitedResponse)(int unsolResponse, const void *data, size_t datalen);
-#endif
-    /**
-     * Call user-specifed "callback" function on on the same thread that
-     * RIL_RequestFunc is called. If "relativeTime" is specified, then it specifies
-     * a relative time value at which the callback is invoked. If relativeTime is
-     * NULL or points to a 0-filled structure, the callback will be invoked as
-     * soon as possible
-     */
-
-    void (*RequestTimedCallback) (RIL_TimedCallback callback,
-                                   void *param, const struct timeval *relativeTime);
-   /**
-    * "t" is parameter passed in on previous call RIL_Notification routine
-    *
-    * RIL_onRequestAck will be called by vendor when an Async RIL request was received
-    * by them and an ack needs to be sent back to java ril.
-    */
-    void (*OnRequestAck) (RIL_Token t);
-};
-
-
-/**
- *  RIL implementations must defined RIL_Init
- *  argc and argv will be command line arguments intended for the RIL implementation
- *  Return NULL on error
- *
- * @param env is environment point defined as RIL_Env
- * @param argc number of arguments
- * @param argv list fo arguments
- *
- */
-const RIL_RadioFunctions *RIL_Init(const struct RIL_Env *env, int argc, char **argv);
-
-/**
- *  If BT SAP(SIM Access Profile) is supported, then RIL implementations must define RIL_SAP_Init
- *  for initializing RIL_RadioFunctions used for BT SAP communcations. It is called whenever RILD
- *  starts or modem restarts. Returns handlers for SAP related request that are made on SAP
- *  sepecific socket, analogous to the RIL_RadioFunctions returned by the call to RIL_Init
- *  and used on the general RIL socket.
- *  argc and argv will be command line arguments intended for the RIL implementation
- *  Return NULL on error.
- *
- * @param env is environment point defined as RIL_Env
- * @param argc number of arguments
- * @param argv list fo arguments
- *
- */
-const RIL_RadioFunctions *RIL_SAP_Init(const struct RIL_Env *env, int argc, char **argv);
-
-#else /* RIL_SHLIB */
-
-/**
- * Call this once at startup to register notification routine
- *
- * @param callbacks user-specifed callback function
- */
-void RIL_register (const RIL_RadioFunctions *callbacks);
-
-void rilc_thread_pool();
-
-
-/**
- *
- * RIL_onRequestComplete will return as soon as possible
- *
- * @param t is parameter passed in on previous call to RIL_Notification
- *          routine.
- * @param e error code
- *          if "e" != SUCCESS, then response can be null/is ignored
- * @param response is owned by caller, and should not be modified or
- *                 freed by callee
- * @param responselen the length of response in byte
- */
-void RIL_onRequestComplete(RIL_Token t, RIL_Errno e,
-                           void *response, size_t responselen);
-
-/**
- * RIL_onRequestAck will be called by vendor when an Async RIL request was received by them and
- * an ack needs to be sent back to java ril. This doesn't mark the end of the command or it's
- * results, just that the command was received and will take a while. After sending this Ack
- * its vendor's responsibility to make sure that AP is up whenever needed while command is
- * being processed.
- *
- * @param t is parameter passed in on previous call to RIL_Notification
- *          routine.
- */
-void RIL_onRequestAck(RIL_Token t);
-
-#if defined(ANDROID_MULTI_SIM)
-/**
- * @param unsolResponse is one of RIL_UNSOL_RESPONSE_*
- * @param data is pointer to data defined for that RIL_UNSOL_RESPONSE_*
- *     "data" is owned by caller, and should not be modified or freed by callee
- * @param datalen the length of data in byte
- */
-
-void RIL_onUnsolicitedResponse(int unsolResponse, const void *data,
-                                size_t datalen, RIL_SOCKET_ID socket_id);
-#else
-/**
- * @param unsolResponse is one of RIL_UNSOL_RESPONSE_*
- * @param data is pointer to data defined for that RIL_UNSOL_RESPONSE_*
- *     "data" is owned by caller, and should not be modified or freed by callee
- * @param datalen the length of data in byte
- */
-
-void RIL_onUnsolicitedResponse(int unsolResponse, const void *data,
-                                size_t datalen);
-#endif
-
-/**
- * Call user-specifed "callback" function on on the same thread that
- * RIL_RequestFunc is called. If "relativeTime" is specified, then it specifies
- * a relative time value at which the callback is invoked. If relativeTime is
- * NULL or points to a 0-filled structure, the callback will be invoked as
- * soon as possible
- *
- * @param callback user-specifed callback function
- * @param param parameter list
- * @param relativeTime a relative time value at which the callback is invoked
- */
-
-void RIL_requestTimedCallback (RIL_TimedCallback callback,
-                               void *param, const struct timeval *relativeTime);
-
-#endif /* RIL_SHLIB */
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif /*ANDROID_RIL_H*/
diff --git a/radio/include/telephony/ril_cdma_sms.h b/radio/include/telephony/ril_cdma_sms.h
deleted file mode 100644
index 835bc92a..00000000
--- a/radio/include/telephony/ril_cdma_sms.h
+++ /dev/null
@@ -1,806 +0,0 @@
-/*
- * Copyright (C) 2006 The Android Open Source Project
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
-/*
- * ISSUES:
- *
- */
-
-/**
- * TODO
- *
- *
- */
-
-
-#ifndef ANDROID_RIL_CDMA_SMS_H
-#define ANDROID_RIL_CDMA_SMS_H 1
-
-#include <stdlib.h>
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-/* Used by RIL_REQUEST_CDMA_SEND_SMS and RIL_UNSOL_RESPONSE_CDMA_NEW_SMS */
-
-#define RIL_CDMA_SMS_ADDRESS_MAX     36
-#define RIL_CDMA_SMS_SUBADDRESS_MAX  36
-#define RIL_CDMA_SMS_BEARER_DATA_MAX 255
-
-typedef enum {
-    RIL_CDMA_SMS_DIGIT_MODE_4_BIT = 0,     /* DTMF digits */
-    RIL_CDMA_SMS_DIGIT_MODE_8_BIT = 1,
-    RIL_CDMA_SMS_DIGIT_MODE_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_DigitMode;
-
-typedef enum {
-    RIL_CDMA_SMS_NUMBER_MODE_NOT_DATA_NETWORK = 0,
-    RIL_CDMA_SMS_NUMBER_MODE_DATA_NETWORK     = 1,
-    RIL_CDMA_SMS_NUMBER_MODE_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_NumberMode;
-
-typedef enum {
-    RIL_CDMA_SMS_NUMBER_TYPE_UNKNOWN                   = 0,
-    RIL_CDMA_SMS_NUMBER_TYPE_INTERNATIONAL_OR_DATA_IP  = 1,
-      /* INTERNATIONAL is used when number mode is not data network address.
-       * DATA_IP is used when the number mode is data network address
-       */
-    RIL_CDMA_SMS_NUMBER_TYPE_NATIONAL_OR_INTERNET_MAIL = 2,
-      /* NATIONAL is used when the number mode is not data network address.
-       * INTERNET_MAIL is used when the number mode is data network address.
-       * For INTERNET_MAIL, in the address data "digits", each byte contains
-       * an ASCII character. Examples are "x@y.com,a@b.com - ref TIA/EIA-637A 3.4.3.3
-       */
-    RIL_CDMA_SMS_NUMBER_TYPE_NETWORK                   = 3,
-    RIL_CDMA_SMS_NUMBER_TYPE_SUBSCRIBER                = 4,
-    RIL_CDMA_SMS_NUMBER_TYPE_ALPHANUMERIC              = 5,
-      /* GSM SMS: address value is GSM 7-bit chars */
-    RIL_CDMA_SMS_NUMBER_TYPE_ABBREVIATED               = 6,
-    RIL_CDMA_SMS_NUMBER_TYPE_RESERVED_7                = 7,
-    RIL_CDMA_SMS_NUMBER_TYPE_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_NumberType;
-
-typedef enum {
-    RIL_CDMA_SMS_NUMBER_PLAN_UNKNOWN     = 0,
-    RIL_CDMA_SMS_NUMBER_PLAN_TELEPHONY   = 1,      /* CCITT E.164 and E.163, including ISDN plan */
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_2  = 2,
-    RIL_CDMA_SMS_NUMBER_PLAN_DATA        = 3,      /* CCITT X.121 */
-    RIL_CDMA_SMS_NUMBER_PLAN_TELEX       = 4,      /* CCITT F.69 */
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_5  = 5,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_6  = 6,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_7  = 7,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_8  = 8,
-    RIL_CDMA_SMS_NUMBER_PLAN_PRIVATE     = 9,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_10 = 10,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_11 = 11,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_12 = 12,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_13 = 13,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_14 = 14,
-    RIL_CDMA_SMS_NUMBER_PLAN_RESERVED_15 = 15,
-    RIL_CDMA_SMS_NUMBER_PLAN_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_NumberPlan;
-
-typedef struct {
-    RIL_CDMA_SMS_DigitMode digit_mode;
-      /* Indicates 4-bit or 8-bit */
-    RIL_CDMA_SMS_NumberMode number_mode;
-      /* Used only when digitMode is 8-bit */
-    RIL_CDMA_SMS_NumberType number_type;
-      /* Used only when digitMode is 8-bit.
-       * To specify an international address, use the following:
-       * digitMode = RIL_CDMA_SMS_DIGIT_MODE_8_BIT
-       * numberMode = RIL_CDMA_SMS_NOT_DATA_NETWORK
-       * numberType = RIL_CDMA_SMS_NUMBER_TYPE_INTERNATIONAL_OR_DATA_IP
-       * numberPlan = RIL_CDMA_SMS_NUMBER_PLAN_TELEPHONY
-       * numberOfDigits = number of digits
-       * digits = ASCII digits, e.g. '1', '2', '3'3, '4', and '5'
-       */
-    RIL_CDMA_SMS_NumberPlan number_plan;
-      /* Used only when digitMode is 8-bit */
-    unsigned char number_of_digits;
-    unsigned char digits[ RIL_CDMA_SMS_ADDRESS_MAX ];
-      /* Each byte in this array represnts a 4-bit or 8-bit digit of address data */
-} RIL_CDMA_SMS_Address;
-
-typedef enum {
-    RIL_CDMA_SMS_SUBADDRESS_TYPE_NSAP           = 0,    /* CCITT X.213 or ISO 8348 AD2 */
-    RIL_CDMA_SMS_SUBADDRESS_TYPE_USER_SPECIFIED = 1,    /* e.g. X.25 */
-    RIL_CDMA_SMS_SUBADDRESS_TYPE_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_SubaddressType;
-
-typedef struct {
-    RIL_CDMA_SMS_SubaddressType subaddressType;
-    /* 1 means the last byte's lower 4 bits should be ignored */
-    unsigned char odd;
-    unsigned char number_of_digits;
-    /* Each byte respresents a 8-bit digit of subaddress data */
-    unsigned char digits[ RIL_CDMA_SMS_SUBADDRESS_MAX ];
-} RIL_CDMA_SMS_Subaddress;
-
-typedef struct {
-    int uTeleserviceID;
-    unsigned char bIsServicePresent;
-    int uServicecategory;
-    RIL_CDMA_SMS_Address sAddress;
-    RIL_CDMA_SMS_Subaddress sSubAddress;
-    int uBearerDataLen;
-    unsigned char aBearerData[ RIL_CDMA_SMS_BEARER_DATA_MAX ];
-} RIL_CDMA_SMS_Message;
-
-/* Used by RIL_REQUEST_CDMA_SMS_ACKNOWLEDGE */
-
-typedef enum {
-    RIL_CDMA_SMS_NO_ERROR       = 0,
-    RIL_CDMA_SMS_ERROR          = 1,
-    RIL_CDMA_SMS_ERROR_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_ErrorClass;
-
-typedef struct {
-    RIL_CDMA_SMS_ErrorClass uErrorClass;
-    int uSMSCauseCode;  /* As defined in N.S00005, 6.5.2.125.
-                           Currently, only 35 (resource shortage) and
-                           39 (other terminal problem) are reported. */
-} RIL_CDMA_SMS_Ack;
-
-/* Used by RIL_REQUEST_CDMA_SMS_GET_BROADCAST_CONFIG and
-   RIL_REQUEST_CDMA_SMS_SET_BROADCAST_CONFIG */
-
-typedef struct {
-    int service_category;
-    int language;
-    unsigned char selected;
-} RIL_CDMA_BroadcastSmsConfigInfo;
-
-/* Used by RIL_REQUEST_CDMA_WRITE_SMS_TO_RUIM */
-
-typedef struct {
-    int status;     /* Status of message.  See TS 27.005 3.1, "<stat>": */
-                  /*      0 = "REC UNREAD"    */
-                  /*      1 = "REC READ"      */
-                  /*      2 = "STO UNSENT"    */
-                  /*      3 = "STO SENT"      */
-
-    RIL_CDMA_SMS_Message message;
-} RIL_CDMA_SMS_WriteArgs;
-
-
-/* Used by RIL_REQUEST_ENCODE_CDMA_SMS and RIL_REQUEST_DECODE_CDMA_SMS*/
-
-#define RIL_CDMA_SMS_UDH_MAX_SND_SIZE           128
-#define RIL_CDMA_SMS_UDH_EO_DATA_SEGMENT_MAX    131 /* 140 - 3 - 6 */
-#define RIL_CDMA_SMS_MAX_UD_HEADERS         7
-#define RIL_CDMA_SMS_USER_DATA_MAX     229
-#define RIL_CDMA_SMS_ADDRESS_MAX            36
-#define RIL_CDMA_SMS_UDH_LARGE_PIC_SIZE     128
-#define RIL_CDMA_SMS_UDH_SMALL_PIC_SIZE     32
-#define RIL_CDMA_SMS_UDH_VAR_PIC_SIZE       134
-#define RIL_CDMA_SMS_UDH_ANIM_NUM_BITMAPS   4
-#define RIL_CDMA_SMS_UDH_LARGE_BITMAP_SIZE  32
-#define RIL_CDMA_SMS_UDH_SMALL_BITMAP_SIZE  8
-#define RIL_CDMA_SMS_UDH_OTHER_SIZE         226
-#define RIL_CDMA_SMS_IP_ADDRESS_SIZE        4
-
-/* ------------------- */
-/* ---- User Data ---- */
-/* ------------------- */
-typedef enum {
-    RIL_CDMA_SMS_UDH_CONCAT_8         = 0x00,
-    RIL_CDMA_SMS_UDH_SPECIAL_SM,
-    /* 02 - 03    Reserved */
-    RIL_CDMA_SMS_UDH_PORT_8           = 0x04,
-    RIL_CDMA_SMS_UDH_PORT_16,
-    RIL_CDMA_SMS_UDH_SMSC_CONTROL,
-    RIL_CDMA_SMS_UDH_SOURCE,
-    RIL_CDMA_SMS_UDH_CONCAT_16,
-    RIL_CDMA_SMS_UDH_WCMP,
-    RIL_CDMA_SMS_UDH_TEXT_FORMATING,
-    RIL_CDMA_SMS_UDH_PRE_DEF_SOUND,
-    RIL_CDMA_SMS_UDH_USER_DEF_SOUND,
-    RIL_CDMA_SMS_UDH_PRE_DEF_ANIM,
-    RIL_CDMA_SMS_UDH_LARGE_ANIM,
-    RIL_CDMA_SMS_UDH_SMALL_ANIM,
-    RIL_CDMA_SMS_UDH_LARGE_PICTURE,
-    RIL_CDMA_SMS_UDH_SMALL_PICTURE,
-    RIL_CDMA_SMS_UDH_VAR_PICTURE,
-
-    RIL_CDMA_SMS_UDH_USER_PROMPT      = 0x13,
-    RIL_CDMA_SMS_UDH_EXTENDED_OBJECT  = 0x14,
-
-    /* 15 - 1F    Reserved for future EMS */
-
-    RIL_CDMA_SMS_UDH_RFC822           = 0x20,
-
-    /*  21 - 6F    Reserved for future use */
-    /*  70 - 7f    Reserved for (U)SIM Toolkit Security Headers */
-    /*  80 - 9F    SME to SME specific use */
-    /*  A0 - BF    Reserved for future use */
-    /*  C0 - DF    SC specific use */
-    /*  E0 - FF    Reserved for future use */
-
-    RIL_CDMA_SMS_UDH_OTHER            = 0xFFFF, /* For unsupported or proprietary headers */
-    RIL_CDMA_SMS_UDH_ID_MAX32 = 0x10000000   /* Force constant ENUM size in structures */
-
-} RIL_CDMA_SMS_UdhId;
-
-typedef struct {
-    /*indicates the reference number for a particular concatenated short message. */
-    /*it is constant for every short message which makes up a particular concatenated short message*/
-    unsigned char       msg_ref;
-
-    /*indicates the total number of short messages within the concatenated short message.
-     The value shall start at 1 and remain constant for every
-     short message which makes up the concatenated short message.
-     if it is 0 then the receiving entity shall ignore the whole Information Element*/
-    unsigned char       total_sm;
-
-    /*
-     * it indicates the sequence number of a particular short message within the concatenated short
-     * message. The value shall start at 1 and increment by one for every short message sent
-     * within the concatenated short message. If the value is zero or the value is
-     * greater than the value in octet 2 then the receiving
-     * entity shall ignore the whole Information Element.
-     */
-    unsigned char      seq_num;
-} RIL_CDMA_SMS_UdhConcat8;
-
-/* GW message waiting actions
-*/
-typedef enum {
-    RIL_CDMA_SMS_GW_MSG_WAITING_NONE,
-    RIL_CDMA_SMS_GW_MSG_WAITING_DISCARD,
-    RIL_CDMA_SMS_GW_MSG_WAITING_STORE,
-    RIL_CDMA_SMS_GW_MSG_WAITING_NONE_1111,
-    RIL_CDMA_SMS_GW_MSG_WAITING_MAX32 = 0x10000000 /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_GWMsgWaiting;
-
-/* GW message waiting types
-*/
-typedef enum {
-    RIL_CDMA_SMS_GW_MSG_WAITING_VOICEMAIL,
-    RIL_CDMA_SMS_GW_MSG_WAITING_FAX,
-    RIL_CDMA_SMS_GW_MSG_WAITING_EMAIL,
-    RIL_CDMA_SMS_GW_MSG_WAITING_OTHER,
-    RIL_CDMA_SMS_GW_MSG_WAITING_KIND_MAX32 = 0x10000000   /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_GWMsgWaitingKind;
-
-typedef struct {
-    RIL_CDMA_SMS_GWMsgWaiting                 msg_waiting;
-    RIL_CDMA_SMS_GWMsgWaitingKind             msg_waiting_kind;
-
-    /*it indicates the number of messages of the type specified in Octet 1 waiting.*/
-    unsigned char                             message_count;
-} RIL_CDMA_SMS_UdhSpecialSM;
-
-typedef struct {
-    unsigned char  dest_port;
-    unsigned char  orig_port;
-} RIL_CDMA_SMS_UdhWap8;
-
-typedef struct {
-    unsigned short  dest_port;
-    unsigned short  orig_port;
-} RIL_CDMA_SMS_UdhWap16;
-
-typedef struct {
-    unsigned short      msg_ref;
-    unsigned char       total_sm;
-    unsigned char       seq_num;
-
-} RIL_CDMA_SMS_UdhConcat16;
-
-typedef enum {
-    RIL_CDMA_SMS_UDH_LEFT_ALIGNMENT = 0,
-    RIL_CDMA_SMS_UDH_CENTER_ALIGNMENT,
-    RIL_CDMA_SMS_UDH_RIGHT_ALIGNMENT,
-    RIL_CDMA_SMS_UDH_DEFAULT_ALIGNMENT,
-    RIL_CDMA_SMS_UDH_MAX_ALIGNMENT,
-    RIL_CDMA_SMS_UDH_ALIGNMENT_MAX32 = 0x10000000   /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_UdhAlignment;
-
-typedef enum {
-    RIL_CDMA_SMS_UDH_FONT_NORMAL = 0,
-    RIL_CDMA_SMS_UDH_FONT_LARGE,
-    RIL_CDMA_SMS_UDH_FONT_SMALL,
-    RIL_CDMA_SMS_UDH_FONT_RESERVED,
-    RIL_CDMA_SMS_UDH_FONT_MAX,
-    RIL_CDMA_SMS_UDH_FONT_MAX32 = 0x10000000   /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_UdhFontSize;
-
-typedef enum {
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BLACK          = 0x0,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_GREY      = 0x1,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_RED       = 0x2,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_YELLOW    = 0x3,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_GREEN     = 0x4,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_CYAN      = 0x5,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_BLUE      = 0x6,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_DARK_MAGENTA   = 0x7,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_GREY           = 0x8,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_WHITE          = 0x9,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BRIGHT_RED     = 0xA,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BRIGHT_YELLOW  = 0xB,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BRIGHT_GREEN   = 0xC,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BRIGHT_CYAN    = 0xD,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BRIGHT_BLUE    = 0xE,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_BRIGHT_MAGENTA = 0xF,
-    RIL_CDMA_SMS_UDH_TEXT_COLOR_MAX32 = 0x10000000   /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_UdhTextColor;
-
-typedef struct {
-    unsigned char              start_position;
-    unsigned char              text_formatting_length;
-    RIL_CDMA_SMS_UdhAlignment  alignment_type ;       /*bit 0 and  bit 1*/
-    RIL_CDMA_SMS_UdhFontSize   font_size ;            /*bit 3 and  bit 2*/
-    unsigned char              style_bold;            /*bit 4 */
-    unsigned char              style_italic;          /*bit 5  */
-    unsigned char              style_underlined;      /*bit 6 */
-    unsigned char              style_strikethrough;   /*bit 7 */
-
-    /* if FALSE, ignore the following color information */
-    unsigned char              is_color_present;
-    RIL_CDMA_SMS_UdhTextColor  text_color_foreground;
-    RIL_CDMA_SMS_UdhTextColor  text_color_background;
-
-} RIL_CDMA_SMS_UdhTextFormating;
-
-/* Predefined sound
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       snd_number;
-} RIL_CDMA_SMS_UdhPreDefSound;
-
-/* User Defined sound
-*/
-typedef struct {
-    unsigned char       data_length;
-    unsigned char       position;
-    unsigned char       user_def_sound[RIL_CDMA_SMS_UDH_MAX_SND_SIZE];
-} RIL_CDMA_SMS_UdhUserDefSound;
-
-/* Large picture
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       data[RIL_CDMA_SMS_UDH_LARGE_PIC_SIZE];
-} RIL_CDMA_SMS_UdhLargePictureData;
-
-/* Small picture
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       data[RIL_CDMA_SMS_UDH_SMALL_PIC_SIZE];
-} RIL_CDMA_SMS_UdhSmallPictureData;
-
-/* Variable length picture
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       width;    /* Number of pixels - Should be a mutliple of 8 */
-    unsigned char       height;
-    unsigned char       data[RIL_CDMA_SMS_UDH_VAR_PIC_SIZE];
-} RIL_CDMA_SMS_UdhVarPicture;
-
-/* Predefined animation
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       animation_number;
-} RIL_CDMA_SMS_UdhPreDefAnim;
-
-/* Large animation
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       data[RIL_CDMA_SMS_UDH_ANIM_NUM_BITMAPS][RIL_CDMA_SMS_UDH_LARGE_BITMAP_SIZE];
-} RIL_CDMA_SMS_UdhLargeAnim;
-
-/* Small animation
-*/
-typedef struct {
-    unsigned char       position;
-    unsigned char       data[RIL_CDMA_SMS_UDH_ANIM_NUM_BITMAPS][RIL_CDMA_SMS_UDH_SMALL_BITMAP_SIZE];
-} RIL_CDMA_SMS_UdhSmallAnim;
-
-/* User Prompt Indicator UDH
-*/
-typedef struct {
-    unsigned char       number_of_objects;
-    /* Number of objects of the same kind that follow this header which will
-    ** be stitched together by the applications. For example, 5 small pictures
-    ** are to be stitched together horizontally, or 6 iMelody tones are to be
-    ** connected together with intermediate iMelody header and footer ignored.
-    ** Allowed objects to be stitched:
-    **   - Images (small, large, variable)
-    **   - User defined sounds
-    */
-} RIL_CDMA_SMS_UdhUserPrompt;
-
-typedef struct {
-    unsigned char         length;
-
-    unsigned char         data[RIL_CDMA_SMS_UDH_EO_DATA_SEGMENT_MAX];
-    /* RIL_CDMA_SMS_UDH_EO_VCARD: See http://www.imc.org/pdi/vcard-21.doc for payload */
-    /* RIL_CDMA_SMS_UDH_EO_VCALENDAR: See http://www.imc.org/pdi/vcal-10.doc */
-    /* Or: Unsupported/proprietary extended objects */
-
-} RIL_CDMA_SMS_UdhEoContent;
-
-/* Extended Object UDH
-*/
-/* Extended Object IDs/types
-*/
-typedef enum {
-    RIL_CDMA_SMS_UDH_EO_VCARD                   = 0x09,
-    RIL_CDMA_SMS_UDH_EO_VCALENDAR               = 0x0A,
-    RIL_CDMA_SMS_UDH_EO_MAX32 = 0x10000000   /* Force constant ENUM size in structures */
-} RIL_CDMA_SMS_UdhEoId;
-
-typedef struct {
-    /* Extended objects are to be used together with 16-bit concatenation
-    ** UDH. The max number of segments supported for E.O. is 8 at least.
-    */
-    RIL_CDMA_SMS_UdhEoContent    content;
-
-    unsigned char                                 first_segment;
-    /* The following fields are only present in the first segment of a
-    ** concatenated SMS message.
-    */
-   unsigned char                                   reference;
-    /* Identify those extended object segments which should be linked together
-    */
-   unsigned short                                  length;
-    /* Length of the whole extended object data
-    */
-    unsigned char                                   control;
-    RIL_CDMA_SMS_UdhEoId                    type;
-    unsigned short                                  position;
-    /* Absolute position of the E.O. in the whole text after concatenation,
-    ** starting from 1.
-    */
-} RIL_CDMA_SMS_UdhEo;
-
-typedef struct {
-    RIL_CDMA_SMS_UdhId  header_id;
-    unsigned char               header_length;
-    unsigned char              data[RIL_CDMA_SMS_UDH_OTHER_SIZE];
-} RIL_CDMA_SMS_UdhOther;
-
-typedef struct {
-    unsigned char        header_length;
-} RIL_CDMA_SMS_UdhRfc822;
-
-typedef struct {
-    RIL_CDMA_SMS_UdhId                header_id;
-
-    union {
-        RIL_CDMA_SMS_UdhConcat8             concat_8;       // 00
-
-        RIL_CDMA_SMS_UdhSpecialSM           special_sm;     // 01
-        RIL_CDMA_SMS_UdhWap8                wap_8;          // 04
-        RIL_CDMA_SMS_UdhWap16               wap_16;         // 05
-        RIL_CDMA_SMS_UdhConcat16            concat_16;      // 08
-        RIL_CDMA_SMS_UdhTextFormating       text_formating; // 0a
-        RIL_CDMA_SMS_UdhPreDefSound         pre_def_sound;  // 0b
-        RIL_CDMA_SMS_UdhUserDefSound        user_def_sound; // 0c
-        RIL_CDMA_SMS_UdhPreDefAnim          pre_def_anim;   // 0d
-        RIL_CDMA_SMS_UdhLargeAnim           large_anim;     // 0e
-        RIL_CDMA_SMS_UdhSmallAnim           small_anim;     // 0f
-        RIL_CDMA_SMS_UdhLargePictureData    large_picture;  // 10
-        RIL_CDMA_SMS_UdhSmallPictureData    small_picture;  // 11
-        RIL_CDMA_SMS_UdhVarPicture          var_picture;    // 12
-
-        RIL_CDMA_SMS_UdhUserPrompt          user_prompt;    // 13
-        RIL_CDMA_SMS_UdhEo                  eo;             // 14
-
-        RIL_CDMA_SMS_UdhRfc822              rfc822;         // 20
-        RIL_CDMA_SMS_UdhOther               other;
-
-    }u;
-} RIL_CDMA_SMS_Udh;
-
-/* ----------------------------- */
-/* -- User data encoding type -- */
-/* ----------------------------- */
-typedef enum {
-    RIL_CDMA_SMS_ENCODING_OCTET        = 0,    /* 8-bit */
-    RIL_CDMA_SMS_ENCODING_IS91EP,              /* varies */
-    RIL_CDMA_SMS_ENCODING_ASCII,               /* 7-bit */
-    RIL_CDMA_SMS_ENCODING_IA5,                 /* 7-bit */
-    RIL_CDMA_SMS_ENCODING_UNICODE,             /* 16-bit */
-    RIL_CDMA_SMS_ENCODING_SHIFT_JIS,           /* 8 or 16-bit */
-    RIL_CDMA_SMS_ENCODING_KOREAN,              /* 8 or 16-bit */
-    RIL_CDMA_SMS_ENCODING_LATIN_HEBREW,        /* 8-bit */
-    RIL_CDMA_SMS_ENCODING_LATIN,               /* 8-bit */
-    RIL_CDMA_SMS_ENCODING_GSM_7_BIT_DEFAULT,   /* 7-bit */
-    RIL_CDMA_SMS_ENCODING_MAX32        = 0x10000000
-
-} RIL_CDMA_SMS_UserDataEncoding;
-
-/* ------------------------ */
-/* -- IS-91 EP data type -- */
-/* ------------------------ */
-typedef enum {
-    RIL_CDMA_SMS_IS91EP_VOICE_MAIL         = 0x82,
-    RIL_CDMA_SMS_IS91EP_SHORT_MESSAGE_FULL = 0x83,
-    RIL_CDMA_SMS_IS91EP_CLI_ORDER          = 0x84,
-    RIL_CDMA_SMS_IS91EP_SHORT_MESSAGE      = 0x85,
-    RIL_CDMA_SMS_IS91EP_MAX32              = 0x10000000
-
-} RIL_CDMA_SMS_IS91EPType;
-
-typedef struct {
-    /* NOTE: If message_id.udh_present == TRUE:
-    **       'num_headers' is the number of User Data Headers (UDHs),
-    **       and 'headers' include all those headers.
-    */
-    unsigned char                              num_headers;
-    RIL_CDMA_SMS_Udh                     headers[RIL_CDMA_SMS_MAX_UD_HEADERS];
-
-    RIL_CDMA_SMS_UserDataEncoding      encoding;
-    RIL_CDMA_SMS_IS91EPType             is91ep_type;
-
-    /*----------------------------------------------------------------------
-     'data_len' indicates the valid number of bytes in the 'data' array.
-
-     'padding_bits' (0-7) indicates how many bits in the last byte of 'data'
-     are invalid bits. This parameter is only used for Mobile-Originated
-     messages. There is no way for the API to tell how many padding bits
-     exist in the received message. Instead, the application can find out how
-     many padding bits exist in the user data when decoding the user data.
-
-     'data' has the raw bits of the user data field of the SMS message.
-     The client software should decode the raw user data according to its
-     supported encoding types and languages.
-
-     EXCEPTION 1: CMT-91 user data raw bits are first translated into BD fields
-     (e.g. num_messages, callback, etc.) The translated user data field in
-     VMN and Short Message is in the form of ASCII characters, each occupying
-     a byte in the resulted 'data'.
-
-     EXCEPTION 2: GSM 7-bit Default characters are decoded so that each byte
-     has one 7-bit GSM character.
-
-     'number_of_digits' is the number of digits/characters (7, 8, 16, or
-     whatever bits) in the raw user data, which can be used by the client
-     when decoding the user data according to the encoding type and language.
-    -------------------------------------------------------------------------*/
-    unsigned char                                data_len;
-    unsigned char                                padding_bits;
-    unsigned char                                data[ RIL_CDMA_SMS_USER_DATA_MAX ];
-    unsigned char                                number_of_digits;
-
-} RIL_CDMA_SMS_CdmaUserData;
-
-/* -------------------- */
-/* ---- Message Id ---- */
-/* -------------------- */
-typedef enum {
-    RIL_CDMA_SMS_BD_TYPE_RESERVED_0     = 0,
-    RIL_CDMA_SMS_BD_TYPE_DELIVER,       /* MT only */
-    RIL_CDMA_SMS_BD_TYPE_SUBMIT,        /* MO only */
-    RIL_CDMA_SMS_BD_TYPE_CANCELLATION,  /* MO only */
-    RIL_CDMA_SMS_BD_TYPE_DELIVERY_ACK,  /* MT only */
-    RIL_CDMA_SMS_BD_TYPE_USER_ACK,      /* MT & MO */
-    RIL_CDMA_SMS_BD_TYPE_READ_ACK,      /* MT & MO */
-    RIL_CDMA_SMS_BD_TYPE_MAX32          = 0x10000000
-
-} RIL_CDMA_SMS_BdMessageType;
-
-typedef unsigned int  RIL_CDMA_SMS_MessageNumber;
-
-typedef struct {
-    RIL_CDMA_SMS_BdMessageType   type;
-    RIL_CDMA_SMS_MessageNumber      id_number;
-    unsigned char                      udh_present;
-    /* NOTE: if FEATURE_SMS_UDH is not defined,
-    ** udh_present should be ignored.
-    */
-} RIL_CDMA_SMS_MessageId;
-
-typedef unsigned char           RIL_CDMA_SMS_UserResponse;
-
-/* ------------------- */
-/* ---- Timestamp ---- */
-/* ------------------- */
-typedef struct {
-    /* If 'year' is between 96 and 99, the actual year is 1900 + 'year';
-       if 'year' is between 00 and 95, the actual year is 2000 + 'year'.
-       NOTE: Each field has two BCD digits and byte arrangement is <MSB, ... ,LSB>
-    */
-    unsigned char      year;        /* 0x00-0x99 */
-    unsigned char      month;       /* 0x01-0x12 */
-    unsigned char      day;         /* 0x01-0x31 */
-    unsigned char      hour;        /* 0x00-0x23 */
-    unsigned char      minute;      /* 0x00-0x59 */
-    unsigned char      second;      /* 0x00-0x59 */
-    signed char      timezone;    /* +/-, [-48,+48] number of 15 minutes - GW only */
-} RIL_CDMA_SMS_Timestamp;
-
-/* ------------------ */
-/* ---- Priority ---- */
-/* ------------------ */
-typedef enum {
-    RIL_CDMA_SMS_PRIORITY_NORMAL      = 0,
-    RIL_CDMA_SMS_PRIORITY_INTERACTIVE,
-    RIL_CDMA_SMS_PRIORITY_URGENT,
-    RIL_CDMA_SMS_PRIORITY_EMERGENCY,
-    RIL_CDMA_SMS_PRIORITY_MAX32       = 0x10000000
-
-} RIL_CDMA_SMS_Priority;
-
-/* ----------------- */
-/* ---- Privacy ---- */
-/* ----------------- */
-typedef enum {
-    RIL_CDMA_SMS_PRIVACY_NORMAL      = 0,
-    RIL_CDMA_SMS_PRIVACY_RESTRICTED,
-    RIL_CDMA_SMS_PRIVACY_CONFIDENTIAL,
-    RIL_CDMA_SMS_PRIVACY_SECRET,
-    RIL_CDMA_SMS_PRIVACY_MAX32       = 0x10000000
-
-} RIL_CDMA_SMS_Privacy;
-
-/* ---------------------- */
-/* ---- Reply option ---- */
-/* ---------------------- */
-typedef struct {
-    /* whether user ack is requested
-    */
-    unsigned char          user_ack_requested;
-
-    /* whether delivery ack is requested.
-       Should be FALSE for incoming messages.
-    */
-    unsigned char          delivery_ack_requested;
-
-    /* Message originator requests the receiving phone to send back a READ_ACK
-    ** message automatically when the user reads the received message.
-    */
-    unsigned char          read_ack_requested;
-
-} RIL_CDMA_SMS_ReplyOption;
-
-typedef enum {
-    RIL_CDMA_SMS_ALERT_MODE_DEFAULT         = 0,
-    RIL_CDMA_SMS_ALERT_MODE_LOW_PRIORITY    = 1,
-    RIL_CDMA_SMS_ALERT_MODE_MEDIUM_PRIORITY = 2,
-    RIL_CDMA_SMS_ALERT_MODE_HIGH_PRIORITY   = 3,
-
-    /* For pre-IS637A implementations, alert_mode only has values of True/False:
-    */
-    RIL_CDMA_SMS_ALERT_MODE_OFF   = 0,
-    RIL_CDMA_SMS_ALERT_MODE_ON    = 1
-
-} RIL_CDMA_SMS_AlertMode;
-
-/* ------------------ */
-/* ---- Language ---- */
-/* ------------------ */
-typedef enum {
-    RIL_CDMA_SMS_LANGUAGE_UNSPECIFIED = 0,
-    RIL_CDMA_SMS_LANGUAGE_ENGLISH,
-    RIL_CDMA_SMS_LANGUAGE_FRENCH,
-    RIL_CDMA_SMS_LANGUAGE_SPANISH,
-    RIL_CDMA_SMS_LANGUAGE_JAPANESE,
-    RIL_CDMA_SMS_LANGUAGE_KOREAN,
-    RIL_CDMA_SMS_LANGUAGE_CHINESE,
-    RIL_CDMA_SMS_LANGUAGE_HEBREW,
-    RIL_CDMA_SMS_LANGUAGE_MAX32       = 0x10000000
-
-} RIL_CDMA_SMS_Language;
-
-/* ---------------------------------- */
-/* ---------- Display Mode ---------- */
-/* ---------------------------------- */
-typedef enum {
-    RIL_CDMA_SMS_DISPLAY_MODE_IMMEDIATE   = 0,
-    RIL_CDMA_SMS_DISPLAY_MODE_DEFAULT     = 1,
-    RIL_CDMA_SMS_DISPLAY_MODE_USER_INVOKE = 2,
-    RIL_CDMA_SMS_DISPLAY_MODE_RESERVED    = 3
-} RIL_CDMA_SMS_DisplayMode;
-
-/* IS-637B parameters/fields
-*/
-
-/* ---------------------------------- */
-/* ---------- Delivery Status ------- */
-/* ---------------------------------- */
-typedef enum {
-    RIL_CDMA_SMS_DELIVERY_STATUS_ACCEPTED              = 0,    /* ERROR_CLASS_NONE */
-    RIL_CDMA_SMS_DELIVERY_STATUS_DEPOSITED_TO_INTERNET = 1,    /* ERROR_CLASS_NONE */
-    RIL_CDMA_SMS_DELIVERY_STATUS_DELIVERED             = 2,    /* ERROR_CLASS_NONE */
-    RIL_CDMA_SMS_DELIVERY_STATUS_CANCELLED             = 3,    /* ERROR_CLASS_NONE */
-
-    RIL_CDMA_SMS_DELIVERY_STATUS_NETWORK_CONGESTION  = 4,    /* ERROR_CLASS_TEMP & PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_NETWORK_ERROR       = 5,    /* ERROR_CLASS_TEMP & PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_CANCEL_FAILED       = 6,    /* ERROR_CLASS_PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_BLOCKED_DESTINATION = 7,    /* ERROR_CLASS_PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_TEXT_TOO_LONG       = 8,    /* ERROR_CLASS_PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_DUPLICATE_MESSAGE   = 9,    /* ERROR_CLASS_PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_INVALID_DESTINATION = 10,   /* ERROR_CLASS_PERM */
-    RIL_CDMA_SMS_DELIVERY_STATUS_MESSAGE_EXPIRED     = 13,   /* ERROR_CLASS_PERM */
-
-    RIL_CDMA_SMS_DELIVERY_STATUS_UNKNOWN_ERROR       = 0x1F  /* ERROR_CLASS_PERM */
-
-    /* All the other values are reserved */
-
-} RIL_CDMA_SMS_DeliveryStatusE;
-
-typedef struct {
-    RIL_CDMA_SMS_ErrorClass       error_class;
-    RIL_CDMA_SMS_DeliveryStatusE   status;
-} RIL_CDMA_SMS_DeliveryStatus;
-
-typedef struct {
-    unsigned char               address[RIL_CDMA_SMS_IP_ADDRESS_SIZE];
-    unsigned char             is_valid;
-} RIL_CDMA_SMS_IpAddress;
-
-/* This special parameter captures any unrecognized/proprietary parameters
-*/
-typedef struct {
-    unsigned char                         input_other_len;
-    unsigned char                         desired_other_len; /* used during decoding */
-    unsigned char                         * other_data;
-} RIL_CDMA_SMS_OtherParm;
-
-typedef struct {
-    /* the mask indicates which fields are present in this message */
-    unsigned int                        mask;
-
-    RIL_CDMA_SMS_MessageId         message_id;
-    RIL_CDMA_SMS_CdmaUserData     user_data;
-    RIL_CDMA_SMS_UserResponse        user_response;
-    RIL_CDMA_SMS_Timestamp          mc_time;
-    RIL_CDMA_SMS_Timestamp          validity_absolute;
-    RIL_CDMA_SMS_Timestamp          validity_relative;
-    RIL_CDMA_SMS_Timestamp          deferred_absolute;
-    RIL_CDMA_SMS_Timestamp          deferred_relative;
-    RIL_CDMA_SMS_Priority           priority;
-    RIL_CDMA_SMS_Privacy            privacy;
-    RIL_CDMA_SMS_ReplyOption       reply_option;
-    unsigned char                         num_messages;  /* the actual value; not BCDs */
-    RIL_CDMA_SMS_AlertMode         alert_mode;
-     /* For pre-IS-637A implementations, alert_mode is either Off or On. */
-    RIL_CDMA_SMS_Language           language;
-    RIL_CDMA_SMS_Address            callback;
-    RIL_CDMA_SMS_DisplayMode       display_mode;
-
-    RIL_CDMA_SMS_DeliveryStatus    delivery_status;
-    unsigned int                        deposit_index;
-
-    RIL_CDMA_SMS_IpAddress         ip_address;
-    unsigned char                         rsn_no_notify;
-
-    /* See function comments of wms_ts_decode() and
-    ** wms_ts_decode_cdma_bd_with_other() for details regarding 'other' parameters
-    */
-    RIL_CDMA_SMS_OtherParm         other;
-
-} RIL_CDMA_SMS_ClientBd;
-
-typedef struct {
-    unsigned char length;   /* length, in bytes, of the encoded SMS message */
-    unsigned char * data;   /* the encoded SMS message (max 255 bytes) */
-} RIL_CDMA_Encoded_SMS;
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif /*ANDROID_RIL_CDMA_SMS_H*/
diff --git a/radio/include/telephony/ril_nv_items.h b/radio/include/telephony/ril_nv_items.h
deleted file mode 100644
index 748ea072..00000000
--- a/radio/include/telephony/ril_nv_items.h
+++ /dev/null
@@ -1,88 +0,0 @@
-/*
- * Copyright (C) 2014 The Android Open Source Project
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
-#ifndef ANDROID_RIL_NV_ITEMS_H
-#define ANDROID_RIL_NV_ITEMS_H 1
-
-#include <stdlib.h>
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-/* Must match the values in RadioNVItems.java in frameworks/opt/telephony. */
-typedef enum {
-
-    // CDMA radio and account information (items 1-10)
-    RIL_NV_CDMA_MEID = 1,                   // CDMA MEID (hex)
-    RIL_NV_CDMA_MIN = 2,                    // CDMA MIN (MSID)
-    RIL_NV_CDMA_MDN = 3,                    // CDMA MDN
-    RIL_NV_CDMA_ACCOLC = 4,                 // CDMA access overload control
-
-    // Carrier device provisioning (items 11-30)
-    RIL_NV_DEVICE_MSL = 11,                 // device MSL
-    RIL_NV_RTN_RECONDITIONED_STATUS = 12,   // RTN reconditioned status
-    RIL_NV_RTN_ACTIVATION_DATE = 13,        // RTN activation date
-    RIL_NV_RTN_LIFE_TIMER = 14,             // RTN life timer
-    RIL_NV_RTN_LIFE_CALLS = 15,             // RTN life calls
-    RIL_NV_RTN_LIFE_DATA_TX = 16,           // RTN life data TX
-    RIL_NV_RTN_LIFE_DATA_RX = 17,           // RTN life data RX
-    RIL_NV_OMADM_HFA_LEVEL = 18,            // HFA in progress
-
-    // Mobile IP profile information (items 31-50)
-    RIL_NV_MIP_PROFILE_NAI = 31,            // NAI realm
-    RIL_NV_MIP_PROFILE_HOME_ADDRESS = 32,   // MIP home address
-    RIL_NV_MIP_PROFILE_AAA_AUTH = 33,       // AAA auth
-    RIL_NV_MIP_PROFILE_HA_AUTH = 34,        // HA auth
-    RIL_NV_MIP_PROFILE_PRI_HA_ADDR = 35,    // primary HA address
-    RIL_NV_MIP_PROFILE_SEC_HA_ADDR = 36,    // secondary HA address
-    RIL_NV_MIP_PROFILE_REV_TUN_PREF = 37,   // reverse TUN preference
-    RIL_NV_MIP_PROFILE_HA_SPI = 38,         // HA SPI
-    RIL_NV_MIP_PROFILE_AAA_SPI = 39,        // AAA SPI
-    RIL_NV_MIP_PROFILE_MN_HA_SS = 40,       // HA shared secret
-    RIL_NV_MIP_PROFILE_MN_AAA_SS = 41,      // AAA shared secret
-
-    // CDMA network and band config (items 51-70)
-    RIL_NV_CDMA_PRL_VERSION = 51,           // CDMA PRL version
-    RIL_NV_CDMA_BC10 = 52,                  // CDMA band class 10
-    RIL_NV_CDMA_BC14 = 53,                  // CDMA band class 14
-    RIL_NV_CDMA_SO68 = 54,                  // CDMA SO68
-    RIL_NV_CDMA_SO73_COP0 = 55,             // CDMA SO73 COP0
-    RIL_NV_CDMA_SO73_COP1TO7 = 56,          // CDMA SO73 COP1-7
-    RIL_NV_CDMA_1X_ADVANCED_ENABLED = 57,   // CDMA 1X Advanced enabled
-    RIL_NV_CDMA_EHRPD_ENABLED = 58,         // CDMA eHRPD enabled
-    RIL_NV_CDMA_EHRPD_FORCED = 59,          // CDMA eHRPD forced
-
-    // LTE network and band config (items 71-90)
-    RIL_NV_LTE_BAND_ENABLE_25 = 71,         // LTE band 25 enable
-    RIL_NV_LTE_BAND_ENABLE_26 = 72,         // LTE band 26 enable
-    RIL_NV_LTE_BAND_ENABLE_41 = 73,         // LTE band 41 enable
-
-    RIL_NV_LTE_SCAN_PRIORITY_25 = 74,       // LTE band 25 scan priority
-    RIL_NV_LTE_SCAN_PRIORITY_26 = 75,       // LTE band 26 scan priority
-    RIL_NV_LTE_SCAN_PRIORITY_41 = 76,       // LTE band 41 scan priority
-
-    RIL_NV_LTE_HIDDEN_BAND_PRIORITY_25 = 77,    // LTE hidden band 25 priority
-    RIL_NV_LTE_HIDDEN_BAND_PRIORITY_26 = 78,    // LTE hidden band 26 priority
-    RIL_NV_LTE_HIDDEN_BAND_PRIORITY_41 = 79,    // LTE hidden band 41 priority
-
-} RIL_NV_Item;
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif /* ANDROID_RIL_NV_ITEMS_H */
diff --git a/radio/rild/Android.bp b/radio/rild/Android.bp
deleted file mode 100644
index 7a90c015..00000000
--- a/radio/rild/Android.bp
+++ /dev/null
@@ -1,43 +0,0 @@
-// Copyright (C) 2006 The Android Open Source Project
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
-package {
-    // See: http://go/android-license-faq
-    default_applicable_licenses: [
-        "Android-Apache-2.0",
-    ],
-}
-
-cc_binary {
-    name: "libgoldfish-rild",
-    cflags: [
-        "-DPRODUCT_COMPATIBLE_PROPERTY",
-        "-DRIL_SHLIB",
-        "-Wall",
-        "-Wextra",
-        "-Werror",
-    ],
-    srcs: ["rild_goldfish.c"],
-    shared_libs: [
-        "libcutils",
-        "libdl",
-        "liblog",
-        "libril-modem-lib",
-    ],
-    header_libs: ["goldfish_ril_headers"],
-    relative_install_path: "hw",
-    proprietary: true,
-    overrides: ["rild"],
-    init_rc: ["rild_goldfish.rc"],
-}
diff --git a/radio/rild/MODULE_LICENSE_APACHE2 b/radio/rild/MODULE_LICENSE_APACHE2
deleted file mode 100644
index e69de29b..00000000
diff --git a/radio/rild/NOTICE b/radio/rild/NOTICE
deleted file mode 100644
index c5b1efa7..00000000
--- a/radio/rild/NOTICE
+++ /dev/null
@@ -1,190 +0,0 @@
-
-   Copyright (c) 2005-2008, The Android Open Source Project
-
-   Licensed under the Apache License, Version 2.0 (the "License");
-   you may not use this file except in compliance with the License.
-
-   Unless required by applicable law or agreed to in writing, software
-   distributed under the License is distributed on an "AS IS" BASIS,
-   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-   See the License for the specific language governing permissions and
-   limitations under the License.
-
-
-                                 Apache License
-                           Version 2.0, January 2004
-                        http://www.apache.org/licenses/
-
-   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
-
-   1. Definitions.
-
-      "License" shall mean the terms and conditions for use, reproduction,
-      and distribution as defined by Sections 1 through 9 of this document.
-
-      "Licensor" shall mean the copyright owner or entity authorized by
-      the copyright owner that is granting the License.
-
-      "Legal Entity" shall mean the union of the acting entity and all
-      other entities that control, are controlled by, or are under common
-      control with that entity. For the purposes of this definition,
-      "control" means (i) the power, direct or indirect, to cause the
-      direction or management of such entity, whether by contract or
-      otherwise, or (ii) ownership of fifty percent (50%) or more of the
-      outstanding shares, or (iii) beneficial ownership of such entity.
-
-      "You" (or "Your") shall mean an individual or Legal Entity
-      exercising permissions granted by this License.
-
-      "Source" form shall mean the preferred form for making modifications,
-      including but not limited to software source code, documentation
-      source, and configuration files.
-
-      "Object" form shall mean any form resulting from mechanical
-      transformation or translation of a Source form, including but
-      not limited to compiled object code, generated documentation,
-      and conversions to other media types.
-
-      "Work" shall mean the work of authorship, whether in Source or
-      Object form, made available under the License, as indicated by a
-      copyright notice that is included in or attached to the work
-      (an example is provided in the Appendix below).
-
-      "Derivative Works" shall mean any work, whether in Source or Object
-      form, that is based on (or derived from) the Work and for which the
-      editorial revisions, annotations, elaborations, or other modifications
-      represent, as a whole, an original work of authorship. For the purposes
-      of this License, Derivative Works shall not include works that remain
-      separable from, or merely link (or bind by name) to the interfaces of,
-      the Work and Derivative Works thereof.
-
-      "Contribution" shall mean any work of authorship, including
-      the original version of the Work and any modifications or additions
-      to that Work or Derivative Works thereof, that is intentionally
-      submitted to Licensor for inclusion in the Work by the copyright owner
-      or by an individual or Legal Entity authorized to submit on behalf of
-      the copyright owner. For the purposes of this definition, "submitted"
-      means any form of electronic, verbal, or written communication sent
-      to the Licensor or its representatives, including but not limited to
-      communication on electronic mailing lists, source code control systems,
-      and issue tracking systems that are managed by, or on behalf of, the
-      Licensor for the purpose of discussing and improving the Work, but
-      excluding communication that is conspicuously marked or otherwise
-      designated in writing by the copyright owner as "Not a Contribution."
-
-      "Contributor" shall mean Licensor and any individual or Legal Entity
-      on behalf of whom a Contribution has been received by Licensor and
-      subsequently incorporated within the Work.
-
-   2. Grant of Copyright License. Subject to the terms and conditions of
-      this License, each Contributor hereby grants to You a perpetual,
-      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
-      copyright license to reproduce, prepare Derivative Works of,
-      publicly display, publicly perform, sublicense, and distribute the
-      Work and such Derivative Works in Source or Object form.
-
-   3. Grant of Patent License. Subject to the terms and conditions of
-      this License, each Contributor hereby grants to You a perpetual,
-      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
-      (except as stated in this section) patent license to make, have made,
-      use, offer to sell, sell, import, and otherwise transfer the Work,
-      where such license applies only to those patent claims licensable
-      by such Contributor that are necessarily infringed by their
-      Contribution(s) alone or by combination of their Contribution(s)
-      with the Work to which such Contribution(s) was submitted. If You
-      institute patent litigation against any entity (including a
-      cross-claim or counterclaim in a lawsuit) alleging that the Work
-      or a Contribution incorporated within the Work constitutes direct
-      or contributory patent infringement, then any patent licenses
-      granted to You under this License for that Work shall terminate
-      as of the date such litigation is filed.
-
-   4. Redistribution. You may reproduce and distribute copies of the
-      Work or Derivative Works thereof in any medium, with or without
-      modifications, and in Source or Object form, provided that You
-      meet the following conditions:
-
-      (a) You must give any other recipients of the Work or
-          Derivative Works a copy of this License; and
-
-      (b) You must cause any modified files to carry prominent notices
-          stating that You changed the files; and
-
-      (c) You must retain, in the Source form of any Derivative Works
-          that You distribute, all copyright, patent, trademark, and
-          attribution notices from the Source form of the Work,
-          excluding those notices that do not pertain to any part of
-          the Derivative Works; and
-
-      (d) If the Work includes a "NOTICE" text file as part of its
-          distribution, then any Derivative Works that You distribute must
-          include a readable copy of the attribution notices contained
-          within such NOTICE file, excluding those notices that do not
-          pertain to any part of the Derivative Works, in at least one
-          of the following places: within a NOTICE text file distributed
-          as part of the Derivative Works; within the Source form or
-          documentation, if provided along with the Derivative Works; or,
-          within a display generated by the Derivative Works, if and
-          wherever such third-party notices normally appear. The contents
-          of the NOTICE file are for informational purposes only and
-          do not modify the License. You may add Your own attribution
-          notices within Derivative Works that You distribute, alongside
-          or as an addendum to the NOTICE text from the Work, provided
-          that such additional attribution notices cannot be construed
-          as modifying the License.
-
-      You may add Your own copyright statement to Your modifications and
-      may provide additional or different license terms and conditions
-      for use, reproduction, or distribution of Your modifications, or
-      for any such Derivative Works as a whole, provided Your use,
-      reproduction, and distribution of the Work otherwise complies with
-      the conditions stated in this License.
-
-   5. Submission of Contributions. Unless You explicitly state otherwise,
-      any Contribution intentionally submitted for inclusion in the Work
-      by You to the Licensor shall be under the terms and conditions of
-      this License, without any additional terms or conditions.
-      Notwithstanding the above, nothing herein shall supersede or modify
-      the terms of any separate license agreement you may have executed
-      with Licensor regarding such Contributions.
-
-   6. Trademarks. This License does not grant permission to use the trade
-      names, trademarks, service marks, or product names of the Licensor,
-      except as required for reasonable and customary use in describing the
-      origin of the Work and reproducing the content of the NOTICE file.
-
-   7. Disclaimer of Warranty. Unless required by applicable law or
-      agreed to in writing, Licensor provides the Work (and each
-      Contributor provides its Contributions) on an "AS IS" BASIS,
-      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
-      implied, including, without limitation, any warranties or conditions
-      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
-      PARTICULAR PURPOSE. You are solely responsible for determining the
-      appropriateness of using or redistributing the Work and assume any
-      risks associated with Your exercise of permissions under this License.
-
-   8. Limitation of Liability. In no event and under no legal theory,
-      whether in tort (including negligence), contract, or otherwise,
-      unless required by applicable law (such as deliberate and grossly
-      negligent acts) or agreed to in writing, shall any Contributor be
-      liable to You for damages, including any direct, indirect, special,
-      incidental, or consequential damages of any character arising as a
-      result of this License or out of the use or inability to use the
-      Work (including but not limited to damages for loss of goodwill,
-      work stoppage, computer failure or malfunction, or any and all
-      other commercial damages or losses), even if such Contributor
-      has been advised of the possibility of such damages.
-
-   9. Accepting Warranty or Additional Liability. While redistributing
-      the Work or Derivative Works thereof, You may choose to offer,
-      and charge a fee for, acceptance of support, warranty, indemnity,
-      or other liability obligations and/or rights consistent with this
-      License. However, in accepting such obligations, You may act only
-      on Your own behalf and on Your sole responsibility, not on behalf
-      of any other Contributor, and only if You agree to indemnify,
-      defend, and hold each Contributor harmless for any liability
-      incurred by, or claims asserted against, such Contributor by reason
-      of your accepting any such warranty or additional liability.
-
-   END OF TERMS AND CONDITIONS
-
diff --git a/radio/rild/rild_goldfish.c b/radio/rild/rild_goldfish.c
deleted file mode 100644
index 574457ca..00000000
--- a/radio/rild/rild_goldfish.c
+++ /dev/null
@@ -1,243 +0,0 @@
-/* //device/system/rild/rild.c
-**
-** Copyright 2006 The Android Open Source Project
-**
-** Licensed under the Apache License, Version 2.0 (the "License");
-** you may not use this file except in compliance with the License.
-** You may obtain a copy of the License at
-**
-**     http://www.apache.org/licenses/LICENSE-2.0
-**
-** Unless required by applicable law or agreed to in writing, software
-** distributed under the License is distributed on an "AS IS" BASIS,
-** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-** See the License for the specific language governing permissions and
-** limitations under the License.
-*/
-
-#include <stdio.h>
-#include <stdlib.h>
-#include <dlfcn.h>
-#include <string.h>
-#include <stdint.h>
-#include <unistd.h>
-#include <fcntl.h>
-#include <errno.h>
-
-#include <telephony/ril.h>
-#define LOG_TAG "RILD"
-#include <log/log.h>
-#include <cutils/properties.h>
-#include <cutils/sockets.h>
-#include <sys/capability.h>
-#include <sys/prctl.h>
-#include <sys/stat.h>
-#include <sys/types.h>
-
-#if defined(PRODUCT_COMPATIBLE_PROPERTY)
-#define LIB_PATH_PROPERTY   "vendor.rild.libpath"
-#define LIB_ARGS_PROPERTY   "vendor.rild.libargs"
-#else
-#define LIB_PATH_PROPERTY   "rild.libpath"
-#define LIB_ARGS_PROPERTY   "rild.libargs"
-#endif
-#define MAX_LIB_ARGS        16
-
-static void usage(const char *argv0) {
-    fprintf(stderr, "Usage: %s -l <ril impl library> [-- <args for impl library>]\n", argv0);
-    exit(EXIT_FAILURE);
-}
-
-typedef enum {
-    RIL_TELEPHONY_SOCKET,
-    RIL_SAP_SOCKET
-} RIL_SOCKET_TYPE;
-
-extern char ril_service_name_base[MAX_SERVICE_NAME_LENGTH];
-extern char ril_service_name[MAX_SERVICE_NAME_LENGTH];
-
-extern void RIL_register (const RIL_RadioFunctions *callbacks);
-extern void rilc_thread_pool ();
-
-extern void RIL_register_socket (const RIL_RadioFunctions *(*rilUimInit)
-        (const struct RIL_Env *, int, char **), RIL_SOCKET_TYPE socketType, int argc, char **argv);
-
-extern void RIL_onRequestComplete(RIL_Token t, RIL_Errno e,
-        void *response, size_t responselen);
-
-extern void RIL_onRequestAck(RIL_Token t);
-
-#if defined(ANDROID_MULTI_SIM)
-extern void RIL_onUnsolicitedResponse(int unsolResponse, const void *data,
-        size_t datalen, RIL_SOCKET_ID socket_id);
-#else
-extern void RIL_onUnsolicitedResponse(int unsolResponse, const void *data,
-        size_t datalen);
-#endif
-
-extern void RIL_requestTimedCallback (RIL_TimedCallback callback,
-        void *param, const struct timeval *relativeTime);
-
-
-static struct RIL_Env s_rilEnv = {
-    RIL_onRequestComplete,
-    RIL_onUnsolicitedResponse,
-    RIL_requestTimedCallback,
-    RIL_onRequestAck
-};
-
-extern void RIL_startEventLoop();
-
-static int make_argv(char * args, char ** argv) {
-    // Note: reserve argv[0]
-    int count = 1;
-    char * tok;
-    char * s = args;
-
-    while ((tok = strtok(s, " \0"))) {
-        argv[count] = tok;
-        s = NULL;
-        count++;
-    }
-    return count;
-}
-
-int main(int argc, char **argv) {
-    // vendor ril lib path either passed in as -l parameter, or read from rild.libpath property
-    const char *rilLibPath = NULL;
-    // ril arguments either passed in as -- parameter, or read from rild.libargs property
-    char **rilArgv;
-    // handle for vendor ril lib
-    void *dlHandle;
-    // Pointer to ril init function in vendor ril
-    const RIL_RadioFunctions *(*rilInit)(const struct RIL_Env *, int, char **);
-    // Pointer to sap init function in vendor ril
-    const RIL_RadioFunctions *(*rilUimInit)(const struct RIL_Env *, int, char **);
-    const char *err_str = NULL;
-
-    // functions returned by ril init function in vendor ril
-    const RIL_RadioFunctions *funcs;
-    // lib path from rild.libpath property (if it's read)
-    char libPath[PROPERTY_VALUE_MAX];
-    // flat to indicate if -- parameters are present
-    unsigned char hasLibArgs = 0;
-
-    int i;
-    // ril/socket id received as -c parameter, otherwise set to 0
-    const char *clientId = NULL;
-
-    RLOGD("**RIL Daemon Started**");
-    RLOGD("**RILd param count=%d**", argc);
-
-    umask(S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);
-    for (i = 1; i < argc ;) {
-        if (0 == strcmp(argv[i], "-l") && (argc - i > 1)) {
-            rilLibPath = argv[i + 1];
-            i += 2;
-        } else if (0 == strcmp(argv[i], "--")) {
-            i++;
-            hasLibArgs = 1;
-            break;
-        } else if (0 == strcmp(argv[i], "-c") &&  (argc - i > 1)) {
-            clientId = argv[i+1];
-            i += 2;
-        } else {
-            usage(argv[0]);
-        }
-    }
-
-    if (clientId == NULL) {
-        clientId = "0";
-    } else if (atoi(clientId) >= MAX_RILDS) {
-        RLOGE("Max Number of rild's supported is: %d", MAX_RILDS);
-        exit(0);
-    }
-    if (strncmp(clientId, "0", MAX_CLIENT_ID_LENGTH)) {
-        snprintf(ril_service_name, sizeof(ril_service_name), "%s%s", ril_service_name_base,
-                 clientId);
-    }
-
-    if (rilLibPath == NULL) {
-        if ( 0 == property_get(LIB_PATH_PROPERTY, libPath, NULL)) {
-            // No lib sepcified on the command line, and nothing set in props.
-            // Assume "no-ril" case.
-            goto done;
-        } else {
-            rilLibPath = libPath;
-        }
-    }
-
-    // force to use libcuttlefish-ril-2.so
-    rilLibPath = "libcuttlefish-ril-2.so";
-
-    dlHandle = dlopen(rilLibPath, RTLD_NOW);
-
-    if (dlHandle == NULL) {
-        RLOGE("dlopen failed: %s", dlerror());
-        exit(EXIT_FAILURE);
-    }
-
-    RLOGI("dlopen good: %s", rilLibPath);
-
-    RIL_startEventLoop();
-
-    rilInit =
-        (const RIL_RadioFunctions *(*)(const struct RIL_Env *, int, char **))
-        dlsym(dlHandle, "RIL_Init");
-
-    if (rilInit == NULL) {
-        RLOGE("RIL_Init not defined or exported in %s\n", rilLibPath);
-        exit(EXIT_FAILURE);
-    }
-
-    dlerror(); // Clear any previous dlerror
-    rilUimInit =
-        (const RIL_RadioFunctions *(*)(const struct RIL_Env *, int, char **))
-        dlsym(dlHandle, "RIL_SAP_Init");
-    err_str = dlerror();
-    if (err_str) {
-        RLOGW("RIL_SAP_Init not defined or exported in %s: %s\n", rilLibPath, err_str);
-    } else if (!rilUimInit) {
-        RLOGW("RIL_SAP_Init defined as null in %s. SAP Not usable\n", rilLibPath);
-    }
-
-    if (hasLibArgs) {
-        rilArgv = argv + i - 1;
-        argc = argc -i + 1;
-    } else {
-        static char * newArgv[MAX_LIB_ARGS];
-        static char args[PROPERTY_VALUE_MAX];
-        rilArgv = newArgv;
-        property_get(LIB_ARGS_PROPERTY, args, "");
-        argc = make_argv(args, rilArgv);
-    }
-
-    rilArgv[argc++] = "-c";
-    rilArgv[argc++] = (char*)clientId;
-    RLOGD("RIL_Init argc = %d clientId = %s", argc, rilArgv[argc-1]);
-
-    // Make sure there's a reasonable argv[0]
-    rilArgv[0] = argv[0];
-
-    funcs = rilInit(&s_rilEnv, argc, rilArgv);
-    RLOGD("RIL_Init rilInit completed");
-
-    RIL_register(funcs);
-
-    RLOGD("RIL_Init RIL_register completed");
-
-    if (rilUimInit) {
-        RLOGD("RIL_register_socket started");
-        RIL_register_socket(rilUimInit, RIL_SAP_SOCKET, argc, rilArgv);
-    }
-
-    RLOGD("RIL_register_socket completed");
-
-    rilc_thread_pool();
-
-done:
-    RLOGD("RIL_Init starting sleep loop");
-    while (true) {
-        sleep(UINT32_MAX);
-    }
-}
diff --git a/radio/rild/rild_goldfish.rc b/radio/rild/rild_goldfish.rc
deleted file mode 100644
index c88e7f84..00000000
--- a/radio/rild/rild_goldfish.rc
+++ /dev/null
@@ -1,6 +0,0 @@
-service vendor.ril-daemon /vendor/bin/hw/libgoldfish-rild
-    class main
-    user radio
-    group radio cache inet misc audio log readproc wakelock
-    capabilities BLOCK_SUSPEND NET_ADMIN NET_RAW
-    disabled
diff --git a/rro_overlays/UwbOverlay/res/values/config.xml b/rro_overlays/UwbOverlay/res/values/config.xml
index 1063d8a5..93401b41 100644
--- a/rro_overlays/UwbOverlay/res/values/config.xml
+++ b/rro_overlays/UwbOverlay/res/values/config.xml
@@ -15,8 +15,4 @@
 -->
 <resources>
   <bool name="is_multicast_list_update_ntf_v2_supported">true</bool>
-
-  <!-- Whether multicast list update response v2 is supported or not.
-  If enabled, the response will be parsed into version 2 if uci major version is 2.0. -->
-  <bool name = "is_multicast_list_update_rsp_v2_supported">true</bool>
 </resources>
\ No newline at end of file
diff --git a/sepolicy/vendor/adbd.te b/sepolicy/vendor/adbd.te
index eb07b454..c762eb64 100644
--- a/sepolicy/vendor/adbd.te
+++ b/sepolicy/vendor/adbd.te
@@ -1,3 +1,6 @@
 set_prop(adbd, ctl_mdnsd_prop);
 
+starting_at_board_api(202504, `
+typeattribute adbd unconstrained_vsock_violators;
+')
 allow adbd self:vsock_socket { create_socket_perms_no_ioctl listen accept };
diff --git a/sepolicy/vendor/bootanim.te b/sepolicy/vendor/bootanim.te
index 3a5a7802..f6b8b0d7 100644
--- a/sepolicy/vendor/bootanim.te
+++ b/sepolicy/vendor/bootanim.te
@@ -5,5 +5,9 @@ dontaudit bootanim system_data_file:dir read;
 
 allow bootanim graphics_device:chr_file { read ioctl open };
 allow bootanim gpu_device:chr_file { read ioctl open };
+
+starting_at_board_api(202504, `
+typeattribute bootanim unconstrained_vsock_violators;
+')
 allow bootanim self:vsock_socket create_socket_perms_no_ioctl;
 allow bootanim hal_graphics_allocator_default:vsock_socket { read write getattr };
diff --git a/sepolicy/vendor/dhcpclient.te b/sepolicy/vendor/dhcpclient.te
deleted file mode 100644
index b28bb51c..00000000
--- a/sepolicy/vendor/dhcpclient.te
+++ /dev/null
@@ -1,18 +0,0 @@
-# DHCP client
-type dhcpclient, domain;
-type dhcpclient_exec, exec_type, vendor_file_type, file_type;
-
-init_daemon_domain(dhcpclient)
-net_domain(dhcpclient)
-
-set_prop(dhcpclient, vendor_net_wlan0_prop);
-set_prop(dhcpclient, vendor_net_eth0_prop);
-allow dhcpclient self:capability { net_admin net_raw sys_module };
-allow dhcpclient self:netlink_route_socket { ioctl write nlmsg_write };
-allow dhcpclient varrun_file:dir search;
-allow dhcpclient self:packet_socket { create bind write read };
-allowxperm dhcpclient self:netlink_route_socket ioctl { SIOCGIFFLAGS
-                                                        SIOCSIFFLAGS
-                                                        SIOCSIFMTU
-                                                        SIOCGIFINDEX
-                                                        SIOCGIFHWADDR };
diff --git a/sepolicy/vendor/file_contexts b/sepolicy/vendor/file_contexts
index 6c250670..a2bc01c9 100644
--- a/sepolicy/vendor/file_contexts
+++ b/sepolicy/vendor/file_contexts
@@ -39,8 +39,7 @@
 /vendor/bin/dlkm_loader  u:object_r:dlkm_loader_exec:s0
 /vendor/bin/qemu-props       u:object_r:qemu_props_exec:s0
 /vendor/bin/mac80211_create_radios u:object_r:mac80211_create_radios_exec:s0
-/vendor/bin/hw/libgoldfish-rild               u:object_r:rild_exec:s0
-/vendor/bin/dhcpclient       u:object_r:dhcpclient_exec:s0
+/vendor/bin/hw/android\.hardware\.radio-service\.ranchu       u:object_r:hal_radio_default_exec:s0
 /vendor/bin/bt_vhci_forwarder  u:object_r:bt_vhci_forwarder_exec:s0
 /vendor/bin/hw/android\.hardware\.graphics\.allocator-service\.ranchu u:object_r:hal_graphics_allocator_default_exec:s0
 /vendor/bin/hw/android\.hardware\.drm-service\.widevine    u:object_r:hal_drm_widevine_exec:s0
diff --git a/sepolicy/vendor/gmscore_app.te b/sepolicy/vendor/gmscore_app.te
index 1d630392..c77cb380 100644
--- a/sepolicy/vendor/gmscore_app.te
+++ b/sepolicy/vendor/gmscore_app.te
@@ -1,3 +1,7 @@
 # b/149481633: dontaudit directory traversal
 dontaudit gmscore_app varrun_file:dir search;
+
+starting_at_board_api(202504, `
+typeattribute gmscore_app unconstrained_vsock_violators;
+')
 allow gmscore_app self:vsock_socket create_socket_perms_no_ioctl;
diff --git a/sepolicy/vendor/hal_audio_default.te b/sepolicy/vendor/hal_audio_default.te
index 4e764b00..b8964b58 100644
--- a/sepolicy/vendor/hal_audio_default.te
+++ b/sepolicy/vendor/hal_audio_default.te
@@ -1 +1,4 @@
+starting_at_board_api(202504, `
+typeattribute hal_audio_default unconstrained_vsock_violators;
+')
 allow hal_audio_default self:vsock_socket create_socket_perms_no_ioctl;
diff --git a/sepolicy/vendor/hal_camera_default.te b/sepolicy/vendor/hal_camera_default.te
index d433214f..db957fb1 100644
--- a/sepolicy/vendor/hal_camera_default.te
+++ b/sepolicy/vendor/hal_camera_default.te
@@ -6,6 +6,10 @@ hal_client_domain(hal_camera_default, hal_graphics_composer);
 # For camera hal to talk with sensor service
 binder_call(hal_camera_default, sensor_service_server)
 binder_call(sensor_service_server, hal_camera_default)
+
+starting_at_board_api(202504, `
+typeattribute hal_camera_default unconstrained_vsock_violators;
+')
 allow hal_camera_default self:vsock_socket create_socket_perms_no_ioctl;
 
 # camera hal with minigbm
diff --git a/sepolicy/vendor/hal_fingerprint_default.te b/sepolicy/vendor/hal_fingerprint_default.te
index 93ee40bd..6d2847c7 100644
--- a/sepolicy/vendor/hal_fingerprint_default.te
+++ b/sepolicy/vendor/hal_fingerprint_default.te
@@ -1 +1,4 @@
+starting_at_board_api(202504, `
+typeattribute hal_fingerprint_default unconstrained_vsock_violators;
+')
 allow hal_fingerprint_default self:vsock_socket create_socket_perms_no_ioctl;
diff --git a/sepolicy/vendor/hal_gnss_default.te b/sepolicy/vendor/hal_gnss_default.te
index 8a76867a..75a10681 100644
--- a/sepolicy/vendor/hal_gnss_default.te
+++ b/sepolicy/vendor/hal_gnss_default.te
@@ -1,3 +1,7 @@
 #============= hal_gnss_default ==============
 vndbinder_use(hal_gnss_default);
+
+starting_at_board_api(202504, `
+typeattribute hal_gnss_default unconstrained_vsock_violators;
+')
 allow hal_gnss_default self:vsock_socket create_socket_perms_no_ioctl;
diff --git a/sepolicy/vendor/hal_graphics_allocator_default.te b/sepolicy/vendor/hal_graphics_allocator_default.te
index 4664eaa2..4d007da7 100644
--- a/sepolicy/vendor/hal_graphics_allocator_default.te
+++ b/sepolicy/vendor/hal_graphics_allocator_default.te
@@ -4,4 +4,8 @@ allow hal_graphics_allocator_default gpu_device:dir search;
 allow hal_graphics_allocator_default gpu_device:chr_file { ioctl open read write map rw_file_perms };
 allow hal_graphics_allocator_default dumpstate:fd use;
 allow hal_graphics_allocator_default dumpstate:fifo_file write;
+
+starting_at_board_api(202504, `
+typeattribute hal_graphics_allocator_default unconstrained_vsock_violators;
+')
 allow hal_graphics_allocator_default self:vsock_socket create_socket_perms_no_ioctl;
diff --git a/sepolicy/vendor/hal_graphics_composer_default.te b/sepolicy/vendor/hal_graphics_composer_default.te
index 16145fba..499f049c 100644
--- a/sepolicy/vendor/hal_graphics_composer_default.te
+++ b/sepolicy/vendor/hal_graphics_composer_default.te
@@ -4,6 +4,11 @@ hal_client_domain(hal_graphics_composer_default, hal_graphics_allocator);
 allow hal_graphics_composer_default vndbinder_device:chr_file { ioctl open read write map };
 allow hal_graphics_composer_default graphics_device:chr_file { ioctl open read write map };
 allow hal_graphics_composer_default gpu_device:chr_file { ioctl open read write map };
+
+starting_at_board_api(202504, `
+typeattribute hal_graphics_composer_default unconstrained_vsock_violators;
+')
 allow hal_graphics_composer_default self:vsock_socket create_socket_perms_no_ioctl;
+
 allow hal_graphics_composer_default hal_graphics_allocator_default:vsock_socket { read write getattr };
 allow hal_graphics_composer_default self:netlink_kobject_uevent_socket { create bind read };
diff --git a/sepolicy/vendor/hal_radio_default.te b/sepolicy/vendor/hal_radio_default.te
new file mode 100644
index 00000000..f7948a45
--- /dev/null
+++ b/sepolicy/vendor/hal_radio_default.te
@@ -0,0 +1,14 @@
+get_prop(rild, vendor_net_eth0_prop);
+get_prop(rild, vendor_net_radio0_prop);
+
+allow hal_radio_default self:{ udp_socket } { create_socket_perms getattr };
+
+allowxperm rild self:udp_socket ioctl { SIOCGIFINDEX
+                                        SIOCGIFFLAGS SIOCSIFFLAGS
+                                        SIOCSIFADDR SIOCSIFNETMASK
+                                        SIOCGIFHWADDR };
+
+starting_at_board_api(202504, `
+typeattribute hal_radio_default unconstrained_vsock_violators;
+')
+allow hal_radio_default self:vsock_socket { create_socket_perms_no_ioctl getattr };
diff --git a/sepolicy/vendor/hal_sensors_default.te b/sepolicy/vendor/hal_sensors_default.te
index 44002a8f..96b4cb7d 100644
--- a/sepolicy/vendor/hal_sensors_default.te
+++ b/sepolicy/vendor/hal_sensors_default.te
@@ -1,2 +1,5 @@
+starting_at_board_api(202504, `
+typeattribute hal_sensors_default unconstrained_vsock_violators;
+')
 allow hal_sensors_default self:vsock_socket create_socket_perms_no_ioctl;
 allow hal_sensors_default system_server:binder call;
diff --git a/sepolicy/vendor/platform_app.te b/sepolicy/vendor/platform_app.te
index 1d9ad7e6..4f68c7b4 100644
--- a/sepolicy/vendor/platform_app.te
+++ b/sepolicy/vendor/platform_app.te
@@ -1,3 +1,6 @@
+starting_at_board_api(202504, `
+typeattribute platform_app unconstrained_vsock_violators;
+')
 allow platform_app self:vsock_socket create_socket_perms_no_ioctl;
 allow platform_app hal_graphics_allocator_default:vsock_socket { read write getattr };
 set_prop(platform_app, radio_control_prop);
diff --git a/sepolicy/vendor/priv_app.te b/sepolicy/vendor/priv_app.te
index 98063129..6bb18c4d 100644
--- a/sepolicy/vendor/priv_app.te
+++ b/sepolicy/vendor/priv_app.te
@@ -3,5 +3,8 @@ dontaudit priv_app firstboot_prop:file { getattr open };
 dontaudit priv_app device:dir { open read };
 dontaudit priv_app proc_interrupts:file { getattr open read };
 dontaudit priv_app proc_modules:file { getattr open read };
+starting_at_board_api(202504, `
+typeattribute priv_app unconstrained_vsock_violators;
+')
 allow priv_app self:vsock_socket create_socket_perms_no_ioctl;
 allow priv_app hal_graphics_allocator_default:vsock_socket { read write getattr };
diff --git a/sepolicy/vendor/qemu_props.te b/sepolicy/vendor/qemu_props.te
index 03e9f6f9..5a61c625 100644
--- a/sepolicy/vendor/qemu_props.te
+++ b/sepolicy/vendor/qemu_props.te
@@ -8,6 +8,9 @@ set_prop(qemu_props, qemu_hw_prop)
 set_prop(qemu_props, qemu_sf_lcd_density_prop)
 set_prop(qemu_props, vendor_qemu_prop)
 set_prop(qemu_props, vendor_net_share_prop)
+starting_at_board_api(202504, `
+typeattribute qemu_props unconstrained_vsock_violators;
+')
 # TODO(b/79502552): Invalid property access from emulator vendor
 allow qemu_props self:vsock_socket create_socket_perms_no_ioctl;
 allow qemu_props sysfs:dir read;
diff --git a/sepolicy/vendor/rild.te b/sepolicy/vendor/rild.te
deleted file mode 100644
index 7ddb21ca..00000000
--- a/sepolicy/vendor/rild.te
+++ /dev/null
@@ -1,11 +0,0 @@
-# Allow rild to read these properties, they only have an SELinux label in the
-# emulator.
-get_prop(rild, vendor_net_eth0_prop);
-get_prop(rild, vendor_net_radio0_prop);
-
-# IPv6 router advertisement detection
-allow rild self:packet_socket { bind create ioctl read setopt };
-allowxperm rild self:packet_socket ioctl { SIOCGIFFLAGS
-                                           SIOCSIFFLAGS
-                                           SIOCGIFHWADDR };
-allow rild self:vsock_socket create_socket_perms_no_ioctl;
diff --git a/sepolicy/vendor/shell.te b/sepolicy/vendor/shell.te
index e3ac86c9..28d4a73b 100644
--- a/sepolicy/vendor/shell.te
+++ b/sepolicy/vendor/shell.te
@@ -1,6 +1,10 @@
 allow shell serial_device:chr_file rw_file_perms;
 allow shell aac_drc_prop:file { getattr map open };
 allow shell device_config_runtime_native_boot_prop:file { getattr map open read };
+
+starting_at_board_api(202504, `
+typeattribute shell unconstrained_vsock_violators;
+')
 allow shell adbd:{ socket vsock_socket } rw_socket_perms_no_ioctl;
 
 # Allow shell to read qemu.sf.lcd_density for CTS.
diff --git a/sepolicy/vendor/surfaceflinger.te b/sepolicy/vendor/surfaceflinger.te
index f583ef72..23ec16f5 100644
--- a/sepolicy/vendor/surfaceflinger.te
+++ b/sepolicy/vendor/surfaceflinger.te
@@ -1,5 +1,8 @@
 allow surfaceflinger self:process execmem;
 allow surfaceflinger ashmem_device:chr_file execute;
 allow surfaceflinger gpu_device:chr_file { ioctl open read write map };
+starting_at_board_api(202504, `
+typeattribute surfaceflinger unconstrained_vsock_violators;
+')
 allow surfaceflinger self:vsock_socket create_socket_perms_no_ioctl;
 allow surfaceflinger hal_graphics_allocator_default:vsock_socket { read write getattr };
diff --git a/sepolicy/vendor/system_app.te b/sepolicy/vendor/system_app.te
index 41e61a9a..ea336e26 100644
--- a/sepolicy/vendor/system_app.te
+++ b/sepolicy/vendor/system_app.te
@@ -1,2 +1,5 @@
+starting_at_board_api(202504, `
+typeattribute system_app unconstrained_vsock_violators;
+')
 allow system_app self:vsock_socket create_socket_perms_no_ioctl;
 allow system_app hal_graphics_allocator_default:vsock_socket { read write getattr };
diff --git a/sepolicy/vendor/system_server.te b/sepolicy/vendor/system_server.te
index 548f206f..a66674c4 100644
--- a/sepolicy/vendor/system_server.te
+++ b/sepolicy/vendor/system_server.te
@@ -1,2 +1,5 @@
+starting_at_board_api(202504, `
+typeattribute system_server unconstrained_vsock_violators;
+')
 allow system_server self:vsock_socket create_socket_perms_no_ioctl;
 allow system_server hal_graphics_allocator_default:vsock_socket { read write getattr };
diff --git a/slim/OWNERS b/slim/OWNERS
index b5678033..9c57a473 100644
--- a/slim/OWNERS
+++ b/slim/OWNERS
@@ -1,2 +1 @@
 yahan@google.com
-brettchabot@google.com
diff --git a/tnc/Android.bp b/tnc/Android.bp
deleted file mode 100644
index aead392d..00000000
--- a/tnc/Android.bp
+++ /dev/null
@@ -1,41 +0,0 @@
-//
-// Copyright (C) 2018 The Android Open Source Project
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
-//
-
-package {
-    // See: http://go/android-license-faq
-    // A large-scale-change added 'default_applicable_licenses' to import
-    // all of the 'license_kinds' from "device_generic_goldfish_license"
-    // to get the below license kinds:
-    //   SPDX-license-identifier-Apache-2.0
-    //   SPDX-license-identifier-BSD
-    default_applicable_licenses: ["device_generic_goldfish_license"],
-}
-
-cc_binary {
-    name: "tnc",
-    vendor: true,
-    cflags: [
-             "-Wall",
-             "-Werror",
-            ],
-    srcs: [
-           "main.cpp",
-          ],
-    shared_libs: [
-        "libcutils",
-        "liblog",
-    ],
-}
diff --git a/tnc/main.cpp b/tnc/main.cpp
deleted file mode 100644
index d6ffd116..00000000
--- a/tnc/main.cpp
+++ /dev/null
@@ -1,217 +0,0 @@
-
-#include <errno.h>
-#include <netdb.h>
-#include <net/if.h>
-#include <stdio.h>
-#include <stdlib.h>
-#include <string.h>
-#include <sys/ioctl.h>
-#include <sys/socket.h>
-#include <sys/types.h>
-#include <unistd.h>
-
-#include <initializer_list>
-
-static void usage(const char* program) {
-    fprintf(stderr, "Usage: %s [-s|-c|-b] <ip> <port>\n", program);
-}
-
-enum class Mode {
-    Bridge,
-    Client,
-    Server,
-};
-
-bool resolve(const char* name, const char* port, struct addrinfo** addrs) {
-    struct addrinfo hints;
-    memset(&hints, 0, sizeof(hints));
-    hints.ai_family = AF_UNSPEC;
-    hints.ai_socktype = SOCK_DGRAM;
-
-    int res = ::getaddrinfo(name, port, &hints, addrs);
-    if (res != 0) {
-        fprintf(stderr, "ERROR: Unable to resolve '%s' and port '%s': %s\n",
-                name, port, gai_strerror(res));
-        return false;
-    }
-    return true;
-}
-
-int runClient(struct addrinfo* addrs) {
-    int fd = -1;
-    for (struct addrinfo* addr = addrs; addr != nullptr; addr = addr->ai_next) {
-        fd = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
-        if (fd < 0) {
-            continue;
-        }
-        if (::connect(fd, addr->ai_addr, addr->ai_addrlen) == 0) {
-            break;
-        }
-        ::close(fd);
-    }
-    ::freeaddrinfo(addrs);
-    if (fd < 0) {
-        fprintf(stderr, "Unable to connect to server\n");
-        return 1;
-    }
-    if (::send(fd, "boop", 4, 0) != 4) {
-        ::close(fd);
-        fprintf(stderr, "Failed to send message to server\n");
-        return 1;
-    }
-    ::close(fd);
-    return 0;
-}
-
-int runServer(struct addrinfo* addrs) {
-    int fd = -1;
-    for (struct addrinfo* addr = addrs; addr != nullptr; addr = addr->ai_next) {
-        fd = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
-        if (fd < 0) {
-            continue;
-        }
-        if (::bind(fd, addr->ai_addr, addr->ai_addrlen) == 0) {
-            break;
-        }
-        ::close(fd);
-    }
-    ::freeaddrinfo(addrs);
-    if (fd < 0) {
-        fprintf(stderr, "Unable to bind to address\n");
-        return 1;
-    }
-    char buffer[1024];
-    for (;;) {
-        struct sockaddr_storage addr;
-        socklen_t addrSize = sizeof(addr);
-        ssize_t bytesRead = recvfrom(fd, buffer, sizeof(buffer), 0,
-                                     reinterpret_cast<struct sockaddr*>(&addr),
-                                     &addrSize);
-        if (bytesRead < 0) {
-            if (errno == EINTR) {
-                continue;
-            }
-            fprintf(stderr, "Error receiving on socket: %s\n", strerror(errno));
-            ::close(fd);
-            return 1;
-        } else if (bytesRead == 0) {
-            fprintf(stderr, "Socket unexpectedly closed\n");
-            ::close(fd);
-            return 1;
-        }
-        printf("Received message from client '%*s'\n",
-               static_cast<int>(bytesRead), buffer);
-    }
-}
-
-static const char kBridgeName[] = "br0";
-
-static int configureBridge() {
-    int fd = ::socket(AF_LOCAL, SOCK_STREAM, 0);
-    if (fd < 0) {
-        fprintf(stderr, "ERROR: Could not open bridge socket: %s\n",
-                strerror(errno));
-        return 1;
-    }
-
-    int res = ::ioctl(fd, SIOCBRADDBR, kBridgeName);
-    if (res < 0) {
-        fprintf(stderr, "ERROR: cannot create bridge: %s\n", strerror(errno));
-        ::close(fd);
-        return 1;
-    }
-
-    for (const auto& ifName : { "eth0", "wlan1", "radio0-peer" }) {
-        struct ifreq request;
-        memset(&request, 0, sizeof(request));
-        request.ifr_ifindex = if_nametoindex(ifName);
-        if (request.ifr_ifindex == 0) {
-            fprintf(stderr, "ERROR: Unable to get interface index for %s\n",
-                    ifName);
-            ::close(fd);
-            return 1;
-        }
-        strlcpy(request.ifr_name, kBridgeName, sizeof(request.ifr_name));
-        res = ::ioctl(fd, SIOCBRADDIF, &request);
-        if (res < 0) {
-            fprintf(stderr, "ERROR: cannot add if %s to bridge: %s\n",
-                    ifName, strerror(errno));
-            ::close(fd);
-            return 1;
-        }
-    }
-
-    struct ifreq request;
-    memset(&request, 0, sizeof(request));
-    request.ifr_ifindex = if_nametoindex(kBridgeName);
-    if (request.ifr_ifindex == 0) {
-        fprintf(stderr, "ERROR: Unable to get interface index for %s\n",
-                kBridgeName);
-        ::close(fd);
-        return 1;
-    }
-    strlcpy(request.ifr_name, kBridgeName, sizeof(request.ifr_name));
-    res = ::ioctl(fd, SIOCGIFFLAGS, &request);
-    if (res != 0) {
-        fprintf(stderr, "ERROR: Unable to get interface index for %s\n",
-                kBridgeName);
-        ::close(fd);
-        return 1;
-    }
-    if ((request.ifr_flags & IFF_UP) == 0) {
-        // Bridge is not up, it needs to be up to work
-        request.ifr_flags |= IFF_UP;
-        res = ::ioctl(fd, SIOCSIFFLAGS, &request);
-        if (res != 0) {
-            fprintf(stderr, "ERROR: Unable to set interface flags for %s\n",
-                    kBridgeName);
-            ::close(fd);
-            return 1;
-        }
-    }
-
-    ::close(fd);
-    return 0;
-}
-
-int main(int argc, char* argv[]) {
-    if (argc < 2) {
-        usage(argv[0]);
-        return 1;
-    }
-
-    Mode mode;
-    if (strcmp("-b", argv[1]) == 0) {
-        mode = Mode::Bridge;
-    } else if (strcmp("-c", argv[1]) == 0) {
-        mode = Mode::Client;
-    } else if (strcmp("-s", argv[1]) == 0) {
-        mode = Mode::Server;
-    } else {
-        fprintf(stderr, "ERROR: Invalid option '%s'\n", argv[1]);
-        usage(argv[0]);
-        return 1;
-    }
-
-    struct addrinfo* addrs = nullptr;
-    if (mode == Mode::Client || mode == Mode::Server) {
-        if (argc != 4) {
-            usage(argv[0]);
-            return 1;
-        }
-        if (!resolve(argv[2], argv[3], &addrs)) {
-            usage(argv[0]);
-            return 1;
-        }
-    }
-
-    switch (mode) {
-        case Mode::Bridge:
-            return configureBridge();
-        case Mode::Client:
-            return runClient(addrs);
-        case Mode::Server:
-            return runServer(addrs);
-    }
-}
-
diff --git a/tools/Android.bp b/tools/Android.bp
index 9b98ea6c..9198fa38 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -28,9 +28,4 @@ python_binary_host {
     name: "mk_combined_img",
     srcs: ["mk_combined_img.py"],
     main: "mk_combined_img.py",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
diff --git a/wifi/wifi_hal/interface.cpp b/wifi/wifi_hal/interface.cpp
index 45ef7fb2..e6f71eef 100644
--- a/wifi/wifi_hal/interface.cpp
+++ b/wifi/wifi_hal/interface.cpp
@@ -262,7 +262,7 @@ wifi_error Interface::getPacketFilterCapabilities(u32* version,
     if (version == nullptr || maxLength == nullptr) {
         return WIFI_ERROR_INVALID_ARGS;
     }
-    *version = 4;
+    *version = 6000;
     *maxLength = kApfRamSize;
     return WIFI_SUCCESS;
 }
```

