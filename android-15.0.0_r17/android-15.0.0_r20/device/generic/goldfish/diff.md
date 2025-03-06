```diff
diff --git a/64bitonly/product/sdk_phone16k_arm64.mk b/64bitonly/product/sdk_phone16k_arm64.mk
index 3d09bf4a..ee7a4933 100644
--- a/64bitonly/product/sdk_phone16k_arm64.mk
+++ b/64bitonly/product/sdk_phone16k_arm64.mk
@@ -22,7 +22,7 @@ PRODUCT_USE_DYNAMIC_PARTITIONS := true
 
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1536 \* 1048576 )
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1800 \* 1048576 )
 BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE) + 8388608 )  # +8M
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
diff --git a/64bitonly/product/sdk_phone16k_x86_64.mk b/64bitonly/product/sdk_phone16k_x86_64.mk
index b93a7375..7d061136 100644
--- a/64bitonly/product/sdk_phone16k_x86_64.mk
+++ b/64bitonly/product/sdk_phone16k_x86_64.mk
@@ -15,7 +15,7 @@
 #
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
 
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1536 \* 1048576 )
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1800 \* 1048576 )
 BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE) + 8388608 )  # +8M
 
 #
diff --git a/64bitonly/product/sdk_phone64_arm64.mk b/64bitonly/product/sdk_phone64_arm64.mk
index 47546d83..085a8779 100644
--- a/64bitonly/product/sdk_phone64_arm64.mk
+++ b/64bitonly/product/sdk_phone64_arm64.mk
@@ -22,7 +22,7 @@ PRODUCT_USE_DYNAMIC_PARTITIONS := true
 
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1536 \* 1048576 )
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1800 \* 1048576 )
 BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE) + 8388608 )  # +8M
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
diff --git a/64bitonly/product/sdk_phone64_arm64_minigbm.mk b/64bitonly/product/sdk_phone64_arm64_minigbm.mk
index 9f8f53bf..15e5213c 100644
--- a/64bitonly/product/sdk_phone64_arm64_minigbm.mk
+++ b/64bitonly/product/sdk_phone64_arm64_minigbm.mk
@@ -16,7 +16,6 @@
 
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/etc/advancedFeatures.ini.minigbm:advancedFeatures.ini \
-    device/generic/goldfish/data/etc/config.ini.nexus5:config.ini
 
 $(call inherit-product, device/generic/goldfish/64bitonly/product/sdk_phone64_arm64.mk)
 
diff --git a/64bitonly/product/sdk_phone64_x86_64.mk b/64bitonly/product/sdk_phone64_x86_64.mk
index af5b412e..6d831b19 100644
--- a/64bitonly/product/sdk_phone64_x86_64.mk
+++ b/64bitonly/product/sdk_phone64_x86_64.mk
@@ -15,7 +15,7 @@
 #
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
 
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1536 \* 1048576 )
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1800 \* 1048576 )
 BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE) + 8388608 )  # +8M
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
diff --git a/64bitonly/product/sdk_tablet_arm64.mk b/64bitonly/product/sdk_tablet_arm64.mk
index 9dbff3bc..a52942cd 100644
--- a/64bitonly/product/sdk_tablet_arm64.mk
+++ b/64bitonly/product/sdk_tablet_arm64.mk
@@ -16,19 +16,9 @@
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
 EMULATOR_DISABLE_RADIO := true
 
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1536 \* 1048576 )
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1800 \* 1048576 )
 BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE) + 8388608 )  # +8M
 
-PRODUCT_COPY_FILES += \
-    device/generic/goldfish/tablet/data/etc/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml \
-    device/generic/goldfish/data/etc/advancedFeatures.ini.tablet:advancedFeatures.ini \
-    device/generic/goldfish/data/etc/config.ini.nexus7tab:config.ini
-
-PRODUCT_COPY_FILES+= \
-        device/generic/goldfish/data/etc/tablet_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml
-
-PRODUCT_COPY_FILES += device/generic/goldfish/tablet/data/etc/tablet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/tablet.xml
-
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
diff --git a/64bitonly/product/sdk_tablet_x86_64.mk b/64bitonly/product/sdk_tablet_x86_64.mk
index fa4b078a..d8f9c7c0 100644
--- a/64bitonly/product/sdk_tablet_x86_64.mk
+++ b/64bitonly/product/sdk_tablet_x86_64.mk
@@ -16,19 +16,9 @@
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
 EMULATOR_DISABLE_RADIO := true
 
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1536 \* 1048576 )
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE ?= $(shell expr 1800 \* 1048576 )
 BOARD_SUPER_PARTITION_SIZE := $(shell expr $(BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE) + 8388608 )  # +8M
 
-PRODUCT_COPY_FILES += \
-    device/generic/goldfish/tablet/data/etc/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml \
-    device/generic/goldfish/data/etc/advancedFeatures.ini.tablet:advancedFeatures.ini \
-    device/generic/goldfish/data/etc/config.ini.nexus7tab:config.ini
-
-PRODUCT_COPY_FILES+= \
-        device/generic/goldfish/data/etc/tablet_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml
-
-PRODUCT_COPY_FILES += device/generic/goldfish/tablet/data/etc/tablet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/tablet.xml
-
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
diff --git a/Android.bp b/Android.bp
index 5bceee87..d7173257 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,23 +24,6 @@ package {
     default_applicable_licenses: ["device_generic_goldfish_license"],
 }
 
-// Added automatically by a large-scale-change that took the approach of
-// 'apply every license found to every target'. While this makes sure we respect
-// every license restriction, it may not be entirely correct.
-//
-// e.g. GPL in an MIT project might only apply to the contrib/ directory.
-//
-// Please consider splitting the single license below into multiple licenses,
-// taking care not to lose any license_kind information, and overriding the
-// default license using the 'licenses: [...]' property on targets as needed.
-//
-// For unused files, consider creating a 'fileGroup' with "//visibility:private"
-// to attach the license to, and including a comment whether the files may be
-// used in the current project.
-//
-// large-scale-change filtered out the below license kinds as false-positives:
-//   SPDX-license-identifier-GPL-2.0
-// See: http://go/android-license-faq
 license {
     name: "device_generic_goldfish_license",
     visibility: [":__subpackages__"],
@@ -50,3 +33,17 @@ license {
     ],
     // large-scale-change unable to identify any license_text files
 }
+
+genrule {
+    name: "gen-emulator-info",
+    srcs: ["emulator-info.txt"],
+    cmd: "grep -v '#' $(in) > $(out)",
+    out: ["output.txt"],
+    dist: {
+        targets: [
+            "dist_files",
+            "sdk",
+        ],
+        dest: "emulator-info.txt",
+    },
+}
diff --git a/Android.mk b/Android.mk
index f0168574..efe0a3cb 100644
--- a/Android.mk
+++ b/Android.mk
@@ -14,28 +14,6 @@
 # limitations under the License.
 #
 
-LOCAL_PATH := $(call my-dir)
 
-ifneq ($(filter $(LOCAL_PATH),$(PRODUCT_SOONG_NAMESPACES)),)
+include device/generic/goldfish/tasks/emu_img_zip.mk
 
-  ifeq ($(BUILD_QEMU_IMAGES),true)
-    QEMU_CUSTOMIZATIONS := true
-  endif
-
-  ifeq ($(QEMU_CUSTOMIZATIONS),true)
-    INSTALLED_EMULATOR_INFO_TXT_TARGET := $(PRODUCT_OUT)/emulator-info.txt
-    emulator_info_txt := $(wildcard ${LOCAL_PATH}/emulator-info.txt)
-
-$(INSTALLED_EMULATOR_INFO_TXT_TARGET): $(emulator_info_txt)
-	$(call pretty,"Generated: ($@)")
-	$(hide) grep -v '#' $< > $@
-
-    $(call dist-for-goals, dist_files, $(INSTALLED_EMULATOR_INFO_TXT_TARGET))
-    $(call dist-for-goals, sdk, $(INSTALLED_EMULATOR_INFO_TXT_TARGET))
-
-    subdir_makefiles=$(call first-makefiles-under,$(LOCAL_PATH))
-    $(foreach mk,$(subdir_makefiles),$(info including $(mk) ...)$(eval include $(mk)))
-
-    include device/generic/goldfish/tasks/emu_img_zip.mk
-  endif
-endif
diff --git a/board/BoardConfigCommon.mk b/board/BoardConfigCommon.mk
index b503f590..4851307e 100644
--- a/board/BoardConfigCommon.mk
+++ b/board/BoardConfigCommon.mk
@@ -91,8 +91,9 @@ BOARD_FLASH_BLOCK_SIZE := 512
 BOARD_WLAN_DEVICE           := emulator
 BOARD_HOSTAPD_DRIVER        := NL80211
 BOARD_WPA_SUPPLICANT_DRIVER := NL80211
-BOARD_HOSTAPD_PRIVATE_LIB   := lib_driver_cmd_simulated
-BOARD_WPA_SUPPLICANT_PRIVATE_LIB := lib_driver_cmd_simulated
+# Use full namespace path for both BOARD_WPA_SUPPLICANT_PRIVATE_LIB and BOARD_HOSTAPD_PRIVATE_LIB due to wlan module for goldfish.
+BOARD_HOSTAPD_PRIVATE_LIB   := //device/generic/goldfish/wifi/wpa_supplicant_8_lib:lib_driver_cmd_simulated
+BOARD_WPA_SUPPLICANT_PRIVATE_LIB := //device/generic/goldfish/wifi/wpa_supplicant_8_lib:lib_driver_cmd_simulated
 WPA_SUPPLICANT_VERSION      := VER_0_8_X
 WIFI_DRIVER_FW_PATH_PARAM   := "/dev/null"
 WIFI_DRIVER_FW_PATH_STA     := "/dev/null"
diff --git a/board/emu64a/details.mk b/board/emu64a/details.mk
index f85e713a..e371c587 100644
--- a/board/emu64a/details.mk
+++ b/board/emu64a/details.mk
@@ -23,6 +23,5 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu \
-    device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini \
 
 $(call inherit-product, device/generic/goldfish/board/16k.mk)
diff --git a/board/emu64a16k/details.mk b/board/emu64a16k/details.mk
index a690da9a..fc53261b 100644
--- a/board/emu64a16k/details.mk
+++ b/board/emu64a16k/details.mk
@@ -23,6 +23,5 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/arm:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu \
-    device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini \
 
 $(call inherit-product, device/generic/goldfish/board/16k.mk)
diff --git a/board/emu64x/details.mk b/board/emu64x/details.mk
index 07e5bf6b..75299f0a 100644
--- a/board/emu64x/details.mk
+++ b/board/emu64x/details.mk
@@ -19,13 +19,7 @@ include device/generic/goldfish/board/kernel/x86_64.mk
 PRODUCT_PROPERTY_OVERRIDES += \
        vendor.rild.libpath=/vendor/lib64/libgoldfish-ril.so
 
-ADVANCED_FEATURES_FILE := advancedFeatures.ini
-ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
-ADVANCED_FEATURES_FILE := advancedFeatures.ini.minigbm
-endif
-
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/data/etc/$(ADVANCED_FEATURES_FILE):advancedFeatures.ini \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu \
     device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu \
diff --git a/board/emu64x/kernel_fstab_32.mk b/board/emu64x/kernel_fstab_32.mk
index f7b68312..556f9aaf 100644
--- a/board/emu64x/kernel_fstab_32.mk
+++ b/board/emu64x/kernel_fstab_32.mk
@@ -22,8 +22,3 @@ PRODUCT_COPY_FILES += \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu-64 \
     device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu
-
-# advancedFeatures.ini should be removed from here in b/299636933
-PRODUCT_COPY_FILES += \
-    device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini \
-
diff --git a/board/emu64x16k/details.mk b/board/emu64x16k/details.mk
index ae8da0a6..7d450c00 100644
--- a/board/emu64x16k/details.mk
+++ b/board/emu64x16k/details.mk
@@ -19,13 +19,7 @@ include device/generic/goldfish/board/kernel/x86_64_16k.mk
 PRODUCT_PROPERTY_OVERRIDES += \
        vendor.rild.libpath=/vendor/lib64/libgoldfish-ril.so
 
-ADVANCED_FEATURES_FILE := advancedFeatures.ini
-ifneq ($(filter %_minigbm, $(TARGET_PRODUCT)),)
-ADVANCED_FEATURES_FILE := advancedFeatures.ini.minigbm
-endif
-
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/data/etc/$(ADVANCED_FEATURES_FILE):advancedFeatures.ini \
     $(EMULATOR_KERNEL_FILE):kernel-ranchu \
     device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
     device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu \
diff --git a/board/kernel/arm64.mk b/board/kernel/arm64.mk
index 6ab08763..640f3c0f 100644
--- a/board/kernel/arm64.mk
+++ b/board/kernel/arm64.mk
@@ -25,20 +25,23 @@ VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
 RAMDISK_KERNEL_MODULES := \
-    virtio_blk.ko \
-    virtio_console.ko \
     virtio_dma_buf.ko \
     virtio_mmio.ko \
+    virtio-rng.ko \
+
+RAMDISK_SYSTEM_KERNEL_MODULES += \
+    virtio_blk.ko \
+    virtio_console.ko \
     virtio_pci.ko \
     virtio_pci_legacy_dev.ko \
     virtio_pci_modern_dev.ko \
-    virtio-rng.ko \
     vmw_vsock_virtio_transport.ko \
 
 BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
-    $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
+    $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
+    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
@@ -47,6 +50,8 @@ BOARD_VENDOR_KERNEL_MODULES := \
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/generic/goldfish/board/kernel/kernel_modules.blocklist
 
+BOARD_DO_NOT_STRIP_VENDOR_RAMDISK_MODULES := true
+
 EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)-gz
 
 # BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
diff --git a/board/kernel/arm64_16k.mk b/board/kernel/arm64_16k.mk
index f1a3a066..34d9d446 100644
--- a/board/kernel/arm64_16k.mk
+++ b/board/kernel/arm64_16k.mk
@@ -27,20 +27,23 @@ VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
 RAMDISK_KERNEL_MODULES := \
-    virtio_blk.ko \
-    virtio_console.ko \
     virtio_dma_buf.ko \
     virtio_mmio.ko \
+    virtio-rng.ko \
+
+RAMDISK_SYSTEM_KERNEL_MODULES += \
+    virtio_blk.ko \
+    virtio_console.ko \
     virtio_pci.ko \
     virtio_pci_legacy_dev.ko \
     virtio_pci_modern_dev.ko \
-    virtio-rng.ko \
     vmw_vsock_virtio_transport.ko \
 
 BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
-    $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
+    $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
+    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
@@ -49,6 +52,8 @@ BOARD_VENDOR_KERNEL_MODULES := \
 BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
     device/generic/goldfish/board/kernel/kernel_modules.blocklist
 
+BOARD_DO_NOT_STRIP_VENDOR_RAMDISK_MODULES := true
+
 EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)-gz
 
 # BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
diff --git a/board/kernel/x86_64.mk b/board/kernel/x86_64.mk
index 645be598..1088216b 100644
--- a/board/kernel/x86_64.mk
+++ b/board/kernel/x86_64.mk
@@ -25,19 +25,22 @@ VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
 RAMDISK_KERNEL_MODULES := \
+    virtio_dma_buf.ko \
+    virtio-rng.ko \
+
+RAMDISK_SYSTEM_KERNEL_MODULES += \
     virtio_blk.ko \
     virtio_console.ko \
-    virtio_dma_buf.ko \
     virtio_pci.ko \
     virtio_pci_legacy_dev.ko \
     virtio_pci_modern_dev.ko \
-    virtio-rng.ko \
     vmw_vsock_virtio_transport.ko \
 
 BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
-    $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
+    $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
+    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
diff --git a/board/kernel/x86_64_16k.mk b/board/kernel/x86_64_16k.mk
index 18e71f8f..20ec3f14 100644
--- a/board/kernel/x86_64_16k.mk
+++ b/board/kernel/x86_64_16k.mk
@@ -27,19 +27,22 @@ VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
 # The list of modules to reach the second stage. For performance reasons we
 # don't want to put all modules into the ramdisk.
 RAMDISK_KERNEL_MODULES := \
+    virtio_dma_buf.ko \
+    virtio-rng.ko \
+
+RAMDISK_SYSTEM_KERNEL_MODULES += \
     virtio_blk.ko \
     virtio_console.ko \
-    virtio_dma_buf.ko \
     virtio_pci.ko \
     virtio_pci_legacy_dev.ko \
     virtio_pci_modern_dev.ko \
-    virtio-rng.ko \
     vmw_vsock_virtio_transport.ko \
 
 BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
 
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
-    $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
+    $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))) \
+    $(wildcard $(patsubst %,$(KERNEL_ARTIFACTS_PATH)/%,$(RAMDISK_SYSTEM_KERNEL_MODULES)))
 
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
diff --git a/data/etc/advancedFeatures.ini.desktop b/data/etc/advancedFeatures.ini.desktop
index 02671453..f1aad493 100644
--- a/data/etc/advancedFeatures.ini.desktop
+++ b/data/etc/advancedFeatures.ini.desktop
@@ -30,3 +30,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 VirtioTablet = on
+Uwb = on
diff --git a/data/etc/advancedFeatures.ini.minigbm b/data/etc/advancedFeatures.ini.minigbm
index 1b38edcd..ac613c8e 100644
--- a/data/etc/advancedFeatures.ini.minigbm
+++ b/data/etc/advancedFeatures.ini.minigbm
@@ -28,4 +28,5 @@ DeviceStateOnBoot = on
 HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
+Uwb = on
 Minigbm = on
diff --git a/data/etc/advancedFeatures.ini.tablet b/data/etc/advancedFeatures.ini.tablet
index bc9d63ac..659aaab0 100644
--- a/data/etc/advancedFeatures.ini.tablet
+++ b/data/etc/advancedFeatures.ini.tablet
@@ -28,3 +28,4 @@ DeviceStateOnBoot = on
 HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
+Uwb = on
diff --git a/data/etc/apns-conf_sdk.xml b/data/etc/apns-conf_sdk.xml
deleted file mode 100644
index 6dbc6304..00000000
--- a/data/etc/apns-conf_sdk.xml
+++ /dev/null
@@ -1,45 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2008 The Android Open Source Project
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
-<!-- This file contains fake APNs that are necessary for the emulator
-     to talk to the network.  It should only be installed for SDK builds.
-
-     This file is not installed by the local Android.mk, it's installed using
-     a PRODUCT_COPY_FILES line in the sdk section of the toplevel Makefile.
--->
-
-<!-- use empty string to specify no proxy or port -->
-<!-- This version must agree with that in apps/common/res/apns.xml -->
-<apns version="8">
-    <apn carrier="Android"
-        mcc="310"
-        mnc="995"
-        apn="internet"
-        user="*"
-        server="*"
-        password="*"
-        mmsc="null"
-    />
-    <apn carrier="TelKila"
-        mcc="310"
-        mnc="260"
-        apn="internet"
-        user="*"
-        server="*"
-        password="*"
-        mmsc="null"
-    />
-</apns>
diff --git a/data/etc/atrace_categories.txt b/data/etc/atrace_categories.txt
new file mode 100644
index 00000000..3ab2fbdc
--- /dev/null
+++ b/data/etc/atrace_categories.txt
@@ -0,0 +1,11 @@
+memory
+ fastrpc/fastrpc_dma_stat
+ dmabuf_heap/dma_heap_stat
+ cma/cma_alloc_start
+ cma/cma_alloc_info
+ion
+ kmem/ion_alloc_buffer_start
+sched
+ scm/scm_call_start
+ scm/scm_call_end
+ systrace/0
diff --git a/data/etc/google/user/advancedFeatures.ini b/data/etc/google/user/advancedFeatures.ini
index 73e3f52a..eb0286eb 100644
--- a/data/etc/google/user/advancedFeatures.ini
+++ b/data/etc/google/user/advancedFeatures.ini
@@ -32,3 +32,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
+Uwb = on
diff --git a/data/etc/google/user/advancedFeatures.ini.desktop b/data/etc/google/user/advancedFeatures.ini.desktop
index c8d2d77b..86e9d3d4 100644
--- a/data/etc/google/user/advancedFeatures.ini.desktop
+++ b/data/etc/google/user/advancedFeatures.ini.desktop
@@ -31,3 +31,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 VirtioTablet = on
+Uwb = on
diff --git a/data/etc/google/user/advancedFeatures.ini.minigbm b/data/etc/google/user/advancedFeatures.ini.minigbm
index 1f28d1ce..666145b4 100644
--- a/data/etc/google/user/advancedFeatures.ini.minigbm
+++ b/data/etc/google/user/advancedFeatures.ini.minigbm
@@ -30,5 +30,6 @@ DeviceStateOnBoot = on
 HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
+Uwb = on
 Minigbm = on
 AndroidVirtualizationFramework = on
diff --git a/data/etc/google/user/advancedFeatures.ini.tablet b/data/etc/google/user/advancedFeatures.ini.tablet
index 02a3c194..f7dbbc5e 100644
--- a/data/etc/google/user/advancedFeatures.ini.tablet
+++ b/data/etc/google/user/advancedFeatures.ini.tablet
@@ -30,3 +30,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
+Uwb = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini b/data/etc/google/userdebug/advancedFeatures.ini
index 3393937a..e907c6ca 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini
+++ b/data/etc/google/userdebug/advancedFeatures.ini
@@ -31,3 +31,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
+Uwb = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini.desktop b/data/etc/google/userdebug/advancedFeatures.ini.desktop
index b407f2e1..12979bbf 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini.desktop
+++ b/data/etc/google/userdebug/advancedFeatures.ini.desktop
@@ -30,3 +30,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 VirtioTablet = on
+Uwb = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini.minigbm b/data/etc/google/userdebug/advancedFeatures.ini.minigbm
index b144671e..337f253e 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini.minigbm
+++ b/data/etc/google/userdebug/advancedFeatures.ini.minigbm
@@ -29,5 +29,6 @@ DeviceStateOnBoot = on
 HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
+Uwb = on
 Minigbm = on
 AndroidVirtualizationFramework = on
diff --git a/data/etc/google/userdebug/advancedFeatures.ini.tablet b/data/etc/google/userdebug/advancedFeatures.ini.tablet
index 21ff01b1..a7098313 100644
--- a/data/etc/google/userdebug/advancedFeatures.ini.tablet
+++ b/data/etc/google/userdebug/advancedFeatures.ini.tablet
@@ -29,3 +29,4 @@ HWCMultiConfigs = on
 VirtioSndCard = on
 DeviceKeyboardHasAssistKey = on
 AndroidVirtualizationFramework = on
+Uwb = on
diff --git a/init.ranchu.rc b/init.ranchu.rc
index ba7618dd..1df747f7 100644
--- a/init.ranchu.rc
+++ b/init.ranchu.rc
@@ -19,9 +19,19 @@ on early-init
     setprop ro.opengles.version ${ro.boot.opengles.version}
     setprop dalvik.vm.heapsize ${ro.boot.dalvik.vm.heapsize:-192m}
     setprop dalvik.vm.checkjni ${ro.boot.dalvik.vm.checkjni}
-    setprop debug.hwui.renderer ${ro.boot.debug.hwui.renderer:-opengl}
+    # default skiagl: skia uses gles to render
+    # option skiavk: skia uses vulkan to render
+    setprop debug.hwui.renderer ${ro.boot.debug.hwui.renderer:-skiagl}
+    # default skiaglthreaded: skia uses gles to render in a separate thread
+    # option skiagl: skia uses gles to render
+    # option skiavk: skia uses vulkan to render
+    # option skiavkthreaded: skia uses vulkan to render in separate thread
+    # option empty: skia uses graphite
+    setprop debug.renderengine.backend ${ro.boot.debug.renderengine.backend:-skiaglthreaded}
     setprop debug.stagefright.ccodec ${ro.boot.debug.stagefright.ccodec}
     setprop debug.sf.nobootanimation ${ro.boot.debug.sf.nobootanimation}
+    setprop debug.angle.feature_overrides_enabled ${ro.boot.hardware.angle_feature_overrides_enabled}
+    setprop debug.angle.feature_overrides_disabled ${ro.boot.hardware.angle_feature_overrides_disabled}
     setprop vendor.qemu.dev.bootcomplete 0
 
     start vendor.dlkm_loader
diff --git a/product/base_handheld.mk b/product/base_handheld.mk
index 095a7e10..76531ebb 100644
--- a/product/base_handheld.mk
+++ b/product/base_handheld.mk
@@ -13,7 +13,6 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_product.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
 $(call inherit-product, frameworks/base/data/sounds/AllAudio.mk)
diff --git a/product/base_phone.mk b/product/base_phone.mk
index 0deb9fea..02eee491 100644
--- a/product/base_phone.mk
+++ b/product/base_phone.mk
@@ -29,3 +29,16 @@ $(call inherit-product, device/generic/goldfish/product/phone_overlays.mk)
 
 PRODUCT_COPY_FILES += \
     device/generic/goldfish/phone/overlay/frameworks/base/packages/overlays/GoldfishSkinConfig/readme.txt:$(TARGET_COPY_OUT_DATA)/misc/GoldfishSkinConfig \
+    device/generic/goldfish/data/etc/handheld_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml \
+
+ifeq ($(EMULATOR_DEVICE_TYPE_FOLDABLE),true)
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/pixel_fold/display_settings.xml:/data/misc/pixel_fold/display_settings.xml \
+    device/generic/goldfish/pixel_fold/device_state_configuration.xml:/data/misc/pixel_fold/devicestate/device_state_configuration.xml \
+    device/generic/goldfish/pixel_fold/display_layout_configuration.xml:/data/misc/pixel_fold/displayconfig/display_layout_configuration.xml \
+    device/generic/goldfish/pixel_fold/sensor_hinge_angle.xml:/data/misc/pixel_fold/extra_feature.xml
+else
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml \
+
+endif
diff --git a/product/generic.mk b/product/generic.mk
index ad8507e4..dacce206 100644
--- a/product/generic.mk
+++ b/product/generic.mk
@@ -33,9 +33,11 @@ TARGET_USES_MKE2FS := true
 # Set Vendor SPL to match platform
 VENDOR_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
 
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
+    ro.surface_flinger.game_default_frame_rate_override=60
+
 # RKPD
 PRODUCT_PRODUCT_PROPERTIES += \
-    remote_provisioning.enable_rkpd=true \
     remote_provisioning.hostname=remoteprovisioning.googleapis.com
 
 PRODUCT_PACKAGES += \
@@ -62,7 +64,6 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.surface_flinger.supports_background_blur=1 \
     ro.surface_flinger.use_color_management=false \
     ro.zygote.disable_gl_preload=1 \
-    debug.renderengine.backend=skiaglthreaded \
     debug.sf.vsync_reactor_ignore_present_fences=true \
     debug.stagefright.c2inputsurface=-1 \
     debug.stagefright.ccodec=4 \
@@ -75,8 +76,9 @@ PRODUCT_VENDOR_PROPERTIES += \
 # Device modules
 PRODUCT_PACKAGES += \
     android.hardware.drm-service-lazy.clearkey \
-    android.hardware.gatekeeper@1.0-service.software \
+    com.android.hardware.gatekeeper.nonsecure \
     android.hardware.usb-service.example \
+    atrace \
     vulkan.ranchu \
     libandroidemu \
     libOpenglCodecCommon \
@@ -120,14 +122,22 @@ DEVICE_MANIFEST_FILE += device/generic/goldfish/radio/manifest.radio.xml
 DISABLE_RILD_OEM_HOOK := true
 # For customize cflags for libril share library building by soong.
 $(call soong_config_set,ril,disable_rild_oem_hook,true)
+
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/radio/init.system_ext.radio.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.system_ext.radio.rc \
+    device/generic/goldfish/radio/data/apns-conf.xml:$(TARGET_COPY_OUT_VENDOR)/etc/apns/apns-conf.xml \
+    device/generic/goldfish/radio/data/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim0.xml \
+    device/generic/goldfish/radio/data/numeric_operator.xml:data/misc/modem_simulator/etc/modem_simulator/files/numeric_operator.xml \
+    device/generic/goldfish/radio/EmulatorRadioConfig/radioconfig.xml:data/misc/emulator/config/radioconfig.xml \
+    device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim_tel_alaska.xml \
+    device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0_for_CtsCarrierApiTestCases.xml:data/misc/modem_simulator/iccprofile_for_carrierapitests.xml \
+
 endif
 
 ifneq ($(EMULATOR_VENDOR_NO_BIOMETRICS), true)
 PRODUCT_PACKAGES += \
     android.hardware.biometrics.fingerprint-service.ranchu \
-    android.hardware.biometrics.face-service.example \
-    android.hardware.fingerprint.prebuilt.xml \
-    android.hardware.biometrics.face.prebuilt.xml
+    android.hardware.fingerprint.prebuilt.xml
 endif
 
 ifneq ($(BUILD_EMULATOR_OPENGL),false)
@@ -253,19 +263,17 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions.mk)
 
 # "Hello, world!" HAL implementations, mostly for compliance
 PRODUCT_PACKAGES += \
-    android.hardware.atrace@1.0-service \
     com.android.hardware.authsecret \
-    android.hardware.contexthub-service.example \
-    android.hardware.dumpstate-service.example \
+    com.android.hardware.contexthub \
+    com.android.hardware.dumpstate \
     android.hardware.health-service.example \
     android.hardware.health.storage-service.default \
     android.hardware.lights-service.example \
     com.android.hardware.neuralnetworks \
-    android.hardware.power-service.example \
-    android.hardware.power.stats-service.example \
+    com.android.hardware.power \
     com.android.hardware.rebootescrow \
-    android.hardware.thermal@2.0-service.mock \
-    android.hardware.vibrator-service.example
+    com.android.hardware.thermal \
+    com.android.hardware.vibrator
 
 # TVs don't use a hardware identity service.
 ifneq ($(PRODUCT_IS_ATV_SDK),true)
@@ -277,13 +285,8 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/empty_data_disk:data/empty_data_disk \
     device/generic/goldfish/data/etc/dtb.img:dtb.img \
     device/generic/goldfish/data/etc/encryptionkey.img:encryptionkey.img \
+    device/generic/goldfish/data/etc/atrace_categories.txt:$(TARGET_COPY_OUT_VENDOR)/etc/atrace/atrace_categories.txt \
     device/generic/goldfish/emulator-info.txt:data/misc/emulator/version.txt \
-    device/generic/goldfish/data/etc/apns-conf.xml:data/misc/apns/apns-conf.xml \
-    device/generic/goldfish/radio/RadioConfig/radioconfig.xml:data/misc/emulator/config/radioconfig.xml \
-    device/generic/goldfish/data/etc/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim0.xml \
-    device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0.xml:data/misc/modem_simulator/iccprofile_for_sim_tel_alaska.xml \
-    device/google/cuttlefish/host/commands/modem_simulator/files/iccprofile_for_sim0_for_CtsCarrierApiTestCases.xml:data/misc/modem_simulator/iccprofile_for_carrierapitests.xml \
-    device/generic/goldfish/data/etc/numeric_operator.xml:data/misc/modem_simulator/etc/modem_simulator/files/numeric_operator.xml \
     device/generic/goldfish/data/etc/local.prop:data/local.prop \
     device/generic/goldfish/init.ranchu.adb.setup.sh:$(TARGET_COPY_OUT_SYSTEM_EXT)/bin/init.ranchu.adb.setup.sh \
     device/generic/goldfish/init_ranchu_device_state.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init_ranchu_device_state.sh \
@@ -309,12 +312,6 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/input/virtio_input_multi_touch_11.idc:$(TARGET_COPY_OUT_VENDOR)/usr/idc/virtio_input_multi_touch_11.idc \
     device/generic/goldfish/display_settings_app_compat.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings_app_compat.xml \
     device/generic/goldfish/display_settings_freeform.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings_freeform.xml \
-    device/generic/goldfish/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml \
-    device/generic/goldfish/pixel_fold/device_state_configuration.xml:/data/misc/pixel_fold/devicestate/device_state_configuration.xml \
-    device/generic/goldfish/pixel_fold/display_layout_configuration.xml:/data/misc/pixel_fold/displayconfig/display_layout_configuration.xml \
-    device/generic/goldfish/pixel_fold/display_settings.xml:/data/misc/pixel_fold/display_settings.xml \
-    device/generic/goldfish/pixel_fold/sensor_hinge_angle.xml:/data/misc/pixel_fold/extra_feature.xml \
-    device/generic/goldfish/data/etc/config.ini:config.ini \
     device/generic/goldfish/wifi/wpa_supplicant.conf:$(TARGET_COPY_OUT_VENDOR)/etc/wifi/wpa_supplicant.conf \
     frameworks/native/data/etc/android.hardware.bluetooth_le.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.bluetooth_le.xml \
     frameworks/native/data/etc/android.hardware.bluetooth.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.bluetooth.xml \
@@ -333,13 +330,5 @@ PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.software.verified_boot.xml:${TARGET_COPY_OUT_PRODUCT}/etc/permissions/android.software.verified_boot.xml \
     device/generic/goldfish/data/etc/permissions/privapp-permissions-goldfish.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/privapp-permissions-goldfish.xml \
 
-ifneq ($(EMULATOR_DISABLE_RADIO),true)
-# Android TV ingests this file, but declares its own set of hardware permissions.
-ifneq ($(PRODUCT_IS_ATV_SDK),true)
-    PRODUCT_COPY_FILES+= \
-        device/generic/goldfish/data/etc/handheld_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml
-endif
-endif
-
 # Goldfish uses 6.X kernels.
 PRODUCT_ENABLE_UFFD_GC := true
diff --git a/product/handheld.mk b/product/handheld.mk
index cf14baaf..7c8f636d 100644
--- a/product/handheld.mk
+++ b/product/handheld.mk
@@ -14,5 +14,6 @@
 # limitations under the License.
 
 $(call inherit-product, device/generic/goldfish/product/base_handheld.mk)
+$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
diff --git a/product/phone.mk b/product/phone.mk
index c6009b63..7209f04d 100644
--- a/product/phone.mk
+++ b/product/phone.mk
@@ -15,3 +15,7 @@
 
 $(call inherit-product, device/generic/goldfish/product/handheld.mk)
 $(call inherit-product, device/generic/goldfish/product/base_phone.mk)
+
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/config.ini.nexus5:config.ini
diff --git a/product/slim_handheld.mk b/product/slim_handheld.mk
index 6765ce73..e5db97f6 100644
--- a/product/slim_handheld.mk
+++ b/product/slim_handheld.mk
@@ -14,8 +14,8 @@
 # limitations under the License.
 
 $(call inherit-product, device/generic/goldfish/product/base_handheld.mk)
-# include webview
-$(call inherit-product, $(SRC_TARGET_DIR)/product/media_product.mk)
+$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
+
 # don't include full handheld_system_Ext which includes SystemUi, Settings etc
 $(call inherit-product, $(SRC_TARGET_DIR)/product/media_system_ext.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
@@ -32,3 +32,6 @@ PRODUCT_PACKAGES += \
 
 $(call inherit-product, device/generic/goldfish/product/generic.mk)
 
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/config.ini.nexus5:config.ini
diff --git a/product/tablet.mk b/product/tablet.mk
index f0603269..1d02fd4f 100644
--- a/product/tablet.mk
+++ b/product/tablet.mk
@@ -32,4 +32,11 @@ PRODUCT_PACKAGES += \
 
 PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += system/bin/curl
 
+PRODUCT_COPY_FILES += \
+    device/generic/goldfish/data/etc/advancedFeatures.ini.tablet:advancedFeatures.ini \
+    device/generic/goldfish/data/etc/config.ini.nexus7tab:config.ini \
+    device/generic/goldfish/data/etc/tablet_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml \
+    device/generic/goldfish/tablet/data/etc/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml \
+    device/generic/goldfish/tablet/data/etc/tablet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/tablet.xml \
+
 $(call inherit-product, device/generic/goldfish/product/generic.mk)
diff --git a/product/uwb.mk b/product/uwb.mk
deleted file mode 100644
index 79967dd2..00000000
--- a/product/uwb.mk
+++ /dev/null
@@ -1,22 +0,0 @@
-#
-# Copyright (C) 2024 The Android Open Source Project
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
-PRODUCT_PACKAGES += \
-    com.android.hardware.uwb \
-    android.hardware.uwb-service \
-    UwbOverlay
-PRODUCT_VENDOR_PROPERTIES += ro.vendor.uwb.dev=/dev/hvc2
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.hardware.uwb.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.uwb.xml
\ No newline at end of file
diff --git a/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java b/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
index 23d87d63..fb10e5c3 100644
--- a/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
+++ b/provision/EmulatorProvisonLib/src/com/android/sdksetup/ProvisionActivity.java
@@ -111,6 +111,10 @@ public abstract class ProvisionActivity extends Activity {
     }
 
     protected void provisionWifi(final String ssid) {
+        if (isVisibleBackgroundUser(getApplicationContext())) {
+            return;
+        }
+
         Settings.Global.putInt(getContentResolver(), Settings.Global.TETHER_OFFLOAD_DISABLED, 1);
 
         final WifiManager mWifiManager = getApplicationContext().getSystemService(WifiManager.class);
@@ -127,9 +131,10 @@ public abstract class ProvisionActivity extends Activity {
         config.setSecurityParams(WifiConfiguration.SECURITY_TYPE_OPEN);
 
         final int netId = mWifiManager.addNetwork(config);
-
-        if (netId == ADD_NETWORK_FAIL || !mWifiManager.enableNetwork(netId, true)) {
+        if (netId == ADD_NETWORK_FAIL) {
             Log.e(TAG(), "Unable to add Wi-Fi network " + quotedSsid + ".");
+        } else if (!mWifiManager.enableNetwork(netId, true)) {
+            Log.e(TAG(), "Unable to enable Wi-Fi network " + quotedSsid + " (netId=" + netId + ")");
         }
     }
 
@@ -250,7 +255,7 @@ public abstract class ProvisionActivity extends Activity {
     }
 
     protected boolean provisionRequired() {
-        return true;
+        return Settings.Global.getInt(getContentResolver(), Settings.Global.DEVICE_PROVISIONED, 0) != 1;
     }
 
     protected boolean isVisibleBackgroundUser(Context context) {
diff --git a/radio/RadioConfig/Android.bp b/radio/EmulatorRadioConfig/Android.bp
similarity index 100%
rename from radio/RadioConfig/Android.bp
rename to radio/EmulatorRadioConfig/Android.bp
diff --git a/radio/RadioConfig/AndroidManifest.xml b/radio/EmulatorRadioConfig/AndroidManifest.xml
similarity index 100%
rename from radio/RadioConfig/AndroidManifest.xml
rename to radio/EmulatorRadioConfig/AndroidManifest.xml
diff --git a/radio/RadioConfig/NOTICE b/radio/EmulatorRadioConfig/NOTICE
similarity index 100%
rename from radio/RadioConfig/NOTICE
rename to radio/EmulatorRadioConfig/NOTICE
diff --git a/radio/RadioConfig/com.android.emulator.radio.config.xml b/radio/EmulatorRadioConfig/com.android.emulator.radio.config.xml
similarity index 100%
rename from radio/RadioConfig/com.android.emulator.radio.config.xml
rename to radio/EmulatorRadioConfig/com.android.emulator.radio.config.xml
diff --git a/radio/RadioConfig/radioconfig.xml b/radio/EmulatorRadioConfig/radioconfig.xml
similarity index 100%
rename from radio/RadioConfig/radioconfig.xml
rename to radio/EmulatorRadioConfig/radioconfig.xml
diff --git a/radio/RadioConfig/src/com/android/emulator/radio/config/MeterService.java b/radio/EmulatorRadioConfig/src/com/android/emulator/radio/config/MeterService.java
similarity index 100%
rename from radio/RadioConfig/src/com/android/emulator/radio/config/MeterService.java
rename to radio/EmulatorRadioConfig/src/com/android/emulator/radio/config/MeterService.java
diff --git a/data/etc/apns-conf.xml b/radio/data/apns-conf.xml
similarity index 100%
rename from data/etc/apns-conf.xml
rename to radio/data/apns-conf.xml
diff --git a/data/etc/iccprofile_for_sim0.xml b/radio/data/iccprofile_for_sim0.xml
similarity index 100%
rename from data/etc/iccprofile_for_sim0.xml
rename to radio/data/iccprofile_for_sim0.xml
diff --git a/data/etc/numeric_operator.xml b/radio/data/numeric_operator.xml
similarity index 100%
rename from data/etc/numeric_operator.xml
rename to radio/data/numeric_operator.xml
diff --git a/radio/include/libril/ril_ex.h b/radio/include/libril/ril_ex.h
deleted file mode 100644
index 757bcf9d..00000000
--- a/radio/include/libril/ril_ex.h
+++ /dev/null
@@ -1,49 +0,0 @@
-/*
-* Copyright (C) 2014 The Android Open Source Project
-*
-* Licensed under the Apache License, Version 2.0 (the "License");
-* you may not use this file except in compliance with the License.
-* You may obtain a copy of the License at
-*
-*     http://www.apache.org/licenses/LICENSE-2.0
-*
-* Unless required by applicable law or agreed to in writing, software
-* distributed under the License is distributed on an "AS IS" BASIS,
-* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-* See the License for the specific language governing permissions and
-* limitations under the License.
-*/
-
-#ifndef RIL_EX_H_INCLUDED
-#define RIL_EX_H_INCLUDED
-
-#include <telephony/ril.h>
-#include <telephony/record_stream.h>
-
-#define NUM_ELEMS_SOCKET(a)     (sizeof (a) / sizeof (a)[0])
-
-struct ril_event;
-
-void rilEventAddWakeup_helper(struct ril_event *ev);
-int blockingWrite_helper(int fd, void* data, size_t len);
-
-enum SocketWakeType {DONT_WAKE, WAKE_PARTIAL};
-
-typedef enum {
-    RIL_TELEPHONY_SOCKET,
-    RIL_SAP_SOCKET
-} RIL_SOCKET_TYPE;
-
-typedef struct SocketListenParam {
-    RIL_SOCKET_ID socket_id;
-    int fdListen;
-    int fdCommand;
-    const char* processName;
-    struct ril_event* commands_event;
-    struct ril_event* listen_event;
-    void (*processCommandsCallback)(int fd, short flags, void *param);
-    RecordStream *p_rs;
-    RIL_SOCKET_TYPE type;
-} SocketListenParam;
-
-#endif
diff --git a/radio/include/telephony/librilutils.h b/radio/include/telephony/librilutils.h
deleted file mode 100644
index d06b3e9b..00000000
--- a/radio/include/telephony/librilutils.h
+++ /dev/null
@@ -1,38 +0,0 @@
-/*
- * Copyright (C) 2013 The Android Open Source Project
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
-#ifndef LIBRILUTILS_H
-#define LIBRILUTILS_H
-
-#include <stdint.h>
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-/**
- * Return system time in nanos.
- *
- * This is a monotonicly increasing clock and
- * return the same value as System.nanoTime in java.
- */
-uint64_t ril_nano_time();
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif // LIBRILUTILS_H
diff --git a/radio/include/telephony/record_stream.h b/radio/include/telephony/record_stream.h
deleted file mode 100644
index 7a89ae4f..00000000
--- a/radio/include/telephony/record_stream.h
+++ /dev/null
@@ -1,43 +0,0 @@
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
- * A simple utility for reading fixed records out of a stream fd
- */
-
-#ifndef _LIBRIL_RECORD_STREAM_H
-#define _LIBRIL_RECORD_STREAM_H
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-
-typedef struct RecordStream RecordStream;
-
-extern RecordStream *record_stream_new(int fd, size_t maxRecordLen);
-extern void record_stream_free(RecordStream *p_rs);
-
-extern int record_stream_get_next (RecordStream *p_rs, void ** p_outRecord,
-                                    size_t *p_outRecordLen);
-
-#ifdef __cplusplus
-}
-#endif
-
-
-#endif /*_LIBRIL_RECORD_STREAM_H*/
-
diff --git a/radio/include/telephony/ril.h b/radio/include/telephony/ril.h
index c879873d..7895a60e 100644
--- a/radio/include/telephony/ril.h
+++ b/radio/include/telephony/ril.h
@@ -21,7 +21,6 @@
 #include <stdint.h>
 #include <telephony/ril_cdma_sms.h>
 #include <telephony/ril_nv_items.h>
-#include <telephony/ril_msim.h>
 
 #ifndef FEATURE_UNIT_TEST
 #include <sys/time.h>
diff --git a/radio/include/telephony/ril_mcc.h b/radio/include/telephony/ril_mcc.h
deleted file mode 100644
index dc56b126..00000000
--- a/radio/include/telephony/ril_mcc.h
+++ /dev/null
@@ -1,71 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-#ifndef RIL_MCC_H
-#define RIL_MCC_H
-
-#include <climits>
-#include <cstdio>
-#include <string>
-
-namespace ril {
-namespace util {
-namespace mcc {
-
-/**
- * Decode an integer mcc and encode as 3 digit string
- *
- * @param an integer mcc, its range should be in 0 to 999.
- *
- * @return string representation of an encoded MCC or an empty string
- * if the MCC is not a valid MCC value.
- */
-static inline std::string decode(int mcc) {
-    char mccStr[4] = {0};
-    if (mcc > 999 || mcc < 0) return "";
-
-    snprintf(mccStr, sizeof(mccStr), "%03d", mcc);
-    return mccStr;
-}
-
-// echo -e "#include \"hardware/ril/include/telephony/ril_mcc.h\"\nint main()"\
-// "{ return ril::util::mcc::test(); }" > ril_test.cpp \
-// && g++ -o /tmp/ril_test -DTEST_RIL_MCC ril_test.cpp; \
-// rm ril_test.cpp; /tmp/ril_test && [ $? ] && echo "passed"
-#ifdef TEST_RIL_MCC
-static int test() {
-    const struct mcc_ints { const int in; const char * out; } legacy_mccs[] = {
-        {INT_MAX, ""},
-        {1, "001"},
-        {11, "011"},
-        {111, "111"},
-        {0, "000"},
-        {9999, ""},
-        {-12, ""},
-    };
-
-    for (int i=0; i < sizeof(legacy_mccs) / sizeof(struct mcc_ints); i++) {
-        if (decode(legacy_mccs[i].in).compare(legacy_mccs[i].out)) return 1;
-    }
-
-    return 0;
-}
-#endif
-
-}
-}
-}
-#endif /* !defined(RIL_MCC_H) */
diff --git a/radio/include/telephony/ril_mnc.h b/radio/include/telephony/ril_mnc.h
deleted file mode 100644
index fcbae997..00000000
--- a/radio/include/telephony/ril_mnc.h
+++ /dev/null
@@ -1,149 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
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
-#ifndef RIL_MNC_H
-#define RIL_MNC_H
-
-#include <climits>
-#include <cstdio>
-#include <string>
-
-namespace ril {
-namespace util {
-namespace mnc {
-
-/**
- * Decode an MNC with an optional length indicator provided in the most-significant nibble.
- *
- * @param mnc an encoded MNC value; if no encoding is provided, then the string is returned
- *     as a minimum length string representing the provided integer.
- *
- * @return string representation of an encoded MNC or an empty string if the MNC is not a valid
- *     MNC value.
- */
-static inline std::string decode(int mnc) {
-    if (mnc == INT_MAX || mnc < 0) return "";
-    unsigned umnc = mnc;
-    char mncNumDigits = (umnc >> (sizeof(int) * 8 - 4)) & 0xF;
-
-    umnc = (umnc << 4) >> 4;
-    if (umnc > 999) return "";
-
-    char mncStr[4] = {0};
-    switch (mncNumDigits) {
-        case 0:
-            // Legacy MNC report hasn't set the number of digits; preserve current
-            // behavior and make a string of the minimum number of required digits.
-            return std::to_string(umnc);
-
-        case 2:
-            snprintf(mncStr, sizeof(mncStr), "%03.3u", umnc);
-            return mncStr + 1;
-
-        case 3:
-            snprintf(mncStr, sizeof(mncStr), "%03.3u", umnc);
-            return mncStr;
-
-        default:
-            // Error case
-            return "";
-    }
-
-}
-
-/**
- * Encode an MNC of the given value and a given number of digits
- *
- * @param mnc an MNC value 0-999 or INT_MAX if unknown
- * @param numDigits the number of MNC digits {2, 3} or 0 if unknown
- *
- * @return an encoded MNC with embedded length information
- */
-static inline int encode(int mnc, int numDigits) {
-    if (mnc > 999 || mnc < 0) return INT_MAX;
-    switch (numDigits) {
-        case 0: // fall through
-        case 2: // fall through
-        case 3:
-            break;
-
-        default:
-            return INT_MAX;
-    };
-
-    return (numDigits << (sizeof(int) * 8 - 4)) | mnc;
-}
-
-/**
- * Encode an MNC of the given value
- *
- * @param mnc the string representation of the MNC, with the length equal to the length of the
- *     provided string.
- *
- * @return an encoded MNC with embedded length information
- */
-static inline int encode(const std::string & mnc) {
-    return encode(std::stoi(mnc), mnc.length());
-}
-
-// echo -e "#include \"hardware/ril/include/telephony/ril_mnc.h\"\nint main()"\
-// "{ return ril::util::mnc::test(); }" > ril_test.cpp \
-// && g++ -o /tmp/ril_test -DTEST_RIL_MNC ril_test.cpp; \
-// rm ril_test.cpp; /tmp/ril_test && [ $? ] && echo "passed"
-#ifdef TEST_RIL_MNC
-static int test() {
-    const struct mnc_strings { const char * in; const char * out; } mncs[] = {
-        {"0001",""},
-        {"9999",""},
-        {"0",""},
-        {"9",""},
-        {"123","123"},
-        {"000","000"},
-        {"001","001"},
-        {"011","011"},
-        {"111","111"},
-        {"00","00"},
-        {"01","01"},
-        {"11","11"},
-        {"09","09"},
-        {"099","099"},
-        {"999", "999"}};
-
-    for (int i=0; i< sizeof(mncs) / sizeof(struct mnc_strings); i++) {
-        if (decode(encode(mncs[i].in)).compare(mncs[i].out)) return 1;
-    }
-
-    const struct mnc_ints { const int in; const char * out; } legacy_mncs[] = {
-        {INT_MAX, ""},
-        {1, "1"},
-        {11, "11"},
-        {111, "111"},
-        {0, "0"},
-        {9999, ""},
-    };
-
-    for (int i=0; i < sizeof(legacy_mncs) / sizeof(struct mnc_ints); i++) {
-        if (decode(legacy_mncs[i].in).compare(legacy_mncs[i].out)) return 1;
-    }
-
-    return 0;
-}
-#endif
-
-}
-}
-}
-#endif /* !defined(RIL_MNC_H) */
diff --git a/radio/include/telephony/ril_msim.h b/radio/include/telephony/ril_msim.h
deleted file mode 100644
index 5c0b8c51..00000000
--- a/radio/include/telephony/ril_msim.h
+++ /dev/null
@@ -1,48 +0,0 @@
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
-
-#ifndef ANDROID_RIL_MSIM_H
-#define ANDROID_RIL_MSIM_H 1
-
-#ifdef __cplusplus
-extern "C" {
-#endif
-
-typedef enum {
-  RIL_UICC_SUBSCRIPTION_DEACTIVATE = 0,
-  RIL_UICC_SUBSCRIPTION_ACTIVATE = 1
-} RIL_UiccSubActStatus;
-
-typedef enum {
-  RIL_SUBSCRIPTION_1 = 0,
-  RIL_SUBSCRIPTION_2 = 1,
-  RIL_SUBSCRIPTION_3 = 2
-} RIL_SubscriptionType;
-
-typedef struct {
-  int   slot;                        /* 0, 1, ... etc. */
-  int   app_index;                   /* array subscriptor from applications[RIL_CARD_MAX_APPS] in
-                                        RIL_REQUEST_GET_SIM_STATUS */
-  RIL_SubscriptionType  sub_type;    /* Indicates subscription 1 or subscription 2 */
-  RIL_UiccSubActStatus  act_status;
-} RIL_SelectUiccSub;
-
-#ifdef __cplusplus
-}
-#endif
-
-#endif /*ANDROID_RIL_MSIM_H*/
diff --git a/radio/init.system_ext.radio.rc b/radio/init.system_ext.radio.rc
new file mode 100644
index 00000000..be8ed093
--- /dev/null
+++ b/radio/init.system_ext.radio.rc
@@ -0,0 +1,4 @@
+on post-fs-data
+    copy /vendor/etc/apns/apns-conf.xml /data/misc/apns/apns-conf.xml
+    chown system system /data/misc/apns/apns-conf.xml
+    chmod 0664 /data/misc/apns/apns-conf.xml
diff --git a/radio/librilutils/Android.bp b/radio/librilutils/Android.bp
deleted file mode 100644
index ff76027f..00000000
--- a/radio/librilutils/Android.bp
+++ /dev/null
@@ -1,46 +0,0 @@
-// Copyright 2013 The Android Open Source Project
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
-cc_library {
-    name: "librilutils-goldfish-fork",
-
-    srcs: [
-        "librilutils.c",
-        "record_stream.c",
-        "proto/sap-api.proto",
-    ],
-
-    header_libs: ["goldfish_ril_headers"],
-    export_header_lib_headers: ["goldfish_ril_headers"],
-
-    cflags: [
-        "-Wall",
-        "-Wextra",
-        "-Werror",
-        "-DPB_FIELD_32BIT"
-    ],
-
-    proto: {
-        type: "nanopb-c-enable_malloc-32bit",
-        export_proto_headers: true,
-    },
-
-    vendor: true,
-}
-
-// Create java protobuf code
-java_library {
-    name: "goldfish-fork-sap-api-java-static",
-    srcs: ["proto/sap-api.proto"],
-    proto: {
-        type: "micro",
-    },
-}
diff --git a/radio/librilutils/librilutils.c b/radio/librilutils/librilutils.c
deleted file mode 100644
index b1b930ea..00000000
--- a/radio/librilutils/librilutils.c
+++ /dev/null
@@ -1,24 +0,0 @@
-/*
- * Copyright (C) 2013 The Android Open Source Project
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
-#include <telephony/librilutils.h>
-#include <time.h>
-
-uint64_t ril_nano_time() {
-    struct timespec now;
-    clock_gettime(CLOCK_MONOTONIC, &now);
-    return now.tv_sec * 1000000000LL + now.tv_nsec;
-}
diff --git a/radio/librilutils/proto/sap-api.options b/radio/librilutils/proto/sap-api.options
deleted file mode 100644
index f76ba931..00000000
--- a/radio/librilutils/proto/sap-api.options
+++ /dev/null
@@ -1,23 +0,0 @@
-#
-# Copyright (C) 2014 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-MsgHeader.payload                 type:FT_POINTER
-RIL_SIM_SAP_APDU_REQ.command      type:FT_POINTER
-RIL_SIM_SAP_APDU_RSP.apduResponse type:FT_POINTER
-RIL_SIM_SAP_TRANSFER_ATR_RSP.atr  type:FT_POINTER
-
-#RIL_SIM_SAP_REQUEST.apdu type:FT_POINTER
-#RIL_SIM_SAP_RESPONSE.apdu type:FT_POINTER
diff --git a/radio/librilutils/proto/sap-api.proto b/radio/librilutils/proto/sap-api.proto
deleted file mode 100644
index 5d125e47..00000000
--- a/radio/librilutils/proto/sap-api.proto
+++ /dev/null
@@ -1,306 +0,0 @@
-syntax = "proto2";
-
-option java_package = "org.android.btsap";
-option java_outer_classname = "SapApi";
-
-//
-// SAP Interface to RIL
-//
-// The protocol for the binary wire format to RIL shall consist of
-// the serialized format of MsgHeader.
-// MsgHeader payload field will contain the serialized format of
-// the actual message being sent, as described by the type and id
-// fields.
-// e.g. If type = REQUEST and id == RIL_SIM_SAP_CONNECT, payload
-// will contain the serialized wire format of a
-// RIL_SIM_SAP_CONNECT_REQ message.
-//
-
-// Message Header
-// Each SAP message stream will always be prepended with a MsgHeader
-message MsgHeader {
-          required fixed32 token = 1; // generated dynamically
-          required MsgType type = 2;
-          required MsgId id = 3;
-          required Error error = 4;
-          required bytes payload = 5;
-}
-
-enum MsgType {
-        UNKNOWN = 0;
-        REQUEST = 1;
-        RESPONSE = 2;
-        UNSOL_RESPONSE = 3;
-     }
-
-enum MsgId {
-        UNKNOWN_REQ = 0;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_CONNECT, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_CONNECT_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_CONNECT, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_CONNECT_RSP
-        //
-        RIL_SIM_SAP_CONNECT = 1;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_DISCONNECT, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_DISCONNECT_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_DISCONNECT, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_DISCONNECT_RSP
-        // For MsgType: UNSOL_RESPONSE, MsgId: RIL_SIM_SAP_DISCONNECT, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_DISCONNECT_IND
-        //
-        RIL_SIM_SAP_DISCONNECT = 2;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_APDU, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_APDU_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_APDU, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_APDU_RSP
-        //
-        RIL_SIM_SAP_APDU = 3;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_TRANSFER_ATR, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_TRANSFER_ATR_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_TRANSFER_ATR, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_TRANSFER_ATR_RSP
-        //
-        RIL_SIM_SAP_TRANSFER_ATR = 4;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_POWER, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_POWER_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_POWER, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_POWER_RSP
-        //
-        RIL_SIM_SAP_POWER = 5;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_RESET_SIM, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_RESET_SIM_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_RESET_SIM, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_RESET_SIM_RSP
-        //
-        RIL_SIM_SAP_RESET_SIM = 6;
-
-        //
-        // For MsgType: UNSOL_RESPONSE, MsgId: RIL_SIM_SAP_STATUS, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_STATUS_IND
-        //
-        RIL_SIM_SAP_STATUS = 7;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS_RSP
-        //
-        RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS = 8;
-
-        //
-        // For MsgType: UNSOL_RESPONSE, MsgId: RIL_SIM_SAP_ERROR_RESP, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_ERROR_RSP
-        //
-        RIL_SIM_SAP_ERROR_RESP = 9;
-
-        //
-        // For MsgType: REQUEST ,MsgId: RIL_SIM_SAP_SET_TRANSFER_PROTOCOL, Error: RIL_E_UNUSED,
-        //              Message: message RIL_SIM_SAP_SET_TRANSFER_PROTOCOL_REQ
-        // For MsgType: RESPONSE, MsgId: RIL_SIM_SAP_SET_TRANSFER_PROTOCOL, Error:Valid errors,
-        //              Message: message RIL_SIM_SAP_SET_TRANSFER_PROTOCOL_RSP
-        //
-        RIL_SIM_SAP_SET_TRANSFER_PROTOCOL = 10;
-     }
-
-    enum Error {
-            RIL_E_SUCCESS = 0;
-            RIL_E_RADIO_NOT_AVAILABLE = 1;
-            RIL_E_GENERIC_FAILURE = 2;
-            RIL_E_REQUEST_NOT_SUPPORTED = 3;
-            RIL_E_CANCELLED = 4;
-            RIL_E_INVALID_PARAMETER = 5;
-            RIL_E_UNUSED = 6;
-    }
-
-// SAP 1.1 spec 5.1.1
-message RIL_SIM_SAP_CONNECT_REQ {
-    required int32 max_message_size = 1;
-}
-
-// SAP 1.1 spec 5.1.2
-message RIL_SIM_SAP_CONNECT_RSP {
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_SAP_CONNECT_FAILURE = 1;
-        RIL_E_SAP_MSG_SIZE_TOO_LARGE = 2;
-        RIL_E_SAP_MSG_SIZE_TOO_SMALL = 3;
-        RIL_E_SAP_CONNECT_OK_CALL_ONGOING = 4;
-    }
-    required Response response = 1;
-// must be present for RIL_E_SAP_MSG_SIZE_TOO_LARGE and contain the
-// the suitable message size
-   optional int32 max_message_size = 2;
-}
-
-// SAP 1.1 spec 5.1.3
-message RIL_SIM_SAP_DISCONNECT_REQ {
-     //no params
-}
-
-
-// SAP 1.1 spec 5.1.4
-message RIL_SIM_SAP_DISCONNECT_RSP {
-    //no params
-}
-
-
-// SAP 1.1 spec 5.1.5
-message RIL_SIM_SAP_DISCONNECT_IND {
-    enum DisconnectType {
-        RIL_S_DISCONNECT_TYPE_GRACEFUL = 0;
-        RIL_S_DISCONNECT_TYPE_IMMEDIATE = 1;
-    }
-    required DisconnectType disconnectType = 1;
-}
-
-// SAP 1.1 spec 5.1.6
-message RIL_SIM_SAP_APDU_REQ { //handles both APDU and APDU7816
-    enum Type {
-        RIL_TYPE_APDU = 0;
-        RIL_TYPE_APDU7816 = 1;
-    }
-    required Type type = 1;
-    required bytes command = 2;
-}
-
-// SAP 1.1 spec 5.1.7
-message RIL_SIM_SAP_APDU_RSP { //handles both APDU and APDU7816
-    enum Type {
-        RIL_TYPE_APDU = 0;
-        RIL_TYPE_APDU7816 = 1;
-    }
-    required Type type = 1;
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_GENERIC_FAILURE = 1;
-        RIL_E_SIM_NOT_READY = 2;
-        RIL_E_SIM_ALREADY_POWERED_OFF = 3;
-        RIL_E_SIM_ABSENT = 4;
-    }
-    required Response response = 2;
-    optional bytes apduResponse = 3;
-}
-
-// SAP 1.1 spec 5.1.8
-message RIL_SIM_SAP_TRANSFER_ATR_REQ {
-    // no params
-}
-
-// SAP 1.1 spec 5.1.9
-message RIL_SIM_SAP_TRANSFER_ATR_RSP {
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_GENERIC_FAILURE = 1;
-        RIL_E_SIM_ALREADY_POWERED_OFF = 3;
-        RIL_E_SIM_ALREADY_POWERED_ON = 18;
-        RIL_E_SIM_ABSENT = 4;
-        RIL_E_SIM_DATA_NOT_AVAILABLE = 6;
-    }
-    required Response response = 1;
-
-    optional bytes atr = 2; //must be present on SUCCESS
-}
-
-
-// SAP 1.1 spec 5.1.10 +5.1.12
-message RIL_SIM_SAP_POWER_REQ {
-    required bool state = 1;  //true = on, False = off
-}
-
-// SAP 1.1 spec 5.1.11 +5.1.13
-message RIL_SIM_SAP_POWER_RSP {
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_GENERIC_FAILURE = 2;
-        RIL_E_SIM_ABSENT = 11;
-        RIL_E_SIM_ALREADY_POWERED_OFF = 17;
-        RIL_E_SIM_ALREADY_POWERED_ON = 18;
-    }
-    required Response response = 1;
-}
-
-// SAP 1.1 spec 5.1.14
-message RIL_SIM_SAP_RESET_SIM_REQ {
-    // no params
-}
-
-// SAP 1.1 spec 5.1.15
-message RIL_SIM_SAP_RESET_SIM_RSP {
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_GENERIC_FAILURE = 2;
-        RIL_E_SIM_ABSENT = 11;
-        RIL_E_SIM_NOT_READY = 16;
-        RIL_E_SIM_ALREADY_POWERED_OFF = 17;
-    }
-    required Response response = 1;
-}
-
-// SAP 1.1 spec 5.1.16
-message RIL_SIM_SAP_STATUS_IND {
-    enum Status {
-        RIL_SIM_STATUS_UNKNOWN_ERROR = 0;
-        RIL_SIM_STATUS_CARD_RESET = 1;
-        RIL_SIM_STATUS_CARD_NOT_ACCESSIBLE = 2;
-        RIL_SIM_STATUS_CARD_REMOVED = 3;
-        RIL_SIM_STATUS_CARD_INSERTED = 4;
-        RIL_SIM_STATUS_RECOVERED = 5;
-    }
-    required Status statusChange = 1;
-}
-
-// SAP 1.1 spec 5.1.17
-message RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS_REQ {
-    //no params
-
-}
-
-// SAP 1.1 spec 5.1.18
-message RIL_SIM_SAP_TRANSFER_CARD_READER_STATUS_RSP {
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_GENERIC_FAILURE = 2;
-        RIL_E_SIM_DATA_NOT_AVAILABLE = 6;
-    }
-    required Response response = 1;
-    optional int32 CardReaderStatus = 2;
-}
-
-// SAP 1.1 spec 5.1.19
-message RIL_SIM_SAP_ERROR_RSP {
-    //no params
-}
-
-// SAP 1.1 spec 5.1.20
-message RIL_SIM_SAP_SET_TRANSFER_PROTOCOL_REQ {
-    enum Protocol {
-        t0 = 0;
-        t1 = 1;
-    }
-    required Protocol protocol = 1;
-}
-
-// SAP 1.1 spec 5.1.21
-message RIL_SIM_SAP_SET_TRANSFER_PROTOCOL_RSP {
-    enum Response {
-        RIL_E_SUCCESS = 0;
-        RIL_E_GENERIC_FAILURE = 2;
-        RIL_E_SIM_ABSENT = 11;
-        RIL_E_SIM_NOT_READY = 16;
-        RIL_E_SIM_ALREADY_POWERED_OFF = 17;
-    }
-    required Response response = 1;
-}
diff --git a/radio/librilutils/record_stream.c b/radio/librilutils/record_stream.c
deleted file mode 100644
index 566f6661..00000000
--- a/radio/librilutils/record_stream.c
+++ /dev/null
@@ -1,186 +0,0 @@
-/*
-**
-** Copyright 2006, The Android Open Source Project
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
-#include <stdlib.h>
-#include <unistd.h>
-#include <assert.h>
-#include <errno.h>
-#include <telephony/record_stream.h>
-#include <string.h>
-#include <stdint.h>
-#if defined(_WIN32)
-#include <winsock2.h>   /* for ntohl */
-#else
-#include <netinet/in.h>
-#endif
-
-#define HEADER_SIZE 4
-
-struct RecordStream {
-    int fd;
-    size_t maxRecordLen;
-
-    unsigned char *buffer;
-
-    unsigned char *unconsumed;
-    unsigned char *read_end;
-    unsigned char *buffer_end;
-};
-
-
-extern RecordStream *record_stream_new(int fd, size_t maxRecordLen)
-{
-    RecordStream *ret;
-
-    assert (maxRecordLen <= 0xffff);
-
-    ret = (RecordStream *)calloc(1, sizeof(RecordStream));
-
-    ret->fd = fd;
-    ret->maxRecordLen = maxRecordLen;
-    ret->buffer = (unsigned char *)malloc (maxRecordLen + HEADER_SIZE);
-
-    ret->unconsumed = ret->buffer;
-    ret->read_end = ret->buffer;
-    ret->buffer_end = ret->buffer + maxRecordLen + HEADER_SIZE;
-
-    return ret;
-}
-
-
-extern void record_stream_free(RecordStream *rs)
-{
-    free(rs->buffer);
-    free(rs);
-}
-
-
-/* returns NULL; if there isn't a full record in the buffer */
-static unsigned char * getEndOfRecord (unsigned char *p_begin,
-                                            unsigned char *p_end)
-{
-    size_t len;
-    unsigned char * p_ret;
-
-    if (p_end < p_begin + HEADER_SIZE) {
-        return NULL;
-    }
-
-    //First four bytes are length
-    len = ntohl(*((uint32_t *)p_begin));
-
-    p_ret = p_begin + HEADER_SIZE + len;
-
-    if (p_end < p_ret) {
-        return NULL;
-    }
-
-    return p_ret;
-}
-
-static void *getNextRecord (RecordStream *p_rs, size_t *p_outRecordLen)
-{
-    unsigned char *record_start, *record_end;
-
-    record_end = getEndOfRecord (p_rs->unconsumed, p_rs->read_end);
-
-    if (record_end != NULL) {
-        /* one full line in the buffer */
-        record_start = p_rs->unconsumed + HEADER_SIZE;
-        p_rs->unconsumed = record_end;
-
-        *p_outRecordLen = record_end - record_start;
-
-        return record_start;
-    }
-
-    return NULL;
-}
-
-/**
- * Reads the next record from stream fd
- * Records are prefixed by a 16-bit big endian length value
- * Records may not be larger than maxRecordLen
- *
- * Doesn't guard against EINTR
- *
- * p_outRecord and p_outRecordLen may not be NULL
- *
- * Return 0 on success, -1 on fail
- * Returns 0 with *p_outRecord set to NULL on end of stream
- * Returns -1 / errno = EAGAIN if it needs to read again
- */
-int record_stream_get_next (RecordStream *p_rs, void ** p_outRecord,
-                                    size_t *p_outRecordLen)
-{
-    void *ret;
-
-    ssize_t countRead;
-
-    /* is there one record already in the buffer? */
-    ret = getNextRecord (p_rs, p_outRecordLen);
-
-    if (ret != NULL) {
-        *p_outRecord = ret;
-        return 0;
-    }
-
-    // if the buffer is full and we don't have a full record
-    if (p_rs->unconsumed == p_rs->buffer
-        && p_rs->read_end == p_rs->buffer_end
-    ) {
-        // this should never happen
-        //ALOGE("max record length exceeded\n");
-        assert (0);
-        errno = EFBIG;
-        return -1;
-    }
-
-    if (p_rs->unconsumed != p_rs->buffer) {
-        // move remainder to the beginning of the buffer
-        size_t toMove;
-
-        toMove = p_rs->read_end - p_rs->unconsumed;
-        if (toMove) {
-            memmove(p_rs->buffer, p_rs->unconsumed, toMove);
-        }
-
-        p_rs->read_end = p_rs->buffer + toMove;
-        p_rs->unconsumed = p_rs->buffer;
-    }
-
-    countRead = read (p_rs->fd, p_rs->read_end, p_rs->buffer_end - p_rs->read_end);
-
-    if (countRead <= 0) {
-        /* note: end-of-stream drops through here too */
-        *p_outRecord = NULL;
-        return countRead;
-    }
-
-    p_rs->read_end += countRead;
-
-    ret = getNextRecord (p_rs, p_outRecordLen);
-
-    if (ret == NULL) {
-        /* not enough of a buffer to for a whole command */
-        errno = EAGAIN;
-        return -1;
-    }
-
-    *p_outRecord = ret;
-    return 0;
-}
diff --git a/radio/rild/Android.bp b/radio/rild/Android.bp
index 07348fdb..7a90c015 100644
--- a/radio/rild/Android.bp
+++ b/radio/rild/Android.bp
@@ -35,8 +35,7 @@ cc_binary {
         "liblog",
         "libril-modem-lib",
     ],
-    // Temporary hack for broken vendor RILs.
-    whole_static_libs: ["librilutils-goldfish-fork"],
+    header_libs: ["goldfish_ril_headers"],
     relative_install_path: "hw",
     proprietary: true,
     overrides: ["rild"],
diff --git a/radio/rild/rild_goldfish.c b/radio/rild/rild_goldfish.c
index f50db36c..574457ca 100644
--- a/radio/rild/rild_goldfish.c
+++ b/radio/rild/rild_goldfish.c
@@ -33,7 +33,6 @@
 #include <sys/prctl.h>
 #include <sys/stat.h>
 #include <sys/types.h>
-#include <libril/ril_ex.h>
 
 #if defined(PRODUCT_COMPATIBLE_PROPERTY)
 #define LIB_PATH_PROPERTY   "vendor.rild.libpath"
@@ -49,6 +48,11 @@ static void usage(const char *argv0) {
     exit(EXIT_FAILURE);
 }
 
+typedef enum {
+    RIL_TELEPHONY_SOCKET,
+    RIL_SAP_SOCKET
+} RIL_SOCKET_TYPE;
+
 extern char ril_service_name_base[MAX_SERVICE_NAME_LENGTH];
 extern char ril_service_name[MAX_SERVICE_NAME_LENGTH];
 
diff --git a/radio/rild/rild_goldfish.legacy.rc b/radio/rild/rild_goldfish.legacy.rc
deleted file mode 100644
index 6d2027c1..00000000
--- a/radio/rild/rild_goldfish.legacy.rc
+++ /dev/null
@@ -1,5 +0,0 @@
-service ril-daemon /vendor/bin/hw/libgoldfish-rild
-    class main
-    user radio
-    group radio cache inet misc audio log readproc wakelock
-    capabilities BLOCK_SUSPEND NET_ADMIN NET_RAW
diff --git a/rro_overlays/UwbOverlay/res/values/config.xml b/rro_overlays/UwbOverlay/res/values/config.xml
index 93401b41..1063d8a5 100644
--- a/rro_overlays/UwbOverlay/res/values/config.xml
+++ b/rro_overlays/UwbOverlay/res/values/config.xml
@@ -15,4 +15,8 @@
 -->
 <resources>
   <bool name="is_multicast_list_update_ntf_v2_supported">true</bool>
+
+  <!-- Whether multicast list update response v2 is supported or not.
+  If enabled, the response will be parsed into version 2 if uci major version is 2.0. -->
+  <bool name = "is_multicast_list_update_rsp_v2_supported">true</bool>
 </resources>
\ No newline at end of file
diff --git a/sepolicy/vendor/file_contexts b/sepolicy/vendor/file_contexts
index c3860980..6c250670 100644
--- a/sepolicy/vendor/file_contexts
+++ b/sepolicy/vendor/file_contexts
@@ -46,7 +46,6 @@
 /vendor/bin/hw/android\.hardware\.drm-service\.widevine    u:object_r:hal_drm_widevine_exec:s0
 /vendor/bin/hw/android\.hardware\.drm-service-lazy\.widevine    u:object_r:hal_drm_widevine_exec:s0
 /vendor/bin/hw/android\.hardware\.drm-service\.clearkey          u:object_r:hal_drm_clearkey_exec:s0
-/vendor/bin/hw/android\.hardware\.gatekeeper@1\.0-service.software    u:object_r:hal_gatekeeper_default_exec:s0
 /vendor/bin/hw/android\.hardware\.thermal@2\.0-service.mock           u:object_r:hal_thermal_default_exec:s0
 /vendor/bin/hw/android\.hardware\.authsecret-service\.example  u:object_r:hal_authsecret_default_exec:s0
 /vendor/bin/hw/android\.hardware\.power\.stats-service\.example  u:object_r:hal_power_stats_default_exec:s0
diff --git a/sepolicy/vendor/keystore.te b/sepolicy/vendor/keystore.te
new file mode 100644
index 00000000..287151b5
--- /dev/null
+++ b/sepolicy/vendor/keystore.te
@@ -0,0 +1 @@
+hal_client_domain(keystore, hal_gatekeeper)
diff --git a/sepolicy/vendor/service_contexts b/sepolicy/vendor/service_contexts
index d15d9f9b..dfd09f5e 100644
--- a/sepolicy/vendor/service_contexts
+++ b/sepolicy/vendor/service_contexts
@@ -3,6 +3,7 @@ android.hardware.camera.provider.ICameraProvider/internal/1 u:object_r:hal_camer
 android.hardware.neuralnetworks.IDevice/nnapi-sample_all u:object_r:hal_neuralnetworks_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_quant    u:object_r:hal_neuralnetworks_service:s0
 android.hardware.neuralnetworks.IDevice/nnapi-sample_sl_shim  u:object_r:hal_neuralnetworks_service:s0
+android.hardware.security.sharedsecret.ISharedSecret/gatekeeper u:object_r:hal_gatekeeper_service:s0
 # see https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/mapper/stable-c
 mapper/minigbm u:object_r:hal_graphics_mapper_service:s0
 mapper/ranchu u:object_r:hal_graphics_mapper_service:s0
diff --git a/slim/FakeSystemApp/src/com/android/fakesystemapp/systemui/SlimMediaProjectionPermissionActivity.java b/slim/FakeSystemApp/src/com/android/fakesystemapp/systemui/SlimMediaProjectionPermissionActivity.java
index 88de46ec..882123bd 100644
--- a/slim/FakeSystemApp/src/com/android/fakesystemapp/systemui/SlimMediaProjectionPermissionActivity.java
+++ b/slim/FakeSystemApp/src/com/android/fakesystemapp/systemui/SlimMediaProjectionPermissionActivity.java
@@ -33,6 +33,7 @@ import android.os.RemoteException;
 import android.os.ServiceManager;
 import android.text.TextPaint;
 import android.util.Log;
+import android.view.Display;
 import android.view.Window;
 import android.view.WindowManager;
 
@@ -146,7 +147,7 @@ public class SlimMediaProjectionPermissionActivity extends Activity implements D
     private Intent getMediaProjectionIntent(int uid, String packageName)
             throws RemoteException {
         IMediaProjection projection = mService.createProjection(uid, packageName,
-                MediaProjectionManager.TYPE_SCREEN_CAPTURE, false /* permanentGrant */);
+                MediaProjectionManager.TYPE_SCREEN_CAPTURE, false /* permanentGrant */, Display.DEFAULT_DISPLAY);
         Intent intent = new Intent();
         intent.putExtra(MediaProjectionManager.EXTRA_MEDIA_PROJECTION, projection.asBinder());
         return intent;
diff --git a/tablet/overlay/frameworks/base/core/res/res/values/config.xml b/tablet/overlay/frameworks/base/core/res/res/values/config.xml
index 08cbf925..91c7c9c3 100644
--- a/tablet/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/tablet/overlay/frameworks/base/core/res/res/values/config.xml
@@ -45,14 +45,6 @@
     <!-- This device is able to support the microphone and camera global toggles. -->
     <bool name="config_supportsMicToggle">true</bool>
     <bool name="config_supportsCamToggle">true</bool>
-    <!-- Specifies priority of automatic time sources. Suggestions from higher entries in the list
-         take precedence over lower ones.
-         See com.android.server.timedetector.TimeDetectorStrategy for available sources. -->
-    <string-array name="config_autoTimeSourcesPriority">
-        <item>telephony</item>
-        <item>network</item>
-    </string-array>
-
 
     <bool name="config_supportMicNearUltrasound">true</bool>
     <bool name="config_supportSpeakerNearUltrasound">true</bool>
diff --git a/wifi/Android.mk b/wifi/Android.mk
deleted file mode 100644
index 196594a0..00000000
--- a/wifi/Android.mk
+++ /dev/null
@@ -1,20 +0,0 @@
-#
-# Copyright 2016 The Android Open-Source Project
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
-LOCAL_PATH:= $(call my-dir)
-
-include $(CLEAR_VARS)
-include $(call all-makefiles-under,$(LOCAL_PATH))
diff --git a/wifi/wpa_supplicant_8_lib/Android.bp b/wifi/wpa_supplicant_8_lib/Android.bp
new file mode 100644
index 00000000..c0c63d6b
--- /dev/null
+++ b/wifi/wpa_supplicant_8_lib/Android.bp
@@ -0,0 +1,63 @@
+//
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
+//
+
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "device_generic_goldfish_wifi_wpa_supplicant_8_lib_license",
+    ],
+}
+
+license {
+    name: "device_generic_goldfish_wifi_wpa_supplicant_8_lib_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-BSD",
+    ],
+}
+
+cc_library_static {
+    name: "lib_driver_cmd_simulated",
+    shared_libs: [
+        "libc",
+        "libcutils",
+        "liblog",
+    ],
+    header_libs: [
+        "libcutils_headers",
+    ],
+    cflags: [
+        "-DCONFIG_ANDROID_LOG",
+        "-Wno-unused-parameter",
+    ],
+    srcs: [
+        "driver_cmd_nl80211.c",
+    ],
+    include_dirs: [
+        "external/libnl/include",
+        "external/wpa_supplicant_8/src",
+        "external/wpa_supplicant_8/src/common",
+        "external/wpa_supplicant_8/src/drivers",
+        "external/wpa_supplicant_8/src/l2_packet",
+        "external/wpa_supplicant_8/src/utils",
+        "external/wpa_supplicant_8/src/wps",
+        "external/wpa_supplicant_8/wpa_supplicant",
+    ],
+    vendor: true,
+    defaults: [
+        "wpa_supplicant_cflags_default",
+    ],
+}
diff --git a/wifi/wpa_supplicant_8_lib/Android.mk b/wifi/wpa_supplicant_8_lib/Android.mk
deleted file mode 100644
index 4c565d41..00000000
--- a/wifi/wpa_supplicant_8_lib/Android.mk
+++ /dev/null
@@ -1,85 +0,0 @@
-#
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
-#
-LOCAL_PATH := $(call my-dir)
-
-ifeq ($(WPA_SUPPLICANT_VERSION),VER_0_8_X)
-
-ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),)
-  CONFIG_DRIVER_$(BOARD_WPA_SUPPLICANT_DRIVER) := y
-endif
-
-# Use a custom libnl on releases before N
-ifeq (0, $(shell test $(PLATFORM_SDK_VERSION) -lt 24; echo $$?))
-EXTERNAL_GCE_LIBNL_INCLUDE := external/gce/libnl/include
-else
-EXTERNAL_GCE_LIBNL_INCLUDE :=
-endif
-
-
-WPA_SUPPL_DIR = external/wpa_supplicant_8
-WPA_SRC_FILE :=
-
-include $(WPA_SUPPL_DIR)/wpa_supplicant/android.config
-
-WPA_SUPPL_DIR_INCLUDE = $(WPA_SUPPL_DIR)/src \
-	$(WPA_SUPPL_DIR)/src/common \
-	$(WPA_SUPPL_DIR)/src/drivers \
-	$(WPA_SUPPL_DIR)/src/l2_packet \
-	$(WPA_SUPPL_DIR)/src/utils \
-	$(WPA_SUPPL_DIR)/src/wps \
-	$(WPA_SUPPL_DIR)/wpa_supplicant \
-	$(EXTERNAL_GCE_LIBNL_INCLUDE)
-
-WPA_SUPPL_DIR_INCLUDE += external/libnl/include
-
-ifdef CONFIG_DRIVER_NL80211
-WPA_SRC_FILE += driver_cmd_nl80211.c
-endif
-
-ifeq ($(TARGET_ARCH),arm)
-# To force sizeof(enum) = 4
-L_CFLAGS += -mabi=aapcs-linux
-endif
-
-ifdef CONFIG_ANDROID_LOG
-L_CFLAGS += -DCONFIG_ANDROID_LOG
-endif
-
-L_CFLAGS += -Wno-unused-parameter
-
-########################
-
-include $(CLEAR_VARS)
-LOCAL_MODULE := lib_driver_cmd_simulated
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-BSD
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_VENDOR_MODULE := true
-LOCAL_SHARED_LIBRARIES := libc libcutils liblog
-LOCAL_HEADER_LIBRARIES := libcutils_headers
-
-LOCAL_CFLAGS := $(L_CFLAGS) \
-    $(GCE_VERSION_CFLAGS)
-
-LOCAL_SRC_FILES := $(WPA_SRC_FILE)
-
-LOCAL_C_INCLUDES := \
-  $(WPA_SUPPL_DIR_INCLUDE)\
-
-include $(BUILD_STATIC_LIBRARY)
-
-########################
-
-endif
```

