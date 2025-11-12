```diff
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index b6e8475..ef228ee 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -15,24 +15,14 @@
 #
 
 PRODUCT_MAKEFILES := \
-    $(LOCAL_DIR)/bluejay_car/aosp_bluejay_car.mk \
     $(LOCAL_DIR)/cheetah_car/aosp_cheetah_car.mk \
-    $(LOCAL_DIR)/oriole_car/aosp_oriole_car.mk \
     $(LOCAL_DIR)/panther_car/aosp_panther_car.mk \
-    $(LOCAL_DIR)/raven_car/aosp_raven_car.mk \
-    $(LOCAL_DIR)/redfin_car/aosp_redfin_car.mk \
-    $(LOCAL_DIR)/sunfish_car/aosp_sunfish_car.mk \
     $(LOCAL_DIR)/husky_car/aosp_husky_car.mk \
     $(LOCAL_DIR)/tangorpro_car/aosp_tangorpro_car.mk
 
 
 COMMON_LUNCH_CHOICES := \
-    aosp_bluejay_car-trunk_staging-userdebug \
     aosp_cheetah_car-trunk_staging-userdebug \
-    aosp_oriole_car-trunk_staging-userdebug \
     aosp_panther_car-trunk_staging-userdebug \
-    aosp_raven_car-trunk_staging-userdebug \
-    aosp_redfin_car-trunk_staging-userdebug \
-    aosp_sunfish_car-trunk_staging-userdebug \
     aosp_husky_car-trunk_staging-userdebug \
     aosp_tangorpro_car-trunk_staging-userdebug
diff --git a/bluejay_car/BoardConfig.mk b/bluejay_car/BoardConfig.mk
deleted file mode 100644
index 8a09d9a..0000000
--- a/bluejay_car/BoardConfig.mk
+++ /dev/null
@@ -1,22 +0,0 @@
-#
-# Copyright (C) 2022 The Android Open-Source Project
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
-# Contents of this file were copied from device/google/raviole/raven/BoardConfig.mk,
-# except for:
-#
-# * TARGET_SCREEN_DENSITY is scaled down by 1.75x
-
-TARGET_SCREEN_DENSITY ?= 240
diff --git a/bluejay_car/aosp_bluejay_car.mk b/bluejay_car/aosp_bluejay_car.mk
deleted file mode 100644
index 7ad665c..0000000
--- a/bluejay_car/aosp_bluejay_car.mk
+++ /dev/null
@@ -1,29 +0,0 @@
-#
-# Copyright 2022 The Android Open Source Project
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
-$(call inherit-product, device/google_car/common/pre_google_car.mk)
-$(call inherit-product, device/google_car/bluejay_car/device-bluejay-car.mk)
-$(call inherit-product-if-exists, vendor/google_devices/raviole/proprietary/raven/device-vendor-bluejay.mk)
-$(call inherit-product, device/google_car/common/post_google_car.mk)
-
-# Disable production validation checks to fix build error from bluejay.scl
-PRODUCT_VALIDATION_CHECKS :=
-
-PRODUCT_MANUFACTURER := Google
-PRODUCT_BRAND := Android
-PRODUCT_NAME := aosp_bluejay_car
-PRODUCT_DEVICE := bluejay
-PRODUCT_MODEL := AOSP on bluejay
diff --git a/bluejay_car/device-bluejay-car.mk b/bluejay_car/device-bluejay-car.mk
deleted file mode 100644
index a0da20e..0000000
--- a/bluejay_car/device-bluejay-car.mk
+++ /dev/null
@@ -1,24 +0,0 @@
-#
-# Copyright 2022 The Android Open Source Project
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
-PHONE_CAR_BOARD_PRODUCT := bluejay_car
-
-$(call inherit-product,device/google/bluejay/device-bluejay.mk)
-
-include device/google/gs101/uwb/uwb.mk
-
-PRODUCT_PRODUCT_PROPERTIES+= \
-    ro.adb.secure=0
diff --git a/common/post_google_car.mk b/common/post_google_car.mk
index 3bf6d86..64b1570 100644
--- a/common/post_google_car.mk
+++ b/common/post_google_car.mk
@@ -62,18 +62,35 @@ PRODUCT_PRODUCT_PROPERTIES += \
 # Explicitly disable support for some Bluetooth profiles included in base phone builds
 PRODUCT_PRODUCT_PROPERTIES += \
         bluetooth.profile.asha.central.enabled=false \
-        bluetooth.profile.bap.broadcast.assist.enabled=false \
-        bluetooth.profile.bap.unicast.client.enabled=false \
-        bluetooth.profile.bas.client.enabled=false \
-        bluetooth.profile.csip.set_coordinator.enabled=false \
-        bluetooth.profile.hap.client.enabled=false \
         bluetooth.profile.hfp.ag.enabled=false \
         bluetooth.profile.hid.device.enabled=false \
         bluetooth.profile.hid.host.enabled=false \
         bluetooth.profile.map.server.enabled=false \
-        bluetooth.profile.mcp.server.enabled=false \
         bluetooth.profile.opp.enabled=false \
         bluetooth.profile.pbap.server.enabled=false \
-        bluetooth.profile.sap.server.enabled=false \
-        bluetooth.profile.ccp.server.enabled=false \
-        bluetooth.profile.vcp.controller.enabled=false
+        bluetooth.profile.sap.server.enabled=false
+
+# Add 'GOOGLE_CAR_USE_LE_AUDIO := true' to allow LE Audio on a given Google Car target
+ifeq ($(GOOGLE_CAR_USE_LE_AUDIO), true)
+PRODUCT_PRODUCT_PROPERTIES += \
+        bluetooth.profile.bap.broadcast.assist.enabled=true \
+        bluetooth.profile.bap.broadcast.source.enabled=true \
+        bluetooth.profile.bap.unicast.client.enabled=true \
+        bluetooth.profile.bas.client.enabled=true \
+        bluetooth.profile.csip.set_coordinator.enabled=true \
+        bluetooth.profile.mcp.server.enabled=true \
+        bluetooth.profile.vcp.controller.enabled=true \
+        bluetooth.profile.hap.client.enabled=false \
+        bluetooth.profile.ccp.server.enabled=false
+else
+PRODUCT_PRODUCT_PROPERTIES += \
+        bluetooth.profile.bap.broadcast.assist.enabled=false \
+        bluetooth.profile.bap.broadcast.source.enabled=false \
+        bluetooth.profile.bap.unicast.client.enabled=false \
+        bluetooth.profile.bas.client.enabled=false \
+        bluetooth.profile.csip.set_coordinator.enabled=false \
+        bluetooth.profile.mcp.server.enabled=false \
+        bluetooth.profile.vcp.controller.enabled=false \
+        bluetooth.profile.hap.client.enabled=false \
+        bluetooth.profile.ccp.server.enabled=false
+endif
diff --git a/common/sepolicy/hal_audiocontrol_default.te b/common/sepolicy/hal_audiocontrol_default.te
new file mode 100644
index 0000000..3ec4f5f
--- /dev/null
+++ b/common/sepolicy/hal_audiocontrol_default.te
@@ -0,0 +1,2 @@
+# Enable audiocontrol to listen to power policy daemon.
+carpowerpolicy_callback_domain(hal_audiocontrol_default)
diff --git a/husky_car/aosp_husky_car.mk b/husky_car/aosp_husky_car.mk
index c96ea51..c51c5ef 100644
--- a/husky_car/aosp_husky_car.mk
+++ b/husky_car/aosp_husky_car.mk
@@ -17,6 +17,8 @@
 DEVICE_IS_64BIT_ONLY := true
 PIXEL_2023_GEN := true
 
+GOOGLE_CAR_USE_LE_AUDIO := true
+
 $(call inherit-product, device/google_car/common/pre_google_car.mk)
 $(call inherit-product, device/google_car/husky_car/device-husky-car.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
diff --git a/husky_car/device-husky-car.mk b/husky_car/device-husky-car.mk
index 55abbae..c47df29 100644
--- a/husky_car/device-husky-car.mk
+++ b/husky_car/device-husky-car.mk
@@ -16,7 +16,10 @@
 
 PHONE_CAR_BOARD_PRODUCT := husky_car
 
-$(call inherit-product, device/google/shusky/husky_generic.mk)
+$(call inherit-product, device/google_car/husky_car/device-husky.mk)
+
+# preloaded_nanoapps.json
+PRODUCT_SOONG_NAMESPACES += vendor/google_contexthub/devices/p23_common
 
 #include device/google/gs101/uwb/uwb.mk
 
diff --git a/husky_car/device-husky.mk b/husky_car/device-husky.mk
new file mode 100644
index 0000000..6641677
--- /dev/null
+++ b/husky_car/device-husky.mk
@@ -0,0 +1,549 @@
+#
+# Copyright (C) 2021 The Android Open-Source Project
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
+# Copied from device/google/shusky/ to resolve build failure of husky_car
+
+# Restrict the visibility of Android.bp files to improve build analysis time
+$(call inherit-product-if-exists, vendor/google/products/sources_pixel.mk)
+
+ifdef RELEASE_GOOGLE_HUSKY_RADIO_DIR
+RELEASE_GOOGLE_PRODUCT_RADIO_DIR := $(RELEASE_GOOGLE_HUSKY_RADIO_DIR)
+endif
+ifdef RELEASE_GOOGLE_HUSKY_RADIOCFG_DIR
+RELEASE_GOOGLE_PRODUCT_RADIOCFG_DIR := $(RELEASE_GOOGLE_HUSKY_RADIOCFG_DIR)
+endif
+RELEASE_GOOGLE_BOOTLOADER_HUSKY_DIR ?= pdk# Keep this for pdk TODO: b/327119000
+RELEASE_GOOGLE_PRODUCT_BOOTLOADER_DIR := bootloader/$(RELEASE_GOOGLE_BOOTLOADER_HUSKY_DIR)
+$(call soong_config_set,shusky_bootloader,prebuilt_dir,$(RELEASE_GOOGLE_BOOTLOADER_HUSKY_DIR))
+
+
+TARGET_LINUX_KERNEL_VERSION := $(RELEASE_KERNEL_HUSKY_VERSION)
+# Keeps flexibility for kasan and ufs builds
+TARGET_KERNEL_DIR ?= $(RELEASE_KERNEL_HUSKY_DIR)
+TARGET_BOARD_KERNEL_HEADERS ?= $(RELEASE_KERNEL_HUSKY_DIR)/kernel-headers
+
+LOCAL_PATH := device/google/shusky
+
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+    USE_UWBFIELDTESTQM := true
+endif
+ifeq ($(filter factory_husky, $(TARGET_PRODUCT)),)
+    include device/google/shusky/uwb/uwb_calibration.mk
+endif
+
+ifneq ($(TARGET_BOOTS_16K),true)
+PRODUCT_16K_DEVELOPER_OPTION := $(RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION)
+endif
+
+$(call inherit-product-if-exists, vendor/google_devices/shusky/prebuilts/device-vendor-husky.mk)
+$(call inherit-product-if-exists, vendor/google_devices/zuma/prebuilts/device-vendor.mk)
+$(call inherit-product-if-exists, vendor/google_devices/zuma/proprietary/device-vendor.mk)
+$(call inherit-product-if-exists, vendor/google_devices/shusky/proprietary/husky/device-vendor-husky.mk)
+$(call inherit-product-if-exists, vendor/google_devices/husky/proprietary/device-vendor.mk)
+$(call inherit-product-if-exists, vendor/qorvo/uwb/qm35-hal/Device.mk)
+$(call inherit-product-if-exists, vendor/google_devices/shusky/proprietary/WallpapersHusky.mk)
+
+# display
+DEVICE_PACKAGE_OVERLAYS += device/google/shusky/husky/overlay
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += ro.surface_flinger.ignore_hdr_camera_layers=true
+
+PRODUCT_COPY_FILES += \
+	device/google/shusky/husky/display_colordata_dev_cal0.pb:$(TARGET_COPY_OUT_VENDOR)/etc/display_colordata_dev_cal0.pb \
+    device/google/shusky/husky/display_golden_google-hk3_cal0.pb:$(TARGET_COPY_OUT_VENDOR)/etc/display_golden_google-hk3_cal0.pb \
+    device/google/shusky/display_golden_external_display_cal2.pb:$(TARGET_COPY_OUT_VENDOR)/etc/display_golden_external_display_cal2.pb
+
+CAMERA_PRODUCT ?= husky
+
+ifeq ($(RELEASE_PIXEL_AIDL_AUDIO_HAL_ZUMA),true)
+USE_AUDIO_HAL_AIDL := true
+endif
+
+include device/google/shusky/camera/camera.mk
+include device/google/shusky/audio/husky/audio-tables.mk
+include device/google/zuma/device-shipping-common.mk
+include device/google/gs-common/bcmbt/bluetooth.mk
+include device/google/gs-common/touch/stm/predump_stm20.mk
+include device/google/gs-common/touch/gti/predump_gti.mk
+include device/google/gs-common/touch/touchinspector/touchinspector.mk
+
+# Init files
+PRODUCT_COPY_FILES += \
+	device/google/shusky/conf/init.husky.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.husky.rc
+
+# Recovery files
+PRODUCT_COPY_FILES += \
+        device/google/shusky/conf/init.recovery.device.rc:$(TARGET_COPY_OUT_RECOVERY)/root/init.recovery.husky.rc
+
+# MIPI Coex Configs
+PRODUCT_COPY_FILES += \
+        device/google/shusky/husky/radio/husky_camera_front_dbr_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/camera_front_dbr_coex_table.csv \
+        device/google/shusky/husky/radio/husky_camera_front_mipi_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/camera_front_mipi_coex_table.csv \
+        device/google/shusky/husky/radio/husky_camera_rear_tele_mipi_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/camera_rear_tele_mipi_coex_table.csv \
+        device/google/shusky/husky/radio/husky_display_primary_mipi_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/display_primary_mipi_coex_table.csv
+
+# NFC
+PRODUCT_COPY_FILES += \
+	frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.xml \
+	frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hce.xml \
+	frameworks/native/data/etc/android.hardware.nfc.hcef.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hcef.xml \
+	frameworks/native/data/etc/com.nxp.mifare.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/com.nxp.mifare.xml \
+	frameworks/native/data/etc/android.hardware.nfc.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.ese.xml \
+	device/google/shusky/nfc/libnfc-hal-st.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf \
+	device/google/shusky/nfc/libnfc-nci.conf:$(TARGET_COPY_OUT_PRODUCT)/etc/libnfc-nci.conf
+
+PRODUCT_PACKAGES += \
+	$(RELEASE_PACKAGE_NFC_STACK) \
+	Tag \
+	android.hardware.nfc-service.st
+
+# SecureElement
+PRODUCT_PACKAGES += \
+	android.hardware.secure_element-service.thales
+
+PRODUCT_COPY_FILES += \
+	frameworks/native/data/etc/android.hardware.se.omapi.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.ese.xml \
+	frameworks/native/data/etc/android.hardware.se.omapi.uicc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.uicc.xml \
+	device/google/shusky/nfc/libse-gto-hal.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libse-gto-hal.conf
+
+# Bluetooth HAL
+PRODUCT_COPY_FILES += \
+	device/google/shusky/bluetooth/bt_vendor_overlay.conf:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth/bt_vendor_overlay.conf
+PRODUCT_PROPERTY_OVERRIDES += \
+    ro.bluetooth.a2dp_offload.supported=true \
+    persist.bluetooth.a2dp_offload.disabled=false \
+    persist.bluetooth.a2dp_offload.cap=sbc-aac-aptx-aptxhd-ldac-opus
+
+# Enable Bluetooth AutoOn feature
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.server.automatic_turn_on=true
+
+# Bluetooth Tx power caps
+PRODUCT_COPY_FILES += \
+    $(LOCAL_PATH)/bluetooth/bluetooth_power_limits_husky.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits.csv \
+    $(LOCAL_PATH)/bluetooth/bluetooth_power_limits_husky_CA.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_CA.csv \
+    $(LOCAL_PATH)/bluetooth/bluetooth_power_limits_husky_EU.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_EU.csv \
+    $(LOCAL_PATH)/bluetooth/bluetooth_power_limits_husky_JP.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_JP.csv \
+    $(LOCAL_PATH)/bluetooth/bluetooth_power_limits_husky_US.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_US.csv \
+    $(LOCAL_PATH)/bluetooth/bluetooth_power_limits_husky_GC3VE_EU.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_GC3VE_EU.csv
+
+# POF
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.bluetooth.finder.supported=true
+
+ifeq ($(USE_AUDIO_HAL_AIDL),true)
+# AIDL
+
+else
+# HIDL
+
+# Spatial Audio
+PRODUCT_PACKAGES += \
+	libspatialaudio
+
+# Sound Dose
+PRODUCT_PACKAGES += \
+	android.hardware.audio.sounddose-vendor-impl \
+	audio_sounddose_aoc
+
+endif
+
+# declare use of spatial audio
+PRODUCT_PROPERTY_OVERRIDES += \
+	ro.audio.spatializer_enabled=true
+
+# HdMic Audio
+PRODUCT_SOONG_NAMESPACES += device/google/shusky/audio/husky/prebuilt/libspeechenhancer
+PRODUCT_PROPERTY_OVERRIDES += \
+    persist.vendor.app.audio.gsenet.version=1
+PRODUCT_PACKAGES += \
+    libspeechenhancer
+
+# Audio CCA property
+PRODUCT_PROPERTY_OVERRIDES += \
+	persist.vendor.audio.cca.enabled=false
+
+# DCK properties based on target
+PRODUCT_PROPERTY_OVERRIDES += \
+    ro.gms.dck.eligible_wcc=3 \
+    ro.gms.dck.se_capability=1
+
+# Bluetooth hci_inject test tool
+PRODUCT_PACKAGES_DEBUG += \
+    hci_inject
+
+# Bluetooth OPUS codec
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.opus.enabled=true
+
+# Bluetooth SAR test tool
+PRODUCT_PACKAGES_DEBUG += \
+    sar_test
+
+# Bluetooth EWP test tool
+PRODUCT_PACKAGES_DEBUG += \
+    ewp_tool
+
+# Bluetooth AAC VBR
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.a2dp_aac.vbr_supported=true
+
+# Override BQR mask to enable LE Audio Choppy report, remove BTRT logging
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.bqr.event_mask=295262 \
+    persist.bluetooth.bqr.vnd_quality_mask=29 \
+    persist.bluetooth.bqr.vnd_trace_mask=0 \
+    persist.bluetooth.vendor.btsnoop=true
+else
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.bqr.event_mask=295262 \
+    persist.bluetooth.bqr.vnd_quality_mask=16 \
+    persist.bluetooth.bqr.vnd_trace_mask=0 \
+    persist.bluetooth.vendor.btsnoop=false
+endif
+
+# Spatial Audio
+PRODUCT_PACKAGES += \
+	libspatialaudio \
+	librondo
+
+# Bluetooth Super Wide Band
+PRODUCT_PRODUCT_PROPERTIES += \
+	bluetooth.hfp.swb.supported=true
+
+# Bluetooth LE Audio
+PRODUCT_PRODUCT_PROPERTIES += \
+	ro.bluetooth.leaudio_switcher.supported?=true \
+	bluetooth.profile.bap.unicast.client.enabled?=true \
+	bluetooth.profile.csip.set_coordinator.enabled?=true \
+	bluetooth.profile.hap.client.enabled?=true \
+	bluetooth.profile.mcp.server.enabled?=true \
+	bluetooth.profile.ccp.server.enabled?=true \
+	bluetooth.profile.vcp.controller.enabled?=true
+
+# Bluetooth LE Audio Broadcast
+PRODUCT_PRODUCT_PROPERTIES += \
+	bluetooth.profile.bap.broadcast.assist.enabled?=true \
+	bluetooth.profile.bap.broadcast.source.enabled?=true
+
+# Bluetooth LE Audio enable hardware offloading
+PRODUCT_PRODUCT_PROPERTIES += \
+	ro.bluetooth.leaudio_offload.supported=true \
+	persist.bluetooth.leaudio_offload.disabled=false
+
+# Bluetooth LE Auido offload capabilities setting
+PRODUCT_COPY_FILES += \
+	device/google/shusky/bluetooth/le_audio_codec_capabilities.xml:$(TARGET_COPY_OUT_VENDOR)/etc/le_audio_codec_capabilities.xml
+
+# LE Audio Unicast Allowlist
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.leaudio.allow_list=SM-R510,WF-1000XM5,SM-R630,G2,AG2,WH-1000XM6
+
+# Bluetooth LE Audio CIS handover to SCO
+# Set the property only for the controller couldn't support CIS/SCO simultaneously. More detailed in b/242908683.
+PRODUCT_PRODUCT_PROPERTIES += \
+	persist.bluetooth.leaudio.notify.idle.during.call=true
+
+# Support LE Audio dual mic SWB call
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.leaudio.dual_bidirection_swb.supported=true
+
+# Disable Bluetooth HAP by default
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.profile.hap.enabled_by_default=false
+
+# Support LE & Classic concurrent encryption (b/330704060)
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.ble.allow_enc_with_bredr=true
+
+# Support One-Handed mode
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.support_one_handed_mode=true
+
+# Keymaster HAL
+#LOCAL_KEYMASTER_PRODUCT_PACKAGE ?= android.hardware.keymaster@4.1-service
+
+# Gatekeeper HAL
+#LOCAL_GATEKEEPER_PRODUCT_PACKAGE ?= android.hardware.gatekeeper@1.0-service.software
+
+
+# Gatekeeper
+# PRODUCT_PACKAGES += \
+# 	android.hardware.gatekeeper@1.0-service.software
+
+# Keymint replaces Keymaster
+# PRODUCT_PACKAGES += \
+# 	android.hardware.security.keymint-service
+
+# Keymaster
+#PRODUCT_PACKAGES += \
+#	android.hardware.keymaster@4.0-impl \
+#	android.hardware.keymaster@4.0-service
+
+#PRODUCT_PACKAGES += android.hardware.keymaster@4.0-service.remote
+#PRODUCT_PACKAGES += android.hardware.keymaster@4.1-service.remote
+#LOCAL_KEYMASTER_PRODUCT_PACKAGE := android.hardware.keymaster@4.1-service
+#LOCAL_KEYMASTER_PRODUCT_PACKAGE ?= android.hardware.keymaster@4.1-service
+
+# PRODUCT_PROPERTY_OVERRIDES += \
+# 	ro.hardware.keystore_desede=true \
+# 	ro.hardware.keystore=software \
+# 	ro.hardware.gatekeeper=software
+
+# PowerStats HAL
+PRODUCT_SOONG_NAMESPACES += \
+    device/google/shusky/powerstats/husky \
+
+# WiFi Overlay
+PRODUCT_PACKAGES += \
+	UwbOverlayHK3 \
+	UwbOverlayHK3Gsi \
+	WifiOverlay2023 \
+	PixelWifiOverlay2023
+
+# Trusty liboemcrypto.so
+PRODUCT_SOONG_NAMESPACES += vendor/google_devices/shusky/prebuilts
+
+# UWB
+PRODUCT_SOONG_NAMESPACES += \
+    device/google/shusky/uwb
+
+# Location
+# SDK build system
+include device/google/gs-common/gps/brcm/device.mk
+
+PRODUCT_COPY_FILES += \
+       device/google/shusky/location/gps.cer:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/gps.cer
+
+# Location
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+    PRODUCT_COPY_FILES += \
+        device/google/shusky/location/lhd.conf:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/lhd.conf \
+        device/google/shusky/location/scd.conf:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/scd.conf \
+        device/google/shusky/location/gps.6.1.xml.hk3:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/gps.xml
+else
+    PRODUCT_COPY_FILES += \
+        device/google/shusky/location/lhd_user.conf:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/lhd.conf \
+        device/google/shusky/location/scd_user.conf:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/scd.conf \
+        device/google/shusky/location/gps_user.6.1.xml.hk3:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/gps.xml
+endif
+
+# Set zram size
+PRODUCT_VENDOR_PROPERTIES += \
+	vendor.zram.size=50p \
+	persist.device_config.configuration.disable_rescue_party=true
+
+# Fingerprint HAL
+GOODIX_CONFIG_BUILD_VERSION := g7_trusty
+APEX_FPS_TA_DIR := //vendor/google_devices/shusky/prebuilts
+$(call inherit-product-if-exists, vendor/goodix/udfps/configuration/udfps_common.mk)
+ifeq ($(filter factory%, $(TARGET_PRODUCT)),)
+$(call inherit-product-if-exists, vendor/goodix/udfps/configuration/udfps_shipping.mk)
+else
+$(call inherit-product-if-exists, vendor/goodix/udfps/configuration/udfps_factory.mk)
+endif
+
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.udfps.als_feed_forward_supported=true \
+    persist.vendor.udfps.lhbm_controlled_in_hal_supported=true
+
+# Fingerprint exposure compensation
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.udfps.auto_exposure_compensation_supported=true
+
+# Camera Vendor property
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.camera.front_720P_always_binning=true
+
+# Media Performance Class 14
+PRODUCT_PRODUCT_PROPERTIES += ro.odm.build.media_performance_class=34
+
+# config of display brightness dimming
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.display.0.brightness.dimming.usage?=1
+PRODUCT_VENDOR_PROPERTIES += \
+    vendor.primarydisplay.op.hs_hz=120 \
+    vendor.primarydisplay.op.ns_hz=60 \
+    vendor.primarydisplay.op.ns_min_dbv=1172
+
+# kernel idle timer for display driver
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += ro.surface_flinger.support_kernel_idle_timer=true
+
+# lhbm peak brightness delay: decided by kernel
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.primarydisplay.lhbm.frames_to_reach_peak_brightness=0
+
+# Display LBE
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.display.lbe.supported=1
+
+# blocking zone for min idle refresh rate
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.vendor.primarydisplay.blocking_zone.min_refresh_rate_by_nits=15:10,:1
+
+# Display ACL
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.display.0.brightness.acl.default=0
+
+# display color data
+PRODUCT_COPY_FILES += \
+	device/google/shusky/husky/panel_config_google-hk3_cal0.pb:$(TARGET_COPY_OUT_VENDOR)/etc/panel_config_google-hk3_cal0.pb
+
+# Vibrator HAL
+$(call soong_config_set,haptics,kernel_ver,v$(subst .,_,$(TARGET_LINUX_KERNEL_VERSION))_fw7_2_91)
+ACTUATOR_MODEL := luxshare_ict_081545
+ADAPTIVE_HAPTICS_FEATURE := adaptive_haptics_v1
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.vibrator.hal.chirp.enabled=0 \
+    ro.vendor.vibrator.hal.device.mass=0.222 \
+    ro.vendor.vibrator.hal.loc.coeff=2.8 \
+    persist.vendor.vibrator.hal.context.enable=false \
+    persist.vendor.vibrator.hal.context.scale=60 \
+    persist.vendor.vibrator.hal.context.fade=true \
+    persist.vendor.vibrator.hal.context.cooldowntime=1600 \
+    persist.vendor.vibrator.hal.context.settlingtime=5000
+
+# Override Output Distortion Gain
+PRODUCT_VENDOR_PROPERTIES += \
+    vendor.audio.hapticgenerator.distortion.output.gain=0.38
+
+# Increment the SVN for any official public releases
+ifdef RELEASE_SVN_HUSKY
+TARGET_SVN ?= $(RELEASE_SVN_HUSKY)
+else
+# Set this for older releases that don't use build flag
+TARGET_SVN ?= 38
+endif
+
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.vendor.build.svn=$(TARGET_SVN)
+
+# Set device family property for SMR
+PRODUCT_PROPERTY_OVERRIDES += \
+    ro.build.device_family=HK3SB3AK3
+
+# Set build properties for SMR builds
+ifeq ($(RELEASE_IS_SMR), true)
+    ifneq (,$(RELEASE_BASE_OS_HUSKY))
+        PRODUCT_BASE_OS := $(RELEASE_BASE_OS_HUSKY)
+    endif
+endif
+
+# Set build properties for EMR builds
+ifeq ($(RELEASE_IS_EMR), true)
+    ifneq (,$(RELEASE_BASE_OS_HUSKY))
+        PRODUCT_PROPERTY_OVERRIDES += \
+        ro.build.version.emergency_base_os=$(RELEASE_BASE_OS_HUSKY)
+    endif
+endif
+# WLC userdebug specific
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+    PRODUCT_COPY_FILES += \
+        device/google/zuma/init.hardware.wlc.rc.userdebug:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.wlc.rc
+endif
+
+# Setup Wizard device-specific settings
+PRODUCT_PRODUCT_PROPERTIES += \
+    setupwizard.feature.enable_quick_start_flow=true \
+
+# Quick Start device-specific settings
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.quick_start.oem_id=00e0 \
+    ro.quick_start.device_id=husky
+
+# PKVM Memory Reclaim
+PRODUCT_VENDOR_PROPERTIES += \
+    hypervisor.memory_reclaim.supported=1
+
+# P23 Devices no longer need rlsservice
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.camera.rls_supported=false
+
+# Settings Overlay
+PRODUCT_PACKAGES += \
+    SettingsHuskyOverlay
+
+# Display RRS default Config
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += persist.vendor.display.primary.boot_config=1008x2244@120
+# TODO: b/250788756 - the property will be phased out after HWC loads user-preferred mode
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.display.preferred_mode=1008x2244@120
+
+# Window Extensions
+$(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions.mk)
+
+# To resolve build failure, comment out this
+# Disable Settings large-screen optimization enabled by Window Extensions
+#PRODUCT_SYSTEM_PROPERTIES += \
+#    persist.settings.large_screen_opt.enabled=false
+
+# Keyboard height ratio and bottom padding in dp for portrait mode
+PRODUCT_PRODUCT_PROPERTIES += \
+         ro.com.google.ime.kb_pad_port_b=10.4
+
+PRODUCT_PRODUCT_PROPERTIES ?= \
+    ro.com.google.ime.height_ratio=1.0
+
+# Enable camera exif model/make reporting
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.camera.exif_reveal_make_model=true
+
+# Enable DeviceAsWebcam support
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.usb.uvc.enabled=true
+
+PRODUCT_PACKAGES += \
+	NfcOverlayHusky \
+
+# Set support hide display cutout feature
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.support_hide_display_cutout=true
+
+PRODUCT_PACKAGES += \
+    NoCutoutOverlay \
+    AvoidAppsInCutoutOverlay
+
+# ETM
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+$(call inherit-product-if-exists, device/google/common/etm/device-userdebug-modules.mk)
+endif
+
+PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true
+
+ifneq ($(wildcard vendor/arm/mali/valhall),)
+PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE := true
+endif
+
+# Bluetooth device id
+# Husky: 0x410D
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.device_id.product_id=16653
+
+# Set support for LEA multicodec
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.core.le_audio.codec_extension_aidl.enabled=true
+
+# LE Audio configuration scenarios
+PRODUCT_COPY_FILES += \
+    device/google/shusky/bluetooth/audio_set_scenarios.json:$(TARGET_COPY_OUT_VENDOR)/etc/aidl/le_audio/aidl_audio_set_scenarios.json
+
+PRODUCT_COPY_FILES += \
+    device/google/shusky/bluetooth/audio_set_configurations.json:$(TARGET_COPY_OUT_VENDOR)/etc/aidl/le_audio/aidl_audio_set_configurations.json
+
+# Enable APF by default
+PRODUCT_VENDOR_PROPERTIES += \
+    vendor.powerhal.apf_disabled=false \
+    vendor.powerhal.apf_enabled=true
+
+# PDK does not use build flags
+ifeq ($(USE_GOOGLE_CARRIER_SETTINGS), true)
+    $(call soong_config_set,carrier_settings,gs_common_paris_assets_path,paris_data_y25q2/latest/pixel2023)
+endif
diff --git a/oriole_car/BoardConfig.mk b/oriole_car/BoardConfig.mk
deleted file mode 100644
index b60da91..0000000
--- a/oriole_car/BoardConfig.mk
+++ /dev/null
@@ -1,22 +0,0 @@
-#
-# Copyright (C) 2021 The Android Open-Source Project
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
-# Contents of this file were copied from device/google/raviole/raven/BoardConfig.mk,
-# except for:
-#
-# * TARGET_SCREEN_DENSITY is scaled down by 1.75x
-
-TARGET_SCREEN_DENSITY := 240
diff --git a/oriole_car/aosp_oriole_car.mk b/oriole_car/aosp_oriole_car.mk
deleted file mode 100644
index dc74f2e..0000000
--- a/oriole_car/aosp_oriole_car.mk
+++ /dev/null
@@ -1,29 +0,0 @@
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
-$(call inherit-product, device/google_car/common/pre_google_car.mk)
-$(call inherit-product, device/google_car/oriole_car/device-oriole-car.mk)
-$(call inherit-product-if-exists, vendor/google_devices/raviole/proprietary/raven/device-vendor-oriole.mk)
-$(call inherit-product, device/google_car/common/post_google_car.mk)
-
-# Disable production validation checks to fix build error from oriole.scl
-PRODUCT_VALIDATION_CHECKS :=
-
-PRODUCT_MANUFACTURER := Google
-PRODUCT_BRAND := Android
-PRODUCT_NAME := aosp_oriole_car
-PRODUCT_DEVICE := oriole
-PRODUCT_MODEL := AOSP on oriole
diff --git a/oriole_car/device-oriole-car.mk b/oriole_car/device-oriole-car.mk
deleted file mode 100644
index f173f09..0000000
--- a/oriole_car/device-oriole-car.mk
+++ /dev/null
@@ -1,24 +0,0 @@
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
-AUTOMOTIVE_PRODUCT_PATH := google_car/oriole_car
-
-$(call inherit-product, device/google/raviole/device-oriole.mk)
-
-include device/google/gs101/uwb/uwb.mk
-
-PRODUCT_PRODUCT_PROPERTIES+= \
-    ro.adb.secure=0
diff --git a/panther_car/device-panther-car.mk b/panther_car/device-panther-car.mk
index 3581291..9d80a2c 100644
--- a/panther_car/device-panther-car.mk
+++ b/panther_car/device-panther-car.mk
@@ -16,7 +16,7 @@
 
 PHONE_CAR_BOARD_PRODUCT := panther_car
 
-$(call inherit-product, device/google/pantah/device-panther.mk)
+$(call inherit-product, device/google_car/panther_car/device-panther.mk)
 
 include device/google/gs101/uwb/uwb.mk
 
diff --git a/panther_car/device-panther.mk b/panther_car/device-panther.mk
new file mode 100644
index 0000000..4ec62df
--- /dev/null
+++ b/panther_car/device-panther.mk
@@ -0,0 +1,478 @@
+#
+# Copyright (C) 2021 The Android Open-Source Project
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
+# Copied from device/google/pantah/ to resolve build failure of panther_car
+
+# Restrict the visibility of Android.bp files to improve build analysis time
+$(call inherit-product-if-exists, vendor/google/products/sources_pixel.mk)
+
+ifdef RELEASE_GOOGLE_PANTHER_RADIO_DIR
+RELEASE_GOOGLE_PRODUCT_RADIO_DIR := $(RELEASE_GOOGLE_PANTHER_RADIO_DIR)
+endif
+RELEASE_GOOGLE_BOOTLOADER_PANTHER_DIR ?= pdk# Keep this for pdk TODO: b/327119000
+RELEASE_GOOGLE_PRODUCT_BOOTLOADER_DIR := bootloader/$(RELEASE_GOOGLE_BOOTLOADER_PANTHER_DIR)
+$(call soong_config_set,pantah_bootloader,prebuilt_dir,$(RELEASE_GOOGLE_BOOTLOADER_PANTHER_DIR))
+ifneq ($(filter trunk%, $(RELEASE_GOOGLE_BOOTLOADER_PANTHER_DIR)),)
+$(call soong_config_set,pantah_fingerprint,prebuilt_dir,trunk)
+else
+$(call soong_config_set,pantah_fingerprint,prebuilt_dir,$(RELEASE_GOOGLE_BOOTLOADER_PANTHER_DIR))
+endif
+
+
+TARGET_LINUX_KERNEL_VERSION := $(RELEASE_KERNEL_PANTHER_VERSION)
+# Keeps flexibility for kasan and ufs builds
+TARGET_KERNEL_DIR ?= $(RELEASE_KERNEL_PANTHER_DIR)
+TARGET_BOARD_KERNEL_HEADERS ?= $(RELEASE_KERNEL_PANTHER_DIR)/kernel-headers
+
+$(call inherit-product-if-exists, vendor/google_devices/pantah/prebuilts/device-vendor-panther.mk)
+$(call inherit-product-if-exists, vendor/google_devices/gs201/prebuilts/device-vendor.mk)
+$(call inherit-product-if-exists, vendor/google_devices/gs201/proprietary/device-vendor.mk)
+$(call inherit-product-if-exists, vendor/google_devices/pantah/proprietary/panther/device-vendor-panther.mk)
+$(call inherit-product-if-exists, vendor/google_devices/panther/proprietary/device-vendor.mk)
+$(call inherit-product-if-exists, vendor/google_devices/pantah/proprietary/WallpapersPanther.mk)
+
+DEVICE_PACKAGE_OVERLAYS += device/google/pantah/panther/overlay
+
+include device/google/pantah/audio/panther/audio-tables.mk
+include device/google/gs201/device-shipping-common.mk
+include device/google/gs-common/bcmbt/bluetooth.mk
+include device/google/gs-common/touch/focaltech/focaltech.mk
+
+# go/lyric-soong-variables
+$(call soong_config_set,lyric,camera_hardware,panther)
+$(call soong_config_set,lyric,tuning_product,panther)
+$(call soong_config_set,google3a_config,target_device,panther)
+
+# Init files
+PRODUCT_COPY_FILES += \
+	device/google/pantah/conf/init.pantah.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.pantah.rc \
+	device/google/pantah/conf/init.panther.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.panther.rc
+
+# Recovery files
+PRODUCT_COPY_FILES += \
+        device/google/pantah/conf/init.recovery.device.rc:$(TARGET_COPY_OUT_RECOVERY)/root/init.recovery.panther.rc
+
+# insmod files. Kernel 5.10 prebuilts don't provide these yet, so provide our
+# own copy if they're not in the prebuilts.
+# TODO(b/369686096): drop this when 5.10 is gone.
+ifeq ($(wildcard $(TARGET_KERNEL_DIR)/init.insmod.*.cfg),)
+PRODUCT_COPY_FILES += \
+	device/google/pantah/init.insmod.panther.cfg:$(TARGET_COPY_OUT_VENDOR_DLKM)/etc/init.insmod.panther.cfg
+endif
+
+# MIPI Coex Configs
+PRODUCT_COPY_FILES += \
+    device/google/pantah/panther/radio/panther_display_primary_mipi_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/display_primary_mipi_coex_table.csv \
+    device/google/pantah/panther/radio/panther_camera_front_mipi_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/camera_front_mipi_coex_table.csv \
+    device/google/pantah/panther/radio/panther_camera_rear_wide_mipi_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/camera_rear_wide_mipi_coex_table.csv \
+    device/google/pantah/panther/radio/panther_camera_front_dbr_coex_table.csv:$(TARGET_COPY_OUT_VENDOR)/etc/modem/camera_front_dbr_coex_table.csv
+
+# Camera
+PRODUCT_COPY_FILES += \
+	device/google/pantah/media_profiles_panther.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml
+
+# Media Performance Class 13
+PRODUCT_PROPERTY_OVERRIDES += ro.odm.build.media_performance_class=33
+
+# Display Config
+PRODUCT_COPY_FILES += \
+        device/google/pantah/panther/display_colordata_dev_cal0.pb:$(TARGET_COPY_OUT_VENDOR)/etc/display_colordata_dev_cal0.pb \
+        device/google/pantah/panther/display_golden_sdc-s6e3fc3-p10_cal0.pb:$(TARGET_COPY_OUT_VENDOR)/etc/display_golden_sdc-s6e3fc3-p10_cal0.pb
+
+# Display LBE
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.display.lbe.supported=1
+
+#config of primary display frames to reach LHBM peak brightness
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += vendor.primarydisplay.lhbm.frames_to_reach_peak_brightness=2
+
+# NFC
+PRODUCT_COPY_FILES += \
+	frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.xml \
+	frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hce.xml \
+	frameworks/native/data/etc/android.hardware.nfc.hcef.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hcef.xml \
+	frameworks/native/data/etc/com.nxp.mifare.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/com.nxp.mifare.xml \
+	frameworks/native/data/etc/android.hardware.nfc.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.ese.xml \
+	device/google/pantah/nfc/libnfc-hal-st-proto1.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st-proto1.conf \
+	device/google/pantah/nfc/libnfc-hal-st.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-hal-st.conf \
+    device/google/pantah/nfc/libnfc-nci-panther.conf:$(TARGET_COPY_OUT_PRODUCT)/etc/libnfc-nci.conf
+
+PRODUCT_PACKAGES += \
+	$(RELEASE_PACKAGE_NFC_STACK) \
+	Tag \
+	android.hardware.nfc-service.st \
+	NfcOverlayPanther
+
+# Shared Modem Platform
+SHARED_MODEM_PLATFORM_VENDOR := lassen
+
+# Shared Modem Platform
+include device/google/gs-common/modem/modem_svc_sit/shared_modem_platform.mk
+
+# SecureElement
+PRODUCT_PACKAGES += \
+	android.hardware.secure_element@1.2-service-gto \
+	android.hardware.secure_element@1.2-service-gto-ese2
+
+PRODUCT_COPY_FILES += \
+	frameworks/native/data/etc/android.hardware.se.omapi.ese.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.ese.xml \
+	frameworks/native/data/etc/android.hardware.se.omapi.uicc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.se.omapi.uicc.xml \
+	device/google/pantah/nfc/libse-gto-hal.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libse-gto-hal.conf \
+	device/google/pantah/nfc/libse-gto-hal2.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libse-gto-hal2.conf
+
+DEVICE_MANIFEST_FILE += \
+	device/google/pantah/nfc/manifest_se.xml
+
+# Thermal Config
+PRODUCT_COPY_FILES += \
+	device/google/pantah/thermal_info_config_panther.json:$(TARGET_COPY_OUT_VENDOR)/etc/thermal_info_config.json \
+	device/google/pantah/thermal_info_config_charge_panther.json:$(TARGET_COPY_OUT_VENDOR)/etc/thermal_info_config_charge.json \
+	device/google/pantah/thermal_info_config_proto.json:$(TARGET_COPY_OUT_VENDOR)/etc/thermal_info_config_proto.json
+
+# Power HAL config
+PRODUCT_COPY_FILES += \
+	device/google/pantah/powerhint-panther.json:$(TARGET_COPY_OUT_VENDOR)/etc/powerhint.json
+PRODUCT_COPY_FILES += \
+	device/google/pantah/powerhint-panther-a0.json:$(TARGET_COPY_OUT_VENDOR)/etc/powerhint-a0.json
+
+# Spatial Audio
+PRODUCT_PACKAGES += \
+	libspatialaudio
+
+# Bluetooth HAL
+PRODUCT_COPY_FILES += \
+	device/google/pantah/bluetooth/bt_vendor_overlay.conf:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth/bt_vendor_overlay.conf
+PRODUCT_PROPERTY_OVERRIDES += \
+    ro.bluetooth.a2dp_offload.supported=true \
+    persist.bluetooth.a2dp_offload.disabled=false \
+    persist.bluetooth.a2dp_offload.cap=sbc-aac-aptx-aptxhd-ldac-opus
+
+# Enable Bluetooth AutoOn feature
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.server.automatic_turn_on=true
+
+# Bluetooth hci_inject test tool
+PRODUCT_PACKAGES_DEBUG += \
+    hci_inject
+
+# Bluetooth OPUS codec
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.opus.enabled=true
+
+# Bluetooth Tx power caps
+PRODUCT_COPY_FILES += \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits.csv \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther_G03Z5_JP.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_G03Z5_JP.csv \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther_GVU6C_CA.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_GVU6C_CA.csv \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther_GQML3_EU.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_GQML3_EU.csv \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther_GVU6C_EU.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_GVU6C_EU.csv \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther_GQML3_US.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_GQML3_US.csv \
+    device/google/pantah/bluetooth/bluetooth_power_limits_panther_GVU6C_US.csv:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_power_limits_GVU6C_US.csv
+
+# Bluetooth SAR test tool
+PRODUCT_PACKAGES_DEBUG += \
+    sar_test
+# default BDADDR for EVB only
+PRODUCT_PROPERTY_OVERRIDES += \
+	ro.vendor.bluetooth.evb_bdaddr="22:22:22:33:44:55"
+
+# Bluetooth LE Audio
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.bluetooth.leaudio_offload.supported=true \
+    persist.bluetooth.leaudio_offload.disabled=false \
+    ro.bluetooth.leaudio_switcher.supported=true \
+    bluetooth.profile.bap.unicast.client.enabled?=true \
+    bluetooth.profile.csip.set_coordinator.enabled?=true \
+    bluetooth.profile.hap.client.enabled?=true \
+    bluetooth.profile.mcp.server.enabled?=true \
+    bluetooth.profile.ccp.server.enabled?=true \
+    bluetooth.profile.vcp.controller.enabled?=true \
+
+# Bluetooth LE Audio CIS handover to SCO
+# Set the property only if the controller doesn't support CIS and SCO
+# simultaneously. More details in b/242908683.
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.leaudio.notify.idle.during.call=true
+
+# BT controller not able to support LE Audio dual mic SWB call
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.leaudio.dual_bidirection_swb.supported=false
+
+# LE Auido Offload Capabilities setting
+PRODUCT_COPY_FILES += \
+    device/google/pantah/bluetooth/le_audio_codec_capabilities.xml:$(TARGET_COPY_OUT_VENDOR)/etc/le_audio_codec_capabilities.xml
+
+# LE Audio Unicast Allowlist
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.leaudio.allow_list=SM-R510,WF-1000XM5,SM-R630,WH-1000XM6
+
+# Disable Bluetooth HAP by default
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.profile.hap.enabled_by_default=false
+
+# Disable Bluetooth LE Audio toggle for ASHA device
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.leaudio.toggle_visible_for_asha=false
+
+# Support LE & Classic concurrent encryption (b/330704060)
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.ble.allow_enc_with_bredr=true
+
+# Bluetooth EWP test tool
+PRODUCT_PACKAGES_DEBUG += \
+    ewp_tool
+
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.firmware.selection=BCM.hcd
+
+# Bluetooth AAC VBR
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.a2dp_aac.vbr_supported=true
+
+# Override BQR mask to enable LE Audio Choppy report, remove BTRT logging
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.bqr.event_mask=295006 \
+    persist.bluetooth.bqr.vnd_quality_mask=29 \
+    persist.bluetooth.bqr.vnd_trace_mask=0 \
+    persist.bluetooth.vendor.btsnoop=true
+else
+PRODUCT_PRODUCT_PROPERTIES += \
+    persist.bluetooth.bqr.event_mask=295006 \
+    persist.bluetooth.bqr.vnd_quality_mask=16 \
+    persist.bluetooth.bqr.vnd_trace_mask=0 \
+    persist.bluetooth.vendor.btsnoop=false
+endif
+
+# declare use of spatial audio
+PRODUCT_PROPERTY_OVERRIDES += \
+       ro.audio.spatializer_enabled=true
+
+# optimize spatializer effect
+PRODUCT_PROPERTY_OVERRIDES += \
+       audio.spatializer.effect.util_clamp_min=300
+
+# Keymaster HAL
+#LOCAL_KEYMASTER_PRODUCT_PACKAGE ?= android.hardware.keymaster@4.1-service
+
+# Gatekeeper HAL
+#LOCAL_GATEKEEPER_PRODUCT_PACKAGE ?= android.hardware.gatekeeper@1.0-service.software
+
+
+# Gatekeeper
+# PRODUCT_PACKAGES += \
+# 	android.hardware.gatekeeper@1.0-service.software
+
+# Keymint replaces Keymaster
+# PRODUCT_PACKAGES += \
+# 	android.hardware.security.keymint-service
+
+# Keymaster
+#PRODUCT_PACKAGES += \
+#	android.hardware.keymaster@4.0-impl \
+#	android.hardware.keymaster@4.0-service
+
+#PRODUCT_PACKAGES += android.hardware.keymaster@4.0-service.remote
+#PRODUCT_PACKAGES += android.hardware.keymaster@4.1-service.remote
+#LOCAL_KEYMASTER_PRODUCT_PACKAGE := android.hardware.keymaster@4.1-service
+#LOCAL_KEYMASTER_PRODUCT_PACKAGE ?= android.hardware.keymaster@4.1-service
+
+# PRODUCT_PROPERTY_OVERRIDES += \
+# 	ro.hardware.keystore_desede=true \
+# 	ro.hardware.keystore=software \
+# 	ro.hardware.gatekeeper=software
+
+# PowerStats HAL
+PRODUCT_SOONG_NAMESPACES += \
+    device/google/pantah/powerstats/panther \
+
+# Fingerprint HAL
+GOODIX_CONFIG_BUILD_VERSION := g7_trusty
+$(call inherit-product-if-exists, vendor/goodix/udfps/configuration/udfps_common.mk)
+ifeq ($(filter factory%, $(TARGET_PRODUCT)),)
+$(call inherit-product-if-exists, vendor/goodix/udfps/configuration/udfps_shipping.mk)
+else
+$(call inherit-product-if-exists, vendor/goodix/udfps/configuration/udfps_factory.mk)
+endif
+
+# Display
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += ro.surface_flinger.set_idle_timer_ms=1500
+PRODUCT_DEFAULT_PROPERTY_OVERRIDES += ro.surface_flinger.ignore_hdr_camera_layers=true
+
+# WiFi Overlay
+PRODUCT_PACKAGES += \
+    WifiOverlay2022_P10
+
+
+# Trusty liboemcrypto.so
+PRODUCT_SOONG_NAMESPACES += vendor/google_devices/pantah/prebuilts
+
+# Location
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+    PRODUCT_COPY_FILES += \
+        device/google/pantah/location/lhd.conf.p10:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/lhd.conf \
+        device/google/pantah/location/scd.conf.p10:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/scd.conf \
+        device/google/pantah/location/gps.6.1.xml.p10:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/gps.xml
+else
+    PRODUCT_COPY_FILES += \
+        device/google/pantah/location/lhd_user.conf.p10:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/lhd.conf \
+        device/google/pantah/location/scd_user.conf.p10:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/scd.conf \
+        device/google/pantah/location/gps_user.6.1.xml.p10:$(TARGET_COPY_OUT_VENDOR)/etc/gnss/gps.xml
+endif
+
+# Set support one-handed mode
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.support_one_handed_mode=true
+
+# Set zram size
+PRODUCT_VENDOR_PROPERTIES += \
+	vendor.zram.size=3g
+
+# Increment the SVN for any official public releases
+ifdef RELEASE_SVN_PANTHER
+TARGET_SVN ?= $(RELEASE_SVN_PANTHER)
+else
+# Set this for older releases that don't use build flag
+TARGET_SVN ?= 61
+endif
+
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.vendor.build.svn=$(TARGET_SVN)
+
+# Set device family property for SMR
+PRODUCT_PROPERTY_OVERRIDES += \
+    ro.build.device_family=P10C10L10
+
+# Set build properties for SMR builds
+ifeq ($(RELEASE_IS_SMR), true)
+    ifneq (,$(RELEASE_BASE_OS_PANTHER))
+        PRODUCT_BASE_OS := $(RELEASE_BASE_OS_PANTHER)
+    endif
+endif
+
+# Set build properties for EMR builds
+ifeq ($(RELEASE_IS_EMR), true)
+    ifneq (,$(RELEASE_BASE_OS_PANTHER))
+        PRODUCT_PROPERTY_OVERRIDES += \
+        ro.build.version.emergency_base_os=$(RELEASE_BASE_OS_PANTHER)
+    endif
+endif
+# DCK properties based on target
+PRODUCT_PROPERTY_OVERRIDES += \
+    ro.gms.dck.eligible_wcc=2 \
+    ro.gms.dck.se_capability=1
+
+
+# Set support hide display cutout feature
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.support_hide_display_cutout=true
+
+PRODUCT_PACKAGES += \
+    NoCutoutOverlay \
+    AvoidAppsInCutoutOverlay
+
+# SKU specific RROs
+PRODUCT_PACKAGES += \
+    SettingsOverlayG03Z5 \
+    SettingsOverlayGQML3 \
+    SettingsOverlayGVU6C \
+    SettingsOverlayGVU6C_VN
+
+# userdebug specific
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+    PRODUCT_COPY_FILES += \
+        device/google/gs201/init.hardware.wlc.rc.userdebug:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.wlc.rc
+endif
+
+# Fingerprint HAL
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.udfps.als_feed_forward_supported=true \
+    persist.vendor.udfps.lhbm_controlled_in_hal_supported=true
+
+# Vibrator HAL
+$(call soong_config_set,haptics,kernel_ver,v$(subst .,_,$(TARGET_LINUX_KERNEL_VERSION))_fw7_2_91)
+ACTUATOR_MODEL := luxshare_ict_081545
+ADAPTIVE_HAPTICS_FEATURE := adaptive_haptics_v1
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.vibrator.hal.chirp.enabled=0 \
+    ro.vendor.vibrator.hal.device.mass=0.195 \
+    ro.vendor.vibrator.hal.loc.coeff=2.65 \
+    persist.vendor.vibrator.hal.context.enable=false \
+    persist.vendor.vibrator.hal.context.scale=60 \
+    persist.vendor.vibrator.hal.context.fade=true \
+    persist.vendor.vibrator.hal.context.cooldowntime=1600 \
+    persist.vendor.vibrator.hal.context.settlingtime=5000
+
+# Override Output Distortion Gain
+PRODUCT_VENDOR_PROPERTIES += \
+    vendor.audio.hapticgenerator.distortion.output.gain=0.38
+
+# Keyboard bottom padding in dp for portrait mode and height ratio
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.com.google.ime.kb_pad_port_b=8 \
+    ro.com.google.ime.height_ratio=1.075
+
+# Enable camera exif model/make reporting
+PRODUCT_VENDOR_PROPERTIES += \
+    persist.vendor.camera.exif_reveal_make_model=true \
+    persist.vendor.camera.front_720P_always_binning=true
+
+# RKPD
+PRODUCT_PRODUCT_PROPERTIES += \
+    remote_provisioning.hostname=remoteprovisioning.googleapis.com \
+
+##Audio Vendor property
+PRODUCT_PROPERTY_OVERRIDES += \
+	persist.vendor.audio.cca.enabled=false
+
+# The default value of this variable is false and should only be set to true when
+# the device allows users to enable the seamless transfer feature.
+PRODUCT_PRODUCT_PROPERTIES += \
+   euicc.seamless_transfer_enabled_in_non_qs=true
+
+# Device features
+PRODUCT_COPY_FILES += \
+    frameworks/native/data/etc/handheld_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml
+
+# To resolve build failure, comment out this
+# Disable Settings large-screen optimization enabled by Window Extensions
+# PRODUCT_SYSTEM_PROPERTIES += \
+#    persist.settings.large_screen_opt.enabled=false
+
+# Enable DeviceAsWebcam support
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.usb.uvc.enabled=true
+
+# Quick Start device-specific settings
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.quick_start.oem_id=00e0 \
+    ro.quick_start.device_id=panther
+
+# Bluetooth device id
+# Panther: 0x4109
+PRODUCT_PRODUCT_PROPERTIES += \
+    bluetooth.device_id.product_id=16649
+
+# ETM
+ifneq (,$(RELEASE_ETM_IN_USERDEBUG_ENG))
+ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
+$(call inherit-product-if-exists, device/google/common/etm/device-userdebug-modules.mk)
+endif
+endif
+
+# PDK does not use build flags
+ifeq ($(USE_GOOGLE_CARRIER_SETTINGS), true)
+    $(call soong_config_set,carrier_settings,gs_common_paris_assets_path,paris_data_y25q2/latest/pixel2022)
+endif
diff --git a/raven_car/BoardConfig.mk b/raven_car/BoardConfig.mk
deleted file mode 100644
index d327f95..0000000
--- a/raven_car/BoardConfig.mk
+++ /dev/null
@@ -1,22 +0,0 @@
-#
-# Copyright (C) 2021 The Android Open-Source Project
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
-# Contents of this file were copied from device/google/raviole/raven/BoardConfig.mk,
-# except for:
-#
-# * TARGET_SCREEN_DENSITY is scaled down by 1.75x
-
-TARGET_SCREEN_DENSITY := 320
diff --git a/raven_car/aosp_raven_car.mk b/raven_car/aosp_raven_car.mk
deleted file mode 100644
index c2a0d34..0000000
--- a/raven_car/aosp_raven_car.mk
+++ /dev/null
@@ -1,32 +0,0 @@
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
-PRODUCT_COPY_FILES += \
-    device/google_car/raven_car/displayconfig/display_id_4619827677550801152.xml:$(TARGET_COPY_OUT_VENDOR)/etc/displayconfig/display_id_4619827677550801152.xml
-
-$(call inherit-product, device/google_car/common/pre_google_car.mk)
-$(call inherit-product, device/google_car/raven_car/device-raven-car.mk)
-$(call inherit-product-if-exists, vendor/google_devices/raviole/proprietary/raven/device-vendor-raven.mk)
-$(call inherit-product, device/google_car/common/post_google_car.mk)
-
-# Disable production validation checks to fix build error from raven.scl
-PRODUCT_VALIDATION_CHECKS :=
-
-PRODUCT_MANUFACTURER := Google
-PRODUCT_BRAND := Android
-PRODUCT_NAME := aosp_raven_car
-PRODUCT_DEVICE := raven
-PRODUCT_MODEL := AOSP on raven
diff --git a/raven_car/device-raven-car.mk b/raven_car/device-raven-car.mk
deleted file mode 100644
index 10a805e..0000000
--- a/raven_car/device-raven-car.mk
+++ /dev/null
@@ -1,24 +0,0 @@
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
-AUTOMOTIVE_PRODUCT_PATH := google_car/raven_car
-
-$(call inherit-product, device/google/raviole/raven_generic.mk)
-
-include device/google/gs101/uwb/uwb.mk
-
-PRODUCT_PRODUCT_PROPERTIES+= \
-    ro.adb.secure=0
diff --git a/raven_car/displayconfig/display_id_4619827677550801152.xml b/raven_car/displayconfig/display_id_4619827677550801152.xml
deleted file mode 100644
index 91841c5..0000000
--- a/raven_car/displayconfig/display_id_4619827677550801152.xml
+++ /dev/null
@@ -1,103 +0,0 @@
-<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
-
-<!-- Copyright (C) 2022 Google Inc.
-
-    Licensed under the Apache License, Version 2.0 (the "License");
-    you may not use this file except in compliance with the License.
-    You may obtain a copy of the License at
-
-      http://www.apache.org/licenses/LICENSE-2.0
-
-    Unless required by applicable law or agreed to in writing, software
-    distributed under the License is distributed on an "AS IS" BASIS,
-    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-    See the License for the specific language governing permissions and
-    limitations under the License.
--->
-
-<!-- This overrides <density> to 320 for Phone_car configuration.  The original file is located at
-    vendor/google_devices/raviole/proprietary/raven/vendor/etc/displayconfig/display_id_4619827677550801152.xml -->
-
-<displayConfiguration>
-    <densityMapping>
-        <density>
-            <height>1440</height>
-            <width>3120</width>
-            <density>320</density>
-        </density>
-    </densityMapping>
-    <screenBrightnessMap>
-        <point>
-            <value>0.0</value>
-            <nits>2.0</nits>
-        </point>
-        <point>
-            <value>0.62</value>
-            <nits>500.0</nits>
-        </point>
-        <point>
-            <value>1.0</value>
-            <nits>800.0</nits>
-        </point>
-    </screenBrightnessMap>
-    <highBrightnessMode enabled="true">
-        <transitionPoint>0.62</transitionPoint>
-        <minimumLux>10000</minimumLux>
-        <timing>
-            <!-- allow for 5 minutes out of every 30 minutes -->
-            <timeWindowSecs>1800</timeWindowSecs>
-            <timeMaxSecs>300</timeMaxSecs>
-            <timeMinSecs>60</timeMinSecs>
-        </timing>
-        <refreshRate>
-            <minimum>120</minimum>
-            <maximum>120</maximum>
-        </refreshRate>
-        <thermalStatusLimit>light</thermalStatusLimit>
-        <allowInLowPowerMode>false</allowInLowPowerMode>
-    </highBrightnessMode>
-    <ambientBrightnessChangeThresholds>
-        <brighteningThresholds>
-            <minimum>10</minimum>
-        </brighteningThresholds>
-        <darkeningThresholds>
-            <minimum>2</minimum>
-        </darkeningThresholds>
-    </ambientBrightnessChangeThresholds>
-
-    <ambientLightHorizonLong>5000</ambientLightHorizonLong>
-    <ambientLightHorizonShort>50</ambientLightHorizonShort>
-
-    <screenBrightnessRampIncreaseMaxMillis>2000</screenBrightnessRampIncreaseMaxMillis>
-
-    <thermalThrottling>
-        <brightnessThrottlingMap>
-            <brightnessThrottlingPoint>
-                <thermalStatus>light</thermalStatus>
-                <!-- Throttling to 465 nits: (465-2.0)/(500-2.0)*(0.62-0.0)+0.0 = 0.576425703 -->
-                <brightness>0.576425703</brightness>
-            </brightnessThrottlingPoint>
-            <brightnessThrottlingPoint>
-                <thermalStatus>moderate</thermalStatus>
-                <!-- Throttling to 297 nits: (297-2.0)/(500-2.0)*(0.62-0.0)+0.0 = 0.367269076 -->
-                <brightness>0.367269076</brightness>
-            </brightnessThrottlingPoint>
-            <brightnessThrottlingPoint>
-                <thermalStatus>severe</thermalStatus>
-                <!-- Throttling to 213 nits: (213-2.0)/(500-2.0)*(0.62-0.0)+0.0 = 0.262690763 -->
-                <brightness>0.262690763</brightness>
-            </brightnessThrottlingPoint>
-            <brightnessThrottlingPoint>
-                <thermalStatus>critical</thermalStatus>
-                <!-- Throttling to 150 nits: (150-2.0)/(500-2.0)*(0.62-0.0)+0.0 = 0.184257028 -->
-                <brightness>0.184257028</brightness>
-            </brightnessThrottlingPoint>
-        </brightnessThrottlingMap>
-    </thermalThrottling>
-
-    <screenBrightnessRampFastDecrease>0.7047244</screenBrightnessRampFastDecrease>
-    <screenBrightnessRampFastIncrease>0.7047244</screenBrightnessRampFastIncrease>
-    <screenBrightnessRampSlowDecrease>0.05</screenBrightnessRampSlowDecrease>
-    <screenBrightnessRampSlowIncrease>0.05</screenBrightnessRampSlowIncrease>
-</displayConfiguration>
-
diff --git a/redfin_car/BoardConfig.mk b/redfin_car/BoardConfig.mk
deleted file mode 100644
index 282707a..0000000
--- a/redfin_car/BoardConfig.mk
+++ /dev/null
@@ -1,32 +0,0 @@
-#
-# Copyright (C) 2020 The Android Open-Source Project
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
-# Contents of this file were copied from device/google/redfin/redfin/BoardConfig.mk,
-# except for:
-#
-# * TARGET_SCREEN_DENSITY is scaled down by 1.75x
-
-TARGET_BOOTLOADER_BOARD_NAME := redfin
-TARGET_SCREEN_DENSITY := 250
-TARGET_RECOVERY_UI_MARGIN_HEIGHT := 165
-
-include device/google/redbull/BoardConfig-common.mk
-DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE += device/google/redfin/device_framework_matrix_product.xml
-
-# Testing related defines
-#   #BOARD_PERFSETUP_SCRIPT := platform_testing/scripts/perf-setup/r3-setup.sh
-
--include vendor/google_devices/redfin/proprietary/BoardConfigVendor.mk
diff --git a/redfin_car/aosp_redfin_car.mk b/redfin_car/aosp_redfin_car.mk
deleted file mode 100644
index 1eb9492..0000000
--- a/redfin_car/aosp_redfin_car.mk
+++ /dev/null
@@ -1,30 +0,0 @@
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
-$(call inherit-product, device/google_car/common/pre_google_car.mk)
-$(call inherit-product, device/google_car/redfin_car/device-redfin-car.mk)
-$(call inherit-product-if-exists, vendor/google_devices/redfin/proprietary/device-vendor.mk)
-$(call inherit-product-if-exists, vendor/google_devices/redfin/prebuilts/device-vendor-redfin.mk)
-$(call inherit-product, device/google_car/common/post_google_car.mk)
-
-# Disable production validation checks to fix build error from redfin.scl
-PRODUCT_VALIDATION_CHECKS :=
-
-PRODUCT_MANUFACTURER := Google
-PRODUCT_BRAND := Android
-PRODUCT_NAME := aosp_redfin_car
-PRODUCT_DEVICE := redfin
-PRODUCT_MODEL := AOSP on redfin
diff --git a/redfin_car/device-redfin-car.mk b/redfin_car/device-redfin-car.mk
deleted file mode 100644
index 0efc7fc..0000000
--- a/redfin_car/device-redfin-car.mk
+++ /dev/null
@@ -1,23 +0,0 @@
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
-AUTOMOTIVE_PRODUCT_PATH := google_car/redfin_car
-
-$(call inherit-product, device/google/redfin/device-redfin.mk)
-
-PRODUCT_PRODUCT_PROPERTIES+= \
-    ro.adb.secure=0
-
diff --git a/sunfish_car/BoardConfig.mk b/sunfish_car/BoardConfig.mk
deleted file mode 100644
index 38c23ee..0000000
--- a/sunfish_car/BoardConfig.mk
+++ /dev/null
@@ -1,26 +0,0 @@
-#
-# Copyright (C) 2020 The Android Open-Source Project
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
-# Contents of this file were copied from device/google/sunfish/sunfish/BoardConfig.mk,
-# except for:
-#
-# * TARGET_SCREEN_DENSITY is scaled down by 1.75x
-
-TARGET_BOOTLOADER_BOARD_NAME := sunfish
-TARGET_SCREEN_DENSITY := 250
-TARGET_RECOVERY_UI_MARGIN_HEIGHT := 165
-
-include device/google/sunfish/BoardConfig-common.mk
diff --git a/sunfish_car/aosp_sunfish_car.mk b/sunfish_car/aosp_sunfish_car.mk
deleted file mode 100644
index 2a3b42e..0000000
--- a/sunfish_car/aosp_sunfish_car.mk
+++ /dev/null
@@ -1,30 +0,0 @@
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
-$(call inherit-product, device/google_car/common/pre_google_car.mk)
-$(call inherit-product, device/google_car/sunfish_car/device-sunfish-car.mk)
-$(call inherit-product-if-exists, vendor/google_devices/sunfish/proprietary/device-vendor.mk)
-$(call inherit-product-if-exists, vendor/google_devices/sunfish/prebuilts/device-vendor-sunfish.mk)
-$(call inherit-product, device/google_car/common/post_google_car.mk)
-
-# Disable production validation checks to fix build error from sunfish.scl
-PRODUCT_VALIDATION_CHECKS :=
-
-PRODUCT_MANUFACTURER := Google
-PRODUCT_BRAND := Android
-PRODUCT_NAME := aosp_sunfish_car
-PRODUCT_DEVICE := sunfish
-PRODUCT_MODEL := AOSP on sunfish
diff --git a/sunfish_car/device-sunfish-car.mk b/sunfish_car/device-sunfish-car.mk
deleted file mode 100644
index 16e4802..0000000
--- a/sunfish_car/device-sunfish-car.mk
+++ /dev/null
@@ -1,22 +0,0 @@
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
-AUTOMOTIVE_PRODUCT_PATH := google_car/sunfish_car
-
-$(call inherit-product, device/google/sunfish/device-sunfish.mk)
-
-PRODUCT_PRODUCT_PROPERTIES+= \
-    ro.adb.secure=0
\ No newline at end of file
diff --git a/tangorpro_car/aosp_tangorpro_car.mk b/tangorpro_car/aosp_tangorpro_car.mk
index 3a2b615..c35db4e 100644
--- a/tangorpro_car/aosp_tangorpro_car.mk
+++ b/tangorpro_car/aosp_tangorpro_car.mk
@@ -26,6 +26,12 @@ $(call inherit-product, device/google_car/common/pre_google_car.mk)
 $(call inherit-product, device/google_car/tangorpro_car/device-tangorpro-car.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Scalable UI configuration
+ifneq (,$(RELEASE_LANDSCAPE_SCALABLE_UI))
+PRODUCT_PACKAGES += CarSystemUIDewdLandAospTangorProRRO
+$(call inherit-product, packages/services/Car/car_product/dewd/car_dewd_landscape_common.mk)
+endif
+
 # Disable production validation checks to fix build error from tangorpro.scl
 PRODUCT_VALIDATION_CHECKS :=
 
```

