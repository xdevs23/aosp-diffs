```diff
diff --git a/Android.bp b/Android.bp
index 80433fd..34718e5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -17,20 +17,6 @@ package {
     default_applicable_licenses: ["device_google_atv_license"],
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
-// See: http://go/android-license-faq
 license {
     name: "device_google_atv_license",
     visibility: [":__subpackages__"],
@@ -38,5 +24,16 @@ license {
         "SPDX-license-identifier-Apache-2.0",
         "legacy_notice",
     ],
-    // large-scale-change unable to identify any license_text files
+}
+
+prebuilt_usr_keylayout {
+    name: "atv_generic_keylayout",
+    product_specific: true,
+    srcs: [
+        "Generic.kl",
+    ],
+    enabled: select(soong_config_variable("atv_keylayouts", "use_atv_generic_keylayout"), {
+        true: true,
+        default: false,
+    }),
 }
diff --git a/MdnsOffloadManagerService/OWNERS b/MdnsOffloadManagerService/OWNERS
index d97785d..ccee1f1 100644
--- a/MdnsOffloadManagerService/OWNERS
+++ b/MdnsOffloadManagerService/OWNERS
@@ -1,10 +1,7 @@
 # Bug component: 1750103
 # Android > Android OS & Apps > TV > Connectivity > Networking
 
-agazal@google.com
 hisbilir@google.com
-arjundhaliwal@google.com
 gubailey@google.com
-maitrim@google.com
 
-include /OWNERS
\ No newline at end of file
+include /OWNERS
diff --git a/emulator_x86/device.mk b/emulator_x86/device.mk
index 0fe29f6..eb3df35 100644
--- a/emulator_x86/device.mk
+++ b/emulator_x86/device.mk
@@ -15,7 +15,6 @@
 #
 
 PRODUCT_SOONG_NAMESPACES += device/generic/goldfish # for libwifi-hal-emu
-PRODUCT_SOONG_NAMESPACES += device/generic/goldfish-opengl # for goldfish deps.
 
 ifdef NET_ETH0_STARTONBOOT
   PRODUCT_VENDOR_PROPERTIES += net.eth0.startonboot=1
diff --git a/emulator_x86/kernel_fstab_32.mk b/emulator_x86/kernel_fstab_32.mk
new file mode 100644
index 0000000..2c5d053
--- /dev/null
+++ b/emulator_x86/kernel_fstab_32.mk
@@ -0,0 +1,24 @@
+# Copyright (C) 2023 The Android Open Source Project
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
+# This file adds the x86_64 kernel and fstab only, it is used on 32bit userspace
+# devices (which is currently ATV only).
+
+include device/google/atv/emulator_x86/x86_64.mk
+
+PRODUCT_COPY_FILES += \
+    $(EMULATOR_KERNEL_FILE):kernel-ranchu-64 \
+    device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/first_stage_ramdisk/fstab.ranchu \
+    device/generic/goldfish/board/fstab/x86:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.ranchu
diff --git a/emulator_x86/kernel_modules.blocklist b/emulator_x86/kernel_modules.blocklist
new file mode 100644
index 0000000..3b96310
--- /dev/null
+++ b/emulator_x86/kernel_modules.blocklist
@@ -0,0 +1,4 @@
+blocklist vkms.ko
+# When enabled, hijacks the first audio device that's expected to be backed by
+# virtio-snd. See also: aosp/3391025
+blocklist snd-aloop.ko
diff --git a/emulator_x86/x86_64.mk b/emulator_x86/x86_64.mk
new file mode 100644
index 0000000..d908e67
--- /dev/null
+++ b/emulator_x86/x86_64.mk
@@ -0,0 +1,54 @@
+#
+# Copyright (C) 2023 The Android Open Source Project
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
+# we do NOT support OTA - suppress the build warning
+TARGET_KERNEL_USE := 6.1
+PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
+
+KERNEL_ARTIFACTS_PATH := kernel/prebuilts/$(TARGET_KERNEL_USE)/x86_64
+
+VIRTUAL_DEVICE_KERNEL_MODULES_PATH := \
+    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/x86-64
+
+# The list of modules to reach the second stage. For performance reasons we
+# don't want to put all modules into the ramdisk.
+RAMDISK_KERNEL_MODULES := \
+    virtio_blk.ko \
+    virtio_console.ko \
+    virtio_dma_buf.ko \
+    virtio_pci.ko \
+    virtio_pci_legacy_dev.ko \
+    virtio_pci_modern_dev.ko \
+    virtio-rng.ko \
+    vmw_vsock_virtio_transport.ko \
+
+BOARD_SYSTEM_KERNEL_MODULES := $(wildcard $(KERNEL_ARTIFACTS_PATH)/*.ko)
+
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
+    $(patsubst %,$(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
+
+BOARD_VENDOR_KERNEL_MODULES := \
+    $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
+                 $(wildcard $(VIRTUAL_DEVICE_KERNEL_MODULES_PATH)/*.ko))
+
+BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE := \
+    device/google/atv/emulator_x86/kernel_modules.blocklist
+
+EMULATOR_KERNEL_FILE := $(KERNEL_ARTIFACTS_PATH)/kernel-$(TARGET_KERNEL_USE)
+
+# BOARD_KERNEL_CMDLINE is not supported (b/361341981), use the file below
+PRODUCT_COPY_FILES += \
+    device/google/atv/emulator_x86/x86_64_cmdline.txt:kernel_cmdline.txt
diff --git a/emulator_x86/x86_64_cmdline.txt b/emulator_x86/x86_64_cmdline.txt
new file mode 100644
index 0000000..76198b5
--- /dev/null
+++ b/emulator_x86/x86_64_cmdline.txt
@@ -0,0 +1 @@
+8250.nr_uarts=1 clocksource=pit
diff --git a/libraries/BluetoothServices/OWNERS b/libraries/BluetoothServices/OWNERS
index de36d35..018553f 100644
--- a/libraries/BluetoothServices/OWNERS
+++ b/libraries/BluetoothServices/OWNERS
@@ -1,9 +1,6 @@
 # Bug component: 1066323
 # Android > Android OS & Apps > TV > Connectivity > BT
 hisbilir@google.com
-arjundhaliwal@google.com
-agazal@google.com
 gubailey@google.com
-maitrim@google.com
 
 include /OWNERS
diff --git a/libraries/BluetoothServices/res/values-fa/strings.xml b/libraries/BluetoothServices/res/values-fa/strings.xml
index 941fb37..70c23df 100644
--- a/libraries/BluetoothServices/res/values-fa/strings.xml
+++ b/libraries/BluetoothServices/res/values-fa/strings.xml
@@ -68,9 +68,9 @@
     <string name="settings_axel" msgid="8253298947221430993">"راه‌اندازی دکمه‌های کنترل ازراه‌دور"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"میزان صدا، ورودی، و روشن/خاموش شدن تلویزیون‌ها، گیرنده‌ها، و بلندگوهای ستونی را کنترل کنید"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"پیدا کردن کنترل از راه دور"</string>
-    <string name="settings_find_my_remote_description" msgid="2434088262598422577">"اگر کنترل از دور Google TV در جای خودش نباشد، برای پیدا کردن آن، صدایی پخش می‌شود"</string>
-    <string name="find_my_remote_slice_description" msgid="4802810369433859327">"دکمه پشت «جاری‌ساز Google TV» را فشار دهید تا صدایی به‌مدت ۳۰ ثانیه در کنترل از دور پخش شود. این ویژگی فقط در «کنترل از دور صوتی جاری‌ساز Google TV» کار می‌کند.\n\nبرای قطع کردن صدا، هر دکمه‌ای را روی کنترل از دور فشار دهید."</string>
-    <string name="find_my_remote_integration_hint" msgid="7131212049012673631">"وقتی روشن باشد، بااستفاده از این دکمه در دستگاهتان می‌توانید صدایی پخش کنید و کنترل از دور را پیدا کنید. وقتی خاموش باشد، این دکمه کار نمی‌کند. همچنان می‌توانید با روش‌های دیگر از «پیدا کردن کنترل از راه دور» استفاده کنید."</string>
+    <string name="settings_find_my_remote_description" msgid="2434088262598422577">"اگر کنترل از راه دور Google TV در جای خودش نباشد، برای پیدا کردن آن، صدایی پخش می‌شود"</string>
+    <string name="find_my_remote_slice_description" msgid="4802810369433859327">"دکمه پشت «جاری‌ساز Google TV» را فشار دهید تا صدایی به‌مدت ۳۰ ثانیه در کنترل از راه دور پخش شود. این ویژگی فقط در «کنترل از راه دور صوتی جاری‌ساز Google TV» کار می‌کند.\n\nبرای قطع کردن صدا، هر دکمه‌ای را روی کنترل از راه دور فشار دهید."</string>
+    <string name="find_my_remote_integration_hint" msgid="7131212049012673631">"وقتی روشن باشد، بااستفاده از این دکمه در دستگاهتان می‌توانید صدایی پخش کنید و کنترل از راه دور را پیدا کنید. وقتی خاموش باشد، این دکمه کار نمی‌کند. همچنان می‌توانید با روش‌های دیگر از «پیدا کردن کنترل از راه دور» استفاده کنید."</string>
     <string name="find_my_remote_play_sound" msgid="1799877650759138251">"پخش صدا"</string>
     <string name="settings_remote_battery_level" msgid="1817513765913707505">"سطح باتری: %1$s"</string>
     <string name="settings_known_devices_category" msgid="2307810690946536753">"لوازم جانبی"</string>
@@ -99,6 +99,6 @@
     <string name="settings_bt_pair_toast_connected" msgid="3073130641004809067">"%1$s متصل شد"</string>
     <string name="settings_bt_pair_toast_disconnected" msgid="2046165143924352053">"اتصال %1$s قطع شد"</string>
     <string name="settings_backlight_title" msgid="2013564937830315646">"حالت نور پس‌زمینه"</string>
-    <string name="settings_backlight_description" msgid="2672529254045062504">"روشنایی دکمه‌های روی کنترل از دور با هر فشردن."</string>
-    <string name="backlight_slice_description" msgid="2417058213200444743">"در کنترل‌های از دور پشتیبانی‌شده Google TV، با فشار دادن دکمه روی کنترل از دور روشنایی نور پس‌زمینه فعال می‌شود."</string>
+    <string name="settings_backlight_description" msgid="2672529254045062504">"روشنایی دکمه‌های روی کنترل از راه دور با هر فشردن."</string>
+    <string name="backlight_slice_description" msgid="2417058213200444743">"در کنترل‌های از دور پشتیبانی‌شده Google TV، با فشار دادن دکمه روی کنترل از راه دور روشنایی نور پس‌زمینه فعال می‌شود."</string>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-it/strings.xml b/libraries/BluetoothServices/res/values-it/strings.xml
index 8e5a2ff..5d7dad8 100644
--- a/libraries/BluetoothServices/res/values-it/strings.xml
+++ b/libraries/BluetoothServices/res/values-it/strings.xml
@@ -71,7 +71,7 @@
     <string name="settings_find_my_remote_description" msgid="2434088262598422577">"Riproduci un suono per trovare il tuo telecomando di Google TV se non sai dov\'è."</string>
     <string name="find_my_remote_slice_description" msgid="4802810369433859327">"Premi il pulsante sul retro del Google TV Streamer per riprodurre un suono per 30 secondi sul telecomando. Questa operazione funziona solo su un telecomando con controllo vocale Google TV Streamer.\n\nPer silenziare il suono, premi un pulsante qualsiasi sul telecomando."</string>
     <string name="find_my_remote_integration_hint" msgid="7131212049012673631">"Se l\'impostazione è attivata, potrai usare il pulsante sul dispositivo per riprodurre un suono che ti aiuterà a trovare il telecomando. Se è disattivata, il pulsante non funzionerà. Potrai comunque usare Trova il telecomando con altri metodi."</string>
-    <string name="find_my_remote_play_sound" msgid="1799877650759138251">"Riproduci audio"</string>
+    <string name="find_my_remote_play_sound" msgid="1799877650759138251">"Riproduci suono"</string>
     <string name="settings_remote_battery_level" msgid="1817513765913707505">"Livello batteria: %1$s"</string>
     <string name="settings_known_devices_category" msgid="2307810690946536753">"Accessori"</string>
     <string name="settings_official_remote_category" msgid="1373956695709331265">"Telecomando"</string>
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
index fa563ec..1ad0b41 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
@@ -400,7 +400,9 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
 
         if (hasActiveDevices) {
             updateFindMyRemoteSlice(psb);
-            updateBacklight(psb);
+            // Temporarily disable the backlight settings due to b/408118325, will re-enable it
+            // after the firmware is upgraded to fix the GATT issue.
+            //updateBacklight(psb);
         }
     }
 
diff --git a/permissions/tv_core_hardware.xml b/permissions/tv_core_hardware.xml
index cf892f6..fb3ad36 100644
--- a/permissions/tv_core_hardware.xml
+++ b/permissions/tv_core_hardware.xml
@@ -37,4 +37,9 @@
     <feature name="android.software.cts" />
     <feature name="android.hardware.security.model.compatible" />
 
+    <!-- ATV hardware is mutually exclusive with other hardware types. -->
+    <unavailable-feature name="android.hardware.type.automotive" />
+    <unavailable-feature name="android.hardware.type.embedded" />
+    <unavailable-feature name="android.hardware.type.pc" />
+    <unavailable-feature name="android.hardware.type.watch" />
 </permissions>
diff --git a/products/aosp_tv_x86.mk b/products/aosp_tv_x86.mk
index f7cad49..aa4d882 100644
--- a/products/aosp_tv_x86.mk
+++ b/products/aosp_tv_x86.mk
@@ -61,7 +61,7 @@ endif
 # All components inherited here go to vendor image
 #
 $(call inherit-product, device/google/atv/products/atv_emulator_vendor.mk)
-$(call inherit-product, device/generic/goldfish/board/emu64x/kernel_fstab_32.mk)
+$(call inherit-product, device/google/atv/emulator_x86/kernel_fstab_32.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/board/generic_x86/device.mk)
 
 ifeq (aosp_tv_x86,$(TARGET_PRODUCT))
diff --git a/products/atv_logpersist.mk b/products/atv_logpersist.mk
index 3e4a291..fbe4ec5 100644
--- a/products/atv_logpersist.mk
+++ b/products/atv_logpersist.mk
@@ -1,5 +1,5 @@
 # Optional configuration that can be used to enable persistent logcat on -eng and -userdebug builds
-# See go/agw/platform/system/logging/+/refs/heads/master/logd/README.property for available options
+# See go/agw/platform/system/logging/+/refs/heads/main/logd/README.property.md for available options
 
 ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
 PRODUCT_PRODUCT_PROPERTIES += \
diff --git a/products/atv_product.mk b/products/atv_product.mk
index 9078a2d..17f87bd 100644
--- a/products/atv_product.mk
+++ b/products/atv_product.mk
@@ -36,6 +36,10 @@ PRODUCT_COPY_FILES += \
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.gamepad.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/android.hardware.gamepad.xml
 
+# Copy .kl file for generic voice remotes
+PRODUCT_PACKAGES += atv_generic_keylayout
+$(call soong_config_set_bool,atv_keylayouts,use_atv_generic_keylayout,true)
+
 # Too many tombstones can cause bugreports to grow too large to be uploaded.
 PRODUCT_PRODUCT_PROPERTIES += \
     tombstoned.max_tombstone_count?=10
diff --git a/products/atv_system.mk b/products/atv_system.mk
index 64252c7..12728b5 100644
--- a/products/atv_system.mk
+++ b/products/atv_system.mk
@@ -18,6 +18,7 @@
 
 # Release Configuration map
 PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/tv/release/release_config_map.textproto)
+PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/tv/release/gms_mainline/required/release_config_map.textproto)
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/media_system.mk)
 
@@ -113,10 +114,6 @@ PRODUCT_PROPERTY_OVERRIDES += \
 PRODUCT_PROPERTY_OVERRIDES += \
     ro.surface_flinger.update_device_product_info_on_hotplug_reconnect=1
 
-# Copy .kl file for generic voice remotes
-PRODUCT_COPY_FILES += \
-    device/google/atv/Generic.kl:system/usr/keylayout/Generic.kl
-
 PRODUCT_COPY_FILES += \
     device/google/atv/permissions/tv_core_hardware.xml:system/etc/permissions/tv_core_hardware.xml
 
diff --git a/products/atv_vendor.mk b/products/atv_vendor.mk
index cc046ce..5132986 100644
--- a/products/atv_vendor.mk
+++ b/products/atv_vendor.mk
@@ -34,3 +34,7 @@ BOARD_SEPOLICY_DIRS += device/google/atv/sepolicy/vendor
 #   Minor Device Class: 0x20 -> 32 (Set-top box) // default value, should be set to 0x3C for a TV
 PRODUCT_VENDOR_PROPERTIES += \
     bluetooth.device.class_of_device?=44,4,32
+
+# Configure TV to be a batteryless device.
+PRODUCT_VENDOR_PROPERTIES += \
+    ro.config.batteryless=true
```

