```diff
diff --git a/common/car.mk b/common/car.mk
index fe80c16..b724414 100644
--- a/common/car.mk
+++ b/common/car.mk
@@ -16,7 +16,7 @@
 
 # Auto modules
 PRODUCT_PACKAGES += \
-    android.hardware.automotive.vehicle@V3-emulator-service \
+    android.hardware.automotive.vehicle@V4-emulator-service \
     android.hardware.broadcastradio-service.default \
     android.hardware.audio.service-caremu \
     android.hardware.automotive.remoteaccess@V2-default-service \
diff --git a/common/config.ini b/common/config.ini
index c9fe78e..0635aed 100644
--- a/common/config.ini
+++ b/common/config.ini
@@ -40,6 +40,7 @@ disk.dataPartition.size=6G
 hw.accelerometer=yes
 hw.accelerometer_uncalibrated=yes
 hw.gyroscope=yes
+hw.sensors.heading=yes
 hw.sensors.light=no
 hw.sensors.pressure=no
 hw.sensors.humidity=no
diff --git a/emulator/Conn/SocketComm/Android.bp b/emulator/Conn/SocketComm/Android.bp
index f302d5e..87f99db 100644
--- a/emulator/Conn/SocketComm/Android.bp
+++ b/emulator/Conn/SocketComm/Android.bp
@@ -32,4 +32,8 @@ cc_library {
         "android.hardware.automotive.vehicle@2.0-libproto-native",
         "EmulatorCommConn",
     ],
+    cflags: select(soong_config_variable("qemu_debug", "socket_comm"), {
+        true: ["-DENABLE_EMULATOR_SOCKET_COMM"],
+        default: [],
+    }),
 }
diff --git a/emulator/Conn/SocketComm/SocketComm.cpp b/emulator/Conn/SocketComm/SocketComm.cpp
index 1e9a9bd..dd26fdb 100644
--- a/emulator/Conn/SocketComm/SocketComm.cpp
+++ b/emulator/Conn/SocketComm/SocketComm.cpp
@@ -42,14 +42,17 @@ SocketComm::~SocketComm() {
 }
 
 void SocketComm::start() {
+#ifdef ENABLE_EMULATOR_SOCKET_COMM
     if (!listen()) {
         return;
     }
 
     mListenThread = std::make_unique<std::thread>(std::bind(&SocketComm::listenThread, this));
+#endif
 }
 
 void SocketComm::stop() {
+#ifdef ENABLE_EMULATOR_SOCKET_COMM
     if (mListenFd > 0) {
         ::close(mListenFd);
         if (mListenThread->joinable()) {
@@ -57,6 +60,7 @@ void SocketComm::stop() {
         }
         mListenFd = -1;
     }
+#endif
 }
 
 void SocketComm::sendMessage(vhal_proto::EmulatorMessage const& msg) {
diff --git a/emulator/car_emulator_vendor.mk b/emulator/car_emulator_vendor.mk
index b4fa7b1..22682f8 100644
--- a/emulator/car_emulator_vendor.mk
+++ b/emulator/car_emulator_vendor.mk
@@ -52,7 +52,7 @@ PRODUCT_COPY_FILES += \
 
 # Auto modules
 PRODUCT_PACKAGES += \
-    android.hardware.automotive.vehicle@V3-emulator-service \
+    android.hardware.automotive.vehicle@V4-emulator-service \
     android.hardware.broadcastradio-service.default \
     android.hardware.audio.service-caremu \
     android.hardware.automotive.remoteaccess@V2-default-service \
@@ -104,6 +104,7 @@ PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.sensor.gyroscope_limited_axes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.gyroscope_limited_axes.xml \
     frameworks/native/data/etc/android.hardware.sensor.accelerometer_limited_axes_uncalibrated.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.accelerometer_limited_axes_uncalibrated.xml \
     frameworks/native/data/etc/android.hardware.sensor.gyroscope_limited_axes_uncalibrated.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.gyroscope_limited_axes_uncalibrated.xml \
+    frameworks/native/data/etc/android.hardware.sensor.heading.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.heading.xml \
 
 # Additional selinux policy
 BOARD_SEPOLICY_DIRS += device/generic/car/common/sepolicy
diff --git a/emulator/car_source.prop_template b/emulator/car_source.prop_template
new file mode 100644
index 0000000..587ee30
--- /dev/null
+++ b/emulator/car_source.prop_template
@@ -0,0 +1,12 @@
+Pkg.Desc=Android SDK System Image
+Pkg.UserSrc=false
+Pkg.Revision=2
+Pkg.Dependencies=emulator#${EMULATOR_MINIMAL_VERSION}
+AndroidVersion.ApiLevel=${PLATFORM_SDK_VERSION}
+AndroidVersion.CodeName=${PLATFORM_VERSION_CODENAME}
+AndroidVersion.ExtensionLevel=${PLATFORM_SDK_EXTENSION_VERSION}
+AndroidVersion.IsBaseSdk=${PLATFORM_IS_BASE_SDK}
+SystemImage.Abi=${TARGET_CPU_ABI}
+SystemImage.GpuSupport=true
+SystemImage.TagId=default
+SystemImage.TagDisplay=Default Android System Image
\ No newline at end of file
diff --git a/emulator/multi-display/androidRRO/res/xml/config_user_types.xml b/emulator/multi-display/androidRRO/res/xml/config_user_types.xml
index 8bd54ad..49a903b 100644
--- a/emulator/multi-display/androidRRO/res/xml/config_user_types.xml
+++ b/emulator/multi-display/androidRRO/res/xml/config_user_types.xml
@@ -15,7 +15,8 @@
 -->
 
 <user-types>
-    <full-type name="android.os.usertype.full.SECONDARY" >
+    <full-type name="android.os.usertype.full.SECONDARY"
+        max-allowed="9" >
         <default-restrictions />
     </full-type>
     <full-type name="android.os.usertype.full.GUEST"
diff --git a/emulator/rotary/car_rotary.mk b/emulator/rotary/car_rotary.mk
index f910724..d614d3b 100644
--- a/emulator/rotary/car_rotary.mk
+++ b/emulator/rotary/car_rotary.mk
@@ -19,4 +19,3 @@ PRODUCT_PACKAGES += \
     CarRotaryController \
     RotaryPlayground \
     RotaryIME \
-    CarRotaryImeRRO \
diff --git a/emulator/sepolicy/dumpstate.te b/emulator/sepolicy/dumpstate.te
new file mode 100644
index 0000000..668aab2
--- /dev/null
+++ b/emulator/sepolicy/dumpstate.te
@@ -0,0 +1,2 @@
+# Allow dumpstate to signal processes to dump.
+allow dumpstate hal_can_socketcan:process signal;
diff --git a/emulator/usbpt/usbip-service/sepolicy/usbip_service.te b/emulator/usbpt/usbip-service/sepolicy/usbip_service.te
index b885493..6640db2 100644
--- a/emulator/usbpt/usbip-service/sepolicy/usbip_service.te
+++ b/emulator/usbpt/usbip-service/sepolicy/usbip_service.te
@@ -1,4 +1,4 @@
-type usbip_service, domain;
+type usbip_service, domain, coredomain;
 type sysfs_usbip, sysfs_type, fs_type;
 type usbip_service_exec, exec_type, system_file_type, file_type;
 
diff --git a/emulator/usbpt/usbip-service/usbip-service.mk b/emulator/usbpt/usbip-service/usbip-service.mk
index 46b2ef7..7abe3ba 100644
--- a/emulator/usbpt/usbip-service/usbip-service.mk
+++ b/emulator/usbpt/usbip-service/usbip-service.mk
@@ -15,5 +15,5 @@
 #
 
 PRODUCT_PACKAGES += usbip_service
-BOARD_SEPOLICY_DIRS += device/generic/car/emulator/usbpt/usbip-service/sepolicy
+PRODUCT_PRIVATE_SEPOLICY_DIRS += device/generic/car/emulator/usbpt/usbip-service/sepolicy
 
diff --git a/emulator/vhal_aidl/Android.bp b/emulator/vhal_aidl/Android.bp
index 09376d7..fa6855d 100644
--- a/emulator/vhal_aidl/Android.bp
+++ b/emulator/vhal_aidl/Android.bp
@@ -20,7 +20,7 @@ package {
 }
 
 cc_binary {
-    name: "android.hardware.automotive.vehicle@V3-emulator-service",
+    name: "android.hardware.automotive.vehicle@V4-emulator-service",
     vendor: true,
     defaults: [
         "FakeVehicleHardwareDefaults",
diff --git a/emulator/vhal_aidl/vhal-emulator-service.rc b/emulator/vhal_aidl/vhal-emulator-service.rc
index db087c0..7a30e5f 100644
--- a/emulator/vhal_aidl/vhal-emulator-service.rc
+++ b/emulator/vhal_aidl/vhal-emulator-service.rc
@@ -1,4 +1,4 @@
-service vendor.vehicle-hal-emulator /vendor/bin/hw/android.hardware.automotive.vehicle@V3-emulator-service
+service vendor.vehicle-hal-emulator /vendor/bin/hw/android.hardware.automotive.vehicle@V4-emulator-service
     class early_hal
     user vehicle_network
     group system inet
diff --git a/emulator/vhal_aidl/vhal-emulator-service.xml b/emulator/vhal_aidl/vhal-emulator-service.xml
index 8148112..21c076a 100644
--- a/emulator/vhal_aidl/vhal-emulator-service.xml
+++ b/emulator/vhal_aidl/vhal-emulator-service.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.automotive.vehicle</name>
-        <version>3</version>
+        <version>4</version>
         <interface>
             <name>IVehicle</name>
             <instance>default</instance>
diff --git a/sdk_car_arm64.mk b/sdk_car_arm64.mk
index 3dbee86..c1ba0a7 100644
--- a/sdk_car_arm64.mk
+++ b/sdk_car_arm64.mk
@@ -24,6 +24,12 @@ PRODUCT_COPY_FILES += \
     device/generic/car/common/config.ini:config.ini
 endif # EMULATOR_DYNAMIC_MULTIDISPLAY_CONFIG
 
+# Set the source property file for SDK car products
+ifneq (,$(filter sdk_car%, $(TARGET_PRODUCT)))
+PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
+    device/generic/car/emulator/car_source.prop_template
+endif
+
 #
 # All components inherited here go to system image
 #
@@ -34,7 +40,9 @@ PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := strict
 
 #
 # All components inherited here go to system_ext image
+# But CarProvision must be excluded
 #
+DO_NOT_INCLUDE_DEFAULT_CAR_PROVISION := true
 $(call inherit-product, packages/services/Car/car_product/build/car_system_ext.mk)
 
 #
diff --git a/sdk_car_cw_x86_64.mk b/sdk_car_cw_x86_64.mk
index 8303c72..5025d53 100644
--- a/sdk_car_cw_x86_64.mk
+++ b/sdk_car_cw_x86_64.mk
@@ -26,9 +26,10 @@ DISABLE_CAR_PRODUCT_VISUAL_OVERLAY := true
 
 # Copy additional files
 PRODUCT_COPY_FILES += \
-    packages/services/Car/car_product/car_ui_portrait/car_ui_portrait.ini:config.ini \
+    packages/services/Car/car_product/dewd/config.ini:config.ini \
     packages/services/Car/car_product/car_ui_portrait/bootanimation/bootanimation.zip:system/media/bootanimation.zip
 
+$(call inherit-product, packages/services/Car/car_product/dewd/car_dewd_common.mk)
 $(call inherit-product, device/generic/car/sdk_car_x86_64.mk)
 
 # TODO(b/303863968): Set it to true after cleaning up the system partition
@@ -36,12 +37,6 @@ $(call inherit-product, device/generic/car/sdk_car_x86_64.mk)
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := false
 
 PRODUCT_NAME := sdk_car_cw_x86_64
-PRODUCT_MODEL := CarUiPortrait on x86_64 emulator
+PRODUCT_MODEL := cw on x86_64 emulator
 PRODUCT_CHARACTERISTICS := automotive
-PRODUCT_SDK_ADDON_NAME := sdk_car_portrait_x86_64
-
-$(call inherit-product, packages/services/Car/car_product/car_ui_portrait/apps/car_ui_portrait_apps.mk)
-$(call inherit-product, packages/services/Car/car_product/car_ui_portrait/rro/car_ui_portrait_rro.mk)
-
-PRODUCT_COPY_FILES += \
-    packages/services/Car/car_product/car_ui_portrait/car_ui_portrait_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/car_ui_portrait_hardware.xml
+PRODUCT_SDK_ADDON_NAME := sdk_car_cw_x86_64
diff --git a/sdk_car_x86_64.mk b/sdk_car_x86_64.mk
index 2069ed5..0d99d88 100644
--- a/sdk_car_x86_64.mk
+++ b/sdk_car_x86_64.mk
@@ -24,6 +24,12 @@ PRODUCT_COPY_FILES += \
     device/generic/car/common/config.ini:config.ini
 endif # EMULATOR_DYNAMIC_MULTIDISPLAY_CONFIG
 
+# Set the source property file for SDK car products
+ifneq (,$(filter sdk_car%, $(TARGET_PRODUCT)))
+PRODUCT_SDK_ADDON_SYS_IMG_SOURCE_PROP := \
+    device/generic/car/emulator/car_source.prop_template
+endif
+
 #
 # All components inherited here go to system image
 #
@@ -34,7 +40,9 @@ PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := strict
 
 #
 # All components inherited here go to system_ext image
+# But CarProvision must be excluded
 #
+DO_NOT_INCLUDE_DEFAULT_CAR_PROVISION := true
 $(call inherit-product, packages/services/Car/car_product/build/car_system_ext.mk)
 
 #
```

