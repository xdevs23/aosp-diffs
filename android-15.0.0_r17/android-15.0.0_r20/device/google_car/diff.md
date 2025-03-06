```diff
diff --git a/common/pre_google_car.mk b/common/pre_google_car.mk
index ff6d709..dc3f969 100644
--- a/common/pre_google_car.mk
+++ b/common/pre_google_car.mk
@@ -57,7 +57,7 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
 ifneq ($(PIXEL_2023_GEN),)
     PRODUCT_PACKAGES += \
         android.hardware.broadcastradio \
-        android.hardware.automotive.vehicle@V3-default-service
+        android.hardware.automotive.vehicle@V4-default-service
 else
     PRODUCT_PACKAGES += \
         android.hardware.broadcastradio@2.0-service \
diff --git a/common/unavailable_features.xml b/common/unavailable_features.xml
index ebadbf7..01a7202 100644
--- a/common/unavailable_features.xml
+++ b/common/unavailable_features.xml
@@ -15,6 +15,27 @@
 -->
 
 <permissions>
-    <!-- No Managed users feature -->
+    <unavailable-feature name="android.hardware.broadcastradio" />
+    <unavailable-feature name="android.hardware.camera.capability.manual_post_processing" />
+    <unavailable-feature name="android.hardware.camera.capability.manual_sensor" />
+    <unavailable-feature name="android.hardware.camera.capability.raw" />
+    <unavailable-feature name="android.hardware.camera.level.full" />
+    <unavailable-feature name="android.hardware.context_hub" />
+    <unavailable-feature name="android.hardware.fingerprint" />
+    <unavailable-feature name="android.hardware.location.network" />
+    <unavailable-feature name="android.hardware.identity_credential" />
+    <unavailable-feature name="android.hardware.sensor.stepcounter" />
+    <unavailable-feature name="android.hardware.sensor.stepdetector" />
+    <unavailable-feature name="android.hardware.telephony" />
+    <unavailable-feature name="android.hardware.telephony.calling" />
+    <unavailable-feature name="android.hardware.telephony.cdma" />
+    <unavailable-feature name="android.hardware.telephony.data" />
+    <unavailable-feature name="android.hardware.telephony.gsm" />
+    <unavailable-feature name="android.hardware.telephony.messaging" />
+    <unavailable-feature name="android.hardware.telephony.radio.access" />
+    <unavailable-feature name="android.hardware.telephony.subscription" />
+    <unavailable-feature name="android.software.app_widgets" />
+    <unavailable-feature name="android.software.backup" />
     <unavailable-feature name="android.software.managed_users" />
+    <unavailable-feature name="android.software.print" />
 </permissions>
\ No newline at end of file
diff --git a/tangorpro_car/BoardConfig.mk b/tangorpro_car/BoardConfig.mk
index 7d7a452..cb4a835 100644
--- a/tangorpro_car/BoardConfig.mk
+++ b/tangorpro_car/BoardConfig.mk
@@ -15,8 +15,11 @@
 #
 
 # Adjust the TARGET_SCREEN_DENSITY based on the target name
-ifeq (,$(findstring tangorpro_ui_portrait_car, $(TARGET_PRODUCT)))
+ifeq (,$(filter tangorpro_ui_portrait_car tangorpro_car_cw, $(TARGET_PRODUCT)))
     TARGET_SCREEN_DENSITY := 280
 else
     TARGET_SCREEN_DENSITY := 150
 endif
+
+# Wifi interface combination - {1 STA + 1 P2P} or {1 STA + 1 NAN} or {1 STA + 1 AP}
+WIFI_HAL_INTERFACE_COMBINATIONS := {{{STA}, 1}, {{P2P, NAN, AP}, 1}}
diff --git a/tangorpro_car/device-tangorpro-car.mk b/tangorpro_car/device-tangorpro-car.mk
index b425e88..98cd7cc 100644
--- a/tangorpro_car/device-tangorpro-car.mk
+++ b/tangorpro_car/device-tangorpro-car.mk
@@ -22,8 +22,13 @@ $(call inherit-product, device/google/tangorpro/device-tangorpro.mk)
 
 #include device/google/gs101/uwb/uwb.mk
 
+PRODUCT_PRODUCT_PROPERTIES+= \
+    ro.oem.key1=AAE00GOOG00TANGORPRO
+
+ifneq ($(TARGET_BUILD_VARIANT),user)
 PRODUCT_PRODUCT_PROPERTIES+= \
     ro.adb.secure=0
+endif
 
 PRODUCT_PACKAGES += \
     librs_jni
```

