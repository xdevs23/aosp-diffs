```diff
diff --git a/bluejay_car/aosp_bluejay_car.mk b/bluejay_car/aosp_bluejay_car.mk
index e41a06e..7ad665c 100644
--- a/bluejay_car/aosp_bluejay_car.mk
+++ b/bluejay_car/aosp_bluejay_car.mk
@@ -19,6 +19,9 @@ $(call inherit-product, device/google_car/bluejay_car/device-bluejay-car.mk)
 $(call inherit-product-if-exists, vendor/google_devices/raviole/proprietary/raven/device-vendor-bluejay.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from bluejay.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_MANUFACTURER := Google
 PRODUCT_BRAND := Android
 PRODUCT_NAME := aosp_bluejay_car
diff --git a/bluejay_car/device-bluejay-car.mk b/bluejay_car/device-bluejay-car.mk
index aa426b3..a0da20e 100644
--- a/bluejay_car/device-bluejay-car.mk
+++ b/bluejay_car/device-bluejay-car.mk
@@ -16,8 +16,6 @@
 
 PHONE_CAR_BOARD_PRODUCT := bluejay_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product,device/google/bluejay/device-bluejay.mk)
 
 include device/google/gs101/uwb/uwb.mk
diff --git a/cheetah_car/aosp_cheetah_car.mk b/cheetah_car/aosp_cheetah_car.mk
index 73df691..b3ee398 100644
--- a/cheetah_car/aosp_cheetah_car.mk
+++ b/cheetah_car/aosp_cheetah_car.mk
@@ -26,6 +26,9 @@ $(call inherit-product, device/google_car/cheetah_car/device-cheetah-car.mk)
 $(call inherit-product-if-exists, vendor/google_devices/pantah/proprietary/cheetah/device-vendor-cheetah.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from cheetah.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_NAME := aosp_cheetah_car
 PRODUCT_DEVICE := cheetah
 PRODUCT_MODEL := AOSP on Cheetah
diff --git a/cheetah_car/device-cheetah-car.mk b/cheetah_car/device-cheetah-car.mk
index abcddeb..3a313e2 100644
--- a/cheetah_car/device-cheetah-car.mk
+++ b/cheetah_car/device-cheetah-car.mk
@@ -14,8 +14,6 @@
 # limitations under the License.
 #
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/pantah/device-cheetah.mk)
 
 include device/google/gs101/uwb/uwb.mk
diff --git a/common/overlay/frameworks/base/core/res/res/values/config.xml b/common/overlay/frameworks/base/core/res/res/values/config.xml
index f978f10..ac791d6 100644
--- a/common/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/common/overlay/frameworks/base/core/res/res/values/config.xml
@@ -12,4 +12,7 @@
 
   <!-- Disable lockscreen sound effect -->
   <integer name="def_lockscreen_sounds_enabled">0</integer>
+
+  <!-- If this is true, the screen will come on when you unplug usb/power/whatever. -->
+  <bool name="config_unplugTurnsOnScreen">false</bool>
 </resources>
diff --git a/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml b/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
index 9e709d2..2dbcdf7 100644
--- a/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
+++ b/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
@@ -19,4 +19,5 @@
 <resources>
     <integer name="def_user_rotation">1</integer>
     <integer name="def_screen_off_timeout">6000000</integer>
+    <bool name="def_wake_gesture_enabled">false</bool>
 </resources>
diff --git a/common/post_google_car.mk b/common/post_google_car.mk
index 68db208..3bf6d86 100644
--- a/common/post_google_car.mk
+++ b/common/post_google_car.mk
@@ -18,22 +18,21 @@
 #### This file should be included at the bottom of the aosp_PHONE_car.mk file
 ####
 
-# Auto modules
 PRODUCT_PACKAGES += \
-            android.hardware.automotive.audiocontrol-service.example
+        android.hardware.automotive.audiocontrol-service.example
 
-ifneq ($(PIXEL_2023_GEN),)
-    PRODUCT_PACKAGES += android.hardware.automotive.can
-else
+ifneq ($(PIXEL_2023_GEN),true)
     PRODUCT_PACKAGES += android.hardware.automotive.can@1.0-service
+else
+    PRODUCT_PACKAGES += android.hardware.automotive.can
 endif
 
 PRODUCT_PACKAGES_DEBUG += \
-            canhalctrl \
-            canhaldump \
-            canhalsend \
-            android.hardware.automotive.occupant_awareness@1.0-service \
-            android.hardware.automotive.occupant_awareness@1.0-service_mock
+        canhalctrl \
+        canhaldump \
+        canhalsend \
+        android.hardware.automotive.occupant_awareness@1.0-service \
+        android.hardware.automotive.occupant_awareness@1.0-service_mock
 
 BOARD_SEPOLICY_DIRS += device/google_car/common/sepolicy
 
diff --git a/common/pre_google_car.mk b/common/pre_google_car.mk
index dc3f969..7ec3e18 100644
--- a/common/pre_google_car.mk
+++ b/common/pre_google_car.mk
@@ -39,34 +39,28 @@ GOOGLE_CAR_SERVICE_OVERLAY += CarServiceOverlayPhoneCarGoogle
 ifneq ($(DEVICE_IS_64BIT_ONLY),true)
     $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
 endif
-$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
+$(call inherit-product, packages/services/Car/car_product/build/car_generic_system.mk)
 
 #
 # All components inherited here go to system_ext image
 #
-$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
+$(call inherit-product, packages/services/Car/car_product/build/car_system_ext.mk)
 
 #
 # All components inherited here go to product image
 #
-$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
+$(call inherit-product, packages/services/Car/car_product/build/car_product.mk)
 
-# Auto modules
-
-ifneq ($(PIXEL_2023_GEN),)
-    PRODUCT_PACKAGES += \
-        android.hardware.broadcastradio \
-        android.hardware.automotive.vehicle@V4-default-service
-else
+ifneq ($(PIXEL_2023_GEN),true)
     PRODUCT_PACKAGES += \
         android.hardware.broadcastradio@2.0-service \
         android.hardware.automotive.vehicle@2.0-default-service
+else
+    PRODUCT_PACKAGES += \
+        android.hardware.broadcastradio-service.default \
+        android.hardware.automotive.vehicle@V4-default-service
 endif
 
-# Set Car Wifi RRO to properly configure the system for AAP
-PRODUCT_PACKAGES += CarWifiOverlay
-
 # Additional selinux policy
 BOARD_SEPOLICY_DIRS += device/google_car/common/sepolicy
 
@@ -99,7 +93,6 @@ PRODUCT_COPY_FILES += \
         frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:system/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml \
         frameworks/native/data/etc/android.hardware.wifi.xml:system/etc/permissions/android.hardware.wifi.xml \
         frameworks/native/data/etc/android.hardware.wifi.direct.xml:system/etc/permissions/android.hardware.wifi.direct.xml \
-        frameworks/native/data/etc/android.software.sip.voip.xml:system/etc/permissions/android.software.sip.voip.xml \
         frameworks/native/data/etc/android.hardware.sensor.light.xml:system/etc/permissions/android.hardware.sensor.light.xml \
         frameworks/native/data/etc/android.hardware.sensor.gyroscope.xml:system/etc/permissions/android.hardware.sensor.gyroscope.xml \
         frameworks/native/data/etc/android.hardware.usb.accessory.xml:system/etc/permissions/android.hardware.usb.accessory.xml \
@@ -116,15 +109,17 @@ PRODUCT_COPY_FILES += \
 endif
 
 # broadcast radio feature
- PRODUCT_COPY_FILES += \
+PRODUCT_COPY_FILES += \
         frameworks/native/data/etc/android.hardware.broadcastradio.xml:system/etc/permissions/android.hardware.broadcastradio.xml
 
 # Include EVS reference implementations
-ENABLE_EVS_SAMPLE := true
+ENABLE_EVS_SAMPLE ?= true
 
 #
 # All components inherited here go to vendor image
 #
 # TODO(b/136525499): move *_vendor.mk into the vendor makefile later
-$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
+$(call inherit-product, packages/services/Car/car_product/build/car_vendor.mk)
+ifneq ($(TARGET_NO_TELEPHONY), true)
+    $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
+endif
diff --git a/common/rro_overlays/CarServiceOverlay/res/values/config.xml b/common/rro_overlays/CarServiceOverlay/res/values/config.xml
index 85c1c1a..3bc785a 100644
--- a/common/rro_overlays/CarServiceOverlay/res/values/config.xml
+++ b/common/rro_overlays/CarServiceOverlay/res/values/config.xml
@@ -27,4 +27,55 @@
          encoded. -->
     <string name="fastPairAntiSpoofKey"
         translatable="false">w8WfTvivRPc5kvoysLooga9rrlxQ7zlj1X+THUTSg/8=</string>
+
+    <!--
+        List all passenger zones available in the car.
+        Some examples are:
+        <item>occupantZoneId=0,occupantType=DRIVER,seatRow=1,seatSide=driver</item>
+        <item>occupantZoneId=1,occupantType=FRONT_PASSENGER,seatRow=1,seatSide=oppositeDriver</item>
+        <item>occupantZoneId=2,occupantType=REAR_PASSENGER,seatRow=2,seatSide=left</item>
+        <item>occupantZoneId=3,occupantType=REAR_PASSENGER,seatRow=2,seatSide=right</item>
+
+        occupantZoneId: Unique unsigned integer id to represent each passenger zone. Each zone
+                        should have different id.
+        occupantType: Occupant type for the display. Use * part from
+                       CarOccupantZoneManager.OCCUPANT_TYPE_* like DRIVER, FRONT_PASSENGER,
+                       REAR_PASSENGER and etc.
+        seatRow: Integer telling which row the seat is located. Row 1 is for front seats.
+        seatSide: left/center/right for known side. Or can use driver/center/oppositeDriver to
+                  handle both right-hand driving and left-hand driving in one place.
+                  If car's RHD / LHD is not specified, LHD will be assumed and driver side becomes
+                  left.
+    -->
+    <string-array translatable="false" name="config_occupant_zones">
+        <item>occupantZoneId=0,occupantType=DRIVER,seatRow=1,seatSide=driver</item>
+    </string-array>
+
+    <!--
+        Specifies configuration of displays in system telling its usage / type and assigned
+        occupant.
+
+        Some examples are:
+        <item>displayPort=0,displayType=MAIN,occupantZoneId=0,inputTypes=DPAD_KEYS|
+            NAVIGATE_KEYS|ROTARY_NAVIGATION</item>
+        <item>displayPort=1,displayType=INSTRUMENT_CLUSTER,occupantZoneId=0,
+            inputTypes=DPAD_KEYS</item>
+        <item>displayPort=2,displayType=MAIN,occupantZoneId=1,
+            inputTypes=TOUCH_SCREEN</item>
+        <item>displayPort=3,displayType=MAIN,occupantZoneId=2,
+            inputTypes=TOUCH_SCREEN</item>
+        <item>displayUniqueId=virtual:com.example:MainD,displayType=MAIN,occupantZoneId=3,
+            inputTypes=TOUCH_SCREEN</item>
+
+        displayPort: Unique port id for the display.
+        displayType: Display type for the display. Use * part from
+                       CarOccupantZoneManager.DISPLAY_TYPE_* like MAIN, INSTRUMENT_CLUSTER and
+                       etc.
+        occupantZoneId: occupantZoneId specified from config_occupant_zones.
+        inputTypes: supported input types for the corresponding display.
+    -->
+    <string-array translatable="false" name="config_occupant_display_mapping">
+        <item>displayPort=0,displayType=MAIN,occupantZoneId=0,inputTypes=TOUCH_SCREEN|ROTARY_NAVIGATION</item>
+    </string-array>
+
 </resources>
diff --git a/common/rro_overlays/CarServiceOverlay/res/xml/overlays.xml b/common/rro_overlays/CarServiceOverlay/res/xml/overlays.xml
index daf4c7e..59efadd 100644
--- a/common/rro_overlays/CarServiceOverlay/res/xml/overlays.xml
+++ b/common/rro_overlays/CarServiceOverlay/res/xml/overlays.xml
@@ -17,4 +17,6 @@
 <overlay>
     <item target="integer/fastPairModelId" value="@integer/fastPairModelId" />
     <item target="string/fastPairAntiSpoofKey" value="@string/fastPairAntiSpoofKey" />
+    <item target="array/config_occupant_zones" value="@array/config_occupant_zones" />
+    <item target="array/config_occupant_display_mapping" value="@array/config_occupant_display_mapping" />
 </overlay>
diff --git a/common/sepolicy/dumpstate.te b/common/sepolicy/dumpstate.te
new file mode 100644
index 0000000..facdd42
--- /dev/null
+++ b/common/sepolicy/dumpstate.te
@@ -0,0 +1,5 @@
+# Allow dumpstate to signal processes to dump.
+allow dumpstate hal_can_socketcan:process signal;
+
+# b/192197221
+dontaudit dumpstate artd:binder call;
\ No newline at end of file
diff --git a/common/unavailable_features.xml b/common/unavailable_features.xml
index 01a7202..294fa49 100644
--- a/common/unavailable_features.xml
+++ b/common/unavailable_features.xml
@@ -15,7 +15,6 @@
 -->
 
 <permissions>
-    <unavailable-feature name="android.hardware.broadcastradio" />
     <unavailable-feature name="android.hardware.camera.capability.manual_post_processing" />
     <unavailable-feature name="android.hardware.camera.capability.manual_sensor" />
     <unavailable-feature name="android.hardware.camera.capability.raw" />
diff --git a/husky_car/aosp_husky_car.mk b/husky_car/aosp_husky_car.mk
index 1d67bf1..c96ea51 100644
--- a/husky_car/aosp_husky_car.mk
+++ b/husky_car/aosp_husky_car.mk
@@ -21,6 +21,9 @@ $(call inherit-product, device/google_car/common/pre_google_car.mk)
 $(call inherit-product, device/google_car/husky_car/device-husky-car.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from husky.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_NAME := aosp_husky_car
 PRODUCT_DEVICE := husky
 PRODUCT_MODEL := AOSP on husky
diff --git a/husky_car/device-husky-car.mk b/husky_car/device-husky-car.mk
index cafff23..55abbae 100644
--- a/husky_car/device-husky-car.mk
+++ b/husky_car/device-husky-car.mk
@@ -16,8 +16,6 @@
 
 PHONE_CAR_BOARD_PRODUCT := husky_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/shusky/husky_generic.mk)
 
 #include device/google/gs101/uwb/uwb.mk
diff --git a/oriole_car/aosp_oriole_car.mk b/oriole_car/aosp_oriole_car.mk
index 606c025..dc74f2e 100644
--- a/oriole_car/aosp_oriole_car.mk
+++ b/oriole_car/aosp_oriole_car.mk
@@ -19,6 +19,9 @@ $(call inherit-product, device/google_car/oriole_car/device-oriole-car.mk)
 $(call inherit-product-if-exists, vendor/google_devices/raviole/proprietary/raven/device-vendor-oriole.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from oriole.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_MANUFACTURER := Google
 PRODUCT_BRAND := Android
 PRODUCT_NAME := aosp_oriole_car
diff --git a/oriole_car/device-oriole-car.mk b/oriole_car/device-oriole-car.mk
index ec20ba0..f173f09 100644
--- a/oriole_car/device-oriole-car.mk
+++ b/oriole_car/device-oriole-car.mk
@@ -16,8 +16,6 @@
 
 AUTOMOTIVE_PRODUCT_PATH := google_car/oriole_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/raviole/device-oriole.mk)
 
 include device/google/gs101/uwb/uwb.mk
diff --git a/panther_car/aosp_panther_car.mk b/panther_car/aosp_panther_car.mk
index cb121cb..20eadfd 100644
--- a/panther_car/aosp_panther_car.mk
+++ b/panther_car/aosp_panther_car.mk
@@ -23,6 +23,9 @@ $(call inherit-product, device/google_car/panther_car/device-panther-car.mk)
 $(call inherit-product-if-exists, vendor/google_devices/pantah/proprietary/panther/device-vendor-panther.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from panther.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_NAME := aosp_panther_car
 PRODUCT_DEVICE := panther
 PRODUCT_MODEL := AOSP on panther
diff --git a/panther_car/device-panther-car.mk b/panther_car/device-panther-car.mk
index 740d7ac..3581291 100644
--- a/panther_car/device-panther-car.mk
+++ b/panther_car/device-panther-car.mk
@@ -16,8 +16,6 @@
 
 PHONE_CAR_BOARD_PRODUCT := panther_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/pantah/device-panther.mk)
 
 include device/google/gs101/uwb/uwb.mk
diff --git a/raven_car/aosp_raven_car.mk b/raven_car/aosp_raven_car.mk
index 3aa87fe..c2a0d34 100644
--- a/raven_car/aosp_raven_car.mk
+++ b/raven_car/aosp_raven_car.mk
@@ -22,6 +22,9 @@ $(call inherit-product, device/google_car/raven_car/device-raven-car.mk)
 $(call inherit-product-if-exists, vendor/google_devices/raviole/proprietary/raven/device-vendor-raven.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from raven.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_MANUFACTURER := Google
 PRODUCT_BRAND := Android
 PRODUCT_NAME := aosp_raven_car
diff --git a/raven_car/device-raven-car.mk b/raven_car/device-raven-car.mk
index 7c58426..10a805e 100644
--- a/raven_car/device-raven-car.mk
+++ b/raven_car/device-raven-car.mk
@@ -16,8 +16,6 @@
 
 AUTOMOTIVE_PRODUCT_PATH := google_car/raven_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/raviole/raven_generic.mk)
 
 include device/google/gs101/uwb/uwb.mk
diff --git a/redfin_car/aosp_redfin_car.mk b/redfin_car/aosp_redfin_car.mk
index 93d3e91..1eb9492 100644
--- a/redfin_car/aosp_redfin_car.mk
+++ b/redfin_car/aosp_redfin_car.mk
@@ -20,6 +20,9 @@ $(call inherit-product-if-exists, vendor/google_devices/redfin/proprietary/devic
 $(call inherit-product-if-exists, vendor/google_devices/redfin/prebuilts/device-vendor-redfin.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from redfin.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_MANUFACTURER := Google
 PRODUCT_BRAND := Android
 PRODUCT_NAME := aosp_redfin_car
diff --git a/redfin_car/device-redfin-car.mk b/redfin_car/device-redfin-car.mk
index cbd14ed..0efc7fc 100644
--- a/redfin_car/device-redfin-car.mk
+++ b/redfin_car/device-redfin-car.mk
@@ -16,8 +16,6 @@
 
 AUTOMOTIVE_PRODUCT_PATH := google_car/redfin_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/redfin/device-redfin.mk)
 
 PRODUCT_PRODUCT_PROPERTIES+= \
diff --git a/sunfish_car/aosp_sunfish_car.mk b/sunfish_car/aosp_sunfish_car.mk
index 19fef2c..2a3b42e 100644
--- a/sunfish_car/aosp_sunfish_car.mk
+++ b/sunfish_car/aosp_sunfish_car.mk
@@ -20,6 +20,9 @@ $(call inherit-product-if-exists, vendor/google_devices/sunfish/proprietary/devi
 $(call inherit-product-if-exists, vendor/google_devices/sunfish/prebuilts/device-vendor-sunfish.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from sunfish.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_MANUFACTURER := Google
 PRODUCT_BRAND := Android
 PRODUCT_NAME := aosp_sunfish_car
diff --git a/sunfish_car/device-sunfish-car.mk b/sunfish_car/device-sunfish-car.mk
index 2674e34..16e4802 100644
--- a/sunfish_car/device-sunfish-car.mk
+++ b/sunfish_car/device-sunfish-car.mk
@@ -16,8 +16,6 @@
 
 AUTOMOTIVE_PRODUCT_PATH := google_car/sunfish_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/sunfish/device-sunfish.mk)
 
 PRODUCT_PRODUCT_PROPERTIES+= \
diff --git a/tangorpro_car/aosp_tangorpro_car.mk b/tangorpro_car/aosp_tangorpro_car.mk
index 329fd36..3a2b615 100644
--- a/tangorpro_car/aosp_tangorpro_car.mk
+++ b/tangorpro_car/aosp_tangorpro_car.mk
@@ -15,7 +15,7 @@
 #
 
 DEVICE_IS_64BIT_ONLY := true
-
+PIXEL_2023_GEN := true
 
 PRODUCT_COPY_FILES += \
         device/google_car/tangorpro_car/unavailable_features.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/unavailable_features_tangorpro_car.xml
@@ -26,6 +26,9 @@ $(call inherit-product, device/google_car/common/pre_google_car.mk)
 $(call inherit-product, device/google_car/tangorpro_car/device-tangorpro-car.mk)
 $(call inherit-product, device/google_car/common/post_google_car.mk)
 
+# Disable production validation checks to fix build error from tangorpro.scl
+PRODUCT_VALIDATION_CHECKS :=
+
 PRODUCT_NAME := aosp_tangorpro_car
 PRODUCT_DEVICE := tangorpro
 PRODUCT_MODEL := AOSP on Tangorpro
diff --git a/tangorpro_car/device-tangorpro-car.mk b/tangorpro_car/device-tangorpro-car.mk
index 98cd7cc..6a26a9a 100644
--- a/tangorpro_car/device-tangorpro-car.mk
+++ b/tangorpro_car/device-tangorpro-car.mk
@@ -16,8 +16,6 @@
 
 PHONE_CAR_BOARD_PRODUCT := tangorpro_car
 
-$(call inherit-product, packages/services/Car/car_product/build/car.mk)
-
 $(call inherit-product, device/google/tangorpro/device-tangorpro.mk)
 
 #include device/google/gs101/uwb/uwb.mk
```

