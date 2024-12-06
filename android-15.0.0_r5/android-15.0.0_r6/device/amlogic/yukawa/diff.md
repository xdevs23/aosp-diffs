```diff
diff --git a/BoardConfigCommon.mk b/BoardConfigCommon.mk
index e3b7152..9500115 100644
--- a/BoardConfigCommon.mk
+++ b/BoardConfigCommon.mk
@@ -33,10 +33,6 @@ WPA_SUPPLICANT_VERSION := VER_0_8_X
 BOARD_WPA_SUPPLICANT_DRIVER := NL80211
 BOARD_HOSTAPD_DRIVER := NL80211
 
-# Treble
-PRODUCT_FULL_TREBLE_OVERRIDE := true
-BOARD_VNDK_VERSION := current
-
 # AVB
 ifeq ($(TARGET_AVB_ENABLE), true)
 BOARD_AVB_ENABLE := true
diff --git a/device-yukawa.mk b/device-yukawa.mk
index c12413e..77f7432 100644
--- a/device-yukawa.mk
+++ b/device-yukawa.mk
@@ -46,4 +46,6 @@ endif
 
 # Include namespaces for non-AB updater
 PRODUCT_SOONG_NAMESPACES += bootable/deprecated-ota
+AB_OTA_UPDATER := false
+
 
```

