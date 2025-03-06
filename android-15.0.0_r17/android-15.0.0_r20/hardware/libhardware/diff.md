```diff
diff --git a/Android.bp b/Android.bp
index b88f5418..67d68686 100644
--- a/Android.bp
+++ b/Android.bp
@@ -131,3 +131,9 @@ cc_library_shared {
     },
     min_sdk_version: "29",
 }
+
+dirgroup {
+    name: "trusty_dirgroup_hardware_libhardware",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/hardware.c b/hardware.c
index 94b5d5d3..a89077df 100644
--- a/hardware.c
+++ b/hardware.c
@@ -181,18 +181,16 @@ static int hw_module_exists(char *path, size_t path_len, const char *name,
 #ifdef __ANDROID_APEX__
     // When used in VAPEX, it should look only into the same APEX because
     // libhardware modules don't provide ABI stability.
-#if __ANDROID_VENDOR_API__ >= 202404
-    AApexInfo *apex_info;
-    if (AApexInfo_create(&apex_info) == AAPEXINFO_OK) {
-        snprintf(path, path_len, "/apex/%s/%s/%s.%s.so",
-                 AApexInfo_getName(apex_info), HAL_LIBRARY_SUBDIR, name, subname);
-        AApexInfo_destroy(apex_info);
-        if (access(path, R_OK) == 0)
-            return 0;
+    if (__builtin_available(android __ANDROID_API_V__, *)) {
+        AApexInfo *apex_info;
+        if (AApexInfo_create(&apex_info) == AAPEXINFO_OK) {
+            snprintf(path, path_len, "/apex/%s/%s/%s.%s.so",
+                    AApexInfo_getName(apex_info), HAL_LIBRARY_SUBDIR, name, subname);
+            AApexInfo_destroy(apex_info);
+            if (access(path, R_OK) == 0)
+                return 0;
+        }
     }
-#else  // __ANDROID_VENDOR_API__
-    ALOGE("hw_module_exists: libapexsupport is not supported in %d.", __ANDROID_VENDOR_API__);
-#endif // __ANDROID_VENDOR_API__
 #else // __ANDROID_APEX__
     snprintf(path, path_len, "%s/%s.%s.so",
              HAL_LIBRARY_PATH3, name, subname);
diff --git a/include_all/hardware/keymaster_defs.h b/include_all/hardware/keymaster_defs.h
index dd286d6d..6f9f7bf3 100644
--- a/include_all/hardware/keymaster_defs.h
+++ b/include_all/hardware/keymaster_defs.h
@@ -177,6 +177,8 @@ typedef enum {
     KM_TAG_STORAGE_KEY = KM_BOOL | 722,             /* storage encryption key */
     KM_TAG_ATTESTATION_ID_SECOND_IMEI = KM_BYTES | 723,   /* Used to provide the device's second
                                                              IMEI to be included in attestation */
+    KM_TAG_MODULE_HASH = KM_BYTES | 724,            /* Used to record the hash of apex module
+                                                       information to be included in attestation */
 
     /* Tags used only to provide data to or receive data from operations */
     KM_TAG_ASSOCIATED_DATA = KM_BYTES | 1000, /* Used to provide associated data for AEAD modes. */
@@ -516,6 +518,8 @@ typedef enum {
     KM_ERROR_MISSING_ISSUER_SUBJECT = -82,
     KM_ERROR_INVALID_ISSUER_SUBJECT = -83,
     KM_ERROR_BOOT_LEVEL_EXCEEDED = -84,
+    KM_ERROR_HARDWARE_NOT_YET_AVAILABLE = -85,
+    KM_ERROR_MODULE_HASH_ALREADY_SET = -86,
 
     KM_ERROR_UNIMPLEMENTED = -100,
     KM_ERROR_VERSION_MISMATCH = -101,
diff --git a/include_all/hardware/sensors.h b/include_all/hardware/sensors.h
index 5f490b53..9b3e3333 100644
--- a/include_all/hardware/sensors.h
+++ b/include_all/hardware/sensors.h
@@ -96,6 +96,11 @@ enum {
  */
 #define SENSOR_PERMISSION_BODY_SENSORS "android.permission.BODY_SENSORS"
 
+/*
+ * The permission to use for reading heart rate sensors.
+ */
+#define SENSOR_PERMISSION_READ_HEART_RATE "android.permission.health.READ_HEART_RATE"
+
 /*
  * sensor flags legacy names
  *
diff --git a/modules/sensors/dynamic_sensor/Android.bp b/modules/sensors/dynamic_sensor/Android.bp
index dbb3d932..00de46db 100644
--- a/modules/sensors/dynamic_sensor/Android.bp
+++ b/modules/sensors/dynamic_sensor/Android.bp
@@ -143,7 +143,9 @@ cc_library_shared {
 cc_binary_host {
     name: "hidrawsensor_host_test",
     defaults: ["dynamic_sensor_defaults"],
-
+    static_libs: [
+        "libutils_binder",
+    ],
     srcs: [
         "HidRawSensor.cpp",
         "BaseSensorObject.cpp",
@@ -159,7 +161,9 @@ cc_binary_host {
 cc_binary_host {
     name: "hidrawdevice_host_test",
     defaults: ["dynamic_sensor_defaults"],
-
+    static_libs: [
+        "libutils_binder",
+    ],
     srcs: [
         "HidRawDevice.cpp",
         "HidRawSensor.cpp",
diff --git a/modules/sensors/dynamic_sensor/HidRawDevice.cpp b/modules/sensors/dynamic_sensor/HidRawDevice.cpp
index 6032ed95..ae763e1f 100644
--- a/modules/sensors/dynamic_sensor/HidRawDevice.cpp
+++ b/modules/sensors/dynamic_sensor/HidRawDevice.cpp
@@ -215,7 +215,7 @@ bool HidRawDevice::getFeature(uint8_t id, std::vector<uint8_t> *out) {
     }
     if (mIoBuffer.front() != id) {
         LOG_E << "HidRawDevice::getFeature: get feature " << static_cast<int>(id)
-              << " result has header " << mIoBuffer.front() << LOG_ENDL;
+              << " result has header " << static_cast<int>(mIoBuffer.front()) << LOG_ENDL;
     }
     out->resize(size - 1);
     std::copy(mIoBuffer.begin() + 1, mIoBuffer.begin() + size, out->begin());
diff --git a/modules/sensors/dynamic_sensor/HidRawSensor.cpp b/modules/sensors/dynamic_sensor/HidRawSensor.cpp
index b61185dc..d9c1e669 100644
--- a/modules/sensors/dynamic_sensor/HidRawSensor.cpp
+++ b/modules/sensors/dynamic_sensor/HidRawSensor.cpp
@@ -18,6 +18,7 @@
 
 #include <android-base/properties.h>
 #include <utils/Errors.h>
+#include <utils/Unicode.h>
 #include <com_android_libhardware_dynamic_sensors_flags.h>
 #include "HidLog.h"
 
@@ -421,7 +422,14 @@ const HidParser::ReportItem *HidRawSensor::find(
 
 void HidRawSensor::initFeatureValueFromHidDeviceInfo(
         FeatureValue *featureValue, const HidDevice::HidDeviceInfo &info) {
-    featureValue->name = info.name;
+    const uint8_t *str8 = (uint8_t *)info.name.c_str();
+    const ssize_t len16 = utf8_to_utf16_length(str8, info.name.size());
+    if (len16 != -1) {
+        featureValue->name = info.name;
+    } else {
+        LOG_E << "Received an invalid sensor name" << LOG_ENDL;
+        featureValue->name = "Invalid sensor name";
+    }
 
     std::ostringstream ss;
     ss << info.busType << " "
@@ -988,12 +996,13 @@ int HidRawSensor::enable(bool enable) {
     SP(HidDevice) device = PROMOTE(mDevice);
 
     if (device == nullptr) {
-        LOG_E << "enable: no device" << LOG_ENDL;
+        LOG_E << "enable(" << enable << "): no device" << LOG_ENDL;
         return NO_INIT;
     }
 
     if (enable == mEnabled) {
-        LOG_D << "enable: already in desired state" << LOG_ENDL;
+        LOG_D << "enable(" << enable << "): already in desired state"
+              << LOG_ENDL;
         return NO_ERROR;
     }
 
@@ -1002,10 +1011,10 @@ int HidRawSensor::enable(bool enable) {
     bool setReportingOk = setReportingState(device, enable);
     if (setPowerOk && setReportingOk && setLeAudioTransportOk) {
         mEnabled = enable;
-        LOG_I << "enable: success" << LOG_ENDL;
+        LOG_I << "enable(" << enable << "): success" << LOG_ENDL;
         return NO_ERROR;
     } else {
-        LOG_E << "enable: set feature failed" << LOG_ENDL;
+        LOG_E << "enable(" << enable << "): set feature failed" << LOG_ENDL;
         return INVALID_OPERATION;
     }
 }
@@ -1047,10 +1056,10 @@ bool HidRawSensor::setLeAudioTransport(const SP(HidDevice) &device, bool enable)
                               mLeTransportBitOffset, mLeTransportBitSize);
             success = device->setFeature(id, buffer);
             if (!success) {
-              LOG_E << "enable: setFeature VENDOR LE TRANSPORT failed" << LOG_ENDL;
+              LOG_E << "enable(" << enable << "): setFeature LE TRANSPORT failed" << LOG_ENDL;
             }
         } else {
-            LOG_E << "enable: changing VENDOR LE TRANSPORT failed" << LOG_ENDL;
+            LOG_E << "enable(" << enable << "): changing LE TRANSPORT failed" << LOG_ENDL;
         }
     }
     return success;
@@ -1070,10 +1079,10 @@ bool HidRawSensor::setPower(const SP(HidDevice) &device, bool enable) {
                               0, mPowerStateBitOffset, mPowerStateBitSize);
             success = device->setFeature(id, buffer);
             if (!success) {
-              LOG_E << "enable: setFeature POWER STATE failed" << LOG_ENDL;
+              LOG_E << "enable(" << enable << "): setFeature POWER STATE failed" << LOG_ENDL;
             }
         } else {
-            LOG_E << "enable: changing POWER STATE failed" << LOG_ENDL;
+            LOG_E << "enable(" << enable << "): changing POWER STATE failed" << LOG_ENDL;
         }
     }
     return success;
@@ -1094,10 +1103,10 @@ bool HidRawSensor::setReportingState(const SP(HidDevice) &device, bool enable) {
                               mReportingStateBitOffset, mReportingStateBitSize);
             success = device->setFeature(id, buffer);
             if (!success) {
-              LOG_E << "enable: setFeature REPORTING STATE failed" << LOG_ENDL;
+              LOG_E << "enable(" << enable << "): setFeature REPORTING STATE failed" << LOG_ENDL;
             }
         } else {
-            LOG_E << "enable: changing REPORTING STATE failed" << LOG_ENDL;
+            LOG_E << "enable(" << enable << "): changing REPORTING STATE failed" << LOG_ENDL;
         }
     }
     return success;
@@ -1133,6 +1142,13 @@ int HidRawSensor::batch(int64_t samplingPeriod, int64_t batchingPeriod) {
                               0, mReportIntervalBitOffset,
                               mReportIntervalBitSize);
             ok = device->setFeature(id, buffer);
+            if (!ok) {
+                LOG_E << "batch(" << samplingPeriod << ", " << batchingPeriod << "): "
+                      << "setFeature failed" << LOG_ENDL;
+            }
+        } else {
+            LOG_E << "batch(" << samplingPeriod << ", " << batchingPeriod << "): "
+                  << "invalid getFeature result (buffer.size: " << buffer.size() << ")" << LOG_ENDL;
         }
     }
 
```

