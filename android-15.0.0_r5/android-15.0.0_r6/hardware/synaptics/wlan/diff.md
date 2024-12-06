```diff
diff --git a/synadhd/wifi_hal/wifi_logger.cpp b/synadhd/wifi_hal/wifi_logger.cpp
index 0552372..a2be05f 100755
--- a/synadhd/wifi_hal/wifi_logger.cpp
+++ b/synadhd/wifi_hal/wifi_logger.cpp
@@ -82,6 +82,7 @@ typedef enum {
 #define OTA_NVRAM_FILE "bcmdhd.cal"
 #define HW_DEV_PROP "ro.revision"
 #define HW_SKU_PROP "ro.boot.hardware.sku"
+#define CRASH_REASON_PROP "vendor.debug.ssrdump.pd_down.crash_reason"
 
 typedef enum {
     NVRAM,
@@ -120,6 +121,7 @@ typedef enum {
     LOGGER_ATTRIBUTE_HANG_REASON		= 19,
     LOGGER_ATTRIBUTE_BUF_RING_NUM		= 20,
     LOGGER_ATTRIBUTE_BUF_RING_MAP		= 21,
+    LOGGER_ATTRIBUTE_HANG_PENDING		= 22,
     /* Add new attributes just above this */
     LOGGER_ATTRIBUTE_MAX
 } LOGGER_ATTRIBUTE;
@@ -1447,6 +1449,7 @@ public:
         nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
         int len = event.get_vendor_data_len();
         int event_id = event.get_vendor_subcmd();
+        int hang_was_pending = 0;
         ALOGI("Got event: %d", event_id);
 
         if (vendor_data == NULL || len == 0) {
@@ -1457,18 +1460,25 @@ public:
             for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
                 if (it.get_type() == LOGGER_ATTRIBUTE_HANG_REASON) {
                     mBuff = (char *)it.get_data();
-                } else {
+                } else if (it.get_type() == LOGGER_ATTRIBUTE_HANG_PENDING) {
+                    hang_was_pending = (int) it.get_u32();
+                }else {
                     ALOGI("Ignoring invalid attribute type = %d, size = %d",
                             it.get_type(), it.get_len());
                 }
             }
 
-            if (*mHandler.on_subsystem_restart) {
-                (*mHandler.on_subsystem_restart)(mBuff);
-                ALOGI("Hang event received. Trigger SSR handler:%p",
-                    mHandler.on_subsystem_restart);
+            if (hang_was_pending) {
+                ALOGI("Set hang reason property: %s", mBuff);
+                property_set(CRASH_REASON_PROP, mBuff);
             } else {
-                ALOGI("No Restart handler registered");
+                if (*mHandler.on_subsystem_restart) {
+                    (*mHandler.on_subsystem_restart)(mBuff);
+                    ALOGI("Hang event received. Trigger SSR handler:%p",
+                        mHandler.on_subsystem_restart);
+                } else {
+                    ALOGI("No Restart handler registered");
+                }
             }
         }
         return NL_OK;
```

