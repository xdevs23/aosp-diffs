```diff
diff --git a/libese_weaver/inc/weaver_transport-impl.h b/libese_weaver/inc/weaver_transport-impl.h
index 5fa4075..2867002 100644
--- a/libese_weaver/inc/weaver_transport-impl.h
+++ b/libese_weaver/inc/weaver_transport-impl.h
@@ -90,8 +90,6 @@ private:
   WeaverTransportImpl(const WeaverTransportImpl &) = delete;
   /* Private operator overload to make class singleton*/
   WeaverTransportImpl &operator=(const WeaverTransportImpl &) = delete;
-  /* Private api to detect if device boot completed or not*/
-  bool isDeviceBootCompleted();
 
   /* Private self instance for singleton purpose*/
   static WeaverTransportImpl *s_instance;
diff --git a/libese_weaver/src/weaver-transport-impl.cpp b/libese_weaver/src/weaver-transport-impl.cpp
index 08f4fd0..37da406 100644
--- a/libese_weaver/src/weaver-transport-impl.cpp
+++ b/libese_weaver/src/weaver-transport-impl.cpp
@@ -18,15 +18,12 @@
 
 #define LOG_TAG "weaver-transport-impl"
 #include <TransportFactory.h>
-#include <cutils/properties.h>
 #include <vector>
 #include <weaver_transport-impl.h>
 #include <weaver_utils.h>
 
 #define MAX_RETRY_COUNT 12
 #define RETRY_DELAY_INTERVAL_SEC 1
-#define PROP_SYSBOOT_COMPLETED "sys.boot_completed"
-#define SYSBOOT_COMPLETED_VALUE 1
 #define IS_APPLET_SELECTION_FAILED(resp)                                       \
   (!resp.empty() && resp[0] == APP_NOT_FOUND_SW1 &&                            \
    resp[1] == APP_NOT_FOUND_SW2)
@@ -179,10 +176,6 @@ bool WeaverTransportImpl::Send(std::vector<uint8_t> data,
   do {
     status = sendInternal(data, resp);
     if (!status) {
-      if (!isDeviceBootCompleted()) {
-        LOG_D(TAG, ": Device boot not completed, no retry required");
-        break;
-      }
       if (retry > MAX_RETRY_COUNT) {
         LOG_E(TAG, ": completed max retries exit failure");
       } else {
@@ -207,17 +200,3 @@ bool WeaverTransportImpl::DeInit() {
   LOG_D(TAG, "Exit");
   return status;
 }
-
-/**
- * \brief Function to determine if phone boot completed
- *
- * \retval This function return true in case of phone boot
- *        completed and false in case not completed.
- */
-bool WeaverTransportImpl::isDeviceBootCompleted() {
-  if (property_get_int64(PROP_SYSBOOT_COMPLETED, 0) ==
-      SYSBOOT_COMPLETED_VALUE) {
-    return true;
-  }
-  return false;
-}
```

