```diff
diff --git a/memtrack.cpp b/memtrack.cpp
index 7c75386..45169bb 100644
--- a/memtrack.cpp
+++ b/memtrack.cpp
@@ -56,10 +56,19 @@ struct memtrack_proc {
 static std::shared_ptr<IMemtrack> get_memtrack_proxy_service() {
     const char* kMemtrackProxyService = "memtrack.proxy";
     static std::shared_ptr<IMemtrack> memtrack_proxy_service = nullptr;
-    if (!memtrack_proxy_service &&
-        !(memtrack_proxy_service = IMemtrack::fromBinder(
-                  ndk::SpAIBinder(AServiceManager_checkService(kMemtrackProxyService))))) {
-        ALOGE("Unable to connect to %s\n", kMemtrackProxyService);
+
+    if (!memtrack_proxy_service) {
+        static std::mutex proxy_service_mutex;
+        std::lock_guard<std::mutex> lock(proxy_service_mutex);
+
+        if (memtrack_proxy_service) {
+            return memtrack_proxy_service;
+        }
+
+        if (!(memtrack_proxy_service = IMemtrack::fromBinder(
+            ndk::SpAIBinder(AServiceManager_checkService(kMemtrackProxyService))))) {
+            ALOGE("Unable to connect to %s\n", kMemtrackProxyService);
+        }
     }
     return memtrack_proxy_service;
 }
```

