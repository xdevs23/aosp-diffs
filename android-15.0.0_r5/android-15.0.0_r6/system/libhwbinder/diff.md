```diff
diff --git a/Utils.cpp b/Utils.cpp
index 3f3eef8..a4626f2 100644
--- a/Utils.cpp
+++ b/Utils.cpp
@@ -27,10 +27,16 @@ void zeroMemory(uint8_t* data, size_t size) {
     memset(data, 0, size);
 }
 
+static bool file_exists(const std::string& file) {
+    int res = access(file.c_str(), F_OK);
+    if (res == 0 || errno == EACCES) return true;
+    return false;
+}
+
 static bool isHwServiceManagerInstalled() {
-    return access("/system_ext/bin/hwservicemanager", F_OK) == 0 ||
-           access("/system/system_ext/bin/hwservicemanager", F_OK) == 0 ||
-           access("/system/bin/hwservicemanager", F_OK) == 0;
+    return file_exists("/system_ext/bin/hwservicemanager") ||
+           file_exists("/system/system_ext/bin/hwservicemanager") ||
+           file_exists("/system/bin/hwservicemanager");
 }
 
 static bool waitForHwServiceManager() {
```

