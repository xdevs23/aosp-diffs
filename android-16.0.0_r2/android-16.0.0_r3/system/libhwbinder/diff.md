```diff
diff --git a/Utils.cpp b/Utils.cpp
index a4626f2..ca93698 100644
--- a/Utils.cpp
+++ b/Utils.cpp
@@ -17,16 +17,11 @@
 #include "Utils.h"
 #include <hwbinder/HidlSupport.h>
 
-#include <string.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 
 namespace android::hardware {
 
-void zeroMemory(uint8_t* data, size_t size) {
-    memset(data, 0, size);
-}
-
 static bool file_exists(const std::string& file) {
     int res = access(file.c_str(), F_OK);
     if (res == 0 || errno == EACCES) return true;
diff --git a/Utils.h b/Utils.h
index 07a5e69..ea0d488 100644
--- a/Utils.h
+++ b/Utils.h
@@ -16,10 +16,13 @@
 
 #include <cstdint>
 #include <stddef.h>
+#include <string.h>
+#include <sys/cdefs.h>
 
 namespace android::hardware {
 
-// avoid optimizations
-void zeroMemory(uint8_t* data, size_t size);
+inline void zeroMemory(uint8_t* data, size_t size) {
+    memset_explicit(data, 0, size);
+}
 
 }   // namespace android::hardware
```

