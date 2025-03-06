```diff
diff --git a/snxxx/1.0/NxpEseService.cpp b/snxxx/1.0/NxpEseService.cpp
index 52b47a7..1383eeb 100644
--- a/snxxx/1.0/NxpEseService.cpp
+++ b/snxxx/1.0/NxpEseService.cpp
@@ -16,9 +16,9 @@
  *
  ******************************************************************************/
 #define LOG_TAG "nxpese@1.0-service"
+#include <android-base/logging.h>
 #include <android-base/stringprintf.h>
 #include <android/hardware/secure_element/1.0/ISecureElement.h>
-#include <base/logging.h>
 #include <hidl/LegacySupport.h>
 #include <string.h>
 #include <vendor/nxp/nxpese/1.0/INxpEse.h>
```

