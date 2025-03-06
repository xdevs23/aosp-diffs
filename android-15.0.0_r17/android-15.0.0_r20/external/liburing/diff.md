```diff
diff --git a/Android.bp b/Android.bp
index 5fc7a9b..d032c66 100644
--- a/Android.bp
+++ b/Android.bp
@@ -31,13 +31,11 @@ cc_defaults {
         "-Werror",
         "-Wno-pointer-arith",
         "-Wno-unused-parameter",
-	"-Wno-implicit-function-declaration",
-	"-D_GNU_SOURCE"
+        "-D_GNU_SOURCE"
     ],
-    include_dirs: ["bionic/libc/kernel"],
     export_include_dirs: [
         "src/include",
-	"src/arch",
+        "src/arch",
     ],
     srcs: [
         "src/queue.c",
diff --git a/src/include/liburing/compat.h b/src/include/liburing/compat.h
index b54b6b2..e492f46 100644
--- a/src/include/liburing/compat.h
+++ b/src/include/liburing/compat.h
@@ -4,7 +4,7 @@
 
 #include <stdint.h>
 #include <inttypes.h>
-#include <uapi/linux/openat2.h>
+#include <linux/openat2.h>
 
 typedef int __kernel_rwf_t;
 
```

