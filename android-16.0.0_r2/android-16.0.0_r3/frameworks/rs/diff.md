```diff
diff --git a/cpu_ref/Android.bp b/cpu_ref/Android.bp
index 6a02a64a..ae4c094b 100644
--- a/cpu_ref/Android.bp
+++ b/cpu_ref/Android.bp
@@ -95,6 +95,7 @@ cc_library_shared {
 
         "libbcinfo",
         "libblas",
+        "libbase",
     ],
     static_libs: ["libbnnmlowp"],
     header_libs: [
diff --git a/cpu_ref/rsCpuExecutable.cpp b/cpu_ref/rsCpuExecutable.cpp
index cc7f7a55..ac4c210b 100644
--- a/cpu_ref/rsCpuExecutable.cpp
+++ b/cpu_ref/rsCpuExecutable.cpp
@@ -11,13 +11,15 @@
 #ifdef RS_COMPATIBILITY_LIB
 #include <stdio.h>
 #else
+#include <android-base/properties.h>
+
 #include "bcc/Config.h"
 #endif
 
-#include <unistd.h>
-#include <dlfcn.h>
 #include <android/dlext.h>
+#include <dlfcn.h>
 #include <sys/stat.h>
+#include <unistd.h>
 
 namespace android {
 namespace renderscript {
@@ -120,6 +122,8 @@ const char* SharedLibraryUtils::LD_EXE_PATH = "/system/bin/ld.mc";
 const char* SharedLibraryUtils::RS_CACHE_DIR = "com.android.renderscript.cache";
 
 #ifndef RS_COMPATIBILITY_LIB
+const char* kMaxPageSizeSysPropName = "ro.product.cpu.pagesize.max";
+
 
 bool SharedLibraryUtils::createSharedLibrary(const char *driverName,
                                              const char *cacheDir,
@@ -156,18 +160,30 @@ bool SharedLibraryUtils::createSharedLibrary(const char *driverName,
     const char *vndkLibPath = isRunningInVndkNamespace() ?
         vndkLibPathString.c_str() : "";
     const char *vendorLibPath = "--library-path=" SYSLIBPATH_VENDOR;
+    static const std::string sharedLibraryAlignment =
+        "max-page-size=" +
+        android::base::GetProperty(
+            kMaxPageSizeSysPropName,
+            /* default_value= */ std::to_string(getpagesize()));
 
     // The search path order should be vendor -> vndk -> system
-    std::vector<const char *> args = {
-        LD_EXE_PATH,
-        "-shared",
-        "-nostdlib",
-        compiler_rt, mTriple, vendorLibPath, vndkLibPath, libPath,
-        linkDriverName.c_str(), "-lm", "-lc",
-        objFileName.c_str(),
-        "-o", sharedLibName.c_str(),
-        nullptr
-    };
+    std::vector<const char *> args = {LD_EXE_PATH,
+                                      "-shared",
+                                      "-nostdlib",
+                                      "-z",
+                                      sharedLibraryAlignment.c_str(),
+                                      compiler_rt,
+                                      mTriple,
+                                      vendorLibPath,
+                                      vndkLibPath,
+                                      libPath,
+                                      linkDriverName.c_str(),
+                                      "-lm",
+                                      "-lc",
+                                      objFileName.c_str(),
+                                      "-o",
+                                      sharedLibName.c_str(),
+                                      nullptr};
 
     return rsuExecuteCommand(LD_EXE_PATH, args.size()-1, args.data());
 
```

