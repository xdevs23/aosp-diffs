```diff
diff --git a/Android.bp b/Android.bp
index 820ecea..552b144 100644
--- a/Android.bp
+++ b/Android.bp
@@ -76,7 +76,7 @@ java_library {
     sdk_version: "none",
     system_modules: "core-all-system-modules",
     libs: [
-        "conscrypt.module.intra.core.api",
+        "conscrypt.module.intra.core.api.stubs",
     ],
     java_version: "1.7",
 }
@@ -107,6 +107,8 @@ java_library {
     visibility: [
         "//art/build/apex",
         "//art/build/sdk",
+        "//art/tools/ahat",
+        "//art/tools/fuzzer",
         "//external/grpc-grpc-java/okhttp",
         "//external/robolectric-shadows",
         "//external/robolectric",
@@ -123,7 +125,7 @@ java_library {
     sdk_version: "none",
     system_modules: "core-all-system-modules",
     libs: [
-        "conscrypt.module.intra.core.api",
+        "conscrypt.module.intra.core.api.stubs",
     ],
     java_version: "1.7",
     apex_available: [
@@ -244,7 +246,7 @@ java_library {
     libs: [
         "okhttp-nojarjar",
         "junit",
-        "conscrypt.module.intra.core.api",
+        "conscrypt.module.intra.core.api.stubs",
         "bouncycastle-unbundled",
     ],
 
```

