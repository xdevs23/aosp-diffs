```diff
diff --git a/Android.bp b/Android.bp
index 51731d3..d476de4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -13,13 +13,17 @@ java_library {
     name: "jspecify",
     host_supported: true,
     srcs: ["src/main/**/*.java"],
-    sdk_version: "current",
+    sdk_version: "core_current",
     min_sdk_version: "1",
     // b/267831518: Pin tradefed and dependencies to Java 11.
     java_version: "11",
     visibility: [
+        "//external/dagger2:__subpackages__",
         "//external/jsoup:__subpackages__",
+        "//external/icing:__subpackages__",
         "//external/truth:__subpackages__",
+        "//external/turbine:__subpackages__",
+        "//packages/modules:__subpackages__",
         "//prebuilts/sdk/current/androidx/m2repository/androidx:__subpackages__",
     ],
     apex_available: [
diff --git a/OWNERS b/OWNERS
index 2e8f086..a2a4268 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

