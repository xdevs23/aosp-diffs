```diff
diff --git a/Android.bp b/Android.bp
index dbf15cd..f6cadb5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -91,6 +91,18 @@ java_import {
     ],
 }
 
+java_import_host {
+    name: "kotlin-serialize-compiler-plugin-lib",
+    jars: ["lib/kotlin-serialization-compiler-plugin.jar"],
+    sdk_version: "core_current",
+    exclude_dirs: ["META-INF/versions"],
+}
+
+kotlin_plugin {
+    name: "kotlin-serialize-compiler-plugin",
+    static_libs: ["kotlin-serialize-compiler-plugin-lib"],
+}
+
 // See: http://go/android-license-faq
 license {
     name: "external_kotlinc_license",
```

