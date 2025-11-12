```diff
diff --git a/Android.bp b/Android.bp
index 859b5de..20ac4bc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,6 +38,15 @@ kotlin_plugin {
     static_libs: ["kotlin-compose-compiler-hosted"],
 }
 
+// "embeddable" plugin for use by corresponding "embeddable" kotlin
+// artifacts. In particular, the kotlin-incremental-client that builds
+// with such artifacts. Use the "kotlin-compose-compiler-plugin" by
+// default unless you know you need th embeddable version.
+kotlin_plugin {
+    name: "kotlin-compose-compiler-embeddable-plugin",
+    static_libs: ["kotlin-compose-compiler-embeddable"],
+}
+
 // exclude_dirs is used to remove META-INF resources for java multi-release
 // jar support that soong does not support. https://openjdk.java.net/jeps/238
 
@@ -121,6 +130,12 @@ kotlin_plugin {
     static_libs: ["kotlin-parcelize-compiler-plugin-lib"],
 }
 
+java_import_host {
+    name: "kotlinc-trove4j",
+    jars: ["lib/trove4j.jar"],
+    exclude_dirs: ["META-INF/versions"],
+}
+
 // See: http://go/android-license-faq
 license {
     name: "external_kotlinc_license",
```

