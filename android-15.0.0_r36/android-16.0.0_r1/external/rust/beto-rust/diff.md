```diff
diff --git a/nearby/Android.bp b/nearby/Android.bp
index 84273c1..4c70f79 100644
--- a/nearby/Android.bp
+++ b/nearby/Android.bp
@@ -173,6 +173,9 @@ java_library_static {
     required: [
         "libukey2_jni_shared",
     ],
+    optimize: {
+        proguard_flags_files: ["proguard.flags"],
+    },
 }
 
 rust_library_rlib {
diff --git a/nearby/proguard.flags b/nearby/proguard.flags
new file mode 100644
index 0000000..1ce15eb
--- /dev/null
+++ b/nearby/proguard.flags
@@ -0,0 +1,3 @@
+-keepclassmembers class com.google.security.cryptauth.lib.securegcm.ukey2.AlertException {
+    <init>(...);
+}
```

