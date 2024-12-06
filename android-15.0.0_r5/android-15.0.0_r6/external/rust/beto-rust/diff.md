```diff
diff --git a/nearby/Android.bp b/nearby/Android.bp
index e68ecf3..84273c1 100644
--- a/nearby/Android.bp
+++ b/nearby/Android.bp
@@ -164,7 +164,6 @@ java_library_static {
     name: "ukey2_jni",
     srcs: [
         "connections/ukey2/ukey2_jni/java/src/main/**/*.java",
-        "connections/ukey2/ukey2_jni/java/src/main/**/*.kt",
     ],
     host_supported: true,
     static_libs: [
```

