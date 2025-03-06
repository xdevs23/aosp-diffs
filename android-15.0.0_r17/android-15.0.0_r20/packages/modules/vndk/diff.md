```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index 8290ce0..8f194df 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -70,11 +70,3 @@ apex_vndk {
     vndk_version: "30",
     system_ext_specific: true,
 }
-
-apex_vndk {
-    name: "com.android.vndk.v29",
-    defaults: ["vndk-apex-defaults"],
-    vndk_version: "29",
-    system_ext_specific: true,
-}
-
```

