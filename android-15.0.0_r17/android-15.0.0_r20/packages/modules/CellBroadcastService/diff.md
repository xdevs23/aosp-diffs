```diff
diff --git a/Android.bp b/Android.bp
index 74c39a8..a668f29 100644
--- a/Android.bp
+++ b/Android.bp
@@ -7,8 +7,8 @@ java_defaults {
     name: "CellBroadcastServiceCommon",
     min_sdk_version: "30",
     srcs: [
-      "src/**/*.java",
-      ":statslog-cellbroadcast-module-java-gen",
+        "src/**/*.java",
+        ":statslog-cellbroadcast-module-java-gen",
     ],
     libs: [
         "framework-annotations-lib",
@@ -44,36 +44,37 @@ android_app {
     manifest: "AndroidManifest.xml",
     apex_available: ["com.android.cellbroadcast"],
     privapp_allowlist: ":privapp_allowlist_com.android.cellbroadcastservice.xml",
+    updatable: true,
 }
 
 android_app {
-     name: "CellBroadcastServiceModulePlatform",
-     target_sdk_version: "33",
-     defaults: ["CellBroadcastServiceCommon"],
-     certificate: "platform",
-     // CellBroadcastServicePlatformModule is a replacement for com.android.cellbroadcast apex
-     // which consists of CellBroadcastServiceModule
-     overrides: ["com.android.cellbroadcast"],
-     manifest: "AndroidManifest_Platform.xml",
-     privapp_allowlist: ":platform_privapp_allowlist_com.android.cellbroadcastservice.xml",
+    name: "CellBroadcastServiceModulePlatform",
+    target_sdk_version: "33",
+    defaults: ["CellBroadcastServiceCommon"],
+    certificate: "platform",
+    // CellBroadcastServicePlatformModule is a replacement for com.android.cellbroadcast apex
+    // which consists of CellBroadcastServiceModule
+    overrides: ["com.android.cellbroadcast"],
+    manifest: "AndroidManifest_Platform.xml",
+    privapp_allowlist: ":platform_privapp_allowlist_com.android.cellbroadcastservice.xml",
 }
 
 genrule {
-  name: "statslog-cellbroadcast-java-gen",
-  tools: ["stats-log-api-gen"],
-  cmd: "$(location stats-log-api-gen) --java $(out) --module cellbroadcast" +
-       " --javaPackage com.android.cellbroadcastservice --javaClass CellBroadcastStatsLog" +
-       " --minApiLevel 30",
-  out: ["com/android/cellbroadcastservice/CellBroadcastStatsLog.java"],
+    name: "statslog-cellbroadcast-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module cellbroadcast" +
+        " --javaPackage com.android.cellbroadcastservice --javaClass CellBroadcastStatsLog" +
+        " --minApiLevel 30",
+    out: ["com/android/cellbroadcastservice/CellBroadcastStatsLog.java"],
 }
 
 genrule {
-  name: "statslog-cellbroadcast-module-java-gen",
-  tools: ["stats-log-api-gen"],
-  cmd: "$(location stats-log-api-gen) --java $(out) --module cellbroadcast" +
-       " --javaPackage com.android.cellbroadcastservice --javaClass CellBroadcastModuleStatsLog" +
-       " --minApiLevel 30",
-  out: ["com/android/cellbroadcastservice/CellBroadcastModuleStatsLog.java"],
+    name: "statslog-cellbroadcast-module-java-gen",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --java $(out) --module cellbroadcast" +
+        " --javaPackage com.android.cellbroadcastservice --javaClass CellBroadcastModuleStatsLog" +
+        " --minApiLevel 30",
+    out: ["com/android/cellbroadcastservice/CellBroadcastModuleStatsLog.java"],
 }
 
 // used to share common constants between cellbroadcastservice and cellbroadcastreceier
```

