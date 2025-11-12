```diff
diff --git a/credentials/Android.bp b/credentials/Android.bp
index 8e744f3..ac553d2 100644
--- a/credentials/Android.bp
+++ b/credentials/Android.bp
@@ -15,3 +15,15 @@ java_library_host {
         },
     },
 }
+
+java_library {
+    name: "google-auth-library-java-credentials-device",
+    srcs: [
+        "java/**/*.java",
+    ],
+    sdk_version: "current",
+    visibility: [
+        "//external/google-auth-library-java:__subpackages__",
+        "//test/dts/libs/device/powerperformance/apphelpers",
+    ],
+}
diff --git a/oauth2_http/Android.bp b/oauth2_http/Android.bp
index 78ec3cc..8335d2e 100644
--- a/oauth2_http/Android.bp
+++ b/oauth2_http/Android.bp
@@ -28,3 +28,28 @@ java_library_host {
         },
     },
 }
+
+java_library {
+    name: "google-auth-library-java-oauth2_http-device",
+    srcs: [
+        "java/**/*.java",
+    ],
+    sdk_version: "current",
+    libs: [
+        "auto_value_annotations",
+        "error_prone_annotations",
+        "google-api-java-client-lite",
+        "google-auth-library-java-credentials-device",
+        "guava",
+    ],
+    plugins: ["auto_value_plugin"],
+    visibility: [
+        "//external/google-auth-library-java:__subpackages__",
+        "//test/dts/libs/device/powerperformance/apphelpers",
+    ],
+    errorprone: {
+        javacflags: [
+            "-Xep:DoubleBraceInitialization:WARN",
+        ],
+    },
+}
```

