```diff
diff --git a/Android.bp b/Android.bp
index 78a59d3d6..0b9bb0468 100644
--- a/Android.bp
+++ b/Android.bp
@@ -99,6 +99,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
     ],
 }
 
@@ -122,5 +123,6 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
     ],
 }
diff --git a/api/Android.bp b/api/Android.bp
index 3426b7acc..52372ec50 100644
--- a/api/Android.bp
+++ b/api/Android.bp
@@ -30,10 +30,11 @@ java_library {
     // b/267831518: Pin tradefed and dependencies to Java 11.
     java_version: "11",
     apex_available: [
-            "//apex_available:platform",
-            "com.android.adservices",
-            "com.android.devicelock",
-            "com.android.extservices",
+        "//apex_available:platform",
+        "com.android.adservices",
+        "com.android.devicelock",
+        "com.android.extservices",
+        "com.android.virt",
     ],
     target: {
         windows: {
diff --git a/context/Android.bp b/context/Android.bp
index 72e72226f..e7aa2a9cc 100644
--- a/context/Android.bp
+++ b/context/Android.bp
@@ -42,6 +42,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
         "//apex_available:platform",
     ],
     target: {
diff --git a/core/Android.bp b/core/Android.bp
index 347a99dac..9ced914d4 100644
--- a/core/Android.bp
+++ b/core/Android.bp
@@ -47,6 +47,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
         "//apex_available:platform",
     ],
     target: {
@@ -110,8 +111,8 @@ java_library {
         },
         host: {
             libs: [
-                "annotations",  // For android.annotation.SuppressLint
-            ]
+                "annotations", // For android.annotation.SuppressLint
+            ],
         },
         windows: {
             enabled: true,
@@ -125,6 +126,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
         "//apex_available:platform",
     ],
     errorprone: {
@@ -153,12 +155,13 @@ java_library {
     java_version: "11",
     sdk_version: "current",
     min_sdk_version: "30",
-     apex_available: [
-         "com.android.adservices",
-         "com.android.devicelock",
-         "com.android.extservices",
-         "//apex_available:platform",
-     ],
+    apex_available: [
+        "com.android.adservices",
+        "com.android.devicelock",
+        "com.android.extservices",
+        "com.android.virt",
+        "//apex_available:platform",
+    ],
     target: {
         windows: {
             enabled: true,
diff --git a/okhttp/Android.bp b/okhttp/Android.bp
index 3505cb48e..646fab6ca 100644
--- a/okhttp/Android.bp
+++ b/okhttp/Android.bp
@@ -53,6 +53,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
     ],
     // b/267831518: Pin tradefed and dependencies to Java 11.
     java_version: "11",
diff --git a/protobuf-lite/Android.bp b/protobuf-lite/Android.bp
index 27d82566d..b929c4722 100644
--- a/protobuf-lite/Android.bp
+++ b/protobuf-lite/Android.bp
@@ -44,6 +44,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
         "//apex_available:platform",
     ],
     target: {
diff --git a/stub/Android.bp b/stub/Android.bp
index e143b4e20..2a3efe19e 100644
--- a/stub/Android.bp
+++ b/stub/Android.bp
@@ -45,6 +45,7 @@ java_library {
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
+        "com.android.virt",
         "//apex_available:platform",
     ],
     target: {
```

