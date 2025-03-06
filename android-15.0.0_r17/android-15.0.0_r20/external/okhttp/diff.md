```diff
diff --git a/Android.bp b/Android.bp
index 552b144..be86538 100644
--- a/Android.bp
+++ b/Android.bp
@@ -29,7 +29,7 @@ license {
         "SPDX-license-identifier-Apache-2.0",
     ],
     license_text: [
-        "LICENSE.txt",
+        "LICENSE",
     ],
 }
 
@@ -164,10 +164,12 @@ java_library {
         "com.android.devicelock",
         "com.android.extservices",
         "com.android.ondevicepersonalization",
+        "com.android.virt",
     ],
     visibility: [
         "//art/build/sdk",
         "//external/grpc-grpc-java/okhttp",
+        "//vendor:__subpackages__",
     ],
 
     srcs: [
diff --git a/LICENSE.txt b/LICENSE
similarity index 100%
rename from LICENSE.txt
rename to LICENSE
diff --git a/android/src/main/java/com/squareup/okhttp/TEST_MAPPING b/android/src/main/java/com/squareup/okhttp/TEST_MAPPING
index b2cf623..9206d92 100644
--- a/android/src/main/java/com/squareup/okhttp/TEST_MAPPING
+++ b/android/src/main/java/com/squareup/okhttp/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "com.squareup.okhttp"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_squareup_okhttp"
     }
   ]
 }
\ No newline at end of file
diff --git a/android/src/main/java/com/squareup/okhttp/internal/TEST_MAPPING b/android/src/main/java/com/squareup/okhttp/internal/TEST_MAPPING
index a4da23b..595ad02 100644
--- a/android/src/main/java/com/squareup/okhttp/internal/TEST_MAPPING
+++ b/android/src/main/java/com/squareup/okhttp/internal/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "com.squareup.okhttp.internal"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_okhttp_internal"
     }
   ]
 }
\ No newline at end of file
diff --git a/okhttp-android-support/src/main/java/com/squareup/okhttp/internal/huc/TEST_MAPPING b/okhttp-android-support/src/main/java/com/squareup/okhttp/internal/huc/TEST_MAPPING
index 452688a..91ede2c 100644
--- a/okhttp-android-support/src/main/java/com/squareup/okhttp/internal/huc/TEST_MAPPING
+++ b/okhttp-android-support/src/main/java/com/squareup/okhttp/internal/huc/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "com.squareup.okhttp.internal.huc"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_internal_huc"
     }
   ]
 }
\ No newline at end of file
diff --git a/okhttp/src/main/java/com/squareup/okhttp/internal/framed/TEST_MAPPING b/okhttp/src/main/java/com/squareup/okhttp/internal/framed/TEST_MAPPING
index 2ae9001..2ca32f6 100644
--- a/okhttp/src/main/java/com/squareup/okhttp/internal/framed/TEST_MAPPING
+++ b/okhttp/src/main/java/com/squareup/okhttp/internal/framed/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "com.squareup.okhttp.internal.framed"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_internal_framed"
     }
   ]
 }
\ No newline at end of file
diff --git a/okhttp/src/main/java/com/squareup/okhttp/internal/http/TEST_MAPPING b/okhttp/src/main/java/com/squareup/okhttp/internal/http/TEST_MAPPING
index 79e9079..a8009a3 100644
--- a/okhttp/src/main/java/com/squareup/okhttp/internal/http/TEST_MAPPING
+++ b/okhttp/src/main/java/com/squareup/okhttp/internal/http/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "com.squareup.okhttp.internal.http"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_internal_http"
     }
   ]
 }
\ No newline at end of file
diff --git a/okhttp/src/main/java/com/squareup/okhttp/internal/tls/TEST_MAPPING b/okhttp/src/main/java/com/squareup/okhttp/internal/tls/TEST_MAPPING
index 8c9cdac..87530d1 100644
--- a/okhttp/src/main/java/com/squareup/okhttp/internal/tls/TEST_MAPPING
+++ b/okhttp/src/main/java/com/squareup/okhttp/internal/tls/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "com.squareup.okhttp.internal.tls"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_internal_tls"
     }
   ]
 }
\ No newline at end of file
diff --git a/okio/okio/src/main/java/okio/TEST_MAPPING b/okio/okio/src/main/java/okio/TEST_MAPPING
index c2f1b40..503d77d 100644
--- a/okio/okio/src/main/java/okio/TEST_MAPPING
+++ b/okio/okio/src/main/java/okio/TEST_MAPPING
@@ -1,12 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "CtsLibcoreOkHttpTestCases",
-      "options": [
-        {
-          "include-filter": "okio"
-        }
-      ]
+      "name": "CtsLibcoreOkHttpTestCases_okio"
     }
   ]
 }
\ No newline at end of file
```

