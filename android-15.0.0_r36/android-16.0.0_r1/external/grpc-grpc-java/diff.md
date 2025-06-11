```diff
diff --git a/Android.bp b/Android.bp
index 0b9bb0468..131240de0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -96,6 +96,7 @@ java_library {
     sdk_version: "current",
     min_sdk_version: "30",
     apex_available: [
+        "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
diff --git a/OWNERS b/OWNERS
index fd1e1bf8a..38347f016 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 jdesprez@google.com
 krzysio@google.com
 ccross@android.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/context/Android.bp b/context/Android.bp
index e7aa2a9cc..db64ffe35 100644
--- a/context/Android.bp
+++ b/context/Android.bp
@@ -39,6 +39,7 @@ java_library {
     sdk_version: "current",
     min_sdk_version: "30",
     apex_available: [
+        "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
diff --git a/core/Android.bp b/core/Android.bp
index 9ced914d4..b21bd0a40 100644
--- a/core/Android.bp
+++ b/core/Android.bp
@@ -44,6 +44,7 @@ java_library {
     sdk_version: "current",
     min_sdk_version: "30",
     apex_available: [
+        "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
@@ -123,6 +124,7 @@ java_library {
     sdk_version: "current",
     min_sdk_version: "30",
     apex_available: [
+        "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
diff --git a/protobuf-lite/Android.bp b/protobuf-lite/Android.bp
index b929c4722..6185128f5 100644
--- a/protobuf-lite/Android.bp
+++ b/protobuf-lite/Android.bp
@@ -41,6 +41,7 @@ java_library {
     sdk_version: "current",
     min_sdk_version: "30",
     apex_available: [
+        "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
diff --git a/stub/Android.bp b/stub/Android.bp
index 2a3efe19e..4825ffe3a 100644
--- a/stub/Android.bp
+++ b/stub/Android.bp
@@ -42,6 +42,7 @@ java_library {
     sdk_version: "current",
     min_sdk_version: "30",
     apex_available: [
+        "//apex_available:platform",
         "com.android.adservices",
         "com.android.devicelock",
         "com.android.extservices",
```

