```diff
diff --git a/OWNERS b/OWNERS
index cbf326d0..a386cdaf 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
 shubang@google.com
 quxiangfang@google.com
-qingxun@google.com
diff --git a/common/tests/robotests/Android.bp b/common/tests/robotests/Android.bp
index 210dfb21..bd5d2240 100644
--- a/common/tests/robotests/Android.bp
+++ b/common/tests/robotests/Android.bp
@@ -44,7 +44,6 @@ android_robolectric_test {
     test_options: {
         timeout: 36000,
     },
-    upstream: true,
 
     strict_mode: false,
 }
diff --git a/tests/common/Android.bp b/tests/common/Android.bp
index ae00673c..a05c9106 100644
--- a/tests/common/Android.bp
+++ b/tests/common/Android.bp
@@ -35,7 +35,7 @@ android_library {
         "mockito-robolectric-prebuilt",
         "tv-lib-truth",
         "androidx.test.uiautomator_uiautomator",
-        "Robolectric_all-target_upstream",
+        "Robolectric_all-target",
     ],
 
     // Link tv-common as shared library to avoid the problem of initialization of the constants
@@ -60,7 +60,7 @@ android_library {
         "src/com/android/tv/testing/shadows/**/*.java",
     ],
     static_libs: [
-        "Robolectric_all-target_upstream",
+        "Robolectric_all-target",
         "mockito-robolectric-prebuilt",
         "tv-test-common",
     ],
diff --git a/tests/robotests/Android.bp b/tests/robotests/Android.bp
index 56a7e701..1a8bcc50 100644
--- a/tests/robotests/Android.bp
+++ b/tests/robotests/Android.bp
@@ -49,5 +49,4 @@ android_robolectric_test {
     test_options: {
         timeout: 36000,
     },
-    upstream: true,
 }
diff --git a/tuner/tests/robotests/Android.bp b/tuner/tests/robotests/Android.bp
index a1baf651..34bf06fc 100644
--- a/tuner/tests/robotests/Android.bp
+++ b/tuner/tests/robotests/Android.bp
@@ -43,5 +43,4 @@ android_robolectric_test {
     test_options: {
         timeout: 36000,
     },
-    upstream: true,
 }
```

