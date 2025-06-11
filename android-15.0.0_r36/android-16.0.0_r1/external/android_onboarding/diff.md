```diff
diff --git a/METADATA b/METADATA
index 84ae087..95873ec 100644
--- a/METADATA
+++ b/METADATA
@@ -2,13 +2,12 @@ name: "Android Onboarding"
 description:
   "AOSP Libraries for use by all components which contribute to the"
   "Android Onboarding Flow."
-language: KOTLIN
 third_party {
   type: PACKAGE
   license_type: NOTICE
   identifier {
-    type: "Copybara"
+    type: "Piper"
     omission_reason: "Exported by google"
     primary_source: true
   }
-}
+}
\ No newline at end of file
diff --git a/OWNERS b/OWNERS
index c0959d3..92d6d00 100644
--- a/OWNERS
+++ b/OWNERS
@@ -7,3 +7,4 @@ mru@google.com #{LAST_RESORT_SUGGESTION}
 petuska@google.com #{LAST_RESORT_SUGGESTION}
 pastychang@google.com #{LAST_RESORT_SUGGESTION}
 tmfang@google.com #{LAST_RESORT_SUGGESTION}
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/java/com/android/onboarding/contracts/testing/Android.bp b/java/com/android/onboarding/contracts/testing/Android.bp
index 85c0036..5330e9d 100644
--- a/java/com/android/onboarding/contracts/testing/Android.bp
+++ b/java/com/android/onboarding/contracts/testing/Android.bp
@@ -10,7 +10,7 @@ android_library {
     ],
     dont_merge_manifests: true,
     static_libs: [
-        "Robolectric_all-target_upstream",
+        "Robolectric_all-target",
         "android_onboarding.contracts",
         "androidx.activity_activity-ktx",
         "androidx.appcompat_appcompat",
diff --git a/java/com/android/onboarding/testing/Android.bp b/java/com/android/onboarding/testing/Android.bp
index aa39cc6..62defed 100644
--- a/java/com/android/onboarding/testing/Android.bp
+++ b/java/com/android/onboarding/testing/Android.bp
@@ -17,7 +17,7 @@ android_library {
     ],
     dont_merge_manifests: true,
     static_libs: [
-        "Robolectric_all-target_upstream",
+        "Robolectric_all-target",
         "androidx.test.core",
         "error_prone_annotations",
         "truth",
```

