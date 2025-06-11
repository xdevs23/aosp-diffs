```diff
diff --git a/OWNERS b/OWNERS
index 30c6f6a..29b603f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,4 @@
 # People who can approve changes for submission.
-jdsouza@google.com
-jinjian@google.com
 sandraalfaro@google.com
 
 # TLs
diff --git a/library/main/build.gradle b/library/main/build.gradle
index a8d16c0..6bc9291 100644
--- a/library/main/build.gradle
+++ b/library/main/build.gradle
@@ -76,7 +76,7 @@ dependencies {
     implementation 'androidx.gridlayout:gridlayout:1.0.0'
     implementation 'androidx.preference:preference:1.1.1'
     implementation libs.androidx.constraintlayout
-    implementation 'androidx.core:core:1.3.2'
+    implementation libs.androidx.core
     implementation 'androidx.annotation:annotation:1.2.0'
     implementation 'androidx.test:core:1.4.0'
 
diff --git a/library/main/tests/robotests/Android.bp b/library/main/tests/robotests/Android.bp
index c1000b6..d229dd3 100644
--- a/library/main/tests/robotests/Android.bp
+++ b/library/main/tests/robotests/Android.bp
@@ -37,6 +37,5 @@ android_robolectric_test {
     ],
 
     instrumentation_for: "CarSetupWizardLib",
-    upstream: true,
     strict_mode: false,
 }
```

