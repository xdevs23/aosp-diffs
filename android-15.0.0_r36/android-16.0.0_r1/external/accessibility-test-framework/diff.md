```diff
diff --git a/METADATA b/METADATA
index 766edcd..6a973ca 100644
--- a/METADATA
+++ b/METADATA
@@ -1,16 +1,20 @@
-name: "accessibility-test-framework"
-description:
-    "This library collects various accessibility-related checks on View objects "
-    "as well as AccessibilityNodeInfo objects (which the Android framework "
-    "derives from Views and sends to AccessibilityServices)."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/accessibility-test-framework
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "accessibility-test-framework"
+description: "This library collects various accessibility-related checks on View objects as well as AccessibilityNodeInfo objects (which the Android framework derives from Views and sends to AccessibilityServices)."
 third_party {
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 16
+  }
   identifier {
     type: "Git"
     value: "https://github.com/google/Accessibility-Test-Framework-for-Android"
+    version: "c65cab02b2a845c29c3da100d6adefd345a144e3"
     primary_source: true
   }
-  version: "858625c4d9ad2acddee5cfbc1dedd54c76da9365"
-  last_upgrade_date { year: 2024 month: 3 day: 18 }
-  license_type: NOTICE
 }
diff --git a/build.gradle b/build.gradle
index 1d28f68..554bd09 100644
--- a/build.gradle
+++ b/build.gradle
@@ -79,7 +79,7 @@ publishing {
         mavenAar(MavenPublication) {
             groupId 'com.google.android.apps.common.testing.accessibility.framework'
             artifactId 'accessibility-test-framework'
-            version '4.1.0'
+            version '4.1.1'
             from components.android
             artifact sourceJar
             artifact javadocJar
@@ -126,8 +126,8 @@ dependencies {
     // to avoid duplicate class and dexing errors
     // see https://github.com/android/android-test/issues/861
     implementation 'org.checkerframework:checker-qual:3.22.1'
-    implementation 'org.hamcrest:hamcrest-core:2.2'
-    implementation 'org.hamcrest:hamcrest-library:2.2'
+    implementation 'org.hamcrest:hamcrest-core:1.3'
+    implementation 'org.hamcrest:hamcrest-library:1.3'
     implementation 'org.jsoup:jsoup:1.15.1'
     compileOnly 'com.google.auto.value:auto-value-annotations:1.6.2'
     annotationProcessor 'com.google.auto.value:auto-value:1.6.2'
```

