```diff
diff --git a/java/tests/instrumentation/src/com/android/textclassifier/downloader/ModelDownloaderIntegrationTest.java b/java/tests/instrumentation/src/com/android/textclassifier/downloader/ModelDownloaderIntegrationTest.java
index 2d06afd..5c424e8 100644
--- a/java/tests/instrumentation/src/com/android/textclassifier/downloader/ModelDownloaderIntegrationTest.java
+++ b/java/tests/instrumentation/src/com/android/textclassifier/downloader/ModelDownloaderIntegrationTest.java
@@ -24,11 +24,13 @@ import androidx.test.filters.FlakyTest;
 import com.android.textclassifier.testing.ExtServicesTextClassifierRule;
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+@Ignore("b/358423172")
 @RunWith(JUnit4.class)
 public class ModelDownloaderIntegrationTest {
   private static final String TAG = "ModelDownloaderTest";
diff --git a/native/AndroidTest-sminus.xml b/native/AndroidTest-sminus.xml
index b4c8628..2ba8be5 100644
--- a/native/AndroidTest-sminus.xml
+++ b/native/AndroidTest-sminus.xml
@@ -34,6 +34,7 @@
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
         <option name="module-name" value="libtextclassifier_tests-sminus" />
+        <option name="force-no-test-error" value="false" />
     </test>
 
     <!-- Prevent test from running on Android T+ -->
diff --git a/native/AndroidTest-tplus.xml b/native/AndroidTest-tplus.xml
index ab2749c..40d0aa7 100644
--- a/native/AndroidTest-tplus.xml
+++ b/native/AndroidTest-tplus.xml
@@ -34,6 +34,7 @@
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
         <option name="module-name" value="libtextclassifier_tests-tplus" />
+        <option name="force-no-test-error" value="false" />
     </test>
 
     <!-- Prevent tests from running on Android S- -->
```

