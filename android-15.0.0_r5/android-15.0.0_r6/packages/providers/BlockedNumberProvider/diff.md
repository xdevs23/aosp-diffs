```diff
diff --git a/Android.bp b/Android.bp
index fd2c3b7..2688f4b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -11,7 +11,6 @@ android_app {
     static_libs: [
         "android-common",
         "guava",
-        "telephony_flags_core_java_lib",
     ],
     jacoco: {
         include_filter: ["com.android.providers.blockednumber.*"],
diff --git a/src/com/android/providers/blockednumber/BlockedNumberProvider.java b/src/com/android/providers/blockednumber/BlockedNumberProvider.java
index 8c720de..f22aad3 100644
--- a/src/com/android/providers/blockednumber/BlockedNumberProvider.java
+++ b/src/com/android/providers/blockednumber/BlockedNumberProvider.java
@@ -416,9 +416,12 @@ public class BlockedNumberProvider extends ContentProvider {
         if (!Flags.enforceTelephonyFeatureMapping()) {
             return tm.isEmergencyNumber(phoneNumber) || tm.isEmergencyNumber(e164Number);
         } else {
+            if (tm == null) {
+                return false;
+            }
             try {
                 return tm.isEmergencyNumber(phoneNumber) || tm.isEmergencyNumber(e164Number);
-            } catch (UnsupportedOperationException e) {
+            } catch (UnsupportedOperationException | IllegalStateException e) {
                 return false;
             }
         }
diff --git a/tests/Android.bp b/tests/Android.bp
index d347aff..1b6d057 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -11,9 +11,9 @@ android_test {
         "androidx.test.rules",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     // Only compile source java files in this apk.
     srcs: ["src/**/*.java"],
diff --git a/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java b/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java
index d3f83f5..1c45905 100644
--- a/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java
+++ b/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java
@@ -22,6 +22,7 @@ import static org.mockito.Matchers.anyInt;
 import static org.mockito.Matchers.anyString;
 import static org.mockito.Matchers.eq;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.spy;
@@ -631,6 +632,20 @@ public class BlockedNumberProviderTest extends AndroidTestCase {
         assertIsBlocked(false, "abc.def@gmail.com");
     }
 
+    public void testNumberBlockingWorksWithoutTelephony() {
+        doThrow(new IllegalStateException()).when(mMockContext.mTelephonyManager)
+                .isEmergencyNumber(anyString());
+        assertEquals(BlockedNumberContract.STATUS_NOT_BLOCKED,
+                SystemContract.shouldSystemBlockNumber(mMockContext, "6505551212", null));
+    }
+
+    public void testNumberBlockingWorksWithoutTelephonyTwo() {
+        doThrow(new UnsupportedOperationException()).when(mMockContext.mTelephonyManager)
+                .isEmergencyNumber(anyString());
+        assertEquals(BlockedNumberContract.STATUS_NOT_BLOCKED,
+                SystemContract.shouldSystemBlockNumber(mMockContext, "6505551212", null));
+    }
+
     public void testEmergencyNumbersAreNotBlockedBySystem() {
         String emergencyNumber = getEmergencyNumberFromSystemPropertiesOrDefault();
         doReturn(true).when(mMockContext.mTelephonyManager).isEmergencyNumber(emergencyNumber);
```

