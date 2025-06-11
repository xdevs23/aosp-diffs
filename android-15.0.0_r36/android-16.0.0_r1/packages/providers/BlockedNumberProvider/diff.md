```diff
diff --git a/src/com/android/providers/blockednumber/BlockedNumberProvider.java b/src/com/android/providers/blockednumber/BlockedNumberProvider.java
index f22aad3..fb97313 100644
--- a/src/com/android/providers/blockednumber/BlockedNumberProvider.java
+++ b/src/com/android/providers/blockednumber/BlockedNumberProvider.java
@@ -51,7 +51,6 @@ import android.util.Log;
 
 import com.android.common.content.ProjectionMap;
 import com.android.internal.annotations.VisibleForTesting;
-import com.android.internal.telephony.flags.Flags;
 import com.android.providers.blockednumber.BlockedNumberDatabaseHelper.Tables;
 
 import java.util.Arrays;
@@ -413,17 +412,13 @@ public class BlockedNumberProvider extends ContentProvider {
         final String e164Number = Utils.getE164Number(context, phoneNumber, null);
         TelephonyManager tm = context.getSystemService(TelephonyManager.class);
 
-        if (!Flags.enforceTelephonyFeatureMapping()) {
+        if (tm == null) {
+            return false;
+        }
+        try {
             return tm.isEmergencyNumber(phoneNumber) || tm.isEmergencyNumber(e164Number);
-        } else {
-            if (tm == null) {
-                return false;
-            }
-            try {
-                return tm.isEmergencyNumber(phoneNumber) || tm.isEmergencyNumber(e164Number);
-            } catch (UnsupportedOperationException | IllegalStateException e) {
-                return false;
-            }
+        } catch (UnsupportedOperationException | IllegalStateException e) {
+            return false;
         }
     }
 
diff --git a/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java b/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java
index 1c45905..9f43165 100644
--- a/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java
+++ b/tests/src/com/android/providers/blockednumber/BlockedNumberProviderTest.java
@@ -18,9 +18,9 @@ package com.android.providers.blockednumber;
 import static android.os.UserHandle.MIN_SECONDARY_USER_ID;
 import static android.os.UserHandle.USER_SYSTEM;
 
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.mock;
```

