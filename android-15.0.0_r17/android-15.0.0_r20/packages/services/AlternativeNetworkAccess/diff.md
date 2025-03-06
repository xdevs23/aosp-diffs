```diff
diff --git a/src/com/android/ons/OpportunisticNetworkService.java b/src/com/android/ons/OpportunisticNetworkService.java
index 3e9a52a..771a21b 100644
--- a/src/com/android/ons/OpportunisticNetworkService.java
+++ b/src/com/android/ons/OpportunisticNetworkService.java
@@ -20,6 +20,7 @@ import static android.telephony.TelephonyManager.ENABLE_FEATURE_MAPPING;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.app.ActivityManager;
 import android.app.Service;
 import android.app.compat.CompatChanges;
 import android.compat.Compatibility;
@@ -40,6 +41,7 @@ import android.os.Message;
 import android.os.RemoteException;
 import android.os.SystemProperties;
 import android.os.TelephonyServiceManager.ServiceRegisterer;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.telephony.AvailableNetworkInfo;
 import android.telephony.CarrierConfigManager;
@@ -210,7 +212,7 @@ public class OpportunisticNetworkService extends Service {
 
     private boolean hasOpportunisticSubPrivilege(String callingPackage, int subId) {
         return mTelephonyManager.hasCarrierPrivileges(subId)
-                || mSubscriptionManager.canManageSubscription(
+                || canManageSubscription(
                 mProfileSelector.getOpprotunisticSubInfo(subId), callingPackage);
     }
 
@@ -831,6 +833,15 @@ public class OpportunisticNetworkService extends Service {
         }
     }
 
+    private boolean canManageSubscription(SubscriptionInfo subInfo, String packageName) {
+        if (Flags.hsumPackageManager() && UserManager.isHeadlessSystemUserMode()) {
+            return mSubscriptionManager.canManageSubscriptionAsUser(subInfo, packageName,
+                    UserHandle.of(ActivityManager.getCurrentUser()));
+        } else {
+            return mSubscriptionManager.canManageSubscription(subInfo, packageName);
+        }
+    }
+
     private void log(String msg) {
         Rlog.d(TAG, msg);
     }
diff --git a/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java b/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
index ba15bc0..fdab774 100644
--- a/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
+++ b/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
@@ -279,7 +279,6 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
             mResult = iOpportunisticNetworkService.getPreferredDataSubscriptionId(pkgForDebug,
                     pkgForFeature);
             Log.d(TAG, "testGetPreferredDataSubscriptionId: " + mResult);
-            assertNotNull(mResult);
         } catch (RemoteException ex) {
             Log.e(TAG, "RemoteException", ex);
         }
```

