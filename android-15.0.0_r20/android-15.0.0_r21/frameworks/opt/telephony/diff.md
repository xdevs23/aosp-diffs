```diff
diff --git a/src/java/com/android/internal/telephony/satellite/SatelliteController.java b/src/java/com/android/internal/telephony/satellite/SatelliteController.java
index bf0d882970..d455863342 100644
--- a/src/java/com/android/internal/telephony/satellite/SatelliteController.java
+++ b/src/java/com/android/internal/telephony/satellite/SatelliteController.java
@@ -7398,6 +7398,7 @@ public class SatelliteController extends Handler {
 
     public int getSelectedSatelliteSubId() {
         synchronized (mSatelliteTokenProvisionedLock) {
+            plogd("getSelectedSatelliteSubId: subId=" + mSelectedSatelliteSubId);
             return mSelectedSatelliteSubId;
         }
     }
@@ -7477,6 +7478,7 @@ public class SatelliteController extends Handler {
         }
         plogd("selectBindingSatelliteSubscription: SelectedSatelliteSubId=" + selectedSubId);
         handleEventSelectedNbIotSatelliteSubscriptionChanged(selectedSubId);
+        handleCarrierRoamingNtnAvailableServicesChanged();
     }
 
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
@@ -7699,7 +7701,7 @@ public class SatelliteController extends Handler {
             return;
         }
         persistNtnSmsSupportedByMessagesApp(ntnSmsSupported);
-        handleCarrierRoamingNtnAvailableServicesChanged(getSelectedSatelliteSubId());
+        handleCarrierRoamingNtnAvailableServicesChanged();
     }
 
     private void persistNtnSmsSupportedByMessagesApp(boolean ntnSmsSupported) {
@@ -7753,6 +7755,7 @@ public class SatelliteController extends Handler {
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected void setSelectedSatelliteSubId(int subId) {
         synchronized (mSatelliteTokenProvisionedLock) {
+            plogd("setSelectedSatelliteSubId: subId=" + subId);
             mSelectedSatelliteSubId = subId;
         }
     }
@@ -7925,7 +7928,9 @@ public class SatelliteController extends Handler {
                     synchronized (mSatelliteAccessConfigLock) {
                         mSatelliteAccessAllowed = isAllowed;
                     }
+                    evaluateESOSProfilesPrioritization();
                     evaluateCarrierRoamingNtnEligibilityChange();
+                    handleCarrierRoamingNtnAvailableServicesChanged();
                 }
 
                 @Override
@@ -8233,8 +8238,23 @@ public class SatelliteController extends Handler {
                         .build();
     }
 
+    private void handleCarrierRoamingNtnAvailableServicesChanged() {
+        int[] activeSubIds = mSubscriptionManagerService.getActiveSubIdList(true);
+        if (activeSubIds == null) {
+            plogd("handleCarrierRoamingNtnAvailableServicesChanged: activeSubIds is null.");
+            return;
+        }
+
+        plogd("handleCarrierRoamingNtnAvailableServicesChanged: activeSubIds size="
+                + activeSubIds.length);
+        for (int subId: activeSubIds) {
+            handleCarrierRoamingNtnAvailableServicesChanged(subId);
+        }
+    }
+
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected void handleCarrierRoamingNtnAvailableServicesChanged(int subId) {
+        plogd("handleCarrierRoamingNtnAvailableServicesChanged: subId=" + subId);
         if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
             plogd("handleCarrierRoamingNtnAvailableServicesChanged: "
                     + "carrierRoamingNbIotNtn flag is disabled");
```

