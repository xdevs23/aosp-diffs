```diff
diff --git a/ClusterHomeSample/src/com/android/car/cluster/home/ClusterHomeApplication.java b/ClusterHomeSample/src/com/android/car/cluster/home/ClusterHomeApplication.java
index 280e589..76d6c37 100644
--- a/ClusterHomeSample/src/com/android/car/cluster/home/ClusterHomeApplication.java
+++ b/ClusterHomeSample/src/com/android/car/cluster/home/ClusterHomeApplication.java
@@ -462,6 +462,8 @@ public final class ClusterHomeApplication extends Application {
             Log.e(TAG, "Can't find the navigation owner");
             return UI_TYPE_CLUSTER_NONE;
         }
+        // TODO(b/412843740): update navigation activity when a new package installed or changed
+        add3PNavigationActivities(ActivityManager.getCurrentUser());
         for (int i = 0; i < focusOwnerPackageNames.size(); ++i) {
             String focusOwnerPackage = focusOwnerPackageNames.get(i);
             for (int j = mClusterActivities.size() - 1; j >= 0; --j) {
```

