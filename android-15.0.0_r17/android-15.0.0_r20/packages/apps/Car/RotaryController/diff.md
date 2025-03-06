```diff
diff --git a/src/com/android/car/rotary/Navigator.java b/src/com/android/car/rotary/Navigator.java
index a77dd73..20ab450 100644
--- a/src/com/android/car/rotary/Navigator.java
+++ b/src/com/android/car/rotary/Navigator.java
@@ -422,8 +422,8 @@ class Navigator {
             return null;
         }
 
-        // Build a list of candidate focus areas, starting with all the other focus areas in the
-        // same window as the current focus area.
+        // Build a list of candidate focus areas, starting with all the other explicit focus areas
+        // in the same window as the current focus area.
         List<AccessibilityNodeInfo> candidateFocusAreas = findNonEmptyFocusAreas(currentWindow);
         for (AccessibilityNodeInfo focusArea : candidateFocusAreas) {
             if (focusArea.equals(currentFocusArea)) {
@@ -439,7 +439,13 @@ class Navigator {
             candidateFocusAreasBounds.add(bounds);
         }
 
-        maybeAddImplicitFocusArea(currentWindow, candidateFocusAreas, candidateFocusAreasBounds);
+        // There is up to one implicit focus area in a window. If the current focus area is an
+        // implicit focus area, we're done with the current window. Otherwise, we need to look for
+        // the potential implicit focus area.
+        if (Utils.isFocusArea(currentFocusArea)) {
+            maybeAddImplicitFocusArea(currentWindow, candidateFocusAreas,
+                    candidateFocusAreasBounds);
+        }
 
         // If the current focus area is an explicit focus area, use its focus area bounds to find
         // nudge target as usual. Otherwise, use the tailored bounds, which was added as the last
diff --git a/src/com/android/car/rotary/RotaryService.java b/src/com/android/car/rotary/RotaryService.java
index c85e893..76b610e 100644
--- a/src/com/android/car/rotary/RotaryService.java
+++ b/src/com/android/car/rotary/RotaryService.java
@@ -592,6 +592,13 @@ public class RotaryService extends AccessibilityService implements
     public void onCreate() {
         L.v("onCreate");
         super.onCreate();
+        if (getBaseContext() != null) {
+            mContentResolver = getContentResolver();
+        }
+        if (mContentResolver == null) {
+            L.w("ContentResolver not available");
+        }
+
         Resources res = getResources();
         mRotationAcceleration3xMs = res.getInteger(R.integer.rotation_acceleration_3x_ms);
         mRotationAcceleration2xMs = res.getInteger(R.integer.rotation_acceleration_2x_ms);
@@ -678,13 +685,6 @@ public class RotaryService extends AccessibilityService implements
         filter.addAction(Intent.ACTION_PACKAGE_REMOVED);
         filter.addDataScheme("package");
         registerReceiver(mAppInstallUninstallReceiver, filter);
-
-        if (getBaseContext() != null) {
-            mContentResolver = getContentResolver();
-        }
-        if (mContentResolver == null) {
-            L.w("ContentResolver not available");
-        }
     }
 
     /**
```

