```diff
diff --git a/builtInServices/Android.bp b/builtInServices/Android.bp
index d6ed2e4..246119e 100644
--- a/builtInServices/Android.bp
+++ b/builtInServices/Android.bp
@@ -16,7 +16,7 @@ java_sdk_library {
     ],
     static_libs: [
         "android.car.watchdoglib",
-        "android.automotive.watchdog.internal-V3-java",
+        "android.automotive.watchdog.internal-java",
     ],
     api_lint: {
         enabled: true,
diff --git a/builtInServices/src/android/content/res/CompatScaleWrapper.java b/builtInServices/src/android/content/res/CompatScaleWrapper.java
index 4624efb..fafac45 100644
--- a/builtInServices/src/android/content/res/CompatScaleWrapper.java
+++ b/builtInServices/src/android/content/res/CompatScaleWrapper.java
@@ -45,4 +45,10 @@ public final class CompatScaleWrapper {
     public float getDensityScaleFactor() {
         return mDensityScaleFactor;
     }
+
+    @Override
+    public String toString() {
+        return "CompatScaleWrapper{ mScaleFactor=" + mScaleFactor + ", mDensityScaleFactor="
+                + mDensityScaleFactor + "}";
+    }
 }
diff --git a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
index e669fc8..4bf9c12 100644
--- a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
+++ b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
@@ -851,16 +851,6 @@ public class CarServiceHelperService extends SystemService
             }
             service.handleClientsNotResponding(processIdentifiers);
         }
-
-        @Override
-        public String getInterfaceHash() {
-            return ICarWatchdogMonitor.HASH;
-        }
-
-        @Override
-        public int getInterfaceVersion() {
-            return ICarWatchdogMonitor.VERSION;
-        }
     }
 
     private final class ProcessTerminator {
diff --git a/builtInServices/src/com/android/server/wm/ActivityRecordWrapper.java b/builtInServices/src/com/android/server/wm/ActivityRecordWrapper.java
index 68f1c5f..c49ad6a 100644
--- a/builtInServices/src/com/android/server/wm/ActivityRecordWrapper.java
+++ b/builtInServices/src/com/android/server/wm/ActivityRecordWrapper.java
@@ -71,7 +71,7 @@ public final class ActivityRecordWrapper {
      * Returns whether this Activity is not displayed.
      */
     public boolean isNoDisplay() {
-        return mActivityRecord.noDisplay;
+        return mActivityRecord.isNoDisplay();
     }
 
     /**
diff --git a/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java b/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java
index 96a90bc..493845b 100644
--- a/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java
+++ b/builtInServices/src/com/android/server/wm/CarDisplayAreaPolicyProvider.java
@@ -129,10 +129,6 @@ public class CarDisplayAreaPolicyProvider implements DisplayAreaPolicy.Provider
                 new DisplayAreaPolicyBuilder.HierarchyBuilder(defaultAppsRoot)
                         .setTaskDisplayAreas(firstTdaList)
                         .setImeContainer(imeContainer)
-                        .addFeature(new DisplayAreaPolicyBuilder.Feature.Builder(wmService.mPolicy,
-                                "ImePlaceholder", FEATURE_IME_PLACEHOLDER)
-                                .and(TYPE_INPUT_METHOD, TYPE_INPUT_METHOD_DIALOG)
-                                .build())
                         .addFeature(new DisplayAreaPolicyBuilder.Feature.Builder(wmService.mPolicy,
                                 "TitleBar", FEATURE_TITLE_BAR)
                                 .and(TYPE_APPLICATION_OVERLAY)
diff --git a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
index e0182b8..dc17c99 100644
--- a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
+++ b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
@@ -21,8 +21,10 @@ import static com.google.common.truth.Truth.assertWithMessage;
 import static org.junit.Assume.assumeTrue;
 
 import android.app.Instrumentation;
+import android.content.ComponentName;
 import android.content.Intent;
 import android.view.KeyEvent;
+import android.view.accessibility.AccessibilityManager;
 
 import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.uiautomator.Condition;
@@ -50,15 +52,20 @@ public final class ActivityResolverTest {
     private static final String DISMISS_BUTTON_RESOURCE_ID =
             "com.google.android.car.kitchensink:id/dismiss_button";
     private static final String TITLE_ID = "android:id/title";
+    private static final ComponentName ROTARY_SERVICE_COMPONENT_NAME =
+            ComponentName.unflattenFromString("com.android.car.rotary/.RotaryService");
 
     private static final String KITCHEN_SINK_APP = "com.google.android.car.kitchensink";
 
     private Instrumentation mInstrumentation;
     private UiDevice mDevice;
+    private AccessibilityManager mAccessibilityManager;
 
     @Before
     public void setUp() throws IOException {
         mInstrumentation = InstrumentationRegistry.getInstrumentation();
+        mAccessibilityManager = mInstrumentation.getContext().getSystemService(
+                AccessibilityManager.class);
         mDevice = UiDevice.getInstance(mInstrumentation);
         closeKitchenSink();
     }
@@ -74,6 +81,7 @@ public final class ActivityResolverTest {
 
     @Test
     public void testListItemFocusable_threeItems() throws UiObjectNotFoundException, IOException {
+        assumeHasRotaryService();
         launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
@@ -100,6 +108,7 @@ public final class ActivityResolverTest {
 
     @Test
     public void testListItemFocusable_twoItems() throws UiObjectNotFoundException, IOException {
+        assumeHasRotaryService();
         launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
@@ -128,6 +137,7 @@ public final class ActivityResolverTest {
     @Test
     public void testActionButtonsNotFocusable_threeItems()
             throws UiObjectNotFoundException, IOException {
+        assumeHasRotaryService();
         launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
@@ -148,6 +158,7 @@ public final class ActivityResolverTest {
 
     @Test
     public void testClickListItem_threeItems() throws UiObjectNotFoundException, IOException {
+        assumeHasRotaryService();
         launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
@@ -195,6 +206,7 @@ public final class ActivityResolverTest {
 
     @Test
     public void testClickListItem_twoItems() throws UiObjectNotFoundException, IOException {
+        assumeHasRotaryService();
         launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
@@ -215,6 +227,7 @@ public final class ActivityResolverTest {
 
     @Test
     public void testClickJustOnceButton_twoItems() throws UiObjectNotFoundException, IOException {
+        assumeHasRotaryService();
         launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
@@ -261,6 +274,14 @@ public final class ActivityResolverTest {
         mDevice.waitForIdle();
     }
 
+    private void assumeHasRotaryService() {
+        assumeTrue("Rotary service not enabled; skipping test",
+                mAccessibilityManager.getInstalledAccessibilityServiceList().stream().anyMatch(
+                        accessibilityServiceInfo ->
+                                ROTARY_SERVICE_COMPONENT_NAME.equals(
+                                        accessibilityServiceInfo.getComponentName())));
+    }
+
     private void waitAndAssertFocused(UiObject view) throws UiObjectNotFoundException {
         mDevice.wait(isViewFocused(view), WAIT_TIMEOUT_MS);
         assertWithMessage("The view " + view + " should be focused")
diff --git a/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java
index b728c54..0c4d99b 100644
--- a/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java
@@ -30,6 +30,7 @@ import android.util.ArraySet;
 import android.util.Log;
 import android.util.SparseArray;
 
+import com.android.car.internal.dep.Trace;
 import com.android.car.internal.util.IndentingPrintWriter;
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
@@ -72,12 +73,15 @@ public final class CarActivityInterceptorUpdatableImpl implements CarActivityInt
             return null;
         }
         ComponentName componentName = info.getIntent().getComponent();
+        beginTraceSection("CarActivityInterceptor-onInterceptActivityLaunch: "
+                + componentName);
 
         synchronized (mLock) {
             int keyIndex = mActivityToRootTaskMap.indexOfKey(componentName);
             if (keyIndex >= 0) {
                 IBinder rootTaskToken = mActivityToRootTaskMap.valueAt(keyIndex);
                 if (!isRootTaskUserSameAsActivityUser(rootTaskToken, info)) {
+                    Trace.endSection();
                     return null;
                 }
 
@@ -89,10 +93,12 @@ public final class CarActivityInterceptorUpdatableImpl implements CarActivityInt
                 // Even if the activity is assigned a root task to open in, the launch display ID
                 // should take preference when opening the activity. More details in b/295893892.
                 if (!isRootTaskDisplayIdSameAsLaunchDisplayId(rootTaskToken, optionsWrapper)) {
+                    Trace.endSection();
                     return null;
                 }
 
                 optionsWrapper.setLaunchRootTask(rootTaskToken);
+                Trace.endSection();
                 return ActivityInterceptResultWrapper.create(info.getIntent(),
                         optionsWrapper.getOptions());
             }
@@ -101,11 +107,13 @@ public final class CarActivityInterceptorUpdatableImpl implements CarActivityInt
                 CarActivityInterceptorUpdatable interceptor = mInterceptors.valueAt(i);
                 ActivityInterceptResultWrapper result = interceptor.onInterceptActivityLaunch(info);
                 if (result != null) {
+                    Trace.endSection();
                     return result;
                 }
             }
         }
 
+        Trace.endSection();
         return null;
     }
 
@@ -195,34 +203,40 @@ public final class CarActivityInterceptorUpdatableImpl implements CarActivityInt
     /**
      * Sets the given {@code activities} to be persistent on the root task corresponding to the
      * given {@code rootTaskToken}.
-     * <p>
-     * If {@code rootTaskToken} is {@code null}, then the earlier root task associations of the
+     *
+     * <p>If {@code rootTaskToken} is {@code null}, then the earlier root task associations of the
      * given {@code activities} will be removed.
      *
-     * @param activities    the list of activities which have to be persisted.
+     * @param activities the list of activities which have to be persisted.
      * @param rootTaskToken the binder token of the root task which the activities have to be
-     *                      persisted on.
+     *     persisted on.
      */
-    public void setPersistentActivityOnRootTask(@NonNull List<ComponentName> activities,
-            IBinder rootTaskToken) {
-        synchronized (mLock) {
-            if (rootTaskToken == null) {
+    public void setPersistentActivityOnRootTask(
+            @NonNull List<ComponentName> activities, IBinder rootTaskToken) {
+        try {
+            beginTraceSection("CarActivityInterceptor-setPersistentActivityOnRootTask: "
+                    + rootTaskToken);
+            synchronized (mLock) {
+                if (rootTaskToken == null) {
+                    int activitiesNum = activities.size();
+                    for (int i = 0; i < activitiesNum; i++) {
+                        mActivityToRootTaskMap.remove(activities.get(i));
+                    }
+                    return;
+                }
+
                 int activitiesNum = activities.size();
                 for (int i = 0; i < activitiesNum; i++) {
-                    mActivityToRootTaskMap.remove(activities.get(i));
+                    mActivityToRootTaskMap.put(activities.get(i), rootTaskToken);
+                }
+                if (!mKnownRootTasks.contains(rootTaskToken)) {
+                    // Seeing the token for the first time, set the listener
+                    removeRootTaskTokenOnDeath(rootTaskToken);
+                    mKnownRootTasks.add(rootTaskToken);
                 }
-                return;
-            }
-
-            int activitiesNum = activities.size();
-            for (int i = 0; i < activitiesNum; i++) {
-                mActivityToRootTaskMap.put(activities.get(i), rootTaskToken);
-            }
-            if (!mKnownRootTasks.contains(rootTaskToken)) {
-                // Seeing the token for the first time, set the listener
-                removeRootTaskTokenOnDeath(rootTaskToken);
-                mKnownRootTasks.add(rootTaskToken);
             }
+        } finally {
+            Trace.endSection();
         }
     }
 
@@ -250,6 +264,11 @@ public final class CarActivityInterceptorUpdatableImpl implements CarActivityInt
         }
     }
 
+    private void beginTraceSection(String sectionName) {
+        // Traces can only have max 127 characters
+        Trace.beginSection(sectionName.substring(0, Math.min(sectionName.length(), 127)));
+    }
+
     @VisibleForTesting
     public Map<ComponentName, IBinder> getActivityToRootTaskMap() {
         synchronized (mLock) {
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
index e8cc75a..fe53e15 100644
--- a/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
+++ b/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
@@ -37,6 +37,7 @@ import android.content.res.Resources;
 import android.os.ServiceSpecificException;
 import android.util.Log;
 
+import com.android.car.internal.dep.Trace;
 import com.android.internal.annotations.VisibleForTesting;
 
 /**
@@ -120,6 +121,9 @@ public final class CarDisplayCompatActivityInterceptor implements CarActivityInt
             return null;
         }
         try {
+            Trace.beginSection(
+                    "CarDisplayActivity-onInterceptActivityLaunchIntentComponent: "
+                            + launchIntent.getComponent());
             boolean requiresDisplayCompat = mDisplayCompatProvider
                     .requiresDisplayCompat(launchIntent.getComponent().getPackageName(),
                             info.getUserId());
@@ -170,8 +174,9 @@ public final class CarDisplayCompatActivityInterceptor implements CarActivityInt
             }
         } catch (ServiceSpecificException e) {
             Slogf.e(TAG, "Error while intercepting activity " + launchIntent.getComponent(), e);
+        } finally {
+            Trace.endSection();
         }
-
         return null;
     }
 }
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
index 943cc39..98dec3d 100644
--- a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
@@ -252,7 +252,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
     @Nullable
     @Override
     public CompatScaleWrapper getCompatScale(@NonNull String packageName, @UserIdInt int userId) {
-        if (!Flags.displayCompatibility()) {
+        if (!Flags.displayCompatibility() || !Flags.displayCompatibilityDensity()) {
             return null;
         }
         if (mPackageManager != null
@@ -277,14 +277,19 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         float compatModeScalingFactor = mCarCompatScaleProviderInterface
                 .getCompatModeScalingFactor(packageName, UserHandle.of(userId));
         if (compatModeScalingFactor == DEFAULT_SCALE) {
+            Slogf.i(TAG, "Returning CompatScale " + compatScale + " for package " + packageName);
             return compatScale;
         }
         // This shouldn't happen outside of CTS, because CompatModeChanges has higher
         // priority and will already return a scale.
         // See {@code com.android.server.wm.CompatModePackage#getCompatScale} for details.
-        CompatScaleWrapper res = new CompatScaleWrapper(DEFAULT_SCALE,
-                (1f / compatModeScalingFactor) * compatScale.getDensityScaleFactor());
-        return res;
+        if(compatScale != null) {
+            CompatScaleWrapper res = new CompatScaleWrapper(DEFAULT_SCALE,
+                    (1f / compatModeScalingFactor) * compatScale.getDensityScaleFactor());
+            return res;
+        }
+        Slogf.i(TAG, "Returning CompatScale " + compatScale + " for package " + packageName);
+        return compatScale;
     }
 
     @Nullable
diff --git a/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
index d385206..ed72b3b 100644
--- a/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
@@ -33,6 +33,7 @@ import android.util.Pair;
 import android.util.SparseIntArray;
 import android.view.Display;
 
+import com.android.car.internal.dep.Trace;
 import com.android.car.internal.util.IndentingPrintWriter;
 import com.android.internal.annotations.GuardedBy;
 
@@ -263,6 +264,7 @@ public final class CarLaunchParamsModifierUpdatableImpl
      * See {@code LaunchParamsController.LaunchParamsModifier.onCalculate()} for the detail.
      */
     public int calculate(CalculateParams params) {
+        Trace.beginSection("CarLaunchParamsModifier-calculate");
         TaskWrapper task = params.getTask();
         ActivityRecordWrapper activity = params.getActivity();
         ActivityRecordWrapper source = params.getSource();
@@ -278,6 +280,7 @@ public final class CarLaunchParamsModifierUpdatableImpl
             userId = activity.getUserId();
         } else {
             Slogf.w(TAG, "onCalculate, cannot decide user");
+            Trace.endSection();
             return LaunchParamsWrapper.RESULT_SKIP;
         }
         // DisplayArea where user wants to launch the Activity.
@@ -387,8 +390,10 @@ public final class CarLaunchParamsModifierUpdatableImpl
                     != ActivityOptionsWrapper.WINDOWING_MODE_UNDEFINED) {
                 outParams.setWindowingMode(options.getLaunchWindowingMode());
             }
+            Trace.endSection();
             return LaunchParamsWrapper.RESULT_DONE;
         } else {
+            Trace.endSection();
             return LaunchParamsWrapper.RESULT_SKIP;
         }
     }
@@ -458,30 +463,36 @@ public final class CarLaunchParamsModifierUpdatableImpl
      * See {@link CarActivityManager#setPersistentActivity(android.content.ComponentName,int, int)}
      */
     public int setPersistentActivity(ComponentName activity, int displayId, int featureId) {
-        if (DBG) {
-            Slogf.d(TAG, "setPersistentActivity: activity=%s, displayId=%d, featureId=%d",
-                    activity, displayId, featureId);
-        }
-        if (featureId == DisplayAreaOrganizerHelper.FEATURE_UNDEFINED) {
-            synchronized (mLock) {
-                TaskDisplayAreaWrapper removed = mPersistentActivities.remove(activity);
-                if (removed == null) {
-                    throw new ServiceSpecificException(
-                            CarActivityManager.ERROR_CODE_ACTIVITY_NOT_FOUND,
-                            "Failed to remove " + activity.toShortString());
+        try {
+            Trace.beginSection(
+                    "CarLaunchParamsModifier-setPersistentActivityOnDisplay: " + displayId);
+            if (DBG) {
+                Slogf.d(TAG, "setPersistentActivity: activity=%s, displayId=%d, featureId=%d",
+                        activity, displayId, featureId);
+            }
+            if (featureId == DisplayAreaOrganizerHelper.FEATURE_UNDEFINED) {
+                synchronized (mLock) {
+                    TaskDisplayAreaWrapper removed = mPersistentActivities.remove(activity);
+                    if (removed == null) {
+                        throw new ServiceSpecificException(
+                                CarActivityManager.ERROR_CODE_ACTIVITY_NOT_FOUND,
+                                "Failed to remove " + activity.toShortString());
+                    }
+                    return CarActivityManager.RESULT_SUCCESS;
                 }
-                return CarActivityManager.RESULT_SUCCESS;
             }
+            TaskDisplayAreaWrapper tda = mBuiltin.findTaskDisplayArea(displayId, featureId);
+            if (tda == null) {
+                throw new IllegalArgumentException(
+                        "Unknown display=" + displayId + " or feature=" + featureId);
+            }
+            synchronized (mLock) {
+                mPersistentActivities.put(activity, tda);
+            }
+            return CarActivityManager.RESULT_SUCCESS;
+        } finally {
+            Trace.endSection();
         }
-        TaskDisplayAreaWrapper tda = mBuiltin.findTaskDisplayArea(displayId, featureId);
-        if (tda == null) {
-            throw new IllegalArgumentException("Unknown display=" + displayId
-                    + " or feature=" + featureId);
-        }
-        synchronized (mLock) {
-            mPersistentActivities.put(activity, tda);
-        }
-        return CarActivityManager.RESULT_SUCCESS;
     }
 
     /**
diff --git a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
index 8e23532..3d61757 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
@@ -17,6 +17,7 @@
 package com.android.server.wm;
 
 import static android.car.feature.Flags.FLAG_DISPLAY_COMPATIBILITY;
+import static android.car.feature.Flags.FLAG_DISPLAY_COMPATIBILITY_DENSITY;
 import static android.content.ContentResolver.NOTIFY_INSERT;
 import static android.content.pm.ApplicationInfo.FLAG_SYSTEM;
 import static android.content.pm.FeatureInfo.FLAG_REQUIRED;
@@ -87,7 +88,7 @@ import java.io.InputStream;
 import java.util.ArrayList;
 import java.util.Collections;
 
-@RequiresFlagsEnabled(FLAG_DISPLAY_COMPATIBILITY)
+@RequiresFlagsEnabled({FLAG_DISPLAY_COMPATIBILITY, FLAG_DISPLAY_COMPATIBILITY_DENSITY})
 @RunWith(AndroidJUnit4.class)
 public class CarDisplayCompatScaleProviderUpdatableTest {
 
```

