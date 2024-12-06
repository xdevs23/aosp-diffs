```diff
diff --git a/builtInServices/Android.bp b/builtInServices/Android.bp
index 046f048..d6ed2e4 100644
--- a/builtInServices/Android.bp
+++ b/builtInServices/Android.bp
@@ -8,7 +8,7 @@ java_sdk_library {
     libs: [
         "services",
         "android.car",
-        "android.car.builtin",  // Will remove once split is complete
+        "android.car.builtin.stubs.module_lib",  // Will remove once split is complete
         "android.hardware.automotive.vehicle-V2.0-java",
     ],
     srcs: [
diff --git a/builtInServices/api/module-lib-current.txt b/builtInServices/api/module-lib-current.txt
index 6f328de..3a9ce4e 100644
--- a/builtInServices/api/module-lib-current.txt
+++ b/builtInServices/api/module-lib-current.txt
@@ -17,9 +17,11 @@ package com.android.internal.car {
     method @Nullable public java.io.File dumpServiceStacks();
     method public int fetchAidlVhalPid();
     method public int getMainDisplayAssignedToUser(int);
+    method public int getOwnerUserIdForDisplay(int);
     method public int getProcessGroup(int);
     method public int getUserAssignedToDisplay(int);
-    method public boolean isOverlayDisplay(int);
+    method public boolean isPublicOverlayDisplay(int);
+    method public boolean isPublicVirtualDisplay(int);
     method public boolean isVisibleBackgroundUsersEnabled();
     method public void setProcessGroup(int, int);
     method public void setProcessProfile(int, int, @NonNull String);
@@ -60,6 +62,7 @@ package com.android.server.wm {
 
   public final class ActivityOptionsWrapper {
     method public static com.android.server.wm.ActivityOptionsWrapper create(android.app.ActivityOptions);
+    method public int getCallerDisplayId();
     method public com.android.server.wm.TaskDisplayAreaWrapper getLaunchTaskDisplayArea();
     method public int getLaunchWindowingMode();
     method public android.app.ActivityOptions getOptions();
@@ -104,6 +107,7 @@ package com.android.server.wm {
   public interface CarDisplayCompatScaleProviderInterface {
     method public float getCompatModeScalingFactor(@NonNull String, @NonNull android.os.UserHandle);
     method @NonNull public android.util.Pair<java.lang.Integer,java.lang.Integer> getCurrentAndTargetUserIds();
+    method @NonNull public java.util.List<android.content.pm.ApplicationInfo> getInstalledApplicationsAsUser(@NonNull android.content.pm.PackageManager.ApplicationInfoFlags, int);
     method public int getMainDisplayAssignedToUser(int);
     method @Nullable public android.content.pm.PackageInfo getPackageInfoAsUser(@NonNull String, @NonNull android.content.pm.PackageManager.PackageInfoFlags, int) throws android.content.pm.PackageManager.NameNotFoundException;
     method @Nullable public String getStringForUser(android.content.ContentResolver, String, int);
@@ -119,7 +123,7 @@ package com.android.server.wm {
     method @Nullable public com.android.server.wm.TaskDisplayAreaWrapper findTaskDisplayArea(int, int);
     method @NonNull public android.util.Pair<java.lang.Integer,java.lang.Integer> getCurrentAndTargetUserIds();
     method @Nullable public com.android.server.wm.TaskDisplayAreaWrapper getDefaultTaskDisplayAreaOnDisplay(int);
-    method @NonNull public java.util.List<com.android.server.wm.TaskDisplayAreaWrapper> getFallbackDisplayAreasForActivity(@NonNull com.android.server.wm.ActivityRecordWrapper, @Nullable com.android.server.wm.RequestWrapper);
+    method @NonNull public java.util.List<com.android.server.wm.TaskDisplayAreaWrapper> getFallbackDisplayAreasForActivity(@Nullable com.android.server.wm.ActivityRecordWrapper, @Nullable com.android.server.wm.RequestWrapper);
     method public int getMainDisplayAssignedToUser(int);
     method public int getUserAssignedToDisplay(int);
   }
diff --git a/builtInServices/src/com/android/internal/car/CarServiceHelperInterface.java b/builtInServices/src/com/android/internal/car/CarServiceHelperInterface.java
index 9168101..3050173 100644
--- a/builtInServices/src/com/android/internal/car/CarServiceHelperInterface.java
+++ b/builtInServices/src/com/android/internal/car/CarServiceHelperInterface.java
@@ -65,8 +65,14 @@ public interface CarServiceHelperInterface {
     /** See {@link android.os.UserManager#isVisibleBackgroundUsersEnabled()}. */
     boolean isVisibleBackgroundUsersEnabled();
 
-    /** Returns true if the given displayId is OverlayDisplay's.*/
-    boolean isOverlayDisplay(int displayId);
+    /** Returns true if the given displayId is PublicOverlayDisplay's.*/
+    boolean isPublicOverlayDisplay(int displayId);
+
+    /** Returns true if the given displayId is PublicVirtualDisplay's*/
+    boolean isPublicVirtualDisplay(int displayId);
+
+    /** Returns the owner user id for a given displayId.*/
+    int getOwnerUserIdForDisplay(int displayId);
 
     /**
      * Dumps service stacks
diff --git a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
index 0adcf69..e669fc8 100644
--- a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
+++ b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
@@ -18,6 +18,7 @@ package com.android.internal.car;
 import static android.view.Display.FLAG_PRIVATE;
 import static android.view.Display.FLAG_TRUSTED;
 import static android.view.Display.TYPE_OVERLAY;
+import static android.view.Display.TYPE_VIRTUAL;
 
 import static com.android.car.internal.common.CommonConstants.INVALID_PID;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_CREATED;
@@ -622,7 +623,8 @@ public class CarServiceHelperService extends SystemService
                 pids, /* processCpuTracker= */ null, /* lastPids= */ null,
                 CompletableFuture.completedFuture(getInterestingNativePids()),
                 /* logExceptionCreatingFile= */ null, /* subject= */ null,
-                /* criticalEventSection= */ null, Runnable::run, /* latencyTracker= */ null);
+                /* criticalEventSection= */ null, /* extraHeaders= */ null,
+                 Runnable::run, /* latencyTracker= */ null);
     }
 
     @Override
@@ -805,7 +807,7 @@ public class CarServiceHelperService extends SystemService
     }
 
     @Override
-    public boolean isOverlayDisplay(int displayId) {
+    public boolean isPublicOverlayDisplay(int displayId) {
         Display display = mDisplayManager.getDisplay(displayId);
         if (display == null) {
             return false;
@@ -815,6 +817,25 @@ public class CarServiceHelperService extends SystemService
                 && display.getType() == TYPE_OVERLAY);
     }
 
+    @Override
+    public boolean isPublicVirtualDisplay(int displayId) {
+        Display display = mDisplayManager.getDisplay(displayId);
+        if (display == null) {
+            return false;
+        }
+        int displayFlags = display.getFlags();
+        return ((displayFlags & FLAG_PRIVATE) == 0 && display.getType() == TYPE_VIRTUAL);
+    }
+
+    @Override
+    public @UserIdInt int getOwnerUserIdForDisplay(int displayId) {
+        Display display = mDisplayManager.getDisplay(displayId);
+        if (display == null) {
+            return UserHandle.USER_NULL;
+        }
+        return UserHandle.getUserId(display.getOwnerUid());
+    }
+
     private class ICarWatchdogMonitorImpl extends ICarWatchdogMonitor.Stub {
         private final WeakReference<CarServiceHelperService> mService;
 
diff --git a/builtInServices/src/com/android/server/wm/ActivityOptionsWrapper.java b/builtInServices/src/com/android/server/wm/ActivityOptionsWrapper.java
index 2607e06..088c68c 100644
--- a/builtInServices/src/com/android/server/wm/ActivityOptionsWrapper.java
+++ b/builtInServices/src/com/android/server/wm/ActivityOptionsWrapper.java
@@ -45,6 +45,13 @@ public final class ActivityOptionsWrapper {
         return new ActivityOptionsWrapper(options);
     }
 
+    /**
+     * Gets caller display. See {@link ActivityOptions#getCallerDisplayId()} for more info.
+     */
+    public int getCallerDisplayId() {
+        return mOptions.getCallerDisplayId();
+    }
+
     /**
      * Gets the underlying {@link ActivityOptions} that is wrapped by this instance.
      */
@@ -73,7 +80,7 @@ public final class ActivityOptionsWrapper {
     @Override
     public String toString() {
         StringBuilder sb = new StringBuilder(mOptions.toString());
-        sb.append(" ,mLaunchDisplayId=");
+        sb.append(", mLaunchDisplayId=");
         sb.append(mOptions.getLaunchDisplayId());
         return sb.toString();
     }
diff --git a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java
index 14b33d2..eb7d1a1 100644
--- a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java
+++ b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java
@@ -41,6 +41,7 @@ import android.car.builtin.util.Slogf;
 import android.car.feature.Flags;
 import android.content.ContentResolver;
 import android.content.Context;
+import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.PackageInfoFlags;
@@ -53,6 +54,8 @@ import android.util.Pair;
 import com.android.server.LocalServices;
 import com.android.server.pm.UserManagerInternal;
 
+import java.util.List;
+
 /**
  * Automotive implementation of {@link CompatScaleProvider}
  * This class is responsible for providing different scaling factor for some automotive specific
@@ -193,6 +196,14 @@ public final class CarDisplayCompatScaleProvider implements CompatScaleProvider
                 }
                 return 1f;
             }
+
+            @NonNull
+            @Override
+            public List<ApplicationInfo> getInstalledApplicationsAsUser(
+                    @NonNull PackageManager.ApplicationInfoFlags flags,
+                    int userId) {
+                return mPackageManager.getInstalledApplicationsAsUser(flags, userId);
+            }
         };
     }
 }
diff --git a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java
index 3940b3c..160f2f4 100644
--- a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java
+++ b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java
@@ -21,6 +21,7 @@ import android.annotation.Nullable;
 import android.annotation.SystemApi;
 import android.annotation.UserIdInt;
 import android.content.ContentResolver;
+import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.PackageInfoFlags;
@@ -28,6 +29,8 @@ import android.os.UserHandle;
 import android.provider.Settings;
 import android.util.Pair;
 
+import java.util.List;
+
 /**
  * Interface implemented by {@link com.android.server.wm.CarDisplayCompatScaleProvider} and
  * used by {@link CarDisplayCompatScaleProviderUpdatable}.
@@ -61,6 +64,14 @@ public interface CarDisplayCompatScaleProviderInterface {
             @NonNull PackageInfoFlags flags, @UserIdInt int userId)
             throws PackageManager.NameNotFoundException;
 
+    /**
+     * See {@link PackageManager#getInstalledApplicationsAsUser(PackageManager.ApplicationInfoFlags,
+     * int)} for details.
+     */
+    @NonNull
+    List<ApplicationInfo> getInstalledApplicationsAsUser(
+            @NonNull PackageManager.ApplicationInfoFlags flags, @UserIdInt int userId);
+
     /**
      * See {@link Settings.Secure#getStringForUser(ContentResolver, String, int)}
      */
diff --git a/builtInServices/src/com/android/server/wm/CarLaunchParamsModifier.java b/builtInServices/src/com/android/server/wm/CarLaunchParamsModifier.java
index 5feb93c..74a3737 100644
--- a/builtInServices/src/com/android/server/wm/CarLaunchParamsModifier.java
+++ b/builtInServices/src/com/android/server/wm/CarLaunchParamsModifier.java
@@ -160,27 +160,30 @@ public final class CarLaunchParamsModifier implements LaunchParamsController.Lau
      * @return the list of {@link TaskDisplayAreaWrapper} to house the task
      */
     private List<TaskDisplayAreaWrapper> getFallbackDisplayAreasForActivity(
-            @NonNull ActivityRecordWrapper activityRecordWrapper,
+            @Nullable ActivityRecordWrapper activityRecordWrapper,
             @Nullable RequestWrapper requestWrapper) {
-        ActivityRecord activityRecord = activityRecordWrapper.getActivityRecord();
+        ActivityRecord activityRecord = activityRecordWrapper != null
+                ? activityRecordWrapper.getActivityRecord() : null;
         Request request = requestWrapper != null ? requestWrapper.getRequest() : null;
         mFallBackDisplayAreaList.clear();
 
-        WindowProcessController controllerFromLaunchingRecord = mAtm.getProcessController(
-                activityRecord.getLaunchedFromPid(), activityRecord.getLaunchedFromUid());
-        TaskDisplayArea displayAreaForLaunchingRecord = controllerFromLaunchingRecord == null
-                ? null : controllerFromLaunchingRecord.getTopActivityDisplayArea();
-        if (displayAreaForLaunchingRecord != null) {
-            mFallBackDisplayAreaList.add(
-                    TaskDisplayAreaWrapper.create(displayAreaForLaunchingRecord));
-        }
-
-        WindowProcessController controllerFromProcess = mAtm.getProcessController(
-                activityRecord.getProcessName(), activityRecord.getUid());
-        TaskDisplayArea displayAreaForRecord = controllerFromProcess == null ? null
-                : controllerFromProcess.getTopActivityDisplayArea();
-        if (displayAreaForRecord != null) {
-            mFallBackDisplayAreaList.add(TaskDisplayAreaWrapper.create(displayAreaForRecord));
+        if (activityRecord != null) {
+            WindowProcessController controllerFromLaunchingRecord = mAtm.getProcessController(
+                    activityRecord.getLaunchedFromPid(), activityRecord.getLaunchedFromUid());
+            TaskDisplayArea displayAreaForLaunchingRecord = controllerFromLaunchingRecord == null
+                    ? null : controllerFromLaunchingRecord.getTopActivityDisplayArea();
+            if (displayAreaForLaunchingRecord != null) {
+                mFallBackDisplayAreaList.add(
+                        TaskDisplayAreaWrapper.create(displayAreaForLaunchingRecord));
+            }
+
+            WindowProcessController controllerFromProcess = mAtm.getProcessController(
+                    activityRecord.getProcessName(), activityRecord.getUid());
+            TaskDisplayArea displayAreaForRecord = controllerFromProcess == null ? null
+                    : controllerFromProcess.getTopActivityDisplayArea();
+            if (displayAreaForRecord != null) {
+                mFallBackDisplayAreaList.add(TaskDisplayAreaWrapper.create(displayAreaForRecord));
+            }
         }
 
         WindowProcessController controllerFromRequest =
@@ -223,7 +226,7 @@ public final class CarLaunchParamsModifier implements LaunchParamsController.Lau
         @NonNull
         @Override
         public List<TaskDisplayAreaWrapper> getFallbackDisplayAreasForActivity(
-                @NonNull ActivityRecordWrapper activityRecord, @Nullable RequestWrapper request) {
+                @Nullable ActivityRecordWrapper activityRecord, @Nullable RequestWrapper request) {
             return CarLaunchParamsModifier.this.getFallbackDisplayAreasForActivity(
                     activityRecord, request);
         }
diff --git a/builtInServices/src/com/android/server/wm/CarLaunchParamsModifierInterface.java b/builtInServices/src/com/android/server/wm/CarLaunchParamsModifierInterface.java
index e7a91a4..1a7e38b 100644
--- a/builtInServices/src/com/android/server/wm/CarLaunchParamsModifierInterface.java
+++ b/builtInServices/src/com/android/server/wm/CarLaunchParamsModifierInterface.java
@@ -51,7 +51,7 @@ public interface CarLaunchParamsModifierInterface {
      * Returns the list of fallback {@link TaskDisplayAreaWrapper} from the source of the request.
      */
     @NonNull List<TaskDisplayAreaWrapper> getFallbackDisplayAreasForActivity(
-            @NonNull ActivityRecordWrapper activityRecord, @Nullable RequestWrapper request);
+            @Nullable ActivityRecordWrapper activityRecord, @Nullable RequestWrapper request);
 
     /**
      * @return a pair of the current userId and the target userId.
diff --git a/builtInServices/tests/Android.bp b/builtInServices/tests/Android.bp
index a2f596b..61faeb5 100644
--- a/builtInServices/tests/Android.bp
+++ b/builtInServices/tests/Android.bp
@@ -22,9 +22,9 @@ android_test {
 
     libs: [
         "android.car",
-        "android.car.builtin",
-        "android.test.runner",
-        "android.test.base",
+        "android.car.builtin.stubs.module_lib",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
         "android.hardware.automotive.vehicle-V2.0-java",
     ],
 
diff --git a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
index ef8abc4..e0182b8 100644
--- a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
+++ b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
@@ -77,14 +77,7 @@ public final class ActivityResolverTest {
         launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
-        // When the ListView is focusable, it'll be focused after pressing TAB key. In this case,
-        // press the TAB key again to get the first list item focused.
-        UiObject list = mDevice.findObject(
-                new UiSelector().className(android.widget.ListView.class));
-        if (list.isFocusable()) {
-            mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
-        }
-
+        // Press TAB key to focus first list item
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
         UiObject listItem1 = mDevice.findObject(new UiSelector()
                 .className(android.widget.LinearLayout.class).focusable(true).instance(0));
@@ -110,14 +103,7 @@ public final class ActivityResolverTest {
         launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
-        // When the ListView is focusable, it'll be focused after pressing TAB key. In this case,
-        // press the TAB key again to get the first listItem focused.
-        UiObject list = mDevice.findObject(
-                new UiSelector().className(android.widget.ListView.class));
-        if (list.isFocusable()) {
-            mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
-        }
-
+        // Press TAB key to focus first list item
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
         UiObject listItem1 = mDevice.findObject(new UiSelector()
                 .className(android.widget.LinearLayout.class).focusable(true).instance(0));
@@ -165,9 +151,9 @@ public final class ActivityResolverTest {
         launchResolverActivity();
         assumeTrue(hasThreeListItems());
 
-        // Press twice to make sure a list item gets focused.
-        mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
+        // Press TAB key to focus first list item
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
+
         UiObject listItem = mDevice.findObject(new UiSelector()
                 .className(android.widget.LinearLayout.class).focused(true));
         waitAndAssertFocused(listItem);
@@ -188,19 +174,13 @@ public final class ActivityResolverTest {
                 .className(android.widget.Button.class).focusable(true).enabled(true).instance(1));
         waitAndAssertFocused(alwaysButton);
 
-        // Right now, the focus is on the "Always" button, so to get to the top of the list, click
-        // the View with id of "title" which is a Subview of the default app choice.
-        mDevice.findObject(new UiSelector().resourceId(TITLE_ID)).click();
+        // Currently, the focus is on the Always button. Send four DPAD_UP events to move the focus
+        // back up to the first element of the list.
+        mDevice.pressKeyCode(KeyEvent.KEYCODE_DPAD_UP);
+        mDevice.pressKeyCode(KeyEvent.KEYCODE_DPAD_UP);
+        mDevice.pressKeyCode(KeyEvent.KEYCODE_DPAD_UP);
+        mDevice.pressKeyCode(KeyEvent.KEYCODE_DPAD_UP);
 
-        // When the ListView is focusable, it'll be focused after pressing TAB key. In this case,
-        // press the TAB key again to get the first listItem focused.
-        UiObject list = mDevice.findObject(
-                new UiSelector().className(android.widget.ListView.class));
-        if (list.isFocusable()) {
-            mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
-        }
-
-        mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
         UiObject listItem1 = mDevice.findObject(new UiSelector()
                 .className(android.widget.LinearLayout.class).focusable(true).instance(0));
         waitAndAssertFocused(listItem1);
@@ -218,14 +198,7 @@ public final class ActivityResolverTest {
         launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
-
-        // When the ListView is focusable, it'll be focused after pressing TAB key. In this case,
-        // press the TAB key again to get the first listItem focused.
-        UiObject list = mDevice.findObject(
-                new UiSelector().className(android.widget.ListView.class));
-        if (list.isFocusable()) {
-            mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
-        }
+        // Press TAB key to focus first list item
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
 
         UiObject listItem = mDevice.findObject(new UiSelector()
@@ -245,13 +218,7 @@ public final class ActivityResolverTest {
         launchResolverActivity();
         assumeTrue(!hasThreeListItems());
 
-        // When the ListView is focusable, it needs 4 rotations to focus on the justOnceButton.
-        // Otherwise, it needs 3 rotations.
-        UiObject list = mDevice.findObject(
-                new UiSelector().className(android.widget.ListView.class));
-        if (list.isFocusable()) {
-            mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
-        }
+        // Press TAB key thrice to focus justOnceButton
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
         mDevice.pressKeyCode(KeyEvent.KEYCODE_TAB);
diff --git a/builtInServices/tests/src/com/android/server/wm/ActivityOptionsWrapperTest.java b/builtInServices/tests/src/com/android/server/wm/ActivityOptionsWrapperTest.java
index 01bb696..a7859db 100644
--- a/builtInServices/tests/src/com/android/server/wm/ActivityOptionsWrapperTest.java
+++ b/builtInServices/tests/src/com/android/server/wm/ActivityOptionsWrapperTest.java
@@ -35,7 +35,7 @@ public final class ActivityOptionsWrapperTest {
         ActivityOptionsWrapper wrapper = ActivityOptionsWrapper.create(options);
         assertThat(wrapper).isNotNull();
         assertThat(wrapper.getOptions()).isSameInstanceAs(options);
-        assertThat(wrapper.toString()).isEqualTo(options.toString());
+        assertThat(wrapper.toString()).startsWith(options.toString());
     }
 
     @Test
diff --git a/tools/repohookScript/annotation_classlist_repohook.py b/tools/repohookScript/annotation_classlist_repohook.py
index d53624e..788696f 100755
--- a/tools/repohookScript/annotation_classlist_repohook.py
+++ b/tools/repohookScript/annotation_classlist_repohook.py
@@ -45,8 +45,8 @@ if rootDir is None or rootDir == "":
 
 javaHomeDir = os.getenv("JAVA_HOME")
 if javaHomeDir is None or javaHomeDir == "":
-    if Path(rootDir + '/prebuilts/jdk/jdk17/linux-x86').is_dir():
-        javaHomeDir = rootDir + "/prebuilts/jdk/jdk17/linux-x86"
+    if Path(rootDir + '/prebuilts/jdk/jdk21/linux-x86').is_dir():
+        javaHomeDir = rootDir + "/prebuilts/jdk/jdk21/linux-x86"
     else:
         print("$JAVA_HOME is not set. Please use source build/envsetup.sh` in $ANDROID_BUILD_TOP")
         sys.exit(1)
diff --git a/updatableServices/Android.bp b/updatableServices/Android.bp
index 5d7c85c..82084f0 100644
--- a/updatableServices/Android.bp
+++ b/updatableServices/Android.bp
@@ -18,8 +18,8 @@ java_library {
     installable: true,
     libs: [
             "android.car",
-            "android.car.builtin",
-            "car-frameworks-service",
+            "android.car.builtin.stubs.module_lib",
+            "car-frameworks-service.stubs.module_lib",
             "framework-annotations-lib",
     ],
     srcs: [
diff --git a/updatableServices/TEST_MAPPING b/updatableServices/TEST_MAPPING
new file mode 100644
index 0000000..a358ed2
--- /dev/null
+++ b/updatableServices/TEST_MAPPING
@@ -0,0 +1,8 @@
+{
+  // Once the test proves stable, we will promote it to auto-presubmit
+  "auto-postsubmit": [
+    {
+      "name": "FrameworkOptCarServicesUpdatableTest"
+    }
+  ]
+}
diff --git a/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java b/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
index 4be7dd6..a6a38da 100644
--- a/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
+++ b/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
@@ -113,7 +113,7 @@ public final class CarServiceHelperServiceUpdatableImpl
     private final CarDisplayCompatScaleProviderUpdatableImpl
             mCarDisplayCompatScaleProviderUpdatable;
 
-    private OverlayDisplayMonitor mOverlayDisplayMonitor;
+    private ExtraDisplayMonitor mExtraDisplayMonitor;
 
     /**
      * This constructor is meant to be called using reflection by the builtin service and hence it
@@ -152,7 +152,7 @@ public final class CarServiceHelperServiceUpdatableImpl
 
         if (mCarServiceHelperInterface.isVisibleBackgroundUsersEnabled()) {
             DisplayManager displayManager = mContext.getSystemService(DisplayManager.class);
-            mOverlayDisplayMonitor = new OverlayDisplayMonitor(
+            mExtraDisplayMonitor = new ExtraDisplayMonitor(
                     displayManager, mHandler, mCarServiceHelperInterface);
         }
     }
@@ -178,8 +178,8 @@ public final class CarServiceHelperServiceUpdatableImpl
                 mCarServiceConnection)) {
             Slogf.wtf(TAG, "cannot start car service");
         }
-        if (mOverlayDisplayMonitor != null) {
-            mOverlayDisplayMonitor.init();
+        if (mExtraDisplayMonitor != null) {
+            mExtraDisplayMonitor.init();
         }
     }
 
@@ -303,9 +303,9 @@ public final class CarServiceHelperServiceUpdatableImpl
                 userFrom == null ? UserManagerHelper.USER_NULL : userFrom.getIdentifier(),
                 userTo.getIdentifier());
         if (eventType == USER_LIFECYCLE_EVENT_TYPE_SWITCHING) {
-            if (mOverlayDisplayMonitor != null) {
+            if (mExtraDisplayMonitor != null) {
                 // TODO: b/341156326 - Consider how to handle OverlayDisplay for passengers.
-                mOverlayDisplayMonitor.handleCurrentUserSwitching(userTo.getIdentifier());
+                mExtraDisplayMonitor.handleCurrentUserSwitching(userTo.getIdentifier());
             }
             mCarDisplayCompatScaleProviderUpdatable.handleCurrentUserSwitching(userTo);
         }
@@ -396,6 +396,16 @@ public final class CarServiceHelperServiceUpdatableImpl
             return mCarServiceHelperInterface.getUserAssignedToDisplay(displayId);
         }
 
+        @Override
+        public boolean assignUserToExtraDisplay(int userId, int displayId) {
+            return mCarServiceHelperInterface.assignUserToExtraDisplay(userId, displayId);
+        }
+
+        @Override
+        public boolean unassignUserFromExtraDisplay(int userId, int displayId) {
+            return mCarServiceHelperInterface.unassignUserFromExtraDisplay(userId, displayId);
+        }
+
         @Override
         public boolean startUserInBackgroundVisibleOnDisplay(int userId, int displayId) {
             return mCarServiceHelperInterface.startUserInBackgroundVisibleOnDisplay(
diff --git a/updatableServices/src/com/android/internal/car/updatable/OverlayDisplayMonitor.java b/updatableServices/src/com/android/internal/car/updatable/ExtraDisplayMonitor.java
similarity index 62%
rename from updatableServices/src/com/android/internal/car/updatable/OverlayDisplayMonitor.java
rename to updatableServices/src/com/android/internal/car/updatable/ExtraDisplayMonitor.java
index 02a57f1..ed2a7d0 100644
--- a/updatableServices/src/com/android/internal/car/updatable/OverlayDisplayMonitor.java
+++ b/updatableServices/src/com/android/internal/car/updatable/ExtraDisplayMonitor.java
@@ -24,14 +24,15 @@ import android.util.SparseIntArray;
 import com.android.internal.car.CarServiceHelperInterface;
 
 /**
- * OverlayDisplay is used to test the multiple display environment in CTS. And in MUMD, every
- * public display should be assigned to a user, or it throws an exception. This class monitors the
- * change of Display and assign it to the driver if the newly added display is a OverlayDisplay.
+ * OverlayDisplay and VirtualDisplay are used to test the multiple display environment in CTS.
+ * And in MUMD, every public display should be assigned to a user, or it throws an exception.
+ * This class monitors the change of Display. If the newly added display is an OverlayDisplay,
+ * assign it to the driver, and if it is a VirtualDisplay, assign it to the owner user.
  *
  * TODO: b/340249048 - Consider how to assign OverlayDisplay to passengers.
  */
-public final class OverlayDisplayMonitor {
-    private static final String TAG = OverlayDisplayMonitor.class.getSimpleName();
+public final class ExtraDisplayMonitor {
+    private static final String TAG = ExtraDisplayMonitor.class.getSimpleName();
     /** Comes from {@link android.os.UserHandle#USER_NULL}. */
     private static final int USER_NULL = -10000;
 
@@ -39,10 +40,10 @@ public final class OverlayDisplayMonitor {
     private final Handler mHandler;
     private final CarServiceHelperInterface mHelper;
     // Key: displayId, Value: userId
-    private final SparseIntArray mOverlayDisplays = new SparseIntArray();
+    private final SparseIntArray mExtraDisplays = new SparseIntArray();
     private int mCurrentUserId;
 
-    public OverlayDisplayMonitor(DisplayManager displayManager, Handler handler,
+    public ExtraDisplayMonitor(DisplayManager displayManager, Handler handler,
             CarServiceHelperInterface helper) {
         mDisplayManager = displayManager;
         mHandler = handler;
@@ -62,24 +63,28 @@ public final class OverlayDisplayMonitor {
     DisplayManager.DisplayListener mDisplayListener = new DisplayManager.DisplayListener() {
         @Override
         public void onDisplayAdded(int displayId) {
-            if (mHelper.isOverlayDisplay(displayId)) {
-                if (!mHelper.assignUserToExtraDisplay(mCurrentUserId, displayId)) {
-                    Slogf.e(TAG, "Failed to assign OverlayDisplay=%d to User=%d",
-                            displayId, mCurrentUserId);
+            int userId = USER_NULL;
+            if (mHelper.isPublicVirtualDisplay(displayId)) {
+                userId = mHelper.getOwnerUserIdForDisplay(displayId);
+            }
+            if (userId != USER_NULL) {
+                if (!mHelper.assignUserToExtraDisplay(userId, displayId)) {
+                    Slogf.e(TAG, "Failed to assign ExtraDisplay=%d to User=%d",
+                            displayId, userId);
                     return;
                 }
-                mOverlayDisplays.put(displayId, mCurrentUserId);
-                Slogf.i(TAG, "Assigned OverlayDisplay=%d to User=%d", displayId, mCurrentUserId);
+                mExtraDisplays.put(displayId, userId);
+                Slogf.i(TAG, "Assigned ExtraDisplay=%d to User=%d", displayId, userId);
             }
         }
 
         @Override
         public void onDisplayRemoved(int displayId) {
-            int userId = mOverlayDisplays.get(displayId, USER_NULL);
+            int userId = mExtraDisplays.get(displayId, USER_NULL);
             if (userId != USER_NULL) {
-                mOverlayDisplays.delete(displayId);
+                mExtraDisplays.delete(displayId);
                 boolean success = mHelper.unassignUserFromExtraDisplay(userId, displayId);
-                Slogf.i(TAG, "Unassign OverlayDisplay=%d from User=%d: %b",
+                Slogf.i(TAG, "Unassign ExtraDisplay=%d from User=%d: %b",
                         displayId, userId, success);
             }
         }
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
index f1db811..943cc39 100644
--- a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
@@ -28,6 +28,8 @@ import static android.view.Display.INVALID_DISPLAY;
 import static com.android.server.wm.CarDisplayCompatConfig.ANY_PACKAGE;
 import static com.android.server.wm.CarDisplayCompatConfig.DEFAULT_SCALE;
 
+import static java.lang.Math.abs;
+
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.SystemApi;
@@ -67,6 +69,7 @@ import org.xmlpull.v1.XmlPullParserException;
 
 import java.io.ByteArrayInputStream;
 import java.io.File;
+import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.io.InputStream;
 import java.util.Collection;
@@ -83,7 +86,6 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         CarDisplayCompatScaleProviderUpdatable, CarActivityInterceptorUpdatable {
     private static final String TAG =
             CarDisplayCompatScaleProviderUpdatableImpl.class.getSimpleName();
-    private static final boolean DBG = Slogf.isLoggable(TAG, Log.DEBUG);
     // {@code PackageManager#FEATURE_CAR_DISPLAY_COMPATIBILITY}
     static final String FEATURE_CAR_DISPLAY_COMPATIBILITY =
             "android.software.car.display_compatibility";
@@ -96,9 +98,9 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
     @VisibleForTesting
     static final int USER_NULL = -10000;
     @VisibleForTesting
-    static final float NO_SCALE = -1f;
+    static final float NO_SCALE = 0f;
     @VisibleForTesting
-    static final float OPT_OUT = -2f;
+    static final float OPT_OUT = -1 * DEFAULT_SCALE;
     // {@code CarPackageManager#ERROR_CODE_NO_PACKAGE}
     private static final int ERROR_CODE_NO_PACKAGE = -100;
     @VisibleForTesting
@@ -139,7 +141,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         @Override
         public void onReceive(Context context, Intent intent) {
             String packageName = intent.getData().getSchemeSpecificPart();
-            if (DBG) {
+            if (isDebugLoggable()) {
                 Slogf.d(TAG, "package intent " + intent);
                 Slogf.d(TAG, "package uri " + intent.getData());
             }
@@ -153,6 +155,11 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
                 } else {
                     updateStateOfPackageForUserLocked(packageName, getCurrentOrTargetUserId());
                 }
+            } catch (PackageManager.NameNotFoundException e) {
+                // This shouldn't be the case if the user requesting the package is the same as
+                // the user launching the app.
+                Slogf.w(TAG, "Package %s for user %d not found", packageName,
+                        getCurrentOrTargetUserId());
             } finally {
                 mConfigLock.unlockWrite(stamp);
             }
@@ -202,15 +209,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
             return;
         }
 
-        long stamp = mConfigLock.writeLock();
-        try {
-            if (!updateConfigForUserFromSettingsLocked(UserHandle.CURRENT)) {
-                updateCurrentConfigFromDeviceLocked();
-            }
-            updateStateOfAllPackagesForUserLocked(getCurrentOrTargetUserId());
-        } finally {
-            mConfigLock.unlockWrite(stamp);
-        }
+        initConfig(UserHandle.of(getCurrentOrTargetUserId()));
 
         // TODO(b/329898692): can we fix the tests so we don't need this?
         if (mContext.getMainLooper() == null) {
@@ -229,7 +228,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
                 if (getCurrentOrTargetUserId() == user.getIdentifier()) {
                     long stamp = mConfigLock.writeLock();
                     try {
-                        updateConfigForUserFromSettingsLocked(user);
+                        initLocalConfigFromSettingsLocked(user);
                     } finally {
                         mConfigLock.unlockWrite(stamp);
                     }
@@ -336,7 +335,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
             }
         }
         if (res != null) {
-            if (DBG) {
+            if (isDebugLoggable()) {
                 Slogf.d(TAG, "Package %s is cached %b", packageName, res.booleanValue());
             }
             return res.booleanValue();
@@ -344,6 +343,10 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
             stamp = mConfigLock.writeLock();
             try {
                 return updateStateOfPackageForUserLocked(packageName, userId);
+            } catch (PackageManager.NameNotFoundException e) {
+                // This shouldn't be the case if the user requesting the package is the same as
+                // the user launching the app.
+                throw new ServiceSpecificException(ERROR_CODE_NO_PACKAGE, e.getMessage());
             } finally {
                 mConfigLock.unlockWrite(stamp);
             }
@@ -352,13 +355,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
 
     /** Notifies user switching. */
     public void handleCurrentUserSwitching(UserHandle newUser) {
-        long stamp = mConfigLock.writeLock();
-        try {
-            updateConfigForUserFromSettingsLocked(newUser);
-            updateStateOfAllPackagesForUserLocked(newUser.getIdentifier());
-        } finally {
-            mConfigLock.unlockWrite(stamp);
-        }
+        initConfig(newUser);
     }
 
     /**
@@ -379,6 +376,19 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         writer.decreaseIndent();
     }
 
+    /** Initialise cache. */
+    private void initConfig(UserHandle user) {
+        long stamp = mConfigLock.writeLock();
+        try {
+            if (!initLocalConfigFromSettingsLocked(user)) {
+                initLocalConfigAndSettingsFromConfigFileLocked();
+                initLocalConfigAndSettingsForAllInstalledPackagesLocked(user.getIdentifier());
+            }
+        } finally {
+            mConfigLock.unlockWrite(stamp);
+        }
+    }
+
     // @GuardedBy("mConfigLock")
     // TODO(b/343755550): add back when error-prone supports {@link StampedLock}
     private int getPackageDisplayIdAsUserLocked(@NonNull String packageName,
@@ -405,14 +415,17 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         } catch (PackageManager.NameNotFoundException e) {
             // This shouldn't be the case if the user requesting the package is the same as
             // the user launching the app.
-            Slogf.e(TAG, "Package " + packageName + " not found", e);
+            Slogf.w(TAG, "Package %s for user %d not found", packageName, userId);
         }
         return displayId;
     }
 
+    /**
+     * Initializes local config and settings for all installed packages for the user.
+     */
     // @GuardedBy("mConfigLock")
     // TODO(b/343755550): add back when error-prone supports {@link StampedLock}
-    private void updateStateOfAllPackagesForUserLocked(@UserIdInt int userId) {
+    private void initLocalConfigAndSettingsForAllInstalledPackagesLocked(@UserIdInt int userId) {
         // TODO(b/329898692): can we fix the tests so we don't need this?
         if (mPackageManager == null) {
             // mPackageManager is null during tests.
@@ -420,49 +433,59 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         }
         ApplicationInfoFlags appFlags = ApplicationInfoFlags.of(GET_META_DATA);
         List<ApplicationInfo> allPackagesForUser =
-                mPackageManager.getInstalledApplications(appFlags);
+                mCarCompatScaleProviderInterface.getInstalledApplicationsAsUser(appFlags, userId);
         for (int i = 0; i < allPackagesForUser.size(); i++) {
             ApplicationInfo appInfo = allPackagesForUser.get(i);
-            updateStateOfPackageForUserLocked(appInfo.packageName, userId);
+            try {
+                updateStateOfPackageForUserLocked(appInfo.packageName, userId);
+            } catch (PackageManager.NameNotFoundException e) {
+                Slogf.w(TAG, "Package %s for user %d not found", appInfo.packageName, userId);
+            }
         }
     }
 
     // @GuardedBy("mConfigLock")
     // TODO(b/343755550): add back when error-prone supports {@link StampedLock}
     private boolean updateStateOfPackageForUserLocked(@NonNull String packageName,
-            @UserIdInt int userId) {
+            @UserIdInt int userId) throws PackageManager.NameNotFoundException {
         int displayId = getPackageDisplayIdAsUserLocked(packageName, userId);
-        try {
-            CarDisplayCompatConfig.Key key =
-                    new CarDisplayCompatConfig.Key(displayId, packageName, userId);
-            float scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-            boolean hasConfig = true;
+        CarDisplayCompatConfig.Key key =
+                new CarDisplayCompatConfig.Key(displayId, packageName, userId);
+        float scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
+        boolean hasConfig = true;
+        if (scaleFactor == NO_SCALE) {
+            key.mUserId = UserHandle.ALL.getIdentifier();
+            scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
             if (scaleFactor == NO_SCALE) {
-                key.mUserId = UserHandle.ALL.getIdentifier();
-                scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-                if (scaleFactor == NO_SCALE) {
-                    hasConfig = false;
-                }
-                key.mUserId = userId;
+                hasConfig = false;
             }
+        }
 
-            boolean result = requiresDisplayCompatNotCachedLocked(packageName, userId);
-            if (!hasConfig && !result) {
-                mConfig.setScaleFactor(key, OPT_OUT);
-            } else if (hasConfig && result && scaleFactor == OPT_OUT) {
-                mConfig.setScaleFactor(key, DEFAULT_SCALE);
+        boolean result = requiresDisplayCompatNotCachedLocked(packageName, userId);
+        if (!hasConfig && !result) {
+            // Package is opt-out
+            mConfig.setScaleFactor(key, OPT_OUT);
+        } else if (!hasConfig && result) {
+            // Apply user default scale or display default scale to the package
+            key.mPackageName = ANY_PACKAGE;
+            key.mUserId = userId;
+            scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
+            if (scaleFactor == NO_SCALE) {
+                key.mUserId = UserHandle.ALL.getIdentifier();
+                scaleFactor = mConfig.getScaleFactor(key, DEFAULT_SCALE);
             }
-
-            mRequiresDisplayCompat.put(packageName, result);
-            return result;
-        } catch (PackageManager.NameNotFoundException e) {
-            // This shouldn't be the case if the user requesting the package is the same as
-            // the user launching the app.
-            Slogf.e(TAG, "Package " + packageName + " not found", e);
-            throw new ServiceSpecificException(
-                    ERROR_CODE_NO_PACKAGE,
-                    e.getMessage());
+            mConfig.setScaleFactor(key, scaleFactor);
+        } else if (hasConfig) {
+            // Package was opt-out, but now is opt-in or the otherway around
+            mConfig.setScaleFactor(key, result ? abs(scaleFactor) : -1 * abs(scaleFactor));
         }
+
+        mRequiresDisplayCompat.put(packageName, result);
+        mCarCompatScaleProviderInterface.putStringForUser(mContext.getContentResolver(),
+                DISPLAYCOMPAT_SETTINGS_SECURE_KEY, mConfig.dump(),
+                getCurrentOrTargetUserId());
+
+        return result;
     }
 
     // @GuardedBy("mConfigLock")
@@ -478,7 +501,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         // application has {@code FEATURE_CAR_DISPLAY_COMPATIBILITY} metadata
         if (applicationInfo != null &&  applicationInfo.metaData != null
                 && applicationInfo.metaData.containsKey(FEATURE_CAR_DISPLAY_COMPATIBILITY)) {
-            if (DBG) {
+            if (isDebugLoggable()) {
                 Slogf.d(TAG, "Package %s has %s metadata", packageName,
                         FEATURE_CAR_DISPLAY_COMPATIBILITY);
             }
@@ -496,7 +519,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
             for (FeatureInfo feature: features) {
                 if (FEATURE_AUTOMOTIVE.equals(feature.name)) {
                     boolean required = ((feature.flags & FLAG_REQUIRED) != 0);
-                    if (DBG) {
+                    if (isDebugLoggable()) {
                         Slogf.d(TAG, "Package %s has %s %b",
                                 packageName, FEATURE_AUTOMOTIVE, required);
                     }
@@ -507,7 +530,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
 
         // Opt out if has no activities
         if (pkgInfo == null || pkgInfo.activities == null) {
-            if (DBG) {
+            if (isDebugLoggable()) {
                 Slogf.d(TAG, "Package %s has no Activity", packageName);
             }
             return false;
@@ -520,7 +543,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
             Bundle activityMetaData = ai.metaData;
             if (activityMetaData != null && activityMetaData
                     .getBoolean(META_DATA_DISTRACTION_OPTIMIZED)) {
-                if (DBG) {
+                if (isDebugLoggable()) {
                     Slogf.d(TAG, "Package %s has %s", packageName,
                             META_DATA_DISTRACTION_OPTIMIZED);
                 }
@@ -531,7 +554,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         if (applicationInfo != null) {
             // Opt out if it's a privileged package
             if (applicationInfo.isPrivilegedApp()) {
-                if (DBG) {
+                if (isDebugLoggable()) {
                     Slogf.d(TAG, "Package %s isPrivileged", packageName);
                 }
                 return false;
@@ -539,7 +562,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
 
             // Opt out if it's a system package
             if ((applicationInfo.flags & FLAG_SYSTEM) != 0) {
-                if (DBG) {
+                if (isDebugLoggable()) {
                     Slogf.d(TAG, "Package %s has FLAG_SYSTEM", packageName);
                 }
                 return false;
@@ -549,7 +572,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         // Opt out if package has platform signature
         if (mPackageManager.checkSignatures(PLATFORM_PACKAGE_NAME, packageName)
                 == SIGNATURE_MATCH) {
-            if (DBG) {
+            if (isDebugLoggable()) {
                 Slogf.d(TAG, "Package %s is platform signed", packageName);
             }
             return false;
@@ -559,15 +582,19 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         return true;
     }
 
+    /**
+     * @return {@code true} if local config and settings is successfully updated, false otherwise.
+     */
     // @GuardedBy("mConfigLock")
     // TODO(b/343755550): add back when error-prone supports {@link StampedLock}
-    private boolean updateCurrentConfigFromDeviceLocked() {
+    private boolean initLocalConfigAndSettingsFromConfigFileLocked() {
         // read the default config from device if user settings is not available.
-        try (InputStream in = getConfigFile().openRead()) {
+        try (InputStream in = openReadConfigFile()) {
             mConfig.populate(in);
+            mRequiresDisplayCompat.clear();
             mCarCompatScaleProviderInterface.putStringForUser(mContext.getContentResolver(),
                     DISPLAYCOMPAT_SETTINGS_SECURE_KEY, mConfig.dump(),
-                    UserHandle.CURRENT.getIdentifier());
+                    getCurrentOrTargetUserId());
             return true;
         } catch (XmlPullParserException | IOException | SecurityException e) {
             Slogf.e(TAG, "read config failed from device " + getConfigFile(), e);
@@ -575,9 +602,13 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         return false;
     }
 
+    /**
+     * @return {@code true} if settings exists and is successfully populated into the local config,
+     * false otherwise.
+     */
     // @GuardedBy("mConfigLock")
     // TODO(b/343755550): add back when error-prone supports {@link StampedLock}
-    private boolean updateConfigForUserFromSettingsLocked(@NonNull UserHandle user) {
+    private boolean initLocalConfigFromSettingsLocked(@NonNull UserHandle user) {
         // Read the config and populate the in memory cache
         String configString = mCarCompatScaleProviderInterface.getStringForUser(
                 mContext.getContentResolver(), DISPLAYCOMPAT_SETTINGS_SECURE_KEY,
@@ -588,6 +619,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         try (InputStream in =
                 new ByteArrayInputStream(configString.getBytes())) {
             mConfig.populate(in);
+            mRequiresDisplayCompat.clear();
             return true;
         } catch (XmlPullParserException | IOException | SecurityException e) {
             Slogf.e(TAG, "read config failed from Settings.Secure", e);
@@ -620,28 +652,28 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         CarDisplayCompatConfig.Key key =
                 new CarDisplayCompatConfig.Key(displayId, packageName, userId);
         float scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE && scaleFactor != OPT_OUT) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, scaleFactor);
+        if (scaleFactor != NO_SCALE) {
+            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
         }
         // Query the scale factor for all packages for a specific user.
         key.mPackageName = ANY_PACKAGE;
         scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE && scaleFactor != OPT_OUT) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, scaleFactor);
+        if (scaleFactor != NO_SCALE) {
+            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
         }
         // Query the scale factor for a specific package across all users.
         key.mPackageName = packageName;
         key.mUserId = UserHandle.ALL.getIdentifier();
         scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE && scaleFactor != OPT_OUT) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, scaleFactor);
+        if (scaleFactor != NO_SCALE) {
+            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
         }
         // Query the scale factor for a specific display regardless of
         // user or package name.
         key.mPackageName = ANY_PACKAGE;
         scaleFactor = mConfig.getScaleFactor(key, NO_SCALE);
-        if (scaleFactor != NO_SCALE && scaleFactor != OPT_OUT) {
-            return new CompatScaleWrapper(DEFAULT_SCALE, scaleFactor);
+        if (scaleFactor != NO_SCALE) {
+            return new CompatScaleWrapper(DEFAULT_SCALE, abs(scaleFactor));
         }
         return null;
     }
@@ -651,4 +683,15 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         File configFile = new File(Environment.getProductDirectory(), CONFIG_PATH);
         return new AtomicFile(configFile);
     }
+
+    /** This method is needed to be overwritten to provide a test InputStream for the config */
+    @VisibleForTesting
+    @NonNull
+    InputStream openReadConfigFile() throws FileNotFoundException {
+        return getConfigFile().openRead();
+    }
+
+    private static boolean isDebugLoggable() {
+        return Slogf.isLoggable(TAG, Log.DEBUG);
+    }
 }
diff --git a/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
index 3077803..d385206 100644
--- a/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
@@ -16,7 +16,6 @@
 
 package com.android.server.wm;
 
-import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.SystemApi;
 import android.annotation.UserIdInt;
@@ -296,13 +295,29 @@ public final class CarLaunchParamsModifierUpdatableImpl
         decision:
         synchronized (mLock) {
             // If originalDisplayArea is set, respect that before ActivityOptions check.
-            if (originalDisplayArea == null) {
-                if (options != null) {
-                    originalDisplayArea = options.getLaunchTaskDisplayArea();
-                    if (originalDisplayArea == null) {
-                        originalDisplayArea = mBuiltin.getDefaultTaskDisplayAreaOnDisplay(
-                                options.getOptions().getLaunchDisplayId());
-                    }
+            if (originalDisplayArea == null && options != null) {
+                originalDisplayArea = options.getLaunchTaskDisplayArea();
+                if (originalDisplayArea == null) {
+                    // If task display area is not specified in options - try launch display id
+                    originalDisplayArea = mBuiltin.getDefaultTaskDisplayAreaOnDisplay(
+                            options.getOptions().getLaunchDisplayId());
+                }
+            }
+            if (originalDisplayArea == null && source != null) {
+                // try the display area of the source
+                TaskDisplayAreaWrapper sourceDisplayArea = source.getDisplayArea();
+                int sourceDisplayId = sourceDisplayArea == null
+                        ? Display.INVALID_DISPLAY : sourceDisplayArea.getDisplay().getDisplayId();
+                if (userId == getUserForDisplayLocked(sourceDisplayId)) {
+                    originalDisplayArea = sourceDisplayArea;
+                }
+            }
+            if (originalDisplayArea == null && options != null) {
+                // try the caller display id
+                int callerDisplayId = options.getCallerDisplayId();
+                if (userId == getUserForDisplayLocked(callerDisplayId)) {
+                    originalDisplayArea = mBuiltin.getDefaultTaskDisplayAreaOnDisplay(
+                            callerDisplayId);
                 }
             }
             if (mPersistentActivities.containsKey(activityName)) {
@@ -391,13 +406,13 @@ public final class CarLaunchParamsModifierUpdatableImpl
     @GuardedBy("mLock")
     @Nullable
     private TaskDisplayAreaWrapper getAlternativeDisplayAreaForPassengerLocked(int userId,
-            @NonNull ActivityRecordWrapper activtyRecord, @Nullable RequestWrapper request) {
+            @Nullable ActivityRecordWrapper activityRecord, @Nullable RequestWrapper request) {
         if (DBG) Slogf.d(TAG, "getAlternativeDisplayAreaForPassengerLocked:%d", userId);
         List<TaskDisplayAreaWrapper> fallbacks = mBuiltin.getFallbackDisplayAreasForActivity(
-                activtyRecord, request);
+                activityRecord, request);
         for (int i = 0, size = fallbacks.size(); i < size; ++i) {
             TaskDisplayAreaWrapper fallbackTda = fallbacks.get(i);
-            int userForDisplay = getUserIdForDisplayLocked(fallbackTda.getDisplay().getDisplayId());
+            int userForDisplay = getUserForDisplayLocked(fallbackTda.getDisplay().getDisplayId());
             if (userForDisplay == userId) {
                 return fallbackTda;
             }
@@ -405,15 +420,6 @@ public final class CarLaunchParamsModifierUpdatableImpl
         return fallbackDisplayAreaForUserLocked(userId);
     }
 
-    /**
-     * Returns {@code userId} who is allowed to use the given {@code displayId}, or
-     * {@code UserHandle.USER_NULL} if the display doesn't exist in the mapping.
-     */
-    @GuardedBy("mLock")
-    private int getUserIdForDisplayLocked(int displayId) {
-        return mDisplayToProfileUserMapping.get(displayId, UserManagerHelper.USER_NULL);
-    }
-
     /**
      * Return a {@link TaskDisplayAreaWrapper} that can be used if a source display area is
      * not found. First check the default display for the user. If it is absent select
diff --git a/updatableServices/tests/Android.bp b/updatableServices/tests/Android.bp
index 266c2f2..f4ee8e2 100644
--- a/updatableServices/tests/Android.bp
+++ b/updatableServices/tests/Android.bp
@@ -24,9 +24,9 @@ android_test {
 
     libs: [
         "android.car",
-        "android.car.builtin",
-        "android.test.runner",
-        "android.test.base",
+        "android.car.builtin.stubs.module_lib",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
         "android.hardware.automotive.vehicle-V2.0-java",
     ],
 
diff --git a/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java b/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java
index 6076bed..a9a0291 100644
--- a/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java
+++ b/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java
@@ -220,6 +220,24 @@ public final class CarServiceHelperServiceUpdatableImplTest
                 .isEqualTo(108);
     }
 
+    @Test
+    public void testAssignUserToExtraDisplay() throws Exception {
+        int userId = 42;
+        int displayId = 37;
+        mCarServiceHelperInterface.assignUserToExtraDisplay(userId, displayId);
+
+        verify(mCarServiceHelperInterface).assignUserToExtraDisplay(userId, displayId);
+    }
+
+    @Test
+    public void testUnassignUserToExtraDisplay() throws Exception {
+        int userId = 42;
+        int displayId = 37;
+        mCarServiceHelperInterface.unassignUserFromExtraDisplay(userId, displayId);
+
+        verify(mCarServiceHelperInterface).unassignUserFromExtraDisplay(userId, displayId);
+    }
+
     private void mockICarBinder() {
         when(ICar.Stub.asInterface(mIBinder)).thenReturn(mICarBinder);
     }
diff --git a/updatableServices/tests/src/com/android/internal/car/updatable/OverlayDisplayMonitorTest.java b/updatableServices/tests/src/com/android/internal/car/updatable/ExtraDisplayMonitorTest.java
similarity index 53%
rename from updatableServices/tests/src/com/android/internal/car/updatable/OverlayDisplayMonitorTest.java
rename to updatableServices/tests/src/com/android/internal/car/updatable/ExtraDisplayMonitorTest.java
index 409c83b..4e3eff0 100644
--- a/updatableServices/tests/src/com/android/internal/car/updatable/OverlayDisplayMonitorTest.java
+++ b/updatableServices/tests/src/com/android/internal/car/updatable/ExtraDisplayMonitorTest.java
@@ -40,8 +40,8 @@ import org.mockito.Captor;
 import org.mockito.Mock;
 
 @RunWith(AndroidJUnit4.class)
-public class OverlayDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
-    private OverlayDisplayMonitor mOverlayDisplayMonitor;
+public class ExtraDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
+    private ExtraDisplayMonitor mExtraDisplayMonitor;
 
     @Mock
     private DisplayManager mDisplayManager;
@@ -51,24 +51,46 @@ public class OverlayDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
     private Display mTestDisplay;
     private final int mTestDisplayId = 1234;
     private final int mTestUserId = 999;
+    private final int mAnotherUserId = 998;
     @Captor
     private ArgumentCaptor<DisplayListener> mDisplayListenerCaptor;
 
     @Before
     public void setUp() {
-        mOverlayDisplayMonitor = new OverlayDisplayMonitor(
+        mExtraDisplayMonitor = new ExtraDisplayMonitor(
                 mDisplayManager, /* handler= */ null, mHelper);
         doNothing().when(mDisplayManager).registerDisplayListener(
                 mDisplayListenerCaptor.capture(), any());
         when(mDisplayManager.getDisplay(mTestDisplayId)).thenReturn(mTestDisplay);
 
-        mOverlayDisplayMonitor.init();
-        mOverlayDisplayMonitor.handleCurrentUserSwitching(999);
+        mExtraDisplayMonitor.init();
+        mExtraDisplayMonitor.handleCurrentUserSwitching(mTestUserId);
     }
 
     @Test
-    public void assignsOverlayDisplayToDriver() {
-        when(mHelper.isOverlayDisplay(mTestDisplayId)).thenReturn(true);
+    public void onDisplayAdded_nonOverlayDisplay_doesNotAssignNonOverlayDisplayToDriver() {
+        when(mHelper.isPublicOverlayDisplay(mTestDisplayId)).thenReturn(false);
+
+        mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
+
+        verify(mHelper, never()).assignUserToExtraDisplay(mTestUserId, mTestDisplayId);
+    }
+
+    @Test
+    public void onDisplayRemoved_nonOverlayDisplay_doesNotUnassignsNonOverlayDisplayFromDriver() {
+        when(mHelper.isPublicOverlayDisplay(mTestDisplayId)).thenReturn(false);
+        when(mHelper.assignUserToExtraDisplay(mTestUserId, mTestDisplayId)).thenReturn(true);
+
+        mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
+        mDisplayListenerCaptor.getValue().onDisplayRemoved(mTestDisplayId);
+
+        verify(mHelper, never()).unassignUserFromExtraDisplay(mTestUserId, mTestDisplayId);
+    }
+
+    @Test
+    public void onDisplayAdded_virtualDisplay_assignsVirtualDisplayToDriver() {
+        when(mHelper.isPublicVirtualDisplay(mTestDisplayId)).thenReturn(true);
+        when(mHelper.getOwnerUserIdForDisplay(mTestDisplayId)).thenReturn(mTestUserId);
 
         mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
 
@@ -76,8 +98,8 @@ public class OverlayDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void doesNotAssignNonOverlayDisplayToDriver() {
-        when(mHelper.isOverlayDisplay(mTestDisplayId)).thenReturn(false);
+    public void onDisplayAdded_nonVirtualDisplay_doesNotAssignNonVirtualDisplayToDriver() {
+        when(mHelper.isPublicVirtualDisplay(mTestDisplayId)).thenReturn(false);
 
         mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
 
@@ -85,8 +107,9 @@ public class OverlayDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void unassignsOverlayDisplayFromDriver() {
-        when(mHelper.isOverlayDisplay(mTestDisplayId)).thenReturn(true);
+    public void onDisplayRemoved_virtualDisplay_unassignsVirtualDisplayFromDriver() {
+        when(mHelper.isPublicVirtualDisplay(mTestDisplayId)).thenReturn(true);
+        when(mHelper.getOwnerUserIdForDisplay(mTestDisplayId)).thenReturn(mTestUserId);
         when(mHelper.assignUserToExtraDisplay(mTestUserId, mTestDisplayId)).thenReturn(true);
 
         mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
@@ -96,8 +119,9 @@ public class OverlayDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void doesNotUnassignsNonOverlayDisplayFromDriver() {
-        when(mHelper.isOverlayDisplay(mTestDisplayId)).thenReturn(false);
+    public void onDisplayRemoved_nonVirtualDisplay_doesNotUnassignsNonVirtualDisplayFromDriver() {
+        when(mHelper.isPublicVirtualDisplay(mTestDisplayId)).thenReturn(false);
+        when(mHelper.getOwnerUserIdForDisplay(mTestDisplayId)).thenReturn(mTestUserId);
         when(mHelper.assignUserToExtraDisplay(mTestUserId, mTestDisplayId)).thenReturn(true);
 
         mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
@@ -105,4 +129,15 @@ public class OverlayDisplayMonitorTest extends AbstractExtendedMockitoTestCase {
 
         verify(mHelper, never()).unassignUserFromExtraDisplay(mTestUserId, mTestDisplayId);
     }
+
+    @Test
+    public void onDisplayAdded_virtualDisplayOfAnotherUser_doesNotAssignVirtualDisplayToDriver() {
+        when(mHelper.isPublicVirtualDisplay(mTestDisplayId)).thenReturn(true);
+        when(mHelper.getOwnerUserIdForDisplay(mTestDisplayId)).thenReturn(mAnotherUserId);
+        when(mHelper.assignUserToExtraDisplay(mTestUserId, mTestDisplayId)).thenReturn(true);
+
+        mDisplayListenerCaptor.getValue().onDisplayAdded(mTestDisplayId);
+
+        verify(mHelper, never()).assignUserToExtraDisplay(mTestUserId, mTestDisplayId);
+    }
 }
diff --git a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
index d034284..8e23532 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableTest.java
@@ -40,6 +40,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSess
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
@@ -56,6 +57,7 @@ import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.ApplicationInfoFlags;
 import android.content.pm.PackageManager.NameNotFoundException;
 import android.content.pm.PackageManager.PackageInfoFlags;
+import android.content.res.CompatScaleWrapper;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.Looper;
@@ -66,6 +68,7 @@ import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.provider.Settings;
 import android.util.Pair;
 
+import androidx.annotation.NonNull;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import org.junit.After;
@@ -81,6 +84,7 @@ import org.xmlpull.v1.XmlPullParserException;
 import java.io.ByteArrayInputStream;
 import java.io.IOException;
 import java.io.InputStream;
+import java.util.ArrayList;
 import java.util.Collections;
 
 @RequiresFlagsEnabled(FLAG_DISPLAY_COMPATIBILITY)
@@ -106,6 +110,8 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
     @Mock
     private ApplicationInfo mApplicationInfo;
     @Mock
+    private ApplicationInfo mApplicationInfo2;
+    @Mock
     private CarDisplayCompatScaleProviderInterface mInterface;
     @Mock
     private ContentResolver mContentResolver;
@@ -132,7 +138,14 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         try (InputStream in = new ByteArrayInputStream(emptyConfig.getBytes());) {
             mConfig.populate(in);
         }
-        mImpl = new CarDisplayCompatScaleProviderUpdatableImpl(mContext, mInterface, mConfig);
+
+        mImpl = new CarDisplayCompatScaleProviderUpdatableImpl(mContext, mInterface, mConfig) {
+            @NonNull
+            @Override
+            InputStream openReadConfigFile() {
+                return new ByteArrayInputStream(emptyConfig.getBytes());
+            }
+        };
     }
 
     @After
@@ -305,10 +318,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -333,10 +342,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -353,7 +358,8 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         mConfig.setScaleFactor(key, 0.5f);
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
-        assertThat(mImpl.getCompatScale("package2", CURRENT_USER)).isNull();
+        assertThat(mImpl.getCompatScale("package2", CURRENT_USER).getDensityScaleFactor())
+                .isEqualTo(DEFAULT_SCALE);
     }
 
     @Test
@@ -361,10 +367,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -382,7 +384,8 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
 
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
-        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER)).isNull();
+        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER).getDensityScaleFactor())
+                .isEqualTo(DEFAULT_SCALE);
     }
 
     @Test
@@ -390,10 +393,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -420,8 +419,10 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
 
         assertThat(mImpl.getCompatScale("package1", CURRENT_USER).getDensityScaleFactor())
                 .isEqualTo(0.5f);
-        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER)).isNull();
-        assertThat(mImpl.getCompatScale("package2", CURRENT_USER)).isNull();
+        assertThat(mImpl.getCompatScale("package1", ANOTHER_USER).getDensityScaleFactor())
+                .isEqualTo(DEFAULT_SCALE);
+        assertThat(mImpl.getCompatScale("package2", CURRENT_USER).getDensityScaleFactor())
+                .isEqualTo(DEFAULT_SCALE);
     }
 
     @Test
@@ -430,10 +431,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -460,10 +457,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -491,10 +484,6 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         ActivityInfo[] activities = new ActivityInfo[1];
         activities[0] = new ActivityInfo();
         mPackageInfo.activities = activities;
-        FeatureInfo[] features = new FeatureInfo[1];
-        features[0] = new FeatureInfo();
-        features[0].name = FEATURE_CAR_DISPLAY_COMPATIBILITY;
-        mPackageInfo.reqFeatures = features;
         when(mInterface.getPackageInfoAsUser(eq("package1"), any(PackageInfoFlags.class),
                 any(int.class))).thenReturn(mPackageInfo);
         when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq("package1")))
@@ -557,7 +546,9 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
     public void packageOptOut_withoutScaling() {
         assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isFalse();
         CarDisplayCompatConfig.Key key =
-                new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, "package1", CURRENT_USER);
+                new CarDisplayCompatConfig.Key(DEFAULT_DISPLAY, "package1",
+                        UserHandle.ALL.getIdentifier());
+
         assertThat(mConfig.getScaleFactor(key, NO_SCALE)).isEqualTo(OPT_OUT);
     }
 
@@ -647,4 +638,127 @@ public class CarDisplayCompatScaleProviderUpdatableTest {
         mImpl.mPackageChangeReceiver.onReceive(mContext, i);
         assertThat(mImpl.requiresDisplayCompat("package1", CURRENT_USER)).isFalse();
     }
+
+    @Test
+    public void configWithDisplayValue_getCompatScaleReturnsDisplayDefault_optInPkg()
+            throws NameNotFoundException {
+        String pkg1Name = "package1";
+        mApplicationInfo.packageName = pkg1Name;
+        ActivityInfo[] activities = new ActivityInfo[1];
+        activities[0] = new ActivityInfo();
+        mPackageInfo.activities = activities;
+        when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq(pkg1Name)))
+                .thenReturn(SIGNATURE_NO_MATCH);
+        when(mPackageManager.getApplicationInfoAsUser(eq(pkg1Name),
+                any(ApplicationInfoFlags.class), any(UserHandle.class)))
+                .thenReturn(mApplicationInfo);
+        when(mApplicationInfo.isPrivilegedApp()).thenReturn(false);
+        when(mInterface.getPackageInfoAsUser(eq(pkg1Name), any(PackageInfoFlags.class),
+                any(int.class))).thenReturn(mPackageInfo);
+        ArrayList<ApplicationInfo> installedApplications = new ArrayList<>();
+        installedApplications.add(mApplicationInfo);
+        when(mInterface.getInstalledApplicationsAsUser(any(ApplicationInfoFlags.class), anyInt()))
+                .thenReturn(installedApplications);
+
+        mImpl = new CarDisplayCompatScaleProviderUpdatableImpl(mContext, mInterface, mConfig) {
+            @NonNull
+            @Override
+            InputStream openReadConfigFile() {
+                String configWithDisplayValue = "<config><scale display=\"0\">0.7</scale></config>";
+                return new ByteArrayInputStream(configWithDisplayValue.getBytes());
+            }
+        };
+        CompatScaleWrapper result = mImpl.getCompatScale(pkg1Name, CURRENT_USER);
+
+        assertThat(result.getDensityScaleFactor()).isEqualTo(0.7f);
+    }
+
+    @Test
+    public void configWithDisplayValue_getCompatScaleDoesNotReturnsDisplayDefault_systemPkg()
+            throws NameNotFoundException {
+        String pkg1Name = "package1";
+        mApplicationInfo.packageName = pkg1Name;
+        ActivityInfo[] activities = new ActivityInfo[1];
+        activities[0] = new ActivityInfo();
+        when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq(pkg1Name)))
+                .thenReturn(SIGNATURE_NO_MATCH);
+        when(mPackageManager.getApplicationInfoAsUser(eq(pkg1Name),
+                any(ApplicationInfoFlags.class), any(UserHandle.class)))
+                .thenReturn(mApplicationInfo);
+        when(mApplicationInfo.isPrivilegedApp()).thenReturn(true);
+        when(mInterface.getPackageInfoAsUser(eq(pkg1Name), any(PackageInfoFlags.class),
+                any(int.class))).thenReturn(mPackageInfo);
+        ArrayList<ApplicationInfo> installedApplications = new ArrayList<>();
+        installedApplications.add(mApplicationInfo);
+        when(mInterface.getInstalledApplicationsAsUser(any(ApplicationInfoFlags.class), anyInt()))
+                .thenReturn(installedApplications);
+
+        mImpl = new CarDisplayCompatScaleProviderUpdatableImpl(mContext, mInterface, mConfig) {
+            @NonNull
+            @Override
+            InputStream openReadConfigFile() {
+                String configWithDisplayValue = "<config><scale display=\"0\">0.7</scale></config>";
+                return new ByteArrayInputStream(configWithDisplayValue.getBytes());
+            }
+        };
+        CompatScaleWrapper result = mImpl.getCompatScale(pkg1Name, CURRENT_USER);
+
+        assertThat(result.getDensityScaleFactor()).isEqualTo(DEFAULT_SCALE);
+    }
+
+    @Test
+    public void configWithDisplayUserPackageValue_getCompatScaleReturnsValueInFile_optInPkg()
+            throws NameNotFoundException {
+        String pkg1Name = "package1";
+        String pkg2Name = "package2";
+        float pkg1ScaleInFile = 0.5f;
+        float displayDefaultScaleInFile = 0.7f;
+        mApplicationInfo.packageName = pkg1Name;
+        mApplicationInfo2.packageName = pkg2Name;
+        ActivityInfo[] activities = new ActivityInfo[1];
+        activities[0] = new ActivityInfo();
+        mPackageInfo.activities = activities;
+        when(mInterface.getPackageInfoAsUser(eq(pkg1Name), any(PackageInfoFlags.class),
+                any(int.class))).thenReturn(mPackageInfo);
+        when(mInterface.getPackageInfoAsUser(eq(pkg2Name), any(PackageInfoFlags.class),
+                any(int.class))).thenReturn(mPackageInfo);
+        when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq(pkg1Name)))
+                .thenReturn(SIGNATURE_NO_MATCH);
+        when(mPackageManager.checkSignatures(eq(PLATFORM_PACKAGE_NAME), eq(pkg2Name)))
+                .thenReturn(SIGNATURE_NO_MATCH);
+        when(mPackageManager.getApplicationInfoAsUser(eq(pkg1Name),
+                any(ApplicationInfoFlags.class), any(UserHandle.class)))
+                .thenReturn(mApplicationInfo);
+        when(mPackageManager.getApplicationInfoAsUser(eq(pkg2Name),
+                any(ApplicationInfoFlags.class), any(UserHandle.class)))
+                .thenReturn(mApplicationInfo2);
+        when(mApplicationInfo.isPrivilegedApp()).thenReturn(false);
+        when(mApplicationInfo2.isPrivilegedApp()).thenReturn(false);
+        ArrayList<ApplicationInfo> installedApplications = new ArrayList<>();
+        installedApplications.add(mApplicationInfo);
+        installedApplications.add(mApplicationInfo2);
+        when(mInterface.getInstalledApplicationsAsUser(any(ApplicationInfoFlags.class), anyInt()))
+                .thenReturn(installedApplications);
+
+        mImpl = new CarDisplayCompatScaleProviderUpdatableImpl(mContext, mInterface, mConfig) {
+            @NonNull
+            @Override
+            InputStream openReadConfigFile() {
+                String configWithDisplayValue =
+                        "<config>"
+                                + "<scale display=\"0\" userId=\"" + CURRENT_USER
+                                + "\" packageName=\"" + pkg1Name + "\">" + pkg1ScaleInFile
+                                + "</scale>"
+                                + "<scale display=\"0\">" + displayDefaultScaleInFile + "</scale>"
+                                + "</config>";
+                return new ByteArrayInputStream(configWithDisplayValue.getBytes());
+            }
+        };
+        CompatScaleWrapper resultPkg1 = mImpl.getCompatScale(pkg1Name, CURRENT_USER);
+        CompatScaleWrapper resultPkg2 = mImpl.getCompatScale(pkg2Name, CURRENT_USER);
+
+        assertThat(resultPkg1.getDensityScaleFactor()).isEqualTo(pkg1ScaleInFile);
+        assertThat(resultPkg2.getDensityScaleFactor()).isEqualTo(displayDefaultScaleInFile);
+    }
+
 }
diff --git a/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
index 38418a5..2bed9dd 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
@@ -88,6 +88,7 @@ public class CarLaunchParamsModifierUpdatableTest {
     private static final int PASSENGER_DISPLAY_ID_11 = 11;
     private static final int RANDOM_DISPLAY_ID_99 = 99;
     private static final int VIRTUAL_DISPLAY_ID_2 = 2;
+    private static final int OVERLAY_DISPLAY_ID_3 = 3;
     private static final int FEATURE_MAP_ID = 1111;
 
     private MockitoSession mMockingSession;
@@ -120,6 +121,8 @@ public class CarLaunchParamsModifierUpdatableTest {
     private InputManagerService mInputManagerService;
     @Mock
     private UserManagerInternal mUserManagerInternal;
+    @Mock
+    private AppCompatConfiguration mAppCompatConfiguration;
 
     @Mock
     private Display mDisplay0ForDriver;
@@ -136,6 +139,13 @@ public class CarLaunchParamsModifierUpdatableTest {
     @Mock
     private Display mDisplay2Virtual;
     private TaskDisplayArea mDisplayArea2Virtual;
+    @Mock
+    private Display mDisplay3Overlay;
+    private TaskDisplayArea mDisplayArea3Overlay;
+    @Mock
+    private Display mDisplay99Random;
+    private TaskDisplayArea mDisplayArea99Random;
+
     private TaskDisplayArea mMapTaskDisplayArea;
 
     // All mocks from here before CarLaunchParamsModifier are arguments for
@@ -213,7 +223,8 @@ public class CarLaunchParamsModifierUpdatableTest {
                 mContext, mInputManagerService, /* showBootMsgs= */ false, /* policy= */ null,
                 mActivityTaskManagerService,
                 /* displayWindowSettingsProvider= */ null, () -> new SurfaceControl.Transaction(),
-                /* surfaceControlFactory= */ null);
+                /* surfaceControlFactory= */ null,
+                /* appCompatConfiguration= */ mAppCompatConfiguration);
         mActivityTaskManagerService.mWindowManager = mWindowManagerService;
         mRootWindowContainer.mWindowManager = mWindowManagerService;
 
@@ -240,6 +251,10 @@ public class CarLaunchParamsModifierUpdatableTest {
                 FLAG_TRUSTED | FLAG_PRIVATE, /* type= */ 0);
         mDisplayArea2Virtual = mockDisplay(mDisplay2Virtual, VIRTUAL_DISPLAY_ID_2,
                 FLAG_PRIVATE, /* type= */ 0);
+        mDisplayArea3Overlay = mockDisplay(mDisplay3Overlay, OVERLAY_DISPLAY_ID_3,
+                FLAG_TRUSTED, /* type= */ Display.TYPE_OVERLAY);
+        mDisplayArea99Random = mockDisplay(mDisplay99Random, RANDOM_DISPLAY_ID_99,
+                FLAG_TRUSTED, /* type= */ 0);
 
         mModifier = new CarLaunchParamsModifier(mContext);
         mBuiltin = mModifier.getBuiltinInterface();
@@ -787,6 +802,64 @@ public class CarLaunchParamsModifierUpdatableTest {
         assertDisplayIsAssigned(visibleUserId, mDisplayArea11ForPassenger);
     }
 
+    @Test
+    public void testCallerDisplayButNoDisplayIsAssigned() {
+        mUpdatable.setPassengerDisplays(
+                new int[]{PASSENGER_DISPLAY_ID_10, OVERLAY_DISPLAY_ID_3});
+        final int visibleUserId = 100;
+        when(mUserManagerInternal.getUserAssignedToDisplay(OVERLAY_DISPLAY_ID_3))
+                .thenReturn(visibleUserId);
+        when(mActivityOptions.getCallerDisplayId()).thenReturn(OVERLAY_DISPLAY_ID_3);
+
+        // CarLaunchParamsModifier admires the callerDisplayId, not assigning a display.
+        assertNoDisplayIsAssigned(visibleUserId);
+    }
+
+    @Test
+    public void testVisibleUserUsesMainDisplayAsFallback_whenCallerDisplayIsRandomDisplay() {
+        mUpdatable.setPassengerDisplays(
+                new int[]{PASSENGER_DISPLAY_ID_10, PASSENGER_DISPLAY_ID_11});
+        final int visibleUserId = 100;
+        when(mUserManagerInternal.getUserAssignedToDisplay(PASSENGER_DISPLAY_ID_11))
+                .thenReturn(visibleUserId);
+        when(mUserManagerInternal.getMainDisplayAssignedToUser(visibleUserId))
+                .thenReturn(PASSENGER_DISPLAY_ID_11);
+        // Try to start Activity on display that is not assigned to the user.
+        when(mActivityOptions.getCallerDisplayId()).thenReturn(RANDOM_DISPLAY_ID_99);
+
+        // For the visible user, fallbacks to the main display.
+        assertDisplayIsAssigned(visibleUserId, mDisplayArea11ForPassenger);
+    }
+
+    @Test
+    public void testDisplayFromSourceButNoDisplayIsAssigned() {
+        mUpdatable.setPassengerDisplays(
+                new int[]{PASSENGER_DISPLAY_ID_10, OVERLAY_DISPLAY_ID_3});
+        final int visibleUserId = 100;
+        when(mUserManagerInternal.getUserAssignedToDisplay(OVERLAY_DISPLAY_ID_3))
+                .thenReturn(visibleUserId);
+        when(mActivityRecordSource.getDisplayArea()).thenReturn(mDisplayArea3Overlay);
+
+        // CarLaunchParamsModifier admires the display area from source, not assigning a display.
+        assertNoDisplayIsAssigned(visibleUserId);
+    }
+
+    @Test
+    public void testVisibleUserUsesMainDisplayAsFallback_whenDisplayFromSourceIsRandomDisplay() {
+        mUpdatable.setPassengerDisplays(
+                new int[]{PASSENGER_DISPLAY_ID_10, PASSENGER_DISPLAY_ID_11});
+        final int visibleUserId = 100;
+        when(mUserManagerInternal.getUserAssignedToDisplay(PASSENGER_DISPLAY_ID_11))
+                .thenReturn(visibleUserId);
+        when(mUserManagerInternal.getMainDisplayAssignedToUser(visibleUserId))
+                .thenReturn(PASSENGER_DISPLAY_ID_11);
+        // Try to start Activity on display that is not assigned to the user.
+        when(mActivityRecordSource.getDisplayArea()).thenReturn(mDisplayArea99Random);
+
+        // For the visible user, fallbacks to the main display.
+        assertDisplayIsAssigned(visibleUserId, mDisplayArea11ForPassenger);
+    }
+
     private static ActivityStarter.Request fakeRequest() {
         ActivityStarter.Request request = new ActivityStarter.Request();
         request.realCallingPid = 1324;
```

