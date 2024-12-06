**build/make**
```
d3d00079d8: Version bump to AP3A.241105.007 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
c3c41f4a31: Version bump to AP3A.241105.006 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
f0601c094a: Move ap3a configuration to build/release. (Ian Kasprzak <iankaz@google.com>)
32a7ed5769: Version bump to AP3A.241105.004 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
bb03ce0557: Version bump to AP3A.241105.003 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
f8bbbe0cbd: Version bump to AP3A.241105.002.X1 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
390c65a255: Version bump to AP3A.241105.002 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
c12eed7b94: Version bump to AP3A.241105.001 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
b37813e557: Version bump to AP3A.241005.016 [core/build_id.mk] (Android Build Coastguard Worker <android-build-c...)
```

**build/release**
```
0d37102: AP3A: Set SPL to 2024-11-05 (Ankur Bakshi <ankurbakshi@google.com>)
2654c89: Update aconfig flags for ap3a and trunk_staging to (ab/AP3A.241105.008). (Bill Yi <byi@google.com>)
```

**cts**
```
389c25f21ed: Disable ASM_RESTRICTIONS flag (Hani Kazmi <hanikazmi@google.com>)
```

**device/google/gs-common**
```
d93d355: bootctrl: fixed OOB read in BootControl (bgkim <bgkim@google.com>)
```

**external/skia**
```
9adb3df618: Avoid potential overflow when allocating 3D mask from emboss filter (Nolan Scobie <nscobie@google.com>)
```

**frameworks/base**
```
5e4364e48b9b: Disable ASM_RESTRICTIONS flag (Hani Kazmi <hanikazmi@google.com>)
61dbf0458ca1: Allows an app to cancel a device state request they made at any point if... (Kenneth Ford <kennethford@google.com>)
f5f5eb6965b7: Don't send BOOT_COMPLETED to app in restricted backup mode (Amith Yamasani <yamasani@google.com>)
1f1204554833: Add notification for onInferenceServiceDisconnected (sandeepbandaru <sandeepbandaru@google.com>)
650f04532d84: Remove dumpmanager from KeyguardStatusView (Matt Pietal <mpietal@google.com>)
a39b9a800884: Fix regression in getting top running task to split with (Winson Chung <winsonc@google.com>)
7db0a1156449: Fix issue where highlight was drawing without bottom inset on one side o... (Winson Chung <winsonc@google.com>)
f94e099ed8d6: Add mechanism for a task to be hidden as a part of starting a drag (Winson Chung <winsonc@google.com>)
4a78cc849725: Fix issue with incorrect drag starter being used and handle removed task... (Winson Chung <winsonc@google.com>)
68eb5dc1200f: Restrict access to directories (Dipankar Bhardwaj <dipankarb@google.com>)
706714b827fb: Disallow device admin package and protected packages to be reinstalled a... (lpeter <lpeter@google.com>)
fc51b1be63dd: Set no data transfer on function switch timeout for accessory mode (Ashish Kumar Gupta <kumarashishg@google.com>)
bd19f063982c: Remove authenticator data if it was disabled. (Dmitry Dementyev <dementyev@google.com>)
```

**frameworks/native**
```
a69ae94ac6: Fix DisplayState sanitization. (Patrick Williams <pdwilliams@google.com>)
```

**frameworks/opt/telephony**
```
6169691f29: Revert "If the phone crash try to clean up the channel which was kept op... (Aman Gupta <amagup@google.com>)
5abd191dde: Revert "If the phone crash try to clean up the channel which was kept op... (Rambo Wang <rambowang@google.com>)
```

**hardware/google/graphics/common**
```
99e8608: libhwc2.1: display temperature in scene (Peter Lin <linpeter@google.com>)
4f2d23c: libhwc2.1: add monitor display thermal temperature (gilliu <gilliu@google.com>)
```

**hardware/google/graphics/gs101**
```
ccd4a23: libhwc2.1: apply the display temperatue to display scene (Peter Lin <linpeter@google.com>)
```

**manifest**
```
ba7d47699: Manifest for Android 15.0.0 Release 4 (The Android Open Source Project <initial-contrib...)
```

**packages/apps/Settings**
```
7c2681d92ad: Stops hiding a11y services with the same package+label as an activity. (Daniel Norman <danielnorman@google.com>)
dcf8f310eef: Only check INTERACT_ACROSS_USERS_FULL when user handle is not current (Chris Antol <cantol@google.com>)
b86100f3541: Checks cross user permission before handling intent (Fan Wu <cechkahn@google.com>)
8c8d3eac3bd: startActivityForResult with new Intent (Adam Bookatz <bookatz@google.com>)
```

**packages/modules/Bluetooth**
```
89d2b52bed: Interop fix to not read PPCP for devices that report incompatible values... (Omair Kamil <okamil@google.com>)
```

**packages/modules/Wifi**
```
e59d5991b9: Fix security isseu by change the field in WifiConfig (Nate Jiang <qiangjiang@google.com>)
```

**packages/providers/MediaProvider**
```
64b0bb2dc: Prevent apps from renaming files they don't own (Omar Eissa <oeissa@google.com>)
```

**system/core**
```
689516ac96: libsnapshot: Address GRF config when updating from Android S config (Akilesh Kailash <akailash@google.com>)
93096918b1: libsnapshot: Check if the vendor is updated from Android S for GRF (Akilesh Kailash <akailash@google.com>)
```

**build/make**
```diff
diff --git a/core/build_id.mk b/core/build_id.mk
index c68fc2387f..015f677cd5 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.
 
-BUILD_ID=AP3A.241005.015.A2
+BUILD_ID=AP3A.241105.007
diff --git a/target/product/generic_system.mk b/target/product/generic_system.mk
index 0a09eb11d4..b9a623dcd3 100644
--- a/target/product/generic_system.mk
+++ b/target/product/generic_system.mk
@@ -152,4 +152,5 @@ _my_paths := \
 $(call require-artifacts-in-path, $(_my_paths), $(_my_allowed_list))
 
 # Product config map to toggle between sources and prebuilts of required mainline modules
+PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard build/release/gms_mainline/required/release_config_map.textproto)
 PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/build/release/gms_mainline/required/release_config_map.textproto)
diff --git a/target/product/go_defaults.mk b/target/product/go_defaults.mk
index dd6a955ce7..6ee8fb415b 100644
--- a/target/product/go_defaults.mk
+++ b/target/product/go_defaults.mk
@@ -18,6 +18,7 @@
 $(call inherit-product, build/make/target/product/go_defaults_common.mk)
 
 # Product config map to toggle between sources and prebuilts of required mainline modules
+PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard build/release/gms_mainline_go/required/release_config_map.textproto)
 PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/build/release/gms_mainline_go/required/release_config_map.textproto)
 
 # TODO (b/342265627): Remove v/g/r once all the flags have been moved to v/g_s/b/r
```

**build/release**
```diff
diff --git a/aconfig/ap3a/android.hardware.devicestate.feature.flags/device_state_requester_cancel_state_flag_values.textproto b/aconfig/ap3a/android.hardware.devicestate.feature.flags/device_state_requester_cancel_state_flag_values.textproto
new file mode 100644
index 0000000..3e1e4a7
--- /dev/null
+++ b/aconfig/ap3a/android.hardware.devicestate.feature.flags/device_state_requester_cancel_state_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.hardware.devicestate.feature.flags"
+  name: "device_state_requester_cancel_state"
+  state: ENABLED
+  permission: READ_ONLY
+}
\ No newline at end of file
diff --git a/flag_values/ap3a/RELEASE_KERNEL_AKITA_DIR.textproto b/flag_values/ap3a/RELEASE_KERNEL_AKITA_DIR.textproto
index d6253e6..3da5f42 100644
--- a/flag_values/ap3a/RELEASE_KERNEL_AKITA_DIR.textproto
+++ b/flag_values/ap3a/RELEASE_KERNEL_AKITA_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_AKITA_DIR"
 value: {
-  string_value: "device/google/akita-kernels/5.15/24Q3-12065098"
+  string_value: "device/google/akita-kernels/5.15/24Q3-12357444"
 }
diff --git a/flag_values/ap3a/RELEASE_KERNEL_BLUEJAY_DIR.textproto b/flag_values/ap3a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
index 06f2752..df642b9 100644
--- a/flag_values/ap3a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
+++ b/flag_values/ap3a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_BLUEJAY_DIR"
 value: {
-  string_value: "device/google/bluejay-kernels/5.10/24Q3-12115410"
+  string_value: "device/google/bluejay-kernels/5.10/24Q3-12357445"
 }
diff --git a/flag_values/ap3a/RELEASE_KERNEL_HUSKY_DIR.textproto b/flag_values/ap3a/RELEASE_KERNEL_HUSKY_DIR.textproto
index 03b8e2f..f4de003 100644
--- a/flag_values/ap3a/RELEASE_KERNEL_HUSKY_DIR.textproto
+++ b/flag_values/ap3a/RELEASE_KERNEL_HUSKY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_HUSKY_DIR"
 value: {
-  string_value: "device/google/shusky-kernels/5.15/24Q3-12065098"
+  string_value: "device/google/shusky-kernels/5.15/24Q3-12357444"
 }
diff --git a/flag_values/ap3a/RELEASE_KERNEL_ORIOLE_DIR.textproto b/flag_values/ap3a/RELEASE_KERNEL_ORIOLE_DIR.textproto
index 5b1cfb4..0ce36ae 100644
--- a/flag_values/ap3a/RELEASE_KERNEL_ORIOLE_DIR.textproto
+++ b/flag_values/ap3a/RELEASE_KERNEL_ORIOLE_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_ORIOLE_DIR"
 value: {
-  string_value: "device/google/raviole-kernels/5.10/24Q3-12115410"
+  string_value: "device/google/raviole-kernels/5.10/24Q3-12357445"
 }
diff --git a/flag_values/ap3a/RELEASE_KERNEL_RAVEN_DIR.textproto b/flag_values/ap3a/RELEASE_KERNEL_RAVEN_DIR.textproto
index bb9b33b..11bab4d 100644
--- a/flag_values/ap3a/RELEASE_KERNEL_RAVEN_DIR.textproto
+++ b/flag_values/ap3a/RELEASE_KERNEL_RAVEN_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_RAVEN_DIR"
 value: {
-  string_value: "device/google/raviole-kernels/5.10/24Q3-12115410"
+  string_value: "device/google/raviole-kernels/5.10/24Q3-12357445"
 }
diff --git a/flag_values/ap3a/RELEASE_KERNEL_SHIBA_DIR.textproto b/flag_values/ap3a/RELEASE_KERNEL_SHIBA_DIR.textproto
index edac628..add95e7 100644
--- a/flag_values/ap3a/RELEASE_KERNEL_SHIBA_DIR.textproto
+++ b/flag_values/ap3a/RELEASE_KERNEL_SHIBA_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_SHIBA_DIR"
 value: {
-  string_value: "device/google/shusky-kernels/5.15/24Q3-12065098"
+  string_value: "device/google/shusky-kernels/5.15/24Q3-12357444"
 }
diff --git a/flag_values/ap3a/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/ap3a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index f27e557..ce29523 100644
--- a/flag_values/ap3a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/ap3a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
-  string_value: "2024-10-05"
+  string_value: "2024-11-05"
 }
```

**cts**
```diff
diff --git a/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelEmbeddingTest.java b/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelEmbeddingTest.java
index 85d1cbaccdb..378a78728e0 100644
--- a/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelEmbeddingTest.java
+++ b/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelEmbeddingTest.java
@@ -23,8 +23,10 @@ import android.content.ComponentName;
 import androidx.test.filters.FlakyTest;
 
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Test;
 
+@Ignore
 public class ActivitySecurityModelEmbeddingTest extends BackgroundActivityTestBase {
 
     @Override
diff --git a/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelTest.java b/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelTest.java
index 9593dadd5a6..f181d7db923 100644
--- a/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelTest.java
+++ b/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/ActivitySecurityModelTest.java
@@ -24,9 +24,11 @@ import android.platform.test.flag.junit.CheckFlagsRule;
 import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.security.Flags;
 
+import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
 
+@Ignore
 public class ActivitySecurityModelTest extends BackgroundActivityTestBase {
     @Rule
     public final CheckFlagsRule mCheckFlagsRule =
diff --git a/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/BackgroundActivityLaunchTest.java b/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/BackgroundActivityLaunchTest.java
index 42a9237bd6a..c71955b6e70 100644
--- a/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/BackgroundActivityLaunchTest.java
+++ b/tests/framework/base/windowmanager/backgroundactivity/src/android/server/wm/BackgroundActivityLaunchTest.java
@@ -194,6 +194,7 @@ public class BackgroundActivityLaunchTest extends BackgroundActivityTestBase {
     }
 
     @Test
+    @Ignore
     public void testBackgroundActivity_withinASMGracePeriod_isBlocked() throws Exception {
         assumeSdkNewerThanUpsideDownCake();
         // Start AppA foreground activity
@@ -207,6 +208,7 @@ public class BackgroundActivityLaunchTest extends BackgroundActivityTestBase {
 
     @Test
     @FlakyTest(bugId = 297339382)
+    @Ignore
     public void testBackgroundActivity_withinBalAfterAsmGracePeriod_isBlocked()
             throws Exception {
         assumeSdkNewerThanUpsideDownCake();
@@ -231,6 +233,7 @@ public class BackgroundActivityLaunchTest extends BackgroundActivityTestBase {
     }
 
     @Test
+    @Ignore
     public void testBackgroundActivityBlockedWhenForegroundActivityNotTop() throws Exception {
         assumeSdkNewerThanUpsideDownCake();
 
@@ -316,6 +319,7 @@ public class BackgroundActivityLaunchTest extends BackgroundActivityTestBase {
     }
 
     @Test
+    @Ignore
     public void testActivityBlockedFromBgActivityInFgTask() {
         assumeSdkNewerThanUpsideDownCake();
         // Launch Activity A, B in the same task with different processes.
```

**device/google/gs-common**
```diff
diff --git a/bootctrl/aidl/BootControl.cpp b/bootctrl/aidl/BootControl.cpp
index e771845..d894f8b 100644
--- a/bootctrl/aidl/BootControl.cpp
+++ b/bootctrl/aidl/BootControl.cpp
@@ -384,7 +384,7 @@ ScopedAStatus BootControl::isSlotMarkedSuccessful(int32_t in_slot, bool* _aidl_r
         *_aidl_return = true;
         return ScopedAStatus::ok();
     }
-    if (in_slot >= slots)
+    if (in_slot < 0 || in_slot >= slots)
         return ScopedAStatus::fromServiceSpecificErrorWithMessage(
                 INVALID_SLOT, (std::string("Invalid slot ") + std::to_string(in_slot)).c_str());
 
```

**external/skia**
```diff
diff --git a/src/effects/SkEmbossMaskFilter.cpp b/src/effects/SkEmbossMaskFilter.cpp
index 3d431f812e..c8f0c536b3 100644
--- a/src/effects/SkEmbossMaskFilter.cpp
+++ b/src/effects/SkEmbossMaskFilter.cpp
@@ -99,11 +99,13 @@ bool SkEmbossMaskFilter::filterMask(SkMaskBuilder* dst, const SkMask& src,
 
     {
         uint8_t* alphaPlane = dst->image();
-        size_t   planeSize = dst->computeImageSize();
-        if (0 == planeSize) {
-            return false;   // too big to allocate, abort
+        size_t totalSize = dst->computeTotalImageSize();
+        if (totalSize == 0) {
+            return false;  // too big to allocate, abort
         }
-        dst->image() = SkMaskBuilder::AllocImage(planeSize * 3);
+        size_t planeSize = dst->computeImageSize();
+        SkASSERT(planeSize != 0);  // if totalSize didn't overflow, this can't either
+        dst->image() = SkMaskBuilder::AllocImage(totalSize);
         memcpy(dst->image(), alphaPlane, planeSize);
         SkMaskBuilder::FreeImage(alphaPlane);
     }
```

**frameworks/base**
```diff
diff --git a/core/java/android/content/ClipDescription.java b/core/java/android/content/ClipDescription.java
index 5953890ad85f..93724bb4949d 100644
--- a/core/java/android/content/ClipDescription.java
+++ b/core/java/android/content/ClipDescription.java
@@ -135,6 +135,14 @@ public class ClipDescription implements Parcelable {
     public static final String EXTRA_LOGGING_INSTANCE_ID =
             "android.intent.extra.LOGGING_INSTANCE_ID";
 
+    /**
+     * The id of the task containing the window that initiated the drag that should be hidden.
+     * Only provided to internal drag handlers as a part of the DRAG_START event.
+     * @hide
+     */
+    public static final String EXTRA_HIDE_DRAG_SOURCE_TASK_ID =
+            "android.intent.extra.HIDE_DRAG_SOURCE_TASK_ID";
+
     /**
      * Indicates that a ClipData contains potentially sensitive information, such as a
      * password or credit card number.
diff --git a/core/java/android/hardware/devicestate/feature/flags.aconfig b/core/java/android/hardware/devicestate/feature/flags.aconfig
index 12d3f94ec982..7ffd26cd94f9 100644
--- a/core/java/android/hardware/devicestate/feature/flags.aconfig
+++ b/core/java/android/hardware/devicestate/feature/flags.aconfig
@@ -8,4 +8,16 @@ flag {
     description: "Updated DeviceState hasProperty API"
     bug: "293636629"
     is_fixed_read_only: true
-}
\ No newline at end of file
+}
+
+flag {
+    name: "device_state_requester_cancel_state"
+    is_exported: true
+    namespace: "windowing_sdk"
+    description: "Removes foreground requirement if process attempting to cancel a state request is the requester"
+    bug: "354772125"
+    is_fixed_read_only: true
+    metadata {
+      purpose: PURPOSE_BUGFIX
+    }
+}
diff --git a/core/java/android/view/View.java b/core/java/android/view/View.java
index 9bc15112debc..2ae5a442355c 100644
--- a/core/java/android/view/View.java
+++ b/core/java/android/view/View.java
@@ -5511,6 +5511,14 @@ public class View implements Drawable.Callback, KeyEvent.Callback,
     @FlaggedApi(FLAG_DELEGATE_UNHANDLED_DRAGS)
     public static final int DRAG_FLAG_START_INTENT_SENDER_ON_UNHANDLED_DRAG = 1 << 13;
 
+    /**
+     * Flag indicating that this drag will result in the caller activity's task to be hidden for the
+     * duration of the drag, this means that the source activity will not receive drag events for
+     * the current drag gesture. Only the current voice interaction service may use this flag.
+     * @hide
+     */
+    public static final int DRAG_FLAG_HIDE_CALLING_TASK_ON_DRAG_START = 1 << 14;
+
     /**
      * Vertical scroll factor cached by {@link #getVerticalScrollFactor}.
      */
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/ShellTaskOrganizer.java b/libs/WindowManager/Shell/src/com/android/wm/shell/ShellTaskOrganizer.java
index 3ded7d246499..863186551f69 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/ShellTaskOrganizer.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/ShellTaskOrganizer.java
@@ -123,6 +123,15 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
         default void dump(@NonNull PrintWriter pw, String prefix) {};
     }
 
+    /**
+     * Limited scope callback to notify when a task is removed from the system.  This signal is
+     * not synchronized with anything (or any transition), and should not be used in cases where
+     * that is necessary.
+     */
+    public interface TaskVanishedListener {
+        default void onTaskVanished(RunningTaskInfo taskInfo) {}
+    }
+
     /**
      * Callbacks for events on a task with a locus id.
      */
@@ -167,6 +176,9 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
 
     private final ArraySet<FocusListener> mFocusListeners = new ArraySet<>();
 
+    // Listeners that should be notified when a task is removed
+    private final ArraySet<TaskVanishedListener> mTaskVanishedListeners = new ArraySet<>();
+
     private final Object mLock = new Object();
     private StartingWindowController mStartingWindow;
 
@@ -409,7 +421,7 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
     }
 
     /**
-     * Removes listener.
+     * Removes a locus id listener.
      */
     public void removeLocusIdListener(LocusIdListener listener) {
         synchronized (mLock) {
@@ -430,7 +442,7 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
     }
 
     /**
-     * Removes listener.
+     * Removes a focus listener.
      */
     public void removeFocusListener(FocusListener listener) {
         synchronized (mLock) {
@@ -438,6 +450,24 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
         }
     }
 
+    /**
+     * Adds a listener to be notified when a task vanishes.
+     */
+    public void addTaskVanishedListener(TaskVanishedListener listener) {
+        synchronized (mLock) {
+            mTaskVanishedListeners.add(listener);
+        }
+    }
+
+    /**
+     * Removes a task-vanished listener.
+     */
+    public void removeTaskVanishedListener(TaskVanishedListener listener) {
+        synchronized (mLock) {
+            mTaskVanishedListeners.remove(listener);
+        }
+    }
+
     /**
      * Returns a surface which can be used to attach overlays to the home root task
      */
@@ -614,6 +644,9 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
                 t.apply();
                 ProtoLog.v(WM_SHELL_TASK_ORG, "Removing overlay surface");
             }
+            for (TaskVanishedListener l : mTaskVanishedListeners) {
+                l.onTaskVanished(taskInfo);
+            }
 
             if (!ENABLE_SHELL_TRANSITIONS && (appearedInfo.getLeash() != null)) {
                 // Preemptively clean up the leash only if shell transitions are not enabled
@@ -647,6 +680,22 @@ public class ShellTaskOrganizer extends TaskOrganizer implements
         }
     }
 
+    /**
+     * Shows/hides the given task surface.  Not for general use as changing the task visibility may
+     * conflict with other Transitions.  This is currently ONLY used to temporarily hide a task
+     * while a drag is in session.
+     */
+    public void setTaskSurfaceVisibility(int taskId, boolean visible) {
+        synchronized (mLock) {
+            final TaskAppearedInfo info = mTasks.get(taskId);
+            if (info != null) {
+                SurfaceControl.Transaction t = new SurfaceControl.Transaction();
+                t.setVisibility(info.getLeash(), visible);
+                t.apply();
+            }
+        }
+    }
+
     private boolean updateTaskListenerIfNeeded(RunningTaskInfo taskInfo, SurfaceControl leash,
             TaskListener oldListener, TaskListener newListener) {
         if (oldListener == newListener) return false;
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/dagger/WMShellModule.java b/libs/WindowManager/Shell/src/com/android/wm/shell/dagger/WMShellModule.java
index 87bd84017dee..7ef8d2a15fa5 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/dagger/WMShellModule.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/dagger/WMShellModule.java
@@ -642,6 +642,7 @@ public abstract class WMShellModule {
             ShellInit shellInit,
             ShellController shellController,
             ShellCommandHandler shellCommandHandler,
+            ShellTaskOrganizer shellTaskOrganizer,
             DisplayController displayController,
             UiEventLogger uiEventLogger,
             IconProvider iconProvider,
@@ -649,8 +650,8 @@ public abstract class WMShellModule {
             Transitions transitions,
             @ShellMainThread ShellExecutor mainExecutor) {
         return new DragAndDropController(context, shellInit, shellController, shellCommandHandler,
-                displayController, uiEventLogger, iconProvider, globalDragListener, transitions,
-                mainExecutor);
+                shellTaskOrganizer, displayController, uiEventLogger, iconProvider,
+                globalDragListener, transitions, mainExecutor);
     }
 
     //
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropController.java b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropController.java
index c374eb8e8f03..280f5f610b6d 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropController.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropController.java
@@ -52,6 +52,7 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowManager;
 import android.widget.FrameLayout;
+import android.window.WindowContainerToken;
 import android.window.WindowContainerTransaction;
 
 import androidx.annotation.BinderThread;
@@ -62,6 +63,7 @@ import com.android.internal.logging.UiEventLogger;
 import com.android.internal.protolog.common.ProtoLog;
 import com.android.launcher3.icons.IconProvider;
 import com.android.wm.shell.R;
+import com.android.wm.shell.ShellTaskOrganizer;
 import com.android.wm.shell.common.DisplayController;
 import com.android.wm.shell.common.ExternalInterfaceBinder;
 import com.android.wm.shell.common.RemoteCallable;
@@ -85,6 +87,7 @@ import java.util.function.Function;
 public class DragAndDropController implements RemoteCallable<DragAndDropController>,
         GlobalDragListener.GlobalDragListenerCallback,
         DisplayController.OnDisplaysChangedListener,
+        ShellTaskOrganizer.TaskVanishedListener,
         View.OnDragListener, ComponentCallbacks2 {
 
     private static final String TAG = DragAndDropController.class.getSimpleName();
@@ -92,6 +95,7 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
     private final Context mContext;
     private final ShellController mShellController;
     private final ShellCommandHandler mShellCommandHandler;
+    private final ShellTaskOrganizer mShellTaskOrganizer;
     private final DisplayController mDisplayController;
     private final DragAndDropEventLogger mLogger;
     private final IconProvider mIconProvider;
@@ -133,6 +137,7 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
             ShellInit shellInit,
             ShellController shellController,
             ShellCommandHandler shellCommandHandler,
+            ShellTaskOrganizer shellTaskOrganizer,
             DisplayController displayController,
             UiEventLogger uiEventLogger,
             IconProvider iconProvider,
@@ -142,6 +147,7 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
         mContext = context;
         mShellController = shellController;
         mShellCommandHandler = shellCommandHandler;
+        mShellTaskOrganizer = shellTaskOrganizer;
         mDisplayController = displayController;
         mLogger = new DragAndDropEventLogger(uiEventLogger);
         mIconProvider = iconProvider;
@@ -163,6 +169,7 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
         }, 0);
         mShellController.addExternalInterface(KEY_EXTRA_SHELL_DRAG_AND_DROP,
                 this::createExternalInterface, this);
+        mShellTaskOrganizer.addTaskVanishedListener(this);
         mShellCommandHandler.addDumpCallback(this::dump, this);
         mGlobalDragListener.setListener(this);
     }
@@ -280,6 +287,34 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
         mDisplayDropTargets.remove(displayId);
     }
 
+    @Override
+    public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
+        if (taskInfo.baseIntent == null) {
+            // Invalid info
+            return;
+        }
+        // Find the active drag
+        PerDisplay pd = null;
+        for (int i = 0; i < mDisplayDropTargets.size(); i++) {
+            final PerDisplay iPd = mDisplayDropTargets.valueAt(i);
+            if (iPd.isHandlingDrag) {
+                pd = iPd;
+                break;
+            }
+        }
+        if (pd == null || pd.activeDragCount <= 0 || !pd.isHandlingDrag) {
+            // Not currently dragging
+            return;
+        }
+
+        // Update the drag session
+        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                "Handling vanished task: id=%d component=%s", taskInfo.taskId,
+                taskInfo.baseIntent.getComponent());
+        pd.dragSession.updateRunningTask();
+        pd.dragLayout.updateSession(pd.dragSession);
+    }
+
     @Override
     public boolean onDrag(View target, DragEvent event) {
         ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
@@ -298,9 +333,10 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
             mActiveDragDisplay = displayId;
             pd.isHandlingDrag = DragUtils.canHandleDrag(event);
             ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
-                    "Clip description: handlingDrag=%b itemCount=%d mimeTypes=%s",
+                    "Clip description: handlingDrag=%b itemCount=%d mimeTypes=%s flags=%s",
                     pd.isHandlingDrag, event.getClipData().getItemCount(),
-                    DragUtils.getMimeTypesConcatenated(description));
+                    DragUtils.getMimeTypesConcatenated(description),
+                    DragUtils.dragFlagsToString(event.getDragFlags()));
         }
 
         if (!pd.isHandlingDrag) {
@@ -313,13 +349,18 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
                     Slog.w(TAG, "Unexpected drag start during an active drag");
                     return false;
                 }
-                // TODO(b/290391688): Also update the session data with task stack changes
                 pd.dragSession = new DragSession(ActivityTaskManager.getInstance(),
                         mDisplayController.getDisplayLayout(displayId), event.getClipData(),
                         event.getDragFlags());
-                pd.dragSession.update();
+                pd.dragSession.initialize();
                 pd.activeDragCount++;
                 pd.dragLayout.prepare(pd.dragSession, mLogger.logStart(pd.dragSession));
+                if (pd.dragSession.hideDragSourceTaskId != -1) {
+                    ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                            "Hiding task surface: taskId=%d", pd.dragSession.hideDragSourceTaskId);
+                    mShellTaskOrganizer.setTaskSurfaceVisibility(
+                            pd.dragSession.hideDragSourceTaskId, false /* visible */);
+                }
                 setDropTargetWindowVisibility(pd, View.VISIBLE);
                 notifyListeners(l -> {
                     l.onDragStarted();
@@ -349,6 +390,13 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
                 if (pd.dragLayout.hasDropped()) {
                     mLogger.logDrop();
                 } else {
+                    if (pd.dragSession.hideDragSourceTaskId != -1) {
+                        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                                "Re-showing task surface: taskId=%d",
+                                pd.dragSession.hideDragSourceTaskId);
+                        mShellTaskOrganizer.setTaskSurfaceVisibility(
+                                pd.dragSession.hideDragSourceTaskId, true /* visible */);
+                    }
                     pd.activeDragCount--;
                     pd.dragLayout.hide(event, () -> {
                         if (pd.activeDragCount == 0) {
@@ -402,7 +450,16 @@ public class DragAndDropController implements RemoteCallable<DragAndDropControll
     private boolean handleDrop(DragEvent event, PerDisplay pd) {
         final SurfaceControl dragSurface = event.getDragSurface();
         pd.activeDragCount--;
-        return pd.dragLayout.drop(event, dragSurface, () -> {
+        // Find the token of the task to hide as a part of entering split
+        WindowContainerToken hideTaskToken = null;
+        if (pd.dragSession.hideDragSourceTaskId != -1) {
+            ActivityManager.RunningTaskInfo info = mShellTaskOrganizer.getRunningTaskInfo(
+                    pd.dragSession.hideDragSourceTaskId);
+            if (info != null) {
+                hideTaskToken = info.token;
+            }
+        }
+        return pd.dragLayout.drop(event, dragSurface, hideTaskToken, () -> {
             if (pd.activeDragCount == 0) {
                 // Hide the window if another drag hasn't been started while animating the drop
                 setDropTargetWindowVisibility(pd, View.INVISIBLE);
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropPolicy.java b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropPolicy.java
index a42ca1905ee7..5644155d74f8 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropPolicy.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragAndDropPolicy.java
@@ -59,6 +59,7 @@ import android.os.RemoteException;
 import android.os.UserHandle;
 import android.util.Log;
 import android.util.Slog;
+import android.window.WindowContainerToken;
 
 import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
@@ -84,7 +85,10 @@ public class DragAndDropPolicy {
     private static final String TAG = DragAndDropPolicy.class.getSimpleName();
 
     private final Context mContext;
-    private final Starter mStarter;
+    // Used only for launching a fullscreen task (or as a fallback if there is no split starter)
+    private final Starter mFullscreenStarter;
+    // Used for launching tasks into splitscreen
+    private final Starter mSplitscreenStarter;
     private final SplitScreenController mSplitScreen;
     private final ArrayList<DragAndDropPolicy.Target> mTargets = new ArrayList<>();
     private final RectF mDisallowHitRegion = new RectF();
@@ -97,10 +101,12 @@ public class DragAndDropPolicy {
     }
 
     @VisibleForTesting
-    DragAndDropPolicy(Context context, SplitScreenController splitScreen, Starter starter) {
+    DragAndDropPolicy(Context context, SplitScreenController splitScreen,
+            Starter fullscreenStarter) {
         mContext = context;
         mSplitScreen = splitScreen;
-        mStarter = mSplitScreen != null ? mSplitScreen : starter;
+        mFullscreenStarter = fullscreenStarter;
+        mSplitscreenStarter = splitScreen;
     }
 
     /**
@@ -229,8 +235,13 @@ public class DragAndDropPolicy {
         return null;
     }
 
+    /**
+     * Handles the drop on a given {@param target}.  If a {@param hideTaskToken} is set, then the
+     * handling of the drop will attempt to hide the given task as a part of the same window
+     * container transaction if possible.
+     */
     @VisibleForTesting
-    void handleDrop(Target target) {
+    void handleDrop(Target target, @Nullable WindowContainerToken hideTaskToken) {
         if (target == null || !mTargets.contains(target)) {
             return;
         }
@@ -245,17 +256,21 @@ public class DragAndDropPolicy {
             mSplitScreen.onDroppedToSplit(position, mLoggerSessionId);
         }
 
+        final Starter starter = target.type == TYPE_FULLSCREEN
+                ? mFullscreenStarter
+                : mSplitscreenStarter;
         if (mSession.appData != null) {
-            launchApp(mSession, position);
+            launchApp(mSession, starter, position, hideTaskToken);
         } else {
-            launchIntent(mSession, position);
+            launchIntent(mSession, starter, position, hideTaskToken);
         }
     }
 
     /**
      * Launches an app provided by SysUI.
      */
-    private void launchApp(DragSession session, @SplitPosition int position) {
+    private void launchApp(DragSession session, Starter starter, @SplitPosition int position,
+            @Nullable WindowContainerToken hideTaskToken) {
         ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "Launching app data at position=%d",
                 position);
         final ClipDescription description = session.getClipDescription();
@@ -275,11 +290,15 @@ public class DragAndDropPolicy {
 
         if (isTask) {
             final int taskId = session.appData.getIntExtra(EXTRA_TASK_ID, INVALID_TASK_ID);
-            mStarter.startTask(taskId, position, opts);
+            starter.startTask(taskId, position, opts, hideTaskToken);
         } else if (isShortcut) {
+            if (hideTaskToken != null) {
+                ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                        "Can not hide task token with starting shortcut");
+            }
             final String packageName = session.appData.getStringExtra(EXTRA_PACKAGE_NAME);
             final String id = session.appData.getStringExtra(EXTRA_SHORTCUT_ID);
-            mStarter.startShortcut(packageName, id, position, opts, user);
+            starter.startShortcut(packageName, id, position, opts, user);
         } else {
             final PendingIntent launchIntent =
                     session.appData.getParcelableExtra(EXTRA_PENDING_INTENT);
@@ -288,15 +307,16 @@ public class DragAndDropPolicy {
                     Log.e(TAG, "Expected app intent's EXTRA_USER to match pending intent user");
                 }
             }
-            mStarter.startIntent(launchIntent, user.getIdentifier(), null /* fillIntent */,
-                    position, opts);
+            starter.startIntent(launchIntent, user.getIdentifier(), null /* fillIntent */,
+                    position, opts, hideTaskToken);
         }
     }
 
     /**
      * Launches an intent sender provided by an application.
      */
-    private void launchIntent(DragSession session, @SplitPosition int position) {
+    private void launchIntent(DragSession session, Starter starter, @SplitPosition int position,
+            @Nullable WindowContainerToken hideTaskToken) {
         ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "Launching intent at position=%d",
                 position);
         final ActivityOptions baseActivityOpts = ActivityOptions.makeBasic();
@@ -309,20 +329,22 @@ public class DragAndDropPolicy {
                 | FLAG_ACTIVITY_MULTIPLE_TASK);
 
         final Bundle opts = baseActivityOpts.toBundle();
-        mStarter.startIntent(session.launchableIntent,
+        starter.startIntent(session.launchableIntent,
                 session.launchableIntent.getCreatorUserHandle().getIdentifier(),
-                null /* fillIntent */, position, opts);
+                null /* fillIntent */, position, opts, hideTaskToken);
     }
 
     /**
      * Interface for actually committing the task launches.
      */
     public interface Starter {
-        void startTask(int taskId, @SplitPosition int position, @Nullable Bundle options);
+        void startTask(int taskId, @SplitPosition int position, @Nullable Bundle options,
+                @Nullable WindowContainerToken hideTaskToken);
         void startShortcut(String packageName, String shortcutId, @SplitPosition int position,
                 @Nullable Bundle options, UserHandle user);
         void startIntent(PendingIntent intent, int userId, Intent fillInIntent,
-                @SplitPosition int position, @Nullable Bundle options);
+                @SplitPosition int position, @Nullable Bundle options,
+                @Nullable WindowContainerToken hideTaskToken);
         void enterSplitScreen(int taskId, boolean leftOrTop);
 
         /**
@@ -344,7 +366,12 @@ public class DragAndDropPolicy {
         }
 
         @Override
-        public void startTask(int taskId, int position, @Nullable Bundle options) {
+        public void startTask(int taskId, int position, @Nullable Bundle options,
+                @Nullable WindowContainerToken hideTaskToken) {
+            if (hideTaskToken != null) {
+                ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                        "Default starter does not support hide task token");
+            }
             try {
                 ActivityTaskManager.getService().startActivityFromRecents(taskId, options);
             } catch (RemoteException e) {
@@ -367,7 +394,12 @@ public class DragAndDropPolicy {
 
         @Override
         public void startIntent(PendingIntent intent, int userId, @Nullable Intent fillInIntent,
-                int position, @Nullable Bundle options) {
+                int position, @Nullable Bundle options,
+                @Nullable WindowContainerToken hideTaskToken) {
+            if (hideTaskToken != null) {
+                ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                        "Default starter does not support hide task token");
+            }
             try {
                 intent.send(mContext, 0, fillInIntent, null, null, null, options);
             } catch (PendingIntent.CanceledException e) {
@@ -420,7 +452,7 @@ public class DragAndDropPolicy {
 
         @Override
         public String toString() {
-            return "Target {hit=" + hitRegion + " draw=" + drawRegion + "}";
+            return "Target {type=" + type + " hit=" + hitRegion + " draw=" + drawRegion + "}";
         }
     }
 }
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragLayout.java b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragLayout.java
index 4bb10dfdf8c6..e458daf9c61b 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragLayout.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragLayout.java
@@ -42,6 +42,7 @@ import android.content.Context;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.graphics.Insets;
+import android.graphics.Point;
 import android.graphics.Rect;
 import android.graphics.Region;
 import android.graphics.drawable.Drawable;
@@ -51,8 +52,10 @@ import android.view.ViewTreeObserver;
 import android.view.WindowInsets;
 import android.view.WindowInsets.Type;
 import android.widget.LinearLayout;
+import android.window.WindowContainerToken;
 
 import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
 
 import com.android.internal.logging.InstanceId;
 import com.android.internal.protolog.common.ProtoLog;
@@ -102,6 +105,8 @@ public class DragLayout extends LinearLayout
     private boolean mIsShowing;
     private boolean mHasDropped;
     private DragSession mSession;
+    // The last position that was handled by the drag layout
+    private final Point mLastPosition = new Point();
 
     @SuppressLint("WrongConstant")
     public DragLayout(Context context, SplitScreenController splitScreenController,
@@ -265,6 +270,15 @@ public class DragLayout extends LinearLayout
      */
     public void prepare(DragSession session, InstanceId loggerSessionId) {
         mPolicy.start(session, loggerSessionId);
+        updateSession(session);
+    }
+
+    /**
+     * Updates the drag layout based on the diven drag session.
+     */
+    public void updateSession(DragSession session) {
+        // Note: The policy currently just keeps a reference to the session
+        boolean updatingExistingSession = mSession != null;
         mSession = session;
         mHasDropped = false;
         mCurrentTarget = null;
@@ -280,6 +294,8 @@ public class DragLayout extends LinearLayout
                     int bgColor1 = getResizingBackgroundColor(taskInfo1).toArgb();
                     mDropZoneView1.setAppInfo(bgColor1, icon1);
                     mDropZoneView2.setAppInfo(bgColor1, icon1);
+                    mDropZoneView1.setForceIgnoreBottomMargin(false);
+                    mDropZoneView2.setForceIgnoreBottomMargin(false);
                     updateDropZoneSizes(null, null); // passing null splits the views evenly
                 } else {
                     // We use the first drop zone to show the fullscreen highlight, and don't need
@@ -312,6 +328,11 @@ public class DragLayout extends LinearLayout
             updateDropZoneSizes(topOrLeftBounds, bottomOrRightBounds);
         }
         requestLayout();
+        if (updatingExistingSession) {
+            // Update targets if we are already currently dragging
+            recomputeDropTargets();
+            update(mLastPosition.x, mLastPosition.y);
+        }
     }
 
     private void updateDropZoneSizesForSingleTask() {
@@ -359,6 +380,9 @@ public class DragLayout extends LinearLayout
         mDropZoneView2.setLayoutParams(dropZoneView2);
     }
 
+    /**
+     * Shows the drag layout.
+     */
     public void show() {
         mIsShowing = true;
         recomputeDropTargets();
@@ -384,13 +408,19 @@ public class DragLayout extends LinearLayout
      * Updates the visible drop target as the user drags.
      */
     public void update(DragEvent event) {
+        update((int) event.getX(), (int) event.getY());
+    }
+
+    /**
+     * Updates the visible drop target as the user drags to the given coordinates.
+     */
+    private void update(int x, int y) {
         if (mHasDropped) {
             return;
         }
         // Find containing region, if the same as mCurrentRegion, then skip, otherwise, animate the
         // visibility of the current region
-        DragAndDropPolicy.Target target = mPolicy.getTargetAtLocation(
-                (int) event.getX(), (int) event.getY());
+        DragAndDropPolicy.Target target = mPolicy.getTargetAtLocation(x, y);
         if (mCurrentTarget != target) {
             ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "Current target: %s", target);
             if (target == null) {
@@ -429,6 +459,7 @@ public class DragLayout extends LinearLayout
             }
             mCurrentTarget = target;
         }
+        mLastPosition.set(x, y);
     }
 
     /**
@@ -436,6 +467,7 @@ public class DragLayout extends LinearLayout
      */
     public void hide(DragEvent event, Runnable hideCompleteCallback) {
         mIsShowing = false;
+        mLastPosition.set(-1, -1);
         animateSplitContainers(false, () -> {
             if (hideCompleteCallback != null) {
                 hideCompleteCallback.run();
@@ -456,13 +488,13 @@ public class DragLayout extends LinearLayout
     /**
      * Handles the drop onto a target and animates out the visible drop targets.
      */
-    public boolean drop(DragEvent event, SurfaceControl dragSurface,
-            Runnable dropCompleteCallback) {
+    public boolean drop(DragEvent event, @NonNull SurfaceControl dragSurface,
+            @Nullable WindowContainerToken hideTaskToken, Runnable dropCompleteCallback) {
         final boolean handledDrop = mCurrentTarget != null;
         mHasDropped = true;
 
         // Process the drop
-        mPolicy.handleDrop(mCurrentTarget);
+        mPolicy.handleDrop(mCurrentTarget, hideTaskToken);
 
         // Start animating the drop UI out with the drag surface
         hide(event, dropCompleteCallback);
@@ -472,7 +504,7 @@ public class DragLayout extends LinearLayout
         return handledDrop;
     }
 
-    private void hideDragSurface(SurfaceControl dragSurface) {
+    private void hideDragSurface(@NonNull SurfaceControl dragSurface) {
         final SurfaceControl.Transaction tx = new SurfaceControl.Transaction();
         final ValueAnimator dragSurfaceAnimator = ValueAnimator.ofFloat(0f, 1f);
         // Currently the splash icon animation runs with the default ValueAnimator duration of
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragSession.java b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragSession.java
index 0addd432aff0..9a652f21c0be 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragSession.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragSession.java
@@ -18,6 +18,7 @@ package com.android.wm.shell.draganddrop;
 
 import static android.app.WindowConfiguration.ACTIVITY_TYPE_STANDARD;
 import static android.app.WindowConfiguration.WINDOWING_MODE_UNDEFINED;
+import static android.content.ClipDescription.EXTRA_HIDE_DRAG_SOURCE_TASK_ID;
 
 import android.app.ActivityManager;
 import android.app.ActivityTaskManager;
@@ -27,10 +28,13 @@ import android.content.ClipData;
 import android.content.ClipDescription;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
+import android.os.PersistableBundle;
 
 import androidx.annotation.Nullable;
 
+import com.android.internal.protolog.common.ProtoLog;
 import com.android.wm.shell.common.DisplayLayout;
+import com.android.wm.shell.protolog.ShellProtoLogGroup;
 
 import java.util.List;
 
@@ -61,6 +65,7 @@ public class DragSession {
     @WindowConfiguration.ActivityType
     int runningTaskActType = ACTIVITY_TYPE_STANDARD;
     boolean dragItemSupportsSplitscreen;
+    int hideDragSourceTaskId = -1;
 
     DragSession(ActivityTaskManager activityTaskManager,
             DisplayLayout dispLayout, ClipData data, int dragFlags) {
@@ -68,6 +73,11 @@ public class DragSession {
         mInitialDragData = data;
         mInitialDragFlags = dragFlags;
         displayLayout = dispLayout;
+        hideDragSourceTaskId = data.getDescription().getExtras() != null
+                ? data.getDescription().getExtras().getInt(EXTRA_HIDE_DRAG_SOURCE_TASK_ID, -1)
+                : -1;
+        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                "Extracting drag source taskId: taskId=%d", hideDragSourceTaskId);
     }
 
     /**
@@ -79,17 +89,38 @@ public class DragSession {
     }
 
     /**
-     * Updates the session data based on the current state of the system.
+     * Updates the running task for this drag session.
      */
-    void update() {
-        List<ActivityManager.RunningTaskInfo> tasks =
-                mActivityTaskManager.getTasks(1, false /* filterOnlyVisibleRecents */);
+    void updateRunningTask() {
+        final boolean hideDragSourceTask = hideDragSourceTaskId != -1;
+        final List<ActivityManager.RunningTaskInfo> tasks =
+                mActivityTaskManager.getTasks(hideDragSourceTask ? 2 : 1,
+                        false /* filterOnlyVisibleRecents */);
         if (!tasks.isEmpty()) {
-            final ActivityManager.RunningTaskInfo task = tasks.get(0);
-            runningTaskInfo = task;
-            runningTaskWinMode = task.getWindowingMode();
-            runningTaskActType = task.getActivityType();
+            for (int i = tasks.size() - 1; i >= 0; i--) {
+                final ActivityManager.RunningTaskInfo task = tasks.get(i);
+                if (hideDragSourceTask && hideDragSourceTaskId == task.taskId) {
+                    ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                            "Skipping running task: id=%d component=%s", task.taskId,
+                            task.baseIntent != null ? task.baseIntent.getComponent() : "null");
+                    continue;
+                }
+                runningTaskInfo = task;
+                runningTaskWinMode = task.getWindowingMode();
+                runningTaskActType = task.getActivityType();
+                ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                        "Running task: id=%d component=%s", task.taskId,
+                        task.baseIntent != null ? task.baseIntent.getComponent() : "null");
+                break;
+            }
         }
+    }
+
+    /**
+     * Updates the session data based on the current state of the system at the start of the drag.
+     */
+    void initialize() {
+        updateRunningTask();
 
         activityInfo = mInitialDragData.getItemAt(0).getActivityInfo();
         // TODO: This should technically check & respect config_supportsNonResizableMultiWindow
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragUtils.java b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragUtils.java
index e215870f1894..22cfa328bfda 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragUtils.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DragUtils.java
@@ -19,16 +19,28 @@ package com.android.wm.shell.draganddrop;
 import static android.content.ClipDescription.MIMETYPE_APPLICATION_ACTIVITY;
 import static android.content.ClipDescription.MIMETYPE_APPLICATION_SHORTCUT;
 import static android.content.ClipDescription.MIMETYPE_APPLICATION_TASK;
+import static android.view.View.DRAG_FLAG_ACCESSIBILITY_ACTION;
+import static android.view.View.DRAG_FLAG_GLOBAL;
+import static android.view.View.DRAG_FLAG_GLOBAL_PERSISTABLE_URI_PERMISSION;
+import static android.view.View.DRAG_FLAG_GLOBAL_PREFIX_URI_PERMISSION;
+import static android.view.View.DRAG_FLAG_GLOBAL_SAME_APPLICATION;
+import static android.view.View.DRAG_FLAG_GLOBAL_URI_READ;
+import static android.view.View.DRAG_FLAG_GLOBAL_URI_WRITE;
+import static android.view.View.DRAG_FLAG_HIDE_CALLING_TASK_ON_DRAG_START;
+import static android.view.View.DRAG_FLAG_OPAQUE;
+import static android.view.View.DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION;
+import static android.view.View.DRAG_FLAG_START_INTENT_SENDER_ON_UNHANDLED_DRAG;
 
 import android.app.PendingIntent;
 import android.content.ClipData;
 import android.content.ClipDescription;
 import android.view.DragEvent;
-import android.view.View;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import java.util.StringJoiner;
+
 /** Collection of utility classes for handling drag and drop. */
 public class DragUtils {
     private static final String TAG = "DragUtils";
@@ -76,7 +88,7 @@ public class DragUtils {
      */
     @Nullable
     public static PendingIntent getLaunchIntent(@NonNull ClipData data, int dragFlags) {
-        if ((dragFlags & View.DRAG_FLAG_START_INTENT_SENDER_ON_UNHANDLED_DRAG) == 0) {
+        if ((dragFlags & DRAG_FLAG_START_INTENT_SENDER_ON_UNHANDLED_DRAG) == 0) {
             // Disallow launching the intent if the app does not want to delegate it to the system
             return null;
         }
@@ -105,4 +117,35 @@ public class DragUtils {
         }
         return mimeTypes;
     }
+
+    /**
+     * Returns the string description of the given {@param dragFlags}.
+     */
+    public static String dragFlagsToString(int dragFlags) {
+        StringJoiner str = new StringJoiner("|");
+        if ((dragFlags & DRAG_FLAG_GLOBAL) != 0) {
+            str.add("GLOBAL");
+        } else if ((dragFlags & DRAG_FLAG_GLOBAL_URI_READ) != 0) {
+            str.add("GLOBAL_URI_READ");
+        } else if ((dragFlags & DRAG_FLAG_GLOBAL_URI_WRITE) != 0) {
+            str.add("GLOBAL_URI_WRITE");
+        } else if ((dragFlags & DRAG_FLAG_GLOBAL_PERSISTABLE_URI_PERMISSION) != 0) {
+            str.add("GLOBAL_PERSISTABLE_URI_PERMISSION");
+        } else if ((dragFlags & DRAG_FLAG_GLOBAL_PREFIX_URI_PERMISSION) != 0) {
+            str.add("GLOBAL_PREFIX_URI_PERMISSION");
+        } else if ((dragFlags & DRAG_FLAG_OPAQUE) != 0) {
+            str.add("OPAQUE");
+        } else if ((dragFlags & DRAG_FLAG_ACCESSIBILITY_ACTION) != 0) {
+            str.add("ACCESSIBILITY_ACTION");
+        } else if ((dragFlags & DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION) != 0) {
+            str.add("REQUEST_SURFACE_FOR_RETURN_ANIMATION");
+        } else if ((dragFlags & DRAG_FLAG_GLOBAL_SAME_APPLICATION) != 0) {
+            str.add("GLOBAL_SAME_APPLICATION");
+        } else if ((dragFlags & DRAG_FLAG_START_INTENT_SENDER_ON_UNHANDLED_DRAG) != 0) {
+            str.add("START_INTENT_SENDER_ON_UNHANDLED_DRAG");
+        } else if ((dragFlags & DRAG_FLAG_HIDE_CALLING_TASK_ON_DRAG_START) != 0) {
+            str.add("HIDE_CALLING_TASK_ON_DRAG_START");
+        }
+        return str.toString();
+    }
 }
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DropZoneView.java b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DropZoneView.java
index 724a130ef52d..a72bae29a9c2 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DropZoneView.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/draganddrop/DropZoneView.java
@@ -19,6 +19,7 @@ package com.android.wm.shell.draganddrop;
 import static com.android.wm.shell.animation.Interpolators.FAST_OUT_SLOW_IN;
 
 import android.animation.Animator;
+import android.animation.AnimatorListenerAdapter;
 import android.animation.ObjectAnimator;
 import android.content.Context;
 import android.graphics.Canvas;
@@ -37,13 +38,16 @@ import android.widget.ImageView;
 import androidx.annotation.Nullable;
 
 import com.android.internal.policy.ScreenDecorationsUtils;
+import com.android.internal.protolog.common.ProtoLog;
 import com.android.wm.shell.R;
+import com.android.wm.shell.protolog.ShellProtoLogGroup;
 
 /**
  * Renders a drop zone area for items being dragged.
  */
 public class DropZoneView extends FrameLayout {
 
+    private static final boolean DEBUG_LAYOUT = false;
     private static final float SPLASHSCREEN_ALPHA = 0.90f;
     private static final float HIGHLIGHT_ALPHA = 1f;
     private static final int MARGIN_ANIMATION_ENTER_DURATION = 400;
@@ -77,6 +81,7 @@ public class DropZoneView extends FrameLayout {
     private int mHighlightColor;
 
     private ObjectAnimator mBackgroundAnimator;
+    private int mTargetBackgroundColor;
     private ObjectAnimator mMarginAnimator;
     private float mMarginPercent;
 
@@ -146,6 +151,10 @@ public class DropZoneView extends FrameLayout {
 
     /** Ignores the bottom margin provided by the insets. */
     public void setForceIgnoreBottomMargin(boolean ignoreBottomMargin) {
+        if (DEBUG_LAYOUT) {
+            ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                    "setForceIgnoreBottomMargin: ignore=%b", ignoreBottomMargin);
+        }
         mIgnoreBottomMargin = ignoreBottomMargin;
         if (mMarginPercent > 0) {
             mMarginView.invalidate();
@@ -154,8 +163,14 @@ public class DropZoneView extends FrameLayout {
 
     /** Sets the bottom inset so the drop zones are above bottom navigation. */
     public void setBottomInset(float bottom) {
+        if (DEBUG_LAYOUT) {
+            ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "setBottomInset: inset=%f",
+                    bottom);
+        }
         mBottomInset = bottom;
-        ((LayoutParams) mSplashScreenView.getLayoutParams()).bottomMargin = (int) bottom;
+        final LayoutParams lp = (LayoutParams) mSplashScreenView.getLayoutParams();
+        lp.bottomMargin = (int) bottom;
+        mSplashScreenView.setLayoutParams(lp);
         if (mMarginPercent > 0) {
             mMarginView.invalidate();
         }
@@ -181,6 +196,9 @@ public class DropZoneView extends FrameLayout {
 
     /** Animates between highlight and splashscreen depending on current state. */
     public void animateSwitch() {
+        if (DEBUG_LAYOUT) {
+            ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "animateSwitch");
+        }
         mShowingHighlight = !mShowingHighlight;
         mShowingSplash = !mShowingHighlight;
         final int newColor = mShowingHighlight ? mHighlightColor : mSplashScreenColor;
@@ -190,6 +208,10 @@ public class DropZoneView extends FrameLayout {
 
     /** Animates the highlight indicating the zone is hovered on or not. */
     public void setShowingHighlight(boolean showingHighlight) {
+        if (DEBUG_LAYOUT) {
+            ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "setShowingHighlight: showing=%b",
+                    showingHighlight);
+        }
         mShowingHighlight = showingHighlight;
         mShowingSplash = !mShowingHighlight;
         final int newColor = mShowingHighlight ? mHighlightColor : mSplashScreenColor;
@@ -199,6 +221,10 @@ public class DropZoneView extends FrameLayout {
 
     /** Animates the margins around the drop zone to show or hide. */
     public void setShowingMargin(boolean visible) {
+        if (DEBUG_LAYOUT) {
+            ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP, "setShowingMargin: visible=%b",
+                    visible);
+        }
         if (mShowingMargin != visible) {
             mShowingMargin = visible;
             animateMarginToState();
@@ -212,6 +238,15 @@ public class DropZoneView extends FrameLayout {
     }
 
     private void animateBackground(int startColor, int endColor) {
+        if (DEBUG_LAYOUT) {
+            ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                    "animateBackground: start=%s end=%s",
+                    Integer.toHexString(startColor), Integer.toHexString(endColor));
+        }
+        if (endColor == mTargetBackgroundColor) {
+            // Already at, or animating to, that background color
+            return;
+        }
         if (mBackgroundAnimator != null) {
             mBackgroundAnimator.cancel();
         }
@@ -223,6 +258,7 @@ public class DropZoneView extends FrameLayout {
             mBackgroundAnimator.setInterpolator(FAST_OUT_SLOW_IN);
         }
         mBackgroundAnimator.start();
+        mTargetBackgroundColor = endColor;
     }
 
     private void animateSplashScreenIcon() {
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/recents/RecentTasksController.java b/libs/WindowManager/Shell/src/com/android/wm/shell/recents/RecentTasksController.java
index 03c8cf8cc795..417b37b1f16f 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/recents/RecentTasksController.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/recents/RecentTasksController.java
@@ -37,6 +37,7 @@ import android.util.Slog;
 import android.util.SparseArray;
 import android.util.SparseIntArray;
 import android.view.IRecentsAnimationRunner;
+import android.window.WindowContainerToken;
 
 import androidx.annotation.BinderThread;
 import androidx.annotation.NonNull;
@@ -453,11 +454,31 @@ public class RecentTasksController implements TaskStackListenerCallback,
     }
 
     /**
-     * Find the background task that match the given component.
+     * Returns the top running leaf task ignoring {@param ignoreTaskToken} if it is specified.
+     * NOTE: This path currently makes assumptions that ignoreTaskToken is for the top task.
+     */
+    @Nullable
+    public ActivityManager.RunningTaskInfo getTopRunningTask(
+            @Nullable WindowContainerToken ignoreTaskToken) {
+        List<ActivityManager.RunningTaskInfo> tasks = mActivityTaskManager.getTasks(2,
+                false /* filterOnlyVisibleRecents */);
+        for (int i = 0; i < tasks.size(); i++) {
+            final ActivityManager.RunningTaskInfo task = tasks.get(i);
+            if (task.token.equals(ignoreTaskToken)) {
+                continue;
+            }
+            return task;
+        }
+        return null;
+    }
+
+    /**
+     * Find the background task that match the given component.  Ignores tasks match
+     * {@param ignoreTaskToken} if it is non-null.
      */
     @Nullable
     public ActivityManager.RecentTaskInfo findTaskInBackground(ComponentName componentName,
-            int userId) {
+            int userId, @Nullable WindowContainerToken ignoreTaskToken) {
         if (componentName == null) {
             return null;
         }
@@ -469,6 +490,9 @@ public class RecentTasksController implements TaskStackListenerCallback,
             if (task.isVisible) {
                 continue;
             }
+            if (task.token.equals(ignoreTaskToken)) {
+                continue;
+            }
             if (componentName.equals(task.baseIntent.getComponent()) && userId == task.userId) {
                 return task;
             }
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/SplitScreenController.java b/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/SplitScreenController.java
index dd219d32bbaa..36cc9101b0dc 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/SplitScreenController.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/SplitScreenController.java
@@ -64,6 +64,7 @@ import android.view.SurfaceSession;
 import android.view.WindowManager;
 import android.widget.Toast;
 import android.window.RemoteTransition;
+import android.window.WindowContainerToken;
 import android.window.WindowContainerTransaction;
 
 import androidx.annotation.BinderThread;
@@ -526,7 +527,15 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
         mStageCoordinator.requestEnterSplitSelect(taskInfo, wct, splitPosition, taskBounds);
     }
 
-    public void startTask(int taskId, @SplitPosition int position, @Nullable Bundle options) {
+    /**
+     * Starts an existing task into split.
+     * TODO(b/351900580): We should remove this path and use StageCoordinator#startTask() instead
+     * @param hideTaskToken is not supported.
+     */
+    public void startTask(int taskId, @SplitPosition int position, @Nullable Bundle options,
+            @Nullable WindowContainerToken hideTaskToken) {
+        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DRAG_AND_DROP,
+                "Legacy startTask does not support hide task token");
         final int[] result = new int[1];
         IRemoteAnimationRunner wrapper = new IRemoteAnimationRunner.Stub() {
             @Override
@@ -584,8 +593,8 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
         if (options == null) options = new Bundle();
         final ActivityOptions activityOptions = ActivityOptions.fromBundle(options);
 
-        if (samePackage(packageName, getPackageName(reverseSplitPosition(position)),
-                user.getIdentifier(), getUserId(reverseSplitPosition(position)))) {
+        if (samePackage(packageName, getPackageName(reverseSplitPosition(position), null),
+                user.getIdentifier(), getUserId(reverseSplitPosition(position), null))) {
             if (mMultiInstanceHelpher.supportsMultiInstanceSplit(
                     getShortcutComponent(packageName, shortcutId, user, mLauncherApps))) {
                 activityOptions.setApplyMultipleTaskFlagForShortcut(true);
@@ -676,10 +685,11 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
      * See {@link #startIntent(PendingIntent, int, Intent, int, Bundle)}
      * @param instanceId to be used by {@link SplitscreenEventLogger}
      */
-    public void startIntent(PendingIntent intent, int userId, @Nullable Intent fillInIntent,
-            @SplitPosition int position, @Nullable Bundle options, @NonNull InstanceId instanceId) {
+    public void startIntentWithInstanceId(PendingIntent intent, int userId,
+            @Nullable Intent fillInIntent, @SplitPosition int position, @Nullable Bundle options,
+            @NonNull InstanceId instanceId) {
         mStageCoordinator.onRequestToSplit(instanceId, ENTER_REASON_LAUNCHER);
-        startIntent(intent, userId, fillInIntent, position, options);
+        startIntent(intent, userId, fillInIntent, position, options, null /* hideTaskToken */);
     }
 
     private void startIntentAndTaskWithLegacyTransition(PendingIntent pendingIntent, int userId1,
@@ -825,9 +835,15 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
                 instanceId);
     }
 
+    /**
+     * Starts the given intent into split.
+     * @param hideTaskToken If non-null, a task matching this token will be moved to back in the
+     *                      same window container transaction as the starting of the intent.
+     */
     @Override
     public void startIntent(PendingIntent intent, int userId1, @Nullable Intent fillInIntent,
-            @SplitPosition int position, @Nullable Bundle options) {
+            @SplitPosition int position, @Nullable Bundle options,
+            @Nullable WindowContainerToken hideTaskToken) {
         ProtoLog.v(ShellProtoLogGroup.WM_SHELL_SPLIT_SCREEN,
                 "startIntent(): intent=%s user=%d fillInIntent=%s position=%d", intent, userId1,
                 fillInIntent, position);
@@ -838,23 +854,24 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
         fillInIntent.addFlags(FLAG_ACTIVITY_NO_USER_ACTION);
 
         final String packageName1 = SplitScreenUtils.getPackageName(intent);
-        final String packageName2 = getPackageName(reverseSplitPosition(position));
-        final int userId2 = getUserId(reverseSplitPosition(position));
+        final String packageName2 = getPackageName(reverseSplitPosition(position), hideTaskToken);
+        final int userId2 = getUserId(reverseSplitPosition(position), hideTaskToken);
         final ComponentName component = intent.getIntent().getComponent();
 
         // To prevent accumulating large number of instances in the background, reuse task
         // in the background. If we don't explicitly reuse, new may be created even if the app
         // isn't multi-instance because WM won't automatically remove/reuse the previous instance
         final ActivityManager.RecentTaskInfo taskInfo = mRecentTasksOptional
-                .map(recentTasks -> recentTasks.findTaskInBackground(component, userId1))
+                .map(recentTasks -> recentTasks.findTaskInBackground(component, userId1,
+                        hideTaskToken))
                 .orElse(null);
         if (taskInfo != null) {
             ProtoLog.v(ShellProtoLogGroup.WM_SHELL_SPLIT_SCREEN,
                     "Found suitable background task=%s", taskInfo);
             if (ENABLE_SHELL_TRANSITIONS) {
-                mStageCoordinator.startTask(taskInfo.taskId, position, options);
+                mStageCoordinator.startTask(taskInfo.taskId, position, options, hideTaskToken);
             } else {
-                startTask(taskInfo.taskId, position, options);
+                startTask(taskInfo.taskId, position, options, hideTaskToken);
             }
             ProtoLog.v(ShellProtoLogGroup.WM_SHELL_SPLIT_SCREEN, "Start task in background");
             return;
@@ -879,19 +896,23 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
             }
         }
 
-        mStageCoordinator.startIntent(intent, fillInIntent, position, options);
+        mStageCoordinator.startIntent(intent, fillInIntent, position, options, hideTaskToken);
     }
 
-    /** Retrieve package name of a specific split position if split screen is activated, otherwise
-     *  returns the package name of the top running task. */
+    /**
+     * Retrieve package name of a specific split position if split screen is activated, otherwise
+     * returns the package name of the top running task.
+     * TODO(b/351900580): Merge this with getUserId() so we don't make multiple binder calls
+     */
     @Nullable
-    private String getPackageName(@SplitPosition int position) {
+    private String getPackageName(@SplitPosition int position,
+            @Nullable WindowContainerToken ignoreTaskToken) {
         ActivityManager.RunningTaskInfo taskInfo;
         if (isSplitScreenVisible()) {
             taskInfo = getTaskInfo(position);
         } else {
             taskInfo = mRecentTasksOptional
-                    .map(recentTasks -> recentTasks.getTopRunningTask())
+                    .map(recentTasks -> recentTasks.getTopRunningTask(ignoreTaskToken))
                     .orElse(null);
             if (!isValidToSplit(taskInfo)) {
                 return null;
@@ -901,15 +922,19 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
         return taskInfo != null ? SplitScreenUtils.getPackageName(taskInfo.baseIntent) : null;
     }
 
-    /** Retrieve user id of a specific split position if split screen is activated, otherwise
-     *  returns the user id of the top running task. */
-    private int getUserId(@SplitPosition int position) {
+    /**
+     * Retrieve user id of a specific split position if split screen is activated, otherwise
+     * returns the user id of the top running task.
+     * TODO: Merge this with getPackageName() so we don't make multiple binder calls
+     */
+    private int getUserId(@SplitPosition int position,
+            @Nullable WindowContainerToken ignoreTaskToken) {
         ActivityManager.RunningTaskInfo taskInfo;
         if (isSplitScreenVisible()) {
             taskInfo = getTaskInfo(position);
         } else {
             taskInfo = mRecentTasksOptional
-                    .map(recentTasks -> recentTasks.getTopRunningTask())
+                    .map(recentTasks -> recentTasks.getTopRunningTask(ignoreTaskToken))
                     .orElse(null);
             if (!isValidToSplit(taskInfo)) {
                 return -1;
@@ -1290,7 +1315,8 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
         @Override
         public void startTask(int taskId, int position, @Nullable Bundle options) {
             executeRemoteCallWithTaskPermission(mController, "startTask",
-                    (controller) -> controller.startTask(taskId, position, options));
+                    (controller) -> controller.startTask(taskId, position, options,
+                            null /* hideTaskToken */));
         }
 
         @Override
@@ -1402,8 +1428,8 @@ public class SplitScreenController implements DragAndDropPolicy.Starter,
         public void startIntent(PendingIntent intent, int userId, Intent fillInIntent, int position,
                 @Nullable Bundle options, InstanceId instanceId) {
             executeRemoteCallWithTaskPermission(mController, "startIntent",
-                    (controller) -> controller.startIntent(intent, userId, fillInIntent, position,
-                            options, instanceId));
+                    (controller) -> controller.startIntentWithInstanceId(intent, userId,
+                            fillInIntent, position, options, instanceId));
         }
 
         @Override
diff --git a/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java b/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java
index 4287daa03223..839700e5b8a2 100644
--- a/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java
+++ b/libs/WindowManager/Shell/src/com/android/wm/shell/splitscreen/StageCoordinator.java
@@ -592,12 +592,21 @@ public class StageCoordinator implements SplitLayout.SplitLayoutHandler,
         }
     }
 
-    /** Use this method to launch an existing Task via a taskId */
-    void startTask(int taskId, @SplitPosition int position, @Nullable Bundle options) {
+    /**
+     * Use this method to launch an existing Task via a taskId.
+     * @param hideTaskToken If non-null, a task matching this token will be moved to back in the
+     *                      same window container transaction as the starting of the intent.
+     */
+    void startTask(int taskId, @SplitPosition int position, @Nullable Bundle options,
+            @Nullable WindowContainerToken hideTaskToken) {
         ProtoLog.d(WM_SHELL_SPLIT_SCREEN, "startTask: task=%d position=%d", taskId, position);
         mSplitRequest = new SplitRequest(taskId, position);
         final WindowContainerTransaction wct = new WindowContainerTransaction();
         options = resolveStartStage(STAGE_TYPE_UNDEFINED, position, options, null /* wct */);
+        if (hideTaskToken != null) {
+            ProtoLog.d(WM_SHELL_SPLIT_SCREEN, "Reordering hide-task to bottom");
+            wct.reorder(hideTaskToken, false /* onTop */);
+        }
         wct.startTask(taskId, options);
         // If this should be mixed, send the task to avoid split handle transition directly.
         if (mMixedHandler != null && mMixedHandler.isTaskInPip(taskId, mTaskOrganizer)) {
@@ -623,9 +632,13 @@ public class StageCoordinator implements SplitLayout.SplitLayoutHandler,
                 extraTransitType, !mIsDropEntering);
     }
 
-    /** Launches an activity into split. */
+    /**
+     * Launches an activity into split.
+     * @param hideTaskToken If non-null, a task matching this token will be moved to back in the
+     *                      same window container transaction as the starting of the intent.
+     */
     void startIntent(PendingIntent intent, Intent fillInIntent, @SplitPosition int position,
-            @Nullable Bundle options) {
+            @Nullable Bundle options, @Nullable WindowContainerToken hideTaskToken) {
         ProtoLog.d(WM_SHELL_SPLIT_SCREEN, "startIntent: intent=%s position=%d", intent.getIntent(),
                 position);
         mSplitRequest = new SplitRequest(intent.getIntent(), position);
@@ -636,6 +649,10 @@ public class StageCoordinator implements SplitLayout.SplitLayoutHandler,
 
         final WindowContainerTransaction wct = new WindowContainerTransaction();
         options = resolveStartStage(STAGE_TYPE_UNDEFINED, position, options, null /* wct */);
+        if (hideTaskToken != null) {
+            ProtoLog.d(WM_SHELL_SPLIT_SCREEN, "Reordering hide-task to bottom");
+            wct.reorder(hideTaskToken, false /* onTop */);
+        }
         wct.sendPendingIntent(intent, fillInIntent, options);
 
         // If this should be mixed, just send the intent to avoid split handle transition directly.
diff --git a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/ShellTaskOrganizerTests.java b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/ShellTaskOrganizerTests.java
index f9b4108bc8c2..8303317d39fc 100644
--- a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/ShellTaskOrganizerTests.java
+++ b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/ShellTaskOrganizerTests.java
@@ -687,6 +687,25 @@ public class ShellTaskOrganizerTests extends ShellTestCase {
         verify(mRecentTasksController).onTaskRunningInfoChanged(task2);
     }
 
+    @Test
+    public void testTaskVanishedCallback() {
+        RunningTaskInfo task1 = createTaskInfo(/* taskId= */ 1, WINDOWING_MODE_FULLSCREEN);
+        mOrganizer.onTaskAppeared(task1, /* leash= */ null);
+
+        RunningTaskInfo[] vanishedTasks = new RunningTaskInfo[1];
+        ShellTaskOrganizer.TaskVanishedListener listener =
+                new ShellTaskOrganizer.TaskVanishedListener() {
+                    @Override
+                    public void onTaskVanished(RunningTaskInfo taskInfo) {
+                        vanishedTasks[0] = taskInfo;
+                    }
+                };
+        mOrganizer.addTaskVanishedListener(listener);
+        mOrganizer.onTaskVanished(task1);
+
+        assertEquals(vanishedTasks[0], task1);
+    }
+
     private static RunningTaskInfo createTaskInfo(int taskId, int windowingMode) {
         RunningTaskInfo taskInfo = new RunningTaskInfo();
         taskInfo.taskId = taskId;
diff --git a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropControllerTest.java b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropControllerTest.java
index a64ebd301c00..840126421c08 100644
--- a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropControllerTest.java
+++ b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropControllerTest.java
@@ -76,6 +76,8 @@ public class DragAndDropControllerTest extends ShellTestCase {
     @Mock
     private ShellCommandHandler mShellCommandHandler;
     @Mock
+    private ShellTaskOrganizer mShellTaskOrganizer;
+    @Mock
     private DisplayController mDisplayController;
     @Mock
     private UiEventLogger mUiEventLogger;
@@ -96,8 +98,8 @@ public class DragAndDropControllerTest extends ShellTestCase {
     public void setUp() throws RemoteException {
         MockitoAnnotations.initMocks(this);
         mController = new DragAndDropController(mContext, mShellInit, mShellController,
-                mShellCommandHandler, mDisplayController, mUiEventLogger, mIconProvider,
-                mGlobalDragListener, mTransitions, mMainExecutor);
+                mShellCommandHandler, mShellTaskOrganizer, mDisplayController, mUiEventLogger,
+                mIconProvider, mGlobalDragListener, mTransitions, mMainExecutor);
         mController.onInit();
     }
 
diff --git a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropPolicyTest.java b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropPolicyTest.java
index 6e72e8df8d62..97fa8d6ceca9 100644
--- a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropPolicyTest.java
+++ b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/draganddrop/DragAndDropPolicyTest.java
@@ -65,8 +65,6 @@ import android.content.res.Resources;
 import android.graphics.Insets;
 import android.os.RemoteException;
 import android.view.DisplayInfo;
-import android.view.DragEvent;
-import android.view.View;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
@@ -76,7 +74,6 @@ import com.android.wm.shell.ShellTestCase;
 import com.android.wm.shell.common.DisplayLayout;
 import com.android.wm.shell.draganddrop.DragAndDropPolicy.Target;
 import com.android.wm.shell.splitscreen.SplitScreenController;
-import com.android.wm.shell.startingsurface.TaskSnapshotWindow;
 
 import org.junit.After;
 import org.junit.Before;
@@ -106,6 +103,8 @@ public class DragAndDropPolicyTest extends ShellTestCase {
     // Both the split-screen and start interface.
     @Mock
     private SplitScreenController mSplitScreenStarter;
+    @Mock
+    private DragAndDropPolicy.Starter mFullscreenStarter;
 
     @Mock
     private InstanceId mLoggerSessionId;
@@ -151,7 +150,7 @@ public class DragAndDropPolicyTest extends ShellTestCase {
         mPortraitDisplayLayout = new DisplayLayout(info2, res, false, false);
         mInsets = Insets.of(0, 0, 0, 0);
 
-        mPolicy = spy(new DragAndDropPolicy(mContext, mSplitScreenStarter, mSplitScreenStarter));
+        mPolicy = spy(new DragAndDropPolicy(mContext, mSplitScreenStarter, mFullscreenStarter));
         mActivityClipData = createAppClipData(MIMETYPE_APPLICATION_ACTIVITY);
         mLaunchableIntentPendingIntent = mock(PendingIntent.class);
         when(mLaunchableIntentPendingIntent.getCreatorUserHandle())
@@ -285,14 +284,14 @@ public class DragAndDropPolicyTest extends ShellTestCase {
         setRunningTask(mHomeTask);
         DragSession dragSession = new DragSession(mActivityTaskManager,
                 mLandscapeDisplayLayout, data, 0 /* dragFlags */);
-        dragSession.update();
+        dragSession.initialize();
         mPolicy.start(dragSession, mLoggerSessionId);
         ArrayList<Target> targets = assertExactTargetTypes(
                 mPolicy.getTargets(mInsets), TYPE_FULLSCREEN);
 
-        mPolicy.handleDrop(filterTargetByType(targets, TYPE_FULLSCREEN));
-        verify(mSplitScreenStarter).startIntent(any(), anyInt(), any(),
-                eq(SPLIT_POSITION_UNDEFINED), any());
+        mPolicy.handleDrop(filterTargetByType(targets, TYPE_FULLSCREEN), null /* hideTaskToken */);
+        verify(mFullscreenStarter).startIntent(any(), anyInt(), any(),
+                eq(SPLIT_POSITION_UNDEFINED), any(), any());
     }
 
     private void dragOverFullscreenApp_expectSplitScreenTargets(ClipData data) {
@@ -300,19 +299,19 @@ public class DragAndDropPolicyTest extends ShellTestCase {
         setRunningTask(mFullscreenAppTask);
         DragSession dragSession = new DragSession(mActivityTaskManager,
                 mLandscapeDisplayLayout, data, 0 /* dragFlags */);
-        dragSession.update();
+        dragSession.initialize();
         mPolicy.start(dragSession, mLoggerSessionId);
         ArrayList<Target> targets = assertExactTargetTypes(
                 mPolicy.getTargets(mInsets), TYPE_SPLIT_LEFT, TYPE_SPLIT_RIGHT);
 
-        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_LEFT));
+        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_LEFT), null /* hideTaskToken */);
         verify(mSplitScreenStarter).startIntent(any(), anyInt(), any(),
-                eq(SPLIT_POSITION_TOP_OR_LEFT), any());
+                eq(SPLIT_POSITION_TOP_OR_LEFT), any(), any());
         reset(mSplitScreenStarter);
 
-        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_RIGHT));
+        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_RIGHT), null /* hideTaskToken */);
         verify(mSplitScreenStarter).startIntent(any(), anyInt(), any(),
-                eq(SPLIT_POSITION_BOTTOM_OR_RIGHT), any());
+                eq(SPLIT_POSITION_BOTTOM_OR_RIGHT), any(), any());
     }
 
     private void dragOverFullscreenAppPhone_expectVerticalSplitScreenTargets(ClipData data) {
@@ -320,19 +319,20 @@ public class DragAndDropPolicyTest extends ShellTestCase {
         setRunningTask(mFullscreenAppTask);
         DragSession dragSession = new DragSession(mActivityTaskManager,
                 mPortraitDisplayLayout, data, 0 /* dragFlags */);
-        dragSession.update();
+        dragSession.initialize();
         mPolicy.start(dragSession, mLoggerSessionId);
         ArrayList<Target> targets = assertExactTargetTypes(
                 mPolicy.getTargets(mInsets), TYPE_SPLIT_TOP, TYPE_SPLIT_BOTTOM);
 
-        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_TOP));
+        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_TOP), null /* hideTaskToken */);
         verify(mSplitScreenStarter).startIntent(any(), anyInt(), any(),
-                eq(SPLIT_POSITION_TOP_OR_LEFT), any());
+                eq(SPLIT_POSITION_TOP_OR_LEFT), any(), any());
         reset(mSplitScreenStarter);
 
-        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_BOTTOM));
+        mPolicy.handleDrop(filterTargetByType(targets, TYPE_SPLIT_BOTTOM),
+                null /* hideTaskToken */);
         verify(mSplitScreenStarter).startIntent(any(), anyInt(), any(),
-                eq(SPLIT_POSITION_BOTTOM_OR_RIGHT), any());
+                eq(SPLIT_POSITION_BOTTOM_OR_RIGHT), any(), any());
     }
 
     @Test
@@ -340,7 +340,7 @@ public class DragAndDropPolicyTest extends ShellTestCase {
         setRunningTask(mFullscreenAppTask);
         DragSession dragSession = new DragSession(mActivityTaskManager,
                 mLandscapeDisplayLayout, mActivityClipData, 0 /* dragFlags */);
-        dragSession.update();
+        dragSession.initialize();
         mPolicy.start(dragSession, mLoggerSessionId);
         ArrayList<Target> targets = mPolicy.getTargets(mInsets);
         for (Target t : targets) {
diff --git a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/splitscreen/SplitScreenControllerTests.java b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/splitscreen/SplitScreenControllerTests.java
index 3c387f0d7c34..5b95b1588814 100644
--- a/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/splitscreen/SplitScreenControllerTests.java
+++ b/libs/WindowManager/Shell/tests/unittest/src/com/android/wm/shell/splitscreen/SplitScreenControllerTests.java
@@ -36,6 +36,7 @@ import static org.mockito.ArgumentMatchers.isA;
 import static org.mockito.ArgumentMatchers.isNull;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -49,6 +50,9 @@ import android.content.ComponentName;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
 import android.os.Bundle;
+import android.os.IBinder;
+import android.window.IWindowContainerToken;
+import android.window.WindowContainerToken;
 
 import androidx.test.annotation.UiThreadTest;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
@@ -195,10 +199,10 @@ public class SplitScreenControllerTests extends ShellTestCase {
                 PendingIntent.getActivity(mContext, 0, startIntent, FLAG_IMMUTABLE);
 
         mSplitScreenController.startIntent(pendingIntent, mContext.getUserId(), null,
-                SPLIT_POSITION_TOP_OR_LEFT, null);
+                SPLIT_POSITION_TOP_OR_LEFT, null /* options */, null /* hideTaskToken */);
 
         verify(mStageCoordinator).startIntent(eq(pendingIntent), mIntentCaptor.capture(),
-                eq(SPLIT_POSITION_TOP_OR_LEFT), isNull());
+                eq(SPLIT_POSITION_TOP_OR_LEFT), isNull(), isNull());
         assertEquals(FLAG_ACTIVITY_NO_USER_ACTION,
                 mIntentCaptor.getValue().getFlags() & FLAG_ACTIVITY_NO_USER_ACTION);
     }
@@ -213,19 +217,20 @@ public class SplitScreenControllerTests extends ShellTestCase {
         ActivityManager.RunningTaskInfo topRunningTask =
                 createTaskInfo(WINDOWING_MODE_FULLSCREEN, ACTIVITY_TYPE_STANDARD, startIntent);
         doReturn(topRunningTask).when(mRecentTasks).getTopRunningTask();
+        doReturn(topRunningTask).when(mRecentTasks).getTopRunningTask(any());
 
         mSplitScreenController.startIntent(pendingIntent, mContext.getUserId(), null,
-                SPLIT_POSITION_TOP_OR_LEFT, null);
+                SPLIT_POSITION_TOP_OR_LEFT, null /* options */, null /* hideTaskToken */);
 
         verify(mStageCoordinator).startIntent(eq(pendingIntent), mIntentCaptor.capture(),
-                eq(SPLIT_POSITION_TOP_OR_LEFT), isNull());
+                eq(SPLIT_POSITION_TOP_OR_LEFT), isNull(), isNull());
         assertEquals(FLAG_ACTIVITY_MULTIPLE_TASK,
                 mIntentCaptor.getValue().getFlags() & FLAG_ACTIVITY_MULTIPLE_TASK);
     }
 
     @Test
     public void startIntent_multiInstancesNotSupported_startTaskInBackgroundBeforeSplitActivated() {
-        doNothing().when(mSplitScreenController).startTask(anyInt(), anyInt(), any());
+        doNothing().when(mSplitScreenController).startTask(anyInt(), anyInt(), any(), any());
         Intent startIntent = createStartIntent("startActivity");
         PendingIntent pendingIntent =
                 PendingIntent.getActivity(mContext, 0, startIntent, FLAG_IMMUTABLE);
@@ -233,15 +238,16 @@ public class SplitScreenControllerTests extends ShellTestCase {
         ActivityManager.RunningTaskInfo topRunningTask =
                 createTaskInfo(WINDOWING_MODE_FULLSCREEN, ACTIVITY_TYPE_STANDARD, startIntent);
         doReturn(topRunningTask).when(mRecentTasks).getTopRunningTask();
+        doReturn(topRunningTask).when(mRecentTasks).getTopRunningTask(any());
         // Put the same component into a task in the background
         ActivityManager.RecentTaskInfo sameTaskInfo = new ActivityManager.RecentTaskInfo();
-        doReturn(sameTaskInfo).when(mRecentTasks).findTaskInBackground(any(), anyInt());
+        doReturn(sameTaskInfo).when(mRecentTasks).findTaskInBackground(any(), anyInt(), any());
 
         mSplitScreenController.startIntent(pendingIntent, mContext.getUserId(), null,
-                SPLIT_POSITION_TOP_OR_LEFT, null);
+                SPLIT_POSITION_TOP_OR_LEFT, null /* options */, null /* hideTaskToken */);
 
         verify(mStageCoordinator).startTask(anyInt(), eq(SPLIT_POSITION_TOP_OR_LEFT),
-                isNull());
+                isNull(), isNull());
         verify(mMultiInstanceHelper, never()).supportsMultiInstanceSplit(any());
         verify(mStageCoordinator, never()).switchSplitPosition(any());
     }
@@ -249,7 +255,7 @@ public class SplitScreenControllerTests extends ShellTestCase {
     @Test
     public void startIntent_multiInstancesSupported_startTaskInBackgroundAfterSplitActivated() {
         doReturn(true).when(mMultiInstanceHelper).supportsMultiInstanceSplit(any());
-        doNothing().when(mSplitScreenController).startTask(anyInt(), anyInt(), any());
+        doNothing().when(mSplitScreenController).startTask(anyInt(), anyInt(), any(), any());
         Intent startIntent = createStartIntent("startActivity");
         PendingIntent pendingIntent =
                 PendingIntent.getActivity(mContext, 0, startIntent, FLAG_IMMUTABLE);
@@ -261,13 +267,13 @@ public class SplitScreenControllerTests extends ShellTestCase {
                 SPLIT_POSITION_BOTTOM_OR_RIGHT);
         // Put the same component into a task in the background
         doReturn(new ActivityManager.RecentTaskInfo()).when(mRecentTasks)
-                .findTaskInBackground(any(), anyInt());
+                .findTaskInBackground(any(), anyInt(), any());
 
         mSplitScreenController.startIntent(pendingIntent, mContext.getUserId(), null,
-                SPLIT_POSITION_TOP_OR_LEFT, null);
+                SPLIT_POSITION_TOP_OR_LEFT, null /* options */, null /* hideTaskToken */);
         verify(mMultiInstanceHelper, never()).supportsMultiInstanceSplit(any());
         verify(mStageCoordinator).startTask(anyInt(), eq(SPLIT_POSITION_TOP_OR_LEFT),
-                isNull());
+                isNull(), isNull());
     }
 
     @Test
@@ -284,7 +290,7 @@ public class SplitScreenControllerTests extends ShellTestCase {
                 SPLIT_POSITION_BOTTOM_OR_RIGHT);
 
         mSplitScreenController.startIntent(pendingIntent, mContext.getUserId(), null,
-                SPLIT_POSITION_TOP_OR_LEFT, null);
+                SPLIT_POSITION_TOP_OR_LEFT, null /* options */, null /* hideTaskToken */);
 
         verify(mStageCoordinator).switchSplitPosition(anyString());
     }
@@ -312,6 +318,7 @@ public class SplitScreenControllerTests extends ShellTestCase {
         info.supportsMultiWindow = true;
         info.baseIntent = strIntent;
         info.baseActivity = strIntent.getComponent();
+        info.token = new WindowContainerToken(mock(IWindowContainerToken.class));
         ActivityInfo activityInfo = new ActivityInfo();
         activityInfo.packageName = info.baseActivity.getPackageName();
         activityInfo.name = info.baseActivity.getClassName();
diff --git a/packages/ExternalStorageProvider/src/com/android/externalstorage/ExternalStorageProvider.java b/packages/ExternalStorageProvider/src/com/android/externalstorage/ExternalStorageProvider.java
index 3409c29d3c2c..defbc1142adb 100644
--- a/packages/ExternalStorageProvider/src/com/android/externalstorage/ExternalStorageProvider.java
+++ b/packages/ExternalStorageProvider/src/com/android/externalstorage/ExternalStorageProvider.java
@@ -16,8 +16,6 @@
 
 package com.android.externalstorage;
 
-import static java.util.regex.Pattern.CASE_INSENSITIVE;
-
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.app.usage.StorageStatsManager;
@@ -61,12 +59,15 @@ import java.io.FileDescriptor;
 import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.io.PrintWriter;
+import java.nio.file.Files;
+import java.nio.file.Paths;
+import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
 import java.util.Locale;
 import java.util.Objects;
 import java.util.UUID;
-import java.util.regex.Pattern;
+import java.util.stream.Collectors;
 
 /**
  * Presents content of the shared (a.k.a. "external") storage.
@@ -89,12 +90,9 @@ public class ExternalStorageProvider extends FileSystemProvider {
     private static final Uri BASE_URI =
             new Uri.Builder().scheme(ContentResolver.SCHEME_CONTENT).authority(AUTHORITY).build();
 
-    /**
-     * Regex for detecting {@code /Android/data/}, {@code /Android/obb/} and
-     * {@code /Android/sandbox/} along with all their subdirectories and content.
-     */
-    private static final Pattern PATTERN_RESTRICTED_ANDROID_SUBTREES =
-            Pattern.compile("^Android/(?:data|obb|sandbox)(?:/.+)?", CASE_INSENSITIVE);
+    private static final String PRIMARY_EMULATED_STORAGE_PATH = "/storage/emulated/";
+
+    private static final String STORAGE_PATH = "/storage/";
 
     private static final String[] DEFAULT_ROOT_PROJECTION = new String[] {
             Root.COLUMN_ROOT_ID, Root.COLUMN_FLAGS, Root.COLUMN_ICON, Root.COLUMN_TITLE,
@@ -309,10 +307,69 @@ public class ExternalStorageProvider extends FileSystemProvider {
             return false;
         }
 
-        final String path = getPathFromDocId(documentId);
-        return PATTERN_RESTRICTED_ANDROID_SUBTREES.matcher(path).matches();
+        try {
+            final RootInfo root = getRootFromDocId(documentId);
+            final String canonicalPath = getPathFromDocId(documentId);
+            return isRestrictedPath(root.rootId, canonicalPath);
+        } catch (Exception e) {
+            return true;
+        }
     }
 
+    /**
+     * Based on the given root id and path, we restrict path access if file is Android/data or
+     * Android/obb or Android/sandbox or one of their subdirectories.
+     *
+     * @param canonicalPath of the file
+     * @return true if path is restricted
+     */
+    private boolean isRestrictedPath(String rootId, String canonicalPath) {
+        if (rootId == null || canonicalPath == null) {
+            return true;
+        }
+
+        final String rootPath;
+        if (rootId.equalsIgnoreCase(ROOT_ID_PRIMARY_EMULATED)) {
+            // Creates "/storage/emulated/<user-id>"
+            rootPath = PRIMARY_EMULATED_STORAGE_PATH + UserHandle.myUserId();
+        } else {
+            // Creates "/storage/<volume-uuid>"
+            rootPath = STORAGE_PATH + rootId;
+        }
+        List<java.nio.file.Path> restrictedPathList = Arrays.asList(
+                Paths.get(rootPath, "Android", "data"),
+                Paths.get(rootPath, "Android", "obb"),
+                Paths.get(rootPath, "Android", "sandbox"));
+        // We need to identify restricted parent paths which actually exist on the device
+        List<java.nio.file.Path> validRestrictedPathsToCheck = restrictedPathList.stream().filter(
+                Files::exists).collect(Collectors.toList());
+
+        boolean isRestricted = false;
+        java.nio.file.Path filePathToCheck = Paths.get(rootPath, canonicalPath);
+        try {
+            while (filePathToCheck != null) {
+                for (java.nio.file.Path restrictedPath : validRestrictedPathsToCheck) {
+                    if (Files.isSameFile(restrictedPath, filePathToCheck)) {
+                        isRestricted = true;
+                        Log.v(TAG, "Restricting access for path: " + filePathToCheck);
+                        break;
+                    }
+                }
+                if (isRestricted) {
+                    break;
+                }
+
+                filePathToCheck = filePathToCheck.getParent();
+            }
+        } catch (Exception e) {
+            Log.w(TAG, "Error in checking file equality check.", e);
+            isRestricted = true;
+        }
+
+        return isRestricted;
+    }
+
+
     /**
      * Check that the directory is the root of storage or blocked file from tree.
      * <p>
diff --git a/packages/SystemUI/src/com/android/keyguard/KeyguardStatusView.java b/packages/SystemUI/src/com/android/keyguard/KeyguardStatusView.java
index d8486029a903..073f33fe5245 100644
--- a/packages/SystemUI/src/com/android/keyguard/KeyguardStatusView.java
+++ b/packages/SystemUI/src/com/android/keyguard/KeyguardStatusView.java
@@ -33,7 +33,6 @@ import com.android.systemui.res.R;
 import com.android.systemui.shade.TouchLogger;
 import com.android.systemui.statusbar.CrossFadeHelper;
 
-import java.io.PrintWriter;
 import java.util.Set;
 
 /**
@@ -117,18 +116,6 @@ public class KeyguardStatusView extends GridLayout {
         return TouchLogger.logDispatchTouch(TAG, ev, super.dispatchTouchEvent(ev));
     }
 
-    public void dump(PrintWriter pw, String[] args) {
-        pw.println("KeyguardStatusView:");
-        pw.println("  mDarkAmount: " + mDarkAmount);
-        pw.println("  visibility: " + getVisibility());
-        if (mClockView != null) {
-            mClockView.dump(pw, args);
-        }
-        if (mKeyguardSlice != null) {
-            mKeyguardSlice.dump(pw, args);
-        }
-    }
-
     @Override
     public ViewPropertyAnimator animate() {
         if (Build.IS_DEBUGGABLE) {
diff --git a/packages/SystemUI/src/com/android/keyguard/KeyguardStatusViewController.java b/packages/SystemUI/src/com/android/keyguard/KeyguardStatusViewController.java
index 603a47e8d26e..63a4af949c8c 100644
--- a/packages/SystemUI/src/com/android/keyguard/KeyguardStatusViewController.java
+++ b/packages/SystemUI/src/com/android/keyguard/KeyguardStatusViewController.java
@@ -48,9 +48,7 @@ import com.android.app.animation.Interpolators;
 import com.android.internal.jank.InteractionJankMonitor;
 import com.android.keyguard.KeyguardClockSwitch.ClockSize;
 import com.android.keyguard.logging.KeyguardLogger;
-import com.android.systemui.Dumpable;
 import com.android.systemui.animation.ViewHierarchyAnimator;
-import com.android.systemui.dump.DumpManager;
 import com.android.systemui.keyguard.MigrateClocksToBlueprint;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
 import com.android.systemui.plugins.clocks.ClockController;
@@ -70,15 +68,12 @@ import com.android.systemui.util.ViewController;
 import kotlin.coroutines.CoroutineContext;
 import kotlin.coroutines.EmptyCoroutineContext;
 
-import java.io.PrintWriter;
-
 import javax.inject.Inject;
 
 /**
  * Injectable controller for {@link KeyguardStatusView}.
  */
-public class KeyguardStatusViewController extends ViewController<KeyguardStatusView> implements
-        Dumpable {
+public class KeyguardStatusViewController extends ViewController<KeyguardStatusView> {
     private static final boolean DEBUG = KeyguardConstants.DEBUG;
     @VisibleForTesting static final String TAG = "KeyguardStatusViewController";
     private static final long STATUS_AREA_HEIGHT_ANIMATION_MILLIS = 133;
@@ -108,7 +103,6 @@ public class KeyguardStatusViewController extends ViewController<KeyguardStatusV
 
     private Boolean mSplitShadeEnabled = false;
     private Boolean mStatusViewCentered = true;
-    private DumpManager mDumpManager;
 
     private final TransitionListenerAdapter mKeyguardStatusAlignmentTransitionListener =
             new TransitionListenerAdapter() {
@@ -176,7 +170,6 @@ public class KeyguardStatusViewController extends ViewController<KeyguardStatusV
             KeyguardLogger logger,
             InteractionJankMonitor interactionJankMonitor,
             KeyguardInteractor keyguardInteractor,
-            DumpManager dumpManager,
             PowerInteractor powerInteractor) {
         super(keyguardStatusView);
         mKeyguardSliceViewController = keyguardSliceViewController;
@@ -188,7 +181,6 @@ public class KeyguardStatusViewController extends ViewController<KeyguardStatusV
                 dozeParameters, screenOffAnimationController, /* animateYPos= */ true,
                 logger.getBuffer());
         mInteractionJankMonitor = interactionJankMonitor;
-        mDumpManager = dumpManager;
         mKeyguardInteractor = keyguardInteractor;
         mPowerInteractor = powerInteractor;
     }
@@ -222,7 +214,6 @@ public class KeyguardStatusViewController extends ViewController<KeyguardStatusV
                     });
         }
 
-        mDumpManager.registerDumpable(getInstanceName(), this);
         if (MigrateClocksToBlueprint.isEnabled()) {
             startCoroutines(EmptyCoroutineContext.INSTANCE);
             mView.setVisibility(View.GONE);
@@ -275,13 +266,6 @@ public class KeyguardStatusViewController extends ViewController<KeyguardStatusV
         mKeyguardClockSwitchController.setShownOnSecondaryDisplay(true);
     }
 
-    /**
-     * Called in notificationPanelViewController to avoid leak
-     */
-    public void onDestroy() {
-        mDumpManager.unregisterDumpable(getInstanceName());
-    }
-
     /**
      * Updates views on doze time tick.
      */
@@ -604,11 +588,6 @@ public class KeyguardStatusViewController extends ViewController<KeyguardStatusV
         return mKeyguardClockSwitchController.getClock();
     }
 
-    @Override
-    public void dump(@NonNull PrintWriter pw, @NonNull String[] args) {
-        mView.dump(pw, args);
-    }
-
     String getInstanceName() {
         return TAG + "#" + hashCode();
     }
diff --git a/packages/SystemUI/src/com/android/systemui/shade/NotificationPanelViewController.java b/packages/SystemUI/src/com/android/systemui/shade/NotificationPanelViewController.java
index fff5e104a7ab..6e74c1ed385c 100644
--- a/packages/SystemUI/src/com/android/systemui/shade/NotificationPanelViewController.java
+++ b/packages/SystemUI/src/com/android/systemui/shade/NotificationPanelViewController.java
@@ -1306,10 +1306,6 @@ public final class NotificationPanelViewController implements ShadeSurface, Dump
     /** Updates the StatusBarViewController and updates any that depend on it. */
     public void updateStatusViewController() {
         // Re-associate the KeyguardStatusViewController
-        if (mKeyguardStatusViewController != null) {
-            mKeyguardStatusViewController.onDestroy();
-        }
-
         if (MigrateClocksToBlueprint.isEnabled()) {
             // Need a shared controller until mKeyguardStatusViewController can be removed from
             // here, due to important state being set in that controller. Rebind in order to pick
diff --git a/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerBaseTest.java b/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerBaseTest.java
index 07504c732bc2..2b4fc5bd5cc5 100644
--- a/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerBaseTest.java
+++ b/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerBaseTest.java
@@ -26,7 +26,6 @@ import android.widget.FrameLayout;
 
 import com.android.keyguard.logging.KeyguardLogger;
 import com.android.systemui.SysuiTestCase;
-import com.android.systemui.dump.DumpManager;
 import com.android.systemui.keyguard.data.repository.FakeKeyguardRepository;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractorFactory;
 import com.android.systemui.kosmos.KosmosJavaAdapter;
@@ -59,7 +58,6 @@ public class KeyguardStatusViewControllerBaseTest extends SysuiTestCase {
     @Mock protected KeyguardLogger mKeyguardLogger;
     @Mock protected KeyguardStatusViewController mControllerMock;
     @Mock protected ViewTreeObserver mViewTreeObserver;
-    @Mock protected DumpManager mDumpManager;
     protected FakeKeyguardRepository mFakeKeyguardRepository;
     protected FakePowerRepository mFakePowerRepository;
 
@@ -90,7 +88,6 @@ public class KeyguardStatusViewControllerBaseTest extends SysuiTestCase {
                 mKeyguardLogger,
                 mKosmos.getInteractionJankMonitor(),
                 deps.getKeyguardInteractor(),
-                mDumpManager,
                 PowerInteractorFactory.create(
                         mFakePowerRepository
                 ).getPowerInteractor()) {
diff --git a/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerTest.java b/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerTest.java
index 0696a4b880d5..8e441a3db242 100644
--- a/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerTest.java
+++ b/packages/SystemUI/tests/src/com/android/keyguard/KeyguardStatusViewControllerTest.java
@@ -139,14 +139,6 @@ public class KeyguardStatusViewControllerTest extends KeyguardStatusViewControll
         verify(mKeyguardClockSwitchController, times(0)).setSplitShadeEnabled(true);
     }
 
-    @Test
-    public void correctlyDump() {
-        mController.onInit();
-        verify(mDumpManager).registerDumpable(eq(mController.getInstanceName()), eq(mController));
-        mController.onDestroy();
-        verify(mDumpManager, times(1)).unregisterDumpable(eq(mController.getInstanceName()));
-    }
-
     @Test
     public void onInit_addsOnLayoutChangeListenerToClockSwitch() {
         when(mKeyguardStatusView.findViewById(R.id.status_view_media_container)).thenReturn(
diff --git a/packages/SystemUI/tests/src/com/android/systemui/shade/NotificationPanelViewControllerBaseTest.java b/packages/SystemUI/tests/src/com/android/systemui/shade/NotificationPanelViewControllerBaseTest.java
index c3cedf84a864..bf22a0c81167 100644
--- a/packages/SystemUI/tests/src/com/android/systemui/shade/NotificationPanelViewControllerBaseTest.java
+++ b/packages/SystemUI/tests/src/com/android/systemui/shade/NotificationPanelViewControllerBaseTest.java
@@ -479,7 +479,6 @@ public class NotificationPanelViewControllerBaseTest extends SysuiTestCase {
                 mKeyguardLogger,
                 mKosmos.getInteractionJankMonitor(),
                 mKeyguardInteractor,
-                mDumpManager,
                 mPowerInteractor));
 
         when(mAuthController.isUdfpsEnrolled(anyInt())).thenReturn(false);
diff --git a/services/core/java/com/android/server/accounts/AccountManagerService.java b/services/core/java/com/android/server/accounts/AccountManagerService.java
index 1d07bcae3f35..69478bbd0d44 100644
--- a/services/core/java/com/android/server/accounts/AccountManagerService.java
+++ b/services/core/java/com/android/server/accounts/AccountManagerService.java
@@ -1234,6 +1234,10 @@ public class AccountManagerService
                             obsoleteAuthType.add(type);
                             // And delete it from the TABLE_META
                             accountsDb.deleteMetaByAuthTypeAndUid(type, uid);
+                        } else if (knownUid != null && knownUid != uid) {
+                            Slog.w(TAG, "authenticator no longer exist for type " + type);
+                            obsoleteAuthType.add(type);
+                            accountsDb.deleteMetaByAuthTypeAndUid(type, uid);
                         }
                     }
                 }
diff --git a/services/core/java/com/android/server/am/ActivityManagerService.java b/services/core/java/com/android/server/am/ActivityManagerService.java
index d41de38ce2a8..46c963f009c7 100644
--- a/services/core/java/com/android/server/am/ActivityManagerService.java
+++ b/services/core/java/com/android/server/am/ActivityManagerService.java
@@ -4898,7 +4898,7 @@ public class ActivityManagerService extends IActivityManager.Stub
             if (!mConstants.mEnableWaitForFinishAttachApplication) {
                 finishAttachApplicationInner(startSeq, callingUid, pid);
             }
-            maybeSendBootCompletedLocked(app);
+            maybeSendBootCompletedLocked(app, isRestrictedBackupMode);
         } catch (Exception e) {
             // We need kill the process group here. (b/148588589)
             Slog.wtf(TAG, "Exception thrown during bind of " + app, e);
@@ -5143,7 +5143,7 @@ public class ActivityManagerService extends IActivityManager.Stub
      * Send LOCKED_BOOT_COMPLETED and BOOT_COMPLETED to the package explicitly when unstopped,
      * or when the package first starts in private space
      */
-    private void maybeSendBootCompletedLocked(ProcessRecord app) {
+    private void maybeSendBootCompletedLocked(ProcessRecord app, boolean isRestrictedBackupMode) {
         boolean sendBroadcast = false;
         if (android.os.Flags.allowPrivateProfile()
                 && android.multiuser.Flags.enablePrivateSpaceFeatures()) {
@@ -5169,6 +5169,9 @@ public class ActivityManagerService extends IActivityManager.Stub
                     RESTRICTION_REASON_USAGE, "unknown", RESTRICTION_SOURCE_USER, 0L);
         }
 
+        // Don't send BOOT_COMPLETED if currently in restricted backup mode
+        if (isRestrictedBackupMode) return;
+
         if (!sendBroadcast) {
             if (!android.content.pm.Flags.stayStopped()) return;
             // Nothing to do if it wasn't previously stopped
diff --git a/services/core/java/com/android/server/devicestate/DeviceStateManagerService.java b/services/core/java/com/android/server/devicestate/DeviceStateManagerService.java
index e8394d43f266..336ba0526668 100644
--- a/services/core/java/com/android/server/devicestate/DeviceStateManagerService.java
+++ b/services/core/java/com/android/server/devicestate/DeviceStateManagerService.java
@@ -47,6 +47,7 @@ import android.hardware.devicestate.DeviceStateManager;
 import android.hardware.devicestate.DeviceStateManagerInternal;
 import android.hardware.devicestate.IDeviceStateManager;
 import android.hardware.devicestate.IDeviceStateManagerCallback;
+import android.hardware.devicestate.feature.flags.Flags;
 import android.os.Binder;
 import android.os.Handler;
 import android.os.IBinder;
@@ -968,16 +969,16 @@ public final class DeviceStateManagerService extends SystemService {
      * @param callingPid Process ID that is requesting this state change
      * @param state state that is being requested.
      */
-    private void assertCanRequestDeviceState(int callingPid, int callingUid, int state) {
+    private void enforceRequestDeviceStatePermitted(int callingPid, int callingUid, int state) {
         final boolean isTopApp = isTopApp(callingPid);
         final boolean isForegroundApp = isForegroundApp(callingPid, callingUid);
         final boolean isStateAvailableForAppRequests = isStateAvailableForAppRequests(state);
 
-        final boolean canRequestState = isTopApp
+        final boolean isAllowedToRequestState = isTopApp
                 && isForegroundApp
                 && isStateAvailableForAppRequests;
 
-        if (!canRequestState) {
+        if (!isAllowedToRequestState) {
             getContext().enforceCallingOrSelfPermission(CONTROL_DEVICE_STATE,
                     "Permission required to request device state, "
                             + "or the call must come from the top app "
@@ -986,19 +987,29 @@ public final class DeviceStateManagerService extends SystemService {
     }
 
     /**
-     * Checks if the process can control the device state. If the calling process ID is
-     * not the top app, then check if this process holds the CONTROL_DEVICE_STATE permission.
+     * Checks if the process can cancel a device state request. If the calling process ID is not
+     * both the top app and foregrounded, verify that the calling process is in the foreground and
+     * that it matches the process ID and user ID that made the device state request. If neither are
+     * true, then check if this process holds the CONTROL_DEVICE_STATE permission.
      *
      * @param callingPid Process ID that is requesting this state change
      * @param callingUid UID that is requesting this state change
      */
-    private void assertCanControlDeviceState(int callingPid, int callingUid) {
+    private void enforceCancelDeviceStatePermitted(int callingPid, int callingUid) {
         final boolean isTopApp = isTopApp(callingPid);
         final boolean isForegroundApp = isForegroundApp(callingPid, callingUid);
 
-        final boolean canControlState = isTopApp && isForegroundApp;
+        boolean isAllowedToControlState = isTopApp && isForegroundApp;
 
-        if (!canControlState) {
+        if (Flags.deviceStateRequesterCancelState()) {
+            synchronized (mLock) {
+                isAllowedToControlState =
+                        isTopApp || (isForegroundApp && doCallingIdsMatchOverrideRequestIdsLocked(
+                                callingPid, callingUid));
+            }
+        }
+
+        if (!isAllowedToControlState) {
             getContext().enforceCallingOrSelfPermission(CONTROL_DEVICE_STATE,
                     "Permission required to request device state, "
                             + "or the call must come from the top app.");
@@ -1032,6 +1043,16 @@ public final class DeviceStateManagerService extends SystemService {
         return topApp != null && topApp.getPid() == callingPid;
     }
 
+    /**
+     * Returns if the provided {@code callingPid} and {@code callingUid} match the same id's that
+     * requested the current device state override.
+     */
+    @GuardedBy("mLock")
+    private boolean doCallingIdsMatchOverrideRequestIdsLocked(int callingPid, int callingUid) {
+        OverrideRequest request = mActiveOverride.orElse(null);
+        return request != null && request.getPid() == callingPid && request.getUid() == callingUid;
+    }
+
     private boolean isStateAvailableForAppRequests(int state) {
         synchronized (mLock) {
             return mDeviceStatesAvailableForAppRequests.contains(state);
@@ -1256,7 +1277,7 @@ public final class DeviceStateManagerService extends SystemService {
             // Allow top processes to request a device state change
             // If the calling process ID is not the top app, then we check if this process
             // holds a permission to CONTROL_DEVICE_STATE
-            assertCanRequestDeviceState(callingPid, callingUid, state);
+            enforceRequestDeviceStatePermitted(callingPid, callingUid, state);
 
             if (token == null) {
                 throw new IllegalArgumentException("Request token must not be null.");
@@ -1281,7 +1302,7 @@ public final class DeviceStateManagerService extends SystemService {
             // Allow top processes to cancel a device state change
             // If the calling process ID is not the top app, then we check if this process
             // holds a permission to CONTROL_DEVICE_STATE
-            assertCanControlDeviceState(callingPid, callingUid);
+            enforceCancelDeviceStatePermitted(callingPid, callingUid);
 
             final long callingIdentity = Binder.clearCallingIdentity();
             try {
diff --git a/services/core/java/com/android/server/ondeviceintelligence/OnDeviceIntelligenceManagerService.java b/services/core/java/com/android/server/ondeviceintelligence/OnDeviceIntelligenceManagerService.java
index 9ef2e12e55c5..f6d9dc29d330 100644
--- a/services/core/java/com/android/server/ondeviceintelligence/OnDeviceIntelligenceManagerService.java
+++ b/services/core/java/com/android/server/ondeviceintelligence/OnDeviceIntelligenceManagerService.java
@@ -648,6 +648,21 @@ public class OnDeviceIntelligenceManagerService extends SystemService {
                                     Slog.w(TAG, "Failed to send connected event", ex);
                                 }
                             }
+
+                            @Override
+                            public void onDisconnected(
+                                    @NonNull IOnDeviceSandboxedInferenceService service) {
+                                ensureRemoteIntelligenceServiceInitialized();
+                                mRemoteOnDeviceIntelligenceService.run(
+                                        IOnDeviceIntelligenceService::notifyInferenceServiceDisconnected);
+                            }
+
+                            @Override
+                            public void onBinderDied() {
+                                ensureRemoteIntelligenceServiceInitialized();
+                                mRemoteOnDeviceIntelligenceService.run(
+                                        IOnDeviceIntelligenceService::notifyInferenceServiceDisconnected);
+                            }
                         });
             }
         }
diff --git a/services/core/java/com/android/server/pm/InstallPackageHelper.java b/services/core/java/com/android/server/pm/InstallPackageHelper.java
index b079fed65d5d..f2a7cb7d3665 100644
--- a/services/core/java/com/android/server/pm/InstallPackageHelper.java
+++ b/services/core/java/com/android/server/pm/InstallPackageHelper.java
@@ -686,6 +686,9 @@ final class InstallPackageHelper {
                     (installFlags & PackageManager.INSTALL_INSTANT_APP) != 0;
             final boolean fullApp =
                     (installFlags & PackageManager.INSTALL_FULL_APP) != 0;
+            final boolean isPackageDeviceAdmin = mPm.isPackageDeviceAdmin(packageName, userId);
+            final boolean isProtectedPackage = mPm.mProtectedPackages != null
+                    && mPm.mProtectedPackages.isPackageStateProtected(userId, packageName);
 
             // writer
             synchronized (mPm.mLock) {
@@ -694,7 +697,8 @@ final class InstallPackageHelper {
                 if (pkgSetting == null || pkgSetting.getPkg() == null) {
                     return Pair.create(PackageManager.INSTALL_FAILED_INVALID_URI, intentSender);
                 }
-                if (instantApp && (pkgSetting.isSystem() || pkgSetting.isUpdatedSystemApp())) {
+                if (instantApp && (pkgSetting.isSystem() || pkgSetting.isUpdatedSystemApp()
+                        || isPackageDeviceAdmin || isProtectedPackage)) {
                     return Pair.create(PackageManager.INSTALL_FAILED_INVALID_URI, intentSender);
                 }
                 if (!snapshot.canViewInstantApps(callingUid, UserHandle.getUserId(callingUid))) {
diff --git a/services/core/java/com/android/server/wm/ActivityStarter.java b/services/core/java/com/android/server/wm/ActivityStarter.java
index e6d81324efa1..365fa950a2d9 100644
--- a/services/core/java/com/android/server/wm/ActivityStarter.java
+++ b/services/core/java/com/android/server/wm/ActivityStarter.java
@@ -98,6 +98,7 @@ import android.app.ProfilerInfo;
 import android.app.WaitResult;
 import android.app.WindowConfiguration;
 import android.compat.annotation.ChangeId;
+import android.compat.annotation.Disabled;
 import android.compat.annotation.EnabledSince;
 import android.content.IIntentSender;
 import android.content.Intent;
@@ -179,7 +180,7 @@ class ActivityStarter {
      * Feature flag for go/activity-security rules
      */
     @ChangeId
-    @EnabledSince(targetSdkVersion = Build.VERSION_CODES.VANILLA_ICE_CREAM)
+    @Disabled
     static final long ASM_RESTRICTIONS = 230590090L;
 
     private final ActivityTaskManagerService mService;
diff --git a/services/core/java/com/android/server/wm/DragDropController.java b/services/core/java/com/android/server/wm/DragDropController.java
index 30f2d0d64d13..6abef8b9a048 100644
--- a/services/core/java/com/android/server/wm/DragDropController.java
+++ b/services/core/java/com/android/server/wm/DragDropController.java
@@ -16,6 +16,7 @@
 
 package com.android.server.wm;
 
+import static android.content.ClipDescription.EXTRA_HIDE_DRAG_SOURCE_TASK_ID;
 import static android.os.Trace.TRACE_TAG_WINDOW_MANAGER;
 import static android.view.View.DRAG_FLAG_GLOBAL;
 import static android.view.View.DRAG_FLAG_GLOBAL_SAME_APPLICATION;
@@ -217,6 +218,11 @@ class DragDropController {
                     mDragState.mToken = dragToken;
                     mDragState.mDisplayContent = displayContent;
                     mDragState.mData = data;
+                    mDragState.mCallingTaskIdToHide = shouldMoveCallingTaskToBack(callingWin,
+                            flags);
+                    if (DEBUG_DRAG) {
+                        Slog.d(TAG_WM, "Calling task to hide=" + mDragState.mCallingTaskIdToHide);
+                    }
 
                     if ((flags & View.DRAG_FLAG_ACCESSIBILITY_ACTION) == 0) {
                         final Display display = displayContent.getDisplay();
@@ -363,6 +369,23 @@ class DragDropController {
         }
     }
 
+    /**
+     * If the calling window's task should be hidden for the duration of the drag, this returns the
+     * task id of the task (or -1 otherwise).
+     */
+    private int shouldMoveCallingTaskToBack(WindowState callingWin, int flags) {
+        if ((flags & View.DRAG_FLAG_HIDE_CALLING_TASK_ON_DRAG_START) == 0) {
+            // Not requested by the app
+            return -1;
+        }
+        final ActivityRecord callingActivity = callingWin.getActivityRecord();
+        if (callingActivity == null || callingActivity.getTask() == null) {
+            // Not an activity
+            return -1;
+        }
+        return callingActivity.getTask().mTaskId;
+    }
+
     /**
      * Notifies the unhandled drag listener if needed.
      * @return whether the listener was notified and subsequent drag completion should be deferred
diff --git a/services/core/java/com/android/server/wm/DragState.java b/services/core/java/com/android/server/wm/DragState.java
index e3827aa86d9e..5a1279024eb5 100644
--- a/services/core/java/com/android/server/wm/DragState.java
+++ b/services/core/java/com/android/server/wm/DragState.java
@@ -16,6 +16,7 @@
 
 package com.android.server.wm;
 
+import static android.content.ClipDescription.EXTRA_HIDE_DRAG_SOURCE_TASK_ID;
 import static android.content.ClipDescription.MIMETYPE_APPLICATION_ACTIVITY;
 import static android.content.ClipDescription.MIMETYPE_APPLICATION_SHORTCUT;
 import static android.content.ClipDescription.MIMETYPE_APPLICATION_TASK;
@@ -48,6 +49,7 @@ import android.graphics.Rect;
 import android.os.Binder;
 import android.os.Build;
 import android.os.IBinder;
+import android.os.PersistableBundle;
 import android.os.RemoteException;
 import android.os.Trace;
 import android.os.UserHandle;
@@ -117,6 +119,8 @@ class DragState {
     InputInterceptor mInputInterceptor;
     ArrayList<WindowState> mNotifiedWindows;
     boolean mDragInProgress;
+    // Set to non -1 value if a valid app requests DRAG_FLAG_HIDE_CALLING_TASK_ON_DRAG_START
+    int mCallingTaskIdToHide;
     /**
      * Whether if animation is completed. Needs to be volatile to update from the animation thread
      * without having a WM lock.
@@ -320,12 +324,12 @@ class DragState {
                 }
             }
             final boolean targetInterceptsGlobalDrag = targetInterceptsGlobalDrag(touchedWin);
-            return obtainDragEvent(DragEvent.ACTION_DROP, x, y, mData,
+            return obtainDragEvent(DragEvent.ACTION_DROP, x, y, mDataDescription, mData,
                     /* includeDragSurface= */ targetInterceptsGlobalDrag,
                     /* includeDragFlags= */ targetInterceptsGlobalDrag,
                     dragAndDropPermissions);
         } else {
-            return obtainDragEvent(DragEvent.ACTION_DROP, x, y, mData,
+            return obtainDragEvent(DragEvent.ACTION_DROP, x, y, mDataDescription, mData,
                     /* includeDragSurface= */ includePrivateInfo,
                     /* includeDragFlags= */ includePrivateInfo,
                     null /* dragAndDropPermissions */);
@@ -527,11 +531,24 @@ class DragState {
                 Slog.d(TAG_WM, "Sending DRAG_STARTED to new window " + newWin);
             }
             // Only allow the extras to be dispatched to a global-intercepting drag target
-            ClipData data = interceptsGlobalDrag ? mData.copyForTransferWithActivityInfo() : null;
+            ClipData data = null;
+            if (interceptsGlobalDrag) {
+                data = mData.copyForTransferWithActivityInfo();
+                PersistableBundle extras = data.getDescription().getExtras() != null
+                        ? data.getDescription().getExtras()
+                        : new PersistableBundle();
+                extras.putInt(EXTRA_HIDE_DRAG_SOURCE_TASK_ID, mCallingTaskIdToHide);
+                // Note that setting extras always copies the bundle
+                data.getDescription().setExtras(extras);
+                if (DEBUG_DRAG) {
+                    Slog.d(TAG_WM, "Adding EXTRA_HIDE_DRAG_SOURCE_TASK_ID=" + mCallingTaskIdToHide);
+                }
+            }
+            ClipDescription description = data != null ? data.getDescription() : mDataDescription;
             DragEvent event = obtainDragEvent(DragEvent.ACTION_DRAG_STARTED,
                     newWin.translateToWindowX(touchX), newWin.translateToWindowY(touchY),
-                    data, false /* includeDragSurface */, true /* includeDragFlags */,
-                    null /* dragAndDropPermission */);
+                    description, data, false /* includeDragSurface */,
+                    true /* includeDragFlags */, null /* dragAndDropPermission */);
             try {
                 newWin.mClient.dispatchDragEvent(event);
                 // track each window that we've notified that the drag is starting
@@ -700,37 +717,51 @@ class DragState {
         return mDragInProgress;
     }
 
-    private DragEvent obtainDragEvent(int action, float x, float y, ClipData data,
-            boolean includeDragSurface, boolean includeDragFlags,
+    private DragEvent obtainDragEvent(int action, float x, float y, ClipDescription description,
+            ClipData data, boolean includeDragSurface, boolean includeDragFlags,
             IDragAndDropPermissions dragAndDropPermissions) {
         return DragEvent.obtain(action, x, y, mThumbOffsetX, mThumbOffsetY,
                 includeDragFlags ? mFlags : 0,
-                null  /* localState */, mDataDescription, data,
+                null  /* localState */, description, data,
                 includeDragSurface ? mSurfaceControl : null,
                 dragAndDropPermissions, false /* result */);
     }
 
     private ValueAnimator createReturnAnimationLocked() {
-        final ValueAnimator animator = ValueAnimator.ofPropertyValuesHolder(
-                PropertyValuesHolder.ofFloat(
-                        ANIMATED_PROPERTY_X, mCurrentX - mThumbOffsetX,
-                        mOriginalX - mThumbOffsetX),
-                PropertyValuesHolder.ofFloat(
-                        ANIMATED_PROPERTY_Y, mCurrentY - mThumbOffsetY,
-                        mOriginalY - mThumbOffsetY),
-                PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_SCALE, mAnimatedScale,
-                        mAnimatedScale),
-                PropertyValuesHolder.ofFloat(
-                        ANIMATED_PROPERTY_ALPHA, mOriginalAlpha, mOriginalAlpha / 2));
-
-        final float translateX = mOriginalX - mCurrentX;
-        final float translateY = mOriginalY - mCurrentY;
-        // Adjust the duration to the travel distance.
-        final double travelDistance = Math.sqrt(translateX * translateX + translateY * translateY);
-        final double displayDiagonal =
-                Math.sqrt(mDisplaySize.x * mDisplaySize.x + mDisplaySize.y * mDisplaySize.y);
-        final long duration = MIN_ANIMATION_DURATION_MS + (long) (travelDistance / displayDiagonal
-                * (MAX_ANIMATION_DURATION_MS - MIN_ANIMATION_DURATION_MS));
+        final ValueAnimator animator;
+        final long duration;
+        if (mCallingTaskIdToHide != -1) {
+            animator = ValueAnimator.ofPropertyValuesHolder(
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_X, mCurrentX, mCurrentX),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_Y, mCurrentY, mCurrentY),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_SCALE, mAnimatedScale,
+                            mAnimatedScale),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_ALPHA, mOriginalAlpha, 0f));
+            duration = MIN_ANIMATION_DURATION_MS;
+        } else {
+            animator = ValueAnimator.ofPropertyValuesHolder(
+                    PropertyValuesHolder.ofFloat(
+                            ANIMATED_PROPERTY_X, mCurrentX - mThumbOffsetX,
+                            mOriginalX - mThumbOffsetX),
+                    PropertyValuesHolder.ofFloat(
+                            ANIMATED_PROPERTY_Y, mCurrentY - mThumbOffsetY,
+                            mOriginalY - mThumbOffsetY),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_SCALE, mAnimatedScale,
+                            mAnimatedScale),
+                    PropertyValuesHolder.ofFloat(
+                            ANIMATED_PROPERTY_ALPHA, mOriginalAlpha, mOriginalAlpha / 2));
+
+            final float translateX = mOriginalX - mCurrentX;
+            final float translateY = mOriginalY - mCurrentY;
+            // Adjust the duration to the travel distance.
+            final double travelDistance = Math.sqrt(
+                    translateX * translateX + translateY * translateY);
+            final double displayDiagonal =
+                    Math.sqrt(mDisplaySize.x * mDisplaySize.x + mDisplaySize.y * mDisplaySize.y);
+            duration = MIN_ANIMATION_DURATION_MS + (long) (travelDistance / displayDiagonal
+                    * (MAX_ANIMATION_DURATION_MS - MIN_ANIMATION_DURATION_MS));
+        }
+
         final AnimationListener listener = new AnimationListener();
         animator.setDuration(duration);
         animator.setInterpolator(mCubicEaseOutInterpolator);
@@ -742,13 +773,24 @@ class DragState {
     }
 
     private ValueAnimator createCancelAnimationLocked() {
-        final ValueAnimator animator = ValueAnimator.ofPropertyValuesHolder(
-                PropertyValuesHolder.ofFloat(
-                        ANIMATED_PROPERTY_X, mCurrentX - mThumbOffsetX, mCurrentX),
-                PropertyValuesHolder.ofFloat(
-                        ANIMATED_PROPERTY_Y, mCurrentY - mThumbOffsetY, mCurrentY),
-                PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_SCALE, mAnimatedScale, 0),
-                PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_ALPHA, mOriginalAlpha, 0));
+        final ValueAnimator animator;
+        if (mCallingTaskIdToHide != -1) {
+             animator = ValueAnimator.ofPropertyValuesHolder(
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_X, mCurrentX, mCurrentX),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_Y, mCurrentY, mCurrentY),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_SCALE, mAnimatedScale,
+                            mAnimatedScale),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_ALPHA, mOriginalAlpha, 0f));
+        } else {
+            animator = ValueAnimator.ofPropertyValuesHolder(
+                    PropertyValuesHolder.ofFloat(
+                            ANIMATED_PROPERTY_X, mCurrentX - mThumbOffsetX, mCurrentX),
+                    PropertyValuesHolder.ofFloat(
+                            ANIMATED_PROPERTY_Y, mCurrentY - mThumbOffsetY, mCurrentY),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_SCALE, mAnimatedScale, 0),
+                    PropertyValuesHolder.ofFloat(ANIMATED_PROPERTY_ALPHA, mOriginalAlpha, 0));
+        }
+
         final AnimationListener listener = new AnimationListener();
         animator.setDuration(MIN_ANIMATION_DURATION_MS);
         animator.setInterpolator(mCubicEaseOutInterpolator);
diff --git a/services/core/java/com/android/server/wm/SafeActivityOptions.java b/services/core/java/com/android/server/wm/SafeActivityOptions.java
index f2dc55f38bc3..2d961e1f0766 100644
--- a/services/core/java/com/android/server/wm/SafeActivityOptions.java
+++ b/services/core/java/com/android/server/wm/SafeActivityOptions.java
@@ -438,7 +438,10 @@ public class SafeActivityOptions {
         return taskDisplayArea;
     }
 
-    private boolean isAssistant(ActivityTaskManagerService atmService, int callingUid) {
+    /**
+     * Returns whether the given UID caller is the assistant.
+     */
+    public static boolean isAssistant(ActivityTaskManagerService atmService, int callingUid) {
         if (atmService.mActiveVoiceInteractionServiceComponent == null) {
             return false;
         }
diff --git a/services/core/java/com/android/server/wm/Session.java b/services/core/java/com/android/server/wm/Session.java
index 0562cd979cb8..4cd27bcdb616 100644
--- a/services/core/java/com/android/server/wm/Session.java
+++ b/services/core/java/com/android/server/wm/Session.java
@@ -377,7 +377,7 @@ class Session extends IWindowSession.Stub implements IBinder.DeathRecipient {
         final int callingPid = Binder.getCallingPid();
         // Validate and resolve ClipDescription data before clearing the calling identity
         validateAndResolveDragMimeTypeExtras(data, callingUid, callingPid, mPackageName);
-        validateDragFlags(flags);
+        validateDragFlags(flags, callingUid);
         final long ident = Binder.clearCallingIdentity();
         try {
             return mDragDropController.performDrag(mPid, mUid, window, flags, surface, touchSource,
@@ -403,12 +403,17 @@ class Session extends IWindowSession.Stub implements IBinder.DeathRecipient {
      * Validates the given drag flags.
      */
     @VisibleForTesting
-    void validateDragFlags(int flags) {
+    void validateDragFlags(int flags, int callingUid) {
         if ((flags & View.DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION) != 0) {
             if (!mCanStartTasksFromRecents) {
                 throw new SecurityException("Requires START_TASKS_FROM_RECENTS permission");
             }
         }
+        if ((flags & View.DRAG_FLAG_HIDE_CALLING_TASK_ON_DRAG_START) != 0) {
+            if (!SafeActivityOptions.isAssistant(mService.mAtmService, callingUid)) {
+                throw new SecurityException("Caller is not the assistant");
+            }
+        }
     }
 
     /**
diff --git a/services/tests/wmtests/src/com/android/server/wm/DragDropControllerTests.java b/services/tests/wmtests/src/com/android/server/wm/DragDropControllerTests.java
index 7faf2aacc0bc..8cdb574a967b 100644
--- a/services/tests/wmtests/src/com/android/server/wm/DragDropControllerTests.java
+++ b/services/tests/wmtests/src/com/android/server/wm/DragDropControllerTests.java
@@ -497,7 +497,8 @@ public class DragDropControllerTests extends WindowTestsBase {
     public void testValidateFlags() {
         final Session session = getTestSession();
         try {
-            session.validateDragFlags(View.DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION);
+            session.validateDragFlags(View.DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION,
+                    0 /* callingUid */);
             fail("Expected failure without permission");
         } catch (SecurityException e) {
             // Expected failure
@@ -510,7 +511,8 @@ public class DragDropControllerTests extends WindowTestsBase {
                 .checkCallingOrSelfPermission(eq(START_TASKS_FROM_RECENTS));
         final Session session = createTestSession(mAtm);
         try {
-            session.validateDragFlags(View.DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION);
+            session.validateDragFlags(View.DRAG_FLAG_REQUEST_SURFACE_FOR_RETURN_ANIMATION,
+                    0 /* callingUid */);
             // Expected pass
         } catch (SecurityException e) {
             fail("Expected no failure with permission");
diff --git a/services/usb/java/com/android/server/usb/UsbDeviceManager.java b/services/usb/java/com/android/server/usb/UsbDeviceManager.java
index 175a09db54e3..ae89996c8d26 100644
--- a/services/usb/java/com/android/server/usb/UsbDeviceManager.java
+++ b/services/usb/java/com/android/server/usb/UsbDeviceManager.java
@@ -78,9 +78,9 @@ import android.os.storage.StorageVolume;
 import android.provider.Settings;
 import android.service.usb.UsbDeviceManagerProto;
 import android.service.usb.UsbHandlerProto;
+import android.text.TextUtils;
 import android.util.Pair;
 import android.util.Slog;
-import android.text.TextUtils;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.logging.MetricsLogger;
@@ -838,7 +838,7 @@ public class UsbDeviceManager implements ActivityTaskManagerInternal.ScreenObser
             }
         }
 
-        private void notifyAccessoryModeExit(int operationId) {
+        protected void notifyAccessoryModeExit(int operationId) {
             // make sure accessory mode is off
             // and restore default functions
             Slog.d(TAG, "exited USB accessory mode");
@@ -2271,8 +2271,13 @@ public class UsbDeviceManager implements ActivityTaskManagerInternal.ScreenObser
                      */
                     operationId = sUsbOperationCount.incrementAndGet();
                     if (msg.arg1 != 1) {
-                        // Set this since default function may be selected from Developer options
-                        setEnabledFunctions(mScreenUnlockedFunctions, false, operationId);
+                        if (mCurrentFunctions == UsbManager.FUNCTION_ACCESSORY) {
+                            notifyAccessoryModeExit(operationId);
+                        } else {
+                            // Set this since default function may be selected from Developer
+                            // options
+                            setEnabledFunctions(mScreenUnlockedFunctions, false, operationId);
+                        }
                     }
                     break;
                 case MSG_GADGET_HAL_REGISTERED:
```

**frameworks/native**
```diff
diff --git a/libs/gui/ISurfaceComposer.cpp b/libs/gui/ISurfaceComposer.cpp
index ff6b558d41..269936858a 100644
--- a/libs/gui/ISurfaceComposer.cpp
+++ b/libs/gui/ISurfaceComposer.cpp
@@ -62,7 +62,7 @@ public:
 
     status_t setTransactionState(
             const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& state,
-            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
+            Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
             InputWindowCommands commands, int64_t desiredPresentTime, bool isAutoTimestamp,
             const std::vector<client_cache_t>& uncacheBuffers, bool hasListenerCallbacks,
             const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId,
diff --git a/libs/gui/SurfaceComposerClient.cpp b/libs/gui/SurfaceComposerClient.cpp
index af91bb3ae2..5db539497c 100644
--- a/libs/gui/SurfaceComposerClient.cpp
+++ b/libs/gui/SurfaceComposerClient.cpp
@@ -1059,7 +1059,8 @@ void SurfaceComposerClient::doUncacheBufferTransaction(uint64_t cacheId) {
     uncacheBuffer.token = BufferCache::getInstance().getToken();
     uncacheBuffer.id = cacheId;
     Vector<ComposerState> composerStates;
-    status_t status = sf->setTransactionState(FrameTimelineInfo{}, composerStates, {},
+    Vector<DisplayState> displayStates;
+    status_t status = sf->setTransactionState(FrameTimelineInfo{}, composerStates, displayStates,
                                               ISurfaceComposer::eOneWay,
                                               Transaction::getDefaultApplyToken(), {}, systemTime(),
                                               true, {uncacheBuffer}, false, {}, generateId(), {});
diff --git a/libs/gui/include/gui/ISurfaceComposer.h b/libs/gui/include/gui/ISurfaceComposer.h
index eb4a802c17..1ecc216dff 100644
--- a/libs/gui/include/gui/ISurfaceComposer.h
+++ b/libs/gui/include/gui/ISurfaceComposer.h
@@ -112,7 +112,7 @@ public:
     /* open/close transactions. requires ACCESS_SURFACE_FLINGER permission */
     virtual status_t setTransactionState(
             const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& state,
-            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
+            Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
             InputWindowCommands inputWindowCommands, int64_t desiredPresentTime,
             bool isAutoTimestamp, const std::vector<client_cache_t>& uncacheBuffer,
             bool hasListenerCallbacks, const std::vector<ListenerCallbacks>& listenerCallbacks,
diff --git a/libs/gui/tests/Surface_test.cpp b/libs/gui/tests/Surface_test.cpp
index 43cd0f8a7f..5e91088378 100644
--- a/libs/gui/tests/Surface_test.cpp
+++ b/libs/gui/tests/Surface_test.cpp
@@ -636,7 +636,7 @@ public:
 
     status_t setTransactionState(
             const FrameTimelineInfo& /*frameTimelineInfo*/, Vector<ComposerState>& /*state*/,
-            const Vector<DisplayState>& /*displays*/, uint32_t /*flags*/,
+            Vector<DisplayState>& /*displays*/, uint32_t /*flags*/,
             const sp<IBinder>& /*applyToken*/, InputWindowCommands /*inputWindowCommands*/,
             int64_t /*desiredPresentTime*/, bool /*isAutoTimestamp*/,
             const std::vector<client_cache_t>& /*cachedBuffer*/, bool /*hasListenerCallbacks*/,
diff --git a/services/surfaceflinger/SurfaceFlinger.cpp b/services/surfaceflinger/SurfaceFlinger.cpp
index fcead9ff6e..2d90d4041a 100644
--- a/services/surfaceflinger/SurfaceFlinger.cpp
+++ b/services/surfaceflinger/SurfaceFlinger.cpp
@@ -5182,7 +5182,7 @@ bool SurfaceFlinger::shouldLatchUnsignaled(const layer_state_t& state, size_t nu
 
 status_t SurfaceFlinger::setTransactionState(
         const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& states,
-        const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
+        Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
         InputWindowCommands inputWindowCommands, int64_t desiredPresentTime, bool isAutoTimestamp,
         const std::vector<client_cache_t>& uncacheBuffers, bool hasListenerCallbacks,
         const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId,
@@ -5197,7 +5197,7 @@ status_t SurfaceFlinger::setTransactionState(
         composerState.state.sanitize(permissions);
     }
 
-    for (DisplayState display : displays) {
+    for (DisplayState& display : displays) {
         display.sanitize(permissions);
     }
 
diff --git a/services/surfaceflinger/SurfaceFlinger.h b/services/surfaceflinger/SurfaceFlinger.h
index a3534b582c..92bd12527d 100644
--- a/services/surfaceflinger/SurfaceFlinger.h
+++ b/services/surfaceflinger/SurfaceFlinger.h
@@ -559,7 +559,7 @@ private:
     sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId) const;
     status_t setTransactionState(
             const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& state,
-            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
+            Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
             InputWindowCommands inputWindowCommands, int64_t desiredPresentTime,
             bool isAutoTimestamp, const std::vector<client_cache_t>& uncacheBuffers,
             bool hasListenerCallbacks, const std::vector<ListenerCallbacks>& listenerCallbacks,
diff --git a/services/surfaceflinger/tests/Credentials_test.cpp b/services/surfaceflinger/tests/Credentials_test.cpp
index ebe11fb0f3..d355e720d1 100644
--- a/services/surfaceflinger/tests/Credentials_test.cpp
+++ b/services/surfaceflinger/tests/Credentials_test.cpp
@@ -26,6 +26,7 @@
 #include <private/android_filesystem_config.h>
 #include <private/gui/ComposerServiceAIDL.h>
 #include <ui/DisplayMode.h>
+#include <ui/DisplayState.h>
 #include <ui/DynamicDisplayInfo.h>
 #include <utils/String8.h>
 #include <functional>
@@ -276,7 +277,7 @@ TEST_F(CredentialsTest, CreateDisplayTest) {
 TEST_F(CredentialsTest, CaptureLayersTest) {
     setupBackgroundSurface();
     sp<GraphicBuffer> outBuffer;
-    std::function<status_t()> condition = [=]() {
+    std::function<status_t()> condition = [=, this]() {
         LayerCaptureArgs captureArgs;
         captureArgs.layerHandle = mBGSurfaceControl->getHandle();
         captureArgs.sourceCrop = {0, 0, 1, 1};
@@ -396,6 +397,56 @@ TEST_F(CredentialsTest, TransactionPermissionTest) {
     }
 }
 
+TEST_F(CredentialsTest, DisplayTransactionPermissionTest) {
+    const auto display = getFirstDisplayToken();
+
+    ui::DisplayState displayState;
+    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayState(display, &displayState));
+    const ui::Rotation initialOrientation = displayState.orientation;
+
+    // Set display orientation from an untrusted process. This should fail silently.
+    {
+        UIDFaker f{AID_BIN};
+        Transaction transaction;
+        Rect layerStackRect;
+        Rect displayRect;
+        transaction.setDisplayProjection(display, initialOrientation + ui::ROTATION_90,
+                                         layerStackRect, displayRect);
+        transaction.apply(/*synchronous=*/true);
+    }
+
+    // Verify that the display orientation did not change.
+    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayState(display, &displayState));
+    ASSERT_EQ(initialOrientation, displayState.orientation);
+
+    // Set display orientation from a trusted process.
+    {
+        UIDFaker f{AID_SYSTEM};
+        Transaction transaction;
+        Rect layerStackRect;
+        Rect displayRect;
+        transaction.setDisplayProjection(display, initialOrientation + ui::ROTATION_90,
+                                         layerStackRect, displayRect);
+        transaction.apply(/*synchronous=*/true);
+    }
+
+    // Verify that the display orientation did change.
+    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayState(display, &displayState));
+    ASSERT_EQ(initialOrientation + ui::ROTATION_90, displayState.orientation);
+
+    // Reset orientation
+    {
+        UIDFaker f{AID_SYSTEM};
+        Transaction transaction;
+        Rect layerStackRect;
+        Rect displayRect;
+        transaction.setDisplayProjection(display, initialOrientation, layerStackRect, displayRect);
+        transaction.apply(/*synchronous=*/true);
+    }
+    ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayState(display, &displayState));
+    ASSERT_EQ(initialOrientation, displayState.orientation);
+}
+
 } // namespace android
 
 // TODO(b/129481165): remove the #pragma below and fix conversion issues
diff --git a/services/surfaceflinger/tests/unittests/TestableSurfaceFlinger.h b/services/surfaceflinger/tests/unittests/TestableSurfaceFlinger.h
index 4197cbd271..b5b36bea19 100644
--- a/services/surfaceflinger/tests/unittests/TestableSurfaceFlinger.h
+++ b/services/surfaceflinger/tests/unittests/TestableSurfaceFlinger.h
@@ -528,7 +528,7 @@ public:
 
     auto setTransactionState(
             const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& states,
-            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
+            Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
             const InputWindowCommands& inputWindowCommands, int64_t desiredPresentTime,
             bool isAutoTimestamp, const std::vector<client_cache_t>& uncacheBuffers,
             bool hasListenerCallbacks, std::vector<ListenerCallbacks>& listenerCallbacks,
```

**frameworks/opt/telephony**
```diff
```

**hardware/google/graphics/common**
```diff
diff --git a/include/displaycolor/displaycolor.h b/include/displaycolor/displaycolor.h
index cd943f3..b25d93b 100644
--- a/include/displaycolor/displaycolor.h
+++ b/include/displaycolor/displaycolor.h
@@ -346,7 +346,8 @@ struct DisplayScene {
                dbv == rhs.dbv &&
                refresh_rate == rhs.refresh_rate &&
                operation_rate == rhs.operation_rate &&
-               hdr_layer_state == rhs.hdr_layer_state;
+               hdr_layer_state == rhs.hdr_layer_state &&
+               temperature == rhs.temperature;
     }
     bool operator!=(const DisplayScene &rhs) const {
         return !(*this == rhs);
@@ -388,6 +389,9 @@ struct DisplayScene {
     /// operation rate to switch between hs/ns mode
     uint32_t operation_rate = 120;
 
+    /// display temperature in degrees Celsius
+    uint32_t temperature = UINT_MAX;
+
     /// hdr layer state on screen
     HdrLayerState hdr_layer_state = HdrLayerState::kHdrNone;
 };
diff --git a/libhwc2.1/libdevice/ExynosDisplay.h b/libhwc2.1/libdevice/ExynosDisplay.h
index 2db9275..1972de6 100644
--- a/libhwc2.1/libdevice/ExynosDisplay.h
+++ b/libhwc2.1/libdevice/ExynosDisplay.h
@@ -1377,6 +1377,8 @@ class ExynosDisplay {
 
         virtual int32_t setFixedTe2Rate(const int __unused rateHz) { return NO_ERROR; }
 
+        virtual int32_t setDisplayTemperature(const int __unused temperature) { return NO_ERROR; }
+
         virtual int32_t registerRefreshRateChangeListener(
                 std::shared_ptr<RefreshRateChangeListener> listener) {
             return NO_ERROR;
diff --git a/libhwc2.1/libhwcService/ExynosHWCService.cpp b/libhwc2.1/libhwcService/ExynosHWCService.cpp
index 42dadb6..5113a8e 100644
--- a/libhwc2.1/libhwcService/ExynosHWCService.cpp
+++ b/libhwc2.1/libhwcService/ExynosHWCService.cpp
@@ -601,4 +601,16 @@ int32_t ExynosHWCService::setFixedTe2Rate(uint32_t displayId, int32_t rateHz) {
     return -EINVAL;
 }
 
+int32_t ExynosHWCService::setDisplayTemperature(uint32_t displayId, int32_t temperature) {
+    ALOGI("ExynosHWCService::%s() displayID(%u) temperature(%d)", __func__, displayId, temperature);
+
+    auto display = mHWCCtx->device->getDisplay(displayId);
+
+    if (display != nullptr) {
+        display->setDisplayTemperature(temperature);
+    }
+
+    return NO_ERROR;
+}
+
 } //namespace android
diff --git a/libhwc2.1/libhwcService/ExynosHWCService.h b/libhwc2.1/libhwcService/ExynosHWCService.h
index 449a829..0ef57f2 100644
--- a/libhwc2.1/libhwcService/ExynosHWCService.h
+++ b/libhwc2.1/libhwcService/ExynosHWCService.h
@@ -94,6 +94,7 @@ public:
                                         const std::vector<std::pair<uint32_t, uint32_t>>& __unused
                                                 settings) override;
     virtual int32_t setFixedTe2Rate(uint32_t displayId, int32_t rateHz);
+    virtual int32_t setDisplayTemperature(uint32_t displayId, int32_t temperature);
 
 private:
     friend class Singleton<ExynosHWCService>;
diff --git a/libhwc2.1/libhwcService/IExynosHWC.cpp b/libhwc2.1/libhwcService/IExynosHWC.cpp
index 87bcdec..e89ae8d 100644
--- a/libhwc2.1/libhwcService/IExynosHWC.cpp
+++ b/libhwc2.1/libhwcService/IExynosHWC.cpp
@@ -82,6 +82,7 @@ enum {
     SET_PRESENT_TIMEOUT_PARAMETERS = 1016,
     SET_PRESENT_TIMEOUT_CONTROLLER = 1017,
     SET_FIXED_TE2_RATE = 1018,
+    SET_DISPLAY_TEMPERATURE = 1019,
 };
 
 class BpExynosHWCService : public BpInterface<IExynosHWCService> {
@@ -584,6 +585,15 @@ public:
         if (result) ALOGE("SET_FIXED_TE2_RATE transact error(%d)", result);
         return result;
     }
+    virtual int32_t setDisplayTemperature(uint32_t displayId, int32_t temperature) {
+        Parcel data, reply;
+        data.writeInterfaceToken(IExynosHWCService::getInterfaceDescriptor());
+        data.writeUint32(displayId);
+        data.writeInt32(temperature);
+        int result = remote()->transact(SET_DISPLAY_TEMPERATURE, data, &reply);
+        if (result) ALOGE("SET_DISPLAY_TEMPERATURE transact error(%d)", result);
+        return result;
+    }
 };
 
 IMPLEMENT_META_INTERFACE(ExynosHWCService, "android.hal.ExynosHWCService");
@@ -925,6 +935,13 @@ status_t BnExynosHWCService::onTransact(
             return setFixedTe2Rate(displayId, rateHz);
         } break;
 
+        case SET_DISPLAY_TEMPERATURE: {
+            CHECK_INTERFACE(IExynosHWCService, data, reply);
+            uint32_t displayId = data.readUint32();
+            int32_t temperature = data.readInt32();
+            return setDisplayTemperature(displayId, temperature);
+        } break;
+
         default:
             return BBinder::onTransact(code, data, reply, flags);
     }
diff --git a/libhwc2.1/libhwcService/IExynosHWC.h b/libhwc2.1/libhwcService/IExynosHWC.h
index 484f141..fe7e0ce 100644
--- a/libhwc2.1/libhwcService/IExynosHWC.h
+++ b/libhwc2.1/libhwcService/IExynosHWC.h
@@ -86,6 +86,7 @@ public:
             uint32_t displayId, int timeoutNs,
             const std::vector<std::pair<uint32_t, uint32_t>>& settings) = 0;
     virtual int32_t setFixedTe2Rate(uint32_t displayId, int32_t rateHz) = 0;
+    virtual int32_t setDisplayTemperature(uint32_t displayId, int32_t temperature) = 0;
 };
 
 /* Native Interface */
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
index 99767a2..34d89f3 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.cpp
@@ -244,6 +244,7 @@ ExynosPrimaryDisplay::ExynosPrimaryDisplay(uint32_t index, ExynosDevice* device,
                 ALOGI("%s(): refresh control is not supported", __func__);
             }
         }
+        mIsDisplayTempMonitorSupported = initDisplayTempMonitor(displayTypeIdentifier);
     }
 
     // Allow to enable dynamic recomposition after every power on
@@ -307,6 +308,14 @@ ExynosPrimaryDisplay::~ExynosPrimaryDisplay()
     if (mDisplayNeedHandleIdleExitOfs.is_open()) {
         mDisplayNeedHandleIdleExitOfs.close();
     }
+
+    if (mIsDisplayTempMonitorSupported) {
+        mTMLoopStatus.store(false, std::memory_order_relaxed);
+        mTMCondition.notify_one();
+        if (mTMThread.joinable()) {
+            mTMThread.join();
+        }
+    }
 }
 
 void ExynosPrimaryDisplay::setDDIScalerEnable(int width, int height) {
@@ -668,6 +677,9 @@ int32_t ExynosPrimaryDisplay::setPowerMode(int32_t mode) {
                                                                      mRefreshRateDelayNanos);
         }
     }
+
+    checkTemperatureMonitorThread(mPowerModeState.has_value() && mode == HWC2_POWER_MODE_ON);
+
     return res;
 }
 
@@ -1325,6 +1337,11 @@ int32_t ExynosPrimaryDisplay::setFixedTe2Rate(const int targetTe2RateHz) {
     }
 }
 
+int32_t ExynosPrimaryDisplay::setDisplayTemperature(const int temperature) {
+    mDisplayTemperature = temperature;
+    return HWC2_ERROR_UNSUPPORTED;
+}
+
 int32_t ExynosPrimaryDisplay::setMinIdleRefreshRate(const int targetFps,
                                                     const RrThrottleRequester requester) {
     if (targetFps < 0) {
@@ -1512,6 +1529,9 @@ void ExynosPrimaryDisplay::dump(String8 &result) {
     for (uint32_t i = 0; i < toUnderlying(RrThrottleRequester::MAX); i++) {
         result.appendFormat("\t[%u] vote to %" PRId64 " ns\n", i, mRrThrottleNanos[i]);
     }
+    if (mIsDisplayTempMonitorSupported) {
+        result.appendFormat("Temperature : %d°C\n", mDisplayTemperature);
+    }
     result.appendFormat("\n");
 }
 
@@ -1715,3 +1735,111 @@ int32_t ExynosPrimaryDisplay::registerRefreshRateChangeListener(
         return -EINVAL;
     }
 }
+
+// TODO(b/355579338): to create a dedicated class DisplayTemperatureMonitor
+bool ExynosPrimaryDisplay::initDisplayTempMonitor(const std::string& display) {
+    mDisplayTempInterval = property_get_int32(kDisplayTempIntervalSec, 0);
+
+    if (mDisplayTempInterval <= 0) {
+        ALOGD("%s: Invalid display temperature interval: %d", __func__, mDisplayTempInterval);
+        return false;
+    }
+
+    auto propertyName = getPropertyDisplayTemperatureStr(display);
+
+    char value[PROPERTY_VALUE_MAX];
+    auto ret = property_get(propertyName.c_str(), value, "");
+
+    if (ret <= 0) {
+        ALOGD("%s: Display temperature property values is empty", __func__);
+        return false;
+    }
+
+    mDisplayTempSysfsNode = String8(value);
+    return true;
+}
+
+int32_t ExynosPrimaryDisplay::getDisplayTemperature() {
+    DISPLAY_ATRACE_CALL();
+
+    if (mDisplayTempSysfsNode.empty()) {
+        ALOGE("%s: Display temp sysfs node string is empty", __func__);
+        return UINT_MAX;
+    }
+
+    int32_t temperature;
+    std::ifstream ifs(mDisplayTempSysfsNode.c_str());
+
+    if (!ifs.is_open()) {
+        ALOGE("%s: Unable to open node '%s', error = %s", __func__, mDisplayTempSysfsNode.c_str(),
+              strerror(errno));
+        return UINT_MAX;
+    }
+
+    if (!(ifs >> temperature) || !ifs.good()) {
+        ALOGE("%s: Unable to read node '%s', error = %s", __func__, mDisplayTempSysfsNode.c_str(),
+              strerror(errno));
+    }
+
+    ifs.close();
+    return temperature / 1000;
+}
+
+bool ExynosPrimaryDisplay::isTemperatureMonitorThreadRunning() {
+    android_atomic_acquire_load(&mTMThreadStatus);
+    return (mTMThreadStatus > 0);
+}
+
+void ExynosPrimaryDisplay::checkTemperatureMonitorThread(bool shouldRun) {
+    ATRACE_CALL();
+    if (!mIsDisplayTempMonitorSupported) {
+        return;
+    }
+
+    // If thread was destroyed, create thread and run.
+    if (!isTemperatureMonitorThreadRunning()) {
+        if (shouldRun) {
+            temperatureMonitorThreadCreate();
+            return;
+        }
+    } else {
+        // if screen state changed make the thread suspend/resume.
+        {
+            std::lock_guard<std::mutex> lock(mThreadMutex);
+            if (mTMLoopStatus != shouldRun) {
+                mTMLoopStatus = shouldRun;
+                mTMCondition.notify_one();
+            }
+        }
+    }
+}
+
+void ExynosPrimaryDisplay::temperatureMonitorThreadCreate() {
+    mTMLoopStatus.store(false, std::memory_order_relaxed);
+
+    ALOGI("Creating monitor display temperature thread");
+    mTMLoopStatus.store(true, std::memory_order_relaxed);
+    mTMThread = std::thread(&ExynosPrimaryDisplay::temperatureMonitorThreadLoop, this);
+    mTMCondition.notify_one();
+}
+
+void* ExynosPrimaryDisplay::temperatureMonitorThreadLoop() {
+    android_atomic_inc(&mTMThreadStatus);
+    while (true) {
+        std::unique_lock<std::mutex> lock(mThreadMutex);
+        mTMCondition.wait(lock, [this] { return mTMLoopStatus.load(std::memory_order_relaxed); });
+
+        mDisplayTemperature = getDisplayTemperature();
+        if (mDisplayTemperature == UINT_MAX) {
+            ALOGE("%s: Failed to get display temperature", LOG_TAG);
+        } else {
+            ALOGI("Display Temperature : %d°C", mDisplayTemperature);
+        }
+
+        // Wait for the specified interval or until the thread is suspended
+        mTMCondition.wait_for(lock, std::chrono::seconds(mDisplayTempInterval),
+                              [this] { return !mTMLoopStatus.load(std::memory_order_relaxed); });
+    }
+    android_atomic_dec(&mTMThreadStatus);
+    return NULL;
+}
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h
index 1489284..95fd5bb 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplay.h
@@ -20,6 +20,7 @@
 
 #include "../libdevice/ExynosDisplay.h"
 #include "../libvrr/VariableRefreshRateController.h"
+#include <cutils/properties.h>
 
 using android::hardware::graphics::composer::PresentListener;
 using android::hardware::graphics::composer::VariableRefreshRateController;
@@ -81,6 +82,8 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
 
         virtual int32_t setFixedTe2Rate(const int rateHz) override;
 
+        virtual int32_t setDisplayTemperature(const int temperatue) override;
+
         const std::string& getPanelName() final;
 
         int32_t notifyExpectedPresent(int64_t timestamp, int32_t frameIntervalNs) override;
@@ -120,10 +123,13 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
         virtual bool isVrrSupported() const override { return mXrrSettings.versionInfo.isVrr(); }
 
         uint32_t mRcdId = -1;
+        uint32_t getDisplayTemperatue() { return mDisplayTemperature; };
 
     private:
         static constexpr const char* kDisplayCalFilePath = "/mnt/vendor/persist/display/";
         static constexpr const char* kPanelGammaCalFilePrefix = "gamma_calib_data";
+        static constexpr const char* kDisplayTempIntervalSec =
+                "ro.vendor.display.read_temp_interval";
         enum PanelGammaSource currentPanelGammaSource = PanelGammaSource::GAMMA_DEFAULT;
 
         bool checkLhbmMode(bool status, nsecs_t timoutNs);
@@ -148,6 +154,26 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
         int32_t setLhbmDisplayConfigLocked(uint32_t peakRate);
         void restoreLhbmDisplayConfigLocked();
 
+
+        // monitor display thermal temperature
+        int32_t getDisplayTemperature();
+        bool initDisplayTempMonitor(const std::string& display);
+        bool isTemperatureMonitorThreadRunning();
+        void checkTemperatureMonitorThread(bool shouldRun);
+        void temperatureMonitorThreadCreate();
+        void* temperatureMonitorThreadLoop();
+        bool mIsDisplayTempMonitorSupported = false;
+        volatile int32_t mTMThreadStatus;
+        std::atomic<bool> mTMLoopStatus;
+        std::condition_variable mTMCondition;
+        std::thread mTMThread;
+        std::mutex mThreadMutex;
+        int32_t mDisplayTempInterval;
+        String8 mDisplayTempSysfsNode;
+        std::string getPropertyDisplayTemperatureStr(const std::string& display) {
+            return "ro.vendor." + display + "." + getPanelName() + ".temperature_path";
+        }
+
         void onConfigChange(int configId);
 
         // LHBM
@@ -207,6 +233,7 @@ class ExynosPrimaryDisplay : public ExynosDisplay {
 
         XrrSettings_t mXrrSettings;
         std::shared_ptr<VariableRefreshRateController> mVariableRefreshRateController;
+        uint32_t mDisplayTemperature = UINT_MAX;
 };
 
 #endif
```

**hardware/google/graphics/gs101**
```diff
diff --git a/libhwc2.1/libcolormanager/ColorManager.cpp b/libhwc2.1/libcolormanager/ColorManager.cpp
index e9590e7..df6dc7c 100644
--- a/libhwc2.1/libcolormanager/ColorManager.cpp
+++ b/libhwc2.1/libcolormanager/ColorManager.cpp
@@ -290,6 +290,7 @@ int32_t ColorManager::updateColorConversionInfo() {
     displayScene.lhbm_on = false;
     displayScene.hdr_layer_state = displaycolor::HdrLayerState::kHdrNone;
     displayScene.dbv = 1000;
+    displayScene.refresh_rate = std::round(displayScene.refresh_rate);
 
     if (brightnessController) {
         displayScene.force_hdr = brightnessController->isDimSdr();
diff --git a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp
index d08ee3d..2f86070 100644
--- a/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp
+++ b/libhwc2.1/libmaindisplay/ExynosPrimaryDisplayModule.cpp
@@ -260,6 +260,7 @@ int32_t ExynosPrimaryDisplayModule::updatePresentColorConversionInfo()
 
     getDisplaySceneInfo().displayScene.lhbm_on = mBrightnessController->isLhbmOn();
     getDisplaySceneInfo().displayScene.dbv = mBrightnessController->getBrightnessLevel();
+    getDisplaySceneInfo().displayScene.temperature = getDisplayTemperatue();
     const DisplayType display = getDcDisplayType();
     if ((ret = displayColorInterface->UpdatePresent(display, getDisplaySceneInfo().displayScene)) !=
         0) {
```

**manifest**
```diff
diff --git a/default.xml b/default.xml
index de3b2080f..e5678717e 100644
--- a/default.xml
+++ b/default.xml
@@ -4,11 +4,11 @@
   <remote  name="aosp"
            fetch=".."
            review="https://android-review.googlesource.com/" />
-  <default revision="refs/tags/android-15.0.0_r3"
+  <default revision="refs/tags/android-15.0.0_r4"
            remote="aosp"
            sync-j="4" />
 
-  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r3"/>
+  <superproject name="platform/superproject" remote="aosp" revision="android-15.0.0_r4"/>
   <contactinfo bugurl="go/repo-bug" />
 
   <!-- BEGIN open-source projects -->
```

**packages/apps/Settings**
```diff
diff --git a/src/com/android/settings/accessibility/AccessibilitySettings.java b/src/com/android/settings/accessibility/AccessibilitySettings.java
index 8441c2acaa5..ecfda27237f 100644
--- a/src/com/android/settings/accessibility/AccessibilitySettings.java
+++ b/src/com/android/settings/accessibility/AccessibilitySettings.java
@@ -21,7 +21,6 @@ import android.accessibilityservice.AccessibilityShortcutInfo;
 import android.app.settings.SettingsEnums;
 import android.content.ComponentName;
 import android.content.Context;
-import android.content.pm.ServiceInfo;
 import android.hardware.input.InputManager;
 import android.os.Bundle;
 import android.os.Handler;
@@ -29,7 +28,6 @@ import android.os.UserHandle;
 import android.provider.Settings;
 import android.text.TextUtils;
 import android.util.ArrayMap;
-import android.util.Pair;
 import android.view.InputDevice;
 import android.view.accessibility.AccessibilityManager;
 
@@ -57,8 +55,6 @@ import java.util.ArrayList;
 import java.util.Collection;
 import java.util.List;
 import java.util.Map;
-import java.util.Set;
-import java.util.stream.Collectors;
 
 /** Activity with the accessibility settings. */
 @SearchIndexable(forTarget = SearchIndexable.ALL & ~SearchIndexable.ARC)
@@ -458,20 +454,9 @@ public class AccessibilitySettings extends DashboardFragment implements
                         UserHandle.myUserId());
         final List<AccessibilityActivityPreference> activityList =
                 preferenceHelper.createAccessibilityActivityPreferenceList(installedShortcutList);
-        final Set<Pair<String, CharSequence>> packageLabelPairs =
-                activityList.stream()
-                        .map(a11yActivityPref -> new Pair<>(
-                                a11yActivityPref.getPackageName(), a11yActivityPref.getLabel())
-                        ).collect(Collectors.toSet());
-
-        // Remove duplicate item here, new a ArrayList to copy unmodifiable list result
-        // (getInstalledAccessibilityServiceList).
+
         final List<AccessibilityServiceInfo> installedServiceList = new ArrayList<>(
                 a11yManager.getInstalledAccessibilityServiceList());
-        if (!packageLabelPairs.isEmpty()) {
-            installedServiceList.removeIf(
-                    target -> containsPackageAndLabelInList(packageLabelPairs, target));
-        }
         final List<RestrictedPreference> serviceList =
                 preferenceHelper.createAccessibilityServicePreferenceList(installedServiceList);
 
@@ -482,16 +467,6 @@ public class AccessibilitySettings extends DashboardFragment implements
         return preferenceList;
     }
 
-    private boolean containsPackageAndLabelInList(
-            Set<Pair<String, CharSequence>> packageLabelPairs,
-            AccessibilityServiceInfo targetServiceInfo) {
-        final ServiceInfo serviceInfo = targetServiceInfo.getResolveInfo().serviceInfo;
-        final String servicePackageName = serviceInfo.packageName;
-        final CharSequence serviceLabel = serviceInfo.loadLabel(getPackageManager());
-
-        return packageLabelPairs.contains(new Pair<>(servicePackageName, serviceLabel));
-    }
-
     private void initializePreBundledServicesMapFromArray(String categoryKey, int key) {
         String[] services = getResources().getStringArray(key);
         PreferenceCategory category = mCategoryToPrefCategoryMap.get(categoryKey);
diff --git a/src/com/android/settings/applications/AppInfoBase.java b/src/com/android/settings/applications/AppInfoBase.java
index 2c41be4ad41..1d774826c2d 100644
--- a/src/com/android/settings/applications/AppInfoBase.java
+++ b/src/com/android/settings/applications/AppInfoBase.java
@@ -18,6 +18,7 @@ package com.android.settings.applications;
 
 import static com.android.settingslib.RestrictedLockUtils.EnforcedAdmin;
 
+import android.Manifest;
 import android.app.Activity;
 import android.app.Dialog;
 import android.app.admin.DevicePolicyManager;
@@ -39,6 +40,7 @@ import android.os.UserManager;
 import android.text.TextUtils;
 import android.util.Log;
 
+import androidx.annotation.VisibleForTesting;
 import androidx.appcompat.app.AlertDialog;
 import androidx.fragment.app.DialogFragment;
 import androidx.fragment.app.Fragment;
@@ -135,8 +137,13 @@ public abstract class AppInfoBase extends SettingsPreferenceFragment
             }
         }
         if (intent != null && intent.hasExtra(Intent.EXTRA_USER_HANDLE)) {
-            mUserId = ((UserHandle) intent.getParcelableExtra(
-                    Intent.EXTRA_USER_HANDLE)).getIdentifier();
+            mUserId = ((UserHandle) intent.getParcelableExtra(Intent.EXTRA_USER_HANDLE))
+                    .getIdentifier();
+            if (mUserId != UserHandle.myUserId() && !hasInteractAcrossUsersFullPermission()) {
+                Log.w(TAG, "Intent not valid.");
+                finish();
+                return "";
+            }
         } else {
             mUserId = UserHandle.myUserId();
         }
@@ -163,6 +170,28 @@ public abstract class AppInfoBase extends SettingsPreferenceFragment
         return mPackageName;
     }
 
+    @VisibleForTesting
+    protected boolean hasInteractAcrossUsersFullPermission() {
+        Activity activity = getActivity();
+        if (!(activity instanceof SettingsActivity)) {
+            return false;
+        }
+        final String callingPackageName =
+                ((SettingsActivity) activity).getInitialCallingPackage();
+
+        if (TextUtils.isEmpty(callingPackageName)) {
+            Log.w(TAG, "Not able to get calling package name for permission check");
+            return false;
+        }
+        if (mPm.checkPermission(Manifest.permission.INTERACT_ACROSS_USERS_FULL, callingPackageName)
+                != PackageManager.PERMISSION_GRANTED) {
+            Log.w(TAG, "Package " + callingPackageName + " does not have required permission "
+                    + Manifest.permission.INTERACT_ACROSS_USERS_FULL);
+            return false;
+        }
+        return true;
+    }
+
     protected void setIntentAndFinish(boolean appChanged) {
         Log.i(TAG, "appChanged=" + appChanged);
         Intent intent = new Intent();
diff --git a/src/com/android/settings/users/AppRestrictionsFragment.java b/src/com/android/settings/users/AppRestrictionsFragment.java
index 1532448718c..c42e2f57b1d 100644
--- a/src/com/android/settings/users/AppRestrictionsFragment.java
+++ b/src/com/android/settings/users/AppRestrictionsFragment.java
@@ -651,7 +651,7 @@ public class AppRestrictionsFragment extends SettingsPreferenceFragment implemen
                     int requestCode = generateCustomActivityRequestCode(
                             RestrictionsResultReceiver.this.preference);
                     AppRestrictionsFragment.this.startActivityForResult(
-                            restrictionsIntent, requestCode);
+                            new Intent(restrictionsIntent), requestCode);
                 }
             }
         }
diff --git a/tests/robotests/src/com/android/settings/accessibility/AccessibilitySettingsTest.java b/tests/robotests/src/com/android/settings/accessibility/AccessibilitySettingsTest.java
index 1463cd0b7f9..41206068d18 100644
--- a/tests/robotests/src/com/android/settings/accessibility/AccessibilitySettingsTest.java
+++ b/tests/robotests/src/com/android/settings/accessibility/AccessibilitySettingsTest.java
@@ -32,6 +32,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
 import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.pm.ServiceInfo;
 import android.database.ContentObserver;
@@ -50,6 +51,7 @@ import com.android.internal.accessibility.util.AccessibilityUtils;
 import com.android.settings.R;
 import com.android.settings.SettingsActivity;
 import com.android.settings.testutils.XmlTestUtils;
+import com.android.settings.testutils.shadow.ShadowAccessibilityManager;
 import com.android.settings.testutils.shadow.ShadowApplicationPackageManager;
 import com.android.settings.testutils.shadow.ShadowBluetoothAdapter;
 import com.android.settings.testutils.shadow.ShadowBluetoothUtils;
@@ -75,7 +77,6 @@ import org.robolectric.RobolectricTestRunner;
 import org.robolectric.android.controller.ActivityController;
 import org.robolectric.annotation.Config;
 import org.robolectric.shadow.api.Shadow;
-import org.robolectric.shadows.ShadowAccessibilityManager;
 import org.robolectric.shadows.ShadowContentResolver;
 import org.xmlpull.v1.XmlPullParserException;
 
@@ -87,6 +88,7 @@ import java.util.List;
 /** Test for {@link AccessibilitySettings}. */
 @RunWith(RobolectricTestRunner.class)
 @Config(shadows = {
+        ShadowAccessibilityManager.class,
         ShadowBluetoothAdapter.class,
         ShadowUserManager.class,
         ShadowColorDisplayManager.class,
@@ -95,8 +97,10 @@ import java.util.List;
 })
 public class AccessibilitySettingsTest {
     private static final String PACKAGE_NAME = "com.android.test";
-    private static final String CLASS_NAME = PACKAGE_NAME + ".test_a11y_service";
-    private static final ComponentName COMPONENT_NAME = new ComponentName(PACKAGE_NAME, CLASS_NAME);
+    private static final ComponentName SERVICE_COMPONENT_NAME =
+            new ComponentName(PACKAGE_NAME, PACKAGE_NAME + ".test_a11y_service");
+    private static final ComponentName ACTIVITY_COMPONENT_NAME =
+            new ComponentName(PACKAGE_NAME, PACKAGE_NAME + ".test_a11y_activity");
     private static final String EMPTY_STRING = "";
     private static final String DEFAULT_SUMMARY = "default summary";
     private static final String DEFAULT_DESCRIPTION = "default description";
@@ -110,9 +114,7 @@ public class AccessibilitySettingsTest {
     private final Context mContext = ApplicationProvider.getApplicationContext();
     @Spy
     private final AccessibilityServiceInfo mServiceInfo = getMockAccessibilityServiceInfo(
-            PACKAGE_NAME, CLASS_NAME);
-    @Mock
-    private AccessibilityShortcutInfo mShortcutInfo;
+            SERVICE_COMPONENT_NAME);
     private ShadowAccessibilityManager mShadowAccessibilityManager;
     @Mock
     private LocalBluetoothManager mLocalBluetoothManager;
@@ -121,11 +123,11 @@ public class AccessibilitySettingsTest {
 
     @Before
     public void setup() {
-        mShadowAccessibilityManager = Shadow.extract(AccessibilityManager.getInstance(mContext));
+        mShadowAccessibilityManager = Shadow.extract(
+                mContext.getSystemService(AccessibilityManager.class));
         mShadowAccessibilityManager.setInstalledAccessibilityServiceList(new ArrayList<>());
         mContext.setTheme(androidx.appcompat.R.style.Theme_AppCompat);
         ShadowBluetoothUtils.sLocalBluetoothManager = mLocalBluetoothManager;
-        setMockAccessibilityShortcutInfo(mShortcutInfo);
 
         Intent intent = new Intent();
         intent.putExtra(SettingsActivity.EXTRA_SHOW_FRAGMENT,
@@ -368,7 +370,7 @@ public class AccessibilitySettingsTest {
         mFragment.onContentChanged();
 
         RestrictedPreference preference = mFragment.getPreferenceScreen().findPreference(
-                COMPONENT_NAME.flattenToString());
+                SERVICE_COMPONENT_NAME.flattenToString());
 
         assertThat(preference).isNotNull();
 
@@ -388,7 +390,7 @@ public class AccessibilitySettingsTest {
         mFragment.onResume();
 
         RestrictedPreference preference = mFragment.getPreferenceScreen().findPreference(
-                COMPONENT_NAME.flattenToString());
+                SERVICE_COMPONENT_NAME.flattenToString());
 
         assertThat(preference).isNotNull();
 
@@ -418,18 +420,44 @@ public class AccessibilitySettingsTest {
         assertThat(pref).isNull();
     }
 
-    private AccessibilityServiceInfo getMockAccessibilityServiceInfo(String packageName,
-            String className) {
-        return getMockAccessibilityServiceInfo(new ComponentName(packageName, className));
+    @Test
+    public void testSameNamedServiceAndActivity_bothPreferencesExist() {
+        final PackageManager pm = mContext.getPackageManager();
+        AccessibilityServiceInfo a11yServiceInfo = mServiceInfo;
+        AccessibilityShortcutInfo a11yShortcutInfo = getMockAccessibilityShortcutInfo();
+        // Ensure the test service and activity have the same package name and label.
+        // Before this change, any service and activity with the same package name and
+        // label would cause the service to be hidden.
+        assertThat(a11yServiceInfo.getComponentName())
+                .isNotEqualTo(a11yShortcutInfo.getComponentName());
+        assertThat(a11yServiceInfo.getComponentName().getPackageName())
+                .isEqualTo(a11yShortcutInfo.getComponentName().getPackageName());
+        assertThat(a11yServiceInfo.getResolveInfo().serviceInfo.loadLabel(pm))
+                .isEqualTo(a11yShortcutInfo.getActivityInfo().loadLabel(pm));
+        // Prepare A11yManager with the test service and activity.
+        mShadowAccessibilityManager.setInstalledAccessibilityServiceList(
+                List.of(mServiceInfo));
+        mShadowAccessibilityManager.setInstalledAccessibilityShortcutListAsUser(
+                List.of(getMockAccessibilityShortcutInfo()));
+        setupFragment();
+
+        // Both service and activity preferences should exist on the page.
+        RestrictedPreference servicePref = mFragment.getPreferenceScreen().findPreference(
+                a11yServiceInfo.getComponentName().flattenToString());
+        RestrictedPreference activityPref = mFragment.getPreferenceScreen().findPreference(
+                a11yShortcutInfo.getComponentName().flattenToString());
+        assertThat(servicePref).isNotNull();
+        assertThat(activityPref).isNotNull();
     }
 
     private AccessibilityServiceInfo getMockAccessibilityServiceInfo(ComponentName componentName) {
-        final ApplicationInfo applicationInfo = new ApplicationInfo();
-        final ServiceInfo serviceInfo = new ServiceInfo();
+        final ApplicationInfo applicationInfo = Mockito.mock(ApplicationInfo.class);
+        final ServiceInfo serviceInfo = Mockito.spy(new ServiceInfo());
         applicationInfo.packageName = componentName.getPackageName();
         serviceInfo.packageName = componentName.getPackageName();
         serviceInfo.name = componentName.getClassName();
         serviceInfo.applicationInfo = applicationInfo;
+        when(serviceInfo.loadLabel(any())).thenReturn(DEFAULT_LABEL);
 
         final ResolveInfo resolveInfo = new ResolveInfo();
         resolveInfo.serviceInfo = serviceInfo;
@@ -445,14 +473,16 @@ public class AccessibilitySettingsTest {
         return null;
     }
 
-    private void setMockAccessibilityShortcutInfo(AccessibilityShortcutInfo mockInfo) {
+    private AccessibilityShortcutInfo getMockAccessibilityShortcutInfo() {
+        AccessibilityShortcutInfo mockInfo = Mockito.mock(AccessibilityShortcutInfo.class);
         final ActivityInfo activityInfo = Mockito.mock(ActivityInfo.class);
         activityInfo.applicationInfo = new ApplicationInfo();
         when(mockInfo.getActivityInfo()).thenReturn(activityInfo);
         when(activityInfo.loadLabel(any())).thenReturn(DEFAULT_LABEL);
         when(mockInfo.loadSummary(any())).thenReturn(DEFAULT_SUMMARY);
         when(mockInfo.loadDescription(any())).thenReturn(DEFAULT_DESCRIPTION);
-        when(mockInfo.getComponentName()).thenReturn(COMPONENT_NAME);
+        when(mockInfo.getComponentName()).thenReturn(ACTIVITY_COMPONENT_NAME);
+        return mockInfo;
     }
 
     private void setInvisibleToggleFragmentType(AccessibilityServiceInfo info) {
diff --git a/tests/robotests/src/com/android/settings/applications/AppInfoWithHeaderTest.java b/tests/robotests/src/com/android/settings/applications/AppInfoWithHeaderTest.java
index 562212e3569..0ed56c0fec6 100644
--- a/tests/robotests/src/com/android/settings/applications/AppInfoWithHeaderTest.java
+++ b/tests/robotests/src/com/android/settings/applications/AppInfoWithHeaderTest.java
@@ -171,6 +171,32 @@ public class AppInfoWithHeaderTest {
         assertThat(mAppInfoWithHeader.mAppEntry).isNotNull();
     }
 
+    @Test
+    public void noCrossUserPermission_retrieveAppEntry_fail()
+            throws PackageManager.NameNotFoundException {
+        TestFragmentWithoutPermission testFragmentWithoutPermission =
+                new TestFragmentWithoutPermission();
+        final int userId = 1002;
+        final String packageName = "com.android.settings";
+
+        testFragmentWithoutPermission.mIntent.putExtra(Intent.EXTRA_USER_HANDLE,
+                new UserHandle(userId));
+        testFragmentWithoutPermission.mIntent.setData(Uri.fromParts("package",
+                packageName, null));
+        final ApplicationsState.AppEntry entry = mock(ApplicationsState.AppEntry.class);
+        entry.info = new ApplicationInfo();
+        entry.info.packageName = packageName;
+
+        when(testFragmentWithoutPermission.mState.getEntry(packageName, userId)).thenReturn(entry);
+        when(testFragmentWithoutPermission.mPm.getPackageInfoAsUser(eq(entry.info.packageName),
+                any(), eq(userId))).thenReturn(
+                testFragmentWithoutPermission.mPackageInfo);
+
+        testFragmentWithoutPermission.retrieveAppEntry();
+
+        assertThat(testFragmentWithoutPermission.mAppEntry).isNull();
+    }
+
     public static class TestFragment extends AppInfoWithHeader {
 
         PreferenceManager mManager;
@@ -223,6 +249,11 @@ public class AppInfoWithHeaderTest {
             return mShadowContext;
         }
 
+        @Override
+        protected boolean hasInteractAcrossUsersFullPermission() {
+            return true;
+        }
+
         @Override
         protected void onPackageRemoved() {
             mPackageRemovedCalled = true;
@@ -233,4 +264,11 @@ public class AppInfoWithHeaderTest {
             return mIntent;
         }
     }
+
+    private static final class TestFragmentWithoutPermission extends TestFragment {
+        @Override
+        protected boolean hasInteractAcrossUsersFullPermission() {
+            return false;
+        }
+    }
 }
diff --git a/tests/robotests/src/com/android/settings/applications/appcompat/UserAspectRatioDetailsTest.java b/tests/robotests/src/com/android/settings/applications/appcompat/UserAspectRatioDetailsTest.java
index ce03a6def34..d597b7ea045 100644
--- a/tests/robotests/src/com/android/settings/applications/appcompat/UserAspectRatioDetailsTest.java
+++ b/tests/robotests/src/com/android/settings/applications/appcompat/UserAspectRatioDetailsTest.java
@@ -39,23 +39,26 @@ import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.Manifest;
+import android.app.Application;
 import android.app.IActivityManager;
 import android.app.settings.SettingsEnums;
 import android.content.Context;
+import android.content.Intent;
+import android.content.pm.PackageManager;
 import android.os.Bundle;
 import android.os.RemoteException;
+import android.os.UserHandle;
 
-import androidx.fragment.app.testing.EmptyFragmentActivity;
 import androidx.test.core.app.ApplicationProvider;
-import androidx.test.ext.junit.rules.ActivityScenarioRule;
 
+import com.android.settings.SettingsActivity;
 import com.android.settings.testutils.FakeFeatureFactory;
 import com.android.settings.testutils.shadow.ShadowActivityManager;
 import com.android.settings.testutils.shadow.ShadowFragment;
 import com.android.settingslib.core.instrumentation.MetricsFeatureProvider;
 
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.InOrder;
@@ -71,14 +74,14 @@ import org.robolectric.annotation.Config;
 @Config(shadows = {ShadowActivityManager.class, ShadowFragment.class})
 public class UserAspectRatioDetailsTest {
 
-    @Rule
-    public ActivityScenarioRule<EmptyFragmentActivity> rule =
-            new ActivityScenarioRule<>(EmptyFragmentActivity.class);
-
     @Mock
     private UserAspectRatioManager mUserAspectRatioManager;
     @Mock
     private IActivityManager mAm;
+    @Mock
+    private PackageManager mPackageManager;
+    @Mock
+    private SettingsActivity mSettingsActivity;
 
     private RadioWithImagePreference mRadioButtonPref;
     private Context mContext;
@@ -93,6 +96,12 @@ public class UserAspectRatioDetailsTest {
         mFragment = spy(new UserAspectRatioDetails());
         when(mFragment.getContext()).thenReturn(mContext);
         when(mFragment.getAspectRatioManager()).thenReturn(mUserAspectRatioManager);
+        when(mFragment.getActivity()).thenReturn(mSettingsActivity);
+        when(mSettingsActivity.getApplication()).thenReturn((Application) mContext);
+        when(mSettingsActivity.getInitialCallingPackage()).thenReturn("test.package");
+        when(mSettingsActivity.getPackageManager()).thenReturn(mPackageManager);
+        when(mPackageManager.checkPermission(eq(Manifest.permission.INTERACT_ACROSS_USERS_FULL),
+                any())).thenReturn(PackageManager.PERMISSION_GRANTED);
         when(mUserAspectRatioManager.isOverrideToFullscreenEnabled(anyString(), anyInt()))
                 .thenReturn(false);
         ShadowActivityManager.setService(mAm);
@@ -111,8 +120,10 @@ public class UserAspectRatioDetailsTest {
                 .getUserMinAspectRatioOrder(USER_MIN_ASPECT_RATIO_FULLSCREEN);
         doReturn(2).when(mUserAspectRatioManager)
                 .getUserMinAspectRatioOrder(USER_MIN_ASPECT_RATIO_UNSET);
-        rule.getScenario().onActivity(a -> doReturn(a).when(mFragment).getActivity());
         final Bundle args = new Bundle();
+        Intent intent = new Intent();
+        intent.putExtra(Intent.EXTRA_USER_HANDLE, new UserHandle(0));
+        args.putParcelable("intent", intent);
         args.putString(ARG_PACKAGE_NAME, anyString());
         mFragment.setArguments(args);
         mFragment.onCreate(Bundle.EMPTY);
@@ -196,8 +207,10 @@ public class UserAspectRatioDetailsTest {
         doReturn(true).when(mUserAspectRatioManager)
                 .hasAspectRatioOption(anyInt(), anyString());
 
-        rule.getScenario().onActivity(a -> doReturn(a).when(mFragment).getActivity());
         final Bundle args = new Bundle();
+        Intent intent = new Intent();
+        intent.putExtra(Intent.EXTRA_USER_HANDLE, new UserHandle(0));
+        args.putParcelable("intent", intent);
         args.putString(ARG_PACKAGE_NAME, anyString());
         mFragment.setArguments(args);
         mFragment.onCreate(Bundle.EMPTY);
diff --git a/tests/robotests/src/com/android/settings/testutils/shadow/ShadowAccessibilityManager.java b/tests/robotests/src/com/android/settings/testutils/shadow/ShadowAccessibilityManager.java
index de7792c2ec0..fcd1e42c547 100644
--- a/tests/robotests/src/com/android/settings/testutils/shadow/ShadowAccessibilityManager.java
+++ b/tests/robotests/src/com/android/settings/testutils/shadow/ShadowAccessibilityManager.java
@@ -16,15 +16,18 @@
 
 package com.android.settings.testutils.shadow;
 
+import android.accessibilityservice.AccessibilityShortcutInfo;
 import android.annotation.NonNull;
 import android.annotation.UserIdInt;
 import android.content.ComponentName;
+import android.content.Context;
 import android.util.ArrayMap;
 import android.view.accessibility.AccessibilityManager;
 
 import org.robolectric.annotation.Implementation;
 import org.robolectric.annotation.Implements;
 
+import java.util.List;
 import java.util.Map;
 
 /**
@@ -33,9 +36,10 @@ import java.util.Map;
 @Implements(AccessibilityManager.class)
 public class ShadowAccessibilityManager extends org.robolectric.shadows.ShadowAccessibilityManager {
     private Map<ComponentName, ComponentName> mA11yFeatureToTileMap = new ArrayMap<>();
+    private List<AccessibilityShortcutInfo> mInstalledAccessibilityShortcutList = List.of();
 
     /**
-     * Implements a hidden method {@link AccessibilityManager.getA11yFeatureToTileMap}
+     * Implements a hidden method {@link AccessibilityManager#getA11yFeatureToTileMap}
      */
     @Implementation
     public Map<ComponentName, ComponentName> getA11yFeatureToTileMap(@UserIdInt int userId) {
@@ -49,4 +53,22 @@ public class ShadowAccessibilityManager extends org.robolectric.shadows.ShadowAc
             @NonNull Map<ComponentName, ComponentName> a11yFeatureToTileMap) {
         mA11yFeatureToTileMap = a11yFeatureToTileMap;
     }
+
+    /**
+     * Implements the hidden method
+     * {@link AccessibilityManager#getInstalledAccessibilityShortcutListAsUser}.
+     */
+    @Implementation
+    public List<AccessibilityShortcutInfo> getInstalledAccessibilityShortcutListAsUser(
+            @NonNull Context context, @UserIdInt int userId) {
+        return mInstalledAccessibilityShortcutList;
+    }
+
+    /**
+     * Sets the value to be returned by {@link #getInstalledAccessibilityShortcutListAsUser}.
+     */
+    public void setInstalledAccessibilityShortcutListAsUser(
+            @NonNull List<AccessibilityShortcutInfo> installedAccessibilityShortcutList) {
+        mInstalledAccessibilityShortcutList = installedAccessibilityShortcutList;
+    }
 }
```

**packages/modules/Bluetooth**
```diff
diff --git a/system/bta/dm/bta_dm_disc.cc b/system/bta/dm/bta_dm_disc.cc
index b8e24551db..3e92f3e978 100644
--- a/system/bta/dm/bta_dm_disc.cc
+++ b/system/bta/dm/bta_dm_disc.cc
@@ -33,9 +33,11 @@
 #include "bta/dm/bta_dm_disc_legacy.h"
 #include "bta/include/bta_gatt_api.h"
 #include "com_android_bluetooth_flags.h"
+#include "btif/include/btif_storage.h"
 #include "common/circular_buffer.h"
 #include "common/init_flags.h"
 #include "common/strings.h"
+#include "device/include/interop.h"
 #include "internal_include/bt_target.h"
 #include "main/shim/dumpsys.h"
 #include "os/logging/log_adapter.h"
@@ -333,8 +335,17 @@ static void bta_dm_disc_result(tBTA_DM_SVC_RES& disc_result) {
     bta_dm_discovery_cb.service_search_cbacks.on_service_discovery_results(
         r.bd_addr, r.uuids, r.result);
   } else {
+    char remote_name[BD_NAME_LEN] = "";
     bta_dm_discovery_cb.transports &= ~BT_TRANSPORT_LE;
-    GAP_BleReadPeerPrefConnParams(bta_dm_discovery_cb.peer_bdaddr);
+    if (btif_storage_get_stored_remote_name(bta_dm_discovery_cb.peer_bdaddr, remote_name) &&
+        interop_match_name(INTEROP_DISABLE_LE_CONN_PREFERRED_PARAMS, remote_name)) {
+      // Some devices provide PPCP values that are incompatible with the device-side firmware.
+      log::info("disable PPCP read: interop matched name {} address {}", remote_name,
+                bta_dm_discovery_cb.peer_bdaddr);
+    } else {
+      log::info("reading PPCP");
+      GAP_BleReadPeerPrefConnParams(bta_dm_discovery_cb.peer_bdaddr);
+    }
 
     bta_dm_discovery_cb.service_search_cbacks.on_gatt_results(
         bta_dm_discovery_cb.peer_bdaddr, BD_NAME{}, disc_result.gatt_uuids,
diff --git a/system/conf/interop_database.conf b/system/conf/interop_database.conf
index a275f6bc6b..8f190ab9ee 100644
--- a/system/conf/interop_database.conf
+++ b/system/conf/interop_database.conf
@@ -194,6 +194,9 @@ Motorola Keyboard KZ500 v122 = Name_Based
 [INTEROP_DISABLE_LE_CONN_PREFERRED_PARAMS]
 BSMBB09DS = Name_Based
 ELECOM = Name_Based
+Dexcom = Name_Based
+DXCM = Name_Based
+DX0 = Name_Based
 
 # Disable role switch for headsets/car-kits
 # Some car kits allow role switch but when DUT initiates role switch
diff --git a/system/device/test/interop_test.cc b/system/device/test/interop_test.cc
index 3ad3db2ce9..24c2c2ab37 100644
--- a/system/device/test/interop_test.cc
+++ b/system/device/test/interop_test.cc
@@ -433,6 +433,9 @@ TEST_F(InteropTest, test_name_hit) {
                                  "Motorola Keyboard KZ500"));
   EXPECT_TRUE(interop_match_name(INTEROP_DISABLE_LE_CONN_PREFERRED_PARAMS,
                                  "BSMBB09DS"));
+  EXPECT_TRUE(interop_match_name(INTEROP_DISABLE_LE_CONN_PREFERRED_PARAMS, "DXCMog"));
+  EXPECT_TRUE(interop_match_name(INTEROP_DISABLE_LE_CONN_PREFERRED_PARAMS, "Dexcom 123"));
+  EXPECT_TRUE(interop_match_name(INTEROP_DISABLE_LE_CONN_PREFERRED_PARAMS, "DX01ab"));
   EXPECT_TRUE(interop_match_name(INTEROP_DISABLE_AAC_CODEC, "abramtek M1"));
   EXPECT_TRUE(
       interop_match_name(INTEROP_DISABLE_AAC_VBR_CODEC, "Audi_MMI_2781"));
```

**packages/modules/Wifi**
```diff
diff --git a/service/java/com/android/server/wifi/WifiConfigurationUtil.java b/service/java/com/android/server/wifi/WifiConfigurationUtil.java
index 4421fcd08e..501a071b34 100644
--- a/service/java/com/android/server/wifi/WifiConfigurationUtil.java
+++ b/service/java/com/android/server/wifi/WifiConfigurationUtil.java
@@ -16,7 +16,11 @@
 
 package com.android.server.wifi;
 
+import static android.net.wifi.WifiConfiguration.SECURITY_TYPE_NUM;
 import static android.net.wifi.WifiManager.ALL_ZEROS_MAC_ADDRESS;
+import static android.net.wifi.hotspot2.PasspointConfiguration.MAX_NUMBER_OF_OI;
+import static android.net.wifi.hotspot2.PasspointConfiguration.MAX_OI_VALUE;
+import static android.net.wifi.hotspot2.PasspointConfiguration.MAX_URL_BYTES;
 
 import static com.android.server.wifi.util.NativeUtil.addEnclosingQuotes;
 
@@ -31,6 +35,7 @@ import android.net.wifi.WifiManager;
 import android.net.wifi.WifiNetworkSpecifier;
 import android.net.wifi.WifiScanner;
 import android.net.wifi.WifiSsid;
+import android.net.wifi.hotspot2.PasspointConfiguration;
 import android.os.PatternMatcher;
 import android.text.TextUtils;
 import android.util.Log;
@@ -46,8 +51,10 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.BitSet;
 import java.util.Comparator;
+import java.util.HashSet;
 import java.util.List;
 import java.util.Objects;
+import java.util.Set;
 
 /**
  * WifiConfiguration utility for any {@link android.net.wifi.WifiConfiguration} related operations.
@@ -70,6 +77,7 @@ public class WifiConfigurationUtil {
     private static final int PSK_SAE_HEX_LEN = 64;
     private static final int WEP104_KEY_BYTES_LEN = 13;
     private static final int WEP40_KEY_BYTES_LEN = 5;
+    private static final int MAX_STRING_LENGTH = 512;
 
     @VisibleForTesting
     public static final String PASSWORD_MASK = "*";
@@ -750,7 +758,8 @@ public class WifiConfigurationUtil {
         if (!validateSsid(config.SSID, isAdd)) {
             return false;
         }
-        if (!validateBssid(config.BSSID)) {
+        if (!validateBssid(config.BSSID) || !validateBssid(config.dhcpServer)
+                || !validateBssid(config.defaultGwMacAddress)) {
             return false;
         }
         if (!validateBitSets(config)) {
@@ -759,9 +768,22 @@ public class WifiConfigurationUtil {
         if (!validateKeyMgmt(config.allowedKeyManagement)) {
             return false;
         }
-        if (config.isSecurityType(WifiConfiguration.SECURITY_TYPE_WEP)
-                && config.wepKeys != null
-                && !validateWepKeys(config.wepKeys, config.wepTxKeyIndex, isAdd)) {
+        if (!validateSecurityParameters(config.getSecurityParamsList())) {
+            return false;
+        }
+        if (!validatePasspoint(config)) {
+            return false;
+        }
+        if (!validateNetworkSelectionStatus(config.getNetworkSelectionStatus())) {
+            return false;
+        }
+
+        if (config.isSecurityType(WifiConfiguration.SECURITY_TYPE_WEP)) {
+            if (config.wepKeys != null
+                    && !validateWepKeys(config.wepKeys, config.wepTxKeyIndex, isAdd)) {
+                return false;
+            }
+        } else if (!validateWepKeys(config.wepKeys, config.wepTxKeyIndex, false)) {
             return false;
         }
         if (config.isSecurityType(WifiConfiguration.SECURITY_TYPE_PSK)
@@ -793,10 +815,92 @@ public class WifiConfigurationUtil {
         if (!validateIpConfiguration(config.getIpConfiguration())) {
             return false;
         }
+
+        if (config.getDppConnector().length > MAX_URL_BYTES
+                || config.getDppCSignKey().length > MAX_URL_BYTES
+                || config.getDppPrivateEcKey().length > MAX_URL_BYTES
+                || config.getDppNetAccessKey().length > MAX_URL_BYTES) {
+            return false;
+        }
         // TBD: Validate some enterprise params as well in the future here.
         return true;
     }
 
+    private static boolean validateStringField(String field, int maxLength) {
+        return field == null || field.length() <= maxLength;
+    }
+
+    private static boolean validatePasspoint(WifiConfiguration config) {
+        if (!validateStringField(config.FQDN, PasspointConfiguration.MAX_STRING_LENGTH)) {
+            return false;
+        }
+        if (!validateStringField(config.providerFriendlyName,
+                PasspointConfiguration.MAX_STRING_LENGTH)) {
+            return false;
+        }
+        if (!validateRoamingConsortiumIds(config.roamingConsortiumIds)) {
+            return false;
+        }
+        if (!validateUpdateIdentifier(config.updateIdentifier)) {
+            return false;
+        }
+        return true;
+    }
+
+    private static boolean validateUpdateIdentifier(String updateIdentifier) {
+        if (TextUtils.isEmpty(updateIdentifier)) {
+            return true;
+        }
+        try {
+            Integer.valueOf(updateIdentifier);
+        } catch (NumberFormatException e) {
+            return false;
+        }
+        return true;
+    }
+
+    private static boolean validateNetworkSelectionStatus(
+            WifiConfiguration.NetworkSelectionStatus status) {
+        if (status == null) {
+            return false;
+        }
+        return validateStringField(status.getConnectChoice(), MAX_STRING_LENGTH)
+                    && validateBssid(status.getNetworkSelectionBSSID());
+    }
+
+    private static boolean validateRoamingConsortiumIds(long[] roamingConsortiumIds) {
+        if (roamingConsortiumIds != null) {
+            if (roamingConsortiumIds.length > MAX_NUMBER_OF_OI) {
+                Log.d(TAG, "too many Roaming Consortium Organization Identifiers in the "
+                        + "profile");
+                return false;
+            }
+            for (long oi : roamingConsortiumIds) {
+                if (oi < 0 || oi > MAX_OI_VALUE) {
+                    Log.d(TAG, "Organization Identifiers is out of range");
+                    return false;
+                }
+            }
+        }
+        return true;
+    }
+
+    private static boolean validateSecurityParameters(List<SecurityParams> paramsList) {
+        Set<Integer> uniqueSecurityTypes = new HashSet<>(SECURITY_TYPE_NUM + 1);
+        for (SecurityParams params : paramsList) {
+            int securityType = params.getSecurityType();
+            if (securityType < 0 || securityType > SECURITY_TYPE_NUM) {
+                return false;
+            }
+            if (uniqueSecurityTypes.contains(securityType)) {
+                return false;
+            }
+            uniqueSecurityTypes.add(securityType);
+        }
+        return true;
+
+    }
+
     private static boolean validateBssidPattern(
             Pair<MacAddress, MacAddress> bssidPatternMatcher) {
         if (bssidPatternMatcher == null) return true;
diff --git a/service/java/com/android/server/wifi/WifiServiceImpl.java b/service/java/com/android/server/wifi/WifiServiceImpl.java
index 30066a2387..22fc6ee42f 100644
--- a/service/java/com/android/server/wifi/WifiServiceImpl.java
+++ b/service/java/com/android/server/wifi/WifiServiceImpl.java
@@ -3891,6 +3891,11 @@ public class WifiServiceImpl extends BaseWifiService {
         boolean isCamera = mWifiPermissionsUtil.checkCameraPermission(callingUid);
         boolean isSystem = mWifiPermissionsUtil.isSystem(packageName, callingUid);
         boolean isPrivileged = isPrivileged(callingPid, callingUid);
+        if (!isPrivileged && !isSystem && !isAdmin && config.getBssidAllowlistInternal() != null) {
+            mLog.info("addOrUpdateNetwork with allow bssid list is not allowed for uid=%")
+                    .c(callingUid).flush();
+            return -1;
+        }
 
         if (!isTargetSdkLessThanQOrPrivileged(packageName, callingPid, callingUid)) {
             mLog.info("addOrUpdateNetwork not allowed for uid=%").c(callingUid).flush();
diff --git a/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java b/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java
index 8dbe628f5c..81b182c9df 100644
--- a/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java
+++ b/service/tests/wifitests/src/com/android/server/wifi/WifiConfigurationUtilTest.java
@@ -18,6 +18,7 @@ package com.android.server.wifi;
 
 import static android.net.wifi.WifiEnterpriseConfig.OCSP_NONE;
 import static android.net.wifi.WifiEnterpriseConfig.OCSP_REQUIRE_CERT_STATUS;
+import static android.net.wifi.hotspot2.PasspointConfiguration.MAX_URL_BYTES;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -53,6 +54,7 @@ import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.nio.charset.StandardCharsets;
 import java.security.cert.X509Certificate;
 import java.util.ArrayList;
 import java.util.Arrays;
@@ -77,6 +79,7 @@ public class WifiConfigurationUtilTest extends WifiBaseTest {
             new UserInfo(CURRENT_USER_ID, "owner", 0),
             new UserInfo(CURRENT_USER_MANAGED_PROFILE_USER_ID, "managed profile", 0));
     private static final long SUPPORTED_FEATURES_ALL = Long.MAX_VALUE;
+    private final String mGeneratedString256 = "a".repeat(256);
 
     private MockitoSession mSession;
 
@@ -1606,4 +1609,76 @@ public class WifiConfigurationUtilTest extends WifiBaseTest {
         assertTrue(WifiConfigurationUtil.isConfigLinkable(saeConfig));
         assertFalse(WifiConfigurationUtil.isConfigLinkable(saeDisabledConfig));
     }
+
+    @Test
+    public void testWepKeyOnNonWepConfig() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        pskConfig.wepKeys = new String[4];
+        pskConfig.wepKeys[0] = mGeneratedString256;
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
+
+    @Test
+    public void testInvalidFqdnAndFriendlyName() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+
+        pskConfig.FQDN = mGeneratedString256;
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+
+        pskConfig.FQDN = null;
+        pskConfig.providerFriendlyName = mGeneratedString256;
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
+
+    @Test
+    public void testInvalidDhcpAndGtw() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        pskConfig.dhcpServer = TEST_BSSID;
+        pskConfig.defaultGwMacAddress = TEST_BSSID;
+        assertTrue(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+        pskConfig.dhcpServer = mGeneratedString256;
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+        pskConfig.dhcpServer = TEST_BSSID;
+        pskConfig.defaultGwMacAddress = mGeneratedString256;
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
+
+    @Test
+    public void testInvalidSecurityParameter() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        List<SecurityParams> securityParamsList = new ArrayList<>();
+        securityParamsList.add(SecurityParams.createSecurityParamsBySecurityType(
+                WifiConfiguration.SECURITY_TYPE_PSK));
+        securityParamsList.add(SecurityParams.createSecurityParamsBySecurityType(
+                WifiConfiguration.SECURITY_TYPE_PSK));
+
+        pskConfig.setSecurityParams(securityParamsList);
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
+
+    @Test
+    public void testInvalidUserConnectChoice() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        String generatedString513 = "a".repeat(513);
+        pskConfig.getNetworkSelectionStatus().setConnectChoice(generatedString513);
+
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
+
+    @Test
+    public void testInvalidDppConfig() {
+        WifiConfiguration pskConfig = WifiConfigurationTestUtil.createPskNetwork();
+        String generatedString = "a".repeat(MAX_URL_BYTES + 1);
+        pskConfig.setDppConfigurator(generatedString.getBytes(StandardCharsets.UTF_8));
+        assertFalse(WifiConfigurationUtil.validate(pskConfig, SUPPORTED_FEATURES_ALL,
+                WifiConfigurationUtil.VALIDATE_FOR_ADD));
+    }
 }
diff --git a/service/tests/wifitests/src/com/android/server/wifi/WifiServiceImplTest.java b/service/tests/wifitests/src/com/android/server/wifi/WifiServiceImplTest.java
index 1e25a458c0..90dc2c86ea 100644
--- a/service/tests/wifitests/src/com/android/server/wifi/WifiServiceImplTest.java
+++ b/service/tests/wifitests/src/com/android/server/wifi/WifiServiceImplTest.java
@@ -6845,6 +6845,31 @@ public class WifiServiceImplTest extends WifiBaseTest {
         verify(mWifiMetrics).incrementNumAddOrUpdateNetworkCalls();
     }
 
+    /**
+     * Verify that add or update networks is allowed for apps targeting below Q SDK.
+     */
+    @Test
+    public void testAddOrUpdateNetworkWithBssidAllowListIsNotAllowedForAppsNotPrivileged()
+            throws Exception {
+        doReturn(AppOpsManager.MODE_ALLOWED).when(mAppOpsManager)
+                .noteOp(AppOpsManager.OPSTR_CHANGE_WIFI_STATE, Process.myUid(), TEST_PACKAGE_NAME);
+        when(mWifiConfigManager.addOrUpdateNetwork(any(),  anyInt(), any(), eq(false))).thenReturn(
+                new NetworkUpdateResult(0));
+        when(mWifiPermissionsUtil.isTargetSdkLessThan(anyString(),
+                eq(Build.VERSION_CODES.Q), anyInt())).thenReturn(true);
+
+        WifiConfiguration config = WifiConfigurationTestUtil.createOpenNetwork();
+        config.setBssidAllowlist(Collections.emptyList());
+        mLooper.startAutoDispatch();
+        assertEquals(-1,
+                mWifiServiceImpl.addOrUpdateNetwork(config, TEST_PACKAGE_NAME, mAttribution));
+        mLooper.stopAutoDispatchAndIgnoreExceptions();
+
+        verifyCheckChangePermission(TEST_PACKAGE_NAME);
+        verify(mWifiConfigManager, never()).addOrUpdateNetwork(any(),  anyInt(), any(), eq(false));
+        verify(mWifiMetrics, never()).incrementNumAddOrUpdateNetworkCalls();
+    }
+
     /**
      * Verify that add or update networks is not allowed for apps targeting below Q SDK
      * when DISALLOW_ADD_WIFI_CONFIG user restriction is set.
```

**packages/providers/MediaProvider**
```diff
diff --git a/src/com/android/providers/media/MediaProvider.java b/src/com/android/providers/media/MediaProvider.java
index 72f45d6a1..34e726ab0 100644
--- a/src/com/android/providers/media/MediaProvider.java
+++ b/src/com/android/providers/media/MediaProvider.java
@@ -8219,6 +8219,8 @@ public class MediaProvider extends ContentProvider {
                 case IMAGES_MEDIA_ID:
                 case DOWNLOADS_ID:
                 case FILES_ID:
+                    // Check if the caller has the required permissions to do placement
+                    enforceCallingPermission(uri, extras, true);
                     break;
                 default:
                     throw new IllegalArgumentException("Movement of " + uri
```

**system/core**
```diff
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
index 6d422c6141..1ec8634444 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
@@ -335,6 +335,9 @@ class SnapshotManager final : public ISnapshotManager {
     // after loading selinux policy.
     bool PrepareSnapuserdArgsForSelinux(std::vector<std::string>* snapuserd_argv);
 
+    // If snapuserd from first stage init was started from system partition.
+    bool MarkSnapuserdFromSystem();
+
     // Detach dm-user devices from the first stage snapuserd. Load
     // new dm-user tables after loading selinux policy.
     bool DetachFirstStageSnapuserdForSelinux();
@@ -670,6 +673,7 @@ class SnapshotManager final : public ISnapshotManager {
     std::string GetForwardMergeIndicatorPath();
     std::string GetOldPartitionMetadataPath();
     std::string GetBootSnapshotsWithoutSlotSwitchPath();
+    std::string GetSnapuserdFromSystemPath();
 
     const LpMetadata* ReadOldPartitionMetadata(LockedFile* lock);
 
diff --git a/fs_mgr/libsnapshot/snapshot.cpp b/fs_mgr/libsnapshot/snapshot.cpp
index c01360e0ba..e4a6153a84 100644
--- a/fs_mgr/libsnapshot/snapshot.cpp
+++ b/fs_mgr/libsnapshot/snapshot.cpp
@@ -20,6 +20,7 @@
 #include <sys/file.h>
 #include <sys/types.h>
 #include <sys/unistd.h>
+#include <sys/xattr.h>
 
 #include <filesystem>
 #include <optional>
@@ -88,7 +89,10 @@ static constexpr char kBootSnapshotsWithoutSlotSwitch[] =
         "/metadata/ota/snapshot-boot-without-slot-switch";
 static constexpr char kBootIndicatorPath[] = "/metadata/ota/snapshot-boot";
 static constexpr char kRollbackIndicatorPath[] = "/metadata/ota/rollback-indicator";
+static constexpr char kSnapuserdFromSystem[] = "/metadata/ota/snapuserd-from-system";
 static constexpr auto kUpdateStateCheckInterval = 2s;
+static constexpr char kOtaFileContext[] = "u:object_r:ota_metadata_file:s0";
+
 /*
  * The readahead size is set to 32kb so that
  * there is no significant memory pressure (/proc/pressure/memory) during boot.
@@ -318,7 +322,7 @@ bool SnapshotManager::RemoveAllUpdateState(LockedFile* lock, const std::function
     std::vector<std::string> files = {
             GetSnapshotBootIndicatorPath(),          GetRollbackIndicatorPath(),
             GetForwardMergeIndicatorPath(),          GetOldPartitionMetadataPath(),
-            GetBootSnapshotsWithoutSlotSwitchPath(),
+            GetBootSnapshotsWithoutSlotSwitchPath(), GetSnapuserdFromSystemPath(),
     };
     for (const auto& file : files) {
         RemoveFileIfExists(file);
@@ -1457,6 +1461,10 @@ std::string SnapshotManager::GetRollbackIndicatorPath() {
     return metadata_dir_ + "/" + android::base::Basename(kRollbackIndicatorPath);
 }
 
+std::string SnapshotManager::GetSnapuserdFromSystemPath() {
+    return metadata_dir_ + "/" + android::base::Basename(kSnapuserdFromSystem);
+}
+
 std::string SnapshotManager::GetForwardMergeIndicatorPath() {
     return metadata_dir_ + "/allow-forward-merge";
 }
@@ -2122,6 +2130,34 @@ bool SnapshotManager::UpdateUsesODirect(LockedFile* lock) {
     return update_status.o_direct();
 }
 
+bool SnapshotManager::MarkSnapuserdFromSystem() {
+    auto path = GetSnapuserdFromSystemPath();
+
+    if (!android::base::WriteStringToFile("1", path)) {
+        PLOG(ERROR) << "Unable to write to vendor update path: " << path;
+        return false;
+    }
+
+    unique_fd fd(open(path.c_str(), O_PATH));
+    if (fd < 0) {
+        PLOG(ERROR) << "Failed to open file: " << path;
+        return false;
+    }
+
+    /*
+     * This function is invoked by first stage init and hence we need to
+     * explicitly set the correct selinux label for this file as update_engine
+     * will try to remove this file later on once the snapshot merge is
+     * complete.
+     */
+    if (fsetxattr(fd.get(), XATTR_NAME_SELINUX, kOtaFileContext, strlen(kOtaFileContext) + 1, 0) <
+        0) {
+        PLOG(ERROR) << "fsetxattr for the path: " << path << " failed";
+    }
+
+    return true;
+}
+
 /*
  * Please see b/304829384 for more details.
  *
@@ -2158,14 +2194,35 @@ bool SnapshotManager::UpdateUsesODirect(LockedFile* lock) {
  *         iii: If both (i) and (ii) are true, then use the dm-snapshot based
  *         approach.
  *
+ * 3: Post OTA reboot, if the vendor partition was updated from Android 12 to
+ * any other release post Android 12, then snapuserd binary will be "system"
+ * partition as post Android 12, init_boot will contain a copy of snapuserd
+ * binary. Thus, during first stage init, if init is able to communicate to
+ * daemon, that gives us a signal that the binary is from "system" copy. Hence,
+ * there is no need to fallback to legacy dm-snapshot. Thus, init will use a
+ * marker in /metadata to signal that the snapuserd binary from first stage init
+ * can handle userspace snapshots.
+ *
  */
 bool SnapshotManager::IsLegacySnapuserdPostReboot() {
-    if (is_legacy_snapuserd_.has_value() && is_legacy_snapuserd_.value() == true) {
-        auto slot = GetCurrentSlot();
-        if (slot == Slot::Target) {
+    auto slot = GetCurrentSlot();
+    if (slot == Slot::Target) {
+        /*
+            If this marker is present, the daemon can handle userspace snapshots.
+            During post-OTA reboot, this implies that the vendor partition is
+            Android 13 or higher. If the snapshots were created on an
+            Android 12 vendor, this means the vendor partition has been updated.
+        */
+        if (access(GetSnapuserdFromSystemPath().c_str(), F_OK) == 0) {
+            is_snapshot_userspace_ = true;
+            return false;
+        }
+        // If the marker isn't present and if the vendor is still in Android 12
+        if (is_legacy_snapuserd_.has_value() && is_legacy_snapuserd_.value() == true) {
             return true;
         }
     }
+
     return false;
 }
 
diff --git a/init/first_stage_mount.cpp b/init/first_stage_mount.cpp
index 5d3a273548..55cce6eaab 100644
--- a/init/first_stage_mount.cpp
+++ b/init/first_stage_mount.cpp
@@ -395,12 +395,7 @@ bool FirstStageMountVBootV2::CreateSnapshotPartitions(SnapshotManager* sm) {
 
     use_snapuserd_ = sm->IsSnapuserdRequired();
     if (use_snapuserd_) {
-        if (sm->UpdateUsesUserSnapshots()) {
-            LaunchFirstStageSnapuserd();
-        } else {
-            LOG(FATAL) << "legacy virtual-ab is no longer supported";
-            return false;
-        }
+        LaunchFirstStageSnapuserd();
     }
 
     sm->SetUeventRegenCallback([this](const std::string& device) -> bool {
diff --git a/init/snapuserd_transition.cpp b/init/snapuserd_transition.cpp
index 9e3ff4175e..2370bc2050 100644
--- a/init/snapuserd_transition.cpp
+++ b/init/snapuserd_transition.cpp
@@ -100,6 +100,10 @@ void LaunchFirstStageSnapuserd() {
     }
     if (client->SupportsSecondStageSocketHandoff()) {
         setenv(kSnapuserdFirstStageInfoVar, "socket", 1);
+        auto sm = SnapshotManager::NewForFirstStageMount();
+        if (!sm->MarkSnapuserdFromSystem()) {
+            LOG(ERROR) << "Failed to update MarkSnapuserdFromSystem";
+        }
     }
 
     setenv(kSnapuserdFirstStagePidVar, std::to_string(pid).c_str(), 1);
```

