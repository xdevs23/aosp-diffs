```diff
diff --git a/AndroidManifest-exclude-overrides.xml b/AndroidManifest-exclude-overrides.xml
index c007dcc..292be75 100644
--- a/AndroidManifest-exclude-overrides.xml
+++ b/AndroidManifest-exclude-overrides.xml
@@ -54,36 +54,8 @@
             tools:node="remove" />
         <receiver android:name=".screenshot.SmartActionsReceiver"
             tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".usb.UsbAccessoryUriActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".usb.UsbContaminantActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".usb.UsbDebuggingActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".usb.UsbDebuggingSecondaryUserActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".wifi.WifiDebuggingActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity-alias android:name=".WifiDebuggingActivityAlias"
-            android:targetActivity=".wifi.WifiDebuggingActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".wifi.WifiDebuggingSecondaryUserActivity"
-            tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".net.NetworkOverLimitActivity"
-            tools:node="remove" />
         <activity android:name=".media.MediaProjectionAppSelectorActivity"
             tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".SlicePermissionActivity"
-            tools:node="remove" />
         <activity android:name=".telephony.ui.activity.SwitchToManagedProfileForCallActivity"
             tools:node="remove" />
         <!-- platform logo easter egg activity -->
@@ -107,9 +79,6 @@
             tools:node="remove" />
         <activity android:name=".keyguard.WorkLockActivity"
             tools:node="remove" />
-        <!-- TODO(b/295161958) check if this can be removed safely -->
-        <activity android:name=".user.CreateUserActivity"
-            tools:node="remove" />
         <activity android:name=".Somnambulator"
             tools:node="remove" />
         <activity android:name=".settings.brightness.BrightnessDialog"
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..353c4ac
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,65 @@
+{
+  "tv-postsubmit": [
+    {
+      "name": "SystemUITests",
+      "options": [
+        {"include-filter": "com.android.systemui.screenrecord.ScreenRecordPermissionDialogDelegateTest"},
+        {"include-filter": "com.android.systemui.mediaprojection.permission"},
+        {"include-filter": "com.android.systemui.sensorprivacy"},
+        {"include-filter": "com.android.systemui.toast"},
+        {"include-filter": "com.android.systemui.usb"},
+        {"include-filter": "com.android.systemui.volume"},
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    },
+    {
+      "name": "TvSystemUITests",
+      "options": [
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    },
+    {
+      "name": "WMShellUnitTests",
+      "options": [
+        {"include-filter": "com.android.wm.shell.pip.tv"},
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    },
+    {
+      "name": "VpnDialogsTests",
+      "options": [
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    },
+    {
+      "name": "CtsSystemUiTestCases",
+      "options": [
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    },
+    {
+      "name": "CtsWindowManagerDeviceOther",
+      "options": [
+        {"include-filter": "android.server.wm.other.PinnedStackTests"},
+        {"include-filter": "android.server.wm.other.TvMaxWindowSizeTests"},
+        {"include-filter": "android.server.wm.other.PictureInPictureParamsBuilderTest"},
+        {"include-filter": "android.server.wm.other.PrivacyIndicatorBoundsTests"},
+        {"include-filter": "android.server.wm.other.KeepClearRectsTests"},
+        {"include-filter": "android.server.wm.other.DreamManagerServiceTests"},
+
+        {"exclude-filter": "android.server.wm.other.PinnedStackTests#testPreventSetAspectRatioWhileExpanding"},
+        {"exclude-filter": "android.server.wm.other.PinnedStackTests#testConfigurationChangeOrderDuringTransition"},
+        {"exclude-filter": "android.server.wm.other.PinnedStackTests#testLaunchTaskByAffinityMatchSingleTask"},
+        {"exclude-filter": "android.server.wm.other.PinnedStackTests#testPipFromTaskWithMultipleActivitiesAndExpandPip"},
+
+        {"exclude-annotation": "org.junit.Ignore"},
+        {"exclude-annotation": "androidx.test.filters.FlakyTest"}
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/res/drawable/ic_volume_media_mute.xml b/res/drawable/ic_volume_media_mute.xml
index b683089..7a44aa6 100644
--- a/res/drawable/ic_volume_media_mute.xml
+++ b/res/drawable/ic_volume_media_mute.xml
@@ -18,11 +18,9 @@
 <vector xmlns:android="http://schemas.android.com/apk/res/android"
     android:width="@dimen/tv_volume_icons_size"
     android:height="@dimen/tv_volume_icons_size"
-    android:viewportWidth="24.0"
-    android:viewportHeight="24.0">
-    <group android:translateX="-4">
-        <path
-            android:fillColor="@color/tv_volume_dialog_accent"
-            android:pathData="M14,8.83v6.34L11.83,13H9v-2h2.83L14,8.83M16,4l-5,5H7v6h4l5,5V4z"/>
-    </group>
+    android:viewportHeight="24"
+    android:viewportWidth="24">
+    <path
+        android:fillColor="@color/tv_volume_dialog_accent"
+        android:pathData="M4.34,2.93L2.93,4.34 7.29,8.7 7,9L3,9v6h4l5,5v-6.59l4.18,4.18c-0.65,0.49 -1.38,0.88 -2.18,1.11v2.06c1.34,-0.3 2.57,-0.92 3.61,-1.75l2.05,2.05 1.41,-1.41L4.34,2.93zM10,15.17L7.83,13L5,13v-2h2.83l0.88,-0.88L10,11.41v3.76zM19,12c0,0.82 -0.15,1.61 -0.41,2.34l1.53,1.53c0.56,-1.17 0.88,-2.48 0.88,-3.87 0,-4.28 -2.99,-7.86 -7,-8.77v2.06c2.89,0.86 5,3.54 5,6.71zM12,4l-1.88,1.88L12,7.76zM16.5,12c0,-1.77 -1.02,-3.29 -2.5,-4.03v1.79l2.48,2.48c0.01,-0.08 0.02,-0.16 0.02,-0.24z"/>
 </vector>
diff --git a/res/drawable/ic_volume_media_off.xml b/res/drawable/ic_volume_media_off.xml
deleted file mode 100644
index 7a44aa6..0000000
--- a/res/drawable/ic_volume_media_off.xml
+++ /dev/null
@@ -1,26 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-  Copyright (C) 2020 The Android Open Source Project
-
-  Licensed under the Apache License, Version 2.0 (the "License");
-  you may not use this file except in compliance with the License.
-  You may obtain a copy of the License at
-
-       http://www.apache.org/licenses/LICENSE-2.0
-
-  Unless required by applicable law or agreed to in writing, software
-  distributed under the License is distributed on an "AS IS" BASIS,
-  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  See the License for the specific language governing permissions and
-  limitations under the License
-  -->
-
-<vector xmlns:android="http://schemas.android.com/apk/res/android"
-    android:width="@dimen/tv_volume_icons_size"
-    android:height="@dimen/tv_volume_icons_size"
-    android:viewportHeight="24"
-    android:viewportWidth="24">
-    <path
-        android:fillColor="@color/tv_volume_dialog_accent"
-        android:pathData="M4.34,2.93L2.93,4.34 7.29,8.7 7,9L3,9v6h4l5,5v-6.59l4.18,4.18c-0.65,0.49 -1.38,0.88 -2.18,1.11v2.06c1.34,-0.3 2.57,-0.92 3.61,-1.75l2.05,2.05 1.41,-1.41L4.34,2.93zM10,15.17L7.83,13L5,13v-2h2.83l0.88,-0.88L10,11.41v3.76zM19,12c0,0.82 -0.15,1.61 -0.41,2.34l1.53,1.53c0.56,-1.17 0.88,-2.48 0.88,-3.87 0,-4.28 -2.99,-7.86 -7,-8.77v2.06c2.89,0.86 5,3.54 5,6.71zM12,4l-1.88,1.88L12,7.76zM16.5,12c0,-1.77 -1.02,-3.29 -2.5,-4.03v1.79l2.48,2.48c0.01,-0.08 0.02,-0.16 0.02,-0.24z"/>
-</vector>
diff --git a/src/com/android/systemui/tv/dagger/TVSystemUICoreStartableModule.kt b/src/com/android/systemui/tv/dagger/TVSystemUICoreStartableModule.kt
index b5a84bf..82aa018 100644
--- a/src/com/android/systemui/tv/dagger/TVSystemUICoreStartableModule.kt
+++ b/src/com/android/systemui/tv/dagger/TVSystemUICoreStartableModule.kt
@@ -27,7 +27,6 @@ import com.android.systemui.media.dialog.MediaOutputSwitcherDialogUI
 import com.android.systemui.media.systemsounds.HomeSoundEffectController
 import com.android.systemui.shortcut.ShortcutKeyDispatcher
 import com.android.systemui.statusbar.notification.InstantAppNotifier
-import com.android.systemui.theme.ThemeOverlayController
 import com.android.systemui.toast.ToastUI
 import com.android.systemui.tv.notifications.TvNotificationHandler
 import com.android.systemui.tv.notifications.TvNotificationPanel
@@ -112,12 +111,6 @@ abstract class TVSystemUICoreStartableModule {
     @ClassKey(StorageNotification::class)
     abstract fun bindStorageNotification(sysui: StorageNotification): CoreStartable
 
-    /** Inject into ThemeOverlayController.  */
-    @Binds
-    @IntoMap
-    @ClassKey(ThemeOverlayController::class)
-    abstract fun bindThemeOverlayController(sysui: ThemeOverlayController): CoreStartable
-
     /** Inject into ToastUI.  */
     @Binds
     @IntoMap
diff --git a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
index 1926f48..fe17eb9 100644
--- a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
+++ b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
@@ -21,6 +21,8 @@ import android.hardware.SensorPrivacyManager
 import com.android.internal.logging.UiEventLogger
 import com.android.keyguard.KeyguardViewController
 import com.android.systemui.Dependency
+import com.android.systemui.accessibility.AccessibilityModule
+import com.android.systemui.accessibility.data.repository.AccessibilityRepositoryModule
 import com.android.systemui.animation.DialogTransitionAnimator
 import com.android.systemui.broadcast.BroadcastSender
 import com.android.systemui.dagger.ReferenceSystemUIModule
@@ -29,8 +31,8 @@ import com.android.systemui.display.ui.viewmodel.ConnectingDisplayViewModel
 import com.android.systemui.dock.DockManager
 import com.android.systemui.dock.DockManagerImpl
 import com.android.systemui.doze.DozeHost
-import com.android.systemui.media.dialog.MediaOutputController
 import com.android.systemui.media.dialog.MediaOutputDialogManager
+import com.android.systemui.media.dialog.MediaSwitchingController
 import com.android.systemui.media.muteawait.MediaMuteAwaitConnectionCli
 import com.android.systemui.media.nearby.NearbyMediaDevicesManager
 import com.android.systemui.navigationbar.gestural.GestureModule
@@ -42,6 +44,7 @@ import com.android.systemui.qs.dagger.QSModule
 import com.android.systemui.qs.tileimpl.QSFactoryImpl
 import com.android.systemui.screenshot.ReferenceScreenshotModule
 import com.android.systemui.settings.MultiUserUtilsModule
+import com.android.systemui.settings.UserTracker
 import com.android.systemui.shade.ShadeEmptyImplModule
 import com.android.systemui.statusbar.KeyboardShortcutsModule
 import com.android.systemui.statusbar.NotificationListener
@@ -68,6 +71,10 @@ import com.android.systemui.tv.privacy.PrivacyModule
 import com.android.systemui.tv.sensorprivacy.TvSensorPrivacyModule
 import com.android.systemui.tv.shade.TvNotificationShadeWindowController
 import com.android.systemui.unfold.SysUIUnfoldStartableModule
+import com.android.systemui.usb.UsbAccessoryUriActivity
+import com.android.systemui.usb.UsbDebuggingActivity
+import com.android.systemui.usb.UsbDebuggingSecondaryUserActivity
+import com.android.systemui.user.CreateUserActivity
 import com.android.systemui.volume.dagger.VolumeModule
 import dagger.Binds
 import dagger.Module
@@ -75,8 +82,8 @@ import dagger.Provides
 import dagger.multibindings.ClassKey
 import dagger.multibindings.IntoMap
 import dagger.multibindings.IntoSet
-import kotlinx.coroutines.ExperimentalCoroutinesApi
 import javax.inject.Named
+import kotlinx.coroutines.ExperimentalCoroutinesApi
 
 /**
  * A TV specific version of [ReferenceSystemUIModule].
@@ -86,6 +93,8 @@ import javax.inject.Named
  */
 @Module(
     includes = [
+    AccessibilityModule::class,
+    AccessibilityRepositoryModule::class,
     AospPolicyModule::class,
     ConnectingDisplayViewModel.StartableModule::class,
     GestureModule::class,
@@ -150,6 +159,32 @@ abstract class TvSystemUIModule {
             tvMediaOutputDialogActivity: TvMediaOutputDialogActivity
     ): Activity
 
+    /** Inject into UsbDebuggingActivity.  */
+    @Binds
+    @IntoMap
+    @ClassKey(UsbDebuggingActivity::class)
+    abstract fun bindUsbDebuggingActivity(activity: UsbDebuggingActivity): Activity
+
+    /** Inject into UsbDebuggingSecondaryUserActivity.  */
+    @Binds
+    @IntoMap
+    @ClassKey(UsbDebuggingSecondaryUserActivity::class)
+    abstract fun bindUsbDebuggingSecondaryUserActivity(
+        activity: UsbDebuggingSecondaryUserActivity,
+    ): Activity
+
+    /** Inject into UsbAccessoryUriActivity.  */
+    @Binds
+    @IntoMap
+    @ClassKey(UsbAccessoryUriActivity::class)
+    abstract fun bindUsbAccessoryUriActivity(activity: UsbAccessoryUriActivity): Activity
+
+    /** Inject into CreateUserActivity.  */
+    @Binds
+    @IntoMap
+    @ClassKey(CreateUserActivity::class)
+    abstract fun bindCreateUserActivity(activity: CreateUserActivity): Activity
+
     companion object {
         @SysUISingleton
         @Provides
@@ -166,9 +201,13 @@ abstract class TvSystemUIModule {
         @Provides
         @SysUISingleton
         fun provideIndividualSensorPrivacyController(
-                sensorPrivacyManager: SensorPrivacyManager
+                sensorPrivacyManager: SensorPrivacyManager,
+            userTracker: UserTracker
         ): IndividualSensorPrivacyController =
-                IndividualSensorPrivacyControllerImpl(sensorPrivacyManager).apply { init() }
+                IndividualSensorPrivacyControllerImpl(
+                    sensorPrivacyManager,
+                    userTracker
+                ).apply { init() }
 
         @SysUISingleton
         @Provides
@@ -196,9 +235,14 @@ abstract class TvSystemUIModule {
                 broadcastSender: BroadcastSender,
                 uiEventLogger: UiEventLogger,
                 dialogTransitionAnimator: DialogTransitionAnimator,
-                mediaOutputControllerFactory: MediaOutputController.Factory,
+                mediaSwitchingControllerFactory: MediaSwitchingController.Factory,
             ): MediaOutputDialogManager =
-                TvMediaOutputDialogManager(context, broadcastSender, uiEventLogger,
-                        dialogTransitionAnimator, mediaOutputControllerFactory)
+                TvMediaOutputDialogManager(
+                    context,
+                    broadcastSender,
+                    uiEventLogger,
+                    dialogTransitionAnimator,
+                    mediaSwitchingControllerFactory
+                )
     }
 }
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
index 104eda9..b03aec6 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
@@ -36,7 +36,7 @@ import com.android.internal.widget.RecyclerView;
 import com.android.settingslib.media.LocalMediaManager;
 import com.android.settingslib.media.MediaDevice;
 import com.android.systemui.media.dialog.MediaItem;
-import com.android.systemui.media.dialog.MediaOutputController;
+import com.android.systemui.media.dialog.MediaSwitchingController;
 import com.android.systemui.tv.res.R;
 
 import java.util.List;
@@ -51,7 +51,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
     private static final boolean DEBUG = false;
 
     private final TvMediaOutputController mMediaOutputController;
-    private final MediaOutputController.Callback mCallback;
+    private final MediaSwitchingController.Callback mCallback;
     private final Context mContext;
     protected List<MediaItem> mMediaItemList = new CopyOnWriteArrayList<>();
 
@@ -59,8 +59,10 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
     private final int mUnfocusedRadioTint;
     private final int mCheckedRadioTint;
 
-    TvMediaOutputAdapter(Context context, TvMediaOutputController mediaOutputController,
-            MediaOutputController.Callback callback) {
+    TvMediaOutputAdapter(
+            Context context,
+            TvMediaOutputController mediaOutputController,
+            MediaSwitchingController.Callback callback) {
         mContext = context;
         mMediaOutputController = mediaOutputController;
         mCallback = callback;
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputController.java b/src/com/android/systemui/tv/media/TvMediaOutputController.java
index fe05b51..59ddc6e 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputController.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputController.java
@@ -36,12 +36,13 @@ import com.android.settingslib.media.MediaDevice;
 import com.android.systemui.animation.DialogTransitionAnimator;
 import com.android.systemui.flags.FeatureFlags;
 import com.android.systemui.media.dialog.MediaItem;
-import com.android.systemui.media.dialog.MediaOutputController;
+import com.android.systemui.media.dialog.MediaSwitchingController;
 import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
 import com.android.systemui.plugins.ActivityStarter;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
 import com.android.systemui.tv.res.R;
+import com.android.systemui.volume.panel.domain.interactor.VolumePanelGlobalStateInteractor;
 
 import org.jetbrains.annotations.NotNull;
 
@@ -49,10 +50,10 @@ import java.util.ArrayList;
 import java.util.List;
 
 /**
- * Extends {@link MediaOutputController} to create a TV specific ordering and grouping of devices
+ * Extends {@link MediaSwitchingController} to create a TV specific ordering and grouping of devices
  * which are shown in the {@link TvMediaOutputDialogActivity}.
  */
-public class TvMediaOutputController extends MediaOutputController {
+public class TvMediaOutputController extends MediaSwitchingController {
 
     private final Context mContext;
     private final AudioManager mAudioManager;
@@ -70,6 +71,7 @@ public class TvMediaOutputController extends MediaOutputController {
             PowerExemptionManager powerExemptionManager,
             KeyguardManager keyGuardManager,
             FeatureFlags featureFlags,
+            VolumePanelGlobalStateInteractor volumePanelGlobalStateInteractor,
             UserTracker userTracker) {
         super(
                 context,
@@ -86,6 +88,7 @@ public class TvMediaOutputController extends MediaOutputController {
                 powerExemptionManager,
                 keyGuardManager,
                 featureFlags,
+                volumePanelGlobalStateInteractor,
                 userTracker);
         mContext = context;
         mAudioManager = audioManager;
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java b/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java
index 6e2d0ec..50142e3 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputDialogActivity.java
@@ -43,12 +43,13 @@ import com.android.settingslib.media.MediaDevice;
 import com.android.settingslib.media.flags.Flags;
 import com.android.systemui.animation.DialogTransitionAnimator;
 import com.android.systemui.flags.FeatureFlags;
-import com.android.systemui.media.dialog.MediaOutputController;
+import com.android.systemui.media.dialog.MediaSwitchingController;
 import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
 import com.android.systemui.plugins.ActivityStarter;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
 import com.android.systemui.tv.res.R;
+import com.android.systemui.volume.panel.domain.interactor.VolumePanelGlobalStateInteractor;
 
 import java.util.Collections;
 
@@ -56,15 +57,14 @@ import javax.annotation.Nullable;
 import javax.inject.Inject;
 
 /**
- * A TV specific variation of the {@link com.android.systemui.media.dialog.MediaOutputDialog}.
- * This activity allows the user to select a default audio output, which is not based on the
- * currently playing media.
- * There are two entry points for the dialog, either by sending a broadcast via the
- * {@link com.android.systemui.media.dialog.MediaOutputDialogReceiver} or by calling
- * {@link MediaRouter2#showSystemOutputSwitcher()}
+ * A TV specific variation of the {@link com.android.systemui.media.dialog.MediaOutputDialog}. This
+ * activity allows the user to select a default audio output, which is not based on the currently
+ * playing media. There are two entry points for the dialog, either by sending a broadcast via the
+ * {@link com.android.systemui.media.dialog.MediaOutputDialogReceiver} or by calling {@link
+ * MediaRouter2#showSystemOutputSwitcher()}
  */
 public class TvMediaOutputDialogActivity extends Activity
-        implements MediaOutputController.Callback {
+        implements MediaSwitchingController.Callback {
     private static final String TAG = TvMediaOutputDialogActivity.class.getSimpleName();
     private static final boolean DEBUG = false;
 
@@ -81,6 +81,7 @@ public class TvMediaOutputDialogActivity extends Activity
     private final PowerExemptionManager mPowerExemptionManager;
     private final KeyguardManager mKeyguardManager;
     private final FeatureFlags mFeatureFlags;
+    private final VolumePanelGlobalStateInteractor mVolumePanelGlobalStateInteractor;
     private final UserTracker mUserTracker;
 
     protected final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
@@ -98,6 +99,7 @@ public class TvMediaOutputDialogActivity extends Activity
             PowerExemptionManager powerExemptionManager,
             KeyguardManager keyguardManager,
             FeatureFlags featureFlags,
+            VolumePanelGlobalStateInteractor volumePanelGlobalStateInteractor,
             UserTracker userTracker) {
         mMediaSessionManager = mediaSessionManager;
         mLocalBluetoothManager = localBluetoothManager;
@@ -109,6 +111,7 @@ public class TvMediaOutputDialogActivity extends Activity
         mPowerExemptionManager = powerExemptionManager;
         mKeyguardManager = keyguardManager;
         mFeatureFlags = featureFlags;
+        mVolumePanelGlobalStateInteractor = volumePanelGlobalStateInteractor;
         mUserTracker = userTracker;
     }
 
@@ -125,11 +128,22 @@ public class TvMediaOutputDialogActivity extends Activity
 
         setContentView(R.layout.media_output_dialog);
 
-        mMediaOutputController = new TvMediaOutputController(this, getPackageName(),
-                mMediaSessionManager, mLocalBluetoothManager, mActivityStarter,
-                mCommonNotifCollection, mDialogTransitionAnimator, mNearbyMediaDevicesManager,
-                mAudioManager, mPowerExemptionManager, mKeyguardManager, mFeatureFlags,
-                mUserTracker);
+        mMediaOutputController =
+                new TvMediaOutputController(
+                        this,
+                        getPackageName(),
+                        mMediaSessionManager,
+                        mLocalBluetoothManager,
+                        mActivityStarter,
+                        mCommonNotifCollection,
+                        mDialogTransitionAnimator,
+                        mNearbyMediaDevicesManager,
+                        mAudioManager,
+                        mPowerExemptionManager,
+                        mKeyguardManager,
+                        mFeatureFlags,
+                        mVolumePanelGlobalStateInteractor,
+                        mUserTracker);
         mAdapter = new TvMediaOutputAdapter(this, mMediaOutputController, this);
 
         Resources res = getResources();
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputDialogManager.kt b/src/com/android/systemui/tv/media/TvMediaOutputDialogManager.kt
index 4cbfa01..5888d06 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputDialogManager.kt
+++ b/src/com/android/systemui/tv/media/TvMediaOutputDialogManager.kt
@@ -26,7 +26,7 @@ import com.android.internal.logging.UiEventLogger
 import com.android.settingslib.media.flags.Flags
 import com.android.systemui.animation.DialogTransitionAnimator
 import com.android.systemui.broadcast.BroadcastSender
-import com.android.systemui.media.dialog.MediaOutputController
+import com.android.systemui.media.dialog.MediaSwitchingController
 import com.android.systemui.media.dialog.MediaOutputDialogManager
 import javax.inject.Inject
 
@@ -38,13 +38,13 @@ class TvMediaOutputDialogManager @Inject constructor(
         broadcastSender: BroadcastSender,
         uiEventLogger: UiEventLogger,
         dialogTransitionAnimator: DialogTransitionAnimator,
-        mediaOutputControllerFactory: MediaOutputController.Factory,
+        mediaSwitchingControllerFactory: MediaSwitchingController.Factory,
 ) : MediaOutputDialogManager(
         context,
         broadcastSender,
         uiEventLogger,
         dialogTransitionAnimator,
-        mediaOutputControllerFactory
+        mediaSwitchingControllerFactory
 ) {
     companion object {
         private const val TAG = "TvMediaOutputDialogFactory"
diff --git a/tests/Android.bp b/tests/Android.bp
index 255a7eb..ae7ecb9 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -34,6 +34,7 @@ android_test {
         "androidx.test.ext.junit",
         "androidx.test.ext.truth",
         "androidx.test.rules",
+        "mockito-kotlin-nodeps",
         "mockito-target-extended-minus-junit4",
         "SystemUI-tests-base",
         "SystemUICustomizationTestUtils",
@@ -41,9 +42,9 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     jni_libs: [
```

