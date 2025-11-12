```diff
diff --git a/app/Android.bp b/app/Android.bp
index b86b545e..fbbcd8d3 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -40,6 +40,7 @@ android_library {
 
     static_libs: [
         "car_launcher_flags_java_lib",
+        "com_android_systemui_car_flags_lib",
         "androidx-constraintlayout_constraintlayout-solver",
         "androidx-constraintlayout_constraintlayout",
         "androidx.lifecycle_lifecycle-extensions",
diff --git a/app/OWNERS b/app/OWNERS
index 6e10365d..395ae306 100644
--- a/app/OWNERS
+++ b/app/OWNERS
@@ -1,12 +1,10 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 
+ankiit@google.com
+snekkalapudi@google.com
 alexstetson@google.com
-danzz@google.com
-babakbo@google.com
-arnaudberry@google.com
-stenning@google.com
-gauravbhola@google.com  # for TaskView only
-
-# Recents
-per-file src/com/android/car/carlauncher/recents/* = jainams@google.com
+priyanksingh@google.com
+farivar@google.com
+calhuang@google.com
+babakbo@google.com
\ No newline at end of file
diff --git a/dewd/res/values/themes.xml b/app/res/color/color_accent.xml
similarity index 58%
rename from dewd/res/values/themes.xml
rename to app/res/color/color_accent.xml
index 3627d9ad..50de4713 100644
--- a/dewd/res/values/themes.xml
+++ b/app/res/color/color_accent.xml
@@ -1,5 +1,6 @@
-<?xml version="1.0" encoding="utf-8" ?><!--
-  ~ Copyright (C) 2025 The Android Open Source Project.
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -13,12 +14,7 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:color="?oemColorPrimary"/>
+</selector>
 
-<resources
-    xmlns:android="http://schemas.android.com/apk/res/android">
-
-    <style name="DewdCarLauncherTheme" parent="Theme.CarUi.NoToolbar">
-        <item name="oemTokenOverrideEnabled">true</item>
-        <item name="android:windowBackground">@android:color/black</item>
-    </style>
-</resources>
\ No newline at end of file
diff --git a/app/res/layout-land/car_launcher.xml b/app/res/layout-land/car_launcher.xml
index 25031309..e7017c23 100644
--- a/app/res/layout-land/car_launcher.xml
+++ b/app/res/layout-land/car_launcher.xml
@@ -21,7 +21,7 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:layoutDirection="ltr"
-    android:background="@android:color/black"
+    android:background="?oemColorSurface"
     tools:context=".CarLauncher">
 
     <com.android.car.ui.FocusParkingView
@@ -69,4 +69,4 @@
         app:layout_constraintRight_toRightOf="parent"
         app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintBottom_toBottomOf="parent"/>
-</androidx.constraintlayout.widget.ConstraintLayout>
\ No newline at end of file
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/app/res/layout/car_launcher.xml b/app/res/layout/car_launcher.xml
index e45a9bf8..712db208 100644
--- a/app/res/layout/car_launcher.xml
+++ b/app/res/layout/car_launcher.xml
@@ -21,7 +21,7 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:layoutDirection="ltr"
-    android:background="@android:color/black"
+    android:background="?oemColorSurface"
     tools:context=".CarLauncher">
 
     <com.android.car.ui.FocusParkingView
@@ -61,4 +61,4 @@
         app:layout_constraintTop_toBottomOf="@+id/bottom_card"
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintRight_toRightOf="parent"/>
-</androidx.constraintlayout.widget.ConstraintLayout>
\ No newline at end of file
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/dewd/res/layout/home.xml b/app/res/layout/home.xml
similarity index 93%
rename from dewd/res/layout/home.xml
rename to app/res/layout/home.xml
index 383ec098..e26364c8 100644
--- a/dewd/res/layout/home.xml
+++ b/app/res/layout/home.xml
@@ -15,7 +15,6 @@
   -->
 <FrameLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:app="http://schemas.android.com/apk/res-auto"
     android:id="@+id/home"
     android:layout_width="match_parent"
     android:layout_height="match_parent"/>
diff --git a/app/res/values-te/strings.xml b/app/res/values-te/strings.xml
index f62412de..aa1ee82f 100644
--- a/app/res/values-te/strings.xml
+++ b/app/res/values-te/strings.xml
@@ -32,7 +32,7 @@
     <string name="fake_weather_footer_text" msgid="8640814250285014485">"మౌంటెయిన్ వ్యూ • H: --° L: --°"</string>
     <string name="times_separator" msgid="1962841895013564645">"/"</string>
     <string name="recents_empty_state_text" msgid="8228569970506899117">"ఇటీవలి ఐటెమ్‌లు ఏవీ లేవు"</string>
-    <string name="recents_clear_all_text" msgid="3594272268167720553">"అన్నీ తీసివేయండి"</string>
+    <string name="recents_clear_all_text" msgid="3594272268167720553">"అన్నీ క్లియర్ చేయండి"</string>
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"యాప్ అందుబాటులో లేదు"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"క్లెయిమ్ మోడ్"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"క్యూ"</string>
diff --git a/app/res/values/colors.xml b/app/res/values/colors.xml
index d741960b..f081d018 100644
--- a/app/res/values/colors.xml
+++ b/app/res/values/colors.xml
@@ -19,11 +19,11 @@
     <color name="tap_for_more_text_color">#DADCE0</color>
     <color name="dialer_button_icon_color">#FFFFFF</color>
     <color name="dialer_end_call_button_color">#EE675C</color>
-    <color name="launcher_home_icon_color">@*android:color/car_accent_light</color>
-    <color name="seek_bar_color">@*android:color/car_accent</color>
+    <color name="launcher_home_icon_color">@color/color_accent</color>
+    <color name="seek_bar_color">@color/color_accent</color>
     <color name="recents_background_color">@*android:color/car_grey_900</color>
     <color name="default_recents_thumbnail_color">@*android:color/car_grey_846</color>
-    <color name="clear_all_recents_text_color">@*android:color/car_accent</color>
+    <color name="clear_all_recents_text_color">@color/color_accent</color>
 
     <!-- CarUiPortraitLauncherReferenceRRO relies on overlaying these values -->
     <color name="media_button_tint">@*android:color/car_tint</color>
diff --git a/app/res/values/config.xml b/app/res/values/config.xml
index bd4bbbaf..aaad6b41 100644
--- a/app/res/values/config.xml
+++ b/app/res/values/config.xml
@@ -77,4 +77,16 @@
     <bool name="config_calmMode_showTemperature">true</bool>
     <string name="config_calmMode_componentName">com.android.car.carlauncher/com.android.car.carlauncher.calmmode.CalmModeActivity</string>
 
+    <!--
+        Rely on the declarative system windows configuration for home screen handling. When this
+        flag is set to `true`, the launcher activity is only used as a static bottom most layer.
+        Unlike "legacy" launcher, the home screen logic is deferred to the relevant panels and,
+        where necessary, system services to handle things beyond panel visibility and transitions
+        (e.g. Terms Of Service handling logic).
+
+        TODO(b/408491355): remove this configuration flag when the transition to DEWD is completed
+            for all affected automotive targets.
+     -->
+    <bool name="config_useDewdLauncher">false</bool>
+
 </resources>
diff --git a/app/res/values/overlayable.xml b/app/res/values/overlayable.xml
index 7d3c7e7f..9db8f5f7 100644
--- a/app/res/values/overlayable.xml
+++ b/app/res/values/overlayable.xml
@@ -45,6 +45,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="bool" name="config_enableCalmMode"/>
       <item type="bool" name="config_homecard_single_line_secondary_descriptive_text"/>
       <item type="bool" name="config_launch_most_recent_task_on_recents_dismiss"/>
+      <item type="bool" name="config_useDewdLauncher"/>
       <item type="bool" name="show_seek_bar"/>
       <item type="bool" name="use_media_source_color_for_seek_bar"/>
       <item type="color" name="card_background_scrim"/>
@@ -370,6 +371,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="style" name="RecentTasksList"/>
       <item type="style" name="RecentTasksListFocusArea"/>
       <item type="style" name="Theme.CalmMode"/>
+      <item type="style" name="Theme.ControlBar"/>
       <item type="style" name="Theme.Launcher"/>
       <item type="style" name="TitleText"/>
       <item type="xml" name="panel_animation_motion_scene"/>
diff --git a/app/src/com/android/car/carlauncher/CarLauncher.java b/app/src/com/android/car/carlauncher/CarLauncher.java
index 37ddb03a..fc82f4d2 100644
--- a/app/src/com/android/car/carlauncher/CarLauncher.java
+++ b/app/src/com/android/car/carlauncher/CarLauncher.java
@@ -22,6 +22,7 @@ import static android.view.WindowManager.LayoutParams.PRIVATE_FLAG_TRUSTED_OVERL
 
 import static com.android.car.carlauncher.AppGridFragment.Mode.ALL_APPS;
 import static com.android.car.carlauncher.CarLauncherViewModel.CarLauncherViewModelFactory;
+import static com.android.systemui.car.Flags.scalableUi;
 
 import android.app.ActivityManager;
 import android.app.ActivityOptions;
@@ -40,7 +41,6 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowManager;
 
-import androidx.annotation.NonNull;
 import androidx.collection.ArraySet;
 import androidx.fragment.app.FragmentActivity;
 import androidx.fragment.app.FragmentTransaction;
@@ -53,7 +53,6 @@ import com.android.car.carlauncher.homescreen.audio.dialer.InCallIntentRouter;
 import com.android.car.carlauncher.homescreen.audio.media.MediaLaunchRouter;
 import com.android.car.carlauncher.taskstack.TaskStackChangeListeners;
 import com.android.car.internal.common.UserHelperLite;
-import com.android.car.media.common.source.MediaSource;
 import com.android.wm.shell.taskview.TaskView;
 
 import com.google.common.annotations.VisibleForTesting;
@@ -114,25 +113,19 @@ public class CarLauncher extends FragmentActivity {
         }
     };
 
-    private final IntentHandler mIntentHandler = new IntentHandler() {
-        @Override
-        public void handleIntent(Intent intent) {
-            if (intent != null) {
-                ActivityOptions options = ActivityOptions.makeBasic();
-                startActivity(intent, options.toBundle());
-            }
+    private final IntentHandler mIntentHandler = intent -> {
+        if (intent != null) {
+            ActivityOptions options = ActivityOptions.makeBasic();
+            startActivity(intent, options.toBundle());
         }
     };
 
     // Used instead of IntentHandler because media apps may provide a PendingIntent instead
-    private final MediaLaunchHandler mMediaMediaLaunchHandler = new MediaLaunchHandler() {
-        @Override
-        public void handleLaunchMedia(@NonNull MediaSource mediaSource) {
-            if (DEBUG) {
-                Log.d(TAG, "Launching media source " + mediaSource);
-            }
-            mediaSource.launchActivity(CarLauncher.this, ActivityOptions.makeBasic());
+    private final MediaLaunchHandler mMediaMediaLaunchHandler = mediaSource -> {
+        if (DEBUG) {
+            Log.d(TAG, "Launching media source " + mediaSource);
         }
+        mediaSource.launchActivity(CarLauncher.this, ActivityOptions.makeBasic());
     };
 
     @Override
@@ -143,17 +136,34 @@ public class CarLauncher extends FragmentActivity {
             Log.d(TAG, "onCreate(" + getUserId() + ") displayId=" + getDisplayId());
         }
         getTheme().applyStyle(R.style.CarLauncherActivityThemeOverlay, true);
+
+        // TODO(b/408491355): remove `isDewdActive()` checks and clean up legacy logic when all
+        //   targets are migrated to DEWD.
+        if (isDewdActive()) {
+            if (DEBUG) {
+                Log.d(TAG, "Dewd Launcher active");
+            }
+
+            if (!scalableUi()) {
+                Log.e(TAG, "Scalable UI is disabled - home screen will appear empty!");
+            }
+
+            setContentView(R.layout.home);
+            return;
+        }
+
         // Since MUMD/MUPAND is introduced, CarLauncher can be called in the main display of
         // visible background users.
         // For Passenger scenarios, replace the maps_card with AppGridActivity, as currently
         // there is no maps use-case for passengers.
+        // Note: for now MUMD/MUPAND are not using DEWD.
         UserManager um = getSystemService(UserManager.class);
         boolean isPassengerDisplay = getDisplayId() != Display.DEFAULT_DISPLAY
                 || um.isVisibleBackgroundUsersOnDefaultDisplaySupported();
 
         // Don't show the maps panel in multi window mode.
-        // NOTE: CTS tests for split screen are not compatible with activity views on the default
-        // activity of the launcher
+        // NOTE: CTS tests for split screen are not compatible with activity views on the
+        // default activity of the launcher
         if (isInMultiWindowMode() || isInPictureInPictureMode()) {
             setContentView(R.layout.car_launcher_multiwindow);
         } else {
@@ -181,8 +191,8 @@ public class CarLauncher extends FragmentActivity {
                 }
             } else {
                 // For Passenger display show the AppGridFragment in place of the Maps view.
-                // Also we can skip initializing all the TaskView related objects as they are not
-                // used in this case.
+                // Also we can skip initializing all the TaskView related objects as they are
+                // not used in this case.
                 getSupportFragmentManager().beginTransaction().replace(R.id.maps_card,
                         AppGridFragment.newInstance(ALL_APPS)).commit();
 
@@ -193,6 +203,7 @@ public class CarLauncher extends FragmentActivity {
         InCallIntentRouter.getInstance().registerInCallIntentHandler(mIntentHandler);
 
         initializeCards();
+
         setupContentObserversForTos();
     }
 
@@ -226,12 +237,19 @@ public class CarLauncher extends FragmentActivity {
     @Override
     protected void onResume() {
         super.onResume();
+
         maybeLogReady();
     }
 
     @Override
     protected void onDestroy() {
         super.onDestroy();
+
+        if (isDewdActive()) {
+            // no-op
+            return;
+        }
+
         TaskStackChangeListeners.getInstance().unregisterTaskStackListener(mTaskStackListener);
         unregisterTosContentObserver();
         release();
@@ -269,6 +287,12 @@ public class CarLauncher extends FragmentActivity {
     @Override
     public void onConfigurationChanged(Configuration newConfig) {
         super.onConfigurationChanged(newConfig);
+
+        if (isDewdActive()) {
+            // no-op
+            return;
+        }
+
         initializeCards();
     }
 
@@ -365,12 +389,14 @@ public class CarLauncher extends FragmentActivity {
                 if (DEBUG) {
                     Log.d(TAG, "TOS disabled apps:" + tosDisabledApps);
                 }
+
                 if (mCarLauncherViewModel != null
                         && mCarLauncherViewModel.getRemoteCarTaskView().getValue() != null) {
                     // Reinitialize the remote car task view with the new maps intent
                     mCarLauncherViewModel.initializeRemoteCarTaskView(getMapsIntent());
                     setUpRemoteCarTaskViewObserver(mMapsCard);
                 }
+
                 if (tosAccepted) {
                     unregisterTosContentObserver();
                 }
@@ -381,4 +407,9 @@ public class CarLauncher extends FragmentActivity {
                 /* notifyForDescendants*/ false,
                 mTosContentObserver);
     }
+
+    /** Returns {@code true} if the declarative launcher configuration is active. */
+    private boolean isDewdActive() {
+        return getResources().getBoolean(R.bool.config_useDewdLauncher);
+    }
 }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java
index 915b2ffd..7a2b6f43 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java
@@ -79,6 +79,7 @@ public class InCallViewModel implements AudioModel {
     private final Clock mElapsedTimeClock;
 
     private final LiveData<Call> mPrimaryCallLiveData;
+    private final LiveData<CallAudioState> mCallAudioStateLiveData;
     private final LiveData<CallDetail> mCallDetailLiveData;
 
     private Observer<Object> mCallObserver;
@@ -110,6 +111,7 @@ public class InCallViewModel implements AudioModel {
             callDetailLiveData.setTelecomCall(call);
             return callDetailLiveData;
         });
+        mCallAudioStateLiveData = mInCallModel.getCallAudioStateLiveData();
     }
 
     @Override
@@ -132,7 +134,7 @@ public class InCallViewModel implements AudioModel {
 
         mCallAudioStateObserver =
                 o -> onCallAudioStateChanged(mInCallModel.getCallAudioStateLiveData().getValue());
-        mInCallModel.getCallAudioStateLiveData().observeForever(mCallAudioStateObserver);
+        mCallAudioStateLiveData.observeForever(mCallAudioStateObserver);
     }
 
     @Override
@@ -140,6 +142,9 @@ public class InCallViewModel implements AudioModel {
         if (mPhoneNumberInfoFuture != null) {
             mPhoneNumberInfoFuture.cancel(/* mayInterruptIfRunning= */true);
         }
+        mPrimaryCallLiveData.removeObserver(mCallObserver);
+        mCallAudioStateLiveData.removeObserver(mCallAudioStateObserver);
+        mOnModelUpdateListener = null;
     }
 
     @Override
@@ -204,7 +209,6 @@ public class InCallViewModel implements AudioModel {
 
     @VisibleForTesting
     void onCallAudioStateChanged(CallAudioState audioState) {
-
         if (updateMuteButtonIconState(audioState)) {
             mOnModelUpdateListener.onModelUpdate(this);
         }
@@ -214,7 +218,7 @@ public class InCallViewModel implements AudioModel {
         if (call != null) {
             mCurrentCall = call;
             handleActiveCall(mCurrentCall);
-        } else {
+        } else if (mCurrentCall != null) {
             mCurrentCall = null;
             mCardHeader = null;
             mCardContent = null;
diff --git a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
index bc8988da..74c71862 100644
--- a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
+++ b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
@@ -181,7 +181,7 @@ public class CarQuickStepService extends Service {
         }
 
         @Override
-        public void enterStageSplitFromRunningApp(boolean leftOrTop) {
+        public void enterStageSplitFromRunningApp(int displayId, boolean leftOrTop) {
             // no-op
         }
 
@@ -245,5 +245,10 @@ public class CarQuickStepService extends Service {
         public void onDisplayRemoveSystemDecorations(int displayId) {
             // no-op
         }
+
+        @Override
+        public void onActionCornerActivated(int action, int displayId) {
+            // no-op
+        }
     }
 }
diff --git a/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java b/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java
index f1588e70..b611c256 100644
--- a/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java
+++ b/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java
@@ -150,10 +150,7 @@ public class CarRecentsActivity extends AppCompatActivity implements
     @Override
     protected void onResume() {
         super.onResume();
-        if (OPEN_RECENT_TASK_ACTION.equals(getIntent().getAction())) {
-            if (mLaunchMostRecentTaskOnDismiss) {
-                mRecentTasksViewModel.openMostRecentTask();
-            }
+        if (handleOpenRecentTaskAction()) {
             return;
         }
         mRecentTasksViewModel.fetchRecentTaskList();
@@ -211,6 +208,19 @@ public class CarRecentsActivity extends AppCompatActivity implements
         }
     }
 
+    /**
+     * Handle OPEN_RECENT_TASK_ACTION if part of the current intent action.
+     */
+    protected boolean handleOpenRecentTaskAction() {
+        if (OPEN_RECENT_TASK_ACTION.equals(getIntent().getAction())) {
+            if (mLaunchMostRecentTaskOnDismiss) {
+                mRecentTasksViewModel.openMostRecentTask();
+            }
+            return true;
+        }
+        return false;
+    }
+
     /**
      * Launches the Home Activity.
      */
diff --git a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
index 07a7ab92..469aeddd 100644
--- a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
+++ b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
@@ -22,7 +22,6 @@ import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_DESK;
 import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FULLSCREEN;
 import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_SPLIT;
 
-import android.app.Activity;
 import android.app.ActivityManager;
 import android.app.TaskInfo;
 import android.content.ComponentName;
@@ -266,8 +265,9 @@ public class RecentTasksProvider implements RecentTasksProviderInterface {
     }
 
     @Override
-    public boolean openTopRunningTask(@NonNull Class<? extends Activity> recentsActivity,
-            int displayId) {
+    public boolean openTopRunningTask(int displayId) {
+        ComponentName recentsActivity = ComponentName.unflattenFromString(
+                mContext.getString(com.android.internal.R.string.config_recentsComponentName));
         ActivityManager.RunningTaskInfo[] runningTasks = mActivityManagerWrapper.getRunningTasks(
                 /* filterOnlyVisibleRecents= */ false, displayId);
         boolean foundRecentsTask = false;
@@ -280,10 +280,10 @@ public class RecentTasksProvider implements RecentTasksProviderInterface {
                 return mActivityManagerWrapper.startActivityFromRecents(
                         runningTask.taskId, /* options= */ null);
             }
-            String topComponent = runningTask.topActivity != null
-                    ? runningTask.topActivity.getClassName()
-                    : runningTask.baseIntent.getComponent().getClassName();
-            if (recentsActivity.getName().equals(topComponent)) {
+            ComponentName topComponent = runningTask.topActivity != null
+                    ? runningTask.topActivity
+                    : runningTask.baseIntent.getComponent();
+            if (recentsActivity.equals(topComponent)) {
                 foundRecentsTask = true;
             }
         }
diff --git a/app/src/com/android/car/carlauncher/recents/RecentTasksProviderInterface.java b/app/src/com/android/car/carlauncher/recents/RecentTasksProviderInterface.java
index 29975d65..f41dc11e 100644
--- a/app/src/com/android/car/carlauncher/recents/RecentTasksProviderInterface.java
+++ b/app/src/com/android/car/carlauncher/recents/RecentTasksProviderInterface.java
@@ -16,7 +16,6 @@
 
 package com.android.car.carlauncher.recents;
 
-import android.app.Activity;
 import android.content.ComponentName;
 import android.content.Intent;
 import android.graphics.Bitmap;
@@ -86,11 +85,10 @@ public interface RecentTasksProviderInterface {
      * {@code recentsActivity} in the top running tasks, the method will not attempt to open the top
      * task and return false.
      *
-     * @param recentsActivity {@link Activity} that is responsible to show recent tasks.
      * @param displayId       the display's id where {@code recentsActivity} is drawn.
      * @return if the top task was found and opened.
      */
-    boolean openTopRunningTask(@NonNull Class<? extends Activity> recentsActivity, int displayId);
+    boolean openTopRunningTask(int displayId);
 
     /**
      * @param taskId the {@code taskId} of the recent task to be removed from recents.
diff --git a/app/src/com/android/car/carlauncher/recents/RecentTasksViewModel.java b/app/src/com/android/car/carlauncher/recents/RecentTasksViewModel.java
index c8caf30b..95ed9acf 100644
--- a/app/src/com/android/car/carlauncher/recents/RecentTasksViewModel.java
+++ b/app/src/com/android/car/carlauncher/recents/RecentTasksViewModel.java
@@ -239,7 +239,7 @@ public class RecentTasksViewModel {
      * Communicates failure through {@link RecentTasksChangeListener}.
      */
     public void openMostRecentTask() {
-        if (!mDataStore.openTopRunningTask(CarRecentsActivity.class, mDisplayId)) {
+        if (!mDataStore.openTopRunningTask(mDisplayId)) {
             mRecentTasksChangeListener.forEach(RecentTasksChangeListener::onOpenTopRunningTaskFail);
         }
     }
diff --git a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
index 29277adb..105e2ca1 100644
--- a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
+++ b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
@@ -130,6 +130,9 @@ public class RecentTasksProviderTest {
             ((Runnable) invocation.getArgument(0)).run();
             return null;
         });
+        mContext.getOrCreateTestableResources().addOverride(
+                com.android.internal.R.string.config_recentsComponentName,
+                new ComponentName(mContext, RECENTS_ACTIVITY.class).flattenToString());
         RecentTasksProvider.setHandler(mHandler);
         mRecentTasksProvider = RecentTasksProvider.getInstance();
         mRecentTasksProvider.setActivityManagerWrapper(mActivityManagerWrapper);
@@ -322,7 +325,7 @@ public class RecentTasksProviderTest {
                 .thenReturn(infos);
         ActivityManager.RunningTaskInfo taskAfterRecents = infos[tasksBeforeRecents + 1];
 
-        mRecentTasksProvider.openTopRunningTask(RECENTS_ACTIVITY.class, displayId);
+        mRecentTasksProvider.openTopRunningTask(displayId);
 
         verify(mActivityManagerWrapper).startActivityFromRecents(eq(taskAfterRecents.taskId),
                 nullable(ActivityOptions.class));
@@ -338,7 +341,7 @@ public class RecentTasksProviderTest {
         when(mActivityManagerWrapper.getRunningTasks(anyBoolean(), eq(displayId)))
                 .thenReturn(infos);
 
-        mRecentTasksProvider.openTopRunningTask(RECENTS_ACTIVITY.class, displayId);
+        mRecentTasksProvider.openTopRunningTask(displayId);
 
         verify(mActivityManagerWrapper, never()).startActivityFromRecents(anyInt(),
                 nullable(ActivityOptions.class));
@@ -354,7 +357,7 @@ public class RecentTasksProviderTest {
         when(mActivityManagerWrapper.getRunningTasks(anyBoolean(), eq(displayId)))
                 .thenReturn(infos);
 
-        boolean ret = mRecentTasksProvider.openTopRunningTask(RECENTS_ACTIVITY.class, displayId);
+        boolean ret = mRecentTasksProvider.openTopRunningTask(displayId);
 
         assertThat(ret).isFalse();
     }
@@ -410,7 +413,7 @@ public class RecentTasksProviderTest {
             ActivityManager.RunningTaskInfo info = mock(ActivityManager.RunningTaskInfo.class);
             info.taskId = i;
             if (i == tasksBeforeRecents) {
-                info.topActivity = new ComponentName("pkg-" + i, recentsClazz);
+                info.topActivity = new ComponentName(mContext, RECENTS_ACTIVITY.class);
             } else {
                 info.topActivity = new ComponentName("pkg-" + i, "class-" + i);
             }
diff --git a/dewd/Android.bp b/dewd/Android.bp
deleted file mode 100644
index 6eb607bc..00000000
--- a/dewd/Android.bp
+++ /dev/null
@@ -1,55 +0,0 @@
-//
-// Copyright (C) 2025 The Android Open Source Project.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-android_app {
-    name: "DewdCarLauncher",
-
-    overrides: [
-        "Launcher2",
-        "Launcher3",
-        "Launcher3QuickStep",
-        "CarLauncher",
-    ],
-
-    srcs: ["src/**/*.java"],
-
-    manifest: "AndroidManifest.xml",
-
-    platform_apis: true,
-    certificate: "platform",
-    static_libs: [
-        "CarLauncher-core",
-        "oem-token-lib",
-        "car-ui-lib",
-    ],
-
-    libs: [
-        "token-shared-lib-prebuilt",
-    ],
-
-    enforce_uses_libs: false,
-
-    optimize: {
-        enabled: false,
-    },
-
-    dex_preopt: {
-        enabled: false,
-    },
-}
diff --git a/dewd/AndroidManifest.xml b/dewd/AndroidManifest.xml
deleted file mode 100644
index bb18f06d..00000000
--- a/dewd/AndroidManifest.xml
+++ /dev/null
@@ -1,63 +0,0 @@
-<!--
-  ~ Copyright (C) 2025 The Android Open Source Project Inc.
-  ~
-  ~ Licensed under the Apache License, Version 2.0 (the "License");
-  ~ you may not use this file except in compliance with the License.
-  ~ You may obtain a copy of the License at
-  ~
-  ~      http://www.apache.org/licenses/LICENSE-2.0
-  ~
-  ~ Unless required by applicable law or agreed to in writing, software
-  ~ distributed under the License is distributed on an "AS IS" BASIS,
-  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  ~ See the License for the specific language governing permissions and
-  ~ limitations under the License.
-  -->
-
-<manifest
-    xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:tools="http://schemas.android.com/tools"
-    package="com.android.car.carlauncher"
-    coreApp="true">
-
-    <!-- Permission to get car driving state -->
-    <uses-permission android:name="android.car.permission.CAR_DRIVING_STATE"/>
-
-    <!-- Permission to manage USB -->
-    <uses-permission android:name="android.permission.MANAGE_USB"/>
-
-    <!-- Permissions to support display compat -->
-    <uses-permission android:name="android.car.permission.MANAGE_DISPLAY_COMPATIBILITY"/>
-
-    <application
-        android:label="Declarative Windowing definition Car Launcher"
-        android:theme="@style/DewdCarLauncherTheme"
-        tools:replace="android:label,android:theme"
-        tools:node="merge">
-        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
-
-        <activity
-            android:name=".DewdHome"
-            android:exported="true"
-            android:launchMode="singleInstance"
-            android:excludeFromRecents="true">
-            <meta-data android:name="distractionOptimized" android:value="true"/>
-            <intent-filter>
-                <action android:name="android.intent.action.MAIN"/>
-                <category android:name="android.intent.category.DEFAULT"/>
-                <category android:name="android.intent.category.HOME"/>
-                <category android:name="android.intent.category.LAUNCHER_APP"/>
-            </intent-filter>
-        </activity>
-
-        <activity
-            android:name="com.android.car.carlauncher.CarLauncher"
-            android:exported="false"
-            tools:node="merge"
-            tools:replace="android:exported">
-            <!-- Disable the CarLauncher activity as we don't want that in the
-                 custom launcher. -->
-            <intent-filter tools:node="removeAll"/>
-        </activity>
-    </application>
-</manifest>
diff --git a/dewd/src/com/android/car/carlauncher/DewdHome.java b/dewd/src/com/android/car/carlauncher/DewdHome.java
deleted file mode 100644
index 1e4a3394..00000000
--- a/dewd/src/com/android/car/carlauncher/DewdHome.java
+++ /dev/null
@@ -1,35 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.car.carlauncher;
-
-import android.os.Bundle;
-
-import androidx.annotation.Nullable;
-import androidx.appcompat.app.AppCompatActivity;
-
-/**
- * Used as the static wallpaper in base layer. This activity is at the bottom of the base layer
- * stack and is visible when there is no other base layer application is running.
- */
-public class DewdHome extends AppCompatActivity {
-
-    @Override
-    protected void onCreate(@Nullable Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-        setContentView(R.layout.home);
-    }
-}
diff --git a/docklib-util/OWNERS b/docklib-util/OWNERS
index 7c73cd2a..ed3128da 100644
--- a/docklib-util/OWNERS
+++ b/docklib-util/OWNERS
@@ -2,6 +2,5 @@
 # Please update this list if you find better candidates.
 set noparent
 
-danzz@google.com
 jainams@google.com
 nehah@google.com
diff --git a/docklib/res/values/styles.xml b/docklib/res/values/styles.xml
index 24f400ec..b5740db0 100644
--- a/docklib/res/values/styles.xml
+++ b/docklib/res/values/styles.xml
@@ -33,6 +33,6 @@
 
     <style name="AppIcon.RoundedBorder">
         <item name="cornerFamily">rounded</item>
-        <item name="cornerSize">50%</item>
+        <item name="cornerSize">?oemShapeCornerLarge</item>
     </style>
 </resources>
diff --git a/libs/OWNERS b/libs/OWNERS
index 0477d2a9..0bf32d31 100644
--- a/libs/OWNERS
+++ b/libs/OWNERS
@@ -3,4 +3,3 @@
 
 ankiit@google.com
 alexstetson@google.com
-danzz@google.com
diff --git a/libs/appgrid/Android.bp b/libs/appgrid/Android.bp
index 22b05f9a..0ea3fe1d 100644
--- a/libs/appgrid/Android.bp
+++ b/libs/appgrid/Android.bp
@@ -15,6 +15,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 java_library_static {
@@ -58,9 +59,13 @@ android_library {
         "androidx.core_core-ktx",
         "kotlinx-coroutines-core",
         "kotlinx-coroutines-android",
+        "oem-token-lib",
     ],
 
-    libs: ["android.car"],
+    libs: [
+        "android.car",
+        "token-shared-lib-prebuilt",
+    ],
 
     manifest: "lib/AndroidManifest.xml",
     // TODO(b/319708040): re-enable use_resource_processor
@@ -92,6 +97,9 @@ android_app {
 
     static_libs: ["CarAppGrid-lib"],
 
+    libs: [
+        "token-shared-lib-prebuilt",
+    ],
     optimize: {
         enabled: true,
     },
diff --git a/libs/appgrid/OWNERS b/libs/appgrid/OWNERS
index ff57a20a..49e20542 100644
--- a/libs/appgrid/OWNERS
+++ b/libs/appgrid/OWNERS
@@ -3,6 +3,5 @@
 
 ankiit@google.com
 alexstetson@google.com
-danzz@google.com
 stenning@google.com
 alanschen@google.com
diff --git a/libs/appgrid/lib/res/drawable/page_indicator_bar.xml b/libs/appgrid/lib/res/drawable/page_indicator_bar.xml
index 141f58cb..73f3bf3d 100644
--- a/libs/appgrid/lib/res/drawable/page_indicator_bar.xml
+++ b/libs/appgrid/lib/res/drawable/page_indicator_bar.xml
@@ -19,8 +19,8 @@
     android:shape="rectangle">
     <corners android:radius="@dimen/page_indicator_edge_corner_radius"/>
     <solid
-        android:color="@color/page_indicator_bar_color"/>
+        android:color="?oemColorPrimary"/>
     <stroke
-        android:color="@color/page_indicator_bar_color">
+        android:color="?oemColorPrimary">
     </stroke>
 </shape>
diff --git a/libs/appgrid/lib/res/values/colors.xml b/libs/appgrid/lib/res/values/colors.xml
index a62fd851..c5ef63bb 100644
--- a/libs/appgrid/lib/res/values/colors.xml
+++ b/libs/appgrid/lib/res/values/colors.xml
@@ -17,10 +17,8 @@
 <resources>
     <color name="icon_tint">#FFF8F9FA</color>
     <color name="recent_apps_line_divider_color">#1FFFFFFF</color>
-    <color name="page_indicator_bar_color">#FF66B5FF</color>
     <color name="app_item_on_hover_border_color">#FF66B5FF</color>
     <color name="app_item_on_hover_background_color">#3D66B5FF</color>
-    <color name="app_name_color">#FFE8EAED</color>
     <color name="banner_background_color">#2E3134</color>
     <color name="banner_button_text_color">#66B5FF</color>
     <color name="banner_title_text_color">#FFFFFF</color>
diff --git a/libs/appgrid/lib/res/values/overlayable.xml b/libs/appgrid/lib/res/values/overlayable.xml
index a9780106..a342a173 100644
--- a/libs/appgrid/lib/res/values/overlayable.xml
+++ b/libs/appgrid/lib/res/values/overlayable.xml
@@ -28,12 +28,10 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="bool" name="use_vertical_app_grid"/>
       <item type="color" name="app_item_on_hover_background_color"/>
       <item type="color" name="app_item_on_hover_border_color"/>
-      <item type="color" name="app_name_color"/>
       <item type="color" name="banner_background_color"/>
       <item type="color" name="banner_button_text_color"/>
       <item type="color" name="banner_title_text_color"/>
       <item type="color" name="icon_tint"/>
-      <item type="color" name="page_indicator_bar_color"/>
       <item type="color" name="recent_apps_line_divider_color"/>
       <item type="dimen" name="app_bar_height"/>
       <item type="dimen" name="app_grid_header_margin"/>
diff --git a/libs/appgrid/lib/res/values/styles.xml b/libs/appgrid/lib/res/values/styles.xml
index 3e1d2049..013bc20d 100644
--- a/libs/appgrid/lib/res/values/styles.xml
+++ b/libs/appgrid/lib/res/values/styles.xml
@@ -18,7 +18,7 @@
 
     <style name="AppDisplayNameStyle">
         <item name="android:textSize">28sp</item>
-        <item name="android:textColor">@color/app_name_color</item>
+        <item name="android:textColor">?oemColorOnSurface</item>
         <item name="android:fontFamily">sans-serif</item>
         <item name="android:ellipsize">end</item>
         <item name="android:maxLines">1</item>
diff --git a/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSourceImplTest.kt b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSourceImplTest.kt
index d32ccc60..b65c8e08 100644
--- a/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSourceImplTest.kt
+++ b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSourceImplTest.kt
@@ -17,12 +17,17 @@
 package com.android.car.carlauncher.datasources
 
 import android.content.BroadcastReceiver
+import android.content.ComponentName
 import android.content.Intent
 import android.content.IntentFilter
 import android.content.pm.LauncherActivityInfo
 import android.content.pm.LauncherApps
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
+import android.content.pm.ServiceInfo
 import android.net.Uri
 import android.os.UserHandle
+import com.android.car.carlauncher.datasources.LauncherActivitiesDataSourceImpl.Companion.CAR_APP_MEDIA_CATEGORY
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.cancelChildren
 import kotlinx.coroutines.flow.collect
@@ -36,6 +41,8 @@ import org.junit.Assert.assertEquals
 import org.junit.Assert.assertNotNull
 import org.junit.Test
 import org.junit.runner.RunWith
+import org.mockito.ArgumentMatchers.anyInt
+import org.mockito.kotlin.any
 import org.mockito.kotlin.doReturn
 import org.mockito.kotlin.mock
 import org.mockito.kotlin.verify
@@ -46,10 +53,20 @@ import org.robolectric.RuntimeEnvironment
 class LauncherActivitiesDataSourceImplTest {
 
     private val scope = TestScope()
+
     private val bgDispatcher =
         StandardTestDispatcher(scope.testScheduler, name = "Background dispatcher")
 
     private val launcherActivities: List<LauncherActivityInfo> = listOf(mock(), mock())
+
+    private val calMediaComponentName = ComponentName(CAR_APP_SERVICE_MEDIA, "Media")
+    private val calNavigationComponentName = ComponentName(CAR_APP_SERVICE_NAVIGATION, "Navigation")
+    private val calMediaLauncherActivityInfo: LauncherActivityInfo = mock {
+        on { componentName } doReturn calMediaComponentName
+    }
+    private val calMediaLauncherActivities: List<LauncherActivityInfo> =
+        listOf(calMediaLauncherActivityInfo)
+
     private var broadcastReceiverCallback: BroadcastReceiver? = null
     private val registerReceiverFun: (BroadcastReceiver, IntentFilter) -> Unit =
         { broadcastReceiver, _ ->
@@ -59,8 +76,50 @@ class LauncherActivitiesDataSourceImplTest {
     private val myUserHandle: UserHandle = mock()
     private val launcherApps: LauncherApps = mock {
         on { getActivityList(null, myUserHandle) } doReturn launcherActivities
+        on {
+            getActivityList(CAR_APP_SERVICE_MEDIA, myUserHandle)
+        } doReturn calMediaLauncherActivities
+        on { getActivityList(CAR_APP_SERVICE_NAVIGATION, myUserHandle) } doReturn launcherActivities
+    }
+
+    private val listOfComponentNames = listOf(
+        calMediaComponentName, // 0, CarAppService MEDIA
+        calNavigationComponentName, // 1, CarAppService NAVIGATION
+    )
+
+    // List of CarAppServices returned by the PackageManager for queryIntentServices.
+    private val carAppServices: List<ResolveInfo> = listOfComponentNames.map { getResolveInfo(it) }
+
+    /**
+     * Returns a mocked ResolveInfo
+     * @param componentName packageName + className of the mocked [ServiceInfo]
+     * with an IntentFilter for the CarAppService category
+     */
+    private fun getResolveInfo(componentName: ComponentName): ResolveInfo {
+        return ResolveInfo().apply {
+            serviceInfo = ServiceInfo().apply {
+                packageName = componentName.packageName
+                name = componentName.className
+            }
+            filter = IntentFilter().apply {
+                if (componentName.packageName == CAR_APP_SERVICE_MEDIA) {
+                    addCategory(CAR_APP_MEDIA_CATEGORY)
+                } else if (componentName.packageName == CAR_APP_SERVICE_NAVIGATION) {
+                    addCategory(CAR_APP_NAVIGATION_CATEGORY)
+                }
+            }
+        }
+    }
+
+    private val packageManager: PackageManager = mock {
+        on {
+            queryIntentServices(
+                any(), anyInt()
+            )
+        } doReturn carAppServices
     }
     private val dataSource: LauncherActivitiesDataSource = LauncherActivitiesDataSourceImpl(
+        packageManager,
         launcherApps,
         registerReceiverFun,
         unregisterReceiverFun,
@@ -133,8 +192,23 @@ class LauncherActivitiesDataSourceImplTest {
         }
     }
 
+    @Test
+    fun getAllCalMediaLauncherActivities_onlyReturnsMediaCategory() = scope.runTest {
+        val outputCalActivityInfoList =
+            dataSource.getAllCalMediaLauncherActivities()
+
+        assertEquals(outputCalActivityInfoList.size, 1)
+        assertEquals(
+            outputCalActivityInfoList[0].componentName.packageName,
+            CAR_APP_SERVICE_MEDIA
+        )
+    }
+
     companion object {
         const val BROADCAST_EXPECTED_PACKAGE_NAME_1 = "com.test.example1"
         const val BROADCAST_EXPECTED_PACKAGE_NAME_2 = "com.test.example2"
+        const val CAR_APP_SERVICE_MEDIA = "com.test.car.app.package.media"
+        const val CAR_APP_SERVICE_NAVIGATION = "com.test.car.app.package.navigation"
+        const val CAR_APP_NAVIGATION_CATEGORY = "androidx.car.app.category.NAVIGATION"
     }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java
index 4f6827b6..07b7f968 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridActivity.java
@@ -27,6 +27,7 @@ import androidx.appcompat.app.AppCompatActivity;
 import androidx.fragment.app.Fragment;
 
 import com.android.car.carlauncher.AppGridFragment.Mode;
+import com.android.car.oem.tokens.Token;
 import com.android.car.ui.core.CarUi;
 import com.android.car.ui.toolbar.MenuItem;
 import com.android.car.ui.toolbar.NavButtonMode;
@@ -51,6 +52,7 @@ public class AppGridActivity extends AppCompatActivity {
         } else {
             setTheme(R.style.Theme_Launcher_AppGridActivity_NoToolbar);
         }
+        Token.applyOemTokenStyle(this);
         super.onCreate(savedInstanceState);
         setContentView(R.layout.app_grid_container_activity);
 
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
index b7cf2e42..7d125c04 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
@@ -266,6 +266,7 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
 
     private fun initViewModel() {
         val launcherActivities: LauncherActivitiesDataSource = LauncherActivitiesDataSourceImpl(
+            requireContext().packageManager,
             requireContext().getSystemService(LauncherApps::class.java),
             { broadcastReceiver: BroadcastReceiver?, intentFilter: IntentFilter? ->
                 requireContext().registerReceiver(broadcastReceiver, intentFilter)
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSource.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSource.kt
index d0613c53..d0c78947 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSource.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/LauncherActivitiesDataSource.kt
@@ -22,6 +22,8 @@ import android.content.Intent
 import android.content.IntentFilter
 import android.content.pm.LauncherActivityInfo
 import android.content.pm.LauncherApps
+import android.content.pm.PackageManager
+import android.content.pm.ResolveInfo
 import android.content.res.Resources
 import android.os.UserHandle
 import com.android.car.carlauncher.R
@@ -41,6 +43,11 @@ interface LauncherActivitiesDataSource {
      */
     suspend fun getAllLauncherActivities(): List<LauncherActivityInfo>
 
+    /**
+     * Gets all the Launchable activities for the user that have a CAL MBS integration.
+     */
+    suspend fun getAllCalMediaLauncherActivities(): List<LauncherActivityInfo>
+
     /**
      * Flow notifying changes if packages are changed.
      */
@@ -70,6 +77,7 @@ interface LauncherActivitiesDataSource {
  * @property [bgDispatcher] Executes all the operations on this background coroutine dispatcher.
  */
 class LauncherActivitiesDataSourceImpl(
+    private val packageManager: PackageManager,
     private val launcherApps: LauncherApps,
     private val registerReceiverFunction: (BroadcastReceiver, IntentFilter) -> Unit,
     private val unregisterReceiverFunction: (BroadcastReceiver) -> Unit,
@@ -80,6 +88,11 @@ class LauncherActivitiesDataSourceImpl(
 
     private val listOfApps = resources.getStringArray(R.array.hidden_apps).toList()
 
+    companion object {
+        const val CAR_APP_SERVICE_INTERFACE: String = "androidx.car.app.CarAppService"
+        const val CAR_APP_MEDIA_CATEGORY: String = "androidx.car.app.category.MEDIA"
+    }
+
     /**
      * Gets all launcherActivities for a user with [userHandle]
      */
@@ -93,6 +106,23 @@ class LauncherActivitiesDataSourceImpl(
         }
     }
 
+    /**
+     * Gets all launcherActivities for a user with [userHandle] that have an MBS service
+     * with CarAppLibrary metadata defined
+     */
+    override suspend fun getAllCalMediaLauncherActivities(): List<LauncherActivityInfo> {
+        return withContext(bgDispatcher) {
+            packageManager.queryIntentServices(
+                Intent(CAR_APP_SERVICE_INTERFACE),
+                PackageManager.GET_RESOLVED_FILTER
+            ).filter {
+                hasCalMediaCategory(it)
+            }.map {
+                launcherApps.getActivityList(it.serviceInfo.packageName, userHandle)
+            }.flatten()
+        }
+    }
+
     /**
      * Gets a flow Producer which report changes in the packages with following actions:
      * [Intent.ACTION_PACKAGE_ADDED], [Intent.ACTION_PACKAGE_CHANGED],
@@ -137,4 +167,17 @@ class LauncherActivitiesDataSourceImpl(
     override fun getAppsToHide(): List<String> {
         return listOfApps
     }
+
+    private fun hasCalMediaCategory(resolveInfo: ResolveInfo?): Boolean {
+        if (resolveInfo == null) return false
+
+        if (resolveInfo.filter == null) return false
+
+        for (i in 0 until resolveInfo.filter.countCategories()) {
+            if (resolveInfo.filter.getCategory(i).equals(CAR_APP_MEDIA_CATEGORY)) {
+                return true
+            }
+        }
+        return false
+    }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt
index f9376a69..8b37e1e5 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/AppGridRepository.kt
@@ -120,7 +120,7 @@ class AppGridRepositoryImpl(
 ) : AppGridRepository {
 
     private val isVisibleBackgroundUser = !userManager.isUserForeground &&
-        userManager.isUserVisible && !userManager.isProfile
+            userManager.isUserVisible && !userManager.isProfile
 
     /**
      * Provides a flow of all apps in the app grid.
@@ -193,9 +193,13 @@ class AppGridRepositoryImpl(
      */
     override fun getMediaAppsList(): Flow<List<AppItem>> {
         return launcherActivities.getOnPackagesChanged().map {
-            mediaTemplateApps.getAllMediaServices(true).map {
+            val templatedMediaApps = mediaTemplateApps.getAllMediaServices(true).map {
                 it.toAppInfo(MEDIA).toAppItem(true)
             }
+            val calMediaApps = launcherActivities.getAllCalMediaLauncherActivities().map {
+                AppInfo(it.label, it.componentName, it.getBadgedIcon(0), LAUNCHER).toAppItem(true)
+            }
+            templatedMediaApps + calMediaApps
         }.flowOn(bgDispatcher).distinctUntilChanged()
     }
 
@@ -229,11 +233,12 @@ class AppGridRepositoryImpl(
         private val _launchActionType: AppLauncherProviderType,
         var redirectIntent: Intent? = null
     ) {
-        val launchActionType get() = if (redirectIntent == null) {
-            _launchActionType
-        } else {
-            MIRRORING
-        }
+        val launchActionType
+            get() = if (redirectIntent == null) {
+                _launchActionType
+            } else {
+                MIRRORING
+            }
 
         val appOrderInfo =
             AppOrderInfo(componentName.packageName, componentName.className, displayName.toString())
@@ -292,8 +297,9 @@ class AppGridRepositoryImpl(
         if (isVisibleBackgroundUser) {
             return try {
                 packageManager.getPackageInfo(
-                    appInfo.componentName.packageName, PackageManager.GET_PERMISSIONS)
-                    .requestedPermissions?.any {it == MANAGE_OWN_CALLS} ?: false
+                    appInfo.componentName.packageName, PackageManager.GET_PERMISSIONS
+                )
+                    .requestedPermissions?.any { it == MANAGE_OWN_CALLS } ?: false
             } catch (e: NameNotFoundException) {
                 Log.e(TAG, "Unable to query app permissions for $appInfo $e")
                 false
diff --git a/libs/appgrid/lib/tests/Android.bp b/libs/appgrid/lib/tests/Android.bp
index 4314dfdc..0acdab29 100644
--- a/libs/appgrid/lib/tests/Android.bp
+++ b/libs/appgrid/lib/tests/Android.bp
@@ -29,6 +29,7 @@ android_test {
         "android.car",
         "android.test.base.stubs.system",
         "android.car-system-stubs",
+        "token-shared-lib-prebuilt",
     ],
 
     optimize: {
@@ -50,6 +51,7 @@ android_test {
         "truth",
         "testables",
         "CarAppGrid-lib",
+        "oem-token-lib",
     ],
 
     platform_apis: true,
diff --git a/libs/car-launcher-common/OWNERS b/libs/car-launcher-common/OWNERS
index 80304ec9..a70cbbe6 100644
--- a/libs/car-launcher-common/OWNERS
+++ b/libs/car-launcher-common/OWNERS
@@ -2,6 +2,5 @@
 # Please update this list if you find better candidates.
 set noparent
 
-danzz@google.com
 ankiit@google.com
 jainams@google.com
```

