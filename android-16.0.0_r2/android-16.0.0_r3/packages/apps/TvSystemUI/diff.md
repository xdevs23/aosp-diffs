```diff
diff --git a/Android.bp b/Android.bp
index d338400..465f97d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -15,6 +15,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_tv_os",
 }
 
 prebuilt_etc {
@@ -48,7 +49,7 @@ android_library {
         "SystemUISharedLib",
         "SystemUI-shared-utils",
         "TvSystemUI-res",
-        "TwoPanelSettingsLib"
+        "TwoPanelSettingsLib",
     ],
     javacflags: ["-Adagger.fastInit=enabled"],
     manifest: "AndroidManifest.xml",
@@ -63,7 +64,7 @@ android_app {
         "SystemUI_optimized_defaults",
     ],
     static_libs: [
-        "TvSystemUI-core"
+        "TvSystemUI-core",
     ],
     overrides: [
         "SystemUI",
@@ -84,6 +85,6 @@ android_app {
     },
     required: [
         "privapp_whitelist_com.android.systemui",
-        "privapp_extension_com.android.systemui"
+        "privapp_extension_com.android.systemui",
     ],
 }
diff --git a/AndroidManifest-exclude-overrides.xml b/AndroidManifest-exclude-overrides.xml
index 292be75..9e184e6 100644
--- a/AndroidManifest-exclude-overrides.xml
+++ b/AndroidManifest-exclude-overrides.xml
@@ -46,6 +46,8 @@
             tools:node="remove" />
         <service android:name=".screenshot.appclips.AppClipsService"
             tools:node="remove" />
+        <service android:name=".screenrecord.ScreenRecordingService"
+            tools:node="remove" />
         <service android:name=".screenrecord.RecordingService"
             tools:node="remove" />
         <receiver android:name=".screenshot.ActionProxyReceiver"
diff --git a/OWNERS b/OWNERS
index 61e0ab4..9a7f153 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,5 @@
 # Android TV
 bronger@google.com
-agazal@google.com
 gubailey@google.com #{LAST_RESORT_SUGGESTION}
 timurc@google.com #{LAST_RESORT_SUGGESTION}
 
diff --git a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
index cc59990..1afcdd5 100644
--- a/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
+++ b/src/com/android/systemui/tv/dagger/TvSystemUIModule.kt
@@ -28,14 +28,18 @@ import com.android.systemui.broadcast.BroadcastSender
 import com.android.systemui.communal.posturing.dagger.NoopPosturingModule
 import com.android.systemui.dagger.ReferenceSystemUIModule
 import com.android.systemui.dagger.SysUISingleton
+import com.android.systemui.display.dagger.SystemUIDisplaySubcomponent
 import com.android.systemui.display.ui.viewmodel.ConnectingDisplayViewModel
 import com.android.systemui.dock.DockManager
 import com.android.systemui.dock.DockManagerImpl
 import com.android.systemui.doze.DozeHost
+import com.android.systemui.Flags
 import com.android.systemui.media.dialog.MediaOutputDialogManager
 import com.android.systemui.media.dialog.MediaSwitchingController
 import com.android.systemui.media.muteawait.MediaMuteAwaitConnectionCli
 import com.android.systemui.media.nearby.NearbyMediaDevicesManager
+import com.android.systemui.minmode.MinModeManager
+import com.android.systemui.minmode.MinModeManagerImpl
 import com.android.systemui.navigationbar.gestural.GestureModule
 import com.android.systemui.plugins.qs.QSFactory
 import com.android.systemui.power.dagger.PowerModule
@@ -85,7 +89,9 @@ import dagger.Provides
 import dagger.multibindings.ClassKey
 import dagger.multibindings.IntoMap
 import dagger.multibindings.IntoSet
+import java.util.Optional
 import javax.inject.Named
+import javax.inject.Provider
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 
 /**
@@ -120,8 +126,9 @@ import kotlinx.coroutines.ExperimentalCoroutinesApi
     TvNotificationsModule::class,
     TvSensorPrivacyModule::class,
     TvVolumeModule::class,
-]
-)
+], subcomponents = [
+    SystemUIDisplaySubcomponent::class,
+])
 abstract class TvSystemUIModule {
     @Binds
     abstract fun bindNotificationLockscreenUserManager(
@@ -250,5 +257,14 @@ abstract class TvSystemUIModule {
                     dialogTransitionAnimator,
                     mediaSwitchingControllerFactory
                 )
-    }
+
+        @Provides
+        @SysUISingleton
+        fun provideMinModeManager(impl: Provider<MinModeManagerImpl>): Optional<MinModeManager> =
+            if (Flags.enableMinmode()) {
+                Optional.of(impl.get())
+            } else {
+                Optional.empty()
+            }
+        }
 }
diff --git a/src/com/android/systemui/tv/media/FadingEdgeUtil.java b/src/com/android/systemui/tv/media/FadingEdgeUtil.java
index 4008bca..12c0278 100644
--- a/src/com/android/systemui/tv/media/FadingEdgeUtil.java
+++ b/src/com/android/systemui/tv/media/FadingEdgeUtil.java
@@ -43,7 +43,13 @@ public class FadingEdgeUtil {
     @SuppressWarnings("nullness")
     private static boolean shouldShowTopFadingEdge(RecyclerView recyclerView) {
         RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
+        if (layoutManager == null) {
+            return false;
+        }
         View firstVisibleChildView = layoutManager.getChildAt(0);
+        if (firstVisibleChildView == null) {
+            return false;
+        }
         int positionOfCurrentFistView = layoutManager.getPosition(firstVisibleChildView);
         boolean isFirstAdapterItemVisible = (positionOfCurrentFistView == 0);
         if (!isFirstAdapterItemVisible) {
diff --git a/src/com/android/systemui/tv/media/OutputDevicesFragment.java b/src/com/android/systemui/tv/media/OutputDevicesFragment.java
index 1fabba2..2e934eb 100644
--- a/src/com/android/systemui/tv/media/OutputDevicesFragment.java
+++ b/src/com/android/systemui/tv/media/OutputDevicesFragment.java
@@ -16,16 +16,12 @@
 
 package com.android.systemui.tv.media;
 
-import android.app.KeyguardManager;
 import android.content.Context;
 import android.graphics.Rect;
 import android.graphics.drawable.Drawable;
-import android.media.AudioManager;
-import android.media.session.MediaSessionManager;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
-import android.os.PowerExemptionManager;
 import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.View;
@@ -37,94 +33,33 @@ import androidx.fragment.app.FragmentManager;
 import androidx.recyclerview.widget.LinearLayoutManager;
 import androidx.recyclerview.widget.RecyclerView;
 
-import com.android.settingslib.bluetooth.LocalBluetoothManager;
 import com.android.settingslib.media.MediaDevice;
-import com.android.systemui.animation.DialogTransitionAnimator;
-import com.android.systemui.flags.FeatureFlags;
-import com.android.systemui.media.dialog.MediaSwitchingController;
-import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
-import com.android.systemui.plugins.ActivityStarter;
-import com.android.systemui.settings.UserTracker;
-import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
 import com.android.systemui.tv.res.R;
-import com.android.systemui.volume.panel.domain.interactor.VolumePanelGlobalStateInteractor;
 
 import javax.annotation.Nullable;
 import javax.inject.Inject;
 
 public class OutputDevicesFragment extends Fragment
-        implements MediaSwitchingController.Callback, TvMediaOutputAdapter.PanelCallback {
+        implements TvMediaOutputController.Callback, TvMediaOutputAdapter.PanelCallback {
 
     private static final String TAG = OutputDevicesFragment.class.getSimpleName();
     private static final boolean DEBUG = false;
 
-    private TvMediaOutputController mMediaOutputController;
+    private final TvMediaOutputController mMediaOutputController;
     private TvMediaOutputAdapter mAdapter;
     private RecyclerView mDevicesRecyclerView;
 
-    private final MediaSessionManager mMediaSessionManager;
-    private final LocalBluetoothManager mLocalBluetoothManager;
-    private final ActivityStarter mActivityStarter;
-    private final CommonNotifCollection mCommonNotifCollection;
-    private final DialogTransitionAnimator mDialogTransitionAnimator;
-    private final NearbyMediaDevicesManager mNearbyMediaDevicesManager;
-    private final AudioManager mAudioManager;
-    private final PowerExemptionManager mPowerExemptionManager;
-    private final KeyguardManager mKeyguardManager;
-    private final FeatureFlags mFeatureFlags;
-    private final VolumePanelGlobalStateInteractor mVolumePanelGlobalStateInteractor;
-    private final UserTracker mUserTracker;
-
     protected final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
     private String mActiveDeviceId;
 
     @Inject
-    public OutputDevicesFragment(
-            MediaSessionManager mediaSessionManager,
-            @Nullable LocalBluetoothManager localBluetoothManager,
-            ActivityStarter activityStarter,
-            CommonNotifCollection commonNotifCollection,
-            DialogTransitionAnimator dialogTransitionAnimator,
-            NearbyMediaDevicesManager nearbyMediaDevicesManager,
-            AudioManager audioManager,
-            PowerExemptionManager powerExemptionManager,
-            KeyguardManager keyguardManager,
-            FeatureFlags featureFlags,
-            VolumePanelGlobalStateInteractor volumePanelGlobalStateInteractor,
-            UserTracker userTracker) {
-        mMediaSessionManager = mediaSessionManager;
-        mLocalBluetoothManager = localBluetoothManager;
-        mActivityStarter = activityStarter;
-        mCommonNotifCollection = commonNotifCollection;
-        mDialogTransitionAnimator = dialogTransitionAnimator;
-        mNearbyMediaDevicesManager = nearbyMediaDevicesManager;
-        mAudioManager = audioManager;
-        mPowerExemptionManager = powerExemptionManager;
-        mKeyguardManager = keyguardManager;
-        mFeatureFlags = featureFlags;
-        mVolumePanelGlobalStateInteractor = volumePanelGlobalStateInteractor;
-        mUserTracker = userTracker;
+    public OutputDevicesFragment(TvMediaOutputController mediaOutputController) {
+        mMediaOutputController = mediaOutputController;
     }
 
     @Override
     public void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-        mMediaOutputController =
-                new TvMediaOutputController(
-                        getContext(),
-                        getContext().getPackageName(),
-                        mMediaSessionManager,
-                        mLocalBluetoothManager,
-                        mActivityStarter,
-                        mCommonNotifCollection,
-                        mDialogTransitionAnimator,
-                        mNearbyMediaDevicesManager,
-                        mAudioManager,
-                        mPowerExemptionManager,
-                        mKeyguardManager,
-                        mFeatureFlags,
-                        mVolumePanelGlobalStateInteractor,
-                        mUserTracker);
         mAdapter = new TvMediaOutputAdapter(getContext(), mMediaOutputController, this);
     }
 
@@ -196,16 +131,6 @@ public class OutputDevicesFragment extends Fragment
         mAdapter.updateItems();
     }
 
-    @Override
-    public void onMediaChanged() {
-        // NOOP
-    }
-
-    @Override
-    public void onMediaStoppedOrPaused() {
-        // NOOP
-    }
-
     @Override
     public void onRouteChanged() {
         mMainThreadHandler.post(() -> refresh(/* deviceSetChanged= */ false));
diff --git a/src/com/android/systemui/tv/media/TvMediaItem.java b/src/com/android/systemui/tv/media/TvMediaItem.java
new file mode 100644
index 0000000..7f2a263
--- /dev/null
+++ b/src/com/android/systemui/tv/media/TvMediaItem.java
@@ -0,0 +1,107 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.tv.media;
+
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
+import com.android.settingslib.media.MediaDevice;
+import com.android.systemui.res.R;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.Optional;
+
+/**
+ * TvMediaItem represents an item in output switcher list (could be a MediaDevice, group divider or
+ * connect new device item).
+ */
+public class TvMediaItem {
+
+    private final Optional<MediaDevice> mMediaDeviceOptional;
+    private final String mTitle;
+    @TvMediaItem.MediaItemType
+    private final int mMediaItemType;
+
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef({TvMediaItem.MediaItemType.TYPE_DEVICE,
+            TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER,
+            TvMediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE})
+    public @interface MediaItemType {
+        int TYPE_DEVICE = 0;
+        int TYPE_GROUP_DIVIDER = 1;
+        int TYPE_PAIR_NEW_DEVICE = 2;
+    }
+
+    private TvMediaItem(@Nullable MediaDevice device, @Nullable String title,
+            @TvMediaItem.MediaItemType int type) {
+        this.mMediaDeviceOptional = Optional.ofNullable(device);
+        this.mTitle = title;
+        this.mMediaItemType = type;
+    }
+
+    /**
+     * Returns a new {@link TvMediaItem.MediaItemType#TYPE_DEVICE} {@link TvMediaItem} with its
+     * {@link #getMediaDevice() media device} set to {@code device} and its title set to
+     * {@code device}'s name.
+     */
+    public static TvMediaItem createDeviceMediaItem(@NonNull MediaDevice device) {
+        return new TvMediaItem(device, device.getName(), MediaItemType.TYPE_DEVICE);
+    }
+
+    /**
+     * Returns a new {@link TvMediaItem.MediaItemType#TYPE_PAIR_NEW_DEVICE} {@link TvMediaItem} with
+     * both {@link #getMediaDevice() media device} and title set to {@code null}.
+     */
+    public static TvMediaItem createPairNewDeviceMediaItem() {
+        return new TvMediaItem(/* device */ null,
+                /* title */ null, TvMediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE);
+    }
+
+    /**
+     * Returns a new {@link TvMediaItem.MediaItemType#TYPE_GROUP_DIVIDER} {@link TvMediaItem} with
+     * the specified title and a {@code null} {@link #getMediaDevice() media device}.
+     */
+    public static TvMediaItem createGroupDividerMediaItem(@Nullable String title) {
+        return new TvMediaItem(/* device */ null, title,
+                TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER);
+    }
+
+    /** Get layout id based on media item Type. */
+    public static int getMediaLayoutId(@TvMediaItem.MediaItemType int mediaItemType) {
+        return switch (mediaItemType) {
+            case TvMediaItem.MediaItemType.TYPE_DEVICE,
+                 TvMediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE ->
+                    R.layout.media_output_list_item_advanced;
+            default -> R.layout.media_output_list_group_divider;
+        };
+    }
+
+    public Optional<MediaDevice> getMediaDevice() {
+        return mMediaDeviceOptional;
+    }
+
+    public String getTitle() {
+        return mTitle;
+    }
+
+    public int getMediaItemType() {
+        return mMediaItemType;
+    }
+
+}
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
index 0e95794..b131837 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputAdapter.java
@@ -46,7 +46,6 @@ import com.android.settingslib.media.BluetoothMediaDevice;
 import com.android.settingslib.media.LocalMediaManager;
 import com.android.settingslib.media.MediaDevice;
 import com.android.settingslib.media.MediaDevice.MediaDeviceType;
-import com.android.systemui.media.dialog.MediaItem;
 import com.android.systemui.tv.media.settings.CenteredImageSpan;
 import com.android.systemui.tv.media.settings.ControlWidget;
 import com.android.systemui.tv.res.R;
@@ -56,7 +55,7 @@ import java.util.List;
 import java.util.concurrent.CopyOnWriteArrayList;
 
 /**
- * Adapter for showing the {@link MediaItem}s in the {@link TvMediaOutputDialogActivity}.
+ * Adapter for showing the {@link TvMediaItem}s in the {@link TvMediaOutputDialogActivity}.
  */
 public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {
 
@@ -66,7 +65,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
     private final TvMediaOutputController mMediaOutputController;
     private final PanelCallback mCallback;
     private final Context mContext;
-    protected List<MediaItem> mMediaItemList = new CopyOnWriteArrayList<>();
+    protected List<TvMediaItem> mMediaItemList = new CopyOnWriteArrayList<>();
 
     private final AccessibilityManager mA11yManager;
 
@@ -94,7 +93,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
     public int getItemViewType(int position) {
         if (position >= mMediaItemList.size()) {
             Log.e(TAG, "Incorrect position for item type: " + position);
-            return MediaItem.MediaItemType.TYPE_GROUP_DIVIDER;
+            return TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER;
         }
         return mMediaItemList.get(position).getMediaItemType();
     }
@@ -102,13 +101,13 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
     @Override
     public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
         View mHolderView = LayoutInflater.from(mContext)
-                .inflate(MediaItem.getMediaLayoutId(viewType), parent, false);
+                .inflate(TvMediaItem.getMediaLayoutId(viewType), parent, false);
 
         switch (viewType) {
-            case MediaItem.MediaItemType.TYPE_GROUP_DIVIDER:
+            case TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER:
                 return new DividerViewHolder(mHolderView);
-            case MediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE:
-            case MediaItem.MediaItemType.TYPE_DEVICE:
+            case TvMediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE:
+            case TvMediaItem.MediaItemType.TYPE_DEVICE:
                 return new DeviceViewHolder(mHolderView);
             default:
                 Log.e(TAG, "unknown viewType: " + viewType);
@@ -122,13 +121,13 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
             Log.e(TAG, "Tried to bind at position > list size (" + getItemCount() + ")");
         }
 
-        MediaItem currentMediaItem = mMediaItemList.get(position);
+        TvMediaItem currentMediaItem = mMediaItemList.get(position);
         switch (currentMediaItem.getMediaItemType()) {
-            case MediaItem.MediaItemType.TYPE_GROUP_DIVIDER ->
+            case TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER ->
                     ((DividerViewHolder) viewHolder).onBind(currentMediaItem.getTitle());
-            case MediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE ->
+            case TvMediaItem.MediaItemType.TYPE_PAIR_NEW_DEVICE ->
                     ((DeviceViewHolder) viewHolder).onBindNewDevice();
-            case MediaItem.MediaItemType.TYPE_DEVICE -> ((DeviceViewHolder) viewHolder).onBind(
+            case TvMediaItem.MediaItemType.TYPE_DEVICE -> ((DeviceViewHolder) viewHolder).onBind(
                     currentMediaItem.getMediaDevice().get(), position);
             default -> Log.d(TAG, "Incorrect position: " + position);
         }
@@ -148,7 +147,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
             return 0;
         }
         for (int i = 0; i < mMediaItemList.size(); i++) {
-            MediaItem item = mMediaItemList.get(i);
+            TvMediaItem item = mMediaItemList.get(i);
             if (item.getMediaDevice().isPresent()) {
                 if (item.getMediaDevice().get().getId().equals(mSavedDeviceId)) {
                     mSavedDeviceId = null;
@@ -186,13 +185,13 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
 
     @Override
     public long getItemId(int position) {
-        MediaItem item = mMediaItemList.get(position);
+        TvMediaItem item = mMediaItemList.get(position);
         if (item.getMediaDevice().isPresent()) {
             return item.getMediaDevice().get().getId().hashCode();
         }
-        if (item.getMediaItemType() == MediaItem.MediaItemType.TYPE_GROUP_DIVIDER) {
+        if (item.getMediaItemType() == TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER) {
             if (item.getTitle() == null || item.getTitle().isEmpty()) {
-                return MediaItem.MediaItemType.TYPE_GROUP_DIVIDER;
+                return TvMediaItem.MediaItemType.TYPE_GROUP_DIVIDER;
             }
             return item.getTitle().hashCode();
         }
@@ -204,7 +203,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         mMediaItemList.addAll(mMediaOutputController.getMediaItemList());
         if (DEBUG) {
             Log.d(TAG, "updateItems");
-            for (MediaItem mediaItem : mMediaItemList) {
+            for (TvMediaItem mediaItem : mMediaItemList) {
                 Log.d(TAG, mediaItem.toString());
             }
         }
@@ -367,7 +366,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
                 if (DEBUG) Log.d(TAG, "Device is already selected as the active output");
                 return;
             }
-            mMediaOutputController.setTemporaryAllowListExceptionIfNeeded(mediaDevice);
+            mMediaOutputController.setTemporaryAllowListExceptionIfNeeded();
             mMediaOutputController.connectDevice(mediaDevice);
             mediaDevice.setState(LocalMediaManager.MediaDeviceState.STATE_CONNECTING);
             notifyDataSetChanged();
@@ -395,7 +394,7 @@ public class TvMediaOutputAdapter extends RecyclerView.Adapter<RecyclerView.View
         private void launchBluetoothSettings() {
             mCallback.dismissDialog();
 
-            String uri = mMediaOutputController.getBluetoothSettingsSliceUri();
+            String uri = TvMediaOutputController.getBluetoothSettingsSliceUri(mContext);
             if (uri == null) {
                 return;
             }
diff --git a/src/com/android/systemui/tv/media/TvMediaOutputController.java b/src/com/android/systemui/tv/media/TvMediaOutputController.java
index 01eb571..bd2dd2b 100644
--- a/src/com/android/systemui/tv/media/TvMediaOutputController.java
+++ b/src/com/android/systemui/tv/media/TvMediaOutputController.java
@@ -16,267 +16,239 @@
 
 package com.android.systemui.tv.media;
 
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_3POINT5_MM_AUDIO_DEVICE;
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_BLUETOOTH_DEVICE;
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_CAST_DEVICE;
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_CAST_GROUP_DEVICE;
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_FAST_PAIR_BLUETOOTH_DEVICE;
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_PHONE_DEVICE;
-import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_USB_C_AUDIO_DEVICE;
-
-import android.app.KeyguardManager;
 import android.content.Context;
 import android.content.pm.PackageManager.NameNotFoundException;
 import android.content.res.Resources;
 import android.media.AudioManager;
-import android.media.session.MediaSessionManager;
 import android.os.PowerExemptionManager;
-import android.text.TextUtils;
 import android.util.Log;
 
+import androidx.annotation.Nullable;
+
 import com.android.settingslib.bluetooth.LocalBluetoothManager;
+import com.android.settingslib.media.InfoMediaManager;
+import com.android.settingslib.media.LocalMediaManager;
 import com.android.settingslib.media.MediaDevice;
-import com.android.systemui.animation.DialogTransitionAnimator;
-import com.android.systemui.flags.FeatureFlags;
-import com.android.systemui.media.dialog.MediaItem;
-import com.android.systemui.media.dialog.MediaSwitchingController;
-import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
-import com.android.systemui.plugins.ActivityStarter;
-import com.android.systemui.settings.UserTracker;
-import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
-import com.android.systemui.tv.res.R;
-import com.android.systemui.volume.panel.domain.interactor.VolumePanelGlobalStateInteractor;
+import com.android.settingslib.utils.ThreadUtils;
 
 import org.jetbrains.annotations.NotNull;
 
-import java.util.ArrayList;
 import java.util.List;
+import java.util.concurrent.CopyOnWriteArrayList;
+
+import javax.inject.Inject;
 
 /**
- * Extends {@link MediaSwitchingController} to create a TV specific ordering and grouping of devices
- * which are shown in the {@link TvMediaOutputDialogActivity}.
+ * Keeps track of output devices and sorts and groups them to be displayed in the
+ * OutputDevicesFragment.
  */
-public class TvMediaOutputController extends MediaSwitchingController {
+public class TvMediaOutputController implements LocalMediaManager.DeviceCallback {
 
     private static final String TAG = TvMediaOutputController.class.getSimpleName();
+    private static final boolean DEBUG = false;
+
     private static final String SETTINGS_PACKAGE = "com.android.tv.settings";
 
+    private static final long POWER_ALLOWLIST_DURATION_MS = 20_000;
+    private static final String POWER_ALLOWLIST_REASON = "mediaoutput:remote_transfer";
+
     private final Context mContext;
     private final AudioManager mAudioManager;
-
+    protected final Object mMediaDevicesLock = new Object();
+    private final InfoMediaManager mInfoMediaManager;
+    private final LocalMediaManager mLocalMediaManager;
+    private final PowerExemptionManager mPowerExemptionManager;
+    private final String mPackageName;
+    private final TvOutputMediaItemListProxy mOutputMediaItemListProxy;
+    private final List<MediaDevice> mCachedMediaDevices = new CopyOnWriteArrayList<>();
+    private Callback mCallback;
+    private boolean mIsRefreshing;
+    private boolean mNeedRefresh;
+
+    @Inject
     public TvMediaOutputController(
             @NotNull Context context,
-            String packageName,
-            MediaSessionManager mediaSessionManager,
-            LocalBluetoothManager lbm,
-            ActivityStarter starter,
-            CommonNotifCollection notifCollection,
-            DialogTransitionAnimator dialogTransitionAnimator,
-            NearbyMediaDevicesManager nearbyMediaDevicesManager,
+            @Nullable LocalBluetoothManager localBluetoothManager,
             AudioManager audioManager,
-            PowerExemptionManager powerExemptionManager,
-            KeyguardManager keyGuardManager,
-            FeatureFlags featureFlags,
-            VolumePanelGlobalStateInteractor volumePanelGlobalStateInteractor,
-            UserTracker userTracker) {
-        super(
-                context,
-                packageName,
-                /* userHandle= */ null,
-                /* token= */ null,
-                mediaSessionManager,
-                lbm,
-                starter,
-                notifCollection,
-                dialogTransitionAnimator,
-                nearbyMediaDevicesManager,
-                audioManager,
-                powerExemptionManager,
-                keyGuardManager,
-                featureFlags,
-                volumePanelGlobalStateInteractor,
-                userTracker);
+            PowerExemptionManager powerExemptionManager) {
         mContext = context;
         mAudioManager = audioManager;
+        mPowerExemptionManager = powerExemptionManager;
+        mPackageName = mContext.getPackageName();
+
+        mInfoMediaManager =
+                InfoMediaManager.createInstance(mContext, mPackageName,
+                        /* userHandle= */ null, localBluetoothManager, /* token= */ null);
+        mLocalMediaManager = new LocalMediaManager(mContext, localBluetoothManager,
+                mInfoMediaManager, mPackageName);
+        mOutputMediaItemListProxy = new TvOutputMediaItemListProxy(context);
     }
 
-    void showVolumeDialog() {
-        mAudioManager.adjustVolume(AudioManager.ADJUST_SAME, AudioManager.FLAG_SHOW_UI);
-    }
+    static String getBluetoothSettingsSliceUri(Context context) {
+        String uri = null;
+        Resources res;
 
-    /**
-     * Assigns lower priorities to devices that should be shown higher up in the list.
-     */
-    private int getDevicePriorityGroup(MediaDevice mediaDevice) {
-        int mediaDeviceType = mediaDevice.getDeviceType();
-        return switch (mediaDeviceType) {
-            case TYPE_PHONE_DEVICE -> 1;
-            case TYPE_USB_C_AUDIO_DEVICE -> 2;
-            case TYPE_3POINT5_MM_AUDIO_DEVICE -> 3;
-            case TYPE_CAST_DEVICE, TYPE_CAST_GROUP_DEVICE, TYPE_BLUETOOTH_DEVICE,
-                    TYPE_FAST_PAIR_BLUETOOTH_DEVICE -> 5;
-            default -> 4;
-        };
+        try {
+            res = context.getPackageManager().getResourcesForApplication(SETTINGS_PACKAGE);
+            int resourceId = res.getIdentifier(
+                    SETTINGS_PACKAGE + ":string/connected_devices_slice_uri", null, null);
+            if (resourceId != 0) {
+                uri = res.getString(resourceId);
+            }
+        } catch (NameNotFoundException exception) {
+            Log.e(TAG, "Could not find TvSettings package: " + exception);
+        }
+        return uri;
     }
 
-    private void sortMediaDevices(List<MediaDevice> mediaDevices) {
-        mediaDevices.sort((device1, device2) -> {
-            int priority1 = getDevicePriorityGroup(device1);
-            int priority2 = getDevicePriorityGroup(device2);
-
-            if (priority1 != priority2) {
-                return (priority1 < priority2) ? -1 : 1;
-            }
-            // Show connected before disconnected devices
-            if (device1.isConnected() != device2.isConnected()) {
-                return device1.isConnected() ? -1 : 1;
-            }
-            return device1.getName().compareToIgnoreCase(device2.getName());
-        });
+    protected void start(@NotNull Callback cb) {
+        synchronized (mMediaDevicesLock) {
+            mCachedMediaDevices.clear();
+            mOutputMediaItemListProxy.clear();
+        }
+        mCallback = cb;
+        mLocalMediaManager.registerCallback(this);
+        mLocalMediaManager.startScan();
     }
 
-    @Override
-    protected List<MediaItem> buildMediaItems(List<MediaItem> oldMediaItems,
-            List<MediaDevice> devices) {
+    protected void stop() {
+        mLocalMediaManager.unregisterCallback(this);
+        mLocalMediaManager.stopScan();
         synchronized (mMediaDevicesLock) {
-            if (oldMediaItems.isEmpty()) {
-                return buildInitialList(devices);
-            }
-            return buildBetterSubsequentList(oldMediaItems, devices);
+            mCachedMediaDevices.clear();
+            mOutputMediaItemListProxy.clear();
         }
     }
 
-    private List<MediaItem> buildInitialList(List<MediaDevice> devices) {
-        sortMediaDevices(devices);
+    public boolean isRefreshing() {
+        return mIsRefreshing;
+    }
 
-        List<MediaItem> finalMediaItems = new ArrayList<>();
-        boolean disconnectedDevicesAdded = false;
-        for (MediaDevice device : devices) {
-            // Add divider before first disconnected device
-            if (!device.isConnected() && !disconnectedDevicesAdded) {
-                addOtherDevicesDivider(finalMediaItems);
-                disconnectedDevicesAdded = true;
-            }
-            finalMediaItems.add(MediaItem.createDeviceMediaItem(device));
+    public void setRefreshing(boolean refreshing) {
+        mIsRefreshing = refreshing;
+    }
+
+    public void refreshDataSetIfNeeded() {
+        if (mNeedRefresh) {
+            buildMediaItems(mCachedMediaDevices);
+            mCallback.onDeviceListChanged();
+            mNeedRefresh = false;
+        }
+    }
+
+    private void buildMediaItems(List<MediaDevice> devices) {
+        synchronized (mMediaDevicesLock) {
+            mOutputMediaItemListProxy.updateMediaDevices(devices);
         }
-        addConnectAnotherDeviceItem(finalMediaItems);
-        return finalMediaItems;
     }
 
     /**
-     * Keep devices that have not changed their connection state in the same order.
-     * If there is a new connected device, put it at the *bottom* of the connected devices list and
-     * if there is a newly disconnected device, add it at the *top* of the disconnected devices.
+     * Returns a list of media items to be rendered in the device list.
      */
-    private List<MediaItem> buildBetterSubsequentList(List<MediaItem> previousMediaItems,
-            List<MediaDevice> devices) {
-
-        final List<MediaItem> targetMediaItems = new ArrayList<>();
-        // Only use the actual devices, not the dividers etc.
-        List<MediaItem> oldMediaItems = previousMediaItems.stream()
-                .filter(mediaItem -> mediaItem.getMediaDevice().isPresent()).toList();
-        addItemsBasedOnConnection(targetMediaItems, oldMediaItems, devices,
-                /* isConnected= */ true);
-        addItemsBasedOnConnection(targetMediaItems, oldMediaItems, devices,
-                /* isConnected= */ false);
-
-        addConnectAnotherDeviceItem(targetMediaItems);
-        return targetMediaItems;
+    public List<TvMediaItem> getMediaItemList() {
+        synchronized (mMediaDevicesLock) {
+            return mOutputMediaItemListProxy.getOutputMediaItemList();
+        }
     }
 
-    private void addItemsBasedOnConnection(List<MediaItem> targetMediaItems,
-            List<MediaItem> oldMediaItems, List<MediaDevice> devices, boolean isConnected) {
-
-        List<MediaDevice> matchingMediaDevices = new ArrayList<>();
-        for (MediaItem originalMediaItem : oldMediaItems) {
-            // Only go through the device items
-            MediaDevice oldDevice = originalMediaItem.getMediaDevice().get();
-
-            for (MediaDevice newDevice : devices) {
-                if (TextUtils.equals(oldDevice.getId(), newDevice.getId())
-                        && oldDevice.isConnected() == isConnected
-                        && newDevice.isConnected() == isConnected) {
-                    matchingMediaDevices.add(newDevice);
-                    break;
+    public boolean isAnyDeviceTransferring() {
+        synchronized (mMediaDevicesLock) {
+            for (TvMediaItem mediaItem : mOutputMediaItemListProxy.getOutputMediaItemList()) {
+                if (mediaItem.getMediaDevice().isPresent()
+                        && mediaItem.getMediaDevice().get().getState()
+                        == LocalMediaManager.MediaDeviceState.STATE_CONNECTING) {
+                    return true;
                 }
             }
         }
-        devices.removeAll(matchingMediaDevices);
+        return false;
+    }
 
-        List<MediaDevice> newMediaDevices = new ArrayList<>();
-        for (MediaDevice remainingDevice : devices) {
-            if (remainingDevice.isConnected() == isConnected) {
-                newMediaDevices.add(remainingDevice);
-            }
-        }
-        devices.removeAll(newMediaDevices);
-
-        // Add new connected devices at the end, add new disconnected devices at the start
-        if (isConnected) {
-            targetMediaItems.addAll(
-                    matchingMediaDevices.stream().map(MediaItem::createDeviceMediaItem).toList());
-            targetMediaItems.addAll(
-                    newMediaDevices.stream().map(MediaItem::createDeviceMediaItem).toList());
-        } else {
-            if (!matchingMediaDevices.isEmpty() || !newMediaDevices.isEmpty()) {
-                addOtherDevicesDivider(targetMediaItems);
-            }
-            targetMediaItems.addAll(
-                    newMediaDevices.stream().map(MediaItem::createDeviceMediaItem).toList());
-            targetMediaItems.addAll(
-                    matchingMediaDevices.stream().map(MediaItem::createDeviceMediaItem).toList());
-        }
+    public MediaDevice getCurrentConnectedMediaDevice() {
+        return mLocalMediaManager.getCurrentConnectedDevice();
     }
 
-    private void addOtherDevicesDivider(List<MediaItem> mediaItems) {
-        mediaItems.add(
-                MediaItem.createGroupDividerMediaItem(
-                        mContext.getString(R.string.media_output_dialog_other_devices)));
+    public List<MediaDevice> getSelectedMediaDevice() {
+        return mLocalMediaManager.getSelectedMediaDevice();
     }
 
-    private void addConnectAnotherDeviceItem(List<MediaItem> mediaItems) {
-        if (getBluetoothSettingsSliceUri() == null) {
-            Log.d(TAG, "No bluetooth slice set.");
+    protected void setTemporaryAllowListExceptionIfNeeded() {
+        if (mPowerExemptionManager == null || mPackageName == null) {
+            Log.w(TAG, "powerExemptionManager or package name is null");
             return;
         }
-        mediaItems.add(MediaItem.createGroupDividerMediaItem(/* title */ null));
-        mediaItems.add(MediaItem.createPairNewDeviceMediaItem());
+        mPowerExemptionManager.addToTemporaryAllowList(mPackageName,
+                PowerExemptionManager.REASON_MEDIA_NOTIFICATION_TRANSFER,
+                POWER_ALLOWLIST_REASON,
+                POWER_ALLOWLIST_DURATION_MS);
     }
 
-    String getBluetoothSettingsSliceUri() {
-        String uri = null;
-        Resources res;
+    protected void connectDevice(MediaDevice device) {
+        mInfoMediaManager.setDeviceState(
+                device, LocalMediaManager.MediaDeviceState.STATE_CONNECTING);
 
-        try {
-            res = mContext.getPackageManager().getResourcesForApplication(SETTINGS_PACKAGE);
-            int resourceId = res.getIdentifier(
-                    SETTINGS_PACKAGE + ":string/connected_devices_slice_uri", null, null);
-            if (resourceId != 0) {
-                uri = res.getString(resourceId);
-            }
-        } catch (NameNotFoundException exception) {
-            Log.e(TAG, "Could not find TvSettings package: " + exception);
+        if (DEBUG) {
+            Log.d(TAG, "initiate switching from " + getCurrentConnectedMediaDevice()
+                    + " to " + device);
         }
-        return uri;
+
+        ThreadUtils.postOnBackgroundThread(() -> {
+            mLocalMediaManager.connectDevice(device);
+        });
+    }
+
+    // Extending DeviceCallback
+
+    void showVolumeDialog() {
+        mAudioManager.adjustVolume(AudioManager.ADJUST_SAME, AudioManager.FLAG_SHOW_UI);
     }
 
     @Override
-    protected void start(@NotNull Callback cb) {
-        super.start(cb);
+    public void onDeviceListUpdate(List<MediaDevice> devices) {
+        if (!mIsRefreshing) {
+            buildMediaItems(devices);
+            mCallback.onDeviceListChanged();
+        } else {
+            synchronized (mMediaDevicesLock) {
+                mNeedRefresh = true;
+                mCachedMediaDevices.clear();
+                mCachedMediaDevices.addAll(devices);
+            }
+        }
     }
 
     @Override
-    protected void stop() {
-        super.stop();
+    public void onSelectedDeviceStateChanged(
+            MediaDevice device, @LocalMediaManager.MediaDeviceState int state) {
+        if (DEBUG) Log.d(TAG, "Successfully switched output to " + device.getName());
+        mCallback.onRouteChanged();
     }
 
     @Override
-    protected void setTemporaryAllowListExceptionIfNeeded(MediaDevice targetDevice) {
-        super.setTemporaryAllowListExceptionIfNeeded(targetDevice);
+    public void onDeviceAttributesChanged() {
+        mCallback.onRouteChanged();
     }
 
     @Override
-    protected void connectDevice(MediaDevice mediaDevice) {
-        super.connectDevice(mediaDevice);
+    public void onRequestFailed(int reason) {
+        if (DEBUG) Log.d(TAG, "Failed to switch output: " + reason);
+        mCallback.onRouteChanged();
+    }
+
+    public interface Callback {
+        /**
+         * Override to handle the device status or attributes updating.
+         */
+        void onRouteChanged();
+
+        /**
+         * Override to handle the devices set updating.
+         */
+        void onDeviceListChanged();
+
+        /**
+         * Override to dismiss dialog.
+         */
+        void dismissDialog();
     }
 }
diff --git a/src/com/android/systemui/tv/media/TvOutputMediaItemListProxy.java b/src/com/android/systemui/tv/media/TvOutputMediaItemListProxy.java
new file mode 100644
index 0000000..d6ac5bc
--- /dev/null
+++ b/src/com/android/systemui/tv/media/TvOutputMediaItemListProxy.java
@@ -0,0 +1,210 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.tv.media;
+
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_3POINT5_MM_AUDIO_DEVICE;
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_BLUETOOTH_DEVICE;
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_CAST_DEVICE;
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_CAST_GROUP_DEVICE;
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_FAST_PAIR_BLUETOOTH_DEVICE;
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_PHONE_DEVICE;
+import static com.android.settingslib.media.MediaDevice.MediaDeviceType.TYPE_USB_C_AUDIO_DEVICE;
+
+import android.content.Context;
+import android.text.TextUtils;
+import android.util.Log;
+
+import com.android.settingslib.media.MediaDevice;
+import com.android.systemui.tv.res.R;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.CopyOnWriteArrayList;
+
+import javax.inject.Inject;
+
+public class TvOutputMediaItemListProxy {
+    private static final String TAG = "TvOutputMediaItemListProxy";
+    private final Context mContext;
+
+    private final List<TvMediaItem> mCurrentMediaItems;
+    private final List<TvMediaItem> mOldMediaItems;
+
+    @Inject
+    public TvOutputMediaItemListProxy(Context context) {
+        mContext = context;
+        mCurrentMediaItems = new CopyOnWriteArrayList<>();
+        mOldMediaItems = new CopyOnWriteArrayList<>();
+    }
+
+    /**
+     * Assigns lower priorities to devices that should be shown higher up in the list.
+     */
+    static int getDevicePriorityGroup(MediaDevice mediaDevice) {
+        int mediaDeviceType = mediaDevice.getDeviceType();
+        return switch (mediaDeviceType) {
+            case TYPE_PHONE_DEVICE -> 1;
+            case TYPE_USB_C_AUDIO_DEVICE -> 2;
+            case TYPE_3POINT5_MM_AUDIO_DEVICE -> 3;
+            case TYPE_CAST_DEVICE, TYPE_CAST_GROUP_DEVICE, TYPE_BLUETOOTH_DEVICE,
+                 TYPE_FAST_PAIR_BLUETOOTH_DEVICE -> 5;
+            default -> 4;
+        };
+    }
+
+    public List<TvMediaItem> getOutputMediaItemList() {
+        return mCurrentMediaItems;
+    }
+
+    public void updateMediaDevices(List<MediaDevice> devices) {
+        if (mCurrentMediaItems.isEmpty()) {
+            mCurrentMediaItems.addAll(buildInitialList(devices));
+            return;
+        }
+
+        mOldMediaItems.clear();
+        mOldMediaItems.addAll(mCurrentMediaItems);
+        mCurrentMediaItems.clear();
+        mCurrentMediaItems.addAll(buildBetterSubsequentList(mOldMediaItems, devices));
+    }
+
+    private List<TvMediaItem> buildInitialList(List<MediaDevice> devices) {
+        sortMediaDevices(devices);
+
+        List<TvMediaItem> finalMediaItems = new ArrayList<>();
+        boolean disconnectedDevicesAdded = false;
+        for (MediaDevice device : devices) {
+            // Add divider before first disconnected device
+            if (!device.isConnected() && !disconnectedDevicesAdded) {
+                addOtherDevicesDivider(finalMediaItems);
+                disconnectedDevicesAdded = true;
+            }
+            finalMediaItems.add(TvMediaItem.createDeviceMediaItem(device));
+        }
+        addConnectAnotherDeviceItem(finalMediaItems);
+        return finalMediaItems;
+    }
+
+    /**
+     * Keep devices that have not changed their connection state in the same order. If there is a
+     * new connected device, put it at the bottom of the connected devices list and if there is a
+     * newly disconnected device, add it at the top of the disconnected devices.
+     */
+    private List<TvMediaItem> buildBetterSubsequentList(
+            List<TvMediaItem> previousMediaItems, List<MediaDevice> devices) {
+
+        final List<TvMediaItem> targetMediaItems = new ArrayList<>();
+        // Only use the actual devices, not the dividers etc.
+        List<TvMediaItem> oldMediaItems =
+                previousMediaItems.stream()
+                        .filter(mediaItem -> mediaItem.getMediaDevice().isPresent())
+                        .toList();
+        addItemsBasedOnConnection(
+                targetMediaItems, oldMediaItems, devices, /* isConnected= */ true);
+        addItemsBasedOnConnection(
+                targetMediaItems, oldMediaItems, devices, /* isConnected= */ false);
+
+        addConnectAnotherDeviceItem(targetMediaItems);
+        return targetMediaItems;
+    }
+
+    private void addItemsBasedOnConnection(
+            List<TvMediaItem> targetMediaItems,
+            List<TvMediaItem> oldMediaItems,
+            List<MediaDevice> devices,
+            boolean isConnected) {
+
+        List<MediaDevice> matchingMediaDevices = new ArrayList<>();
+        for (TvMediaItem originalMediaItem : oldMediaItems) {
+            // Only go through the device items
+            MediaDevice oldDevice = originalMediaItem.getMediaDevice().get();
+
+            for (MediaDevice newDevice : devices) {
+                if (TextUtils.equals(oldDevice.getId(), newDevice.getId())
+                        && oldDevice.isConnected() == isConnected
+                        && newDevice.isConnected() == isConnected) {
+                    matchingMediaDevices.add(newDevice);
+                    break;
+                }
+            }
+        }
+        devices.removeAll(matchingMediaDevices);
+
+        List<MediaDevice> newMediaDevices = new ArrayList<>();
+        for (MediaDevice remainingDevice : devices) {
+            if (remainingDevice.isConnected() == isConnected) {
+                newMediaDevices.add(remainingDevice);
+            }
+        }
+        devices.removeAll(newMediaDevices);
+
+        // Add new connected devices at the end, add new disconnected devices at the start
+        if (isConnected) {
+            targetMediaItems.addAll(
+                    matchingMediaDevices.stream().map(TvMediaItem::createDeviceMediaItem).toList());
+            targetMediaItems.addAll(
+                    newMediaDevices.stream().map(TvMediaItem::createDeviceMediaItem).toList());
+        } else {
+            if (!matchingMediaDevices.isEmpty() || !newMediaDevices.isEmpty()) {
+                addOtherDevicesDivider(targetMediaItems);
+            }
+            targetMediaItems.addAll(
+                    newMediaDevices.stream().map(TvMediaItem::createDeviceMediaItem).toList());
+            targetMediaItems.addAll(
+                    matchingMediaDevices.stream().map(TvMediaItem::createDeviceMediaItem).toList());
+        }
+    }
+
+    private void addOtherDevicesDivider(List<TvMediaItem> mediaItems) {
+        mediaItems.add(
+                TvMediaItem.createGroupDividerMediaItem(
+                        mContext.getString(R.string.media_output_dialog_other_devices)));
+    }
+
+    private void addConnectAnotherDeviceItem(List<TvMediaItem> mediaItems) {
+        if (TvMediaOutputController.getBluetoothSettingsSliceUri(mContext) == null) {
+            Log.d(TAG, "No bluetooth slice set.");
+            return;
+        }
+        mediaItems.add(TvMediaItem.createGroupDividerMediaItem(/* title */ null));
+        mediaItems.add(TvMediaItem.createPairNewDeviceMediaItem());
+    }
+
+    private void sortMediaDevices(List<MediaDevice> mediaDevices) {
+        mediaDevices.sort((device1, device2) -> {
+            int priority1 = getDevicePriorityGroup(device1);
+            int priority2 = getDevicePriorityGroup(device2);
+
+            if (priority1 != priority2) {
+                return (priority1 < priority2) ? -1 : 1;
+            }
+            // Show connected before disconnected devices
+            if (device1.isConnected() != device2.isConnected()) {
+                return device1.isConnected() ? -1 : 1;
+            }
+            return device1.getName().compareToIgnoreCase(device2.getName());
+        });
+    }
+
+    public void clear() {
+        mCurrentMediaItems.clear();
+    }
+
+    public boolean isEmpty() {
+        return mCurrentMediaItems.isEmpty();
+    }
+}
diff --git a/tests/screenshot/Android.bp b/tests/screenshot/Android.bp
new file mode 100644
index 0000000..b18c01b
--- /dev/null
+++ b/tests/screenshot/Android.bp
@@ -0,0 +1,75 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+android_app {
+    name: "TvSystemUIRobo",
+    //overrides: ["TvSystemUI"],
+    srcs: [],
+    defaults: [
+        "platform_app_defaults",
+        "SystemUI_optimized_defaults",
+    ],
+    static_libs: [
+        "androidx.test.espresso.core",
+        "androidx.appcompat_appcompat",
+        "flag-junit",
+        "mockito-kotlin-nodeps",
+        "SystemUI-tests-base",
+        "TvSystemUI-core",
+    ],
+    manifest: "AndroidManifest.xml",
+    javacflags: [
+        "-Adagger.useBindingGraphFix=ENABLED",
+    ],
+    aaptflags: [
+        "--extra-packages",
+        "com.android.systemui",
+    ],
+    dont_merge_manifests: true,
+    platform_apis: true,
+    system_ext_specific: true,
+    certificate: "platform",
+    privileged: true,
+    kotlincflags: ["-Xjvm-default=all"],
+    plugins: ["dagger2-compiler"],
+    use_resource_processor: true,
+}
+
+android_robolectric_test {
+    name: "TvSystemUIRoboRNGTests",
+    srcs: [
+        "src/**/*.kt",
+        ":platform-test-screenshot-rules",
+        ":SystemUI-tests-utils",
+    ],
+    // Do not add any new libraries here, they should be added to TvSystemUIRobo above.
+    static_libs: [
+        "androidx.compose.runtime_runtime",
+        "androidx.test.uiautomator_uiautomator",
+        "androidx.test.ext.junit",
+        "inline-mockito-robolectric-prebuilt",
+        "uiautomator-helpers",
+    ],
+    libs: [
+        "android.test.runner.impl",
+        "android.test.base.impl",
+        "android.test.mock.impl",
+        "truth",
+    ],
+    java_resource_dirs: ["config"],
+    instrumentation_for: "TvSystemUIRobo",
+    test_suites: ["general-tests"],
+
+    strict_mode: false,
+}
diff --git a/tests/screenshot/AndroidManifest.xml b/tests/screenshot/AndroidManifest.xml
new file mode 100644
index 0000000..7644e02
--- /dev/null
+++ b/tests/screenshot/AndroidManifest.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?><!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui"
+    android:sharedUserId="android.uid.system">
+
+    <application>
+        <!-- Disable providers from SystemUI. Those are also disabled in SystemUIGoogleTests. -->
+        <activity
+            android:name="platform.test.screenshot.ScreenshotActivity"
+            android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize"
+            android:exported="true"
+            android:theme="@style/Theme.PlatformUi.Screenshot"></activity>
+    </application>
+</manifest>
\ No newline at end of file
diff --git a/tests/screenshot/config/robolectric.properties b/tests/screenshot/config/robolectric.properties
new file mode 100644
index 0000000..c22040d
--- /dev/null
+++ b/tests/screenshot/config/robolectric.properties
@@ -0,0 +1,17 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+sdk=NEWEST_SDK
+graphicsMode=NATIVE
\ No newline at end of file
diff --git a/tests/screenshot/src/com/android/systemui/volume/dialog/footer/ui/viewbinder/TvVolumeDialogFooterViewBinderKosmos.kt b/tests/screenshot/src/com/android/systemui/volume/dialog/footer/ui/viewbinder/TvVolumeDialogFooterViewBinderKosmos.kt
new file mode 100644
index 0000000..04d1107
--- /dev/null
+++ b/tests/screenshot/src/com/android/systemui/volume/dialog/footer/ui/viewbinder/TvVolumeDialogFooterViewBinderKosmos.kt
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.volume.dialog.footer.ui.viewbinder
+
+import com.android.systemui.kosmos.Kosmos
+import com.android.systemui.tv.volume.dialog.footer.ui.binder.TvVolumeDialogFooterViewBinder
+import com.android.systemui.volume.dialog.footer.ui.viewmodel.tvVolumeDialogFooterViewModel
+
+val Kosmos.tvVolumeDialogFooterViewBinder by
+    Kosmos.Fixture { TvVolumeDialogFooterViewBinder(tvVolumeDialogFooterViewModel) }
diff --git a/tests/screenshot/src/com/android/systemui/volume/dialog/footer/ui/viewmodel/TvVolumeDialogFooterViewModelKosmos.kt b/tests/screenshot/src/com/android/systemui/volume/dialog/footer/ui/viewmodel/TvVolumeDialogFooterViewModelKosmos.kt
new file mode 100644
index 0000000..1904de9
--- /dev/null
+++ b/tests/screenshot/src/com/android/systemui/volume/dialog/footer/ui/viewmodel/TvVolumeDialogFooterViewModelKosmos.kt
@@ -0,0 +1,25 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.volume.dialog.footer.ui.viewmodel
+
+import com.android.systemui.kosmos.Kosmos
+import com.android.systemui.kosmos.backgroundScope
+import com.android.systemui.tv.volume.dialog.footer.ui.viewmodel.TvVolumeDialogFooterViewModel
+import com.android.systemui.volume.dialog.sliders.ui.viewmodel.volumeDialogSlidersViewModel
+
+val Kosmos.tvVolumeDialogFooterViewModel by
+    Kosmos.Fixture { TvVolumeDialogFooterViewModel(volumeDialogSlidersViewModel, backgroundScope) }
diff --git a/tests/screenshot/src/com/android/systemui/volume/dialog/header/ui/binder/TvVolumeDialogHeaderViewBinderKosmos.kt b/tests/screenshot/src/com/android/systemui/volume/dialog/header/ui/binder/TvVolumeDialogHeaderViewBinderKosmos.kt
new file mode 100644
index 0000000..9ce58ca
--- /dev/null
+++ b/tests/screenshot/src/com/android/systemui/volume/dialog/header/ui/binder/TvVolumeDialogHeaderViewBinderKosmos.kt
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.volume.dialog.header.ui.binder
+
+import com.android.systemui.kosmos.Kosmos
+import com.android.systemui.tv.volume.dialog.header.ui.binder.TvVolumeDialogHeaderViewBinder
+import com.android.systemui.volume.dialog.header.ui.viewmodel.tvVolumeDialogHeaderViewModel
+
+val Kosmos.tvVolumeDialogHeaderViewBinder by
+    Kosmos.Fixture { TvVolumeDialogHeaderViewBinder(tvVolumeDialogHeaderViewModel) }
diff --git a/tests/screenshot/src/com/android/systemui/volume/dialog/header/ui/viewmodel/TvVolumeDialogHeaderViewModelKosmos.kt b/tests/screenshot/src/com/android/systemui/volume/dialog/header/ui/viewmodel/TvVolumeDialogHeaderViewModelKosmos.kt
new file mode 100644
index 0000000..acfea0f
--- /dev/null
+++ b/tests/screenshot/src/com/android/systemui/volume/dialog/header/ui/viewmodel/TvVolumeDialogHeaderViewModelKosmos.kt
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.volume.dialog.header.ui.viewmodel
+
+import com.android.systemui.kosmos.Kosmos
+import com.android.systemui.tv.volume.dialog.header.ui.viewmodel.TvVolumeDialogHeaderViewModel
+import com.android.systemui.volume.dialog.sliders.dagger.volumeDialogSliderComponentFactory
+import com.android.systemui.volume.dialog.sliders.domain.interactor.volumeDialogSlidersInteractor
+
+val Kosmos.tvVolumeDialogHeaderViewModel by
+    Kosmos.Fixture {
+        TvVolumeDialogHeaderViewModel(
+            volumeDialogSlidersInteractor,
+            volumeDialogSliderComponentFactory,
+        )
+    }
diff --git a/tests/screenshot/src/com/android/systemui/volume/dialog/slider/ui/binder/TvVolumeDialogSliderViewBinderKosmos.kt b/tests/screenshot/src/com/android/systemui/volume/dialog/slider/ui/binder/TvVolumeDialogSliderViewBinderKosmos.kt
new file mode 100644
index 0000000..4acf26d
--- /dev/null
+++ b/tests/screenshot/src/com/android/systemui/volume/dialog/slider/ui/binder/TvVolumeDialogSliderViewBinderKosmos.kt
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.volume.dialog.slider.ui.binder
+
+import com.android.systemui.kosmos.Kosmos
+import com.android.systemui.tv.volume.dialog.slider.ui.binder.TvVolumeDialogSliderViewBinder
+import com.android.systemui.volume.dialog.sliders.ui.viewmodel.volumeDialogSlidersViewModel
+
+val Kosmos.tvVolumeDialogSliderViewBinder by
+    Kosmos.Fixture { TvVolumeDialogSliderViewBinder(volumeDialogSlidersViewModel) }
diff --git a/tests/screenshot/src/com/android/systemui/volume/dialog/ui/binder/TvVolumeDialogViewBinderKosmos.kt b/tests/screenshot/src/com/android/systemui/volume/dialog/ui/binder/TvVolumeDialogViewBinderKosmos.kt
new file mode 100644
index 0000000..6c5c747
--- /dev/null
+++ b/tests/screenshot/src/com/android/systemui/volume/dialog/ui/binder/TvVolumeDialogViewBinderKosmos.kt
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.systemui.volume.dialog.ui.binder
+
+import com.android.systemui.kosmos.Kosmos
+import com.android.systemui.volume.dialog.footer.ui.viewbinder.tvVolumeDialogFooterViewBinder
+import com.android.systemui.volume.dialog.header.ui.binder.tvVolumeDialogHeaderViewBinder
+import com.android.systemui.volume.dialog.slider.ui.binder.tvVolumeDialogSliderViewBinder
+
+val Kosmos.tvSystemUiVolumeDialogViewBinders: List<ViewBinder> by
+    Kosmos.Fixture {
+        listOf(
+            tvVolumeDialogSliderViewBinder,
+            tvVolumeDialogFooterViewBinder,
+            tvVolumeDialogHeaderViewBinder,
+        )
+    }
```

