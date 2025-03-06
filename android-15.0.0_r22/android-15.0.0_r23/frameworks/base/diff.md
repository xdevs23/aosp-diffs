```diff
diff --git a/packages/SystemUI/shared/src/com/android/systemui/shared/recents/IOverviewProxy.aidl b/packages/SystemUI/shared/src/com/android/systemui/shared/recents/IOverviewProxy.aidl
index 83ca496dbef2..2b71c87bfa27 100644
--- a/packages/SystemUI/shared/src/com/android/systemui/shared/recents/IOverviewProxy.aidl
+++ b/packages/SystemUI/shared/src/com/android/systemui/shared/recents/IOverviewProxy.aidl
@@ -19,10 +19,11 @@ package com.android.systemui.shared.recents;
 import android.graphics.Rect;
 import android.graphics.Region;
 import android.os.Bundle;
+import android.os.IRemoteCallback;
 import android.view.MotionEvent;
 import com.android.systemui.shared.recents.ISystemUiProxy;
 
-// Next ID: 34
+// Next ID: 36
 oneway interface IOverviewProxy {
 
     void onActiveNavBarRegionChanges(in Region activeRegion) = 11;
@@ -137,4 +138,10 @@ oneway interface IOverviewProxy {
      * Sent when {@link TaskbarDelegate#appTransitionPending} is called.
      */
     void appTransitionPending(boolean pending) = 34;
+
+    /**
+     * Sent right after OverviewProxy calls unbindService() on the TouchInteractionService.
+     * TouchInteractionService is expected to send the reply once it has finished cleaning up.
+     */
+    void onUnbind(IRemoteCallback reply) = 35;
 }
diff --git a/packages/SystemUI/src/com/android/systemui/education/data/repository/UserContextualEducationRepository.kt b/packages/SystemUI/src/com/android/systemui/education/data/repository/UserContextualEducationRepository.kt
index 29785959de18..9596a540b63b 100644
--- a/packages/SystemUI/src/com/android/systemui/education/data/repository/UserContextualEducationRepository.kt
+++ b/packages/SystemUI/src/com/android/systemui/education/data/repository/UserContextualEducationRepository.kt
@@ -20,10 +20,12 @@ import android.content.Context
 import android.hardware.input.InputManager
 import android.hardware.input.KeyGestureEvent
 import androidx.datastore.core.DataStore
+import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
 import androidx.datastore.preferences.core.MutablePreferences
 import androidx.datastore.preferences.core.PreferenceDataStoreFactory
 import androidx.datastore.preferences.core.Preferences
 import androidx.datastore.preferences.core.edit
+import androidx.datastore.preferences.core.emptyPreferences
 import androidx.datastore.preferences.core.intPreferencesKey
 import androidx.datastore.preferences.core.longPreferencesKey
 import androidx.datastore.preferences.preferencesDataStoreFile
@@ -68,7 +70,7 @@ interface ContextualEducationRepository {
 
     suspend fun updateGestureEduModel(
         gestureType: GestureType,
-        transform: (GestureEduModel) -> GestureEduModel
+        transform: (GestureEduModel) -> GestureEduModel,
     )
 
     suspend fun updateEduDeviceConnectionTime(
@@ -149,6 +151,8 @@ constructor(
                         String.format(DATASTORE_DIR, userId)
                     )
                 },
+                corruptionHandler =
+                    ReplaceFileCorruptionHandler(produceNewData = { emptyPreferences() }),
                 scope = newDsScope,
             )
         dataStoreScope = newDsScope
@@ -159,7 +163,7 @@ constructor(
 
     private fun getGestureEduModel(
         gestureType: GestureType,
-        preferences: Preferences
+        preferences: Preferences,
     ): GestureEduModel {
         return GestureEduModel(
             signalCount = preferences[getSignalCountKey(gestureType)] ?: 0,
@@ -183,7 +187,7 @@ constructor(
 
     override suspend fun updateGestureEduModel(
         gestureType: GestureType,
-        transform: (GestureEduModel) -> GestureEduModel
+        transform: (GestureEduModel) -> GestureEduModel,
     ) {
         datastore.filterNotNull().first().edit { preferences ->
             val currentModel = getGestureEduModel(gestureType, preferences)
@@ -193,17 +197,17 @@ constructor(
             setInstant(
                 preferences,
                 updatedModel.lastShortcutTriggeredTime,
-                getLastShortcutTriggeredTimeKey(gestureType)
+                getLastShortcutTriggeredTimeKey(gestureType),
             )
             setInstant(
                 preferences,
                 updatedModel.usageSessionStartTime,
-                getUsageSessionStartTimeKey(gestureType)
+                getUsageSessionStartTimeKey(gestureType),
             )
             setInstant(
                 preferences,
                 updatedModel.lastEducationTime,
-                getLastEducationTimeKey(gestureType)
+                getLastEducationTimeKey(gestureType),
             )
         }
     }
@@ -220,12 +224,12 @@ constructor(
             setInstant(
                 preferences,
                 updatedModel.keyboardFirstConnectionTime,
-                getKeyboardFirstConnectionTimeKey()
+                getKeyboardFirstConnectionTimeKey(),
             )
             setInstant(
                 preferences,
                 updatedModel.touchpadFirstConnectionTime,
-                getTouchpadFirstConnectionTimeKey()
+                getTouchpadFirstConnectionTimeKey(),
             )
         }
     }
@@ -235,7 +239,7 @@ constructor(
             keyboardFirstConnectionTime =
                 preferences[getKeyboardFirstConnectionTimeKey()]?.let { Instant.ofEpochSecond(it) },
             touchpadFirstConnectionTime =
-                preferences[getTouchpadFirstConnectionTimeKey()]?.let { Instant.ofEpochSecond(it) }
+                preferences[getTouchpadFirstConnectionTimeKey()]?.let { Instant.ofEpochSecond(it) },
         )
     }
 
@@ -263,7 +267,7 @@ constructor(
     private fun setInstant(
         preferences: MutablePreferences,
         instant: Instant?,
-        key: Preferences.Key<Long>
+        key: Preferences.Key<Long>,
     ) {
         if (instant != null) {
             // Use epochSecond because an instant is defined as a signed long (64bit number) of
diff --git a/packages/SystemUI/src/com/android/systemui/inputdevice/tutorial/data/repository/TutorialSchedulerRepository.kt b/packages/SystemUI/src/com/android/systemui/inputdevice/tutorial/data/repository/TutorialSchedulerRepository.kt
index a89ec7076e93..315d3b1be9dc 100644
--- a/packages/SystemUI/src/com/android/systemui/inputdevice/tutorial/data/repository/TutorialSchedulerRepository.kt
+++ b/packages/SystemUI/src/com/android/systemui/inputdevice/tutorial/data/repository/TutorialSchedulerRepository.kt
@@ -18,8 +18,10 @@ package com.android.systemui.inputdevice.tutorial.data.repository
 
 import android.content.Context
 import androidx.datastore.core.DataStore
+import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
 import androidx.datastore.preferences.core.Preferences
 import androidx.datastore.preferences.core.edit
+import androidx.datastore.preferences.core.emptyPreferences
 import androidx.datastore.preferences.core.longPreferencesKey
 import androidx.datastore.preferences.preferencesDataStore
 import com.android.systemui.dagger.SysUISingleton
@@ -45,7 +47,12 @@ class TutorialSchedulerRepository(
     ) : this(applicationContext, backgroundScope, dataStoreName = DATASTORE_NAME)
 
     private val Context.dataStore: DataStore<Preferences> by
-        preferencesDataStore(name = dataStoreName, scope = backgroundScope)
+        preferencesDataStore(
+            name = dataStoreName,
+            corruptionHandler =
+                ReplaceFileCorruptionHandler(produceNewData = { emptyPreferences() }),
+            scope = backgroundScope,
+        )
 
     suspend fun isLaunched(deviceType: DeviceType): Boolean = loadData()[deviceType]!!.isLaunched
 
diff --git a/packages/SystemUI/src/com/android/systemui/recents/OverviewProxyService.java b/packages/SystemUI/src/com/android/systemui/recents/OverviewProxyService.java
index e3cf41191384..adf9eb44e162 100644
--- a/packages/SystemUI/src/com/android/systemui/recents/OverviewProxyService.java
+++ b/packages/SystemUI/src/com/android/systemui/recents/OverviewProxyService.java
@@ -58,6 +58,7 @@ import android.os.Binder;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.IBinder;
+import android.os.IRemoteCallback;
 import android.os.Looper;
 import android.os.PatternMatcher;
 import android.os.Process;
@@ -146,7 +147,6 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
     public static final String TAG_OPS = "OverviewProxyService";
     private static final long BACKOFF_MILLIS = 1000;
     private static final long DEFERRED_CALLBACK_MILLIS = 5000;
-
     // Max backoff caps at 5 mins
     private static final long MAX_BACKOFF_MILLIS = 10 * 60 * 1000;
 
@@ -183,6 +183,10 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
     private int mConnectionBackoffAttempts;
     private boolean mBound;
     private boolean mIsEnabled;
+    // This is set to false when the overview service is requested to be bound until it is notified
+    // that the previous service has been cleaned up in IOverviewProxy#onUnbind(). It is also set to
+    // true after a 1000ms timeout by mDeferredBindAfterTimedOutCleanup.
+    private boolean mIsPrevServiceCleanedUp = true;
 
     private boolean mIsSystemOrVisibleBgUser;
     private int mCurrentBoundedUserId = -1;
@@ -489,6 +493,12 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
         retryConnectionWithBackoff();
     };
 
+    private final Runnable mDeferredBindAfterTimedOutCleanup = () -> {
+        Log.w(TAG_OPS, "Timed out waiting for previous service to clean up, binding to new one");
+        mIsPrevServiceCleanedUp = true;
+        maybeBindService();
+    };
+
     private final BroadcastReceiver mUserEventReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
@@ -859,6 +869,7 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
                 mShadeViewControllerLazy.get().cancelInputFocusTransfer();
             });
         }
+        mIsPrevServiceCleanedUp = true;
         startConnectionToCurrentUser();
     }
 
@@ -889,6 +900,19 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
         }
         mHandler.removeCallbacks(mConnectionRunnable);
 
+        maybeBindService();
+    }
+
+    private void maybeBindService() {
+        if (!mIsPrevServiceCleanedUp) {
+            Log.w(TAG_OPS, "Skipping connection to TouchInteractionService until previous"
+                    + " instance is cleaned up.");
+            if (!mHandler.hasCallbacks(mDeferredConnectionCallback)) {
+                mHandler.postDelayed(mDeferredBindAfterTimedOutCleanup, BACKOFF_MILLIS);
+            }
+            return;
+        }
+
         // Avoid creating TouchInteractionService because the System user in HSUM mode does not
         // interact with UI elements
         UserHandle currentUser = UserHandle.of(mUserTracker.getUserId());
@@ -907,6 +931,7 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
             Log.e(TAG_OPS, "Unable to bind because of security error", e);
         }
         if (mBound) {
+            mIsPrevServiceCleanedUp = false;
             // Ensure that connection has been established even if it thinks it is bound
             mHandler.postDelayed(mDeferredConnectionCallback, DEFERRED_CALLBACK_MILLIS);
         } else {
@@ -960,6 +985,24 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
             // Always unbind the service (ie. if called through onNullBinding or onBindingDied)
             mContext.unbindService(mOverviewServiceConnection);
             mBound = false;
+            if (mOverviewProxy != null) {
+                try {
+                    mOverviewProxy.onUnbind(new IRemoteCallback.Stub() {
+                        @Override
+                        public void sendResult(Bundle data) throws RemoteException {
+                            // Received Launcher reply, try to bind anew.
+                            mIsPrevServiceCleanedUp = true;
+                            if (mHandler.hasCallbacks(mDeferredBindAfterTimedOutCleanup)) {
+                                mHandler.removeCallbacks(mDeferredBindAfterTimedOutCleanup);
+                                maybeBindService();
+                            }
+                        }
+                    });
+                } catch (RemoteException e) {
+                    Log.w(TAG_OPS, "disconnectFromLauncherService failed to notify Launcher");
+                    mIsPrevServiceCleanedUp = true;
+                }
+            }
         }
 
         if (mOverviewProxy != null) {
@@ -1189,6 +1232,7 @@ public class OverviewProxyService implements CallbackController<OverviewProxyLis
         pw.print("  mInputFocusTransferStartMillis="); pw.println(mInputFocusTransferStartMillis);
         pw.print("  mActiveNavBarRegion="); pw.println(mActiveNavBarRegion);
         pw.print("  mNavBarMode="); pw.println(mNavBarMode);
+        pw.print("  mIsPrevServiceCleanedUp="); pw.println(mIsPrevServiceCleanedUp);
         mSysUiState.dump(pw, args);
     }
 
```

