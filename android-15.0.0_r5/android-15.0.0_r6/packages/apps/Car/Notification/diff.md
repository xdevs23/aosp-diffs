```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 950bdb5d..b5034216 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -25,7 +25,7 @@
     <!-- Permission to get the current user id to cancel all notifications -->
     <uses-permission android:name="android.permission.MANAGE_USERS"/>
     <!-- Permission to get status if a user in on call -->
-    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
+    <uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
     <uses-permission android:name="android.permission.MODIFY_PHONE_STATE"/>
 
     <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 2c068422..a9848568 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -26,7 +26,7 @@
     <string name="action_unmute_long" msgid="22482625837159466">"વાતચીત અનમ્યૂટ કરો"</string>
     <string name="action_canned_reply" msgid="4045960823021872834">"\"હાલમાં ડ્રાઇવ કરું છું.\""</string>
     <string name="canned_reply_message" msgid="7959257272917598063">"હાલમાં ડ્રાઇવ કરું છું."</string>
-    <string name="toast_message_sent_success" msgid="1159956191974273064">"સંદેશ સફળતાપૂર્વક મોકલ્યો."</string>
+    <string name="toast_message_sent_success" msgid="1159956191974273064">"મેસેજ સફળતાપૂર્વક મોકલ્યો."</string>
     <string name="notification_service_label" msgid="7512186049723777468">"કાર નોટિફિકેશન સાંભળનાર સેવા"</string>
     <string name="notifications" msgid="2865534625906329283">"નોટિફિકેશન કેન્દ્ર"</string>
     <string name="clear_all" msgid="1845314281571237722">"બધું સાફ કરો"</string>
@@ -48,7 +48,7 @@
       <item quantity="other"><xliff:g id="COUNT_1">%d</xliff:g> નવા મેસેજ</item>
     </plurals>
     <string name="see_more_message" msgid="6343183827924395955">"વધુ જુઓ"</string>
-    <string name="restricted_hun_message_content" msgid="631111937988857716">"નવો સંદેશ"</string>
+    <string name="restricted_hun_message_content" msgid="631111937988857716">"નવો મેસેજ"</string>
     <string name="manage_text" msgid="4225197445283791757">"મેનેજ કરો"</string>
     <string name="category_navigation" msgid="4406139232918521087">"નૅવિગેશન"</string>
     <string name="category_call" msgid="2249490790700877973">"કૉલ"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index df8037bc..e2853a67 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -56,5 +56,5 @@
     <string name="hun_suppression_channel_name" msgid="8298850157350352525">"Notifiche di avviso disattivate"</string>
     <string name="hun_suppression_notification_title_park" msgid="2790860076784227523">"Non perderti le ultime novità"</string>
     <string name="hun_suppression_notification_title_drive" msgid="4403363470548899844">"Concentrati sulla guida"</string>
-    <string name="hun_suppression_notification_description" msgid="5269238832987802104">"Alcune nuove notifiche vengono salvate nel centro notifiche"</string>
+    <string name="hun_suppression_notification_description" msgid="5269238832987802104">"Alcune nuove notifiche vengono salvate nel Centro notifiche"</string>
 </resources>
diff --git a/src/com/android/car/notification/CarHeadsUpNotificationManager.java b/src/com/android/car/notification/CarHeadsUpNotificationManager.java
index 1a285b34..2d645bae 100644
--- a/src/com/android/car/notification/CarHeadsUpNotificationManager.java
+++ b/src/com/android/car/notification/CarHeadsUpNotificationManager.java
@@ -388,7 +388,7 @@ public class CarHeadsUpNotificationManager
      * Returns the active headsUpEntry or creates a new one while adding it to the list of
      * mActiveHeadsUpNotifications.
      */
-    private HeadsUpEntry addNewHeadsUpEntry(AlertEntry alertEntry) {
+    private HeadsUpEntry getOrCreateHeadsUpEntry(AlertEntry alertEntry) {
         if (!isActiveHun(alertEntry)) {
             HeadsUpEntry newActiveHeadsUpNotification = new HeadsUpEntry(
                     alertEntry.getStatusBarNotification());
@@ -432,7 +432,7 @@ public class CarHeadsUpNotificationManager
         // needs to be done here because after this the new notification will be added to the map
         // holding ongoing notifications.
         boolean shouldShowAnimation = !isUpdate(alertEntry);
-        HeadsUpEntry currentNotification = addNewHeadsUpEntry(alertEntry);
+        HeadsUpEntry currentNotification = getOrCreateHeadsUpEntry(alertEntry);
         if (currentNotification.mIsNewHeadsUp) {
             playSound(alertEntry, rankingMap);
             setAutoDismissViews(currentNotification, alertEntry);
@@ -643,7 +643,6 @@ public class CarHeadsUpNotificationManager
             }
         });
         animatorSet.start();
-
     }
 
     /**
diff --git a/src/com/android/car/notification/CarNotificationCenterActivity.java b/src/com/android/car/notification/CarNotificationCenterActivity.java
index 8918918a..d5a5dd8e 100644
--- a/src/com/android/car/notification/CarNotificationCenterActivity.java
+++ b/src/com/android/car/notification/CarNotificationCenterActivity.java
@@ -124,6 +124,11 @@ public class CarNotificationCenterActivity extends Activity {
         if (mNotificationViewController != null) {
             mNotificationViewController.onVisibilityChanged(isVisible);
         }
+        if (NotificationUtils.isVisibleBackgroundUser(this)) {
+            // TODO: b/341604160 - Supports visible background users properly.
+            Log.d(TAG, "IStatusBarService is unavailable for visible background users");
+            return;
+        }
         try {
             if (isVisible) {
                 mStatusBarService.onPanelRevealed(/* clearNotificationEffects= */ true,
diff --git a/src/com/android/car/notification/CarNotificationView.java b/src/com/android/car/notification/CarNotificationView.java
index 5dd43f83..dcdbf464 100644
--- a/src/com/android/car/notification/CarNotificationView.java
+++ b/src/com/android/car/notification/CarNotificationView.java
@@ -419,7 +419,7 @@ public class CarNotificationView extends ConstraintLayout
             Handler handler = getHandler();
             if (handler != null) {
                 handler.postDelayed(() -> {
-                    mClickHandlerFactory.collapsePanel();
+                    mClickHandlerFactory.collapsePanel(getContext());
                 }, collapsePanelDelay);
             }
         }
@@ -475,7 +475,7 @@ public class CarNotificationView extends ConstraintLayout
                 UserHandle.of(NotificationUtils.getCurrentUser(getContext())));
 
         if (mClickHandlerFactory != null && mCollapsePanelAfterManageButton) {
-            mClickHandlerFactory.collapsePanel();
+            mClickHandlerFactory.collapsePanel(getContext());
         }
     }
 
diff --git a/src/com/android/car/notification/NotificationClickHandlerFactory.java b/src/com/android/car/notification/NotificationClickHandlerFactory.java
index 73e187b9..4d52ac30 100644
--- a/src/com/android/car/notification/NotificationClickHandlerFactory.java
+++ b/src/com/android/car/notification/NotificationClickHandlerFactory.java
@@ -30,6 +30,7 @@ import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.service.notification.NotificationStats;
 import android.util.Log;
 import android.view.View;
@@ -355,7 +356,17 @@ public class NotificationClickHandlerFactory {
     /**
      * Collapses the notification shade panel.
      */
-    public void collapsePanel() {
+    public void collapsePanel(Context context) {
+        if (NotificationUtils.isVisibleBackgroundUser(context)) {
+            // TODO: b/341604160 - Support visible background users properly.
+            Log.d(TAG, "IStatusBarService is unavailable for visible background users");
+            // Use backup method of closing panel by sending intent to close system dialogs -
+            // this should only be used if the bar service is not available for a user
+            Intent intent = new Intent(Intent.ACTION_CLOSE_SYSTEM_DIALOGS);
+            context.sendBroadcastAsUser(intent,
+                    UserHandle.of(NotificationUtils.getCurrentUser(context)));
+            return;
+        }
         try {
             mBarService.collapsePanels();
         } catch (RemoteException e) {
diff --git a/src/com/android/car/notification/NotificationUtils.java b/src/com/android/car/notification/NotificationUtils.java
index ec338235..8b6dc953 100644
--- a/src/com/android/car/notification/NotificationUtils.java
+++ b/src/com/android/car/notification/NotificationUtils.java
@@ -159,17 +159,23 @@ public class NotificationUtils {
         return Color.luminance(backgroundColor) > LIGHT_COLOR_LUMINANCE_THRESHOLD;
     }
 
+    /**
+     * Returns true if the current notification process is running for a visible background user.
+     */
+    public static boolean isVisibleBackgroundUser(Context context) {
+        UserManager userManager = context.getSystemService(UserManager.class);
+        UserHandle processUser = Process.myUserHandle();
+        return userManager.isVisibleBackgroundUsersSupported()
+                && !processUser.isSystem()
+                && processUser.getIdentifier() != ActivityManager.getCurrentUser();
+    }
+
     /**
      * Returns the current user id for this instance of the notification app/library.
      */
     public static int getCurrentUser(Context context) {
-        UserManager userManager = context.getSystemService(UserManager.class);
         UserHandle processUser = Process.myUserHandle();
-        boolean isSecondaryUserNotifications =
-                userManager.isVisibleBackgroundUsersSupported()
-                        && !processUser.isSystem()
-                        && processUser.getIdentifier() != ActivityManager.getCurrentUser();
-        return isSecondaryUserNotifications ? processUser.getIdentifier()
+        return isVisibleBackgroundUser(context) ? processUser.getIdentifier()
                 : ActivityManager.getCurrentUser();
     }
 
diff --git a/src/com/android/car/notification/PreprocessingManager.java b/src/com/android/car/notification/PreprocessingManager.java
index 7d3c0260..9ce89de3 100644
--- a/src/com/android/car/notification/PreprocessingManager.java
+++ b/src/com/android/car/notification/PreprocessingManager.java
@@ -15,6 +15,8 @@
  */
 package com.android.car.notification;
 
+import static android.app.Notification.FLAG_AUTOGROUP_SUMMARY;
+
 import android.annotation.Nullable;
 import android.app.Notification;
 import android.app.NotificationManager;
@@ -587,9 +589,13 @@ public class PreprocessingManager {
                     return mOldProcessedNotifications;
                 }
             }
-            // If child notifications do not exist, insert the summary as a new notification
             newGroup.setGroupSummaryNotification(newNotification);
-            insertRankedNotification(newGroup, newRankingMap);
+            if ((notification.flags & FLAG_AUTOGROUP_SUMMARY) == 0) {
+                // If child notifications do not exist
+                // and isn't an autogenerated group summary
+                // insert the summary as a new notification
+                insertRankedNotification(newGroup, newRankingMap);
+            }
             return mOldProcessedNotifications;
         }
 
diff --git a/src/com/android/car/notification/template/CarNotificationActionsView.java b/src/com/android/car/notification/template/CarNotificationActionsView.java
index 22a436cd..d4508aff 100644
--- a/src/com/android/car/notification/template/CarNotificationActionsView.java
+++ b/src/com/android/car/notification/template/CarNotificationActionsView.java
@@ -80,6 +80,8 @@ public class CarNotificationActionsView extends LinearLayout implements
     private final String mMuteText;
     private final String mUnmuteText;
     @ColorInt
+    private final int mMuteTextColor;
+    @ColorInt
     private final int mUnmuteTextColor;
     private final boolean mEnableDirectReply;
     private final boolean mEnablePlay;
@@ -152,6 +154,7 @@ public class CarNotificationActionsView extends LinearLayout implements
                 mContext.getResources().getBoolean(R.bool.config_enableMessageNotificationPlay);
         mEnableDirectReply = mContext.getResources()
                 .getBoolean(R.bool.config_enableMessageNotificationDirectReply);
+        mMuteTextColor = mContext.getColor(R.color.icon_tint);
         mUnmuteTextColor = mContext.getColor(R.color.dark_icon_tint);
         init(attrs);
     }
@@ -227,6 +230,8 @@ public class CarNotificationActionsView extends LinearLayout implements
             Icon icon = action.getIcon();
             if (icon != null) {
                 icon.loadDrawableAsync(packageContext, button::setImageDrawable, getAsyncHandler());
+            } else {
+                button.setImageDrawable(null);
             }
         }
 
@@ -252,7 +257,6 @@ public class CarNotificationActionsView extends LinearLayout implements
         for (CarNotificationActionButton button : mActionButtons) {
             button.setVisibility(View.GONE);
             button.setText(null);
-            button.setImageDrawable(null);
             button.setOnClickListener(null);
         }
     }
@@ -327,7 +331,7 @@ public class CarNotificationActionsView extends LinearLayout implements
 
     private void setMuteStatus(CarNotificationActionButton button, boolean isMuted) {
         button.setText(isMuted ? mUnmuteText : mMuteText);
-        button.setTextColor(isMuted ? mUnmuteTextColor : button.getDefaultTextColor());
+        button.setTextColor(isMuted ? mUnmuteTextColor : mMuteTextColor);
         button.setImageDrawable(isMuted ? mUnmuteButtonDrawable : mMuteButtonDrawable);
         button.setBackground(isMuted ? mUnmuteButtonBackground : mActionButtonBackground);
     }
diff --git a/src/com/android/car/notification/template/CarNotificationBodyView.java b/src/com/android/car/notification/template/CarNotificationBodyView.java
index cceb3aa9..d8d1e26b 100644
--- a/src/com/android/car/notification/template/CarNotificationBodyView.java
+++ b/src/com/android/car/notification/template/CarNotificationBodyView.java
@@ -174,9 +174,12 @@ public class CarNotificationBodyView extends RelativeLayout {
                 } else {
                     Log.w(TAG, "Notification with title=" + title
                             + " did not specify a large icon");
+                    mLargeIconView.setVisibility(View.GONE);
+                    mLargeIconView.setImageDrawable(null);
                 }
             } else {
                 mLargeIconView.setVisibility(View.GONE);
+                mLargeIconView.setImageDrawable(null);
             }
         }
 
@@ -298,9 +301,6 @@ public class CarNotificationBodyView extends RelativeLayout {
             setContentMaxLines(mMaxLines);
             mContentView.setVisibility(View.GONE);
         }
-        if (mLargeIconView != null) {
-            mLargeIconView.setVisibility(View.GONE);
-        }
         setPrimaryTextColor(mDefaultPrimaryTextColor);
         setSecondaryTextColor(mDefaultSecondaryTextColor);
         if (mTimeView != null) {
diff --git a/src/com/android/car/notification/template/CarNotificationFooterViewHolder.java b/src/com/android/car/notification/template/CarNotificationFooterViewHolder.java
index 16623b03..1b1a47d6 100644
--- a/src/com/android/car/notification/template/CarNotificationFooterViewHolder.java
+++ b/src/com/android/car/notification/template/CarNotificationFooterViewHolder.java
@@ -97,7 +97,7 @@ public class CarNotificationFooterViewHolder extends RecyclerView.ViewHolder {
                 UserHandle.of(NotificationUtils.getCurrentUser(mContext)));
 
         if (mClickHandlerFactory != null && mCollapsePanelAfterManageButton) {
-            mClickHandlerFactory.collapsePanel();
+            mClickHandlerFactory.collapsePanel(mContext);
         }
     }
 }
diff --git a/src/com/android/car/notification/template/CarNotificationHeaderView.java b/src/com/android/car/notification/template/CarNotificationHeaderView.java
index 224f2cef..6b7b36ee 100644
--- a/src/com/android/car/notification/template/CarNotificationHeaderView.java
+++ b/src/com/android/car/notification/template/CarNotificationHeaderView.java
@@ -23,8 +23,10 @@ import android.app.Notification;
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.content.res.TypedArray;
-import android.graphics.drawable.Drawable;
+import android.graphics.drawable.Icon;
 import android.os.Bundle;
+import android.os.Handler;
+import android.os.Looper;
 import android.service.notification.StatusBarNotification;
 import android.text.BidiFormatter;
 import android.text.TextDirectionHeuristics;
@@ -129,13 +131,22 @@ public class CarNotificationHeaderView extends LinearLayout {
         Notification notification = alertEntry.getNotification();
         StatusBarNotification sbn = alertEntry.getStatusBarNotification();
 
-        Context packageContext = sbn.getPackageContext(getContext());
 
         // App icon
         if (mIconView != null) {
-            mIconView.setVisibility(View.VISIBLE);
-            Drawable drawable = notification.getSmallIcon().loadDrawable(packageContext);
-            mIconView.setImageDrawable(drawable);
+            if (notification.getSmallIcon() != null) {
+                Context packageContext = sbn.getPackageContext(getContext());
+                Icon.OnDrawableLoadedListener loadedListener = drawable -> {
+                    mIconView.setVisibility(View.VISIBLE);
+                    mIconView.setImageDrawable(drawable);
+                };
+                Handler handler = Handler.createAsync(Looper.myLooper());
+                notification.getSmallIcon().loadDrawableAsync(packageContext, loadedListener,
+                        handler);
+            } else {
+                mIconView.setVisibility(View.GONE);
+                mIconView.setImageDrawable(null);
+            }
         }
 
         StringBuilder stringBuilder = new StringBuilder();
@@ -216,8 +227,6 @@ public class CarNotificationHeaderView extends LinearLayout {
      */
     public void reset() {
         if (mIconView != null) {
-            mIconView.setVisibility(View.GONE);
-            mIconView.setImageDrawable(null);
             setSmallIconColor(mDefaultTextColor);
         }
 
diff --git a/src/com/android/car/notification/template/CarNotificationHeaderViewHolder.java b/src/com/android/car/notification/template/CarNotificationHeaderViewHolder.java
index beaaffc4..4b5ae5cc 100644
--- a/src/com/android/car/notification/template/CarNotificationHeaderViewHolder.java
+++ b/src/com/android/car/notification/template/CarNotificationHeaderViewHolder.java
@@ -110,7 +110,7 @@ public class CarNotificationHeaderViewHolder extends RecyclerView.ViewHolder {
                 UserHandle.of(NotificationUtils.getCurrentUser(mContext)));
 
         if (mClickHandlerFactory != null && mCollapsePanelAfterManageButton) {
-            mClickHandlerFactory.collapsePanel();
+            mClickHandlerFactory.collapsePanel(mContext);
         }
     }
 }
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index cc28a22d..161f6eee 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -27,9 +27,9 @@ android_test {
     srcs: ["src/**/*.java"],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     static_libs: [
diff --git a/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java b/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
index 869858a7..671044d5 100644
--- a/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
+++ b/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
@@ -255,6 +255,40 @@ public class NotificationUtilsTest {
                 CarNotificationTypeItem.BASIC);
     }
 
+    @Test
+    public void isVisibleBackgroundUser_whenVisibleBackgroundUsersNotSupported_returnsFalse() {
+        UserHandle myUserHandle = UserHandle.of(1000);
+        when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(false);
+        when(Process.myUserHandle()).thenReturn(myUserHandle);
+
+        assertThat(NotificationUtils.isVisibleBackgroundUser(mContext)).isEqualTo(false);
+    }
+
+    @Test
+    public void isVisibleBackgroundUser_whenSystemUser_returnsFalse() {
+        when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(true);
+        when(Process.myUserHandle()).thenReturn(UserHandle.SYSTEM);
+
+        assertThat(NotificationUtils.isVisibleBackgroundUser(mContext)).isEqualTo(false);
+    }
+
+    @Test
+    public void isVisibleBackgroundUser_whenPrimaryUser_returnsFalse() {
+        when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(true);
+        when(Process.myUserHandle()).thenReturn(UserHandle.of(ActivityManager.getCurrentUser()));
+
+        assertThat(NotificationUtils.isVisibleBackgroundUser(mContext)).isEqualTo(false);
+    }
+
+    @Test
+    public void isVisibleBackgroundUser_whenVisibleBackgroundUser_returnsTrue() {
+        UserHandle myUserHandle = UserHandle.of(1000);
+        when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(true);
+        when(Process.myUserHandle()).thenReturn(myUserHandle);
+
+        assertThat(NotificationUtils.isVisibleBackgroundUser(mContext)).isEqualTo(true);
+    }
+
     @Test
     public void getCurrentUser_visibleBackgroundUsersNotSupported_returnsPrimaryUser() {
         when(mUserManager.isVisibleBackgroundUsersSupported()).thenReturn(false);
diff --git a/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java b/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
index 296f6c9a..8b1e6d43 100644
--- a/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
+++ b/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
@@ -792,7 +792,7 @@ public class PreprocessingManagerTest {
     }
 
     @Test
-    public void onAdditionalGroupAndRank_isGroupSummary_prependsHighRankNotification() {
+    public void onAdditionalGroupAndRank_isGroupSummary_noChildren_prependsHighRankNotification() {
         // Seed the list
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
 
@@ -813,6 +813,19 @@ public class PreprocessingManagerTest {
         assertThat(result.get(0).getSingleNotification()).isEqualTo(newEntry);
     }
 
+    @Test
+    public void onAdditionalGroupAndRank_isAutoGroupSummary_noChildren_doNothing() {
+        // Seed the list
+        mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
+        List<NotificationGroup> expected = mPreprocessingManager.getOldProcessedNotifications();
+        AlertEntry newEntry = getEmptyAutoGeneratedGroupSummary();
+
+        List<NotificationGroup> actual = mPreprocessingManager.additionalGroupAndRank(newEntry,
+                generateRankingMap(mAlertEntries), /* isUpdate= */ false);
+
+        assertThat(actual).isEqualTo(expected);
+    }
+
     @Test
     public void onAdditionalGroupAndRank_notGroupSummary_isUpdate_notificationUpdated() {
         when(mNotificationDataManager.isNotificationSeen(mImportantForeground)).thenReturn(false);
```

