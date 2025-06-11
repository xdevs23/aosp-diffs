```diff
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 06e320c1..809f8ac2 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -29,7 +29,7 @@
     <string name="toast_message_sent_success" msgid="1159956191974273064">"বাৰ্তা সফলভাৱে পঠিওৱা হ’ল।"</string>
     <string name="notification_service_label" msgid="7512186049723777468">"গাড়ীৰ জাননী শুনা সেৱা"</string>
     <string name="notifications" msgid="2865534625906329283">"জাননীৰ কেন্দ্ৰ"</string>
-    <string name="clear_all" msgid="1845314281571237722">"সকলো মচক"</string>
+    <string name="clear_all" msgid="1845314281571237722">"আটাইবোৰ মচক"</string>
     <string name="ellipsized_string" msgid="6993649229498857557">"…"</string>
     <string name="show_more" msgid="7291378544926443344">"অধিক দেখুৱাওক"</string>
     <string name="notification_header" msgid="324550431063568049">"জাননীসমূহ"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index d7e21e1b..a33a6118 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="5911862216123243843">"Upravitelj obavijestima automobila"</string>
     <string name="assist_action_play_label" msgid="6278705468288338172">"Pokreni"</string>
-    <string name="assist_action_reply_label" msgid="6946087036560525072">"Odgovori"</string>
+    <string name="assist_action_reply_label" msgid="6946087036560525072">"Odgovorite"</string>
     <string name="action_mute_short" msgid="5239851786101022633">"Zanemari"</string>
     <string name="action_mute_long" msgid="6846675719189989477">"Zanemari razgovor"</string>
     <string name="action_unmute_short" msgid="7157822835069715986">"Opozovi"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 10c67f88..0e8f1cf6 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -32,7 +32,7 @@
     <string name="clear_all" msgid="1845314281571237722">"सबै हटाउनुहोस्"</string>
     <string name="ellipsized_string" msgid="6993649229498857557">"…"</string>
     <string name="show_more" msgid="7291378544926443344">"कम देखाउनुहोस्"</string>
-    <string name="notification_header" msgid="324550431063568049">"सूचनाहरू"</string>
+    <string name="notification_header" msgid="324550431063568049">"नोटिफिकेसनहरू"</string>
     <string name="notification_recents" msgid="5855769440781958546">"हालैका"</string>
     <string name="notification_older" msgid="8162161020296499690">"अझ पुराना नोटिफिकेसनहरू"</string>
     <string name="empty_notification_header" msgid="4928379791607839720">"कुनै पनि सूचना छैन"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index f0955f74..65504cfd 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -35,7 +35,7 @@
     <string name="notification_header" msgid="324550431063568049">"Уведомления"</string>
     <string name="notification_recents" msgid="5855769440781958546">"Недавние уведомления"</string>
     <string name="notification_older" msgid="8162161020296499690">"Старые уведомления"</string>
-    <string name="empty_notification_header" msgid="4928379791607839720">"Уведомлений нет"</string>
+    <string name="empty_notification_header" msgid="4928379791607839720">"Уведомлений нет."</string>
     <string name="collapse_group" msgid="3487426973871208501">"Скрыть"</string>
     <string name="show_more_from_app" msgid="4270626118092846628">"Ещё <xliff:g id="COUNT">%1$d</xliff:g> от приложения \"<xliff:g id="APP">%2$s</xliff:g>\""</string>
     <string name="show_count_more" msgid="480555295700318609">"Показать ещё <xliff:g id="COUNT">%d</xliff:g>"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 6cfaef97..7eae8d53 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="5911862216123243843">"Správca upozornení v aute"</string>
     <string name="assist_action_play_label" msgid="6278705468288338172">"Prehrať"</string>
-    <string name="assist_action_reply_label" msgid="6946087036560525072">"Odpoveď"</string>
+    <string name="assist_action_reply_label" msgid="6946087036560525072">"Odpovedať"</string>
     <string name="action_mute_short" msgid="5239851786101022633">"Ignorovať"</string>
     <string name="action_mute_long" msgid="6846675719189989477">"Ignorovať konverzáciu"</string>
     <string name="action_unmute_short" msgid="7157822835069715986">"Prestať ignorovať"</string>
diff --git a/src/com/android/car/notification/CarNotificationViewAdapter.java b/src/com/android/car/notification/CarNotificationViewAdapter.java
index 4885bd77..67be3cc4 100644
--- a/src/com/android/car/notification/CarNotificationViewAdapter.java
+++ b/src/com/android/car/notification/CarNotificationViewAdapter.java
@@ -262,14 +262,7 @@ public class CarNotificationViewAdapter extends ContentLimitingAdapter<RecyclerV
         }
 
         // progress
-        int progressMax = extras.getInt(Notification.EXTRA_PROGRESS_MAX);
-        boolean isIndeterminate = extras.getBoolean(
-                Notification.EXTRA_PROGRESS_INDETERMINATE);
-        boolean hasValidProgress = isIndeterminate || progressMax != 0;
-        boolean isProgress = extras.containsKey(Notification.EXTRA_PROGRESS)
-                && extras.containsKey(Notification.EXTRA_PROGRESS_MAX)
-                && hasValidProgress
-                && !notification.hasCompletedProgress();
+        boolean isProgress = NotificationUtils.isProgress(notification);
         if (isProgress) {
             return mIsGroupNotificationAdapter
                     ? NotificationViewType.PROGRESS_IN_GROUP : NotificationViewType.PROGRESS;
diff --git a/src/com/android/car/notification/NotificationGroup.java b/src/com/android/car/notification/NotificationGroup.java
index 92790eb3..87cf716c 100644
--- a/src/com/android/car/notification/NotificationGroup.java
+++ b/src/com/android/car/notification/NotificationGroup.java
@@ -243,6 +243,33 @@ public class NotificationGroup {
         return mNotifications;
     }
 
+    /**
+     * Returns a notification with matching key or else returns {@code null}.
+     */
+    public AlertEntry getChildNotification(String key) {
+        for (int i = 0; i < mNotifications.size(); i++) {
+            AlertEntry alertEntry = mNotifications.get(i);
+            if (alertEntry.getKey().equals(key)) {
+                return alertEntry;
+            }
+        }
+        return null;
+    }
+
+    /**
+     * Returns {@code true} if old notification is set to new notification.
+     */
+    public boolean updateNotification(AlertEntry oldValue, AlertEntry newValue) {
+        for (int i = 0; i < mNotifications.size(); i++) {
+            AlertEntry alertEntry = mNotifications.get(i);
+            if (alertEntry.getKey().equals(oldValue.getKey())) {
+                mNotifications.set(i, newValue);
+                return true;
+            }
+        }
+        return false;
+    }
+
     /**
      * Returns the group summary notification.
      */
@@ -352,6 +379,6 @@ public class NotificationGroup {
 
     @Override
     public String toString() {
-        return mGroupKey + ": " + mNotifications.toString();
+        return mGroupKey + ": " + mNotifications;
     }
 }
diff --git a/src/com/android/car/notification/NotificationUtils.java b/src/com/android/car/notification/NotificationUtils.java
index 8b6dc953..cb199f01 100644
--- a/src/com/android/car/notification/NotificationUtils.java
+++ b/src/com/android/car/notification/NotificationUtils.java
@@ -179,6 +179,21 @@ public class NotificationUtils {
                 : ActivityManager.getCurrentUser();
     }
 
+    /**
+     * @return {@code true} if notification is a valid progress notification.
+     */
+    public static boolean isProgress(Notification notification) {
+        Bundle extras = notification.extras;
+        int progressMax = extras.getInt(Notification.EXTRA_PROGRESS_MAX);
+        boolean isIndeterminate = extras.getBoolean(
+                Notification.EXTRA_PROGRESS_INDETERMINATE);
+        boolean hasValidProgress = isIndeterminate || progressMax != 0;
+        return extras.containsKey(Notification.EXTRA_PROGRESS)
+                && extras.containsKey(Notification.EXTRA_PROGRESS_MAX)
+                && hasValidProgress
+                && !notification.hasCompletedProgress();
+    }
+
     private static boolean isSystemPrivilegedOrPlatformKeyInner(Context context,
             AlertEntry alertEntry, boolean checkForPrivilegedApp) {
         PackageInfo packageInfo = getPackageInfo(context, alertEntry.getStatusBarNotification());
diff --git a/src/com/android/car/notification/NotificationViewController.java b/src/com/android/car/notification/NotificationViewController.java
index 2602ef28..549fe609 100644
--- a/src/com/android/car/notification/NotificationViewController.java
+++ b/src/com/android/car/notification/NotificationViewController.java
@@ -1,3 +1,18 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
 package com.android.car.notification;
 
 import android.car.drivingstate.CarUxRestrictions;
@@ -5,8 +20,6 @@ import android.os.Build;
 import android.os.Handler;
 import android.os.Message;
 import android.util.Log;
-import android.view.View;
-import android.widget.Toast;
 
 import java.util.List;
 
@@ -25,7 +38,6 @@ public class NotificationViewController {
     private final NotificationDataManager mNotificationDataManager;
     private final NotificationUpdateHandler mNotificationUpdateHandler =
             new NotificationUpdateHandler();
-    private boolean mShowLessImportantNotifications;
     private boolean mIsVisible;
 
     public NotificationViewController(CarNotificationView carNotificationView,
@@ -39,25 +51,7 @@ public class NotificationViewController {
         mNotificationDataManager = NotificationDataManager.getInstance();
         mShowRecentsAndOlderHeaders = mCarNotificationView.getContext()
                         .getResources().getBoolean(R.bool.config_showRecentAndOldHeaders);
-
-        // Long clicking on the notification center title toggles hiding media, navigation, and
-        // less important (< IMPORTANCE_DEFAULT) ongoing foreground service notifications.
-        // This is only available for ENG and USERDEBUG builds.
-        View view = mCarNotificationView.findViewById(R.id.notification_center_title);
-        if (view != null && (Build.IS_ENG || Build.IS_USERDEBUG)) {
-            view.setOnLongClickListener(v -> {
-                mShowLessImportantNotifications = !mShowLessImportantNotifications;
-                Toast.makeText(
-                        carNotificationView.getContext(),
-                        "Foreground, navigation and media notifications " + (
-                                mShowLessImportantNotifications ? "ENABLED" : "DISABLED"),
-                        Toast.LENGTH_SHORT).show();
-                resetNotifications(mShowLessImportantNotifications);
-                return true;
-            });
-        }
-
-        resetNotifications(mShowLessImportantNotifications);
+        resetNotifications();
     }
 
     /**
@@ -91,7 +85,7 @@ public class NotificationViewController {
         mCarNotificationListener.onVisibilityChanged(mIsVisible);
         // Reset and collapse all groups when notification view disappears.
         if (!mIsVisible) {
-            resetNotifications(mShowLessImportantNotifications);
+            resetNotifications();
             mCarNotificationView.resetState();
         }
     }
@@ -99,7 +93,7 @@ public class NotificationViewController {
     /**
      * Reset notifications to the latest state.
      */
-    private void resetNotifications(boolean showLessImportantNotifications) {
+    private void resetNotifications() {
         mPreprocessingManager.init(mCarNotificationListener.getNotifications(),
                 mCarNotificationListener.getCurrentRanking());
 
@@ -109,7 +103,6 @@ public class NotificationViewController {
         }
 
         List<NotificationGroup> notificationGroups = mPreprocessingManager.process(
-                showLessImportantNotifications,
                 mCarNotificationListener.getNotifications(),
                 mCarNotificationListener.getCurrentRanking());
 
@@ -128,17 +121,16 @@ public class NotificationViewController {
      * Update notifications: no grouping/ranking updates will go through.
      * Insertion, deletion and content update will apply immediately.
      */
-    private void updateNotifications(
-            boolean showLessImportantNotifications, int what, AlertEntry alertEntry) {
+    private void updateNotifications(int what, AlertEntry alertEntry) {
 
         if (mPreprocessingManager.shouldFilter(alertEntry,
-                mCarNotificationListener.getCurrentRanking())) {
+                mCarNotificationListener.getCurrentRanking())
+                && what != CarNotificationListener.NOTIFY_NOTIFICATION_REMOVED) {
             // if the new notification should be filtered out, return early
             return;
         }
 
         List<NotificationGroup> notificationGroups = mPreprocessingManager.updateNotifications(
-                showLessImportantNotifications,
                 alertEntry,
                 what,
                 mCarNotificationListener.getCurrentRanking());
@@ -162,12 +154,9 @@ public class NotificationViewController {
                     return;
                 }
 
-                updateNotifications(
-                        mShowLessImportantNotifications,
-                        message.what,
-                        (AlertEntry) message.obj);
+                updateNotifications(message.what, (AlertEntry) message.obj);
             } else {
-                resetNotifications(mShowLessImportantNotifications);
+                resetNotifications();
             }
         }
     }
diff --git a/src/com/android/car/notification/PreprocessingManager.java b/src/com/android/car/notification/PreprocessingManager.java
index 9ce89de3..8683316d 100644
--- a/src/com/android/car/notification/PreprocessingManager.java
+++ b/src/com/android/car/notification/PreprocessingManager.java
@@ -79,7 +79,7 @@ public class PreprocessingManager {
     private int mMaxStringLength = Integer.MAX_VALUE;
     private Map<String, AlertEntry> mOldNotifications;
     private List<NotificationGroup> mOldProcessedNotifications;
-    private NotificationListenerService.RankingMap mOldRankingMap;
+    private RankingMap mOldRankingMap;
     private NotificationDataManager mNotificationDataManager;
 
     private boolean mIsInCall;
@@ -138,38 +138,34 @@ public class PreprocessingManager {
     public void init(Map<String, AlertEntry> notifications, RankingMap rankingMap) {
         mOldNotifications = notifications;
         mOldRankingMap = rankingMap;
-        mOldProcessedNotifications =
-                process(/* showLessImportantNotifications = */ false, notifications, rankingMap);
+        mOldProcessedNotifications = process(notifications, rankingMap);
     }
 
     /**
      * Process the given notifications. In order for DiffUtil to work, the adapter needs a new
      * data object each time it updates, therefore wrapping the return value in a new list.
      *
-     * @param showLessImportantNotifications whether less important notifications should be shown.
      * @param notifications the list of notifications to be processed.
      * @param rankingMap the ranking map for the notifications.
      * @return the processed notifications in a new list.
      */
-    public List<NotificationGroup> process(boolean showLessImportantNotifications,
-            Map<String, AlertEntry> notifications, RankingMap rankingMap) {
+    public List<NotificationGroup> process(Map<String, AlertEntry> notifications,
+            RankingMap rankingMap) {
         return new ArrayList<>(
                 rank(group(optimizeForDriving(
-                                filter(showLessImportantNotifications,
-                                        new ArrayList<>(notifications.values()),
+                                filter(new ArrayList<>(notifications.values()),
                                         rankingMap))),
                         rankingMap));
     }
 
     /**
-     * Create a new list of notifications based on existing list.
+     * Create a new list of notifications based adding/removing a notification to/from
+     * an existing list.
      *
-     * @param showLessImportantNotifications whether less important notifications should be shown.
      * @param newRankingMap the latest ranking map for the notifications.
      * @return the new notification group list that should be shown to the user.
      */
     public List<NotificationGroup> updateNotifications(
-            boolean showLessImportantNotifications,
             AlertEntry alertEntry,
             int updateType,
             RankingMap newRankingMap) {
@@ -179,7 +175,7 @@ public class PreprocessingManager {
                 // removal of a notification is the same as a normal preprocessing
                 mOldNotifications.remove(alertEntry.getKey());
                 mOldProcessedNotifications =
-                        process(showLessImportantNotifications, mOldNotifications, mOldRankingMap);
+                        process(mOldNotifications, mOldRankingMap);
                 break;
             case CarNotificationListener.NOTIFY_NOTIFICATION_POSTED:
                 AlertEntry notification = optimizeForDriving(alertEntry);
@@ -220,14 +216,8 @@ public class PreprocessingManager {
      */
     @VisibleForTesting
     protected List<AlertEntry> filter(
-            boolean showLessImportantNotifications,
             List<AlertEntry> notifications,
             RankingMap rankingMap) {
-        // remove notifications that should be filtered.
-        if (!showLessImportantNotifications) {
-            notifications.removeIf(alertEntry -> shouldFilter(alertEntry, rankingMap));
-        }
-
         // Call notifications should not be shown in the panel.
         // Since they're shown as persistent HUNs, and notifications are not added to the panel
         // until after they're dismissed as HUNs, it does not make sense to have them in the panel,
@@ -323,6 +313,10 @@ public class PreprocessingManager {
         }
 
         Bundle extras = alertEntry.getNotification().extras;
+        if (extras == null) {
+            return alertEntry;
+        }
+
         for (String key : extras.keySet()) {
             switch (key) {
                 case Notification.EXTRA_TITLE:
@@ -331,8 +325,6 @@ public class PreprocessingManager {
                 case Notification.EXTRA_SUMMARY_TEXT:
                     CharSequence value = extras.getCharSequence(key);
                     extras.putCharSequence(key, trimText(value));
-                default:
-                    continue;
             }
         }
         return alertEntry;
@@ -573,6 +565,7 @@ public class PreprocessingManager {
     protected List<NotificationGroup> additionalGroupAndRank(AlertEntry newNotification,
             RankingMap newRankingMap, boolean isUpdate) {
         Notification notification = newNotification.getNotification();
+        boolean isProgress = NotificationUtils.isProgress(notification);
         NotificationGroup newGroup = new NotificationGroup();
 
         // The newGroup should appear in the recent section so mark the group as not seen. Since the
@@ -612,21 +605,51 @@ public class PreprocessingManager {
         // 3. present in an unseen group.
         for (int i = 0; i < mOldProcessedNotifications.size(); i++) {
             NotificationGroup oldGroup = mOldProcessedNotifications.get(i);
+            AlertEntry oldNotification = null;
 
-            if (!TextUtils.equals(oldGroup.getGroupKey(),
-                    newNotification.getStatusBarNotification().getGroupKey())) {
-                continue;
+            boolean isGroupKeySame = TextUtils.equals(oldGroup.getGroupKey(),
+                    newNotification.getStatusBarNotification().getGroupKey());
+
+            if (isUpdate) {
+                // If this is an update, existing notification in group must have the same key
+                oldNotification =
+                        oldGroup.getChildNotification(newNotification.getKey());
+                if (oldNotification == null) {
+                    continue;
+                }
+            } else {
+                // If not an update, group key must be the same
+                if (!isGroupKeySame) {
+                    continue;
+                }
             }
 
-            if (mShowRecentsAndOlderHeaders && oldGroup.isSeen()) {
-                if (isUpdate) {
-                    boolean isRemoved = oldGroup.removeNotification(newNotification);
-                    if (isRemoved) {
-                        mOldProcessedNotifications.set(i, oldGroup);
-                        if (oldGroup.getChildCount() == 0) {
-                            emptySeenGroupsToBeRemoved.add(oldGroup);
-                        }
+            // If updating a progress notification with another progress notification, then update
+            // while maintaining order
+            if (isUpdate && isProgress
+                    && NotificationUtils.isProgress(oldNotification.getNotification())
+                    && oldGroup.updateNotification(oldNotification, newNotification)) {
+                mOldProcessedNotifications.set(i, oldGroup);
+                return mOldProcessedNotifications;
+            }
+
+            // If updating:
+            // 1) progress notification with non-progress notification
+            // 2) non-progress notification with non-progress notification
+            // 2) non-progress notification with progress notification
+            if (isUpdate && oldGroup.removeNotification(newNotification)) {
+                if (mShowRecentsAndOlderHeaders && oldGroup.isSeen()) {
+                    // and old group is seen, then remove old notification from group to make
+                    // space for new notification group that is unseen.
+                    mOldProcessedNotifications.set(i, oldGroup);
+                    if (oldGroup.getChildCount() == 0) {
+                        emptySeenGroupsToBeRemoved.add(oldGroup);
                     }
+                } else {
+                    // If seen/unseen isn't enabled, just add new notification to the old group.
+                    oldGroup.addNotification(newNotification);
+                    mOldProcessedNotifications.set(i, oldGroup);
+                    return mOldProcessedNotifications;
                 }
                 continue;
             }
@@ -647,13 +670,9 @@ public class PreprocessingManager {
             }
 
             // Group with same group key exist with multiple children
-            // For update, replace the old notification with the updated notification
-            // else add the new notification to the existing group if it's notification
+            // Add the new notification to the existing group if it's notification
             // count is greater than the minimum threshold.
-            if (isUpdate) {
-                oldGroup.removeNotification(newNotification);
-            }
-            if (isUpdate || oldGroup.getChildCount() >= mMinimumGroupingThreshold) {
+            if (oldGroup.getChildCount() >= mMinimumGroupingThreshold) {
                 oldGroup.addNotification(newNotification);
                 mOldProcessedNotifications.set(i, oldGroup);
                 return mOldProcessedNotifications;
@@ -818,9 +837,9 @@ public class PreprocessingManager {
      * Comparator that sorts the notification groups by their representative notification's rank.
      */
     private class NotificationComparator implements Comparator<NotificationGroup> {
-        private final NotificationListenerService.RankingMap mRankingMap;
+        private final RankingMap mRankingMap;
 
-        NotificationComparator(NotificationListenerService.RankingMap rankingMap) {
+        NotificationComparator(RankingMap rankingMap) {
             mRankingMap = rankingMap;
         }
 
diff --git a/tests/robotests/Android.bp b/tests/robotests/Android.bp
index 54965e64..d12d1e21 100644
--- a/tests/robotests/Android.bp
+++ b/tests/robotests/Android.bp
@@ -39,7 +39,6 @@ android_robolectric_test {
     test_options: {
         timeout: 36000,
     },
-    upstream: true,
 
     strict_mode: false,
 }
diff --git a/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java b/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java
index 85f49056..93b6bdb9 100644
--- a/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java
+++ b/tests/unit/src/com/android/car/notification/CarNotificationListenerTest.java
@@ -423,7 +423,8 @@ public class CarNotificationListenerTest {
                 /* rankingAdjustment= */ 0,
                 /* isBubble= */ false,
                 /* proposedImportance= */ 0,
-                /* sensitiveContent= */ false
+                /* sensitiveContent= */ false,
+                /* summarization = */ null
         );
         mRankingMap = new NotificationListenerService.RankingMap(
                 new NotificationListenerService.Ranking[]{ranking});
diff --git a/tests/unit/src/com/android/car/notification/NotificationDataManagerTest.java b/tests/unit/src/com/android/car/notification/NotificationDataManagerTest.java
index c02fe7f2..7e8d38a1 100644
--- a/tests/unit/src/com/android/car/notification/NotificationDataManagerTest.java
+++ b/tests/unit/src/com/android/car/notification/NotificationDataManagerTest.java
@@ -329,7 +329,8 @@ public class NotificationDataManagerTest {
                     /* rankingAdjustment= */ 0,
                     /* isBubble= */ false,
                     /* proposedImportance= */ 0,
-                    /* sensitiveContent= */ false
+                    /* sensitiveContent= */ false,
+                    /* summarization = */ null
             );
             rankings[i] = ranking;
         }
diff --git a/tests/unit/src/com/android/car/notification/NotificationGroupTest.java b/tests/unit/src/com/android/car/notification/NotificationGroupTest.java
index 090e18d9..8e3f8727 100644
--- a/tests/unit/src/com/android/car/notification/NotificationGroupTest.java
+++ b/tests/unit/src/com/android/car/notification/NotificationGroupTest.java
@@ -51,7 +51,8 @@ public class NotificationGroupTest {
     private static final int INITIAL_PID = 3;
     private static final String CHANNEL_ID = "CHANNEL_ID";
     private static final String CONTENT_TITLE = "CONTENT_TITLE";
-    private static final String OVERRIDE_GROUP_KEY = "OVERRIDE_GROUP_KEY";
+    private static final String OVERRIDE_GROUP_KEY_1 = "OVERRIDE_GROUP_KEY_1";
+    private static final String OVERRIDE_GROUP_KEY_2 = "OVERRIDE_GROUP_KEY_2";
     private static final long POST_TIME = 12345l;
     private static final UserHandle USER_HANDLE = new UserHandle(12);
     @Rule
@@ -73,10 +74,10 @@ public class NotificationGroupTest {
                 .setSmallIcon(android.R.drawable.sym_def_app_icon);
         mNotification1 = new AlertEntry(new StatusBarNotification(PKG_1, OP_PKG,
                 ID, TAG, UID, INITIAL_PID, mNotificationBuilder.build(), USER_HANDLE,
-                OVERRIDE_GROUP_KEY, POST_TIME));
+                OVERRIDE_GROUP_KEY_1, POST_TIME));
         mNotification2 = new AlertEntry(new StatusBarNotification(PKG_2, OP_PKG,
                 ID, TAG, UID, INITIAL_PID, mNotificationBuilder.build(), USER_HANDLE,
-                OVERRIDE_GROUP_KEY, POST_TIME));
+                OVERRIDE_GROUP_KEY_2, POST_TIME));
     }
 
     /**
@@ -232,4 +233,45 @@ public class NotificationGroupTest {
         assertThat(mNotificationGroup.isDismissible()).isTrue();
     }
 
+    @Test
+    public void  getChildNotification_exists() {
+        mNotificationGroup.addNotification(mNotification1);
+
+        AlertEntry actual = mNotificationGroup.getChildNotification(mNotification1.getKey());
+
+        assertThat(actual).isEqualTo(mNotification1);
+    }
+
+    @Test
+    public void  getChildNotification_doesNotExist_returnNull() {
+        mNotificationGroup.addNotification(mNotification1);
+
+        AlertEntry actual = mNotificationGroup.getChildNotification(mNotification2.getKey());
+
+        assertThat(actual).isNull();
+    }
+
+    @Test
+    public void updateNotification_doesNotExist_returnFalse() {
+        mNotificationGroup.addNotification(mNotification1);
+
+        assertThat(mNotificationGroup.updateNotification(mNotification2, mNotification1)).isFalse();
+    }
+
+    @Test
+    public void updateNotification_doesExist_returnTrue() {
+        mNotificationGroup.addNotification(mNotification1);
+
+        assertThat(mNotificationGroup.updateNotification(mNotification1, mNotification2)).isTrue();
+    }
+
+    @Test
+    public void updateNotification_doesExist_isUpdated() {
+        mNotificationGroup.addNotification(mNotification1);
+
+        mNotificationGroup.updateNotification(mNotification1, mNotification2);
+
+        assertThat(mNotificationGroup.getChildNotification(mNotification2.getKey()))
+                .isEqualTo(mNotification2);
+    }
 }
diff --git a/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java b/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
index 671044d5..832a8429 100644
--- a/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
+++ b/tests/unit/src/com/android/car/notification/NotificationUtilsTest.java
@@ -57,11 +57,15 @@ public class NotificationUtilsTest {
     public final TestableContext mContext = new TestableContext(
             InstrumentationRegistry.getInstrumentation().getTargetContext());
 
+    private static final String CHANNEL_ID = "CHANNEL_ID";
+    private static final String CONTENT_TITLE = "CONTENT_TITLE";
+
     private MockitoSession mSession;
     private AlertEntry mAlertEntry;
 
     @Mock
     private StatusBarNotification mStatusBarNotification;
+    private Notification mNotification;
     @Mock
     private PackageManager mPackageManager;
     @Mock
@@ -325,6 +329,39 @@ public class NotificationUtilsTest {
                 myUserHandle.getIdentifier());
     }
 
+    @Test
+    public void isProgress_isValid_returnTrue() {
+        mNotification = new Notification.Builder(mContext, CHANNEL_ID)
+                .setContentTitle(CONTENT_TITLE)
+                .setSmallIcon(android.R.drawable.sym_def_app_icon)
+                .setProgress(100,  50, true)
+                .build();
+
+        assertThat(NotificationUtils.isProgress(mNotification)).isTrue();
+    }
+
+    @Test
+    public void isProgress_invalidProgress_returnFalse() {
+        mNotification = new Notification.Builder(mContext, CHANNEL_ID)
+                .setContentTitle(CONTENT_TITLE)
+                .setSmallIcon(android.R.drawable.sym_def_app_icon)
+                .setProgress(0,  50, false)
+                .build();
+
+        assertThat(NotificationUtils.isProgress(mNotification)).isFalse();
+    }
+
+    @Test
+    public void isProgress_hasCompletedProgress_returnFalse() {
+        mNotification = new Notification.Builder(mContext, CHANNEL_ID)
+                .setContentTitle(CONTENT_TITLE)
+                .setSmallIcon(android.R.drawable.sym_def_app_icon)
+                .setProgress(100,  100, true)
+                .build();
+
+        assertThat(NotificationUtils.isProgress(mNotification)).isFalse();
+    }
+
     private void setApplicationInfo(boolean signedWithPlatformKey, boolean isSystemApp,
             boolean isPrivilegedApp) throws PackageManager.NameNotFoundException {
         ApplicationInfo applicationInfo = new ApplicationInfo();
diff --git a/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java b/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
index 8b1e6d43..9982f30e 100644
--- a/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
+++ b/tests/unit/src/com/android/car/notification/PreprocessingManagerTest.java
@@ -89,6 +89,7 @@ public class PreprocessingManagerTest {
     private static final String GROUP_KEY_A = "GROUP_KEY_A";
     private static final String GROUP_KEY_B = "GROUP_KEY_B";
     private static final String GROUP_KEY_C = "GROUP_KEY_C";
+    private static final String GROUP_KEY_D = "GROUP_KEY_D";
     private static final int MAX_STRING_LENGTH = 10;
     private static final int DEFAULT_MIN_GROUPING_THRESHOLD = 4;
     @Rule
@@ -119,6 +120,8 @@ public class PreprocessingManagerTest {
     @Mock
     private StatusBarNotification mStatusBarNotification12;
     @Mock
+    private StatusBarNotification mStatusBarNotification13;
+    @Mock
     private StatusBarNotification mAdditionalStatusBarNotification;
     @Mock
     private StatusBarNotification mSummaryAStatusBarNotification;
@@ -148,12 +151,14 @@ public class PreprocessingManagerTest {
     private Notification mForegroundNotification;
     private Notification mBackgroundNotification;
     private Notification mNavigationNotification;
+    private Notification mProgressNotification;
 
     // Following AlertEntry var names describe the type of notifications they wrap.
     private AlertEntry mLessImportantBackground;
     private AlertEntry mLessImportantForeground;
     private AlertEntry mMedia;
     private AlertEntry mNavigation;
+    private AlertEntry mProgress;
     private AlertEntry mImportantBackground;
     private AlertEntry mImportantForeground;
     private AlertEntry mImportantForeground2;
@@ -188,11 +193,13 @@ public class PreprocessingManagerTest {
         mPreprocessingManager = PreprocessingManager.getInstance(mContext);
 
         mForegroundNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         mBackgroundNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         mNavigationNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ true, /* isGroupSummary= */ true);
+                /* isNavigation= */ true, /* isGroupSummary= */ true, /* isProgress= */ false);
+        mProgressNotification = generateNotification(/* isForeground= */ false,
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ true);
 
         when(mMediaNotification.isMediaNotification()).thenReturn(true);
 
@@ -209,6 +216,7 @@ public class PreprocessingManagerTest {
         when(mStatusBarNotification10.getKey()).thenReturn("KEY_IMPORTANT_FOREGROUND_5");
         when(mStatusBarNotification11.getKey()).thenReturn("KEY_IMPORTANT_FOREGROUND_6");
         when(mStatusBarNotification12.getKey()).thenReturn("KEY_IMPORTANT_FOREGROUND_7");
+        when(mStatusBarNotification13.getKey()).thenReturn("KEY_PROGRESS");
         when(mSummaryAStatusBarNotification.getKey()).thenReturn("KEY_SUMMARY_A");
         when(mSummaryBStatusBarNotification.getKey()).thenReturn("KEY_SUMMARY_B");
         when(mSummaryCStatusBarNotification.getKey()).thenReturn("KEY_SUMMARY_C");
@@ -219,6 +227,7 @@ public class PreprocessingManagerTest {
         when(mStatusBarNotification4.getGroupKey()).thenReturn(GROUP_KEY_B);
         when(mStatusBarNotification5.getGroupKey()).thenReturn(GROUP_KEY_B);
         when(mStatusBarNotification6.getGroupKey()).thenReturn(GROUP_KEY_C);
+        when(mStatusBarNotification13.getGroupKey()).thenReturn(GROUP_KEY_D);
         when(mSummaryAStatusBarNotification.getGroupKey()).thenReturn(GROUP_KEY_A);
         when(mSummaryBStatusBarNotification.getGroupKey()).thenReturn(GROUP_KEY_B);
         when(mSummaryCStatusBarNotification.getGroupKey()).thenReturn(GROUP_KEY_C);
@@ -235,6 +244,7 @@ public class PreprocessingManagerTest {
         when(mStatusBarNotification10.getNotification()).thenReturn(mForegroundNotification);
         when(mStatusBarNotification11.getNotification()).thenReturn(mForegroundNotification);
         when(mStatusBarNotification12.getNotification()).thenReturn(mForegroundNotification);
+        when(mStatusBarNotification13.getNotification()).thenReturn(mProgressNotification);
         when(mSummaryAStatusBarNotification.getNotification()).thenReturn(mSummaryNotification);
         when(mSummaryBStatusBarNotification.getNotification()).thenReturn(mSummaryNotification);
         when(mSummaryCStatusBarNotification.getNotification()).thenReturn(mSummaryNotification);
@@ -251,6 +261,7 @@ public class PreprocessingManagerTest {
         when(mStatusBarNotification10.getPackageName()).thenReturn(PKG);
         when(mStatusBarNotification11.getPackageName()).thenReturn(PKG);
         when(mStatusBarNotification12.getPackageName()).thenReturn(PKG);
+        when(mStatusBarNotification13.getPackageName()).thenReturn(PKG);
         when(mSummaryAStatusBarNotification.getPackageName()).thenReturn(PKG);
         when(mSummaryBStatusBarNotification.getPackageName()).thenReturn(PKG);
         when(mSummaryCStatusBarNotification.getPackageName()).thenReturn(PKG);
@@ -265,78 +276,6 @@ public class PreprocessingManagerTest {
         initTestData(/* includeAdditionalNotifs= */ false);
     }
 
-    @Test
-    public void onFilter_showLessImportantNotifications_doesNotFilterNotifications() {
-        List<AlertEntry> unfiltered = mAlertEntries.stream().collect(Collectors.toList());
-        mPreprocessingManager
-                .filter(/* showLessImportantNotifications= */ true, mAlertEntries, mRankingMap);
-
-        assertThat(mAlertEntries.equals(unfiltered)).isTrue();
-    }
-
-    @Test
-    public void onFilter_dontShowLessImportantNotifications_filtersLessImportantForeground()
-            throws PackageManager.NameNotFoundException {
-        mPreprocessingManager
-                .filter( /* showLessImportantNotifications= */ false, mAlertEntries, mRankingMap);
-
-        assertThat(mAlertEntries.contains(mLessImportantBackground)).isTrue();
-        assertThat(mAlertEntries.contains(mLessImportantForeground)).isFalse();
-    }
-
-    @Test
-    public void onFilter_dontShowLessImportantNotifications_doesNotFilterMoreImportant() {
-        mPreprocessingManager
-                .filter(/* showLessImportantNotifications= */ false, mAlertEntries, mRankingMap);
-
-        assertThat(mAlertEntries.contains(mImportantBackground)).isTrue();
-        assertThat(mAlertEntries.contains(mImportantForeground)).isTrue();
-    }
-
-    @Test
-    public void onFilter_dontShowLessImportantNotifications_filtersMediaAndNavigation() {
-        mPreprocessingManager
-                .filter(/* showLessImportantNotifications= */ false, mAlertEntries, mRankingMap);
-
-        assertThat(mAlertEntries.contains(mMedia)).isFalse();
-        assertThat(mAlertEntries.contains(mNavigation)).isFalse();
-    }
-
-    @Test
-    public void onFilter_doShowLessImportantNotifications_doesNotFilterMediaOrNavigation() {
-        mPreprocessingManager
-                .filter(/* showLessImportantNotifications= */ true, mAlertEntries, mRankingMap);
-
-        assertThat(mAlertEntries.contains(mMedia)).isTrue();
-        assertThat(mAlertEntries.contains(mNavigation)).isTrue();
-    }
-
-    @Test
-    public void onFilter_doShowLessImportantNotifications_filtersCalls() {
-        StatusBarNotification callSBN = mock(StatusBarNotification.class);
-        Notification callNotification = new Notification();
-        callNotification.category = Notification.CATEGORY_CALL;
-        when(callSBN.getNotification()).thenReturn(callNotification);
-        List<AlertEntry> entries = new ArrayList<>();
-        entries.add(new AlertEntry(callSBN));
-
-        mPreprocessingManager.filter(true, entries, mRankingMap);
-        assertThat(entries).isEmpty();
-    }
-
-    @Test
-    public void onFilter_dontShowLessImportantNotifications_filtersCalls() {
-        StatusBarNotification callSBN = mock(StatusBarNotification.class);
-        Notification callNotification = new Notification();
-        callNotification.category = Notification.CATEGORY_CALL;
-        when(callSBN.getNotification()).thenReturn(callNotification);
-        List<AlertEntry> entries = new ArrayList<>();
-        entries.add(new AlertEntry(callSBN));
-
-        mPreprocessingManager.filter(false, entries, mRankingMap);
-        assertThat(entries).isEmpty();
-    }
-
     @Test
     public void onOptimizeForDriving_alertEntryHasNonMessageNotification_trimsNotificationTexts() {
         when(mCarUxRestrictions.getMaxRestrictedStringLength()).thenReturn(MAX_STRING_LENGTH);
@@ -345,7 +284,7 @@ public class PreprocessingManagerTest {
         mPreprocessingManager.setCarUxRestrictionManagerWrapper(mCarUxRestrictionManagerWrapper);
 
         Notification nonMessageNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ true, /* isGroupSummary= */ true);
+                /* isNavigation= */ true, /* isGroupSummary= */ true, /* isProgress= */ false);
         nonMessageNotification.extras
                 .putString(Notification.EXTRA_TITLE, generateStringOfLength(100));
         nonMessageNotification.extras
@@ -382,7 +321,7 @@ public class PreprocessingManagerTest {
         mPreprocessingManager.setCarUxRestrictionManagerWrapper(mCarUxRestrictionManagerWrapper);
 
         Notification messageNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ true, /* isGroupSummary= */ true);
+                /* isNavigation= */ true, /* isGroupSummary= */ true, /* isProgress= */ false);
         messageNotification.extras
                 .putString(Notification.EXTRA_TITLE, generateStringOfLength(100));
         messageNotification.extras
@@ -419,7 +358,7 @@ public class PreprocessingManagerTest {
         mPreprocessingManager = PreprocessingManager.getInstance(mContext);
         List<NotificationGroup> groupResult = mPreprocessingManager.group(mAlertEntries);
         String[] actualGroupKeys = new String[groupResult.size()];
-        String[] expectedGroupKeys = {GROUP_KEY_A, GROUP_KEY_B, GROUP_KEY_C};
+        String[] expectedGroupKeys = {GROUP_KEY_A, GROUP_KEY_B, GROUP_KEY_C, GROUP_KEY_D};
 
         for (int i = 0; i < groupResult.size(); i++) {
             actualGroupKeys[i] = groupResult.get(i).getGroupKey();
@@ -438,7 +377,8 @@ public class PreprocessingManagerTest {
         mPreprocessingManager = PreprocessingManager.getInstance(mContext);
         List<NotificationGroup> groupResult = mPreprocessingManager.group(mAlertEntries);
         String[] actualGroupKeys = new String[groupResult.size()];
-        String[] expectedGroupKeys = {GROUP_KEY_A, GROUP_KEY_B, GROUP_KEY_B, GROUP_KEY_C};
+        String[] expectedGroupKeys =
+                {GROUP_KEY_A, GROUP_KEY_B, GROUP_KEY_B, GROUP_KEY_C, GROUP_KEY_D};
 
         for (int i = 0; i < groupResult.size(); i++) {
             actualGroupKeys[i] = groupResult.get(i).getGroupKey();
@@ -470,6 +410,7 @@ public class PreprocessingManagerTest {
         when(mNotificationDataManager.isNotificationSeen(mImportantForeground6)).thenReturn(false);
         when(mNotificationDataManager.isNotificationSeen(mImportantForeground7)).thenReturn(false);
         when(mNotificationDataManager.isNotificationSeen(mNavigation)).thenReturn(false);
+        when(mNotificationDataManager.isNotificationSeen(mProgress)).thenReturn(false);
         when(mStatusBarNotification1.getGroupKey()).thenReturn(GROUP_KEY_A);
         when(mStatusBarNotification2.getGroupKey()).thenReturn(GROUP_KEY_A);
         when(mStatusBarNotification3.getGroupKey()).thenReturn(GROUP_KEY_A);
@@ -482,12 +423,14 @@ public class PreprocessingManagerTest {
         when(mStatusBarNotification10.getGroupKey()).thenReturn(GROUP_KEY_A);
         when(mStatusBarNotification11.getGroupKey()).thenReturn(GROUP_KEY_A);
         when(mStatusBarNotification12.getGroupKey()).thenReturn(GROUP_KEY_A);
+        when(mStatusBarNotification13.getGroupKey()).thenReturn(GROUP_KEY_A);
 
         mPreprocessingManager.setNotificationDataManager(mNotificationDataManager);
 
         Set expectedResultUnseen = new HashSet();
         expectedResultUnseen.add(mImportantBackground.getKey());
         expectedResultUnseen.add(mNavigation.getKey());
+        expectedResultUnseen.add(mProgress.getKey());
         expectedResultUnseen.add(mImportantForeground4.getKey());
         expectedResultUnseen.add(mImportantForeground5.getKey());
         expectedResultUnseen.add(mImportantForeground6.getKey());
@@ -677,6 +620,7 @@ public class PreprocessingManagerTest {
 
         // generateRankingMap ranked the notifications in the reverse order.
         String[] expectedOrder = {
+                GROUP_KEY_D,
                 GROUP_KEY_C,
                 GROUP_KEY_B,
                 GROUP_KEY_A
@@ -697,7 +641,7 @@ public class PreprocessingManagerTest {
         mPreprocessingManager = PreprocessingManager.getInstance(mContext);
         List<NotificationGroup> groupResult = mPreprocessingManager.group(mAlertEntries);
         List<NotificationGroup> rankResult = mPreprocessingManager.rank(groupResult, mRankingMap);
-        NotificationGroup groupB = rankResult.get(1);
+        NotificationGroup groupB = rankResult.get(2);
 
         // first make sure that we have Group B
         assertThat(groupB.getGroupKey()).isEqualTo(GROUP_KEY_B);
@@ -719,7 +663,7 @@ public class PreprocessingManagerTest {
     @Test
     public void onAdditionalGroupAndRank_isGroupSummary_returnsTheSameGroupsAsStandardGroup() {
         Notification additionalNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         additionalNotification.category = Notification.CATEGORY_MESSAGE;
         when(mAdditionalStatusBarNotification.getKey()).thenReturn("ADDITIONAL");
         when(mAdditionalStatusBarNotification.getGroupKey()).thenReturn(GROUP_KEY_C);
@@ -727,8 +671,8 @@ public class PreprocessingManagerTest {
         AlertEntry additionalAlertEntry = new AlertEntry(mAdditionalStatusBarNotification);
 
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
-        List<AlertEntry> copy = mPreprocessingManager.filter(/* showLessImportantNotifications= */
-                false, new ArrayList<>(mAlertEntries), mRankingMap);
+        List<AlertEntry> copy = mPreprocessingManager.filter(
+                new ArrayList<>(mAlertEntries), mRankingMap);
         copy.add(additionalAlertEntry);
         copy.add(new AlertEntry(mSummaryCStatusBarNotification));
         List<NotificationGroup> expected = mPreprocessingManager.group(copy);
@@ -759,7 +703,7 @@ public class PreprocessingManagerTest {
         String key = "NEW_KEY";
         String groupKey = "NEW_GROUP_KEY";
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -780,8 +724,7 @@ public class PreprocessingManagerTest {
                 .collect(Collectors.toList());
 
         List<NotificationGroup> standardRanked = mPreprocessingManager.rank(
-                mPreprocessingManager.process(/* showLessImportantNotifications = */ false,
-                        testCopy, mRankingMap), mRankingMap);
+                mPreprocessingManager.process(testCopy, mRankingMap), mRankingMap);
 
         assertThat(additionalRanked.size()).isEqualTo(standardRanked.size());
 
@@ -799,7 +742,7 @@ public class PreprocessingManagerTest {
         String key = "NEW_KEY";
         String groupKey = "NEW_GROUP_KEY";
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -834,7 +777,30 @@ public class PreprocessingManagerTest {
         String key = mImportantForeground.getKey();
         String groupKey = mImportantForeground.getStatusBarNotification().getGroupKey();
         Notification newNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
+        StatusBarNotification newSbn = mock(StatusBarNotification.class);
+        when(newSbn.getNotification()).thenReturn(newNotification);
+        when(newSbn.getKey()).thenReturn(key);
+        when(newSbn.getGroupKey()).thenReturn(groupKey);
+        when(newSbn.getId()).thenReturn(123);
+        AlertEntry newEntry = new AlertEntry(newSbn);
+
+        List<NotificationGroup> result = mPreprocessingManager.additionalGroupAndRank(newEntry,
+                generateRankingMap(mAlertEntries), /* isUpdate= */ true);
+
+        assertThat(result.get(1).getSingleNotification().getStatusBarNotification().getId())
+                .isEqualTo(123);
+    }
+
+    @Test
+    public void onAdditionalGroupAndRank_progressUpdate_notificationUpdatedInOrder() {
+        when(mNotificationDataManager.isNotificationSeen(mProgress)).thenReturn(true);
+        // Seed the list
+        mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
+        String key = mProgress.getKey();
+        String groupKey = mProgress.getStatusBarNotification().getGroupKey();
+        Notification newNotification = generateNotification(/* isForeground= */ true,
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ true);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -849,6 +815,29 @@ public class PreprocessingManagerTest {
                 .isEqualTo(123);
     }
 
+    @Test
+    public void onAdditionalGroupAndRank_progressUpdatesNonProgress_notificationUpdatedNewGroup() {
+        when(mNotificationDataManager.isNotificationSeen(mImportantForeground)).thenReturn(true);
+        // Seed the list
+        mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
+        String key = mImportantForeground.getKey();
+        String groupKey = mImportantForeground.getStatusBarNotification().getGroupKey();
+        Notification newNotification = generateNotification(/* isForeground= */ true,
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ true);
+        StatusBarNotification newSbn = mock(StatusBarNotification.class);
+        when(newSbn.getNotification()).thenReturn(newNotification);
+        when(newSbn.getKey()).thenReturn(key);
+        when(newSbn.getGroupKey()).thenReturn(groupKey);
+        when(newSbn.getId()).thenReturn(123);
+        AlertEntry newEntry = new AlertEntry(newSbn);
+
+        List<NotificationGroup> result = mPreprocessingManager.additionalGroupAndRank(newEntry,
+                generateRankingMap(mAlertEntries), /* isUpdate= */ true);
+
+        assertThat(result.get(1).getSingleNotification().getStatusBarNotification().getId())
+                .isEqualTo(123);
+    }
+
     @Test
     public void onAdditionalGroupAndRank_updateToNotificationInSeenGroup_newUnseenGroupCreated() {
         when(mStatusBarNotification6.getGroupKey()).thenReturn(GROUP_KEY_C);
@@ -878,7 +867,7 @@ public class PreprocessingManagerTest {
         // Create a notification with same key and group key to be sent as an update
         String key = mImportantForeground.getKey();
         Notification newNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -924,7 +913,7 @@ public class PreprocessingManagerTest {
         // Create a notification with same key and group key to be sent as an update
         String key = mImportantForeground.getKey();
         Notification newNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -953,7 +942,7 @@ public class PreprocessingManagerTest {
         // Create a notification with same key and group key to be sent as an update
         String key = mImportantForeground.getKey();
         Notification newNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -975,7 +964,7 @@ public class PreprocessingManagerTest {
         mPreprocessingManager.setNotificationDataManager(mNotificationDataManager);
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -1001,7 +990,7 @@ public class PreprocessingManagerTest {
         generateGroupSummaryNotification(groupKey);
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -1032,7 +1021,7 @@ public class PreprocessingManagerTest {
         generateGroupSummaryNotification(groupKey);
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -1059,7 +1048,7 @@ public class PreprocessingManagerTest {
         generateGroupSummaryNotification(groupKey);
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -1087,7 +1076,7 @@ public class PreprocessingManagerTest {
         generateNotificationsWithSameGroupKey(numberOfGroupNotifications, groupKey);
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
         Notification newNotification = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ false);
+                /* isNavigation= */ false, /* isGroupSummary= */ false, /* isProgress= */ false);
         StatusBarNotification newSbn = mock(StatusBarNotification.class);
         when(newSbn.getNotification()).thenReturn(newNotification);
         when(newSbn.getKey()).thenReturn(key);
@@ -1109,7 +1098,6 @@ public class PreprocessingManagerTest {
 
         List<NotificationGroup> newList =
                 mPreprocessingManager.updateNotifications(
-                        /* showLessImportantNotifications= */ false,
                         mImportantForeground,
                         CarNotificationListener.NOTIFY_NOTIFICATION_REMOVED,
                         mRankingMap);
@@ -1132,7 +1120,6 @@ public class PreprocessingManagerTest {
                 .thenReturn(newNotification);
         List<NotificationGroup> newList =
                 mPreprocessingManager.updateNotifications(
-                        /* showLessImportantNotifications= */ false,
                         mImportantForeground,
                         CarNotificationListener.NOTIFY_NOTIFICATION_POSTED,
                         mRankingMap);
@@ -1150,7 +1137,7 @@ public class PreprocessingManagerTest {
         mPreprocessingManager.init(mAlertEntriesMap, mRankingMap);
         int beforeSize = mPreprocessingManager.getOldNotifications().size();
         Notification additionalNotification = generateNotification(/* isForeground= */ true,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         additionalNotification.category = Notification.CATEGORY_MESSAGE;
         when(mAdditionalStatusBarNotification.getKey()).thenReturn("ADDITIONAL");
         when(mAdditionalStatusBarNotification.getGroupKey()).thenReturn(GROUP_KEY_C);
@@ -1159,7 +1146,6 @@ public class PreprocessingManagerTest {
 
         List<NotificationGroup> newList =
                 mPreprocessingManager.updateNotifications(
-                        /* showLessImportantNotifications= */ false,
                         additionalAlertEntry,
                         CarNotificationListener.NOTIFY_NOTIFICATION_POSTED,
                         mRankingMap);
@@ -1192,6 +1178,7 @@ public class PreprocessingManagerTest {
         mLessImportantForeground = new AlertEntry(mStatusBarNotification2);
         mMedia = new AlertEntry(mStatusBarNotification3);
         mNavigation = new AlertEntry(mStatusBarNotification4);
+        mProgress = new AlertEntry(mStatusBarNotification13);
         mImportantBackground = new AlertEntry(mStatusBarNotification5);
         mImportantForeground = new AlertEntry(mStatusBarNotification6);
         if (includeAdditionalNotifs) {
@@ -1216,6 +1203,7 @@ public class PreprocessingManagerTest {
             mAlertEntries.add(mImportantForeground6);
             mAlertEntries.add(mImportantForeground7);
         }
+        mAlertEntries.add(mProgress);
         mAlertEntriesMap = new HashMap<>();
         mAlertEntriesMap.put(mLessImportantBackground.getKey(), mLessImportantBackground);
         mAlertEntriesMap.put(mLessImportantForeground.getKey(), mLessImportantForeground);
@@ -1231,6 +1219,7 @@ public class PreprocessingManagerTest {
             mAlertEntriesMap.put(mImportantForeground6.getKey(), mImportantForeground6);
             mAlertEntriesMap.put(mImportantForeground7.getKey(), mImportantForeground7);
         }
+        mAlertEntriesMap.put(mProgress.getKey(), mProgress);
         mRankingMap = generateRankingMap(mAlertEntries);
     }
 
@@ -1250,13 +1239,18 @@ public class PreprocessingManagerTest {
     }
 
     private Notification generateNotification(boolean isForeground, boolean isNavigation,
-            boolean isGroupSummary) {
-        Notification notification = new Notification.Builder(mContext, CHANNEL_ID)
+            boolean isGroupSummary, boolean isProgress) {
+        Notification.Builder builder = new Notification.Builder(mContext, CHANNEL_ID)
                 .setContentTitle(CONTENT_TITLE)
                 .setSmallIcon(android.R.drawable.sym_def_app_icon)
                 .setGroup(OVERRIDE_GROUP_KEY)
-                .setGroupSummary(isGroupSummary)
-                .build();
+                .setGroupSummary(isGroupSummary);
+
+        if (isProgress) {
+            builder.setProgress(100, 0, false);
+        }
+
+        Notification notification = builder.build();
 
         if (isForeground) {
             // this will reset flags previously set like FLAG_GROUP_SUMMARY
@@ -1318,7 +1312,8 @@ public class PreprocessingManagerTest {
                     getRankingAdjustment(i),
                     isBubble(i),
                     /* proposedImportance= */ 0,
-                    /* sensitiveContent= */ false
+                    /* sensitiveContent= */ false,
+                    /* summarization = */ null
             );
             rankings[i] = ranking;
         }
@@ -1332,8 +1327,9 @@ public class PreprocessingManagerTest {
     private void generateNotificationsWithSameGroupKey(int numberOfNotifications, String groupKey) {
         for (int i = 0; i < numberOfNotifications; i++) {
             String key = "BASE_KEY_" + i;
-            Notification notification = generateNotification(/* isForeground= */ false,
-                    /* isNavigation= */ false, /* isGroupSummary= */ false);
+            Notification notification =
+                    generateNotification(/* isForeground= */ false, /* isNavigation= */ false,
+                            /* isGroupSummary= */ false, /* isProgress= */ false);
             StatusBarNotification sbn = mock(StatusBarNotification.class);
             when(sbn.getNotification()).thenReturn(notification);
             when(sbn.getKey()).thenReturn(key);
@@ -1346,7 +1342,7 @@ public class PreprocessingManagerTest {
 
     private void generateGroupSummaryNotification(String groupKey) {
         Notification groupSummary = generateNotification(/* isForeground= */ false,
-                /* isNavigation= */ false, /* isGroupSummary= */ true);
+                /* isNavigation= */ false, /* isGroupSummary= */ true, /* isProgress= */ false);
         StatusBarNotification sbn = mock(StatusBarNotification.class);
         when(sbn.getNotification()).thenReturn(groupSummary);
         when(sbn.getKey()).thenReturn("KEY_GROUP_SUMMARY");
```

