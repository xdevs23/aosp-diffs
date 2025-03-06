```diff
diff --git a/res/layout/car_notification_body_view.xml b/res/layout/car_notification_body_view.xml
index e195eb10..0d2495bf 100644
--- a/res/layout/car_notification_body_view.xml
+++ b/res/layout/car_notification_body_view.xml
@@ -25,47 +25,52 @@
         android:layout_marginStart="@dimen/body_big_icon_margin"
         style="@style/NotificationBodyImageIcon"/>
 
-    <TextView
-        android:id="@+id/notification_body_title"
+    <LinearLayout
+        android:id="@+id/notification_body_title_container"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_alignTop="@id/notification_body_icon"
         android:layout_toEndOf="@id/notification_body_icon"
         android:layout_alignWithParentIfMissing="true"
         android:layout_marginStart="@dimen/card_start_margin"
-        android:layout_marginEnd="@dimen/notification_body_title_margin"
-        style="@style/NotificationBodyTitleText"/>
+        android:gravity="center_vertical"
+        android:orientation="horizontal">
 
-    <ImageView
-        android:id="@+id/notification_body_title_icon"
-        android:layout_width="@dimen/notification_secondary_icon_size"
-        android:layout_height="@dimen/notification_secondary_icon_size"
-        android:layout_toEndOf="@id/notification_body_title"
-        android:layout_marginEnd="@dimen/notification_body_title_margin"
-        android:layout_marginTop="@dimen/notification_title_icon_top_margin"
-        android:adjustViewBounds="true"
-        android:background="@null"
-        android:clickable="false"
-        android:focusable="false"
-        android:scaleType="fitXY"/>
+        <TextView
+            android:id="@+id/notification_body_title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/notification_body_title_margin"
+            style="@style/NotificationBodyTitleText"/>
 
-    <DateTimeView
-        android:id="@+id/time"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:layout_toEndOf="@id/notification_body_title_icon"
-        android:layout_alignTop="@id/notification_body_title"
-        android:layout_alignBottom="@id/notification_body_title"
-        android:layout_marginEnd="@dimen/notification_body_title_margin"
-        android:gravity="center_vertical"
-        style="@style/NotificationHeaderText"/>
+        <ImageView
+            android:id="@+id/notification_body_title_icon"
+            android:layout_width="@dimen/notification_secondary_icon_size"
+            android:layout_height="@dimen/notification_secondary_icon_size"
+            android:layout_marginEnd="@dimen/notification_body_title_margin"
+            android:layout_marginTop="@dimen/notification_title_icon_top_margin"
+            android:adjustViewBounds="true"
+            android:background="@null"
+            android:clickable="false"
+            android:focusable="false"
+            android:scaleType="fitXY"/>
+
+        <DateTimeView
+            android:id="@+id/time"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginEnd="@dimen/notification_body_title_margin"
+            android:gravity="center_vertical"
+            style="@style/NotificationHeaderText"/>
+    </LinearLayout>
 
     <TextView
         android:id="@+id/notification_body_content"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
-        android:layout_alignStart="@id/notification_body_title"
-        android:layout_below="@id/notification_body_title"
+        android:layout_alignStart="@id/notification_body_title_container"
+        android:layout_below="@id/notification_body_title_container"
+        android:layout_alignWithParentIfMissing="true"
         android:layout_marginEnd="@dimen/card_end_margin"
         android:layout_marginTop="@dimen/notification_body_content_top_margin"
         style="@style/NotificationBodyContentText"/>
diff --git a/res/layout/headsup_container_bottom.xml b/res/layout/headsup_container_bottom.xml
index b89ad647..86f2ea2a 100644
--- a/res/layout/headsup_container_bottom.xml
+++ b/res/layout/headsup_container_bottom.xml
@@ -48,7 +48,7 @@
 
     <com.android.car.notification.headsup.HeadsUpContainerView
         android:id="@+id/headsup_content"
-        android:layout_width="wrap_content"
+        android:layout_width="match_parent"
         android:layout_height="wrap_content"
         android:layout_marginTop="@dimen/headsup_notification_top_margin"
         app:layout_constraintEnd_toStartOf="parent"
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 2594cefb..1ab4bfd1 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -51,7 +51,7 @@
     </plurals>
     <string name="see_more_message" msgid="6343183827924395955">"Prikaži više"</string>
     <string name="restricted_hun_message_content" msgid="631111937988857716">"Nova poruka"</string>
-    <string name="manage_text" msgid="4225197445283791757">"Upravljaj"</string>
+    <string name="manage_text" msgid="4225197445283791757">"Upravljajte"</string>
     <string name="category_navigation" msgid="4406139232918521087">"navigacija"</string>
     <string name="category_call" msgid="2249490790700877973">"poziv"</string>
     <string name="category_message" msgid="451360226248504859">"msg"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 3618f4df..2d9e95e8 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -19,7 +19,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="5911862216123243843">"Auto märguandehaldur"</string>
     <string name="assist_action_play_label" msgid="6278705468288338172">"Esita"</string>
-    <string name="assist_action_reply_label" msgid="6946087036560525072">"Vastamine"</string>
+    <string name="assist_action_reply_label" msgid="6946087036560525072">"Vasta"</string>
     <string name="action_mute_short" msgid="5239851786101022633">"Vaigista"</string>
     <string name="action_mute_long" msgid="6846675719189989477">"Vaigista vestlus"</string>
     <string name="action_unmute_short" msgid="7157822835069715986">"Tühista vaigistus"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index b0c4fa97..c07f6c41 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -20,7 +20,7 @@
     <string name="app_label" msgid="5911862216123243843">"Autoko jakinarazpenen kudeatzailea"</string>
     <string name="assist_action_play_label" msgid="6278705468288338172">"Erreproduzitu"</string>
     <string name="assist_action_reply_label" msgid="6946087036560525072">"Erantzun"</string>
-    <string name="action_mute_short" msgid="5239851786101022633">"Desaktibatu audioa"</string>
+    <string name="action_mute_short" msgid="5239851786101022633">"Ezkutatu"</string>
     <string name="action_mute_long" msgid="6846675719189989477">"Ezkutatu elkarrizketa"</string>
     <string name="action_unmute_short" msgid="7157822835069715986">"Aktibatu audioa"</string>
     <string name="action_unmute_long" msgid="22482625837159466">"Erakutsi elkarrizketa"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 375edd3d..d7e21e1b 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -51,7 +51,7 @@
     </plurals>
     <string name="see_more_message" msgid="6343183827924395955">"Pogledajte više"</string>
     <string name="restricted_hun_message_content" msgid="631111937988857716">"Nova poruka"</string>
-    <string name="manage_text" msgid="4225197445283791757">"Upravljanje"</string>
+    <string name="manage_text" msgid="4225197445283791757">"Upravljaj"</string>
     <string name="category_navigation" msgid="4406139232918521087">"kretanje"</string>
     <string name="category_call" msgid="2249490790700877973">"poziv"</string>
     <string name="category_message" msgid="451360226248504859">"por"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index e1fa7e39..10c67f88 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -34,7 +34,7 @@
     <string name="show_more" msgid="7291378544926443344">"कम देखाउनुहोस्"</string>
     <string name="notification_header" msgid="324550431063568049">"सूचनाहरू"</string>
     <string name="notification_recents" msgid="5855769440781958546">"हालैका"</string>
-    <string name="notification_older" msgid="8162161020296499690">"अझ पुराना सूचनाहरू"</string>
+    <string name="notification_older" msgid="8162161020296499690">"अझ पुराना नोटिफिकेसनहरू"</string>
     <string name="empty_notification_header" msgid="4928379791607839720">"कुनै पनि सूचना छैन"</string>
     <string name="collapse_group" msgid="3487426973871208501">"कम देखाउनुहोस्"</string>
     <string name="show_more_from_app" msgid="4270626118092846628">"<xliff:g id="APP">%2$s</xliff:g> बाट प्राप्त थप <xliff:g id="COUNT">%1$d</xliff:g> सूचनाहरू"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 47b9900b..3f97c18a 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -18,9 +18,9 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="5911862216123243843">"କାର ବିଜ୍ଞପ୍ତି ମେନେଜର"</string>
-    <string name="assist_action_play_label" msgid="6278705468288338172">"ଚଲାନ୍ତୁ"</string>
-    <string name="assist_action_reply_label" msgid="6946087036560525072">"ପ୍ରତ୍ୟୁତ୍ତର କରନ୍ତୁ"</string>
-    <string name="action_mute_short" msgid="5239851786101022633">"ମ୍ୟୁଟ୍ କରନ୍ତୁ"</string>
+    <string name="assist_action_play_label" msgid="6278705468288338172">"ପ୍ଲେ କରନ୍ତୁ"</string>
+    <string name="assist_action_reply_label" msgid="6946087036560525072">"ପ୍ରତ୍ୟୁତ୍ତର ଦିଅନ୍ତୁ"</string>
+    <string name="action_mute_short" msgid="5239851786101022633">"ମ୍ୟୁଟ କରନ୍ତୁ"</string>
     <string name="action_mute_long" msgid="6846675719189989477">"ବାର୍ତ୍ତାଳାପ ମ୍ୟୁଟ୍ କରନ୍ତୁ"</string>
     <string name="action_unmute_short" msgid="7157822835069715986">"ଅନ୍‍ମ୍ୟୁଟ୍ କରନ୍ତୁ"</string>
     <string name="action_unmute_long" msgid="22482625837159466">"ବାର୍ତ୍ତାଳାପ ଅନ୍‍ମ୍ୟୁଟ୍ କରନ୍ତୁ"</string>
@@ -34,7 +34,7 @@
     <string name="show_more" msgid="7291378544926443344">"ଅଧିକ ଦେଖାନ୍ତୁ"</string>
     <string name="notification_header" msgid="324550431063568049">"ବିଜ୍ଞପ୍ତିଗୁଡ଼ିକ"</string>
     <string name="notification_recents" msgid="5855769440781958546">"ବର୍ତ୍ତମାନର"</string>
-    <string name="notification_older" msgid="8162161020296499690">"ପୁରୁଣା ବିଜ୍ଞପ୍ତିଗୁଡ଼ିକ"</string>
+    <string name="notification_older" msgid="8162161020296499690">"ପୁରୁଣା ବିଜ୍ଞପ୍ତି"</string>
     <string name="empty_notification_header" msgid="4928379791607839720">"କୌଣସି ବିଜ୍ଞପ୍ତି ନାହିଁ"</string>
     <string name="collapse_group" msgid="3487426973871208501">"କମ ଦେଖାନ୍ତୁ"</string>
     <string name="show_more_from_app" msgid="4270626118092846628">"<xliff:g id="APP">%2$s</xliff:g>ରୁ <xliff:g id="COUNT">%1$d</xliff:g>ଟି ଅଧିକ"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index a46bdd37..de782517 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -34,7 +34,7 @@
     <string name="show_more" msgid="7291378544926443344">"显示更多"</string>
     <string name="notification_header" msgid="324550431063568049">"通知"</string>
     <string name="notification_recents" msgid="5855769440781958546">"近期通知"</string>
-    <string name="notification_older" msgid="8162161020296499690">"时间较早的通知"</string>
+    <string name="notification_older" msgid="8162161020296499690">"较早的通知"</string>
     <string name="empty_notification_header" msgid="4928379791607839720">"没有通知"</string>
     <string name="collapse_group" msgid="3487426973871208501">"收起"</string>
     <string name="show_more_from_app" msgid="4270626118092846628">"“<xliff:g id="APP">%2$s</xliff:g>”还有 <xliff:g id="COUNT">%1$d</xliff:g> 条通知"</string>
diff --git a/src/com/android/car/notification/template/CarNotificationBodyView.java b/src/com/android/car/notification/template/CarNotificationBodyView.java
index d8d1e26b..cd94c116 100644
--- a/src/com/android/car/notification/template/CarNotificationBodyView.java
+++ b/src/com/android/car/notification/template/CarNotificationBodyView.java
@@ -184,13 +184,21 @@ public class CarNotificationBodyView extends RelativeLayout {
         }
 
         if (mTitleView != null) {
-            mTitleView.setVisibility(View.VISIBLE);
-            mTitleView.setText(title);
+            if (!TextUtils.isEmpty(title)) {
+                mTitleView.setVisibility(View.VISIBLE);
+                mTitleView.setText(title);
+            } else {
+                mTitleView.setVisibility(View.GONE);
+            }
         }
 
-        if (mTitleIconView != null && titleIcon != null) {
-            mTitleIconView.setVisibility(View.VISIBLE);
-            mTitleIconView.setImageDrawable(titleIcon);
+        if (mTitleIconView != null) {
+            if (titleIcon != null) {
+                mTitleIconView.setVisibility(View.VISIBLE);
+                mTitleIconView.setImageDrawable(titleIcon);
+            } else {
+                mTitleIconView.setVisibility(View.GONE);
+            }
         }
 
         if (mContentView != null) {
```

