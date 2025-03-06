```diff
diff --git a/app/Android.bp b/app/Android.bp
index 8537aca7..fde4bd58 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -27,6 +27,7 @@ genrule {
 
 carlauncher_srcs = [
     "src/**/*.java",
+    "src/**/*.kt",
     ":statslog-carlauncher-java-gen",
 ]
 
diff --git a/app/AndroidManifest.xml b/app/AndroidManifest.xml
index 50f4d47b..b6100e22 100644
--- a/app/AndroidManifest.xml
+++ b/app/AndroidManifest.xml
@@ -163,6 +163,16 @@
                 android:name="com.android.settings.category"
                 android:value="com.android.settings.category.ia.display"/>
         </activity>
+        <activity android:name="com.android.car.carlauncher.homescreen.MapTosActivity"
+            android:taskAffinity=""
+            android:launchMode="singleTask"
+            android:allowEmbedded="true"
+            android:alwaysRetainTaskState="true"
+            android:screenOrientation="user"
+            android:resizeableActivity="true"
+            android:exported="true">
+            <meta-data android:name="distractionOptimized" android:value="true"/>
+        </activity>
 
         <provider android:name=".calmmode.CalmModeQCProvider"
                   android:authorities="com.android.car.carlauncher.calmmode"
diff --git a/app/car_launcher_flags.aconfig b/app/car_launcher_flags.aconfig
index e7a16d2f..c213b7ee 100644
--- a/app/car_launcher_flags.aconfig
+++ b/app/car_launcher_flags.aconfig
@@ -21,3 +21,10 @@ flag {
   description: "This flag controls Media widget redesign"
   bug: "310686518"
 }
+
+flag {
+  name: "tos_restrictions_enabled"
+  namespace: "car_sys_exp"
+  description: "This flag controls the terms of service restriction experience"
+  bug: "369672428"
+}
diff --git a/app/res/anim/media_card_panel_handlebar_fade_in.xml b/app/res/anim/media_card_panel_handlebar_fade_in.xml
new file mode 100644
index 00000000..cc9d586d
--- /dev/null
+++ b/app/res/anim/media_card_panel_handlebar_fade_in.xml
@@ -0,0 +1,21 @@
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<alpha xmlns:android="http://schemas.android.com/apk/res/android"
+    android:duration="@integer/media_card_panel_handlebar_fade_duration"
+    android:fromAlpha="0.0"
+    android:toAlpha="1.0"
+    android:fillAfter="true"/>
diff --git a/app/res/anim/media_card_panel_handlebar_fade_out.xml b/app/res/anim/media_card_panel_handlebar_fade_out.xml
new file mode 100644
index 00000000..67736878
--- /dev/null
+++ b/app/res/anim/media_card_panel_handlebar_fade_out.xml
@@ -0,0 +1,21 @@
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<alpha xmlns:android="http://schemas.android.com/apk/res/android"
+    android:duration="@integer/media_card_panel_handlebar_fade_duration"
+    android:fromAlpha="1.0"
+    android:toAlpha="0.0"
+    android:fillAfter="true"/>
diff --git a/app/res/drawable/ic_dialpad.xml b/app/res/drawable/ic_dialpad.xml
index 638b37b2..b84d0ac4 100644
--- a/app/res/drawable/ic_dialpad.xml
+++ b/app/res/drawable/ic_dialpad.xml
@@ -19,7 +19,8 @@
         android:width="@dimen/home_card_button_size"
         android:height="@dimen/home_card_button_size"
         android:viewportWidth="24"
-        android:viewportHeight="24">
+        android:viewportHeight="24"
+        android:tint="@color/dialer_icon_tint_state_list">
     <path
         android:pathData="M12,19c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM6,1c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM6,7c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM6,13c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM18,5c1.1,0 2,-0.9 2,-2s-0.9,-2 -2,-2 -2,0.9 -2,2 0.9,2 2,2zM12,13c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM18,13c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM18,7c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM12,7c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2zM12,1c-1.1,0 -2,0.9 -2,2s0.9,2 2,2 2,-0.9 2,-2 -0.9,-2 -2,-2z"
         android:fillColor="@color/dialer_button_icon_color"/>
diff --git a/app/res/drawable/media_card_default_album_art.xml b/app/res/drawable/media_card_default_album_art.xml
new file mode 100644
index 00000000..242dbcec
--- /dev/null
+++ b/app/res/drawable/media_card_default_album_art.xml
@@ -0,0 +1,38 @@
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
+    <item>
+        <shape>
+            <solid android:color="@color/car_surface_variant"/>
+        </shape>
+    </item>
+    <item
+        android:top="10dp"
+        android:bottom="10dp"
+        android:start="10dp"
+        android:end="10dp">
+        <vector
+            android:width="24dp"
+            android:height="24dp"
+            android:viewportWidth="960"
+            android:viewportHeight="960">
+            <path
+                android:pathData="M400,840q-66,0 -113,-47t-47,-113q0,-66 47,-113t113,-47q23,0 42.5,5.5T480,542v-422h240v160L560,280v400q0,66 -47,113t-113,47Z"
+                android:fillColor="@color/car_inverse_on_surface"/>
+        </vector>
+    </item>
+</layer-list>
diff --git a/app/res/layout/map_tos_activity.xml b/app/res/layout/map_tos_activity.xml
new file mode 100644
index 00000000..46f69d93
--- /dev/null
+++ b/app/res/layout/map_tos_activity.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+  <FrameLayout
+      xmlns:android="http://schemas.android.com/apk/res/android"
+      android:background="@color/car_green_500"
+      android:layout_width="match_parent"
+      android:layout_height="match_parent" >
+
+      <com.android.car.ui.uxr.DrawableStateTextView
+          android:id="@+id/review_button"
+          android:layout_width="wrap_content"
+          android:layout_height="wrap_content"
+          android:textColor="@color/car_text_primary"/>
+  </FrameLayout>
\ No newline at end of file
diff --git a/app/res/layout/media_card_fullscreen.xml b/app/res/layout/media_card_fullscreen.xml
index 10ad76eb..ba6167e1 100644
--- a/app/res/layout/media_card_fullscreen.xml
+++ b/app/res/layout/media_card_fullscreen.xml
@@ -74,7 +74,9 @@
             android:layout_height="@dimen/media_card_album_art_size"
             android:scaleType="fitCenter"
             android:adjustViewBounds="true"
-            android:background="@android:color/transparent"
+            android:background="@drawable/radius_16_background"
+            android:src="@drawable/media_card_default_album_art"
+            android:clipToOutline="true"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginEnd="@dimen/media_card_album_art_end_margin"
             android:layout_marginTop="@dimen/media_card_horizontal_margin"
diff --git a/app/res/layout/media_card_history_header_item.xml b/app/res/layout/media_card_history_header_item.xml
index 5b073e37..c3c47e1f 100644
--- a/app/res/layout/media_card_history_header_item.xml
+++ b/app/res/layout/media_card_history_header_item.xml
@@ -23,7 +23,6 @@
         android:id="@+id/history_card_header_icon"
         android:layout_width="@dimen/media_card_view_header_icon_size"
         android:layout_height="@dimen/media_card_view_header_icon_size"
-        android:layout_marginStart="@dimen/media_card_horizontal_margin"
         android:layout_marginEnd="@dimen/media_card_view_separation_margin"
         android:src="@drawable/ic_history"/>
 
diff --git a/app/res/layout/media_card_history_item.xml b/app/res/layout/media_card_history_item.xml
index eeb9bb47..ad8350be 100644
--- a/app/res/layout/media_card_history_item.xml
+++ b/app/res/layout/media_card_history_item.xml
@@ -21,8 +21,7 @@
     android:layout_width="match_parent"
     android:foreground="?android:attr/selectableItemBackground"
     app:cardBackgroundColor="@android:color/transparent"
-    app:contentPaddingLeft="@dimen/media_card_horizontal_margin"
-    app:contentPaddingRight="@dimen/media_card_horizontal_margin">
+    app:cardElevation="0dp">
     <androidx.constraintlayout.widget.ConstraintLayout
         android:id="@+id/history_card_container_active"
         android:layout_height="match_parent"
diff --git a/app/res/layout/media_card_panel_content_item.xml b/app/res/layout/media_card_panel_content_item.xml
index 1c11c1b1..c27b8385 100644
--- a/app/res/layout/media_card_panel_content_item.xml
+++ b/app/res/layout/media_card_panel_content_item.xml
@@ -90,8 +90,7 @@
         android:id="@+id/queue_list_container"
         android:layout_width="match_parent"
         android:layout_height="match_parent"
-        android:paddingStart="@dimen/media_card_horizontal_margin"
-        android:paddingEnd="@dimen/media_card_horizontal_margin"
+        android:paddingHorizontal="@dimen/media_card_horizontal_margin"
         android:background="@color/car_surface_container_highest"
         android:visibility="gone">
         <com.android.car.apps.common.CarUiRecyclerViewNoScrollbar
@@ -107,6 +106,7 @@
         android:id="@+id/history_list_container"
         android:layout_width="match_parent"
         android:layout_height="match_parent"
+        android:paddingHorizontal="@dimen/media_card_horizontal_margin"
         android:background="@color/car_surface_container_highest"
         android:visibility="gone">
         <com.android.car.apps.common.CarUiRecyclerViewNoScrollbar
diff --git a/app/res/values-af/strings.xml b/app/res/values-af/strings.xml
index 99cd4c67..5b71dc13 100644
--- a/app/res/values-af/strings.xml
+++ b/app/res/values-af/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App is nie beskikbaar nie"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Kalmmodus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Waglys"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Mediabron"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps is gedeaktiveer. Diensbepalings is nie aanvaar nie"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps is gedeaktiveer. Hersien ná jou rit."</string>
 </resources>
diff --git a/app/res/values-am/strings.xml b/app/res/values-am/strings.xml
index 1106cb86..784bc528 100644
--- a/app/res/values-am/strings.xml
+++ b/app/res/values-am/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"መተግበሪያ አይገኝም"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"የእርጋታ ሁነታ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ሰልፍ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"የሚዲያ ምንጭ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"ካርታዎች ተሰናክሏል። የአገልግሎት ውል ተቀባይነት አላገኘም"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"ካርታዎች ተሰናክሏል። ከነዱ በኋላ ይገምግሙ።"</string>
 </resources>
diff --git a/app/res/values-ar/strings.xml b/app/res/values-ar/strings.xml
index 1eedd067..1eccf2fb 100644
--- a/app/res/values-ar/strings.xml
+++ b/app/res/values-ar/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"التطبيق غير متاح."</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"وضع الهدوء"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"قائمة المحتوى التالي"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"مصدر الوسائط"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"تطبيق \"خرائط Google\" غير مفعّل. لم يتم قبول بنود الخدمة"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"تطبيق \"خرائط Google\" غير مفعّل. يمكنك مراجعة ذلك بعد الانتهاء من القيادة."</string>
 </resources>
diff --git a/app/res/values-as/strings.xml b/app/res/values-as/strings.xml
index a2afc9f9..2b4b252c 100644
--- a/app/res/values-as/strings.xml
+++ b/app/res/values-as/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"এপ্‌টো উপলব্ধ নহয়"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"শান্ত ম’ড"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"শাৰী"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"মিডিয়াৰ উৎস"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps অক্ষম কৰা আছে। সেৱাৰ চৰ্তাৱলী গ্ৰহণ কৰা নাই।"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps অক্ষম কৰা আছে। আপুনি গাড়ী চলাই হ’লে পৰ্যালোচনা কৰক।"</string>
 </resources>
diff --git a/app/res/values-az/strings.xml b/app/res/values-az/strings.xml
index d35931b3..a7ad0ae5 100644
--- a/app/res/values-az/strings.xml
+++ b/app/res/values-az/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Tətbiq əlçatan deyil"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Sakit rejim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Növbə"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Media mənbəyi"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Xəritə deaktiv edilib. Xidmət şərtləri qəbul edilməyib"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Xəritə deaktiv edilib. Sürdükdən sonra nəzərdən keçirin."</string>
 </resources>
diff --git a/app/res/values-b+sr+Latn/strings.xml b/app/res/values-b+sr+Latn/strings.xml
index b08076ca..6c1bd124 100644
--- a/app/res/values-b+sr+Latn/strings.xml
+++ b/app/res/values-b+sr+Latn/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija nije dostupna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Režim opuštanja"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Redosled"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Izvor medija"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Mape su onemogućene. Niste prihvatili uslove korišćenja"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Mape su onemogućene. Ocenite posle vožnje."</string>
 </resources>
diff --git a/app/res/values-be/strings.xml b/app/res/values-be/strings.xml
index 1029f33f..69231f35 100644
--- a/app/res/values-be/strings.xml
+++ b/app/res/values-be/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Праграма недаступная"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Рэжым спакою"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Чарга"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Крыніца мультымедыя"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Карты адключаны. Умовы выкарыстання не прыняты."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Карты адключаны. Пакіньце водгук пасля паездкі."</string>
 </resources>
diff --git a/app/res/values-bg/strings.xml b/app/res/values-bg/strings.xml
index 37e0d595..cee4579f 100644
--- a/app/res/values-bg/strings.xml
+++ b/app/res/values-bg/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим на покой"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Опашка"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Източник на мултимедията"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Приложението Карти е деактивирано. Не са приети Общите условия"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Приложението Карти е деактивирано. Прегледайте, след като спрете да шофирате."</string>
 </resources>
diff --git a/app/res/values-bn/strings.xml b/app/res/values-bn/strings.xml
index 9bfb8c3e..26bf50ec 100644
--- a/app/res/values-bn/strings.xml
+++ b/app/res/values-bn/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"অ্যাপ উপলভ্য নেই"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm মোড"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"সারি"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"মিডিয়া সোর্স"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps বন্ধ করা হয়েছে। পরিষেবার শর্তাবলীতে সম্মতি দেওয়া হয়নি"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps বন্ধ করা হয়েছে। গাড়ি চালানো শেষ হলে পর্যালোচনা করুন।"</string>
 </resources>
diff --git a/app/res/values-bs/strings.xml b/app/res/values-bs/strings.xml
index 0ce67924..a04bd43b 100644
--- a/app/res/values-bs/strings.xml
+++ b/app/res/values-bs/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija nije dostupna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Način rada za opuštanje"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Red čekanja"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Izvor medijskog sadržaja"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Mape su onemogućene. Niste prihvatili Uslove korištenja usluge"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Mape su onemogućene. Napišite recenziju nakon vožnje."</string>
 </resources>
diff --git a/app/res/values-ca/strings.xml b/app/res/values-ca/strings.xml
index a8c75544..04438e0a 100644
--- a/app/res/values-ca/strings.xml
+++ b/app/res/values-ca/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"L\'aplicació no està disponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode de calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Cua"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Font del contingut multimèdia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps està desactivat. Condicions del servei no acceptades."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps està desactivat. Revisa després de conduir."</string>
 </resources>
diff --git a/app/res/values-cs/strings.xml b/app/res/values-cs/strings.xml
index aa9dae16..d2570086 100644
--- a/app/res/values-cs/strings.xml
+++ b/app/res/values-cs/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikace není k dispozici"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Klidný režim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fronta"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Zdroj médií"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Mapy jsou deaktivovány. Nepřijali jste smluvní podmínky."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Mapy jsou deaktivovány. Zkontrolujte to, až zastavíte."</string>
 </resources>
diff --git a/app/res/values-da/strings.xml b/app/res/values-da/strings.xml
index b3415440..7147bae8 100644
--- a/app/res/values-da/strings.xml
+++ b/app/res/values-da/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appen er ikke tilgængelig"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Beroligende tilstand"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kø"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Mediekilde"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps er deaktiveret. Servicevilkårene blev ikke accepteret."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps er deaktiveret. Gennemgå vilkårene, når køreturen er slut."</string>
 </resources>
diff --git a/app/res/values-de/strings.xml b/app/res/values-de/strings.xml
index d74c8807..7d04d18a 100644
--- a/app/res/values-de/strings.xml
+++ b/app/res/values-de/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App nicht verfügbar"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Ruhemodus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Wiedergabeliste"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Medienquelle"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps ist deaktiviert. Nutzungsbedingungen nicht akzeptiert."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps ist deaktiviert. Nach der Fahrt prüfen."</string>
 </resources>
diff --git a/app/res/values-el/strings.xml b/app/res/values-el/strings.xml
index 6afdf258..992252be 100644
--- a/app/res/values-el/strings.xml
+++ b/app/res/values-el/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Η εφαρμογή δεν είναι διαθέσιμη"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Λειτουργία ηρεμίας"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Ουρά"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Πηγή μέσων"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Οι Χάρτες είναι απενεργοποιημένοι. Οι Όροι Παροχής Υπηρεσιών δεν έγιναν αποδεκτοί"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Οι Χάρτες είναι απενεργοποιημένοι. Ελέγξτε μετά την οδήγηση."</string>
 </resources>
diff --git a/app/res/values-en-rAU/strings.xml b/app/res/values-en-rAU/strings.xml
index 6e93f7a4..d629b12e 100644
--- a/app/res/values-en-rAU/strings.xml
+++ b/app/res/values-en-rAU/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Media source"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps is disabled. Terms of Service not accepted"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps is disabled. Review after your drive."</string>
 </resources>
diff --git a/app/res/values-en-rCA/strings.xml b/app/res/values-en-rCA/strings.xml
index f3a023b2..896222f9 100644
--- a/app/res/values-en-rCA/strings.xml
+++ b/app/res/values-en-rCA/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Media Source"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps is disabled. Terms of service not accepted"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps is disabled. Review after your drive."</string>
 </resources>
diff --git a/app/res/values-en-rGB/strings.xml b/app/res/values-en-rGB/strings.xml
index 6e93f7a4..d629b12e 100644
--- a/app/res/values-en-rGB/strings.xml
+++ b/app/res/values-en-rGB/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Media source"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps is disabled. Terms of Service not accepted"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps is disabled. Review after your drive."</string>
 </resources>
diff --git a/app/res/values-en-rIN/strings.xml b/app/res/values-en-rIN/strings.xml
index 6e93f7a4..d629b12e 100644
--- a/app/res/values-en-rIN/strings.xml
+++ b/app/res/values-en-rIN/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App isn\'t available"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Media source"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps is disabled. Terms of Service not accepted"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps is disabled. Review after your drive."</string>
 </resources>
diff --git a/app/res/values-es-rUS/strings.xml b/app/res/values-es-rUS/strings.xml
index be3e667d..98d004ef 100644
--- a/app/res/values-es-rUS/strings.xml
+++ b/app/res/values-es-rUS/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"La app no está disponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fila"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Fuente multimedia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps está inhabilitado. No se aceptaron las Condiciones del Servicio."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps está inhabilitado. Comparte tu opinión luego de tu viaje."</string>
 </resources>
diff --git a/app/res/values-es/strings.xml b/app/res/values-es/strings.xml
index 1656039c..5390a158 100644
--- a/app/res/values-es/strings.xml
+++ b/app/res/values-es/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"La aplicación no está disponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo Calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Cola"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Fuente de contenido multimedia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps está inhabilitado. Términos del Servicio no aceptados."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps está inhabilitado. Revísalo cuando dejes de conducir."</string>
 </resources>
diff --git a/app/res/values-et/strings.xml b/app/res/values-et/strings.xml
index 6188298e..1f5647a8 100644
--- a/app/res/values-et/strings.xml
+++ b/app/res/values-et/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Rakendus ei ole saadaval"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Lõõgastusrežiim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Järjekord"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Meediaallikas"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps on keelatud. Teenusetingimustega pole nõustutud"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps on keelatud. Vaadake see pärast sõitu üle."</string>
 </resources>
diff --git a/app/res/values-eu/strings.xml b/app/res/values-eu/strings.xml
index f52428f8..b9bc33a0 100644
--- a/app/res/values-eu/strings.xml
+++ b/app/res/values-eu/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Ez dago erabilgarri aplikazioa"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modu lasaia"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Ilara"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Multimedia-iturburua"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps desgaituta dago. Zerbitzu-baldintzak onartzeke daude."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps desgaituta dago. Berrikusi gidatzen amaitu ondoren."</string>
 </resources>
diff --git a/app/res/values-fa/strings.xml b/app/res/values-fa/strings.xml
index c92cf39e..0982ade3 100644
--- a/app/res/values-fa/strings.xml
+++ b/app/res/values-fa/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"برنامه دردسترس نیست"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"حالت «آرام»"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"صف پخش"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"منبع رسانه"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"‫Maps غیرفعال است. «شرایط خدمات» پذیرفته نشده است."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"‫Maps غیرفعال است. پس‌از توقف مرور کنید."</string>
 </resources>
diff --git a/app/res/values-fi/strings.xml b/app/res/values-fi/strings.xml
index e125de8e..fbed423e 100644
--- a/app/res/values-fi/strings.xml
+++ b/app/res/values-fi/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Sovellus ei ole käytettävissä"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Rauhallinen tila"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Jono"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Medialähde"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps on poistettu käytöstä. Käyttöehtoja ei ole hyväksytty."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps on poistettu käytöstä. Tarkista ajamisen jälkeen."</string>
 </resources>
diff --git a/app/res/values-fr-rCA/strings.xml b/app/res/values-fr-rCA/strings.xml
index ce7dc0e5..7ca4d4fe 100644
--- a/app/res/values-fr-rCA/strings.xml
+++ b/app/res/values-fr-rCA/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"L\'application n\'est pas accessible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode Calme"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"File d\'attente"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Source du contenu multimédia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps est désactivée. Conditions d\'utilisation non acceptées"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps est désactivée. Vérifiez après avoir conduit."</string>
 </resources>
diff --git a/app/res/values-fr/strings.xml b/app/res/values-fr/strings.xml
index da78d0bf..8bd95389 100644
--- a/app/res/values-fr/strings.xml
+++ b/app/res/values-fr/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appli indisponible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode calme"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"File d\'attente"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Source multimédia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps est désactivé. Conditions d\'utilisation non acceptées"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps est désactivé. Consultez une fois à l\'arrêt."</string>
 </resources>
diff --git a/app/res/values-gl/strings.xml b/app/res/values-gl/strings.xml
index 070ed1e9..bdc6c199 100644
--- a/app/res/values-gl/strings.xml
+++ b/app/res/values-gl/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"A aplicación non está dispoñible"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo de calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Cola"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Fonte do contido multimedia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps está desactivado. Condicións de servizo non aceptadas"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps está desactivado. Revisar despois da condución."</string>
 </resources>
diff --git a/app/res/values-gu/strings.xml b/app/res/values-gu/strings.xml
index 129ad033..571ac032 100644
--- a/app/res/values-gu/strings.xml
+++ b/app/res/values-gu/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ઍપ ઉપલબ્ધ નથી"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"શાંત મોડ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"કતાર"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"મીડિયા સૉર્સ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps બંધ કરવામાં આવ્યું છે. સેવાની શરતો સ્વીકારી નથી"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps બંધ કરવામાં આવ્યું છે. તમારી ડ્રાઇવ પછી રિવ્યૂ કરો."</string>
 </resources>
diff --git a/app/res/values-hi/strings.xml b/app/res/values-hi/strings.xml
index 5402141a..06547873 100644
--- a/app/res/values-hi/strings.xml
+++ b/app/res/values-hi/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ऐप्लिकेशन उपलब्ध नहीं है"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"काम (शांत) मोड"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"सूची"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"मीडिया सोर्स"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps की सुविधा बंद है. सेवा की शर्तें स्वीकार नहीं की गई हैं"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps की सुविधा बंद है. ड्राइव करने के बाद समीक्षा करें."</string>
 </resources>
diff --git a/app/res/values-hr/strings.xml b/app/res/values-hr/strings.xml
index 3ce008d9..3e648ce0 100644
--- a/app/res/values-hr/strings.xml
+++ b/app/res/values-hr/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija nije dostupna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Način opuštanja"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Red čekanja"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Izvor medija"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Karte su onemogućene. Uvjeti pružanja usluge nisu prihvaćeni"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Karte su onemogućene. Pregledajte nakon vožnje."</string>
 </resources>
diff --git a/app/res/values-hu/strings.xml b/app/res/values-hu/strings.xml
index 6b626909..7172779e 100644
--- a/app/res/values-hu/strings.xml
+++ b/app/res/values-hu/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Nyugalom mód"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Lejátszási sor"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Médiaforrás"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"A Térkép le van tiltva. Nem fogadta el az Általános Szerződési Feltételeket."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"A Térkép le van tiltva. Ellenőrizze vezetés után."</string>
 </resources>
diff --git a/app/res/values-hy/strings.xml b/app/res/values-hy/strings.xml
index eaa87945..52f28713 100644
--- a/app/res/values-hy/strings.xml
+++ b/app/res/values-hy/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Հավելվածը հասանելի չէ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Հանգստի ռեժիմ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Հերթացանկ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Մեդիաֆայլի աղբյուրը"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Քարտեզներ ծառայությունն անջատված է։ Անհրաժեշտ է ընդունել օգտագործման պայմանները։"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Քարտեզներ ծառայությունն անջատված է։ Ծանոթացեք երթն ավարտելուց հետո։"</string>
 </resources>
diff --git a/app/res/values-in/strings.xml b/app/res/values-in/strings.xml
index 53d121c9..f403ba52 100644
--- a/app/res/values-in/strings.xml
+++ b/app/res/values-in/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikasi tidak tersedia"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Mode tenang"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Antrean"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Sumber Media"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps dinonaktifkan. Persyaratan layanan belum disetujui"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps dinonaktifkan. Tinjau setelah kendaraan terparkir."</string>
 </resources>
diff --git a/app/res/values-is/strings.xml b/app/res/values-is/strings.xml
index a4e628ef..0dbbe6a0 100644
--- a/app/res/values-is/strings.xml
+++ b/app/res/values-is/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Forritið er ekki í boði"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Róleg stilling"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Röð"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Uppruni efnis"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Slökkt er á Kortum. Þjónustuskilmálar ekki samþykktir"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Slökkt er á Kortum. Farðu yfir þegar akstri er lokið."</string>
 </resources>
diff --git a/app/res/values-it/strings.xml b/app/res/values-it/strings.xml
index 2c21e8ea..86fa2a9c 100644
--- a/app/res/values-it/strings.xml
+++ b/app/res/values-it/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Modalità Calma"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Coda"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Fonte di contenuti multimediali"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps è disattivato. Termini di servizio non accettati"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps è disattivato. Recensisci dopo la guida."</string>
 </resources>
diff --git a/app/res/values-iw/strings.xml b/app/res/values-iw/strings.xml
index 612cc52a..614df3d0 100644
--- a/app/res/values-iw/strings.xml
+++ b/app/res/values-iw/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"האפליקציה לא זמינה"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"מצב רגיעה"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"הבאים בתור"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"מקור המדיה"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"עוד אי אפשר להשתמש במפות Google. לא אישרת את התנאים וההגבלות"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"עוד אי אפשר להשתמש במפות Google. אפשר לבדוק את הפרטים אחרי הנסיעה."</string>
 </resources>
diff --git a/app/res/values-ja/strings.xml b/app/res/values-ja/strings.xml
index 2a37dd90..d2a56ae4 100644
--- a/app/res/values-ja/strings.xml
+++ b/app/res/values-ja/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm モード"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"キュー"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"メディアソース"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"マップが無効になっています。利用規約に同意していません。"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"マップが無効になっています。運転後に確認してください。"</string>
 </resources>
diff --git a/app/res/values-ka/strings.xml b/app/res/values-ka/strings.xml
index b8ebc5e9..13f60d8f 100644
--- a/app/res/values-ka/strings.xml
+++ b/app/res/values-ka/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"აპი მიუწვდომელია"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"წყნარი რეჟიმი"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"რიგი"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"მედიაწყარო"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps გათიშულია. მომსახურების პირობები არ არის დადასტურებული"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps გათიშულია. გადახედეთ მანქანის დასრულების შემდეგ."</string>
 </resources>
diff --git a/app/res/values-kk/strings.xml b/app/res/values-kk/strings.xml
index a8017a3e..bfd1f545 100644
--- a/app/res/values-kk/strings.xml
+++ b/app/res/values-kk/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Қолданба қолжетімді емес."</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Тыныштық режимі"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Кезек"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Медиа дереккөздері"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps өшірулі. Қызмет көрсету шарттары қабылданбады."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps өшірулі. Көлік жүргізіп болғаннан кейін қарап шығыңыз."</string>
 </resources>
diff --git a/app/res/values-km/strings.xml b/app/res/values-km/strings.xml
index 0a7471a8..efe5afef 100644
--- a/app/res/values-km/strings.xml
+++ b/app/res/values-km/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"មិន​មាន​កម្មវិធី"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"មុខងារស្ងាត់"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ជួរ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"ប្រភព​មេឌៀ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"ផែនទីត្រូវបានបិទ។ លក្ខខណ្ឌ​ប្រើប្រាស់មិនត្រូវបានទទួលយក"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"ផែនទីត្រូវបានបិទ។ សូមពិនិត្យមើល បន្ទាប់ពីការបើកបររបស់អ្នក។"</string>
 </resources>
diff --git a/app/res/values-kn/strings.xml b/app/res/values-kn/strings.xml
index d0df27f9..121b3ed7 100644
--- a/app/res/values-kn/strings.xml
+++ b/app/res/values-kn/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ಆ್ಯಪ್ ಲಭ್ಯವಿಲ್ಲ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ಶಾಂತ ಮೋಡ್"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ಸರದಿ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"ಮಾಧ್ಯಮದ ಮೂಲ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps ಅನ್ನು ನಿಷ್ಕ್ರಿಯಗೊಳಿಸಲಾಗಿದೆ. ಸೇವಾ ನಿಯಮಗಳನ್ನು ಸಮ್ಮತಿಸಲಾಗಿಲ್ಲ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps ಅನ್ನು ನಿಷ್ಕ್ರಿಯಗೊಳಿಸಲಾಗಿದೆ. ನಿಮ್ಮ ಡ್ರೈವ್‌ ನಂತರ ಪರಿಶೀಲಿಸಿ."</string>
 </resources>
diff --git a/app/res/values-ko/strings.xml b/app/res/values-ko/strings.xml
index 4c5bd057..861d119d 100644
--- a/app/res/values-ko/strings.xml
+++ b/app/res/values-ko/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"고요 모드"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"현재 재생목록"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"미디어 소스"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"지도가 사용 중지되었습니다. 서비스 약관에 동의하지 않았습니다."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"지도가 사용 중지되었습니다. 주행이 끝난 후 검토하세요."</string>
 </resources>
diff --git a/app/res/values-ky/strings.xml b/app/res/values-ky/strings.xml
index 8b453ede..c5d90258 100644
--- a/app/res/values-ky/strings.xml
+++ b/app/res/values-ky/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Колдонмо жеткиликтүү эмес"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Тынчтык режими"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Кезек"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Мультимедия булагы"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Карталар өчүрүлдү. Тейлөө шарттары кабыл алынган жок"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Карталар өчүрүлдү. Унааңызды айдап бүткөндөн кийин текшериңиз."</string>
 </resources>
diff --git a/app/res/values-lo/strings.xml b/app/res/values-lo/strings.xml
index e8dbde1f..dbbd1055 100644
--- a/app/res/values-lo/strings.xml
+++ b/app/res/values-lo/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ແອັບບໍ່ພ້ອມໃຫ້ນຳໃຊ້"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ໂໝດສະຫງົບ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ຄິວ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"ແຫຼ່ງທີ່ມາຂອງສື່"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"ແຜນທີ່ປິດການນຳໃຊ້ຢູ່. ຍັງບໍ່ໄດ້ຍອມຮັບຂໍ້ກຳນົດບໍລິການ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"ແຜນທີ່ປິດການນຳໃຊ້ຢູ່. ກະລຸນາກວດສອບຫຼັງຈາກການຂັບຂີ່ຂອງທ່ານ."</string>
 </resources>
diff --git a/app/res/values-lt/strings.xml b/app/res/values-lt/strings.xml
index 917f0ec4..b9b774c0 100644
--- a/app/res/values-lt/strings.xml
+++ b/app/res/values-lt/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Ramybės režimas"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Eilė"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Medijos šaltinis"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Žemėlapiai išjungti. Nesutikta su paslaugų teikimo sąlygomis"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Žemėlapiai išjungti. Peržiūrėkite po važiavimo."</string>
 </resources>
diff --git a/app/res/values-lv/strings.xml b/app/res/values-lv/strings.xml
index e9d276ce..5bc2f9d5 100644
--- a/app/res/values-lv/strings.xml
+++ b/app/res/values-lv/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Lietotne nav pieejama"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Miera režīms"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Rinda"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Multivides avots"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Pakalpojums Maps ir atspējots. Nav sniegta piekrišana pakalpojumu sniegšanas noteikumiem."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Pakalpojums Maps ir atspējots. Pārskatiet pēc brauciena pabeigšanas."</string>
 </resources>
diff --git a/app/res/values-mk/strings.xml b/app/res/values-mk/strings.xml
index f8e3d06f..437ff7ab 100644
--- a/app/res/values-mk/strings.xml
+++ b/app/res/values-mk/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Апликацијата не е достапна"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим на мирување"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Редица"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Извор на аудиовизуелни содржини"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"„Карти“ е оневозможена. „Условите за користење“ не се прифатени"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"„Карти“ е оневозможена. Прегледајте по возењето."</string>
 </resources>
diff --git a/app/res/values-ml/strings.xml b/app/res/values-ml/strings.xml
index 3c98b43c..d9df3e2f 100644
--- a/app/res/values-ml/strings.xml
+++ b/app/res/values-ml/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ആപ്പ് ലഭ്യമല്ല"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"\'ശാന്തം\' മോഡ്"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ക്യൂ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"മീഡിയാ ഉറവിടം"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps പ്രവർത്തനരഹിതമാക്കി. സേവന നിബന്ധനകൾ അംഗീകരിച്ചിട്ടില്ല"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps പ്രവർത്തനരഹിതമാക്കി. നിങ്ങൾ ഡ്രൈവ് ചെയ്ത ശേഷം റിവ്യൂ ചെയ്യുക."</string>
 </resources>
diff --git a/app/res/values-mn/strings.xml b/app/res/values-mn/strings.xml
index afc1c3fd..7f4a9b80 100644
--- a/app/res/values-mn/strings.xml
+++ b/app/res/values-mn/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Апп боломжгүй байна"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Тайван горим"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Дараалал"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Медиагийн эх сурвалж"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Газрын зургийг идэвхгүй болгосон. Үйлчилгээний нөхцөлийг зөвшөөрөөгүй"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Газрын зургийг идэвхгүй болгосон. Жолоо барьсаныхаа дараа шалгана уу."</string>
 </resources>
diff --git a/app/res/values-mr/strings.xml b/app/res/values-mr/strings.xml
index 0801e385..973f595f 100644
--- a/app/res/values-mr/strings.xml
+++ b/app/res/values-mr/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"अ‍ॅप उपलब्ध नाही"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"शांत मोड"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"क्यू"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"मीडिया स्रोत"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps बंद केलेले आहे. सेवा अटी स्वीकारलेल्या नाहीत"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps बंद केलेले आहे. तुम्ही ड्राइव्ह केल्यानंतर पुनरावलोकन करा."</string>
 </resources>
diff --git a/app/res/values-ms/strings.xml b/app/res/values-ms/strings.xml
index a5c1f393..7119fb35 100644
--- a/app/res/values-ms/strings.xml
+++ b/app/res/values-ms/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Mod Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Baris gilir"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Sumber Media"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps dilumpuhkan. Syarat perkhidmatan tidak diterima"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps dilumpuhkan. Ulas selepas anda memandu."</string>
 </resources>
diff --git a/app/res/values-my/strings.xml b/app/res/values-my/strings.xml
index 4401c9f7..8dcd6ff9 100644
--- a/app/res/values-my/strings.xml
+++ b/app/res/values-my/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"အငြိမ်မုဒ်"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"စာရင်းစဉ်"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"မီဒီယာရင်းမြစ်"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps ပိတ်ထားသည်။ ဝန်ဆောင်မှုစည်းမျဉ်းများကို လက်မခံပါ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps ပိတ်ထားသည်။ သင်ယာဉ်မောင်းပြီးနောက် စစ်ဆေးပါ။"</string>
 </resources>
diff --git a/app/res/values-nb/strings.xml b/app/res/values-nb/strings.xml
index 4e25c723..01fa4704 100644
--- a/app/res/values-nb/strings.xml
+++ b/app/res/values-nb/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appen er ikke tilgjengelig"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Roligmodus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kø"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Mediekilde"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps er deaktivert. Vilkårene for bruk er ikke godtatt."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps er deaktivert. Gå gjennom etter kjøreturen."</string>
 </resources>
diff --git a/app/res/values-ne/strings.xml b/app/res/values-ne/strings.xml
index d70c2d2e..d223782d 100644
--- a/app/res/values-ne/strings.xml
+++ b/app/res/values-ne/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"शान्त मोड"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"लाइन"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"मिडियाको स्रोत"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"नक्सा अफ गरिएको छ। सेवाका सर्तहरू स्वीकार गरिएको छैन"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"नक्सा अफ गरिएको छ। सवारी चलाईसकेपछि समीक्षा गर्नुहोस्।"</string>
 </resources>
diff --git a/app/res/values-nl/strings.xml b/app/res/values-nl/strings.xml
index 15535e6e..70dc9f80 100644
--- a/app/res/values-nl/strings.xml
+++ b/app/res/values-nl/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"App is niet beschikbaar"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Kalme modus"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Wachtrij"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Mediabron"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps staat uit. Servicevoorwaarden niet geaccepteerd."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps staat uit. Check dit na je rit."</string>
 </resources>
diff --git a/app/res/values-or/strings.xml b/app/res/values-or/strings.xml
index 1bfdf27d..a807d59e 100644
--- a/app/res/values-or/strings.xml
+++ b/app/res/values-or/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ଆପ ଉପଲବ୍ଧ ନାହିଁ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ଶାନ୍ତ ମୋଡ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ଧାଡ଼ି"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"ମିଡିଆ ସୋର୍ସ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Mapsକୁ ଅକ୍ଷମ କରାଯାଇଛି। ସେବାର ସର୍ତ୍ତାବଳୀକୁ ଗ୍ରହଣ କରାଯାଇନାହିଁ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Mapsକୁ ଅକ୍ଷମ କରାଯାଇଛି। ଆପଣଙ୍କ ଡ୍ରାଇଭ ପରେ ସମୀକ୍ଷା କରନ୍ତୁ।"</string>
 </resources>
diff --git a/app/res/values-pa/strings.xml b/app/res/values-pa/strings.xml
index 5bf3b065..64f63f1d 100644
--- a/app/res/values-pa/strings.xml
+++ b/app/res/values-pa/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ਐਪ ਉਪਲਬਧ ਨਹੀਂ ਹੈ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"ਸ਼ਾਂਤ ਮੋਡ"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"ਕਤਾਰ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"ਮੀਡੀਆ ਸਰੋਤ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps ਬੰਦ ਹੈ। ਸੇਵਾ ਦੇ ਨਿਯਮ ਸਵੀਕਾਰ ਨਹੀਂ ਕੀਤੇ ਗਏ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps ਬੰਦ ਹੈ। ਆਪਣੀ ਡਰਾਈਵ ਤੋਂ ਬਾਅਦ ਸਮੀਖਿਆ ਕਰੋ।"</string>
 </resources>
diff --git a/app/res/values-pl/strings.xml b/app/res/values-pl/strings.xml
index 73478c11..5d3f1caf 100644
--- a/app/res/values-pl/strings.xml
+++ b/app/res/values-pl/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacja jest niedostępna"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Tryb cichy"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kolejka"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Źródło multimediów"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Mapy są wyłączone. Nie zaakceptowano warunków usługi"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Mapy są wyłączone. Oceń po zakończeniu jazdy."</string>
 </resources>
diff --git a/app/res/values-pt-rPT/strings.xml b/app/res/values-pt-rPT/strings.xml
index a3f7bd26..d2bc248f 100644
--- a/app/res/values-pt-rPT/strings.xml
+++ b/app/res/values-pt-rPT/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fila"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"Origem de multimédia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"O Maps está desativado. Termos de Utilização não aceites"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"O Maps está desativado. Reveja após a condução."</string>
 </resources>
diff --git a/app/res/values-pt/strings.xml b/app/res/values-pt/strings.xml
index a4576c88..f3636b16 100644
--- a/app/res/values-pt/strings.xml
+++ b/app/res/values-pt/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"O app não está disponível"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modo foco"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Fila"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Fonte de mídia"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"O Maps está desativado. Termos de Serviço não aceitos."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"O Maps está desativado. Verifique depois de dirigir."</string>
 </resources>
diff --git a/app/res/values-ro/strings.xml b/app/res/values-ro/strings.xml
index 03f63b3a..7f67a613 100644
--- a/app/res/values-ro/strings.xml
+++ b/app/res/values-ro/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplicația nu este disponibilă"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modul Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Coadă"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Sursă media"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps este dezactivat. Termenii și condițiile nu au fost acceptate"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps este dezactivat. Examinează după călătorie."</string>
 </resources>
diff --git a/app/res/values-ru/strings.xml b/app/res/values-ru/strings.xml
index 49af8e88..2831a7e6 100644
--- a/app/res/values-ru/strings.xml
+++ b/app/res/values-ru/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Приложение недоступно"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим покоя"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Очередь"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Источник мультимедиа"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Карты отключены, поскольку не приняты Условия использования"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Карты отключены, проверьте, в чем дело, после поездки"</string>
 </resources>
diff --git a/app/res/values-si/strings.xml b/app/res/values-si/strings.xml
index 10c106f1..b6f13c9d 100644
--- a/app/res/values-si/strings.xml
+++ b/app/res/values-si/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"යෙදුම නොතිබේ"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"සන්සුන් ප්‍රකාරය"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"පෝලිම"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"මාධ්‍ය ප්‍රභවය"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"සිතියම් අබල කර ඇත. සේවා නියම පිළිගනු නොලැබේ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"සිතියම් අබල කර ඇත. ඔබේ ධාවනයෙන් පසු සමාලෝචනය කරන්න."</string>
 </resources>
diff --git a/app/res/values-sk/strings.xml b/app/res/values-sk/strings.xml
index 0ead5fad..c52d4495 100644
--- a/app/res/values-sk/strings.xml
+++ b/app/res/values-sk/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikácia nie je k dispozícii"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Pokojný režim"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Poradie"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Zdroj médií"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Mapy sú deaktivované. Zmluvné podmienky neboli prijaté."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Mapy sú deaktivované. Skontrolujte to po jazde."</string>
 </resources>
diff --git a/app/res/values-sl/strings.xml b/app/res/values-sl/strings.xml
index e26cdffe..c38d8e0d 100644
--- a/app/res/values-sl/strings.xml
+++ b/app/res/values-sl/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacija ni na voljo"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Umirjeni način"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Čakalna vrsta"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Vir predstavnosti"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Zemljevidi so onemogočeni. Pogoji storitve niso sprejeti"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Zemljevidi so onemogočeni. Preglejte po končani vožnji."</string>
 </resources>
diff --git a/app/res/values-sq/strings.xml b/app/res/values-sq/strings.xml
index 894da297..31064850 100644
--- a/app/res/values-sq/strings.xml
+++ b/app/res/values-sq/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Aplikacioni nuk ofrohet"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Modaliteti i qetësisë"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Radha"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Burimi i medias"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps është çaktivizuar. \"Kushtet e shërbimit\" nuk u pranuan"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps është çaktivizuar. Rishiko pas drejtimit të automjetit."</string>
 </resources>
diff --git a/app/res/values-sr/strings.xml b/app/res/values-sr/strings.xml
index 77a252c3..ab1019ae 100644
--- a/app/res/values-sr/strings.xml
+++ b/app/res/values-sr/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Апликација није доступна"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Режим опуштања"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Редослед"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Извор медија"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Мапе су онемогућене. Нисте прихватили услове коришћења"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Мапе су онемогућене. Оцените после вожње."</string>
 </resources>
diff --git a/app/res/values-sv/strings.xml b/app/res/values-sv/strings.xml
index 5aafac81..d51ddf21 100644
--- a/app/res/values-sv/strings.xml
+++ b/app/res/values-sv/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Appen är inte tillgänglig"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Lugnt läge"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Kö"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Mediekälla"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps är inaktiverat. Användarvillkoren har inte godkänts"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps är inaktiverat. Granska efter körturen."</string>
 </resources>
diff --git a/app/res/values-sw/strings.xml b/app/res/values-sw/strings.xml
index c150d0ba..00e983de 100644
--- a/app/res/values-sw/strings.xml
+++ b/app/res/values-sw/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Programu haipatikani"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Hali ya utulivu"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Foleni"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Chanzo cha Maudhui"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Programu ya Ramani imezimwa. Hujakubali Sheria na Masharti"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Programu ya Ramani imezimwa. Toa maoni ukimaliza kuendesha gari."</string>
 </resources>
diff --git a/app/res/values-ta/strings.xml b/app/res/values-ta/strings.xml
index 487493dc..ff6b1c43 100644
--- a/app/res/values-ta/strings.xml
+++ b/app/res/values-ta/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ஆப்ஸ் கிடைக்கவில்லை"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"அமைதிப் பயன்முறை"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"வரிசை"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"மீடியா ஆதாரம்"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps முடக்கப்பட்டுள்ளது. சேவை விதிமுறைகள் ஏற்கப்படவில்லை."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps முடக்கப்பட்டுள்ளது. பயன்படுத்திய பிறகு மதிப்பாய்வு செய்யுங்கள்."</string>
 </resources>
diff --git a/app/res/values-te/strings.xml b/app/res/values-te/strings.xml
index 08b5b895..f62412de 100644
--- a/app/res/values-te/strings.xml
+++ b/app/res/values-te/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"క్లెయిమ్ మోడ్"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"క్యూ"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"మీడియా సోర్స్"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps డిజేబుల్ అయ్యింది. సర్వీస్ నియమాలను ఆమోదించలేదు."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps డిజేబుల్ అయ్యింది. డ్రైవ్ చేసిన తర్వాత రివ్యూ చేయండి."</string>
 </resources>
diff --git a/app/res/values-th/strings.xml b/app/res/values-th/strings.xml
index f3c88edd..d2c87325 100644
--- a/app/res/values-th/strings.xml
+++ b/app/res/values-th/strings.xml
@@ -37,4 +37,6 @@
     <string name="calm_mode_title" msgid="4364804976931157567">"โหมด Calm"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"คิว"</string>
     <string name="media_card_history_header_title" msgid="8337396297165848931">"แหล่งที่มาของสื่อ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Maps ปิดใช้อยู่ ยังไม่ได้ยอมรับข้อกำหนดในการให้บริการ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Maps ปิดใช้อยู่ โปรดตรวจสอบหลังจากขับรถเสร็จ"</string>
 </resources>
diff --git a/app/res/values-tl/strings.xml b/app/res/values-tl/strings.xml
index cb390553..4c5c0099 100644
--- a/app/res/values-tl/strings.xml
+++ b/app/res/values-tl/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Hindi available ang app"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Calm mode"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Queue"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Source ng Media"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Naka-disable ang Maps. Hindi tinatanggap ang mga tuntunin ng serbisyo"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Naka-disable ang Maps. Suriin pagkatapos ng iyong pagmamaneho."</string>
 </resources>
diff --git a/app/res/values-tr/strings.xml b/app/res/values-tr/strings.xml
index 02522743..f2f23c71 100644
--- a/app/res/values-tr/strings.xml
+++ b/app/res/values-tr/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Uygulama kullanılamıyor"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Sakin mod"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Sıra"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Medya Kaynağı"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Haritalar devre dışı. Hizmet Şartları kabul edilmedi."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Haritalar devre dışı. Arabayı sürmeyi bıraktıktan sonra inceleyin."</string>
 </resources>
diff --git a/app/res/values-uk/strings.xml b/app/res/values-uk/strings.xml
index 7855e2ef..ac9e38ba 100644
--- a/app/res/values-uk/strings.xml
+++ b/app/res/values-uk/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Додаток недоступний"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Спокійний режим"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Черга"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Джерело мультимедіа"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Карти вимкнено. Не прийнято умови використання."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Карти вимкнено. Перегляньте після поїздки."</string>
 </resources>
diff --git a/app/res/values-ur/strings.xml b/app/res/values-ur/strings.xml
index f3510272..034c2d28 100644
--- a/app/res/values-ur/strings.xml
+++ b/app/res/values-ur/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"ایپ دستیاب نہیں ہے"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"پُرسکون وضع"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"قطار"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"میڈیا کا ماخذ"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"‫Maps غیر فعال ہے۔ سروس کی شرائط قبول نہیں کی گئیں"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"‫Maps غیر فعال ہے۔ اپنی ڈرائیو مکمل کرنے کے بعد جائزہ لیں۔"</string>
 </resources>
diff --git a/app/res/values-uz/strings.xml b/app/res/values-uz/strings.xml
index a0930d52..0b142fc2 100644
--- a/app/res/values-uz/strings.xml
+++ b/app/res/values-uz/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Ilova mavjud emas"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Dam olish rejimi"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Navbat"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Media manbasi"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Xaritalar faolsizlantirildi. Xizmat shartlari qabul qilinmagan."</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Xaritalar faolsizlantirildi. Safaringizdan keyin tekshiring."</string>
 </resources>
diff --git a/app/res/values-vi/strings.xml b/app/res/values-vi/strings.xml
index 1bb9e6e7..7d733349 100644
--- a/app/res/values-vi/strings.xml
+++ b/app/res/values-vi/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"Hiện không có ứng dụng"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Chế độ Tĩnh lặng"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Danh sách chờ"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Nguồn nội dung nghe nhìn"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"Đã tắt Maps. Chưa chấp nhận Điều khoản dịch vụ"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"Đã tắt Maps. Đánh giá sau khi bạn lái xe."</string>
 </resources>
diff --git a/app/res/values-zh-rCN/strings.xml b/app/res/values-zh-rCN/strings.xml
index fa238ed9..c65d453b 100644
--- a/app/res/values-zh-rCN/strings.xml
+++ b/app/res/values-zh-rCN/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"应用无法打开"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"平静模式"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"队列"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"媒体来源"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"地图已停用。尚未接受《服务条款》"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"地图已停用。请在停止驾车后查看。"</string>
 </resources>
diff --git a/app/res/values-zh-rHK/strings.xml b/app/res/values-zh-rHK/strings.xml
index b763bdcb..8812b95b 100644
--- a/app/res/values-zh-rHK/strings.xml
+++ b/app/res/values-zh-rHK/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"目前無法使用這個應用程式"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"平靜模式"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"序列"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"媒體來源"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"「地圖」已停用。並未接受《服務條款》"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"「地圖」已停用。請在駕駛完畢後再作檢查。"</string>
 </resources>
diff --git a/app/res/values-zh-rTW/strings.xml b/app/res/values-zh-rTW/strings.xml
index 1e55679c..2502a718 100644
--- a/app/res/values-zh-rTW/strings.xml
+++ b/app/res/values-zh-rTW/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"應用程式目前無法使用"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"平靜模式"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"待播清單"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"媒體來源"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"尚未接受《服務條款》，因此 Google 地圖已停用"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"地圖已停用。請先將車輛停妥，再詳閱《服務條款》。"</string>
 </resources>
diff --git a/app/res/values-zu/strings.xml b/app/res/values-zu/strings.xml
index 64b13a63..51160ff1 100644
--- a/app/res/values-zu/strings.xml
+++ b/app/res/values-zu/strings.xml
@@ -36,6 +36,7 @@
     <string name="failure_opening_recent_task_message" msgid="963567570097465902">"I-app ayitholakali"</string>
     <string name="calm_mode_title" msgid="4364804976931157567">"Imodi ezolile"</string>
     <string name="media_card_queue_header_title" msgid="8801994125708995575">"Ulayini"</string>
-    <!-- no translation found for media_card_history_header_title (8337396297165848931) -->
-    <skip />
+    <string name="media_card_history_header_title" msgid="8337396297165848931">"Umthombo Wemidiya"</string>
+    <string name="map_tos_review_button_text" msgid="5609545803755287215">"IMaps ikhutshaziwe. Imigomo Yesevisi ayamukelwe"</string>
+    <string name="map_tos_review_button_distraction_optimized_text" msgid="2126379934796527013">"IMaps ikhutshaziwe. Buyekeza ngemva kokushayela kwakho."</string>
 </resources>
diff --git a/app/res/values/integers.xml b/app/res/values/integers.xml
index cbd57462..84dba2c2 100644
--- a/app/res/values/integers.xml
+++ b/app/res/values/integers.xml
@@ -27,4 +27,7 @@ limitations under the License.
 
     <!-- Fullscreen media card animation duration in ms -->
     <integer name="media_card_bottom_panel_open_duration">400</integer>
+
+    <!-- Fullscreen media card panel handlebar animation duration in ms -->
+    <integer name="media_card_panel_handlebar_fade_duration">200</integer>
 </resources>
diff --git a/app/res/values/overlayable.xml b/app/res/values/overlayable.xml
index d4c72efd..0b7979bb 100644
--- a/app/res/values/overlayable.xml
+++ b/app/res/values/overlayable.xml
@@ -20,6 +20,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="animator" name="recents_clear_all"/>
       <item type="anim" name="fade_in"/>
       <item type="anim" name="fade_out"/>
+      <item type="anim" name="media_card_panel_handlebar_fade_in"/>
+      <item type="anim" name="media_card_panel_handlebar_fade_out"/>
       <item type="array" name="config_homeCardModuleClasses"/>
       <item type="array" name="config_homeCardPreferredMapActivities"/>
       <item type="array" name="config_taskViewPackages"/>
@@ -169,6 +171,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="drawable" name="ic_search_black"/>
       <item type="drawable" name="ic_temperature"/>
       <item type="drawable" name="media_card_button_panel_background"/>
+      <item type="drawable" name="media_card_default_album_art"/>
       <item type="drawable" name="media_card_panel_button_shape"/>
       <item type="drawable" name="media_card_panel_handlebar"/>
       <item type="drawable" name="media_card_seekbar_progress"/>
@@ -264,6 +267,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="id" name="recent_tasks_list"/>
       <item type="id" name="recent_tasks_list_focus_area"/>
       <item type="id" name="recents_clear_all_button"/>
+      <item type="id" name="review_button"/>
       <item type="id" name="secondary_text"/>
       <item type="id" name="start_edge"/>
       <item type="id" name="subtitle"/>
@@ -286,6 +290,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="integer" name="calm_mode_content_fade_duration"/>
       <item type="integer" name="card_content_text_block_max_lines"/>
       <item type="integer" name="media_card_bottom_panel_open_duration"/>
+      <item type="integer" name="media_card_panel_handlebar_fade_duration"/>
       <item type="integer" name="optional_seekbar_max"/>
       <item type="integer" name="playback_controls_bar_columns"/>
       <item type="layout" name="button_trio"/>
@@ -301,6 +306,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="layout" name="card_fragment_audio_card"/>
       <item type="layout" name="control_bar_container"/>
       <item type="layout" name="descriptive_text"/>
+      <item type="layout" name="map_tos_activity"/>
       <item type="layout" name="media_card_fullscreen"/>
       <item type="layout" name="media_card_history_header_item"/>
       <item type="layout" name="media_card_history_item"/>
@@ -326,6 +332,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="string" name="failure_opening_recent_task_message"/>
       <item type="string" name="fake_weather_footer_text"/>
       <item type="string" name="fake_weather_main_text"/>
+      <item type="string" name="map_tos_review_button_distraction_optimized_text"/>
+      <item type="string" name="map_tos_review_button_text"/>
       <item type="string" name="media_card_history_header_title"/>
       <item type="string" name="media_card_queue_header_title"/>
       <item type="string" name="ongoing_call_duration_text_separator"/>
diff --git a/app/res/values/strings.xml b/app/res/values/strings.xml
index bcb5546b..bf62ad1f 100644
--- a/app/res/values/strings.xml
+++ b/app/res/values/strings.xml
@@ -61,4 +61,8 @@
     <!-- Fullscreen media card strings -->
     <string name="media_card_queue_header_title">Queue</string>
     <string name="media_card_history_header_title">Media Source</string>
+
+    <!-- MapTos strings -->
+    <string name="map_tos_review_button_text">Maps is disabled. Terms of service not accepted</string>
+    <string name="map_tos_review_button_distraction_optimized_text">Maps is disabled. Review after your drive.</string>
 </resources>
diff --git a/app/src/com/android/car/carlauncher/CarLauncher.java b/app/src/com/android/car/carlauncher/CarLauncher.java
index d256a058..368e203c 100644
--- a/app/src/com/android/car/carlauncher/CarLauncher.java
+++ b/app/src/com/android/car/carlauncher/CarLauncher.java
@@ -47,6 +47,7 @@ import androidx.lifecycle.ViewModelProvider;
 
 import com.android.car.carlauncher.homescreen.HomeCardModule;
 import com.android.car.carlauncher.homescreen.audio.IntentHandler;
+import com.android.car.carlauncher.homescreen.audio.dialer.InCallIntentRouter;
 import com.android.car.carlauncher.homescreen.audio.media.MediaIntentRouter;
 import com.android.car.carlauncher.taskstack.TaskStackChangeListeners;
 import com.android.car.internal.common.UserHelperLite;
@@ -110,7 +111,7 @@ public class CarLauncher extends FragmentActivity {
         }
     };
 
-    private final IntentHandler mMediaIntentHandler = new IntentHandler() {
+    private final IntentHandler mIntentHandler = new IntentHandler() {
         @Override
         public void handleIntent(Intent intent) {
             if (intent != null) {
@@ -173,16 +174,16 @@ public class CarLauncher extends FragmentActivity {
             }
         }
 
-        MediaIntentRouter.getInstance().registerMediaIntentHandler(mMediaIntentHandler);
+        MediaIntentRouter.getInstance().registerMediaIntentHandler(mIntentHandler);
+        InCallIntentRouter.getInstance().registerInCallIntentHandler(mIntentHandler);
         initializeCards();
         setupContentObserversForTos();
     }
 
     private void setupRemoteCarTaskView(ViewGroup parent) {
         mCarLauncherViewModel = new ViewModelProvider(this,
-                new CarLauncherViewModelFactory(this))
+                new CarLauncherViewModelFactory(this, getMapsIntent()))
                 .get(CarLauncherViewModel.class);
-        mCarLauncherViewModel.initializeRemoteCarTaskView(getMapsIntent());
 
         getLifecycle().addObserver(mCarLauncherViewModel);
         addOnNewIntentListener(mCarLauncherViewModel.getNewIntentListener());
@@ -315,18 +316,6 @@ public class CarLauncher extends FragmentActivity {
                 ? CarLauncherUtils.getSmallCanvasOptimizedMapIntent(this)
                 : CarLauncherUtils.getMapsIntent(this);
 
-        String packageName = mapIntent.getComponent() != null
-                ? mapIntent.getComponent().getPackageName()
-                : null;
-        Set<String> tosDisabledPackages = AppLauncherUtils.getTosDisabledPackages(this);
-
-        // Launch tos map intent when the user has not accepted tos and when the
-        // default maps package is not available to package manager, or it's disabled by tos
-        if (!AppLauncherUtils.tosAccepted(this)
-                && (packageName == null || tosDisabledPackages.contains(packageName))) {
-            mapIntent = CarLauncherUtils.getTosMapIntent(this);
-            Log.i(TAG, "Launching tos activity in task view");
-        }
         // Don't want to show this Activity in Recents.
         mapIntent.addFlags(Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS);
         return mapIntent;
@@ -356,9 +345,10 @@ public class CarLauncher extends FragmentActivity {
                 if (DEBUG) {
                     Log.d(TAG, "TOS disabled apps:" + tosDisabledApps);
                 }
-                if (mCarLauncherViewModel.getRemoteCarTaskView().getValue() != null) {
-                    mCarLauncherViewModel.getRemoteCarTaskView().getValue().release();
-                    setupRemoteCarTaskView(mMapsCard);
+                if (mCarLauncherViewModel != null
+                        && mCarLauncherViewModel.getRemoteCarTaskView().getValue() != null) {
+                    // Reinitialize the remote car task view with the new maps intent
+                    mCarLauncherViewModel.initializeRemoteCarTaskView(getMapsIntent());
                 }
                 if (tosAccepted) {
                     unregisterTosContentObserver();
diff --git a/app/src/com/android/car/carlauncher/CarLauncherUtils.java b/app/src/com/android/car/carlauncher/CarLauncherUtils.java
index 9440ed07..b5804d7e 100644
--- a/app/src/com/android/car/carlauncher/CarLauncherUtils.java
+++ b/app/src/com/android/car/carlauncher/CarLauncherUtils.java
@@ -22,7 +22,10 @@ import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.util.Log;
 
+import com.google.common.annotations.VisibleForTesting;
+
 import java.net.URISyntaxException;
+import java.util.Set;
 
 /**
  * Utils for CarLauncher package.
@@ -63,25 +66,10 @@ public class CarLauncherUtils {
             }
 
             if (preferredIntent.resolveActivityInfo(pm, /* flags= */ 0) != null) {
-                return preferredIntent;
+                return maybeReplaceWithTosMapIntent(context, preferredIntent);
             }
         }
-        return defaultIntent;
-    }
-
-    /**
-     * Return an intent used to launch the tos map activity
-     * @param context The application context
-     * @return Tos Intent, null if the config is incorrect
-     */
-    public static Intent getTosMapIntent(Context context) {
-        String intentString = context.getString(R.string.config_tosMapIntent);
-        try {
-            return Intent.parseUri(intentString, Intent.URI_ANDROID_APP_SCHEME);
-        } catch (URISyntaxException se) {
-            Log.w(TAG, "Invalid intent URI in config_tosMapIntent", se);
-            return null;
-        }
+        return maybeReplaceWithTosMapIntent(context, defaultIntent);
     }
 
     /**
@@ -114,11 +102,44 @@ public class CarLauncherUtils {
         try {
             Intent intent = Intent.parseUri(intentString, Intent.URI_INTENT_SCHEME);
             intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-            return intent;
+            return maybeReplaceWithTosMapIntent(context, intent);
         } catch (URISyntaxException e) {
             Log.w(TAG, "Invalid intent URI in config_smallCanvasOptimizedMapIntent: \""
                     + intentString + "\". Falling back to fullscreen map.");
-            return getMapsIntent(context);
+            return maybeReplaceWithTosMapIntent(context, getMapsIntent(context));
+        }
+    }
+
+    private static Intent maybeReplaceWithTosMapIntent(Context context, Intent mapIntent) {
+        String packageName = mapIntent.getComponent() != null
+                ? mapIntent.getComponent().getPackageName()
+                : null;
+        Set<String> tosDisabledPackages = AppLauncherUtils.getTosDisabledPackages(context);
+
+        // Launch tos map intent when the user has not accepted tos and when the
+        // default maps package is not available to package manager, or it's disabled by tos
+        if (!AppLauncherUtils.tosAccepted(context)
+                && (packageName == null || tosDisabledPackages.contains(packageName))) {
+            Log.i(TAG, "Replacing default maps intent with tos map intent");
+            mapIntent = getTosMapIntent(context);
+        }
+        return mapIntent;
+    }
+
+    /**
+     * Return an intent used to launch the tos map activity
+     * @param context The application context
+     * @return Tos Intent, null if the config is incorrect
+     */
+    @VisibleForTesting
+    public static Intent getTosMapIntent(Context context) {
+        String intentString = context.getString(R.string.config_tosMapIntent);
+        try {
+            return Intent.parseUri(intentString, Intent.URI_ANDROID_APP_SCHEME);
+        } catch (URISyntaxException se) {
+            Log.w(TAG, "Invalid intent URI in config_tosMapIntent", se);
+            return null;
         }
     }
+
 }
diff --git a/app/src/com/android/car/carlauncher/CarLauncherViewModel.java b/app/src/com/android/car/carlauncher/CarLauncherViewModel.java
index 3b2b0813..2acbfa89 100644
--- a/app/src/com/android/car/carlauncher/CarLauncherViewModel.java
+++ b/app/src/com/android/car/carlauncher/CarLauncherViewModel.java
@@ -48,6 +48,8 @@ import androidx.lifecycle.MutableLiveData;
 import androidx.lifecycle.ViewModel;
 import androidx.lifecycle.ViewModelProvider;
 
+import com.google.common.annotations.VisibleForTesting;
+
 /**
  * A car launcher view model to manage the lifecycle of {@link RemoteCarTaskView}.
  */
@@ -66,21 +68,27 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
     private CarTaskViewControllerHostLifecycle mHostLifecycle;
     private MutableLiveData<RemoteCarTaskView> mRemoteCarTaskView;
 
-    public CarLauncherViewModel(@UiContext Context context) {
+    public CarLauncherViewModel(@UiContext Context context, Intent mapsIntent) {
         mWindowContext = context.createWindowContext(TYPE_APPLICATION_STARTING, /* options */ null);
         mCar = Car.createCar(mWindowContext);
         mCarActivityManager = mCar.getCarManager(CarActivityManager.class);
+        initializeRemoteCarTaskView(mapsIntent);
     }
 
     /**
      * Initialize the remote car task view with the maps intent.
      */
-    void initializeRemoteCarTaskView(@NonNull Intent mapsIntent) {
+    public void initializeRemoteCarTaskView(@NonNull Intent mapsIntent) {
         if (DEBUG) {
             Log.d(TAG, "Maps intent in the task view = " + mapsIntent.getComponent());
         }
         mMapsIntent = mapsIntent;
-        mRemoteCarTaskView = new MutableLiveData<>(null);
+        if (mRemoteCarTaskView != null && mRemoteCarTaskView.getValue() != null) {
+            // Release the remote car task view instance if it exists since otherwise there could
+            // be a memory leak
+            mRemoteCarTaskView.getValue().release();
+        }
+        mRemoteCarTaskView = new MutableLiveData<>(/* value= */ null);
         mHostLifecycle = new CarTaskViewControllerHostLifecycle();
         ControlledRemoteCarTaskViewCallback controlledRemoteCarTaskViewCallback =
                 new ControlledRemoteCarTaskViewCallbackImpl(mRemoteCarTaskView);
@@ -96,6 +104,11 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
         return mRemoteCarTaskView;
     }
 
+    @VisibleForTesting
+    Intent getMapsIntent() {
+        return mMapsIntent;
+    }
+
     /**
      * Returns remote car task view task Id.
      */
@@ -164,6 +177,9 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
 
         @Override
         public void onTaskViewCreated(@NonNull ControlledRemoteCarTaskView taskView) {
+            if (DEBUG) {
+                Log.d(TAG, "MapsTaskView: onTaskViewCreated");
+            }
             mRemoteCarTaskView.setValue(taskView);
         }
 
@@ -220,24 +236,23 @@ public final class CarLauncherViewModel extends ViewModel implements DefaultLife
 
         @Override
         public void onDisconnected(@NonNull CarTaskViewController carTaskViewController) {
-            if (DEBUG) {
-                Log.d(TAG, "onDisconnected");
-            }
             mRemoteCarTaskView.setValue(null);
         }
     }
 
     static final class CarLauncherViewModelFactory implements ViewModelProvider.Factory {
         private final Context mContext;
+        private final Intent mMapsIntent;
 
-        CarLauncherViewModelFactory(@UiContext Context context) {
+        CarLauncherViewModelFactory(@UiContext Context context, @NonNull Intent mapsIntent) {
+            mMapsIntent = requireNonNull(mapsIntent);
             mContext = requireNonNull(context);
         }
 
         @NonNull
         @Override
         public <T extends ViewModel> T create(Class<T> modelClass) {
-            return modelClass.cast(new CarLauncherViewModel(mContext));
+            return modelClass.cast(new CarLauncherViewModel(mContext, mMapsIntent));
         }
     }
 }
diff --git a/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt b/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt
new file mode 100644
index 00000000..a73301fa
--- /dev/null
+++ b/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt
@@ -0,0 +1,143 @@
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
+
+package com.android.car.carlauncher.homescreen
+
+import android.car.Car
+import android.car.drivingstate.CarUxRestrictionsManager
+import android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS
+import android.database.ContentObserver
+import android.os.Bundle
+import android.os.Handler
+import android.os.Looper
+import android.provider.Settings
+import android.util.Log
+import androidx.appcompat.app.AppCompatActivity
+import androidx.lifecycle.lifecycleScope
+import com.android.car.carlauncher.AppLauncherUtils
+import com.android.car.carlauncher.Flags
+import com.android.car.carlauncher.R
+import com.android.car.ui.utils.CarUiUtils
+import com.android.car.ui.uxr.DrawableStateTextView
+import com.google.common.annotations.VisibleForTesting
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.withContext
+
+/**
+ * A placeholder map activity to display when terms of service have not been accepted.
+ *
+ * This activity can be used to launch an activity to help the user accept terms of service.
+ */
+class MapTosActivity : AppCompatActivity() {
+    private val bgDispatcher: CoroutineDispatcher = Dispatchers.Default
+    @VisibleForTesting lateinit var reviewButton: DrawableStateTextView
+    private var car: Car? = null
+    @VisibleForTesting var tosContentObserver: ContentObserver? = null
+
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+
+        setContentView(R.layout.map_tos_activity)
+        reviewButton = findViewById(R.id.review_button)
+        reviewButton.setOnClickListener {
+            val tosIntent = AppLauncherUtils.getIntentForTosAcceptanceFlow(it.context)
+            log("Launching tos acceptance activity")
+            AppLauncherUtils.launchApp(it.context, tosIntent)
+        }
+
+        setupCarUxRestrictionsListener()
+        handleReviewButtonDistractionOptimized(requiresDistractionOptimization = false)
+
+        if (Flags.tosRestrictionsEnabled()) {
+            setupContentObserverForTos()
+        }
+    }
+
+    override fun onDestroy() {
+        car?.getCarManager(CarUxRestrictionsManager::class.java)?.unregisterListener()
+        car?.disconnect()
+
+        if (Flags.tosRestrictionsEnabled()) {
+            unregisterContentObserverForTos()
+        }
+
+        super.onDestroy()
+    }
+
+    private fun setupCarUxRestrictionsListener() = lifecycleScope.launch {
+        withContext(bgDispatcher) {
+            car = Car.createCar(baseContext)
+        }
+        val carUxRestrictionsManager = car?.getCarManager(CarUxRestrictionsManager::class.java)
+        carUxRestrictionsManager?.registerListener {
+            handleReviewButtonDistractionOptimized(it.isRequiresDistractionOptimization)
+        }
+        val requiresDistractionOptimization = carUxRestrictionsManager
+            ?.currentCarUxRestrictions
+            ?.isRequiresDistractionOptimization ?: false
+        handleReviewButtonDistractionOptimized(requiresDistractionOptimization)
+    }
+
+    //  TODO: b/319266967 - Remove annotation once FakeCarUxRestrictionsService allows setting
+    //  requiresDistractionOptimization
+    @VisibleForTesting
+    fun handleReviewButtonDistractionOptimized(requiresDistractionOptimization: Boolean) {
+        CarUiUtils.makeAllViewsEnabled(
+            reviewButton,
+            !requiresDistractionOptimization // enabled
+        )
+        when (requiresDistractionOptimization) {
+            true -> reviewButton.setText(R.string.map_tos_review_button_distraction_optimized_text)
+            false -> reviewButton.setText(R.string.map_tos_review_button_text)
+        }
+    }
+
+    private fun setupContentObserverForTos() {
+        tosContentObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
+            override fun onChange(selfChange: Boolean) {
+                val tosAccepted = AppLauncherUtils.tosAccepted(applicationContext)
+                log("TOS state updated:$tosAccepted")
+                if (tosAccepted) {
+                    finish()
+                }
+            }
+        }.also {
+            contentResolver.registerContentObserver(
+                Settings.Secure.getUriFor(KEY_UNACCEPTED_TOS_DISABLED_APPS),
+                false, // notifyForDescendants
+                it
+            )
+        }
+    }
+
+    private fun unregisterContentObserverForTos() {
+        tosContentObserver?.let { contentResolver.unregisterContentObserver(it) }
+        tosContentObserver = null
+    }
+
+    private companion object {
+        const val TAG = "MapTosActivity"
+        val DEBUG = Log.isLoggable(TAG, Log.DEBUG)
+
+        fun log(msg: String) {
+            if (DEBUG) {
+                Log.d(TAG, msg)
+            }
+        }
+    }
+}
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java
index f24281c9..710dc4f6 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java
@@ -16,13 +16,7 @@
 
 package com.android.car.carlauncher.homescreen.audio;
 
-import android.os.SystemClock;
-
-import androidx.annotation.NonNull;
-import androidx.lifecycle.ViewModelProvider;
-
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
-import com.android.car.carlauncher.homescreen.audio.dialer.DialerCardModel;
 
 /** A wrapper around {@code MediaViewModel} and {@code InCallModel}. */
 public class AudioCardModel implements HomeCardInterface.Model {
@@ -30,9 +24,9 @@ public class AudioCardModel implements HomeCardInterface.Model {
     private final MediaViewModel mMediaViewModel;
     private final InCallModel mInCallViewModel;
 
-    public AudioCardModel(@NonNull ViewModelProvider viewModelProvider) {
-        mMediaViewModel = viewModelProvider.get(MediaViewModel.class);
-        mInCallViewModel = new DialerCardModel(SystemClock.elapsedRealtimeClock());
+    public AudioCardModel(MediaViewModel mediaViewModel, InCallModel inCallModel) {
+        mMediaViewModel = mediaViewModel;
+        mInCallViewModel = inCallModel;
     }
 
     MediaViewModel getMediaViewModel() {
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java
index fec78a8a..67ba0676 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java
@@ -16,6 +16,8 @@
 
 package com.android.car.carlauncher.homescreen.audio;
 
+import android.os.SystemClock;
+
 import androidx.lifecycle.ViewModelProvider;
 
 import com.android.car.carlauncher.R;
@@ -32,6 +34,7 @@ public class AudioCardModule implements HomeCardModule {
     protected AudioCardPresenter mAudioCardPresenter;
     protected HomeCardInterface.View mAudioCardView;
     protected ViewModelProvider mViewModelProvider;
+
     @Override
     public void setViewModelProvider(ViewModelProvider viewModelProvider) {
         if (mViewModelProvider != null) {
@@ -41,7 +44,10 @@ public class AudioCardModule implements HomeCardModule {
 
         mAudioCardPresenter = new AudioCardPresenter(
                 new DialerCardPresenter(), new MediaCardPresenter());
-        mAudioCardPresenter.setModel(new AudioCardModel(mViewModelProvider));
+        AudioCardModel audioCardModel = new AudioCardModel(
+                viewModelProvider.get(MediaViewModel.class),
+                new InCallModel(SystemClock.elapsedRealtimeClock()));
+        mAudioCardPresenter.setModel(audioCardModel);
         mAudioCardView = new AudioCardFragment();
         mAudioCardPresenter.setView(mAudioCardView);
     }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
index 9f49eca6..d87b2465 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
@@ -19,7 +19,6 @@ package com.android.car.carlauncher.homescreen.audio;
 import static android.content.pm.PackageManager.GET_RESOLVED_FILTER;
 
 import android.Manifest;
-import android.app.ActivityOptions;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -32,7 +31,6 @@ import android.telecom.PhoneAccountHandle;
 import android.telecom.TelecomManager;
 import android.text.TextUtils;
 import android.util.Log;
-import android.view.Display;
 import android.view.View;
 
 import androidx.annotation.NonNull;
@@ -40,6 +38,7 @@ import androidx.annotation.Nullable;
 import androidx.core.content.ContextCompat;
 
 import com.android.car.carlauncher.R;
+import com.android.car.carlauncher.homescreen.audio.dialer.InCallIntentRouter;
 import com.android.car.carlauncher.homescreen.audio.telecom.InCallServiceImpl;
 import com.android.car.carlauncher.homescreen.ui.CardContent;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
@@ -73,27 +72,29 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
     private static final boolean DEBUG = false;
     protected static InCallServiceManager sInCallServiceManager;
 
-    private Context mContext;
+    protected Context mContext;
     private TelecomManager mTelecomManager;
 
     private PackageManager mPackageManager;
     private final Clock mElapsedTimeClock;
 
-    private Call mCurrentCall;
+    protected Call mCurrentCall;
     private CompletableFuture<Void> mPhoneNumberInfoFuture;
 
-    private InCallServiceImpl mInCallService;
+    protected InCallServiceImpl mInCallService;
 
     private CardHeader mDefaultDialerCardHeader;
     private CardHeader mCardHeader;
     private CardContent mCardContent;
     private CharSequence mOngoingCallSubtitle;
     private CharSequence mDialingCallSubtitle;
-    private DescriptiveTextWithControlsView.Control mMuteButton;
-    private DescriptiveTextWithControlsView.Control mEndCallButton;
-    private DescriptiveTextWithControlsView.Control mDialpadButton;
+    protected DescriptiveTextWithControlsView.Control mMuteButton;
+    protected DescriptiveTextWithControlsView.Control mEndCallButton;
+    protected DescriptiveTextWithControlsView.Control mDialpadButton;
     private Drawable mContactImageBackground;
-    private OnModelUpdateListener mOnModelUpdateListener;
+    protected OnModelUpdateListener mOnModelUpdateListener;
+
+    protected final InCallIntentRouter mInCallIntentRouter = InCallIntentRouter.getInstance();
 
     private Call.Callback mCallback = new Call.Callback() {
         @Override
@@ -195,12 +196,7 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
     public void onClick(View view) {
         Intent intent = getIntent();
         if (intent != null) {
-            // Launch activity in the default app task container: the display area where
-            // applications are launched by default.
-            // If not set, activity launches in the calling TDA.
-            ActivityOptions options = ActivityOptions.makeBasic();
-            options.setLaunchDisplayId(Display.DEFAULT_DISPLAY);
-            mContext.startActivity(intent, options.toBundle());
+            mInCallIntentRouter.handleInCallIntent(intent);
         } else {
             if (DEBUG) {
                 Log.d(TAG, "No launch intent found to show in call ui for call : " + mCurrentCall);
@@ -208,6 +204,11 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         }
     }
 
+    /** Indicates whether there is an active call or not. */
+    public boolean hasActiveCall() {
+        return mCurrentCall != null;
+    }
+
     /**
      * When a {@link Call} is added, notify the {@link HomeCardInterface.Presenter} to update the
      * card to display content on the ongoing phone call.
@@ -395,7 +396,7 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         }
     }
 
-    private void initializeAudioControls() {
+    protected void initializeAudioControls() {
         mMuteButton = new DescriptiveTextWithControlsView.Control(
                 mContext.getDrawable(R.drawable.ic_mute_activatable),
                 v -> {
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
index e320c1cd..4aeef026 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
@@ -33,13 +33,13 @@ import androidx.lifecycle.Observer;
 import com.android.car.apps.common.imaging.ImageBinder;
 import com.android.car.carlauncher.Flags;
 import com.android.car.carlauncher.MediaSessionUtils;
+import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
 import com.android.car.carlauncher.homescreen.ui.CardContent;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
 import com.android.car.carlauncher.homescreen.ui.SeekBarViewModel;
 import com.android.car.media.common.MediaItemMetadata;
-import com.android.car.media.common.R;
 import com.android.car.media.common.playback.PlaybackProgress;
 import com.android.car.media.common.playback.PlaybackViewModel;
 import com.android.car.media.common.source.MediaModels;
@@ -158,7 +158,8 @@ public class MediaViewModel extends AndroidViewModel implements AudioModel {
 
         mContext = context;
         Resources resources = mContext.getResources();
-        int max = resources.getInteger(R.integer.media_items_bitmap_max_size_px);
+        int max = resources.getInteger(
+                com.android.car.media.common.R.integer.media_items_bitmap_max_size_px);
         mMediaBackground = resources
                 .getDrawable(R.drawable.control_bar_image_background);
         Size maxArtSize = new Size(max, max);
@@ -174,12 +175,10 @@ public class MediaViewModel extends AndroidViewModel implements AudioModel {
         mPlaybackViewModel.getPlaybackController().observeForever(mPlaybackControllerObserver);
         mPlaybackViewModel.getPlaybackStateWrapper().observeForever(mPlaybackStateWrapperObserver);
 
-        mSeekBarColor = mDefaultSeekBarColor = resources.getColor(
-                com.android.car.carlauncher.R.color.seek_bar_color, null);
-        mSeekBarMax = resources.getInteger(
-                com.android.car.carlauncher.R.integer.optional_seekbar_max);
+        mSeekBarColor = mDefaultSeekBarColor = resources.getColor(R.color.seek_bar_color, null);
+        mSeekBarMax = resources.getInteger(R.integer.optional_seekbar_max);
         mUseMediaSourceColor = resources.getBoolean(R.bool.use_media_source_color_for_seek_bar);
-        mTimesSeparator = resources.getString(com.android.car.carlauncher.R.string.times_separator);
+        mTimesSeparator = resources.getString(R.string.times_separator);
         mOnModelUpdateListener.onModelUpdate(/* model = */ this);
 
         updateModel(); // Make sure the name of the media source properly reflects the locale.
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardModel.java
deleted file mode 100644
index 8f1372ec..00000000
--- a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardModel.java
+++ /dev/null
@@ -1,91 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package com.android.car.carlauncher.homescreen.audio.dialer;
-
-import android.telecom.Call;
-
-import com.android.car.carlauncher.homescreen.audio.InCallModel;
-import com.android.car.telephony.common.CallDetail;
-
-import org.jetbrains.annotations.NotNull;
-
-import java.time.Clock;
-import java.util.List;
-
-/** A wrapper around InCallModel to track when an active call is in progress. */
-public class DialerCardModel extends InCallModel {
-
-    private boolean mHasActiveCall;
-    private List<Integer> mAvailableRoutes;
-    private int mActiveRoute;
-
-    public DialerCardModel(Clock elapsedTimeClock) {
-        super(elapsedTimeClock);
-    }
-
-    /** Indicates whether there is an active call or not. */
-    public boolean hasActiveCall() {
-        return mHasActiveCall;
-    }
-
-    @Override
-    public void onCallAdded(Call call) {
-        mHasActiveCall = call != null;
-        super.onCallAdded(call);
-    }
-
-    @Override
-    public void onCallRemoved(Call call) {
-        mHasActiveCall = false;
-        super.onCallRemoved(call);
-    }
-
-    @Override
-    protected void handleActiveCall(@NotNull Call call) {
-        CallDetail callDetails = CallDetail.fromTelecomCallDetail(call.getDetails());
-        mAvailableRoutes = sInCallServiceManager.getSupportedAudioRoute(callDetails);
-        mActiveRoute = sInCallServiceManager.getAudioRoute(
-                CallDetail.fromTelecomCallDetail(call.getDetails()).getScoState());
-        super.handleActiveCall(call);
-    }
-
-    /**
-     * Returns audio routes supported by current call.
-     */
-    public List<Integer> getAvailableAudioRoutes() {
-        return mAvailableRoutes;
-    }
-
-    /**
-     * Returns current call audio state.
-     */
-    public int getActiveAudioRoute() {
-        return mActiveRoute;
-    }
-
-    /**
-     * Sets current call audio route.
-     */
-    public void setActiveAudioRoute(int audioRoute) {
-        if (getCurrentCall() == null) {
-            // AudioRouteButton is disabled if it is null. Simply ignore it.
-            return;
-        }
-        sInCallServiceManager.setAudioRoute(audioRoute, getCurrentCall());
-        mActiveRoute = audioRoute;
-    }
-}
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java
index aaaf5cdf..2e36fe0f 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java
@@ -16,10 +16,7 @@
 
 package com.android.car.carlauncher.homescreen.audio.dialer;
 
-import android.app.ActivityOptions;
-import android.content.Context;
 import android.content.Intent;
-import android.view.Display;
 
 import androidx.annotation.VisibleForTesting;
 
@@ -36,6 +33,8 @@ import java.util.List;
  */
 public class DialerCardPresenter extends CardPresenter {
 
+    private final InCallIntentRouter mInCallIntentRouter = InCallIntentRouter.getInstance();
+
     /** A listener to notify when an in-call state changes. */
     public interface OnInCallStateChangeListener {
 
@@ -60,13 +59,8 @@ public class DialerCardPresenter extends CardPresenter {
             new OnViewClickListener() {
                 @Override
                 public void onViewClicked() {
-                    ActivityOptions options = ActivityOptions.makeBasic();
-                    options.setLaunchDisplayId(Display.DEFAULT_DISPLAY);
                     Intent intent = mViewModel.getIntent();
-                    Context context = mFragment.getContext();
-                    if (context != null) {
-                        context.startActivity(intent, options.toBundle());
-                    }
+                    mInCallIntentRouter.handleInCallIntent(intent);
                 }
             };
     @VisibleForTesting
@@ -74,7 +68,7 @@ public class DialerCardPresenter extends CardPresenter {
             new HomeCardInterface.Model.OnModelUpdateListener() {
                 @Override
                 public void onModelUpdate(HomeCardInterface.Model model) {
-                    DialerCardModel dialerCardModel = (DialerCardModel) model;
+                    InCallModel dialerCardModel = (InCallModel) model;
                     if (dialerCardModel.getCardHeader() != null) {
                         mFragment.updateHeaderView(dialerCardModel.getCardHeader());
                     }
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/InCallIntentRouter.java b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/InCallIntentRouter.java
new file mode 100644
index 00000000..eb66d38d
--- /dev/null
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/InCallIntentRouter.java
@@ -0,0 +1,55 @@
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
+package com.android.car.carlauncher.homescreen.audio.dialer;
+
+import android.content.Intent;
+
+import com.android.car.carlauncher.homescreen.audio.IntentHandler;
+
+/**
+ * Routes dialer {@link Intent} to {@link IntentHandler}.
+ */
+public class InCallIntentRouter {
+
+    private static InCallIntentRouter sInstance;
+    private IntentHandler mIntentHandler;
+
+    /**
+     * @return an instance of {@link InCallIntentRouter}.
+     */
+    public static InCallIntentRouter getInstance() {
+        if (sInstance == null) {
+            sInstance = new InCallIntentRouter();
+        }
+        return sInstance;
+    }
+
+    /**
+     * Register a {@link IntentHandler}.
+     */
+    public void registerInCallIntentHandler(IntentHandler intentHandler) {
+        mIntentHandler = intentHandler;
+    }
+
+    /**
+     * Dispatch a dailer intent to {@link IntentHandler}
+     */
+    public void handleInCallIntent(Intent intent) {
+        if (intent != null) {
+            mIntentHandler.handleIntent(intent);
+        }
+    }
+}
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
index 655428a3..ee15c49a 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
@@ -33,6 +33,8 @@ import android.view.GestureDetector;
 import android.view.MotionEvent;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.animation.Animation;
+import android.view.animation.AnimationUtils;
 import android.widget.ImageButton;
 import android.widget.LinearLayout;
 
@@ -158,9 +160,15 @@ public class MediaCardController extends PlaybackCardController implements
         mSkipPrevButton = mView.findViewById(R.id.playback_action_id1);
         mSkipNextButton = mView.findViewById(R.id.playback_action_id2);
 
+        Animation handlebarFadeOut = AnimationUtils.loadAnimation(mView.getContext(),
+                R.anim.media_card_panel_handlebar_fade_out);
+        Animation handlebarFadeIn = AnimationUtils.loadAnimation(mView.getContext(),
+                R.anim.media_card_panel_handlebar_fade_in);
         mMotionLayout.addTransitionListener(new MotionLayout.TransitionListener() {
             @Override
             public void onTransitionStarted(MotionLayout motionLayout, int i, int i1) {
+                mPanelHandlebar.startAnimation(mCardViewModel.getPanelExpanded() ? handlebarFadeIn
+                        : handlebarFadeOut);
             }
 
             @Override
@@ -229,7 +237,10 @@ public class MediaCardController extends PlaybackCardController implements
 
     @Override
     protected void updateAlbumCoverWithDrawable(Drawable drawable) {
-        RoundedDrawable roundedDrawable = new RoundedDrawable(drawable, mView.getResources()
+        Drawable drawableToUse = drawable == null ? mView.getResources().getDrawable(
+                /* drawable */ R.drawable.media_card_default_album_art, /* theme */ null)
+                : drawable;
+        RoundedDrawable roundedDrawable = new RoundedDrawable(drawableToUse, mView.getResources()
                 .getFloat(R.dimen.media_card_album_art_drawable_corner_ratio));
         super.updateAlbumCoverWithDrawable(roundedDrawable);
 
@@ -487,6 +498,7 @@ public class MediaCardController extends PlaybackCardController implements
         mSkipPrevVisibility = mSkipPrevButton.getVisibility();
         mSkipNextVisibility = mSkipNextButton.getVisibility();
         mAlbumCoverVisibility = mAlbumCover.getVisibility();
+        mSeekBar.setEnabled(false);
     }
 
     private void restoreExtraViewsWhenPanelClosed() {
@@ -496,6 +508,7 @@ public class MediaCardController extends PlaybackCardController implements
         mSkipNextButton.setVisibility(mSkipNextVisibility);
         mSubtitle.setVisibility(mSubtitleVisibility);
         mLogo.setVisibility(mLogoVisibility);
+        mSeekBar.setEnabled(true);
     }
 
     /**
diff --git a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
index e5e3c1ba..4e5224cf 100644
--- a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
+++ b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
@@ -17,7 +17,6 @@
 package com.android.car.carlauncher.recents;
 
 import static com.android.car.carlauncher.recents.CarRecentsActivity.OPEN_RECENT_TASK_ACTION;
-import static com.android.wm.shell.shared.ShellSharedConstants.KEY_EXTRA_SHELL_RECENT_TASKS;
 
 import android.app.ActivityManager;
 import android.app.Service;
@@ -94,7 +93,7 @@ public class CarQuickStepService extends Service {
         @Override
         public void onInitialize(Bundle params) throws RemoteException {
             IRecentTasks recentTasks = IRecentTasks.Stub.asInterface(
-                    params.getBinder(KEY_EXTRA_SHELL_RECENT_TASKS));
+                    params.getBinder(IRecentTasks.DESCRIPTOR));
             mRecentTasksProvider.init(getApplicationContext(), recentTasks);
         }
 
@@ -192,22 +191,22 @@ public class CarQuickStepService extends Service {
         }
 
         @Override
-        public void checkNavBarModes() {
+        public void checkNavBarModes(int displayId) {
             // no-op
         }
 
         @Override
-        public void finishBarAnimations() {
+        public void finishBarAnimations(int displayId) {
             // no-op
         }
 
         @Override
-        public void touchAutoDim(boolean reset) {
+        public void touchAutoDim(int displayid, boolean reset) {
             // no-op
         }
 
         @Override
-        public void transitionTo(@BarTransitions.TransitionMode int barMode,
+        public void transitionTo(int displayId, @BarTransitions.TransitionMode int barMode,
                 boolean animate) {
             // no-op
         }
diff --git a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
index ec1b4af8..03ec2aba 100644
--- a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
+++ b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
@@ -18,12 +18,13 @@ package com.android.car.carlauncher.recents;
 
 import static android.app.ActivityManager.RECENT_IGNORE_UNAVAILABLE;
 
-import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_FREEFORM;
-import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SINGLE;
-import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SPLIT;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FREEFORM;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FULLSCREEN;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_SPLIT;
 
 import android.app.Activity;
 import android.app.ActivityManager;
+import android.app.TaskInfo;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -49,7 +50,7 @@ import com.android.systemui.shared.system.PackageManagerWrapper;
 import com.android.systemui.shared.system.TaskStackChangeListener;
 import com.android.systemui.shared.system.TaskStackChangeListeners;
 import com.android.wm.shell.recents.IRecentTasks;
-import com.android.wm.shell.shared.GroupedRecentTaskInfo;
+import com.android.wm.shell.shared.GroupedTaskInfo;
 
 import com.google.common.annotations.VisibleForTesting;
 
@@ -152,7 +153,7 @@ public class RecentTasksProvider implements RecentTasksProviderInterface {
             return;
         }
         sRecentsModelExecutor.execute(() -> {
-            GroupedRecentTaskInfo[] groupedRecentTasks;
+            GroupedTaskInfo[] groupedRecentTasks;
             try {
                 // todo: b/271498799 use ActivityManagerWrapper.getInstance().getCurrentUserId()
                 //  or equivalent instead of hidden API mContext.getUserId()
@@ -171,12 +172,12 @@ public class RecentTasksProvider implements RecentTasksProviderInterface {
             mRecentTaskIds = new ArrayList<>(groupedRecentTasks.length);
             mRecentTaskIdToTaskMap = new HashMap<>(groupedRecentTasks.length);
             boolean areSplitOrFreeformTypeTasksPresent = false;
-            for (GroupedRecentTaskInfo groupedRecentTask : groupedRecentTasks) {
+            for (GroupedTaskInfo groupedRecentTask : groupedRecentTasks) {
                 switch (groupedRecentTask.getType()) {
-                    case TYPE_SINGLE:
+                    case TYPE_FULLSCREEN:
                         // Automotive doesn't have split screen functionality, only process tasks
-                        // of TYPE_SINGLE.
-                        ActivityManager.RecentTaskInfo taskInfo = groupedRecentTask.getTaskInfo1();
+                        // of TYPE_FULLSCREEN.
+                        TaskInfo taskInfo = groupedRecentTask.getTaskInfo1();
                         Task.TaskKey taskKey = new Task.TaskKey(taskInfo);
 
                         // isLocked is always set to false since this value is not required in
@@ -186,7 +187,6 @@ public class RecentTasksProvider implements RecentTasksProviderInterface {
                         // where this value is necessary to check if profile user associated with
                         // the task is unlocked.
                         Task task = Task.from(taskKey, taskInfo, /* isLocked= */ false);
-                        task.setLastSnapshotData(taskInfo);
                         mRecentTaskIds.add(task.key.id);
                         mRecentTaskIdToTaskMap.put(task.key.id, task);
                         getRecentTaskThumbnailAsync(task.key.id);
diff --git a/app/tests/Android.bp b/app/tests/Android.bp
index 0eb8b297..444d2e54 100644
--- a/app/tests/Android.bp
+++ b/app/tests/Android.bp
@@ -22,7 +22,10 @@ package {
 android_test {
     name: "CarLauncherTests",
 
-    srcs: ["src/**/*.java"],
+    srcs: [
+        "src/**/*.java",
+        "src/**/*.kt",
+    ],
 
     resource_dirs: ["res"],
 
@@ -48,6 +51,7 @@ android_test {
         "androidx.test.ext.junit",
         "androidx.fragment_fragment-testing",
         "hamcrest-library",
+        "mockito-kotlin2",
         "mockito-target-extended",
         "truth",
         "testables",
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
index d62d0feb..620e26f9 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
@@ -34,11 +34,12 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.any;
 
-import android.car.app.RemoteCarTaskView;
 import android.car.test.mocks.AbstractExtendedMockitoTestCase;
 import android.content.Intent;
+import android.content.pm.PackageManager;
 import android.platform.test.annotations.RequiresFlagsDisabled;
 import android.platform.test.annotations.RequiresFlagsEnabled;
 import android.platform.test.flag.junit.CheckFlagsRule;
@@ -55,6 +56,7 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import org.junit.After;
+import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -78,13 +80,7 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
             + "component=com.android.car.carlauncher/"
             + "com.android.car.carlauncher.homescreen.MapActivityTos;"
             + "action=android.intent.action.MAIN;end";
-    private static final String DEFAULT_MAP_INTENT = "intent:#Intent;"
-            + "component=com.android.car.maps/"
-            + "com.android.car.maps.MapActivity;"
-            + "action=android.intent.action.MAIN;end";
-    private static final String CUSTOM_MAP_INTENT = "intent:#Intent;component=com.custom.car.maps/"
-            + "com.custom.car.maps.MapActivity;"
-            + "action=android.intent.action.MAIN;end";
+
     // TOS disabled app list is non empty when TOS is not accepted.
     private static final String NON_EMPTY_TOS_DISABLED_APPS =
             "com.test.package1, com.test.package2";
@@ -97,6 +93,11 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         session.spyStatic(CarLauncherUtils.class);
     }
 
+    @Before
+    public void setUp() {
+        assumeFalse(hasSplitscreenMultitaskingFeature());
+    }
+
     @After
     public void tearDown() {
         if (mActivityScenario != null) {
@@ -143,15 +144,12 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void onCreate_tosMapActivity_tosUnaccepted_canvasOptimizedMapsDisabledByTos() {
+    public void onCreate_tosUnacceptedAndCanvasOptimizedMapsDisabledByTos_launchesTosMapIntent() {
         doReturn(false).when(() -> AppLauncherUtils.tosAccepted(any()));
         doReturn(true)
-                        .when(() ->
-                                CarLauncherUtils.isSmallCanvasOptimizedMapIntentConfigured(any()));
+                .when(() -> CarLauncherUtils.isSmallCanvasOptimizedMapIntentConfigured(any()));
         doReturn(createIntentFromString(TOS_MAP_INTENT))
                 .when(() -> CarLauncherUtils.getTosMapIntent(any()));
-        doReturn(createIntentFromString(DEFAULT_MAP_INTENT))
-                .when(() -> CarLauncherUtils.getSmallCanvasOptimizedMapIntent(any()));
         doReturn(tosDisabledPackages())
                 .when(() -> AppLauncherUtils.getTosDisabledPackages(any()));
 
@@ -168,12 +166,12 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
     }
 
     @Test
-    public void onCreate_tosMapActivity_tosUnaccepted_mapsNotDisabledByTos() {
+    public void onCreate_tosUnacceptedAndDefaultMapsNotDisabledByTos_doesNotLaunchTosMapIntent() {
         doReturn(false).when(() -> AppLauncherUtils.tosAccepted(any()));
-        doReturn(true)
+        doReturn(false)
                 .when(() -> CarLauncherUtils.isSmallCanvasOptimizedMapIntentConfigured(any()));
-        doReturn(createIntentFromString(CUSTOM_MAP_INTENT))
-                .when(() -> CarLauncherUtils.getSmallCanvasOptimizedMapIntent(any()));
+        doReturn(createIntentFromString(TOS_MAP_INTENT))
+                .when(() -> CarLauncherUtils.getTosMapIntent(any()));
         doReturn(tosDisabledPackages())
                 .when(() -> AppLauncherUtils.getTosDisabledPackages(any()));
 
@@ -185,14 +183,14 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
             // these can be some other navigation app set as default,
             // package name will not be null.
             // We will not replace the map intent with TOS map activity
-            assertEquals(
-                    createIntentFromString(CUSTOM_MAP_INTENT).getComponent().getClassName(),
+            assertNotEquals(
+                    createIntentFromString(TOS_MAP_INTENT).getComponent().getClassName(),
                     mapIntent.getComponent().getClassName());
         });
     }
 
     @Test
-    public void onCreate_tosMapActivity_tosAccepted() {
+    public void onCreate_tosAccepted_doesNotLaunchTosMapIntent() {
         doReturn(true).when(() -> AppLauncherUtils.tosAccepted(any()));
         doReturn(createIntentFromString(TOS_MAP_INTENT))
                 .when(() -> CarLauncherUtils.getTosMapIntent(any()));
@@ -202,7 +200,8 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         mActivityScenario.onActivity(activity -> {
             Intent mapIntent = activity.getMapsIntent();
             // If TOS is accepted, map intent is not replaced
-            assertNotEquals("com.android.car.carlauncher.homescreen.MapActivityTos",
+            assertNotEquals(
+                    createIntentFromString(TOS_MAP_INTENT).getComponent().getClassName(),
                     mapIntent.getComponent().getClassName());
         });
     }
@@ -278,6 +277,15 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         mActivityScenario.onActivity(activity -> assertNull(activity.mTosContentObserver));
     }
 
+    @Test
+    public void onCreate_whenTosIsNull_tosStateContentObserverIsNotNull() {
+        // Settings.Secure KEY_USER_TOS_ACCEPTED is null when not set explicitly.
+        mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
+
+        // Content observer is not null after activity is created
+        mActivityScenario.onActivity(activity -> assertNotNull(activity.mTosContentObserver));
+    }
+
     @Test
     public void recreate_afterTosIsInitialized_tosStateContentObserverIsNotNull() {
         TestableContext mContext = new TestableContext(InstrumentationRegistry.getContext());
@@ -313,9 +321,8 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         mActivityScenario.onActivity(activity -> {
             assertNotNull(activity.mCarLauncherViewModel); // CarLauncherViewModel is setup
 
-            RemoteCarTaskView oldRemoteCarTaskView =
-                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue();
-            assertNotNull(oldRemoteCarTaskView);
+            Intent oldMapsIntent = activity.mCarLauncherViewModel.getMapsIntent();
+            assertNotNull(oldMapsIntent);
 
             // Initialize TOS
             Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 1);
@@ -323,9 +330,10 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
                     KEY_UNACCEPTED_TOS_DISABLED_APPS, NON_EMPTY_TOS_DISABLED_APPS);
             activity.mTosContentObserver.onChange(true);
 
-            // Different instance of task view since TOS has gone from uninitialized to initialized
-            assertThat(oldRemoteCarTaskView).isNotSameInstanceAs(
-                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue());
+            // Different instance of maps intent since TOS has gone from uninitialized to
+            // initialized
+            assertThat(oldMapsIntent).isNotSameInstanceAs(
+                    activity.mCarLauncherViewModel.getMapsIntent());
         });
     }
 
@@ -341,9 +349,8 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         mActivityScenario.onActivity(activity -> {
             assertNotNull(activity.mCarLauncherViewModel); // CarLauncherViewModel is setup
 
-            RemoteCarTaskView oldRemoteCarTaskView =
-                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue();
-            assertNotNull(oldRemoteCarTaskView);
+            Intent oldMapsIntent = activity.mCarLauncherViewModel.getMapsIntent();
+            assertNotNull(oldMapsIntent);
 
             // Accept TOS
             Settings.Secure.putInt(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, 2);
@@ -351,9 +358,9 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
                     KEY_UNACCEPTED_TOS_DISABLED_APPS, EMPTY_TOS_DISABLED_APPS);
             activity.mTosContentObserver.onChange(true);
 
-            // Different instance of task view since TOS has been accepted
-            assertThat(oldRemoteCarTaskView).isNotSameInstanceAs(
-                    activity.mCarLauncherViewModel.getRemoteCarTaskView().getValue());
+            // Different instance of maps intent since TOS has been accepted
+            assertThat(oldMapsIntent).isNotSameInstanceAs(
+                    activity.mCarLauncherViewModel.getMapsIntent());
         });
     }
 
@@ -383,4 +390,12 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
             });
         });
     }
+
+    /**
+     * Checks whether the device has automotive split-screen multitasking feature enabled
+     */
+    private boolean hasSplitscreenMultitaskingFeature() {
+        return mContext.getPackageManager()
+                .hasSystemFeature(PackageManager.FEATURE_CAR_SPLITSCREEN_MULTITASKING);
+    }
 }
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java
index b11a40fa..a61a0a5e 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelFactoryTest.java
@@ -64,7 +64,7 @@ public class CarLauncherViewModelFactoryTest extends AbstractExtendedMockitoTest
                 .createWindowContext(TYPE_APPLICATION_STARTING, /* options */ null);
         when(mContext.createWindowContext(eq(WindowManager.LayoutParams.TYPE_APPLICATION_STARTING),
                 any())).thenReturn(windowContext);
-        mCarLauncherViewModelFactory = new CarLauncherViewModelFactory(mContext);
+        mCarLauncherViewModelFactory = new CarLauncherViewModelFactory(mContext, mIntent);
     }
 
     @After
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java
index 33d1611d..cee9451d 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherViewModelTest.java
@@ -95,8 +95,7 @@ public final class CarLauncherViewModelTest extends AbstractExtendedMockitoTestC
     }
 
     private CarLauncherViewModel createCarLauncherViewModel() {
-        CarLauncherViewModel carLauncherViewModel = new CarLauncherViewModel(mActivity);
-        carLauncherViewModel.initializeRemoteCarTaskView(mIntent);
+        CarLauncherViewModel carLauncherViewModel = new CarLauncherViewModel(mActivity, mIntent);
         runOnMain(() -> carLauncherViewModel.getRemoteCarTaskView().observeForever(
                 remoteCarTaskView -> mRemoteCarTaskView = remoteCarTaskView));
         mInstrumentation.waitForIdleSync();
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/MapTosActivityTest.kt b/app/tests/src/com/android/car/carlauncher/homescreen/MapTosActivityTest.kt
new file mode 100644
index 00000000..d9a666c9
--- /dev/null
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/MapTosActivityTest.kt
@@ -0,0 +1,136 @@
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
+
+package com.android.car.carlauncher.homescreen
+
+import android.car.settings.CarSettings.Secure.KEY_UNACCEPTED_TOS_DISABLED_APPS
+import android.car.settings.CarSettings.Secure.KEY_USER_TOS_ACCEPTED
+import android.content.Intent
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import android.provider.Settings
+import android.testing.TestableContext
+import androidx.test.core.app.ActivityScenario
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.car.carlauncher.Flags
+import com.android.car.carlauncher.R
+import com.google.common.truth.Truth.assertThat
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class MapTosActivityTest {
+    @get:Rule val setFlagsRule = SetFlagsRule()
+    private val context =
+        TestableContext(InstrumentationRegistry.getInstrumentation().targetContext)
+    private val resources = context.resources
+
+    @Test
+    fun onCreate_whenCarUxRestrictionsActive_shouldDisplayDistractionOptimizedText() {
+        ActivityScenario.launch(MapTosActivity::class.java).use { scenario ->
+            scenario.onActivity {
+                it.handleReviewButtonDistractionOptimized(requiresDistractionOptimization = true)
+
+                assertThat(it.reviewButton.text).isEqualTo(
+                    resources.getText(R.string.map_tos_review_button_distraction_optimized_text)
+                )
+            }
+        }
+    }
+
+    @Test
+    fun onCreate_whenCarUxRestrictionsInactive_shouldDisplayNonDistractionOptimizedText() {
+        ActivityScenario.launch(MapTosActivity::class.java).use { scenario ->
+            scenario.onActivity {
+                it.handleReviewButtonDistractionOptimized(requiresDistractionOptimization = false)
+
+                assertThat(it.reviewButton.text).isEqualTo(
+                    resources.getText(R.string.map_tos_review_button_text)
+                )
+            }
+        }
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun onCreate_tosContentObserver_isNotNull() {
+        Settings.Secure.putInt(context.contentResolver, KEY_USER_TOS_ACCEPTED, 1)
+        Settings.Secure.putString(
+            context.contentResolver,
+            KEY_UNACCEPTED_TOS_DISABLED_APPS,
+            NON_EMPTY_TOS_DISABLED_APPS
+        )
+
+        ActivityScenario.launch<MapTosActivity>(
+            Intent(context, MapTosActivity::class.java)
+        ).use { scenario ->
+            scenario.onActivity { assertThat(it.tosContentObserver).isNotNull() }
+        }
+    }
+
+    @Test
+    @DisableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun onCreate_whenFlagDisabled_tosContentObserver_isNull() {
+        Settings.Secure.putInt(context.contentResolver, KEY_USER_TOS_ACCEPTED, 1)
+        Settings.Secure.putString(
+            context.contentResolver,
+            KEY_UNACCEPTED_TOS_DISABLED_APPS,
+            NON_EMPTY_TOS_DISABLED_APPS
+        )
+
+        ActivityScenario.launch<MapTosActivity>(
+            Intent(context, MapTosActivity::class.java)
+        ).use { scenario ->
+            scenario.onActivity { assertThat(it.tosContentObserver).isNull() }
+        }
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun afterTosIsAccepted_activityIsFinishing() {
+        Settings.Secure.putInt(context.contentResolver, KEY_USER_TOS_ACCEPTED, 1)
+        Settings.Secure.putString(
+            context.contentResolver,
+            KEY_UNACCEPTED_TOS_DISABLED_APPS,
+            NON_EMPTY_TOS_DISABLED_APPS
+        )
+
+        ActivityScenario.launch<MapTosActivity>(
+            Intent(context, MapTosActivity::class.java)
+        ).use { scenario ->
+            scenario.onActivity {
+                // Accept TOS
+                Settings.Secure.putInt(context.contentResolver, KEY_USER_TOS_ACCEPTED, 2)
+                Settings.Secure.putString(
+                    context.contentResolver,
+                    KEY_UNACCEPTED_TOS_DISABLED_APPS,
+                    EMPTY_TOS_DISABLED_APPS
+                )
+                it.tosContentObserver?.onChange(true)
+
+                assertThat(it.isFinishing).isTrue()
+            }
+        }
+    }
+
+    private companion object {
+        const val NON_EMPTY_TOS_DISABLED_APPS = "com.test.package1,com.test.package2"
+        const val EMPTY_TOS_DISABLED_APPS = ""
+    }
+}
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java
index 0be8313c..3f9bb9f0 100644
--- a/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java
@@ -23,6 +23,7 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
+import com.android.car.carlauncher.homescreen.audio.InCallModel;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextView;
 
@@ -46,7 +47,7 @@ public class DialerCardPresenterTest {
     @Mock
     private DialerCardFragment mView;
     @Mock
-    private DialerCardModel mModel;
+    private InCallModel mModel;
 
     @Mock
     private DialerCardPresenter.OnInCallStateChangeListener mOnInCallStateChangeListener;
diff --git a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
index 71aa8d84..5e7703ee 100644
--- a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
+++ b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
@@ -18,9 +18,9 @@ package com.android.car.carlauncher.recents;
 
 import static android.app.ActivityManager.RECENT_IGNORE_UNAVAILABLE;
 
-import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_FREEFORM;
-import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SINGLE;
-import static com.android.wm.shell.shared.GroupedRecentTaskInfo.TYPE_SPLIT;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FREEFORM;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FULLSCREEN;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_SPLIT;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -37,6 +37,7 @@ import static org.mockito.Mockito.when;
 import android.app.Activity;
 import android.app.ActivityManager;
 import android.app.ActivityOptions;
+import android.app.TaskInfo;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -56,7 +57,7 @@ import com.android.systemui.shared.recents.model.Task;
 import com.android.systemui.shared.system.ActivityManagerWrapper;
 import com.android.systemui.shared.system.PackageManagerWrapper;
 import com.android.wm.shell.recents.IRecentTasks;
-import com.android.wm.shell.shared.GroupedRecentTaskInfo;
+import com.android.wm.shell.shared.GroupedTaskInfo;
 
 import com.google.common.util.concurrent.MoreExecutors;
 
@@ -78,7 +79,7 @@ public class RecentTasksProviderTest {
     private static final int FREEFORM_RECENT_TASKS_LENGTH = 3;
 
     private RecentTasksProvider mRecentTasksProvider;
-    private GroupedRecentTaskInfo[] mGroupedRecentTaskInfo;
+    private GroupedTaskInfo[] mGroupedRecentTaskInfo;
 
     @Mock
     private IRecentTasks mRecentTaskProxy;
@@ -363,10 +364,10 @@ public class RecentTasksProviderTest {
     }
 
     private void initRecentTaskList(boolean addTypeSplit, boolean addTypeFreeform) {
-        List<GroupedRecentTaskInfo> groupedRecentTaskInfos = new ArrayList<>();
+        List<GroupedTaskInfo> groupedRecentTaskInfos = new ArrayList<>();
         for (int i = 0; i < RECENT_TASKS_LENGTH; i++) {
             groupedRecentTaskInfos.add(
-                    createGroupedRecentTaskInfo(createRecentTaskInfo(i), TYPE_SINGLE));
+                    createGroupedRecentTaskInfo(createRecentTaskInfo(i), TYPE_FULLSCREEN));
         }
         if (addTypeSplit) {
             for (int i = 0; i < SPLIT_RECENT_TASKS_LENGTH; i++) {
@@ -380,18 +381,18 @@ public class RecentTasksProviderTest {
                         createGroupedRecentTaskInfo(createRecentTaskInfo(i), TYPE_FREEFORM));
             }
         }
-        mGroupedRecentTaskInfo = groupedRecentTaskInfos.toArray(GroupedRecentTaskInfo[]::new);
+        mGroupedRecentTaskInfo = groupedRecentTaskInfos.toArray(GroupedTaskInfo[]::new);
     }
 
-    private GroupedRecentTaskInfo createGroupedRecentTaskInfo(ActivityManager.RecentTaskInfo info,
-            int type) {
-        GroupedRecentTaskInfo groupedRecentTaskInfo = mock(GroupedRecentTaskInfo.class);
+    private GroupedTaskInfo createGroupedRecentTaskInfo(TaskInfo info, int type) {
+        GroupedTaskInfo groupedRecentTaskInfo =
+                (GroupedTaskInfo) mock(GroupedTaskInfo.class);
         when(groupedRecentTaskInfo.getType()).thenReturn(type);
         when(groupedRecentTaskInfo.getTaskInfo1()).thenReturn(info);
         return groupedRecentTaskInfo;
     }
 
-    private ActivityManager.RecentTaskInfo createRecentTaskInfo(int taskId) {
+    private TaskInfo createRecentTaskInfo(int taskId) {
         when(mBaseIntent.getComponent()).thenReturn(mComponent);
         ActivityManager.RecentTaskInfo recentTaskInfo = new ActivityManager.RecentTaskInfo();
         recentTaskInfo.taskId = taskId;
diff --git a/docklib-util/res/values/config.xml b/docklib-util/res/values/config.xml
index 2a283508..f886e9fe 100644
--- a/docklib-util/res/values/config.xml
+++ b/docklib-util/res/values/config.xml
@@ -16,4 +16,8 @@
   -->
 
 <resources>
+    <!--list of all the display ids where dock feature is supported-->
+    <integer-array name="dock_supported_displays">
+        <item>0</item>
+    </integer-array>
 </resources>
diff --git a/docklib-util/src/com/android/car/dockutil/events/DockCompatUtils.kt b/docklib-util/src/com/android/car/dockutil/events/DockCompatUtils.kt
new file mode 100644
index 00000000..f06605de
--- /dev/null
+++ b/docklib-util/src/com/android/car/dockutil/events/DockCompatUtils.kt
@@ -0,0 +1,39 @@
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
+
+package com.android.car.dockutil.events
+
+import android.content.Context
+import com.android.car.dockutil.R
+import java.util.Arrays
+
+object DockCompatUtils {
+    /**
+     * @param context application context
+     * @param displayId current displayId
+     * @return true if dock feature is supported on the display, false otherwise.
+     */
+    @JvmStatic
+    fun isDockSupportedOnDisplay(
+        context: Context,
+        displayId: Int
+    ): Boolean {
+        val supportedDisplays: IntArray = context.resources.getIntArray(
+            R.array.dock_supported_displays
+        )
+        return Arrays.stream(supportedDisplays).anyMatch { id: Int -> id == displayId }
+    }
+}
diff --git a/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java b/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java
index 42197d62..39362752 100644
--- a/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java
+++ b/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java
@@ -16,13 +16,13 @@
 
 package com.android.car.dockutil.events;
 
+import static com.android.car.dockutil.events.DockCompatUtils.isDockSupportedOnDisplay;
 import static com.android.car.hidden.apis.HiddenApiAccess.getDisplayId;
 
 import android.app.ActivityManager;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
-import android.view.Display;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
@@ -81,7 +81,7 @@ public class DockEventSenderHelper {
     @VisibleForTesting
     void sendEventBroadcast(@NonNull DockEvent event,
             @NonNull ActivityManager.RunningTaskInfo taskInfo) {
-        if (getDisplayId(taskInfo) != Display.DEFAULT_DISPLAY) {
+        if (!isDockSupportedOnDisplay(mContext, getDisplayId(taskInfo))) {
             return;
         }
         ComponentName component = getComponentName(taskInfo);
diff --git a/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java b/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java
index 81f8bbb5..bb5ad666 100644
--- a/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java
+++ b/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java
@@ -23,6 +23,7 @@ import static com.android.car.dockutil.events.DockEventSenderHelper.EXTRA_COMPON
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.never;
@@ -66,17 +67,19 @@ public class DockEventSenderHelperTest {
     @Captor
     public ArgumentCaptor<Intent> mIntentCaptor;
     private DockEventSenderHelper mDockEventSenderHelper;
+    private final int[] mDockSupportedDisplayId = {DEFAULT_DISPLAY};
 
     @Before
     public void setup() {
         MockitoAnnotations.initMocks(this);
         when(mContext.getResources()).thenReturn(mResources);
+        when(mResources.getIntArray(anyInt())).thenReturn(mDockSupportedDisplayId);
         mSetFlagsRule.enableFlags(Flags.FLAG_DOCK_FEATURE);
         mDockEventSenderHelper = new DockEventSenderHelper(mContext);
     }
 
     @Test
-    public void sendEventBroadcast_nonDefaultDisplay_broadcastNotSent() {
+    public void sendEventBroadcast_nonSupportedDisplay_broadcastNotSent() {
         when(mRunningTaskInfo.getDisplayId()).thenReturn(DEFAULT_DISPLAY + 1);
 
         mDockEventSenderHelper.sendEventBroadcast(DockEvent.LAUNCH, mRunningTaskInfo);
diff --git a/docklib/res/values/config.xml b/docklib/res/values/config.xml
index e026e7fd..293b4618 100644
--- a/docklib/res/values/config.xml
+++ b/docklib/res/values/config.xml
@@ -26,16 +26,16 @@
         <item>com.android.car.dialer/com.android.car.dialer.ui.TelecomActivity</item>
     </string-array>
 
-    <!-- A list of components that are excluded from being shown on Dock -->
+    <!-- A list of packages that are excluded from being shown on Dock -->
     <string-array name="config_packagesExcludedFromDock" translatable="false">
         <item>com.android.car.carlauncher</item>
         <item>android.car.usb.handler</item>
+        <item>com.google.android.carassistant</item>
     </string-array>
 
     <!-- A list of components that are excluded from being shown on Dock -->
     <string-array name="config_componentsExcludedFromDock" translatable="false">
         <item>com.google.android.apps.maps/com.google.android.apps.gmm.car.embedded.activity.LimitedMapsActivity</item>
-        <item>com.google.android.carassistant/com.google.android.libraries.assistant.auto.tng.assistant.ui.activity.AutoAssistantActivity</item>
         <item>com.android.car.media/com.android.car.media.MediaDispatcherActivity</item>
         <item>com.android.car.media/com.android.car.media.MediaBlockingActivity</item>
         <item>com.android.systemui/com.android.systemui.car.wm.activity.LaunchOnPrivateDisplayRouterActivity</item>
diff --git a/docklib/src/com/android/car/docklib/DockViewController.kt b/docklib/src/com/android/car/docklib/DockViewController.kt
index a3b179e5..3c70e80f 100644
--- a/docklib/src/com/android/car/docklib/DockViewController.kt
+++ b/docklib/src/com/android/car/docklib/DockViewController.kt
@@ -43,6 +43,7 @@ import com.android.car.docklib.media.MediaUtils
 import com.android.car.docklib.task.DockTaskStackChangeListener
 import com.android.car.docklib.view.DockAdapter
 import com.android.car.docklib.view.DockView
+import com.android.car.dockutil.events.DockCompatUtils.isDockSupportedOnDisplay
 import com.android.launcher3.icons.IconFactory
 import com.android.systemui.shared.system.TaskStackChangeListeners
 import java.io.File
@@ -87,6 +88,10 @@ open class DockViewController(
 
     init {
         if (DEBUG) Log.d(TAG, "Init DockViewController for user ${userContext.userId}")
+        val displayId = dockView.context.displayId
+        if (!isDockSupportedOnDisplay(dockView.context, displayId)) {
+            throw IllegalStateException("Dock tried to init on unsupported display: $displayId")
+        }
         adapter = DockAdapter(this, userContext)
         dockView.setAdapter(adapter)
         dockViewWeakReference = WeakReference(dockView)
@@ -151,7 +156,9 @@ open class DockViewController(
 
         mediaSessionManager =
             userContext.getSystemService(MediaSessionManager::class.java) as MediaSessionManager
-        if (Flags.mediaSessionCard()) {
+        if (Flags.mediaSessionCard() && userContext.resources.getBoolean(
+                com.android.car.carlaunchercommon.R.bool
+                .config_enableMediaSessionAppsWhileDriving)) {
             handleMediaSessionChange(mediaSessionManager.getActiveSessionsForUser(
                 /* notificationListener= */
                 null,
diff --git a/docklib/src/com/android/car/docklib/events/DockEventsReceiver.java b/docklib/src/com/android/car/docklib/events/DockEventsReceiver.java
index 101bd73d..2ad5739a 100644
--- a/docklib/src/com/android/car/docklib/events/DockEventsReceiver.java
+++ b/docklib/src/com/android/car/docklib/events/DockEventsReceiver.java
@@ -18,6 +18,7 @@ package com.android.car.docklib.events;
 
 import static android.content.Context.RECEIVER_EXPORTED;
 
+import static com.android.car.dockutil.events.DockCompatUtils.isDockSupportedOnDisplay;
 import static com.android.car.dockutil.events.DockEventSenderHelper.EXTRA_COMPONENT;
 
 import android.content.BroadcastReceiver;
@@ -48,6 +49,10 @@ public class DockEventsReceiver extends BroadcastReceiver {
 
     @Override
     public void onReceive(Context context, Intent intent) {
+        if (!isDockSupportedOnDisplay(context, context.getDisplayId())) {
+            Log.e(TAG, "Dock event received on unsupported display " + context.getDisplayId());
+            return;
+        }
         DockEvent event = DockEvent.toDockEvent(intent.getAction());
         ComponentName component = intent.getParcelableExtra(EXTRA_COMPONENT, ComponentName.class);
 
diff --git a/libs/appgrid/app/src/main/AndroidManifest.xml b/libs/appgrid/app/src/main/AndroidManifest.xml
index 0b0f30d8..128489ad 100644
--- a/libs/appgrid/app/src/main/AndroidManifest.xml
+++ b/libs/appgrid/app/src/main/AndroidManifest.xml
@@ -38,18 +38,38 @@
         android:label="@string/app_name"
         android:supportsRtl="true">
 
-    <activity-alias
-            android:name="com.android.car.appgrid.test.AppGridActivity"
-            android:targetActivity="com.android.car.carlauncher.AppGridActivity"
-            android:launchMode="singleInstance"
+        <activity-alias
+                android:name="com.android.car.appgrid.test.AppGridActivity"
+                android:targetActivity="com.android.car.carlauncher.AppGridActivity"
+                android:launchMode="singleInstance"
+                android:exported="true"
+                android:theme="@style/Theme.Launcher.AppGridActivity"
+                android:excludeFromRecents="true">
+                <meta-data android:name="distractionOptimized" android:value="true"/>
+                <intent-filter>
+                    <action android:name="android.intent.action.MAIN" />
+                    <category android:name="android.intent.category.LAUNCHER" />
+                </intent-filter>
+        </activity-alias>
+
+        <activity-alias
+            android:name="com.android.car.appgrid.test.ResetLauncherActivity"
+            android:excludeFromRecents="true"
             android:exported="true"
-            android:theme="@style/Theme.Launcher.AppGridActivity"
-            android:excludeFromRecents="true">
-            <meta-data android:name="distractionOptimized" android:value="true"/>
+            android:launchMode="singleInstance"
+            android:targetActivity="com.android.car.carlauncher.ResetLauncherActivity"
+            android:theme="@style/ActionDialogTheme">
             <intent-filter>
-                <action android:name="android.intent.action.MAIN" />
-                <category android:name="android.intent.category.LAUNCHER" />
+                <action android:name="com.android.settings.action.EXTRA_SETTINGS" />
+                <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
+
+            <meta-data
+                android:name="com.android.settings.title"
+                android:resource="@string/reset_appgrid_title" />
+            <meta-data
+                android:name="com.android.settings.category"
+                android:value="com.android.settings.category.ia.apps" />
         </activity-alias>
 
     </application>
diff --git a/libs/appgrid/lib/res/values/config.xml b/libs/appgrid/lib/res/values/config.xml
index 34497aa5..1e0f8d2f 100644
--- a/libs/appgrid/lib/res/values/config.xml
+++ b/libs/appgrid/lib/res/values/config.xml
@@ -45,11 +45,6 @@
          * Integer value 0 implies to show the banner after every reboot
    -->
     <integer name="config_tos_banner_resurface_time_days">1</integer>
-
-    <!--
-        Config for allowing NDO apps to be opened while driving if they contain an active media
-        session. These NDO apps will still be blocked by blocking UI, but may be provided controls.
-        This does not affect the media widget's ability to show or control media sessions.
-    -->
-    <bool name="config_enableMediaSessionAppsWhileDriving">true</bool>
+    <!--    Config for displaying the terms of service banner on the app grid. -->
+    <bool name="config_enable_tos_banner">true</bool>
 </resources>
diff --git a/libs/appgrid/lib/res/values/dimens.xml b/libs/appgrid/lib/res/values/dimens.xml
index e137acf4..909d25b5 100644
--- a/libs/appgrid/lib/res/values/dimens.xml
+++ b/libs/appgrid/lib/res/values/dimens.xml
@@ -17,6 +17,8 @@
 <resources>
     <dimen name="app_grid_width">1440dp</dimen>
     <dimen name="app_grid_height">628dp</dimen>
+    <dimen name="car_app_selector_column_min_width">300dp</dimen>
+    <dimen name="car_app_selector_column_min_height">200dp</dimen>
     <dimen name="app_grid_margin_horizontal">70dp</dimen>
     <dimen name="app_grid_margin_vertical">0dp</dimen>
     <dimen name="app_icon_size">84dp</dimen>
diff --git a/libs/appgrid/lib/res/values/integers.xml b/libs/appgrid/lib/res/values/integers.xml
index 18fa1684..557b41a7 100644
--- a/libs/appgrid/lib/res/values/integers.xml
+++ b/libs/appgrid/lib/res/values/integers.xml
@@ -14,9 +14,6 @@ See the License for the specific language governing permissions and
 limitations under the License.
 -->
 <resources>
-    <!-- Columns -->
-    <integer name="car_app_selector_column_number">5</integer>
-    <integer name="car_app_selector_row_number">3</integer>
 
     <!-- Number of milliseconds users need to hover the app icon on the side of the app grid during
     drag and drop before the page is scrolled in the direction it was held.-->
diff --git a/libs/appgrid/lib/res/values/overlayable.xml b/libs/appgrid/lib/res/values/overlayable.xml
index 90f36e65..53ba4f49 100644
--- a/libs/appgrid/lib/res/values/overlayable.xml
+++ b/libs/appgrid/lib/res/values/overlayable.xml
@@ -23,7 +23,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="bool" name="car_app_show_recent_apps"/>
       <item type="bool" name="car_app_show_toolbar"/>
       <item type="bool" name="config_allow_reordering"/>
-      <item type="bool" name="config_enableMediaSessionAppsWhileDriving"/>
+      <item type="bool" name="config_enable_tos_banner"/>
       <item type="bool" name="use_defined_app_grid_dimensions"/>
       <item type="bool" name="use_vertical_app_grid"/>
       <item type="color" name="app_item_on_hover_background_color"/>
@@ -58,6 +58,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="banner_button_maximum_width"/>
       <item type="dimen" name="banner_content_margin"/>
       <item type="dimen" name="banner_image_view_size"/>
+      <item type="dimen" name="car_app_selector_column_min_height"/>
+      <item type="dimen" name="car_app_selector_column_min_width"/>
       <item type="dimen" name="fling_threshold"/>
       <item type="dimen" name="icon_size"/>
       <item type="dimen" name="page_indicator_edge_corner_radius"/>
diff --git a/libs/appgrid/lib/robotests/Android.bp b/libs/appgrid/lib/robotests/Android.bp
index b968ba52..4c2bacd7 100644
--- a/libs/appgrid/lib/robotests/Android.bp
+++ b/libs/appgrid/lib/robotests/Android.bp
@@ -37,6 +37,8 @@ android_robolectric_test {
         "androidx.test.core",
         "android.car.testapi",
         "android.car-system-stubs",
+        "flag-junit",
+        "truth",
     ],
 
     test_suites: [
diff --git a/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/AppGridViewModelTest.kt b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/AppGridViewModelTest.kt
new file mode 100644
index 00000000..214d977b
--- /dev/null
+++ b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/AppGridViewModelTest.kt
@@ -0,0 +1,90 @@
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
+
+package com.android.car.carlauncher
+
+import android.app.Application
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import androidx.test.core.app.ApplicationProvider
+import com.android.car.carlauncher.datasources.restricted.TosState
+import com.google.common.truth.Truth.assertThat
+import kotlinx.coroutines.flow.lastOrNull
+import kotlinx.coroutines.test.runTest
+import org.junit.After
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.robolectric.RobolectricTestRunner
+import org.robolectric.annotation.Config
+import shadows.ShadowResources
+
+@RunWith(RobolectricTestRunner::class)
+@Config(shadows = [ShadowResources::class])
+class AppGridViewModelTest {
+    @get:Rule val setFlagsRule = SetFlagsRule()
+    private val appGridRepository = FakeAppGridRepository()
+    private val application = ApplicationProvider.getApplicationContext<Application>()
+    private val viewModel = AppGridViewModel(appGridRepository, application)
+
+    @After
+    fun tearDown() {
+        ShadowResources.reset()
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun getShouldShowTosBanner_whenFlagEnabledAndBannerDisabledByConfig_returnsFalse() = runTest {
+        ShadowResources.setBoolean(R.bool.config_enable_tos_banner, false)
+
+        val enableBanner = viewModel.getShouldShowTosBanner().lastOrNull()
+
+        assertThat(enableBanner).isFalse()
+    }
+
+    @Test
+    @DisableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun getShouldShowTosBanner_whenFlagDisabled_returnsTrue() = runTest {
+        ShadowResources.setBoolean(R.bool.config_enable_tos_banner, false)
+
+        val enableBanner = viewModel.getShouldShowTosBanner().lastOrNull()
+
+        assertThat(enableBanner).isTrue()
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun getShouldShowTosBanner_whenBlockTosAppsIsFalse_returnsFalse() = runTest {
+        appGridRepository.tosState = TosState(false, emptyList())
+        ShadowResources.setBoolean(R.bool.config_enable_tos_banner, true)
+
+        val enableBanner = viewModel.getShouldShowTosBanner().lastOrNull()
+
+        assertThat(enableBanner).isFalse()
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_TOS_RESTRICTIONS_ENABLED)
+    fun getShouldShowTosBanner_whenBlockTosAppsIsTrue_returnsTrue() = runTest {
+        appGridRepository.tosState = TosState(true, emptyList())
+        ShadowResources.setBoolean(R.bool.config_enable_tos_banner, true)
+
+        val enableBanner = viewModel.getShouldShowTosBanner().lastOrNull()
+
+        assertThat(enableBanner).isTrue()
+    }
+}
diff --git a/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/FakeAppGridRepository.kt b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/FakeAppGridRepository.kt
new file mode 100644
index 00000000..e33a8a5b
--- /dev/null
+++ b/libs/appgrid/lib/robotests/src/com/android/car/carlauncher/FakeAppGridRepository.kt
@@ -0,0 +1,42 @@
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
+
+package com.android.car.carlauncher
+
+import com.android.car.carlauncher.datasources.restricted.TosState
+import com.android.car.carlauncher.repositories.AppGridRepository
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.flowOf
+
+/** Fake implementation of a [AppGridRepository] to be used in tests. */
+class FakeAppGridRepository : AppGridRepository {
+    var allAppsList = emptyList<AppItem>()
+    var mediaAppsList = emptyList<AppItem>()
+    var distractionOptimization = true
+
+    /** Fakes the terms of service state of the system. */
+    var tosState = TosState(true, emptyList())
+
+    override fun getAllAppsList(): Flow<List<AppItem>> = flowOf(allAppsList)
+
+    override fun requiresDistractionOptimization() = flowOf(distractionOptimization)
+
+    override fun getTosState(): Flow<TosState> = flowOf(tosState)
+
+    override suspend fun saveAppOrder(currentAppOrder: List<AppItem>) {}
+
+    override fun getMediaAppsList(): Flow<List<AppItem>> = flowOf(mediaAppsList)
+}
diff --git a/libs/appgrid/lib/robotests/src/shadows/ShadowResources.kt b/libs/appgrid/lib/robotests/src/shadows/ShadowResources.kt
new file mode 100644
index 00000000..02d46e00
--- /dev/null
+++ b/libs/appgrid/lib/robotests/src/shadows/ShadowResources.kt
@@ -0,0 +1,42 @@
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
+
+package shadows
+
+import android.annotation.BoolRes
+import android.content.res.Resources
+import org.robolectric.annotation.Implementation
+import org.robolectric.annotation.Implements
+
+/** Shadow of [Resources]. */
+@Implements(Resources::class)
+class ShadowResources {
+    @Implementation
+    fun getBoolean(@BoolRes id: Int): Boolean =
+            booleanResourceMap.getOrDefault(id, defaultValue = false)
+
+    companion object {
+        private var booleanResourceMap = mutableMapOf<Int, Boolean>()
+
+        fun setBoolean(id: Int, value: Boolean) {
+            booleanResourceMap[id] = value
+        }
+
+        fun reset() {
+            booleanResourceMap.clear()
+        }
+    }
+}
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
index 62735c0f..81e757db 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
@@ -117,8 +117,6 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
     private var appGridWidth = 0
     private var appGridHeight = 0
     private var offPageHoverBeforeScrollMs = 0L
-    private var numOfCols = 0
-    private var numOfRows = 0
     private var nextScrollDestination = 0
     private var currentScrollOffset = 0
     private var currentScrollState = 0
@@ -147,8 +145,6 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
         snapCallback = AppGridPageSnapCallback(this)
         dragCallback = AppItemDragCallback(this)
 
-        numOfCols = resources.getInteger(R.integer.car_app_selector_column_number)
-        numOfRows = resources.getInteger(R.integer.car_app_selector_row_number)
         appGridDragController = AppGridDragController()
         offPageHoverBeforeScrollMs = resources.getInteger(
             R.integer.ms_off_page_hover_before_scroll
@@ -164,13 +160,11 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
         appGridRecyclerView = view.requireViewById(R.id.apps_grid)
         appGridRecyclerView.isFocusable = false
         layoutManager =
-            AppGridLayoutManager(requireContext(), numOfCols, numOfRows, pageOrientation)
+            AppGridLayoutManager(requireContext(), pageOrientation)
         appGridRecyclerView.layoutManager = layoutManager
 
         val pageSnapper = AppGridPageSnapper(
             requireContext(),
-            numOfCols,
-            numOfRows,
             snapCallback
         )
         pageSnapper.attachToRecyclerView(appGridRecyclerView)
@@ -194,10 +188,8 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
         appGridRecyclerView.layoutDirection = View.LAYOUT_DIRECTION_LTR
         pageIndicatorContainer.layoutDirection = View.LAYOUT_DIRECTION_LTR
 
-        // we create but do not attach the adapter to recyclerview until view tree layout is
-        // complete and the total size of the app grid is measureable.
         adapter = AppGridAdapter(
-            requireContext(), numOfCols, numOfRows, dragCallback, snapCallback, this, mode
+            requireContext(), dragCallback, snapCallback, this, mode
         )
 
         adapter.registerAdapterDataObserver(object : RecyclerView.AdapterDataObserver() {
@@ -240,7 +232,8 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
         dimensionUpdateCallback.addListener(appGridRecyclerView)
         dimensionUpdateCallback.addListener(pageIndicator)
         dimensionUpdateCallback.addListener(this)
-        paginationController = PaginationController(windowBackground, dimensionUpdateCallback)
+        paginationController =
+            PaginationController(windowBackground, dimensionUpdateCallback)
 
         banner = view.requireViewById(R.id.tos_banner)
 
@@ -421,7 +414,10 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
             } else {
                 appGridHeight + 2 * appGridMarginVertical
             }
-        layoutManager.scrollToPositionWithOffset(offsetPageCount * numOfRows * numOfCols, 0)
+        layoutManager.scrollToPositionWithOffset(
+            offsetPageCount * appGridRecyclerView.numOfRows * appGridRecyclerView.numOfCols,
+            0
+        )
         pageIndicator.updateOffset(currentScrollOffset)
         pageIndicator.updatePageCount(adapter.pageCount)
     }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridPageSnapper.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridPageSnapper.java
index a77568e5..8b7716a8 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridPageSnapper.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridPageSnapper.java
@@ -37,22 +37,17 @@ public class AppGridPageSnapper extends LinearSnapHelper {
 
     @NonNull
     private final Context mContext;
-    @Nullable
-    private RecyclerView mRecyclerView;
-    private int mBlockSize = 0;
+    private AppGridRecyclerView mRecyclerView;
     private int mPrevFirstVisiblePos = 0;
     private AppGridPageSnapCallback mSnapCallback;
 
     public AppGridPageSnapper(
             @NonNull Context context,
-            int numOfCol,
-            int numOfRow,
             AppGridPageSnapCallback snapCallback) {
         mSnapCallback = snapCallback;
         mContext = context;
         mPageSnapThreshold = context.getResources().getFloat(R.dimen.page_snap_threshold);
         mFlingThreshold = context.getResources().getFloat(R.dimen.fling_threshold);
-        mBlockSize = numOfCol * numOfRow;
     }
 
     // Orientation helpers are lazily created per LayoutManager.
@@ -85,6 +80,7 @@ public class AppGridPageSnapper extends LinearSnapHelper {
         View currentPosView = getFirstMostVisibleChild(orientationHelper);
         int adapterPos = findAdapterPosition(currentPosView);
         int posToReturn;
+        int blockSize = mRecyclerView.getNumOfRows() * mRecyclerView.getNumOfCols();
 
         // In the case of swiping left, the current adapter position is smaller than the previous
         // first visible position. In the case of swiping right, the current adapter position is
@@ -92,11 +88,11 @@ public class AppGridPageSnapper extends LinearSnapHelper {
         // by only 1 column, the page should remain the same since we want to demonstrate some
         // stickiness
         if (adapterPos <= mPrevFirstVisiblePos
-                || (float) adapterPos % mBlockSize / mBlockSize < mPageSnapThreshold) {
-            posToReturn = adapterPos - adapterPos % mBlockSize;
+                || (float) adapterPos % blockSize / blockSize < mPageSnapThreshold) {
+            posToReturn = adapterPos - adapterPos % blockSize;
         } else {
             // Snap to next page
-            posToReturn = (adapterPos / mBlockSize + 1) * mBlockSize + mBlockSize - 1;
+            posToReturn = (adapterPos / blockSize + 1) * blockSize + blockSize - 1;
         }
         handleScrollToPos(posToReturn, orientationHelper);
         return null;
@@ -109,16 +105,19 @@ public class AppGridPageSnapper extends LinearSnapHelper {
 
     @VisibleForTesting
     int findFirstItemOnNextPage(int adapterPos) {
-        return (adapterPos / mBlockSize + 1) * mBlockSize + mBlockSize - 1;
+        int blockSize = mRecyclerView.getNumOfRows() * mRecyclerView.getNumOfCols();
+        return (adapterPos / blockSize + 1) * blockSize + blockSize - 1;
     }
 
     @VisibleForTesting
     int findFirstItemOnPrevPage(int adapterPos) {
-        return adapterPos - (adapterPos - 1) % mBlockSize - 1;
+        int blockSize = mRecyclerView.getNumOfRows() * mRecyclerView.getNumOfCols();
+        return adapterPos - (adapterPos - 1) % blockSize - 1;
     }
 
     private void handleScrollToPos(int posToReturn, OrientationHelper orientationHelper) {
-        mPrevFirstVisiblePos = posToReturn / mBlockSize * mBlockSize;
+        int blockSize = mRecyclerView.getNumOfRows() * mRecyclerView.getNumOfCols();
+        mPrevFirstVisiblePos = posToReturn / blockSize * blockSize;
         mRecyclerView.smoothScrollToPosition(posToReturn);
         mSnapCallback.notifySnapToPosition(posToReturn);
 
@@ -225,11 +224,15 @@ public class AppGridPageSnapper extends LinearSnapHelper {
 
     @Override
     public void attachToRecyclerView(@Nullable RecyclerView recyclerView) {
-        super.attachToRecyclerView(recyclerView);
-        mRecyclerView = recyclerView;
-        if (mRecyclerView == null) {
+        if (recyclerView == null) {
             return;
         }
+        if (!(recyclerView instanceof AppGridRecyclerView)) {
+            throw new IllegalStateException(
+                    "AppGridPageSnapper can only be used with AppGridRecyclerView.");
+        }
+        super.attachToRecyclerView(recyclerView);
+        mRecyclerView = (AppGridRecyclerView) recyclerView;
 
         // When a fling happens, try to find the target snap view and go there.
         mOnFlingListener = new RecyclerView.OnFlingListener() {
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java
index 8cd8936f..0af13f21 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java
@@ -17,6 +17,7 @@
 package com.android.car.carlauncher;
 
 import static com.android.car.carlauncher.AppGridConstants.PageOrientation;
+import static com.android.car.carlauncher.AppGridConstants.isHorizontal;
 
 import android.content.Context;
 import android.graphics.Rect;
@@ -24,6 +25,8 @@ import android.util.AttributeSet;
 import android.view.View;
 import android.view.ViewGroup;
 
+import androidx.annotation.VisibleForTesting;
+import androidx.recyclerview.widget.GridLayoutManager;
 import androidx.recyclerview.widget.RecyclerView;
 
 import com.android.car.carlauncher.pagination.PageIndexingHelper;
@@ -39,17 +42,18 @@ import com.android.car.carlauncher.recyclerview.PageMarginDecoration;
 public class AppGridRecyclerView extends RecyclerView implements DimensionUpdateListener {
     // the previous rotary focus direction
     private int mPrevRotaryPageScrollDirection = View.FOCUS_FORWARD;
-    private final int mNumOfCols;
-    private final int mNumOfRows;
+    private int mNumOfCols;
+    private int mNumOfRows;
+
     @PageOrientation
     private final int mPageOrientation;
     private AppGridAdapter mAdapter;
     private PageMarginDecoration mPageMarginDecoration;
+    private PageIndexingHelper mPageIndexingHelper;
+    private static final String TAG = "AppGridRecyclerView";
 
     public AppGridRecyclerView(Context context, AttributeSet attrs) {
         super(context, attrs);
-        mNumOfCols = getResources().getInteger(R.integer.car_app_selector_column_number);
-        mNumOfRows = getResources().getInteger(R.integer.car_app_selector_row_number);
         mPageOrientation = getResources().getBoolean(R.bool.use_vertical_app_grid)
                 ? PageOrientation.VERTICAL : PageOrientation.HORIZONTAL;
     }
@@ -59,8 +63,10 @@ public class AppGridRecyclerView extends RecyclerView implements DimensionUpdate
         if (!(adapter instanceof AppGridAdapter)) {
             throw new IllegalStateException("Expected Adapter of type AppGridAdapter");
         }
+        // skip super.setAdapter() call. We create but do not attach the adapter to recyclerview
+        // until view tree layout is complete and the total size of the app grid is measurable.
+        // Check AppGridRecyclerView#onDimensionsUpdated
         mAdapter = (AppGridAdapter) adapter;
-        super.setAdapter(mAdapter);
     }
 
     /**
@@ -125,11 +131,46 @@ public class AppGridRecyclerView extends RecyclerView implements DimensionUpdate
         }
     }
 
+    public PageIndexingHelper getPageIndexingHelper() {
+        return mPageIndexingHelper;
+    }
+
+    public int getNumOfRows() {
+        return mNumOfRows;
+    }
+
+    public int getNumOfCols() {
+        return mNumOfCols;
+    }
+
+    /**
+     * Forces the adapter to be attached with the specified number of rows and columns.
+     *
+     * <p>This method is intended for testing purposes only.
+     */
+    @VisibleForTesting
+    protected void forceAttachAdapter(int numOfRows, int numOfCols) {
+        mNumOfRows = numOfRows;
+        mNumOfCols = numOfCols;
+        super.setAdapter(mAdapter);
+    }
+
     @Override
     public void onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens) {
         ViewGroup.LayoutParams layoutParams = getLayoutParams();
         layoutParams.width = pageDimens.recyclerViewWidthPx;
         layoutParams.height = pageDimens.recyclerViewHeightPx;
+        this.mNumOfRows = gridDimens.mNumOfRows;
+        this.mNumOfCols = gridDimens.mNumOfCols;
+        if (!(getLayoutManager() instanceof GridLayoutManager)) {
+            throw new IllegalStateException(
+                    "AppGridRecyclerView can only be used with GridLayoutManager.");
+        }
+        if (isHorizontal(mPageOrientation)) {
+            ((GridLayoutManager) getLayoutManager()).setSpanCount(mNumOfRows);
+        } else {
+            ((GridLayoutManager) getLayoutManager()).setSpanCount(mNumOfCols);
+        }
 
         Rect pageBounds = new Rect();
         getGlobalVisibleRect(pageBounds);
@@ -140,9 +181,11 @@ public class AppGridRecyclerView extends RecyclerView implements DimensionUpdate
         if (mPageMarginDecoration != null) {
             removeItemDecoration(mPageMarginDecoration);
         }
+        mPageIndexingHelper = new PageIndexingHelper(mNumOfCols, mNumOfRows, mPageOrientation);
         mPageMarginDecoration = new PageMarginDecoration(pageDimens.marginHorizontalPx,
-                pageDimens.marginVerticalPx, new PageIndexingHelper(mNumOfCols, mNumOfRows,
-                mPageOrientation));
+                pageDimens.marginVerticalPx, mPageIndexingHelper);
         addItemDecoration(mPageMarginDecoration);
+        // Now attach adapter to the recyclerView, after dimens are updated.
+        super.setAdapter(mAdapter);
     }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt
index 37871111..a9aaf830 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridViewModel.kt
@@ -37,6 +37,7 @@ import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.SharingStarted
 import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.emitAll
+import kotlinx.coroutines.flow.flowOf
 import kotlinx.coroutines.flow.mapLatest
 import kotlinx.coroutines.flow.shareIn
 import kotlinx.coroutines.flow.transformLatest
@@ -127,6 +128,12 @@ class AppGridViewModel(
      */
     @OptIn(ExperimentalCoroutinesApi::class)
     fun getShouldShowTosBanner(): Flow<Boolean> {
+        if (Flags.tosRestrictionsEnabled()) {
+            val enableBanner = application.resources.getBoolean(R.bool.config_enable_tos_banner)
+            if (!enableBanner) {
+                return flowOf(false)
+            }
+        }
         return appGridRepository.getTosState().mapLatest {
             if (!it.shouldBlockTosApps) {
                 return@mapLatest false
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java
index a597ce0e..2cdd16b0 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppLauncherUtils.java
@@ -116,13 +116,13 @@ public class AppLauncherUtils {
      * @param context The application context
      * @return true if tos is uninitialized, false otherwise
      */
-    static boolean tosStatusUninitialized(Context context) {
+    public static boolean tosStatusUninitialized(Context context) {
         ContentResolver contentResolverForUser = context.createContextAsUser(
                         UserHandle.getUserHandleForUid(Process.myUid()), /* flags= */ 0)
                 .getContentResolver();
         String settingsValue = Settings.Secure.getString(
                 contentResolverForUser,
                 KEY_USER_TOS_ACCEPTED);
-        return Objects.equals(settingsValue, TOS_UNINITIALIZED);
+        return settingsValue == null || Objects.equals(settingsValue, TOS_UNINITIALIZED);
     }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt
index 2ad09029..fad5995e 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt
@@ -29,6 +29,8 @@ import kotlinx.coroutines.flow.emitAll
 import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOn
 import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onCompletion
+import kotlinx.coroutines.flow.onStart
 import kotlinx.coroutines.withContext
 
 /**
@@ -130,7 +132,7 @@ class AppOrderProtoDataSourceImpl(
      * __Handling Unavailable Apps:__
      * The client can choose to exclude apps that are unavailable (e.g., uninstalled or disabled)
      * from the sorted list.
-    */
+     */
     override fun getSavedAppOrder(): Flow<List<AppOrderInfo>> = flow {
         withContext(bgDispatcher) {
             val appOrderFromFiles = launcherItemListSource.readFromFile()?.launcherItemMessageList
@@ -143,7 +145,21 @@ class AppOrderProtoDataSourceImpl(
             }
         }
         emitAll(appOrderFlow)
-    }.flowOn(bgDispatcher)
+    }.flowOn(bgDispatcher).onStart {
+        /**
+         * Ideally, the client of this flow should use [clearAppOrder] to
+         * delete/reset the app order. However, if the file gets deleted
+         * externally (e.g., by another API or process), we need to observe
+         * the deletion event and update the flow accordingly.
+         */
+        launcherItemListSource.attachFileDeletionObserver {
+            // When the file is deleted, reset the appOrderFlow to an empty list.
+            appOrderFlow.value = emptyList()
+        }
+    }.onCompletion {
+        // Detach the observer to prevent leaks and unnecessary callbacks.
+        launcherItemListSource.detachFileDeletionObserver()
+    }
 
     /**
      * Provides a Flow of comparators to sort a list of apps.
@@ -157,7 +173,7 @@ class AppOrderProtoDataSourceImpl(
      */
     override fun getSavedAppOrderComparator(): Flow<Comparator<AppOrderInfo>> {
         return getSavedAppOrder().map { appOrderInfoList ->
-            val appOrderMap = appOrderInfoList.withIndex().associateBy({it.value}, {it.index})
+            val appOrderMap = appOrderInfoList.withIndex().associateBy({ it.value }, { it.index })
             Comparator<AppOrderInfo> { app1, app2 ->
                 when {
                     // Both present in predefined list.
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt
index afb2ff7e..5b088a0f 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/UXRestrictionDataSource.kt
@@ -26,7 +26,7 @@ import android.util.Log
 import androidx.lifecycle.asFlow
 import com.android.car.carlauncher.Flags
 import com.android.car.carlauncher.MediaSessionUtils
-import com.android.car.carlauncher.R
+import com.android.car.carlaunchercommon.R
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.channels.awaitClose
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/datastore/ProtoDataSource.java b/libs/appgrid/lib/src/com/android/car/carlauncher/datastore/ProtoDataSource.java
index 16ea685d..2bc30225 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/datastore/ProtoDataSource.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/datastore/ProtoDataSource.java
@@ -16,6 +16,7 @@
 
 package com.android.car.carlauncher.datastore;
 
+import android.os.FileObserver;
 import android.util.Log;
 
 import androidx.annotation.Nullable;
@@ -44,6 +45,8 @@ public abstract class ProtoDataSource<T extends MessageLite> {
     private static final String TAG = "ProtoDataSource";
     private FileInputStream mInputStream;
     private FileOutputStream mOutputStream;
+    private FileDeletionObserver mFileDeletionObserver;
+    private FileObserver mFileObserver;
 
     public ProtoDataSource(File dataFileDirectory, String dataFileName) {
         mFile = new File(dataFileDirectory, dataFileName);
@@ -80,6 +83,7 @@ public abstract class ProtoDataSource<T extends MessageLite> {
      */
     public boolean writeToFile(T data) {
         boolean success = true;
+        boolean dataFileAlreadyExisted = getDataFile().exists();
         try {
             if (mOutputStream == null) {
                 mOutputStream = new FileOutputStream(getDataFile(), false);
@@ -100,6 +104,23 @@ public abstract class ProtoDataSource<T extends MessageLite> {
                 Log.e(TAG, "Unable to close output stream. ");
             }
         }
+        // If writing to the file was successful and this file is newly created, attach deletion
+        // observer.
+        if (success && !dataFileAlreadyExisted) {
+            // Stop watching for deletions on any previously monitored file.
+            detachFileDeletionObserver();
+            mFileObserver = new FileObserver(getDataFile()) {
+                @Override
+                public void onEvent(int event, @Nullable String path) {
+                    if (DELETE_SELF == event) {
+                        Log.i(TAG, "DELETE_SELF event triggered");
+                        mFileDeletionObserver.onDeleted();
+                        mFileObserver.stopWatching();
+                    }
+                }
+            };
+            mFileObserver.startWatching();
+        }
         return success;
     }
 
@@ -148,6 +169,31 @@ public abstract class ProtoDataSource<T extends MessageLite> {
         return success;
     }
 
+    /**
+     * Attaches a {@link FileDeletionObserver} that will be notified when the
+     * associated proto file is deleted.
+     *
+     * <p>Calling this method replaces any previously attached observer.
+     *
+     * @param observer The {@link FileDeletionObserver} to attach, or {@code null}
+     *        to remove any existing observer.
+     */
+    public void attachFileDeletionObserver(FileDeletionObserver observer) {
+        mFileDeletionObserver = observer;
+    }
+
+    /**
+     * Detaches the currently attached {@link FileDeletionObserver}, if any.
+     *
+     * <p>This stops the observer from receiving further notifications about file
+     * deletion events.
+     */
+    public void detachFileDeletionObserver() {
+        if (mFileObserver != null) {
+            mFileObserver.stopWatching();
+        }
+    }
+
     /**
      * This method will be called by {@link ProtoDataSource#readFromFile}.
      *
@@ -176,4 +222,21 @@ public abstract class ProtoDataSource<T extends MessageLite> {
      */
     protected abstract void writeDelimitedTo(T outputData, OutputStream outputStream)
             throws IOException;
+
+    /**
+     * An interface for observing the deletion of a file.
+     *
+     * <p>Classes that implement this interface can be attached to a
+     * {@code ProtoDataSource} (or a similar class managing file monitoring)
+     * to receive notifications when the associated file is deleted.
+     *
+     * @see ProtoDataSource#attachFileDeletionObserver(FileDeletionObserver)
+     * @see ProtoDataSource#detachFileDeletionObserver()
+     */
+    public interface FileDeletionObserver {
+        /**
+         * Called when the observed file is deleted.
+         */
+        void onDeleted();
+    }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PageMeasurementHelper.java b/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PageMeasurementHelper.java
index 18b6ac29..eb09b182 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PageMeasurementHelper.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PageMeasurementHelper.java
@@ -27,8 +27,6 @@ import com.android.car.carlauncher.recyclerview.PageMarginDecoration;
  * Helper class for PaginationController that computes the measurements of app grid and app items.
  */
 public class PageMeasurementHelper {
-    private final int mNumOfCols;
-    private final int mNumOfRows;
     @PageOrientation
     private final int mPageOrientation;
     private final boolean mUseDefinedDimensions;
@@ -37,6 +35,8 @@ public class PageMeasurementHelper {
     private final int mDefinedMarginHorizontal;
     private final int mDefinedMarginVertical;
     private final int mDefinedPageIndicatorSize;
+    private final int mMinItemWidth;
+    private final int mMinItemHeight;
 
     private int mWindowWidth;
     private int mWindowHeight;
@@ -44,10 +44,6 @@ public class PageMeasurementHelper {
     private PageDimensions mPageDimensions;
 
     public PageMeasurementHelper(View windowBackground) {
-        mNumOfCols = windowBackground.getResources().getInteger(
-                R.integer.car_app_selector_column_number);
-        mNumOfRows = windowBackground.getResources().getInteger(
-                R.integer.car_app_selector_row_number);
         mPageOrientation = windowBackground.getResources().getBoolean(R.bool.use_vertical_app_grid)
                 ? PageOrientation.VERTICAL : PageOrientation.HORIZONTAL;
         mUseDefinedDimensions = windowBackground.getResources().getBoolean(
@@ -62,6 +58,10 @@ public class PageMeasurementHelper {
                 R.dimen.app_grid_margin_vertical);
         mDefinedPageIndicatorSize = windowBackground.getResources().getDimensionPixelSize(
                 R.dimen.page_indicator_height);
+        mMinItemWidth = windowBackground.getResources().getDimensionPixelSize(
+                R.dimen.car_app_selector_column_min_width);
+        mMinItemHeight = windowBackground.getResources().getDimensionPixelSize(
+                R.dimen.car_app_selector_column_min_height);
     }
 
     /**
@@ -109,11 +109,21 @@ public class PageMeasurementHelper {
                     - (isHorizontal() ? mDefinedPageIndicatorSize : 0);
 
             // Step 2: Round the measurements to ensure child view holder cells have an exact fit.
-            gridWidth = roundDownToModuloMultiple(gridWidth, mNumOfCols);
-            gridHeight = roundDownToModuloMultiple(gridHeight, mNumOfRows);
-            int cellWidth = gridWidth / mNumOfCols;
-            int cellHeight = gridHeight / mNumOfRows;
-            mGridDimensions = new GridDimensions(gridWidth, gridHeight, cellWidth, cellHeight);
+
+            // Calculate the maximum number of columns that can fit in the grid,
+            // ensuring each column has at least the minimum item width.
+            int numOfCols = gridWidth / mMinItemWidth;
+            gridWidth = roundDownToModuloMultiple(gridWidth, numOfCols);
+
+            // Calculate the maximum number of columns that can fit in the grid,
+            // ensuring each column has at least the minimum item width.
+            int numOfRows = gridHeight / mMinItemHeight;
+            gridHeight = roundDownToModuloMultiple(gridHeight, numOfRows);
+
+            int cellWidth = gridWidth / numOfCols;
+            int cellHeight = gridHeight / numOfRows;
+            mGridDimensions = new GridDimensions(gridWidth, gridHeight, cellWidth, cellHeight,
+                    numOfRows, numOfCols);
 
             // Step 3: Since the grid dimens are rounded, we need to recalculate the margins.
             int marginHorizontal = (windowWidth - gridWidth) / 2;
@@ -172,12 +182,17 @@ public class PageMeasurementHelper {
         public int gridHeightPx;
         public int cellWidthPx;
         public int cellHeightPx;
+        public int mNumOfRows;
+        public int mNumOfCols;
 
-        public GridDimensions(int gridWidth, int gridHeight, int cellWidth, int cellHeight) {
+        public GridDimensions(int gridWidth, int gridHeight, int cellWidth, int cellHeight,
+                int numOfRows, int numOfCols) {
             gridWidthPx = gridWidth;
             gridHeightPx = gridHeight;
             cellWidthPx = cellWidth;
             cellHeightPx = cellHeight;
+            mNumOfRows = numOfRows;
+            mNumOfCols = numOfCols;
         }
 
         @Override
@@ -187,6 +202,8 @@ public class PageMeasurementHelper {
                     + " gridHeightPx: %d".formatted(gridHeightPx)
                     + " cellWidthPx: %d".formatted(cellWidthPx)
                     + " cellHeightPx: %d".formatted(cellHeightPx)
+                    + " numOfRows: %d".formatted(mNumOfRows)
+                    + " numOfCols: %d".formatted(mNumOfCols)
                     + "}";
         }
     }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java
index 66405708..252283d2 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridAdapter.java
@@ -17,7 +17,6 @@
 package com.android.car.carlauncher.recyclerview;
 
 import static com.android.car.carlauncher.AppGridConstants.AppItemBoundDirection;
-import static com.android.car.carlauncher.AppGridConstants.PageOrientation;
 
 import android.content.Context;
 import android.graphics.Rect;
@@ -26,11 +25,13 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.widget.LinearLayout;
 
+import androidx.annotation.NonNull;
 import androidx.recyclerview.widget.DiffUtil;
 import androidx.recyclerview.widget.RecyclerView;
 
 import com.android.car.carlauncher.AppGridFragment.Mode;
 import com.android.car.carlauncher.AppGridPageSnapper;
+import com.android.car.carlauncher.AppGridRecyclerView;
 import com.android.car.carlauncher.AppItem;
 import com.android.car.carlauncher.LauncherItem;
 import com.android.car.carlauncher.LauncherItemDiffCallback;
@@ -51,11 +52,11 @@ public class AppGridAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder
     private static final String TAG = "AppGridAdapter";
     private final Context mContext;
     private final LayoutInflater mInflater;
-    private final PageIndexingHelper mIndexingHelper;
+    private PageIndexingHelper mIndexingHelper;
     private final AppItemViewHolder.AppItemDragCallback mDragCallback;
     private final AppGridPageSnapper.AppGridPageSnapCallback mSnapCallback;
-    private final int mNumOfCols;
-    private final int mNumOfRows;
+    private int mNumOfCols;
+    private int mNumOfRows;
     private int mAppItemWidth;
     private int mAppItemHeight;
     // grid order of the mLauncherItems used by DiffUtils in dispatchUpdates to animate UI updates
@@ -70,25 +71,38 @@ public class AppGridAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder
 
     private AppGridAdapterListener mAppGridAdapterListener;
 
-    public AppGridAdapter(Context context, int numOfCols, int numOfRows,
+    public AppGridAdapter(Context context,
             AppItemViewHolder.AppItemDragCallback dragCallback,
             AppGridPageSnapper.AppGridPageSnapCallback snapCallback,
             AppGridAdapterListener appGridAdapterListener,
             Mode mode) {
         mContext = context;
         mInflater = LayoutInflater.from(context);
-        mNumOfCols = numOfCols;
-        mNumOfRows = numOfRows;
         mDragCallback = dragCallback;
         mSnapCallback = snapCallback;
-        int pageOrientation =  context.getResources().getBoolean(R.bool.use_vertical_app_grid)
-                ? PageOrientation.VERTICAL : PageOrientation.HORIZONTAL;
-        mIndexingHelper = new PageIndexingHelper(numOfCols, numOfRows, pageOrientation);
         mGridOrderedLauncherItems = new ArrayList<>();
         mAppGridMode = mode;
         mAppGridAdapterListener = appGridAdapterListener;
     }
 
+    @Override
+    public void onAttachedToRecyclerView(@NonNull RecyclerView recyclerView) {
+        if (!(recyclerView instanceof AppGridRecyclerView)) {
+            throw new IllegalStateException(
+                    "AppGridPageSnapper can only be used with AppGridRecyclerView.");
+        }
+        super.onAttachedToRecyclerView(recyclerView);
+        mNumOfRows = ((AppGridRecyclerView) recyclerView).getNumOfRows();
+        mNumOfCols = ((AppGridRecyclerView) recyclerView).getNumOfCols();
+        mIndexingHelper = ((AppGridRecyclerView) recyclerView).getPageIndexingHelper();
+        if (mIndexingHelper == null) {
+            throw new IllegalStateException(
+                    "AppGridRecyclerView's PageIndexingHelper is not initialized. "
+                            + "Please ensure the adapter is attached to AppGridRecyclerView only "
+                            + "after the bounds are ready.");
+        }
+    }
+
     /**
      * Updates the dimension measurements of the app items and app grid bounds.
      *
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridLayoutManager.java b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridLayoutManager.java
index df4b0d0b..96a6c545 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridLayoutManager.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/recyclerview/AppGridLayoutManager.java
@@ -24,15 +24,27 @@ import android.content.Context;
 import androidx.recyclerview.widget.GridLayoutManager;
 import androidx.recyclerview.widget.RecyclerView;
 
+import com.android.car.carlauncher.AppGridRecyclerView;
+import com.android.car.carlauncher.pagination.PageMeasurementHelper;
+
 /**
- * Grid style layout manager for AppGridRecyclerView.
+ * Grid style layout manager for {@link AppGridRecyclerView}
  */
 public class AppGridLayoutManager extends GridLayoutManager {
     boolean mShouldLayoutChildren = true;
 
-    public AppGridLayoutManager(Context context, int numOfCols, int numOfRows,
+    private static final int DEFAULT_SPAN_COUNT = 3;
+
+    /**
+     * Initializes the layoutManager.
+     * Note: The spanCount is updated when dimensions are available,
+     * check:{@link
+     * AppGridRecyclerView#onDimensionsUpdated(PageMeasurementHelper.PageDimensions,
+     * PageMeasurementHelper.GridDimensions)}
+     */
+    public AppGridLayoutManager(Context context,
             @PageOrientation int pageOrientation) {
-        super(context, isHorizontal(pageOrientation) ? numOfRows : numOfCols,
+        super(context, DEFAULT_SPAN_COUNT,
                 isHorizontal(pageOrientation)
                         ? GridLayoutManager.HORIZONTAL : GridLayoutManager.VERTICAL, false);
     }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt
index 37f0c0e3..5d68f9c7 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt
@@ -21,11 +21,13 @@ import android.content.ComponentName
 import android.content.Context
 import android.os.Process
 import android.os.UserHandle
+import android.view.Display.INVALID_DISPLAY
 import android.view.View
 import com.android.car.carlaunchercommon.shortcuts.AppInfoShortcutItem
 import com.android.car.carlaunchercommon.shortcuts.ForceStopShortcutItem
 import com.android.car.carlaunchercommon.shortcuts.PinShortcutItem
 import com.android.car.dockutil.Flags
+import com.android.car.dockutil.events.DockCompatUtils.isDockSupportedOnDisplay
 import com.android.car.dockutil.events.DockEventSenderHelper
 import com.android.car.ui.shortcutspopup.CarUiShortcutsPopup
 
@@ -79,7 +81,9 @@ class AppShortcutsFactory(
                         UserHandle.getUserHandleForUid(Process.myUid())
                     )
                 )
-        if (Flags.dockFeature()) {
+        if (Flags.dockFeature() &&
+            isDockSupportedOnDisplay(context, context.display?.displayId ?: INVALID_DISPLAY)
+        ) {
             carUiShortcutsPopupBuilder
                 .addShortcut(buildPinToDockShortcut(componentName, context))
         }
diff --git a/libs/appgrid/lib/tests/res/xml/empty_test_activity.xml b/libs/appgrid/lib/tests/res/xml/empty_test_activity.xml
index 44e80f20..8abeca25 100644
--- a/libs/appgrid/lib/tests/res/xml/empty_test_activity.xml
+++ b/libs/appgrid/lib/tests/res/xml/empty_test_activity.xml
@@ -19,7 +19,7 @@
     android:id="@+id/test_container"
     android:layout_width="match_parent"
     android:layout_height="match_parent">
-    <androidx.recyclerview.widget.RecyclerView
+    <com.android.car.carlauncher.AppGridRecyclerView
         android:id="@+id/list"
         android:layout_width="match_parent"
         android:layout_height="match_parent"
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java
index b22e9e8d..accebebb 100644
--- a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java
+++ b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridAdapterTest.java
@@ -36,6 +36,7 @@ import com.android.car.carlauncher.recyclerview.AppItemViewHolder;
 import org.junit.Before;
 import org.junit.Test;
 import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
 
 public class AppGridAdapterTest {
     private final Context mContext =
@@ -46,21 +47,28 @@ public class AppGridAdapterTest {
     public AppGridPageSnapper.AppGridPageSnapCallback mMockSnapCallback;
     @Mock
     public Rect mMockPageBound;
+    @Mock
+    public AppGridRecyclerView mAppGridRecyclerView;
     public AppGridAdapter mTestAppGridAdapter;
 
     @Before
     public void setUp() throws Exception {
-        mMockDragCallback = mock(AppItemViewHolder.AppItemDragCallback.class);
-        mMockSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
+        MockitoAnnotations.initMocks(this);
     }
 
     @Test
     public void testPageRounding_getItemCount_getPageCount() {
         int numOfCols = 5;
         int numOfRows = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+        when(mAppGridRecyclerView.getNumOfRows()).thenReturn(numOfRows);
+        when(mAppGridRecyclerView.getNumOfCols()).thenReturn(numOfCols);
+        when(mAppGridRecyclerView.getPageIndexingHelper()).thenReturn(
+                new PageIndexingHelper(numOfCols, numOfRows,
+                        PageOrientation.HORIZONTAL));
+        mTestAppGridAdapter = new AppGridAdapter(mContext,
                 mMockDragCallback, mMockSnapCallback,
                 mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
+        mTestAppGridAdapter.onAttachedToRecyclerView(mAppGridRecyclerView);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -86,9 +94,10 @@ public class AppGridAdapterTest {
         numOfCols = 4;
         numOfRows = 6;
 
-        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+        mTestAppGridAdapter = new AppGridAdapter(mContext,
                 mMockDragCallback, mMockSnapCallback,
                 mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
+        mTestAppGridAdapter.onAttachedToRecyclerView(mAppGridRecyclerView);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -115,9 +124,15 @@ public class AppGridAdapterTest {
         // an adapter with 45 items
         int numOfCols = 5;
         int numOfRows = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+        when(mAppGridRecyclerView.getNumOfRows()).thenReturn(numOfRows);
+        when(mAppGridRecyclerView.getNumOfCols()).thenReturn(numOfCols);
+        when(mAppGridRecyclerView.getPageIndexingHelper()).thenReturn(
+                new PageIndexingHelper(numOfCols, numOfRows,
+                        PageOrientation.HORIZONTAL));
+        mTestAppGridAdapter = new AppGridAdapter(mContext,
                 mMockDragCallback, mMockSnapCallback,
                 mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
+        mTestAppGridAdapter.onAttachedToRecyclerView(mAppGridRecyclerView);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -150,9 +165,15 @@ public class AppGridAdapterTest {
         // an adapter with 45 items
         int numOfRows = 5;
         int numOfCols = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+        when(mAppGridRecyclerView.getNumOfRows()).thenReturn(numOfRows);
+        when(mAppGridRecyclerView.getNumOfCols()).thenReturn(numOfCols);
+        when(mAppGridRecyclerView.getPageIndexingHelper()).thenReturn(
+                new PageIndexingHelper(numOfCols, numOfRows,
+                        PageOrientation.HORIZONTAL));
+        mTestAppGridAdapter = new AppGridAdapter(mContext,
                 mMockDragCallback, mMockSnapCallback,
                 mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
+        mTestAppGridAdapter.onAttachedToRecyclerView(mAppGridRecyclerView);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -193,9 +214,15 @@ public class AppGridAdapterTest {
         // an adapter with 40 items, 3 page, and 5 padded empty items
         int numOfCols = 5;
         int numOfRows = 3;
-        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+        when(mAppGridRecyclerView.getNumOfRows()).thenReturn(numOfRows);
+        when(mAppGridRecyclerView.getNumOfCols()).thenReturn(numOfCols);
+        when(mAppGridRecyclerView.getPageIndexingHelper()).thenReturn(
+                new PageIndexingHelper(numOfCols, numOfRows,
+                        PageOrientation.HORIZONTAL));
+        mTestAppGridAdapter = new AppGridAdapter(mContext,
                 mMockDragCallback, mMockSnapCallback,
                 mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
+        mTestAppGridAdapter.onAttachedToRecyclerView(mAppGridRecyclerView);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
@@ -246,9 +273,15 @@ public class AppGridAdapterTest {
         // an adapter with 44 items, 3 page, and 16 padded empty items
         int numOfCols = 4;
         int numOfRows = 5;
-        mTestAppGridAdapter = new AppGridAdapter(mContext, numOfCols, numOfRows,
+        when(mAppGridRecyclerView.getNumOfRows()).thenReturn(numOfRows);
+        when(mAppGridRecyclerView.getNumOfCols()).thenReturn(numOfCols);
+        when(mAppGridRecyclerView.getPageIndexingHelper()).thenReturn(
+                new PageIndexingHelper(numOfCols, numOfRows,
+                        PageOrientation.HORIZONTAL));
+        mTestAppGridAdapter = new AppGridAdapter(mContext,
                 mMockDragCallback, mMockSnapCallback,
                 mock(AppGridAdapter.AppGridAdapterListener.class), AppGridFragment.Mode.ALL_APPS);
+        mTestAppGridAdapter.onAttachedToRecyclerView(mAppGridRecyclerView);
         mTestAppGridAdapter.updateViewHolderDimensions(mMockPageBound,
                 /* appItemWidth */ 260, /* appItemHeight */ 200);
         mTestAppGridAdapter = spy(mTestAppGridAdapter);
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridPageSnapperTest.java b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridPageSnapperTest.java
index da1a2d70..50cac054 100644
--- a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridPageSnapperTest.java
+++ b/libs/appgrid/lib/tests/src/com/android/car/carlauncher/AppGridPageSnapperTest.java
@@ -97,11 +97,12 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = mock(Context.class);
-            RecyclerView rv = activity.requireViewById(R.id.list);
-            GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext, mRowNo,
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
+            GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext, 1,
                     GridLayoutManager.HORIZONTAL, false);
             rv.setLayoutManager(gridLayoutManager);
             rv.setAdapter(adapter);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             RecyclerViewIdlingResource.register(mActivityRule.getScenario());
         });
         // Check if first item on the first page is displayed
@@ -109,13 +110,12 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = (Context) spy(activity);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             mAppGridPageSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
             mPageSnapper = new AppGridPageSnapper(
                     testableContext,
-                    mColNo,
-                    mRowNo,
                     mAppGridPageSnapCallback);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             mPageSnapper.attachToRecyclerView(rv);
         });
         // Check if first item on the first page is displayed
@@ -145,13 +145,14 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = mock(Context.class);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext,
                     mRowNo,
                     GridLayoutManager.HORIZONTAL,
                     false);
             rv.setLayoutManager(gridLayoutManager);
             rv.setAdapter(adapter);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             RecyclerViewIdlingResource.register(mActivityRule.getScenario());
         });
 
@@ -159,13 +160,12 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = (Context) spy(activity);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             mAppGridPageSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
             mPageSnapper = new AppGridPageSnapper(
                     testableContext,
-                    mColNo,
-                    mRowNo,
                     mAppGridPageSnapCallback);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             mPageSnapper.attachToRecyclerView(rv);
         });
 
@@ -195,13 +195,14 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = mock(Context.class);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext,
                     mRowNo,
                     GridLayoutManager.HORIZONTAL,
                     false);
             rv.setLayoutManager(gridLayoutManager);
             rv.setAdapter(adapter);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             RecyclerViewIdlingResource.register(mActivityRule.getScenario());
         });
 
@@ -209,13 +210,12 @@ public class AppGridPageSnapperTest {
         onView(withText(getItemText(0, 0))).check(matches(isCompletelyDisplayed()));
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = (Context) spy(activity);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             mAppGridPageSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
             mPageSnapper = new AppGridPageSnapper(
                     testableContext,
-                    mColNo,
-                    mRowNo,
                     mAppGridPageSnapCallback);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             mPageSnapper.attachToRecyclerView(rv);
         });
 
@@ -269,11 +269,12 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = mock(Context.class);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext, mRowNo,
                     GridLayoutManager.HORIZONTAL, false);
             rv.setLayoutManager(gridLayoutManager);
             rv.setAdapter(adapter);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             RecyclerViewIdlingResource.register(mActivityRule.getScenario());
         });
 
@@ -281,13 +282,12 @@ public class AppGridPageSnapperTest {
         onView(withText(getItemText(0, 0))).check(matches(isCompletelyDisplayed()));
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = (Context) spy(activity);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             mAppGridPageSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
             mPageSnapper = new AppGridPageSnapper(
                     testableContext,
-                    mColNo,
-                    mRowNo,
                     mAppGridPageSnapCallback);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             mPageSnapper.attachToRecyclerView(rv);
         });
 
@@ -329,11 +329,12 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = mock(Context.class);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext, mRowNo,
                     GridLayoutManager.HORIZONTAL, false);
             rv.setLayoutManager(gridLayoutManager);
             rv.setAdapter(adapter);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             RecyclerViewIdlingResource.register(mActivityRule.getScenario());
 
         });
@@ -342,13 +343,12 @@ public class AppGridPageSnapperTest {
         onView(withText(getItemText(0, 0))).check(matches(isCompletelyDisplayed()));
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = (Context) spy(activity);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             mAppGridPageSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
             mPageSnapper = spy(new AppGridPageSnapper(
                     testableContext,
-                    mColNo,
-                    mRowNo,
                     mAppGridPageSnapCallback));
+            rv.forceAttachAdapter(mRowNo, mColNo);
             mPageSnapper.attachToRecyclerView(rv);
         });
 
@@ -372,11 +372,12 @@ public class AppGridPageSnapperTest {
 
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = mock(Context.class);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             GridLayoutManager gridLayoutManager = new GridLayoutManager(testableContext, mRowNo,
                     GridLayoutManager.HORIZONTAL, false);
             rv.setLayoutManager(gridLayoutManager);
             rv.setAdapter(adapter);
+            rv.forceAttachAdapter(mRowNo, mColNo);
             RecyclerViewIdlingResource.register(mActivityRule.getScenario());
 
         });
@@ -385,13 +386,12 @@ public class AppGridPageSnapperTest {
         onView(withText(getItemText(0, 0))).check(matches(isCompletelyDisplayed()));
         mActivityRule.getScenario().onActivity(activity -> {
             Context testableContext = (Context) spy(activity);
-            RecyclerView rv = activity.requireViewById(R.id.list);
+            AppGridRecyclerView rv = activity.requireViewById(R.id.list);
             mAppGridPageSnapCallback = mock(AppGridPageSnapper.AppGridPageSnapCallback.class);
             mPageSnapper = spy(new AppGridPageSnapper(
                     testableContext,
-                    mColNo,
-                    mRowNo,
                     mAppGridPageSnapCallback));
+            rv.forceAttachAdapter(mRowNo, mColNo);
             mPageSnapper.attachToRecyclerView(rv);
         });
 
diff --git a/libs/car-launcher-common/res/values/config.xml b/libs/car-launcher-common/res/values/config.xml
new file mode 100644
index 00000000..18772a0c
--- /dev/null
+++ b/libs/car-launcher-common/res/values/config.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<resources>
+    <!--
+        Config for allowing NDO apps to be opened while driving if they contain an active media
+        session and media notification. These NDO apps will still be blocked by blocking UI, but may
+        be provided playback controls.
+    -->
+    <bool name="config_enableMediaSessionAppsWhileDriving">true</bool>
+</resources>
\ No newline at end of file
```

