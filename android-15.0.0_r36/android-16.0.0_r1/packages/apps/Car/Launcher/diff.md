```diff
diff --git a/OWNERS b/OWNERS
index b022f363..d485d6bc 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,5 +5,4 @@ alexstetson@google.com
 priyanksingh@google.com
 
 # Secondary
-nehah@google.com
 babakbo@google.com
diff --git a/app/Android.bp b/app/Android.bp
index fde4bd58..b86b545e 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -52,10 +52,15 @@ android_library {
         "CarAppGrid-lib",
         "SystemUISharedLib",
         "android.car.cluster.navigation",
-        "car-resource-common",
+        "oem-token-lib",
     ],
 
-    libs: ["android.car"],
+    libs: [
+        "android.car",
+        "token-shared-lib-prebuilt",
+    ],
+
+    enforce_uses_libs: false,
 
     manifest: "AndroidManifest.xml",
     // TODO(b/319708040): re-enable use_resource_processor
@@ -83,9 +88,17 @@ android_app {
         "Launcher3QuickStep",
     ],
 
-    static_libs: ["CarLauncher-core"],
+    static_libs: [
+        "CarLauncher-core",
+        "oem-token-lib",
+    ],
+
+    libs: [
+        "android.car",
+        "token-shared-lib-prebuilt",
+    ],
 
-    libs: ["android.car"],
+    enforce_uses_libs: false,
 
     optimize: {
         enabled: false,
diff --git a/app/AndroidManifest.xml b/app/AndroidManifest.xml
index b6100e22..1ef55297 100644
--- a/app/AndroidManifest.xml
+++ b/app/AndroidManifest.xml
@@ -91,6 +91,7 @@
         android:label="@string/app_title"
         android:theme="@style/Theme.Launcher"
         android:supportsRtl="true">
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
         <activity
             android:name=".CarLauncher"
             android:configChanges="uiMode|mcc|mnc"
@@ -111,6 +112,7 @@
         </activity>
         <activity
             android:name=".ControlBarActivity"
+            android:theme="@style/Theme.ControlBar"
             android:launchMode="singleInstance"
             android:clearTaskOnLaunch="true"
             android:stateNotNeeded="true"
diff --git a/app/OWNERS b/app/OWNERS
index 820a6050..6e10365d 100644
--- a/app/OWNERS
+++ b/app/OWNERS
@@ -3,7 +3,6 @@
 
 alexstetson@google.com
 danzz@google.com
-nehah@google.com
 babakbo@google.com
 arnaudberry@google.com
 stenning@google.com
diff --git a/app/res/color/media_card_action_button_color.xml b/app/res/color/media_card_action_button_color.xml
new file mode 100644
index 00000000..2d2b5907
--- /dev/null
+++ b/app/res/color/media_card_action_button_color.xml
@@ -0,0 +1,19 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:color="?oemColorSurfaceVariant"/>
+</selector>
diff --git a/app/res/color/media_card_custom_action_button_color.xml b/app/res/color/media_card_custom_action_button_color.xml
new file mode 100644
index 00000000..e84ac07e
--- /dev/null
+++ b/app/res/color/media_card_custom_action_button_color.xml
@@ -0,0 +1,19 @@
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+  <item android:color="?oemColorOnSurface"/>
+</selector>
diff --git a/app/res/color/media_card_panel_button_background_tint_state_list.xml b/app/res/color/media_card_panel_button_background_tint_state_list.xml
index e75e3bbd..134b6b3e 100644
--- a/app/res/color/media_card_panel_button_background_tint_state_list.xml
+++ b/app/res/color/media_card_panel_button_background_tint_state_list.xml
@@ -15,8 +15,8 @@
   -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:color="@color/car_surface_container_highest"
+    <item android:color="?oemColorSurfaceContainerHighest"
         android:state_selected="false"/>
-    <item android:color="@color/car_on_surface"
+    <item android:color="?oemColorOnSurface"
         android:state_selected="true"/>
 </selector>
diff --git a/app/res/color/media_card_panel_button_tint_state_list.xml b/app/res/color/media_card_panel_button_tint_state_list.xml
index 3cdf6ab2..7342d905 100644
--- a/app/res/color/media_card_panel_button_tint_state_list.xml
+++ b/app/res/color/media_card_panel_button_tint_state_list.xml
@@ -15,8 +15,8 @@
   -->
 
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
-    <item android:color="@color/car_surface"
+    <item android:color="?oemColorSurface"
         android:state_selected="true"/>
-    <item android:color="@color/car_on_surface"
+    <item android:color="?oemColorOnSurface"
         android:state_selected="false"/>
 </selector>
diff --git a/app/res/color/media_card_seekbar_thumb_color.xml b/app/res/color/media_card_seekbar_thumb_color.xml
index f81a6762..dc63ceef 100644
--- a/app/res/color/media_card_seekbar_thumb_color.xml
+++ b/app/res/color/media_card_seekbar_thumb_color.xml
@@ -17,6 +17,6 @@
 <selector xmlns:android="http://schemas.android.com/apk/res/android">
     <item android:color="@android:color/transparent"
         android:state_selected="true"/>
-    <item android:color="@color/car_on_surface"
+    <item android:color="?oemColorOnSurface"
         android:state_selected="false"/>
 </selector>
diff --git a/app/res/drawable/circle_button_background.xml b/app/res/drawable/circle_button_background.xml
index 64226821..a639122a 100644
--- a/app/res/drawable/circle_button_background.xml
+++ b/app/res/drawable/circle_button_background.xml
@@ -18,7 +18,7 @@
     <item>
         <shape
             android:shape="oval">
-            <solid android:color="@color/car_surface_container_highest"/>
+            <solid android:color="?oemColorSurfaceContainerHighest"/>
         </shape>
     </item>
     <item android:drawable="@drawable/button_ripple"/>
diff --git a/app/res/drawable/divider.xml b/app/res/drawable/divider.xml
index 6c48401e..66c558e0 100644
--- a/app/res/drawable/divider.xml
+++ b/app/res/drawable/divider.xml
@@ -16,6 +16,6 @@
 
 <shape xmlns:android="http://schemas.android.com/apk/res/android"
     android:shape="rectangle">
-    <solid android:color="@color/car_on_background"/>
+    <solid android:color="?oemColorOnBackground"/>
     <size android:height="0.5dp"/>
 </shape>
\ No newline at end of file
diff --git a/app/res/drawable/ic_history.xml b/app/res/drawable/ic_history.xml
index 9f16dd8a..9820051a 100644
--- a/app/res/drawable/ic_history.xml
+++ b/app/res/drawable/ic_history.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="960"
     android:viewportHeight="960">
     <path
-        android:fillColor="@color/car_on_surface"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M146.67,880Q119.67,880 99.83,860.17Q80,840.33 80,813.33L80,386.67Q80,359.67 99.83,339.83Q119.67,320 146.67,320L813.33,320Q840.33,320 860.17,339.83Q880,359.67 880,386.67L880,813.33Q880,840.33 860.17,860.17Q840.33,880 813.33,880L146.67,880ZM146.67,813.33L813.33,813.33Q813.33,813.33 813.33,813.33Q813.33,813.33 813.33,813.33L813.33,386.67Q813.33,386.67 813.33,386.67Q813.33,386.67 813.33,386.67L146.67,386.67Q146.67,386.67 146.67,386.67Q146.67,386.67 146.67,386.67L146.67,813.33Q146.67,813.33 146.67,813.33Q146.67,813.33 146.67,813.33ZM404.67,752.67L632,600L404.67,448L404.67,752.67ZM152.67,266.67L152.67,200L807.33,200L807.33,266.67L152.67,266.67ZM280,146.67L280,80L680,80L680,146.67L280,146.67ZM146.67,813.33Q146.67,813.33 146.67,813.33Q146.67,813.33 146.67,813.33L146.67,386.67Q146.67,386.67 146.67,386.67Q146.67,386.67 146.67,386.67L146.67,386.67Q146.67,386.67 146.67,386.67Q146.67,386.67 146.67,386.67L146.67,813.33Q146.67,813.33 146.67,813.33Q146.67,813.33 146.67,813.33Z"/>
 </vector>
diff --git a/app/res/drawable/ic_overflow_horizontal.xml b/app/res/drawable/ic_overflow_horizontal.xml
index 9cc19e17..7bc5a2cb 100644
--- a/app/res/drawable/ic_overflow_horizontal.xml
+++ b/app/res/drawable/ic_overflow_horizontal.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="960"
     android:viewportHeight="960">
     <path
-        android:fillColor="@color/car_on_surface"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M218.57,538.67Q194.33,538.67 177.17,521.41Q160,504.14 160,479.91Q160,455.67 177.26,438.5Q194.52,421.33 218.76,421.33Q243,421.33 260.17,438.59Q277.33,455.86 277.33,480.09Q277.33,504.33 260.07,521.5Q242.81,538.67 218.57,538.67ZM479.91,538.67Q455.67,538.67 438.5,521.41Q421.33,504.14 421.33,479.91Q421.33,455.67 438.6,438.5Q455.86,421.33 480.09,421.33Q504.33,421.33 521.5,438.59Q538.67,455.86 538.67,480.09Q538.67,504.33 521.41,521.5Q504.14,538.67 479.91,538.67ZM741.24,538.67Q717,538.67 699.83,521.41Q682.67,504.14 682.67,479.91Q682.67,455.67 699.93,438.5Q717.19,421.33 741.43,421.33Q765.67,421.33 782.83,438.59Q800,455.86 800,480.09Q800,504.33 782.74,521.5Q765.48,538.67 741.24,538.67Z"/>
 </vector>
diff --git a/app/res/drawable/ic_play_pause_selector.xml b/app/res/drawable/ic_play_pause_selector.xml
index 142869ab..077e371d 100644
--- a/app/res/drawable/ic_play_pause_selector.xml
+++ b/app/res/drawable/ic_play_pause_selector.xml
@@ -22,7 +22,7 @@
             android:viewportWidth="960"
             android:viewportHeight="960">
             <path
-                android:fillColor="@color/car_surface"
+                android:fillColor="?oemColorSurface"
                 android:pathData="M556.67,760L556.67,200L726.67,200L726.67,760L556.67,760ZM233.33,760L233.33,200L403.33,200L403.33,760L233.33,760Z"/>
         </vector>
     </item>
@@ -33,7 +33,7 @@
             android:viewportWidth="960"
             android:viewportHeight="960">
             <path
-                android:fillColor="@color/car_surface"
+                android:fillColor="?oemColorSurface"
                 android:pathData="M320,758L320,198L760,478L320,758Z"/>
         </vector>
     </item>
@@ -44,7 +44,7 @@
             android:viewportWidth="960"
             android:viewportHeight="960">
             <path
-                android:fillColor="@color/car_surface"
+                android:fillColor="?oemColorSurface"
                 android:pathData="M642.67,557.33L328,247.33L328,198L768,478L642.67,557.33ZM792,895.33L528,630.67L328,758L328,430.67L65.33,167.33L112,120.67L840,848.67L792,895.33Z"/>
         </vector>
     </item>
diff --git a/app/res/drawable/ic_queue.xml b/app/res/drawable/ic_queue.xml
index bd7b6614..634ff6d8 100644
--- a/app/res/drawable/ic_queue.xml
+++ b/app/res/drawable/ic_queue.xml
@@ -20,6 +20,6 @@
     android:viewportWidth="960"
     android:viewportHeight="960">
     <path
-        android:fillColor="@color/car_on_surface"
+        android:fillColor="?oemColorOnSurface"
         android:pathData="M641.96,800Q593.33,800 559.33,765.96Q525.33,731.92 525.33,683.29Q525.33,634.67 558.78,600.67Q592.22,566.67 640,566.67Q654.31,566.67 667.32,569.17Q680.33,571.67 692,578L692,240L880,240L880,314L758.67,314L758.67,684Q758.67,732.33 724.63,766.17Q690.59,800 641.96,800ZM120,640L120,573.33L430.67,573.33L430.67,640L120,640ZM120,473.33L120,406.67L595.33,406.67L595.33,473.33L120,473.33ZM120,306.67L120,240L595.33,240L595.33,306.67L120,306.67Z"/>
 </vector>
diff --git a/app/res/drawable/media_card_default_album_art.xml b/app/res/drawable/media_card_default_album_art.xml
index 242dbcec..8fc5127d 100644
--- a/app/res/drawable/media_card_default_album_art.xml
+++ b/app/res/drawable/media_card_default_album_art.xml
@@ -17,7 +17,7 @@
 <layer-list xmlns:android="http://schemas.android.com/apk/res/android">
     <item>
         <shape>
-            <solid android:color="@color/car_surface_variant"/>
+            <solid android:color="?oemColorSurfaceVariant"/>
         </shape>
     </item>
     <item
@@ -32,7 +32,7 @@
             android:viewportHeight="960">
             <path
                 android:pathData="M400,840q-66,0 -113,-47t-47,-113q0,-66 47,-113t113,-47q23,0 42.5,5.5T480,542v-422h240v160L560,280v400q0,66 -47,113t-113,47Z"
-                android:fillColor="@color/car_inverse_on_surface"/>
+                android:fillColor="?oemColorOnSurfaceInverse"/>
         </vector>
     </item>
 </layer-list>
diff --git a/app/res/drawable/media_card_panel_handlebar.xml b/app/res/drawable/media_card_panel_handlebar.xml
index e98db817..6a4bff47 100644
--- a/app/res/drawable/media_card_panel_handlebar.xml
+++ b/app/res/drawable/media_card_panel_handlebar.xml
@@ -20,7 +20,7 @@
     <item>
         <shape android:shape="rectangle">
             <corners android:radius="16dp"/>
-            <solid android:color="@color/car_on_surface_variant"/>
+            <solid android:color="?oemColorOnSurfaceVariant"/>
         </shape>
     </item>
 </ripple>
diff --git a/app/res/drawable/media_card_seekbar_thumb.xml b/app/res/drawable/media_card_seekbar_thumb.xml
index b9dee233..71d64072 100644
--- a/app/res/drawable/media_card_seekbar_thumb.xml
+++ b/app/res/drawable/media_card_seekbar_thumb.xml
@@ -50,7 +50,7 @@
                     android:pathData="M6 4C7.10457 4 8 4.89543 8 6V26C8 27.1046 7.10457 28 6 28C4.89543 28 4 27.1046 4 26V6C4 4.89543 4.89543 4 6 4Z" />
                 <path
                     android:pathData="M4 4V28H8V4"
-                    android:fillColor="@color/car_on_surface" />
+                    android:fillColor="?oemColorOnSurface" />
             </group>
             <group>
                 <clip-path
diff --git a/app/res/drawable/pill_button_shape.xml b/app/res/drawable/pill_button_shape.xml
index 69342add..9cbbc4e4 100644
--- a/app/res/drawable/pill_button_shape.xml
+++ b/app/res/drawable/pill_button_shape.xml
@@ -18,8 +18,8 @@
     <item>
         <shape
             android:shape="rectangle">
-            <corners android:radius="@dimen/media_card_pill_radius" />
-            <solid android:color="@color/car_surface_container_highest" />
+            <corners android:radius="?mediaCardPillRadius" />
+            <solid android:color="?oemColorSurfaceContainerHighest" />
         </shape>
     </item>
     <item android:drawable="@drawable/button_ripple"/>
diff --git a/app/res/layout/calm_mode_fragment.xml b/app/res/layout/calm_mode_fragment.xml
index c1d1502b..9fbdfd33 100644
--- a/app/res/layout/calm_mode_fragment.xml
+++ b/app/res/layout/calm_mode_fragment.xml
@@ -33,6 +33,7 @@
     <TextClock
         android:id="@+id/date"
         style="@style/CalmModeText.Date"
+        android:textAppearance="?oemTextAppearanceBodyMedium"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_marginTop="@dimen/calm_mode_padding_vertical"
@@ -45,6 +46,7 @@
     <TextView
         android:id="@+id/temperature_icon"
         style="@style/CalmModeText.Temperature"
+        android:textAppearance="?oemTextAppearanceBodyMedium"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:visibility="gone"
@@ -56,6 +58,7 @@
     <TextView
         android:id="@+id/temperature"
         style="@style/CalmModeText.Temperature"
+        android:textAppearance="?oemTextAppearanceBodyMedium"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:visibility="gone"
@@ -81,6 +84,7 @@
     <TextView
         android:id="@+id/nav_state"
         style="@style/CalmModeText"
+        android:textAppearance="?oemTextAppearanceBodyMedium"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:visibility="gone"
@@ -95,6 +99,7 @@
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:visibility="gone"
+        android:textAppearance="?oemTextAppearanceDisplayLarge"
         app:layout_constraintTop_toBottomOf="@id/date"
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintStart_toStartOf="parent"
@@ -103,6 +108,7 @@
     <TextView
         android:id="@+id/media_title"
         style="@style/CalmModeText.MediaTitle"
+        android:textAppearance="?oemTextAppearanceBodyMedium"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:visibility="gone"
diff --git a/app/res/layout/control_bar_container.xml b/app/res/layout/control_bar_container.xml
index 4c3d9553..1caf5ed5 100644
--- a/app/res/layout/control_bar_container.xml
+++ b/app/res/layout/control_bar_container.xml
@@ -18,17 +18,29 @@
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent" >
+
+     <com.android.car.ui.FocusArea
+        android:id="@+id/top_card"
+        android:layout_width="0dp"
+        android:layout_height="0dp"
+        android:layout_marginHorizontal="@dimen/main_screen_widget_margin"
+        android:layout_marginBottom="@dimen/main_screen_widget_margin"
+        android:layoutDirection="locale"
+        app:layout_constraintLeft_toLeftOf="parent"
+        app:layout_constraintRight_toRightOf="parent"
+        app:layout_constraintTop_toTopOf="parent"
+        app:layout_constraintBottom_toTopOf="@+id/bottom_card"/>
 
     <com.android.car.ui.FocusArea
         android:id="@+id/bottom_card"
         android:layout_width="0dp"
         android:layout_height="0dp"
+        android:layout_marginHorizontal="@dimen/main_screen_widget_margin"
         android:layoutDirection="locale"
-        android:padding="@dimen/control_bar_padding"
         app:layout_constraintLeft_toLeftOf="parent"
-        app:layout_constraintTop_toTopOf="parent"
         app:layout_constraintRight_toRightOf="parent"
+        app:layout_constraintTop_toBottomOf="@+id/top_card"
         app:layout_constraintBottom_toBottomOf="parent"/>
 
 </androidx.constraintlayout.widget.ConstraintLayout>
\ No newline at end of file
diff --git a/app/res/layout/map_tos_activity.xml b/app/res/layout/map_tos_activity.xml
index 46f69d93..8b65b082 100644
--- a/app/res/layout/map_tos_activity.xml
+++ b/app/res/layout/map_tos_activity.xml
@@ -25,5 +25,5 @@
           android:id="@+id/review_button"
           android:layout_width="wrap_content"
           android:layout_height="wrap_content"
-          android:textColor="@color/car_text_primary"/>
+          android:textColor="?carTextPrimary"/>
   </FrameLayout>
\ No newline at end of file
diff --git a/app/res/layout/media_card_fullscreen.xml b/app/res/layout/media_card_fullscreen.xml
index ba6167e1..7acae7e4 100644
--- a/app/res/layout/media_card_fullscreen.xml
+++ b/app/res/layout/media_card_fullscreen.xml
@@ -19,8 +19,8 @@
     xmlns:app="http://schemas.android.com/apk/res-auto"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
-    app:cardBackgroundColor="@color/car_surface_container_high"
-    app:cardCornerRadius="@dimen/media_card_card_radius"
+    app:cardBackgroundColor="?oemColorSurfaceContainerHigh"
+    app:cardCornerRadius="?mediaCardCardRadius"
     app:cardElevation="0dp">
 
     <androidx.constraintlayout.motion.widget.MotionLayout
@@ -34,7 +34,7 @@
             android:layout_width="match_parent"
             android:layout_height="match_parent"
             android:layout_marginTop="@dimen/media_card_panel_content_margin_top"
-            android:background="@color/car_surface_container_highest"
+            android:background="?oemColorSurfaceContainerHighest"
             android:orientation="vertical"
             app:layout_constraintBottom_toBottomOf="parent">
             <FrameLayout
@@ -56,7 +56,7 @@
 
             <androidx.viewpager2.widget.ViewPager2
                 android:id="@+id/view_pager"
-                android:background="@color/car_surface_container_highest"
+                android:background="?oemColorSurfaceContainerHighest"
                 android:layout_width="match_parent"
                 android:layout_height="match_parent" />
         </LinearLayout>
@@ -65,7 +65,7 @@
             android:id="@+id/empty_panel"
             android:layout_width="match_parent"
             android:layout_height="match_parent"
-            android:background="@color/car_surface_container_high"
+            android:background="?oemColorSurfaceContainerHigh"
             app:layout_constraintTop_toTopOf="parent"/>
 
         <ImageView
@@ -108,7 +108,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:text="@string/metadata_default_title"
-            android:textColor="@color/car_text_primary"
+            android:textColor="?carTextPrimary"
             android:gravity="center_vertical"
             android:maxLines="1"
             android:ellipsize="end"
@@ -124,8 +124,8 @@
             android:id="@+id/subtitle"
             android:layout_height="wrap_content"
             android:layout_width="0dp"
-            style="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/car_text_secondary"
+            android:textAppearance="?oemTextAppearanceBodyMedium"
+            android:textColor="?carTextSecondary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginTop="@dimen/media_card_artist_top_margin"
@@ -140,12 +140,12 @@
             android:layout_height="wrap_content"
             android:paddingEnd="0dp"
             android:paddingStart="0dp"
-            android:progressBackgroundTint="@color/car_surface_container_highest"
+            android:progressBackgroundTint="?oemColorSurfaceContainerHighest"
             android:progressDrawable="@drawable/media_card_seekbar_progress"
-            android:progressTint="@color/car_primary"
+            android:progressTint="?oemColorPrimary"
             android:splitTrack="true"
             android:thumb="@drawable/media_card_seekbar_thumb"
-            android:thumbTint="@color/car_on_surface"
+            android:thumbTint="?oemColorOnSurface"
             android:thumbOffset="0px"
             android:layout_marginTop="@dimen/media_card_view_separation_margin"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
@@ -164,7 +164,7 @@
             android:layout_gravity="center_vertical"
             android:adjustViewBounds="true"
             android:scaleType="fitStart"
-            app:logoTint="@color/car_on_surface_variant"
+            app:logoTint="?oemColorOnSurfaceVariant"
             app:logoSize="small"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             app:layout_constraintStart_toEndOf="@id/playback_seek_bar"
@@ -178,9 +178,9 @@
             android:layout_height="@dimen/media_card_large_button_size"
             android:src="@drawable/ic_play_pause_selector"
             android:scaleType="center"
-            android:tint="@color/car_surface_container_high"
+            android:tint="?oemColorSurfaceContainerHigh"
             android:background="@drawable/pill_button_shape"
-            android:backgroundTint="@color/car_primary"
+            android:backgroundTint="?oemColorPrimary"
             android:layout_marginBottom="@dimen/media_card_play_button_bottom_margin"
             app:layout_goneMarginEnd="@dimen/media_card_horizontal_margin"
             app:layout_goneMarginStart="@dimen/media_card_horizontal_margin"
@@ -197,7 +197,7 @@
             android:scaleType="fitCenter"
             android:padding="@dimen/media_card_large_button_icon_padding"
             android:cropToPadding="true"
-            android:tint="@color/car_on_surface_variant"
+            android:tint="?oemColorOnSurfaceVariant"
             android:background="@drawable/circle_button_background"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginEnd="@dimen/media_card_play_button_horizontal_margin"
@@ -214,7 +214,7 @@
             android:scaleType="fitCenter"
             android:padding="@dimen/media_card_large_button_icon_padding"
             android:cropToPadding="true"
-            android:tint="@color/car_on_surface_variant"
+            android:tint="?oemColorOnSurfaceVariant"
             android:background="@drawable/circle_button_background"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             android:layout_marginStart="@dimen/media_card_play_button_horizontal_margin"
@@ -229,7 +229,7 @@
             android:layout_width="match_parent"
             android:layout_height="@dimen/media_card_bottom_panel_height"
             android:background="@drawable/media_card_button_panel_background"
-            android:backgroundTint="@color/car_surface_container_highest"
+            android:backgroundTint="?oemColorSurfaceContainerHighest"
             app:layout_constraintStart_toStartOf="parent"
             app:layout_constraintEnd_toEndOf="parent"
             app:layout_constraintTop_toTopOf="parent"
diff --git a/app/res/layout/media_card_history_header_item.xml b/app/res/layout/media_card_history_header_item.xml
index c3c47e1f..839dd9ff 100644
--- a/app/res/layout/media_card_history_header_item.xml
+++ b/app/res/layout/media_card_history_header_item.xml
@@ -32,6 +32,6 @@
         android:layout_height="wrap_content"
         android:includeFontPadding="false"
         android:text="@string/media_card_history_header_title"
-        android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_text_primary"/>
+        android:textAppearance="?oemTextAppearanceBodyMedium"
+        android:textColor="?carTextPrimary"/>
 </LinearLayout>
diff --git a/app/res/layout/media_card_history_item.xml b/app/res/layout/media_card_history_item.xml
index ad8350be..4e19f15c 100644
--- a/app/res/layout/media_card_history_item.xml
+++ b/app/res/layout/media_card_history_item.xml
@@ -30,8 +30,8 @@
             android:id="@+id/history_card_title_active"
             android:layout_height="wrap_content"
             android:layout_width="0dp"
-            android:textAppearance="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/car_text_primary"
+            android:textAppearance="?oemTextAppearanceBodySmall"
+            android:textColor="?carTextPrimary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginEnd="@dimen/media_card_view_separation_margin"
@@ -44,8 +44,8 @@
             android:id="@+id/history_card_subtitle_active"
             android:layout_height="wrap_content"
             android:layout_width="0dp"
-            android:textAppearance="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/car_text_secondary"
+            android:textAppearance="?oemTextAppearanceBodySmall"
+            android:textColor="?carTextSecondary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginStart="@dimen/media_card_view_separation_margin"
@@ -84,8 +84,8 @@
             android:id="@+id/history_card_app_title_inactive"
             android:layout_height="wrap_content"
             android:layout_width="0dp"
-            android:textAppearance="@style/TextAppearance.Car.Body.Small"
-            android:textColor="@color/car_text_primary"
+            android:textAppearance="?oemTextAppearanceBodySmall"
+            android:textColor="?carTextPrimary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginEnd="@dimen/media_card_view_separation_margin"
diff --git a/app/res/layout/media_card_panel_content_item.xml b/app/res/layout/media_card_panel_content_item.xml
index c27b8385..cfc479f9 100644
--- a/app/res/layout/media_card_panel_content_item.xml
+++ b/app/res/layout/media_card_panel_content_item.xml
@@ -24,7 +24,7 @@
         android:visibility="gone"
         android:id="@+id/overflow_grid"
         android:stretchColumns="0,1"
-        android:background="@color/car_surface_container_highest">
+        android:background="?oemColorSurfaceContainerHighest">
         <TableRow
             android:layout_weight="1"
             android:gravity="center">
@@ -91,7 +91,7 @@
         android:layout_width="match_parent"
         android:layout_height="match_parent"
         android:paddingHorizontal="@dimen/media_card_horizontal_margin"
-        android:background="@color/car_surface_container_highest"
+        android:background="?oemColorSurfaceContainerHighest"
         android:visibility="gone">
         <com.android.car.apps.common.CarUiRecyclerViewNoScrollbar
             android:id="@+id/queue_list"
@@ -107,7 +107,7 @@
         android:layout_width="match_parent"
         android:layout_height="match_parent"
         android:paddingHorizontal="@dimen/media_card_horizontal_margin"
-        android:background="@color/car_surface_container_highest"
+        android:background="?oemColorSurfaceContainerHighest"
         android:visibility="gone">
         <com.android.car.apps.common.CarUiRecyclerViewNoScrollbar
             android:id="@+id/history_list"
diff --git a/app/res/layout/media_card_queue_header_item.xml b/app/res/layout/media_card_queue_header_item.xml
index e7b11117..3522e43d 100644
--- a/app/res/layout/media_card_queue_header_item.xml
+++ b/app/res/layout/media_card_queue_header_item.xml
@@ -31,6 +31,6 @@
         android:layout_height="wrap_content"
         android:includeFontPadding="false"
         android:text="@string/media_card_queue_header_title"
-        android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_text_primary"/>
+        android:textAppearance="?oemTextAppearanceBodySmall"
+        android:textColor="?carTextPrimary"/>
 </LinearLayout>
diff --git a/app/res/layout/media_card_queue_item.xml b/app/res/layout/media_card_queue_item.xml
index 966bb2e8..b3db5be7 100644
--- a/app/res/layout/media_card_queue_item.xml
+++ b/app/res/layout/media_card_queue_item.xml
@@ -42,8 +42,8 @@
         android:id="@+id/queue_list_item_title"
         android:layout_height="wrap_content"
         android:layout_width="0dp"
-        android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_text_primary"
+        android:textAppearance="?oemTextAppearanceBodySmall"
+        android:textColor="?carTextPrimary"
         android:maxLines="1"
         android:ellipsize="end"
         android:layout_marginEnd="@dimen/media_card_view_separation_margin"
@@ -58,8 +58,8 @@
         android:id="@+id/queue_list_item_subtitle"
         android:layout_height="wrap_content"
         android:layout_width="0dp"
-        android:textAppearance="@style/TextAppearance.Car.Body.Small"
-        android:textColor="@color/car_text_secondary"
+        android:textAppearance="?oemTextAppearanceBodySmall"
+        android:textColor="?carTextSecondary"
         android:maxLines="1"
         android:ellipsize="end"
         android:layout_marginEnd="@dimen/media_card_view_separation_margin"
diff --git a/app/res/values-ca/strings.xml b/app/res/values-ca/strings.xml
index 04438e0a..c5767cd5 100644
--- a/app/res/values-ca/strings.xml
+++ b/app/res/values-ca/strings.xml
@@ -28,7 +28,7 @@
     <string name="projected_onclick_launch_error_toast_text" msgid="8853804785626030351">"No es pot iniciar Android Auto. No s\'ha trobat cap activitat."</string>
     <string name="projection_devices" msgid="2556503818120676439">"{count,plural, =1{# dispositiu}other{# dispositius}}"</string>
     <string name="weather_app_name" msgid="4356705068077942048">"Temps"</string>
-    <string name="fake_weather_main_text" msgid="2545755284647327839">"--° Principalment assolellat"</string>
+    <string name="fake_weather_main_text" msgid="2545755284647327839">"--° Majoritàriament assolellat"</string>
     <string name="fake_weather_footer_text" msgid="8640814250285014485">"Mountain View • Màx.: --° Mín.: --°"</string>
     <string name="times_separator" msgid="1962841895013564645">"/"</string>
     <string name="recents_empty_state_text" msgid="8228569970506899117">"No hi ha cap element recent"</string>
diff --git a/app/res/values-iw/strings.xml b/app/res/values-iw/strings.xml
index 614df3d0..e6554ca7 100644
--- a/app/res/values-iw/strings.xml
+++ b/app/res/values-iw/strings.xml
@@ -19,8 +19,8 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_title" msgid="1056886619192068947">"מרכז האפליקציות ברכב"</string>
     <string name="default_media_song_title" msgid="7837564242036091946"></string>
-    <string name="tap_for_more_info_text" msgid="4240146824238692769">"יש להקיש על הכרטיס למידע נוסף"</string>
-    <string name="tap_to_launch_text" msgid="7150379866796152196">"יש להקיש על הכרטיס כדי להפעיל"</string>
+    <string name="tap_for_more_info_text" msgid="4240146824238692769">"יש ללחוץ על הכרטיס למידע נוסף"</string>
+    <string name="tap_to_launch_text" msgid="7150379866796152196">"יש ללחוץ על הכרטיס כדי להפעיל"</string>
     <string name="ongoing_call_duration_text_separator" msgid="2140398350095052096">" • "</string>
     <string name="ongoing_call_text" msgid="7160701768924041827">"שיחה פעילה"</string>
     <string name="dialing_call_text" msgid="3286036311692512894">"מתבצע חיוג…"</string>
diff --git a/app/res/values/attrs.xml b/app/res/values/attrs.xml
index 99b757cc..9c56aef5 100644
--- a/app/res/values/attrs.xml
+++ b/app/res/values/attrs.xml
@@ -15,9 +15,6 @@
   -->
 
 <resources>
-    <!-- Corner radius for CardView. -->
-    <attr name="cardCornerRadius" format="dimension" />
-
     <!-- ShapeableImageView attributes -->
     <attr name="cornerFamily" format="enum" >
         <enum name="rounded" value="0"/>
@@ -27,4 +24,11 @@
     <attr name="shapeAppearanceOverlay" format="reference" />
     <attr name="strokeColor" format="color" />
     <attr name="strokeWidth" format="dimension" />
+
+    <attr name="launcherCardCornerRadius" format="reference|dimension"/>
+    <attr name="mediaCardCardRadius" format="reference|dimension"/>
+    <attr name="mediaCardPillRadius" format="reference|dimension"/>
+
+    <attr name="carTextPrimary" format="color|reference"/>
+    <attr name="carTextSecondary" format="color|reference"/>
 </resources>
\ No newline at end of file
diff --git a/app/res/values/dimens.xml b/app/res/values/dimens.xml
index 48c87222..fbc11733 100644
--- a/app/res/values/dimens.xml
+++ b/app/res/values/dimens.xml
@@ -15,8 +15,6 @@
     limitations under the License.
 -->
 <resources>
-    <!-- CarLauncher Activity values -->
-    <dimen name="launcher_card_corner_radius">32dp</dimen>
     <!-- Vertical percentage of screen (not occupied by maps to devote to the contextual space
       (Ex: date time temp) -->
     <item name="contextual_screen_percentage" type="dimen" format="float">.6</item>
@@ -112,7 +110,6 @@
     <dimen name="media_card_large_button_size">80dp</dimen>
     <dimen name="media_card_bottom_panel_button_size">56dp</dimen>
     <dimen name="media_card_bottom_panel_height">96dp</dimen>
-    <dimen name="media_card_card_radius">32dp</dimen>
     <dimen name="media_card_play_button_bottom_margin">120dp</dimen>
     <dimen name="media_card_play_button_horizontal_margin">8dp</dimen>
     <dimen name="media_card_margin_panel_open">24dp</dimen>
@@ -121,15 +118,12 @@
     <dimen name="media_card_panel_handlebar_offscreen_start_position">1000dp</dimen>
     <dimen name="media_card_bottom_panel_animated_size">@dimen/media_card_bottom_panel_button_size</dimen>
     <dimen name="media_card_bottom_panel_animated_horizontal_margin">0dp</dimen>
-    <dimen name="media_card_pill_radius">160dp</dimen>
     <dimen name="media_card_panel_handlebar_height">8dp</dimen>
     <dimen name="media_card_panel_handlebar_touch_target_height">60dp</dimen>
     <dimen name="media_card_panel_handlebar_horizontal_padding">164dp</dimen>
     <dimen name="media_card_queue_header_app_icon_size">26dp</dimen>
     <dimen name="media_card_queue_item_thumbnail_size">80dp</dimen>
     <dimen name="media_card_panel_content_margin_top">216dp</dimen>
-    <dimen name="media_card_title_animated_line_height">36dp</dimen>
-    <dimen name="media_card_title_default_line_height">40dp</dimen>
     <dimen name="media_card_title_animated_text_size">28sp</dimen>
     <dimen name="media_card_title_default_text_size">32sp</dimen>
     <dimen name="media_card_recycler_view_fading_edge_length">80dp</dimen>
diff --git a/app/res/values/overlayable.xml b/app/res/values/overlayable.xml
index 0b7979bb..7d3c7e7f 100644
--- a/app/res/values/overlayable.xml
+++ b/app/res/values/overlayable.xml
@@ -1,5 +1,5 @@
 <?xml version='1.0' encoding='UTF-8'?>
-<!-- Copyright (C) 2024 The Android Open Source Project
+<!-- Copyright (C) 2025 The Android Open Source Project
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
@@ -27,9 +27,13 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="array" name="config_taskViewPackages"/>
       <item type="array" name="launcher_qc_provider_package_allowlist"/>
       <item type="array" name="packages_hidden_from_recents"/>
-      <item type="attr" name="cardCornerRadius"/>
+      <item type="attr" name="carTextPrimary"/>
+      <item type="attr" name="carTextSecondary"/>
       <item type="attr" name="cornerFamily"/>
       <item type="attr" name="cornerSize"/>
+      <item type="attr" name="launcherCardCornerRadius"/>
+      <item type="attr" name="mediaCardCardRadius"/>
+      <item type="attr" name="mediaCardPillRadius"/>
       <item type="attr" name="shapeAppearanceOverlay"/>
       <item type="attr" name="strokeColor"/>
       <item type="attr" name="strokeWidth"/>
@@ -52,6 +56,8 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="color" name="dialer_icon_tint_state_list"/>
       <item type="color" name="launcher_home_icon_color"/>
       <item type="color" name="media_button_tint"/>
+      <item type="color" name="media_card_action_button_color"/>
+      <item type="color" name="media_card_custom_action_button_color"/>
       <item type="color" name="media_card_panel_button_background_tint_state_list"/>
       <item type="color" name="media_card_panel_button_tint_state_list"/>
       <item type="color" name="media_card_seekbar_thumb_color"/>
@@ -87,7 +93,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="disabled_recent_task_alpha"/>
       <item type="dimen" name="home_card_button_size"/>
       <item type="dimen" name="horizontal_border_size"/>
-      <item type="dimen" name="launcher_card_corner_radius"/>
       <item type="dimen" name="main_screen_widget_margin"/>
       <item type="dimen" name="media_card_album_art_drawable_corner_ratio"/>
       <item type="dimen" name="media_card_album_art_end_margin"/>
@@ -100,7 +105,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="media_card_bottom_panel_button_size"/>
       <item type="dimen" name="media_card_bottom_panel_height"/>
       <item type="dimen" name="media_card_bottom_panel_margin_top"/>
-      <item type="dimen" name="media_card_card_radius"/>
       <item type="dimen" name="media_card_history_item_height"/>
       <item type="dimen" name="media_card_history_item_icon_size"/>
       <item type="dimen" name="media_card_history_item_thumbnail_size"/>
@@ -116,7 +120,6 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="media_card_panel_handlebar_horizontal_padding"/>
       <item type="dimen" name="media_card_panel_handlebar_offscreen_start_position"/>
       <item type="dimen" name="media_card_panel_handlebar_touch_target_height"/>
-      <item type="dimen" name="media_card_pill_radius"/>
       <item type="dimen" name="media_card_play_button_bottom_margin"/>
       <item type="dimen" name="media_card_play_button_horizontal_margin"/>
       <item type="dimen" name="media_card_queue_header_app_icon_size"/>
@@ -124,9 +127,7 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="dimen" name="media_card_recycler_view_fading_edge_length"/>
       <item type="dimen" name="media_card_small_button_size"/>
       <item type="dimen" name="media_card_text_view_guideline_start"/>
-      <item type="dimen" name="media_card_title_animated_line_height"/>
       <item type="dimen" name="media_card_title_animated_text_size"/>
-      <item type="dimen" name="media_card_title_default_line_height"/>
       <item type="dimen" name="media_card_title_default_text_size"/>
       <item type="dimen" name="media_card_view_header_icon_size"/>
       <item type="dimen" name="media_card_view_separation_margin"/>
@@ -354,10 +355,12 @@ REGENERATE USING packages/apps/Car/libs/tools/rro/generate-overlayable.py
       <item type="style" name="CalmModeText.Date"/>
       <item type="style" name="CalmModeText.MediaTitle"/>
       <item type="style" name="CalmModeText.Temperature"/>
+      <item type="style" name="CarLauncherActivityThemeOverlay"/>
       <item type="style" name="CardViewStyle"/>
       <item type="style" name="ClearAllRecentTasksButton"/>
       <item type="style" name="ContextualSpace"/>
       <item type="style" name="HiddenRecentTaskThumbnail"/>
+      <item type="style" name="MapTosActivityThemeOverlay"/>
       <item type="style" name="MediaCardCustomActionButtonStyle"/>
       <item type="style" name="MediaCardPanelButtonStyle"/>
       <item type="style" name="RecentTaskDismissButton"/>
diff --git a/app/res/values/strings.xml b/app/res/values/strings.xml
index bf62ad1f..cd2b34b4 100644
--- a/app/res/values/strings.xml
+++ b/app/res/values/strings.xml
@@ -22,7 +22,7 @@
     <string name="tap_for_more_info_text">Tap card for more info</string>
     <string name="tap_to_launch_text">Tap card to launch</string>
 
-    <!-- InCallModel strings -->
+    <!-- InCallViewModel strings -->
     <!-- Separates the duration from the ongoing_call_text -->
     <string name="ongoing_call_duration_text_separator">&#160;&#8226;&#160;</string>
     <string name="ongoing_call_text">Ongoing call</string>
diff --git a/app/res/values/styles.xml b/app/res/values/styles.xml
index de9c13fb..59a27bc1 100644
--- a/app/res/values/styles.xml
+++ b/app/res/values/styles.xml
@@ -16,7 +16,7 @@
 -->
 <resources>
     <style name="CardViewStyle">
-        <item name="cardCornerRadius">@dimen/launcher_card_corner_radius</item>
+        <item name="cardCornerRadius">?launcherCardCornerRadius</item>
         <item name="cardElevation">0dp</item>
     </style>
 
@@ -86,7 +86,7 @@
         <item name="cornerSize">8dp</item>
     </style>
 
-    <style name="CalmModeText" parent="TextAppearance.Car.Body.Small">
+    <style name="CalmModeText">
         <item name="android:textColor">@android:color/white</item>
     </style>
 
@@ -101,13 +101,13 @@
     </style>
 
     <style name="CalmModeText.Date">
-        <item name="android:textColor">@color/car_outline</item>
+        <item name="android:textColor">?oemColorOutline</item>
         <item name="android:format12Hour">EE, MMM dd</item>
         <item name="android:format24Hour">EE, MMM dd</item>
     </style>
 
     <style name="CalmModeText.MediaTitle">
-        <item name="android:textColor">@color/car_outline</item>
+        <item name="android:textColor">?oemColorOutline</item>
         <item name="android:ellipsize">end</item>
         <item name="android:maxWidth">1024dp</item>
         <item name="android:maxLines">2</item>
@@ -115,14 +115,14 @@
     </style>
 
     <style name="CalmModeText.Temperature">
-        <item name="android:textColor">@color/car_outline</item>
+        <item name="android:textColor">?oemColorOutline</item>
     </style>
 
-    <style name="CalmModeClock" parent="TextAppearance.Car.Display">
+    <style name="CalmModeClock">
         <item name="android:fontFamily">roboto-flex</item>
         <item name="android:textFontWeight">300</item>
         <item name="android:fontVariationSettings">"'wght' 300, 'wdth' 100, 'xtra' 468, 'xopq' 96, 'yopq' 79, 'ytuc' 712, 'ytas' 750, 'ytde' -203, 'ytfi' 738, 'opsz' 144"</item>
-        <item name="android:textColor">@color/car_neutral_90</item>
+        <item name="android:textColor">?oemColorOnBackground</item>
         <item name="android:textSize">300sp</item>
         <item name="android:textAlignment">center</item>
         <item name="android:format12Hour">hh:mm</item>
@@ -143,7 +143,7 @@
 
     <style name="MediaCardCustomActionButtonStyle">
         <item name="android:scaleType">fitCenter</item>
-        <item name="android:tint">@color/car_on_surface</item>
+        <item name="android:tint">?oemColorOnSurface</item>
         <item name="android:background">@android:color/transparent</item>
     </style>
 
diff --git a/app/res/values/themes.xml b/app/res/values/themes.xml
index 0ce0fd4f..837d956a 100644
--- a/app/res/values/themes.xml
+++ b/app/res/values/themes.xml
@@ -19,9 +19,16 @@
     <style name="Theme.Launcher" parent="Theme.CarUi.NoToolbar">
         <item name="textAppearanceGridItem">@android:style/TextAppearance.DeviceDefault.Medium</item>
         <item name="textAppearanceGridItemSecondary">@android:style/TextAppearance.DeviceDefault.Small</item>
+        <item name="oemTokenOverrideEnabled">true</item>
+    </style>
+
+    <style name="Theme.ControlBar" parent="Theme.CarUi.NoToolbar">
+        <item name="oemTokenOverrideEnabled">true</item>
+        <item name="android:windowBackground">@android:color/transparent</item>
     </style>
 
     <style name="Theme.CalmMode" parent="Theme.CarUi.NoToolbar">
+        <item name="oemTokenOverrideEnabled">true</item>
         <item name="android:windowNoTitle">true</item>
         <item name="android:windowIsTranslucent">true</item>
         <item name="android:windowSplashScreenAnimatedIcon">@android:color/transparent</item>
@@ -29,4 +36,16 @@
         <item name="android:activityOpenEnterAnimation">@anim/fade_in</item>
         <item name="android:activityOpenExitAnimation">@anim/fade_out</item>
     </style>
+
+    <style name="CarLauncherActivityThemeOverlay">
+        <item name="launcherCardCornerRadius">?oemShapeCornerLarge</item>
+        <item name="mediaCardCardRadius">?oemShapeCornerLarge</item>
+        <item name="mediaCardPillRadius">?oemShapeCornerFull</item>
+        <item name="carTextPrimary">?oemColorNeutralPalette95</item>
+        <item name="carTextSecondary">?oemColorNeutralVariantPalette70</item>
+    </style>
+
+    <style name="MapTosActivityThemeOverlay">
+        <item name="carTextPrimary">?oemColorNeutralPalette95</item>
+    </style>
 </resources>
diff --git a/app/res/xml/panel_animation_motion_scene.xml b/app/res/xml/panel_animation_motion_scene.xml
index 2ef5eb4a..6d4ae25c 100644
--- a/app/res/xml/panel_animation_motion_scene.xml
+++ b/app/res/xml/panel_animation_motion_scene.xml
@@ -93,9 +93,6 @@
             android:id="@id/title">
             <PropertySet
                 motion:visibilityMode="ignore"/>
-            <CustomAttribute
-                motion:attributeName="lineHeight"
-                motion:customDimension="@dimen/media_card_title_default_line_height" />
             <CustomAttribute
                 motion:attributeName="textSize"
                 motion:customDimension="@dimen/media_card_title_default_text_size" />
@@ -140,9 +137,9 @@
             android:layout_height="@dimen/media_card_large_button_size"
             android:src="@drawable/ic_play_pause_selector"
             android:scaleType="center"
-            android:tint="@color/car_surface_container_high"
+            android:tint="?oemColorSurfaceContainerHigh"
             android:background="@drawable/pill_button_shape"
-            android:backgroundTint="@color/car_primary"
+            android:backgroundTint="?oemColorPrimary"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginTop="@dimen/media_card_margin_panel_open"
             motion:layout_constraintStart_toStartOf="parent"
@@ -153,7 +150,7 @@
             android:layout_width="match_parent"
             android:layout_height="@dimen/media_card_bottom_panel_animated_size"
             android:background="@drawable/media_card_button_panel_background"
-            android:backgroundTint="@color/car_surface_container_highest"
+            android:backgroundTint="?oemColorSurfaceContainerHighest"
             android:layout_marginStart="@dimen/media_card_horizontal_margin"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
             android:layout_marginTop="@dimen/media_card_margin_panel_open"
@@ -165,7 +162,7 @@
             android:id="@+id/empty_panel"
             android:layout_width="match_parent"
             android:layout_height="0dp"
-            android:background="@color/car_surface_container_high"
+            android:background="?oemColorSurfaceContainerHigh"
             motion:layout_constraintTop_toTopOf="parent">
         </Constraint>
         <ConstraintOverride
@@ -179,7 +176,7 @@
             android:layout_height="wrap_content"
             android:layout_width="0dp"
             android:text="@string/metadata_default_title"
-            android:textColor="@color/car_text_primary"
+            android:textColor="?carTextPrimary"
             android:maxLines="1"
             android:ellipsize="end"
             android:layout_marginStart="@dimen/media_card_margin_panel_open"
@@ -192,9 +189,6 @@
             motion:layout_constraintVertical_bias="0">
             <PropertySet
                 motion:visibilityMode="ignore"/>
-            <CustomAttribute
-                motion:attributeName="lineHeight"
-                motion:customDimension="@dimen/media_card_title_animated_line_height" />
             <CustomAttribute
                 motion:attributeName="textSize"
                 motion:customDimension="@dimen/media_card_title_animated_text_size" />
@@ -218,12 +212,12 @@
             android:clickable="false"
             android:paddingEnd="0dp"
             android:paddingStart="0dp"
-            android:progressBackgroundTint="@color/car_surface_container_highest"
+            android:progressBackgroundTint="?oemColorSurfaceContainerHighest"
             android:progressDrawable="@drawable/media_card_seekbar_progress"
-            android:progressTint="@color/car_primary"
+            android:progressTint="?oemColorPrimary"
             android:splitTrack="false"
             android:thumb="@drawable/media_card_seekbar_thumb"
-            android:thumbTint="@color/car_on_surface"
+            android:thumbTint="?oemColorOnSurface"
             android:thumbOffset="0px"
             android:layout_marginStart="@dimen/media_card_margin_panel_open"
             android:layout_marginEnd="@dimen/media_card_horizontal_margin"
diff --git a/app/src/com/android/car/carlauncher/CarLauncher.java b/app/src/com/android/car/carlauncher/CarLauncher.java
index 368e203c..37ddb03a 100644
--- a/app/src/com/android/car/carlauncher/CarLauncher.java
+++ b/app/src/com/android/car/carlauncher/CarLauncher.java
@@ -40,6 +40,7 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowManager;
 
+import androidx.annotation.NonNull;
 import androidx.collection.ArraySet;
 import androidx.fragment.app.FragmentActivity;
 import androidx.fragment.app.FragmentTransaction;
@@ -47,10 +48,12 @@ import androidx.lifecycle.ViewModelProvider;
 
 import com.android.car.carlauncher.homescreen.HomeCardModule;
 import com.android.car.carlauncher.homescreen.audio.IntentHandler;
+import com.android.car.carlauncher.homescreen.audio.MediaLaunchHandler;
 import com.android.car.carlauncher.homescreen.audio.dialer.InCallIntentRouter;
-import com.android.car.carlauncher.homescreen.audio.media.MediaIntentRouter;
+import com.android.car.carlauncher.homescreen.audio.media.MediaLaunchRouter;
 import com.android.car.carlauncher.taskstack.TaskStackChangeListeners;
 import com.android.car.internal.common.UserHelperLite;
+import com.android.car.media.common.source.MediaSource;
 import com.android.wm.shell.taskview.TaskView;
 
 import com.google.common.annotations.VisibleForTesting;
@@ -121,6 +124,17 @@ public class CarLauncher extends FragmentActivity {
         }
     };
 
+    // Used instead of IntentHandler because media apps may provide a PendingIntent instead
+    private final MediaLaunchHandler mMediaMediaLaunchHandler = new MediaLaunchHandler() {
+        @Override
+        public void handleLaunchMedia(@NonNull MediaSource mediaSource) {
+            if (DEBUG) {
+                Log.d(TAG, "Launching media source " + mediaSource);
+            }
+            mediaSource.launchActivity(CarLauncher.this, ActivityOptions.makeBasic());
+        }
+    };
+
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
@@ -128,6 +142,7 @@ public class CarLauncher extends FragmentActivity {
         if (DEBUG) {
             Log.d(TAG, "onCreate(" + getUserId() + ") displayId=" + getDisplayId());
         }
+        getTheme().applyStyle(R.style.CarLauncherActivityThemeOverlay, true);
         // Since MUMD/MUPAND is introduced, CarLauncher can be called in the main display of
         // visible background users.
         // For Passenger scenarios, replace the maps_card with AppGridActivity, as currently
@@ -174,8 +189,9 @@ public class CarLauncher extends FragmentActivity {
             }
         }
 
-        MediaIntentRouter.getInstance().registerMediaIntentHandler(mIntentHandler);
+        MediaLaunchRouter.getInstance().registerMediaLaunchHandler(mMediaMediaLaunchHandler);
         InCallIntentRouter.getInstance().registerInCallIntentHandler(mIntentHandler);
+
         initializeCards();
         setupContentObserversForTos();
     }
@@ -188,6 +204,10 @@ public class CarLauncher extends FragmentActivity {
         getLifecycle().addObserver(mCarLauncherViewModel);
         addOnNewIntentListener(mCarLauncherViewModel.getNewIntentListener());
 
+        setUpRemoteCarTaskViewObserver(parent);
+    }
+
+    private void setUpRemoteCarTaskViewObserver(ViewGroup parent) {
         mCarLauncherViewModel.getRemoteCarTaskView().observe(this, taskView -> {
             if (taskView == null || taskView.getParent() == parent) {
                 // Discard if the parent is still the same because it doesn't signify a config
@@ -349,6 +369,7 @@ public class CarLauncher extends FragmentActivity {
                         && mCarLauncherViewModel.getRemoteCarTaskView().getValue() != null) {
                     // Reinitialize the remote car task view with the new maps intent
                     mCarLauncherViewModel.initializeRemoteCarTaskView(getMapsIntent());
+                    setUpRemoteCarTaskViewObserver(mMapsCard);
                 }
                 if (tosAccepted) {
                     unregisterTosContentObserver();
diff --git a/app/src/com/android/car/carlauncher/ControlBarActivity.java b/app/src/com/android/car/carlauncher/ControlBarActivity.java
index 7394d7f7..218a3c6b 100644
--- a/app/src/com/android/car/carlauncher/ControlBarActivity.java
+++ b/app/src/com/android/car/carlauncher/ControlBarActivity.java
@@ -16,19 +16,25 @@
 
 package com.android.car.carlauncher;
 
-import static android.view.WindowManager.LayoutParams.PRIVATE_FLAG_TRUSTED_OVERLAY;
-
+import android.app.ActivityOptions;
+import android.content.Intent;
 import android.content.res.Configuration;
 import android.os.Bundle;
 import android.util.Log;
-import android.view.WindowManager;
+import android.view.View;
 
+import androidx.annotation.NonNull;
 import androidx.collection.ArraySet;
 import androidx.fragment.app.FragmentActivity;
 import androidx.fragment.app.FragmentTransaction;
 import androidx.lifecycle.ViewModelProvider;
 
 import com.android.car.carlauncher.homescreen.HomeCardModule;
+import com.android.car.carlauncher.homescreen.audio.IntentHandler;
+import com.android.car.carlauncher.homescreen.audio.MediaLaunchHandler;
+import com.android.car.carlauncher.homescreen.audio.dialer.InCallIntentRouter;
+import com.android.car.carlauncher.homescreen.audio.media.MediaLaunchRouter;
+import com.android.car.media.common.source.MediaSource;
 
 import java.util.Set;
 
@@ -41,17 +47,37 @@ public class ControlBarActivity extends FragmentActivity {
 
     private Set<HomeCardModule> mHomeCardModules;
 
+    private final IntentHandler mIntentHandler = new IntentHandler() {
+        @Override
+        public void handleIntent(Intent intent) {
+            if (intent != null) {
+                ActivityOptions options = ActivityOptions.makeBasic();
+                startActivity(intent, options.toBundle());
+            }
+        }
+    };
+
+    // Used instead of IntentHandler because media apps may provide a PendingIntent instead
+    private final MediaLaunchHandler mMediaMediaLaunchHandler = new MediaLaunchHandler() {
+        @Override
+        public void handleLaunchMedia(@NonNull MediaSource mediaSource) {
+            if (DEBUG) {
+                Log.d(TAG, "Launching media source " + mediaSource);
+            }
+            mediaSource.launchActivity(ControlBarActivity.this, ActivityOptions.makeBasic());
+        }
+    };
+
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
-
-        // Setting as trusted overlay to let touches pass through.
-        getWindow().addPrivateFlags(PRIVATE_FLAG_TRUSTED_OVERLAY);
-        // To pass touches to the underneath task.
-        getWindow().addFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL);
+        getTheme().applyStyle(R.style.CarLauncherActivityThemeOverlay, true);
 
         setContentView(R.layout.control_bar_container);
         initializeCards();
+
+        MediaLaunchRouter.getInstance().registerMediaLaunchHandler(mMediaMediaLaunchHandler);
+        InCallIntentRouter.getInstance().registerInCallIntentHandler(mIntentHandler);
     }
 
     @Override
@@ -67,8 +93,13 @@ public class ControlBarActivity extends FragmentActivity {
                     R.array.config_homeCardModuleClasses)) {
                 try {
                     long reflectionStartTime = System.currentTimeMillis();
-                    HomeCardModule cardModule = (HomeCardModule) Class.forName(
-                            providerClassName).newInstance();
+                    HomeCardModule cardModule = (HomeCardModule)
+                            Class.forName(providerClassName).newInstance();
+                    if (Flags.mediaCardFullscreen()) {
+                        if (cardModule.getCardResId() == R.id.top_card) {
+                            findViewById(R.id.top_card).setVisibility(View.GONE);
+                        }
+                    }
                     cardModule.setViewModelProvider(new ViewModelProvider(/* owner= */this));
                     mHomeCardModules.add(cardModule);
                     if (DEBUG) {
@@ -77,7 +108,7 @@ public class ControlBarActivity extends FragmentActivity {
                                 + " took " + reflectionTime + " ms");
                     }
                 } catch (IllegalAccessException | InstantiationException
-                        | ClassNotFoundException e) {
+                         | ClassNotFoundException e) {
                     Log.w(TAG, "Unable to create HomeCardProvider class " + providerClassName, e);
                 }
             }
diff --git a/app/src/com/android/car/carlauncher/calmmode/CalmModeFragment.java b/app/src/com/android/car/carlauncher/calmmode/CalmModeFragment.java
index 124cffad..0bbd1938 100644
--- a/app/src/com/android/car/carlauncher/calmmode/CalmModeFragment.java
+++ b/app/src/com/android/car/carlauncher/calmmode/CalmModeFragment.java
@@ -375,4 +375,4 @@ public final class CalmModeFragment extends Fragment {
         CalmModeStatsLogHelper.getInstance().logSessionFinished();
     }
 
-}
+}
\ No newline at end of file
diff --git a/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt b/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt
index a73301fa..333058c2 100644
--- a/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt
+++ b/app/src/com/android/car/carlauncher/homescreen/MapTosActivity.kt
@@ -25,7 +25,9 @@ import android.os.Handler
 import android.os.Looper
 import android.provider.Settings
 import android.util.Log
+import android.view.WindowInsets
 import androidx.appcompat.app.AppCompatActivity
+import androidx.core.view.WindowCompat
 import androidx.lifecycle.lifecycleScope
 import com.android.car.carlauncher.AppLauncherUtils
 import com.android.car.carlauncher.Flags
@@ -51,7 +53,7 @@ class MapTosActivity : AppCompatActivity() {
 
     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
-
+        theme.applyStyle(R.style.MapTosActivityThemeOverlay, true)
         setContentView(R.layout.map_tos_activity)
         reviewButton = findViewById(R.id.review_button)
         reviewButton.setOnClickListener {
@@ -60,6 +62,21 @@ class MapTosActivity : AppCompatActivity() {
             AppLauncherUtils.launchApp(it.context, tosIntent)
         }
 
+        if (Flags.tosRestrictionsEnabled()) {
+            // Enable edge-to-edge display
+            WindowCompat.setDecorFitsSystemWindows(window, false)
+            window.decorView.rootView.setOnApplyWindowInsetsListener { v, insets ->
+                val appliedInsets = insets.getInsets(WindowInsets.Type.systemBars())
+                v.setPadding(
+                    appliedInsets.left,
+                    0, // top
+                    appliedInsets.right,
+                    0 // bottom
+                )
+                insets.inset(appliedInsets)
+            }
+        }
+
         setupCarUxRestrictionsListener()
         handleReviewButtonDistractionOptimized(requiresDistractionOptimization = false)
 
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragment.java b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragment.java
index 25f0ad8f..0ba2332b 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragment.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardFragment.java
@@ -118,6 +118,7 @@ public class AudioCardFragment extends Fragment implements HomeCardInterface.Vie
 
     /** Does a fragment transaction to show the media card and hide the dialer card */
     public void showMediaCard() {
+        if (!isAdded()) return;
         FragmentManager fragmentManager = getChildFragmentManager();
         FragmentTransaction transaction = fragmentManager.beginTransaction();
         transaction.show(mMediaFragment);
@@ -127,6 +128,7 @@ public class AudioCardFragment extends Fragment implements HomeCardInterface.Vie
 
     /** Does a fragment transaction to show the dialer card and hide the media card */
     public void showInCallCard() {
+        if (!isAdded()) return;
         FragmentManager fragmentManager = getChildFragmentManager();
         FragmentTransaction transaction = fragmentManager.beginTransaction();
         transaction.hide(mMediaFragment);
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java
index 710dc4f6..63d82819 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModel.java
@@ -18,22 +18,22 @@ package com.android.car.carlauncher.homescreen.audio;
 
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
 
-/** A wrapper around {@code MediaViewModel} and {@code InCallModel}. */
+/** A wrapper around {@code MediaViewModel} and {@code InCallViewModel}. */
 public class AudioCardModel implements HomeCardInterface.Model {
 
     private final MediaViewModel mMediaViewModel;
-    private final InCallModel mInCallViewModel;
+    private final InCallViewModel mInCallViewModel;
 
-    public AudioCardModel(MediaViewModel mediaViewModel, InCallModel inCallModel) {
+    public AudioCardModel(MediaViewModel mediaViewModel, InCallViewModel inCallViewModel) {
         mMediaViewModel = mediaViewModel;
-        mInCallViewModel = inCallModel;
+        mInCallViewModel = inCallViewModel;
     }
 
     MediaViewModel getMediaViewModel() {
         return mMediaViewModel;
     }
 
-    InCallModel getInCallViewModel() {
+    InCallViewModel getInCallViewModel() {
         return mInCallViewModel;
     }
 
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java
index 67ba0676..8d27dcf3 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/AudioCardModule.java
@@ -16,8 +16,6 @@
 
 package com.android.car.carlauncher.homescreen.audio;
 
-import android.os.SystemClock;
-
 import androidx.lifecycle.ViewModelProvider;
 
 import com.android.car.carlauncher.R;
@@ -45,8 +43,7 @@ public class AudioCardModule implements HomeCardModule {
         mAudioCardPresenter = new AudioCardPresenter(
                 new DialerCardPresenter(), new MediaCardPresenter());
         AudioCardModel audioCardModel = new AudioCardModel(
-                viewModelProvider.get(MediaViewModel.class),
-                new InCallModel(SystemClock.elapsedRealtimeClock()));
+                viewModelProvider.get(MediaViewModel.class), new InCallViewModel());
         mAudioCardPresenter.setModel(audioCardModel);
         mAudioCardView = new AudioCardFragment();
         mAudioCardPresenter.setView(mAudioCardView);
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java
similarity index 76%
rename from app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
rename to app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java
index d87b2465..915b2ffd 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/InCallModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/InCallViewModel.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2020 Google Inc.
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -25,32 +25,33 @@ import android.content.Intent;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.graphics.drawable.Drawable;
+import android.os.SystemClock;
 import android.telecom.Call;
 import android.telecom.CallAudioState;
-import android.telecom.PhoneAccountHandle;
 import android.telecom.TelecomManager;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.View;
 
 import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
 import androidx.core.content.ContextCompat;
+import androidx.lifecycle.LiveData;
+import androidx.lifecycle.Observer;
+import androidx.lifecycle.Transformations;
 
 import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.homescreen.audio.dialer.InCallIntentRouter;
-import com.android.car.carlauncher.homescreen.audio.telecom.InCallServiceImpl;
 import com.android.car.carlauncher.homescreen.ui.CardContent;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
-import com.android.car.telephony.calling.InCallServiceManager;
+import com.android.car.telephony.calling.CallComparator;
+import com.android.car.telephony.calling.CallDetailLiveData;
+import com.android.car.telephony.calling.InCallModel;
 import com.android.car.telephony.common.CallDetail;
 import com.android.car.telephony.common.TelecomUtils;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.ArrayUtils;
 
-import java.beans.PropertyChangeEvent;
-import java.beans.PropertyChangeListener;
 import java.io.FileNotFoundException;
 import java.io.InputStream;
 import java.time.Clock;
@@ -59,18 +60,17 @@ import java.util.concurrent.CompletableFuture;
 /**
  * The {@link HomeCardInterface.Model} for ongoing phone calls.
  */
-public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener,
-        PropertyChangeListener {
+public class InCallViewModel implements AudioModel {
 
-    private static final String TAG = "InCallModel";
-    private static final String PROPERTY_IN_CALL_SERVICE = "PROPERTY_IN_CALL_SERVICE";
+    private static final String TAG = "InCallViewModel";
     private static final String CAR_APP_SERVICE_INTERFACE = "androidx.car.app.CarAppService";
     private static final String CAR_APP_ACTIVITY_INTERFACE =
             "androidx.car.app.activity.CarAppActivity";
     /** androidx.car.app.CarAppService.CATEGORY_CALLING_APP from androidx car app library. */
     private static final String CAR_APP_CATEGORY_CALLING = "androidx.car.app.category.CALLING";
     private static final boolean DEBUG = false;
-    protected static InCallServiceManager sInCallServiceManager;
+
+    private InCallModel mInCallModel;
 
     protected Context mContext;
     private TelecomManager mTelecomManager;
@@ -78,11 +78,15 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
     private PackageManager mPackageManager;
     private final Clock mElapsedTimeClock;
 
+    private final LiveData<Call> mPrimaryCallLiveData;
+    private final LiveData<CallDetail> mCallDetailLiveData;
+
+    private Observer<Object> mCallObserver;
+    private Observer<Object> mCallAudioStateObserver;
+
     protected Call mCurrentCall;
     private CompletableFuture<Void> mPhoneNumberInfoFuture;
 
-    protected InCallServiceImpl mInCallService;
-
     private CardHeader mDefaultDialerCardHeader;
     private CardHeader mCardHeader;
     private CardContent mCardContent;
@@ -96,16 +100,16 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
 
     protected final InCallIntentRouter mInCallIntentRouter = InCallIntentRouter.getInstance();
 
-    private Call.Callback mCallback = new Call.Callback() {
-        @Override
-        public void onStateChanged(Call call, int state) {
-            super.onStateChanged(call, state);
-            handleActiveCall(call);
-        }
-    };
 
-    public InCallModel(Clock elapsedTimeClock) {
-        mElapsedTimeClock = elapsedTimeClock;
+    public InCallViewModel() {
+        mElapsedTimeClock = SystemClock.elapsedRealtimeClock();
+        mInCallModel = new InCallModel(InCallServiceManagerProvider.get(), new CallComparator());
+        mPrimaryCallLiveData = mInCallModel.getPrimaryCallLiveData();
+        mCallDetailLiveData = Transformations.switchMap(mPrimaryCallLiveData, call -> {
+            CallDetailLiveData callDetailLiveData = new CallDetailLiveData();
+            callDetailLiveData.setTelecomCall(call);
+            return callDetailLiveData;
+        });
     }
 
     @Override
@@ -116,30 +120,23 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         mOngoingCallSubtitle = context.getResources().getString(R.string.ongoing_call_text);
         mDialingCallSubtitle = context.getResources().getString(R.string.dialing_call_text);
         mContactImageBackground = context.getResources()
-                .getDrawable(R.drawable.control_bar_contact_image_background);
+                .getDrawable(R.drawable.control_bar_contact_image_background, context.getTheme());
         initializeAudioControls();
 
         mPackageManager = context.getPackageManager();
         mDefaultDialerCardHeader = createCardHeader(mTelecomManager.getDefaultDialerPackage());
         mCardHeader = mDefaultDialerCardHeader;
 
-        sInCallServiceManager = InCallServiceManagerProvider.get();
-        sInCallServiceManager.addObserver(this);
-        if (sInCallServiceManager.getInCallService() != null) {
-            onInCallServiceConnected();
-        }
+        mCallObserver = o -> onCallChanged(mPrimaryCallLiveData.getValue());
+        mPrimaryCallLiveData.observeForever(mCallObserver);
+
+        mCallAudioStateObserver =
+                o -> onCallAudioStateChanged(mInCallModel.getCallAudioStateLiveData().getValue());
+        mInCallModel.getCallAudioStateLiveData().observeForever(mCallAudioStateObserver);
     }
 
     @Override
     public void onDestroy(Context context) {
-        sInCallServiceManager.removeObserver(this);
-        if (mInCallService != null) {
-            if (mInCallService.getCalls() != null && !mInCallService.getCalls().isEmpty()) {
-                onCallRemoved(mInCallService.getCalls().get(0));
-            }
-            mInCallService.removeListener(InCallModel.this);
-            mInCallService = null;
-        }
         if (mPhoneNumberInfoFuture != null) {
             mPhoneNumberInfoFuture.cancel(/* mayInterruptIfRunning= */true);
         }
@@ -168,8 +165,9 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
     @Override
     public Intent getIntent() {
         Intent intent = null;
-        if (isSelfManagedCall()) {
-            String callingAppPackageName = getCallingAppPackageName();
+        CallDetail callDetail = mCallDetailLiveData.getValue();
+        if (callDetail != null && callDetail.isSelfManaged()) {
+            String callingAppPackageName = callDetail.getCallingAppPackageName();
             if (!TextUtils.isEmpty(callingAppPackageName)) {
                 if (isCarAppCallingService(callingAppPackageName)) {
                     intent = new Intent();
@@ -204,54 +202,33 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         }
     }
 
-    /** Indicates whether there is an active call or not. */
-    public boolean hasActiveCall() {
-        return mCurrentCall != null;
-    }
+    @VisibleForTesting
+    void onCallAudioStateChanged(CallAudioState audioState) {
 
-    /**
-     * When a {@link Call} is added, notify the {@link HomeCardInterface.Presenter} to update the
-     * card to display content on the ongoing phone call.
-     */
-    @Override
-    public void onCallAdded(Call call) {
-        if (call == null) {
-            return;
-        }
-        mCurrentCall = call;
-        call.registerCallback(mCallback);
-        @Call.CallState int callState = call.getDetails().getState();
-        if (callState == Call.STATE_ACTIVE || callState == Call.STATE_DIALING) {
-            handleActiveCall(call);
+        if (updateMuteButtonIconState(audioState)) {
+            mOnModelUpdateListener.onModelUpdate(this);
         }
     }
 
-    /**
-     * When a {@link Call} is removed, notify the {@link HomeCardInterface.Presenter} to update the
-     * card to remove the content on the no longer ongoing phone call.
-     */
-    @Override
-    public void onCallRemoved(Call call) {
-        mCurrentCall = null;
-        mCardHeader = null;
-        mCardContent = null;
-        mOnModelUpdateListener.onModelUpdate(this);
+    private void onCallChanged(Call call) {
         if (call != null) {
-            call.unregisterCallback(mCallback);
+            mCurrentCall = call;
+            handleActiveCall(mCurrentCall);
+        } else {
+            mCurrentCall = null;
+            mCardHeader = null;
+            mCardContent = null;
+            mOnModelUpdateListener.onModelUpdate(this);
         }
     }
 
-    /**
-     * When a {@link CallAudioState} is changed, update the model and notify the
-     * {@link HomeCardInterface.Presenter} to update the view.
-     */
-    @Override
-    public void onCallAudioStateChanged(CallAudioState audioState) {
-        // This is implemented to listen to changes to audio from other sources and update the
-        // content accordingly.
-        if (updateMuteButtonIconState(audioState)) {
-            mOnModelUpdateListener.onModelUpdate(this);
-        }
+    /** Indicates whether there is an active call or not. */
+    public boolean hasActiveCall() {
+        return mCurrentCall != null;
+    }
+
+    protected Call getCurrentCall() {
+        return mCurrentCall;
     }
 
     /**
@@ -341,15 +318,11 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         mOnModelUpdateListener.onModelUpdate(this);
     }
 
-    protected Call getCurrentCall() {
-        return mCurrentCall;
-    }
-
     protected void handleActiveCall(@NonNull Call call) {
         @Call.CallState int callState = call.getDetails().getState();
         CallDetail callDetails = CallDetail.fromTelecomCallDetail(call.getDetails());
         if (callDetails.isSelfManaged()) {
-            String packageName = getCallingAppPackageName();
+            String packageName = callDetails.getCallingAppPackageName();
             mCardHeader = createCardHeader(packageName);
         }
         if (mCardHeader == null) {
@@ -401,7 +374,7 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
                 mContext.getDrawable(R.drawable.ic_mute_activatable),
                 v -> {
                     boolean toggledValue = !v.isSelected();
-                    mInCallService.setMuted(toggledValue);
+                    InCallServiceManagerProvider.get().setMuted(toggledValue);
                     v.setSelected(toggledValue);
                 });
         mEndCallButton = new DescriptiveTextWithControlsView.Control(
@@ -421,20 +394,6 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         return mMuteButton.getIcon().getState();
     }
 
-    @Nullable
-    private String getCallingAppPackageName() {
-        Call.Details callDetails = mCurrentCall == null ? null : mCurrentCall.getDetails();
-        PhoneAccountHandle phoneAccountHandle =
-                callDetails == null ? null : callDetails.getAccountHandle();
-        return phoneAccountHandle == null ? null
-                : phoneAccountHandle.getComponentName().getPackageName();
-    }
-
-    private boolean isSelfManagedCall() {
-        return mCurrentCall != null
-                && mCurrentCall.getDetails().hasProperty(Call.Details.PROPERTY_SELF_MANAGED);
-    }
-
     private CardHeader createCardHeader(String packageName) {
         if (!TextUtils.isEmpty(packageName)) {
             try {
@@ -450,24 +409,6 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
         return null;
     }
 
-    @Override
-    public void propertyChange(PropertyChangeEvent evt) {
-        Log.d(TAG, "InCallService has updated.");
-        if (PROPERTY_IN_CALL_SERVICE.equals(evt.getPropertyName())
-                && sInCallServiceManager.getInCallService() != null) {
-            onInCallServiceConnected();
-        }
-    }
-
-    private void onInCallServiceConnected() {
-        Log.d(TAG, "InCall service is connected");
-        mInCallService = (InCallServiceImpl) sInCallServiceManager.getInCallService();
-        mInCallService.addListener(this);
-        if (mInCallService.getCalls() != null && !mInCallService.getCalls().isEmpty()) {
-            onCallAdded(mInCallService.getCalls().get(0));
-        }
-    }
-
     private boolean isCarAppCallingService(String packageName) {
         // Check that app is integrated with CAL and handles calls
         Intent serviceIntent =
@@ -479,7 +420,7 @@ public class InCallModel implements AudioModel, InCallServiceImpl.InCallListener
             return false;
         }
 
-        // Check that app has CAl activity
+        // Check that app has CAL activity
         Intent activityIntent = new Intent();
         activityIntent.setComponent(new ComponentName(packageName, CAR_APP_ACTIVITY_INTERFACE));
 
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/MediaLaunchHandler.java b/app/src/com/android/car/carlauncher/homescreen/audio/MediaLaunchHandler.java
new file mode 100644
index 00000000..f05a6eba
--- /dev/null
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/MediaLaunchHandler.java
@@ -0,0 +1,31 @@
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
+package com.android.car.carlauncher.homescreen.audio;
+
+import androidx.annotation.NonNull;
+
+import com.android.car.media.common.source.MediaSource;
+
+/**
+ * Handles launching a media app
+ */
+public interface MediaLaunchHandler {
+    /**
+     * Handle launching a {@link MediaSource}.
+     */
+    void handleLaunchMedia(@NonNull MediaSource mediaSource);
+}
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java b/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
index 4aeef026..3eaa4220 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/MediaViewModel.java
@@ -161,7 +161,7 @@ public class MediaViewModel extends AndroidViewModel implements AudioModel {
         int max = resources.getInteger(
                 com.android.car.media.common.R.integer.media_items_bitmap_max_size_px);
         mMediaBackground = resources
-                .getDrawable(R.drawable.control_bar_image_background);
+                .getDrawable(R.drawable.control_bar_image_background, mContext.getTheme());
         Size maxArtSize = new Size(max, max);
         mAlbumArtBinder = new ImageBinder<>(ImageBinder.PlaceholderType.FOREGROUND, maxArtSize,
                 drawable -> {
@@ -175,7 +175,8 @@ public class MediaViewModel extends AndroidViewModel implements AudioModel {
         mPlaybackViewModel.getPlaybackController().observeForever(mPlaybackControllerObserver);
         mPlaybackViewModel.getPlaybackStateWrapper().observeForever(mPlaybackStateWrapperObserver);
 
-        mSeekBarColor = mDefaultSeekBarColor = resources.getColor(R.color.seek_bar_color, null);
+        mSeekBarColor = mDefaultSeekBarColor = resources.getColor(R.color.seek_bar_color,
+                mContext.getTheme());
         mSeekBarMax = resources.getInteger(R.integer.optional_seekbar_max);
         mUseMediaSourceColor = resources.getBoolean(R.bool.use_media_source_color_for_seek_bar);
         mTimesSeparator = resources.getString(R.string.times_separator);
@@ -204,6 +205,10 @@ public class MediaViewModel extends AndroidViewModel implements AudioModel {
         return mediaSource != null ? mediaSource.getIntent() : null;
     }
 
+    public MediaSource getMediaSource() {
+        return getMediaSourceViewModel().getPrimaryMediaSource().getValue();
+    }
+
     @Override
     public void setOnModelUpdateListener(OnModelUpdateListener onModelUpdateListener) {
         mOnModelUpdateListener = onModelUpdateListener;
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java
index 2e36fe0f..888167d1 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenter.java
@@ -24,7 +24,7 @@ import com.android.car.carlauncher.homescreen.CardPresenter;
 import com.android.car.carlauncher.homescreen.HomeCardFragment.OnViewClickListener;
 import com.android.car.carlauncher.homescreen.HomeCardFragment.OnViewLifecycleChangeListener;
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
-import com.android.car.carlauncher.homescreen.audio.InCallModel;
+import com.android.car.carlauncher.homescreen.audio.InCallViewModel;
 
 import java.util.List;
 
@@ -42,7 +42,7 @@ public class DialerCardPresenter extends CardPresenter {
         void onInCallStateChanged(boolean hasActiveCall);
     }
 
-    private InCallModel mViewModel;
+    private InCallViewModel mViewModel;
     private DialerCardFragment mFragment;
 
     @VisibleForTesting
@@ -68,7 +68,7 @@ public class DialerCardPresenter extends CardPresenter {
             new HomeCardInterface.Model.OnModelUpdateListener() {
                 @Override
                 public void onModelUpdate(HomeCardInterface.Model model) {
-                    InCallModel dialerCardModel = (InCallModel) model;
+                    InCallViewModel dialerCardModel = (InCallViewModel) model;
                     if (dialerCardModel.getCardHeader() != null) {
                         mFragment.updateHeaderView(dialerCardModel.getCardHeader());
                     }
@@ -103,7 +103,7 @@ public class DialerCardPresenter extends CardPresenter {
         // No-op
     }
 
-    public void setModel(InCallModel viewModel) {
+    public void setModel(InCallViewModel viewModel) {
         mViewModel = viewModel;
     }
 
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
index ee15c49a..4046491e 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardController.java
@@ -23,7 +23,6 @@ import static com.android.car.media.common.ui.PlaybackCardControllerUtilities.up
 
 import static java.lang.Integer.max;
 
-import android.content.Intent;
 import android.content.res.Resources;
 import android.graphics.drawable.Drawable;
 import android.net.Uri;
@@ -65,7 +64,7 @@ public class MediaCardController extends PlaybackCardController implements
     private static final int SWIPE_MAX_OFF_PATH = 75;
     private static final int SWIPE_THRESHOLD_VELOCITY = 200;
 
-    private final MediaIntentRouter mMediaIntentRouter = MediaIntentRouter.getInstance();
+    private final MediaLaunchRouter mMediaLaunchRouter = MediaLaunchRouter.getInstance();
     private Resources mViewResources;
     private View mPanelHandlebar;
     private LinearLayout mPanel;
@@ -238,7 +237,8 @@ public class MediaCardController extends PlaybackCardController implements
     @Override
     protected void updateAlbumCoverWithDrawable(Drawable drawable) {
         Drawable drawableToUse = drawable == null ? mView.getResources().getDrawable(
-                /* drawable */ R.drawable.media_card_default_album_art, /* theme */ null)
+                /* drawable */ R.drawable.media_card_default_album_art,
+                /* theme */ mView.getContext().getTheme())
                 : drawable;
         RoundedDrawable roundedDrawable = new RoundedDrawable(drawableToUse, mView.getResources()
                 .getFloat(R.dimen.media_card_album_art_drawable_corner_ratio));
@@ -453,9 +453,7 @@ public class MediaCardController extends PlaybackCardController implements
         if (mCardViewModel.getPanelExpanded()) {
             animateClosePanel();
         } else {
-            MediaSource mediaSource = mDataModel.getMediaSource().getValue();
-            Intent intent = mediaSource != null ? mediaSource.getIntent() : null;
-            mMediaIntentRouter.handleMediaIntent(intent);
+            mMediaLaunchRouter.handleLaunchMedia(mDataModel.getMediaSource().getValue());
         }
     }
 
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java
index 007bbf2e..1e3f704c 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPanelViewPagerAdapter.java
@@ -154,8 +154,8 @@ public class MediaCardPanelViewPagerAdapter extends
                 button.setBackground(null);
                 button.setImageDrawable(defaultDrawable);
                 button.setImageTintList(ColorStateList.valueOf(
-                        mContext.getResources().getColor(
-                                R.color.car_surface_variant, /* theme */ null)));
+                        mContext.getResources().getColor(R.color.media_card_action_button_color,
+                            mContext.getTheme())));
                 ViewUtils.setVisible(button, true);
             }
         }
@@ -169,7 +169,8 @@ public class MediaCardPanelViewPagerAdapter extends
                     actionsToFill.get(i).setBackgroundColor(Color.TRANSPARENT);
                     actionsToFill.get(i).setImageTintList(ColorStateList.valueOf(
                             mContext.getResources().getColor(
-                                    R.color.car_on_surface, /* theme */ null)));
+                                R.color.media_card_custom_action_button_color,
+                                mContext.getTheme())));
                     ViewUtils.setVisible(actionsToFill.get(i), true);
                     actionsToFill.get(i).setOnClickListener(v -> {
                         if (mPlaybackController != null) {
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPresenter.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPresenter.java
index 4ba575b4..2c12cf64 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPresenter.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaCardPresenter.java
@@ -16,8 +16,6 @@
 
 package com.android.car.carlauncher.homescreen.audio.media;
 
-import android.content.Intent;
-
 import androidx.annotation.VisibleForTesting;
 
 import com.android.car.carlauncher.homescreen.CardPresenter;
@@ -37,7 +35,7 @@ import java.util.List;
  */
 public class MediaCardPresenter extends CardPresenter {
 
-    public final MediaIntentRouter mMediaIntentRouter = MediaIntentRouter.getInstance();
+    public final MediaLaunchRouter mMediaLaunchRouter = MediaLaunchRouter.getInstance();
 
     private MediaViewModel mViewModel;
     private MediaCardFragment mFragment;
@@ -49,8 +47,7 @@ public class MediaCardPresenter extends CardPresenter {
             new HomeCardFragment.OnViewClickListener() {
                 @Override
                 public void onViewClicked() {
-                    Intent intent = mViewModel.getIntent();
-                    mMediaIntentRouter.handleMediaIntent(intent);
+                    mMediaLaunchRouter.handleLaunchMedia(mViewModel.getMediaSource());
                 }
             };
 
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaIntentRouter.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaIntentRouter.java
deleted file mode 100644
index 191d4fad..00000000
--- a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaIntentRouter.java
+++ /dev/null
@@ -1,55 +0,0 @@
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
-package com.android.car.carlauncher.homescreen.audio.media;
-
-import android.content.Intent;
-
-import com.android.car.carlauncher.homescreen.audio.IntentHandler;
-
-/**
- * Routes media {@link Intent} to {@link IntentHandler}.
- */
-public class MediaIntentRouter {
-    private static MediaIntentRouter sInstance;
-    private IntentHandler mIntentHandler;
-
-    /**
-     * @return an instance of {@link MediaIntentRouter}.
-     */
-    public static MediaIntentRouter getInstance() {
-        if (sInstance == null) {
-            sInstance = new MediaIntentRouter();
-        }
-        return sInstance;
-    }
-
-    /**
-     * Register a {@link IntentHandler}.
-     */
-    public void registerMediaIntentHandler(IntentHandler intentHandler) {
-        mIntentHandler = intentHandler;
-    }
-
-    /**
-     * Dispatch a media intent to {@link IntentHandler}
-     */
-    public void handleMediaIntent(Intent intent) {
-        if (intent != null) {
-            mIntentHandler.handleIntent(intent);
-        }
-    }
-}
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaLaunchRouter.java b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaLaunchRouter.java
new file mode 100644
index 00000000..4fe4baa8
--- /dev/null
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/media/MediaLaunchRouter.java
@@ -0,0 +1,54 @@
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
+package com.android.car.carlauncher.homescreen.audio.media;
+
+import com.android.car.carlauncher.homescreen.audio.MediaLaunchHandler;
+import com.android.car.media.common.source.MediaSource;
+
+/**
+ * Routes media launches to {@link MediaLaunchHandler}.
+ */
+public class MediaLaunchRouter {
+    private static MediaLaunchRouter sInstance;
+    private MediaLaunchHandler mMediaLaunchHandler;
+
+    /**
+     * @return an instance of {@link MediaLaunchRouter}.
+     */
+    public static MediaLaunchRouter getInstance() {
+        if (sInstance == null) {
+            sInstance = new MediaLaunchRouter();
+        }
+        return sInstance;
+    }
+
+    /**
+     * Register a {@link MediaLaunchHandler}.
+     */
+    public void registerMediaLaunchHandler(MediaLaunchHandler mediaLaunchHandler) {
+        mMediaLaunchHandler = mediaLaunchHandler;
+    }
+
+    /**
+     * Dispatch a media source to {@link MediaLaunchHandler}
+     */
+    public void handleLaunchMedia(MediaSource mediaSource) {
+        if (mediaSource != null) {
+            mMediaLaunchHandler.handleLaunchMedia(mediaSource);
+        }
+    }
+}
diff --git a/app/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImpl.java b/app/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImpl.java
index ee652633..8a8c9263 100644
--- a/app/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImpl.java
+++ b/app/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImpl.java
@@ -16,36 +16,22 @@
 
 package com.android.car.carlauncher.homescreen.audio.telecom;
 
-import android.content.Intent;
-import android.os.Binder;
-import android.os.IBinder;
-import android.os.Process;
-import android.telecom.Call;
-import android.telecom.CallAudioState;
 import android.telecom.InCallService;
-import android.util.Log;
 
-import com.android.car.carlauncher.homescreen.audio.InCallModel;
 import com.android.car.carlauncher.homescreen.audio.InCallServiceManagerProvider;
-
-import java.util.ArrayList;
+import com.android.car.carlauncher.homescreen.audio.InCallViewModel;
+import com.android.car.telephony.calling.InCallModel;
+import com.android.car.telephony.calling.SimpleInCallServiceImpl;
 
 /**
  * Implementation of {@link InCallService}, an {@link android.telecom} service which must be
  * implemented by an app that wishes to provide functionality for managing phone calls. This service
- * is bound by android telecom and {@link InCallModel}.
+ * is bound by android telecom and {@link InCallViewModel}. {@link SimpleInCallServiceImpl} provides
+ * an interface for call state callbacks which can be used together with {@link InCallModel} to
+ * ensure call model consistency between all apps that use these classes.
  */
-public class InCallServiceImpl extends InCallService {
+public class InCallServiceImpl extends SimpleInCallServiceImpl {
     private static final String TAG = "Home.InCallServiceImpl";
-    private static final boolean DEBUG = false;
-
-    /**
-     * An action which indicates a bind is from local component. Local components must use this
-     * action to be able to bind the service.
-     */
-    public static final String ACTION_LOCAL_BIND = "local_bind";
-
-    private ArrayList<InCallListener> mInCallListeners = new ArrayList<>();
 
     @Override
     public void onCreate() {
@@ -58,98 +44,4 @@ public class InCallServiceImpl extends InCallService {
         InCallServiceManagerProvider.get().setInCallService(null);
         super.onDestroy();
     }
-
-    @Override
-    public void onCallAdded(Call call) {
-        if (DEBUG) Log.d(TAG, "onCallAdded: " + call);
-        for (InCallListener listener : mInCallListeners) {
-            listener.onCallAdded(call);
-        }
-    }
-
-    @Override
-    public void onCallRemoved(Call call) {
-        if (DEBUG) Log.d(TAG, "onCallRemoved: " + call);
-        for (InCallListener listener : mInCallListeners) {
-            listener.onCallRemoved(call);
-        }
-    }
-
-    @Override
-    public void onCallAudioStateChanged(CallAudioState audioState) {
-        if (DEBUG) Log.d(TAG, "onCallAudioStateChanged: " + audioState);
-        for (InCallListener listener : mInCallListeners) {
-            listener.onCallAudioStateChanged(audioState);
-        }
-    }
-
-    @Override
-    public IBinder onBind(Intent intent) {
-        if (DEBUG) Log.d(TAG, "onBind, intent: " + intent);
-        return ACTION_LOCAL_BIND.equals(intent.getAction())
-                ? new LocalBinder()
-                : super.onBind(intent);
-    }
-
-    @Override
-    public boolean onUnbind(Intent intent) {
-        if (DEBUG) Log.d(TAG, "onUnbind, intent: " + intent);
-        if (ACTION_LOCAL_BIND.equals(intent.getAction())) {
-            return false;
-        }
-        return super.onUnbind(intent);
-    }
-
-    /**
-     * Adds a listener for {@link InCallService} events
-     */
-    public void addListener(InCallListener listener) {
-        mInCallListeners.add(listener);
-    }
-
-    /**
-     * Removes a listener for {@link InCallService} events
-     */
-    public void removeListener(InCallListener listener) {
-        if (!mInCallListeners.isEmpty()) mInCallListeners.remove(listener);
-    }
-
-    /**
-     * Class used for the client Binder to access the service.
-     */
-    public class LocalBinder extends Binder {
-
-        /**
-         * Returns this instance of {@link InCallServiceImpl} if running in the Home App process,
-         * otherwise null
-         */
-        public InCallServiceImpl getService() {
-            if (getCallingPid() == Process.myPid()) {
-                return InCallServiceImpl.this;
-            }
-            return null;
-        }
-    }
-
-    /**
-     * Listens for {@link #onCallAdded(Call)} and {@link #onCallRemoved(Call)} events
-     */
-    public interface InCallListener {
-        /**
-         * Called when a {@link Call} has been added to this in-call session, generally indicating
-         * that the call has been received.
-         */
-        void onCallAdded(Call call);
-
-        /**
-         * Called when a {@link Call} has been removed from this in-call session, generally
-         * indicating that the call has ended.
-         */
-        void onCallRemoved(Call call);
-
-        /**
-         * Called when {@link CallAudioState} changes.
-         */
-        void onCallAudioStateChanged(CallAudioState audioState);
-    }
 }
diff --git a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
index 3634641b..bc8988da 100644
--- a/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
+++ b/app/src/com/android/car/carlauncher/recents/CarQuickStepService.java
@@ -31,7 +31,7 @@ import android.util.Log;
 
 import androidx.annotation.Nullable;
 
-import com.android.systemui.shared.recents.IOverviewProxy;
+import com.android.systemui.shared.recents.ILauncherProxy;
 import com.android.systemui.shared.statusbar.phone.BarTransitions;
 import com.android.systemui.shared.system.QuickStepContract.SystemUiStateFlags;
 import com.android.wm.shell.recents.IRecentTasks;
@@ -57,7 +57,7 @@ public class CarQuickStepService extends Service {
     @Nullable
     @Override
     public IBinder onBind(Intent intent) {
-        return new CarOverviewProxyBinder();
+        return new CarLauncherProxyBinder();
     }
 
     @Override
@@ -89,7 +89,7 @@ public class CarQuickStepService extends Service {
         startActivity(intent);
     }
 
-    private class CarOverviewProxyBinder extends IOverviewProxy.Stub {
+    private class CarLauncherProxyBinder extends ILauncherProxy.Stub {
         @Override
         public void onActiveNavBarRegionChanges(Region activeRegion) {
             // no-op
@@ -146,7 +146,7 @@ public class CarQuickStepService extends Service {
         }
 
         @Override
-        public void onSystemUiStateChanged(@SystemUiStateFlags long stateFlags) {
+        public void onSystemUiStateChanged(@SystemUiStateFlags long stateFlags, int displayId) {
             // no-op
         }
 
@@ -230,5 +230,20 @@ public class CarQuickStepService extends Service {
                 Log.w(TAG, "onUnbind: Failed to reply to OverviewProxyService", e);
             }
         }
+
+        @Override
+        public void onDisplayRemoved(int displayId) {
+            // no-op
+        }
+
+        @Override
+        public void onDisplayAddSystemDecorations(int displayId) {
+            // no-op
+        }
+
+        @Override
+        public void onDisplayRemoveSystemDecorations(int displayId) {
+            // no-op
+        }
     }
 }
diff --git a/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java b/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java
index 07310075..f1588e70 100644
--- a/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java
+++ b/app/src/com/android/car/carlauncher/recents/CarRecentsActivity.java
@@ -90,7 +90,8 @@ public class CarRecentsActivity extends AppCompatActivity implements
                 /* windowInsets= */ windowMetrics.getWindowInsets()
                         .getInsetsIgnoringVisibility(WindowInsets.Type.systemBars()).toRect(),
                 /* defaultThumbnailColor= */
-                getResources().getColor(R.color.default_recents_thumbnail_color, /* theme= */null));
+                getResources().getColor(R.color.default_recents_thumbnail_color,
+                        /* theme= */ getTheme()));
 
         if (!(mRecentsRecyclerView.getLayoutManager() instanceof GridLayoutManager)) {
             throw new UnsupportedOperationException(
diff --git a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
index 03ec2aba..07a7ab92 100644
--- a/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
+++ b/app/src/com/android/car/carlauncher/recents/RecentTasksProvider.java
@@ -18,7 +18,7 @@ package com.android.car.carlauncher.recents;
 
 import static android.app.ActivityManager.RECENT_IGNORE_UNAVAILABLE;
 
-import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FREEFORM;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_DESK;
 import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FULLSCREEN;
 import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_SPLIT;
 
@@ -193,12 +193,12 @@ public class RecentTasksProvider implements RecentTasksProviderInterface {
                         getRecentTaskIconAsync(task.key.id);
                         break;
                     case TYPE_SPLIT:
-                    case TYPE_FREEFORM:
+                    case TYPE_DESK:
                         areSplitOrFreeformTypeTasksPresent = true;
                 }
             }
             if (areSplitOrFreeformTypeTasksPresent && DEBUG) {
-                Log.d(TAG, "Automotive doesn't support TYPE_SPLIT and TYPE_FREEFORM tasks");
+                Log.d(TAG, "Automotive doesn't support TYPE_SPLIT and TYPE_DESK tasks");
             }
             if (mRecentsDataChangeListener != null) {
                 sMainHandler.post(() -> mRecentsDataChangeListener.recentTasksFetched());
diff --git a/app/tests/Android.bp b/app/tests/Android.bp
index 444d2e54..e899f994 100644
--- a/app/tests/Android.bp
+++ b/app/tests/Android.bp
@@ -33,6 +33,7 @@ android_test {
         "android.car",
         "android.test.base.stubs.system",
         "android.car-system-stubs",
+        "token-shared-lib-prebuilt",
     ],
 
     optimize: {
@@ -59,6 +60,8 @@ android_test {
         "flag-junit",
     ],
 
+    enforce_uses_libs: false,
+
     // b/341652226: temporarily disable multi-dex until D8 is fixed
     no_dex_container: true,
 
diff --git a/app/tests/AndroidManifest.xml b/app/tests/AndroidManifest.xml
index 1bb4f4e7..1bef2250 100644
--- a/app/tests/AndroidManifest.xml
+++ b/app/tests/AndroidManifest.xml
@@ -23,8 +23,22 @@
         android:label="@string/app_test_title"
         tools:replace="android:label">
 
-        <activity android:name="com.android.car.carlauncher.CarLauncherViewModelTest$TestActivity"/>
+        <activity android:name="com.android.car.carlauncher.CarLauncherViewModelTest$TestActivity"
+            android:theme="@style/TestActivityTheme">
+        </activity>
+        <activity
+            android:name="com.android.car.carlauncher.CarLauncherTest$TestMapActivity"
+            android:enabled="false"
+            android:exported="false"
+            android:theme="@style/TestMapActivityTheme">
+            <intent-filter android:priority="100">
+                <action android:name="android.intent.action.MAIN" />
+                <category android:name="android.intent.category.APP_MAPS" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+        </activity>
         <uses-library android:name="android.test.runner"/>
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
         <provider android:name="com.android.car.carlauncher.calmmode.CalmModeQCProvider"
                  tools:node="remove"/>
     </application>
diff --git a/app/tests/res/values/styles.xml b/app/tests/res/values/styles.xml
new file mode 100644
index 00000000..abfa6188
--- /dev/null
+++ b/app/tests/res/values/styles.xml
@@ -0,0 +1,35 @@
+<?xml version="1.0" encoding="UTF-8"?>
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
+<resources
+    xmlns:android="http://schemas.android.com/apk/res/android">
+  <style name="TestActivityTheme" parent="Theme.CarUi.NoToolbar">
+    <item name="oemTokenOverrideEnabled">true</item>
+  </style>
+
+  <style name="TestMapActivityTheme" parent="Theme.CarUi.NoToolbar">
+    <item name="oemTokenOverrideEnabled">true</item>
+  </style>
+
+  <!--For fragment tests, the fragment is hosted by FragmentScenarioEmptyFragmentActivity-->
+  <!--not the parent activity. Therefore, we need to apply TokenInstaller to this-->
+  <!--activity theme-->
+  <style name="FragmentScenarioEmptyFragmentActivityTheme" parent="android:Theme.WithActionBar">
+    <item name="android:windowIsFloating">false</item>
+    <item name="oemTokenOverrideEnabled">true</item>
+  </style>
+</resources>
diff --git a/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java b/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
index 620e26f9..f2618b2e 100644
--- a/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
+++ b/app/tests/src/com/android/car/carlauncher/CarLauncherTest.java
@@ -37,7 +37,10 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.any;
 
+import android.app.Activity;
 import android.car.test.mocks.AbstractExtendedMockitoTestCase;
+import android.content.ComponentName;
+import android.content.Context;
 import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.platform.test.annotations.RequiresFlagsDisabled;
@@ -174,6 +177,8 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
                 .when(() -> CarLauncherUtils.getTosMapIntent(any()));
         doReturn(tosDisabledPackages())
                 .when(() -> AppLauncherUtils.getTosDisabledPackages(any()));
+        // Enable the TestMapActivity
+        TestMapActivity.enableActivity(mContext, true);
 
         mActivityScenario = ActivityScenario.launch(CarLauncher.class);
 
@@ -187,13 +192,20 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
                     createIntentFromString(TOS_MAP_INTENT).getComponent().getClassName(),
                     mapIntent.getComponent().getClassName());
         });
+
+        // Cleanup - Disable TestMapActivity
+        TestMapActivity.enableActivity(mContext, false);
     }
 
     @Test
     public void onCreate_tosAccepted_doesNotLaunchTosMapIntent() {
         doReturn(true).when(() -> AppLauncherUtils.tosAccepted(any()));
+        doReturn(false)
+                .when(() -> CarLauncherUtils.isSmallCanvasOptimizedMapIntentConfigured(any()));
         doReturn(createIntentFromString(TOS_MAP_INTENT))
                 .when(() -> CarLauncherUtils.getTosMapIntent(any()));
+        // Enable the TestMapActivity
+        TestMapActivity.enableActivity(mContext, true);
 
         mActivityScenario = ActivityScenario.launch(CarLauncher.class);
 
@@ -204,6 +216,9 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
                     createIntentFromString(TOS_MAP_INTENT).getComponent().getClassName(),
                     mapIntent.getComponent().getClassName());
         });
+
+        // Cleanup - Disable TestMapActivity
+        TestMapActivity.enableActivity(mContext, false);
     }
 
     @Test
@@ -279,7 +294,7 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
 
     @Test
     public void onCreate_whenTosIsNull_tosStateContentObserverIsNotNull() {
-        // Settings.Secure KEY_USER_TOS_ACCEPTED is null when not set explicitly.
+        Settings.Secure.putString(mContext.getContentResolver(), KEY_USER_TOS_ACCEPTED, null);
         mActivityScenario = ActivityScenario.launch(new Intent(mContext, CarLauncher.class));
 
         // Content observer is not null after activity is created
@@ -398,4 +413,19 @@ public class CarLauncherTest extends AbstractExtendedMockitoTestCase {
         return mContext.getPackageManager()
                 .hasSystemFeature(PackageManager.FEATURE_CAR_SPLITSCREEN_MULTITASKING);
     }
+
+    public static class TestMapActivity extends Activity {
+        static void enableActivity(Context context, boolean enable) {
+            PackageManager pm = context.getPackageManager();
+            // Enable the TestMapActivity
+            ComponentName componentName = new ComponentName(
+                    "com.android.car.carlauncher.test", // pkg
+                    "com.android.car.carlauncher.CarLauncherTest$TestMapActivity" // cls
+            );
+            int state = enable
+                    ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
+                    : PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
+            pm.setComponentEnabledSetting(componentName, state, PackageManager.DONT_KILL_APP);
+        }
+    }
 }
diff --git a/libs/appgrid/lib/tests/src/com/android/car/carlauncher/InstantTaskExecutorRule.java b/app/tests/src/com/android/car/carlauncher/InstantTaskExecutorRule.java
similarity index 100%
rename from libs/appgrid/lib/tests/src/com/android/car/carlauncher/InstantTaskExecutorRule.java
rename to app/tests/src/com/android/car/carlauncher/InstantTaskExecutorRule.java
diff --git a/app/tests/src/com/android/car/carlauncher/calmmode/NavigationStateViewModelTest.java b/app/tests/src/com/android/car/carlauncher/calmmode/NavigationStateViewModelTest.java
index f9549d61..f31c855b 100644
--- a/app/tests/src/com/android/car/carlauncher/calmmode/NavigationStateViewModelTest.java
+++ b/app/tests/src/com/android/car/carlauncher/calmmode/NavigationStateViewModelTest.java
@@ -36,7 +36,7 @@ import android.icu.util.MeasureUnit;
 import androidx.annotation.NonNull;
 import androidx.test.core.app.ApplicationProvider;
 
-import com.android.car.apps.common.testutils.InstantTaskExecutorRule;
+import com.android.car.carlauncher.InstantTaskExecutorRule;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
 
 import org.junit.Before;
diff --git a/app/tests/src/com/android/car/carlauncher/calmmode/TemperatureViewModelTest.java b/app/tests/src/com/android/car/carlauncher/calmmode/TemperatureViewModelTest.java
index 8c759523..ecd5de25 100644
--- a/app/tests/src/com/android/car/carlauncher/calmmode/TemperatureViewModelTest.java
+++ b/app/tests/src/com/android/car/carlauncher/calmmode/TemperatureViewModelTest.java
@@ -42,7 +42,7 @@ import androidx.annotation.NonNull;
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.car.apps.common.testutils.InstantTaskExecutorRule;
+import com.android.car.carlauncher.InstantTaskExecutorRule;
 
 import org.junit.Before;
 import org.junit.Rule;
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/audio/InCallModelTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/audio/InCallViewModelTest.java
similarity index 96%
rename from app/tests/src/com/android/car/carlauncher/homescreen/audio/InCallModelTest.java
rename to app/tests/src/com/android/car/carlauncher/homescreen/audio/InCallViewModelTest.java
index 346f7088..0581f87a 100644
--- a/app/tests/src/com/android/car/carlauncher/homescreen/audio/InCallModelTest.java
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/audio/InCallViewModelTest.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2020 Google Inc.
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -33,6 +33,7 @@ import android.telecom.CallAudioState;
 
 import androidx.test.core.app.ApplicationProvider;
 
+import com.android.car.carlauncher.InstantTaskExecutorRule;
 import com.android.car.carlauncher.R;
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
@@ -41,22 +42,24 @@ import com.android.internal.util.ArrayUtils;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
+import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
-import java.time.Clock;
-
 @RunWith(JUnit4.class)
-public class InCallModelTest {
+public class InCallViewModelTest {
 
+    @Rule
+    public TestRule rule = new InstantTaskExecutorRule();
     private static final String PHONE_NUMBER = "01234567";
     private static final String DISPLAY_NAME = "Test Caller";
     private static final String INITIALS = "T";
 
-    private InCallModel mInCallModel;
+    private InCallViewModel mInCallModel;
     private String mOngoingCallSecondaryText;
     private String mDialingCallSecondaryText;
 
@@ -64,8 +67,6 @@ public class InCallModelTest {
 
     @Mock
     private HomeCardInterface.Model.OnModelUpdateListener mOnModelUpdateListener;
-    @Mock
-    private Clock mClock;
 
     private Call mCall = null;
 
@@ -73,7 +74,7 @@ public class InCallModelTest {
     public void setUp() {
         MockitoAnnotations.initMocks(this);
         mContext = ApplicationProvider.getApplicationContext();
-        mInCallModel = new InCallModel(mClock);
+        mInCallModel = new InCallViewModel();
         mInCallModel.setOnModelUpdateListener(mOnModelUpdateListener);
         mInCallModel.onCreate(mContext);
         Resources resources = ApplicationProvider.getApplicationContext().getResources();
@@ -91,13 +92,6 @@ public class InCallModelTest {
         verify(mOnModelUpdateListener, never()).onModelUpdate(any());
     }
 
-    @Test
-    public void onCallRemoved_callsPresenter() {
-        mInCallModel.onCallRemoved(mCall);
-
-        verify(mOnModelUpdateListener).onModelUpdate(mInCallModel);
-    }
-
     @Test
     public void updateModelWithPhoneNumber_active_setsPhoneNumberAndSubtitle() {
         mInCallModel.updateModelWithPhoneNumber(PHONE_NUMBER, Call.STATE_ACTIVE);
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/audio/MediaViewModelTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/audio/MediaViewModelTest.java
index e6e6583c..2c0f1d25 100644
--- a/app/tests/src/com/android/car/carlauncher/homescreen/audio/MediaViewModelTest.java
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/audio/MediaViewModelTest.java
@@ -34,8 +34,8 @@ import androidx.test.annotation.UiThreadTest;
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.car.apps.common.testutils.InstantTaskExecutorRule;
 import com.android.car.carlauncher.AppLauncherUtils;
+import com.android.car.carlauncher.InstantTaskExecutorRule;
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextWithControlsView;
@@ -241,4 +241,3 @@ public class MediaViewModelTest extends AbstractExtendedMockitoTestCase  {
         assertEquals(seekBarViewModel.getSeekBarColor(), COLORS);
     }
 }
-
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java
index 3f9bb9f0..8c62f546 100644
--- a/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java
+++ b/app/tests/src/com/android/car/carlauncher/homescreen/audio/dialer/DialerCardPresenterTest.java
@@ -23,7 +23,7 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import com.android.car.carlauncher.homescreen.HomeCardInterface;
-import com.android.car.carlauncher.homescreen.audio.InCallModel;
+import com.android.car.carlauncher.homescreen.audio.InCallViewModel;
 import com.android.car.carlauncher.homescreen.ui.CardHeader;
 import com.android.car.carlauncher.homescreen.ui.DescriptiveTextView;
 
@@ -47,7 +47,7 @@ public class DialerCardPresenterTest {
     @Mock
     private DialerCardFragment mView;
     @Mock
-    private InCallModel mModel;
+    private InCallViewModel mModel;
 
     @Mock
     private DialerCardPresenter.OnInCallStateChangeListener mOnInCallStateChangeListener;
diff --git a/app/tests/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImplTest.java b/app/tests/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImplTest.java
deleted file mode 100644
index 461784d0..00000000
--- a/app/tests/src/com/android/car/carlauncher/homescreen/audio/telecom/InCallServiceImplTest.java
+++ /dev/null
@@ -1,89 +0,0 @@
-/*
- * Copyright (C) 2020 Google Inc.
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
-package com.android.car.carlauncher.homescreen.audio.telecom;
-
-import static org.mockito.Mockito.verify;
-
-import android.content.Intent;
-import android.os.IBinder;
-import android.telecom.Call;
-import android.telecom.CallAudioState;
-
-import androidx.test.core.app.ApplicationProvider;
-import androidx.test.rule.ServiceTestRule;
-
-import com.android.car.carlauncher.homescreen.audio.InCallModel;
-
-import org.junit.Before;
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
-
-import java.util.concurrent.TimeoutException;
-
-@RunWith(JUnit4.class)
-public class InCallServiceImplTest {
-
-    private InCallServiceImpl mService;
-    private Call mCall = null;
-
-    @Mock
-    private InCallModel mInCallModel;
-
-    @Rule
-    public final ServiceTestRule mServiceTestRule = new ServiceTestRule();
-
-    @Before
-    public void setUp() throws TimeoutException {
-        MockitoAnnotations.initMocks(this);
-
-        Intent intent = new Intent(ApplicationProvider.getApplicationContext(),
-                InCallServiceImpl.class);
-        intent.setAction(InCallServiceImpl.ACTION_LOCAL_BIND);
-        IBinder binder = mServiceTestRule.bindService(intent);
-        mService = ((InCallServiceImpl.LocalBinder) binder).getService();
-    }
-
-    @Test
-    public void onCallAdded_callsListener() {
-        mService.addListener(mInCallModel);
-        mService.onCallAdded(mCall);
-
-        verify(mInCallModel).onCallAdded(mCall);
-    }
-
-    @Test
-    public void onCallRemoved_callsListener() {
-        mService.addListener(mInCallModel);
-        mService.onCallRemoved(mCall);
-
-        verify(mInCallModel).onCallRemoved(mCall);
-    }
-
-    @Test
-    public void onCallAudioStateChanged_callsListeners() {
-        CallAudioState callAudioState = new CallAudioState(false,
-                CallAudioState.ROUTE_WIRED_OR_EARPIECE, CallAudioState.ROUTE_WIRED_OR_EARPIECE);
-        mService.addListener(mInCallModel);
-        mService.onCallAudioStateChanged(callAudioState);
-
-        verify(mInCallModel).onCallAudioStateChanged(callAudioState);
-    }
-}
diff --git a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
index 5e7703ee..29277adb 100644
--- a/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
+++ b/app/tests/src/com/android/car/carlauncher/recents/RecentTasksProviderTest.java
@@ -18,7 +18,7 @@ package com.android.car.carlauncher.recents;
 
 import static android.app.ActivityManager.RECENT_IGNORE_UNAVAILABLE;
 
-import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FREEFORM;
+import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_DESK;
 import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_FULLSCREEN;
 import static com.android.wm.shell.shared.GroupedTaskInfo.TYPE_SPLIT;
 
@@ -76,7 +76,7 @@ import java.util.List;
 public class RecentTasksProviderTest {
     private static final int RECENT_TASKS_LENGTH = 20;
     private static final int SPLIT_RECENT_TASKS_LENGTH = 2;
-    private static final int FREEFORM_RECENT_TASKS_LENGTH = 3;
+    private static final int DESK_RECENT_TASKS_LENGTH = 3;
 
     private RecentTasksProvider mRecentTasksProvider;
     private GroupedTaskInfo[] mGroupedRecentTaskInfo;
@@ -195,7 +195,7 @@ public class RecentTasksProviderTest {
     @Test
     public void getRecentTasksAsync_getRecentTaskIds_filters_TYPE_SPLIT() throws
             RemoteException {
-        initRecentTaskList(/* addTypeSplit= */ true, /* addTypeFreeform= */ false);
+        initRecentTaskList(/* addTypeSplit= */ true, /* addTypeDesk= */ false);
         assertThat(mGroupedRecentTaskInfo.length).isEqualTo(
                 RECENT_TASKS_LENGTH + SPLIT_RECENT_TASKS_LENGTH);
         when(mRecentTaskProxy.getRecentTasks(anyInt(), eq(RECENT_IGNORE_UNAVAILABLE),
@@ -218,9 +218,9 @@ public class RecentTasksProviderTest {
     @Test
     public void getRecentTasksAsync_getRecentTaskIds_filters_TYPE_FREEFORM() throws
             RemoteException {
-        initRecentTaskList(/* addTypeSplit= */ false, /* addTypeFreeform= */ true);
+        initRecentTaskList(/* addTypeSplit= */ false, /* addTypeDesk= */ true);
         assertThat(mGroupedRecentTaskInfo.length).isEqualTo(
-                RECENT_TASKS_LENGTH + FREEFORM_RECENT_TASKS_LENGTH);
+                RECENT_TASKS_LENGTH + DESK_RECENT_TASKS_LENGTH);
         when(mRecentTaskProxy.getRecentTasks(anyInt(), eq(RECENT_IGNORE_UNAVAILABLE),
                 anyInt())).thenReturn(mGroupedRecentTaskInfo);
 
@@ -360,10 +360,10 @@ public class RecentTasksProviderTest {
     }
 
     private void initRecentTaskList() {
-        initRecentTaskList(/* addTypeSplit= */ false, /* addTypeFreeform= */ false);
+        initRecentTaskList(/* addTypeSplit= */ false, /* addTypeDesk= */ false);
     }
 
-    private void initRecentTaskList(boolean addTypeSplit, boolean addTypeFreeform) {
+    private void initRecentTaskList(boolean addTypeSplit, boolean addTypeDesk) {
         List<GroupedTaskInfo> groupedRecentTaskInfos = new ArrayList<>();
         for (int i = 0; i < RECENT_TASKS_LENGTH; i++) {
             groupedRecentTaskInfos.add(
@@ -375,10 +375,10 @@ public class RecentTasksProviderTest {
                         createGroupedRecentTaskInfo(createRecentTaskInfo(i), TYPE_SPLIT));
             }
         }
-        if (addTypeFreeform) {
-            for (int i = 0; i < FREEFORM_RECENT_TASKS_LENGTH; i++) {
+        if (addTypeDesk) {
+            for (int i = 0; i < DESK_RECENT_TASKS_LENGTH; i++) {
                 groupedRecentTaskInfos.add(
-                        createGroupedRecentTaskInfo(createRecentTaskInfo(i), TYPE_FREEFORM));
+                        createGroupedRecentTaskInfo(createRecentTaskInfo(i), TYPE_DESK));
             }
         }
         mGroupedRecentTaskInfo = groupedRecentTaskInfos.toArray(GroupedTaskInfo[]::new);
diff --git a/dewd/Android.bp b/dewd/Android.bp
new file mode 100644
index 00000000..6eb607bc
--- /dev/null
+++ b/dewd/Android.bp
@@ -0,0 +1,55 @@
+//
+// Copyright (C) 2025 The Android Open Source Project.
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
+//
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_app {
+    name: "DewdCarLauncher",
+
+    overrides: [
+        "Launcher2",
+        "Launcher3",
+        "Launcher3QuickStep",
+        "CarLauncher",
+    ],
+
+    srcs: ["src/**/*.java"],
+
+    manifest: "AndroidManifest.xml",
+
+    platform_apis: true,
+    certificate: "platform",
+    static_libs: [
+        "CarLauncher-core",
+        "oem-token-lib",
+        "car-ui-lib",
+    ],
+
+    libs: [
+        "token-shared-lib-prebuilt",
+    ],
+
+    enforce_uses_libs: false,
+
+    optimize: {
+        enabled: false,
+    },
+
+    dex_preopt: {
+        enabled: false,
+    },
+}
diff --git a/dewd/AndroidManifest.xml b/dewd/AndroidManifest.xml
new file mode 100644
index 00000000..bb18f06d
--- /dev/null
+++ b/dewd/AndroidManifest.xml
@@ -0,0 +1,63 @@
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project Inc.
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
+<manifest
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.android.car.carlauncher"
+    coreApp="true">
+
+    <!-- Permission to get car driving state -->
+    <uses-permission android:name="android.car.permission.CAR_DRIVING_STATE"/>
+
+    <!-- Permission to manage USB -->
+    <uses-permission android:name="android.permission.MANAGE_USB"/>
+
+    <!-- Permissions to support display compat -->
+    <uses-permission android:name="android.car.permission.MANAGE_DISPLAY_COMPATIBILITY"/>
+
+    <application
+        android:label="Declarative Windowing definition Car Launcher"
+        android:theme="@style/DewdCarLauncherTheme"
+        tools:replace="android:label,android:theme"
+        tools:node="merge">
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
+
+        <activity
+            android:name=".DewdHome"
+            android:exported="true"
+            android:launchMode="singleInstance"
+            android:excludeFromRecents="true">
+            <meta-data android:name="distractionOptimized" android:value="true"/>
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+                <category android:name="android.intent.category.HOME"/>
+                <category android:name="android.intent.category.LAUNCHER_APP"/>
+            </intent-filter>
+        </activity>
+
+        <activity
+            android:name="com.android.car.carlauncher.CarLauncher"
+            android:exported="false"
+            tools:node="merge"
+            tools:replace="android:exported">
+            <!-- Disable the CarLauncher activity as we don't want that in the
+                 custom launcher. -->
+            <intent-filter tools:node="removeAll"/>
+        </activity>
+    </application>
+</manifest>
diff --git a/dewd/res/layout/home.xml b/dewd/res/layout/home.xml
new file mode 100644
index 00000000..383ec098
--- /dev/null
+++ b/dewd/res/layout/home.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8" ?><!--
+  ~ Copyright (C) 2025 The Android Open Source Project.
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/home"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"/>
diff --git a/dewd/res/values/themes.xml b/dewd/res/values/themes.xml
new file mode 100644
index 00000000..3627d9ad
--- /dev/null
+++ b/dewd/res/values/themes.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="utf-8" ?><!--
+  ~ Copyright (C) 2025 The Android Open Source Project.
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
+<resources
+    xmlns:android="http://schemas.android.com/apk/res/android">
+
+    <style name="DewdCarLauncherTheme" parent="Theme.CarUi.NoToolbar">
+        <item name="oemTokenOverrideEnabled">true</item>
+        <item name="android:windowBackground">@android:color/black</item>
+    </style>
+</resources>
\ No newline at end of file
diff --git a/dewd/src/com/android/car/carlauncher/DewdHome.java b/dewd/src/com/android/car/carlauncher/DewdHome.java
new file mode 100644
index 00000000..1e4a3394
--- /dev/null
+++ b/dewd/src/com/android/car/carlauncher/DewdHome.java
@@ -0,0 +1,35 @@
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
+package com.android.car.carlauncher;
+
+import android.os.Bundle;
+
+import androidx.annotation.Nullable;
+import androidx.appcompat.app.AppCompatActivity;
+
+/**
+ * Used as the static wallpaper in base layer. This activity is at the bottom of the base layer
+ * stack and is visible when there is no other base layer application is running.
+ */
+public class DewdHome extends AppCompatActivity {
+
+    @Override
+    protected void onCreate(@Nullable Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.home);
+    }
+}
diff --git a/docklib-util/Android.bp b/docklib-util/Android.bp
index 29ae2156..c9b03a0f 100644
--- a/docklib-util/Android.bp
+++ b/docklib-util/Android.bp
@@ -28,21 +28,8 @@ android_library {
     resource_dirs: ["res"],
 
     static_libs: [
-        "dock_flags_java_lib",
         "androidx.lifecycle_lifecycle-extensions",
     ],
 
     manifest: "AndroidManifest.xml",
 }
-
-aconfig_declarations {
-    name: "dock_flags",
-    package: "com.android.car.dockutil",
-    container: "system",
-    srcs: ["dock_flags.aconfig"],
-}
-
-java_aconfig_library {
-    name: "dock_flags_java_lib",
-    aconfig_declarations: "dock_flags",
-}
diff --git a/docklib-util/dock_flags.aconfig b/docklib-util/dock_flags.aconfig
deleted file mode 100644
index b9e73694..00000000
--- a/docklib-util/dock_flags.aconfig
+++ /dev/null
@@ -1,9 +0,0 @@
-package: "com.android.car.dockutil"
-container: "system"
-
-flag {
-  name: "dock_feature"
-  namespace: "car_sys_exp"
-  description: "This flag enables dock in Car"
-  bug: "301482374"
-}
diff --git a/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java b/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java
index 39362752..43394cce 100644
--- a/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java
+++ b/docklib-util/src/com/android/car/dockutil/events/DockEventSenderHelper.java
@@ -28,8 +28,6 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
-import com.android.car.dockutil.Flags;
-
 /**
  * Helper used to send Dock Events.
  */
@@ -91,10 +89,6 @@ public class DockEventSenderHelper {
     }
 
     private void sendEventBroadcast(@NonNull DockEvent event, @NonNull ComponentName component) {
-        if (!Flags.dockFeature()) {
-            return;
-        }
-
         Intent intent = new Intent();
         intent.setAction(event.toString());
         intent.putExtra(EXTRA_COMPONENT, component);
diff --git a/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java b/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java
index bb5ad666..6c4820c6 100644
--- a/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java
+++ b/docklib-util/tests/src/com/android/car/dockutil/events/DockEventSenderHelperTest.java
@@ -35,14 +35,10 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.res.Resources;
-import android.platform.test.flag.junit.SetFlagsRule;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.car.dockutil.Flags;
-
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
@@ -52,8 +48,6 @@ import org.mockito.MockitoAnnotations;
 
 @RunWith(AndroidJUnit4.class)
 public class DockEventSenderHelperTest {
-    @Rule
-    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
     @Mock
     public ActivityManager.RunningTaskInfo mRunningTaskInfo;
     @Mock
@@ -74,7 +68,6 @@ public class DockEventSenderHelperTest {
         MockitoAnnotations.initMocks(this);
         when(mContext.getResources()).thenReturn(mResources);
         when(mResources.getIntArray(anyInt())).thenReturn(mDockSupportedDisplayId);
-        mSetFlagsRule.enableFlags(Flags.FLAG_DOCK_FEATURE);
         mDockEventSenderHelper = new DockEventSenderHelper(mContext);
     }
 
diff --git a/docklib/Android.bp b/docklib/Android.bp
index 8fd67858..1630085a 100644
--- a/docklib/Android.bp
+++ b/docklib/Android.bp
@@ -37,7 +37,10 @@ android_library {
 
     resource_dirs: ["res"],
 
-    libs: ["android.car"],
+    libs: [
+        "android.car",
+        "token-shared-lib-prebuilt",
+    ],
 
     static_libs: [
         "androidx.recyclerview_recyclerview",
@@ -49,12 +52,14 @@ android_library {
         "CarLauncherCommon",
         "SystemUISharedLib",
         "//frameworks/libs/systemui:iconloader",
-        "car-resource-common",
         "dock_item",
         "car_launcher_flags_java_lib",
         "car-media-common-no-overlayable",
+        "oem-token-lib",
     ],
 
+    enforce_uses_libs: false,
+
     platform_apis: true,
 
     manifest: "AndroidManifest.xml",
diff --git a/docklib/res/color/icon_default_color.xml b/docklib/res/color/icon_default_color.xml
new file mode 100644
index 00000000..8549442d
--- /dev/null
+++ b/docklib/res/color/icon_default_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorOnBackground"/>
+</selector>
diff --git a/docklib/res/color/icon_excited_stroke_color.xml b/docklib/res/color/icon_excited_stroke_color.xml
new file mode 100644
index 00000000..c5424123
--- /dev/null
+++ b/docklib/res/color/icon_excited_stroke_color.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:alpha="1.0"
+        android:color="?oemColorSurfaceContainer" />
+</selector>
diff --git a/docklib/res/color/icon_restricted_stroke_color.xml b/docklib/res/color/icon_restricted_stroke_color.xml
new file mode 100644
index 00000000..63310c1e
--- /dev/null
+++ b/docklib/res/color/icon_restricted_stroke_color.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item
+        android:alpha="0.27"
+        android:color="?oemColorOnSecondary"/>
+</selector>
diff --git a/docklib/res/color/icon_static_stroke_color.xml b/docklib/res/color/icon_static_stroke_color.xml
new file mode 100644
index 00000000..6502cdae
--- /dev/null
+++ b/docklib/res/color/icon_static_stroke_color.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
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
+<selector xmlns:android="http://schemas.android.com/apk/res/android">
+    <item android:color="?oemColorBackground"/>
+</selector>
diff --git a/docklib/res/values/colors.xml b/docklib/res/values/colors.xml
deleted file mode 100644
index ea791c6f..00000000
--- a/docklib/res/values/colors.xml
+++ /dev/null
@@ -1,22 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2023 The Android Open Source Project
-
-Licensed under the Apache License, Version 2.0 (the "License");
-you may not use this file except in compliance with the License.
-You may obtain a copy of the License at
-
-  http://www.apache.org/licenses/LICENSE-2.0
-
-Unless required by applicable law or agreed to in writing, software
-distributed under the License is distributed on an "AS IS" BASIS,
-WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-See the License for the specific language governing permissions and
-limitations under the License.
--->
-<resources>
-    <!-- todo(b/314859977): reset color to #000000 -->
-    <color name="icon_default_color">#FFFFFF</color>
-    <color name="icon_static_stroke_color">#000000</color>
-    <color name="icon_excited_stroke_color">@*android:color/car_grey_900</color>
-    <color name="icon_restricted_stroke_color">#69696952</color>
-</resources>
diff --git a/docklib/src/com/android/car/docklib/DockViewController.kt b/docklib/src/com/android/car/docklib/DockViewController.kt
index 3c70e80f..fde544e4 100644
--- a/docklib/src/com/android/car/docklib/DockViewController.kt
+++ b/docklib/src/com/android/car/docklib/DockViewController.kt
@@ -60,7 +60,7 @@ import java.util.UUID
  */
 open class DockViewController(
         dockView: DockView,
-        private val userContext: Context = dockView.context,
+        val userContext: Context = dockView.context,
         dataFile: File,
 ) : DockInterface {
     companion object {
diff --git a/docklib/src/com/android/car/docklib/DockViewModel.kt b/docklib/src/com/android/car/docklib/DockViewModel.kt
index c169c181..080049bb 100644
--- a/docklib/src/com/android/car/docklib/DockViewModel.kt
+++ b/docklib/src/com/android/car/docklib/DockViewModel.kt
@@ -69,10 +69,9 @@ open class DockViewModel(
     }
 
     private val noSpotAvailableToPinToastMsg = context.getString(R.string.pin_failed_no_spots)
-    private val colorExtractor = ColorExtractor()
     private val defaultIconColor = context.resources.getColor(
             R.color.icon_default_color,
-            null // theme
+            context.theme // theme
     )
     private val currentItems = MutableLiveData<List<DockAppItem>>()
     private val mediaServiceComponents = MediaUtils.fetchMediaServiceComponents(packageManager)
@@ -444,7 +443,7 @@ open class DockViewModel(
         return getIconColor(ai.loadIcon(packageManager))
     }
 
-    private fun getIconColor(icon: Drawable) = colorExtractor.findDominantColorByHue(
+    private fun getIconColor(icon: Drawable) = ColorExtractor.findDominantColorByHue(
             iconFactory.createScaledBitmap(icon, BaseIconFactory.MODE_DEFAULT)
     )
 
diff --git a/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt b/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt
index a718265e..c1023fd9 100644
--- a/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt
+++ b/docklib/src/com/android/car/docklib/view/DockItemViewHolder.kt
@@ -67,7 +67,7 @@ class DockItemViewHolder(
             .getDimension(R.dimen.icon_stroke_width_static)
     private val defaultIconColor = itemView.resources.getColor(
             R.color.icon_default_color,
-            null // theme
+            userContext.theme
     )
     private val appIcon: ShapeableImageView = itemView.requireViewById(R.id.dock_app_icon)
     private val iconColorExecutor = Executors.newSingleThreadExecutor()
@@ -95,15 +95,15 @@ class DockItemViewHolder(
                 .getDimension(R.dimen.icon_stroke_width_excited),
             staticIconStrokeColor = itemView.resources.getColor(
                 R.color.icon_static_stroke_color,
-                null // theme
+                userContext.theme
             ),
             excitedIconStrokeColor = itemView.resources.getColor(
                 R.color.icon_excited_stroke_color,
-                null // theme
+                userContext.theme
             ),
             restrictedIconStrokeColor = itemView.resources.getColor(
                 R.color.icon_restricted_stroke_color,
-                null // theme
+                userContext.theme
             ),
             defaultIconColor,
             excitedColorFilter = PorterDuffColorFilter(
diff --git a/docklib/tests/Android.bp b/docklib/tests/Android.bp
index 49b22724..b956b84c 100644
--- a/docklib/tests/Android.bp
+++ b/docklib/tests/Android.bp
@@ -30,8 +30,11 @@ android_test {
     libs: [
         "android.car",
         "android.test.base.stubs.system",
+        "token-shared-lib-prebuilt",
     ],
 
+    enforce_uses_libs: false,
+
     optimize: {
         enabled: false,
     },
diff --git a/docklib/tests/AndroidManifest.xml b/docklib/tests/AndroidManifest.xml
index d768497c..2caafbf4 100644
--- a/docklib/tests/AndroidManifest.xml
+++ b/docklib/tests/AndroidManifest.xml
@@ -29,6 +29,7 @@
 
     <application android:debuggable="true">
         <uses-library android:name="android.test.runner"/>
+        <uses-library android:name="com.android.oem.tokens" android:required="false"/>
     </application>
 
     <instrumentation
diff --git a/docklib/tests/src/com/android/car/docklib/events/DockEventsReceiverTest.java b/docklib/tests/src/com/android/car/docklib/events/DockEventsReceiverTest.java
index 0a9bd837..f2a7394d 100644
--- a/docklib/tests/src/com/android/car/docklib/events/DockEventsReceiverTest.java
+++ b/docklib/tests/src/com/android/car/docklib/events/DockEventsReceiverTest.java
@@ -22,16 +22,18 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
 
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
+import android.content.res.Resources;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.car.docklib.DockInterface;
+import com.android.car.dockutil.R;
 import com.android.car.dockutil.events.DockEvent;
 
 import org.junit.Before;
@@ -48,6 +50,8 @@ public class DockEventsReceiverTest {
     public Intent mIntent;
     @Mock
     public DockInterface mDockInterface;
+    @Mock
+    public Resources mResources;
 
     private DockEventsReceiver mDockEventsReceiver;
 
@@ -55,6 +59,8 @@ public class DockEventsReceiverTest {
     public void setup() {
         MockitoAnnotations.initMocks(this);
         mDockEventsReceiver = new DockEventsReceiver(mDockInterface);
+        when(mContext.getResources()).thenReturn(mResources);
+        when(mResources.getIntArray(R.array.dock_supported_displays)).thenReturn(new int[] {0});
     }
 
     @Test
@@ -63,7 +69,7 @@ public class DockEventsReceiverTest {
 
         mDockEventsReceiver.onReceive(mContext, mIntent);
 
-        verifyZeroInteractions(mDockInterface);
+        verifyNoMoreInteractions(mDockInterface);
     }
 
     @Test
@@ -74,7 +80,7 @@ public class DockEventsReceiverTest {
 
         mDockEventsReceiver.onReceive(mContext, mIntent);
 
-        verifyZeroInteractions(mDockInterface);
+        verifyNoMoreInteractions(mDockInterface);
     }
 
     @Test
@@ -85,7 +91,7 @@ public class DockEventsReceiverTest {
 
         mDockEventsReceiver.onReceive(mContext, mIntent);
 
-        verifyZeroInteractions(mDockInterface);
+        verifyNoMoreInteractions(mDockInterface);
     }
 
     @Test
diff --git a/libs/appgrid/OWNERS b/libs/appgrid/OWNERS
index c4871a70..ff57a20a 100644
--- a/libs/appgrid/OWNERS
+++ b/libs/appgrid/OWNERS
@@ -4,6 +4,5 @@
 ankiit@google.com
 alexstetson@google.com
 danzz@google.com
-nehah@google.com
 stenning@google.com
 alanschen@google.com
diff --git a/libs/appgrid/lib/res/values-af/strings.xml b/libs/appgrid/lib/res/values-af/strings.xml
index e4a4ed35..663e1459 100644
--- a/libs/appgrid/lib/res/values-af/strings.xml
+++ b/libs/appgrid/lib/res/values-af/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"App kan nie gestop word nie."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Versteek ontfoutingapps"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Wys ontfoutingapps"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"voorneme:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Stem in tot gebruikerdiensbepalings om apps te gebruik wat deur gebruikerdiensbepalings gedeaktiveer is"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Hersien"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Nie nou nie"</string>
diff --git a/libs/appgrid/lib/res/values-am/strings.xml b/libs/appgrid/lib/res/values-am/strings.xml
index 694a108c..4a2f7815 100644
--- a/libs/appgrid/lib/res/values-am/strings.xml
+++ b/libs/appgrid/lib/res/values-am/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"መተግበሪያው ሊቆም አይችልም።"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"የስህተት ማረሚያ መተግበሪያዎችን ደብቅ"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"የስህተት ማረሚያ መተግበሪያዎችን አሳይ"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"በተጠቃሚ የአገልግሎት ውል የተሰናከሉ መተግበሪያዎችን ለመጠቀም በተጠቃሚ የአገልግሎት ውሉ ይስማሙ"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ግምገማ"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"አሁን አይደለም"</string>
diff --git a/libs/appgrid/lib/res/values-ar/strings.xml b/libs/appgrid/lib/res/values-ar/strings.xml
index a93f352f..7449ab80 100644
--- a/libs/appgrid/lib/res/values-ar/strings.xml
+++ b/libs/appgrid/lib/res/values-ar/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"يتعذّر إيقاف التطبيق."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"إخفاء تطبيقات تصحيح الأخطاء"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"إظهار تطبيقات تصحيح الأخطاء"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"لاستخدام التطبيقات غير المفعَّلة بواسطة بنود خدمة المستخدم، يجب الموافقة على البنود"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"المراجعة"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"لاحقًا"</string>
diff --git a/libs/appgrid/lib/res/values-as/strings.xml b/libs/appgrid/lib/res/values-as/strings.xml
index a51fe0f3..9d49bcdf 100644
--- a/libs/appgrid/lib/res/values-as/strings.xml
+++ b/libs/appgrid/lib/res/values-as/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"এপ্‌ বন্ধ কৰিব নোৱাৰি।"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ডিবাগ এপ্‌সমূহ লুকুৱাওক"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ডিবাগ এপ্‌সমূহ দেখুৱাওক"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ব্যৱহাৰকাৰীৰ সেৱাৰ চৰ্তাৱলী অক্ষম কৰি থোৱা এপ্‌সমূহ ব্যৱহাৰ কৰিবলৈ, ব্যৱহাৰকাৰীৰ সেৱাৰ চৰ্তাৱলীত সন্মতি দিয়ক"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"পৰ্যালোচনা কৰক"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"এতিয়া নহয়"</string>
diff --git a/libs/appgrid/lib/res/values-az/strings.xml b/libs/appgrid/lib/res/values-az/strings.xml
index fc5918d3..aef1c669 100644
--- a/libs/appgrid/lib/res/values-az/strings.xml
+++ b/libs/appgrid/lib/res/values-az/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Tətbiqi dayandırmaq olmur."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Sazlama tətbiqlərini gizlədin"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Sazlama tətbiqlərini göstərin"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"İstifadəçi xidmət şərtlərinə əsasən deaktiv edilən tətbiqlərdən istifadə etmək üçün İstifadəçi xidmət şərtlərini qəbul edin"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Nəzərdən keçirin"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"İndi yox"</string>
diff --git a/libs/appgrid/lib/res/values-b+sr+Latn/strings.xml b/libs/appgrid/lib/res/values-b+sr+Latn/strings.xml
index 1a36a31d..ca65a625 100644
--- a/libs/appgrid/lib/res/values-b+sr+Latn/strings.xml
+++ b/libs/appgrid/lib/res/values-b+sr+Latn/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikacija ne može da se zaustavi."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Sakrij aplikacije za otklanjanje grešaka"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Prikaži aplikacije za otklanjanje grešaka"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Da biste koristili aplikacije onemogućene u skladu sa uslovima korišćenja usluge za korisnika, prihvatite uslove korišćenja usluge za korisnika."</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Pregledaj"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ne sada"</string>
diff --git a/libs/appgrid/lib/res/values-be/strings.xml b/libs/appgrid/lib/res/values-be/strings.xml
index 7dfb7073..596c55e6 100644
--- a/libs/appgrid/lib/res/values-be/strings.xml
+++ b/libs/appgrid/lib/res/values-be/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Немагчыма спыніць праграму."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Схаваць праграмы адладкі"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Паказаць праграмы адладкі"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Каб выкарыстоўваць выключаныя праграмы з умовамі выкарыстання для карыстальніка, згадзіцеся з імі"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Прагледзець"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Не зараз"</string>
diff --git a/libs/appgrid/lib/res/values-bg/strings.xml b/libs/appgrid/lib/res/values-bg/strings.xml
index 9efac535..2f3feb22 100644
--- a/libs/appgrid/lib/res/values-bg/strings.xml
+++ b/libs/appgrid/lib/res/values-bg/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Приложението не може да бъде спряно."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Скриване на приложенията за отстраняване на грешки"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Показване на приложенията за отстраняв. на грешки"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"За да използвате деактивираните от ОУ за потребителите приложения, приемете Общите условия за потребителите"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Преглед"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Не сега"</string>
diff --git a/libs/appgrid/lib/res/values-bn/strings.xml b/libs/appgrid/lib/res/values-bn/strings.xml
index a3fe8dfe..64d32fe1 100644
--- a/libs/appgrid/lib/res/values-bn/strings.xml
+++ b/libs/appgrid/lib/res/values-bn/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"অ্যাপ বন্ধ করা যাচ্ছে না।"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ডিবাগ অ্যাপ লুকান"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ডিবাগ অ্যাপ দেখুন"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"পরিষেবার শর্তাবলীর মাধ্যমে বন্ধ করে দেওয়া অ্যাপগুলি ব্যবহার করতে, ব্যবহারকারীর পরিষেবার শর্তাবলীতে সম্মতি দিন"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"পর্যালোচনা করুন"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"এখন নয়"</string>
diff --git a/libs/appgrid/lib/res/values-bs/strings.xml b/libs/appgrid/lib/res/values-bs/strings.xml
index 09d27534..6e047876 100644
--- a/libs/appgrid/lib/res/values-bs/strings.xml
+++ b/libs/appgrid/lib/res/values-bs/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Nije moguće zaustaviti aplikaciju."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Sakrij aplikacije za otklanjanje grešaka"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Prikaži aplikacije za otklanjanje grešaka"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Da koristite aplikacije onemogućene prema Uslovima korištenja usluge za korisnike, prihvatite Uslove korištenja usluge za korisnike"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Pregledajte"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ne sada"</string>
diff --git a/libs/appgrid/lib/res/values-ca/strings.xml b/libs/appgrid/lib/res/values-ca/strings.xml
index 53d48a08..ff8f505b 100644
--- a/libs/appgrid/lib/res/values-ca/strings.xml
+++ b/libs/appgrid/lib/res/values-ca/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"L\'aplicació no es pot aturar."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Amaga les aplicacions de depuració"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostra les aplicacions de depuració"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Per utilitzar les aplicacions desactivades per les condicions del servei d\'usuari, accepta aquestes condicions"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Revisa"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ara no"</string>
diff --git a/libs/appgrid/lib/res/values-cs/strings.xml b/libs/appgrid/lib/res/values-cs/strings.xml
index 0c6d1341..f7efaa89 100644
--- a/libs/appgrid/lib/res/values-cs/strings.xml
+++ b/libs/appgrid/lib/res/values-cs/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikaci nelze ukončit."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Skrýt ladicí aplikace"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Zobrazit ladicí aplikace"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Pokud chcete používat aplikace deaktivované na základě smluvních podmínek pro uživatele, vyjádřete souhlas se smluvními podmínkami pro uživatele"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Kontrola"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Teď ne"</string>
diff --git a/libs/appgrid/lib/res/values-da/strings.xml b/libs/appgrid/lib/res/values-da/strings.xml
index 39b61d7b..6ae6fe3e 100644
--- a/libs/appgrid/lib/res/values-da/strings.xml
+++ b/libs/appgrid/lib/res/values-da/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Appen kan ikke standses."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Skjul apps til fejlretning"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Vis apps til fejlretning"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Hvis du vil bruge apps, der er deaktiveret i henhold til servicevilkår for brugere, skal du acceptere servicevilkårene for brugere"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Gennemgå"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ikke nu"</string>
diff --git a/libs/appgrid/lib/res/values-de/strings.xml b/libs/appgrid/lib/res/values-de/strings.xml
index 7817c119..bbec6e89 100644
--- a/libs/appgrid/lib/res/values-de/strings.xml
+++ b/libs/appgrid/lib/res/values-de/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Die App kann nicht beendet werden."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Debug-Apps verbergen"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Debug-Apps anzeigen"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Wenn du die deaktivierten Apps verwenden möchtest, musst du den Nutzungsbedingungen zustimmen"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Lesen"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Jetzt nicht"</string>
diff --git a/libs/appgrid/lib/res/values-el/strings.xml b/libs/appgrid/lib/res/values-el/strings.xml
index 4a989392..843b461c 100644
--- a/libs/appgrid/lib/res/values-el/strings.xml
+++ b/libs/appgrid/lib/res/values-el/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Δεν είναι δυνατή η διακοπή της εφαρμογής."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Απόκρυψη εφαρμογών εντοπισμού σφαλμάτων"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Εμφάνιση εφαρμογών εντοπισμού σφαλμάτων"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Για να χρησιμοποιήσετε εφαρμογές που έχουν απενεργοποιηθεί σύμφωνα με τους Όρους Παροχής Υπηρεσιών χρήστη, αποδεχτείτε τους Όρους Παροχής Υπηρεσιών χρήστη"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Έλεγχος"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Όχι τώρα"</string>
diff --git a/libs/appgrid/lib/res/values-en-rAU/strings.xml b/libs/appgrid/lib/res/values-en-rAU/strings.xml
index 06e44c58..b9e392b3 100644
--- a/libs/appgrid/lib/res/values-en-rAU/strings.xml
+++ b/libs/appgrid/lib/res/values-en-rAU/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"App can\'t be stopped."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Hide debug apps"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Show debug apps"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"To use user tos disabled apps, agree to User tos"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Review"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Not now"</string>
diff --git a/libs/appgrid/lib/res/values-en-rCA/strings.xml b/libs/appgrid/lib/res/values-en-rCA/strings.xml
index 09c85fd9..0a093735 100644
--- a/libs/appgrid/lib/res/values-en-rCA/strings.xml
+++ b/libs/appgrid/lib/res/values-en-rCA/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"App can’t be stopped."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Hide debug apps"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Show debug apps"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"To use user tos disabled apps, agree to User tos"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Review"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Not Now"</string>
diff --git a/libs/appgrid/lib/res/values-en-rGB/strings.xml b/libs/appgrid/lib/res/values-en-rGB/strings.xml
index 06e44c58..b9e392b3 100644
--- a/libs/appgrid/lib/res/values-en-rGB/strings.xml
+++ b/libs/appgrid/lib/res/values-en-rGB/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"App can\'t be stopped."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Hide debug apps"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Show debug apps"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"To use user tos disabled apps, agree to User tos"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Review"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Not now"</string>
diff --git a/libs/appgrid/lib/res/values-en-rIN/strings.xml b/libs/appgrid/lib/res/values-en-rIN/strings.xml
index 06e44c58..b9e392b3 100644
--- a/libs/appgrid/lib/res/values-en-rIN/strings.xml
+++ b/libs/appgrid/lib/res/values-en-rIN/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"App can\'t be stopped."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Hide debug apps"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Show debug apps"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"To use user tos disabled apps, agree to User tos"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Review"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Not now"</string>
diff --git a/libs/appgrid/lib/res/values-es-rUS/strings.xml b/libs/appgrid/lib/res/values-es-rUS/strings.xml
index bf1fdbcd..3dd533a5 100644
--- a/libs/appgrid/lib/res/values-es-rUS/strings.xml
+++ b/libs/appgrid/lib/res/values-es-rUS/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"No se puede detener la app."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ocultar apps de depuración"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostrar apps de depuración"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Para usar las apps inhabilitadas, acepta las Condiciones del Servicio del Usuario"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Revisar"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ahora no"</string>
diff --git a/libs/appgrid/lib/res/values-es/strings.xml b/libs/appgrid/lib/res/values-es/strings.xml
index 63cbadf9..53198f1b 100644
--- a/libs/appgrid/lib/res/values-es/strings.xml
+++ b/libs/appgrid/lib/res/values-es/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"La aplicación no se puede detener."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ocultar aplicaciones de depuración"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostrar aplicaciones de depuración"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Para usar las aplicaciones inhabilitadas por los términos del servicio del usuario, acepta estos términos"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Revisar"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ahora no"</string>
diff --git a/libs/appgrid/lib/res/values-et/strings.xml b/libs/appgrid/lib/res/values-et/strings.xml
index dfb991f2..ba8c2ad4 100644
--- a/libs/appgrid/lib/res/values-et/strings.xml
+++ b/libs/appgrid/lib/res/values-et/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Rakendust ei saa peatada."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Peida silumisrakendused"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Kuva silumisrakendused"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Kasutajatingimuste tõttu keelatud rakenduste kasutamiseks nõustuge kasutajatingimustega"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Vaadake üle"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Mitte praegu"</string>
diff --git a/libs/appgrid/lib/res/values-eu/strings.xml b/libs/appgrid/lib/res/values-eu/strings.xml
index 8100fe59..11d7e727 100644
--- a/libs/appgrid/lib/res/values-eu/strings.xml
+++ b/libs/appgrid/lib/res/values-eu/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Ezin da gelditu aplikazioa."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ezkutatu arazteko aplikazioak"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Erakutsi arazteko aplikazioak"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Erabiltzaileentzako zerbitzu-baldintzak desgaituta dauzkaten aplikazioak erabiltzeko, onartu erabiltzaileentzako zerbitzu-baldintzak"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Berrikusi"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Orain ez"</string>
diff --git a/libs/appgrid/lib/res/values-fa/strings.xml b/libs/appgrid/lib/res/values-fa/strings.xml
index 1750368d..90e68f05 100644
--- a/libs/appgrid/lib/res/values-fa/strings.xml
+++ b/libs/appgrid/lib/res/values-fa/strings.xml
@@ -20,11 +20,10 @@
     <string name="reset_appgrid_title" msgid="6491348358859198288">"بازنشانی جدول برنامه‌ها به ترتیب حروف الفبا"</string>
     <string name="reset_appgrid_dialogue_message" msgid="2278301828239327586">"این عملکرد همه ترتیب‌های سفارشی را حذف خواهد کرد. می‌خواهید ادامه دهید؟"</string>
     <string name="app_launcher_title_all_apps" msgid="3522783138519460233">"همه برنامه‌ها"</string>
-    <string name="app_launcher_title_media_only" msgid="7194631822174015710">"برنامه‌های رسانه"</string>
+    <string name="app_launcher_title_media_only" msgid="7194631822174015710">"برنامه‌های رسانه‌ای"</string>
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"برنامه متوقف نمی‌شود."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"پنهان کردن برنامه‌های اشکال‌زدایی"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"نمایش برنامه‌های اشکال‌زدایی"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"برای استفاده از برنامه‌هایی که به‌دلیل شرایط خدمات کاربر غیرفعال شده‌اند، با «شرایط خدمات کاربر» موافقت کنید"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"مرور کردن"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"حالا نه"</string>
diff --git a/libs/appgrid/lib/res/values-fi/strings.xml b/libs/appgrid/lib/res/values-fi/strings.xml
index e56ac63d..4c205a39 100644
--- a/libs/appgrid/lib/res/values-fi/strings.xml
+++ b/libs/appgrid/lib/res/values-fi/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Sovellusta ei voi keskeyttää."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Piilota virheenkorjaussovellukset"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Näytä virheenkorjaussovellukset"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Jos haluat käyttää käyttäjien käyttöehtojen estämiä sovelluksia, hyväksy käyttäjien käyttöehdot"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Tarkistus"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ei nyt"</string>
diff --git a/libs/appgrid/lib/res/values-fr-rCA/strings.xml b/libs/appgrid/lib/res/values-fr-rCA/strings.xml
index 49d83e5e..685b2208 100644
--- a/libs/appgrid/lib/res/values-fr-rCA/strings.xml
+++ b/libs/appgrid/lib/res/values-fr-rCA/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Impossible d\'arrêter l\'application."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Masquer les applications de débogage"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Afficher les applications de débogage"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Pour utiliser les applications désactivées, acceptez les conditions d\'utilisation de l\'utilisateur"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Avis"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Pas maintenant"</string>
diff --git a/libs/appgrid/lib/res/values-fr/strings.xml b/libs/appgrid/lib/res/values-fr/strings.xml
index a24af5a9..42b0d4d0 100644
--- a/libs/appgrid/lib/res/values-fr/strings.xml
+++ b/libs/appgrid/lib/res/values-fr/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Impossible d\'arrêter l\'appli."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Masquer les applis de débogage"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Afficher les applis de débogage"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Pour utiliser les applis dont les conditions d\'utilisation pour les utilisateurs sont désactivées, acceptez les conditions d\'utilisation pour les utilisateurs"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Examen"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Pas maintenant"</string>
diff --git a/libs/appgrid/lib/res/values-gl/strings.xml b/libs/appgrid/lib/res/values-gl/strings.xml
index a9a821a5..6920efa1 100644
--- a/libs/appgrid/lib/res/values-gl/strings.xml
+++ b/libs/appgrid/lib/res/values-gl/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Non se pode deter a aplicación."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ocultar aplicacións de depuración"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostrar aplicacións de depuración"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Para poder usar as aplicacións desactivadas debido ás Condicións de servizo do usuario, acepta esas condicións"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Revisar"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Agora non"</string>
diff --git a/libs/appgrid/lib/res/values-gu/strings.xml b/libs/appgrid/lib/res/values-gu/strings.xml
index 893e20b6..d0dfb63b 100644
--- a/libs/appgrid/lib/res/values-gu/strings.xml
+++ b/libs/appgrid/lib/res/values-gu/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ઍપ બંધ કરી શકાતી નથી."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ડિબગ ઍપ છુપાવો"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ડિબગ ઍપ બતાવો"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"વપરાશકર્તા માટેની TOS હેઠળ બંધ કરેલી હોય એવી ઍપનો ઉપયોગ કરવા માટે, વપરાશકર્તા માટેની TOSથી સંમત થાઓ"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"રિવ્યૂ કરો"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"હમણાં નહીં"</string>
diff --git a/libs/appgrid/lib/res/values-hi/strings.xml b/libs/appgrid/lib/res/values-hi/strings.xml
index 7cfe1dc9..31880e61 100644
--- a/libs/appgrid/lib/res/values-hi/strings.xml
+++ b/libs/appgrid/lib/res/values-hi/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ऐप्लिकेशन को बंद नहीं किया जा सका."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"डीबग किए गए ऐप्लिकेशन छिपाएं"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"डीबग किए गए ऐप्लिकेशन दिखाएं"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"उपयोगकर्ता की सेवा की शर्तों के तहत बंद किए गए ऐप्लिकेशन को इस्तेमाल करने के लिए, उन शर्तों के लिए सहमति दें"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"समीक्षा करें"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"अभी नहीं"</string>
diff --git a/libs/appgrid/lib/res/values-hr/strings.xml b/libs/appgrid/lib/res/values-hr/strings.xml
index d040c326..d41fc1a5 100644
--- a/libs/appgrid/lib/res/values-hr/strings.xml
+++ b/libs/appgrid/lib/res/values-hr/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikacija se ne može zaustaviti."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Sakrij aplikacije za otklanjanje pogrešaka"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Prikaži aplikacije za otklanjanje pogrešaka"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Da biste koristili aplikacije koje su onemogućene TOS-om za korisnike, prihvatite TOS za korisnike"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Pregled"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ne sad"</string>
diff --git a/libs/appgrid/lib/res/values-hu/strings.xml b/libs/appgrid/lib/res/values-hu/strings.xml
index e048db7c..724a2264 100644
--- a/libs/appgrid/lib/res/values-hu/strings.xml
+++ b/libs/appgrid/lib/res/values-hu/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Az alkalmazás nem állítható le."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Hibakereső alkalmazások elrejtése"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Hibakereső alkalmazások megjelenítése"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"A felhasználói ÁSZF alapján letiltott alkalmazások használatához fogadja el a felhasználói ÁSZF-et"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Ellenőrzés"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ne most"</string>
diff --git a/libs/appgrid/lib/res/values-hy/strings.xml b/libs/appgrid/lib/res/values-hy/strings.xml
index d7b1fbf6..447730d7 100644
--- a/libs/appgrid/lib/res/values-hy/strings.xml
+++ b/libs/appgrid/lib/res/values-hy/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Չհաջողվեց կանգնեցնել հավելվածի աշխատանքը։"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Թաքցնել վրիպազերծման հավելվածները"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Ցույց տալ վրիպազերծման հավելվածները"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ընդունեք օգտատիրոջ օգտագործման պայմանները, որպեսզի կարողանաք օգտվել այն հավելվածներից, որոնք անջատվել են այդ պայմանների համաձայն"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Դիտել"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ոչ հիմա"</string>
diff --git a/libs/appgrid/lib/res/values-in/strings.xml b/libs/appgrid/lib/res/values-in/strings.xml
index 0c753920..bdec9f74 100644
--- a/libs/appgrid/lib/res/values-in/strings.xml
+++ b/libs/appgrid/lib/res/values-in/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikasi tidak dapat dihentikan."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Sembunyikan aplikasi debug"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Tampilkan aplikasi debug"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Untuk menggunakan aplikasi yang dinonaktifkan karena TOS pengguna, setujui TOS Pengguna"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Tinjau"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Lain Kali"</string>
diff --git a/libs/appgrid/lib/res/values-is/strings.xml b/libs/appgrid/lib/res/values-is/strings.xml
index 037666ac..b2344a73 100644
--- a/libs/appgrid/lib/res/values-is/strings.xml
+++ b/libs/appgrid/lib/res/values-is/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Ekki er hægt að stöðva forrit."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Fela villuleitarforrit"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Sýna villuleitarforrit"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Til að nota forrit sem þjónustuskilmálar notenda hafa gert óvirk skaltu samþykkja þjónustuskilmála notenda"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Yfirfara"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ekki núna"</string>
diff --git a/libs/appgrid/lib/res/values-it/strings.xml b/libs/appgrid/lib/res/values-it/strings.xml
index f7be1fa5..d42dc877 100644
--- a/libs/appgrid/lib/res/values-it/strings.xml
+++ b/libs/appgrid/lib/res/values-it/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Impossibile interrompere l\'app."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Nascondi app di debug"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostra app di debug"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Per usare le app disattivate in relazione ai TdS per l\'utente, acconsenti ai TdS per l\'utente"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Controlla"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Non ora"</string>
diff --git a/libs/appgrid/lib/res/values-iw/strings.xml b/libs/appgrid/lib/res/values-iw/strings.xml
index ecd18056..3c53b18f 100644
--- a/libs/appgrid/lib/res/values-iw/strings.xml
+++ b/libs/appgrid/lib/res/values-iw/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"לא ניתן לעצור את פעולת האפליקציה."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"הסתרת אפליקציות לניפוי באגים"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"הצגת אפליקציות לניפוי באגים"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"כדי להשתמש באפליקציות המושבתות לפי התנאים וההגבלות של המשתמש, יש לאשר את התנאים וההגבלות"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"בדיקה"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"לא עכשיו"</string>
diff --git a/libs/appgrid/lib/res/values-ja/strings.xml b/libs/appgrid/lib/res/values-ja/strings.xml
index c34b3014..39ed9554 100644
--- a/libs/appgrid/lib/res/values-ja/strings.xml
+++ b/libs/appgrid/lib/res/values-ja/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"アプリを停止できません。"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"デバッグアプリを表示しない"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"デバッグアプリを表示する"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ユーザー利用規約が無効なアプリを使用するには、ユーザー利用規約に同意してください"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"確認"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"スキップ"</string>
diff --git a/libs/appgrid/lib/res/values-ka/strings.xml b/libs/appgrid/lib/res/values-ka/strings.xml
index 6114bb84..0fdfc147 100644
--- a/libs/appgrid/lib/res/values-ka/strings.xml
+++ b/libs/appgrid/lib/res/values-ka/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"აპის შეჩერება შეუძლებელია."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"გამართვის აპების დამალვა"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"გამართვის აპების ჩვენება"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"მომსახურების პირობების გამო გათიშული აპების გამოსაყენებლად დაეთანხმეთ მომსახურების პირობებს"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"მიმოხილვა"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ახლა არა"</string>
diff --git a/libs/appgrid/lib/res/values-kk/strings.xml b/libs/appgrid/lib/res/values-kk/strings.xml
index 35616a01..e7536ec3 100644
--- a/libs/appgrid/lib/res/values-kk/strings.xml
+++ b/libs/appgrid/lib/res/values-kk/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Қолданба жұмысын тоқтату мүмкін емес."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Түзету қолданбаларын жасыру"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Түзету қолданбаларын көрсету"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Қызмет көрсету шарттарына байланысты өшірілген қолданбаларды пайдалану үшін Қызмет көрсету шарттарына келісіңіз."</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Тексеру"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Қазір емес"</string>
diff --git a/libs/appgrid/lib/res/values-km/strings.xml b/libs/appgrid/lib/res/values-km/strings.xml
index 65991422..0330a5ce 100644
--- a/libs/appgrid/lib/res/values-km/strings.xml
+++ b/libs/appgrid/lib/res/values-km/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"មិនអាច​បញ្ឈប់កម្មវិធី​បានទេ។"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"លាក់កម្មវិធីជួសជុល"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"បង្ហាញកម្មវិធីជួសជុល"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ដើម្បីប្រើកម្មវិធី​ដែលបានបិទដោយ​លក្ខខណ្ឌប្រើប្រាស់​សម្រាប់អ្នកប្រើប្រាស់ សូមយល់ព្រមតាម​លក្ខខណ្ឌប្រើប្រាស់​សម្រាប់អ្នកប្រើប្រាស់"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ពិនិត្យមើល"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"កុំទាន់"</string>
diff --git a/libs/appgrid/lib/res/values-kn/strings.xml b/libs/appgrid/lib/res/values-kn/strings.xml
index 5b0c65fc..401ec11c 100644
--- a/libs/appgrid/lib/res/values-kn/strings.xml
+++ b/libs/appgrid/lib/res/values-kn/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ಆ್ಯಪ್ ನಿಲ್ಲಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ಡೀಬಗ್ ಆ್ಯಪ್‌ಗಳನ್ನು ಮರೆಮಾಡಿ"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ಡೀಬಗ್ ಆ್ಯಪ್‌ಗಳನ್ನು ತೋರಿಸಿ"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ಬಳಕೆದಾರರ ಸೇವಾ ನಿಯಮಗಳು ನಿಷ್ಕ್ರಿಯಗೊಳಿಸಿದ ಆ್ಯಪ್‌ಗಳನ್ನು ಬಳಸಲು, ಬಳಕೆದಾರರ ಸೇವಾ ನಿಯಮಗಳಿಗೆ ಸಮ್ಮತಿಸಿ"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ಪರಿಶೀಲಿಸಿ"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ಈಗ ಬೇಡ"</string>
diff --git a/libs/appgrid/lib/res/values-ko/strings.xml b/libs/appgrid/lib/res/values-ko/strings.xml
index 846e8f24..d20f5f43 100644
--- a/libs/appgrid/lib/res/values-ko/strings.xml
+++ b/libs/appgrid/lib/res/values-ko/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"앱을 닫을 수 없습니다."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"디버그 앱 숨기기"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"디버그 앱 표시"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=true;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"사용자 서비스 약관으로 인해 중지된 앱을 사용하려면 사용자 서비스 약관에 동의하세요"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"검토"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"나중에"</string>
diff --git a/libs/appgrid/lib/res/values-ky/strings.xml b/libs/appgrid/lib/res/values-ky/strings.xml
index 37b02b09..2e428caa 100644
--- a/libs/appgrid/lib/res/values-ky/strings.xml
+++ b/libs/appgrid/lib/res/values-ky/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Колдонмону токтотууга болбойт."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Мүчүлүштүктөрдү оңдоочу колдонмолорду жашыруу"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Мүчүлүштүктөрдү оңдоочу колдонмолорду көрсөтүү"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Колдонуучунун пайдалануу шарттарын кабыл албасаңыз, айрым колдонмолорду пайдалана албайсыз"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Карап чыгуу"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Азыр эмес"</string>
diff --git a/libs/appgrid/lib/res/values-lo/strings.xml b/libs/appgrid/lib/res/values-lo/strings.xml
index fe98eae4..27b7db8d 100644
--- a/libs/appgrid/lib/res/values-lo/strings.xml
+++ b/libs/appgrid/lib/res/values-lo/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ບໍ່ສາມາດຢຸດແອັບໄດ້."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ເຊື່ອງແອັບດີບັກ"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ສະແດງແອັບດີບັກ"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ເພື່ອໃຊ້ແອັບທີ່ປິດການນຳໃຊ້ໂດຍຂໍ້ກຳນົດບໍລິການຂອງຜູ້ໃຊ້, ໃຫ້ຍອມຮັບຂໍ້ກຳນົດບໍລິການຂອງຜູ້ໃຊ້"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ກວດສອບ"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ບໍ່ຟ້າວເທື່ອ"</string>
diff --git a/libs/appgrid/lib/res/values-lt/strings.xml b/libs/appgrid/lib/res/values-lt/strings.xml
index 12ddee82..e29fbdbf 100644
--- a/libs/appgrid/lib/res/values-lt/strings.xml
+++ b/libs/appgrid/lib/res/values-lt/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Programos negalima sustabdyti."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Slėpti derinimo programas"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Rodyti derinimo programas"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Jei norite naudoti programas, kuriose išjungtos PTS, sutikite su naudotojo PTS"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Peržiūrėti"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ne dabar"</string>
diff --git a/libs/appgrid/lib/res/values-lv/strings.xml b/libs/appgrid/lib/res/values-lv/strings.xml
index 93fdbdaa..a388a55d 100644
--- a/libs/appgrid/lib/res/values-lv/strings.xml
+++ b/libs/appgrid/lib/res/values-lv/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Lietotnes darbību nevar apturēt."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Slēpt atkļūdošanas lietotnes"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Rādīt atkļūdošanas lietotnes"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Lai varētu izmantot lietotnes, kas ir atspējotas saskaņā ar lietotājiem paredzētajiem pakalpojumu sniegšanas noteikumiem, piekrītiet šiem noteikumiem."</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Pārskatīt"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Vēlāk"</string>
diff --git a/libs/appgrid/lib/res/values-mk/strings.xml b/libs/appgrid/lib/res/values-mk/strings.xml
index dee31cbb..0f72f21b 100644
--- a/libs/appgrid/lib/res/values-mk/strings.xml
+++ b/libs/appgrid/lib/res/values-mk/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Апликацијата не може да се сопре."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Скриј апликации за отстранување грешки"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Прикажи апликации за отстранување грешки"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"За да користите оневозможени апликации со TOS за корисниците, согласете се со TOS за корисниците"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Рецензирајте"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Не сега"</string>
diff --git a/libs/appgrid/lib/res/values-ml/strings.xml b/libs/appgrid/lib/res/values-ml/strings.xml
index e1bfd413..3fe68ce3 100644
--- a/libs/appgrid/lib/res/values-ml/strings.xml
+++ b/libs/appgrid/lib/res/values-ml/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ആപ്പ് നിർത്താനാകില്ല."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ഡീബഗ് ആപ്പുകൾ മറയ്ക്കുക"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ഡീബഗ് ആപ്പുകൾ കാണിക്കുക"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"പ്രവർത്തനരഹിതമാക്കിയ ആപ്പുകൾക്കുള്ള ഉപയോക്തൃ സേവന നിബന്ധനകൾ ഉപയോഗിക്കാൻ, ഉപയോക്തൃ സേവന നിബന്ധനകൾ അംഗീകരിക്കുക"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"അവലോകനം ചെയ്യുക"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ഇപ്പോൾ വേണ്ട"</string>
diff --git a/libs/appgrid/lib/res/values-mn/strings.xml b/libs/appgrid/lib/res/values-mn/strings.xml
index 6fe8f517..cfbff39a 100644
--- a/libs/appgrid/lib/res/values-mn/strings.xml
+++ b/libs/appgrid/lib/res/values-mn/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Аппыг зогсоох боломжгүй."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Дебаг хийх аппуудыг нуух"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Дебаг хийх аппуудыг харуулах"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Хэрэглэгчийн үйлчилгээний нөхцөлөөр (TOS) идэвхгүй болгосон аппуудыг ашиглахын тулд Хэрэглэгчийн үйлчилгээний нөхцөлийг (TOS) зөвшөөрнө үү"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Шалгах"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Одоо биш"</string>
diff --git a/libs/appgrid/lib/res/values-mr/strings.xml b/libs/appgrid/lib/res/values-mr/strings.xml
index f28ff673..fcaa6ba1 100644
--- a/libs/appgrid/lib/res/values-mr/strings.xml
+++ b/libs/appgrid/lib/res/values-mr/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"अ‍ॅप थांबवू शकत नाही."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"डीबग केलेली ॲप्स लपवा"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"डीबग केलेली ॲप्स दाखवा"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"वापरकर्ता ToS बंद केलेली अ‍ॅप्स वापरण्यासाठी, वापरकर्ता ToS ला सहमती द्या"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"पुनरावलोकन करा"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"आता नाही"</string>
diff --git a/libs/appgrid/lib/res/values-ms/strings.xml b/libs/appgrid/lib/res/values-ms/strings.xml
index 606187f0..a32b3fb0 100644
--- a/libs/appgrid/lib/res/values-ms/strings.xml
+++ b/libs/appgrid/lib/res/values-ms/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Apl tidak dapat dihentikan."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Sembunyikan apl nyahpepijat"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Tunjukkan apl nyahpepijat"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=true;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Untuk menggunakan apl dilumpuhkan tos pengguna, sila bersetuju untuk menerima tos Pengguna"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Semak"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Bukan Sekarang"</string>
diff --git a/libs/appgrid/lib/res/values-my/strings.xml b/libs/appgrid/lib/res/values-my/strings.xml
index 98680999..0d615e69 100644
--- a/libs/appgrid/lib/res/values-my/strings.xml
+++ b/libs/appgrid/lib/res/values-my/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"အက်ပ်ကို ရပ်၍မရပါ။"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"အမှားရှာပြင်သည့်အက်ပ်များ ဖျောက်ထားရန်"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"အမှားရှာပြင်သည့်အက်ပ်များ ပြပါ"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"အသုံးပြုသူဆိုင်ရာ ဝန်ဆောင်မှုစည်းမျဉ်းများပိတ်ထားသည့် အက်ပ်များ သုံးရန် ‘အသုံးပြုသူဆိုင်ရာ TOS’ ကို လက်ခံပါ"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"စိစစ်ရန်"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ယခုမလုပ်ပါ"</string>
diff --git a/libs/appgrid/lib/res/values-nb/strings.xml b/libs/appgrid/lib/res/values-nb/strings.xml
index ce3165e6..c55411c2 100644
--- a/libs/appgrid/lib/res/values-nb/strings.xml
+++ b/libs/appgrid/lib/res/values-nb/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Appen kan ikke stoppes."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Skjul feilsøkingsapper"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Vis feilsøkingsapper"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"For å bruke apper som er deaktivert av vilkårene for bruk, må du godta vilkårene for bruk"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Gjennomgå"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ikke nå"</string>
diff --git a/libs/appgrid/lib/res/values-ne/strings.xml b/libs/appgrid/lib/res/values-ne/strings.xml
index 0d2ffb6d..0ef245ea 100644
--- a/libs/appgrid/lib/res/values-ne/strings.xml
+++ b/libs/appgrid/lib/res/values-ne/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"एप बन्द गर्न सकिँदैन।"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"डिबग एपहरू लुकाउनुहोस्"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"डिबग एपहरू देखाउनुहोस्"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"तपाईं प्रयोगकर्ताले सहमति जनाउनु पर्ने सेवाका सर्तहरूका कारण निष्क्रिय पारिएका एपहरू प्रयोग गर्न चाहनुहुन्छ भने प्रयोगकर्ताले सहमति जनाउनु पर्ने सेवाका सर्तहरूमा सहमति जनाउनुहोस्"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"समीक्षा गर्नुहोस्"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"अहिले होइन"</string>
diff --git a/libs/appgrid/lib/res/values-nl/strings.xml b/libs/appgrid/lib/res/values-nl/strings.xml
index f2494413..32c8be7a 100644
--- a/libs/appgrid/lib/res/values-nl/strings.xml
+++ b/libs/appgrid/lib/res/values-nl/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"De app kan niet worden gestopt."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Foutopsporingsapps verbergen"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Foutopsporingsapps tonen"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ga akkoord met de servicevoorwaarden voor gebruikers om apps te gebruiken waarvoor de servicevoorwaarden voor gebruikers zijn uitgezet"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Beoordelen"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Niet nu"</string>
diff --git a/libs/appgrid/lib/res/values-or/strings.xml b/libs/appgrid/lib/res/values-or/strings.xml
index 326df071..735c4d1b 100644
--- a/libs/appgrid/lib/res/values-or/strings.xml
+++ b/libs/appgrid/lib/res/values-or/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ଆପ ବନ୍ଦ କରାଯାଇପାରିବ ନାହିଁ।"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ଡିବଗ ଆପ୍ସ ଲୁଚାନ୍ତୁ"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ଡିବଗ ଆପ୍ସ ଦେଖାନ୍ତୁ"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ୟୁଜର TOS ଅକ୍ଷମ କରାଯାଇଥିବା ଆପ୍ସକୁ ବ୍ୟବହାର କରିବା ପାଇଁ ୟୁଜର TOSରେ ସମ୍ମତ ହୁଅନ୍ତୁ"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ସମୀକ୍ଷା କରନ୍ତୁ"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ବର୍ତ୍ତମାନ ନୁହେଁ"</string>
diff --git a/libs/appgrid/lib/res/values-pa/strings.xml b/libs/appgrid/lib/res/values-pa/strings.xml
index 5eded97d..db6733f8 100644
--- a/libs/appgrid/lib/res/values-pa/strings.xml
+++ b/libs/appgrid/lib/res/values-pa/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ਐਪ ਨੂੰ ਬੰਦ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ।"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ਡੀਬੱਗ ਐਪਾਂ ਲੁਕਾਓ"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ਡੀਬੱਗ ਐਪਾਂ ਦਿਖਾਓ"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"ਵਰਤੋਂਕਾਰ ਦੇ ਸੇਵਾ ਦੇ ਨਿਯਮਾਂ ਅਧੀਨ ਬੰਦ ਕੀਤੀਆਂ ਐਪਾਂ ਨੂੰ ਵਰਤਣ ਲਈ, ਵਰਤੋਂਕਾਰ ਦੇ ਸੇਵਾ ਦੇ ਨਿਯਮਾਂ ਨਾਲ ਸਹਿਮਤ ਹੋਵੋ"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ਸਮੀਖਿਆ"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ਹਾਲੇ ਨਹੀਂ"</string>
diff --git a/libs/appgrid/lib/res/values-pl/strings.xml b/libs/appgrid/lib/res/values-pl/strings.xml
index db032848..75b2a31e 100644
--- a/libs/appgrid/lib/res/values-pl/strings.xml
+++ b/libs/appgrid/lib/res/values-pl/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikacji nie można zatrzymać."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ukryj aplikacje do debugowania"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Pokaż aplikacje do debugowania"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Aby używać aplikacji wyłączonych z powodu warunków korzystania z usługi, zaakceptuj te warunki"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Sprawdź"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Nie teraz"</string>
diff --git a/libs/appgrid/lib/res/values-pt-rPT/strings.xml b/libs/appgrid/lib/res/values-pt-rPT/strings.xml
index db6dadce..eb311eec 100644
--- a/libs/appgrid/lib/res/values-pt-rPT/strings.xml
+++ b/libs/appgrid/lib/res/values-pt-rPT/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Não é possível parar a app."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ocultar apps de depuração"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostrar apps de depuração"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Para usar apps desativadas pelos TdU do Utilizador, aceite os TdU do Utilizador"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Rever"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Agora não"</string>
diff --git a/libs/appgrid/lib/res/values-pt/strings.xml b/libs/appgrid/lib/res/values-pt/strings.xml
index 5cd5927e..2b8b378e 100644
--- a/libs/appgrid/lib/res/values-pt/strings.xml
+++ b/libs/appgrid/lib/res/values-pt/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Não é possível interromper o app."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ocultar apps de depuração"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Mostrar apps de depuração"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Para usar apps desativados pelos Termos de Serviço do usuário, aceite esses termos"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Revisar"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Agora não"</string>
diff --git a/libs/appgrid/lib/res/values-ro/strings.xml b/libs/appgrid/lib/res/values-ro/strings.xml
index c3f2e447..eb3964b4 100644
--- a/libs/appgrid/lib/res/values-ro/strings.xml
+++ b/libs/appgrid/lib/res/values-ro/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplicația nu poate fi oprită."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ascunde aplicațiile de remediere a erorilor"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Afișează aplicațiile de remediere a erorilor"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ca să folosești aplicațiile dezactivate deoarece nu au fost acceptate condițiile pentru utilizatori, acceptă condițiile pentru utilizatori"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Examinează"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Nu acum"</string>
diff --git a/libs/appgrid/lib/res/values-ru/strings.xml b/libs/appgrid/lib/res/values-ru/strings.xml
index 18282f5c..77b01857 100644
--- a/libs/appgrid/lib/res/values-ru/strings.xml
+++ b/libs/appgrid/lib/res/values-ru/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Невозможно остановить приложение."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Скрыть приложения для отладки"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Показать приложения для отладки"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Примите условия использования, чтобы пользоваться отключенными приложениями."</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Проверить"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Не сейчас"</string>
diff --git a/libs/appgrid/lib/res/values-si/strings.xml b/libs/appgrid/lib/res/values-si/strings.xml
index bc281c72..11d6821d 100644
--- a/libs/appgrid/lib/res/values-si/strings.xml
+++ b/libs/appgrid/lib/res/values-si/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"යෙදුම නැවැත්විය නොහැක."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"නිදොස් කිරීමේ යෙදුම් සඟවන්න"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"නිදොස් කිරීමේ යෙදුම් පෙන්වන්න"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"පරිශීලක tos අබලිත යෙදුම් භාවිතය සඳහා, පරිශීලක tos වෙත එකඟ වන්න"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"සමාලෝචනය කරන්න"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"දැන් නොවේ"</string>
diff --git a/libs/appgrid/lib/res/values-sk/strings.xml b/libs/appgrid/lib/res/values-sk/strings.xml
index 4c03800f..8db5baef 100644
--- a/libs/appgrid/lib/res/values-sk/strings.xml
+++ b/libs/appgrid/lib/res/values-sk/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikáciu nie je možné ukončiť."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Skryť aplikácie na ladenie"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Zobraziť aplikácie na ladenie"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ak chcete používať aplikácie deaktivované na základe zmluvných podmienok pre používateľov, vyjadrite súhlas so zmluvnými podmienkami pre používateľov"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Skontrolovať"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Teraz nie"</string>
diff --git a/libs/appgrid/lib/res/values-sl/strings.xml b/libs/appgrid/lib/res/values-sl/strings.xml
index 2ecf7671..b11b4e92 100644
--- a/libs/appgrid/lib/res/values-sl/strings.xml
+++ b/libs/appgrid/lib/res/values-sl/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikacije ni mogoče ustaviti."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Skrij aplikacije za odpravljanje napak"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Prikaži aplikacije za odpravljanje napak"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Če želite uporabljati aplikacije, ki so onemogočene glede na pogoje storitve za uporabnika, sprejmite te pogoje storitve"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Pregled"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Ne zdaj"</string>
diff --git a/libs/appgrid/lib/res/values-sq/strings.xml b/libs/appgrid/lib/res/values-sq/strings.xml
index 0cf2bec5..ca55c74f 100644
--- a/libs/appgrid/lib/res/values-sq/strings.xml
+++ b/libs/appgrid/lib/res/values-sq/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Aplikacioni nuk mund të ndalohet."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Fshih aplikacionet e korrigjimit të defekteve"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Shfaq aplikacionet e korrigjimit të defekteve"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Për të përdorur aplikacionet e çaktivizuara sipas kushteve të shërbimit të përdoruesit, prano \"Kushtet e shërbimit të përdoruesit\""</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Shqyrto"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Jo tani"</string>
diff --git a/libs/appgrid/lib/res/values-sr/strings.xml b/libs/appgrid/lib/res/values-sr/strings.xml
index 3d519432..bc2483a9 100644
--- a/libs/appgrid/lib/res/values-sr/strings.xml
+++ b/libs/appgrid/lib/res/values-sr/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Апликација не може да се заустави."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Сакриј апликације за отклањање грешака"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Прикажи апликације за отклањање грешака"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Да бисте користили апликације онемогућене у складу са условима коришћења услуге за корисника, прихватите услове коришћења услуге за корисника."</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Прегледај"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Не сада"</string>
diff --git a/libs/appgrid/lib/res/values-sv/strings.xml b/libs/appgrid/lib/res/values-sv/strings.xml
index 016f3ceb..58186c10 100644
--- a/libs/appgrid/lib/res/values-sv/strings.xml
+++ b/libs/appgrid/lib/res/values-sv/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Det går inte att avsluta appen."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Dölj felsökningsappar"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Visa felsökningsappar"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Du måste godkänna användarvillkoren för appar för att kunna använda dem"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Granska"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Inte nu"</string>
diff --git a/libs/appgrid/lib/res/values-sw/strings.xml b/libs/appgrid/lib/res/values-sw/strings.xml
index 9650d1d1..ff43e4ad 100644
--- a/libs/appgrid/lib/res/values-sw/strings.xml
+++ b/libs/appgrid/lib/res/values-sw/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Programu haiwezi kuzimwa."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ficha programu za kutatua hitilafu"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Onyesha programu za kutatua hitilafu"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ili utumie programu zilizozimwa kutokana na sheria na masharti ya mtumiaji, kubali Sheria na Masharti ya Mtumiaji"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Kagua"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Si Sasa"</string>
diff --git a/libs/appgrid/lib/res/values-ta/strings.xml b/libs/appgrid/lib/res/values-ta/strings.xml
index 8374a006..992b9b9f 100644
--- a/libs/appgrid/lib/res/values-ta/strings.xml
+++ b/libs/appgrid/lib/res/values-ta/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ஆப்ஸை நிறுத்த முடியாது."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"பிழைதிருத்தும் ஆப்ஸை மறை"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"பிழைதிருத்தும் ஆப்ஸைக் காட்டு"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"பயனர் சேவை விதிமுறைகள் (TOS) முடக்கப்பட்ட ஆப்ஸைப் பயன்படுத்த, அதன் விதிமுறைகளை ஏற்றுக்கொள்ளுங்கள்"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"பாருங்கள்"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"இப்போது வேண்டாம்"</string>
diff --git a/libs/appgrid/lib/res/values-te/strings.xml b/libs/appgrid/lib/res/values-te/strings.xml
index 346ca686..6b294633 100644
--- a/libs/appgrid/lib/res/values-te/strings.xml
+++ b/libs/appgrid/lib/res/values-te/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"యాప్‌ను ఆపడం సాధ్యం కాదు."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"డీబగ్ యాప్‌లను దాచండి"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"డీబగ్ యాప్‌లను చూపించండి"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"డిజేబుల్ చేసిన యూజర్ TOS యాప్‌లను ఉపయోగించడానికి, యూజర్ TOSను అంగీకరించండి"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"రివ్యూ చేయండి"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ఇప్పుడు కాదు"</string>
diff --git a/libs/appgrid/lib/res/values-th/strings.xml b/libs/appgrid/lib/res/values-th/strings.xml
index 98dcdd9f..f8f426fe 100644
--- a/libs/appgrid/lib/res/values-th/strings.xml
+++ b/libs/appgrid/lib/res/values-th/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"หยุดแอปไม่ได้"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ซ่อนแอปแก้ไขข้อบกพร่อง"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"แสดงแอปแก้ไขข้อบกพร่อง"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"หากต้องการใช้แอปที่ปิดใช้โดยข้อกำหนดในการให้บริการของผู้ใช้ ให้ยอมรับข้อกำหนดดังกล่าว"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"ตรวจสอบ"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ไว้ทีหลัง"</string>
diff --git a/libs/appgrid/lib/res/values-tl/strings.xml b/libs/appgrid/lib/res/values-tl/strings.xml
index 623a5219..5f53fb0f 100644
--- a/libs/appgrid/lib/res/values-tl/strings.xml
+++ b/libs/appgrid/lib/res/values-tl/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Hindi puwedeng ihinto ang app."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"I-hide ang mga debug app"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Ipakita ang mga debug app"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Para gumamit ng mga app na naka-disable ang TOS sa user, sumang-ayon sa TOS sa User"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Pagsusuri"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Hindi Ngayon"</string>
diff --git a/libs/appgrid/lib/res/values-tr/strings.xml b/libs/appgrid/lib/res/values-tr/strings.xml
index 8a96385f..dcfc7b4b 100644
--- a/libs/appgrid/lib/res/values-tr/strings.xml
+++ b/libs/appgrid/lib/res/values-tr/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Uygulama durdurulamıyor."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Hata ayıklama uygulamalarını gizle"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Hata ayıklama uygulamalarını göster"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Kullanıcı Hizmet Şartları\'nın devre dışı bıraktığı uygulamaları kullanmak için Kullanıcı Hizmet Şartları\'nı kabul edin"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"İncele"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Şimdi Değil"</string>
diff --git a/libs/appgrid/lib/res/values-uk/strings.xml b/libs/appgrid/lib/res/values-uk/strings.xml
index dec8afb0..6719ef14 100644
--- a/libs/appgrid/lib/res/values-uk/strings.xml
+++ b/libs/appgrid/lib/res/values-uk/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Не вдалося припинити роботу додатка."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Сховати додатки для налагодження"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Показати додатки для налагодження"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Щоб використовувати вимкнені додатки, прийміть Умови використання"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Переглянути"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Не зараз"</string>
diff --git a/libs/appgrid/lib/res/values-ur/strings.xml b/libs/appgrid/lib/res/values-ur/strings.xml
index 3b65bc7a..b441b5de 100644
--- a/libs/appgrid/lib/res/values-ur/strings.xml
+++ b/libs/appgrid/lib/res/values-ur/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"ایپ کو بند نہیں کیا جا سکتا۔"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"ڈیبگ ایپس چھپائیں"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"ڈیبگ ایپس دکھائیں"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"صارف کی غیر فعال کردہ سروس کی شرائط والی ایپس کا استعمال کرنے کے لیے صارف کی سروس کی شرائط سے اتفاق کریں"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"جائزہ لیں"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"ابھی نہیں"</string>
diff --git a/libs/appgrid/lib/res/values-uz/strings.xml b/libs/appgrid/lib/res/values-uz/strings.xml
index 26cbf5cb..18b7d10e 100644
--- a/libs/appgrid/lib/res/values-uz/strings.xml
+++ b/libs/appgrid/lib/res/values-uz/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Ilovani toʻxtatish imkonsiz."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Nosozliklarni aniqlash ilovalarini berkitish"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Nosozliklarni aniqlash ilovalarini chiqarish"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ayrim ilovalardan faqatgina foydalanish shartlarini qabul qilgandan keyin foydalanish mumkin"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Tekshirish"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Hozir emas"</string>
diff --git a/libs/appgrid/lib/res/values-vi/strings.xml b/libs/appgrid/lib/res/values-vi/strings.xml
index 0c0f70f5..fb973fc8 100644
--- a/libs/appgrid/lib/res/values-vi/strings.xml
+++ b/libs/appgrid/lib/res/values-vi/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"Không dừng được ứng dụng."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Ẩn các ứng dụng gỡ lỗi"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Hiện các ứng dụng gỡ lỗi"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Để sử dụng ứng dụng chưa kích hoạt điều khoản dịch vụ cho người dùng, hãy chấp nhận điều khoản dịch vụ cho người dùng"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Đánh giá"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Để sau"</string>
diff --git a/libs/appgrid/lib/res/values-zh-rCN/strings.xml b/libs/appgrid/lib/res/values-zh-rCN/strings.xml
index 5b404853..e384f60b 100644
--- a/libs/appgrid/lib/res/values-zh-rCN/strings.xml
+++ b/libs/appgrid/lib/res/values-zh-rCN/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"无法停止应用。"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"隐藏调试应用"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"显示调试应用"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"若要使用《用户服务条款》所停用的应用，请同意《用户服务条款》"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"查看"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"以后再说"</string>
diff --git a/libs/appgrid/lib/res/values-zh-rHK/strings.xml b/libs/appgrid/lib/res/values-zh-rHK/strings.xml
index 2b632b95..b372e976 100644
--- a/libs/appgrid/lib/res/values-zh-rHK/strings.xml
+++ b/libs/appgrid/lib/res/values-zh-rHK/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"無法停止應用程式。"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"隱藏偵錯應用程式"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"顯示偵錯應用程式"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"如要使用使用者服務條款停用的應用程式，請同意使用者服務條款"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"審核"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"暫時不要"</string>
diff --git a/libs/appgrid/lib/res/values-zh-rTW/strings.xml b/libs/appgrid/lib/res/values-zh-rTW/strings.xml
index 2eb60036..505a16b7 100644
--- a/libs/appgrid/lib/res/values-zh-rTW/strings.xml
+++ b/libs/appgrid/lib/res/values-zh-rTW/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"無法停止應用程式。"</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"隱藏偵錯應用程式"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"顯示偵錯應用程式"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"如要使用因尚未同意使用者服務條款而停用的應用程式，請同意使用者服務條款"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"查看"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"暫時不要"</string>
diff --git a/libs/appgrid/lib/res/values-zu/strings.xml b/libs/appgrid/lib/res/values-zu/strings.xml
index f8610980..d97fa3cd 100644
--- a/libs/appgrid/lib/res/values-zu/strings.xml
+++ b/libs/appgrid/lib/res/values-zu/strings.xml
@@ -24,7 +24,6 @@
     <string name="app_launcher_stop_app_cant_stop_text" msgid="6513703446595313338">"I-App ayikwazi ukumiswa."</string>
     <string name="hide_debug_apps" msgid="7140064693464751647">"Fihla ama-app okususa iphutha"</string>
     <string name="show_debug_apps" msgid="2748157232151197494">"Bonisa ama-app okususa iphutha"</string>
-    <string name="user_tos_activity_intent" msgid="5323981034042569291">"intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end"</string>
     <string name="banner_title_text" msgid="8827498256184464356">"Ukuze usebenzise ama-app akhutshaziwe e-tos, vumelana ne-tos Yomsebenzisi"</string>
     <string name="banner_review_button_text" msgid="369410598918950148">"Buyekeza"</string>
     <string name="banner_dismiss_button_text" msgid="5389352614429069562">"Hhayi Manje"</string>
diff --git a/libs/appgrid/lib/res/values/overlayable.xml b/libs/appgrid/lib/res/values/overlayable.xml
index 53ba4f49..a9780106 100644
--- a/libs/appgrid/lib/res/values/overlayable.xml
+++ b/libs/appgrid/lib/res/values/overlayable.xml
@@ -1,5 +1,5 @@
 <?xml version='1.0' encoding='UTF-8'?>
-<!-- Copyright (C) 2024 The Android Open Source Project
+<!-- Copyright (C) 2025 The Android Open Source Project
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
diff --git a/libs/appgrid/lib/res/values/strings.xml b/libs/appgrid/lib/res/values/strings.xml
index 55abe291..9257cf3d 100644
--- a/libs/appgrid/lib/res/values/strings.xml
+++ b/libs/appgrid/lib/res/values/strings.xml
@@ -39,7 +39,7 @@
          "intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=true;end"
     -->
 
-    <string name="user_tos_activity_intent">
+    <string name="user_tos_activity_intent" translatable="false">
         intent:#Intent;action=com.android.car.SHOW_USER_TOS_ACTIVITY;B.show_value_prop=false;end
     </string>
 
diff --git a/libs/appgrid/lib/robotests/Android.bp b/libs/appgrid/lib/robotests/Android.bp
index 4c2bacd7..114b2f8a 100644
--- a/libs/appgrid/lib/robotests/Android.bp
+++ b/libs/appgrid/lib/robotests/Android.bp
@@ -51,7 +51,6 @@ android_robolectric_test {
     },
 
     instrumentation_for: "CarAppGridTestApp",
-    upstream: true,
 
     strict_mode: false,
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
index 81e757db..b7cf2e42 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridFragment.kt
@@ -201,22 +201,6 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
         })
         appGridRecyclerView.adapter = adapter
 
-        appGridViewModel.getAppList().asLiveData().observe(
-            viewLifecycleOwner
-        ) { appItems: List<AppItem?>? ->
-            adapter.setLauncherItems(appItems)
-            nextScrollDestination = snapCallback.snapPosition
-            updateScrollState()
-        }
-
-        appGridViewModel.requiresDistractionOptimization().asLiveData().observe(
-            viewLifecycleOwner
-        ) { uxRestrictions: Boolean ->
-            handleDistractionOptimization(
-                uxRestrictions
-            )
-        }
-
         // set drag listener and global layout listener, which will dynamically adjust app grid
         // height and width depending on device screen size. ize.
         if (resources.getBoolean(R.bool.config_allow_reordering)) {
@@ -240,6 +224,28 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
         backgroundAnimationHelper = BackgroundAnimationHelper(windowBackground, banner)
 
         setupTosBanner()
+
+        dimensionUpdateCallback.addListener { _, _ ->
+            // TODO(b/402879929): Await for the first pass of dimensionUpdateCallback before setting
+            //  the list on the recycler view
+            appGridViewModel.getAppList().asLiveData().observe(
+                viewLifecycleOwner
+            ) { appItems: List<AppItem?>? ->
+                adapter.setLauncherItems(appItems)
+                nextScrollDestination = snapCallback.snapPosition
+                updateScrollState()
+            }
+
+            appGridViewModel.requiresDistractionOptimization().asLiveData().observe(
+                viewLifecycleOwner
+            ) { uxRestrictions: Boolean ->
+                handleDistractionOptimization(
+                    uxRestrictions
+                )
+            }
+            // remove self after first callback is received.
+            true
+        }
     }
 
     /**
@@ -489,12 +495,13 @@ class AppGridFragment : Fragment(), PageSnapListener, AppItemDragListener, Dimen
     override fun onDimensionsUpdated(
         pageDimens: PageMeasurementHelper.PageDimensions,
         gridDimens: PageMeasurementHelper.GridDimensions
-    ) {
+    ): Boolean {
         // TODO(b/271637411): move this method into a scroll controller
         appGridMarginHorizontal = pageDimens.marginHorizontalPx
         appGridMarginVertical = pageDimens.marginVerticalPx
         appGridWidth = gridDimens.gridWidthPx
         appGridHeight = gridDimens.gridHeightPx
+        return false
     }
 
     override fun onAppPositionChanged(newPosition: Int, appItem: AppItem) {
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java
index 0af13f21..5b50e30d 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/AppGridRecyclerView.java
@@ -156,7 +156,7 @@ public class AppGridRecyclerView extends RecyclerView implements DimensionUpdate
     }
 
     @Override
-    public void onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens) {
+    public boolean onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens) {
         ViewGroup.LayoutParams layoutParams = getLayoutParams();
         layoutParams.width = pageDimens.recyclerViewWidthPx;
         layoutParams.height = pageDimens.recyclerViewHeightPx;
@@ -187,5 +187,6 @@ public class AppGridRecyclerView extends RecyclerView implements DimensionUpdate
         addItemDecoration(mPageMarginDecoration);
         // Now attach adapter to the recyclerView, after dimens are updated.
         super.setAdapter(mAdapter);
+        return false;
     }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/PageIndicator.java b/libs/appgrid/lib/src/com/android/car/carlauncher/PageIndicator.java
index 57aab627..fdbdf2e1 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/PageIndicator.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/PageIndicator.java
@@ -75,7 +75,7 @@ public class PageIndicator extends FrameLayout implements DimensionUpdateListene
     }
 
     @Override
-    public void onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens) {
+    public boolean onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens) {
         ViewGroup.LayoutParams indicatorContainerParams = mContainer.getLayoutParams();
         indicatorContainerParams.width = pageDimens.pageIndicatorWidthPx;
         indicatorContainerParams.height = pageDimens.pageIndicatorHeightPx;
@@ -85,6 +85,7 @@ public class PageIndicator extends FrameLayout implements DimensionUpdateListene
         mAppGridWidth = gridDimens.gridWidthPx;
         mAppGridHeight = gridDimens.gridHeightPx;
         updatePageCount(mPageCount);
+        return false;
     }
 
     /**
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt
index fad5995e..e35da715 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/datasources/AppOrderDataSource.kt
@@ -142,6 +142,9 @@ class AppOrderProtoDataSourceImpl(
                 appOrderFlow.value =
                     appOrderFromFiles.sortedBy { it.relativePosition }
                         .map { AppOrderInfo(it.packageName, it.className, it.displayName) }
+            } else {
+                // Reset the appOrder to empty list
+                appOrderFlow.value = emptyList()
             }
         }
         emitAll(appOrderFlow)
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PaginationController.java b/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PaginationController.java
index e144da5b..308a4161 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PaginationController.java
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/pagination/PaginationController.java
@@ -23,6 +23,7 @@ import com.android.car.carlauncher.pagination.PageMeasurementHelper.GridDimensio
 import com.android.car.carlauncher.pagination.PageMeasurementHelper.PageDimensions;
 
 import java.util.HashSet;
+import java.util.Iterator;
 import java.util.Set;
 
 /**
@@ -74,8 +75,11 @@ public class PaginationController {
          * Updates all listeners with the new measured dimensions.
          */
         public void notifyDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens) {
-            for (DimensionUpdateListener listener : mListeners) {
-                listener.onDimensionsUpdated(pageDimens, gridDimens);
+            Iterator<DimensionUpdateListener> iterator = mListeners.iterator();
+            while (iterator.hasNext()) {
+                if (iterator.next().onDimensionsUpdated(pageDimens, gridDimens)) {
+                    iterator.remove();
+                }
             }
         }
     }
@@ -89,7 +93,11 @@ public class PaginationController {
     public interface DimensionUpdateListener {
         /**
          * Updates layout params from the updated dimensions measurements in {@link PageDimensions}
-         * and {@link GridDimensions}*/
-        void onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens);
+         * and {@link GridDimensions}
+         *
+         * @return true if this listener should be removed after the first invocation,
+         * indicating it's designed for a single execution.
+         */
+        boolean onDimensionsUpdated(PageDimensions pageDimens, GridDimensions gridDimens);
     }
 }
diff --git a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt
index 5d68f9c7..f3a98f3e 100644
--- a/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt
+++ b/libs/appgrid/lib/src/com/android/car/carlauncher/repositories/appactions/AppShortcutsFactory.kt
@@ -26,7 +26,6 @@ import android.view.View
 import com.android.car.carlaunchercommon.shortcuts.AppInfoShortcutItem
 import com.android.car.carlaunchercommon.shortcuts.ForceStopShortcutItem
 import com.android.car.carlaunchercommon.shortcuts.PinShortcutItem
-import com.android.car.dockutil.Flags
 import com.android.car.dockutil.events.DockCompatUtils.isDockSupportedOnDisplay
 import com.android.car.dockutil.events.DockEventSenderHelper
 import com.android.car.ui.shortcutspopup.CarUiShortcutsPopup
@@ -81,9 +80,7 @@ class AppShortcutsFactory(
                         UserHandle.getUserHandleForUid(Process.myUid())
                     )
                 )
-        if (Flags.dockFeature() &&
-            isDockSupportedOnDisplay(context, context.display?.displayId ?: INVALID_DISPLAY)
-        ) {
+        if (isDockSupportedOnDisplay(context, context.display?.displayId ?: INVALID_DISPLAY)) {
             carUiShortcutsPopupBuilder
                 .addShortcut(buildPinToDockShortcut(componentName, context))
         }
diff --git a/libs/car-launcher-common/OWNERS b/libs/car-launcher-common/OWNERS
index 6ece7f0f..80304ec9 100644
--- a/libs/car-launcher-common/OWNERS
+++ b/libs/car-launcher-common/OWNERS
@@ -5,5 +5,3 @@ set noparent
 danzz@google.com
 ankiit@google.com
 jainams@google.com
-nehah@google.com
-igorr@google.com
```

